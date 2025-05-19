use crate::crypto::encrypt::{DefaultEncryptionScheme, EncryptedData, EncryptionScheme};
use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use crate::crypto::{Finalizeable, Retirable, ScratchpadContent};
use crate::{Core, Receipt};
use anyhow::{anyhow, bail};
use autonomi::{Client, Scratchpad, ScratchpadAddress};
use bytes::Bytes;
use once_cell::sync::Lazy;
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;

const EOL_ENCODING: u64 = u64::MAX;
const EOL_COUNTER: u64 = u64::MAX;
static TOMBSTONE_VALUE: Lazy<Bytes> = Lazy::new(|| Bytes::from_static("RIP".as_bytes()));

pub trait Content: Into<Bytes> + TryFrom<Bytes> {
    const ENCODING: u64;
}

pub type EncryptedContent<R, V, S: EncryptionScheme = DefaultEncryptionScheme> =
    EncryptedData<R, V, S>;

impl<R, V: Content, S: EncryptionScheme> Content for EncryptedContent<R, V, S> {
    const ENCODING: u64 = V::ENCODING;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedScratchpadAddress<T, V> {
    inner: ScratchpadAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> TypedScratchpadAddress<T, V> {
    fn new(inner: ScratchpadAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner().clone());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }

    pub(crate) fn from_public_key(pk: TypedPublicKey<T>) -> Self {
        Self::new(ScratchpadAddress::new(pk.inner))
    }

    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &ScratchpadAddress {
        &self.inner
    }
}

pub type TypedScratchpad<T, V> = PlaintextScratchpad<T, V>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextScratchpad<T, V> {
    content: Bytes,
    data_encoding: u64,
    counter: u64,
    address: TypedScratchpadAddress<T, V>,
}

impl<T, V> PlaintextScratchpad<T, V> {
    pub fn address(&self) -> &TypedScratchpadAddress<T, V> {
        &self.address
    }

    pub fn size(&self) -> usize {
        size_of::<Scratchpad>() + self.content.len()
    }
}

impl<T, V: Content> PlaintextScratchpad<T, V> {
    pub(crate) fn try_from_scratchpad(pad: Scratchpad) -> anyhow::Result<Self> {
        if pad.is_retired() {
            bail!("scratchpad is retired");
        }

        if pad.data_encoding() != V::ENCODING {
            bail!(
                "incorrect data_encoding for content: expected [{}] but got [{}]",
                V::ENCODING,
                pad.data_encoding(),
            );
        }

        Ok(Self {
            content: pad.encrypted_data().clone(),
            data_encoding: pad.data_encoding(),
            counter: pad.counter(),
            address: TypedScratchpadAddress::new(pad.address().clone()),
        })
    }
}

impl<T, V: TryFrom<Bytes>> PlaintextScratchpad<T, V> {
    pub fn try_into_inner(self) -> anyhow::Result<V>
    where
        <V as TryFrom<Bytes>>::Error: Display,
    {
        V::try_from(self.content)
            .map_err(|e| anyhow!("conversion from plaintext scratchpad failed: {}", e))
    }
}

impl<T, V> PlaintextScratchpad<T, V> {
    pub fn is_mutable(&self) -> bool {
        self.counter < EOL_COUNTER
    }
}

impl<T, V: Retirable> PlaintextScratchpad<T, V> {
    pub fn is_retired(&self) -> bool {
        self.data_encoding == EOL_ENCODING
            && self.counter == EOL_COUNTER
            && &self.content == TOMBSTONE_VALUE.deref()
    }
}

impl<T: Clone, V> PlaintextScratchpad<T, V> {
    pub(crate) fn try_into_owned(
        self,
        owner: &TypedSecretKey<T>,
    ) -> anyhow::Result<TypedOwnedScratchpad<T, V>> {
        if owner.public_key().as_ref() != self.address.owner.as_ref() {
            eprintln!(
                "[{:?}] != [{:?}]",
                owner.public_key().as_ref(),
                self.address.owner.as_ref(),
            );
            bail!("invalid owner");
        }
        Ok(TypedOwnedScratchpad {
            owner: owner.clone(),
            inner: self,
        })
    }
}

pub struct TypedOwnedScratchpad<T, V> {
    owner: TypedSecretKey<T>,
    inner: TypedScratchpad<T, V>,
}

impl<T, V: Content> TypedOwnedScratchpad<T, V> {
    pub(crate) fn new(value: V, owner: TypedSecretKey<T>) -> Self {
        let pk = owner.public_key().inner.clone();
        Self {
            owner,
            inner: TypedScratchpad {
                content: value.into(),
                data_encoding: V::ENCODING,
                counter: 1,
                address: TypedScratchpadAddress::new(ScratchpadAddress::new(pk)),
            },
        }
    }
}

impl<T, V> TypedOwnedScratchpad<T, V> {
    pub fn address(&self) -> &TypedScratchpadAddress<T, V> {
        self.inner.address()
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }
    pub fn is_mutable(&self) -> bool {
        self.inner.is_mutable()
    }

    pub fn is_equivalent(&self, other: &Scratchpad) -> bool {
        self.inner.counter == other.counter()
            && self.inner.data_encoding == other.data_encoding()
            && &self.inner.content == other.encrypted_data()
    }
}

impl<T, V: Finalizeable> TypedOwnedScratchpad<T, V> {
    fn make_immutable(mut self) -> anyhow::Result<Scratchpad> {
        if !self.is_mutable() {
            bail!("scratchpad is already immutable");
        }

        self.inner.counter = EOL_COUNTER;

        self.try_into_scratchpad()
    }
}

impl<T, V: Retirable> TypedOwnedScratchpad<T, V> {
    fn retire(mut self) -> anyhow::Result<Scratchpad> {
        if self.is_retired() {
            bail!("scratchpad already retired");
        }

        if !self.is_mutable() {
            bail!("scratchpad is immutable");
        }

        self.inner.data_encoding = EOL_ENCODING;
        self.inner.counter = EOL_COUNTER;
        self.inner.content = TOMBSTONE_VALUE.clone();

        self.try_into_scratchpad()
    }

    pub fn is_retired(&self) -> bool {
        self.inner.is_retired()
    }
}

impl<T, V> TypedOwnedScratchpad<T, V> {
    fn try_into_scratchpad(self) -> anyhow::Result<Scratchpad> {
        if self.owner.public_key().as_ref() != self.inner.address.owner().as_ref() {
            bail!("invalid owner");
        }
        let signature = self.owner.as_ref().sign(
            Scratchpad::bytes_for_signature(
                self.inner.address.inner.clone(),
                self.inner.data_encoding,
                &self.inner.content,
                self.inner.counter,
            )
            .as_slice(),
        );

        let pad = Scratchpad::new_with_signature(
            self.owner.public_key().as_ref().clone(),
            self.inner.data_encoding,
            self.inner.content,
            self.inner.counter,
            signature,
        );

        Client::scratchpad_verify(&pad)?;

        Ok(pad)
    }
}

impl<T, V: Content> TypedOwnedScratchpad<T, V> {
    pub fn update(&mut self, value: V) -> anyhow::Result<u64> {
        if !self.is_mutable() {
            bail!("scratchpad is immutable");
        }

        if V::ENCODING != self.inner.data_encoding {
            bail!(
                "incorrect data_encoding for content: expected [{}] but got [{}]",
                self.inner.data_encoding,
                V::ENCODING
            );
        }
        self.inner.content = value.into();
        self.inner.counter += 1;
        Ok(self.inner.counter)
    }
}

pub(crate) trait ScratchpadExt {
    fn is_mutable(&self) -> bool;
    fn is_retired(&self) -> bool;
}

impl ScratchpadExt for Scratchpad {
    fn is_mutable(&self) -> bool {
        self.counter() < EOL_COUNTER
    }

    fn is_retired(&self) -> bool {
        self.data_encoding() == EOL_ENCODING
            && !self.is_mutable()
            && self.encrypted_data() == TOMBSTONE_VALUE.deref()
    }
}

impl Core {
    /// Creates a new **ENCRYPTED** scratchpad owned by the given owner yet readable by `R`.
    pub(crate) async fn create_encrypted_scratchpad<
        O: Clone + PartialEq,
        R,
        V: Content,
        S: EncryptionScheme,
    >(
        &self,
        pad: TypedOwnedScratchpad<O, EncryptedContent<R, V, S>>,
        //encrypted_content: EncryptedScratchpadContent<R, V, S>,
        //owner: TypedOwnedScratchpad<O, EncryptedData<R, V, S>>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedScratchpadAddress<O, EncryptedContent<R, V, S>>> {
        self.create_scratchpad(pad, receipt).await
    }

    /// Creates a new **PLAINTEXT** scratchpad owned by the given owner.
    async fn create_scratchpad<T: Clone + PartialEq, V: Content>(
        &self,
        pad: TypedOwnedScratchpad<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<TypedScratchpadAddress<T, V>> {
        let pad = pad.try_into_scratchpad()?;
        if self.scratchpad_cache.contains_key(pad.address())
            || self
                .client
                .scratchpad_check_existance(pad.address())
                .await?
        {
            bail!("scratchpad already exists");
        }
        let address = pad.address().clone();
        let res = self.client.scratchpad_put(pad, self.payment()).await;
        self.scratchpad_cache.invalidate(&address).await;
        let (attos, address) = res?;
        receipt.add(attos);

        Ok(TypedScratchpadAddress::new(address))
    }

    pub(crate) async fn read_scratchpad<T, V: Content>(
        &self,
        address: &TypedScratchpadAddress<T, V>,
    ) -> anyhow::Result<V>
    where
        <V as TryFrom<Bytes>>::Error: Display,
    {
        Ok(self
            .get_scratchpad(address)
            .await?
            .map(|s| s.try_into_inner())
            .transpose()?
            .ok_or(anyhow!("scratchpad not found"))?)
    }

    pub(crate) async fn get_scratchpad<T, V: Content>(
        &self,
        address: &TypedScratchpadAddress<T, V>,
    ) -> anyhow::Result<Option<TypedScratchpad<T, V>>> {
        Ok(self
            ._scratchpad_get(address.as_ref())
            .await?
            .map(|s| TypedScratchpad::<T, V>::try_from_scratchpad(s))
            .transpose()?)
    }

    async fn _scratchpad_get(
        &self,
        address: &ScratchpadAddress,
    ) -> anyhow::Result<Option<Scratchpad>> {
        self.scratchpad_cache
            .try_get_with_by_ref(address, self._scratchpad_get_live(address))
            .await
            .map_err(|e| anyhow!("{}", e))
    }

    async fn _scratchpad_get_live(
        &self,
        address: &ScratchpadAddress,
    ) -> anyhow::Result<Option<Scratchpad>> {
        if !self.client.scratchpad_check_existance(address).await? {
            return Ok(None);
        }
        Ok(Some(
            self.client
                .scratchpad_get_from_public_key(address.owner())
                .await?,
        ))
    }

    pub(crate) async fn update_scratchpad<T: Clone + PartialEq, V: Content>(
        &self,
        mut pad: TypedOwnedScratchpad<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<u64> {
        let existing = self
            ._scratchpad_get(pad.address().as_ref())
            .await?
            .ok_or(anyhow!("scratchpad does not exist"))?;
        if existing.is_retired() {
            bail!("scratchpad is retired");
        }
        if !existing.is_mutable() {
            bail!("scratchpad is immutable");
        }

        if existing.counter() > pad.inner.counter {
            pad.inner.counter = existing.counter();
        }

        if pad.is_equivalent(&existing) {
            // already up-to-date
            // no need to send to the network
            return Ok(existing.counter());
        }

        if existing.counter() >= pad.inner.counter {
            pad.inner.counter = existing.counter() + 1;
        }

        let new_pad = pad.try_into_scratchpad()?;

        let counter = new_pad.counter();
        self._scratchpad_put(new_pad, receipt).await?;
        Ok(counter)
    }

    pub(crate) async fn danger_retire_scratchpad<
        T: Clone + PartialEq,
        V: ScratchpadContent + Retirable,
    >(
        &self,
        pad: TypedOwnedScratchpad<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        self._scratchpad_put(pad.retire()?, receipt).await?;
        Ok(())
    }

    async fn danger_finalize_scratchpad<
        T: Clone + PartialEq,
        V: ScratchpadContent + Finalizeable,
    >(
        &self,
        pad: TypedOwnedScratchpad<T, V>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        self._scratchpad_put(pad.make_immutable()?, receipt).await?;
        Ok(())
    }

    async fn _scratchpad_put(&self, pad: Scratchpad, receipt: &mut Receipt) -> anyhow::Result<()> {
        let address = pad.address().clone();
        let res = self.client.scratchpad_put(pad, self.payment()).await;
        self.scratchpad_cache.invalidate(&address).await;
        let (attos, _) = res?;
        receipt.add(attos);
        Ok(())
    }
}
