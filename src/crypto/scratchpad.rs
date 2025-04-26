use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use crate::crypto::EncryptedData;
use anyhow::{anyhow, bail};
use autonomi::{Client, Scratchpad, ScratchpadAddress};
use bytes::Bytes;
use std::fmt::Display;
use std::marker::PhantomData;

pub trait Content: Into<Bytes> + TryFrom<Bytes> {
    const ENCODING: u64;
}

pub type EncryptedContent<R, V> = EncryptedData<R, V>;

impl<R, V: Content> Content for EncryptedContent<R, V> {
    const ENCODING: u64 = V::ENCODING;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedScratchpad<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedScratchpadAddress<T, V>,
}

impl<T, V> TypedOwnedScratchpad<T, V> {
    pub(super) fn new(owner: TypedSecretKey<T>) -> Self {
        let address = TypedScratchpadAddress::new(ScratchpadAddress::new(
            owner.public_key().as_ref().clone(),
        ));
        Self { owner, address }
    }

    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedScratchpadAddress<T, V> {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedScratchpadAddress<T, V> {
    inner: ScratchpadAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> TypedScratchpadAddress<T, V> {
    pub(super) fn new(inner: ScratchpadAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner().clone());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }

    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &ScratchpadAddress {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextScratchpad<T, V> {
    content: Bytes,
    data_encoding: u64,
    counter: u64,
    address: TypedScratchpadAddress<T, V>,
}

impl<T, V: Content> PlaintextScratchpad<T, V> {
    pub fn address(&self) -> &TypedScratchpadAddress<T, V> {
        &self.address
    }

    pub fn size(&self) -> usize {
        size_of::<Scratchpad>() + self.content.len()
    }
}

impl<T, V: Content> PlaintextScratchpad<T, V> {
    pub(crate) fn try_from_scratchpad(pad: Scratchpad) -> anyhow::Result<Self> {
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

    pub(crate) fn new_from_value(value: V, owner: TypedPublicKey<T>) -> Self {
        Self {
            content: value.into(),
            data_encoding: V::ENCODING,
            counter: 1,
            address: TypedScratchpadAddress::new(ScratchpadAddress::new(owner.as_ref().clone())),
        }
    }

    pub fn update(&mut self, value: V) -> anyhow::Result<u64> {
        if V::ENCODING != self.data_encoding {
            bail!(
                "incorrect data_encoding for content: expected [{}] but got [{}]",
                self.data_encoding,
                V::ENCODING
            );
        }
        self.content = value.into();
        self.counter += 1;
        Ok(self.counter)
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
    pub(crate) fn try_into_scratchpad(
        self,
        owner: &TypedOwnedScratchpad<T, V>,
    ) -> anyhow::Result<Scratchpad> {
        if self.address.as_ref() != owner.address.as_ref() {
            bail!("invalid owner");
        }
        let signature = owner.owner.as_ref().sign(
            Scratchpad::bytes_for_signature(
                self.address.inner.clone(),
                self.data_encoding,
                &self.content,
                self.counter,
            )
            .as_slice(),
        );

        let pad = Scratchpad::new_with_signature(
            owner.owner.public_key().as_ref().clone(),
            self.data_encoding,
            self.content,
            self.counter,
            signature,
        );

        Client::scratchpad_verify(&pad)?;

        Ok(pad)
    }
}
