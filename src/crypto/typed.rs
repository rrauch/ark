use anyhow::{anyhow, bail};
use autonomi::client::key_derivation::DerivationIndex;
use autonomi::pointer::PointerTarget;
use autonomi::register::RegisterAddress;
use autonomi::{Chunk, ChunkAddress, PointerAddress, PublicKey, SecretKey};
use bech32::{Bech32m, EncodeError, Hrp};
use blsttc::Ciphertext;
use bytes::Bytes;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use zeroize::Zeroize;

impl<T> From<[u8; 32]> for TypedDerivationIndex<T> {
    fn from(value: [u8; 32]) -> Self {
        Self {
            inner: DerivationIndex::from_bytes(value),
            _type: Default::default(),
        }
    }
}

impl<T> Into<[u8; 32]> for TypedDerivationIndex<T> {
    fn into(self) -> [u8; 32] {
        self.inner.into_bytes()
    }
}

impl<T> TryFrom<&[u8]> for TypedDerivationIndex<T> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            bail!("value length [{}] != 32", value.len());
        }
        let value: [u8; 32] = value.try_into()?;
        Ok(Self::from(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedDerivationIndex<T> {
    inner: DerivationIndex,
    _type: PhantomData<T>,
}

impl<T> TypedDerivationIndex<T> {
    pub fn random() -> Self {
        let seed: [u8; 32] = rand::random();
        Self::from(seed)
    }
}

#[derive(Zeroize, Debug, Clone, PartialEq, Eq)]
pub struct TypedSecretKey<T> {
    inner: SecretKey,
    #[zeroize(skip)]
    public_key: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    pub(super) fn new(inner: SecretKey) -> Self {
        let public_key = TypedPublicKey::from(inner.public_key());
        Self { inner, public_key }
    }

    pub fn public_key(&self) -> &TypedPublicKey<T> {
        &self.public_key
    }

    pub fn decrypt<V: for<'a> TryFrom<&'a [u8]>>(
        &self,
        input: &EncryptedData<T, V>,
    ) -> anyhow::Result<V>
    where
        for<'a> <V as TryFrom<&'a [u8]>>::Error: Display,
    {
        let mut plaintext = self
            .inner
            .decrypt(&input.inner)
            .ok_or(anyhow!("unable to decrypt ciphertext"))?;
        let res = plaintext
            .as_slice()
            .try_into()
            .map_err(|e| anyhow!("error converting plaintext: {}", e));
        plaintext.zeroize();
        res
    }

    pub(super) fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedSecretKey<C> {
        TypedSecretKey::new(self.inner.derive_child(idx.inner.as_bytes()))
    }

    pub(crate) fn as_ref(&self) -> &SecretKey {
        &self.inner
    }
}

pub(super) trait Bech32Secret {
    const HRP: &'static str;
}

impl<T: Bech32Secret> TypedSecretKey<T> {
    pub fn danger_to_string(&self) -> String {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        bech32::encode::<Bech32m>(hrp, self.inner.to_bytes().as_slice())
            .expect("bytes to be encodable")
    }
}

impl<T: Bech32Secret> FromStr for TypedSecretKey<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        let (hrp, mut bytes) = bech32::decode(s.as_ref())?;
        if hrp != expected_hrp {
            bytes.zeroize();
            bail!("hrp [{}] != [{}]", hrp, expected_hrp);
        };
        if bytes.len() != 32 {
            bytes.zeroize();
            bail!("invalid key len: [{}] != [{}]", bytes.len(), 32);
        }

        Ok(Self::new(SecretKey::from_bytes(
            bytes.try_into().expect("byte vec of len 32"),
        )?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedPublicKey<T> {
    inner: PublicKey,
    _type: PhantomData<T>,
}

impl<T> TypedPublicKey<T> {
    pub(super) fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedPublicKey<C> {
        TypedPublicKey::from(self.inner.derive_child(idx.inner.as_bytes()))
    }

    pub(crate) fn as_ref(&self) -> &PublicKey {
        &self.inner
    }

    pub(crate) fn encrypt<V: Into<Bytes>>(&self, input: V) -> EncryptedData<T, V> {
        let plaintext = input.into();
        let encrypted = EncryptedData::from_ciphertext(self.inner.encrypt(plaintext.as_ref()));
        encrypted
    }
}

impl<T> From<PublicKey> for TypedPublicKey<T> {
    fn from(value: PublicKey) -> Self {
        Self {
            inner: value,
            _type: Default::default(),
        }
    }
}

impl<T> Into<PublicKey> for TypedPublicKey<T> {
    fn into(self) -> PublicKey {
        self.inner
    }
}

pub(super) trait Bech32Public {
    const HRP: &'static str;
}

impl<T: Bech32Public> Display for TypedPublicKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        bech32::encode_to_fmt::<Bech32m, _>(f, hrp, &self.inner.to_bytes().as_ref()).map_err(|e| {
            match e {
                EncodeError::Fmt(e) => e,
                _ => {
                    // not really sure what to do here
                    panic!("{}", e)
                }
            }
        })
    }
}

impl<T: Bech32Public> FromStr for TypedPublicKey<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_hrp = Hrp::parse(T::HRP).expect("hrp to be valid");

        let (hrp, bytes) = bech32::decode(s.as_ref())?;
        if hrp != expected_hrp {
            bail!("hrp [{}] != [{}]", hrp, expected_hrp);
        };
        if bytes.len() != 48 {
            bail!("invalid key len: [{}] != [{}]", bytes.len(), 48);
        }
        Ok(Self::from(PublicKey::from_bytes(
            bytes.try_into().expect("byte vec of len 48"),
        )?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedRegister<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedRegisterAddress<T, V>,
}

impl<T: Clone, V> TypedOwnedRegister<T, V> {
    pub(super) fn new(owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedRegisterAddress::new(RegisterAddress::new(owner.public_key().clone().into()));
        Self { owner, address }
    }
}

impl<T, V> TypedOwnedRegister<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedRegisterAddress<T, V> {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedRegisterAddress<T, V> {
    inner: RegisterAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> TypedRegisterAddress<T, V> {
    pub(super) fn new(inner: RegisterAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }

    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &RegisterAddress {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedPointerAddress<T, V> {
    inner: PointerAddress,
    owner: TypedPublicKey<T>,
    _value_type: PhantomData<V>,
}

impl<T, V: Into<PointerTarget>> TypedPointerAddress<T, V> {
    pub(super) fn new(inner: PointerAddress) -> Self {
        let owner = TypedPublicKey::from(inner.owner().clone());
        Self {
            inner,
            owner,
            _value_type: Default::default(),
        }
    }
}

impl<T, V> TypedPointerAddress<T, V> {
    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }

    pub(crate) fn as_ref(&self) -> &PointerAddress {
        &self.inner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedPointer<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedPointerAddress<T, V>,
}

impl<T, V: Into<PointerTarget>> TypedOwnedPointer<T, V> {
    pub(super) fn new(owner: TypedSecretKey<T>) -> Self {
        let address =
            TypedPointerAddress::new(PointerAddress::new(owner.public_key().as_ref().clone()));
        Self { owner, address }
    }
}

impl<T, V> TypedOwnedPointer<T, V> {
    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedPointerAddress<T, V> {
        &self.address
    }
}

impl<T> From<TypedChunk<T>> for PointerTarget {
    fn from(value: TypedChunk<T>) -> Self {
        PointerTarget::ChunkAddress(value.address.inner)
    }
}

impl<T> TryFrom<PointerTarget> for TypedChunkAddress<T> {
    type Error = anyhow::Error;

    fn try_from(value: PointerTarget) -> Result<Self, Self::Error> {
        let address = match value {
            PointerTarget::ChunkAddress(address) => address,
            _ => bail!("pointer target not a chunk address"),
        };

        Ok(Self::new(address))
    }
}

pub struct EncryptedData<T, V> {
    inner: Ciphertext,
    _type: PhantomData<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> EncryptedData<T, V> {
    fn from_ciphertext(inner: Ciphertext) -> Self {
        Self {
            inner,
            _type: Default::default(),
            _value_type: Default::default(),
        }
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let ciphertext = Ciphertext::from_bytes(bytes.as_ref())?;
        if !ciphertext.verify() {
            bail!("ciphertext verification failed, not a valid ciphertext");
        }
        Ok(Self::from_ciphertext(ciphertext))
    }
}

pub struct TypedChunkAddress<T> {
    inner: ChunkAddress,
    _type: PhantomData<T>,
}

impl<T> TypedChunkAddress<T> {
    pub(crate) fn new(inner: ChunkAddress) -> Self {
        Self {
            inner,
            _type: Default::default(),
        }
    }

    pub(crate) fn as_ref(&self) -> &ChunkAddress {
        &self.inner
    }
}

pub struct TypedChunk<T> {
    inner: Chunk,
    address: TypedChunkAddress<T>,
}

impl<T> TypedChunk<T> {
    pub(crate) fn from_chunk(inner: Chunk) -> Self {
        let address = inner.address.clone();
        Self {
            inner,
            address: TypedChunkAddress::new(address),
        }
    }

    pub fn address(&self) -> &TypedChunkAddress<T> {
        &self.address
    }

    pub fn size(&self) -> usize {
        self.inner.size()
    }

    pub(crate) fn as_ref(&self) -> &Chunk {
        &self.inner
    }
}

impl<T: Into<Bytes>> TypedChunk<T> {
    pub fn from_value(value: T) -> Self {
        Self::from_chunk(Chunk::new(value.into()))
    }
}

impl<T: TryFrom<Bytes>> TypedChunk<T> {
    pub fn try_into_inner(self) -> anyhow::Result<T>
    where
        <T as TryFrom<Bytes>>::Error: Display,
    {
        T::try_from(self.inner.value).map_err(|e| anyhow!("converting from chunk failed: {}", e))
    }
}

impl<T, V> Into<Bytes> for EncryptedData<T, V> {
    fn into(self) -> Bytes {
        Bytes::from(self.inner.to_bytes())
    }
}

impl<T, V> TryFrom<Bytes> for EncryptedData<T, V> {
    type Error = anyhow::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        EncryptedData::try_from_bytes(value.as_ref())
    }
}

pub type EncryptedChunk<T, V> = TypedChunk<EncryptedData<T, V>>;
