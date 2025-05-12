use crate::crypto::{AllowRandom, Bech32Public, Bech32Secret};
use anyhow::bail;
use autonomi::client::key_derivation::DerivationIndex;
use bech32::{Bech32m, EncodeError, Hrp};
use blsttc::{PublicKey, SecretKey};
use chrono::{DateTime, Utc};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use zeroize::Zeroize;

#[derive(Zeroize, Debug, Clone, PartialEq, Eq)]
pub struct TypedSecretKey<T> {
    pub(super) inner: SecretKey,
    #[zeroize(skip)]
    public_key: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    pub(crate) fn new(inner: SecretKey) -> Self {
        let public_key = TypedPublicKey::from(inner.public_key());
        Self { inner, public_key }
    }

    pub fn public_key(&self) -> &TypedPublicKey<T> {
        &self.public_key
    }

    pub(crate) fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedSecretKey<C> {
        TypedSecretKey::new(self.inner.derive_child(idx.inner.as_bytes()))
    }

    pub(crate) fn as_ref(&self) -> &SecretKey {
        &self.inner
    }
}

impl<T: AllowRandom> TypedSecretKey<T> {
    pub fn random() -> Self {
        Self::new(SecretKey::random())
    }
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
    pub(super) inner: PublicKey,
    _type: PhantomData<T>,
}

impl<T> TypedPublicKey<T> {
    pub(crate) fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedPublicKey<C> {
        TypedPublicKey::from(self.inner.derive_child(idx.inner.as_bytes()))
    }

    pub(crate) fn as_ref(&self) -> &PublicKey {
        &self.inner
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

#[derive(Debug, Clone, Hash)]
pub struct RetiredKey<T> {
    inner: TypedPublicKey<T>,
    retired_at: DateTime<Utc>,
}

impl<T> RetiredKey<T> {
    pub fn new(inner: TypedPublicKey<T>, retired_at: DateTime<Utc>) -> Self {
        (inner, retired_at).into()
    }

    pub fn retired_at(&self) -> &DateTime<Utc> {
        &self.retired_at
    }

    pub fn into_inner(self) -> TypedPublicKey<T> {
        self.inner
    }
}

impl<T: Eq> Eq for RetiredKey<T> {}

impl<T: PartialEq> PartialEq<Self> for RetiredKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner) && self.retired_at.eq(&other.retired_at)
    }
}

impl<T: PartialEq> PartialOrd<Self> for RetiredKey<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.retired_at.partial_cmp(&other.retired_at)
    }
}

impl<T: Eq> Ord for RetiredKey<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.retired_at.cmp(&other.retired_at)
    }
}

impl<T> AsRef<TypedPublicKey<T>> for RetiredKey<T> {
    fn as_ref(&self) -> &TypedPublicKey<T> {
        &self.inner
    }
}

impl<T> From<(TypedPublicKey<T>, DateTime<Utc>)> for RetiredKey<T> {
    fn from(value: (TypedPublicKey<T>, DateTime<Utc>)) -> Self {
        Self {
            inner: value.0,
            retired_at: value.1,
        }
    }
}

#[derive(Clone, Debug)]
pub enum EitherKey<T> {
    Secret(TypedSecretKey<T>),
    Public(TypedPublicKey<T>),
}

impl<T> EitherKey<T> {
    pub fn public_key(&self) -> &TypedPublicKey<T> {
        match self {
            Self::Secret(sk) => sk.public_key(),
            Self::Public(pk) => pk,
        }
    }
}

impl<T> From<TypedPublicKey<T>> for EitherKey<T> {
    fn from(value: TypedPublicKey<T>) -> Self {
        Self::Public(value)
    }
}

impl<T> From<TypedSecretKey<T>> for EitherKey<T> {
    fn from(value: TypedSecretKey<T>) -> Self {
        Self::Secret(value)
    }
}

impl<T> Zeroize for EitherKey<T> {
    fn zeroize(&mut self) {
        match self {
            Self::Secret(sk) => sk.zeroize(),
            Self::Public(_) => {}
        }
    }
}

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
