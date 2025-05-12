use crate::crypto::{Bech32Public, Bech32Secret};
use anyhow::bail;
use autonomi::client::key_derivation::DerivationIndex;
use bech32::{Bech32m, EncodeError, Hrp};
use blsttc::{PublicKey, SecretKey};
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
