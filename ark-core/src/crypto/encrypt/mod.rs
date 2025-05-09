mod age;

use crate::crypto::Retirable;
use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use anyhow::anyhow;
use blsttc::{Ciphertext, PublicKey, SecretKey};
use bytes::{Bytes, BytesMut};
use std::fmt::Display;
use std::iter;
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::Zeroize;

pub(super) use age::{AgeEncryptionScheme, AgeSingleKeyEncryptionScheme};

pub struct EncryptedData<T, V, S: EncryptionScheme = DefaultEncryptionScheme> {
    inner: S::EncryptedData,
    _type: PhantomData<T>,
    _value_type: PhantomData<V>,
}

impl<T, V: Retirable, S: EncryptionScheme> Retirable for EncryptedData<T, V, S> {}

pub trait EncryptionScheme {
    type Encryptor;
    type Decryptor;
    type EncryptedData;
    type Error: std::error::Error + Send + Sync + 'static;

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self::EncryptedData, Self::Error>;
    fn to_bytes(encrypted_data: Self::EncryptedData) -> Bytes;

    fn decrypt(
        ciphertext: &Self::EncryptedData,
        decryptor: &Self::Decryptor,
    ) -> Result<Vec<u8>, Self::Error>;
    fn encrypt(
        plaintext: impl AsRef<[u8]>,
        encryptor: &Self::Encryptor,
    ) -> Result<Self::EncryptedData, Self::Error>;
}

pub struct DefaultEncryptionScheme;

#[derive(Error, Debug)]
pub enum DefaultEncryptionSchemeError {
    #[error("unable to decrypt ciphertext")]
    DecryptionFailed,
    #[error("ciphertext verification failed, not a valid ciphertext")]
    CiphertextVerificationFailed,
}

impl EncryptionScheme for DefaultEncryptionScheme {
    type Encryptor = PublicKey;
    type Decryptor = SecretKey;
    type EncryptedData = Ciphertext;
    type Error = DefaultEncryptionSchemeError;

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self::EncryptedData, Self::Error> {
        let ciphertext = Ciphertext::from_bytes(bytes.as_ref())
            .map_err(|_| Self::Error::CiphertextVerificationFailed)?;
        if !ciphertext.verify() {
            return Err(Self::Error::CiphertextVerificationFailed);
        }
        Ok(ciphertext)
    }

    fn to_bytes(encrypted_data: Self::EncryptedData) -> Bytes {
        Bytes::from(encrypted_data.to_bytes())
    }

    fn decrypt(
        ciphertext: &Self::EncryptedData,
        secret_key: &Self::Decryptor,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(secret_key
            .decrypt(ciphertext)
            .ok_or(Self::Error::DecryptionFailed)?)
    }

    fn encrypt(
        plaintext: impl AsRef<[u8]>,
        public_key: &Self::Encryptor,
    ) -> Result<Self::EncryptedData, Self::Error> {
        Ok(public_key.encrypt(plaintext))
    }
}

impl<T, V, S: EncryptionScheme> EncryptedData<T, V, S> {
    fn from_ciphertext(inner: S::EncryptedData) -> Self {
        Self {
            inner,
            _type: Default::default(),
            _value_type: Default::default(),
        }
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, S::Error> {
        Ok(Self::from_ciphertext(S::try_from_bytes(bytes)?))
    }
}

impl<T, V, S: EncryptionScheme> Into<Bytes> for EncryptedData<T, V, S> {
    fn into(self) -> Bytes {
        S::to_bytes(self.inner)
    }
}

impl<T, V, S: EncryptionScheme> TryFrom<Bytes> for EncryptedData<T, V, S> {
    type Error = S::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        EncryptedData::try_from_bytes(value.as_ref())
    }
}

pub(super) trait TypedDecryptor<T> {
    type Decryptor;

    fn decryptor(&self) -> &Self::Decryptor;

    fn decrypt<V: for<'a> TryFrom<&'a [u8]>, S: EncryptionScheme<Decryptor = Self::Decryptor>>(
        &self,
        input: &EncryptedData<T, V, S>,
    ) -> anyhow::Result<V>
    where
        for<'a> <V as TryFrom<&'a [u8]>>::Error: Display,
    {
        let mut plaintext = S::decrypt(&input.inner, self.decryptor())?;
        let res = plaintext
            .as_slice()
            .try_into()
            .map_err(|e| anyhow!("error converting plaintext: {}", e));
        plaintext.zeroize();
        res
    }
}

impl<T> TypedDecryptor<T> for TypedSecretKey<T> {
    type Decryptor = SecretKey;
    fn decryptor(&self) -> &Self::Decryptor {
        &self.inner
    }
}

pub(super) trait TypedEncryptor<T> {
    type Encryptor;

    fn encryptor(&self) -> &Self::Encryptor;

    fn encrypt<V: Into<Bytes>, S: EncryptionScheme<Encryptor = Self::Encryptor>>(
        &self,
        input: V,
    ) -> anyhow::Result<EncryptedData<T, V, S>> {
        let plaintext = input.into();
        let encrypted =
            EncryptedData::from_ciphertext(S::encrypt(plaintext.as_ref(), self.encryptor())?);
        if plaintext.is_unique() {
            BytesMut::from(plaintext).zeroize();
        }
        Ok(encrypted)
    }
}
impl<T> TypedEncryptor<T> for TypedPublicKey<T> {
    type Encryptor = PublicKey;
    fn encryptor(&self) -> &Self::Encryptor {
        &self.inner
    }
}

pub(super) trait TypedPublicKeys<T>: PublicKeys {}

impl<T, E: TypedPublicKeys<T>> TypedEncryptor<T> for E {
    type Encryptor = E;

    fn encryptor(&self) -> &Self::Encryptor {
        self
    }
}

pub(super) trait PublicKeys {
    fn iter(&self) -> impl Iterator<Item = &PublicKey>;
}

impl PublicKeys for Vec<PublicKey> {
    fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.as_slice().iter()
    }
}

impl PublicKeys for PublicKey {
    fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        iter::once(self)
    }
}
