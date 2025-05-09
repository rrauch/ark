use crate::crypto::EncryptionScheme;
use crate::crypto::encrypt::PublicKeys;
use age::{DecryptError, EncryptError, Identity, Recipient};
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use blsttc::{Ciphertext, PublicKey, SecretKey};
use bytes::Bytes;
use std::collections::HashSet;
use std::io::Write;
use std::marker::PhantomData;
use thiserror::Error;

const TAG: &str = "blsttc";

struct MyPublicKey<'a>(&'a PublicKey);
struct MySecretKey<'a>(&'a SecretKey);

impl Recipient for MyPublicKey<'_> {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let ciphertext = self.0.encrypt(file_key.expose_secret().as_slice());

        Ok((
            vec![Stanza {
                tag: TAG.to_string(),
                args: vec![self.0.to_hex()],
                body: ciphertext.to_bytes(),
            }],
            HashSet::default(),
        ))
    }
}

impl Identity for MySecretKey<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag.as_str() != TAG {
            return None;
        }
        let mut correct_key = false;
        for candidate in &stanza.args {
            let pk = match PublicKey::from_hex(candidate) {
                Ok(pk) => pk,
                Err(_) => {
                    continue;
                }
            };
            if &self.0.public_key() == &pk {
                correct_key = true;
                break;
            }
        }
        if !correct_key {
            return Some(Err(DecryptError::NoMatchingKeys));
        }
        let ciphertext = match Ciphertext::from_bytes(stanza.body.as_slice()) {
            Ok(c) => c,
            Err(_) => return Some(Err(DecryptError::UnknownFormat)),
        };

        let plaintext = match self.0.decrypt(&ciphertext) {
            Some(plaintext) => plaintext,
            None => {
                return Some(Err(DecryptError::DecryptionFailed));
            }
        };

        if plaintext.len() != FILE_KEY_BYTES {
            return Some(Err(DecryptError::UnknownFormat));
        }

        Some(Ok(FileKey::new(
            plaintext
                .try_into()
                .map(Box::new)
                .expect("conversion into array should never fail"),
        )))
    }
}

pub struct AgeEncryptionScheme<T>(PhantomData<T>);
pub type AgeSingleKeyEncryptionScheme = AgeEncryptionScheme<PublicKey>;

#[derive(Error, Debug)]
pub enum AgeError {
    #[error(transparent)]
    EncryptionError(#[from] EncryptError),
    #[error(transparent)]
    DecryptionError(#[from] DecryptError),
}

impl<T: PublicKeys> EncryptionScheme for AgeEncryptionScheme<T> {
    type Encryptor = T;
    type Decryptor = SecretKey;
    type EncryptedData = Bytes;
    type Error = AgeError;

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self::EncryptedData, Self::Error> {
        Ok(Bytes::copy_from_slice(bytes.as_ref()))
    }

    fn to_bytes(encrypted_data: Self::EncryptedData) -> Bytes {
        encrypted_data
    }

    fn decrypt(
        ciphertext: &Self::EncryptedData,
        secret_key: &Self::Decryptor,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(age::decrypt(&MySecretKey(secret_key), ciphertext.as_ref())?)
    }

    fn encrypt(
        plaintext: impl AsRef<[u8]>,
        public_keys: &Self::Encryptor,
    ) -> Result<Self::EncryptedData, Self::Error> {
        let public_keys = public_keys
            .iter()
            .map(|k| MyPublicKey(k))
            .collect::<Vec<_>>();
        let encryptor = age::Encryptor::with_recipients(public_keys.iter().map(|k| k as _))?;
        let plaintext = plaintext.as_ref();
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .expect("writing to buffer should succeed");
        writer
            .write_all(plaintext)
            .expect("writing to buffer should succeed");
        writer.finish().expect("writing to buffer should succeed");
        Ok(Bytes::from(ciphertext))
    }
}
