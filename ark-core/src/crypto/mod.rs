mod chunk;
mod encrypt;
mod keyring;
mod keys;
mod pointer;
mod register;
mod scratchpad;

pub(crate) use crate::crypto::encrypt::{
    EncryptedData, EncryptionScheme, TypedDecryptor, TypedEncryptor,
};
pub(crate) use crate::crypto::keyring::KeyRing;
use anyhow::anyhow;
use sn_bls_ckd::derive_master_sk;
use sn_curv::elliptic::curves::ECScalar;

pub(crate) use crate::crypto::encrypt::{
    AgeEncryptionScheme, AgeSingleKeyEncryptionScheme, DefaultEncryptionScheme, PublicKeys,
    TypedPublicKeys,
};
pub(crate) use chunk::{TypedChunk, TypedChunkAddress};
pub(crate) use keys::{
    AllowDerivation, Derived, DerivedPublicKey, DerivedSecretKey, EitherKey, RetiredKey,
    TypedDerivationIndex, TypedPublicKey, TypedSecretKey,
};
pub(crate) use pointer::{TypedOwnedPointer, TypedPointerAddress};
pub(crate) use register::{TypedOwnedRegister, TypedRegister, TypedRegisterAddress};
pub(crate) use scratchpad::{
    Content as ScratchpadContent, TypedOwnedScratchpad, TypedScratchpadAddress,
};

#[macro_export]
macro_rules! impl_decryptor_for {
    ($key_type:ty, $data_type:ty) => {
        impl crate::crypto::TypedDecryptor<$data_type> for $key_type {
            type Decryptor = autonomi::SecretKey;

            fn decryptor(&self) -> &Self::Decryptor {
                self.as_ref()
            }
        }
    };

    // Overload to implement for multiple data types at once
    ($key_type:ty, $($data_type:ty),+) => {
        $(
            impl_decryptor_for!($key_type, $data_type);
        )+
    }
}

#[macro_export]
macro_rules! encryptor {
    ($vis:vis $topic:ident, $($key_name:ident: $key_type:ty),+ $(,)?) => {
        paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq)]
            $vis struct [<$topic Encryptor>] {
                $(pub $key_name: $key_type,)+
            }

            impl [<$topic Encryptor>] {
                pub fn new(
                    $($key_name: $key_type,)+
                ) -> Self {
                    Self {
                        $($key_name,)+
                    }
                }

                pub fn [<encrypt_ $topic:lower>](&self, [<$topic:lower>]: &$topic) -> anyhow::Result<[<Encrypted $topic>]> {
                    self.encrypt([<$topic:lower>].clone())
                }
            }

            impl crate::crypto::PublicKeys for [<$topic Encryptor>] {
                fn iter(&self) -> impl Iterator<Item = &autonomi::PublicKey> {
                    let keys: Vec<&autonomi::PublicKey> = vec![
                        $(self.$key_name.as_ref(),)+
                    ];

                    keys.into_iter()
                }
            }

            impl crate::crypto::TypedPublicKeys<$topic> for [<$topic Encryptor>] {}
        }
    };
}

#[macro_export]
macro_rules! decryptor {
    ($vis:vis $topic:ident) => {
        paste::paste! {
            $vis trait [<$topic Decryptor>] {
                fn [<decrypt_ $topic:lower>](&self, [<encrypted_ $topic:lower>]: &[<Encrypted $topic>]) -> anyhow::Result<$topic>;
            }

            impl<T: crate::crypto::TypedDecryptor<$topic, Decryptor = autonomi::SecretKey>> [<$topic Decryptor>] for T {
                fn [<decrypt_ $topic:lower>](&self, [<encrypted_ $topic:lower>]: &[<Encrypted $topic>]) -> anyhow::Result<$topic> {
                    self.decrypt([<encrypted_ $topic:lower>])
                }
            }
        }
    };
}

pub trait Bech32Secret {
    const HRP: &'static str;
}

pub trait Bech32Public {
    const HRP: &'static str;
}

pub trait Retirable {}
pub trait AllowRandom {}
pub trait Finalizeable {}

pub(crate) fn eip2333(seed: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
    // Derive BLS12-381 master secret key from seed using EIP-2333 standard.
    // Guarantees a valid, non-zero scalar represented as 32 Big-Endian bytes.
    let key_bytes: [u8; 32] = derive_master_sk(seed.as_ref())
        .map_err(|e| anyhow!("derive_master_sk error: {}", e))?
        .serialize() // Get the 32-byte Big-Endian representation
        .into(); // Convert GenericArray<u8, 32> to [u8; 32]
    Ok(key_bytes)
}
