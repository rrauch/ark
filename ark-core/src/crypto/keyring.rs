use crate::crypto::keys::{TypedPublicKey, TypedSecretKey};
use crate::crypto::Bech32Secret;
use crate::protos::{deserialize_with_header, serialize_with_header};
use bytes::Bytes;
use std::collections::HashMap;
use std::hash::Hash;
use zeroize::Zeroize;

const MAGIC_NUMBER: &'static [u8; 16] = &[
    0x61, 0x72, 0x6B, 0x5F, 0x6B, 0x65, 0x79, 0x5F, 0x72, 0x69, 0x6E, 0x67, 0x5F, 0x76, 0x30, 0x30,
];

#[derive(Debug, Clone)]
pub struct KeyRing<T> {
    key_map: HashMap<TypedPublicKey<T>, TypedSecretKey<T>>,
}

impl<T> KeyRing<T> {
    pub fn len(&self) -> usize {
        self.key_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.key_map.is_empty()
    }
}

impl<T> Zeroize for KeyRing<T> {
    fn zeroize(&mut self) {
        self.key_map.values_mut().for_each(|v| v.zeroize());
    }
}

impl<T: Hash + Eq> KeyRing<T> {
    pub fn get(&self, public_key: &TypedPublicKey<T>) -> Option<&TypedSecretKey<T>> {
        self.key_map.get(public_key)
    }
}

impl<T: Hash + Eq + Clone> FromIterator<TypedSecretKey<T>> for KeyRing<T> {
    fn from_iter<I: IntoIterator<Item = TypedSecretKey<T>>>(iter: I) -> Self {
        Self {
            key_map: iter
                .into_iter()
                .map(|s| (s.public_key().clone(), s))
                .collect(),
        }
    }
}

impl<T: Bech32Secret + Hash + Eq + Clone> KeyRing<T> {
    pub(crate) fn deserialize(data: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let proto: protos::KeyRing = deserialize_with_header(data, MAGIC_NUMBER)?;
        proto.try_into()
    }

    pub(crate) fn serialize(&self) -> Bytes {
        let proto = protos::KeyRing::from(self.clone());
        serialize_with_header(&proto, MAGIC_NUMBER)
    }
}

impl<T: Bech32Secret + Hash + Eq + Clone> TryFrom<Bytes> for KeyRing<T> {
    type Error = anyhow::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::deserialize(value)
    }
}

impl<T: Bech32Secret + Hash + Eq + Clone> From<KeyRing<T>> for Bytes {
    fn from(value: KeyRing<T>) -> Self {
        value.serialize()
    }
}

impl<T: Bech32Secret + Hash + Eq + Clone> TryFrom<&[u8]> for KeyRing<T> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize(value)
    }
}

mod protos {
    use crate::crypto::keys::TypedSecretKey;
    use crate::crypto::Bech32Secret;
    use std::hash::Hash;
    use std::str::FromStr;

    include!(concat!(env!("OUT_DIR"), "/protos/keyring.rs"));

    impl<T: Bech32Secret> From<TypedSecretKey<T>> for SecretKey {
        fn from(value: TypedSecretKey<T>) -> Self {
            Self {
                bech32: value.danger_to_string(),
            }
        }
    }

    impl<T: Bech32Secret> From<super::KeyRing<T>> for KeyRing {
        fn from(value: super::KeyRing<T>) -> Self {
            Self {
                secret_keys: value
                    .key_map
                    .into_values()
                    .into_iter()
                    .map(|k| k.into())
                    .collect(),
            }
        }
    }

    impl<T: Bech32Secret> TryFrom<SecretKey> for TypedSecretKey<T> {
        type Error = anyhow::Error;

        fn try_from(value: SecretKey) -> Result<Self, Self::Error> {
            Self::from_str(value.bech32.as_str())
        }
    }

    impl<T: Bech32Secret + Hash + Eq + Clone> TryFrom<KeyRing> for super::KeyRing<T> {
        type Error = anyhow::Error;

        fn try_from(value: KeyRing) -> Result<Self, Self::Error> {
            Ok(value
                .secret_keys
                .into_iter()
                .map(|k| k.try_into())
                .collect::<anyhow::Result<_>>()?)
        }
    }
}
