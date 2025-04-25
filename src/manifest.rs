use crate::crypto::ArkAddress;
use crate::ArkCreationSettings;
use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};
use prost::Message;

const MAGIC_NUMBER: &'static [u8; 16] = &[
    0x61, 0x72, 0x6B, 0x5F, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x5F, 0x76, 0x30, 0x30,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Manifest {
    pub address: ArkAddress,
    pub created: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
}

impl Manifest {
    pub(super) fn new(address: &ArkAddress, settings: &ArkCreationSettings) -> Self {
        Self {
            address: address.clone(),
            created: Utc::now(),
            name: settings.name.clone(),
            description: settings.description.clone(),
        }
    }

    pub(super) fn deserialize(data: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let mut buf = data.as_ref();
        let mut header = [0u8; MAGIC_NUMBER.len()];
        buf.copy_to_slice(&mut header);
        if header.as_ref() != MAGIC_NUMBER {
            bail!("invalid manifest, header mismatch");
        }
        let proto = protos::Manifest::decode(data.as_ref())?;
        proto.try_into()
    }

    pub(super) fn serialize(&self) -> Bytes {
        let proto = protos::Manifest::from(self.clone());
        let len = MAGIC_NUMBER.len() + proto.encoded_len();
        let mut buf = BytesMut::with_capacity(len);
        buf.put(MAGIC_NUMBER.as_slice());
        proto
            .encode(&mut buf)
            .expect("writing to buffer should never fail");
        buf.freeze()
    }
}

impl From<Manifest> for Bytes {
    fn from(value: Manifest) -> Self {
        value.serialize()
    }
}

impl TryFrom<&[u8]> for Manifest {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Manifest::deserialize(value)
    }
}

mod protos {
    use anyhow::anyhow;

    include!(concat!(env!("OUT_DIR"), "/protos/manifest.rs"));

    impl From<super::Manifest> for Manifest {
        fn from(value: super::Manifest) -> Self {
            Manifest {
                name: value.name,
                address: Some(value.address.into()),
                created: Some(value.created.into()),
                description: value.description,
            }
        }
    }

    impl TryFrom<Manifest> for super::Manifest {
        type Error = anyhow::Error;

        fn try_from(value: Manifest) -> Result<Self, Self::Error> {
            Ok(super::Manifest {
                name: value.name,
                address: value
                    .address
                    .ok_or(anyhow!("address is missing"))?
                    .try_into()?,
                created: value
                    .created
                    .ok_or(anyhow!("created is missing"))?
                    .try_into()?,
                description: value.description,
            })
        }
    }
}
