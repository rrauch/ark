use crate::VaultId;
use crate::ark::ArkCreationSettings;
use crate::crypto::{ArkAddress, Retirable};
use crate::protos::{deserialize_with_header, serialize_with_header};
use crate::vault::{VaultConfig, VaultCreationSettings};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const MAGIC_NUMBER: &'static [u8; 16] = &[
    0x61, 0x72, 0x6B, 0x5F, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x5F, 0x76, 0x30, 0x30,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Manifest {
    pub ark_address: ArkAddress,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub vaults: Vec<VaultConfig>,
}

impl Retirable for Manifest {}

impl From<VaultCreationSettings> for VaultConfig {
    fn from(value: VaultCreationSettings) -> Self {
        Self {
            id: VaultId::new(Uuid::now_v7()),
            created: Utc::now(),
            last_modified: Utc::now(),
            name: value.name,
            description: value.description,
            active: value.active,
        }
    }
}

impl Manifest {
    pub(super) fn new(address: &ArkAddress, settings: ArkCreationSettings) -> Self {
        Self {
            ark_address: address.clone(),
            created: Utc::now(),
            last_modified: Utc::now(),
            name: settings.name,
            description: settings.description,
            vaults: Default::default(),
        }
    }

    pub(super) fn deserialize(data: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let proto: protos::Manifest = deserialize_with_header(data, MAGIC_NUMBER)?;
        proto.try_into()
    }

    pub(super) fn serialize(&self) -> Bytes {
        let proto = protos::Manifest::from(self.clone());
        serialize_with_header(&proto, MAGIC_NUMBER)
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

impl TryFrom<Bytes> for Manifest {
    type Error = anyhow::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Manifest::deserialize(value)
    }
}

mod protos {
    use crate::VaultId;
    use anyhow::anyhow;

    include!(concat!(env!("OUT_DIR"), "/protos/manifest.rs"));

    impl From<super::Manifest> for Manifest {
        fn from(value: super::Manifest) -> Self {
            Self {
                name: value.name,
                address: Some(value.ark_address.into()),
                created: Some(value.created.into()),
                last_modified: Some(value.last_modified.into()),
                description: value.description,
                vaults: value.vaults.into_iter().map(|v| v.into()).collect(),
            }
        }
    }

    impl TryFrom<Manifest> for super::Manifest {
        type Error = anyhow::Error;

        fn try_from(value: Manifest) -> Result<Self, Self::Error> {
            Ok(Self {
                name: value.name,
                ark_address: value
                    .address
                    .ok_or(anyhow!("address is missing"))?
                    .try_into()?,
                created: value
                    .created
                    .ok_or(anyhow!("created is missing"))?
                    .try_into()?,
                last_modified: value
                    .last_modified
                    .ok_or(anyhow!("last_modified is missing"))?
                    .try_into()?,
                description: value.description,
                vaults: value
                    .vaults
                    .into_iter()
                    .map(|v| v.try_into())
                    .collect::<anyhow::Result<Vec<super::VaultConfig>>>()?,
            })
        }
    }

    impl From<super::VaultConfig> for Vault {
        fn from(value: super::VaultConfig) -> Self {
            Self {
                id: Some(value.id.into_inner().into()),
                created: Some(value.created.into()),
                last_modified: Some(value.last_modified.into()),
                name: value.name,
                description: value.description,
                active: value.active,
            }
        }
    }

    impl TryFrom<Vault> for super::VaultConfig {
        type Error = anyhow::Error;

        fn try_from(value: Vault) -> Result<Self, Self::Error> {
            Ok(Self {
                id: VaultId::new(value.id.ok_or(anyhow!("id is missing"))?.try_into()?),
                created: value
                    .created
                    .ok_or(anyhow!("created is missing"))?
                    .try_into()?,
                last_modified: value
                    .last_modified
                    .ok_or(anyhow!("last_modified is missing"))?
                    .try_into()?,
                name: value.name,
                description: value.description,
                active: value.active,
            })
        }
    }
}
