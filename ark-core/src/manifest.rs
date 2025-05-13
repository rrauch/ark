use crate::ark::ArkCreationSettings;
use crate::crypto::{
    AgeEncryptionScheme, EncryptedData, Retirable, ScratchpadContent, TypedOwnedScratchpad,
    TypedScratchpadAddress,
};
use std::collections::BTreeSet;

use crate::crypto::TypedEncryptor;
use crate::helm_key::HelmKeyKind;
use crate::protos::{deserialize_with_header, serialize_with_header};
use crate::vault::{VaultConfig, VaultCreationSettings};
use crate::{
    ArkAccessor, ArkAddress, ArkSeed, Core, DataKey, HelmKey, PublicHelmKey, PublicWorkerKey,
    Receipt, RetiredWorkerKey, SealKey, VaultId, WorkerKey, decryptor, encryptor,
    impl_decryptor_for,
};
use anyhow::bail;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use uuid::Uuid;

const MAGIC_NUMBER: &'static [u8; 16] = &[
    0x61, 0x72, 0x6B, 0x5F, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x5F, 0x76, 0x30, 0x30,
];

const MANIFEST_SCRATCHPAD_ENCODING: u64 = 344850175421548714;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Manifest {
    pub ark_address: ArkAddress,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub authorized_worker: PublicWorkerKey,
    pub retired_workers: BTreeSet<RetiredWorkerKey>,
    pub vaults: Vec<VaultConfig>,
}

impl Manifest {
    pub fn vault(&self, vault_id: VaultId) -> Option<&VaultConfig> {
        self.vaults.iter().find(|v| v.id == vault_id)
    }

    pub fn vault_mut(&mut self, vault_id: VaultId) -> Option<&mut VaultConfig> {
        self.vaults.iter_mut().find(|v| v.id == vault_id)
    }
}

impl Retirable for Manifest {}

impl ScratchpadContent for Manifest {
    const ENCODING: u64 = MANIFEST_SCRATCHPAD_ENCODING;
}

pub(crate) type EncryptedManifest =
    EncryptedData<Manifest, Manifest, AgeEncryptionScheme<ManifestEncryptor>>;

encryptor!(
    pub(crate) Manifest,
    ark_address: ArkAddress,
    public_helm_key: PublicHelmKey,
    public_worker_key: PublicWorkerKey,
    seal_key: SealKey,
);

decryptor!(pub(crate) Manifest);

impl_decryptor_for!(ArkSeed, Manifest);
impl_decryptor_for!(HelmKey, Manifest);
impl_decryptor_for!(WorkerKey, Manifest);
impl_decryptor_for!(DataKey, Manifest);

impl crate::crypto::TypedDecryptor<Manifest> for ArkAccessor {
    type Decryptor = autonomi::SecretKey;

    fn decryptor(&self) -> &Self::Decryptor {
        self.secret_key()
    }
}

pub type OwnedManifest = TypedOwnedScratchpad<HelmKeyKind, EncryptedManifest>;
pub type ManifestAddress = TypedScratchpadAddress<HelmKeyKind, EncryptedManifest>;

impl From<VaultCreationSettings> for VaultConfig {
    fn from(value: VaultCreationSettings) -> Self {
        Self {
            id: VaultId::new(Uuid::now_v7()),
            created: Utc::now(),
            last_modified: Utc::now(),
            name: value.name,
            description: value.description,
            active: value.active,
            bridge: value.bridge,
            object_type: value.object_type,
        }
    }
}

impl Manifest {
    pub(super) fn new(
        address: &ArkAddress,
        settings: ArkCreationSettings,
        authorized_worker: PublicWorkerKey,
    ) -> Self {
        Self {
            ark_address: address.clone(),
            created: Utc::now(),
            last_modified: Utc::now(),
            name: settings.name,
            description: settings.description,
            vaults: Default::default(),
            authorized_worker,
            retired_workers: Default::default(),
        }
    }

    pub(crate) fn update_worker(&mut self, new_worker: &PublicWorkerKey) {
        let previous = std::mem::replace(&mut self.authorized_worker, new_worker.clone());
        if &previous == new_worker {
            return;
        }
        let retired = RetiredWorkerKey::new(previous, Utc::now());
        self.retired_workers.insert(retired);
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

impl Core {
    pub(crate) async fn create_manifest(
        &self,
        manifest: &Manifest,
        helm_key: &HelmKey,
        manifest_encryptor: &ManifestEncryptor,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        self.create_encrypted_scratchpad(
            manifest_encryptor.encrypt_manifest(&manifest)?,
            &helm_key.manifest(),
            receipt,
        )
        .await
    }

    pub(super) async fn get_manifest<D: ManifestDecryptor>(
        &self,
        decryptor: &D,
    ) -> anyhow::Result<Manifest> {
        let public_helm_key = self.public_helm_key().await?;
        self.get_specific_manifest(decryptor, &public_helm_key)
            .await
    }

    pub(super) async fn get_specific_manifest<D: ManifestDecryptor>(
        &self,
        decryptor: &D,
        public_helm_key: &PublicHelmKey,
    ) -> anyhow::Result<Manifest> {
        let encrypted_manifest = self.read_scratchpad(&public_helm_key.manifest()).await?;
        decryptor.decrypt_manifest(&encrypted_manifest)
    }

    pub(super) async fn manifest_encryptor<D: ManifestDecryptor>(
        &self,
        decryptor: &D,
    ) -> anyhow::Result<ManifestEncryptor> {
        Ok(ManifestEncryptor::new(
            self.ark_address.clone(),
            self.public_helm_key().await?,
            self.public_worker_key(decryptor).await?,
            self.seal_key().await?,
        ))
    }

    pub(super) async fn update_manifest(
        &self,
        manifest: &Manifest,
        helm_key: &HelmKey,
        receipt: &mut Receipt,
    ) -> anyhow::Result<u64> {
        if &manifest.ark_address != &self.ark_address {
            bail!("manifest ark address does not match given ark address");
        }
        self.verify_helm_key(helm_key).await?;
        self.update_scratchpad(
            self.manifest_encryptor(helm_key)
                .await?
                .encrypt_manifest(&manifest)?,
            &helm_key.manifest(),
            receipt,
        )
        .await
    }

    pub(super) async fn retire_manifest(
        &self,
        helm_key: &HelmKey,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        if &self.public_helm_key().await? == helm_key.public_key() {
            bail!(
                "helm_key is still active for ark [{}], cannot retire manifest",
                self.ark_address
            )
        };
        self.danger_retire_scratchpad(&helm_key.manifest(), receipt)
            .await?;
        Ok(())
    }
}

mod protos {
    use crate::VaultId;
    use anyhow::anyhow;
    use std::collections::BTreeSet;

    include!(concat!(env!("OUT_DIR"), "/protos/manifest.rs"));

    impl From<super::Manifest> for Manifest {
        fn from(value: super::Manifest) -> Self {
            Self {
                name: value.name,
                address: Some(value.ark_address.into()),
                created: Some(value.created.into()),
                last_modified: Some(value.last_modified.into()),
                description: value.description,
                authorized_worker: Some(value.authorized_worker.into()),
                retired_workers: value
                    .retired_workers
                    .into_iter()
                    .map(|w| w.into())
                    .collect::<Vec<_>>(),
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
                authorized_worker: value
                    .authorized_worker
                    .ok_or(anyhow!("authorized_worker is missing"))?
                    .try_into()?,
                retired_workers: value
                    .retired_workers
                    .into_iter()
                    .map(|r| r.try_into())
                    .collect::<anyhow::Result<BTreeSet<super::RetiredWorkerKey>>>()?,
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
                bridge: value.bridge.map(|b| b.into()),
                object_type: Some(value.object_type.into()),
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
                bridge: value.bridge.map(|a| a.try_into()).transpose()?,
                object_type: value
                    .object_type
                    .ok_or(anyhow!("object_type is missing"))?
                    .try_into()?,
            })
        }
    }
}
