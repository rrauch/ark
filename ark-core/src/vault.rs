use crate::crypto::BridgeAddress;
use crate::HelmKey;
use crate::objects::ObjectType;
use crate::{Core, Receipt, TypedUuid, with_receipt};
use bon::Builder;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultKind;

pub type VaultId = TypedUuid<VaultKind>;

async fn create(
    settings: VaultCreationSettings,
    helm_key: &HelmKey,
    core: &Core,
    receipt: &mut Receipt,
) -> anyhow::Result<VaultId> {
    core.verify_helm_key(helm_key).await?;
    let worker_key = core.worker_key(helm_key).await?;
    let mut manifest = core.get_manifest(&worker_key).await?;
    let vault_config = VaultConfig::from(settings);
    let id = vault_config.id;
    manifest.vaults.push(vault_config.clone());
    manifest.last_modified = Utc::now();
    core.update_manifest(&manifest, helm_key, receipt).await?;
    Ok(id)
}

#[derive(Builder, Clone, Debug)]
pub struct VaultCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    #[builder(default = true)]
    pub(crate) active: bool,
    pub(crate) object_type: ObjectType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultConfig {
    pub id: VaultId,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
    pub bridge: Option<BridgeAddress>,
    pub object_type: ObjectType,
}

impl Core {
    pub async fn create_vault(
        &self,
        settings: VaultCreationSettings,
        helm_key: &HelmKey,
    ) -> crate::Result<VaultId> {
        with_receipt(async move |receipt| create(settings, helm_key, &self, receipt).await).await
    }
}
