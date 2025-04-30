use crate::crypto::HelmKey;
use crate::{Core, Receipt};
use bon::Builder;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub type VaultId = Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vault {
    pub id: VaultId,
    pub name: String,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub active: bool,
}

impl Vault {
    pub(crate) async fn create(
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

    pub(crate) fn from_config(config: VaultConfig) -> Self {
        Self {
            id: config.id,
            name: config.name,
            description: config.description,
            created: config.created,
            last_modified: config.last_modified,
            active: config.active,
        }
    }

    pub(crate) fn differs(&self, config: &VaultConfig) -> bool {
        if self.name != config.name
            || self.description != config.description
            || self.created != config.created
            || self.last_modified != config.last_modified
            || self.active != config.active
        {
            true
        } else {
            false
        }
    }

    pub(crate) fn apply(&mut self, config: VaultConfig) {
        self.name = config.name;
        self.description = config.description;
        self.created = config.created;
        self.last_modified = config.last_modified;
        self.active = config.active;
    }
}

#[derive(Builder, Clone, Debug)]
pub struct VaultCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    #[builder(default = true)]
    pub(crate) active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultConfig {
    pub id: Uuid,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
}
