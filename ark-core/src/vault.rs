use crate::objects::ObjectType;
use crate::progress::Task;
use crate::{BridgeAddress, HelmKey, Progress, PublicWorkerKey};
use crate::{Core, Receipt, Result, TypedUuid, with_receipt};
use anyhow::anyhow;
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
    mut task: Task,
) -> anyhow::Result<VaultConfig> {
    let mut verify_helm = task.child(1, "Verify Helm Key".to_string());
    let mut read_manifest = task.child(1, "Retrieve Current Manifest".to_string());
    let mut update_manifest = task.child(1, "Updating Manifest".to_string());
    task.start();

    verify_helm.start();
    core.verify_helm_key(helm_key).await?;
    verify_helm.complete();
    read_manifest.start();
    let mut manifest = core.get_manifest(helm_key).await?;
    read_manifest.complete();
    let vault_config = VaultConfig::from(settings);
    manifest.vaults.push(vault_config.clone());
    manifest.last_modified = Utc::now();
    update_manifest.start();
    core.update_manifest(&manifest, helm_key, receipt).await?;
    update_manifest.complete();
    task.complete();
    Ok(vault_config)
}

#[derive(Builder, Clone, Debug)]
pub struct VaultCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) bridge: Option<BridgeAddress>,
    #[builder(default = true)]
    pub(crate) active: bool,
    pub(crate) object_type: ObjectType,
}

impl VaultCreationSettings {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(|s| s.as_str())
    }

    pub fn authorized_bridge(&self) -> Option<&BridgeAddress> {
        self.bridge.as_ref()
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub fn object_type(&self) -> &ObjectType {
        &self.object_type
    }
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

impl VaultConfig {
    fn apply(&mut self, req: &ModificationRequest) {
        if let Some(name) = &req.name {
            self.name = name.clone();
        }
        if let Some(description) = &req.description {
            self.description = description.clone();
        }
        if let Some(active) = req.active {
            self.active = active;
        }
        if let Some(bridge) = &req.bridge {
            self.bridge = bridge.clone();
        }
    }
}

impl Core {
    pub fn create_vault(
        &self,
        settings: VaultCreationSettings,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<VaultConfig>> + Send) {
        let (progress, task) = Progress::new(1, "Vault Creation".to_string());

        let fut = with_receipt(async move |receipt| {
            create(settings, helm_key, &self, receipt, task).await
        });

        (progress, fut)
    }

    pub async fn activate_vault(
        &self,
        vault_id: VaultId,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Activate Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_id,
                helm_key,
                &ModificationRequest::builder().active(true).build(),
                receipt,
                task,
            )
            .await
        });

        (progress, fut)
    }

    pub async fn deactivate_vault(
        &self,
        vault_id: VaultId,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Deactivate Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_id,
                helm_key,
                &ModificationRequest::builder().active(false).build(),
                receipt,
                task,
            )
            .await
        });

        (progress, fut)
    }

    pub async fn update_vault_bridge(
        &self,
        vault_id: VaultId,
        bridge: Option<BridgeAddress>,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Updating Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_id,
                helm_key,
                &ModificationRequest::builder().bridge(bridge).build(),
                receipt,
                task,
            )
            .await
        });

        (progress, fut)
    }

    async fn _modify_vault(
        &self,
        vault_id: VaultId,
        helm_key: &HelmKey,
        modification_request: &ModificationRequest,
        receipt: &mut Receipt,
        mut task: Task,
    ) -> anyhow::Result<()> {
        if modification_request.is_empty() {
            //nothing to do
            return Ok(());
        }
        let mut read_manifest = task.child(1, "Retrieve Current Manifest".to_string());
        let mut update_manifest = task.child(1, "Updating Manifest".to_string());
        task.start();
        read_manifest.start();
        let mut manifest = self.get_manifest(helm_key).await?;
        read_manifest.complete();
        let mut vault_config = manifest
            .vault_mut(vault_id)
            .ok_or(anyhow!("vault not found"))?;
        vault_config.apply(modification_request);

        update_manifest.start();
        self.update_manifest(&manifest, helm_key, receipt).await?;
        update_manifest.complete();
        task.complete();
        Ok(())
    }
}

#[derive(Builder)]
struct ModificationRequest {
    active: Option<bool>,
    bridge: Option<Option<BridgeAddress>>,
    name: Option<String>,
    description: Option<Option<String>>,
}

impl ModificationRequest {
    fn is_empty(&self) -> bool {
        self.active.is_none()
            && self.bridge.is_none()
            && self.name.is_none()
            && self.description.is_none()
    }
}
