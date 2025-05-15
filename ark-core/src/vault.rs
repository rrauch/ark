use crate::crypto::PointerExt;
use crate::crypto::{
    AllowRandom, Bech32Public, TypedDerivationIndex, TypedOwnedPointer, TypedPointerAddress,
    TypedPublicKey, TypedSecretKey,
};
use crate::objects::ObjectType;
use crate::progress::Task;
use crate::{ArkAddress, AutonomiClient, BridgeAddress, HelmKey, Progress};
use crate::{Core, Receipt, Result, with_receipt};
use anyhow::{anyhow, bail};
use autonomi::PointerAddress;
use autonomi::pointer::PointerTarget;
use bon::Builder;
use chrono::{DateTime, Utc};

const ARK_POINTER_NAME: &str = "/ark/v0/vault/ark/pointer";

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultKind;

pub type VaultAddress = TypedPublicKey<VaultKind>;

impl Bech32Public for VaultKind {
    const HRP: &'static str = "arkvaultaddr";
}

pub(crate) type VaultKey = TypedSecretKey<VaultKind>;
impl AllowRandom for VaultKind {}

type ArkPointerDerivationIndex = TypedDerivationIndex<VaultKind>;
type ArkPointer = TypedPointerAddress<VaultKind, ArkAddress>;

impl ArkPointer {
    fn from_vault_address(vault_address: &VaultAddress) -> Self {
        Self::new(PointerAddress::new(
            vault_address
                .derive_child(&ArkPointerDerivationIndex::from_name(ARK_POINTER_NAME))
                .into(),
        ))
    }
}

type OwnedArkPointer = TypedOwnedPointer<VaultKind, ArkAddress>;

impl OwnedArkPointer {
    fn from_vault_key(vault_key: &VaultKey) -> Self {
        Self::new(vault_key.derive_child(&ArkPointerDerivationIndex::from_name(ARK_POINTER_NAME)))
    }
}

async fn create(
    settings: VaultCreationSettings,
    helm_key: &HelmKey,
    core: &Core,
    receipt: &mut Receipt,
    mut task: Task,
) -> anyhow::Result<VaultConfig> {
    let mut verify_helm = task.child(1, "Verify Helm Key".to_string());
    let mut vault_pointer = task.child(1, "Create Vault Address".to_string());
    let mut read_manifest = task.child(1, "Retrieve Current Manifest".to_string());
    let mut update_manifest = task.child(1, "Updating Manifest".to_string());
    task.start();

    verify_helm.start();
    core.verify_helm_key(helm_key).await?;
    verify_helm.complete();

    vault_pointer.start();
    core.create_pointer(
        &OwnedArkPointer::from_vault_key(&settings.vault_key),
        core.ark_address.clone(),
        true,
        receipt,
    )
    .await?;
    vault_pointer.complete();

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
    #[builder(skip = VaultKey::random())]
    pub(crate) vault_key: VaultKey,
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
    pub address: VaultAddress,
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
    pub fn ark_from_vault_address(
        client: &AutonomiClient,
        vault_address: &VaultAddress,
    ) -> (
        Progress,
        impl Future<Output = anyhow::Result<Option<ArkAddress>>> + Send,
    ) {
        let (progress, task) = Progress::new(1, "Check Vault Address".to_string());

        let fut = Self::_ark_from_vault_address(client, vault_address, task);

        (progress, fut)
    }

    async fn _ark_from_vault_address(
        client: &AutonomiClient,
        vault_address: &VaultAddress,
        mut task: Task,
    ) -> anyhow::Result<Option<ArkAddress>> {
        task.start();
        let ark_pointer = ArkPointer::from_vault_address(vault_address);
        if !client.pointer_check_existance(ark_pointer.as_ref()).await? {
            return Ok(None);
        }

        let pointer = client.pointer_get(ark_pointer.as_ref()).await?;
        if !pointer.is_final() {
            bail!("pointer needs to be final to be trusted");
        }

        let ark_address = match pointer.target() {
            PointerTarget::PointerAddress(addr) => ArkAddress::from(addr.owner().clone()),
            _ => bail!("expected address pointer"),
        };

        //todo: additional checks might be a good idea here
        task.complete();
        Ok(Some(ark_address))
    }

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
        vault_address: &VaultAddress,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Activate Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_address,
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
        vault_address: &VaultAddress,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Deactivate Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_address,
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
        vault_address: &VaultAddress,
        bridge: Option<BridgeAddress>,
        helm_key: &HelmKey,
    ) -> (Progress, impl Future<Output = Result<()>> + Send) {
        let (progress, task) = Progress::new(1, "Updating Vault".to_string());

        let fut = with_receipt(async move |receipt| {
            self._modify_vault(
                vault_address,
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
        vault_address: &VaultAddress,
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
            .vault_mut(vault_address)
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
