use crate::ark_seed::ArkRoot;
use crate::crypto::{
    AllowDerivation, Bech32Secret, Derived, TypedDerivationIndex, TypedOwnedRegister,
    TypedPublicKey, TypedRegister, TypedRegisterAddress, TypedSecretKey,
};
use crate::manifest::{EncryptedManifest, ManifestAddress, OwnedManifest};
use crate::progress::Task;
use crate::{ArkAddress, ArkSeed, Core, Progress, Receipt, with_receipt};
use anyhow::{anyhow, bail};
use autonomi::register::RegisterAddress;
use once_cell::sync::Lazy;
use std::ops::Deref;

const HELM_REGISTER_NAME: &str = "/ark/v0/helm/register";
static HELM_REGISTER_DERIVATOR: Lazy<HelmRegisterDerivator> =
    Lazy::new(|| HelmRegisterDerivator::from_name(HELM_REGISTER_NAME));

type HelmRegisterDerivator = TypedDerivationIndex<HelmRegisterKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmRegisterKind;

pub type HelmRegister = TypedRegister<HelmRegisterOwner, HelmKeySeed>;

pub type HelmRegisterOwner = Derived<HelmRegisterKind, ArkRoot>;

impl AllowDerivation<ArkRoot, HelmRegisterKind> for ArkRoot {
    type Derivator = HelmRegisterDerivator;
}

pub type OwnedHelmRegister = TypedOwnedRegister<HelmRegisterOwner, HelmKeySeed>;
pub type HelmRegisterAddress = TypedRegisterAddress<HelmRegisterOwner, HelmKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Helm;

impl AllowDerivation<ArkRoot, Helm> for ArkRoot {
    type Derivator = HelmKeySeed;
}

pub type HelmKind = Derived<Helm, ArkRoot>;

impl Bech32Secret for HelmKind {
    const HRP: &'static str = "arkhelmsec";
}

pub type HelmKeySeed = TypedDerivationIndex<Helm>;
pub type HelmKey = TypedSecretKey<HelmKind>;

impl HelmKey {
    pub fn manifest(&self, value: EncryptedManifest) -> OwnedManifest {
        OwnedManifest::new(value, self.derive_manifest_key())
    }
}
pub type PublicHelmKey = TypedPublicKey<HelmKind>;

impl PublicHelmKey {
    pub fn manifest(&self) -> ManifestAddress {
        ManifestAddress::from_public_key(self.derive_manifest_addr())
    }
}

impl OwnedHelmRegister {
    pub fn new_derived(ark_seed: &ArkSeed) -> Self {
        Self::new(
            HelmKeySeed::random(),
            ark_seed.derive_child(HELM_REGISTER_DERIVATOR.deref()),
        )
    }
}

impl HelmRegister {
    pub fn derive_address(ark_address: &ArkAddress) -> HelmRegisterAddress {
        HelmRegisterAddress::new(RegisterAddress::new(
            ark_address
                .derive_child::<HelmRegisterKind>(HELM_REGISTER_DERIVATOR.deref())
                .into(),
        ))
    }

    pub fn into_owned(self, ark_seed: &ArkSeed) -> anyhow::Result<OwnedHelmRegister> {
        Ok(self.try_into_owned(&(ark_seed.derive_child(HELM_REGISTER_DERIVATOR.deref())))?)
    }
}

impl ArkSeed {
    pub fn helm_key(&self, seed: &HelmKeySeed) -> HelmKey {
        self.derive_child(seed)
    }
}

impl ArkAddress {
    pub fn helm_key(&self, seed: &HelmKeySeed) -> PublicHelmKey {
        self.derive_child(seed)
    }
}

impl Core {
    /// Retrieves the active `PublicHelmKey`.
    pub(super) async fn public_helm_key(&self) -> anyhow::Result<PublicHelmKey> {
        Ok(self.ark_address.helm_key(
            &self
                .read_register(&HelmRegister::derive_address(&self.ark_address))
                .await?,
        ))
    }

    /// Retrieves the active `HelmKey`.
    pub(super) async fn helm_key(&self, ark_seed: &ArkSeed) -> anyhow::Result<HelmKey> {
        Ok(ark_seed.helm_key(
            &self
                .read_register(&HelmRegister::derive_address(ark_seed.address()))
                .await?,
        ))
    }

    /// Verify the given `helm_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    pub(super) async fn verify_helm_key(&self, helm_key: &HelmKey) -> anyhow::Result<()> {
        if &self.public_helm_key().await? != helm_key.public_key() {
            bail!("helm_key not valid for ark [{}]", self.ark_address)
        }
        Ok(())
    }

    pub fn rotate_helm_key<'a>(
        &'a self,
        ark_seed: &'a ArkSeed,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<HelmKey>> + Send + 'a,
    ) {
        let (progress, task) = Progress::new(1, "Helm Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| self._rotate_helm_key(ark_seed, receipt, task).await),
        )
    }

    pub(super) async fn _rotate_helm_key(
        &self,
        ark_seed: &ArkSeed,
        receipt: &mut Receipt,
        mut task: Task,
    ) -> anyhow::Result<HelmKey> {
        task.start();

        let mut verify_seed = task.child(1, "Verify Ark Seed".to_string());
        let mut read_current_keys = task.child(1, "Retrieve current Key details".to_string());
        let mut read_manifest = task.child(2, "Read Manifest".to_string());
        let mut update_keys = task.child(2, "Update Key".to_string());
        let mut new_manifest = task.child(1, "Update Manifest".to_string());
        let mut retire_previous = task.child(1, "Retire Previous Manifest".to_string());

        verify_seed.start();
        self.verify_ark_seed(ark_seed)?;
        verify_seed.complete();

        read_current_keys.start();
        let previous_helm_key = self.helm_key(ark_seed).await?;
        read_current_keys.complete();

        read_manifest.start();
        let manifest = self.get_manifest(&previous_helm_key).await?;
        read_manifest += 1;
        let mut manifest_encryptor = self.manifest_encryptor(&previous_helm_key).await?;
        read_manifest.complete();

        update_keys.start();
        let new_helm_key_seed = HelmKeySeed::random();
        let new_helm_key = ark_seed.helm_key(&new_helm_key_seed);
        update_keys += 1;

        let mut helm_register = self
            .get_register(&HelmRegister::derive_address(ark_seed.public_key()))
            .await?
            .ok_or(anyhow!("helm register not found"))?
            .into_owned(ark_seed)?;
        helm_register.update(new_helm_key_seed)?;

        self.update_register(helm_register, receipt).await?;
        manifest_encryptor.public_helm_key = new_helm_key.public_key().clone();
        update_keys.complete();

        new_manifest.start();
        self.create_manifest(&manifest, &new_helm_key, &manifest_encryptor, receipt)
            .await?;
        new_manifest.complete();

        retire_previous.start();
        self.retire_manifest(&previous_helm_key, receipt).await?;
        retire_previous.complete();

        task.complete();
        Ok(new_helm_key)
    }
}
