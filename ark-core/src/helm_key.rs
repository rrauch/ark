use crate::crypto::{
    Bech32Secret, TypedDerivationIndex, TypedOwnedRegister, TypedPublicKey, TypedRegisterAddress,
    TypedSecretKey, key_from_name, register_address_from_name, scratchpad_address_from_name,
};
use crate::manifest::{ManifestAddress, OwnedManifest};
use crate::progress::Task;
use crate::worker_key::{WorkerKeySeed, WorkerRegister, WorkerRegisterAddress};
use crate::{ArkSeed, Core, Progress, PublicWorkerKey, Receipt, WorkerKey, with_receipt};
use anyhow::bail;
use autonomi::Client;

const MANIFEST_NAME: &str = "/ark/v0/manifest/scratchpad";
const WORKER_REGISTER_NAME: &str = "/ark/v0/worker/register";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmRegisterKind;
pub type HelmRegister = TypedOwnedRegister<HelmRegisterKind, HelmKeySeed>;
pub type HelmRegisterAddress = TypedRegisterAddress<HelmRegisterKind, HelmKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmKeyKind;

impl Bech32Secret for HelmKeyKind {
    const HRP: &'static str = "arkhelmsec";
}

pub type HelmKeySeed = TypedDerivationIndex<HelmKeyKind>;
pub type HelmKey = TypedSecretKey<HelmKeyKind>;

impl HelmKey {
    pub fn worker_register(&self) -> WorkerRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            WORKER_REGISTER_NAME,
        ));

        WorkerRegister::new(owner)
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> WorkerKey {
        self.derive_child(seed)
    }

    pub fn manifest(&self) -> OwnedManifest {
        let owner = TypedSecretKey::new(key_from_name(self.as_ref(), MANIFEST_NAME));

        OwnedManifest::new(owner)
    }
}
pub type PublicHelmKey = TypedPublicKey<HelmKeyKind>;

impl PublicHelmKey {
    pub fn worker_register(&self) -> WorkerRegisterAddress {
        WorkerRegisterAddress::new(register_address_from_name(
            self.as_ref(),
            WORKER_REGISTER_NAME,
        ))
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> PublicWorkerKey {
        self.derive_child(seed)
    }

    pub fn manifest(&self) -> ManifestAddress {
        ManifestAddress::new(scratchpad_address_from_name(self.as_ref(), MANIFEST_NAME))
    }
}

impl Core {
    /// Retrieves the active `PublicHelmKey`.
    pub(super) async fn public_helm_key(&self) -> anyhow::Result<PublicHelmKey> {
        Ok(self.ark_address.helm_key(
            &self
                .read_register(&self.ark_address.helm_register())
                .await?,
        ))
    }

    /// Retrieves the active `HelmKey`.
    pub(super) async fn helm_key(&self, ark_seed: &ArkSeed) -> anyhow::Result<HelmKey> {
        Ok(ark_seed.helm_key(
            &self
                .read_register(&ark_seed.helm_register().address())
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
        impl Future<Output = crate::Result<(HelmKey, WorkerKey)>> + Send + 'a,
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
    ) -> anyhow::Result<(HelmKey, WorkerKey)> {
        task.start();

        let mut verify_seed = task.child(1, "Verify Ark Seed".to_string());
        let mut read_current_keys = task.child(2, "Retrieve current Key details".to_string());
        let mut update_keys = task.child(3, "Update Key".to_string());
        let mut retire_previous = task.child(1, "Retire Previous Manifest".to_string());

        verify_seed.start();
        self.verify_ark_seed(ark_seed)?;
        verify_seed.complete();

        read_current_keys.start();
        let previous_helm_key = self.helm_key(ark_seed).await?;
        read_current_keys += 1;
        let previous_worker_key = self.worker_key(&previous_helm_key).await?;
        read_current_keys.complete();

        update_keys.start();
        let new_helm_key_seed = HelmKeySeed::random();
        update_keys += 1;
        let new_helm_key = ark_seed.helm_key(&new_helm_key_seed);
        let new_worker_key = self
            ._rotate_worker_key(
                &previous_helm_key,
                &previous_worker_key,
                &new_helm_key,
                receipt,
                update_keys.child(1, "Rotate Worker Key".to_string()),
            )
            .await?;
        update_keys += 1;

        self.update_register(&ark_seed.helm_register(), new_helm_key_seed, receipt)
            .await?;
        update_keys.complete();

        retire_previous.start();
        self.retire_manifest(&previous_helm_key, receipt).await?;
        retire_previous.complete();

        task.complete();
        Ok((new_helm_key, new_worker_key))
    }
}
