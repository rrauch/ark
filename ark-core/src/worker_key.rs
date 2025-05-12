use crate::HelmKey;
use crate::crypto::{
    Bech32Secret, TypedDerivationIndex, TypedOwnedRegister, TypedPublicKey, TypedRegisterAddress,
    TypedSecretKey,
};
use crate::progress::Task;
use crate::{ArkSeed, Core, Progress, Receipt, with_receipt};
use anyhow::bail;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerRegisterKind;

pub type WorkerRegister = TypedOwnedRegister<WorkerRegisterKind, WorkerKeySeed>;

pub type WorkerRegisterAddress = TypedRegisterAddress<WorkerRegisterKind, WorkerKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerKeyKind;

impl Bech32Secret for WorkerKeyKind {
    const HRP: &'static str = "arkworkersec";
}

pub type WorkerKeySeed = TypedDerivationIndex<WorkerKeyKind>;
pub type WorkerKey = TypedSecretKey<WorkerKeyKind>;

pub type PublicWorkerKey = TypedPublicKey<WorkerKeyKind>;

impl Core {
    /// Verify the given `worker_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    pub(super) async fn verify_worker_key(&self, worker_key: &WorkerKey) -> anyhow::Result<()> {
        if &self.public_worker_key().await? != worker_key.public_key() {
            bail!("worker_key not valid for ark [{}]", self.ark_address)
        }
        Ok(())
    }

    /// Retrieves the active `PublicWorkerKey`.
    pub(super) async fn public_worker_key(&self) -> anyhow::Result<PublicWorkerKey> {
        let helm_key = self.public_helm_key().await?;
        Ok(helm_key.worker_key(&self.read_register(&helm_key.worker_register()).await?))
    }

    /// Retrieves the active secret `WorkerKey`.
    pub(super) async fn worker_key(&self, helm_key: &HelmKey) -> anyhow::Result<WorkerKey> {
        self.verify_helm_key(helm_key).await?;
        Ok(helm_key.worker_key(
            &self
                .read_register(&helm_key.public_key().worker_register())
                .await?,
        ))
    }

    pub fn rotate_worker_key_with_seed(
        &self,
        ark_seed: &ArkSeed,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<WorkerKey>> + Send,
    ) {
        let (progress, task) = Progress::new(1, "Worker Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                self.verify_ark_seed(ark_seed)?;
                let helm_key = self.helm_key(ark_seed).await?;
                self._rotate_worker_key(
                    &helm_key,
                    &self.worker_key(&helm_key).await?,
                    &helm_key,
                    receipt,
                    task,
                )
                .await
            }),
        )
    }

    pub fn rotate_worker_key<'a>(
        &'a self,
        helm_key: &'a HelmKey,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<WorkerKey>> + Send + 'a,
    ) {
        let (progress, task) = Progress::new(1, "Worker Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                self._rotate_worker_key(
                    helm_key,
                    &self.worker_key(&helm_key).await?,
                    helm_key,
                    receipt,
                    task,
                )
                .await
            }),
        )
    }

    pub(super) async fn _rotate_worker_key(
        &self,
        previous_helm_key: &HelmKey,
        previous_worker_key: &WorkerKey,
        new_helm_key: &HelmKey,
        receipt: &mut Receipt,
        mut task: Task,
    ) -> anyhow::Result<WorkerKey> {
        task.start();

        let mut read_manifest = task.child(1, "Read Manifest".to_string());
        let mut derive_new_key = task.child(1, "Derive New Key".to_string());
        let mut update_network = task.child(2, "Update Network".to_string());
        read_manifest.start();
        let manifest = self
            .get_specific_manifest(previous_worker_key, previous_helm_key.public_key())
            .await?;
        read_manifest.complete();

        derive_new_key.start();
        let new_worker_key_seed = WorkerKeySeed::random();
        let new_worker_key = new_helm_key.worker_key(&new_worker_key_seed);
        derive_new_key.complete();

        update_network.start();
        let mut manifest_encryptor = self.manifest_encryptor().await?;
        manifest_encryptor.public_worker_key = new_worker_key.public_key().clone();

        if previous_helm_key == new_helm_key {
            // Only the `WorkerKey` is rotated, nothing else
            self.update_scratchpad(
                manifest_encryptor.encrypt_manifest(&manifest)?,
                &previous_helm_key.manifest(),
                receipt,
            )
            .await?;
            update_network += 1;
            self.update_register(
                &previous_helm_key.worker_register(),
                new_worker_key_seed,
                receipt,
            )
            .await?;
            update_network += 1;
        } else {
            // Part of a bigger rotation
            self.create_encrypted_scratchpad(
                manifest_encryptor.encrypt_manifest(&manifest)?,
                &new_helm_key.manifest(),
                receipt,
            )
            .await?;
            update_network += 1;
            self.create_register(
                &new_helm_key.worker_register(),
                new_worker_key_seed,
                receipt,
            )
            .await?;
            update_network += 1;
        }
        update_network.complete();
        task.complete();
        Ok(new_worker_key)
    }
}
