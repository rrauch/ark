use crate::HelmKey;
use crate::crypto::{
    AllowRandom, Bech32Public, Bech32Secret, EitherKey, Retirable, RetiredKey, TypedPublicKey,
    TypedSecretKey,
};
use crate::manifest::ManifestDecryptor;
use crate::progress::Task;
use crate::{ArkSeed, Core, Progress, Receipt, with_receipt};
use anyhow::bail;
use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerKeyKind;

impl Bech32Secret for WorkerKeyKind {
    const HRP: &'static str = "arkworkersec";
}

impl Bech32Public for WorkerKeyKind {
    const HRP: &'static str = "arkworkerpub";
}

pub type WorkerKey = TypedSecretKey<WorkerKeyKind>;
impl Retirable for WorkerKeyKind {}
impl AllowRandom for WorkerKeyKind {}
pub type RetiredWorkerKey = RetiredKey<WorkerKeyKind>;
pub type EitherWorkerKey = EitherKey<WorkerKeyKind>;
pub type PublicWorkerKey = TypedPublicKey<WorkerKeyKind>;

impl Core {
    /// Verify the given `worker_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    pub(super) async fn verify_worker_key(&self, worker_key: &WorkerKey) -> anyhow::Result<()> {
        let manifest = self.get_manifest(worker_key).await?;
        if &manifest.authorized_worker != worker_key.public_key() {
            bail!("worker_key not valid for ark [{}]", self.ark_address)
        }
        Ok(())
    }

    /// Retrieves the active `PublicWorkerKey`.
    pub(super) async fn public_worker_key<D: ManifestDecryptor>(
        &self,
        decryptor: &D,
    ) -> anyhow::Result<PublicWorkerKey> {
        Ok(self.get_manifest(decryptor).await?.authorized_worker)
    }

    pub fn rotate_worker_key_with_seed(
        &self,
        ark_seed: &ArkSeed,
        new_worker_key: Option<PublicWorkerKey>,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<EitherWorkerKey>> + Send,
    ) {
        let (progress, task) = Progress::new(1, "Worker Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                self.verify_ark_seed(ark_seed)?;
                let helm_key = self.helm_key(ark_seed).await?;

                self._rotate_worker_key(&helm_key, new_worker_key, receipt, task)
                    .await
            }),
        )
    }

    pub fn rotate_worker_key<'a>(
        &'a self,
        helm_key: &'a HelmKey,
        new_worker_key: Option<PublicWorkerKey>,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<EitherWorkerKey>> + Send + 'a,
    ) {
        let (progress, task) = Progress::new(1, "Worker Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                self._rotate_worker_key(helm_key, new_worker_key, receipt, task)
                    .await
            }),
        )
    }

    pub(super) async fn _rotate_worker_key(
        &self,
        helm_key: &HelmKey,
        new_worker_key: Option<PublicWorkerKey>,
        receipt: &mut Receipt,
        mut task: Task,
    ) -> anyhow::Result<EitherWorkerKey> {
        task.start();

        let new_worker_key: EitherWorkerKey = new_worker_key
            .map(|pk| pk.into())
            .unwrap_or(WorkerKey::random().into());

        let mut read_manifest = task.child(2, "Read Manifest".to_string());
        let mut update_manifest = task.child(1, "Update Manifest".to_string());
        read_manifest.start();
        let mut manifest = self.get_manifest(helm_key).await?;
        read_manifest += 1;
        let mut manifest_encryptor = self.manifest_encryptor(helm_key).await?;
        manifest_encryptor.public_worker_key = new_worker_key.public_key().clone();
        read_manifest.complete();

        manifest.update_worker(new_worker_key.public_key());
        manifest.last_modified = Utc::now();

        update_manifest.start();
        self.update_manifest(&manifest, &helm_key, receipt).await?;
        update_manifest.complete();

        task.complete();
        Ok(new_worker_key)
    }
}
