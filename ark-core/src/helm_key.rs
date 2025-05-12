use crate::crypto::{
    Bech32Secret, TypedDerivationIndex, TypedOwnedRegister, TypedPublicKey, TypedRegisterAddress,
    TypedSecretKey, key_from_name, scratchpad_address_from_name,
};
use crate::manifest::{ManifestAddress, OwnedManifest};
use crate::progress::Task;
use crate::{ArkSeed, Core, Progress, Receipt, with_receipt};
use anyhow::bail;

const MANIFEST_NAME: &str = "/ark/v0/manifest/scratchpad";

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
    pub fn manifest(&self) -> OwnedManifest {
        let owner = TypedSecretKey::new(key_from_name(self.as_ref(), MANIFEST_NAME));

        OwnedManifest::new(owner)
    }
}
pub type PublicHelmKey = TypedPublicKey<HelmKeyKind>;

impl PublicHelmKey {
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

        self.update_register(&ark_seed.helm_register(), new_helm_key_seed, receipt)
            .await?;
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
