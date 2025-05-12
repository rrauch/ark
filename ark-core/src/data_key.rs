use crate::crypto::{
    Bech32Secret, EncryptedData, ScratchpadContent, TypedDecryptor, TypedDerivationIndex,
    TypedEncryptor, TypedOwnedRegister, TypedOwnedScratchpad, TypedPublicKey, TypedRegisterAddress,
    TypedScratchpadAddress, TypedSecretKey,
};
use crate::progress::Task;
use crate::{ArkSeed, Core, Progress, Receipt, with_receipt};
use anyhow::bail;

const DATA_KEYRING_SCRATCHPAD_ENCODING: u64 = 845573457394578892;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRegisterKind;
pub type DataRegister = TypedOwnedRegister<DataRegisterKind, DataKeySeed>;
pub type DataRegisterAddress = TypedRegisterAddress<DataRegisterKind, DataKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataKeyKind;

impl Bech32Secret for DataKeyKind {
    const HRP: &'static str = "arkdatasec";
}

pub type DataKeySeed = TypedDerivationIndex<DataKeyKind>;
pub type DataKey = TypedSecretKey<DataKeyKind>;

impl DataKey {
    pub fn decrypt_data_keyring(
        &self,
        encrypted_keyring: &EncryptedDataKeyRing,
    ) -> anyhow::Result<DataKeyRing> {
        self.decrypt(encrypted_keyring)
    }
}

pub type SealKey = TypedPublicKey<DataKeyKind>;

impl SealKey {
    pub fn encrypt_data_keyring(
        &self,
        keyring: &DataKeyRing,
    ) -> anyhow::Result<EncryptedDataKeyRing> {
        self.encrypt(keyring.clone())
    }
}

pub type DataKeyRing = crate::crypto::KeyRing<DataKeyKind>;

impl ScratchpadContent for DataKeyRing {
    const ENCODING: u64 = DATA_KEYRING_SCRATCHPAD_ENCODING;
}

pub type EncryptedDataKeyRing = EncryptedData<DataKeyKind, DataKeyRing>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataKeyRingKind;

pub type DataKeyRingOwner =
    TypedOwnedScratchpad<DataKeyRingKind, EncryptedData<DataKeyKind, DataKeyRing>>;

pub type DataKeyRingAddress =
    TypedScratchpadAddress<DataKeyRingKind, EncryptedData<DataKeyKind, DataKeyRing>>;

impl Core {
    pub(super) async fn get_data_keyring(&self, data_key: &DataKey) -> anyhow::Result<DataKeyRing> {
        self.verify_data_key(data_key).await?;
        data_key.decrypt_data_keyring(
            &self
                .read_scratchpad(&self.ark_address.data_keyring())
                .await?,
        )
    }

    /// Verify the given `data_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    pub(super) async fn verify_data_key(&self, data_key: &DataKey) -> anyhow::Result<()> {
        if &self.seal_key().await? != data_key.public_key() {
            bail!("data_key not valid for ark [{}]", self.ark_address)
        }
        Ok(())
    }

    /// Retrieves the active `SealKey`.
    pub(super) async fn seal_key(&self) -> anyhow::Result<SealKey> {
        Ok(self.ark_address.seal_key(
            &self
                .read_register(&self.ark_address.data_register())
                .await?,
        ))
    }

    /// Does a full refresh of the data keyring.
    pub async fn update_data_keyring(&self, ark_seed: &ArkSeed) -> crate::Result<u64> {
        with_receipt(async move |receipt| {
            self.verify_ark_seed(ark_seed)?;
            self.update_scratchpad(
                self.seal_key()
                    .await?
                    .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?)?,
                &ark_seed.data_keyring(),
                receipt,
            )
            .await
        })
        .await
    }

    /// Retrieves the **FULL** data key history given a valid `ArkSeed`.
    pub(super) async fn derive_data_keyring(
        &self,
        ark_seed: &ArkSeed,
    ) -> anyhow::Result<DataKeyRing> {
        self.verify_ark_seed(ark_seed)?;
        let keyring: DataKeyRing = self
            .register_history(&ark_seed.public_key().data_register())
            .await?
            .into_iter()
            .map(|seed| ark_seed.data_key(&seed))
            .collect();
        if keyring.is_empty() {
            bail!("data_keyring is empty");
        }
        Ok(keyring)
    }

    pub fn rotate_data_key<'a>(
        &'a self,
        ark_seed: &'a ArkSeed,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<DataKey>> + Send + 'a,
    ) {
        let (progress, task) = Progress::new(1, "Data Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| self._rotate_data_key(ark_seed, receipt, task).await),
        )
    }

    pub(super) async fn _rotate_data_key(
        &self,
        ark_seed: &ArkSeed,
        receipt: &mut Receipt,
        mut task: Task,
    ) -> anyhow::Result<DataKey> {
        task.start();
        let mut verify_seed = task.child(1, "Verify Ark Seed".to_string());
        let mut read_current = task.child(1, "Retrieve current Data Key details".to_string());
        let mut update_key = task.child(2, "Update Data Key".to_string());
        let mut update_keyring = task.child(1, "Update Data Keyring".to_string());
        let mut update_manifest = task.child(3, "Update Manifest".to_string());

        verify_seed.start();
        self.verify_ark_seed(ark_seed)?;
        verify_seed.complete();

        read_current.start();
        let data_register = ark_seed.data_register();
        read_current.complete();

        update_key.start();
        let new_data_key_seed = DataKeySeed::random();
        update_key += 1;
        let new_data_key = ark_seed.data_key(&new_data_key_seed);
        self.update_register(&data_register, new_data_key_seed, receipt)
            .await?;
        update_key.complete();

        update_keyring.start();
        self.update_scratchpad(
            new_data_key
                .public_key()
                .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?)?,
            &ark_seed.data_keyring(),
            receipt,
        )
        .await?;
        update_keyring.complete();

        update_manifest.start();
        let manifest = self.get_manifest(ark_seed).await?;
        update_manifest += 1;
        let helm_key = self.helm_key(ark_seed).await?;
        update_manifest += 1;
        self.update_manifest(&manifest, &helm_key, receipt).await?;
        update_manifest.complete();

        task.complete();
        Ok(new_data_key)
    }
}
