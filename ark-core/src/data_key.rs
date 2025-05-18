use crate::ark_seed::ArkRoot;
use crate::crypto::{
    AllowDerivation, Bech32Secret, Derived, EncryptedData, ScratchpadContent, TypedDecryptor,
    TypedDerivationIndex, TypedEncryptor, TypedOwnedRegister, TypedOwnedScratchpad, TypedPublicKey,
    TypedRegisterAddress, TypedScratchpadAddress, TypedSecretKey,
};
use crate::progress::Task;
use crate::{ArkAddress, ArkSeed, Core, Progress, Receipt, crypto, with_receipt};
use anyhow::bail;
use autonomi::register::RegisterAddress;
use once_cell::sync::Lazy;
use std::ops::Deref;

const DATA_KEYRING_SCRATCHPAD_ENCODING: u64 = 845573457394578892;

const DATA_KEYRING_NAME: &str = "/ark/v0/data/keyring/scratchpad";
static DATA_KEYRING_DERIVATION_IDX: Lazy<DataKeyringDerivator> =
    Lazy::new(|| DataKeyringDerivator::from_name(DATA_KEYRING_NAME));

type DataKeyringDerivator = TypedDerivationIndex<DataKeyRing>;

const DATA_REGISTER_NAME: &str = "/ark/v0/data/register";
static DATA_REGISTER_DERIVATOR: Lazy<DataRegisterDerivator> =
    Lazy::new(|| DataRegisterDerivator::from_name(DATA_REGISTER_NAME));

type DataRegisterDerivator = TypedDerivationIndex<DataRegister>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRegister;

pub type DataRegisterKind = Derived<DataRegister, ArkRoot>;

pub type OwnedDataRegister = TypedOwnedRegister<DataRegisterKind, DataKeySeed>;
pub type DataRegisterAddress = TypedRegisterAddress<DataRegisterKind, DataKeySeed>;

impl AllowDerivation<ArkRoot, DataRegister> for ArkRoot {
    type Derivator = DataRegisterDerivator;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Data;

impl AllowDerivation<ArkRoot, Data> for ArkRoot {
    type Derivator = DataKeySeed;
}

pub type DataKeyKind = Derived<Data, ArkRoot>;

impl Bech32Secret for DataKeyKind {
    const HRP: &'static str = "arkdatasec";
}

pub type DataKeySeed = TypedDerivationIndex<Data>;
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

pub type DataKeyRing = crypto::KeyRing<DataKeyKind>;

impl ScratchpadContent for DataKeyRing {
    const ENCODING: u64 = DATA_KEYRING_SCRATCHPAD_ENCODING;
}

pub type EncryptedDataKeyRing = EncryptedData<DataKeyKind, DataKeyRing>;

pub type DataKeyRingKind = Derived<DataKeyRing, ArkRoot>;

impl AllowDerivation<ArkRoot, DataKeyRing> for ArkRoot {
    type Derivator = DataKeyringDerivator;
}

pub type OwnedDataKeyRing = TypedOwnedScratchpad<DataKeyRingKind, EncryptedDataKeyRing>;

pub type DataKeyRingAddress = TypedScratchpadAddress<DataKeyRingKind, EncryptedDataKeyRing>;

impl ArkSeed {
    pub fn data_register(&self) -> OwnedDataRegister {
        OwnedDataRegister::new(self.derive_child(DATA_REGISTER_DERIVATOR.deref()))
    }
    pub fn data_key(&self, seed: &DataKeySeed) -> DataKey {
        self.derive_child(seed)
    }

    pub fn data_keyring(&self, value: EncryptedDataKeyRing) -> OwnedDataKeyRing {
        OwnedDataKeyRing::new(
            value,
            self.derive_child(DATA_KEYRING_DERIVATION_IDX.deref()),
        )
    }
}

impl ArkAddress {
    pub fn data_register(&self) -> DataRegisterAddress {
        DataRegisterAddress::new(RegisterAddress::new(
            self.derive_child::<DataRegister>(DATA_REGISTER_DERIVATOR.deref())
                .into(),
        ))
    }

    pub fn data_keyring(&self) -> DataKeyRingAddress {
        DataKeyRingAddress::from_public_key(self.derive_child(DATA_KEYRING_DERIVATION_IDX.deref()))
    }
}

impl Core {
    pub(super) async fn get_data_keyring(&self, data_key: &DataKey) -> anyhow::Result<DataKeyRing> {
        self.verify_data_key(data_key).await?;
        data_key.decrypt_data_keyring(
            &self
                .read_scratchpad_content(&self.ark_address.data_keyring())
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
                ark_seed.data_keyring(
                    self.seal_key()
                        .await?
                        .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?)?,
                ),
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
            ark_seed.data_keyring(
                new_data_key
                    .public_key()
                    .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?)?,
            ),
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
