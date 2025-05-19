use crate::ark_seed::ArkRoot;
use crate::crypto::{
    AllowDerivation, Bech32Secret, Derived, EncryptedData, ScratchpadContent, TypedDecryptor,
    TypedDerivationIndex, TypedEncryptor, TypedOwnedRegister, TypedOwnedScratchpad, TypedPublicKey,
    TypedRegister, TypedRegisterAddress, TypedScratchpadAddress, TypedSecretKey,
};
use crate::progress::Task;
use crate::{ArkAddress, ArkSeed, Core, Progress, Receipt, crypto, with_receipt};
use anyhow::{anyhow, bail};
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

type DataRegisterDerivator = TypedDerivationIndex<DataRegisterKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRegisterKind;

pub type DataRegisterOwner = Derived<DataRegisterKind, ArkRoot>;

pub type DataRegister = TypedRegister<DataRegisterOwner, DataKeySeed>;

pub type OwnedDataRegister = TypedOwnedRegister<DataRegisterOwner, DataKeySeed>;
pub type DataRegisterAddress = TypedRegisterAddress<DataRegisterOwner, DataKeySeed>;

impl AllowDerivation<ArkRoot, DataRegisterKind> for ArkRoot {
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

impl DataRegister {
    pub fn derive_address(ark_address: &ArkAddress) -> DataRegisterAddress {
        DataRegisterAddress::new(RegisterAddress::new(
            ark_address
                .derive_child::<DataRegisterKind>(DATA_REGISTER_DERIVATOR.deref())
                .into(),
        ))
    }

    pub fn into_owned(self, ark_seed: &ArkSeed) -> anyhow::Result<OwnedDataRegister> {
        Ok(self.try_into_owned(&(ark_seed.derive_child(DATA_REGISTER_DERIVATOR.deref())))?)
    }
}

impl OwnedDataRegister {
    pub fn new_derived(ark_seed: &ArkSeed) -> Self {
        Self::new(
            DataKeySeed::random(),
            ark_seed.derive_child(DATA_REGISTER_DERIVATOR.deref()),
        )
    }
}

impl ArkSeed {
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
    pub fn data_keyring(&self) -> DataKeyRingAddress {
        DataKeyRingAddress::from_public_key(self.derive_child(DATA_KEYRING_DERIVATION_IDX.deref()))
    }
}

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
                .read_register(&DataRegister::derive_address(&self.ark_address))
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
            .register_history(&DataRegister::derive_address(&self.ark_address))
            .await?
            .into_iter()
            .map(|seed| ark_seed.data_key(seed.as_ref()))
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
        let mut data_register = self
            .get_register(&DataRegister::derive_address(ark_seed.address()))
            .await?
            .ok_or(anyhow!("data register not found"))?
            .into_owned(ark_seed)?;
        read_current.complete();

        update_key.start();
        data_register.update(DataKeySeed::random())?;
        update_key += 1;
        let new_data_key = ark_seed.data_key(data_register.value());
        self.update_register(data_register, receipt).await?;
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
