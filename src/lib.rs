mod crypto;
mod manifest;
mod util;
mod vault;

use anyhow::{anyhow, bail};
use autonomi::client::payment::PaymentOption;
use autonomi::register::RegisterValue;
use autonomi::{Client, Wallet};
use bon::Builder;
use std::collections::HashMap;

use crate::crypto::{
    ArkAddress, ArkSeed, DataKey, DataKeySeed, EncryptedChunk, HelmKey, HelmKeySeed, PublicHelmKey,
    PublicWorkerKey, TypedChunk, TypedChunkAddress, TypedOwnedPointer, TypedOwnedRegister,
    TypedPointerAddress, TypedRegisterAddress, WorkerKey, WorkerKeySeed,
};
use crate::manifest::{Manifest, VaultConfig};
use crate::util::{diff_maps, Comparison};
use crate::vault::{Vault, VaultId};
use autonomi::pointer::PointerTarget;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Engine {
    client: Client,
    wallet: Wallet,
    arks: HashMap<ArkAddress, Ark>,
}

pub struct Ark {
    address: ArkAddress,
    created: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    name: String,
    description: Option<String>,
    worker_key: WorkerKey,
    vaults: HashMap<VaultId, Vault>,
}

impl Ark {
    fn new(manifest: Manifest, worker_key: WorkerKey) -> Self {
        let vaults = manifest
            .vaults
            .into_iter()
            .map(|c| {
                let vault = Vault::from_config(c);
                (vault.id().clone(), vault)
            })
            .collect();

        Self {
            address: manifest.ark_address,
            created: manifest.created,
            last_modified: manifest.last_modified,
            name: manifest.name,
            description: manifest.description,
            worker_key,
            vaults,
        }
    }

    fn apply_manifest(&mut self, manifest: Manifest) -> usize {
        let mut change_counter = 0;

        if self.name != manifest.name {
            self.name = manifest.name;
            change_counter += 1;
        }

        if self.description != manifest.description {
            self.description = manifest.description;
            change_counter += 1;
        }

        if self.created != manifest.created {
            self.created = manifest.created;
            change_counter += 1;
        }

        if self.last_modified != manifest.last_modified {
            self.last_modified = manifest.last_modified;
            change_counter += 1;
        }

        // detect changed vaults
        let mut vaults_in_manifest: HashMap<VaultId, VaultConfig> =
            manifest.vaults.into_iter().map(|c| (c.id, c)).collect();

        let diffs = diff_maps(&self.vaults, &vaults_in_manifest, |v1, v2| {
            if v1.differs(v2) {
                Comparison::Modified
            } else {
                Comparison::Equivalent
            }
        });

        for vault_id in diffs.added {
            let config = vaults_in_manifest
                .remove(&vault_id)
                .expect("vault_config to be there");
            self.vaults.insert(vault_id, Vault::from_config(config));
            change_counter += 1;
        }

        for vault_id in diffs.removed {
            self.vaults.remove(&vault_id);
            change_counter += 1;
        }

        for vault_id in diffs.modified {
            let config = vaults_in_manifest
                .remove(&vault_id)
                .expect("vault_config to be there");
            self.vaults
                .get_mut(&vault_id)
                .expect("vault to be there")
                .apply(config);
            change_counter += 1;
        }

        change_counter
    }
}

#[derive(Builder, Clone, Debug)]
pub struct VaultCreationSettings {
    #[builder(into)]
    name: String,
    description: Option<String>,
    #[builder(default = true)]
    active: bool,
}

#[derive(Builder, Clone, Debug)]
pub struct ArkCreationSettings {
    #[builder(into)]
    name: String,
    description: Option<String>,
}

impl Engine {
    pub fn new(client: Client, wallet: Wallet) -> Self {
        Self {
            client,
            wallet,
            arks: Default::default(),
        }
    }

    pub async fn create_ark(
        &mut self,
        settings: &ArkCreationSettings,
    ) -> anyhow::Result<ArkCreationDetails> {
        let (ark_seed, mnemonic) = ArkSeed::random();
        let helm_register = ark_seed.helm_register();
        let helm_key_seed = HelmKeySeed::random();
        self.create_register(&helm_register, helm_key_seed.clone())
            .await?;
        let helm_key = ark_seed.helm_key(&helm_key_seed);

        let data_register = ark_seed.data_register();
        let data_key_seed = DataKeySeed::random();
        self.create_register(&data_register, data_key_seed.clone())
            .await?;
        let data_key = ark_seed.data_key(&data_key_seed);

        let worker_register = helm_key.worker_register();
        let worker_key_seed = WorkerKeySeed::random();
        self.create_register(&worker_register, worker_key_seed.clone())
            .await?;
        let worker_key = helm_key.worker_key(&worker_key_seed);

        let ark_address = ark_seed.address();

        let manifest = Manifest::new(&ark_address, settings);
        let manifest_chunk =
            EncryptedChunk::from_value(worker_key.public_key().encrypt_manifest(&manifest));
        self.put_chunk(&manifest_chunk).await?;

        let manifest_pointer = helm_key.manifest_pointer();
        self.create_pointer(&manifest_pointer, manifest_chunk)
            .await?;

        Ok(ArkCreationDetails {
            address: ark_address.clone(),
            mnemonic,
            helm_key,
            data_key,
            worker_key,
            manifest,
        })
    }

    pub async fn add_ark(
        &mut self,
        address: &ArkAddress,
        worker_key: WorkerKey,
    ) -> anyhow::Result<()> {
        if self.arks.contains_key(address) {
            bail!("ark already registered");
        }
        self.verify_worker_key(&worker_key, address).await?;
        let manifest = self.get_manifest(address, &worker_key).await?;
        self.arks
            .insert(address.clone(), Ark::new(manifest, worker_key));
        Ok(())
    }

    pub async fn create_vault(
        &mut self,
        settings: VaultCreationSettings,
        helm_key: &HelmKey,
        ark_address: &ArkAddress,
    ) -> anyhow::Result<VaultId> {
        if !self.arks.contains_key(ark_address) {
            bail!("ark [{}] unknown", ark_address);
        }
        self.verify_helm_key(helm_key, ark_address).await?;
        let worker_key = self.worker_key(ark_address, helm_key).await?;
        let mut manifest = self.get_manifest(ark_address, &worker_key).await?;
        let vault_config = VaultConfig::from(settings);
        let id = vault_config.id;
        manifest.vaults.push(vault_config.clone());
        manifest.last_modified = Utc::now();
        self.update_manifest(&manifest, ark_address, helm_key)
            .await?;
        self.refresh_from_manifest(manifest).await?;
        Ok(id)
    }

    async fn refresh_from_manifest(&mut self, manifest: Manifest) -> anyhow::Result<usize> {
        let ark = self
            .arks
            .get_mut(&manifest.ark_address)
            .ok_or(anyhow!("ark [{}] not found", &manifest.ark_address))?;

        let changes = ark.apply_manifest(manifest);

        if changes > 0 {
            tracing::info!(
                num_changes = changes,
                ark_address = %ark.address,
                "detected and applied ark changes"
            );
        } else {
            tracing::debug!(
                ark_address = %ark.address,
                "no ark changes detected"
            )
        }

        Ok(changes)
    }

    /// Verify the given `worker_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    async fn verify_worker_key(
        &self,
        worker_key: &WorkerKey,
        ark_address: &ArkAddress,
    ) -> anyhow::Result<()> {
        if &self.public_worker_key(ark_address).await? != worker_key.public_key() {
            bail!("worker_key not valid for ark [{}]", ark_address)
        }
        Ok(())
    }

    /// Verify the given `helm_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    async fn verify_helm_key(
        &self,
        helm_key: &HelmKey,
        ark_address: &ArkAddress,
    ) -> anyhow::Result<()> {
        if &self.public_helm_key(&ark_address).await? != helm_key.public_key() {
            bail!("helm_key not valid for ark [{}]", ark_address)
        }
        Ok(())
    }

    /// Retrieves the latest `PublicHelmKey` for the given `ArkAddress`.
    async fn public_helm_key(&self, ark_address: &ArkAddress) -> anyhow::Result<PublicHelmKey> {
        Ok(ark_address.helm_key(&self.read_register(&ark_address.helm_register()).await?))
    }

    /// Retrieves the latest `PublicWorkerKey` for the given `ArkAddress`.
    async fn public_worker_key(&self, ark_address: &ArkAddress) -> anyhow::Result<PublicWorkerKey> {
        let helm_key = self.public_helm_key(ark_address).await?;
        Ok(helm_key.worker_key(&self.read_register(&helm_key.worker_register()).await?))
    }

    /// Retrieves the latest secret `WorkerKey` for the given `ArkAddress`.
    async fn worker_key(
        &self,
        ark_address: &ArkAddress,
        helm_key: &HelmKey,
    ) -> anyhow::Result<WorkerKey> {
        self.verify_helm_key(helm_key, ark_address).await?;
        Ok(helm_key.worker_key(
            &self
                .read_register(&helm_key.public_key().worker_register())
                .await?,
        ))
    }

    async fn get_manifest(
        &self,
        ark_address: &ArkAddress,
        worker_key: &WorkerKey,
    ) -> anyhow::Result<Manifest> {
        let encrypted_manifest = self
            .read_chunk_pointer(&self.public_helm_key(ark_address).await?.manifest_pointer())
            .await?;
        worker_key.decrypt_manifest(&encrypted_manifest)
    }

    async fn update_manifest(
        &mut self,
        manifest: &Manifest,
        ark_address: &ArkAddress,
        helm_key: &HelmKey,
    ) -> anyhow::Result<()> {
        if &manifest.ark_address != ark_address {
            bail!("manifest ark address does not match given ark address");
        }
        self.verify_helm_key(helm_key, ark_address).await?;
        let public_worker_key = self.public_worker_key(ark_address).await?;
        let manifest_chunk =
            EncryptedChunk::from_value(public_worker_key.encrypt_manifest(&manifest));
        self.put_chunk(&manifest_chunk).await?;
        self.update_pointer(&helm_key.manifest_pointer(), manifest_chunk)
            .await?;
        Ok(())
    }

    async fn put_chunk<T>(&mut self, chunk: &TypedChunk<T>) -> anyhow::Result<()> {
        let address = self
            .client
            .chunk_put(chunk.as_ref(), self.payment())
            .await?
            .1;
        if chunk.address().as_ref() != &address {
            bail!("incorrect chunk address returned");
        }
        Ok(())
    }

    async fn get_chunk<T: TryFrom<Bytes>>(
        &self,
        address: &TypedChunkAddress<T>,
    ) -> anyhow::Result<T>
    where
        <T as TryFrom<Bytes>>::Error: Display,
    {
        let chunk = TypedChunk::from_chunk(self.client.chunk_get(address.as_ref()).await?);
        chunk.try_into_inner()
    }

    async fn create_register<T, V: Into<RegisterValue>>(
        &mut self,
        register: &TypedOwnedRegister<T, V>,
        value: V,
    ) -> anyhow::Result<()> {
        let address = self
            .client
            .register_create(register.owner().as_ref(), value.into(), self.payment())
            .await?
            .1;
        if register.address().as_ref() != &address {
            bail!("incorrect register address returned");
        }
        Ok(())
    }

    async fn read_register<T, V: TryFrom<RegisterValue>>(
        &self,
        address: &TypedRegisterAddress<T, V>,
    ) -> anyhow::Result<V>
    where
        <V as TryFrom<RegisterValue>>::Error: Display,
    {
        Ok(self
            .client
            .register_get(address.as_ref())
            .await
            .map(|v| V::try_from(v).map_err(|e| anyhow!("{}", e)))??)
    }

    async fn create_pointer<T, V: Into<PointerTarget>>(
        &mut self,
        pointer: &TypedOwnedPointer<T, V>,
        value: V,
    ) -> anyhow::Result<()> {
        let address = self
            .client
            .pointer_create(pointer.owner().as_ref(), value.into(), self.payment())
            .await?
            .1;
        if pointer.address().as_ref() != &address {
            bail!("incorrect pointer address returned");
        }
        Ok(())
    }

    async fn update_pointer<T, V: Into<PointerTarget>>(
        &mut self,
        pointer: &TypedOwnedPointer<T, V>,
        value: V,
    ) -> anyhow::Result<()> {
        self.client
            .pointer_update(pointer.owner().as_ref(), value.into())
            .await?;
        Ok(())
    }

    async fn read_chunk_pointer<T, V: TryFrom<Bytes>>(
        &self,
        address: &TypedPointerAddress<T, TypedChunk<V>>,
    ) -> anyhow::Result<V>
    where
        <V as TryFrom<Bytes>>::Error: Display,
    {
        let address = match self.client.pointer_get(address.as_ref()).await?.target() {
            PointerTarget::ChunkAddress(address) => address.clone(),
            _ => bail!("pointer does not point  to chunk"),
        };
        let address = TypedChunkAddress::new(address);
        self.get_chunk(&address).await
    }

    fn payment(&self) -> PaymentOption {
        PaymentOption::Wallet(self.wallet.clone())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArkCreationDetails {
    #[zeroize(skip)]
    pub address: ArkAddress,
    pub mnemonic: String,
    pub helm_key: HelmKey,
    pub data_key: DataKey,
    pub worker_key: WorkerKey,
    #[zeroize(skip)]
    pub manifest: Manifest,
}

mod protos {
    use crate::crypto::ArkAddress;
    use anyhow::anyhow;
    use chrono::{DateTime, Utc};
    use std::str::FromStr;

    include!(concat!(env!("OUT_DIR"), "/protos/common.rs"));

    impl From<ArkAddress> for Address {
        fn from(value: ArkAddress) -> Self {
            Self {
                bech32: value.to_string(),
            }
        }
    }

    impl TryFrom<Address> for ArkAddress {
        type Error = anyhow::Error;

        fn try_from(value: Address) -> Result<Self, Self::Error> {
            ArkAddress::from_str(value.bech32.as_str())
        }
    }

    impl From<DateTime<Utc>> for Timestamp {
        fn from(value: DateTime<Utc>) -> Self {
            Self {
                seconds: value.timestamp(),
                nanos: value.timestamp_subsec_nanos(),
            }
        }
    }

    impl TryFrom<Timestamp> for DateTime<Utc> {
        type Error = anyhow::Error;

        fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
            DateTime::from_timestamp(value.seconds, value.nanos).ok_or(anyhow!("invalid timestamp"))
        }
    }

    impl From<&uuid::Uuid> for Uuid {
        fn from(value: &uuid::Uuid) -> Self {
            let (most_significant, least_significant) = value.as_u64_pair();
            Self {
                most_significant,
                least_significant,
            }
        }
    }

    impl From<uuid::Uuid> for Uuid {
        fn from(value: uuid::Uuid) -> Self {
            From::from(&value)
        }
    }

    impl From<&Uuid> for uuid::Uuid {
        fn from(value: &Uuid) -> Self {
            Self::from_u64_pair(value.most_significant, value.least_significant)
        }
    }

    impl From<Uuid> for uuid::Uuid {
        fn from(value: Uuid) -> Self {
            From::from(&value)
        }
    }
}
