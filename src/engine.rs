use crate::crypto::{
    ArkAddress, ArkSeed, DataKey, DataKeyRing, DataKeySeed, EncryptedData,
    EncryptedScratchpadContent, HelmKey, HelmKeySeed, PlaintextScratchpad, PublicHelmKey,
    PublicWorkerKey, ScratchpadContent, SealKey, Terminable, TypedChunk, TypedChunkAddress,
    TypedOwnedPointer, TypedOwnedRegister, TypedOwnedScratchpad, TypedPointerAddress,
    TypedRegisterAddress, TypedScratchpadAddress, WorkerKey, WorkerKeySeed,
};
use crate::manifest::{Manifest, VaultConfig};
use crate::vault::VaultId;
use crate::{Ark, ArkCreationDetails, ArkCreationSettings, VaultCreationSettings};
use anyhow::{anyhow, bail};
use autonomi::client::payment::PaymentOption;
use autonomi::pointer::PointerTarget;
use autonomi::register::RegisterValue;
use autonomi::{Client, Wallet};
use bytes::Bytes;
use chrono::Utc;
use std::collections::HashMap;
use std::fmt::Display;

pub struct Engine {
    client: Client,
    wallet: Wallet,
    arks: HashMap<ArkAddress, Ark>,
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

        self.create_encrypted_scratchpad(
            data_key
                .public_key()
                .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?),
            &ark_seed.data_keyring(),
        )
        .await?;

        let worker_register = helm_key.worker_register();
        let worker_key_seed = WorkerKeySeed::random();
        self.create_register(&worker_register, worker_key_seed.clone())
            .await?;
        let worker_key = helm_key.worker_key(&worker_key_seed);

        let ark_address = ark_seed.address();
        let manifest = Manifest::new(&ark_address, settings);
        self.create_encrypted_scratchpad(
            worker_key.public_key().encrypt_manifest(&manifest),
            &helm_key.manifest(),
        )
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

    /// Does a full refresh of the data keyring.
    pub async fn update_data_keyring(&mut self, ark_seed: &ArkSeed) -> anyhow::Result<u64> {
        self.update_scratchpad(
            self.seal_key(ark_seed.address())
                .await?
                .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?),
            &ark_seed.data_keyring(),
        )
        .await
    }

    /// Retrieves the **FULL** data key history given a valid `ArkSeed`.
    async fn derive_data_keyring(&self, ark_seed: &ArkSeed) -> anyhow::Result<DataKeyRing> {
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

    /// Creates a new **ENCRYPTED** scratchpad owned by the given owner yet readable by `R`.
    async fn create_encrypted_scratchpad<O: Clone + PartialEq, R, V: ScratchpadContent>(
        &mut self,
        encrypted_content: EncryptedScratchpadContent<R, V>,
        owner: &TypedOwnedScratchpad<O, EncryptedData<R, V>>,
    ) -> anyhow::Result<()> {
        self.create_scratchpad(encrypted_content, owner).await
    }

    /// Creates a new **PLAINTEXT** scratchpad owned by the given owner.
    async fn create_scratchpad<T: Clone + PartialEq, V: ScratchpadContent>(
        &mut self,
        content: V,
        owner: &TypedOwnedScratchpad<T, V>,
    ) -> anyhow::Result<()> {
        let pad = PlaintextScratchpad::new_from_value(content, owner.owner().public_key().clone())
            .try_into_scratchpad(owner)?;
        if self
            .client
            .scratchpad_check_existance(pad.address())
            .await?
        {
            bail!("scratchpad already exists");
        }
        let address = self.client.scratchpad_put(pad, self.payment()).await?.1;
        if &address != owner.address().as_ref() {
            bail!("incorrect scratchpad address returned");
        }
        Ok(())
    }

    async fn read_scratchpad<T, V: ScratchpadContent>(
        &self,
        address: &TypedScratchpadAddress<T, V>,
    ) -> anyhow::Result<V>
    where
        <V as TryFrom<Bytes>>::Error: Display,
    {
        let pad = self
            .client
            .scratchpad_get_from_public_key(address.as_ref().owner())
            .await?;
        Ok(PlaintextScratchpad::<T, V>::try_from_scratchpad(pad)?.try_into_inner()?)
    }

    async fn update_scratchpad<T: Clone + PartialEq, V: ScratchpadContent>(
        &mut self,
        content: V,
        owner: &TypedOwnedScratchpad<T, V>,
    ) -> anyhow::Result<u64> {
        let mut pad = PlaintextScratchpad::try_from_scratchpad(
            self.client
                .scratchpad_get_from_public_key(owner.address().as_ref().owner())
                .await?,
        )?;
        let counter = pad.update(content)?;
        self.client
            .scratchpad_put(pad.try_into_scratchpad(owner)?, self.payment())
            .await?;
        Ok(counter)
    }

    async fn danger_terminate_scratchpad<
        T: Clone + PartialEq,
        V: ScratchpadContent + Terminable,
    >(
        &mut self,
        owner: &TypedOwnedScratchpad<T, V>,
    ) -> anyhow::Result<()> {
        let pad = PlaintextScratchpad::try_from_scratchpad(
            self.client
                .scratchpad_get_from_public_key(owner.address().as_ref().owner())
                .await?,
        )?;
        self.client
            .scratchpad_put(pad.terminate(owner)?, self.payment())
            .await?;
        Ok(())
    }

    async fn get_data_keyring(
        &self,
        ark_address: &ArkAddress,
        data_key: &DataKey,
    ) -> anyhow::Result<DataKeyRing> {
        self.verify_data_key(data_key, ark_address).await?;
        data_key.decrypt_data_keyring(&self.read_scratchpad(&ark_address.data_keyring()).await?)
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

    /// Verify the given `data_key` against the Ark.
    /// Ensures the key is the current, active one for the Ark.
    async fn verify_data_key(
        &self,
        data_key: &DataKey,
        ark_address: &ArkAddress,
    ) -> anyhow::Result<()> {
        if &self.seal_key(&ark_address).await? != data_key.public_key() {
            bail!("data_key not valid for ark [{}]", ark_address)
        }
        Ok(())
    }

    /// Retrieves the latest `SealKey` for the given `ArkAddress`.
    async fn seal_key(&self, ark_address: &ArkAddress) -> anyhow::Result<SealKey> {
        Ok(ark_address.seal_key(&self.read_register(&ark_address.data_register()).await?))
    }

    /// Retrieves the latest `PublicHelmKey` for the given `ArkAddress`.
    async fn public_helm_key(&self, ark_address: &ArkAddress) -> anyhow::Result<PublicHelmKey> {
        Ok(ark_address.helm_key(&self.read_register(&ark_address.helm_register()).await?))
    }

    /// Retrieves the latest `HelmKey` for the given `ArkSeed`.
    async fn helm_key(&self, ark_seed: &ArkSeed) -> anyhow::Result<HelmKey> {
        Ok(ark_seed.helm_key(
            &self
                .read_register(&ark_seed.helm_register().address())
                .await?,
        ))
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

    pub async fn rotate_data_key(&mut self, ark_seed: &ArkSeed) -> anyhow::Result<DataKey> {
        let data_register = ark_seed.data_register();
        let new_data_key_seed = DataKeySeed::random();
        let new_data_key = ark_seed.data_key(&new_data_key_seed);
        self.update_register(&data_register, new_data_key_seed)
            .await?;

        self.update_scratchpad(
            new_data_key
                .public_key()
                .encrypt_data_keyring(&self.derive_data_keyring(&ark_seed).await?),
            &ark_seed.data_keyring(),
        )
        .await?;

        Ok(new_data_key)
    }

    pub async fn rotate_helm_key(
        &mut self,
        ark_seed: &ArkSeed,
    ) -> anyhow::Result<(HelmKey, WorkerKey)> {
        let previous_helm_key = self.helm_key(ark_seed).await?;
        let previous_worker_key = self
            .worker_key(ark_seed.address(), &previous_helm_key)
            .await?;
        let new_helm_key_seed = HelmKeySeed::random();
        let new_helm_key = ark_seed.helm_key(&new_helm_key_seed);

        let new_worker_key = self
            .rotate_worker_key(&previous_helm_key, &previous_worker_key, &new_helm_key)
            .await?;

        self.update_register(&ark_seed.helm_register(), new_helm_key_seed)
            .await?;

        self.terminate_manifest(ark_seed.address(), &previous_helm_key)
            .await?;

        Ok((new_helm_key, new_worker_key))
    }

    pub async fn rotate_worker_key(
        &mut self,
        previous_helm_key: &HelmKey,
        previous_worker_key: &WorkerKey,
        new_helm_key: &HelmKey,
    ) -> anyhow::Result<WorkerKey> {
        let manifest = self
            .get_specific_manifest(&previous_worker_key, previous_helm_key.public_key())
            .await?;
        let new_worker_key_seed = WorkerKeySeed::random();
        let new_worker_key = new_helm_key.worker_key(&new_worker_key_seed);

        if previous_helm_key == new_helm_key {
            // Only the `WorkerKey` is rotated, nothing else
            self.update_scratchpad(
                new_worker_key.public_key().encrypt_manifest(&manifest),
                &previous_helm_key.manifest(),
            )
            .await?;
            self.update_register(&previous_helm_key.worker_register(), new_worker_key_seed)
                .await?;
        } else {
            // Part of a bigger rotation
            self.create_encrypted_scratchpad(
                new_worker_key.public_key().encrypt_manifest(&manifest),
                &new_helm_key.manifest(),
            )
            .await?;

            self.create_register(&new_helm_key.worker_register(), new_worker_key_seed)
                .await?;
        }

        Ok(new_worker_key)
    }

    async fn get_manifest(
        &self,
        ark_address: &ArkAddress,
        worker_key: &WorkerKey,
    ) -> anyhow::Result<Manifest> {
        let public_helm_key = self.public_helm_key(ark_address).await?;
        self.get_specific_manifest(worker_key, &public_helm_key)
            .await
    }

    async fn get_specific_manifest(
        &self,
        worker_key: &WorkerKey,
        public_helm_key: &PublicHelmKey,
    ) -> anyhow::Result<Manifest> {
        let encrypted_manifest = self.read_scratchpad(&public_helm_key.manifest()).await?;
        worker_key.decrypt_manifest(&encrypted_manifest)
    }

    async fn update_manifest(
        &mut self,
        manifest: &Manifest,
        ark_address: &ArkAddress,
        helm_key: &HelmKey,
    ) -> anyhow::Result<u64> {
        if &manifest.ark_address != ark_address {
            bail!("manifest ark address does not match given ark address");
        }
        self.verify_helm_key(helm_key, ark_address).await?;
        self.update_scratchpad(
            self.public_worker_key(ark_address)
                .await?
                .encrypt_manifest(&manifest),
            &helm_key.manifest(),
        )
        .await
    }

    async fn terminate_manifest(
        &mut self,
        ark_address: &ArkAddress,
        helm_key: &HelmKey,
    ) -> anyhow::Result<()> {
        if &self.public_helm_key(&ark_address).await? == helm_key.public_key() {
            bail!(
                "helm_key is still active for ark [{}], cannot terminate manifest",
                ark_address
            )
        };
        self.danger_terminate_scratchpad(&helm_key.manifest())
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

    async fn update_register<T, V: Into<RegisterValue>>(
        &mut self,
        register: &TypedOwnedRegister<T, V>,
        value: V,
    ) -> anyhow::Result<()> {
        self.client
            .register_update(register.owner().as_ref(), value.into(), self.payment())
            .await?;
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

    async fn register_history<T, V: TryFrom<RegisterValue>>(
        &self,
        address: &TypedRegisterAddress<T, V>,
    ) -> anyhow::Result<Vec<V>>
    where
        <V as TryFrom<RegisterValue>>::Error: Display,
    {
        Ok(self
            .client
            .register_history(address.as_ref())
            .collect()
            .await?
            .into_iter()
            .map(|v| V::try_from(v).map_err(|e| anyhow!("{}", e)))
            .collect::<anyhow::Result<Vec<_>>>()?)
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
