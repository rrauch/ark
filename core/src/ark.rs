use crate::crypto::{
    ArkAddress, DataKey, DataKeySeed, HelmKey, HelmKeySeed, WorkerKey, WorkerKeySeed,
};
use crate::manifest::Manifest;
use crate::util::{Comparison, diff_maps};
use crate::vault::{Vault, VaultConfig, VaultId};
use crate::{ArkSeed, AutonomiClient, AutonomiWallet, Core, Receipt};
use bon::Builder;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Ark {
    pub address: ArkAddress,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub name: String,
    pub description: Option<String>,
    pub vaults: HashMap<VaultId, Vault>,
}

impl From<Manifest> for Ark {
    fn from(manifest: Manifest) -> Self {
        let vaults = manifest
            .vaults
            .into_iter()
            .map(|c| {
                let vault = Vault::from_config(c);
                (vault.id.clone(), vault)
            })
            .collect();

        Self {
            address: manifest.ark_address,
            created: manifest.created,
            last_modified: manifest.last_modified,
            name: manifest.name,
            description: manifest.description,
            vaults,
        }
    }
}

impl Ark {
    pub(crate) async fn create(
        settings: ArkCreationSettings,
        client: &AutonomiClient,
        wallet: &AutonomiWallet,
        receipt: &mut Receipt,
    ) -> anyhow::Result<ArkCreationDetails> {
        let (ark_seed, mnemonic) = ArkSeed::random();
        let core = Core::builder()
            .ark_address(ark_seed.address().clone())
            .client(client.clone())
            .wallet(wallet.clone())
            .build();

        let helm_register = ark_seed.helm_register();
        let helm_key_seed = HelmKeySeed::random();
        core.create_register(&helm_register, helm_key_seed.clone(), receipt)
            .await?;
        let helm_key = ark_seed.helm_key(&helm_key_seed);

        let data_register = ark_seed.data_register();
        let data_key_seed = DataKeySeed::random();
        core.create_register(&data_register, data_key_seed.clone(), receipt)
            .await?;
        let data_key = ark_seed.data_key(&data_key_seed);

        core.create_encrypted_scratchpad(
            data_key
                .public_key()
                .encrypt_data_keyring(&core.derive_data_keyring(&ark_seed).await?),
            &ark_seed.data_keyring(),
            receipt,
        )
        .await?;

        let worker_register = helm_key.worker_register();
        let worker_key_seed = WorkerKeySeed::random();
        core.create_register(&worker_register, worker_key_seed.clone(), receipt)
            .await?;
        let worker_key = helm_key.worker_key(&worker_key_seed);

        let ark_address = ark_seed.address();
        let manifest = Manifest::new(&ark_address, settings);
        core.create_encrypted_scratchpad(
            worker_key.public_key().encrypt_manifest(&manifest),
            &helm_key.manifest(),
            receipt,
        )
        .await?;

        Ok(ArkCreationDetails {
            address: ark_address.clone(),
            mnemonic,
            helm_key,
            data_key,
            worker_key,
            ark: Ark::from(manifest),
        })
    }

    pub fn apply_manifest(&mut self, manifest: Manifest) -> usize {
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
pub struct ArkCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
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
    pub ark: Ark,
}
