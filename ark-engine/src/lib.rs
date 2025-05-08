mod util;

use crate::util::{Comparison, diff_maps};
use chrono::{DateTime, Utc};
use core::{ArkAddress, AutonomiClient, AutonomiWallet, Manifest, VaultConfig, VaultId};
use std::collections::HashMap;

pub struct Engine {
    client: AutonomiClient,
    wallet: AutonomiWallet,
}

pub struct Ark {
    address: ArkAddress,
    created: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    name: String,
    description: Option<String>,
    vaults: HashMap<VaultId, VaultConfig>,
}

impl Ark {
    pub(crate) fn apply_manifest(&mut self, manifest: Manifest) -> usize {
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
            self.vaults.insert(vault_id, config);
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vault {
    id: VaultId,
    name: String,
    description: Option<String>,
    created: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    active: bool,
}

impl Vault {
    pub(crate) fn apply_config(&mut self, config: VaultConfig) -> usize {
        let mut change_counter = 0;

        if self.name != config.name {
            self.name = config.name;
            change_counter += 1;
        }

        if self.description != config.description {
            self.description = config.description;
            change_counter += 1;
        }

        if self.created != config.created {
            self.created = config.created;
            change_counter += 1;
        }

        if self.last_modified != config.last_modified {
            self.last_modified = config.last_modified;
            change_counter += 1;
        }

        if self.active != config.active {
            self.active = config.active;
            change_counter += 1;
        }

        change_counter
    }
}
