use crate::manifest::VaultConfig;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub type VaultId = Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vault {
    id: Uuid,
    name: String,
    description: Option<String>,
    created: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    active: bool,
}

impl Vault {
    pub(crate) fn from_config(config: VaultConfig) -> Self {
        Self {
            id: config.id,
            name: config.name,
            description: config.description,
            created: config.created,
            last_modified: config.last_modified,
            active: config.active,
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub(crate) fn differs(&self, config: &VaultConfig) -> bool {
        if self.name != config.name
            || self.description != config.description
            || self.created != config.created
            || self.last_modified != config.last_modified
            || self.active != config.active
        {
            true
        } else {
            false
        }
    }

    pub(crate) fn apply(&mut self, config: VaultConfig) {
        self.name = config.name;
        self.description = config.description;
        self.created = config.created;
        self.last_modified = config.last_modified;
        self.active = config.active;
    }
}
