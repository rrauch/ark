mod crypto;
mod engine;
mod manifest;
mod util;
mod vault;

use bon::Builder;
use std::collections::HashMap;

use crate::crypto::{ArkAddress, DataKey, HelmKey, WorkerKey};
use crate::manifest::{Manifest, VaultConfig};
use crate::util::{diff_maps, Comparison};
use crate::vault::{Vault, VaultId};
use chrono::{DateTime, Utc};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use crypto::ArkSeed;
pub use engine::Engine;

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
    use anyhow::{anyhow, bail, Context};
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use chrono::{DateTime, Utc};
    use prost::Message;
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

    /// Serializes a Protobuf message by prepending a fixed magic number header.
    ///
    /// # Arguments
    /// * `message`: The Protobuf message to serialize.
    /// * `magic_number`: The byte slice representing the magic number to prepend.
    ///
    /// # Returns
    /// * `Bytes` containing the header followed by the encoded message.
    pub fn serialize_with_header<M, H>(message: &M, magic_number: H) -> Bytes
    where
        M: Message,
        H: AsRef<[u8]>,
    {
        let magic_bytes = magic_number.as_ref();
        let header_len = magic_bytes.len();
        let msg_len = message.encoded_len();
        let total_len = header_len + msg_len;
        let mut buf = BytesMut::with_capacity(total_len);

        buf.put(magic_bytes);
        message
            .encode(&mut buf)
            .expect("Encoding to BytesMut with sufficient capacity should not fail");

        buf.freeze()
    }

    /// Deserializes data into a Protobuf message, expecting a fixed magic number header.
    ///
    /// # Arguments
    /// * `data`: The raw byte slice containing the header and message.
    /// * `magic_number`: The expected magic number byte slice.
    ///
    /// # Type Parameters
    /// * `T`: The target Protobuf message type (must implement `prost::Message` and `Default`).
    ///
    /// # Returns
    /// * `Result<T>` containing the decoded Protobuf message or an error.
    pub fn deserialize_with_header<T, H>(
        data: impl AsRef<[u8]>,
        magic_number: H,
    ) -> anyhow::Result<T>
    where
        T: Message + Default,
        H: AsRef<[u8]>,
    {
        let mut buf = data.as_ref();
        let magic_bytes = magic_number.as_ref();
        let header_len = magic_bytes.len();

        if buf.len() < header_len {
            bail!(
                "data too short ({} bytes) to contain header ({} bytes)",
                buf.len(),
                header_len
            );
        }

        // Check the header without consuming the original buffer reference yet
        if &buf[..header_len] != magic_bytes {
            bail!("invalid data format: header mismatch");
        }

        // Advance the buffer reference *past* the header for decoding
        buf.advance(header_len);

        // Decode the *remaining* part of the buffer
        T::decode(buf).context("failed to decode Protobuf message after header")
    }
}
