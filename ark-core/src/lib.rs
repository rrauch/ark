mod announcement;
mod ark;
mod ark_seed;
mod autonomi_config;
mod bridge_key;
mod crypto;
mod data_key;
mod helm_key;
mod manifest;
pub(crate) mod objects;
mod progress;
mod vault;
mod worker_key;

pub use ark::{ArkAccessor, ArkCreationDetails, ArkCreationSettings};
pub use ark_seed::{ArkAddress, ArkSeed};
pub use autonomi::{Client as AutonomiClient, Wallet as EvmWallet};
pub use autonomi_config::ClientConfig as AutonomiClientConfig;
pub use bridge_key::{BridgeAddress, BridgeKey};
pub use chrono::{DateTime, Utc};
pub use data_key::{DataKey, SealKey};
pub use helm_key::{HelmKey, PublicHelmKey};
pub use manifest::Manifest;
pub use objects::ObjectType;
pub use progress::{Progress, Report as ProgressReport, Status as ProgressStatus};
pub use vault::{VaultAddress, VaultConfig, VaultCreationSettings};
pub use worker_key::{EitherWorkerKey, PublicWorkerKey, RetiredWorkerKey, WorkerKey};

use crate::crypto::{TypedChunk, TypedChunkAddress};
use anyhow::bail;
use autonomi::client::payment::PaymentOption;
use autonomi::register::{RegisterAddress, RegisterValue};
use autonomi::{AttoTokens, Pointer, PointerAddress, Scratchpad, ScratchpadAddress};
use bon::bon;
use bytes::Bytes;
use moka::future::Cache;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::AddAssign;
use std::time::Duration;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct LineItem {
    cost: AttoTokens,
    timestamp: DateTime<Utc>,
}
pub struct Receipt {
    items: Vec<LineItem>,
}

impl AddAssign for Receipt {
    fn add_assign(&mut self, mut rhs: Self) {
        self.items.append(&mut rhs.items);
    }
}

impl Receipt {
    fn new() -> Self {
        Self {
            items: Vec::default(),
        }
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LineItem> {
        self.items.iter()
    }

    pub fn total_cost(&self) -> AttoTokens {
        let mut attos = AttoTokens::zero();
        self.items
            .iter()
            .for_each(|i| attos = attos.checked_add(i.cost).expect("attos not to overflow"));
        attos
    }

    pub(crate) fn add(&mut self, cost: AttoTokens) {
        self.items.push(LineItem {
            cost,
            timestamp: Utc::now(),
        })
    }
}

pub type CostlyResult<T, E> = core::result::Result<(T, Receipt), (E, Receipt)>;
pub type Result<T> = CostlyResult<T, anyhow::Error>;

async fn with_receipt<T>(f: impl AsyncFnOnce(&mut Receipt) -> anyhow::Result<T>) -> Result<T> {
    let mut receipt = Receipt::new();
    match f(&mut receipt).await {
        Ok(ok) => Ok((ok, receipt)),
        Err(err) => Err((err.into(), receipt)),
    }
}

pub struct Core {
    client: AutonomiClient,
    wallet: EvmWallet,
    ark_address: ArkAddress,
    register_cache: Cache<RegisterAddress, Option<RegisterValue>>,
    register_history_cache: Cache<RegisterAddress, Vec<RegisterValue>>,
    pointer_cache: Cache<PointerAddress, Option<Pointer>>,
    scratchpad_cache: Cache<ScratchpadAddress, Option<Scratchpad>>,
}

#[bon]
impl Core {
    #[builder]
    pub fn new(
        client: AutonomiClient,
        wallet: EvmWallet,
        ark_address: ArkAddress,
        #[builder(default = Duration::from_secs(3600))] cache_ttl: Duration,
        #[builder(default = Duration::from_secs(900))] cache_tti: Duration,
        #[builder(default = 1000)] register_cache_capacity: u64,
        #[builder(default = 200)] register_history_cache_capacity: u64,
        #[builder(default = 1000)] pointer_cache_capacity: u64,
        #[builder(default = 1024 * 1024 * 8)] scratchpad_cache_capacity: u64,
    ) -> Self {
        Self {
            client,
            wallet,
            ark_address,
            register_cache: Cache::builder()
                .name("register_cache")
                .time_to_live(cache_ttl)
                .time_to_idle(cache_tti)
                .max_capacity(register_cache_capacity)
                .build(),
            register_history_cache: Cache::builder()
                .name("register_history_cache")
                .time_to_live(cache_ttl)
                .time_to_idle(cache_tti)
                .max_capacity(register_history_cache_capacity)
                .build(),
            pointer_cache: Cache::builder()
                .name("pointer_cache")
                .time_to_live(cache_ttl)
                .time_to_idle(cache_tti)
                .max_capacity(pointer_cache_capacity)
                .build(),
            scratchpad_cache: Cache::builder()
                .name("scratchpad_cache")
                .time_to_live(cache_ttl)
                .time_to_idle(cache_tti)
                .max_capacity(scratchpad_cache_capacity)
                .weigher(|_, pad: &Option<Scratchpad>| {
                    pad.as_ref().map(|p| p.size() as u32).unwrap_or(1)
                })
                .build(),
        }
    }

    async fn put_chunk<T>(
        &self,
        chunk: &TypedChunk<T>,
        receipt: &mut Receipt,
    ) -> anyhow::Result<()> {
        let (attos, address) = self
            .client
            .chunk_put(chunk.as_ref(), self.payment())
            .await?;
        receipt.add(attos);
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

    fn payment(&self) -> PaymentOption {
        PaymentOption::Wallet(self.wallet.clone())
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypedUuid<T> {
    inner: Uuid,
    _type: PhantomData<T>,
}

impl<T> Display for TypedUuid<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl<T> AsRef<Uuid> for TypedUuid<T> {
    fn as_ref(&self) -> &Uuid {
        &self.inner
    }
}

impl<T> TypedUuid<T> {
    pub(crate) fn new(inner: Uuid) -> Self {
        Self {
            inner,
            _type: Default::default(),
        }
    }

    pub fn into_inner(self) -> Uuid {
        self.inner
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct ConfidentialString(String);

impl From<String> for ConfidentialString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Debug for ConfidentialString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted>")
    }
}

impl AsRef<str> for ConfidentialString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

mod protos {
    use crate::crypto::{Bech32Public, Bech32Secret, Retirable, TypedPublicKey, TypedSecretKey};
    use anyhow::{Context, anyhow, bail};
    use bytes::{Buf, BufMut, Bytes, BytesMut};
    use chrono::{DateTime, Utc};
    use prost::Message;
    use std::fmt::Display;
    use std::str::FromStr;

    include!(concat!(env!("OUT_DIR"), "/protos/common.rs"));

    impl<T: Bech32Public> From<TypedPublicKey<T>> for Address {
        fn from(value: TypedPublicKey<T>) -> Self {
            Self {
                bech32: value.to_string(),
            }
        }
    }

    impl<T: Bech32Public> TryFrom<Address> for TypedPublicKey<T> {
        type Error = anyhow::Error;

        fn try_from(value: Address) -> Result<Self, Self::Error> {
            Self::from_str(value.bech32.as_str())
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

    impl<T: Bech32Secret> From<TypedSecretKey<T>> for SecretKey {
        fn from(value: TypedSecretKey<T>) -> Self {
            Self {
                bech32: value.danger_to_string(),
            }
        }
    }

    impl<T: Bech32Secret> TryFrom<SecretKey> for TypedSecretKey<T> {
        type Error = anyhow::Error;

        fn try_from(value: SecretKey) -> Result<Self, Self::Error> {
            Self::from_str(value.bech32.as_str())
        }
    }

    impl<T: Bech32Public> From<TypedPublicKey<T>> for PublicKey {
        fn from(value: TypedPublicKey<T>) -> Self {
            Self {
                bech32: value.to_string(),
            }
        }
    }

    impl<T: Bech32Public> TryFrom<PublicKey> for TypedPublicKey<T> {
        type Error = anyhow::Error;

        fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
            Self::from_str(value.bech32.as_str())
        }
    }

    impl<T> From<crate::crypto::RetiredKey<T>> for RetiredKey
    where
        PublicKey: From<TypedPublicKey<T>>,
        T: Retirable,
    {
        fn from(value: crate::crypto::RetiredKey<T>) -> Self {
            Self {
                retired_at: Some(value.retired_at().clone().into()),
                public_key: Some(value.into_inner().into()),
            }
        }
    }

    impl<T> TryFrom<RetiredKey> for crate::crypto::RetiredKey<T>
    where
        TypedPublicKey<T>: TryFrom<PublicKey>,
        <TypedPublicKey<T> as TryFrom<PublicKey>>::Error: Display,
        T: Retirable,
    {
        type Error = anyhow::Error;

        fn try_from(value: RetiredKey) -> Result<Self, Self::Error> {
            Ok(Self::new(
                value
                    .public_key
                    .map(|pk| pk.try_into().map_err(|e| anyhow!("{}", e)))
                    .transpose()?
                    .ok_or(anyhow!("public_key is missing"))?,
                value
                    .retired_at
                    .map(|r| r.try_into())
                    .transpose()?
                    .ok_or(anyhow!("retired_at is missing"))?,
            ))
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
    pub(crate) fn serialize_with_header<M, H>(message: &M, magic_number: H) -> Bytes
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
    pub(crate) fn deserialize_with_header<T, H>(
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
