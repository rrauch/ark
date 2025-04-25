mod crypto;
mod manifest;

use anyhow::{anyhow, bail};
use autonomi::client::payment::PaymentOption;
use autonomi::register::RegisterValue;
use autonomi::{Client, Wallet};
use bon::Builder;

use crate::crypto::{
    ArkAddress, ArkSeed, DataKey, DataKeySeed, EncryptedChunk, HelmKey, HelmKeySeed, TypedChunk,
    TypedChunkAddress, TypedOwnedPointer, TypedOwnedRegister, TypedPointerAddress,
    TypedRegisterAddress, WorkerKey, WorkerKeySeed,
};
use crate::manifest::Manifest;
use autonomi::pointer::PointerTarget;
use bytes::Bytes;
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Engine {
    client: Client,
    wallet: Wallet,
}

#[derive(Builder, Clone, Debug)]
pub struct ArkCreationSettings {
    #[builder(into)]
    name: String,
    description: Option<String>,
}

impl Engine {
    pub fn new(client: Client, wallet: Wallet) -> Self {
        Self { client, wallet }
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
            EncryptedChunk::from_value(worker_key.public_key().encrypt(manifest.clone()));
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
}
