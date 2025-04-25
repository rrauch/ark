mod keys;

use anyhow::{anyhow, bail};
use autonomi::client::payment::PaymentOption;
use autonomi::register::RegisterValue;
use autonomi::{Client, Wallet};

use crate::keys::{
    ArkAddress, ArkSeed, DataKey, DataKeySeed, HelmKey, HelmKeySeed, TypedOwnedRegister,
    TypedRegisterAddress, WorkerKey, WorkerKeySeed,
};
use std::fmt::Display;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub struct Worker {
    client: Client,
    wallet: Wallet,
}

impl Worker {
    pub fn new(client: Client, wallet: Wallet) -> Self {
        Self { client, wallet }
    }

    pub async fn create_ark(&mut self) -> anyhow::Result<ArkCreationDetails> {
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

        Ok(ArkCreationDetails {
            address: ark_seed.address(),
            mnemonic,
            helm_key,
            data_key,
            worker_key,
        })
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
            .map(|e| V::try_from(e).map_err(|e| anyhow!("{}", e)))??)
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
}
