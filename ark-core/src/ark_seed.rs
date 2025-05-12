use crate::crypto::Bech32Public;
use crate::data_key::{
    DataKeyRingAddress, DataKeyRingOwner, DataKeySeed, DataRegister, DataRegisterAddress,
};
use crate::helm_key::{HelmKeySeed, HelmRegister, HelmRegisterAddress};
use crate::{DataKey, HelmKey, PublicHelmKey, SealKey, WorkerKey};

use crate::{Core, Manifest, Progress, crypto, impl_decryptor_for, with_receipt};
use anyhow::bail;
use autonomi::Client;
use bip39::Mnemonic;
use blsttc::SecretKey;
use zeroize::Zeroize;

const DATA_KEYRING_NAME: &str = "/ark/v0/data/keyring/scratchpad";
const DATA_REGISTER_NAME: &str = "/ark/v0/data/register";
const HELM_REGISTER_NAME: &str = "/ark/v0/helm/register";

impl TryFrom<Mnemonic> for ArkSeed {
    type Error = anyhow::Error;

    fn try_from(mut value: Mnemonic) -> Result<Self, Self::Error> {
        let mut seed = value.to_seed_normalized("");
        value.zeroize();
        let key_bytes = match crypto::eip2333(&seed) {
            Ok(key_bytes) => key_bytes,
            Err(err) => {
                seed.zeroize();
                return Err(err);
            }
        };
        seed.zeroize();
        Ok(Self::new(SecretKey::from_bytes(key_bytes)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArkRoot;

pub type ArkSeed = crypto::TypedSecretKey<ArkRoot>;
impl_decryptor_for!(ArkSeed, Manifest);

impl ArkSeed {
    pub fn random() -> (Self, String) {
        let mnemonic = Mnemonic::generate(24).expect("24 to be a valid word count");
        let s = mnemonic.to_string();

        let this = Self::try_from(mnemonic).expect("generated mnemonic to lead to valid ark seed");
        (this, s)
    }

    pub fn try_from_mnemonic(mut s: String) -> anyhow::Result<Self> {
        let mnemonic = match Mnemonic::parse_normalized(s.as_str()) {
            Ok(mnemonic) => mnemonic,
            Err(err) => {
                s.zeroize();
                return Err(err.into());
            }
        };
        s.zeroize();

        Ok(Self::try_from(mnemonic)?)
    }

    pub fn address(&self) -> &ArkAddress {
        self.public_key()
    }

    pub fn helm_register(&self) -> HelmRegister {
        let owner = crate::crypto::TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            HELM_REGISTER_NAME,
        ));

        HelmRegister::new(owner)
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> HelmKey {
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegister {
        let owner = crypto::TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            DATA_REGISTER_NAME,
        ));

        DataRegister::new(owner)
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> DataKey {
        self.derive_child(seed)
    }

    pub fn data_keyring(&self) -> DataKeyRingOwner {
        let owner =
            crypto::TypedSecretKey::new(crypto::key_from_name(self.as_ref(), DATA_KEYRING_NAME));

        DataKeyRingOwner::new(owner)
    }
}

impl Bech32Public for ArkRoot {
    const HRP: &'static str = "arkaddr";
}

pub type ArkAddress = crypto::TypedPublicKey<ArkRoot>;

impl ArkAddress {
    pub fn helm_register(&self) -> HelmRegisterAddress {
        HelmRegisterAddress::new(crypto::register_address_from_name(
            self.as_ref(),
            HELM_REGISTER_NAME,
        ))
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> PublicHelmKey {
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegisterAddress {
        DataRegisterAddress::new(crypto::register_address_from_name(
            self.as_ref(),
            DATA_REGISTER_NAME,
        ))
    }

    pub fn seal_key(&self, seed: &DataKeySeed) -> SealKey {
        self.derive_child(seed)
    }

    pub fn data_keyring(&self) -> DataKeyRingAddress {
        DataKeyRingAddress::new(crypto::scratchpad_address_from_name(
            self.as_ref(),
            DATA_KEYRING_NAME,
        ))
    }
}

impl Core {
    pub(super) fn verify_ark_seed(&self, ark_seed: &ArkSeed) -> anyhow::Result<()> {
        if &self.ark_address != ark_seed.address() {
            bail!("ark_seed not valid for ark_address [{}]", self.ark_address);
        }
        Ok(())
    }

    pub fn rotate_all_keys<'a>(
        &'a self,
        ark_seed: &'a ArkSeed,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<(DataKey, HelmKey, WorkerKey)>> + Send + 'a,
    ) {
        let (progress, mut task) = Progress::new(1, "Full Ark Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                task.start();
                let mut verify_seed = task.child(1, "Verify Ark Seed".to_string());
                let mut hw_keys = task.child(1, "Helm and Worker Key".to_string());
                let data_key_task = task.child(1, "Data Key".to_string());
                verify_seed.start();
                self.verify_ark_seed(ark_seed)?;
                verify_seed.complete();

                hw_keys.start();
                let (helm_key, worker_key) = self
                    ._rotate_helm_key(
                        &ark_seed,
                        receipt,
                        task.child(1, "Rotate Helm Key".to_string()),
                    )
                    .await?;
                hw_keys.complete();
                let data_key = self
                    ._rotate_data_key(ark_seed, receipt, data_key_task)
                    .await?;
                task.complete();
                Ok((data_key, helm_key, worker_key))
            }),
        )
    }
}
