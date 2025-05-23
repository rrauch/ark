use crate::crypto::Bech32Public;
use crate::data_key::DataKeySeed;
use crate::{ConfidentialString, DataKey, EitherWorkerKey, HelmKey, PublicWorkerKey, SealKey};

use crate::{Core, Progress, crypto, with_receipt};
use anyhow::bail;
use autonomi::PointerAddress;
use autonomi::pointer::PointerTarget;
use bip39::Mnemonic;
use blsttc::SecretKey;
use zeroize::Zeroize;

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

impl ArkSeed {
    pub fn random() -> (Self, ConfidentialString) {
        let mnemonic = Mnemonic::generate(24).expect("24 to be a valid word count");
        let s = mnemonic.to_string().into();

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
}

impl Bech32Public for ArkRoot {
    const HRP: &'static str = "arkaddr";
}

pub type ArkAddress = crypto::TypedPublicKey<ArkRoot>;

impl ArkAddress {
    pub fn seal_key(&self, seed: &DataKeySeed) -> SealKey {
        self.derive_child(seed)
    }
}

impl From<ArkAddress> for PointerTarget {
    fn from(value: ArkAddress) -> Self {
        PointerTarget::PointerAddress(PointerAddress::new(value.as_ref().clone()))
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
        new_worker_key: Option<PublicWorkerKey>,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<(DataKey, HelmKey, EitherWorkerKey)>> + Send + 'a,
    ) {
        let (progress, mut task) = Progress::new(1, "Full Ark Key Rotation".to_string());
        (
            progress,
            with_receipt(async move |receipt| {
                task.start();
                let mut verify_seed = task.child(1, "Verify Ark Seed".to_string());
                let helm_key_task = task.child(2, "Helm Key".to_string());
                let worker_key_task = task.child(1, "Worker Key".to_string());
                let data_key_task = task.child(1, "Data Key".to_string());

                verify_seed.start();
                self.verify_ark_seed(ark_seed)?;
                verify_seed.complete();

                let helm_key = self
                    ._rotate_helm_key(&ark_seed, receipt, helm_key_task)
                    .await?;

                let new_worker_key = self
                    ._rotate_worker_key(&helm_key, new_worker_key, receipt, worker_key_task)
                    .await?;

                let data_key = self
                    ._rotate_data_key(ark_seed, receipt, data_key_task)
                    .await?;

                task.complete();
                Ok((data_key, helm_key, new_worker_key))
            }),
        )
    }
}
