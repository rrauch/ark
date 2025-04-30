mod chunk;
mod keyring;
mod keys;
mod pointer;
mod register;
mod scratchpad;

use crate::crypto::keyring::KeyRing;
use crate::crypto::keys::{TypedDerivationIndex, TypedPublicKey, TypedSecretKey};
use crate::manifest::Manifest;
use anyhow::{anyhow, bail};
use autonomi::client::key_derivation::{DerivationIndex, MainSecretKey};
use autonomi::register::RegisterAddress;
use autonomi::{Client, PointerAddress, PublicKey, ScratchpadAddress, SecretKey, XorName};
use bip39::Mnemonic;
use blsttc::Ciphertext;
use bytes::Bytes;
use sn_bls_ckd::derive_master_sk;
use sn_curv::elliptic::curves::ECScalar;
use std::marker::PhantomData;
use zeroize::Zeroize;

pub(crate) use chunk::{TypedChunk, TypedChunkAddress};
pub(crate) use pointer::{TypedOwnedPointer, TypedPointerAddress};
pub(crate) use register::{TypedOwnedRegister, TypedRegisterAddress};
pub(crate) use scratchpad::{
    Content as ScratchpadContent, EncryptedContent as EncryptedScratchpadContent,
    PlaintextScratchpad, TypedOwnedScratchpad, TypedScratchpadAddress,
};

const HELM_REGISTER_NAME: &str = "/ark/v0/helm/register";
const DATA_REGISTER_NAME: &str = "/ark/v0/data/register";
const WORKER_REGISTER_NAME: &str = "/ark/v0/worker/register";
const MANIFEST_NAME: &str = "/ark/v0/manifest/scratchpad";
const MANIFEST_SCRATCHPAD_ENCODING: u64 = 344850175421548714;
const DATA_KEYRING_NAME: &str = "/ark/v0/data/keyring/scratchpad";
const DATA_KEYRING_SCRATCHPAD_ENCODING: u64 = 845573457394578892;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmRegisterKind;
pub type HelmRegister = TypedOwnedRegister<HelmRegisterKind, HelmKeySeed>;
pub type HelmRegisterAddress = TypedRegisterAddress<HelmRegisterKind, HelmKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmKeyKind;

impl Bech32Secret for HelmKeyKind {
    const HRP: &'static str = "arkhelmsec";
}

pub type HelmKeySeed = TypedDerivationIndex<HelmKeyKind>;
pub type HelmKey = TypedSecretKey<HelmKeyKind>;

impl HelmKey {
    pub fn worker_register(&self) -> WorkerRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            WORKER_REGISTER_NAME,
        ));

        WorkerRegister::new(owner)
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> WorkerKey {
        self.derive_child(seed)
    }

    pub fn manifest(&self) -> OwnedManifest {
        let owner = TypedSecretKey::new(key_from_name(self.as_ref(), MANIFEST_NAME));

        OwnedManifest::new(owner)
    }
}

impl ScratchpadContent for Manifest {
    const ENCODING: u64 = MANIFEST_SCRATCHPAD_ENCODING;
}

pub type OwnedManifest = TypedOwnedScratchpad<HelmKeyKind, EncryptedManifest>;

pub type ManifestAddress = TypedScratchpadAddress<HelmKeyKind, EncryptedManifest>;

pub type PublicHelmKey = TypedPublicKey<HelmKeyKind>;

impl PublicHelmKey {
    pub fn worker_register(&self) -> WorkerRegisterAddress {
        WorkerRegisterAddress::new(register_address_from_name(
            self.as_ref(),
            WORKER_REGISTER_NAME,
        ))
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> PublicWorkerKey {
        self.derive_child(seed)
    }

    pub fn manifest(&self) -> ManifestAddress {
        ManifestAddress::new(scratchpad_address_from_name(self.as_ref(), MANIFEST_NAME))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataRegisterKind;
pub type DataRegister = TypedOwnedRegister<DataRegisterKind, DataKeySeed>;
pub type DataRegisterAddress = TypedRegisterAddress<DataRegisterKind, DataKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataKeyKind;

impl Bech32Secret for DataKeyKind {
    const HRP: &'static str = "arkdatasec";
}

pub type DataKeySeed = TypedDerivationIndex<DataKeyKind>;
pub type DataKey = TypedSecretKey<DataKeyKind>;

impl DataKey {
    pub fn decrypt_data_keyring(
        &self,
        encrypted_keyring: &EncryptedDataKeyRing,
    ) -> anyhow::Result<DataKeyRing> {
        self.decrypt(encrypted_keyring)
    }
}

pub type SealKey = TypedPublicKey<DataKeyKind>;

impl SealKey {
    pub fn encrypt_data_keyring(&self, keyring: &DataKeyRing) -> EncryptedDataKeyRing {
        self.encrypt(keyring.clone())
    }
}

pub type DataKeyRing = KeyRing<DataKeyKind>;

impl ScratchpadContent for DataKeyRing {
    const ENCODING: u64 = DATA_KEYRING_SCRATCHPAD_ENCODING;
}

pub type EncryptedDataKeyRing = EncryptedData<DataKeyKind, DataKeyRing>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataKeyRingKind;

pub type DataKeyRingOwner =
    TypedOwnedScratchpad<DataKeyRingKind, EncryptedData<DataKeyKind, DataKeyRing>>;

pub type DataKeyRingAddress =
    TypedScratchpadAddress<DataKeyRingKind, EncryptedData<DataKeyKind, DataKeyRing>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerRegisterKind;

pub type WorkerRegister = TypedOwnedRegister<WorkerRegisterKind, WorkerKeySeed>;

pub type WorkerRegisterAddress = TypedRegisterAddress<WorkerRegisterKind, WorkerKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerKeyKind;

impl Bech32Secret for WorkerKeyKind {
    const HRP: &'static str = "arkworkersec";
}

pub type WorkerKeySeed = TypedDerivationIndex<WorkerKeyKind>;
pub type EncryptedManifest = EncryptedData<WorkerKeyKind, Manifest>;
pub type WorkerKey = TypedSecretKey<WorkerKeyKind>;

impl WorkerKey {
    pub fn decrypt_manifest(
        &self,
        encrypted_manifest: &EncryptedManifest,
    ) -> anyhow::Result<Manifest> {
        self.decrypt(encrypted_manifest)
    }
}

pub type PublicWorkerKey = TypedPublicKey<WorkerKeyKind>;

impl PublicWorkerKey {
    pub fn encrypt_manifest(&self, manifest: &Manifest) -> EncryptedManifest {
        self.encrypt(manifest.clone())
    }
}

impl TryFrom<Mnemonic> for ArkSeed {
    type Error = anyhow::Error;

    fn try_from(mut value: Mnemonic) -> Result<Self, Self::Error> {
        let mut seed = value.to_seed_normalized("");
        value.zeroize();
        let key_bytes = match eip2333(&seed) {
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

pub type ArkSeed = TypedSecretKey<ArkRoot>;

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
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            HELM_REGISTER_NAME,
        ));

        HelmRegister::new(owner)
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> HelmKey {
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            self.as_ref(),
            DATA_REGISTER_NAME,
        ));

        DataRegister::new(owner)
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> DataKey {
        self.derive_child(seed)
    }

    pub fn data_keyring(&self) -> DataKeyRingOwner {
        let owner = TypedSecretKey::new(key_from_name(self.as_ref(), DATA_KEYRING_NAME));

        DataKeyRingOwner::new(owner)
    }
}

impl Bech32Public for ArkRoot {
    const HRP: &'static str = "arkaddr";
}

pub type ArkAddress = TypedPublicKey<ArkRoot>;

impl ArkAddress {
    pub fn helm_register(&self) -> HelmRegisterAddress {
        HelmRegisterAddress::new(register_address_from_name(
            self.as_ref(),
            HELM_REGISTER_NAME,
        ))
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> PublicHelmKey {
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegisterAddress {
        DataRegisterAddress::new(register_address_from_name(
            self.as_ref(),
            DATA_REGISTER_NAME,
        ))
    }

    pub fn seal_key(&self, seed: &DataKeySeed) -> SealKey {
        self.derive_child(seed)
    }

    pub fn data_keyring(&self) -> DataKeyRingAddress {
        DataKeyRingAddress::new(scratchpad_address_from_name(
            self.as_ref(),
            DATA_KEYRING_NAME,
        ))
    }
}

pub trait Bech32Secret {
    const HRP: &'static str;
}

pub trait Bech32Public {
    const HRP: &'static str;
}

pub struct EncryptedData<T, V> {
    inner: Ciphertext,
    _type: PhantomData<T>,
    _value_type: PhantomData<V>,
}

impl<T, V: Terminable> Terminable for EncryptedData<T, V> {}

impl<T, V> EncryptedData<T, V> {
    fn from_ciphertext(inner: Ciphertext) -> Self {
        Self {
            inner,
            _type: Default::default(),
            _value_type: Default::default(),
        }
    }

    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        let ciphertext = Ciphertext::from_bytes(bytes.as_ref())?;
        if !ciphertext.verify() {
            bail!("ciphertext verification failed, not a valid ciphertext");
        }
        Ok(Self::from_ciphertext(ciphertext))
    }
}

impl<T, V> Into<Bytes> for EncryptedData<T, V> {
    fn into(self) -> Bytes {
        Bytes::from(self.inner.to_bytes())
    }
}

impl<T, V> TryFrom<Bytes> for EncryptedData<T, V> {
    type Error = anyhow::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        EncryptedData::try_from_bytes(value.as_ref())
    }
}

pub trait Terminable {}

fn eip2333(seed: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
    // Derive BLS12-381 master secret key from seed using EIP-2333 standard.
    // Guarantees a valid, non-zero scalar represented as 32 Big-Endian bytes.
    let key_bytes: [u8; 32] = derive_master_sk(seed.as_ref())
        .map_err(|e| anyhow!("derive_master_sk error: {}", e))?
        .serialize() // Get the 32-byte Big-Endian representation
        .into(); // Convert GenericArray<u8, 32> to [u8; 32]
    Ok(key_bytes)
}

fn key_from_name(owner: &SecretKey, name: &str) -> SecretKey {
    let main_key = MainSecretKey::new(owner.clone());
    let derivation_index = DerivationIndex::from_bytes(XorName::from_content(name.as_bytes()).0);
    main_key.derive_key(&derivation_index).into()
}

fn register_address_from_name(owner: &PublicKey, name: impl AsRef<str>) -> RegisterAddress {
    let derivation_index =
        DerivationIndex::from_bytes(XorName::from_content(name.as_ref().as_bytes()).0);
    RegisterAddress::new(owner.derive_child(derivation_index.as_bytes().as_slice()))
}

fn pointer_address_from_name(owner: &PublicKey, name: impl AsRef<str>) -> PointerAddress {
    let derivation_index =
        DerivationIndex::from_bytes(XorName::from_content(name.as_ref().as_bytes()).0);
    PointerAddress::new(owner.derive_child(derivation_index.as_bytes().as_slice()))
}

fn scratchpad_address_from_name(owner: &PublicKey, name: impl AsRef<str>) -> ScratchpadAddress {
    let derivation_index =
        DerivationIndex::from_bytes(XorName::from_content(name.as_ref().as_bytes()).0);
    ScratchpadAddress::new(owner.derive_child(derivation_index.as_bytes().as_slice()))
}
