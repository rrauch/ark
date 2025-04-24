use anyhow::{anyhow, bail};
use argon2::Argon2;
use autonomi::client::key_derivation::DerivationIndex;
use autonomi::register::RegisterAddress;
use autonomi::{Client, PublicKey, SecretKey, XorName};
use bech32::{Bech32m, EncodeError, Hrp};
use bip39::Mnemonic;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use zeroize::Zeroize;

const SEED_SALT: &str = "/ark/v0/seed";
const HELM_REGISTER_NAME: &str = "/ark/v0/helm/register";
const HELM_KEY_SALT: &str = "/ark/v0/helm/key";
const DATA_REGISTER_NAME: &str = "/ark/v0/data/register";
const DATA_KEY_SALT: &str = "/ark/v0/data/key";

const WORKER_REGISTER_NAME: &str = "/ark/v0/worker/register";
const WORKER_KEY_SALT: &str = "/ark/v0/worker/key";

#[derive(Clone, PartialEq, Eq)]
struct KeyMaterial(Option<[u8; 32]>);

impl From<[u8; 32]> for KeyMaterial {
    fn from(value: [u8; 32]) -> Self {
        Self(Some(value))
    }
}

impl TryInto<SecretKey> for KeyMaterial {
    type Error = anyhow::Error;

    fn try_into(mut self) -> Result<SecretKey, Self::Error> {
        match self.0.take() {
            Some(bytes) => Ok(SecretKey::from_bytes(bytes)?),
            None => {
                bail!("bytes already taken")
            }
        }
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        if let Some(mut bytes) = self.0.take() {
            bytes.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Seed<T> {
    bytes: KeyMaterial,
    _type: PhantomData<T>,
}

impl<T: Kdf> Seed<T> {
    fn try_from_bytes(bytes: impl AsRef<[u8]>) -> anyhow::Result<Self> {
        Ok(Self {
            bytes: KeyMaterial::from(T::derive_key(bytes)?),
            _type: Default::default(),
        })
    }
}

impl<T> Seed<T> {
    fn key_material(&self) -> &KeyMaterial {
        &self.bytes
    }
}

impl<T> TryInto<TypedSecretKey<T>> for Seed<T> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<TypedSecretKey<T>, Self::Error> {
        Ok(TypedSecretKey::new(self.bytes.try_into()?))
    }
}

trait Kdf {
    fn derive_key(input: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]>;
}

struct TypedDerivationIndex<T> {
    inner: DerivationIndex,
    _type: PhantomData<T>,
}

impl<T> From<&Seed<T>> for TypedDerivationIndex<T> {
    fn from(value: &Seed<T>) -> Self {
        value.key_material().clone().0.unwrap().into()
    }
}

impl<T> From<[u8; 32]> for TypedDerivationIndex<T> {
    fn from(value: [u8; 32]) -> Self {
        let inner = DerivationIndex::from_bytes(value);
        Self {
            inner,
            _type: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSecretKey<T> {
    inner: SecretKey,
    public_key: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    fn new(inner: SecretKey) -> Self {
        let public_key = TypedPublicKey::new(inner.public_key());
        Self { inner, public_key }
    }

    pub fn public_key(&self) -> &TypedPublicKey<T> {
        &self.public_key
    }

    fn derive_child_from_seed<C>(&self, seed: &Seed<C>) -> TypedSecretKey<C> {
        let idx = TypedDerivationIndex::from(seed);
        self.derive_child(&idx)
    }

    fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedSecretKey<C> {
        TypedSecretKey::new(self.inner.derive_child(idx.inner.as_bytes()))
    }
}

impl<T: Bech32Secret> TypedSecretKey<T> {
    pub fn danger_to_string(&self) -> String {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        bech32::encode::<Bech32m>(hrp, self.inner.to_bytes().as_slice())
            .expect("bytes to be encodable")
    }
}

impl<T: Bech32Secret> FromStr for TypedSecretKey<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        Ok(Self::new(secret_key_from_bech32(&hrp, s)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedPublicKey<T> {
    inner: PublicKey,
    _type: PhantomData<T>,
}

trait Bech32Public {
    const HRP: &'static str;
}

trait Bech32Secret {
    const HRP: &'static str;
}

impl<T> TypedPublicKey<T> {
    fn new(inner: PublicKey) -> Self {
        Self {
            inner,
            _type: Default::default(),
        }
    }

    fn derive_child_from_seed<C>(&self, seed: &Seed<C>) -> TypedPublicKey<C> {
        let idx = TypedDerivationIndex::from(seed);
        self.derive_child(&idx)
    }

    fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedPublicKey<C> {
        TypedPublicKey::new(self.inner.derive_child(idx.inner.as_bytes()))
    }
}

impl<T: Bech32Public> Display for TypedPublicKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        bech32::encode_to_fmt::<Bech32m, _>(f, hrp, &self.inner.to_bytes().as_ref()).map_err(|e| {
            match e {
                EncodeError::Fmt(e) => e,
                _ => {
                    // not really sure what to do here
                    panic!("{}", e)
                }
            }
        })
    }
}

impl<T: Bech32Public> FromStr for TypedPublicKey<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        Ok(Self::new(public_key_from_bech32(&hrp, s)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedOwnedRegister<T, V> {
    owner: TypedSecretKey<T>,
    address: TypedRegisterAddress<T, V>,
}

impl<T, V> TypedOwnedRegister<T, V> {
    fn new(owner: TypedSecretKey<T>) -> Self {
        let address = TypedRegisterAddress::new(RegisterAddress::new(owner.public_key().inner));
        Self { owner, address }
    }

    pub fn owner(&self) -> &TypedSecretKey<T> {
        &self.owner
    }

    pub fn address(&self) -> &TypedRegisterAddress<T, V> {
        &self.address
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedRegisterAddress<T, V> {
    inner: RegisterAddress,
    owner: TypedPublicKey<T>,
    _type: PhantomData<T>,
    _value_type: PhantomData<V>,
}

impl<T, V> TypedRegisterAddress<T, V> {
    fn new(inner: RegisterAddress) -> Self {
        let owner = TypedPublicKey::new(inner.owner());
        Self {
            inner,
            owner,
            _type: Default::default(),
            _value_type: Default::default(),
        }
    }

    pub fn owner(&self) -> &TypedPublicKey<T> {
        &self.owner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmRegisterKind;
pub type HelmRegister = TypedOwnedRegister<HelmRegisterKind, HelmKeySeed>;
pub type HelmRegisterAddress = TypedRegisterAddress<HelmRegisterKind, HelmKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HelmKeyKind;

impl Bech32Secret for HelmKeyKind {
    const HRP: &'static str = "arkhelmsec";
}

impl Kdf for HelmKeyKind {
    fn derive_key(input: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
        argon2id_kdf(input, HELM_KEY_SALT)
    }
}

pub type HelmKeySeed = Seed<HelmKeyKind>;
pub type HelmKey = TypedSecretKey<HelmKeyKind>;

impl HelmKey {
    pub fn worker_register(&self) -> WorkerRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            &self.inner,
            WORKER_REGISTER_NAME,
        ));

        WorkerRegister::new(owner)
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> WorkerKey {
        self.derive_child_from_seed(seed)
    }
}

pub type PublicHelmKey = TypedPublicKey<HelmKeyKind>;

impl PublicHelmKey {
    pub fn worker_register(&self) -> WorkerRegisterAddress {
        WorkerRegisterAddress::new(register_address_from_name(
            &self.inner,
            WORKER_REGISTER_NAME,
        ))
    }

    pub fn worker_key(&self, seed: &WorkerKeySeed) -> PublicWorkerKey {
        self.derive_child_from_seed(seed)
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

impl Kdf for DataKeyKind {
    fn derive_key(input: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
        argon2id_kdf(input, DATA_KEY_SALT)
    }
}

pub type DataKeySeed = Seed<DataKeyKind>;
pub type DataKey = TypedSecretKey<DataKeyKind>;
pub type PublicDataKey = TypedPublicKey<DataKeyKind>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerRegisterKind;

pub type WorkerRegister = TypedOwnedRegister<WorkerRegisterKind, WorkerKeySeed>;

pub type WorkerRegisterAddress = TypedRegisterAddress<WorkerRegisterKind, WorkerKeySeed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkerKeyKind;

impl Bech32Secret for WorkerKeyKind {
    const HRP: &'static str = "arkworkersec";
}

impl Kdf for WorkerKeyKind {
    fn derive_key(input: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
        argon2id_kdf(input, WORKER_KEY_SALT)
    }
}

pub type WorkerKeySeed = Seed<WorkerKeyKind>;
pub type WorkerKey = TypedSecretKey<WorkerKeyKind>;
pub type PublicWorkerKey = TypedPublicKey<WorkerKeyKind>;

impl TryFrom<Mnemonic> for Seed<ArkSeedKind> {
    type Error = anyhow::Error;

    fn try_from(value: Mnemonic) -> Result<Self, Self::Error> {
        Seed::try_from_bytes(value.to_entropy_array().0.as_slice())
    }
}

pub struct ArkSeedKind;

impl Kdf for ArkSeedKind {
    fn derive_key(input: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
        argon2id_kdf(&input, SEED_SALT)
    }
}

pub type ArkSeed = TypedSecretKey<ArkSeedKind>;

impl ArkSeed {
    pub fn random() -> (Self, String) {
        let mnemonic = Mnemonic::generate(24).expect("24 to be a valid word count");
        // todo: zeroize?
        let s = mnemonic.to_string();

        let this = Self::_try_from_mnemonic(mnemonic)
            .expect("generated mnemonic to lead to valid ark seed");
        (this, s)
    }

    pub fn try_from_mnemonic(s: impl AsRef<str>) -> anyhow::Result<Self> {
        Self::_try_from_mnemonic(Mnemonic::parse_normalized(s.as_ref())?)
    }

    fn _try_from_mnemonic(mnemonic: Mnemonic) -> anyhow::Result<Self> {
        Ok(Seed::<ArkSeedKind>::try_from(mnemonic)?.try_into()?)
    }

    pub fn address(&self) -> ArkAddress {
        ArkAddress::new(self.inner.public_key())
    }

    pub fn helm_register(&self) -> HelmRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            &self.inner,
            HELM_REGISTER_NAME,
        ));

        HelmRegister::new(owner)
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> HelmKey {
        self.derive_child_from_seed(seed)
    }

    pub fn data_register(&self) -> DataRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            &self.inner,
            DATA_REGISTER_NAME,
        ));

        DataRegister::new(owner)
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> DataKey {
        self.derive_child_from_seed(seed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArkAddressKind;

impl Bech32Public for ArkAddressKind {
    const HRP: &'static str = "arkaddr";
}

pub type ArkAddress = TypedPublicKey<ArkAddressKind>;

impl ArkAddress {
    pub fn helm_register(&self) -> HelmRegisterAddress {
        HelmRegisterAddress::new(register_address_from_name(&self.inner, HELM_REGISTER_NAME))
    }

    pub fn helm_key(&self, seed: &HelmKeySeed) -> PublicHelmKey {
        self.derive_child_from_seed(seed)
    }

    pub fn data_register(&self) -> DataRegisterAddress {
        DataRegisterAddress::new(register_address_from_name(&self.inner, DATA_REGISTER_NAME))
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> PublicDataKey {
        self.derive_child_from_seed(seed)
    }
}

fn register_address_from_name(owner: &PublicKey, name: impl AsRef<str>) -> RegisterAddress {
    let derivation_index =
        DerivationIndex::from_bytes(XorName::from_content(name.as_ref().as_bytes()).0);
    RegisterAddress::new(owner.derive_child(derivation_index.as_bytes().as_slice()))
}

fn public_key_from_bech32(expected_hrp: &Hrp, input: impl AsRef<str>) -> anyhow::Result<PublicKey> {
    let (hrp, bytes) = bech32::decode(input.as_ref())?;
    if &hrp != expected_hrp {
        bail!("hrp [{}] != [{}]", hrp, expected_hrp);
    };
    if bytes.len() != 48 {
        bail!("invalid key len: [{}] != [{}]", bytes.len(), 48);
    }
    Ok(PublicKey::from_bytes(
        bytes.try_into().expect("byte vec of len 48"),
    )?)
}

fn secret_key_from_bech32(expected_hrp: &Hrp, input: impl AsRef<str>) -> anyhow::Result<SecretKey> {
    //todo: zeroize?
    let (hrp, bytes) = bech32::decode(input.as_ref())?;
    if &hrp != expected_hrp {
        bail!("hrp [{}] != [{}]", hrp, expected_hrp);
    };
    if bytes.len() != 32 {
        bail!("invalid key len: [{}] != [{}]", bytes.len(), 32);
    }
    Ok(SecretKey::from_bytes(
        bytes.try_into().expect("byte vec of len 48"),
    )?)
}

// --- SHAVING STEP (Big-Endian) ---
// Context:
// BLS12-381 scalar field elements must be in a 'canonical' range [0, q-1],
// where q is the scalar field modulus.
// The modulus q is a large prime, slightly less than 2^255.
// The 32 bytes derived from the seed represent a 256-bit number (2^256 - 1 max value).
// This number *could* be >= q, which is not allowed by SecretKey::from_bytes
// (it expects the number represented by the bytes to be < q).

// Action:
// To ensure the 256-bit number is overwhelmingly likely to be < q,
// we force its highest possible bit (the 2^255 position) to zero.
// In a 32-byte big-endian representation, the 2^255 bit is the
// most significant bit (MSB) of the first byte (index 0).
// The bitmask 0x7F (binary 01111111) is applied using bitwise AND (&).
// This clears the MSB (bit 7) while leaving bits 0-6 unchanged.

// Why:
// By clearing the 2^255 bit, the resulting 256-bit number is mathematically
// guaranteed to be strictly less than 2^255. Since q is only slightly
// less than 2^255, any number < 2^255 is almost certainly also < q.
// This satisfies the canonical requirement for SecretKey::from_bytes
// with extremely high probability (~1 - 2^-128 failure rate).
fn shave(seed: &mut [u8; 32]) {
    seed[0] &= 0x7F;
}

fn argon2id_kdf(input: impl AsRef<[u8]>, salt: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    Argon2::default()
        .hash_password_into(input.as_ref(), salt.as_ref(), &mut seed)
        .map_err(|e| anyhow!("argon2 error: {}", e))?;
    shave(&mut seed);
    Ok(seed)
}
