use anyhow::{anyhow, bail};
use autonomi::client::key_derivation::DerivationIndex;
use autonomi::client::payment::PaymentOption;
use autonomi::register::{RegisterAddress, RegisterValue};
use autonomi::{Client, PublicKey, SecretKey, Wallet, XorName};
use bech32::{Bech32m, EncodeError, Hrp};
use bip39::Mnemonic;
use sn_bls_ckd::derive_master_sk;
use sn_curv::elliptic::curves::ECScalar;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;
use zeroize::{Zeroize, ZeroizeOnDrop};

const HELM_REGISTER_NAME: &str = "/ark/v0/helm/register";
const DATA_REGISTER_NAME: &str = "/ark/v0/data/register";
const WORKER_REGISTER_NAME: &str = "/ark/v0/worker/register";

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
            .register_create(register.owner.as_ref(), value.into(), self.payment())
            .await?
            .1;
        if &register.address.inner != &address {
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
            .register_get(&address.inner)
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

impl<T> From<[u8; 32]> for TypedDerivationIndex<T> {
    fn from(value: [u8; 32]) -> Self {
        Self {
            inner: DerivationIndex::from_bytes(value),
            _type: Default::default(),
        }
    }
}

impl<T> TryFrom<&[u8]> for TypedDerivationIndex<T> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            bail!("value length [{}] != 32", value.len());
        }
        let value: [u8; 32] = value.try_into()?;
        Ok(Self::from(value))
    }
}

impl<T> Into<RegisterValue> for TypedDerivationIndex<T> {
    fn into(self) -> RegisterValue {
        self.inner.into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedDerivationIndex<T> {
    inner: DerivationIndex,
    _type: PhantomData<T>,
}

impl<T> TypedDerivationIndex<T> {
    fn random() -> Self {
        let seed: [u8; 32] = rand::random();
        Self::from(seed)
    }
}

#[derive(Zeroize, Debug, Clone, PartialEq, Eq)]
pub struct TypedSecretKey<T> {
    inner: SecretKey,
    #[zeroize(skip)]
    public_key: TypedPublicKey<T>,
}

impl<T> TypedSecretKey<T> {
    fn new(inner: SecretKey) -> Self {
        let public_key = TypedPublicKey::new(inner.public_key());
        Self { inner, public_key }
    }

    fn public_key(&self) -> &TypedPublicKey<T> {
        &self.public_key
    }

    fn derive_child<C>(&self, idx: &TypedDerivationIndex<C>) -> TypedSecretKey<C> {
        TypedSecretKey::new(self.inner.derive_child(idx.inner.as_bytes()))
    }

    fn as_ref(&self) -> &SecretKey {
        &self.inner
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
        let expected_hrp = Hrp::parse(T::HRP).expect("hrp to be valid");
        let (hrp, mut bytes) = bech32::decode(s.as_ref())?;
        if hrp != expected_hrp {
            bytes.zeroize();
            bail!("hrp [{}] != [{}]", hrp, expected_hrp);
        };
        if bytes.len() != 32 {
            bytes.zeroize();
            bail!("invalid key len: [{}] != [{}]", bytes.len(), 32);
        }

        Ok(Self::new(SecretKey::from_bytes(
            bytes.try_into().expect("byte vec of len 32"),
        )?))
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
        let expected_hrp = Hrp::parse(T::HRP).expect("hrp to be valid");

        let (hrp, bytes) = bech32::decode(s.as_ref())?;
        if hrp != expected_hrp {
            bail!("hrp [{}] != [{}]", hrp, expected_hrp);
        };
        if bytes.len() != 48 {
            bail!("invalid key len: [{}] != [{}]", bytes.len(), 48);
        }
        Ok(Self::new(PublicKey::from_bytes(
            bytes.try_into().expect("byte vec of len 48"),
        )?))
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

pub type HelmKeySeed = TypedDerivationIndex<HelmKeyKind>;
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
        self.derive_child(seed)
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
        self.derive_child(seed)
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

pub type WorkerKeySeed = TypedDerivationIndex<WorkerKeyKind>;
pub type WorkerKey = TypedSecretKey<WorkerKeyKind>;
pub type PublicWorkerKey = TypedPublicKey<WorkerKeyKind>;

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

pub struct ArkSeedKind;

pub type ArkSeed = TypedSecretKey<ArkSeedKind>;

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
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegister {
        let owner = TypedSecretKey::new(Client::register_key_from_name(
            &self.inner,
            DATA_REGISTER_NAME,
        ));

        DataRegister::new(owner)
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> DataKey {
        self.derive_child(seed)
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
        self.derive_child(seed)
    }

    pub fn data_register(&self) -> DataRegisterAddress {
        DataRegisterAddress::new(register_address_from_name(&self.inner, DATA_REGISTER_NAME))
    }

    pub fn data_key(&self, seed: &DataKeySeed) -> PublicDataKey {
        self.derive_child(seed)
    }
}

fn register_address_from_name(owner: &PublicKey, name: impl AsRef<str>) -> RegisterAddress {
    let derivation_index =
        DerivationIndex::from_bytes(XorName::from_content(name.as_ref().as_bytes()).0);
    RegisterAddress::new(owner.derive_child(derivation_index.as_bytes().as_slice()))
}

fn eip2333(seed: impl AsRef<[u8]>) -> anyhow::Result<[u8; 32]> {
    // Derive BLS12-381 master secret key from seed using EIP-2333 standard.
    // Guarantees a valid, non-zero scalar represented as 32 Big-Endian bytes.
    let key_bytes: [u8; 32] = derive_master_sk(seed.as_ref())
        .map_err(|e| anyhow!("derive_master_sk error: {}", e))?
        .serialize() // Get the 32-byte Big-Endian representation
        .into(); // Convert GenericArray<u8, 32> to [u8; 32]
    Ok(key_bytes)
}
