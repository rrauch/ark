use crate::data_key::OwnedDataRegister;
use crate::helm_key::OwnedHelmRegister;
use crate::manifest::{Manifest, ManifestEncryptor};
use crate::progress::Task;
use crate::worker_key::{EitherWorkerKey, WorkerKey};
use crate::{
    ArkAddress, ArkSeed, AutonomiClient, ConfidentialString, Core, EvmWallet, Progress,
    PublicWorkerKey, Receipt, with_receipt,
};
use crate::{DataKey, HelmKey};
use blsttc::SecretKey;
use bon::Builder;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub enum ArkAccessor {
    ArkSeed(ArkSeed),
    HelmKey(HelmKey),
    DataKey(DataKey),
    WorkerKey(WorkerKey),
}

impl ArkAccessor {
    pub(crate) fn secret_key(&self) -> &SecretKey {
        match &self {
            Self::ArkSeed(k) => k.as_ref(),
            Self::HelmKey(k) => k.as_ref(),
            Self::DataKey(k) => k.as_ref(),
            Self::WorkerKey(k) => k.as_ref(),
        }
    }
}

impl From<ArkSeed> for ArkAccessor {
    fn from(value: ArkSeed) -> Self {
        Self::ArkSeed(value)
    }
}

impl From<HelmKey> for ArkAccessor {
    fn from(value: HelmKey) -> Self {
        Self::HelmKey(value)
    }
}

impl From<DataKey> for ArkAccessor {
    fn from(value: DataKey) -> Self {
        Self::DataKey(value)
    }
}

impl From<WorkerKey> for ArkAccessor {
    fn from(value: WorkerKey) -> Self {
        Self::WorkerKey(value)
    }
}

async fn create(
    mut settings: ArkCreationSettings,
    client: &AutonomiClient,
    wallet: &EvmWallet,
    receipt: &mut Receipt,
    mut task: Task,
) -> anyhow::Result<ArkCreationDetails> {
    task.start();

    let mut seed_task = task.child(2, "Ark Seed".to_string());
    let mut helm_key_task = task.child(2, "Helm Key".to_string());
    let mut data_key_task = task.child(3, "Data Key".to_string());
    let mut manifest_task = task.child(1, "Manifest".to_string());

    seed_task.start();
    let (ark_seed, mnemonic) = ArkSeed::random();
    seed_task += 1;
    let core = Core::builder()
        .ark_address(ark_seed.address().clone())
        .client(client.clone())
        .wallet(wallet.clone())
        .build();
    seed_task += 1;
    seed_task.complete();

    helm_key_task.start();
    let helm_register = OwnedHelmRegister::new_derived(&ark_seed);
    let helm_key = ark_seed.helm_key(helm_register.value());
    helm_key_task += 1;
    core.create_register(helm_register, receipt).await?;
    helm_key_task += 1;
    helm_key_task.complete();

    data_key_task.start();
    let data_register = OwnedDataRegister::new_derived(&ark_seed);
    let data_key = ark_seed.data_key(data_register.value());
    data_key_task += 1;
    core.create_register(data_register, receipt).await?;
    data_key_task += 1;

    core.create_encrypted_scratchpad(
        ark_seed.data_keyring(
            data_key
                .public_key()
                .encrypt_data_keyring(&core.derive_data_keyring(&ark_seed).await?)?,
        ),
        receipt,
    )
    .await?;
    data_key_task += 1;
    data_key_task.complete();

    manifest_task.start();
    let ark_address = ark_seed.address();

    let worker_key: EitherWorkerKey = settings
        .authorized_worker
        .take()
        .map(|pk| pk.into())
        .unwrap_or(WorkerKey::random().into());

    let manifest = Manifest::new(&ark_address, settings, worker_key.public_key().clone());
    core.create_manifest(
        &manifest,
        &helm_key,
        &ManifestEncryptor::new(
            ark_address.clone(),
            helm_key.public_key().clone(),
            worker_key.public_key().clone(),
            data_key.public_key().clone(),
        ),
        receipt,
    )
    .await?;
    manifest_task += 1;
    manifest_task.complete();

    task.complete();

    Ok(ArkCreationDetails {
        address: ark_address.clone(),
        mnemonic,
        helm_key,
        data_key,
        worker_key,
        manifest,
    })
}

#[derive(Builder, Clone, Debug)]
pub struct ArkCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) authorized_worker: Option<PublicWorkerKey>,
}

impl ArkCreationSettings {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(|s| s.as_str())
    }

    pub fn authorized_worker(&self) -> Option<&PublicWorkerKey> {
        self.authorized_worker.as_ref()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArkCreationDetails {
    #[zeroize(skip)]
    pub address: ArkAddress,
    pub mnemonic: ConfidentialString,
    pub helm_key: HelmKey,
    pub data_key: DataKey,
    pub worker_key: EitherWorkerKey,
    #[zeroize(skip)]
    pub manifest: Manifest,
}

impl Core {
    pub fn create_ark(
        setting: ArkCreationSettings,
        client: &AutonomiClient,
        wallet: &EvmWallet,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<ArkCreationDetails>> + Send,
    ) {
        let (progress, task) = Progress::new(1, "Ark Creation".to_string());

        let fut =
            with_receipt(async move |receipt| create(setting, client, wallet, receipt, task).await);

        (progress, fut)
    }

    pub fn ark_details(
        &self,
        ark_accessor: &ArkAccessor,
    ) -> (
        Progress,
        impl Future<Output = crate::Result<Manifest>> + Send,
    ) {
        let (progress, mut task) = Progress::new(1, "Retrieve Current Manifest".to_string());

        let fut = with_receipt(async move |receipt| {
            task.start();
            self.get_manifest(ark_accessor).await
        });

        (progress, fut)
    }
}
