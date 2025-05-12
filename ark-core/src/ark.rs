use crate::data_key::DataKeySeed;
use crate::helm_key::HelmKeySeed;
use crate::manifest::{Manifest, ManifestEncryptor};
use crate::progress::Task;
use crate::worker_key::{WorkerKey, WorkerKeySeed};
use crate::{
    ArkAddress, ArkSeed, AutonomiClient, ConfidentialString, Core, EvmWallet, Progress, Receipt,
    with_receipt,
};
use crate::{DataKey, HelmKey};
use bon::Builder;
use zeroize::{Zeroize, ZeroizeOnDrop};

async fn create(
    settings: ArkCreationSettings,
    client: &AutonomiClient,
    wallet: &EvmWallet,
    receipt: &mut Receipt,
    mut task: Task,
) -> anyhow::Result<ArkCreationDetails> {
    task.start();

    let mut seed_task = task.child(2, "Ark Seed".to_string());
    let mut helm_key_task = task.child(2, "Helm Key".to_string());
    let mut data_key_task = task.child(3, "Data Key".to_string());
    let mut worker_key_task = task.child(2, "Worker Key".to_string());
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
    let helm_register = ark_seed.helm_register();
    let helm_key_seed = HelmKeySeed::random();
    helm_key_task += 1;
    core.create_register(&helm_register, helm_key_seed.clone(), receipt)
        .await?;
    helm_key_task += 1;
    let helm_key = ark_seed.helm_key(&helm_key_seed);
    helm_key_task.complete();

    data_key_task.start();
    let data_register = ark_seed.data_register();
    let data_key_seed = DataKeySeed::random();
    data_key_task += 1;
    core.create_register(&data_register, data_key_seed.clone(), receipt)
        .await?;
    data_key_task += 1;
    let data_key = ark_seed.data_key(&data_key_seed);

    core.create_encrypted_scratchpad(
        data_key
            .public_key()
            .encrypt_data_keyring(&core.derive_data_keyring(&ark_seed).await?)?,
        &ark_seed.data_keyring(),
        receipt,
    )
    .await?;
    data_key_task += 1;
    data_key_task.complete();

    worker_key_task.start();
    let worker_register = helm_key.worker_register();
    let worker_key_seed = WorkerKeySeed::random();
    worker_key_task += 1;
    core.create_register(&worker_register, worker_key_seed.clone(), receipt)
        .await?;
    worker_key_task += 2;
    let worker_key = helm_key.worker_key(&worker_key_seed);
    worker_key_task.complete();

    manifest_task.start();
    let ark_address = ark_seed.address();
    let manifest = Manifest::new(&ark_address, settings);
    core.create_encrypted_scratchpad(
        ManifestEncryptor::new(
            ark_address.clone(),
            helm_key.public_key().clone(),
            worker_key.public_key().clone(),
            data_key.public_key().clone(),
        )
        .encrypt_manifest(&manifest)?,
        &helm_key.manifest(),
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
}

impl ArkCreationSettings {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_ref().map(|s| s.as_str())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArkCreationDetails {
    #[zeroize(skip)]
    pub address: ArkAddress,
    pub mnemonic: ConfidentialString,
    pub helm_key: HelmKey,
    pub data_key: DataKey,
    pub worker_key: WorkerKey,
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
}
