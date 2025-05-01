use crate::crypto::{
    ArkAddress, DataKey, DataKeySeed, HelmKey, HelmKeySeed, WorkerKey, WorkerKeySeed,
};
use crate::manifest::Manifest;
use crate::{ArkSeed, AutonomiClient, AutonomiWallet, Core, Receipt};
use bon::Builder;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) async fn create(
    settings: ArkCreationSettings,
    client: &AutonomiClient,
    wallet: &AutonomiWallet,
    receipt: &mut Receipt,
) -> anyhow::Result<ArkCreationDetails> {
    let (ark_seed, mnemonic) = ArkSeed::random();
    let core = Core::builder()
        .ark_address(ark_seed.address().clone())
        .client(client.clone())
        .wallet(wallet.clone())
        .build();

    let helm_register = ark_seed.helm_register();
    let helm_key_seed = HelmKeySeed::random();
    core.create_register(&helm_register, helm_key_seed.clone(), receipt)
        .await?;
    let helm_key = ark_seed.helm_key(&helm_key_seed);

    let data_register = ark_seed.data_register();
    let data_key_seed = DataKeySeed::random();
    core.create_register(&data_register, data_key_seed.clone(), receipt)
        .await?;
    let data_key = ark_seed.data_key(&data_key_seed);

    core.create_encrypted_scratchpad(
        data_key
            .public_key()
            .encrypt_data_keyring(&core.derive_data_keyring(&ark_seed).await?),
        &ark_seed.data_keyring(),
        receipt,
    )
    .await?;

    let worker_register = helm_key.worker_register();
    let worker_key_seed = WorkerKeySeed::random();
    core.create_register(&worker_register, worker_key_seed.clone(), receipt)
        .await?;
    let worker_key = helm_key.worker_key(&worker_key_seed);

    let ark_address = ark_seed.address();
    let manifest = Manifest::new(&ark_address, settings);
    core.create_encrypted_scratchpad(
        worker_key.public_key().encrypt_manifest(&manifest),
        &helm_key.manifest(),
        receipt,
    )
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

#[derive(Builder, Clone, Debug)]
pub struct ArkCreationSettings {
    #[builder(into)]
    pub(crate) name: String,
    pub(crate) description: Option<String>,
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
