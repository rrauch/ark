use autonomi::{Client, Wallet};
use core::{ArkCreationSettings, ArkSeed, Core, VaultCreationSettings};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::ERROR.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::Layer::default())
        .init();

    let client = Client::init_local().await?;
    let wallet = Wallet::new_from_private_key(
        client.evm_network().clone(),
        std::env::var("SECRET_KEY")?.as_str(),
    )?;
    let ark_details = Core::create_ark(
        ArkCreationSettings::builder().name("Test Ark").build(),
        &client,
        &wallet,
    )
    .await?;

    println!("-----------------------------------------");
    println!("New Ark Created!");
    println!();
    println!("Address: {}", ark_details.address);
    println!("Created at: {}", ark_details.ark.created);
    println!("Name: {}", ark_details.ark.name);
    if let Some(description) = ark_details.ark.description.as_ref() {
        println!("-----------");
        println!("{}", description);
        println!("-----------")
    }
    println!();
    println!("Your recovery words:");
    println!("{}", ark_details.mnemonic);
    println!();
    println!("Data Key: {}", ark_details.data_key.danger_to_string());
    println!("Helm Key: {}", ark_details.helm_key.danger_to_string());
    println!("Worker Key: {}", ark_details.worker_key.danger_to_string());
    println!("-----------------------------------------");

    let core = Core::new(client, wallet, ark_details.address.clone());
    let vault_id = core
        .create_vault(
            VaultCreationSettings::builder().name("Vault 1").build(),
            &ark_details.helm_key,
        )
        .await?;

    println!("added vault {}", vault_id);
    println!("-----------------------------------------");
    println!("rotating keys");
    println!();

    let ark_seed = ArkSeed::try_from_mnemonic(ark_details.mnemonic.clone())?;
    let data_key = core.rotate_data_key(&ark_seed).await?;
    println!("new data key: {}", data_key.danger_to_string());
    let (helm_key, worker_key) = core.rotate_helm_key(&ark_seed).await?;
    println!("new helm key: {}", helm_key.danger_to_string());
    println!("new worker key: {}", worker_key.danger_to_string());
    println!("-----------------------------------------");
    println!();
    Ok(())
}
