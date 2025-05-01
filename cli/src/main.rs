use autonomi::Wallet;
use core::{ArkCreationSettings, ArkSeed, AutonomiClientConfig, Core, VaultCreationSettings};
use std::str::FromStr;
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

    let client_config = AutonomiClientConfig::from_str(std::env::var("AUTONOMI_CONFIG")?.as_str())?;

    let client = client_config.try_new_client().await?;
    let wallet = Wallet::new_from_private_key(
        client.evm_network().clone(),
        std::env::var("SECRET_KEY")?.as_str(),
    )?;
    let (ark_details, mut receipt) = Core::create_ark(
        ArkCreationSettings::builder().name("Test Ark").build(),
        &client,
        &wallet,
    )
    .await
    .map_err(|(e, _)| e)?;

    println!("-----------------------------------------");
    println!("New Ark Created!");
    println!();
    println!("Address: {}", ark_details.address);
    println!("Created at: {}", ark_details.manifest.created);
    println!("Name: {}", ark_details.manifest.name);
    if let Some(description) = ark_details.manifest.description.as_ref() {
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

    let core = Core::builder()
        .ark_address(ark_details.address.clone())
        .client(client)
        .wallet(wallet)
        .build();
    let (vault_id, r) = core
        .create_vault(
            VaultCreationSettings::builder().name("Vault 1").build(),
            &ark_details.helm_key,
        )
        .await
        .map_err(|(e, _)| e)?;
    receipt += r;

    println!("added vault {}", vault_id);
    println!("-----------------------------------------");
    println!("rotating keys");
    println!();

    let ark_seed = ArkSeed::try_from_mnemonic(ark_details.mnemonic.clone())?;
    let (data_key, r) = core.rotate_data_key(&ark_seed).await.map_err(|(e, _)| e)?;
    receipt += r;
    println!("new data key: {}", data_key.danger_to_string());
    let ((helm_key, worker_key), receipt) =
        core.rotate_helm_key(&ark_seed).await.map_err(|(e, _)| e)?;
    println!("new helm key: {}", helm_key.danger_to_string());
    println!("new worker key: {}", worker_key.danger_to_string());
    println!("-----------------------------------------");
    println!();
    println!(
        "total cost: {} attos over {} items",
        receipt.total_cost(),
        receipt.len()
    );
    println!();
    println!("-----------------------------------------");
    println!();
    Ok(())
}
