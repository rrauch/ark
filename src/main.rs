use autonomi::{Client, Wallet};
use poc::{ArkCreationSettings, Engine, VaultCreationSettings};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();
    let (filter, _reload_handle) = tracing_subscriber::reload::Layer::new(filter);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::Layer::default())
        .init();

    let client = Client::init_local().await?;
    let wallet = Wallet::new_from_private_key(
        client.evm_network().clone(),
        std::env::var("SECRET_KEY")?.as_str(),
    )?;

    let mut engine = Engine::new(client, wallet);
    let ark_details = engine
        .create_ark(&ArkCreationSettings::builder().name("Test Ark").build())
        .await?;

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

    engine
        .add_ark(&ark_details.address, ark_details.worker_key.clone())
        .await?;

    let vault_id = engine
        .create_vault(
            VaultCreationSettings::builder().name("Vault 1").build(),
            &ark_details.helm_key,
            &ark_details.address,
        )
        .await?;
    println!("added vault {}", vault_id);

    println!();
    Ok(())
}
