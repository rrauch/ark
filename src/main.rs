use autonomi::{Client, Wallet};
use poc::Worker;
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

    let mut worker = Worker::new(client, wallet);
    let ark_details = worker.create_ark().await?;

    println!("-----------------------------------------");
    println!("New Ark Created!");
    println!();
    println!("Address: {}", ark_details.address);
    println!();
    println!("Your recovery words:");
    println!("{}", ark_details.mnemonic);
    println!();
    println!("Data Key: {}", ark_details.data_key.danger_to_string());
    println!("Helm Key: {}", ark_details.helm_key.danger_to_string());
    println!("Worker Key: {}", ark_details.worker_key.danger_to_string());
    println!("-----------------------------------------");

    println!("foo");
    Ok(())
}
