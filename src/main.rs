use anyhow::anyhow;
use argon2::{Argon2, PasswordHasher};
use autonomi::client::key_derivation::{DerivationIndex, MainPubkey, MainSecretKey};
use autonomi::client::payment::PaymentOption;
use autonomi::client::quote::DataTypes;
use autonomi::register::{RegisterAddress, RegisterValue};
use autonomi::{Bytes, Chunk, ChunkAddress, Client, Network, SecretKey, Wallet};
use bip39::{Language, Mnemonic};
use poc::{ArkAddress, ArkSeed};
use rand::random;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

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

    let seed_phrase: &str =
        "economy turkey lemon gym tongue there spell height seminar middle twice autumn";
    //let seed_phrase: &str = "burger stereo merit exit runway chef scale list doll first zero tackle";

    let (ark_seed, mnemonic) = ArkSeed::random();
    let ark_address = ark_seed.address();

    let x = ark_address.to_string();
    let y = ArkAddress::from_str(x.as_str())?;
    let m = y == ark_address;

    let helm_reg_addr = ark_address.helm_register();
    let helm_reg = ark_seed.helm_register();
    let helm_reg_addr2 = helm_reg.address();
    let matches = &helm_reg_addr == helm_reg_addr2;

    let root = SecretKey::random();
    let address = root.public_key();
    /*let deriv_index = DerivationIndex::from_bytes(random());

    let derived_pubkey = MainPubkey::new(address.clone()).derive_key(&deriv_index);
    let derived_secret = MainSecretKey::new(root.clone()).derive_key(&deriv_index);

    let msg = "foo".as_bytes();
    let signature = derived_secret.sign(msg);
    let valid = derived_pubkey.verify(&signature, msg);
    println!("{}", valid);

    let derived_pubkey = address.derive_child(deriv_index.as_bytes());
    let derived_secret = root.derive_child(deriv_index.as_bytes());

    let ciphertext = derived_pubkey.encrypt(msg);
    let plaintext = derived_secret.decrypt(&ciphertext).unwrap();
    let valid = plaintext.as_slice() == msg;
    println!("{}", valid);*/

    let client = Client::init_local().await?;
    let wallet = Wallet::new_from_private_key(
        client.evm_network().clone(),
        std::env::var("SECRET_KEY")?.as_str(),
    )?;

    let register = Client::register_key_from_name(&root, "reg1");
    let (cost, address) = client
        .register_create(
            &register,
            Client::register_value_from_bytes("thisisatest1".as_bytes()).unwrap(),
            PaymentOption::Wallet(wallet.clone()),
        )
        .await?;
    let cost2 = client
        .register_update(
            &register,
            Client::register_value_from_bytes("thisisatest2".as_bytes()).unwrap(),
            PaymentOption::Wallet(wallet.clone()),
        )
        .await?;
    let mut history = client.register_history(&address);
    while let Some(entry) = history.next().await? {
        println!("history: {:?}", entry);
    }
    println!("");

    /*let toks = wallet.balance_of_tokens().await?;
    let gas = wallet.balance_of_gas_tokens().await?;
    println!("tokens: {}, gas: {}", toks, gas);*/

    let data = b"hello world";
    //let chunk = Chunk::new(Bytes::from(data.as_slice()));

    //let (paid, address) = client.chunk_put(&chunk, PaymentOption::Wallet(wallet.clone())).await?;
    //println!("address: {}", address);
    //let chunk = client.chunk_get(&address).await?;
    //let identical = chunk.value.as_ref() == data.as_slice();
    //println!("identical: {}", identical);

    let chunk = client
        .chunk_get(&ChunkAddress::try_from_hex(
            "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
        )?)
        .await?;

    println!("{}", String::from_utf8_lossy(chunk.value.as_ref()));

    /*let x = client
    .get_raw_quotes(
        DataTypes::Chunk,
        vec![(*chunk.address().xorname(), chunk.value.len())].into_iter(),
    )
    .await;*/

    //let c = client.chunk_cost(chunk.address()).await?;
    //println!("{}", c);

    /*let c = client
        .file_cost(&PathBuf::from_str(
            "/home/roland/Downloads/2025.1.2.14.autonomi.x86_64-unknown-linux-musl.zip",
        )?)
        .await?;
    println!("{}", c);*/

    println!("foo");
    Ok(())
}
