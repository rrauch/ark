use ark_cli::{
    ProgressView, ask_confirmation, press_enter_key, read_ark_key, read_helm_key, read_seed,
};
use ark_core::{
    ArkAddress, ArkCreationSettings, ArkSeed, AutonomiClientConfig, BridgeAddress,
    ConfidentialString, Core, EitherWorkerKey, HelmKey, ObjectType, PublicWorkerKey, VaultAddress,
    VaultConfig, VaultCreationSettings,
};
use autonomi::{Client, Wallet};
use clap::{Parser, Subcommand};
use colored::Colorize;
use futures_util::future::{BoxFuture, FutureExt};
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser)]
#[command(version)]
/// Ark (Proof of Concept) CLI tool.
///
/// WIP
struct Arguments {
    /// Autonomi Network Configuration
    #[arg(long, short = 'c', env, default_value = "autonomi:config:mainnet")]
    autonomi_config: AutonomiClientConfig,
    /// Wallet Secret Key
    #[arg(env)]
    secret_key: ConfidentialString,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Ark related actions
    #[command(subcommand)]
    Ark(ArkCommand),
    /// Vault related actions
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Key rotation and recovery
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    /// Create a new Vault
    ///
    /// Requires the Helm Key
    Create {
        /// Name of the new Vault
        name: String,
        /// Type of Objects to store
        ///
        /// This can NOT be changed later
        object_type: ObjectType,
        /// The Ark Address - e.g. arkaddr1XXXXXX...
        ark_address: ArkAddress,
        /// Description of the new Ark
        #[arg(long, short = 'd')]
        description: Option<String>,
        /// Bridge Address
        #[arg(long, short = 'b')]
        bridge: Option<BridgeAddress>,
    },
    /// Checks if a given Vault Address is valid
    ///
    /// Returns the corresponding Ark Address if it is
    Check {
        /// The Vault Address - e.g. arkvaultaddr1XXXXXX...
        vault_address: VaultAddress,
    },
}

#[derive(Debug, Subcommand)]
enum ArkCommand {
    /// Create a new Ark
    Create {
        /// Name of the new Ark
        name: String,
        /// Description of the new Ark
        #[arg(long, short = 'd')]
        description: Option<String>,
        /// Public Worker Key
        #[arg(long, short = 'w')]
        worker: Option<PublicWorkerKey>,
    },
    /// Show up-to-date details about a given Ark
    #[command(subcommand)]
    Show(ShowArkCommand),
}

#[derive(Debug, Subcommand)]
enum ShowArkCommand {
    /// Use an authorized key to access the Ark details.
    WithKey {
        /// The Ark Address - e.g. arkaddr1XXXXXX...
        ark_address: ArkAddress,
    },
    /// Use an Ark Seed to access the Ark details.
    WithSeed,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Rotate one or more keys
    #[command(subcommand)]
    Rotate(KeyRotateCommand),
}

#[derive(Debug, Subcommand)]
enum KeyRotateCommand {
    /// Rotate the current Data Key
    ///
    /// Requires the Ark Seed to succeed.
    Data,
    /// Rotate the current Helm Key
    ///
    /// Requires the Ark Seed to succeed.
    Helm,
    /// Rotate the current Worker Key
    ///
    /// Requires either the current Helm Key
    /// or the Ark Seed to succeed.
    #[command(subcommand)]
    Worker(WorkerKeyRotateCommand),
    /// Rotate ALL current keys of an Ark
    ///
    /// Rotates Data Key, Helm Key & Worker Key
    /// Requires the Ark Seed to succeed.
    All {
        /// Public Worker Key
        #[arg(long, short = 'w')]
        worker: Option<PublicWorkerKey>,
    },
}

#[derive(Debug, Subcommand)]
enum WorkerKeyRotateCommand {
    /// Use the current Helm key to rotate the Worker key.
    WithHelm {
        /// The Ark Address - e.g. arkaddr1XXXXXX...
        address: ArkAddress,
        /// Public Worker Key
        #[arg(long, short = 'w')]
        worker: Option<PublicWorkerKey>,
    },
    /// Use the Ark Seed to rotate the Worker key.
    ///
    /// The Ark Address is derived automatically.
    WithSeed {
        /// Public Worker Key
        #[arg(long, short = 'w')]
        worker: Option<PublicWorkerKey>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(Level::ERROR.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::Layer::default())
        .init();

    let arguments = Arguments::parse();

    let client = (&arguments.autonomi_config).try_new_client().await?;
    let wallet =
        Wallet::new_from_private_key(client.evm_network().clone(), arguments.secret_key.as_ref())?;

    match arguments.command {
        Commands::Ark(ArkCommand::Create {
            name,
            description,
            worker,
        }) => {
            create_ark(
                name,
                description,
                worker,
                &client,
                &wallet,
                &arguments.autonomi_config,
            )
            .await?;
        }
        Commands::Ark(ArkCommand::Show(show)) => {
            show_ark(show, &client, &wallet, &arguments.autonomi_config).await?;
        }
        Commands::Vault(VaultCommand::Create {
            name,
            description,
            bridge,
            object_type,
            ark_address,
        }) => {
            create_vault(
                name,
                description,
                bridge,
                object_type,
                ark_address,
                &client,
                &wallet,
                &arguments.autonomi_config,
            )
            .await?;
        }
        Commands::Vault(VaultCommand::Check { vault_address }) => {
            check_vault_address(vault_address, &client, &arguments.autonomi_config).await?;
        }
        Commands::Key(KeyCommand::Rotate(rotate)) => {
            rotate_key(rotate, &client, &wallet, &arguments.autonomi_config).await?;
        }
    }

    Ok(())
}

async fn check_vault_address(
    vault_address: VaultAddress,
    client: &Client,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    action_preview(
        "Check Vault Address",
        Some(format!("Vault Address: {}", &vault_address).as_str()),
        None,
        autonomi_config,
    );

    let (mut progress, fut) = Core::ark_from_vault_address(client, &vault_address);
    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let res = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
            }
        }
    };

    progress_view.clear();

    println!();

    if let Some(ark_address) = res {
        println!("{} ✅", "Vault Address is valid!".green().bold());
        println!();
        println!("    {}", "ARK ADDRESS:".bold());
        println!("    {}", ark_address);
        println!();
    } else {
        println!(" ❌ {}", "Not a valid Vault Address".red());
        println!();
    }
    Ok(())
}

async fn create_vault(
    name: String,
    description: Option<String>,
    bridge: Option<BridgeAddress>,
    object_type: ObjectType,
    ark_address: ArkAddress,
    client: &Client,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    let settings = VaultCreationSettings::builder()
        .name(name)
        .maybe_description(description)
        .maybe_bridge(bridge)
        .object_type(object_type)
        .build();

    action_preview(
        "Create New Vault",
        Some(
            format!(
                r#"{} {}

{} {}
{}
{}
{} {}
{} {}
{} {} {}"#,
                "Ark:".bold(),
                ark_address,
                "New Vault Name:".bold(),
                settings.name(),
                "Description".bold(),
                settings.description().unwrap_or("<no description>"),
                "Authorized Bridge:".bold(),
                settings
                    .authorized_bridge()
                    .map(|k| k.to_string())
                    .unwrap_or("<none>".to_string()),
                "Active:".bold(),
                settings.active(),
                "Object Type:".bold(),
                settings.object_type(),
                "Warning: can NOT be changed later!".yellow()
            )
            .as_str(),
        ),
        Some(wallet),
        autonomi_config,
    );

    if !ask_proceed().await {
        println!(" ❌ {}", "Aborting".red());
        println!();
        return Ok(());
    }

    println!();
    println!(" Provide the {} now ", "HELM KEY".bold());
    println!();

    let helm_key = read_helm_key().await?;

    println!();
    println!("✅ {}", "Provided secrets appear valid".green().bold());

    let core = Core::builder()
        .client(client.clone())
        .wallet(wallet.clone())
        .ark_address(ark_address.clone())
        .build();

    let (mut progress, fut) = core.create_vault(settings, &helm_key);
    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let (vault_config, receipt) = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res.map_err(|(err, _)| err)?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
            }
        }
    };

    progress_view.clear();

    const INDENT: &str = "    ";

    println!();
    println!("{} ✅", "Vault Creation Successful".green().bold());

    println!();
    display_vault_config(&vault_config, INDENT);
    println!();

    println!();
    println!("{}", "TOTAL NETWORK COST:".cyan().bold());
    println!("{}{}", INDENT, receipt.total_cost().to_string().italic());
    println!();

    println!("{}", "All Good!".green().bold());
    println!();
    Ok(())
}

async fn show_ark(
    show: ShowArkCommand,
    client: &Client,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    let (ark_address, ark_accessor) = match show {
        ShowArkCommand::WithKey { ark_address } => {
            action_preview(
                "Display Ark Details",
                Some("Provide the Secret Key now"),
                None,
                autonomi_config,
            );
            (ark_address, read_ark_key().await?)
        }
        ShowArkCommand::WithSeed => {
            action_preview(
                "Display Ark Details",
                Some("Provide the Ark Seed now"),
                None,
                autonomi_config,
            );
            let ark_seed = read_seed().await?;
            let ark_address = ark_seed.address().clone();
            (ark_address, ark_seed.into())
        }
    };

    const INDENT: &str = "    ";

    println!();
    println!("✅ {}", "Provided secrets appear valid".green().bold());

    println!();
    println!("{}", "DETAILS".cyan().bold());

    println!("{}{}", INDENT, "ARK ADDRESS:".bold());
    println!("{}{}", INDENT, ark_address);
    println!();

    let core = Core::builder()
        .client(client.clone())
        .wallet(wallet.clone())
        .ark_address(ark_address.clone())
        .build();

    let (mut progress, fut) = core.ark_details(&ark_accessor);
    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let (manifest, _) = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res.map_err(|(err, _)| err)?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
            }
        }
    };

    progress_view.clear();

    println!();
    println!("{}", "ARK DETAILS".cyan().bold());

    println!("{}{}", INDENT, "ADDRESS:".bold());
    println!("{}{}", INDENT, manifest.ark_address);
    println!();

    println!("{}{}", INDENT, "CREATED AT:".bold());
    println!("{}{}", INDENT, manifest.created);
    println!();

    println!("{}{}", INDENT, "LAST MODIFIED AT:".bold());
    println!("{}{}", INDENT, manifest.last_modified);
    println!();

    println!("{}{}", INDENT, "NAME:".bold());
    println!("{}{}", INDENT, manifest.name);
    println!();

    if let Some(description) = &manifest.description {
        println!("{}{}", INDENT, "DESCRIPTION:".bold());
        println!("{}{}", INDENT, description);
        println!();
    }

    println!(
        "{}{}",
        INDENT,
        "CURRENT AUTHORIZED WORKER PUBLIC KEY:".bold()
    );
    println!("{}{}", INDENT, manifest.authorized_worker);
    println!();

    if !manifest.retired_workers.is_empty() {
        println!(
            "{}{}",
            INDENT,
            "PREVIOUS AUTHORIZED WORKER PUBLIC KEYS:".bold()
        );

        for k in &manifest.retired_workers {
            println!("{}{}{} {}", INDENT, INDENT, k.retired_at(), k.as_ref());
        }

        println!();
    }
    println!();
    println!("{}", "VAULTS".cyan().bold());

    for vault in &manifest.vaults {
        println!();
        display_vault_config(vault, format!("{}{}", INDENT, INDENT).as_str());
        println!("{}{}---", INDENT, INDENT);
    }

    println!();
    Ok(())
}

fn display_vault_config(vault: &VaultConfig, indent: &str) {
    println!("{}{}", indent, "VAULT ADDRESS:".bold());
    println!("{}{}", indent, vault.address);
    println!();

    println!("{}{}", indent, "CREATED AT:".bold());
    println!("{}{}", indent, vault.created);
    println!();

    println!("{}{}", indent, "LAST MODIFIED AT:".bold());
    println!("{}{}", indent, vault.last_modified);
    println!();

    println!("{}{}", indent, "VAULT NAME:".bold());
    println!("{}{}", indent, vault.name);
    println!();

    if let Some(description) = &vault.description {
        println!("{}{}", indent, "DESCRIPTION:".bold());
        println!("{}{}", indent, description);
        println!();
    }

    println!("{}{}", indent, "ACTIVE:".bold());
    let active = if vault.active {
        format!("{}", "YES".green())
    } else {
        format!("{}", "NO".red())
    };
    println!("{}{}", indent, active);
    println!();

    println!("{}{}", indent, "AUTHORIZED BRIDGE:".bold());
    println!(
        "{}{}",
        indent,
        vault
            .bridge
            .as_ref()
            .map(|b| b.to_string())
            .unwrap_or("<none>".to_string())
    );
    println!();

    println!("{}{}", indent, "OBJECT TYPE:".bold());
    println!("{}{}", indent, vault.object_type);
}

async fn rotate_key(
    rotate: KeyRotateCommand,
    client: &Client,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    let (key, source) = match &rotate {
        KeyRotateCommand::Data => (RotatableKey::Data, "Ark Seed"),
        KeyRotateCommand::Helm => (RotatableKey::Helm, "Ark Seed"),
        KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithHelm { .. }) => {
            (RotatableKey::Worker(None), "Helm Key")
        }
        KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithSeed { .. }) => {
            (RotatableKey::Worker(None), "Ark Seed")
        }
        KeyRotateCommand::All { .. } => (RotatableKey::All(None), "Ark Seed"),
    };

    action_preview(
        format!("Rotate {}", key),
        Some(format!("Provide the required {} now", source).as_str()),
        Some(wallet),
        autonomi_config,
    );

    let details = match &rotate {
        KeyRotateCommand::Data
        | KeyRotateCommand::Helm
        | KeyRotateCommand::All { .. }
        | KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithSeed { .. }) => {
            let ark_seed = read_seed().await?;
            RotationDetails {
                address: ark_seed.address().clone(),
                key: (&rotate).into(),
                source: RotationSource::ArkSeed(ark_seed),
            }
        }
        KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithHelm { address, .. }) => {
            let helm_key = read_helm_key().await?;
            RotationDetails {
                address: address.clone(),
                key: (&rotate).into(),
                source: RotationSource::HelmKey(helm_key),
            }
        }
    };

    const INDENT: &str = "    ";

    println!();
    println!("✅ {}", "Provided secrets appear valid".green().bold());

    println!();
    println!("{}", "DETAILS".cyan().bold());

    println!("{}{}", INDENT, "ARK ADDRESS:".bold());
    println!("{}{}", INDENT, details.address);
    println!();

    println!("{}{}", INDENT, "KEY TO ROTATE (CHANGE):".bold());
    println!("{}{}", INDENT, details.key);
    println!();

    if !ask_proceed().await {
        println!(" ❌ {}", "Aborting".red());
        println!();
        return Ok(());
    }

    let core = Core::builder()
        .client(client.clone())
        .wallet(wallet.clone())
        .ark_address(details.address.clone())
        .build();

    let (mut progress, fut): (
        _,
        BoxFuture<ark_core::Result<Vec<(RotatableKey, String)>>>,
        //_,
    ) = match details.key {
        RotatableKey::Worker(new_worker_key) => {
            let (progress, fut) = match &details.source {
                RotationSource::HelmKey(helm_key) => {
                    let (progress, fut) = core.rotate_worker_key(helm_key, new_worker_key);
                    (progress, fut.boxed())
                }
                RotationSource::ArkSeed(seed) => {
                    let (progress, fut) = core.rotate_worker_key_with_seed(seed, new_worker_key);
                    (progress, fut.boxed())
                }
            };
            (
                progress,
                async move {
                    let (new_worker_key, receipt) = fut.await?;
                    let mut vec = vec![];
                    if let EitherWorkerKey::Secret(sk) = &new_worker_key {
                        vec.push((RotatableKey::Worker(None), sk.danger_to_string()));
                    }
                    Ok((vec, receipt))
                }
                .boxed(),
            )
        }
        RotatableKey::Data => {
            let (progress, fut) = match &details.source {
                RotationSource::ArkSeed(seed) => core.rotate_data_key(seed),
                _ => unreachable!("only ark seed can rotate data key"),
            };
            (
                progress,
                async move {
                    let (new_data_key, receipt) = fut.await?;
                    Ok((
                        vec![(RotatableKey::Data, new_data_key.danger_to_string())],
                        receipt,
                    ))
                }
                .boxed(),
            )
        }
        RotatableKey::Helm => {
            let (progress, fut) = match &details.source {
                RotationSource::ArkSeed(seed) => core.rotate_helm_key(seed),
                _ => unreachable!("only ark seed can rotate helm key"),
            };
            (
                progress,
                async move {
                    let (new_helm_key, receipt) = fut.await?;
                    Ok((
                        vec![(RotatableKey::Helm, new_helm_key.danger_to_string())],
                        receipt,
                    ))
                }
                .boxed(),
            )
        }
        RotatableKey::All(new_worker_key) => {
            let (progress, fut) = match &details.source {
                RotationSource::ArkSeed(seed) => core.rotate_all_keys(seed, new_worker_key),
                _ => unreachable!("only ark seed can rotate helm key"),
            };
            (
                progress,
                async move {
                    let ((new_data_key, new_helm_key, new_worker_key), receipt) = fut.await?;
                    let mut vec = vec![
                        (RotatableKey::Data, new_data_key.danger_to_string()),
                        (RotatableKey::Helm, new_helm_key.danger_to_string()),
                    ];

                    if let EitherWorkerKey::Secret(sk) = new_worker_key {
                        vec.push((RotatableKey::Worker(None), sk.danger_to_string()));
                    }

                    Ok((vec, receipt))
                }
                .boxed(),
            )
        }
    };

    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let (rotated_keys, receipt) = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res.map_err(|(err, _)| err)?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
            }
        }
    };

    progress_view.clear();

    println!();
    println!("{} ✅", "Key Rotation Successful".green().bold());

    println!();
    println!("{}", "SECURITY WARNING".yellow().bold());
    println!("{}You are about to view SECRET ARK KEYS", INDENT);
    println!("{}• Ensure no one is looking at your screen", INDENT);
    println!("{}• Clear or close your terminal once you are done", INDENT);

    press_enter_key().await;

    println!();
    println!("{}", "SECRET ARK KEYS (ROTATED)".red().bold());
    println!();

    for (key_type, secret_value) in rotated_keys {
        println!(
            "{}{}",
            INDENT,
            format!("{}:", key_type.to_string().to_uppercase())
                .as_str()
                .bold()
        );
        println!("{}{}", INDENT, secret_value);
    }

    println!();
    println!("{}", "TOTAL NETWORK COST:".cyan().bold());
    println!("{}{}", INDENT, receipt.total_cost().to_string().italic());
    println!();

    println!("{}", "All Good!".green().bold());
    println!();
    Ok(())
}

enum RotatableKey {
    Data,
    Helm,
    Worker(Option<PublicWorkerKey>),
    All(Option<PublicWorkerKey>),
}

impl From<&KeyRotateCommand> for RotatableKey {
    fn from(value: &KeyRotateCommand) -> Self {
        match value {
            KeyRotateCommand::Data => Self::Data,
            KeyRotateCommand::Helm => Self::Helm,
            KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithSeed { worker }) => {
                Self::Worker(worker.clone())
            }
            KeyRotateCommand::Worker(WorkerKeyRotateCommand::WithHelm { worker, .. }) => {
                Self::Worker(worker.clone())
            }
            KeyRotateCommand::All { worker } => Self::All(worker.clone()),
        }
    }
}

impl Display for RotatableKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Data => "Data Key",
            Self::Helm => "Helm Key",
            Self::Worker(_) => "Worker Key",
            Self::All(_) => "All Keys",
        };
        write!(f, "{}", name)
    }
}

enum RotationSource {
    ArkSeed(ArkSeed),
    HelmKey(HelmKey),
}

struct RotationDetails {
    address: ArkAddress,
    key: RotatableKey,
    source: RotationSource,
}

async fn create_ark(
    name: String,
    description: Option<String>,
    public_worker_key: Option<PublicWorkerKey>,
    client: &Client,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    let settings = ArkCreationSettings::builder()
        .name(name)
        .maybe_description(description)
        .maybe_authorized_worker(public_worker_key)
        .build();

    action_preview(
        "Create New Ark",
        Some(
            format!(
                r#"{} {}
{}
{}
{} {}"#,
                "Name:".bold(),
                settings.name(),
                "Description".bold(),
                settings.description().unwrap_or("<no description>"),
                "Authorized Worker".bold(),
                settings
                    .authorized_worker()
                    .map(|k| k.to_string())
                    .unwrap_or("<generated automatically>".to_string()),
            )
            .as_str(),
        ),
        Some(wallet),
        autonomi_config,
    );

    if !ask_proceed().await {
        println!(" ❌ {}", "Aborting".red());
        println!();
        return Ok(());
    }

    let (mut progress, fut) = Core::create_ark(settings, &client, &wallet);
    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let (ark_details, receipt) = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res.map_err(|(err, _)| err)?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
            }
        }
    };

    progress_view.clear();

    const INDENT: &str = "    ";

    println!();
    println!("{} ✅", "Ark Creation Successful".green().bold());

    println!();
    println!("{}", "SECURITY WARNING".yellow().bold());
    println!(
        "{}You are about to view your ARK SEED and SECRET ARK KEYS",
        INDENT
    );
    println!(
        "{}• The ARK SEED is your MASTER KEY - it CANNOT be recovered",
        INDENT
    );
    println!(
        "{}• All other keys can be regenerated from this seed",
        INDENT
    );
    println!(
        "{}• Write down the 24-word seed and store it securely offline",
        INDENT
    );
    println!("{}• Verify each word multiple times when copying", INDENT);
    println!("{}• Ensure no one is looking at your screen", INDENT);
    println!("{}• Clear or close your terminal once you are done", INDENT);

    press_enter_key().await;

    println!();
    println!("{}", "ARK DETAILS".cyan().bold());

    println!("{}{}", INDENT, "ADDRESS:".bold());
    println!("{}{}", INDENT, ark_details.address);
    println!();

    println!("{}{}", INDENT, "CREATED AT:".bold());
    println!("{}{}", INDENT, ark_details.manifest.created);
    println!();

    println!("{}{}", INDENT, "NAME:".bold());
    println!("{}{}", INDENT, ark_details.manifest.name);
    println!();

    println!("{}{}", INDENT, "DESCRIPTION:".bold());
    println!(
        "{}{}",
        INDENT,
        ark_details
            .manifest
            .description
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("<no description>")
    );
    println!();

    println!("{}{}", INDENT, "PUBLIC WORKER KEY:".bold());
    println!("{}{}", INDENT, ark_details.worker_key.public_key());
    println!();

    println!("{}{}", INDENT, "TOTAL CREATION COST:".bold());
    println!("{}{}", INDENT, receipt.total_cost().to_string().italic());
    println!();

    println!("{}", "ARK SEED (MASTER KEY)".red().bold());
    println!("{}", "WRITE DOWN THESE 24 WORDS IN EXACT ORDER:".red());
    println!();

    // Format the 24-word mnemonic in a grid (6 rows of 4 words)
    let words: Vec<&str> = ark_details.mnemonic.as_ref().split_whitespace().collect();
    for row in 0..6 {
        let mut row_str = String::from(INDENT);
        for col in 0..4 {
            let idx = row * 4 + col;
            if idx < words.len() {
                row_str.push_str(&format!("{:<10} ", words[idx]));
            }
        }
        println!("{}", row_str.red());
    }
    println!();
    println!(
        "{}",
        "VERIFY EACH WORD CAREFULLY - THIS SEED CANNOT BE RECOVERED".red()
    );

    println!();
    println!("{}", "SECRET ARK KEYS".cyan().bold());
    println!("{}These keys can be regenerated from your Ark Seed", INDENT);
    println!();

    println!("{}{}", INDENT, "DATA KEY:".bold());
    println!("{}{}", INDENT, ark_details.data_key.danger_to_string());
    println!();

    println!("{}{}", INDENT, "HELM KEY:".bold(),);
    println!("{}{}", INDENT, ark_details.helm_key.danger_to_string());
    println!();

    if let EitherWorkerKey::Secret(sk) = &ark_details.worker_key {
        println!("{}{}", INDENT, "WORKER KEY:".bold());
        println!("{}{}", INDENT, sk.danger_to_string());
    }

    println!();
    println!("{}", "All Good!".green().bold());
    println!();

    Ok(())
}

fn action_preview(
    action: impl AsRef<str>,
    details: Option<&str>,
    wallet: Option<&Wallet>,
    autonomi_config: &AutonomiClientConfig,
) {
    println!("{} {}", "ACTION:".bold(), action.as_ref().cyan().bold());
    println!(
        "{} {}",
        "Autonomi Network:".bold(),
        autonomi_config.friendly()
    );
    if let Some(wallet) = wallet {
        println!(
            "{} {}",
            "Wallet:".bold(),
            wallet.address().to_string().red()
        );
    }
    println!();
    if let Some(details) = details {
        println!("{}", details);
        println!();
    }
}

async fn ask_proceed() -> bool {
    ask_confirmation("Do you want to proceed (y/n)?").await
}
