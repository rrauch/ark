use autonomi::{Client, Wallet};
use clap::{Parser, Subcommand};
use cli::{ProgressView, ask_confirmation};
use colored::Colorize;
use core::{ArkCreationSettings, AutonomiClientConfig, Core};
use std::fmt::{Debug, Formatter};
use std::time::{Duration, SystemTime};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
}

#[derive(Debug, Subcommand)]
enum ArkCommand {
    /// Create a new Ark
    Create {
        /// Name of the new Ark
        #[arg(long, short = 'n')]
        name: String,
        /// Description of the new Ark
        #[arg(long, short = 'd')]
        description: Option<String>,
    },
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
struct ConfidentialString(String);

impl From<String> for ConfidentialString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Debug for ConfidentialString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted>")
    }
}

impl AsRef<str> for ConfidentialString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
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
        Commands::Ark(ArkCommand::Create { name, description }) => {
            create_ark(
                name,
                description,
                &client,
                &wallet,
                &arguments.autonomi_config,
            )
            .await?;
        }
    }

    Ok(())
}

async fn create_ark(
    name: String,
    description: Option<String>,
    client: &Client,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> anyhow::Result<()> {
    let settings = ArkCreationSettings::builder()
        .name(name)
        .maybe_description(description)
        .build();

    if !action_preview(
        "Create New Ark",
        Some(
            format!(
                r#"{} {}
{}
{}"#,
                "Name:".bold(),
                settings.name(),
                "Description".bold(),
                settings.description().unwrap_or("<no description>")
            )
            .as_str(),
        ),
        wallet,
        autonomi_config,
    )
    .await
    {
        println!("{}", "Aborting".red());
        println!();
        return Ok(());
    }

    let (mut progress, fut) = Core::create_ark(settings, &client, &wallet);
    tokio::pin!(fut);

    let mut progress_view = ProgressView::new(&progress.latest(), Duration::from_millis(100));
    let mut last_tick = SystemTime::now();
    let (ark_details, receipt) = loop {
        let next_tick_in = progress_view.next_tick_in();

        tokio::select! {
            res = &mut fut => {
                break res.map_err(|(err, _)| err)?;
            },
            _ = &mut progress => {
                progress_view.update(&progress.latest());
                last_tick = SystemTime::now();
            },
            _ = tokio::time::sleep(next_tick_in) => {
                progress_view.tick();
                last_tick = SystemTime::now();
            }
        }
    };

    progress_view.clear();

    const INDENT: &str = "    ";

    println!();
    println!("{} ✅", "Ark Creation Successful".green().bold());

    println!();
    println!("{}", "SECURITY WARNING".yellow().bold());
    println!("{}You are about to view your ARK SEED and ARK KEYS", INDENT);
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

    println!("{}{}", INDENT, "TOTAL CREATION COST:".bold());
    println!("{}{}", INDENT, receipt.total_cost().to_string().italic());
    println!();

    println!("{}", "ARK SEED (MASTER KEY)".red().bold());
    println!("{}", "WRITE DOWN THESE 24 WORDS IN EXACT ORDER:".red());
    println!();

    // Format the 24-word mnemonic in a grid (6 rows of 4 words)
    let words: Vec<&str> = ark_details.mnemonic.split_whitespace().collect();
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
    println!("{}", "ARK KEYS".cyan().bold());
    println!("{}These keys can be regenerated from your Ark Seed", INDENT);
    println!();

    println!("{}{}", INDENT, "DATA KEY:".bold());
    println!("{}{}", INDENT, ark_details.data_key.danger_to_string());
    println!();

    println!("{}{}", INDENT, "HELM KEY:".bold(),);
    println!("{}{}", INDENT, ark_details.helm_key.danger_to_string());
    println!();

    println!("{}{}", INDENT, "WORKER KEY:".bold());
    println!("{}{}", INDENT, ark_details.worker_key.danger_to_string());

    println!();
    println!("{}", "All Good!".green().bold());
    println!();

    Ok(())
}

async fn action_preview(
    action: impl AsRef<str>,
    details: Option<&str>,
    wallet: &Wallet,
    autonomi_config: &AutonomiClientConfig,
) -> bool {
    println!("{} {}", "ACTION:".bold(), action.as_ref().cyan().bold());
    println!(
        "{} {}",
        "Autonomi Network:".bold(),
        autonomi_config.friendly()
    );
    println!(
        "{} {}",
        "Wallet:".bold(),
        wallet.address().to_string().red()
    );
    println!();
    if let Some(details) = details {
        println!("{}", details);
        println!();
    }
    ask_confirmation("Do you want to proceed (y/n)?").await
}
