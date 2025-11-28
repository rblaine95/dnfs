//! DNFS CLI - Domain Name File System Command Line Interface
//!
//! A CLI tool for storing and retrieving files using DNS TXT records.

#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use clap::{Args, Parser, Subcommand};
use cloudflare::framework::{
    Environment, auth,
    client::{ClientConfig, async_api},
};
use color_eyre::eyre::Result;
use config::Config;
use dnfs_lib::{DEFAULT_CONCURRENCY, File, FileRecord, check_usage_agreement, get_all_files};
use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use securefmt::Debug;
use tracing::{debug, info, warn};

mod config;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Domain Name File System - Store files in DNS TXT records"
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug)]
struct GlobalArgs {
    /// Number of concurrent upload/delete operations
    #[arg(short, long, global = true, default_value_t = DEFAULT_CONCURRENCY)]
    jobs: usize,

    /// Dry run mode - don't actually modify DNS records
    #[arg(long, global = true)]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Upload a file to DNS
    Upload(UploadArgs),
    /// Download a file from DNS
    Download(DownloadArgs),
    /// Delete a file from DNS
    Delete {
        /// The file FQDN to delete (e.g., myfile.dnfs.example.com)
        fqdn: String,
    },
    /// List all files stored in DNS
    List,
    /// Delete all DNFS files from the DNS zone
    Purge {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args, Debug)]
struct UploadArgs {
    /// Path to the file to upload
    path: String,

    /// Encrypt the file using AES-256 (requires `encryption_key` in config)
    #[arg(short, long)]
    encrypt: bool,
}

#[derive(Args, Debug)]
struct DownloadArgs {
    /// The file FQDN to download (e.g., myfile.dnfs.example.com)
    fqdn: String,

    /// Decrypt the file (requires `encryption_key` in config)
    #[arg(short, long)]
    decrypt: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    debug!("CLI args: {cli:?}");

    let config = Config::load(Path::new("config.toml"))?;
    debug!("Config loaded: {config:?}");

    let resolver = create_resolver();
    let cf_client = create_cloudflare_client(&config)?;

    // Verify usage agreement
    check_usage_agreement(&config.dnfs.domain_name, &resolver).await?;
    info!("Usage agreement verified");

    run_command(&cli, &config, &cf_client, &resolver).await
}

/// Initializes the tracing subscriber for logging.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .init();
}

/// Creates a DNS resolver using Cloudflare's DNS-over-HTTPS.
fn create_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(
        ResolverConfig::cloudflare_https(),
        TokioConnectionProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
}

/// Creates a Cloudflare API client.
fn create_cloudflare_client(config: &Config) -> Result<async_api::Client> {
    let client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key.clone(),
        },
        ClientConfig::default(),
        Environment::Production,
    )?;
    Ok(client)
}

/// Runs the appropriate command based on CLI args.
async fn run_command(
    cli: &Cli,
    config: &Config,
    cf_client: &async_api::Client,
    resolver: &TokioResolver,
) -> Result<()> {
    let jobs = cli.global.jobs;
    let dry_run = cli.global.dry_run;

    match &cli.command {
        Commands::Upload(args) => {
            let magic_crypt = get_encryption_key(config, args.encrypt)?;
            let file = File::new(Path::new(&args.path))?;

            let file_fqdn = file
                .upload(
                    cf_client,
                    &config.cloudflare.zone_id,
                    &config.dnfs.domain_name,
                    magic_crypt.as_ref(),
                    jobs,
                    dry_run,
                )
                .await?;

            println!("File successfully uploaded: {file_fqdn}");
        }

        Commands::Download(args) => {
            let magic_crypt = get_encryption_key(config, args.decrypt)?;
            let file = File::read(&args.fqdn, resolver, magic_crypt.as_ref()).await?;
            file.write_to_stdout()?;
        }

        Commands::Delete { fqdn } => {
            FileRecord::delete(
                fqdn,
                cf_client,
                &config.cloudflare.zone_id,
                resolver,
                jobs,
                dry_run,
            )
            .await?;
            println!("File successfully deleted: {fqdn}");
        }

        Commands::List => {
            let records = get_all_files(cf_client, &config.cloudflare.zone_id).await?;
            for record in records {
                println!("{}", record.name);
            }
        }

        Commands::Purge { force } => {
            if !*force && !confirm_purge()? {
                warn!("Purge aborted");
                return Ok(());
            }

            if *force {
                warn!("Force flag set, skipping confirmation");
            }

            info!("By fire be purged");
            FileRecord::purge(
                cf_client,
                &config.cloudflare.zone_id,
                resolver,
                jobs,
                dry_run,
            )
            .await?;
            warn!("All files successfully purged");
        }
    }

    Ok(())
}

/// Gets the encryption key if encryption is requested.
fn get_encryption_key(
    config: &Config,
    encrypt: bool,
) -> Result<Option<magic_crypt::MagicCrypt256>> {
    if !encrypt {
        return Ok(None);
    }

    let key = config.dnfs.encryption_key.as_ref().ok_or_else(|| {
        color_eyre::eyre::eyre!("Encryption requested but no encryption_key in config")
    })?;

    Ok(Some(magic_crypt::new_magic_crypt!(key, 256)))
}

/// Prompts the user to confirm the purge operation.
fn confirm_purge() -> Result<bool> {
    warn!("BE CAREFUL!");
    warn!("This will purge ALL DNFS files from the DNS zone");
    print!("Are you sure you want to purge all data? This action cannot be undone. (y/N): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().eq_ignore_ascii_case("y"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use cloudflare::framework::{
        Environment, auth,
        client::{ClientConfig, async_api},
    };
    use hickory_resolver::{
        TokioResolver,
        config::{ResolverConfig, ResolverOpts},
        name_server::TokioConnectionProvider,
    };

    use super::Config;
    use dnfs_lib::{DEFAULT_CONCURRENCY, File, check_usage_agreement};

    fn create_test_resolver() -> TokioResolver {
        TokioResolver::builder_with_config(
            ResolverConfig::cloudflare_https(),
            TokioConnectionProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
    }

    #[test]
    fn test_config_loading() {
        // Config is at workspace root, not crate root
        let config = Config::load(Path::new("../config.toml"));
        assert!(config.is_ok(), "Config should load successfully");
    }

    #[tokio::test]
    async fn test_usage_agreement_valid() {
        let config = Config::load(Path::new("../config.toml")).expect("Config should be loaded");
        let resolver = create_test_resolver();
        let result = check_usage_agreement(&config.dnfs.domain_name, &resolver).await;
        assert!(result.is_ok(), "Valid domain should pass agreement check");
    }

    #[tokio::test]
    async fn test_usage_agreement_invalid() {
        let resolver = create_test_resolver();
        let result = check_usage_agreement("example.com", &resolver).await;
        assert!(result.is_err(), "Domain without agreement should fail");
    }

    #[tokio::test]
    async fn test_file_upload() {
        let config = Config::load(Path::new("../config.toml")).expect("Config should load");

        let cf_client = async_api::Client::new(
            auth::Credentials::UserAuthToken {
                token: config.cloudflare.api_key.clone(),
            },
            ClientConfig::default(),
            Environment::Production,
        )
        .expect("Client should be created");

        let file = File::new(Path::new("../test.txt")).expect("File should be created");

        let encryption = Some(magic_crypt::new_magic_crypt!("test", 256));

        let result = file
            .upload(
                &cf_client,
                &config.cloudflare.zone_id,
                &config.dnfs.domain_name,
                encryption.as_ref(),
                DEFAULT_CONCURRENCY,
                false,
            )
            .await;

        assert!(result.is_ok(), "Upload should succeed");
    }

    #[tokio::test]
    async fn test_file_download() {
        let resolver = create_test_resolver();
        let file_fqdn = "test.dnfs.bunkerlab.net";
        let encryption = Some(magic_crypt::new_magic_crypt!("test", 256));

        let result = File::read(file_fqdn, &resolver, encryption.as_ref()).await;
        assert!(result.is_ok(), "Download should succeed");

        let file = result.expect("File should be present");
        let content = file.to_string();
        assert!(content.is_ok(), "File content should be valid UTF-8");
    }
}
