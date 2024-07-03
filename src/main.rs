// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use clap::{arg, Args, Parser, Subcommand};
use cloudflare::framework::{async_api, auth, Environment, HttpApiClientConfig};
use color_eyre::eyre::Result;
use config::Config;
use file::File;
use file_record::FileRecord;
use helpers::{check_usage_agreement, get_all_files};
use securefmt::Debug;
use tracing::{debug, warn};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

mod config;
mod file;
mod file_record;
mod helpers;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug)]
struct GlobalArgs {
    #[arg(
        long,
        global = true,
        help = "Number of concurrent jobs",
        default_value = "4"
    )]
    jobs: usize,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Upload(UploadArgs),
    Download(DownloadArgs),
    Delete {
        #[arg(help = "The file FQDN to delete")]
        fqdn: String,
    },
    List,
    Purge {
        #[arg(long, help = "Skip confirmation")]
        force: bool,
    },
}

#[derive(Args, Debug)]
struct UploadArgs {
    #[arg(help = "Path to the file to upload")]
    path: String,

    #[arg(long, help = "Whether to encrypt the file")]
    encrypt: bool,
}

#[derive(Args, Debug)]
struct DownloadArgs {
    #[arg(help = "The file FQDN to download")]
    fqdn: String,

    #[arg(long, help = "Whether to decrypt the file")]
    decrypt: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Default log level is `info`
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            std::env::var("LOG_LEVEL").unwrap_or("info".to_string()),
        );
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    // Default number of jobs for streams is 4
    std::env::set_var("JOBS", cli.global.jobs.to_string());

    // Load config
    let config = Config::new(Path::new("config.toml"))?;
    debug!("{config:?}");

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());

    // Check usage agreement
    if let Err(e) = check_usage_agreement(&config.dnfs.domain_name, &resolver).await {
        panic!("Error checking usage agreement: {e}");
    }

    let cf_client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key,
        },
        HttpApiClientConfig::default(),
        Environment::Production,
    )?;

    match &cli.command {
        Commands::Upload(args) => {
            let magic_crypt = if args.encrypt {
                Some(magic_crypt::new_magic_crypt!(
                    &config
                        .dnfs
                        .encryption_key
                        .expect("Encrypt set to true, key is required"),
                    256
                ))
            } else {
                None
            };
            let file = File::new(Path::new(&args.path))?;
            let file_upload = file
                .upload(
                    &cf_client,
                    &config.cloudflare.zone_id,
                    &config.dnfs.domain_name,
                    magic_crypt.as_ref(),
                )
                .await?;
            println!("File successfully uploaded - {file_upload}");
        }
        Commands::Download(args) => {
            let magic_crypt = if args.decrypt {
                Some(magic_crypt::new_magic_crypt!(
                    &config
                        .dnfs
                        .encryption_key
                        .expect("Decrypt set to true, key is required"),
                    256
                ))
            } else {
                None
            };
            let file = File::read(&args.fqdn, &resolver, magic_crypt.as_ref()).await?;
            let file_data = file.read_to_string();
            println!("{file_data}");
        }
        Commands::Delete { fqdn } => {
            FileRecord::delete(fqdn, &cf_client, &config.cloudflare.zone_id, &resolver).await?;
            println!("File successfully deleted - {fqdn}");
        }
        Commands::List => {
            let records = get_all_files(&cf_client, &config.cloudflare.zone_id).await?;
            for record in records {
                println!("{name}", name = record.name);
            }
        }
        Commands::Purge { force } => {
            if *force {
                warn!("Force has been passed, skipping confirmation");
                FileRecord::purge(&cf_client, &config.cloudflare.zone_id, &resolver).await?;
                warn!("All files successfully purged");
            } else {
                warn!("BE CAREFUL!");
                warn!("This will purge all DNFS Files from the DNS zone");
                print!("Are you sure you want to purge all data? This action cannot be undone. (y/N): ");
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                if input.trim().to_lowercase() == "y" {
                    println!("By fire be purged");
                    FileRecord::purge(&cf_client, &config.cloudflare.zone_id, &resolver).await?;
                } else {
                    warn!("Purge aborted");
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use trust_dns_resolver::{config, TokioAsyncResolver};

    use crate::File;

    use super::{check_usage_agreement, Config};

    #[test]
    fn test_config() {
        let config = Config::new(Path::new("config.toml"));
        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn test_check_usage_agreement() {
        let resolver = TokioAsyncResolver::tokio(
            config::ResolverConfig::cloudflare_tls(),
            config::ResolverOpts::default(),
        );

        let result = check_usage_agreement("bunkerlab.net", &resolver).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_usage_agreement_bad() {
        let resolver = TokioAsyncResolver::tokio(
            config::ResolverConfig::cloudflare_tls(),
            config::ResolverOpts::default(),
        );

        let result = check_usage_agreement("example.com", &resolver).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upload() {
        let config = Config::new(Path::new("config.toml")).unwrap();
        let cf_client = cloudflare::framework::async_api::Client::new(
            cloudflare::framework::auth::Credentials::UserAuthToken {
                token: config.cloudflare.api_key,
            },
            cloudflare::framework::HttpApiClientConfig::default(),
            cloudflare::framework::Environment::Production,
        )
        .unwrap();

        let test = File::new(Path::new("test.txt")).unwrap();
        let result = test
            .upload(
                &cf_client,
                &config.cloudflare.zone_id,
                &config.dnfs.domain_name,
                Some(&magic_crypt::new_magic_crypt!("test", 256)),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_read_from_dns_record() {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::cloudflare_tls(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );

        let file_fqdn = "test.dnfs.bunkerlab.net";

        let file = File::read(
            file_fqdn,
            &resolver,
            Some(&magic_crypt::new_magic_crypt!("test", 256)),
        )
        .await;
        assert!(file.is_ok());

        let file_data = file
            .unwrap()
            .data
            .iter()
            .fold(String::new(), |mut acc, chunk| {
                acc.push_str(std::str::from_utf8(&chunk.data).unwrap());
                acc
            });
        println!("{file_data:?}");
    }
}
