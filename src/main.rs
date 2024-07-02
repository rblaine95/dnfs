// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::{io, path::Path};

use clap::{Parser, Subcommand};
use cloudflare::framework::{async_api, auth, Environment, HttpApiClientConfig};
use color_eyre::eyre::Result;
use config::Config;
use file::File;
use file_record::FileRecord;
use helpers::{check_usage_agreement, get_all_files};
use securefmt::Debug;
use tracing::debug;
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
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Upload {
        #[arg(help = "Path to the file to upload")]
        path: String,
    },
    Download {
        #[arg(help = "The file FQDN to download")]
        fqdn: String,
    },
    Delete {
        #[arg(help = "The file FQDN to delete")]
        fqdn: String,
    },
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

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

    let cli = Cli::parse();
    match &cli.command {
        Commands::Upload { path } => {
            let file = File::new(Path::new(path))?;
            let file_upload = file
                .upload(
                    &cf_client,
                    &config.cloudflare.zone_id,
                    &config.dnfs.domain_name,
                )
                .await?;
            println!("File successfully uploaded - {file_upload}");
        }
        Commands::Download { fqdn } => {
            let file = File::read(fqdn, &resolver).await?;
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

        let file = File::read(file_fqdn, &resolver).await;
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
