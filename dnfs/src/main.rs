// This is extremely safe, it says so right here!
#![deny(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use clap::{Args, Parser, Subcommand, arg};
use cloudflare::framework::{
    Environment, auth,
    client::{ClientConfig, async_api},
};
use color_eyre::eyre::Result;
use config::Config;
use dnfs_lib::{
    file::File,
    file_record::FileRecord,
    helpers::{check_usage_agreement, get_all_files},
};
use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use securefmt::Debug;
use tracing::{debug, warn};

mod config;

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

    #[arg(long, help = "Dry run mode, do not actually perform any actions")]
    dry_run: bool,
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
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Default log level is `info`
    if std::env::var("RUST_LOG").is_err() {
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();

    // Default number of jobs for streams is 4
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("JOBS", cli.global.jobs.to_string());
    }

    // Load config
    let config = Config::new(Path::new("config.toml"))?;
    debug!("{config:?}");

    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::cloudflare_tls(),
        TokioConnectionProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build();

    // Check usage agreement
    if let Err(e) = check_usage_agreement(&config.dnfs.domain_name, &resolver).await {
        panic!("Error checking usage agreement: {e}");
    }

    let cf_client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key,
        },
        ClientConfig::default(),
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
                    cli.global.dry_run,
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
            file.read_to_stdout()?;
        }
        Commands::Delete { fqdn } => {
            FileRecord::delete(
                fqdn,
                &cf_client,
                &config.cloudflare.zone_id,
                &resolver,
                cli.global.dry_run,
            )
            .await?;
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
                FileRecord::purge(
                    &cf_client,
                    &config.cloudflare.zone_id,
                    &resolver,
                    cli.global.dry_run,
                )
                .await?;
                warn!("All files successfully purged");
            } else {
                warn!("BE CAREFUL!");
                warn!("This will purge all DNFS Files from the DNS zone");
                print!(
                    "Are you sure you want to purge all data? This action cannot be undone. (y/N): "
                );
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                if input.trim().to_lowercase() == "y" {
                    println!("By fire be purged");
                    FileRecord::purge(
                        &cf_client,
                        &config.cloudflare.zone_id,
                        &resolver,
                        cli.global.dry_run,
                    )
                    .await?;
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

    use cloudflare::framework::{
        Environment, auth,
        client::{ClientConfig, async_api},
    };
    use hickory_resolver::{TokioResolver, config, name_server::TokioConnectionProvider};

    use crate::File;

    use super::{Config, check_usage_agreement};

    #[test]
    fn test_config() {
        let config = Config::new(Path::new("config.toml"));
        assert!(config.is_ok());
    }

    #[tokio::test]
    async fn test_check_usage_agreement() {
        let resolver = TokioResolver::builder_with_config(
            config::ResolverConfig::cloudflare_tls(),
            TokioConnectionProvider::default(),
        )
        .with_options(config::ResolverOpts::default())
        .build();

        let result = check_usage_agreement("bunkerlab.net", &resolver).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_usage_agreement_bad() {
        let resolver = TokioResolver::builder_with_config(
            config::ResolverConfig::cloudflare_tls(),
            TokioConnectionProvider::default(),
        )
        .with_options(config::ResolverOpts::default())
        .build();

        let result = check_usage_agreement("example.com", &resolver).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upload() {
        let config = Config::new(Path::new("config.toml")).unwrap();
        let cf_client = async_api::Client::new(
            auth::Credentials::UserAuthToken {
                token: config.cloudflare.api_key,
            },
            ClientConfig::default(),
            Environment::Production,
        )
        .unwrap();

        let test = File::new(Path::new("test.txt")).unwrap();
        let result = test
            .upload(
                &cf_client,
                &config.cloudflare.zone_id,
                &config.dnfs.domain_name,
                Some(&magic_crypt::new_magic_crypt!("test", 256)),
                false,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_read_from_dns_record() {
        let resolver = hickory_resolver::TokioResolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::cloudflare_tls(),
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .with_options(hickory_resolver::config::ResolverOpts::default())
        .build();

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
