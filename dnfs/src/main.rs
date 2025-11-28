//! DNFS CLI - Domain Name File System Command Line Interface
//!
//! A CLI tool for storing and retrieving files using DNS TXT records.

#![forbid(unsafe_code)]

mod cli;
mod clients;
mod commands;
mod config;

#[cfg(test)]
mod tests;

use std::{io, path::Path};

use clap::Parser;
use color_eyre::eyre::Result;
use tracing::{debug, info};

use cli::{Cli, Command};
use clients::{create_cloudflare_client, create_resolver};
use commands::CommandContext;
use config::Config;
use dnfs_lib::check_usage_agreement;

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

    run(&cli, &config, &cf_client, &resolver).await
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

/// Dispatches to the appropriate command handler.
async fn run(
    cli: &Cli,
    config: &Config,
    cf_client: &cloudflare::framework::client::async_api::Client,
    resolver: &hickory_resolver::TokioResolver,
) -> Result<()> {
    let ctx = CommandContext::new(
        config,
        cf_client,
        resolver,
        cli.global.jobs,
        cli.global.dry_run,
    );

    match &cli.command {
        Command::Upload(args) => commands::upload(&ctx, &args.path, args.encrypt).await,
        Command::Download(args) => commands::download(&ctx, &args.fqdn, args.decrypt).await,
        Command::Delete(args) => commands::delete(&ctx, &args.fqdn).await,
        Command::List => commands::list(&ctx).await,
        Command::Purge(args) => commands::purge(&ctx, args.force).await,
    }
}
