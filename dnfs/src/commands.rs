//! Command handlers for the DNFS CLI.
//!
//! This module contains the implementation of each CLI command,
//! keeping the main module focused on argument parsing and setup.

#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use cloudflare::framework::client::async_api;
use color_eyre::eyre::Result;
use hickory_resolver::TokioResolver;
use tracing::{info, warn};

use crate::config::Config;
use dnfs_lib::{Encryptor, File, FileRecord, get_all_files};

/// Context for CLI operations.
///
/// Bundles together the common dependencies needed by most commands
/// to avoid passing many individual parameters.
pub struct CommandContext<'a> {
    /// Configuration loaded from config.toml.
    pub config: &'a Config,
    /// Cloudflare API client.
    pub cf_client: &'a async_api::Client,
    /// DNS resolver.
    pub resolver: &'a TokioResolver,
    /// Number of concurrent operations.
    pub concurrency: usize,
    /// Whether to perform a dry run without actually modifying records.
    pub dry_run: bool,
}

impl<'a> CommandContext<'a> {
    /// Creates a new command context.
    pub const fn new(
        config: &'a Config,
        cf_client: &'a async_api::Client,
        resolver: &'a TokioResolver,
        concurrency: usize,
        dry_run: bool,
    ) -> Self {
        Self {
            config,
            cf_client,
            resolver,
            concurrency,
            dry_run,
        }
    }

    /// Gets the zone ID from the config.
    pub fn zone_id(&self) -> &str {
        &self.config.cloudflare.zone_id
    }

    /// Gets the domain name from the config.
    pub fn domain_name(&self) -> &str {
        &self.config.dnfs.domain_name
    }
}

/// Uploads a file to DNS.
pub async fn upload(ctx: &CommandContext<'_>, path: &str, encrypt: bool) -> Result<()> {
    let encryptor = get_encryptor(ctx.config, encrypt)?;
    let file = File::new(Path::new(path))?;

    let file_fqdn = file
        .upload(
            ctx.cf_client,
            ctx.zone_id(),
            ctx.domain_name(),
            encryptor.as_ref(),
            ctx.concurrency,
            ctx.dry_run,
        )
        .await?;

    println!("File successfully uploaded: {file_fqdn}");
    Ok(())
}

/// Downloads a file from DNS and writes it to stdout.
pub async fn download(ctx: &CommandContext<'_>, fqdn: &str, decrypt: bool) -> Result<()> {
    let encryptor = get_encryptor(ctx.config, decrypt)?;
    let file = File::read(fqdn, ctx.resolver, encryptor.as_ref()).await?;
    file.write_to_stdout()?;
    Ok(())
}

/// Deletes a file from DNS.
pub async fn delete(ctx: &CommandContext<'_>, fqdn: &str) -> Result<()> {
    FileRecord::delete(
        fqdn,
        ctx.cf_client,
        ctx.zone_id(),
        ctx.resolver,
        ctx.concurrency,
        ctx.dry_run,
    )
    .await?;
    println!("File successfully deleted: {fqdn}");
    Ok(())
}

/// Lists all files stored in DNS.
pub async fn list(ctx: &CommandContext<'_>) -> Result<()> {
    let records = get_all_files(ctx.cf_client, ctx.zone_id()).await?;
    for record in records {
        println!("{}", record.name);
    }
    Ok(())
}

/// Purges all DNFS files from the DNS zone.
pub async fn purge(ctx: &CommandContext<'_>, force: bool) -> Result<()> {
    if !force && !confirm_purge()? {
        warn!("Purge aborted");
        return Ok(());
    }

    if force {
        warn!("Force flag set, skipping confirmation");
    }

    info!("By fire be purged");
    FileRecord::purge(
        ctx.cf_client,
        ctx.zone_id(),
        ctx.resolver,
        ctx.concurrency,
        ctx.dry_run,
    )
    .await?;
    warn!("All files successfully purged");
    Ok(())
}

/// Gets the encryptor if encryption/decryption is requested.
///
/// Creates an AES-256-GCM encryptor with key derived from the config's
/// `encryption_key` using Argon2id with the domain name as salt.
fn get_encryptor(config: &Config, needs_encryption: bool) -> Result<Option<Encryptor>> {
    if !needs_encryption {
        return Ok(None);
    }

    let key = config.dnfs.encryption_key.as_ref().ok_or_else(|| {
        color_eyre::eyre::eyre!("Encryption requested but no encryption_key in config")
    })?;

    Ok(Some(Encryptor::new(key, &config.dnfs.domain_name)?))
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
