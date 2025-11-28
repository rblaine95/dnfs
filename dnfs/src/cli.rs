//! CLI argument parsing for DNFS.
//!
//! This module defines the command-line interface using clap.

#![forbid(unsafe_code)]

use clap::{Args, Parser, Subcommand};
use dnfs_lib::DEFAULT_CONCURRENCY;
use securefmt::Debug;

/// Main CLI structure.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Domain Name File System - Store files in DNS TXT records"
)]
pub struct Cli {
    /// Global arguments shared across all commands.
    #[command(flatten)]
    pub global: GlobalArgs,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Global arguments available to all commands.
#[derive(Args, Debug)]
pub struct GlobalArgs {
    /// Number of concurrent upload/delete operations.
    #[arg(short, long, global = true, default_value_t = DEFAULT_CONCURRENCY)]
    pub jobs: usize,

    /// Dry run mode - don't actually modify DNS records.
    #[arg(long, global = true)]
    pub dry_run: bool,
}

/// Available CLI commands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Upload a file to DNS.
    Upload(UploadArgs),

    /// Download a file from DNS.
    Download(DownloadArgs),

    /// Delete a file from DNS.
    Delete(DeleteArgs),

    /// List all files stored in DNS.
    List,

    /// Delete all DNFS files from the DNS zone.
    Purge(PurgeArgs),
}

/// Arguments for the upload command.
#[derive(Args, Debug)]
pub struct UploadArgs {
    /// Path to the file to upload.
    pub path: String,

    /// Encrypt the file using AES-256 (requires `encryptionKey` in config).
    #[arg(short, long)]
    pub encrypt: bool,
}

/// Arguments for the download command.
#[derive(Args, Debug)]
pub struct DownloadArgs {
    /// The file FQDN to download (e.g., myfile.dnfs.example.com).
    pub fqdn: String,

    /// Decrypt the file (requires `encryptionKey` in config).
    #[arg(short, long)]
    pub decrypt: bool,
}

/// Arguments for the delete command.
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// The file FQDN to delete (e.g., myfile.dnfs.example.com).
    pub fqdn: String,
}

/// Arguments for the purge command.
#[derive(Args, Debug)]
pub struct PurgeArgs {
    /// Skip confirmation prompt.
    #[arg(long)]
    pub force: bool,
}
