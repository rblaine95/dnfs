//! Configuration loading for DNFS CLI.

#![forbid(unsafe_code)]

use std::path::Path;

use dnfs_lib::DnfsError;
use securefmt::Debug;
use serde::{Deserialize, Serialize};

/// DNFS CLI configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Cloudflare API configuration.
    pub cloudflare: CloudflareConfig,
    /// DNFS-specific configuration.
    pub dnfs: DnfsConfig,
}

/// Cloudflare API credentials and settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareConfig {
    /// Cloudflare API token with DNS write permissions.
    #[sensitive]
    pub api_key: String,
    /// Cloudflare Zone ID for the target domain.
    pub zone_id: String,
}

/// DNFS-specific settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnfsConfig {
    /// The domain name to use for DNFS storage.
    pub domain_name: String,
    /// Optional encryption key for AES-256 encryption.
    #[sensitive]
    pub encryption_key: Option<String>,
}

impl Config {
    /// Loads configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self, DnfsError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DnfsError::Config(format!("failed to read config file: {e}")))?;

        toml::from_str(&content)
            .map_err(|e| DnfsError::Config(format!("failed to parse config: {e}")))
    }
}
