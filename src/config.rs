// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::path::Path;

use color_eyre::eyre::Result;
use securefmt::Debug;
use serde_derive::{Deserialize, Serialize};

use crate::helpers::DNFSError;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub cloudflare: Cloudflare,
    pub dnfs: Dnfs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct Cloudflare {
    #[sensitive]
    pub api_key: String,
    pub zone_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::module_name_repetitions)]
pub struct Dnfs {
    pub domain_name: String,
}

impl Config {
    pub fn new(path: &Path) -> Result<Self> {
        match toml::from_str(std::fs::read_to_string(path)?.as_str()) {
            Ok(config) => Ok(config),
            Err(e) => Err(DNFSError::ConfigError(e.to_string()).into()),
        }
    }
}
