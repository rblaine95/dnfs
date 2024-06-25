use std::{collections::BTreeMap, path::Path};

use anyhow::{anyhow, Result};
use securefmt::Debug;
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::TXT,
    AsyncResolver, TokioAsyncResolver,
};

const USAGE_AGREEMENT: &str = "I understand that DNFS is a terrible idea and I promise I will never use it for anything important ever";
const MAX_CHUNK_SIZE: usize = 2048;
// const SEPARATOR: &str = "|";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct File {
    data: Vec<Chunk>,
    extension: Option<String>,
    mime: Option<String>,
    name: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Chunk {
    #[sensitive]
    data: Vec<u8>,
    index: usize,
}

impl File {
    fn new(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("Invalid file name"))?
            .to_string_lossy()
            .into_owned();
        let data = std::fs::read(path)?;
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned());
        let mime = mime_guess::from_path(path)
            .first()
            .map(|mime| mime.essence_str().to_string());
        let sha256 = sha256::digest(data.as_slice()).to_string();

        // Ensure that the data is split into chunks of at most 2048 bytes
        // We need to subtract:
        // - 1 byte for the separator
        // - 2 bytes for the chunk index (0-99)
        let chunk_size = MAX_CHUNK_SIZE - 1 - 2;

        Ok(Self {
            data: data
                .chunks(chunk_size)
                .enumerate()
                .map(|(index, data)| Chunk {
                    data: data.to_vec(),
                    index,
                })
                .collect(),
            extension,
            mime,
            name,
            sha256,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Dir {
    /// A map of File/Directory names to their corresponding Cloudflare TXT record IDs
    content: BTreeMap<String, String>,
    name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    cloudflare: CloudflareConfig,
    dnfs: DNFSConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CloudflareConfig {
    account_id: String,
    #[sensitive]
    api_key: String,
    email: String,
    zone_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DNFSConfig {
    domain_name: String,
}

#[derive(Error, Debug)]
pub enum DNFSError {
    #[error("Invalid DNFS usage agreement: {0}")]
    InvalidUsageAgreement(String),
}

async fn check_usage_agreement(
    domain_name: &str,
    resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
) -> Result<()> {
    let usage_agreement_host = format!("_dnfs-agreement.{domain_name}");
    let usage_agreement = resolver.txt_lookup(usage_agreement_host).await?;

    // #[allow(clippy::redundant_closure_for_method_calls)]
    usage_agreement
        .iter()
        .flat_map(TXT::txt_data)
        .find_map(|txt_data| {
            std::str::from_utf8(txt_data).ok().and_then(|s| {
                if s.starts_with(USAGE_AGREEMENT) {
                    info!("Valid DNFS usage agreement found");
                    Some(Ok(()))
                } else {
                    warn!("Found TXT record, but it doesn't match. Found: {s}");
                    None
                }
            })
        })
        .unwrap_or_else(|| {
            Err(anyhow!(
                "Usage agreement not found or does not match expected text"
            ))
        })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Default log level is `info`
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            std::env::var("LOG_LEVEL").unwrap_or("info".to_string()),
        );
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load config
    let config: Config =
        toml::from_str(std::fs::read_to_string(Path::new("config.toml"))?.as_str())?;
    debug!("{config:?}");

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());

    // Check usage agreement
    if let Err(e) = check_usage_agreement(&config.dnfs.domain_name, &resolver).await {
        error!("Error checking usage agreement: {}", e);
        std::process::exit(1);
    }

    // Read `rfc1464.txt` into a `File` struct
    let rfc1464 = File::new(Path::new("rfc1464.txt"))?;
    println!("{rfc1464:?}");

    Ok(())
}
