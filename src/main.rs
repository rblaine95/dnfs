use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use securefmt::Debug;
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, TokioAsyncResolver,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct File {
    data: Vec<u8>,
    extention: Option<String>,
    mime: Option<String>,
    name: String,
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

const EXPECTED_AGREEMENT: &str = "I understand that DNFS is a terrible idea and I promise I will never use it for anything important ever";

async fn check_usage_agreement(
    domain_name: &str,
    resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
) -> Result<()> {
    let usage_agreement_host = format!("_dnfs-agreement.{domain_name}");
    let usage_agreement = resolver.txt_lookup(usage_agreement_host).await?;

    #[allow(clippy::redundant_closure_for_method_calls)]
    usage_agreement
        .iter()
        .flat_map(|txt| txt.txt_data())
        .find_map(|txt_data| {
            std::str::from_utf8(txt_data).ok().and_then(|s| {
                if s.starts_with(EXPECTED_AGREEMENT) {
                    info!("Valid DNFS usage agreement found");
                    Some(Ok(()))
                } else {
                    warn!("Found TXT record, but it doesn't match. Found: {s}");
                    None
                }
            })
        })
        .unwrap_or_else(|| {
            Err(anyhow!("Usage agreement not found or does not match expected text"))
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

    let config: Config = toml::from_str(std::fs::read_to_string("config.toml")?.as_str())?;
    debug!("{config:?}");

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    if let Err(e) = check_usage_agreement(&config.dnfs.domain_name, &resolver).await {
        error!("Error checking usage agreement: {}", e);
        // You can choose to exit here or handle the error in another way
        std::process::exit(1);
    }

    Ok(())
}
