// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::path::Path;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use cloudflare::{
    endpoints::dns,
    framework::{async_api, auth, Environment, HttpApiClientConfig},
};
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

#[derive(Debug, Clone)]
struct File {
    data: Vec<Chunk>,
    extension: Option<String>,
    mime: String,
    name: String,
    sha256: String,
}

#[derive(Debug, Clone)]
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
        let mime = mime_guess::from_path(path).first().map_or_else(
            || "application/octet-stream".to_string(),
            |mime| mime.essence_str().to_string(),
        );
        let sha256 = sha256::digest(data.as_slice()).to_string();

        Ok(Self {
            data: data
                .chunks(MAX_CHUNK_SIZE)
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

    async fn upload(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
    ) -> Result<String> {
        // Create File Record
        let file_record = FileRecord::create(self);
        cf_client
            .request(&dns::CreateDnsRecord {
                zone_identifier,
                params: dns::CreateDnsRecordParams {
                    name: format!("{name}.dnfs.{domain_name}", name = file_record.name).as_str(),
                    content: dns::DnsContent::TXT {
                        content: format!(
                            "v={version} chunks={chunks} size={size} sha256hash={sha256}",
                            version = file_record.version,
                            chunks = file_record.chunks,
                            size = file_record.size,
                            sha256 = file_record.sha256,
                        ),
                    },
                    priority: None,
                    proxied: None,
                    ttl: None,
                },
            })
            .await?;

        // Create File Chunks
        for chunk in &self.data {
            let chunk_name = format!(
                "chunk{index}.{name}.dnfs.{domain_name}",
                index = chunk.index,
                name = file_record.name,
            );
            let base64_data = BASE64_STANDARD.encode(&chunk.data);
            cf_client
                .request(&dns::CreateDnsRecord {
                    zone_identifier,
                    params: dns::CreateDnsRecordParams {
                        name: &chunk_name,
                        content: dns::DnsContent::TXT {
                            content: base64_data,
                        },
                        priority: None,
                        proxied: None,
                        ttl: None,
                    },
                })
                .await?;
        }

        // Create meta record
        let meta_record = MetaRecord::create(self);
        cf_client
            .request(&dns::CreateDnsRecord {
                zone_identifier,
                params: dns::CreateDnsRecordParams {
                    name: format!("meta.{name}.dnfs.{domain_name}", name = file_record.name)
                        .as_str(),
                    content: dns::DnsContent::TXT {
                        content: format!(
                            "mime={mime} extension={extension}",
                            mime = meta_record.mime,
                            extension = meta_record.extension.unwrap_or_default(),
                        ),
                    },
                    priority: None,
                    proxied: None,
                    ttl: None,
                },
            })
            .await?;

        let file_fqdn = format!(
            "{name}.dnfs.{domain_name}",
            name = file_record.name,
            domain_name = domain_name
        );

        Ok(file_fqdn)
    }
}

#[derive(Debug, Clone)]
struct FileRecord {
    chunks: usize,
    name: String,
    sha256: String,
    size: usize,
    version: String,
}

impl FileRecord {
    fn create(file: &File) -> Self {
        Self {
            chunks: file.data.len(),
            name: file.name.split('.').next().unwrap().to_string(),
            sha256: file.sha256.clone(),
            size: file.data.iter().map(|chunk| chunk.data.len()).sum(),
            version: "DNFS1".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct MetaRecord {
    author: Option<String>,
    description: Option<String>,
    extension: Option<String>,
    mime: String,
    title: Option<String>,
}

impl MetaRecord {
    fn create(file: &File) -> Self {
        Self {
            author: None,
            description: None,
            extension: file.extension.clone(),
            mime: file.mime.clone(),
            title: None,
        }
    }
}

// #[derive(Debug, Clone)]
// struct Dir {
//     /// A map of File/Directory names to their corresponding Cloudflare TXT record IDs
//     content: BTreeMap<String, String>,
//     name: String,
// }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    cloudflare: CloudflareConfig,
    dnfs: DNFSConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CloudflareConfig {
    #[sensitive]
    api_key: String,
    zone_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DNFSConfig {
    domain_name: String,
}

impl Config {
    fn new(path: &Path) -> Result<Self> {
        match toml::from_str(std::fs::read_to_string(path)?.as_str()) {
            Ok(config) => Ok(config),
            Err(e) => Err(anyhow!("Error parsing config file: {}", e)),
        }
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Error, Debug)]
pub enum DNFSError {
    #[error("Invalid DNFS usage agreement: {0}")]
    InvalidUsageAgreement(String),
}

// Helper function to Write a TXT record
// Checks if record already exists
// If it does, update the record
async fn write_txt_record(
    name: &str,
    content: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Result<String> {
    debug!("Writing TXT record: {name:?}");
    // Check if the record already exists
    let records = cf_client
        .request(&dns::ListDnsRecords {
            zone_identifier,
            params: dns::ListDnsRecordsParams {
                name: Some(name.to_string()),
                ..Default::default()
            },
        })
        .await?;
    let identifier = records.result.iter().find_map(|record| {
        if record.name.eq(name) {
            Some(record.id.clone())
        } else {
            None
        }
    });

    if let Some(id) = identifier {
        debug!("Existing Record for {name} found with ID: {id:?}");
        let result = cf_client
            .request(&dns::UpdateDnsRecord {
                zone_identifier,
                identifier: id.as_str(),
                params: dns::UpdateDnsRecordParams {
                    name,
                    content: dns::DnsContent::TXT {
                        content: content.to_string(),
                    },
                    proxied: None,
                    ttl: None,
                },
            })
            .await?;
        Ok(result.result.name)
    } else {
        let result = cf_client
            .request(&dns::CreateDnsRecord {
                zone_identifier,
                params: dns::CreateDnsRecordParams {
                    name,
                    content: dns::DnsContent::TXT {
                        content: content.to_string(),
                    },
                    priority: None,
                    proxied: None,
                    ttl: None,
                },
            })
            .await?;
        Ok(result.result.name)
    }
}

async fn check_usage_agreement(
    domain_name: &str,
    resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
) -> Result<()> {
    let usage_agreement_host = format!("_dnfs-agreement.{domain_name}");
    let usage_agreement = resolver.txt_lookup(usage_agreement_host).await?;

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
    let config = Config::new(Path::new("config.toml"))?;
    debug!("{config:?}");

    let cf_client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key,
        },
        HttpApiClientConfig::default(),
        Environment::Production,
    )?;

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());

    // Check usage agreement
    if let Err(e) = check_usage_agreement(&config.dnfs.domain_name, &resolver).await {
        error!("Error checking usage agreement: {}", e);
        std::process::exit(1);
    }

    // Read `test.txt` into a `File` struct
    let test = File::new(Path::new("test.txt"))?;

    let test_upload = test
        .upload(
            &cf_client,
            &config.cloudflare.zone_id,
            &config.dnfs.domain_name,
        )
        .await?;
    println!("{test_upload}");

    // Read `rfc1464.txt` into a `File` struct
    // let rfc1464 = File::new(Path::new("rfc1464.txt"))?;

    Ok(())
}
