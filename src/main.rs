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
const MAX_CHUNK_SIZE: usize = 1024;

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
        let file_record = FileRecord::new(self);
        let file_fqdn =
            FileRecord::create(&file_record, cf_client, zone_identifier, domain_name).await?;

        // Create File Chunks
        let _file_chunks = self
            .create_chunks(cf_client, zone_identifier, domain_name, &file_record)
            .await?;

        Ok(file_fqdn)
    }

    async fn create_chunks(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        file_record: &FileRecord,
    ) -> Result<Vec<String>> {
        let mut chunk_vec = Vec::new();

        for chunk in &self.data {
            let chunk_fqdn = format!(
                "chunk{index}.{name}.dnfs.{domain_name}",
                index = chunk.index,
                name = file_record.name,
            );

            let base64_data = BASE64_STANDARD.encode(&chunk.data);

            chunk_vec.push(
                write_txt_record(&chunk_fqdn, &base64_data, cf_client, zone_identifier).await?,
            );
        }

        Ok(chunk_vec)
    }

    // Given `file_name.dnfs.domain_name TXT "v=dnfs1 chunks=1 size=12 sha256hash=d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26 mime=text/plain extension=txt"`
    // Reconstruct the file from its chunks, verify the sha256 hash, and output to STDOUT
    async fn read(
        file_fqdn: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<File> {
        debug!("Reading file: {file_fqdn}");

        let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;
        let file_chunks = File::get_chunks(file_fqdn, &file_record, resolver).await?;
        let file_data = file_chunks.iter().fold(Vec::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk.data);
            acc
        });

        let file_sha256 = sha256::digest(file_data.as_slice()).to_string();

        if file_sha256 != file_record.sha256 {
            return Err(anyhow!("File integrity check failed"));
        }

        // parse `file_data` to `File` struct
        let file = File {
            data: file_chunks,
            extension: file_record.extension,
            mime: file_record.mime,
            name: file_record.name,
            sha256: file_record.sha256,
        };

        debug!("File: {file:?}");

        Ok(file)
    }

    fn read_to_string(&self) -> String {
        self.data.iter().fold(String::new(), |mut acc, chunk| {
            acc.push_str(std::str::from_utf8(&chunk.data).unwrap());
            acc
        })
    }

    async fn get_chunks(
        file_fqdn: &str,
        file_record: &FileRecord,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<Vec<Chunk>> {
        debug!("Getting chunks for file: {file_fqdn}");

        // use `file_fqdn` to get the domain name
        // `file_name.dnfs.domain_name.tld`
        let domain_name = file_fqdn.split(".dnfs.").last().unwrap();

        debug!("Domain name: {domain_name}");

        let mut chunks = Vec::new();
        for i in 0..file_record.chunks {
            let chunk_fqdn = format!(
                "chunk{i}.{name}.dnfs.{domain_name}",
                i = i,
                name = file_record.name,
            );
            debug!("Reading chunk {chunk_fqdn}");

            let chunk_lookup = resolver.txt_lookup(chunk_fqdn).await?;

            // Convert the full TXT record data from `Vec<u8>` to `&str`
            let chunk_data: String = chunk_lookup
                .iter()
                .flat_map(TXT::txt_data)
                .filter_map(|txt_data| std::str::from_utf8(txt_data).ok())
                .collect();
            debug!("Chunk data: {chunk_data:?}");

            let data = BASE64_STANDARD.decode(chunk_data.as_bytes())?;
            debug!("Decoded data: {data:?}");

            chunks.push(Chunk { data, index: i });
        }

        Ok(chunks)
    }
}

#[derive(Debug, Clone)]
struct FileRecord {
    chunks: usize,
    extension: Option<String>,
    mime: String,
    name: String,
    sha256: String,
    size: usize,
    version: String,
}

impl FileRecord {
    fn new(file: &File) -> Self {
        Self {
            chunks: file.data.len(),
            extension: file.extension.clone(),
            mime: file.mime.clone(),
            name: file.name.split('.').next().unwrap().to_string(),
            sha256: file.sha256.clone(),
            size: file.data.iter().map(|chunk| chunk.data.len()).sum(),
            version: "dnfs1".to_string(),
        }
    }

    fn from_txt(name: &str, txt: &str) -> Self {
        let mut chunks = 0;
        let mut extension = None;
        let mut mime = String::new();
        let mut sha256 = String::new();
        let mut size = 0;
        let mut version = String::new();

        for pair in txt.split(' ') {
            let mut split = pair.split('=');
            let key = split.next().unwrap();
            let value = split.next().unwrap();

            match key {
                "chunks" => chunks = value.parse().unwrap(),
                "extension" => extension = Some(value.to_string()),
                "mime" => mime = value.to_string(),
                "sha256hash" => sha256 = value.to_string(),
                "size" => size = value.parse().unwrap(),
                "v" => version = value.to_string(),
                _ => (),
            }
        }

        Self {
            chunks,
            extension,
            mime,
            name: name.to_string(),
            sha256,
            size,
            version,
        }
    }

    async fn from_dns_record(
        file_fqdn: &str, // `file_name.dnfs.domain_name`
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<Self> {
        let file_lookup = resolver.txt_lookup(file_fqdn).await?;
        let file_txt = file_lookup
            .iter()
            .flat_map(TXT::txt_data)
            .find_map(|txt_data| std::str::from_utf8(txt_data).ok())
            .ok_or_else(|| anyhow!("Error parsing TXT record"))?;

        debug!("File Data: {file_txt:?}");

        Ok(Self::from_txt(
            file_fqdn.split('.').next().unwrap(),
            file_txt,
        ))
    }

    async fn create(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
    ) -> Result<String> {
        let fqdn = format!("{name}.dnfs.{domain_name}", name = self.name);
        let content = format!(
                "v={version} chunks={chunks} size={size} sha256hash={sha256} mime={mime} extension={extension}",
                version = self.version,
                chunks = self.chunks,
                size = self.size,
                sha256 = self.sha256,
                mime = self.mime,
                extension = self.extension.clone().unwrap_or_default());
        write_txt_record(&fqdn, &content, cf_client, zone_identifier).await
    }

    async fn delete(
        file_fqdn: &str,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<()> {
        debug!("Deleting file: {file_fqdn}");
        let identifier = get_record_id(file_fqdn, cf_client, zone_identifier).await;

        if let Some(id) = identifier {
            let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;
            let chunk_fqdns = (0..file_record.chunks)
                .map(|i| format!("chunk{i}.{file_fqdn}",))
                .collect::<Vec<String>>();
            for chunk_fqdn in chunk_fqdns {
                debug!("Deleting chunk: {chunk_fqdn}");
                let chunk_id = get_record_id(chunk_fqdn.as_str(), cf_client, zone_identifier).await;
                if let Some(id) = chunk_id {
                    cf_client
                        .request(&dns::DeleteDnsRecord {
                            zone_identifier,
                            identifier: id.as_str(),
                        })
                        .await?;
                }
            }
            cf_client
                .request(&dns::DeleteDnsRecord {
                    zone_identifier,
                    identifier: id.as_str(),
                })
                .await?;
        } else {
            return Err(anyhow!("Record not found"));
        }
        Ok(())
    }
}

// #[derive(Debug, Clone)]
// struct MetaRecord {
//     author: Option<String>,
//     description: Option<String>,
//     extension: Option<String>,
//     mime: String,
//     title: Option<String>,
// }

// impl MetaRecord {
//     fn new(file: &File) -> Self {
//         Self {
//             author: None,
//             description: None,
//             extension: file.extension.clone(),
//             mime: file.mime.clone(),
//             title: None,
//         }
//     }
// }

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

async fn get_record_id(
    name: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Option<String> {
    cf_client
        .request(&dns::ListDnsRecords {
            zone_identifier,
            params: dns::ListDnsRecordsParams {
                name: Some(name.to_string()),
                ..Default::default()
            },
        })
        .await
        .ok()?
        .result
        .iter()
        .find(|record| record.name.eq(name))
        .map(|record| record.id.clone())
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
    let identifier = get_record_id(name, cf_client, zone_identifier).await;

    if let Some(id) = identifier {
        debug!("Existing Record for {name} found with ID: {id:?}");
        let request = dns::UpdateDnsRecord {
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
        };
        debug!("Request: {request:?}");
        let response = cf_client.request(&request).await?;
        Ok(response.result.name)
    } else {
        let request = dns::CreateDnsRecord {
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
        };
        debug!("Request: {request:?}");
        let response = cf_client.request(&request).await?;
        Ok(response.result.name)
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
                if s.eq(USAGE_AGREEMENT) {
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

    // Read `test.dnfs.bunkerlab.net` into a `File` struct
    let test_file_data = (File::read("test.dnfs.bunkerlab.net", &resolver).await?).read_to_string();
    println!("{test_file_data}");

    // Read `rfc1464.txt` into a `File` struct
    // let rfc1464 = File::new(Path::new("rfc1464.txt"))?;

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
