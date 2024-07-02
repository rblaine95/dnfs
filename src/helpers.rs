// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use cloudflare::{endpoints::dns, framework::async_api};
use color_eyre::eyre::Result;
use securefmt::Debug;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::TXT,
    AsyncResolver,
};

const USAGE_AGREEMENT: &str = "I understand that DNFS is a terrible idea and I promise I will never use it for anything important ever";
// Max TXT Content per record is 2048 characters
// Base64 encoding by ±33% (for every 3 bytes of input, you get 4 bytes out)
const MAX_TXT_CONTENT_SIZE: usize = 2048;
pub const MAX_CHUNK_SIZE: usize = (MAX_TXT_CONTENT_SIZE * 3) / 4;

#[derive(Error, Debug)]
pub enum DNFSError {
    #[error("Invalid DNFS usage agreement: {0}")]
    InvalidUsageAgreement(String),
    #[error("Invalid SHA256 hash: {0}")]
    InvalidSHA256(String),
    #[error("Error parsing DNS record: {0}")]
    ParseError(String),
    #[error("Error parsing Config file: {0}")]
    ConfigError(String),
    #[error("Record not found: {0}")]
    RecordNotFound(String),
}

pub async fn get_record_id(
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
pub async fn write_txt_record(
    name: &str,
    content: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Result<String> {
    info!("Writing TXT record: {name:?}");
    // Check if the record already exists
    let identifier = get_record_id(name, cf_client, zone_identifier).await;

    if let Some(id) = identifier {
        info!("Existing Record for {name} found with ID: {id:?}");
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

pub async fn check_usage_agreement(
    domain_name: &str,
    resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
) -> Result<()> {
    debug!("Checking DNFS usage agreement for {domain_name}");
    let usage_agreement_host = format!("_dnfs-agreement.{domain_name}");
    let usage_agreement = resolver.txt_lookup(usage_agreement_host.clone()).await?;

    usage_agreement
        .iter()
        .flat_map(TXT::txt_data)
        .find_map(|txt_data| {
            std::str::from_utf8(txt_data).ok().and_then(|s| {
                if s.eq(USAGE_AGREEMENT) {
                    debug!("Valid DNFS usage agreement found");
                    Some(Ok(()))
                } else {
                    warn!("Found TXT record, but it doesn't match. Found: {s}");
                    None
                }
            })
        })
        .unwrap_or_else(|| Err(DNFSError::InvalidUsageAgreement(usage_agreement_host).into()))
}
