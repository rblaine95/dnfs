// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use cloudflare::{
    endpoints::dns::dns::{
        CreateDnsRecord, CreateDnsRecordParams, DnsContent, DnsRecord, ListDnsRecords,
        ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
    },
    framework::client::async_api,
};
use color_eyre::eyre::Result;
use hickory_resolver::{TokioResolver, proto::rr::rdata::TXT};
use securefmt::Debug;
use thiserror::Error;
use tracing::{debug, error, info, warn};

const USAGE_AGREEMENT: &str = "I understand that DNFS is a terrible idea and I promise I will never use it for anything important ever";
// Max TXT Content per record is 2048 characters
// Base64 encoding adds ±33% (for every 3 bytes of input, you get 4 bytes out)
// const MAX_TXT_CONTENT_SIZE: usize = 2048;
// pub const MAX_CHUNK_SIZE: usize = (MAX_TXT_CONTENT_SIZE * 3) / 4;
// BUT because we're encrypting now as well
// 1536 in = 2078 out which is just a little too big
pub const MAX_CHUNK_SIZE: usize = 1500;

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

// Helper function to the ID of a specific record
pub async fn get_record_id(
    name: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Option<String> {
    cf_client
        .request(&ListDnsRecords {
            zone_identifier,
            params: ListDnsRecordsParams {
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

/// Helper function to get all records under the `dnfs` subdomain
/// Returns a `Vec` of all records of File FQDNs
///
/// # Errors
/// Returns an error if the request fails
pub async fn get_all_files(
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Result<Vec<DnsRecord>> {
    let request = ListDnsRecords {
        zone_identifier,
        params: ListDnsRecordsParams {
            ..Default::default()
        },
    };
    debug!("Request: {request:?}");
    let response = cf_client.request(&request).await?;
    // Filter for records under the `dnfs` subdomain
    let records = response
        .result
        .into_iter()
        .filter(|record| record.name.contains(".dnfs") && !record.name.contains("chunk"))
        .collect();
    Ok(records)
}

/// Helper function to Write a TXT record
/// Checks if record already exists
/// If it does, update the record
///
/// # Errors
/// Returns an error if the request fails
pub async fn write_txt_record(
    name: &str,
    content: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
    dry_run: bool,
) -> Result<String> {
    info!("Writing TXT record: {name:?}");
    // Check if the record already exists
    let identifier = get_record_id(name, cf_client, zone_identifier).await;

    if let Some(id) = identifier {
        info!("Existing Record for {name} found with ID: {id:?}");
        let request = UpdateDnsRecord {
            zone_identifier,
            identifier: id.as_str(),
            params: UpdateDnsRecordParams {
                name,
                content: DnsContent::TXT {
                    content: content.to_string(),
                },
                proxied: None,
                ttl: None,
            },
        };
        debug!("Request: {request:?}");
        if dry_run {
            info!("Dry run enabled, not updating record");
            Ok(name.to_string())
        } else {
            let response = cf_client.request(&request).await?;
            Ok(response.result.name)
        }
    } else {
        let request = CreateDnsRecord {
            zone_identifier,
            params: CreateDnsRecordParams {
                name,
                content: DnsContent::TXT {
                    content: content.to_string(),
                },
                priority: None,
                proxied: None,
                ttl: None,
            },
        };
        debug!("Request: {request:?}");
        if dry_run {
            info!("Dry run enabled, not creating record");
            Ok(name.to_string())
        } else {
            let response = cf_client.request(&request).await?;
            Ok(response.result.name)
        }
    }
}

/// Helper function to check the DNFS usage agreement
///
/// # Errors
/// Returns an error if the TXT record is not found or if the content doesn't match
pub async fn check_usage_agreement(domain_name: &str, resolver: &TokioResolver) -> Result<()> {
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
