//! DNS operations for DNFS.
//!
//! This module provides utilities for interacting with Cloudflare DNS,
//! including reading and writing TXT records.

#![forbid(unsafe_code)]

use cloudflare::{
    endpoints::dns::dns::{
        CreateDnsRecord, CreateDnsRecordParams, DnsContent, DnsRecord, ListDnsRecords,
        ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
    },
    framework::client::async_api,
};
use hickory_resolver::{TokioResolver, proto::rr::rdata::TXT};
use tracing::{debug, info, warn};

use crate::error::DnfsError;

/// The required TXT record content for DNFS usage agreement.
const USAGE_AGREEMENT: &str = "I understand that DNFS is a terrible idea and I promise I will never use it for anything important ever";

/// Gets the Cloudflare record ID for a DNS record by name.
///
/// Returns `None` if the record doesn't exist.
///
/// # Errors
///
/// Returns an error if the Cloudflare API request fails.
pub async fn get_record_id(
    name: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Result<Option<String>, DnfsError> {
    let response = cf_client
        .request(&ListDnsRecords {
            zone_identifier,
            params: ListDnsRecordsParams {
                name: Some(name.to_string()),
                ..Default::default()
            },
        })
        .await?;

    let record_id = response
        .result
        .iter()
        .find(|record| record.name == name)
        .map(|record| record.id.clone());

    Ok(record_id)
}

/// Gets all DNFS file records from the DNS zone.
///
/// Returns a list of DNS records for files (excluding chunk records).
///
/// # Errors
///
/// Returns an error if the Cloudflare API request fails.
pub async fn get_all_files(
    cf_client: &async_api::Client,
    zone_identifier: &str,
) -> Result<Vec<DnsRecord>, DnfsError> {
    let request = ListDnsRecords {
        zone_identifier,
        params: ListDnsRecordsParams::default(),
    };
    debug!("Listing DNS records: {request:?}");

    let response = cf_client.request(&request).await?;

    // Filter for file records under the `dnfs` subdomain (excluding chunks)
    let records = response
        .result
        .into_iter()
        .filter(|record| record.name.contains(".dnfs") && !record.name.contains("chunk"))
        .collect();

    Ok(records)
}

/// Writes a TXT record to Cloudflare DNS.
///
/// If a record with the same name already exists, it will be updated.
/// Otherwise, a new record will be created.
///
/// # Errors
///
/// Returns an error if the Cloudflare API request fails.
pub async fn write_txt_record(
    name: &str,
    content: &str,
    cf_client: &async_api::Client,
    zone_identifier: &str,
    dry_run: bool,
) -> Result<String, DnfsError> {
    info!("Writing TXT record: {name:?}");

    let existing_id = get_record_id(name, cf_client, zone_identifier).await?;
    let txt_content = DnsContent::TXT {
        content: content.to_string(),
    };

    if dry_run {
        info!(
            "Dry run: would {} record {name}",
            if existing_id.is_some() {
                "update"
            } else {
                "create"
            }
        );
        return Ok(name.to_string());
    }

    let result_name = if let Some(id) = existing_id {
        info!("Updating existing record {name} (ID: {id})");
        let request = UpdateDnsRecord {
            zone_identifier,
            identifier: &id,
            params: UpdateDnsRecordParams {
                name,
                content: txt_content,
                proxied: None,
                ttl: None,
            },
        };
        debug!("Update request: {request:?}");
        cf_client.request(&request).await?.result.name
    } else {
        let request = CreateDnsRecord {
            zone_identifier,
            params: CreateDnsRecordParams {
                name,
                content: txt_content,
                priority: None,
                proxied: None,
                ttl: None,
            },
        };
        debug!("Create request: {request:?}");
        cf_client.request(&request).await?.result.name
    };

    Ok(result_name)
}

/// Checks that the domain has a valid DNFS usage agreement TXT record.
///
/// The domain must have a `_dnfs-agreement` TXT record with the exact
/// required agreement text.
///
/// # Errors
///
/// Returns an error if:
/// - The TXT record lookup fails
/// - The agreement record is missing or has incorrect content
pub async fn check_usage_agreement(
    domain_name: &str,
    resolver: &TokioResolver,
) -> Result<(), DnfsError> {
    debug!("Checking DNFS usage agreement for {domain_name}");
    let agreement_host = format!("_dnfs-agreement.{domain_name}");
    let lookup_result = resolver.txt_lookup(&agreement_host).await?;

    let agreement_found = lookup_result
        .iter()
        .flat_map(TXT::txt_data)
        .filter_map(|data| std::str::from_utf8(data).ok())
        .any(|txt| txt == USAGE_AGREEMENT);

    if agreement_found {
        debug!("Valid DNFS usage agreement found for {domain_name}");
        Ok(())
    } else {
        warn!("DNFS usage agreement not found or invalid for {domain_name}");
        Err(DnfsError::InvalidUsageAgreement {
            domain: domain_name.to_string(),
        })
    }
}
