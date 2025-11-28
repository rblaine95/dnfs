//! File record metadata stored in DNS TXT records.
//!
//! A `FileRecord` contains metadata about a file stored in DNFS, including
//! the number of chunks, file size, SHA256 hash, MIME type, and extension.

#![forbid(unsafe_code)]

use cloudflare::{endpoints::dns::dns::DeleteDnsRecord, framework::client::async_api};
use futures::stream::{self, StreamExt};
use hickory_resolver::{TokioResolver, proto::rr::rdata::TXT};
use securefmt::Debug;
use tracing::{debug, info};

use crate::{
    dns::{get_all_files, get_record_id, write_txt_record},
    error::DnfsError,
    file::File,
    helpers::DEFAULT_CONCURRENCY,
};

/// Current DNFS protocol version.
const DNFS_VERSION: &str = "dnfs1";

/// Options for DNS operations (delete, purge).
pub struct DnsOperationOptions<'a> {
    /// Cloudflare API client.
    pub cf_client: &'a async_api::Client,
    /// Cloudflare Zone ID.
    pub zone_id: &'a str,
    /// DNS resolver for looking up records.
    pub resolver: &'a TokioResolver,
    /// Number of concurrent operations.
    pub concurrency: usize,
    /// Whether to perform a dry run without modifying records.
    pub dry_run: bool,
}

impl<'a> DnsOperationOptions<'a> {
    /// Creates new DNS operation options.
    #[must_use]
    pub fn new(
        cf_client: &'a async_api::Client,
        zone_id: &'a str,
        resolver: &'a TokioResolver,
    ) -> Self {
        Self {
            cf_client,
            zone_id,
            resolver,
            concurrency: DEFAULT_CONCURRENCY,
            dry_run: false,
        }
    }

    /// Sets the concurrency level for parallel operations.
    #[must_use]
    pub const fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Enables or disables dry run mode.
    #[must_use]
    pub const fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }
}

impl std::fmt::Debug for DnsOperationOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsOperationOptions")
            .field("zone_id", &self.zone_id)
            .field("concurrency", &self.concurrency)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

/// Metadata record for a file stored in DNFS.
///
/// This struct represents the TXT record content that describes a file,
/// including information needed to reassemble and verify its chunks.
#[derive(Debug, Clone)]
pub struct FileRecord {
    /// Number of chunks the file is split into.
    pub chunks: usize,
    /// File extension (e.g., "txt", "pdf").
    pub extension: Option<String>,
    /// MIME type of the file.
    pub mime: String,
    /// Base name of the file (without extension).
    pub name: String,
    /// SHA256 hash of the uncompressed file content.
    pub sha256: String,
    /// Total size of the compressed data in bytes.
    pub size: usize,
    /// DNFS protocol version.
    pub version: String,
}

impl FileRecord {
    /// Creates a new `FileRecord` from a `File`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file name is invalid or empty.
    pub fn new(file: &File) -> Result<Self, DnfsError> {
        let name = file
            .name
            .split('.')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DnfsError::InvalidFileName(file.name.clone()))?
            .to_string();

        Ok(Self {
            chunks: file.data.len(),
            extension: file.extension.clone(),
            mime: file.mime.clone(),
            name,
            sha256: file.sha256.clone(),
            size: file.data.iter().map(|chunk| chunk.data.len()).sum(),
            version: DNFS_VERSION.to_string(),
        })
    }

    /// Parses a `FileRecord` from TXT record content.
    fn from_txt(name: &str, txt: &str) -> Result<Self, DnfsError> {
        let mut chunks = None;
        let mut extension = None;
        let mut mime = None;
        let mut sha256 = None;
        let mut size = None;
        let mut version = None;

        for pair in txt.split(' ') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };

            match key {
                "chunks" => {
                    chunks = Some(value.parse().map_err(|_| DnfsError::ParseError {
                        name: name.to_string(),
                        reason: format!("invalid chunks value: {value}"),
                    })?);
                }
                "extension" => extension = Some(value.to_string()),
                "mime" => mime = Some(value.to_string()),
                "sha256hash" => sha256 = Some(value.to_string()),
                "size" => {
                    size = Some(value.parse().map_err(|_| DnfsError::ParseError {
                        name: name.to_string(),
                        reason: format!("invalid size value: {value}"),
                    })?);
                }
                "v" => version = Some(value.to_string()),
                _ => {}
            }
        }

        Ok(Self {
            chunks: chunks.ok_or_else(|| DnfsError::ParseError {
                name: name.to_string(),
                reason: "missing 'chunks' field".to_string(),
            })?,
            extension,
            mime: mime.unwrap_or_else(|| "application/octet-stream".to_string()),
            name: name.to_string(),
            sha256: sha256.ok_or_else(|| DnfsError::ParseError {
                name: name.to_string(),
                reason: "missing 'sha256hash' field".to_string(),
            })?,
            size: size.ok_or_else(|| DnfsError::ParseError {
                name: name.to_string(),
                reason: "missing 'size' field".to_string(),
            })?,
            version: version.unwrap_or_else(|| DNFS_VERSION.to_string()),
        })
    }

    /// Creates a `FileRecord` by looking up a DNS TXT record.
    ///
    /// # Errors
    ///
    /// Returns an error if the DNS lookup fails or the record cannot be parsed.
    pub async fn from_dns_record(
        file_fqdn: &str,
        resolver: &TokioResolver,
    ) -> Result<Self, DnfsError> {
        let file_lookup = resolver.txt_lookup(file_fqdn).await?;
        let file_txt = file_lookup
            .iter()
            .flat_map(TXT::txt_data)
            .find_map(|txt_data| std::str::from_utf8(txt_data).ok())
            .ok_or_else(|| DnfsError::ParseError {
                name: file_fqdn.to_string(),
                reason: "no valid UTF-8 TXT data found".to_string(),
            })?;

        debug!("File TXT data: {file_txt:?}");

        let name = file_fqdn
            .split('.')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| DnfsError::ParseError {
                name: file_fqdn.to_string(),
                reason: "invalid FQDN format".to_string(),
            })?;

        Self::from_txt(name, file_txt)
    }

    /// Creates a DNS TXT record for this `FileRecord`.
    ///
    /// # Errors
    ///
    /// Returns an error if the DNS record creation fails.
    pub async fn create(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        dry_run: bool,
    ) -> Result<String, DnfsError> {
        let fqdn = format!("{}.dnfs.{domain_name}", self.name);
        let content = format!(
            "v={} chunks={} size={} sha256hash={} mime={} extension={}",
            self.version,
            self.chunks,
            self.size,
            self.sha256,
            self.mime,
            self.extension.as_deref().unwrap_or("")
        );
        write_txt_record(&fqdn, &content, cf_client, zone_identifier, dry_run).await
    }

    /// Deletes a file and all its chunks from DNS.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not found or deletion fails.
    pub async fn delete(
        file_fqdn: &str,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &TokioResolver,
        concurrency: usize,
        dry_run: bool,
    ) -> Result<(), DnfsError> {
        info!("Deleting file: {file_fqdn}");

        let file_id = get_record_id(file_fqdn, cf_client, zone_identifier)
            .await?
            .ok_or_else(|| DnfsError::RecordNotFound(file_fqdn.to_string()))?;

        let file_record = Self::from_dns_record(file_fqdn, resolver).await?;

        // Generate chunk FQDNs
        let chunk_fqdns: Vec<String> = (0..file_record.chunks)
            .map(|i| format!("chunk{i}.{file_fqdn}"))
            .collect();

        // Delete chunks in parallel
        let concurrency = if concurrency == 0 {
            DEFAULT_CONCURRENCY
        } else {
            concurrency
        };

        stream::iter(chunk_fqdns)
            .map(|chunk_fqdn| async move {
                info!("Deleting chunk: {chunk_fqdn}");
                if let Some(chunk_id) =
                    get_record_id(&chunk_fqdn, cf_client, zone_identifier).await?
                {
                    if dry_run {
                        info!("Dry run: would delete chunk {chunk_fqdn}");
                    } else {
                        cf_client
                            .request(&DeleteDnsRecord {
                                zone_identifier,
                                identifier: &chunk_id,
                            })
                            .await?;
                    }
                }
                Ok::<(), DnfsError>(())
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<Result<(), DnfsError>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, DnfsError>>()?;

        // Delete the file record itself
        if dry_run {
            info!("Dry run: would delete file record {file_fqdn}");
        } else {
            cf_client
                .request(&DeleteDnsRecord {
                    zone_identifier,
                    identifier: &file_id,
                })
                .await?;
        }

        Ok(())
    }

    /// Purges all DNFS files from the DNS zone.
    ///
    /// # Errors
    ///
    /// Returns an error if listing or deletion fails.
    pub async fn purge(
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &TokioResolver,
        concurrency: usize,
        dry_run: bool,
    ) -> Result<(), DnfsError> {
        let records = get_all_files(cf_client, zone_identifier).await?;

        for record in records {
            Self::delete(
                &record.name,
                cf_client,
                zone_identifier,
                resolver,
                concurrency,
                dry_run,
            )
            .await?;
        }

        Ok(())
    }
}
