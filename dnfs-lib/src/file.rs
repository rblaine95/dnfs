//! File representation and operations for DNFS.
//!
//! This module provides the `File` struct for reading files from disk,
//! compressing them, splitting into chunks, and uploading to DNS.

#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use base64::prelude::*;
use cloudflare::framework::client::async_api;
use futures::stream::{self, StreamExt};
use heck::ToKebabCase;
use hickory_resolver::{TokioResolver, proto::rr::rdata::TXT};
use securefmt::Debug;
use tracing::debug;

use crate::{
    crypto::Encryptor,
    dns::write_txt_record,
    error::DnfsError,
    file_record::FileRecord,
    helpers::{DEFAULT_CONCURRENCY, MAX_CHUNK_SIZE},
};

/// Options for uploading a file to DNS.
pub struct UploadOptions<'a> {
    /// Cloudflare API client.
    pub cf_client: &'a async_api::Client,
    /// Cloudflare Zone ID.
    pub zone_id: &'a str,
    /// Domain name for DNFS records.
    pub domain_name: &'a str,
    /// Optional encryptor for encrypting chunks.
    pub encryptor: Option<&'a Encryptor>,
    /// Number of concurrent upload operations.
    pub concurrency: usize,
    /// Whether to perform a dry run without modifying records.
    pub dry_run: bool,
}

impl std::fmt::Debug for UploadOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadOptions")
            .field("zone_id", &self.zone_id)
            .field("domain_name", &self.domain_name)
            .field("encryptor", &self.encryptor.map(|_| "[PRESENT]"))
            .field("concurrency", &self.concurrency)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

impl<'a> UploadOptions<'a> {
    /// Creates new upload options.
    #[must_use]
    pub fn new(cf_client: &'a async_api::Client, zone_id: &'a str, domain_name: &'a str) -> Self {
        Self {
            cf_client,
            zone_id,
            domain_name,
            encryptor: None,
            concurrency: DEFAULT_CONCURRENCY,
            dry_run: false,
        }
    }

    /// Sets the encryptor for encrypting file chunks.
    #[must_use]
    pub const fn with_encryptor(mut self, encryptor: Option<&'a Encryptor>) -> Self {
        self.encryptor = encryptor;
        self
    }

    /// Sets the concurrency level for parallel uploads.
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

/// A file that can be stored in DNFS.
///
/// Contains the compressed and chunked file data along with metadata.
#[derive(Debug, Clone)]
pub struct File {
    /// Compressed file data split into chunks.
    pub data: Vec<Chunk>,
    /// File extension (e.g., "txt", "pdf").
    pub extension: Option<String>,
    /// MIME type of the file.
    pub mime: String,
    /// File name (kebab-case, with extension).
    pub name: String,
    /// SHA256 hash of the original uncompressed data.
    pub sha256: String,
}

/// A chunk of compressed file data.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// The compressed chunk data.
    #[sensitive]
    pub data: Vec<u8>,
    /// Zero-based index of this chunk.
    pub index: usize,
}

impl File {
    /// Creates a new `File` from a filesystem path.
    ///
    /// Reads the file, compresses it using Snappy, and splits it into chunks
    /// suitable for DNS TXT records.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file name is invalid
    /// - The file cannot be read
    /// - Compression fails
    pub fn new(path: &Path) -> Result<Self, DnfsError> {
        let file_name = path
            .file_name()
            .ok_or_else(|| DnfsError::InvalidFileName(path.display().to_string()))?
            .to_string_lossy();

        let name = file_name.rsplit_once('.').map_or_else(
            || file_name.to_kebab_case(),
            |(name, ext)| format!("{}.{ext}", name.to_kebab_case()),
        );

        let data = std::fs::read(path)?;
        let sha256 = sha256::digest(&data);
        let compressed_data = snap::raw::Encoder::new()
            .compress_vec(&data)
            .map_err(|e| DnfsError::Compression(e.to_string()))?;

        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned());

        let mime = mime_guess::from_path(path).first().map_or_else(
            || "application/octet-stream".to_string(),
            |m| m.essence_str().to_string(),
        );

        let chunks = compressed_data
            .chunks(MAX_CHUNK_SIZE)
            .enumerate()
            .map(|(index, data)| Chunk {
                data: data.to_vec(),
                index,
            })
            .collect();

        Ok(Self {
            data: chunks,
            extension,
            mime,
            name,
            sha256,
        })
    }

    /// Uploads the file to Cloudflare DNS.
    ///
    /// Creates a file metadata record and uploads all chunks in parallel.
    ///
    /// # Errors
    ///
    /// Returns an error if any DNS record creation fails.
    pub async fn upload(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        encryptor: Option<&Encryptor>,
        concurrency: usize,
        dry_run: bool,
    ) -> Result<String, DnfsError> {
        let file_record = FileRecord::new(self)?;
        let file_fqdn = file_record
            .create(cf_client, zone_identifier, domain_name, dry_run)
            .await?;

        let opts = UploadOptions::new(cf_client, zone_identifier, domain_name)
            .with_encryptor(encryptor)
            .with_concurrency(concurrency)
            .with_dry_run(dry_run);

        self.upload_chunks(&file_record, &opts).await?;

        Ok(file_fqdn)
    }

    /// Uploads all file chunks in parallel.
    async fn upload_chunks(
        &self,
        file_record: &FileRecord,
        opts: &UploadOptions<'_>,
    ) -> Result<Vec<String>, DnfsError> {
        let concurrency = if opts.concurrency == 0 {
            DEFAULT_CONCURRENCY
        } else {
            opts.concurrency
        };

        stream::iter(&self.data)
            .map(|chunk| {
                let chunk_fqdn = format!(
                    "chunk{}.{}.dnfs.{}",
                    chunk.index, file_record.name, opts.domain_name,
                );
                let zone_id = opts.zone_id.to_string();
                let cf_client = opts.cf_client;
                let dry_run = opts.dry_run;

                let encoded_data = match opts.encryptor {
                    Some(enc) => enc.encrypt_to_base64(&chunk.data),
                    None => Ok(BASE64_STANDARD.encode(&chunk.data)),
                };

                async move {
                    let data = encoded_data?;
                    write_txt_record(&chunk_fqdn, &data, cf_client, &zone_id, dry_run).await
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<Result<String, DnfsError>>>()
            .await
            .into_iter()
            .collect()
    }

    /// Downloads and reconstructs a file from DNS.
    ///
    /// Looks up the file metadata record, downloads all chunks, decompresses
    /// the data, and verifies the SHA256 hash.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DNS lookup fails
    /// - Decompression fails
    /// - The SHA256 hash doesn't match
    pub async fn read(
        file_fqdn: &str,
        resolver: &TokioResolver,
        encryptor: Option<&Encryptor>,
    ) -> Result<Self, DnfsError> {
        debug!("Reading file: {file_fqdn}");

        let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;
        let file_chunks =
            Self::download_chunks(file_fqdn, &file_record, resolver, encryptor).await?;

        // Reassemble compressed data
        let compressed_data: Vec<u8> = file_chunks
            .iter()
            .flat_map(|chunk| &chunk.data)
            .copied()
            .collect();

        // Decompress and verify hash
        let uncompressed_data = snap::raw::Decoder::new()
            .decompress_vec(&compressed_data)
            .map_err(|e| DnfsError::Compression(e.to_string()))?;

        let computed_hash = sha256::digest(&uncompressed_data);
        if computed_hash != file_record.sha256 {
            return Err(DnfsError::HashMismatch {
                expected: file_record.sha256,
                actual: computed_hash,
            });
        }

        let file = Self {
            data: file_chunks,
            extension: file_record.extension,
            mime: file_record.mime,
            name: file_record.name,
            sha256: file_record.sha256,
        };

        debug!("File loaded: {file:?}");
        Ok(file)
    }

    /// Writes the decompressed file contents to stdout.
    ///
    /// # Errors
    ///
    /// Returns an error if decompression or writing fails.
    pub fn write_to_stdout(&self) -> Result<(), DnfsError> {
        let decompressed = self.decompress()?;
        io::stdout().write_all(&decompressed)?;
        Ok(())
    }

    /// Returns the decompressed file contents as a String.
    ///
    /// # Errors
    ///
    /// Returns an error if decompression fails or the content is not valid UTF-8.
    #[allow(dead_code)]
    pub fn to_string(&self) -> Result<String, DnfsError> {
        let decompressed = self.decompress()?;
        Ok(String::from_utf8(decompressed)?)
    }

    /// Decompresses the file data.
    fn decompress(&self) -> Result<Vec<u8>, DnfsError> {
        let compressed: Vec<u8> = self
            .data
            .iter()
            .flat_map(|chunk| &chunk.data)
            .copied()
            .collect();

        snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .map_err(|e| DnfsError::Compression(e.to_string()))
    }

    /// Downloads all chunks for a file from DNS.
    async fn download_chunks(
        file_fqdn: &str,
        file_record: &FileRecord,
        resolver: &TokioResolver,
        encryptor: Option<&Encryptor>,
    ) -> Result<Vec<Chunk>, DnfsError> {
        debug!("Downloading chunks for: {file_fqdn}");

        let domain_name =
            file_fqdn
                .split(".dnfs.")
                .last()
                .ok_or_else(|| DnfsError::ParseError {
                    name: file_fqdn.to_string(),
                    reason: "FQDN must contain '.dnfs.'".to_string(),
                })?;

        debug!("Domain: {domain_name}");

        let mut chunks = Vec::with_capacity(file_record.chunks);

        for i in 0..file_record.chunks {
            let chunk_fqdn = format!("chunk{i}.{}.dnfs.{domain_name}", file_record.name,);
            debug!("Reading chunk: {chunk_fqdn}");

            let chunk_lookup = resolver.txt_lookup(&chunk_fqdn).await?;

            let chunk_data: String = chunk_lookup
                .iter()
                .flat_map(TXT::txt_data)
                .filter_map(|data| std::str::from_utf8(data).ok())
                .collect();

            debug!("Chunk data length: {}", chunk_data.len());

            let data = match encryptor {
                Some(enc) => enc.decrypt_from_base64(&chunk_data)?,
                None => BASE64_STANDARD.decode(&chunk_data)?,
            };

            chunks.push(Chunk { data, index: i });
        }

        Ok(chunks)
    }
}
