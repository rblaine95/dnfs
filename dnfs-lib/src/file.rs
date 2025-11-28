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
    file_record::FileRecord,
    helpers::{DEFAULT_CONCURRENCY, DnfsError, MAX_CHUNK_SIZE, Result, write_txt_record},
};

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
    pub fn new(path: &Path) -> Result<Self> {
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
            .map_err(|e| DnfsError::CompressionError(e.to_string()))?;

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
    ) -> Result<String> {
        let file_record = FileRecord::new(self)?;
        let file_fqdn = file_record
            .create(cf_client, zone_identifier, domain_name, dry_run)
            .await?;

        self.upload_chunks(
            cf_client,
            zone_identifier,
            domain_name,
            &file_record,
            encryptor,
            concurrency,
            dry_run,
        )
        .await?;

        Ok(file_fqdn)
    }

    /// Uploads all file chunks in parallel.
    #[allow(clippy::too_many_arguments)]
    async fn upload_chunks(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        file_record: &FileRecord,
        encryptor: Option<&Encryptor>,
        concurrency: usize,
        dry_run: bool,
    ) -> Result<Vec<String>> {
        let concurrency = if concurrency == 0 {
            DEFAULT_CONCURRENCY
        } else {
            concurrency
        };

        stream::iter(&self.data)
            .map(|chunk| {
                let chunk_fqdn = format!(
                    "chunk{}.{}.dnfs.{domain_name}",
                    chunk.index, file_record.name,
                );
                let zone_id = zone_identifier.to_string();

                let encoded_data = match encryptor {
                    Some(enc) => enc.encrypt_to_base64(&chunk.data),
                    None => Ok(BASE64_STANDARD.encode(&chunk.data)),
                };

                async move {
                    let data = encoded_data?;
                    write_txt_record(&chunk_fqdn, &data, cf_client, &zone_id, dry_run).await
                }
            })
            .buffer_unordered(concurrency)
            .collect::<Vec<Result<String>>>()
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
    ) -> Result<Self> {
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
            .map_err(|e| DnfsError::CompressionError(e.to_string()))?;

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
    pub fn write_to_stdout(&self) -> Result<()> {
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
    pub fn to_string(&self) -> Result<String> {
        let decompressed = self.decompress()?;
        Ok(String::from_utf8(decompressed)?)
    }

    /// Decompresses the file data.
    fn decompress(&self) -> Result<Vec<u8>> {
        let compressed: Vec<u8> = self
            .data
            .iter()
            .flat_map(|chunk| &chunk.data)
            .copied()
            .collect();

        snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .map_err(|e| DnfsError::CompressionError(e.to_string()))
    }

    /// Downloads all chunks for a file from DNS.
    async fn download_chunks(
        file_fqdn: &str,
        file_record: &FileRecord,
        resolver: &TokioResolver,
        encryptor: Option<&Encryptor>,
    ) -> Result<Vec<Chunk>> {
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
