// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    path::Path,
};

use base64::prelude::*;
use cloudflare::framework::client::async_api;
use color_eyre::{
    Result,
    eyre::{OptionExt, WrapErr},
};
use futures::stream::{self, StreamExt};
use heck::ToKebabCase;
use hickory_resolver::{TokioResolver, proto::rr::rdata::TXT};
use magic_crypt::MagicCryptTrait;
use securefmt::Debug;
use tracing::debug;

use crate::{
    file_record::FileRecord,
    helpers::{DNFSError, MAX_CHUNK_SIZE, write_txt_record},
};

#[derive(Debug, Clone)]
pub struct File {
    pub data: Vec<Chunk>,
    pub extension: Option<String>,
    pub mime: String,
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    #[sensitive]
    pub data: Vec<u8>,
    pub index: usize,
}

impl File {
    /// Create a new File from a Path
    /// This will read the file, compress it, and split it into chunks
    ///
    /// # Errors
    /// This function will return an error if the file name is invalid, the file cannot be read, or the file cannot be compressed.
    pub fn new(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .ok_or_eyre("Invalid file name")?
            .to_string_lossy();
        let name = file_name.rsplit_once('.').map_or_else(
            || file_name.to_kebab_case(),
            |(name, ext)| format!("{}.{}", name.to_kebab_case(), ext),
        );
        let data = std::fs::read(path)?;
        let compressed_data = snap::raw::Encoder::new().compress_vec(&data)?;
        let extension = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned());
        let mime = mime_guess::from_path(path).first().map_or_else(
            || "application/octet-stream".to_string(),
            |mime| mime.essence_str().to_string(),
        );
        let sha256 = sha256::digest(data.as_slice()).clone();

        Ok(Self {
            data: compressed_data
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

    /// Upload the file to the cloud
    /// This will create a `FileRecord` and `FileChunks`
    ///
    /// # Errors
    /// This function will return an error if the file cannot be uploaded
    pub async fn upload(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        magic_crypt: Option<&magic_crypt::MagicCrypt256>,
        dry_run: bool,
    ) -> Result<String> {
        // Create File Record
        let file_record = FileRecord::new(self);
        let file_fqdn = FileRecord::create(
            &file_record,
            cf_client,
            zone_identifier,
            domain_name,
            dry_run,
        )
        .await?;

        // Create File Chunks
        let _file_chunks = self
            .create_chunks(
                cf_client,
                zone_identifier,
                domain_name,
                &file_record,
                magic_crypt,
                dry_run,
            )
            .await?;

        Ok(file_fqdn)
    }

    async fn create_chunks(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        file_record: &FileRecord,
        magic_crypt: Option<&magic_crypt::MagicCrypt256>,
        dry_run: bool,
    ) -> Result<Vec<String>> {
        stream::iter(&self.data)
            .map(|chunk| {
                let chunk_fqdn = format!(
                    "chunk{index}.{name}.dnfs.{domain_name}",
                    index = chunk.index,
                    name = file_record.name,
                );
                let zone_identifier = zone_identifier.to_string();

                let data = if let Some(magic_crypt) = magic_crypt {
                    magic_crypt.encrypt_bytes_to_base64(&chunk.data)
                } else {
                    BASE64_STANDARD.encode(&chunk.data)
                };

                async move {
                    write_txt_record(&chunk_fqdn, &data, cf_client, &zone_identifier, dry_run)
                        .await
                        .wrap_err_with(|| format!("Failed to create chunk: {chunk_fqdn}"))
                }
            })
            .buffer_unordered(std::env::var("JOBS")?.parse()?)
            .collect::<Vec<Result<String>>>()
            .await
            .into_iter()
            .collect()
    }

    /// Given `file_name.dnfs.domain_name TXT "v=dnfs1 chunks=1 size=12 sha256hash=d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26 mime=text/plain extension=txt"`
    /// Reconstruct the file from its chunks and verify the sha256 hash
    ///
    /// # Errors
    /// This function will return an error if the file cannot be read, the file cannot be decompressed, or the sha256 hash is invalid
    pub async fn read(
        file_fqdn: &str,
        resolver: &TokioResolver,
        magic_crypt: Option<&magic_crypt::MagicCrypt256>,
    ) -> Result<Self> {
        debug!("Reading file: {file_fqdn}");

        let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;
        let file_chunks = File::get_chunks(file_fqdn, &file_record, resolver, magic_crypt).await?;

        // Calculate and validate SHA256 hash
        let compressed_data = file_chunks.iter().fold(Vec::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk.data);
            acc
        });
        let uncompressed_data = snap::raw::Decoder::new().decompress_vec(&compressed_data)?;
        let file_sha256 = sha256::digest(uncompressed_data.as_slice()).clone();

        if file_sha256 != file_record.sha256 {
            return Err(DNFSError::InvalidSHA256(file_record.sha256).into());
        }

        // parse to `File` struct
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

    /// Get the chunks of a file from DNS, uncompress, and output to STDOUT
    ///
    /// # Errors
    /// This function will return an error if the file cannot be read, the file cannot be decompressed, or the sha256 hash is invalid
    pub fn read_to_stdout(&self) -> Result<()> {
        let compressed = self.data.iter().fold(Vec::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk.data);
            acc
        });
        let uncompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap_or_else(|_| Vec::new());
        io::stdout().write_all(&uncompressed)?;
        Ok(())
    }

    /// Get the chunks of a file from DNS, uncompress, and output to a `String`
    ///
    /// # Errors
    /// This function will return an error if the file cannot be read, the file cannot be decompressed, the sha256 hash is invalid, or the output is not valid UTF-8
    #[allow(dead_code)]
    pub fn read_to_string(&self) -> Result<String> {
        let compressed = self.data.iter().fold(Vec::new(), |mut acc, chunk| {
            acc.extend_from_slice(&chunk.data);
            acc
        });
        let uncompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap_or_else(|_| Vec::new());
        Ok(String::from_utf8(uncompressed)?)
    }

    async fn get_chunks(
        file_fqdn: &str,
        file_record: &FileRecord,
        resolver: &TokioResolver,
        magic_crypt: Option<&magic_crypt::MagicCrypt256>,
    ) -> Result<Vec<Chunk>> {
        debug!("Getting chunks for file: {file_fqdn}");

        // use `file_fqdn` to get the domain name
        // `file_name.dnfs.domain_name.tld`
        let domain_name = file_fqdn
            .split(".dnfs.")
            .last()
            .expect("FQDN should contain .dnfs.");

        debug!("Domain name: {domain_name}");

        let mut chunks = Vec::new();
        for i in 0..file_record.chunks {
            let chunk_fqdn = format!(
                "chunk{i}.{name}.dnfs.{domain_name}",
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

            let data = if let Some(magic_crypt) = magic_crypt {
                magic_crypt.decrypt_base64_to_bytes(&chunk_data)?
            } else {
                BASE64_STANDARD.decode(&chunk_data)?
            };
            debug!("Decoded data: {data:?}");

            chunks.push(Chunk { data, index: i });
        }

        Ok(chunks)
    }
}
