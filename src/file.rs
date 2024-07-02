// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use std::path::Path;

use base64::prelude::*;
use cloudflare::framework::async_api;
use color_eyre::eyre::{OptionExt, Result};
use securefmt::Debug;
use tracing::debug;
use trust_dns_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::TXT,
    AsyncResolver,
};

use crate::{
    file_record::FileRecord,
    helpers::{write_txt_record, DNFSError, MAX_CHUNK_SIZE},
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
    pub fn new(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .ok_or_eyre("Invalid file name")?
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

    pub async fn upload(
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
    pub async fn read(
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
            return Err(DNFSError::InvalidSHA256(file_record.sha256).into());
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

    pub fn read_to_string(&self) -> String {
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
