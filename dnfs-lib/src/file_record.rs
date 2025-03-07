// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use cloudflare::{endpoints::dns, framework::async_api};
use color_eyre::{Result, eyre::WrapErr};
use futures::stream::{self, StreamExt};
use hickory_resolver::{
    AsyncResolver,
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::TXT,
};
use securefmt::Debug;
use tracing::{debug, info};

use crate::{
    file::File,
    helpers::{DNFSError, get_all_files, get_record_id, write_txt_record},
};

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub chunks: usize,
    pub extension: Option<String>,
    pub mime: String,
    pub name: String,
    pub sha256: String,
    pub size: usize,
    pub version: String,
}

impl FileRecord {
    /// Create a new `FileRecord` from a `File`
    ///
    /// # Panics
    /// This function will panic if the file name is invalid
    #[must_use]
    pub fn new(file: &File) -> Self {
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

    /// Create a new `FileRecord` from a DNS record
    ///
    /// # Errors
    /// This function will return an error if the DNS record cannot be found or parsed
    ///
    /// # Panics
    /// This function will panic if the file name is invalid
    pub async fn from_dns_record(
        file_fqdn: &str, // `file_name.dnfs.domain_name`
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<Self> {
        let file_lookup = resolver.txt_lookup(file_fqdn).await?;
        let file_txt = file_lookup
            .iter()
            .flat_map(TXT::txt_data)
            .find_map(|txt_data| std::str::from_utf8(txt_data).ok())
            .ok_or_else(|| DNFSError::ParseError(file_fqdn.to_string()))?;

        debug!("File Data: {file_txt:?}");

        Ok(Self::from_txt(
            file_fqdn.split('.').next().unwrap(),
            file_txt,
        ))
    }

    /// Create a DNS record for the `FileRecord`
    ///
    /// # Errors
    /// This function will return an error if the DNS record cannot be found or parsed
    pub async fn create(
        &self,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        domain_name: &str,
        dry_run: bool,
    ) -> Result<String> {
        let fqdn = format!("{name}.dnfs.{domain_name}", name = self.name);
        let content = format!(
            "v={version} chunks={chunks} size={size} sha256hash={sha256} mime={mime} extension={extension}",
            version = self.version,
            chunks = self.chunks,
            size = self.size,
            sha256 = self.sha256,
            mime = self.mime,
            extension = self.extension.clone().unwrap_or_default()
        );
        write_txt_record(&fqdn, &content, cf_client, zone_identifier, dry_run).await
    }

    /// Delete a DNS File Record and all chunks
    ///
    /// # Errors
    /// This function will return an error if the DNS record cannot be found or parsed
    pub async fn delete(
        file_fqdn: &str,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
        dry_run: bool,
    ) -> Result<()> {
        info!("Deleting file: {file_fqdn}");
        let identifier = get_record_id(file_fqdn, cf_client, zone_identifier).await;

        let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;

        if let Some(id) = identifier {
            let chunk_fqdns = (0..file_record.chunks)
                .map(|i| format!("chunk{i}.{file_fqdn}",))
                .collect::<Vec<String>>();

            // Use stream to process chunks in parallel
            stream::iter(chunk_fqdns)
                .map(|chunk_fqdn| async move {
                    info!("Deleting chunk: {chunk_fqdn}");
                    if let Some(chunk_id) =
                        get_record_id(&chunk_fqdn, cf_client, zone_identifier).await
                    {
                        if dry_run {
                            info!("Dry run enabled, not deleting chunk");
                            return Ok(());
                        }
                        cf_client
                            .request(&dns::DeleteDnsRecord {
                                zone_identifier,
                                identifier: chunk_id.as_str(),
                            })
                            .await
                            .wrap_err_with(|| format!("Failed to delete chunk {chunk_fqdn}"))?;
                    }
                    Ok(())
                })
                .buffer_unordered(std::env::var("JOBS")?.parse()?)
                .collect::<Vec<Result<()>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;

            if dry_run {
                info!("Dry run enabled, not deleting file");
                return Ok(());
            }
            cf_client
                .request(&dns::DeleteDnsRecord {
                    zone_identifier,
                    identifier: id.as_str(),
                })
                .await?;
        } else {
            return Err(DNFSError::RecordNotFound(file_fqdn.to_string()).into());
        }
        Ok(())
    }

    /// Purge all files in DNFS
    ///
    /// # Errors
    /// This function will return an error if the DNS record cannot be found or parsed
    pub async fn purge(
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
        dry_run: bool,
    ) -> Result<()> {
        let records = get_all_files(cf_client, zone_identifier).await?;
        for record in records {
            FileRecord::delete(&record.name, cf_client, zone_identifier, resolver, dry_run).await?;
        }
        Ok(())
    }
}
