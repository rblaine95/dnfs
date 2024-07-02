// This is extremely safe, it says so right here!
#![forbid(unsafe_code)]

use cloudflare::{endpoints::dns, framework::async_api};
use color_eyre::eyre::Result;
use securefmt::Debug;
use tracing::{debug, info};
use trust_dns_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::TXT,
    AsyncResolver,
};

use crate::{
    file::File,
    helpers::{get_all_files, get_record_id, write_txt_record, DNFSError},
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

    pub async fn create(
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

    pub async fn delete(
        file_fqdn: &str,
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<()> {
        info!("Deleting file: {file_fqdn}");
        let identifier = get_record_id(file_fqdn, cf_client, zone_identifier).await;

        if let Some(id) = identifier {
            let file_record = FileRecord::from_dns_record(file_fqdn, resolver).await?;
            let chunk_fqdns = (0..file_record.chunks)
                .map(|i| format!("chunk{i}.{file_fqdn}",))
                .collect::<Vec<String>>();
            for chunk_fqdn in chunk_fqdns {
                info!("Deleting chunk: {chunk_fqdn}");
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
            return Err(DNFSError::RecordNotFound(file_fqdn.to_string()).into());
        }
        Ok(())
    }

    pub async fn purge(
        cf_client: &async_api::Client,
        zone_identifier: &str,
        resolver: &AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    ) -> Result<()> {
        let records = get_all_files(cf_client, zone_identifier).await?;
        for record in records {
            FileRecord::delete(&record.name, cf_client, zone_identifier, resolver).await?;
        }
        Ok(())
    }
}
