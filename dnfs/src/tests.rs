//! Integration tests for DNFS CLI.

use std::path::Path;

use cloudflare::framework::{
    Environment, auth,
    client::{ClientConfig, async_api},
};

use crate::clients::create_resolver;
use crate::config::Config;
use dnfs_lib::{DEFAULT_CONCURRENCY, Encryptor, File, check_usage_agreement};

#[test]
fn test_config_loading() {
    // Config is at workspace root, not crate root
    let config = Config::load(Path::new("../config.toml"));
    assert!(config.is_ok(), "Config should load successfully");
}

#[tokio::test]
async fn test_usage_agreement_valid() {
    let config = Config::load(Path::new("../config.toml")).expect("Config should be loaded");
    let resolver = create_resolver();
    let result = check_usage_agreement(&config.dnfs.domain_name, &resolver).await;
    assert!(result.is_ok(), "Valid domain should pass agreement check");
}

#[tokio::test]
async fn test_usage_agreement_invalid() {
    let resolver = create_resolver();
    let result = check_usage_agreement("example.com", &resolver).await;
    assert!(result.is_err(), "Domain without agreement should fail");
}

#[tokio::test]
async fn test_file_upload() {
    let config = Config::load(Path::new("../config.toml")).expect("Config should load");

    let cf_client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key.clone(),
        },
        ClientConfig::default(),
        Environment::Production,
    )
    .expect("Client should be created");

    let file = File::new(Path::new("../test.txt")).expect("File should be created");

    let encryptor = Encryptor::new("test", "bunkerlab.net").expect("Encryptor should be created");

    let result = file
        .upload(
            &cf_client,
            &config.cloudflare.zone_id,
            &config.dnfs.domain_name,
            Some(&encryptor),
            DEFAULT_CONCURRENCY,
            false,
        )
        .await;

    assert!(result.is_ok(), "Upload should succeed");
}

#[tokio::test]
async fn test_file_download() {
    let resolver = create_resolver();
    let file_fqdn = "test.dnfs.bunkerlab.net";
    let encryptor = Encryptor::new("test", "bunkerlab.net").expect("Encryptor should be created");

    let result = File::read(file_fqdn, &resolver, Some(&encryptor)).await;
    assert!(result.is_ok(), "Download should succeed");

    let file = result.expect("File should be present");
    let content = file.to_string();
    assert!(content.is_ok(), "File content should be valid UTF-8");
}
