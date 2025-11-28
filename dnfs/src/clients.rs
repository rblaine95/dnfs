//! Client creation utilities for DNFS.
//!
//! This module provides factory functions for creating DNS resolvers
//! and Cloudflare API clients.

#![forbid(unsafe_code)]

use cloudflare::framework::{
    Environment, auth,
    client::{ClientConfig, async_api},
};
use color_eyre::eyre::Result;
use hickory_resolver::{
    TokioResolver,
    config::{ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};

use crate::config::Config;

/// Creates a DNS resolver using Cloudflare's DNS-over-HTTPS.
///
/// This resolver is used to look up DNFS records from DNS.
#[must_use]
pub fn create_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(
        ResolverConfig::cloudflare_https(),
        TokioConnectionProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
}

/// Creates a Cloudflare API client.
///
/// # Errors
///
/// Returns an error if the client cannot be created with the provided credentials.
pub fn create_cloudflare_client(config: &Config) -> Result<async_api::Client> {
    let client = async_api::Client::new(
        auth::Credentials::UserAuthToken {
            token: config.cloudflare.api_key.clone(),
        },
        ClientConfig::default(),
        Environment::Production,
    )?;
    Ok(client)
}
