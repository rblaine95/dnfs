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
    config::{CLOUDFLARE, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};

use crate::config::Config;

/// Creates a DNS resolver using Cloudflare's DNS-over-HTTPS.
///
/// This resolver is used to look up DNFS records from DNS.
///
/// # Errors
///
/// Returns an error if the resolver cannot be constructed.
pub fn create_resolver() -> Result<TokioResolver> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::https(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()?;
    Ok(resolver)
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
