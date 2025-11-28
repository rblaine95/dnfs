//! Error types for DNFS operations.
//!
//! This module defines all error types used throughout the DNFS library,
//! providing structured errors with meaningful context.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Errors that can occur during DNFS operations.
#[derive(Error, Debug)]
pub enum DnfsError {
    /// The DNFS usage agreement TXT record is missing or invalid.
    #[error("invalid DNFS usage agreement for domain: {domain}")]
    InvalidUsageAgreement {
        /// The domain that was checked.
        domain: String,
    },

    /// SHA256 hash verification failed.
    #[error("SHA256 hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The expected hash value.
        expected: String,
        /// The actual computed hash value.
        actual: String,
    },

    /// Failed to parse a DNS record.
    #[error("failed to parse DNS record for '{name}': {reason}")]
    ParseError {
        /// The name of the record that failed to parse.
        name: String,
        /// The reason for the parse failure.
        reason: String,
    },

    /// Configuration file error.
    #[error("configuration error: {0}")]
    Config(String),

    /// DNS record not found.
    #[error("record not found: {0}")]
    RecordNotFound(String),

    /// Invalid file name.
    #[error("invalid file name: {0}")]
    InvalidFileName(String),

    /// Compression/decompression error.
    #[error("compression error: {0}")]
    Compression(String),

    /// Encryption/decryption error.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// DNS lookup error.
    #[error("DNS lookup failed: {0}")]
    DnsLookup(#[from] hickory_resolver::ResolveError),

    /// Cloudflare API error.
    #[error("Cloudflare API error: {0}")]
    Cloudflare(#[from] cloudflare::framework::response::ApiFailure),

    /// Base64 decode error.
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// UTF-8 conversion error.
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}
