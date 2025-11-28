//! DNFS Library - Domain Name File System
//!
//! A library for storing and retrieving files using DNS TXT records.
//!
//! # Overview
//!
//! DNFS encodes files as DNS TXT records, splitting large files into chunks
//! and compressing the data with Snappy. Optional encryption is supported
//! using AES-256-GCM with Argon2id key derivation.
//!
//! # Modules
//!
//! - [`crypto`]: Encryption and decryption using AES-256-GCM
//! - [`dns`]: DNS record operations and Cloudflare API interaction
//! - [`error`]: Error types for DNFS operations
//! - [`mod@file`]: File reading, compression, chunking, and upload/download
//! - [`file_record`]: Metadata records stored in DNS
//!
//! # Example
//!
//! ```ignore
//! use dnfs_lib::File;
//! use std::path::Path;
//!
//! // Read a file from disk
//! let file = File::new(Path::new("example.txt"))?;
//!
//! // Upload to DNS
//! file.upload(&cf_client, zone_id, domain, None, 4, false).await?;
//! ```

#![forbid(unsafe_code)]

pub mod crypto;
pub mod dns;
pub mod error;
pub mod file;
pub mod file_record;
pub mod helpers;

// Re-export commonly used types at the crate root
pub use crypto::Encryptor;
pub use dns::{check_usage_agreement, get_all_files, get_record_id, write_txt_record};
pub use error::DnfsError;
pub use file::{Chunk, File, UploadOptions};
pub use file_record::{DnsOperationOptions, FileRecord};
pub use helpers::{DEFAULT_CONCURRENCY, MAX_CHUNK_SIZE};
