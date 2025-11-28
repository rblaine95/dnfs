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
//! # Example
//!
//! ```ignore
//! use dnfs_lib::file::File;
//!
//! // Read a file from disk
//! let file = File::new(Path::new("example.txt"))?;
//!
//! // Upload to DNS
//! file.upload(&cf_client, zone_id, domain, None, 4, false).await?;
//! ```

pub mod crypto;
pub mod file;
pub mod file_record;
pub mod helpers;

// Re-export commonly used types
pub use crypto::Encryptor;
pub use file::{Chunk, File};
pub use file_record::FileRecord;
pub use helpers::{
    DEFAULT_CONCURRENCY, DnfsError, MAX_CHUNK_SIZE, Result, check_usage_agreement, get_all_files,
};
