//! Constants and shared utilities for DNFS operations.
//!
//! This module contains constants used throughout the library.

#![forbid(unsafe_code)]

/// Maximum chunk size in bytes.
///
/// Max TXT Content per record is 2048 characters.
/// Base64 encoding adds ~33% overhead (4 bytes out for every 3 bytes in).
/// With encryption, 1536 bytes in produces 2078 bytes out, which exceeds the limit.
/// Therefore, we use 1500 bytes as a safe maximum.
pub const MAX_CHUNK_SIZE: usize = 1500;

/// Default number of concurrent operations.
pub const DEFAULT_CONCURRENCY: usize = 4;
