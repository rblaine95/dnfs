//! Cryptographic operations for DNFS.
//!
//! This module provides secure encryption using AES-256-GCM with Argon2id
//! key derivation. It replaces the vulnerable `magic-crypt` library.
//!
//! # Security Features
//!
//! - **AES-256-GCM**: Authenticated encryption providing confidentiality and integrity
//! - **Argon2id**: Memory-hard password hashing resistant to GPU/ASIC attacks
//! - **Random nonces**: Each encryption uses a unique 96-bit nonce
//! - **No unsafe code**: All operations use safe Rust

#![forbid(unsafe_code)]

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Argon2, Params};
use base64::prelude::*;
use rand::Rng;

use crate::error::DnfsError;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;

/// Size of the GCM nonce in bytes.
const NONCE_SIZE: usize = 12;

/// An encryptor that uses AES-256-GCM for authenticated encryption.
///
/// The encryption key is derived from a password using Argon2id,
/// which is resistant to GPU and ASIC-based attacks.
///
/// # Example
///
/// ```
/// use dnfs_lib::crypto::Encryptor;
///
/// let encryptor = Encryptor::new("my-secret-password", "example.com").unwrap();
/// let ciphertext = encryptor.encrypt(b"Hello, World!").unwrap();
/// let plaintext = encryptor.decrypt(&ciphertext).unwrap();
/// assert_eq!(plaintext, b"Hello, World!");
/// ```
#[derive(Clone)]
pub struct Encryptor {
    /// The AES-GCM cipher instance.
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

impl Encryptor {
    /// Creates a new encryptor from a password and domain name.
    ///
    /// The password is processed through Argon2id with the domain name as salt
    /// to derive a 256-bit key. This ensures that the same password produces
    /// different keys for different domains.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use dnfs_lib::crypto::Encryptor;
    ///
    /// let encryptor = Encryptor::new("my-secret-password", "example.com").unwrap();
    /// ```
    pub fn new(password: &str, salt: &str) -> Result<Self, DnfsError> {
        let key_bytes = derive_key(password, salt)?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    /// Encrypts data and returns the ciphertext with prepended nonce.
    ///
    /// The output format is: `nonce (12 bytes) || ciphertext || auth tag (16 bytes)`
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (should not happen with valid inputs).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DnfsError> {
        // Generate a random nonce for each encryption
        let nonce_bytes: [u8; NONCE_SIZE] = rand::rng().random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| DnfsError::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypts data that was encrypted with `encrypt`.
    ///
    /// Expects input format: `nonce (12 bytes) || ciphertext || auth tag (16 bytes)`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is too short to contain a nonce
    /// - The authentication tag is invalid (data was tampered with)
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DnfsError> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(DnfsError::Encryption(
                "Ciphertext too short to contain nonce".to_string(),
            ));
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|e| DnfsError::Encryption(format!("Decryption failed: {e}")))
    }

    /// Encrypts data and returns it as a base64-encoded string.
    ///
    /// This is convenient for storing encrypted data in DNS TXT records.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_to_base64(&self, plaintext: &[u8]) -> Result<String, DnfsError> {
        let ciphertext = self.encrypt(plaintext)?;
        Ok(BASE64_STANDARD.encode(ciphertext))
    }

    /// Decrypts base64-encoded ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base64 decoding fails
    /// - Decryption fails (authentication tag mismatch)
    pub fn decrypt_from_base64(&self, encoded: &str) -> Result<Vec<u8>, DnfsError> {
        let ciphertext = BASE64_STANDARD.decode(encoded)?;
        self.decrypt(&ciphertext)
    }
}

/// Derives a 256-bit key from a password and domain using Argon2id.
///
/// The domain name is hashed with SHA-256 to create a consistent-length salt.
/// This ensures:
/// - Same password on different domains = different encryption keys
/// - Deterministic: same password+domain always produces the same key
/// - No rainbow table attacks: domain acts as a unique salt per deployment
///
/// Argon2id is the recommended variant that provides both:
/// - Side-channel resistance (from Argon2i)
/// - GPU/ASIC resistance (from Argon2d)
fn derive_key(password: &str, domain: &str) -> Result<[u8; KEY_SIZE], DnfsError> {
    let mut key = [0u8; KEY_SIZE];

    // Use SHA-256 hash of domain as salt for consistent 32-byte salt
    let domain_hash = sha256::digest(domain.as_bytes());
    let salt = domain_hash.as_bytes();

    // Argon2 parameters: moderate memory and iterations for reasonable performance
    // m=19456 (19 MiB), t=2 iterations, p=1 parallelism
    let params = Params::new(19456, 2, 1, Some(KEY_SIZE))
        .map_err(|e| DnfsError::Encryption(format!("Invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| DnfsError::Encryption(format!("Key derivation failed: {e}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext = b"Hello, DNFS!";

        let ciphertext = encryptor.encrypt(plaintext).expect("Should encrypt");
        let decrypted = encryptor.decrypt(&ciphertext).expect("Should decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_base64_roundtrip() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext = b"Hello, DNFS!";

        let encoded = encryptor
            .encrypt_to_base64(plaintext)
            .expect("Should encrypt to base64");
        let decrypted = encryptor
            .decrypt_from_base64(&encoded)
            .expect("Should decrypt from base64");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext = b"Same message";

        let ciphertext1 = encryptor.encrypt(plaintext).expect("Should encrypt");
        let ciphertext2 = encryptor.encrypt(plaintext).expect("Should encrypt");

        // Ciphertexts should be different due to random nonces
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryptor.decrypt(&ciphertext1).expect("Should decrypt");
        let decrypted2 = encryptor.decrypt(&ciphertext2).expect("Should decrypt");
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext = b"Hello, DNFS!";

        let mut ciphertext = encryptor.encrypt(plaintext).expect("Should encrypt");

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = encryptor.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_password_fails() {
        let encryptor1 =
            Encryptor::new("password1", "example.com").expect("Should create encryptor");
        let encryptor2 =
            Encryptor::new("password2", "example.com").expect("Should create encryptor");
        let plaintext = b"Secret message";

        let ciphertext = encryptor1.encrypt(plaintext).expect("Should encrypt");

        // Decryption with wrong password should fail
        let result = encryptor2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_domains_produce_different_keys() {
        let encryptor1 =
            Encryptor::new("password", "domain1.com").expect("Should create encryptor");
        let encryptor2 =
            Encryptor::new("password", "domain2.com").expect("Should create encryptor");
        let plaintext = b"Secret message";

        let ciphertext = encryptor1.encrypt(plaintext).expect("Should encrypt");

        // Same password but different domain should produce different keys
        let result = encryptor2.decrypt(&ciphertext);
        assert!(
            result.is_err(),
            "Different domains should produce incompatible keys"
        );
    }

    #[test]
    fn test_empty_plaintext() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext = b"";

        let ciphertext = encryptor.encrypt(plaintext).expect("Should encrypt");
        let decrypted = encryptor.decrypt(&ciphertext).expect("Should decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let encryptor =
            Encryptor::new("test-password", "example.com").expect("Should create encryptor");
        let plaintext: Vec<u8> = (0_u8..=255).cycle().take(10000).collect();

        let ciphertext = encryptor.encrypt(&plaintext).expect("Should encrypt");
        let decrypted = encryptor.decrypt(&ciphertext).expect("Should decrypt");

        assert_eq!(decrypted, plaintext);
    }
}
