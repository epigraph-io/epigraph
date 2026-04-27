//! `EncryptionProvider` — pluggable encryption for `EpiGraph` subgraphs.
//!
//! The kernel ships with [`NoOpEncryptionProvider`], which passes data through
//! unchanged. The enterprise layer supplies an AES-256-GCM implementation that
//! encrypts claim content, edge metadata, and evidence payloads at rest inside
//! group-keyed subgraphs.
//!
//! # Extension point contract
//!
//! - `encrypt` and `decrypt` are inverses: `decrypt(encrypt(pt, k), k) == pt`
//! - Both are infallible for the no-op; enterprise impls may return
//!   [`EncryptionError`] on key-not-found or decryption failures.
//! - `key_id` is opaque to the kernel — it passes it through without
//!   interpreting it. Enterprise key management defines the format.

use async_trait::async_trait;

use crate::InterfaceError;

/// Errors returned by [`EncryptionProvider`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// The requested key ID is unknown or has been rotated out.
    #[error("encryption key not found: {key_id}")]
    KeyNotFound { key_id: String },
    /// Decryption authentication tag check failed (ciphertext is corrupt or tampered).
    #[error("decryption failed for key {key_id}: authentication tag mismatch")]
    AuthenticationFailed { key_id: String },
    /// Any other provider-specific error.
    #[error("encryption provider error: {0}")]
    Provider(#[from] InterfaceError),
}

/// Pluggable encryption provider.
///
/// The kernel holds an `Arc<dyn EncryptionProvider>` in [`AppState`]. At
/// startup the kernel installs [`NoOpEncryptionProvider`]; the enterprise
/// layer replaces it with an AES-256-GCM implementation keyed per group.
///
/// [`AppState`]: epigraph_api::state::AppState
#[async_trait]
pub trait EncryptionProvider: Send + Sync + 'static {
    /// Encrypt `plaintext` under the key identified by `key_id`.
    ///
    /// Returns the ciphertext. The no-op implementation returns `plaintext`
    /// unchanged.
    async fn encrypt(&self, plaintext: &[u8], key_id: &str) -> Result<Vec<u8>, EncryptionError>;

    /// Decrypt `ciphertext` under the key identified by `key_id`.
    ///
    /// Returns the plaintext. The no-op implementation returns `ciphertext`
    /// unchanged.
    async fn decrypt(&self, ciphertext: &[u8], key_id: &str) -> Result<Vec<u8>, EncryptionError>;

    /// Return `true` if this provider performs real encryption.
    ///
    /// Handlers may use this to skip encryption-related DB writes when the
    /// no-op provider is active, avoiding unnecessary overhead.
    fn is_active(&self) -> bool;
}

/// Kernel-default no-op encryption provider.
///
/// All data passes through unchanged. `is_active()` returns `false`, so
/// handlers skip encryption metadata writes entirely.
#[derive(Debug, Default, Clone)]
pub struct NoOpEncryptionProvider;

impl NoOpEncryptionProvider {
    /// Create a new no-op encryption provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EncryptionProvider for NoOpEncryptionProvider {
    async fn encrypt(&self, plaintext: &[u8], _key_id: &str) -> Result<Vec<u8>, EncryptionError> {
        Ok(plaintext.to_vec())
    }

    async fn decrypt(&self, ciphertext: &[u8], _key_id: &str) -> Result<Vec<u8>, EncryptionError> {
        Ok(ciphertext.to_vec())
    }

    fn is_active(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_encrypt_is_identity() {
        let p = NoOpEncryptionProvider::new();
        let plain = b"hello world";
        let ct = p.encrypt(plain, "any-key").await.unwrap();
        assert_eq!(ct, plain);
    }

    #[tokio::test]
    async fn noop_decrypt_is_identity() {
        let p = NoOpEncryptionProvider::new();
        let ct = b"some bytes";
        let pt = p.decrypt(ct, "any-key").await.unwrap();
        assert_eq!(pt, ct);
    }

    #[tokio::test]
    async fn noop_roundtrip() {
        let p = NoOpEncryptionProvider::new();
        let original = b"epistemic kernel";
        let ct = p.encrypt(original, "k1").await.unwrap();
        let pt = p.decrypt(&ct, "k1").await.unwrap();
        assert_eq!(pt, original);
    }

    #[test]
    fn noop_is_not_active() {
        assert!(!NoOpEncryptionProvider::new().is_active());
    }
}
