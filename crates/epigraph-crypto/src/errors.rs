//! Cryptographic error types

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Failed to serialize data to canonical form
    #[error("Canonical serialization failed: {0}")]
    SerializationError(String),

    /// Invalid public key format
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey { reason: String },

    /// Invalid signature format
    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid secret key format
    #[error("Invalid secret key: {reason}")]
    InvalidSecretKey { reason: String },

    /// Encryption failed
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    /// Decryption failed (wrong key, corrupted ciphertext, or tampered AAD)
    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    /// Invalid payload format
    #[error("Invalid encrypted payload: {reason}")]
    InvalidPayload { reason: String },

    /// Key exchange failed
    #[error("Key exchange failed: {reason}")]
    KeyExchangeFailed { reason: String },
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::InvalidSignature {
            reason: err.to_string(),
        }
    }
}
