//! Cryptographic primitives for `EpiGraph`
//!
//! This crate provides:
//! - **Canonical serialization**: Deterministic JSON for consistent hashing
//! - **BLAKE3 hashing**: Fast, secure content addressing
//! - **Ed25519 signing**: Agent signatures for data integrity
//!
//! # Security Model
//!
//! All evidence and reasoning traces in `EpiGraph` are cryptographically signed.
//! This ensures:
//! 1. **Integrity**: Data cannot be tampered with after signing
//! 2. **Non-repudiation**: Agents cannot deny creating signed content
//! 3. **Auditability**: Full provenance chain is verifiable

pub mod canonical;
pub mod did_key;
pub mod encryption;
pub mod epoch;
pub mod errors;
pub mod hasher;
pub mod key_exchange;
pub mod proxy_re;
pub mod signer;
pub mod verifier;

pub use canonical::{to_canonical_bytes, to_canonical_json, Canonical};
pub use did_key::DidKey;
pub use encryption::{decrypt, encrypt, EncryptedPayload};
pub use epoch::derive_epoch_key;
pub use errors::CryptoError;
pub use hasher::ContentHasher;
pub use key_exchange::{
    ecdh_shared_secret, ed25519_to_x25519_public, ed25519_to_x25519_secret, unwrap_group_key,
    wrap_group_key,
};
pub use signer::AgentSigner;
pub use verifier::SignatureVerifier;

/// Standard hash output size (BLAKE3 produces 32 bytes)
pub const HASH_SIZE: usize = 32;

/// Standard signature size (Ed25519 produces 64 bytes)
pub const SIGNATURE_SIZE: usize = 64;

/// Standard public key size (Ed25519 uses 32-byte keys)
pub const PUBLIC_KEY_SIZE: usize = 32;
