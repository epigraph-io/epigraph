//! W3C `did:key` identifiers for Ed25519 agents
//!
//! Implements deterministic `did:key` generation for human author agents.
//! An ORCID (or normalized author name) is hashed with BLAKE3 to produce
//! a deterministic Ed25519 keypair, then encoded as a `did:key` URI.
//!
//! # did:key Format
//!
//! ```text
//! did:key:z<base58btc(0xed01 || public_key)>
//! ```
//!
//! - `0xed01` is the multicodec prefix for Ed25519 public keys
//! - The `z` prefix indicates base58btc multibase encoding
//!
//! # Deterministic Derivation
//!
//! ```text
//! BLAKE3("orcid:0000-0002-1825-0097") → 32-byte seed → Ed25519 keypair → did:key
//! ```
//!
//! The same ORCID always produces the same `did:key`. For authors without an
//! ORCID, the normalized name hash serves as fallback.

use crate::errors::CryptoError;
use crate::signer::AgentSigner;
use crate::PUBLIC_KEY_SIZE;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Ed25519 multicodec prefix: 0xed01
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// A W3C `did:key` identifier wrapping an Ed25519 public key
///
/// The DID string encodes the public key directly — no external resolution needed.
/// Two agents with the same public key will always have the same `did:key`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DidKey(String);

impl DidKey {
    /// Create a `did:key` from an Ed25519 public key
    ///
    /// Encodes as `did:key:z<base58btc(0xed01 || pubkey)>`
    #[must_use]
    pub fn from_public_key(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        let mut prefixed = Vec::with_capacity(34);
        prefixed.extend_from_slice(&ED25519_MULTICODEC);
        prefixed.extend_from_slice(public_key);
        let encoded = bs58::encode(&prefixed).into_string();
        Self(format!("did:key:z{encoded}"))
    }

    /// Extract the Ed25519 public key bytes from this `did:key`
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidPublicKey` if the DID is malformed.
    pub fn to_public_key(&self) -> Result<[u8; PUBLIC_KEY_SIZE], CryptoError> {
        let multibase =
            self.0
                .strip_prefix("did:key:z")
                .ok_or_else(|| CryptoError::InvalidPublicKey {
                    reason: "did:key must start with 'did:key:z'".into(),
                })?;

        let decoded =
            bs58::decode(multibase)
                .into_vec()
                .map_err(|e| CryptoError::InvalidPublicKey {
                    reason: format!("base58 decode failed: {e}"),
                })?;

        if decoded.len() != 34 {
            return Err(CryptoError::InvalidPublicKey {
                reason: format!(
                    "expected 34 bytes (2 prefix + 32 key), got {}",
                    decoded.len()
                ),
            });
        }

        if decoded[0] != ED25519_MULTICODEC[0] || decoded[1] != ED25519_MULTICODEC[1] {
            return Err(CryptoError::InvalidPublicKey {
                reason: "not an Ed25519 key (wrong multicodec prefix 0xed01)".into(),
            });
        }

        let mut key = [0u8; PUBLIC_KEY_SIZE];
        key.copy_from_slice(&decoded[2..]);
        Ok(key)
    }

    /// The raw DID string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.len() > 24 {
            write!(
                f,
                "DidKey({}...{})",
                &self.0[..16],
                &self.0[self.0.len() - 8..]
            )
        } else {
            write!(f, "DidKey({})", self.0)
        }
    }
}

impl fmt::Display for DidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Derive a deterministic Ed25519 keypair from an ORCID identifier.
///
/// Uses BLAKE3 to hash the canonical string `"orcid:{ORCID}"` into a
/// 32-byte seed, which becomes the Ed25519 secret key.
///
/// The same ORCID always produces the same keypair and `did:key`.
#[must_use]
pub fn keypair_from_orcid(orcid: &str) -> AgentSigner {
    let seed_input = format!("orcid:{orcid}");
    keypair_from_seed(&seed_input)
}

/// Derive a deterministic Ed25519 keypair from an author name (fallback).
///
/// The name is normalized (lowercased, whitespace → underscore, non-alnum stripped)
/// then hashed as `"author:{normalized}"`.
#[must_use]
pub fn keypair_from_name(name: &str) -> AgentSigner {
    let normalized = normalize_author_name(name);
    let seed_input = format!("author:{normalized}");
    keypair_from_seed(&seed_input)
}

/// Generate a `did:key` for a human author agent.
///
/// If an ORCID is provided, uses deterministic derivation from the ORCID.
/// Otherwise falls back to name-based derivation.
///
/// Returns `(did_key, public_key_bytes)`.
#[must_use]
pub fn did_key_for_author(orcid: Option<&str>, name: &str) -> (DidKey, [u8; PUBLIC_KEY_SIZE]) {
    let signer = match orcid {
        Some(orcid) if !orcid.is_empty() => keypair_from_orcid(orcid),
        _ => keypair_from_name(name),
    };
    let public_key = signer.public_key();
    let did = DidKey::from_public_key(&public_key);
    (did, public_key)
}

/// Normalize an author name for deterministic hashing.
///
/// Matches the Python normalization in `ingest_papers_cdst.py`:
/// 1. Lowercase
/// 2. Strip leading/trailing whitespace
/// 3. Replace whitespace runs with underscore
/// 4. Remove characters that aren't `[a-z0-9_-]`
#[must_use]
pub fn normalize_author_name(name: &str) -> String {
    let lowered = name.to_lowercase();
    let trimmed = lowered.trim();

    // Replace whitespace runs with underscore
    let mut result = String::with_capacity(trimmed.len());
    let mut prev_was_ws = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_was_ws {
                result.push('_');
            }
            prev_was_ws = true;
        } else {
            prev_was_ws = false;
            result.push(ch);
        }
    }

    // Keep only [a-z0-9_-]
    result.retain(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    result
}

/// Internal: derive keypair from a seed string using BLAKE3
fn keypair_from_seed(seed_input: &str) -> AgentSigner {
    let hash = blake3::hash(seed_input.as_bytes());
    let seed_bytes: [u8; 32] = *hash.as_bytes();
    // Safety: from_bytes cannot fail — any 32 bytes are a valid Ed25519 secret key
    AgentSigner::from_bytes(&seed_bytes).expect("BLAKE3 output is always 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip() {
        let signer = AgentSigner::generate();
        let did = DidKey::from_public_key(&signer.public_key());
        let recovered = did.to_public_key().unwrap();
        assert_eq!(recovered, signer.public_key());
    }

    #[test]
    fn did_key_starts_with_correct_prefix() {
        let signer = AgentSigner::generate();
        let did = DidKey::from_public_key(&signer.public_key());
        assert!(
            did.as_str().starts_with("did:key:z6Mk"),
            "Ed25519 did:key should start with z6Mk, got: {}",
            did.as_str()
        );
    }

    #[test]
    fn orcid_derivation_is_deterministic() {
        let orcid = "0000-0002-1825-0097";
        let signer1 = keypair_from_orcid(orcid);
        let signer2 = keypair_from_orcid(orcid);
        assert_eq!(signer1.public_key(), signer2.public_key());

        let did1 = DidKey::from_public_key(&signer1.public_key());
        let did2 = DidKey::from_public_key(&signer2.public_key());
        assert_eq!(did1, did2);
    }

    #[test]
    fn different_orcids_produce_different_keys() {
        let s1 = keypair_from_orcid("0000-0002-1825-0097");
        let s2 = keypair_from_orcid("0000-0001-5109-3700");
        assert_ne!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn name_derivation_is_deterministic() {
        let signer1 = keypair_from_name("John Smith");
        let signer2 = keypair_from_name("John Smith");
        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn name_normalization_is_case_insensitive() {
        let s1 = keypair_from_name("John Smith");
        let s2 = keypair_from_name("john smith");
        assert_eq!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn name_normalization_handles_whitespace() {
        let s1 = keypair_from_name("John  Smith");
        let s2 = keypair_from_name("John Smith");
        assert_eq!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn name_normalization_strips_special_chars() {
        let s1 = keypair_from_name("José García");
        let normalized = normalize_author_name("José García");
        assert_eq!(normalized, "jos_garca"); // accented chars stripped
        assert!(!normalized.is_empty());
        let _ = s1; // just ensure it doesn't panic
    }

    #[test]
    fn did_key_for_author_prefers_orcid() {
        let (did_orcid, _) = did_key_for_author(Some("0000-0002-1825-0097"), "John Smith");
        let (did_name, _) = did_key_for_author(None, "John Smith");
        // ORCID-derived and name-derived should differ
        assert_ne!(did_orcid, did_name);
    }

    #[test]
    fn did_key_for_author_falls_back_to_name() {
        let (did1, _) = did_key_for_author(None, "John Smith");
        let (did2, _) = did_key_for_author(Some(""), "John Smith");
        // Empty ORCID should fall back to name
        assert_eq!(did1, did2);
    }

    #[test]
    fn invalid_did_prefix_rejected() {
        let bad = DidKey("did:web:example.com".into());
        assert!(bad.to_public_key().is_err());
    }

    #[test]
    fn invalid_did_base58_rejected() {
        let bad = DidKey("did:key:z!!!invalid".into());
        assert!(bad.to_public_key().is_err());
    }

    #[test]
    fn invalid_did_wrong_length_rejected() {
        // Valid base58 but wrong length (too short)
        let bad = DidKey("did:key:z6Mk".into());
        assert!(bad.to_public_key().is_err());
    }

    #[test]
    fn normalize_author_name_matches_python() {
        // Must match Python: re.sub(r'[^a-z0-9_\-]', '', re.sub(r'\s+', '_', name.lower().strip()))
        assert_eq!(normalize_author_name("John Smith"), "john_smith");
        assert_eq!(normalize_author_name("  Jane  Doe  "), "jane_doe");
        assert_eq!(normalize_author_name("O'Brien"), "obrien");
        assert_eq!(normalize_author_name("van der Berg"), "van_der_berg");
    }

    #[test]
    fn did_key_serializes_as_string() {
        let (did, _) = did_key_for_author(Some("0000-0002-1825-0097"), "Test");
        let json = serde_json::to_string(&did).unwrap();
        assert!(json.starts_with("\"did:key:z"));
        let deserialized: DidKey = serde_json::from_str(&json).unwrap();
        assert_eq!(did, deserialized);
    }

    #[test]
    fn did_key_display_and_debug() {
        let (did, _) = did_key_for_author(Some("0000-0002-1825-0097"), "Test");
        let display = format!("{did}");
        let debug = format!("{did:?}");
        assert!(display.starts_with("did:key:z"));
        assert!(debug.contains("DidKey("));
    }

    #[test]
    fn cross_language_orcid_determinism() {
        // Must match Python: generate_did_key("orcid:0000-0002-1825-0097")
        let signer = keypair_from_orcid("0000-0002-1825-0097");
        let did = DidKey::from_public_key(&signer.public_key());
        assert_eq!(
            did.as_str(),
            "did:key:z6MkgnfY62EYiJb6kdRrkuviJYsGGoC2J3Zc9bem2TxnPVY1",
            "Rust ORCID did:key must match Python output"
        );
    }

    #[test]
    fn cross_language_name_determinism() {
        // Must match Python: generate_did_key("author:john_smith")
        let signer = keypair_from_name("John Smith");
        let did = DidKey::from_public_key(&signer.public_key());
        assert_eq!(
            did.as_str(),
            "did:key:z6MkkrdVVTbpsKkKx5j6PmXfwqXJuMf6ShTbQPoC2Y7GEz3q",
            "Rust name did:key must match Python output"
        );
    }
}
