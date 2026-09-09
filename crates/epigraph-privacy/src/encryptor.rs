//! Encrypt/decrypt claim content, labels, versions, evidence and edge
//! properties, each bound to the entity, the key epoch **and the field** it
//! belongs to.
//!
//! # AAD
//!
//! ```text
//! AAD = entity_id (16B, UUID byte order) || epoch (4B, LE) || field_tag (1B)
//! ```
//!
//! The first two components make ciphertext non-transplantable between entities
//! and non-replayable across key rotations. The third makes it
//! non-transplantable between the *fields* of one entity: without it, two
//! fields of the same claim at the same epoch produce byte-identical AAD, so a
//! ciphertext taken from one authenticates as the other. The tag is the change
//! this port makes to an otherwise-unmodified construction.
//!
//! The epoch is little-endian, matching
//! `epigraph_crypto::derive_epoch_key`, which is the function that turns a
//! group's base key into the `epoch_key` these functions consume.
//!
//! # Padding is the caller's
//!
//! Plaintext length leaks through ciphertext length. The remedy is padding, and
//! it is applied by the caller before it gets here: these functions accept an
//! already-padded byte slice and return exactly what they were given. Nothing
//! in this module pads, and nothing strips padding — a decrypt returns the
//! padded bytes, and unpadding belongs with whoever chose the scheme.
//! [`encrypt_content`] is therefore the byte-oriented entry point for padded
//! data; the `&str` helpers are conveniences for the unpadded case and cannot
//! carry padding, since the pad bytes are not valid UTF-8.

use epigraph_crypto::{decrypt, derive_epoch_key, encrypt, EncryptedPayload};
use uuid::Uuid;

use crate::errors::PrivacyError;

/// Which field of an entity a ciphertext belongs to.
///
/// The discriminants are wire values: they are authenticated into every
/// ciphertext's AAD, so changing one invalidates every ciphertext already
/// sealed under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FieldTag {
    /// A claim's `content`.
    Content = 0x01,
    /// A claim's `labels`.
    Labels = 0x02,
    /// A claim's `properties`, and an edge's properties. Edges are separated
    /// from claims by the entity id, which is the edge's own UUID.
    Properties = 0x03,
    /// A `claim_versions` row's `content`.
    VersionContent = 0x04,
    /// An `evidence` row's `raw_content`.
    EvidenceContent = 0x05,
    /// An `evidence` row's `properties`.
    EvidenceProperties = 0x06,
}

impl FieldTag {
    /// Every tag, in wire order. Exhaustive by construction: adding a variant
    /// without adding it here fails `tests::field_tag_all_is_exhaustive`.
    pub const ALL: [Self; 6] = [
        Self::Content,
        Self::Labels,
        Self::Properties,
        Self::VersionContent,
        Self::EvidenceContent,
        Self::EvidenceProperties,
    ];

    /// The single AAD byte this tag contributes.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Size of the AAD: `entity_id (16) || epoch (4, LE) || field_tag (1)`.
const AAD_BYTES: usize = 16 + 4 + 1;

/// Build AAD bytes: `entity_id (16B UUID) || epoch (4B LE u32) || field_tag (1B)`.
fn build_aad(entity_id: Uuid, epoch: u32, field: FieldTag) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_BYTES);
    aad.extend_from_slice(entity_id.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.push(field.as_byte());
    aad
}

/// Encrypt arbitrary — and, where it matters, already-padded — bytes bound to
/// an entity, an epoch and a field.
///
/// The `epoch_key` must already be derived via
/// `epigraph_crypto::derive_epoch_key`; this function does NOT re-derive it.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if AES-GCM encryption fails.
pub fn encrypt_content(
    plaintext: &[u8],
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
) -> Result<EncryptedPayload, PrivacyError> {
    let aad = build_aad(entity_id, epoch, field);
    Ok(encrypt(plaintext, epoch_key, &aad)?)
}

/// Decrypt content that was encrypted with [`encrypt_content`].
///
/// Returns the bytes as they were supplied to `encrypt_content`, padding
/// included. Removing padding is the caller's, exactly as adding it was.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails — wrong key, wrong
/// entity, wrong epoch, wrong field, or tampered ciphertext.
pub fn decrypt_content(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
) -> Result<Vec<u8>, PrivacyError> {
    let aad = build_aad(entity_id, epoch, field);
    Ok(decrypt(payload, epoch_key, &aad)?)
}

/// Decrypt to a UTF-8 string under a given field tag.
fn decrypt_utf8(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
) -> Result<String, PrivacyError> {
    let bytes = decrypt_content(payload, epoch_key, entity_id, epoch, field)?;
    String::from_utf8(bytes).map_err(|e| {
        epigraph_crypto::CryptoError::DecryptionFailed {
            reason: format!("decrypted content is not valid UTF-8: {e}"),
        }
        .into()
    })
}

/// Encrypt a claim's `content`.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if encryption fails.
pub fn encrypt_claim_content(
    content: &str,
    epoch_key: &[u8; 32],
    claim_id: Uuid,
    epoch: u32,
) -> Result<EncryptedPayload, PrivacyError> {
    encrypt_content(
        content.as_bytes(),
        epoch_key,
        claim_id,
        epoch,
        FieldTag::Content,
    )
}

/// Decrypt a claim's `content` back to a UTF-8 string.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails or the plaintext is not
/// valid UTF-8.
pub fn decrypt_claim_content(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    claim_id: Uuid,
    epoch: u32,
) -> Result<String, PrivacyError> {
    decrypt_utf8(payload, epoch_key, claim_id, epoch, FieldTag::Content)
}

/// Encrypt a `claim_versions` row's `content`.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if encryption fails.
pub fn encrypt_version_content(
    content: &str,
    epoch_key: &[u8; 32],
    version_id: Uuid,
    epoch: u32,
) -> Result<EncryptedPayload, PrivacyError> {
    encrypt_content(
        content.as_bytes(),
        epoch_key,
        version_id,
        epoch,
        FieldTag::VersionContent,
    )
}

/// Decrypt a `claim_versions` row's `content`.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails or the plaintext is not
/// valid UTF-8.
pub fn decrypt_version_content(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    version_id: Uuid,
    epoch: u32,
) -> Result<String, PrivacyError> {
    decrypt_utf8(
        payload,
        epoch_key,
        version_id,
        epoch,
        FieldTag::VersionContent,
    )
}

/// Encrypt an `evidence` row's `raw_content`.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if encryption fails.
pub fn encrypt_evidence_content(
    content: &str,
    epoch_key: &[u8; 32],
    evidence_id: Uuid,
    epoch: u32,
) -> Result<EncryptedPayload, PrivacyError> {
    encrypt_content(
        content.as_bytes(),
        epoch_key,
        evidence_id,
        epoch,
        FieldTag::EvidenceContent,
    )
}

/// Decrypt an `evidence` row's `raw_content`.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails or the plaintext is not
/// valid UTF-8.
pub fn decrypt_evidence_content(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    evidence_id: Uuid,
    epoch: u32,
) -> Result<String, PrivacyError> {
    decrypt_utf8(
        payload,
        epoch_key,
        evidence_id,
        epoch,
        FieldTag::EvidenceContent,
    )
}

/// Encrypt edge properties (serialised JSON bytes).
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if encryption fails.
pub fn encrypt_edge_properties(
    properties_json: &[u8],
    epoch_key: &[u8; 32],
    edge_id: Uuid,
    epoch: u32,
) -> Result<EncryptedPayload, PrivacyError> {
    encrypt_content(
        properties_json,
        epoch_key,
        edge_id,
        epoch,
        FieldTag::Properties,
    )
}

/// Decrypt edge properties back to JSON bytes.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails.
pub fn decrypt_edge_properties(
    payload: &EncryptedPayload,
    epoch_key: &[u8; 32],
    edge_id: Uuid,
    epoch: u32,
) -> Result<Vec<u8>, PrivacyError> {
    decrypt_content(payload, epoch_key, edge_id, epoch, FieldTag::Properties)
}

/// Convenience: derive the epoch key from a base key, then encrypt.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if encryption fails.
pub fn encrypt_with_base_key(
    plaintext: &[u8],
    base_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
) -> Result<EncryptedPayload, PrivacyError> {
    let epoch_key = derive_epoch_key(base_key, epoch);
    encrypt_content(plaintext, &epoch_key, entity_id, epoch, field)
}

/// Convenience: derive the epoch key from a base key, then decrypt.
///
/// # Errors
///
/// Returns [`PrivacyError::Crypto`] if decryption fails.
pub fn decrypt_with_base_key(
    payload: &EncryptedPayload,
    base_key: &[u8; 32],
    entity_id: Uuid,
    epoch: u32,
    field: FieldTag,
) -> Result<Vec<u8>, PrivacyError> {
    let epoch_key = derive_epoch_key(base_key, epoch);
    decrypt_content(payload, &epoch_key, entity_id, epoch, field)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the seven ported round-trip / binding tests -----------------------

    #[test]
    fn test_encrypt_decrypt_claim_content_roundtrip() {
        let key = [42u8; 32];
        let claim_id = Uuid::new_v4();
        let epoch = 1u32;
        let content = "This claim asserts something important about epistemology.";

        let payload = encrypt_claim_content(content, &key, claim_id, epoch).unwrap();
        let recovered = decrypt_claim_content(&payload, &key, claim_id, epoch).unwrap();
        assert_eq!(recovered, content);
    }

    #[test]
    fn test_wrong_entity_id_fails() {
        let key = [42u8; 32];
        let claim_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let epoch = 1u32;

        let payload = encrypt_claim_content("secret", &key, claim_id, epoch).unwrap();
        let result = decrypt_claim_content(&payload, &key, wrong_id, epoch);
        assert!(
            result.is_err(),
            "AAD mismatch should cause decryption failure"
        );
    }

    #[test]
    fn test_wrong_epoch_fails() {
        let key = [42u8; 32];
        let claim_id = Uuid::new_v4();

        let payload = encrypt_claim_content("secret", &key, claim_id, 1).unwrap();
        let result = decrypt_claim_content(&payload, &key, claim_id, 2);
        assert!(
            result.is_err(),
            "wrong epoch should cause decryption failure"
        );
    }

    #[test]
    fn test_encrypt_decrypt_raw_bytes() {
        let key = [7u8; 32];
        let entity_id = Uuid::new_v4();
        let epoch = 0u32;
        let data = vec![0u8, 1, 2, 3, 255, 254];

        let payload = encrypt_content(&data, &key, entity_id, epoch, FieldTag::Content).unwrap();
        let recovered =
            decrypt_content(&payload, &key, entity_id, epoch, FieldTag::Content).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_encrypt_decrypt_edge_properties() {
        let key = [13u8; 32];
        let edge_id = Uuid::new_v4();
        let epoch = 5u32;
        let props = br#"{"weight": 0.85, "type": "SUPPORTS"}"#;

        let payload = encrypt_edge_properties(props, &key, edge_id, epoch).unwrap();
        let recovered = decrypt_edge_properties(&payload, &key, edge_id, epoch).unwrap();
        assert_eq!(recovered, props);
    }

    #[test]
    fn test_encrypt_with_base_key_roundtrip() {
        let base_key = [99u8; 32];
        let entity_id = Uuid::new_v4();
        let epoch = 3u32;
        let plaintext = b"base key convenience test";

        let payload =
            encrypt_with_base_key(plaintext, &base_key, entity_id, epoch, FieldTag::Content)
                .unwrap();
        let recovered =
            decrypt_with_base_key(&payload, &base_key, entity_id, epoch, FieldTag::Content)
                .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_different_epochs_produce_different_ciphertext() {
        let key = [42u8; 32];
        let claim_id = Uuid::new_v4();

        let p1 = encrypt_claim_content("same", &key, claim_id, 0).unwrap();
        let p2 = encrypt_claim_content("same", &key, claim_id, 1).unwrap();
        // Different AAD means different ciphertext (even ignoring random nonce)
        assert_ne!(p1.ciphertext, p2.ciphertext);
    }

    // ---- the field tag -----------------------------------------------------

    #[test]
    fn field_tag_all_is_exhaustive() {
        // A seventh field added without a tag, or a tag added without a place
        // in ALL, fails here rather than shipping a field that shares another
        // field's AAD.
        for (i, tag) in FieldTag::ALL.iter().enumerate() {
            let expected = u8::try_from(i + 1).unwrap();
            assert_eq!(tag.as_byte(), expected, "ALL is not in wire order at {i}");
        }
        // Destructuring every variant: a new variant makes this fail to compile.
        for tag in FieldTag::ALL {
            match tag {
                FieldTag::Content
                | FieldTag::Labels
                | FieldTag::Properties
                | FieldTag::VersionContent
                | FieldTag::EvidenceContent
                | FieldTag::EvidenceProperties => {}
            }
        }
    }

    #[test]
    fn every_field_tag_produces_a_distinct_aad_for_one_entity_and_epoch() {
        // The acceptance clause names five fields; the tag table defines six,
        // because evidence has two sealed fields. Pairwise distinctness across
        // all six strictly implies the five-way clause.
        let entity_id = Uuid::new_v4();
        let epoch = 9u32;

        let aads: Vec<Vec<u8>> = FieldTag::ALL
            .iter()
            .map(|f| build_aad(entity_id, epoch, *f))
            .collect();

        for (i, a) in aads.iter().enumerate() {
            assert_eq!(a.len(), AAD_BYTES);
            for (j, b) in aads.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "tags {i} and {j} share an AAD");
                }
            }
        }
    }

    #[test]
    fn aad_encoding_is_pinned() {
        // A known byte vector, not a round trip: a round trip stays green
        // through an endianness flip or a reordering of the three components,
        // and the two ends of a seal are written by different programs.
        let entity_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let aad = build_aad(entity_id, 258, FieldTag::EvidenceProperties);
        assert_eq!(
            aad,
            vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, // epoch 258 = 0x0102, little-endian
                0x02, 0x01, 0x00, 0x00, // field tag
                0x06,
            ]
        );
    }

    #[test]
    fn a_ciphertext_does_not_transplant_between_fields() {
        // The defect the tag exists to close: before it, a claim's content and
        // its edge/properties ciphertext at the same epoch authenticated
        // interchangeably.
        let key = [42u8; 32];
        let entity_id = Uuid::new_v4();
        let epoch = 4u32;

        let sealed =
            encrypt_content(b"payload", &key, entity_id, epoch, FieldTag::Content).unwrap();

        for other in FieldTag::ALL {
            if other == FieldTag::Content {
                continue;
            }
            let result = decrypt_content(&sealed, &key, entity_id, epoch, other);
            assert!(
                result.is_err(),
                "content ciphertext was accepted as {other:?}"
            );
        }
    }

    #[test]
    fn claim_content_and_version_content_of_one_id_do_not_interchange() {
        // Named helpers, not raw tags: this is the shape a caller of the seal
        // ceremony actually writes, and it is where a copy-paste would land.
        let key = [3u8; 32];
        let id = Uuid::new_v4();
        let epoch = 2u32;

        let claim = encrypt_claim_content("body", &key, id, epoch).unwrap();
        assert!(decrypt_version_content(&claim, &key, id, epoch).is_err());

        let version = encrypt_version_content("body", &key, id, epoch).unwrap();
        assert!(decrypt_claim_content(&version, &key, id, epoch).is_err());
    }

    #[test]
    fn evidence_content_and_evidence_properties_do_not_interchange() {
        let key = [5u8; 32];
        let id = Uuid::new_v4();
        let epoch = 1u32;

        let content = encrypt_evidence_content("raw", &key, id, epoch).unwrap();
        let as_props = decrypt_content(&content, &key, id, epoch, FieldTag::EvidenceProperties);
        assert!(as_props.is_err());
    }

    // ---- padding is accepted verbatim -------------------------------------

    #[test]
    fn a_pre_padded_plaintext_survives_a_round_trip_byte_for_byte() {
        // ISO/IEC 7816-4 padding is `plaintext || 0x80 || 0x00*`, which is not
        // valid UTF-8, so the byte-oriented path is the one that must carry it.
        // Nothing here pads or unpads: what went in comes back out.
        let key = [11u8; 32];
        let id = Uuid::new_v4();
        let epoch = 0u32;

        let mut padded = b"short".to_vec();
        padded.push(0x80);
        padded.resize(256, 0x00);

        let sealed = encrypt_content(&padded, &key, id, epoch, FieldTag::Content).unwrap();
        let recovered = decrypt_content(&sealed, &key, id, epoch, FieldTag::Content).unwrap();

        assert_eq!(recovered, padded);
        assert_eq!(recovered.len(), 256, "decrypt must not strip padding");
    }

    #[test]
    fn two_plaintexts_padded_to_one_length_seal_to_one_ciphertext_length() {
        let key = [12u8; 32];
        let epoch = 0u32;

        let seal = |plain: &str| {
            let mut padded = plain.as_bytes().to_vec();
            padded.push(0x80);
            padded.resize(256, 0x00);
            encrypt_content(&padded, &key, Uuid::new_v4(), epoch, FieldTag::Content)
                .unwrap()
                .to_bytes()
                .len()
        };

        assert_eq!(seal("a"), seal(&"b".repeat(200)));
    }
}
