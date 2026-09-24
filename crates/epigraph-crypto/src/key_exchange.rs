//! ECDH key exchange for group member onboarding.
//!
//! Converts Ed25519 keys to X25519 (Curve25519 Montgomery form) for
//! Diffie-Hellman key agreement. The agreed secret is run through a BLAKE3 KDF
//! and the result is used to wrap group keys for distribution to new members.
//!
//! # Two properties this module is responsible for
//!
//! 1. **The wrapping key is a KDF output, not the raw curve point.** A raw DH
//!    output is a group element with algebraic structure and no domain
//!    separation; `blake3::derive_key` gives both. The KDF binds both public
//!    keys as well as the agreed point. Note what this is not: both inputs are
//!    long-term identity keys, there is no ephemeral and no session, so the
//!    derived key is the same for every wrap a given pair performs. Separation
//!    across group, epoch and member comes entirely from the AAD below.
//! 2. **The wrapped share is bound to the tuple it is meant for.** The AAD is
//!    `group_id || epoch || member_agent_id`, so a share is only accepted by
//!    the exact (group, epoch, member) it was produced for. AES-GCM
//!    authenticates the AAD without transmitting it, so binding three more
//!    values costs zero wire bytes: a wrapped 32-byte key is still exactly
//!    60 bytes (12-byte nonce + 32-byte ciphertext + 16-byte tag).
//!
//! **Wire compatibility:** the construction below is not interchangeable with
//! the previous one. A share produced by either cannot be unwrapped by the
//! other, and the 60-byte wire format carries no version discriminator.

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::encryption::{decrypt, encrypt, EncryptedPayload};
use crate::errors::CryptoError;

/// BLAKE3 KDF context for the group-key wrapping key.
///
/// `blake3::derive_key` domain-separates on this string, so it is part of the
/// scheme: two implementations that disagree on a single character derive
/// different keys and interoperate with nothing. It is pinned by
/// `tests::kdf_context_string_is_pinned`.
const KEY_WRAP_KDF_CONTEXT: &str = "epigraph-key-wrap-v2";

/// Size of the wrap AAD: `group_id (16) || epoch (4, LE) || member_agent_id (16)`.
const WRAP_AAD_BYTES: usize = 16 + 4 + 16;

/// Convert an Ed25519 signing key to an X25519 static secret.
///
/// Per RFC 8032: hash the secret key with SHA-512, take the lower 32 bytes,
/// and apply X25519 clamping (clear bits 0,1,2,255; set bit 254).
#[must_use]
pub fn ed25519_to_x25519_secret(signing_key: &SigningKey) -> X25519Secret {
    let hash = Sha512::digest(signing_key.as_bytes());
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // X25519 clamping — use hex literals for clarity (clippy::decimal_bitwise_operands)
    scalar[0] &= 0xf8; // clear bits 0, 1, 2
    scalar[31] &= 0x7f; // clear bit 255
    scalar[31] |= 0x40; // set bit 254
    X25519Secret::from(scalar)
}

/// Convert an Ed25519 verifying key to an X25519 public key.
///
/// Uses the birational map from Edwards to Montgomery form.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] if `verifying_key`'s bytes are not
/// a decompressible Edwards-y coordinate. `ed25519_dalek::VerifyingKey` only
/// ever holds a well-formed compressed point, so this is unreachable through
/// that type; the error is propagated rather than panicking on input that
/// reached us some other way.
///
/// **This function does not, and cannot, reject small-order points.** They are
/// perfectly valid encodings, they decompress, and they map to low-order
/// Montgomery keys. Rejecting them is [`ecdh_shared_secret`]'s job, via the
/// contributory-exchange check — not this conversion's.
pub fn ed25519_to_x25519_public(verifying_key: &VerifyingKey) -> Result<X25519Public, CryptoError> {
    let edwards = curve25519_dalek::edwards::CompressedEdwardsY(verifying_key.to_bytes());
    let point = edwards
        .decompress()
        .ok_or_else(|| CryptoError::InvalidPublicKey {
            reason: "Ed25519 public key decompression failed (invalid Edwards point)".into(),
        })?;
    let montgomery = point.to_montgomery();
    Ok(X25519Public::from(montgomery.to_bytes()))
}

/// Compute the ECDH-derived key-wrapping key between two parties.
///
/// The returned value is **not** the Diffie-Hellman output. It is
/// `blake3::derive_key(KEY_WRAP_KDF_CONTEXT, dh_output || min(pk) || max(pk))`,
/// where `pk` are the two X25519 public keys of the exchange.
///
/// Ordering the two public keys by their byte encoding is what makes the result
/// agree in both directions: each party knows both public keys but disagrees
/// about which is "ours", so an unordered concatenation would give the two
/// parties two different keys.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] if `their_public` cannot be
/// converted to an X25519 key (see [`ed25519_to_x25519_public`]).
///
/// Returns [`CryptoError::KeyExchangeFailed`] if the exchange is
/// non-contributory — i.e. the peer's key is a low-order point, for which the
/// Diffie-Hellman output is a fixed value the peer can predict without knowing
/// any secret. Without this check the peer, not the pair, would choose the
/// wrapping key.
pub fn ecdh_shared_secret(
    our_secret: &SigningKey,
    their_public: &VerifyingKey,
) -> Result<[u8; 32], CryptoError> {
    let x_secret = ed25519_to_x25519_secret(our_secret);
    let our_public = X25519Public::from(&x_secret);
    let x_public = ed25519_to_x25519_public(their_public)?;

    let shared = x_secret.diffie_hellman(&x_public);
    if !shared.was_contributory() {
        return Err(CryptoError::KeyExchangeFailed {
            reason: "non-contributory ECDH exchange (peer key is a low-order point)".to_string(),
        });
    }

    let (first, second) = if our_public.as_bytes() <= x_public.as_bytes() {
        (our_public.as_bytes(), x_public.as_bytes())
    } else {
        (x_public.as_bytes(), our_public.as_bytes())
    };

    let mut input = Vec::with_capacity(32 * 3);
    input.extend_from_slice(shared.as_bytes());
    input.extend_from_slice(first);
    input.extend_from_slice(second);

    Ok(blake3::derive_key(KEY_WRAP_KDF_CONTEXT, &input))
}

/// Build the wrap AAD: `group_id (16B) || epoch (4B LE) || member_agent_id (16B)`.
///
/// The epoch is encoded little-endian, matching
/// [`derive_epoch_key`](crate::epoch::derive_epoch_key); both sides of a wrap
/// must agree on it byte-for-byte, so the encoding is pinned by
/// `tests::wrap_aad_encoding_is_pinned` rather than left to a round trip.
fn build_wrap_aad(group_id: Uuid, epoch: u32, member_agent_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_BYTES);
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(member_agent_id.as_bytes());
    aad
}

/// Wrap a 32-byte group key for one member of one group at one epoch.
///
/// `shared_secret` is [`ecdh_shared_secret`]'s output. The `(group_id, epoch,
/// member_agent_id)` triple is authenticated as AAD, not encrypted: the wire
/// payload stays exactly 60 bytes, and [`unwrap_group_key`] must be given the
/// same triple or the tag check fails.
///
/// # Errors
///
/// Returns [`CryptoError::EncryptionFailed`] if AES-GCM encryption fails.
pub fn wrap_group_key(
    group_key: &[u8; 32],
    shared_secret: &[u8; 32],
    group_id: Uuid,
    epoch: u32,
    member_agent_id: Uuid,
) -> Result<EncryptedPayload, CryptoError> {
    let aad = build_wrap_aad(group_id, epoch, member_agent_id);
    encrypt(group_key, shared_secret, &aad)
}

/// Unwrap a group key that was wrapped for this member, group and epoch.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if the shared secret is wrong, the
/// ciphertext is corrupted, or the `(group_id, epoch, member_agent_id)` triple
/// differs from the one the share was produced for. Returns
/// [`CryptoError::KeyExchangeFailed`] if the decrypted payload is not exactly
/// 32 bytes.
pub fn unwrap_group_key(
    wrapped: &EncryptedPayload,
    shared_secret: &[u8; 32],
    group_id: Uuid,
    epoch: u32,
    member_agent_id: Uuid,
) -> Result<[u8; 32], CryptoError> {
    let aad = build_wrap_aad(group_id, epoch, member_agent_id);
    let bytes = decrypt(wrapped, shared_secret, &aad)?;
    if bytes.len() != 32 {
        return Err(CryptoError::KeyExchangeFailed {
            reason: format!("expected 32-byte key, got {}", bytes.len()),
        });
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ids() -> (Uuid, u32, Uuid) {
        (Uuid::new_v4(), 3u32, Uuid::new_v4())
    }

    #[test]
    fn test_ecdh_shared_secret_symmetric() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let secret_ab = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let secret_ba = ecdh_shared_secret(&bob, &alice.verifying_key()).unwrap();
        // This is the assertion that proves the public keys are ordered before
        // they enter the KDF: without the sort the two directions concatenate
        // them in opposite orders and derive two different keys.
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn test_ecdh_different_parties_different_secrets() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let carol = SigningKey::generate(&mut OsRng);

        let ab = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let ac = ecdh_shared_secret(&alice, &carol.verifying_key()).unwrap();
        assert_ne!(ab, ac);
    }

    #[test]
    fn ecdh_output_is_a_kdf_result_not_the_raw_dh_point() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);

        let x_secret = ed25519_to_x25519_secret(&alice);
        let x_public = ed25519_to_x25519_public(&bob.verifying_key()).unwrap();
        let raw = *x_secret.diffie_hellman(&x_public).as_bytes();

        let derived = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        assert_ne!(
            derived, raw,
            "the wrapping key must not be the Diffie-Hellman output verbatim"
        );
    }

    #[test]
    fn kdf_context_string_is_pinned() {
        // A typo in the context string yields a different, still-working
        // scheme, so the literal is asserted rather than merely used.
        assert_eq!(KEY_WRAP_KDF_CONTEXT, "epigraph-key-wrap-v2");

        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let x_secret = ed25519_to_x25519_secret(&alice);
        let our_public = X25519Public::from(&x_secret);
        let their_public = ed25519_to_x25519_public(&bob.verifying_key()).unwrap();
        let dh = x_secret.diffie_hellman(&their_public);

        let (first, second) = if our_public.as_bytes() <= their_public.as_bytes() {
            (our_public.as_bytes(), their_public.as_bytes())
        } else {
            (their_public.as_bytes(), our_public.as_bytes())
        };
        let mut input = Vec::new();
        input.extend_from_slice(dh.as_bytes());
        input.extend_from_slice(first);
        input.extend_from_slice(second);

        assert_eq!(
            ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap(),
            blake3::derive_key("epigraph-key-wrap-v2", &input)
        );
    }

    #[test]
    fn ed25519_to_x25519_conversion_pair_agrees() {
        // The sort in `ecdh_shared_secret` compares OUR public key (derived
        // from the secret) against THEIRS (derived from a verifying key). If
        // those two derivations disagreed for the same identity, the two
        // parties would sort different byte strings and derive different keys.
        let k = SigningKey::generate(&mut OsRng);
        let from_secret = X25519Public::from(&ed25519_to_x25519_secret(&k));
        let from_public = ed25519_to_x25519_public(&k.verifying_key()).unwrap();
        assert_eq!(from_secret.as_bytes(), from_public.as_bytes());
    }

    #[test]
    fn non_contributory_exchange_is_refused() {
        // The Ed25519 point of order 8 whose Montgomery image is the identity;
        // any exchange against it produces an all-zero Diffie-Hellman output
        // that the peer knows without holding a secret.
        let low_order = [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ];
        let peer = VerifyingKey::from_bytes(&low_order).unwrap();
        let ours = SigningKey::generate(&mut OsRng);

        let result = ecdh_shared_secret(&ours, &peer);
        assert!(
            matches!(result, Err(CryptoError::KeyExchangeFailed { .. })),
            "a non-contributory exchange must be refused, got {result:?}"
        );
    }

    #[test]
    fn wrap_aad_encoding_is_pinned() {
        // A known byte vector, not a round trip: a round trip is symmetric
        // under an endianness flip or a reordering of the three fields and
        // would stay green through either.
        let group_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let member = Uuid::parse_str("0f0e0d0c-0b0a-0908-0706-050403020100").unwrap();
        let aad = build_wrap_aad(group_id, 258, member);

        assert_eq!(aad.len(), WRAP_AAD_BYTES);
        assert_eq!(
            aad,
            vec![
                // group_id, big-endian UUID byte order
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, // epoch 258 = 0x0102, little-endian
                0x02, 0x01, 0x00, 0x00, // member_agent_id
                0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
                0x01, 0x00,
            ]
        );
    }

    #[test]
    fn test_wrap_unwrap_group_key() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();

        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let group_key = [77u8; 32];

        let wrapped = wrap_group_key(&group_key, &shared, group_id, epoch, member).unwrap();
        let unwrapped = unwrap_group_key(&wrapped, &shared, group_id, epoch, member).unwrap();
        assert_eq!(unwrapped, group_key);
    }

    #[test]
    fn a_wrapped_share_is_exactly_sixty_bytes_on_the_wire() {
        // `routes/groups.rs::add_member` rejects anything else outright, so a
        // change that grew the payload would strand the onboarding ceremony.
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();

        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let wrapped = wrap_group_key(&[9u8; 32], &shared, group_id, epoch, member).unwrap();
        assert_eq!(wrapped.to_bytes().len(), 12 + 32 + 16);
    }

    #[test]
    fn test_wrong_shared_secret_fails_unwrap() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();

        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();
        let group_key = [77u8; 32];

        let wrapped = wrap_group_key(&group_key, &shared, group_id, epoch, member).unwrap();
        let wrong_secret = [0u8; 32];
        let result = unwrap_group_key(&wrapped, &wrong_secret, group_id, epoch, member);
        assert!(result.is_err());
    }

    #[test]
    fn a_share_does_not_transplant_to_another_group() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();
        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();

        let wrapped = wrap_group_key(&[77u8; 32], &shared, group_id, epoch, member).unwrap();
        let result = unwrap_group_key(&wrapped, &shared, Uuid::new_v4(), epoch, member);
        assert!(result.is_err(), "share accepted under another group id");
    }

    #[test]
    fn a_share_does_not_transplant_to_another_epoch() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();
        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();

        let wrapped = wrap_group_key(&[77u8; 32], &shared, group_id, epoch, member).unwrap();
        let result = unwrap_group_key(&wrapped, &shared, group_id, epoch + 1, member);
        assert!(result.is_err(), "share accepted under another epoch");
    }

    #[test]
    fn a_share_does_not_transplant_to_another_member() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let (group_id, epoch, member) = ids();
        let shared = ecdh_shared_secret(&alice, &bob.verifying_key()).unwrap();

        let wrapped = wrap_group_key(&[77u8; 32], &shared, group_id, epoch, member).unwrap();
        let result = unwrap_group_key(&wrapped, &shared, group_id, epoch, Uuid::new_v4());
        assert!(result.is_err(), "share accepted under another member id");
    }
}
