//! ISO/IEC 7816-4 length padding, sized so the STORED BLOB lands on the bucket.
//!
//! # What leaks without this
//!
//! AES-GCM is length-preserving, so `octet_length(claim_encryption.encrypted_content)`
//! is an affine function of the plaintext length. A sealed corpus whose rows are
//! all distinct lengths is a sealed corpus whose rows are all distinguishable,
//! and length alone is enough to fingerprint a document against a known set.
//! FINAL-PLAN §6.5.4 answers it with a bucket: `pad_to ∈ {0, 256, 1024, 4096}`,
//! default 256.
//!
//! # THE PLAN'S PADDING TARGET IS CORRECTED HERE, AND THE CORRECTION IS THE
//! POINT
//!
//! §6.5.4 says "pad the plaintext to a bucket"; the PR-21 acceptance line says
//! `octet_length(encrypted_content) % pad_to = 0`. **Those two sentences
//! describe different numbers and cannot both hold.** What the database stores
//! is `EncryptedPayload::to_bytes()` = `nonce(12) || ciphertext+tag(|pt|+16)` =
//! `|padded plaintext| + `[`PAYLOAD_OVERHEAD`], so padding the *plaintext* to a
//! multiple of `pad_to` makes the stored blob `≡ 28 (mod pad_to)` and the
//! acceptance clause fails on every row.
//!
//! The clause is the binding reading, because it is the only one the SERVER can
//! evaluate: seal is client-driven and the server never sees a plaintext, so a
//! plaintext-side padding rule gives it nothing to verify and the verification
//! step in §6.5.6 would be decorative. So [`pad`] targets
//! `|padded| + PAYLOAD_OVERHEAD ≡ 0 (mod pad_to)`.
//!
//! Both readings satisfy the security property the padding exists for — a
//! 1-byte and a 200-byte plaintext are the same stored length at `pad_to = 256`
//! either way. Only one of them is checkable by the party that has to enforce
//! it.
//!
//! # Padding is not confidentiality
//!
//! It narrows a length side channel to a bucket. It does not remove one: a
//! 9 KiB plaintext is still distinguishable from a 12-byte one at
//! `pad_to = 256`, and `pad_to = 0` — permitted by the schema for `restrict`
//! and forbidden for `seal` by migration 080's `pp_seal_needs_pad` — removes the
//! defence entirely.

use crate::errors::PrivacyError;

/// Bytes [`epigraph_crypto::EncryptedPayload::to_bytes`] adds to a plaintext:
/// a 12-byte nonce and a 16-byte GCM tag.
///
/// Pinned by a test against a real encryption rather than restated from the
/// wire-format doc comment, because the two ends of a seal are written by
/// different programs and this constant is what makes the server's modulus
/// check and the client's padding agree.
pub const PAYLOAD_OVERHEAD: usize = 12 + 16;

/// The bucket sizes migration 080's `pp_pad_check` admits.
///
/// `0` means "do not pad". It is in the set because `restrict`-mode plans carry
/// a `pad_to` they never use; `pp_seal_needs_pad` is what keeps it out of a
/// seal.
pub const PAD_BUCKETS: [u32; 4] = [0, 256, 1024, 4096];

/// The ISO/IEC 7816-4 delimiter: one `0x80`, then `0x00` to the boundary.
const DELIMITER: u8 = 0x80;

/// Pad `plaintext` so that its ciphertext lands on a `pad_to` boundary.
///
/// Returns `plaintext` unchanged when `pad_to == 0`.
///
/// The padded length is the smallest `n * pad_to - `[`PAYLOAD_OVERHEAD`]
/// strictly greater than `plaintext.len()` — strictly, because ISO 7816-4 always
/// writes at least the `0x80` delimiter, so an exact fit still moves to the next
/// bucket. That is what makes [`unpad`] total: there is no ambiguity between a
/// plaintext that ended in `0x80` and a padded one.
///
/// # Errors
///
/// [`PrivacyError::Padding`] when `pad_to` is not one of [`PAD_BUCKETS`], or
/// when `pad_to` is smaller than [`PAYLOAD_OVERHEAD`] would need — the latter is
/// unreachable for the admitted buckets and is checked rather than assumed.
pub fn pad(plaintext: &[u8], pad_to: u32) -> Result<Vec<u8>, PrivacyError> {
    if !PAD_BUCKETS.contains(&pad_to) {
        return Err(PrivacyError::Padding {
            reason: format!("pad_to must be one of {PAD_BUCKETS:?}, got {pad_to}"),
        });
    }
    if pad_to == 0 {
        return Ok(plaintext.to_vec());
    }
    let bucket = pad_to as usize;
    if bucket <= PAYLOAD_OVERHEAD {
        return Err(PrivacyError::Padding {
            reason: format!(
                "a {bucket}-byte bucket cannot hold the {PAYLOAD_OVERHEAD}-byte payload overhead"
            ),
        });
    }
    // The smallest multiple of `bucket` STRICTLY greater than the unpadded
    // stored length. `+ 1` is the delimiter byte, which is never optional.
    let stored_min = plaintext.len() + PAYLOAD_OVERHEAD + 1;
    let buckets = stored_min.div_ceil(bucket);
    let target = buckets * bucket - PAYLOAD_OVERHEAD;

    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(plaintext);
    out.push(DELIMITER);
    out.resize(target, 0x00);
    Ok(out)
}

/// Strip the padding [`pad`] added.
///
/// Returns `padded` unchanged when `pad_to == 0`, which is the only case in
/// which an unpadded value is a legal input.
///
/// # Errors
///
/// [`PrivacyError::Padding`] when the trailing bytes are not `0x80 0x00*` — a
/// wrong key would have failed the GCM tag first, so reaching this error means
/// the plaintext was padded under a different scheme or not at all.
pub fn unpad(padded: &[u8], pad_to: u32) -> Result<Vec<u8>, PrivacyError> {
    if pad_to == 0 {
        return Ok(padded.to_vec());
    }
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || padded[end - 1] != DELIMITER {
        return Err(PrivacyError::Padding {
            reason: "padded plaintext does not end in the ISO/IEC 7816-4 delimiter".to_string(),
        });
    }
    Ok(padded[..end - 1].to_vec())
}

/// The stored-blob length [`pad`] produces for a plaintext of `len` bytes.
///
/// The server's half of the agreement, exposed so a caller can predict a row's
/// `octet_length` without encrypting. It is not used to VERIFY a commit — the
/// server checks the modulus against the bytes it was actually given, because a
/// predicted length it computed itself proves nothing about them.
#[must_use]
pub fn stored_len(len: usize, pad_to: u32) -> usize {
    if pad_to == 0 {
        return len + PAYLOAD_OVERHEAD;
    }
    let bucket = pad_to as usize;
    (len + PAYLOAD_OVERHEAD + 1).div_ceil(bucket) * bucket
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_byte_and_a_two_hundred_byte_plaintext_store_the_same_length() {
        // The direct length-side-channel property, at the plan's default bucket.
        let short = pad(b"x", 256).unwrap();
        let long = pad(&[b'y'; 200], 256).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(short.len() + PAYLOAD_OVERHEAD, 256);
    }

    #[test]
    fn the_stored_length_is_a_multiple_of_the_bucket() {
        for pad_to in [256_u32, 1024, 4096] {
            for len in [0_usize, 1, 27, 28, 227, 228, 229, 1000, 5000] {
                let padded = pad(&vec![b'a'; len], pad_to).unwrap();
                let stored = padded.len() + PAYLOAD_OVERHEAD;
                assert_eq!(
                    stored % pad_to as usize,
                    0,
                    "len={len} pad_to={pad_to} stored={stored}"
                );
                assert!(padded.len() > len, "padding must add at least a delimiter");
                assert_eq!(stored, stored_len(len, pad_to));
            }
        }
    }

    #[test]
    fn padding_round_trips_including_a_plaintext_that_ends_in_the_delimiter() {
        // The ambiguity ISO/IEC 7816-4 exists to remove: a plaintext whose own
        // last byte is 0x80, and one whose last bytes are 0x80 0x00.
        for original in [
            vec![],
            vec![0x80],
            vec![b'a', 0x80, 0x00, 0x00],
            b"the quick brown fox".to_vec(),
        ] {
            let padded = pad(&original, 256).unwrap();
            assert_eq!(unpad(&padded, 256).unwrap(), original);
        }
    }

    #[test]
    fn an_exact_fit_moves_to_the_next_bucket() {
        // 228 = 256 - PAYLOAD_OVERHEAD. There is no room for the delimiter, so
        // the value must not silently store at 256 with no padding marker.
        let padded = pad(&vec![b'a'; 228], 256).unwrap();
        assert_eq!(padded.len() + PAYLOAD_OVERHEAD, 512);
        assert_eq!(unpad(&padded, 256).unwrap().len(), 228);
    }

    #[test]
    fn pad_to_zero_is_the_identity_in_both_directions() {
        let original = b"unpadded".to_vec();
        assert_eq!(pad(&original, 0).unwrap(), original);
        assert_eq!(unpad(&original, 0).unwrap(), original);
    }

    #[test]
    fn an_unadmitted_bucket_is_refused_rather_than_rounded() {
        assert!(pad(b"x", 512).is_err());
        assert!(pad(b"x", 1).is_err());
    }

    #[test]
    fn unpadding_something_that_was_never_padded_is_an_error_not_a_truncation() {
        assert!(unpad(b"plain", 256).is_err());
        assert!(unpad(&[], 256).is_err());
        assert!(unpad(&[0x00, 0x00], 256).is_err());
    }

    #[test]
    fn the_payload_overhead_constant_matches_a_real_encryption() {
        // The constant is the whole agreement between the client's padding and
        // the server's modulus check. Pinned against the crypto crate rather
        // than against its doc comment.
        let payload = epigraph_crypto::encrypt(b"0123456789", &[7u8; 32], b"aad").unwrap();
        assert_eq!(payload.to_bytes().len(), 10 + PAYLOAD_OVERHEAD);
    }
}
