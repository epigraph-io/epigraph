//! Per-entity-type domain separation of signed messages (backlog `1a79c4d9`,
//! ruling R-34).
//!
//! # The defect this closes
//!
//! Claims, evidence and edges are each addressed by a 32-byte BLAKE3 digest,
//! and the writers signed THAT BARE DIGEST. A signature carries no statement of
//! what kind of thing it attests, so a signature an agent produced over an
//! evidence row's hash `H` verified just as well as a signature over a claim
//! whose content hash is also `H` (the two hash the same bytes whenever the
//! evidence text and the claim body are equal, which is common: an atom quoted
//! as its own evidence).
//!
//! # The scheme
//!
//! Version 1 signs a TAGGED message, never the digest itself:
//!
//! ```text
//! b"epigraph-sig-v1:" || <kind> || b":" || digest      kind ∈ {claim, evidence, edge, dataset}
//! ```
//!
//! Only the signed message changes. The stored `content_hash`, every content
//! address and every identity derived from one are exactly what they were, so
//! no row is rewritten and no migration is needed.
//!
//! Verification is versioned: [`crate::SignatureVerifier::verify_entity`] tries
//! the v1 message for the expected kind first and then the legacy bare digest,
//! and reports which one verified ([`SignatureScheme`]). A legacy signature
//! keeps verifying (rows signed before v1 are not orphaned), and is reported as
//! `legacy` so a reader can tell it carries no type binding. A v1 signature for
//! one kind never verifies as another kind under either rung: the v1 rung
//! compares a different tag, and the legacy rung compares the bare digest,
//! which a tagged message never equals.

use crate::HASH_SIZE;
use serde::{Deserialize, Serialize};

/// Prefix of every version-1 signed message.
pub const SIGNING_DOMAIN_V1: &[u8] = b"epigraph-sig-v1:";

/// The kind of entity a signature attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignedEntity {
    /// A `claims` row; the digest is its `content_hash`.
    Claim,
    /// An `evidence` row; the digest is its `content_hash`.
    Evidence,
    /// An `edges` row; the digest is its `content_hash` (the edge attestation
    /// digest, see `epigraph_db::repos::edge_signature`).
    Edge,
    /// The structured fields of a `dataset` evidence row (root, manifest
    /// digest, counts), bound to that row's evidence and claim ids; the digest
    /// is `EvidenceType::dataset_attestation_digest` in epigraph-core
    /// (backlog c8beb101). A kind of its own, so the evidence row's signature
    /// over its `content_hash` is exactly what it was.
    Dataset,
}

impl SignedEntity {
    /// The tag written into the signed message.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Evidence => "evidence",
            Self::Edge => "edge",
            Self::Dataset => "dataset",
        }
    }
}

/// Which message a verifying signature was made over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureScheme {
    /// The bare 32-byte digest (every signature written before v1). It binds
    /// no entity type.
    Legacy,
    /// [`signing_message`]: the digest tagged with its entity kind.
    V1,
}

impl SignatureScheme {
    /// The wire spelling (`"legacy"` / `"v1"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::V1 => "v1",
        }
    }
}

/// The version-1 message a signer signs for an entity of `kind` whose digest is
/// `digest`: `b"epigraph-sig-v1:<kind>:" || digest`.
#[must_use]
pub fn signing_message(kind: SignedEntity, digest: &[u8; HASH_SIZE]) -> Vec<u8> {
    let tag = kind.tag().as_bytes();
    let mut message = Vec::with_capacity(SIGNING_DOMAIN_V1.len() + tag.len() + 1 + HASH_SIZE);
    message.extend_from_slice(SIGNING_DOMAIN_V1);
    message.extend_from_slice(tag);
    message.push(b':');
    message.extend_from_slice(digest);
    message
}

/// Prefix of a key-kind declaration's proof of possession (backlog
/// 57943a39). Distinct from [`SIGNING_DOMAIN_V1`] (neither is a prefix of the
/// other) and longer than a bare digest, so a declaration proof never verifies
/// as a v1 or legacy entity signature, and no entity signature verifies as a
/// declaration proof.
pub const KEY_KIND_DECLARATION_V1: &[u8] = b"epigraph-key-kind-v1:";

/// The message whose signature under `public_key` proves that the caller of
/// `POST /api/v1/agents` holds the private half of the key it declares as
/// `kind` (`seed-derived`): `b"epigraph-key-kind-v1:<kind>:" || public_key`.
///
/// Declaring a key `seed-derived` makes it a non-verifier for good (the
/// application role cannot rewrite `key_kind`), so without a proof anyone
/// holding `agents:write` could declare SOMEONE ELSE'S not yet registered key
/// and lock its holder out. Whoever really derived the key from its seed can
/// always sign this; a squatter cannot for a key they do not hold.
#[must_use]
pub fn key_kind_declaration_message(kind: &str, public_key: &[u8; 32]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(KEY_KIND_DECLARATION_V1.len() + kind.len() + 1 + public_key.len());
    message.extend_from_slice(KEY_KIND_DECLARATION_V1);
    message.extend_from_slice(kind.as_bytes());
    message.push(b':');
    message.extend_from_slice(public_key);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentSigner, ContentHasher, SignatureVerifier};

    fn signer() -> AgentSigner {
        AgentSigner::from_bytes(&[0x42; 32]).expect("signer")
    }

    /// The backlog's headline: an EVIDENCE signature over `H` must not verify
    /// as a CLAIM signature over the same `H`. Before v1 the writers signed the
    /// bare digest for both, so this verified.
    #[test]
    fn an_evidence_signature_does_not_verify_as_a_claim_signature() {
        let s = signer();
        let h = ContentHasher::hash(b"the same text, stored as a claim and as evidence");
        let evidence_sig = s.sign_entity(SignedEntity::Evidence, &h);

        let as_claim = SignatureVerifier::verify_entity(
            &s.public_key(),
            SignedEntity::Claim,
            &h,
            &evidence_sig,
        )
        .expect("well-formed key");
        assert_eq!(
            as_claim, None,
            "an evidence signature over H verified as a claim signature over H: the signed \
             message carries no entity type"
        );
        let as_edge = SignatureVerifier::verify_entity(
            &s.public_key(),
            SignedEntity::Edge,
            &h,
            &evidence_sig,
        )
        .expect("well-formed key");
        assert_eq!(as_edge, None, "nor as an edge signature over H");

        // The converse, so "never verify" cannot pass: it verifies as evidence, as v1.
        let as_evidence = SignatureVerifier::verify_entity(
            &s.public_key(),
            SignedEntity::Evidence,
            &h,
            &evidence_sig,
        )
        .expect("well-formed key");
        assert_eq!(as_evidence, Some(SignatureScheme::V1));
    }

    /// Every pair of distinct kinds is separated, not only evidence/claim.
    #[test]
    fn every_kind_pair_is_separated() {
        let s = signer();
        let h = ContentHasher::hash(b"digest shared by every kind");
        let kinds = [
            SignedEntity::Claim,
            SignedEntity::Evidence,
            SignedEntity::Edge,
            SignedEntity::Dataset,
        ];
        for signed_as in kinds {
            let sig = s.sign_entity(signed_as, &h);
            for checked_as in kinds {
                let got = SignatureVerifier::verify_entity(&s.public_key(), checked_as, &h, &sig)
                    .expect("well-formed key");
                let want = (signed_as == checked_as).then_some(SignatureScheme::V1);
                assert_eq!(
                    got, want,
                    "signed as {signed_as:?}, checked as {checked_as:?}"
                );
            }
        }
    }

    /// A row signed before v1 (the bare digest) keeps verifying, as `legacy`,
    /// for the kind it is checked as: the ruling keeps old rows verifiable.
    #[test]
    fn a_legacy_bare_digest_signature_still_verifies_as_legacy() {
        let s = signer();
        let h = ContentHasher::hash(b"a claim signed before the tagged scheme");
        let legacy_sig = s.sign(&h);
        let got =
            SignatureVerifier::verify_entity(&s.public_key(), SignedEntity::Claim, &h, &legacy_sig)
                .expect("well-formed key");
        assert_eq!(got, Some(SignatureScheme::Legacy));

        // And it is still bound to the digest and the key.
        let other = ContentHasher::hash(b"another body");
        assert_eq!(
            SignatureVerifier::verify_entity(
                &s.public_key(),
                SignedEntity::Claim,
                &other,
                &legacy_sig
            )
            .expect("well-formed key"),
            None
        );
        let stranger = AgentSigner::from_bytes(&[0x43; 32]).expect("signer");
        assert_eq!(
            SignatureVerifier::verify_entity(
                &stranger.public_key(),
                SignedEntity::Claim,
                &h,
                &legacy_sig
            )
            .expect("well-formed key"),
            None
        );
    }

    /// The exact wire format the ruling fixes, byte for byte: a verifier in
    /// another language reproduces it from this test.
    #[test]
    fn the_v1_message_is_the_ruled_byte_string() {
        let h = [0xABu8; HASH_SIZE];
        let mut want = b"epigraph-sig-v1:claim:".to_vec();
        want.extend_from_slice(&h);
        assert_eq!(signing_message(SignedEntity::Claim, &h), want);

        let mut want = b"epigraph-sig-v1:evidence:".to_vec();
        want.extend_from_slice(&h);
        assert_eq!(signing_message(SignedEntity::Evidence, &h), want);

        let mut want = b"epigraph-sig-v1:edge:".to_vec();
        want.extend_from_slice(&h);
        assert_eq!(signing_message(SignedEntity::Edge, &h), want);

        let mut want = b"epigraph-sig-v1:dataset:".to_vec();
        want.extend_from_slice(&h);
        assert_eq!(signing_message(SignedEntity::Dataset, &h), want);
    }

    #[test]
    fn the_scheme_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(SignatureScheme::Legacy).unwrap(),
            serde_json::json!("legacy")
        );
        assert_eq!(
            serde_json::to_value(SignatureScheme::V1).unwrap(),
            serde_json::json!("v1")
        );
        assert_eq!(SignatureScheme::V1.as_str(), "v1");
    }

    /// A key-kind declaration proof is its own domain: it is not an entity
    /// signature under either rung, and an entity signature is not a proof.
    #[test]
    fn a_key_kind_declaration_proof_is_no_entity_signature() {
        let s = signer();
        let key = s.public_key();
        let message = key_kind_declaration_message("seed-derived", &key);
        assert!(!message.starts_with(SIGNING_DOMAIN_V1));
        assert!(!SIGNING_DOMAIN_V1.starts_with(KEY_KIND_DECLARATION_V1));
        assert_ne!(message.len(), HASH_SIZE, "would collide with a legacy bare digest");
        let proof = s.sign(&message);
        assert!(SignatureVerifier::verify(&key, &message, &proof).unwrap());

        // The proof over the declaration, read as a claim signature over the
        // key bytes taken as a digest: neither rung verifies.
        for kind in [SignedEntity::Claim, SignedEntity::Edge, SignedEntity::Evidence] {
            assert!(
                SignatureVerifier::verify_entity(&key, kind, &key, &proof)
                    .unwrap()
                    .is_none(),
                "{kind:?}"
            );
        }
        // And a v1 claim signature over the key bytes is no proof.
        let claim_sig = s.sign_entity(SignedEntity::Claim, &key);
        assert!(!SignatureVerifier::verify(&key, &message, &claim_sig).unwrap());
    }
}
