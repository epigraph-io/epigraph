//! The packet-level Ed25519 signature `POST /api/v1/submit/packet` verifies.
//!
//! # What the server checks
//!
//! With `EPIGRAPH_REQUIRE_SIGNATURES=true` (`ApiConfig::require_packet_signatures`),
//! `submit_packet` looks up the Ed25519 public key of `claim.agent_id` and
//! verifies `packet.signature` over `EpistemicPacket::signable_bytes()`. Those
//! bytes are the canonical JSON (`epigraph_crypto::to_canonical_bytes`, keys
//! sorted recursively) of `{claim, evidence, reasoning_trace}`, re-serialized
//! from the SERVER's own deserialized structs, not taken from the bytes on the
//! wire. An all-zeros signature fails verification.
//!
//! # Why the ingesters sign their own mirror structs
//!
//! The CLI cannot use the server's types at runtime. `epigraph-api`'s `genai`
//! feature depends on `epigraph-cli`, so a normal dependency in the other
//! direction would be a cycle. The ingesters therefore keep mirror structs, and a
//! signature over a mirror verifies only if the mirror serializes to the same
//! JSON *value* the server's struct re-serializes to. Four `ClaimSubmission`
//! fields do not line up automatically, and each one turns a real signature into
//! a 401 without any other error:
//!
//! - `initial_truth`: the server OMITS it when `None`, and rejects an explicit
//!   `null` outright;
//! - `idempotency_key`: the server always emits it, `null` when `None`;
//! - `properties`: the server always emits it, `null` when `None`;
//! - `labels`: the server always emits it, `[]` when empty.
//!
//! Each ingester pins its mirror with a unit test. The test sends a signed
//! packet through the wire encoding into
//! `epigraph_api::routes::submit::EpistemicPacket` (a dev-dependency) and
//! verifies the signature against that type's own `signable_bytes()`. If the
//! server gains a field with a serialized default, that test breaks, not a
//! production ingest.
//!
//! # Sign last
//!
//! Every field of `claim`, `evidence` and `reasoning_trace` is covered. That
//! includes the labels `ingest_git` bakes into the claim just before it POSTs,
//! and the per-evidence signatures. Sign immediately before sending, after the
//! last mutation.

use epigraph_crypto::{AgentSigner, CryptoError};
use serde::Serialize;

/// The signature an ingester sends when it holds no key for `claim.agent_id`.
///
/// The server still requires the field. It checks the value only when
/// `EPIGRAPH_REQUIRE_SIGNATURES=true`, and then rejects this value with 401. It
/// is a declared "unsigned" marker, not a signature.
#[must_use]
pub fn unsigned_packet_signature() -> String {
    "0".repeat(128)
}

/// Hex-encoded Ed25519 signature over the packet's signable bytes, the same
/// bytes `EpistemicPacket::signable_bytes()` recomputes on the server.
///
/// `claim`, `evidence` and `reasoning_trace` must serialize exactly as the
/// server's `ClaimSubmission`, `EvidenceSubmission` and
/// `ReasoningTraceSubmission` re-serialize. See the module docs for the fields
/// where that is not automatic.
///
/// # Errors
/// Returns `CryptoError::SerializationError` if a part cannot be serialized to
/// JSON.
pub fn packet_signature<C, E, R>(
    signer: &AgentSigner,
    claim: &C,
    evidence: &[E],
    reasoning_trace: &R,
) -> Result<String, CryptoError>
where
    C: Serialize,
    E: Serialize,
    R: Serialize,
{
    // Field names must match the server's private `PacketSignable` envelope.
    // The test below checks them against `signable_bytes()` directly.
    #[derive(Serialize)]
    struct PacketSignable<'a, C, E, R> {
        claim: &'a C,
        evidence: &'a [E],
        reasoning_trace: &'a R,
    }
    let bytes = epigraph_crypto::to_canonical_bytes(&PacketSignable {
        claim,
        evidence,
        reasoning_trace,
    })?;
    Ok(hex::encode(signer.sign(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_api::routes::submit::{
        ClaimSubmission, EpistemicPacket, EvidenceSubmission, EvidenceTypeSubmission,
        MethodologySubmission, OptionalTruth, ReasoningTraceSubmission, TraceInputSubmission,
    };
    use epigraph_crypto::SignatureVerifier;
    use uuid::Uuid;

    fn verifies(signer: &AgentSigner, packet: &EpistemicPacket) -> bool {
        let mut sig = [0u8; 64];
        hex::decode_to_slice(&packet.signature, &mut sig).expect("128 hex chars");
        SignatureVerifier::verify(
            &signer.public_key(),
            &packet.signable_bytes().expect("server canonicalizes"),
            &sig,
        )
        .expect("well-formed public key")
    }

    /// The helper's envelope (`{claim, evidence, reasoning_trace}`) matches
    /// the server's: signing the SERVER's own parts through the helper must
    /// verify against the server's `signable_bytes()`.
    #[test]
    fn signature_over_server_parts_verifies_against_server_signable_bytes() {
        let signer = AgentSigner::generate();
        let mut packet = EpistemicPacket {
            claim: ClaimSubmission {
                content: "Envelope pin".into(),
                initial_truth: OptionalTruth(Some(0.7)),
                agent_id: Uuid::new_v4(),
                idempotency_key: Some("k".into()),
                properties: Some(serde_json::json!({"z": 1, "a": [1, 2]})),
                labels: vec!["x".into()],
            },
            evidence: vec![EvidenceSubmission {
                content_hash: "00".repeat(32),
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".into(),
                },
                raw_content: Some("e".into()),
                signature: None,
            }],
            reasoning_trace: ReasoningTraceSubmission {
                methodology: MethodologySubmission::Heuristic,
                inputs: vec![TraceInputSubmission::Evidence { index: 0 }],
                confidence: 0.8,
                explanation: "why".into(),
                signature: None,
            },
            signature: String::new(),
        };
        packet.signature = packet_signature(
            &signer,
            &packet.claim,
            &packet.evidence,
            &packet.reasoning_trace,
        )
        .unwrap();
        assert!(verifies(&signer, &packet));

        // And the placeholder is exactly what enforcement rejects.
        packet.signature = unsigned_packet_signature();
        assert!(!verifies(&signer, &packet));
    }
}
