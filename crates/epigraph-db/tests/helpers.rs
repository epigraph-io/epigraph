//! Shared test helpers for `epigraph-db` integration tests.
//!
//! These functions construct domain structs using the actual constructors from
//! `epigraph_core`. They do NOT insert into the database — callers handle
//! persistence themselves.

use epigraph_core::domain::{
    agent::Agent,
    claim::Claim,
    evidence::{Evidence, EvidenceType},
    ids::{AgentId, ClaimId},
    reasoning_trace::{Methodology, ReasoningTrace, TraceInput},
};
use epigraph_core::TruthValue;

// ── Agent helpers ──────────────────────────────────────────────────────────

/// Build an `Agent` with a random keypair.
///
/// `display_name` is forwarded as-is; pass `None` to get the default
/// hex-truncated key display.
#[allow(dead_code)]
pub fn make_agent(display_name: Option<&str>) -> Agent {
    let mut public_key = [0u8; 32];
    // Randomise the public key so each call produces a unique agent.
    for (i, byte) in public_key.iter_mut().enumerate() {
        *byte = (i as u8)
            .wrapping_mul(17)
            .wrapping_add(uuid::Uuid::new_v4().as_bytes()[i % 16]);
    }
    Agent::new(public_key, display_name.map(String::from))
}

/// Build an `Agent` with a display name and a set of PROV-O labels.
#[allow(dead_code)]
pub fn make_agent_with_labels(display_name: &str, labels: Vec<String>) -> Agent {
    let mut agent = make_agent(Some(display_name));
    agent.labels = labels;
    agent
}

// ── Claim helpers ──────────────────────────────────────────────────────────

/// Build a `Claim` for `agent_id` with the given content and truth value.
///
/// Uses a zero public-key placeholder — sufficient for DB-level tests that do
/// not exercise signature verification.
#[allow(dead_code)]
pub fn make_claim(agent_id: AgentId, content: &str, truth_value: f64) -> Claim {
    let truth = TruthValue::new(truth_value).expect("truth_value must be in [0.0, 1.0]");
    Claim::new(content.to_string(), agent_id, [0u8; 32], truth)
}

// ── Evidence helpers ───────────────────────────────────────────────────────

/// Build a `Document`-typed `Evidence` node linking `claim_id` to
/// `raw_content`.
///
/// The content hash is computed via `epigraph_crypto::ContentHasher::hash`.
#[allow(dead_code)]
pub fn make_evidence(agent_id: AgentId, claim_id: ClaimId, raw_content: &str) -> Evidence {
    let content_hash = epigraph_crypto::ContentHasher::hash(raw_content.as_bytes());
    Evidence::new(
        agent_id,
        [0u8; 32], // placeholder public key
        content_hash,
        EvidenceType::Document {
            source_url: Some("https://example.com/doc.pdf".to_string()),
            mime_type: "application/pdf".to_string(),
            checksum: None,
        },
        Some(raw_content.to_string()),
        claim_id,
    )
}

// ── ReasoningTrace helpers ─────────────────────────────────────────────────

/// Build a `ReasoningTrace` with empty inputs.
///
/// Callers that need specific `TraceInput` entries should push them into
/// `trace.inputs` after calling this helper, or construct the trace directly.
#[allow(dead_code)]
pub fn make_trace(
    agent_id: AgentId,
    methodology: Methodology,
    confidence: f64,
    explanation: &str,
) -> ReasoningTrace {
    ReasoningTrace::new(
        agent_id,
        [0u8; 32], // placeholder public key
        methodology,
        vec![],
        confidence,
        explanation.to_string(),
    )
}

/// Build a `ReasoningTrace` with a single evidence input.
///
/// Convenience wrapper over `make_trace` for the common case where a trace
/// cites one piece of evidence.
#[allow(dead_code)]
pub fn make_trace_with_evidence_input(
    agent_id: AgentId,
    methodology: Methodology,
    confidence: f64,
    explanation: &str,
    evidence_id: epigraph_core::domain::ids::EvidenceId,
) -> ReasoningTrace {
    ReasoningTrace::new(
        agent_id,
        [0u8; 32],
        methodology,
        vec![TraceInput::Evidence { id: evidence_id }],
        confidence,
        explanation.to_string(),
    )
}
