//! `ReasoningTrace` domain model
//!
//! A `ReasoningTrace` captures the logical derivation path of a claim, forming a DAG
//! (Directed Acyclic Graph) of reasoning dependencies.
//!
//! # Key Principles
//!
//! - No cycles allowed - creates a DAG, not a general graph
//! - Traces reference their inputs (evidence or other claims)
//! - Different methodologies have different trust modifiers
//! - All traces must be signed by the agent who created them

use super::ids::{AgentId, ClaimId, EvidenceId, TraceId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// Reasoning methodology used to derive a claim
///
/// Different methodologies have different trust/weight modifiers.
/// Formal proofs are weighted highest, heuristics lowest.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Methodology {
    /// Deductive reasoning (conclusion follows necessarily from premises)
    Deductive,

    /// Inductive reasoning (generalizing from specific observations)
    Inductive,

    /// Abductive reasoning (inference to best explanation)
    Abductive,

    /// Instrumental measurement or calculation
    Instrumental,

    /// Extraction from literature or documents
    Extraction,

    /// Bayesian inference with explicit probabilities
    BayesianInference,

    /// Visual inspection or pattern recognition
    VisualInspection,

    /// Formal mathematical or logical proof
    FormalProof,

    /// Heuristic or rule-of-thumb
    Heuristic,
}

impl Methodology {
    /// The largest [`Self::weight_modifier`], the methodology with the most
    /// weight (`FormalProof`). A truth formula that normalizes a methodology
    /// weight to `[0, 1]` divides by this, so it never copies the top weight
    /// as a literal (backlog 19e46f05). The test
    /// `max_weight_modifier_is_the_largest_weight` keeps it the maximum.
    pub const MAX_WEIGHT_MODIFIER: f64 = Self::FormalProof.weight_modifier();

    /// Returns a weight modifier for truth calculation
    ///
    /// Formal proofs get bonuses (> 1.0), heuristics get penalties (< 1.0)
    #[must_use]
    pub const fn weight_modifier(self) -> f64 {
        match self {
            Self::FormalProof => 1.2,
            Self::Deductive => 1.1,
            Self::BayesianInference => 1.0,
            Self::Inductive => 0.9,
            Self::Instrumental => 0.85,
            Self::VisualInspection => 0.8,
            Self::Extraction => 0.75,
            Self::Abductive => 0.7,
            Self::Heuristic => 0.5,
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::FormalProof => "Formal mathematical or logical proof",
            Self::Deductive => "Deductive reasoning from premises",
            Self::BayesianInference => "Bayesian probabilistic inference",
            Self::Inductive => "Inductive generalization",
            Self::Instrumental => "Instrumental measurement",
            Self::VisualInspection => "Visual inspection",
            Self::Extraction => "Literature or document extraction",
            Self::Abductive => "Abductive inference (best explanation)",
            Self::Heuristic => "Heuristic or rule-of-thumb",
        }
    }
}

/// Input to a reasoning trace (either evidence or another claim)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TraceInput {
    /// Evidence as input
    Evidence { id: EvidenceId },

    /// Another claim as input (creates reasoning chain)
    Claim { id: ClaimId },
}

impl TraceInput {
    /// Get the ID as a UUID (for database queries)
    #[must_use]
    pub const fn id_as_uuid(&self) -> uuid::Uuid {
        match self {
            Self::Evidence { id } => id.as_uuid(),
            Self::Claim { id } => id.as_uuid(),
        }
    }

    /// Get the type as a string
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Evidence { .. } => "evidence",
            Self::Claim { .. } => "claim",
        }
    }
}

/// A reasoning trace capturing the derivation of a claim
///
/// # Design Notes
///
/// - `inputs`: Evidence or claims that this trace builds upon
/// - `methodology`: How the reasoning was performed
/// - `confidence`: Agent's confidence in this reasoning (0.0 to 1.0)
/// - `explanation`: Human-readable reasoning explanation
/// - Must be signed by the agent who created it
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTrace {
    /// Unique identifier for this trace
    pub id: TraceId,

    /// The agent who created this reasoning trace
    pub agent_id: AgentId,

    /// Ed25519 public key of the signing agent (32 bytes)
    /// Required for signature verification without database lookup
    #[serde_as(as = "Bytes")]
    pub public_key: [u8; 32],

    /// BLAKE3 content hash (32 bytes) for content addressing
    #[serde_as(as = "Bytes")]
    pub content_hash: [u8; 32],

    /// The methodology used for this reasoning
    pub methodology: Methodology,

    /// Inputs to this reasoning (evidence or other claims)
    pub inputs: Vec<TraceInput>,

    /// Agent's confidence in this reasoning [0.0, 1.0]
    pub confidence: f64,

    /// Human-readable explanation of the reasoning
    pub explanation: String,

    /// Ed25519 signature from the agent (64 bytes)
    #[serde_as(as = "Option<Bytes>")]
    pub signature: Option<[u8; 64]>,

    /// When this trace was created
    pub created_at: DateTime<Utc>,
}

impl ReasoningTrace {
    /// Create a new reasoning trace (signature must be added separately)
    ///
    /// # Panics
    /// Panics if confidence is not in [0.0, 1.0]
    #[must_use]
    pub fn new(
        agent_id: AgentId,
        public_key: [u8; 32],
        methodology: Methodology,
        inputs: Vec<TraceInput>,
        confidence: f64,
        explanation: String,
    ) -> Self {
        assert!(
            (0.0..=1.0).contains(&confidence),
            "Confidence must be in [0.0, 1.0]"
        );

        Self {
            id: TraceId::new(),
            agent_id,
            public_key,
            content_hash: [0u8; 32],
            methodology,
            inputs,
            confidence,
            explanation,
            signature: None,
            created_at: Utc::now(),
        }
    }

    /// Create a reasoning trace with a specific ID (for database deserialization)
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn with_id(
        id: TraceId,
        agent_id: AgentId,
        public_key: [u8; 32],
        content_hash: [u8; 32],
        methodology: Methodology,
        inputs: Vec<TraceInput>,
        confidence: f64,
        explanation: String,
        signature: Option<[u8; 64]>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            agent_id,
            public_key,
            content_hash,
            methodology,
            inputs,
            confidence,
            explanation,
            signature,
            created_at,
        }
    }

    /// Check if this trace has been signed
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Get the weight modifier for this trace's methodology
    #[must_use]
    pub const fn methodology_weight(&self) -> f64 {
        self.methodology.weight_modifier()
    }

    /// Calculate the effective weight combining methodology and confidence
    #[must_use]
    pub fn effective_weight(&self) -> f64 {
        self.methodology.weight_modifier() * self.confidence
    }

    /// Get all claim IDs referenced by this trace
    #[must_use]
    pub fn claim_dependencies(&self) -> Vec<ClaimId> {
        self.inputs
            .iter()
            .filter_map(|input| match input {
                TraceInput::Claim { id } => Some(*id),
                TraceInput::Evidence { .. } => None,
            })
            .collect()
    }

    /// Get all evidence IDs referenced by this trace
    #[must_use]
    pub fn evidence_dependencies(&self) -> Vec<EvidenceId> {
        self.inputs
            .iter()
            .filter_map(|input| match input {
                TraceInput::Evidence { id } => Some(*id),
                TraceInput::Claim { .. } => None,
            })
            .collect()
    }
}

impl std::hash::Hash for ReasoningTrace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// Only compare by ID for equality (structural equivalence)
impl PartialEq for ReasoningTrace {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ReasoningTrace {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methodology_weight_modifiers() {
        assert!(Methodology::FormalProof.weight_modifier() > 1.0);
        assert!(Methodology::Deductive.weight_modifier() > 1.0);
        assert_eq!(Methodology::BayesianInference.weight_modifier(), 1.0);
        assert!(Methodology::Heuristic.weight_modifier() < 1.0);
    }

    #[test]
    fn create_trace_with_evidence_input() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let evidence_id = EvidenceId::new();

        let trace = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::Deductive,
            vec![TraceInput::Evidence { id: evidence_id }],
            0.9,
            "Based on evidence X, we conclude Y".to_string(),
        );

        assert_eq!(trace.agent_id, agent_id);
        assert_eq!(trace.methodology, Methodology::Deductive);
        assert_eq!(trace.inputs.len(), 1);
        assert_eq!(trace.confidence, 0.9);
        assert!(!trace.is_signed());
    }

    #[test]
    fn create_trace_with_claim_inputs() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let claim1 = ClaimId::new();
        let claim2 = ClaimId::new();

        let trace = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::Inductive,
            vec![
                TraceInput::Claim { id: claim1 },
                TraceInput::Claim { id: claim2 },
            ],
            0.75,
            "Generalizing from claims X and Y".to_string(),
        );

        let deps = trace.claim_dependencies();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&claim1));
        assert!(deps.contains(&claim2));
    }

    #[test]
    fn effective_weight_combines_methodology_and_confidence() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let trace = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::FormalProof, // weight = 1.2
            vec![],
            0.5, // confidence = 0.5
            "test".to_string(),
        );

        let effective = trace.effective_weight();
        assert!((effective - 0.6).abs() < f64::EPSILON); // 1.2 * 0.5 = 0.6
    }

    #[test]
    #[should_panic(expected = "Confidence must be in [0.0, 1.0]")]
    fn create_trace_panics_with_invalid_confidence() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let _ = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::Deductive,
            vec![],
            1.5, // Invalid confidence > 1.0
            "test".to_string(),
        );
    }

    #[test]
    fn trace_serializes_to_json() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let evidence_id = EvidenceId::new();

        let trace = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::BayesianInference,
            vec![TraceInput::Evidence { id: evidence_id }],
            0.85,
            "Bayesian update".to_string(),
        );

        let json = serde_json::to_string(&trace).unwrap();
        let deserialized: ReasoningTrace = serde_json::from_str(&json).unwrap();

        assert_eq!(trace.id, deserialized.id);
        assert_eq!(trace.methodology, deserialized.methodology);
        assert_eq!(trace.confidence, deserialized.confidence);
    }

    #[test]
    fn evidence_dependencies_extraction() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let evidence1 = EvidenceId::new();
        let evidence2 = EvidenceId::new();
        let claim1 = ClaimId::new();

        let trace = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::Abductive,
            vec![
                TraceInput::Evidence { id: evidence1 },
                TraceInput::Claim { id: claim1 },
                TraceInput::Evidence { id: evidence2 },
            ],
            0.7,
            "Mixed inputs".to_string(),
        );

        let evidence_deps = trace.evidence_dependencies();
        assert_eq!(evidence_deps.len(), 2);
        assert!(evidence_deps.contains(&evidence1));
        assert!(evidence_deps.contains(&evidence2));
    }

    #[test]
    fn trace_input_type_names() {
        let evidence_input = TraceInput::Evidence {
            id: EvidenceId::new(),
        };
        let claim_input = TraceInput::Claim { id: ClaimId::new() };

        assert_eq!(evidence_input.type_name(), "evidence");
        assert_eq!(claim_input.type_name(), "claim");
    }

    #[test]
    fn trace_input_id_as_uuid() {
        let evidence_id = EvidenceId::new();
        let claim_id = ClaimId::new();

        let evidence_input = TraceInput::Evidence { id: evidence_id };
        let claim_input = TraceInput::Claim { id: claim_id };

        assert_eq!(evidence_input.id_as_uuid(), evidence_id.as_uuid());
        assert_eq!(claim_input.id_as_uuid(), claim_id.as_uuid());
    }

    #[test]
    fn methodology_descriptions() {
        assert!(!Methodology::FormalProof.description().is_empty());
        assert!(!Methodology::Deductive.description().is_empty());
        assert!(!Methodology::Inductive.description().is_empty());
        assert!(!Methodology::Abductive.description().is_empty());
        assert!(!Methodology::Instrumental.description().is_empty());
        assert!(!Methodology::Extraction.description().is_empty());
        assert!(!Methodology::BayesianInference.description().is_empty());
        assert!(!Methodology::VisualInspection.description().is_empty());
        assert!(!Methodology::Heuristic.description().is_empty());
    }

    /// Every variant, listed through an exhaustive match so a new variant
    /// does not compile until it is added here.
    fn every_methodology() -> [Methodology; 9] {
        let all = [
            Methodology::Deductive,
            Methodology::Inductive,
            Methodology::Abductive,
            Methodology::Instrumental,
            Methodology::Extraction,
            Methodology::BayesianInference,
            Methodology::VisualInspection,
            Methodology::FormalProof,
            Methodology::Heuristic,
        ];
        for m in all {
            match m {
                Methodology::Deductive
                | Methodology::Inductive
                | Methodology::Abductive
                | Methodology::Instrumental
                | Methodology::Extraction
                | Methodology::BayesianInference
                | Methodology::VisualInspection
                | Methodology::FormalProof
                | Methodology::Heuristic => {}
            }
        }
        all
    }

    #[test]
    fn max_weight_modifier_is_the_largest_weight() {
        let all = every_methodology();
        for m in all {
            assert!(
                m.weight_modifier() <= Methodology::MAX_WEIGHT_MODIFIER,
                "{m:?} weighs {} above MAX_WEIGHT_MODIFIER {}",
                m.weight_modifier(),
                Methodology::MAX_WEIGHT_MODIFIER
            );
        }
        assert!(
            all.iter()
                .any(|m| m.weight_modifier() == Methodology::MAX_WEIGHT_MODIFIER),
            "MAX_WEIGHT_MODIFIER is no methodology's weight"
        );
    }

    #[test]
    fn methodology_weight_ordering() {
        // Higher confidence methodologies should have higher weights
        assert!(
            Methodology::FormalProof.weight_modifier() > Methodology::Heuristic.weight_modifier()
        );
        assert!(
            Methodology::Deductive.weight_modifier() > Methodology::Abductive.weight_modifier()
        );
    }

    #[test]
    #[should_panic(expected = "Confidence must be in [0.0, 1.0]")]
    fn create_trace_panics_with_negative_confidence() {
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let _ = ReasoningTrace::new(
            agent_id,
            public_key,
            Methodology::Deductive,
            vec![],
            -0.1, // Invalid confidence < 0.0
            "test".to_string(),
        );
    }

    #[test]
    fn trace_with_id_and_signature() {
        let id = TraceId::new();
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];
        let signature = [0xCDu8; 64];
        let created_at = Utc::now();

        let trace = ReasoningTrace::with_id(
            id,
            agent_id,
            public_key,
            content_hash,
            Methodology::Extraction,
            vec![],
            0.6,
            "Extracted from document".to_string(),
            Some(signature),
            created_at,
        );

        assert_eq!(trace.id, id);
        assert!(trace.is_signed());
        assert_eq!(trace.signature, Some(signature));
    }

    #[test]
    fn trace_equality_by_id() {
        let id = TraceId::new();
        let agent_id = AgentId::new();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];
        let now = Utc::now();

        let trace1 = ReasoningTrace::with_id(
            id,
            agent_id,
            public_key,
            content_hash,
            Methodology::Deductive,
            vec![],
            0.5,
            "trace 1".to_string(),
            None,
            now,
        );

        let trace2 = ReasoningTrace::with_id(
            id,
            agent_id,
            public_key,
            content_hash,
            Methodology::Inductive, // Different methodology
            vec![],
            0.9, // Different confidence
            "trace 2".to_string(),
            None,
            now,
        );

        assert_eq!(trace1, trace2, "Traces with same ID should be equal");
    }
}
