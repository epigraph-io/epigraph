//! Conversion between protobuf types and domain types
//!
//! This module handles mapping between the harvester gRPC protocol
//! and EpiGraph's domain models.

use crate::errors::HarvesterError;
use crate::proto::{self, ExtractedClaim, VerifiedGraph};
use epigraph_core::Methodology;
use serde::{Deserialize, Serialize};

/// A claim extracted by the harvester that hasn't been signed yet
///
/// Once signed by an agent, this becomes a full [`epigraph_core::Claim`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialClaim {
    /// The claim statement
    pub content: String,

    /// Methodology used to derive this claim
    pub methodology: Methodology,

    /// Confidence in the claim [0.0, 1.0]
    pub confidence: f64,

    /// Citations from the source text
    pub citations: Vec<Citation>,

    /// Name of the agent who made this claim (if extracted from source)
    pub agent_name: Option<String>,

    /// Reasoning explanation
    pub reasoning_trace: Option<String>,

    /// Whether this was flagged as low confidence
    pub low_confidence_flag: bool,
}

/// A citation pointing to source text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Citation {
    /// The quoted text
    pub quote: String,

    /// Character offset where quote starts
    pub char_start: usize,

    /// Character offset where quote ends
    pub char_end: usize,
}

/// Convert a protobuf ExtractedClaim to a domain PartialClaim
///
/// # Errors
/// Returns error if:
/// - Confidence is not in [0.0, 1.0]
/// - Required fields are missing
pub fn proto_claim_to_domain(proto: &ExtractedClaim) -> Result<PartialClaim, HarvesterError> {
    // Convert f32 to f64 and validate confidence
    let confidence = f64::from(proto.confidence);
    if !(0.0..=1.0).contains(&confidence) {
        return Err(HarvesterError::InvalidConfidence { value: confidence });
    }

    // Convert citations
    let citations = proto
        .citations
        .iter()
        .map(|c| Citation {
            quote: c.quote.clone(),
            char_start: c.char_start as usize,
            char_end: c.char_end as usize,
        })
        .collect();

    Ok(PartialClaim {
        content: proto.statement.clone(),
        methodology: methodology_from_proto(proto.methodology),
        confidence,
        citations,
        agent_name: if proto.agent_name.is_empty() {
            None
        } else {
            Some(proto.agent_name.clone())
        },
        reasoning_trace: if proto.reasoning_trace.is_empty() {
            None
        } else {
            Some(proto.reasoning_trace.clone())
        },
        low_confidence_flag: proto.low_confidence_flag,
    })
}

/// Convert a VerifiedGraph to a list of PartialClaims
///
/// # Errors
/// Returns error if any claim conversion fails
pub fn proto_graph_to_claims(graph: &VerifiedGraph) -> Result<Vec<PartialClaim>, HarvesterError> {
    graph.claims.iter().map(proto_claim_to_domain).collect()
}

/// Convert protobuf Methodology enum to domain Methodology
///
/// Maps the proto enum values to their domain equivalents.
/// Unspecified defaults to Extraction.
#[must_use]
pub fn methodology_from_proto(m: i32) -> Methodology {
    match proto::Methodology::try_from(m) {
        Ok(proto::Methodology::Deductive) => Methodology::Deductive,
        Ok(proto::Methodology::Inductive) => Methodology::Inductive,
        Ok(proto::Methodology::Abductive) => Methodology::Abductive,
        Ok(proto::Methodology::Instrumental) => Methodology::Instrumental,
        Ok(proto::Methodology::Extraction) => Methodology::Extraction,
        _ => Methodology::Extraction, // Default for unspecified
    }
}

/// Convert domain Methodology to protobuf enum
#[must_use]
pub fn methodology_to_proto(m: Methodology) -> i32 {
    match m {
        Methodology::Deductive => proto::Methodology::Deductive as i32,
        Methodology::Inductive => proto::Methodology::Inductive as i32,
        Methodology::Abductive => proto::Methodology::Abductive as i32,
        Methodology::Instrumental => proto::Methodology::Instrumental as i32,
        Methodology::Extraction => proto::Methodology::Extraction as i32,
        // For methodologies not in proto, default to Extraction
        _ => proto::Methodology::Extraction as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methodology_round_trip() {
        let methods = vec![
            Methodology::Deductive,
            Methodology::Inductive,
            Methodology::Abductive,
            Methodology::Instrumental,
            Methodology::Extraction,
        ];

        for method in methods {
            let proto = methodology_to_proto(method);
            let back = methodology_from_proto(proto);
            assert_eq!(method, back, "Methodology should round-trip");
        }
    }

    #[test]
    fn proto_claim_to_domain_validates_confidence() {
        let mut proto_claim = ExtractedClaim {
            id: "test".to_string(),
            statement: "Test claim".to_string(),
            agent_name: String::new(),
            reasoning_trace: String::new(),
            methodology: proto::Methodology::Extraction as i32,
            citations: vec![],
            claim_type: proto::ClaimType::Factual as i32,
            confidence: 1.5, // Invalid
            low_confidence_flag: false,
        };

        let result = proto_claim_to_domain(&proto_claim);
        assert!(
            matches!(result, Err(HarvesterError::InvalidConfidence { .. })),
            "Should reject confidence > 1.0"
        );

        proto_claim.confidence = 0.8; // Valid
        let result = proto_claim_to_domain(&proto_claim);
        assert!(result.is_ok(), "Should accept valid confidence");
    }

    #[test]
    fn proto_claim_converts_citations() {
        let proto_claim = ExtractedClaim {
            id: "test".to_string(),
            statement: "Test claim".to_string(),
            agent_name: "Author".to_string(),
            reasoning_trace: "Because reasons".to_string(),
            methodology: proto::Methodology::Extraction as i32,
            citations: vec![proto::Citation {
                quote: "quoted text".to_string(),
                char_start: 10,
                char_end: 21,
            }],
            claim_type: proto::ClaimType::Factual as i32,
            confidence: 0.9,
            low_confidence_flag: false,
        };

        let domain = proto_claim_to_domain(&proto_claim).unwrap();
        assert_eq!(domain.citations.len(), 1);
        assert_eq!(domain.citations[0].quote, "quoted text");
        assert_eq!(domain.citations[0].char_start, 10);
        assert_eq!(domain.citations[0].char_end, 21);
    }
}
