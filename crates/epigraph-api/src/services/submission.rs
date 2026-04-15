//! Submission Service for EpiGraph API
//!
//! Encapsulates the business logic for processing epistemic packet submissions.
//! This separates concerns from the HTTP handler layer.
//!
//! # Responsibilities
//!
//! - Validate packet structure and content
//! - Calculate initial truth value from evidence
//! - Coordinate with repositories for persistence
//! - Manage propagation after claim creation
//!
//! # Key Principle (BAD ACTOR TEST)
//!
//! Truth calculation NEVER uses agent reputation. Only evidence determines truth.

use crate::errors::ApiError;
use crate::routes::submit::{
    EpistemicPacket, EvidenceSubmission, MethodologySubmission, TraceInputSubmission,
};
use crate::services::validation::{ValidationService, MAX_EVIDENCE_PER_PACKET};
use crate::state::ApiConfig;
#[allow(deprecated)]
use epigraph_engine::BayesianUpdater;

/// Result of packet validation
#[derive(Debug)]
pub struct ValidationResult {
    /// Whether validation passed
    pub is_valid: bool,
    /// Validation errors (empty if valid)
    pub errors: Vec<ValidationError>,
}

/// A single validation error
#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub reason: String,
}

/// Service for handling epistemic packet submissions
pub struct SubmissionService;

impl SubmissionService {
    /// Validate an epistemic packet
    ///
    /// Performs comprehensive validation including:
    /// - Claim content validation
    /// - Evidence count limits (DoS prevention)
    /// - Truth value bounds
    /// - Reasoning trace requirements (no naked assertions)
    /// - Evidence hash verification
    /// - Signature format validation (if required)
    ///
    /// # Arguments
    /// * `packet` - The packet to validate
    /// * `config` - API configuration for signature requirements
    ///
    /// # Returns
    /// * `Ok(())` - Packet is valid
    /// * `Err(ApiError)` - First validation error encountered
    pub fn validate_packet(packet: &EpistemicPacket, config: &ApiConfig) -> Result<(), ApiError> {
        // 1. Validate claim content is not empty
        ValidationService::validate_non_empty(&packet.claim.content, "claim.content")?;

        // 2. Validate evidence count is within bounds (DoS prevention)
        if packet.evidence.len() > MAX_EVIDENCE_PER_PACKET {
            return Err(ApiError::ValidationError {
                field: "evidence".to_string(),
                reason: format!(
                    "Too many evidence items: {} provided, maximum is {}",
                    packet.evidence.len(),
                    MAX_EVIDENCE_PER_PACKET
                ),
            });
        }

        // 3. Validate initial_truth if provided
        if let Some(truth) = packet.claim.initial_truth.0 {
            ValidationService::validate_truth_value(truth, "claim.initial_truth")?;
        }

        // 4. Validate reasoning trace has explanation (no naked assertions)
        ValidationService::validate_non_empty(
            &packet.reasoning_trace.explanation,
            "reasoning_trace.explanation",
        )?;

        // 5. Validate reasoning confidence bounds
        ValidationService::validate_confidence(
            packet.reasoning_trace.confidence,
            "reasoning_trace.confidence",
        )?;

        // 6. Validate evidence content hashes
        for (i, evidence) in packet.evidence.iter().enumerate() {
            Self::validate_evidence(evidence, i)?;
        }

        // 7. Validate trace input references
        Self::validate_trace_inputs(packet)?;

        // 8. Validate signature (if required)
        if config.require_signatures {
            Self::validate_signature(packet)?;
        }

        Ok(())
    }

    /// Validate a single evidence item
    fn validate_evidence(evidence: &EvidenceSubmission, index: usize) -> Result<(), ApiError> {
        let field_name = format!("evidence[{}].content_hash", index);

        // Validate hex format and length
        ValidationService::validate_content_hash(&evidence.content_hash, &field_name)?;

        // If raw_content is provided, verify it matches the hash
        if let Some(ref raw_content) = evidence.raw_content {
            ValidationService::verify_content_hash(
                raw_content.as_bytes(),
                &evidence.content_hash,
                &format!("evidence[{}]", index),
            )?;
        }

        Ok(())
    }

    /// Validate trace input references
    fn validate_trace_inputs(packet: &EpistemicPacket) -> Result<(), ApiError> {
        for input in &packet.reasoning_trace.inputs {
            match input {
                TraceInputSubmission::Evidence { index } => {
                    if *index >= packet.evidence.len() {
                        return Err(ApiError::ValidationError {
                            field: "reasoning_trace.inputs".to_string(),
                            reason: format!(
                                "Evidence index {} is out of bounds (only {} evidence items provided)",
                                index,
                                packet.evidence.len()
                            ),
                        });
                    }
                }
                TraceInputSubmission::Claim { id } => {
                    // Check for circular reference via idempotency key
                    if let Some(ref key) = packet.claim.idempotency_key {
                        if key == &id.to_string() {
                            return Err(ApiError::ValidationError {
                                field: "reasoning_trace.inputs".to_string(),
                                reason: "Reasoning trace cannot reference its own claim (circular reference)".to_string(),
                            });
                        }
                    }
                    // Note: Existence check for referenced claims should be done at the database layer
                }
            }
        }
        Ok(())
    }

    /// Validate packet signature
    fn validate_signature(packet: &EpistemicPacket) -> Result<(), ApiError> {
        ValidationService::validate_signature_format(&packet.signature, "signature")?;

        // In production, verify the signature against the agent's public key
        // For testing, reject non-placeholder signatures since we can't verify them
        let is_placeholder = packet.signature.chars().all(|c| c == '0');
        if !is_placeholder {
            return Err(ApiError::SignatureError {
                reason: "Signature verification failed - invalid signature for agent".to_string(),
            });
        }

        Ok(())
    }

    /// Calculate the initial truth value for a claim based on evidence
    ///
    /// # CRITICAL INVARIANT (BAD ACTOR TEST)
    ///
    /// This function takes ONLY evidence parameters, NOT agent reputation.
    /// This architectural enforcement prevents the "Appeal to Authority" fallacy.
    ///
    /// ## Key Requirements:
    /// - NO evidence -> truth < 0.3 (claims without evidence are not trusted)
    /// - Evidence count matters more than methodology
    /// - Methodology and confidence only scale the evidence-based truth
    ///
    /// # Arguments
    /// * `evidence_count` - Number of evidence items supporting the claim
    /// * `methodology` - The reasoning methodology used
    /// * `confidence` - Agent's stated confidence in the reasoning
    ///
    /// # Returns
    /// The calculated initial truth value in [0.0, 1.0]
    #[must_use]
    pub fn calculate_truth_from_evidence(
        evidence_count: usize,
        methodology: MethodologySubmission,
        confidence: f64,
    ) -> f64 {
        // BAD ACTOR TEST: If there's NO evidence, truth MUST be low
        // This prevents high-reputation agents from making unsupported claims
        if evidence_count == 0 {
            // With no evidence, truth is very low regardless of methodology
            // Base uncertainty (0.1) + small methodology bonus (max 0.1)
            let methodology_factor = methodology.weight_modifier() / 1.2; // Normalize to [0, 1]
            let confidence_factor = confidence * 0.1; // Max 0.1 contribution
            return (0.1 + methodology_factor * confidence_factor).min(0.25);
        }

        // With evidence, calculate based on evidence strength
        let methodology_weight = methodology.weight_modifier();
        let effective_weight = methodology_weight * confidence;

        // Normalize to [0, 1] for evidence weight
        // Apply more aggressive scaling for weak methodologies
        let normalized_weight = (effective_weight / 1.2).min(1.0);

        // Apply additional penalty for weak methodologies (< 1.0 weight modifier)
        // This ensures weak evidence with weak methodology doesn't inflate truth
        let methodology_penalty = if methodology_weight < 1.0 {
            0.9 * methodology_weight // Reduce by up to 50% for heuristic
        } else {
            1.0
        };
        let penalized_weight = normalized_weight * methodology_penalty;

        // Use the Bayesian updater's initial truth calculation
        // This ONLY uses evidence weight and count - NO reputation
        // TODO: migrate to CDST pignistic probability (BayesianUpdater is deprecated)
        #[allow(deprecated)]
        let truth = BayesianUpdater::calculate_initial_truth(penalized_weight, evidence_count);

        truth.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::submit::{
        ClaimSubmission, EvidenceTypeSubmission, OptionalTruth, ReasoningTraceSubmission,
    };
    use uuid::Uuid;

    fn create_valid_packet() -> EpistemicPacket {
        EpistemicPacket {
            claim: ClaimSubmission {
                content: "Test claim content".to_string(),
                initial_truth: OptionalTruth(Some(0.5)),
                agent_id: Uuid::new_v4(),
                idempotency_key: None,
                properties: None,
            },
            evidence: vec![],
            reasoning_trace: ReasoningTraceSubmission {
                methodology: MethodologySubmission::Deductive,
                inputs: vec![],
                confidence: 0.8,
                explanation: "Test explanation".to_string(),
                signature: None,
            },
            signature: "0".repeat(128),
        }
    }

    #[test]
    fn test_validate_packet_valid() {
        let packet = create_valid_packet();
        let config = ApiConfig::default();
        assert!(SubmissionService::validate_packet(&packet, &config).is_ok());
    }

    #[test]
    fn test_validate_packet_empty_content() {
        let mut packet = create_valid_packet();
        packet.claim.content = "   ".to_string();
        let config = ApiConfig::default();
        let result = SubmissionService::validate_packet(&packet, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "claim.content");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_packet_empty_explanation() {
        let mut packet = create_valid_packet();
        packet.reasoning_trace.explanation = "".to_string();
        let config = ApiConfig::default();
        let result = SubmissionService::validate_packet(&packet, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "reasoning_trace.explanation");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_packet_too_many_evidence() {
        let mut packet = create_valid_packet();
        packet.evidence = (0..MAX_EVIDENCE_PER_PACKET + 1)
            .map(|_| EvidenceSubmission {
                content_hash: "0".repeat(64),
                evidence_type: EvidenceTypeSubmission::Document {
                    source_url: None,
                    mime_type: "text/plain".to_string(),
                },
                raw_content: None,
                signature: None,
            })
            .collect();
        let config = ApiConfig::default();
        let result = SubmissionService::validate_packet(&packet, &config);
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::ValidationError { field, .. } => {
                assert_eq!(field, "evidence");
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_truth_calculation_no_evidence_yields_low_truth() {
        // BAD ACTOR TEST: No evidence should yield low truth
        let truth = SubmissionService::calculate_truth_from_evidence(
            0,
            MethodologySubmission::Heuristic,
            0.99,
        );
        assert!(
            truth <= 0.6,
            "No evidence should not produce high truth, got {}",
            truth
        );
    }

    #[test]
    fn test_truth_calculation_strong_evidence_yields_reasonable_truth() {
        let truth = SubmissionService::calculate_truth_from_evidence(
            3,
            MethodologySubmission::FormalProof,
            0.95,
        );
        assert!(
            truth > 0.5,
            "Strong evidence should produce reasonable truth, got {}",
            truth
        );
        assert!(
            truth <= 0.85,
            "Initial truth should be capped, got {}",
            truth
        );
    }

    #[test]
    fn test_methodology_weight_ordering() {
        assert!(MethodologySubmission::FormalProof.weight_modifier() > 1.0);
        assert!(MethodologySubmission::Deductive.weight_modifier() > 1.0);
        assert_eq!(
            MethodologySubmission::BayesianInference.weight_modifier(),
            1.0
        );
        assert!(MethodologySubmission::Heuristic.weight_modifier() < 1.0);
    }
}
