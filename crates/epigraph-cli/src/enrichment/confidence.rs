//! Confidence assessment probes for epistemic commit analysis
//!
//! Implements two LLM-based probes that adjust the parser's heuristic confidence:
//!
//! - **Skeptic Probe**: Assesses whether the evidence actually supports the claim
//! - **Coherence Probe**: Checks if a claim is consistent with nearby claims in the same scope
//!
//! The final confidence is always ≤ the parser's value — LLM can only lower, never raise.

use super::llm_client::LlmClient;
use serde::{Deserialize, Serialize};

// =============================================================================
// TYPES
// =============================================================================

/// Result of the skeptic probe assessing evidence quality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSupport {
    StrongSupport,
    WeakSupport,
    Unrelated,
    Contradicts,
}

impl EvidenceSupport {
    /// Adjustment factor applied to parser confidence
    pub fn factor(&self) -> f64 {
        match self {
            Self::StrongSupport => 1.0,
            Self::WeakSupport => 0.7,
            Self::Unrelated => 0.4,
            Self::Contradicts => 0.3,
        }
    }
}

/// Result of the coherence probe checking cross-claim consistency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoherenceResult {
    Consistent,
    Tension,
    Contradiction,
}

impl CoherenceResult {
    /// Adjustment factor applied to parser confidence
    pub fn factor(&self) -> f64 {
        match self {
            Self::Consistent => 1.0,
            Self::Tension => 0.8,
            Self::Contradiction => 0.5,
        }
    }
}

// =============================================================================
// SKEPTIC PROBE
// =============================================================================

/// Build the prompt for the skeptic probe
fn build_skeptic_prompt(claim: &str, evidence: &[String]) -> String {
    let evidence_text = if evidence.is_empty() {
        "No evidence provided.".to_string()
    } else {
        evidence
            .iter()
            .enumerate()
            .map(|(i, e)| format!("{}. {}", i + 1, e))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"You are an epistemic skeptic assessing evidence quality.

Claim: "{claim}"

Evidence:
{evidence_text}

Does this evidence directly support the claim? Rate the support level:

- STRONG_SUPPORT: Evidence clearly and directly proves the claim
- WEAK_SUPPORT: Evidence is tangentially related but doesn't directly prove the claim
- UNRELATED: Evidence has no bearing on the claim
- CONTRADICTS: Evidence actually undermines the claim

Return a JSON object with a single field "rating" set to one of the four values above.
Return ONLY the JSON object, no other text.

Example: {{"rating": "STRONG_SUPPORT"}}"#
    )
}

/// Run the skeptic probe to assess evidence quality
pub async fn skeptic_probe(
    client: &dyn LlmClient,
    claim: &str,
    evidence: &[String],
) -> EvidenceSupport {
    if evidence.is_empty() {
        return EvidenceSupport::Unrelated;
    }

    let prompt = build_skeptic_prompt(claim, evidence);

    match client.complete_json(&prompt).await {
        Ok(value) => {
            if let Some(rating) = value["rating"].as_str() {
                match rating {
                    "STRONG_SUPPORT" => EvidenceSupport::StrongSupport,
                    "WEAK_SUPPORT" => EvidenceSupport::WeakSupport,
                    "UNRELATED" => EvidenceSupport::Unrelated,
                    "CONTRADICTS" => EvidenceSupport::Contradicts,
                    _ => EvidenceSupport::WeakSupport, // Conservative default
                }
            } else {
                EvidenceSupport::WeakSupport // Conservative default on parse failure
            }
        }
        Err(_) => EvidenceSupport::WeakSupport, // Conservative default on API failure
    }
}

// =============================================================================
// COHERENCE PROBE
// =============================================================================

/// Build the prompt for the coherence probe
fn build_coherence_prompt(
    claim: &str,
    scope: &str,
    prior_claims: &[(String, f64)], // (claim_text, truth_value)
) -> String {
    let prior_text = prior_claims
        .iter()
        .enumerate()
        .map(|(i, (text, truth))| format!("{}. \"{}\" (truth: {:.2})", i + 1, text, truth))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"You are checking logical consistency between claims in the same scope.

Scope: "{scope}"

Previous claims in this scope:
{prior_text}

New claim: "{claim}"

Is the new claim consistent with the existing claims?

- CONSISTENT: The new claim aligns with or builds upon existing claims
- TENSION: The new claim partially conflicts with some existing claims
- CONTRADICTION: The new claim directly contradicts existing claims

Return a JSON object with a single field "rating" set to one of the three values above.
Return ONLY the JSON object, no other text.

Example: {{"rating": "CONSISTENT"}}"#
    )
}

/// Run the coherence probe to check cross-claim consistency
pub async fn coherence_probe(
    client: &dyn LlmClient,
    claim: &str,
    scope: &str,
    prior_claims: &[(String, f64)],
) -> CoherenceResult {
    // First claim in a scope is always consistent
    if prior_claims.is_empty() {
        return CoherenceResult::Consistent;
    }

    let prompt = build_coherence_prompt(claim, scope, prior_claims);

    match client.complete_json(&prompt).await {
        Ok(value) => {
            if let Some(rating) = value["rating"].as_str() {
                match rating {
                    "CONSISTENT" => CoherenceResult::Consistent,
                    "TENSION" => CoherenceResult::Tension,
                    "CONTRADICTION" => CoherenceResult::Contradiction,
                    _ => CoherenceResult::Tension, // Conservative default
                }
            } else {
                CoherenceResult::Tension // Conservative default on parse failure
            }
        }
        Err(_) => CoherenceResult::Tension, // Conservative default on API failure
    }
}

// =============================================================================
// COMBINED CONFIDENCE
// =============================================================================

/// Compute the final confidence by combining skeptic and coherence factors.
///
/// `final_confidence = min(parser_confidence, parser_confidence * skeptic_factor * coherence_factor)`
///
/// The result never goes below 0.0.
/// The result never exceeds the parser's heuristic confidence.
pub fn combined_confidence(
    parser_confidence: f64,
    skeptic: EvidenceSupport,
    coherence: CoherenceResult,
) -> f64 {
    let adjusted = parser_confidence * skeptic.factor() * coherence.factor();
    adjusted.min(parser_confidence).max(0.0)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::llm_client::MockLlmClient;

    // --- Skeptic Probe ---

    #[tokio::test]
    async fn test_skeptic_strong_support_no_adjustment() {
        let client =
            MockLlmClient::with_responses(vec![serde_json::json!({"rating": "STRONG_SUPPORT"})]);
        let result = skeptic_probe(
            &client,
            "add truth validation",
            &["Plan requires it".to_string()],
        )
        .await;
        assert_eq!(result, EvidenceSupport::StrongSupport);
        assert!((result.factor() - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_skeptic_weak_support_lowers_confidence() {
        let client =
            MockLlmClient::with_responses(vec![serde_json::json!({"rating": "WEAK_SUPPORT"})]);
        let result = skeptic_probe(&client, "add feature", &["some evidence".to_string()]).await;
        assert_eq!(result, EvidenceSupport::WeakSupport);
        assert!((result.factor() - 0.7).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_skeptic_unrelated_evidence_flags_low_confidence() {
        let client =
            MockLlmClient::with_responses(vec![serde_json::json!({"rating": "UNRELATED"})]);
        let result = skeptic_probe(&client, "fix bug", &["updated README".to_string()]).await;
        assert_eq!(result, EvidenceSupport::Unrelated);
        assert!((result.factor() - 0.4).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_skeptic_handles_no_evidence_commits() {
        let client = MockLlmClient::new(); // Won't be called
        let result = skeptic_probe(&client, "chore: update deps", &[]).await;
        assert_eq!(result, EvidenceSupport::Unrelated);
    }

    #[tokio::test]
    async fn test_skeptic_handles_api_failure() {
        let client = MockLlmClient::new();
        client.set_malformed(true);
        let result = skeptic_probe(&client, "claim", &["evidence".to_string()]).await;
        // Should default to WeakSupport on failure
        assert_eq!(result, EvidenceSupport::WeakSupport);
    }

    // --- Coherence Probe ---

    #[tokio::test]
    async fn test_coherence_consistent_claims_pass() {
        let client =
            MockLlmClient::with_responses(vec![serde_json::json!({"rating": "CONSISTENT"})]);
        let prior = vec![("define Claim model".to_string(), 0.6)];
        let result = coherence_probe(&client, "add truth validation", "core", &prior).await;
        assert_eq!(result, CoherenceResult::Consistent);
        assert!((result.factor() - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_coherence_contradiction_detected() {
        let client =
            MockLlmClient::with_responses(vec![serde_json::json!({"rating": "CONTRADICTION"})]);
        let prior = vec![("add truth validation".to_string(), 0.6)];
        let result = coherence_probe(&client, "remove truth validation", "core", &prior).await;
        assert_eq!(result, CoherenceResult::Contradiction);
        assert!((result.factor() - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_coherence_first_claim_in_scope_always_passes() {
        let client = MockLlmClient::new(); // Won't be called
        let result = coherence_probe(&client, "first claim", "core", &[]).await;
        assert_eq!(result, CoherenceResult::Consistent);
    }

    #[tokio::test]
    async fn test_coherence_tension_factor() {
        let result = CoherenceResult::Tension;
        assert!((result.factor() - 0.8).abs() < f64::EPSILON);
    }

    // --- Combined Confidence ---

    #[test]
    fn test_combined_confidence_never_exceeds_parser() {
        // Even with perfect factors, result can't exceed parser confidence
        let result = combined_confidence(
            0.5,
            EvidenceSupport::StrongSupport,
            CoherenceResult::Consistent,
        );
        assert!((result - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_combined_confidence_multiplies_factors() {
        // parser=0.85, skeptic=0.7, coherence=0.8 → 0.85 * 0.7 * 0.8 = 0.476
        let result =
            combined_confidence(0.85, EvidenceSupport::WeakSupport, CoherenceResult::Tension);
        let expected = 0.85 * 0.7 * 0.8;
        assert!(
            (result - expected).abs() < 1e-10,
            "Expected {expected}, got {result}"
        );
    }

    #[test]
    fn test_combined_confidence_allows_below_0_1() {
        // Low factors should NOT be clamped — LLM must never artificially raise confidence
        let result = combined_confidence(
            0.3,
            EvidenceSupport::Contradicts,
            CoherenceResult::Contradiction,
        );
        // 0.3 * 0.3 * 0.5 = 0.045
        let expected = 0.3 * 0.3 * 0.5;
        assert!(
            (result - expected).abs() < f64::EPSILON,
            "Expected {expected}, got {result}"
        );
    }

    #[test]
    fn test_combined_confidence_all_strong() {
        let result = combined_confidence(
            0.85,
            EvidenceSupport::StrongSupport,
            CoherenceResult::Consistent,
        );
        assert!((result - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_combined_confidence_worst_case() {
        let result = combined_confidence(
            0.85,
            EvidenceSupport::Contradicts,
            CoherenceResult::Contradiction,
        );
        // 0.85 * 0.3 * 0.5 = 0.1275
        let expected = 0.85 * 0.3 * 0.5;
        assert!(
            (result - expected).abs() < 1e-10,
            "Expected {expected}, got {result}"
        );
    }
}
