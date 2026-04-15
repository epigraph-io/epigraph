//! Counterfactual engine for generating discriminating experiments (G4, G5)
//!
//! When two claims contradict, this module generates hypothetical scenarios
//! and identifies experiments that could distinguish between them.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to generate counterfactual scenarios for conflicting claims
#[derive(Debug, Clone)]
pub struct CounterfactualRequest {
    pub claim_a_id: Uuid,
    pub claim_b_id: Uuid,
    pub claim_a_content: String,
    pub claim_b_content: String,
}

/// A hypothetical scenario assuming one claim is true
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualScenario {
    /// The assumption made (e.g., "If Claim A is true...")
    pub assumption: String,
    /// Observable predictions that follow
    pub predictions: Vec<String>,
}

/// An experiment that could distinguish between two scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscriminatingTest {
    /// What the test involves
    pub test_description: String,
    /// Expected outcome if claim A is correct
    pub favors_a_if: String,
    /// Expected outcome if claim B is correct
    pub favors_b_if: String,
}

/// Result of counterfactual analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualResult {
    pub claim_a_id: Uuid,
    pub claim_b_id: Uuid,
    pub scenario_a: CounterfactualScenario,
    pub scenario_b: CounterfactualScenario,
    pub discriminating_tests: Vec<DiscriminatingTest>,
}

/// Generate a prompt for LLM-based counterfactual analysis.
///
/// This is the pure prompt-building function. The actual LLM call
/// is handled by the caller (using `LlmClient` trait).
#[must_use]
pub fn build_counterfactual_prompt(request: &CounterfactualRequest) -> String {
    format!(
        r#"Two scientific claims are in direct conflict. Your task is to design
experiments that could FALSIFY each one.

CRITICAL INSTRUCTIONS:
- You must be equally skeptical of BOTH claims
- Generate tests that could DISPROVE each claim, not just confirm it
- Do NOT assume the more conventional or expected claim is more likely correct
- Each discriminating test MUST have a concrete, measurable outcome
- If you cannot think of a falsifying test for a claim, say so explicitly

Claim Alpha: {}
Claim Beta: {}

For each claim, generate:
1. A scenario assuming it is true (with 2-3 specific, measurable predictions)
2. At least one experiment designed to FALSIFY it
3. Observable outcomes that would distinguish between them

Respond with JSON:
{{
  "scenario_a": {{
    "assumption": "If Claim Alpha is true...",
    "predictions": ["prediction1", "prediction2"]
  }},
  "scenario_b": {{
    "assumption": "If Claim Beta is true...",
    "predictions": ["prediction1", "prediction2"]
  }},
  "discriminating_tests": [
    {{
      "test_description": "...",
      "favors_a_if": "...",
      "favors_b_if": "..."
    }}
  ]
}}"#,
        request.claim_a_content, request.claim_b_content,
    )
}

/// Parse an LLM response into a [`CounterfactualResult`].
///
/// Returns None if the response cannot be parsed.
#[must_use]
pub fn parse_counterfactual_response(
    response: &str,
    first_claim_id: Uuid,
    second_claim_id: Uuid,
) -> Option<CounterfactualResult> {
    // Try to find JSON in the response (may have markdown fences)
    let json_str = response
        .find('{')
        .and_then(|start| response.rfind('}').map(|end| &response[start..=end]))?;

    let value: serde_json::Value = serde_json::from_str(json_str).ok()?;

    let scenario_a: CounterfactualScenario =
        serde_json::from_value(value.get("scenario_a")?.clone()).ok()?;
    let scenario_b: CounterfactualScenario =
        serde_json::from_value(value.get("scenario_b")?.clone()).ok()?;
    let discriminating_tests: Vec<DiscriminatingTest> =
        serde_json::from_value(value.get("discriminating_tests")?.clone()).ok()?;

    Some(CounterfactualResult {
        claim_a_id: first_claim_id,
        claim_b_id: second_claim_id,
        scenario_a,
        scenario_b,
        discriminating_tests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_prompt_contains_claims() {
        let req = CounterfactualRequest {
            claim_a_id: Uuid::nil(),
            claim_b_id: Uuid::nil(),
            claim_a_content: "DNA origami can assemble at room temperature".to_string(),
            claim_b_content: "DNA origami requires elevated temperature for assembly".to_string(),
        };
        let prompt = build_counterfactual_prompt(&req);
        assert!(prompt.contains("room temperature"));
        assert!(prompt.contains("elevated temperature"));
        assert!(prompt.contains("discriminating"));
        // Adversarial framing checks
        assert!(prompt.contains("FALSIFY"));
        assert!(prompt.contains("equally skeptical"));
        assert!(prompt.contains("Do NOT assume the more conventional"));
        // Position-bias-reduced labels
        assert!(prompt.contains("Claim Alpha"));
        assert!(prompt.contains("Claim Beta"));
        assert!(!prompt.contains("Claim A:"));
        assert!(!prompt.contains("Claim B:"));
    }

    #[test]
    fn test_parse_valid_response() {
        let response = r#"```json
        {
            "scenario_a": {
                "assumption": "If room temp assembly works...",
                "predictions": ["No heating step needed", "Yield >50% at 25°C"]
            },
            "scenario_b": {
                "assumption": "If elevated temp is required...",
                "predictions": ["Assembly fails below 40°C", "Annealing step is essential"]
            },
            "discriminating_tests": [
                {
                    "test_description": "Run assembly at 25°C vs 60°C",
                    "favors_a_if": "Similar yield at both temperatures",
                    "favors_b_if": "Significantly higher yield at 60°C"
                }
            ]
        }
        ```"#;

        let result = parse_counterfactual_response(response, Uuid::nil(), Uuid::nil());
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.scenario_a.predictions.len(), 2);
        assert_eq!(r.discriminating_tests.len(), 1);
        assert!(r.discriminating_tests[0]
            .test_description
            .contains("25\u{00b0}C"));
    }

    #[test]
    fn test_parse_invalid_response() {
        let result = parse_counterfactual_response("not json at all", Uuid::nil(), Uuid::nil());
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_partial_response() {
        let result = parse_counterfactual_response(
            r#"{"scenario_a": {"assumption": "test", "predictions": []}}"#,
            Uuid::nil(),
            Uuid::nil(),
        );
        // Missing scenario_b, should return None
        assert!(result.is_none());
    }
}
