//! Unconstrained analysis endpoint: answer a question using an LLM.
//!
//! `POST /api/v1/analyze/unconstrained` takes a question and returns structured
//! factual claims produced by an LLM — no graph constraints. This output is
//! paired with graph-constrained analysis for gap detection.
//!
//! The handler routes through the `LlmClient` trait
//! (`epigraph_cli::enrichment::llm_client::create_llm_client`), which currently
//! supports `"anthropic"` (HTTP, OAuth or API key) and `"mock"`. Downstream
//! distributions can extend the factory with additional providers.
//!
//! This route is feature-gated behind `genai`. With the feature off the handler
//! returns 501.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::errors::ApiError;
use crate::state::AppState;

/// Request body for unconstrained analysis
#[derive(Debug, Deserialize)]
pub struct UnconstrainedAnalysisRequest {
    /// The question to analyze
    pub question: String,
    /// Optional additional search queries to run
    pub search_queries: Option<Vec<String>>,
}

/// A single factual claim from the unconstrained analysis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnconstrainedClaim {
    pub claim: String,
    pub confidence: f64,
    pub source_type: String,
    #[serde(default)]
    pub method_name: Option<String>,
}

/// Response from unconstrained analysis
#[derive(Debug, Serialize)]
pub struct UnconstrainedAnalysisResponse {
    pub question: String,
    pub claims: Vec<UnconstrainedClaim>,
    pub model_used: String,
    pub raw_response_length: usize,
}

#[cfg(feature = "genai")]
fn build_prompt(question: &str) -> String {
    format!(
        r#"Answer this question using your full knowledge:

Question: {question}

Structure your answer as a JSON array of factual claims. Each claim should be an object with:
- "claim": a single factual statement (one sentence)
- "confidence": your confidence in this claim (0.0 to 1.0)
- "source_type": one of "textbook", "paper", "general_knowledge", "web"
- "method_name": if the claim mentions a specific method or technique, name it (null otherwise)

Return ONLY the JSON array, no other text. Include 5-20 claims covering the most important facts."#
    )
}

/// POST /api/v1/analyze/unconstrained
///
/// Run an unconstrained analysis using an LLM provider. Returns structured
/// factual claims that can be compared with graph-constrained analysis for gap
/// detection.
///
/// Requires the `genai` feature; returns 501 otherwise.
#[cfg(feature = "genai")]
pub async fn unconstrained_analysis(
    State(_state): State<AppState>,
    Json(request): Json<UnconstrainedAnalysisRequest>,
) -> Result<(StatusCode, Json<UnconstrainedAnalysisResponse>), ApiError> {
    use epigraph_cli::enrichment::llm_client::{create_llm_client, LlmError};

    let question = request.question.trim().to_string();
    if question.is_empty() {
        return Err(ApiError::ValidationError {
            field: "question".to_string(),
            reason: "Question must not be empty".to_string(),
        });
    }

    let provider = std::env::var("EPIGRAPH_LLM_PROVIDER").unwrap_or_else(|_| "anthropic".into());
    let client = create_llm_client(&provider).map_err(|e| ApiError::ServiceUnavailable {
        service: format!("LLM client init failed for provider '{provider}': {e}"),
    })?;
    let model_used = client.model_name().to_string();

    let prompt = build_prompt(&question);

    let raw_value = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        client.complete_json(&prompt),
    )
    .await
    .map_err(|_| ApiError::ServiceUnavailable {
        service: "LLM request timed out after 120 seconds".into(),
    })?
    .map_err(|e: LlmError| ApiError::ServiceUnavailable {
        service: format!("LLM request failed: {e}"),
    })?;

    let raw_response = match raw_value {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    };
    let raw_len = raw_response.len();

    let claims = parse_claims_from_response(&raw_response);

    Ok((
        StatusCode::OK,
        Json(UnconstrainedAnalysisResponse {
            question,
            claims,
            model_used,
            raw_response_length: raw_len,
        }),
    ))
}

/// Stub when the `genai` feature is disabled.
#[cfg(not(feature = "genai"))]
pub async fn unconstrained_analysis(
    State(_state): State<AppState>,
    Json(_request): Json<UnconstrainedAnalysisRequest>,
) -> Result<(StatusCode, Json<UnconstrainedAnalysisResponse>), ApiError> {
    Err(ApiError::ServiceUnavailable {
        service:
            "Unconstrained analysis requires the 'genai' feature; rebuild with --features genai"
                .into(),
    })
}

/// Parse structured claims from the LLM response.
/// Tries JSON array parsing first, then falls back to a single-claim wrap.
#[cfg(any(feature = "genai", test))]
fn parse_claims_from_response(response: &str) -> Vec<UnconstrainedClaim> {
    let trimmed = response.trim();

    if let Ok(claims) = serde_json::from_str::<Vec<UnconstrainedClaim>>(trimmed) {
        return claims;
    }

    if let Some(start) = trimmed.find('[') {
        if let Some(end) = trimmed.rfind(']') {
            let json_slice = &trimmed[start..=end];
            if let Ok(claims) = serde_json::from_str::<Vec<UnconstrainedClaim>>(json_slice) {
                return claims;
            }
        }
    }

    if !trimmed.is_empty() {
        vec![UnconstrainedClaim {
            claim: trimmed.chars().take(500).collect(),
            confidence: 0.5,
            source_type: "general_knowledge".into(),
            method_name: None,
        }]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_claims_valid_json() {
        let json = r#"[
            {"claim": "Water boils at 100°C", "confidence": 0.99, "source_type": "textbook", "method_name": null},
            {"claim": "Ice melts at 0°C", "confidence": 0.99, "source_type": "textbook", "method_name": null}
        ]"#;
        let claims = parse_claims_from_response(json);
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].source_type, "textbook");
    }

    #[test]
    fn test_parse_claims_json_in_markdown() {
        let response = "Here are the claims:\n```json\n[{\"claim\": \"test\", \"confidence\": 0.8, \"source_type\": \"web\"}]\n```";
        let claims = parse_claims_from_response(response);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].claim, "test");
    }

    #[test]
    fn test_parse_claims_fallback() {
        let response = "This is not JSON at all";
        let claims = parse_claims_from_response(response);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].source_type, "general_knowledge");
    }

    #[test]
    fn test_empty_response() {
        let claims = parse_claims_from_response("");
        assert!(claims.is_empty());
    }

    #[test]
    fn test_empty_question_validation() {
        let req = UnconstrainedAnalysisRequest {
            question: "   ".to_string(),
            search_queries: None,
        };
        assert!(req.question.trim().is_empty());
    }
}
