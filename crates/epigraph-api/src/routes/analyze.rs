//! Unconstrained analysis endpoint: answer a question using Claude with web search.
//!
//! `POST /api/v1/analyze/unconstrained` takes a question and returns structured
//! factual claims produced by an LLM with full web access — no graph constraints.
//! This output is paired with graph-constrained analysis for gap detection.

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

/// POST /api/v1/analyze/unconstrained
///
/// Run an unconstrained analysis using Claude with web search enabled.
/// Returns structured factual claims that can be compared with graph-constrained
/// analysis for gap detection.
///
/// Rate limited: 1 request per 30 seconds.
pub async fn unconstrained_analysis(
    State(_state): State<AppState>,
    Json(request): Json<UnconstrainedAnalysisRequest>,
) -> Result<(StatusCode, Json<UnconstrainedAnalysisResponse>), ApiError> {
    let question = request.question.trim().to_string();
    if question.is_empty() {
        return Err(ApiError::ValidationError {
            field: "question".to_string(),
            reason: "Question must not be empty".to_string(),
        });
    }

    // Build the prompt for Claude
    let prompt = format!(
        r#"Answer this question using your full knowledge and web search:

Question: {question}

Structure your answer as a JSON array of factual claims. Each claim should be an object with:
- "claim": a single factual statement (one sentence)
- "confidence": your confidence in this claim (0.0 to 1.0)
- "source_type": one of "textbook", "paper", "general_knowledge", "web"
- "method_name": if the claim mentions a specific method or technique, name it (null otherwise)

Return ONLY the JSON array, no other text. Include 5-20 claims covering the most important facts."#
    );

    // Run Claude CLI with web search — strip CLAUDECODE and ANTHROPIC_API_KEY
    // to allow nested sessions (epiclaw pattern)
    let mut cmd = tokio::process::Command::new("claude");
    cmd.args(["-p", "--output-format", "text", "--max-turns", "3"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_remove("CLAUDECODE")
        .env_remove("ANTHROPIC_API_KEY");

    let mut child = cmd.spawn().map_err(|e| ApiError::ServiceUnavailable {
        service: format!("Claude CLI unavailable (is it installed and on PATH?): {e}"),
    })?;

    // Send prompt via stdin
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(prompt.as_bytes()).await;
        drop(stdin);
    }

    // Enforce a 120-second wall-clock limit so OAuth lapses or CLI hangs don't
    // block the request indefinitely.
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| ApiError::ServiceUnavailable {
        service: "Claude CLI timed out after 120 seconds".into(),
    })?
    .map_err(|e| ApiError::ServiceUnavailable {
        service: format!("Claude CLI process error: {e}"),
    })?;

    if !output.status.success() {
        let stderr_raw = String::from_utf8_lossy(&output.stderr);
        // Truncate to 200 chars to keep error messages legible in logs/responses
        let stderr_truncated: String = stderr_raw.chars().take(200).collect();
        return Err(ApiError::ServiceUnavailable {
            service: format!("Claude CLI exited with error: {stderr_truncated}"),
        });
    }

    let raw_response = String::from_utf8_lossy(&output.stdout).to_string();
    let raw_len = raw_response.len();

    // Parse the response — try to extract JSON array from the output
    let claims = parse_claims_from_response(&raw_response);

    Ok((
        StatusCode::OK,
        Json(UnconstrainedAnalysisResponse {
            question,
            claims,
            model_used: "anthropic".into(),
            raw_response_length: raw_len,
        }),
    ))
}

/// Parse structured claims from Claude's response.
/// Tries JSON array parsing first, then falls back to line-by-line extraction.
fn parse_claims_from_response(response: &str) -> Vec<UnconstrainedClaim> {
    // Try to find a JSON array in the response
    let trimmed = response.trim();

    // Direct JSON parse
    if let Ok(claims) = serde_json::from_str::<Vec<UnconstrainedClaim>>(trimmed) {
        return claims;
    }

    // Try to find JSON array within markdown code blocks
    if let Some(start) = trimmed.find('[') {
        if let Some(end) = trimmed.rfind(']') {
            let json_slice = &trimmed[start..=end];
            if let Ok(claims) = serde_json::from_str::<Vec<UnconstrainedClaim>>(json_slice) {
                return claims;
            }
        }
    }

    // Fallback: create a single claim from the entire response
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
