//! LLM client abstraction for enrichment
//!
//! Provides a trait-based abstraction over LLM APIs so the enrichment
//! pipeline can swap between mock, Anthropic, and other providers.

use async_trait::async_trait;
use std::fmt;
use thiserror::Error;

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Error, Debug)]
pub enum LlmError {
    #[error("LLM API request failed: {message}")]
    RequestFailed { message: String },

    #[error("LLM returned malformed JSON: {message}")]
    MalformedResponse { message: String },

    #[error("LLM rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("LLM API key not configured for provider: {provider}")]
    MissingApiKey { provider: String },
}

// =============================================================================
// LLM CLIENT TRAIT
// =============================================================================

/// Abstraction over LLM providers for structured JSON completion
#[async_trait]
pub trait LlmClient: Send + Sync + fmt::Debug {
    /// Send a prompt and get back a parsed JSON value
    async fn complete_json(&self, prompt: &str) -> Result<serde_json::Value, LlmError>;

    /// Name of the model being used
    fn model_name(&self) -> &str;
}

// =============================================================================
// MOCK CLIENT (for tests)
// =============================================================================

/// Mock LLM client that returns pre-configured JSON responses
#[derive(Debug)]
pub struct MockLlmClient {
    /// JSON responses to return, consumed in order. If empty, returns empty array.
    responses: std::sync::Mutex<Vec<serde_json::Value>>,
    /// Whether to simulate a rate limit error on the next call
    simulate_rate_limit: std::sync::atomic::AtomicBool,
    /// Whether to simulate malformed JSON on the next call
    simulate_malformed: std::sync::atomic::AtomicBool,
}

impl Default for MockLlmClient {
    fn default() -> Self {
        Self::new()
    }
}

impl MockLlmClient {
    /// Create a mock client with no pre-configured responses (returns empty arrays)
    pub fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(Vec::new()),
            simulate_rate_limit: std::sync::atomic::AtomicBool::new(false),
            simulate_malformed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a mock client with a sequence of JSON responses
    pub fn with_responses(responses: Vec<serde_json::Value>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses),
            simulate_rate_limit: std::sync::atomic::AtomicBool::new(false),
            simulate_malformed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Configure the mock to return a rate limit error on next call
    pub fn set_rate_limited(&self, limited: bool) {
        self.simulate_rate_limit
            .store(limited, std::sync::atomic::Ordering::SeqCst);
    }

    /// Configure the mock to return malformed JSON on next call
    pub fn set_malformed(&self, malformed: bool) {
        self.simulate_malformed
            .store(malformed, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl LlmClient for MockLlmClient {
    async fn complete_json(&self, _prompt: &str) -> Result<serde_json::Value, LlmError> {
        // Check for simulated errors
        if self
            .simulate_rate_limit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(LlmError::RateLimited {
                retry_after_secs: 60,
            });
        }

        if self
            .simulate_malformed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(LlmError::MalformedResponse {
                message: "Simulated malformed response".to_string(),
            });
        }

        // Get next response or default to empty array
        let value = {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                serde_json::json!([])
            } else {
                responses.remove(0)
            }
        };

        Ok(value)
    }

    fn model_name(&self) -> &str {
        "mock"
    }
}

// =============================================================================
// ANTHROPIC CLIENT
// =============================================================================

/// Authentication method for Anthropic API
#[derive(Debug, Clone)]
enum AuthMethod {
    /// Pay-per-token API key — uses `x-api-key` header
    ApiKey(String),
    /// OAuth token (Max plan subscription) — uses `Authorization: Bearer` header
    OAuthToken(String),
}

/// Anthropic Claude API client for structured JSON completion
#[derive(Debug)]
pub struct AnthropicClient {
    auth: AuthMethod,
    model: String,
    http_client: reqwest::Client,
}

impl AnthropicClient {
    /// Create a new Anthropic client with an API key
    ///
    /// # Errors
    /// Returns `LlmError::MissingApiKey` if the API key is empty.
    pub fn new(api_key: String, model: Option<String>) -> Result<Self, LlmError> {
        if api_key.is_empty() {
            return Err(LlmError::MissingApiKey {
                provider: "anthropic".to_string(),
            });
        }

        Ok(Self {
            auth: AuthMethod::ApiKey(api_key),
            model: model.unwrap_or_else(|| {
                std::env::var("ENRICHMENT_MODEL")
                    .unwrap_or_else(|_| "claude-sonnet-4-5-20250929".to_string())
            }),
            http_client: reqwest::Client::new(),
        })
    }

    /// Create a new Anthropic client with an OAuth token (Max plan subscription)
    ///
    /// # Errors
    /// Returns `LlmError::MissingApiKey` if the token is empty.
    pub fn with_oauth(token: String, model: Option<String>) -> Result<Self, LlmError> {
        if token.is_empty() {
            return Err(LlmError::MissingApiKey {
                provider: "anthropic (oauth)".to_string(),
            });
        }

        Ok(Self {
            auth: AuthMethod::OAuthToken(token),
            model: model.unwrap_or_else(|| {
                std::env::var("ENRICHMENT_MODEL")
                    .unwrap_or_else(|_| "claude-sonnet-4-5-20250929".to_string())
            }),
            http_client: reqwest::Client::new(),
        })
    }

    /// Returns `true` if this client is using OAuth authentication
    pub fn is_oauth(&self) -> bool {
        matches!(self.auth, AuthMethod::OAuthToken(_))
    }

    /// Build the request body for the Anthropic Messages API
    fn build_request_body(&self, prompt: &str) -> serde_json::Value {
        serde_json::json!({
            "model": self.model,
            "max_tokens": 4096,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        })
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn complete_json(&self, prompt: &str) -> Result<serde_json::Value, LlmError> {
        let body = self.build_request_body(prompt);

        let request = self
            .http_client
            .post("https://api.anthropic.com/v1/messages")
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json");

        let request = match &self.auth {
            AuthMethod::ApiKey(key) => request.header("x-api-key", key),
            AuthMethod::OAuthToken(token) => {
                request.header("Authorization", format!("Bearer {token}"))
            }
        };

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::RequestFailed {
                message: format!("HTTP request failed: {e}"),
            })?;

        let status = response.status();

        if status.as_u16() == 429 {
            return Err(LlmError::RateLimited {
                retry_after_secs: 60,
            });
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(LlmError::RequestFailed {
                message: format!("API returned HTTP {status}: {body}"),
            });
        }

        // Parse the Anthropic response format
        let resp_json: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| LlmError::MalformedResponse {
                    message: format!("Failed to parse API response: {e}"),
                })?;

        // Extract text content from the response
        let text = resp_json["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .ok_or_else(|| LlmError::MalformedResponse {
                message: "No text content in Anthropic response".to_string(),
            })?;

        // Try to extract JSON from the text (may be wrapped in markdown code blocks)
        let json_str = extract_json_from_text(text);

        serde_json::from_str(&json_str).map_err(|e| LlmError::MalformedResponse {
            message: format!("Failed to parse JSON from LLM response: {e}. Raw text: {json_str}"),
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Extract JSON from text that may contain markdown code blocks
fn extract_json_from_text(text: &str) -> String {
    let trimmed = text.trim();

    // Try to find JSON inside ```json ... ``` blocks
    if let Some(start) = trimmed.find("```json") {
        let after_marker = &trimmed[start + 7..];
        if let Some(end) = after_marker.find("```") {
            return after_marker[..end].trim().to_string();
        }
    }

    // Try to find JSON inside ``` ... ``` blocks
    if let Some(start) = trimmed.find("```") {
        let after_marker = &trimmed[start + 3..];
        if let Some(end) = after_marker.find("```") {
            let content = after_marker[..end].trim();
            // Only use if it looks like JSON
            if content.starts_with('[') || content.starts_with('{') {
                return content.to_string();
            }
        }
    }

    // Return the raw text (may already be JSON)
    trimmed.to_string()
}

// =============================================================================
// FACTORY
// =============================================================================

/// Create an LLM client based on the provider configuration.
///
/// Providers:
/// - `"anthropic"` — direct HTTP to `api.anthropic.com`. Prefers `CLAUDE_CODE_OAUTH_TOKEN`
///   (Max plan, `Authorization: Bearer`) and falls back to `ANTHROPIC_API_KEY` (`x-api-key`).
/// - `"mock"` — returns pre-configured or empty responses (for tests).
pub fn create_llm_client(provider: &str) -> Result<Box<dyn LlmClient>, LlmError> {
    match provider {
        "mock" => Ok(Box::new(MockLlmClient::new())),
        "anthropic" => {
            let model = std::env::var("ENRICHMENT_MODEL").ok();
            // Prefer OAuth token (Max plan — uses subscription, not pay-per-token)
            if let Ok(oauth_token) = std::env::var("CLAUDE_CODE_OAUTH_TOKEN") {
                if !oauth_token.is_empty() {
                    return Ok(Box::new(AnthropicClient::with_oauth(oauth_token, model)?));
                }
            }
            // Fall back to API key
            let api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
            Ok(Box::new(AnthropicClient::new(api_key, model)?))
        }
        other => Err(LlmError::RequestFailed {
            message: format!(
                "Unknown LLM provider: {other}. Use 'anthropic' or 'mock'."
            ),
        }),
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_llm_client_returns_valid_json() {
        let response = serde_json::json!([
            {
                "source_index": 0,
                "target_index": 1,
                "relationship": "supports",
                "strength": 0.8,
                "rationale": "Commit 1 provides foundation for Commit 2"
            }
        ]);

        let client = MockLlmClient::with_responses(vec![response]);
        let result = client.complete_json("test prompt").await.unwrap();
        let arr = result.as_array().unwrap();

        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["relationship"], "supports");
        assert_eq!(arr[0]["strength"], 0.8);
    }

    #[tokio::test]
    async fn test_mock_llm_client_empty_returns_empty_array() {
        let client = MockLlmClient::new();
        let result = client.complete_json("test").await.unwrap();
        assert!(result.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_llm_client_handles_malformed_response() {
        let client = MockLlmClient::new();
        client.set_malformed(true);

        let result = client.complete_json("test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, LlmError::MalformedResponse { .. }));
    }

    #[tokio::test]
    async fn test_llm_client_respects_rate_limit() {
        let client = MockLlmClient::new();
        client.set_rate_limited(true);

        let result = client.complete_json("test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            LlmError::RateLimited {
                retry_after_secs: 60
            }
        ));
    }

    #[tokio::test]
    async fn test_mock_consumes_responses_in_order() {
        let responses = vec![
            serde_json::json!([{"id": 1}]),
            serde_json::json!([{"id": 2}]),
        ];

        let client = MockLlmClient::with_responses(responses);

        let r1 = client.complete_json("first").await.unwrap();
        assert_eq!(r1.as_array().unwrap()[0]["id"], 1);

        let r2 = client.complete_json("second").await.unwrap();
        assert_eq!(r2.as_array().unwrap()[0]["id"], 2);

        // No more responses → empty array
        let r3 = client.complete_json("third").await.unwrap();
        assert!(r3.as_array().unwrap().is_empty());
    }

    #[test]
    fn test_anthropic_client_builds_correct_request() {
        let client = AnthropicClient::new("test-key".to_string(), None).unwrap();
        let body = client.build_request_body("Hello world");

        assert_eq!(body["model"], "claude-sonnet-4-5-20250929");
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "Hello world");
    }

    #[test]
    fn test_anthropic_client_custom_model() {
        let client =
            AnthropicClient::new("test-key".to_string(), Some("claude-opus-4-6".to_string()))
                .unwrap();
        assert_eq!(client.model_name(), "claude-opus-4-6");
    }

    #[test]
    fn test_anthropic_client_rejects_empty_key() {
        let result = AnthropicClient::new(String::new(), None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LlmError::MissingApiKey { .. }
        ));
    }

    #[test]
    fn test_extract_json_from_text_plain() {
        let text = r#"[{"source_index": 0, "target_index": 1}]"#;
        let result = extract_json_from_text(text);
        assert_eq!(result, text);
    }

    #[test]
    fn test_extract_json_from_text_markdown() {
        let text = "Here are the relationships:\n```json\n[{\"source_index\": 0}]\n```\nDone.";
        let result = extract_json_from_text(text);
        assert_eq!(result, r#"[{"source_index": 0}]"#);
    }

    #[test]
    fn test_extract_json_from_text_bare_code_block() {
        let text = "```\n[{\"a\": 1}]\n```";
        let result = extract_json_from_text(text);
        assert_eq!(result, r#"[{"a": 1}]"#);
    }

    #[test]
    fn test_anthropic_client_with_oauth() {
        let client = AnthropicClient::with_oauth("sk-ant-oat01-test".to_string(), None).unwrap();
        assert!(client.is_oauth());
        assert_eq!(client.model_name(), "claude-sonnet-4-5-20250929");
    }

    #[test]
    fn test_anthropic_client_oauth_rejects_empty() {
        let result = AnthropicClient::with_oauth(String::new(), None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LlmError::MissingApiKey { .. }
        ));
    }

    #[test]
    fn test_anthropic_client_api_key_is_not_oauth() {
        let client = AnthropicClient::new("sk-ant-api03-test".to_string(), None).unwrap();
        assert!(!client.is_oauth());
    }

    #[test]
    fn test_create_llm_client_prefers_oauth() {
        // Set OAuth token, clear API key
        std::env::set_var("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-test");
        std::env::remove_var("ANTHROPIC_API_KEY");

        let client = create_llm_client("anthropic").unwrap();
        // Client should have been created (not MissingApiKey error)
        assert_eq!(client.model_name(), "claude-sonnet-4-5-20250929");

        // Clean up
        std::env::remove_var("CLAUDE_CODE_OAUTH_TOKEN");
    }

    #[test]
    fn test_create_llm_client_falls_back_to_api_key() {
        // Clear OAuth token, set API key
        std::env::remove_var("CLAUDE_CODE_OAUTH_TOKEN");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-api03-test");

        let client = create_llm_client("anthropic").unwrap();
        assert_eq!(client.model_name(), "claude-sonnet-4-5-20250929");

        // Clean up
        std::env::remove_var("ANTHROPIC_API_KEY");
    }

    #[test]
    fn test_create_llm_client_mock() {
        let client = create_llm_client("mock").unwrap();
        assert_eq!(client.model_name(), "mock");
    }

    #[test]
    fn test_create_llm_client_unknown_provider() {
        let result = create_llm_client("invalid_provider");
        assert!(result.is_err());
    }
}
