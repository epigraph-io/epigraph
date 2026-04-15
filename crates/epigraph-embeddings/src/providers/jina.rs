//! Jina AI multimodal embedding provider
//!
//! Implements both `EmbeddingService` and `MultimodalEmbeddingService` using
//! Jina's Embeddings v4 API, which supports text and image inputs in the same
//! vector space.
//!
//! # Security Properties
//!
//! 1. **Request Timeout**: All API calls have a timeout to prevent `DoS`
//! 2. **Connection Timeout**: Connection establishment is time-bounded
//! 3. **API Key Safety**: API key is never logged or exposed in error messages
//! 4. **Rate Limiting**: Respects API quotas to prevent throttling

use async_trait::async_trait;
use std::sync::Mutex;
#[cfg(feature = "jina")]
use std::time::Duration;
use uuid::Uuid;

use crate::cache::EmbeddingCache;
use crate::config::EmbeddingConfig;
use crate::errors::EmbeddingError;
use crate::normalizer::Normalizer;
use crate::rate_limiter::RateLimiter;
use crate::service::{
    EmbeddingService, MultimodalEmbeddingService, MultimodalInput, SimilarClaim, TokenUsage,
};
use crate::tokenizer::Tokenizer;

// ============================================================================
// Security Constants
// ============================================================================

/// Request timeout in seconds for Jina API calls.
#[cfg(feature = "jina")]
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Connection timeout in seconds.
#[cfg(feature = "jina")]
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum number of inputs in a single batch request.
const MAX_BATCH_SIZE: usize = 2048;

/// Default Jina API base URL
const DEFAULT_API_BASE: &str = "https://api.jina.ai";

/// Jina AI multimodal embedding provider
///
/// Supports both text and image embedding via Jina Embeddings v4.
/// Text and image embeddings share the same vector space, enabling
/// cross-modal similarity search.
pub struct JinaProvider {
    /// Configuration
    config: EmbeddingConfig,
    /// API key for authentication
    #[allow(dead_code)]
    api_key: String,
    /// HTTP client
    #[cfg(feature = "jina")]
    client: reqwest::Client,
    /// Tokenizer for validation and counting
    tokenizer: Tokenizer,
    /// Cache for embeddings
    cache: EmbeddingCache,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Token usage tracking
    token_usage: Mutex<TokenUsage>,
}

#[allow(dead_code)]
impl JinaProvider {
    /// Create a new Jina provider
    ///
    /// # Arguments
    /// * `config` - Embedding configuration (should use `ProviderConfig::Jina`)
    /// * `api_key` - Jina API key
    ///
    /// # Returns
    /// * `Ok(JinaProvider)` - Successfully created provider
    /// * `Err(EmbeddingError)` - If configuration is invalid or feature not enabled
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: EmbeddingConfig, api_key: String) -> Result<Self, EmbeddingError> {
        #[cfg(not(feature = "jina"))]
        {
            let _ = (&config, &api_key);
            Err(EmbeddingError::ConfigError(
                "Jina feature not enabled. Compile with --features jina".to_string(),
            ))
        }

        #[cfg(feature = "jina")]
        {
            let tokenizer = Tokenizer::new(config.max_tokens);
            let cache = if config.cache_enabled {
                EmbeddingCache::new(config.cache_ttl_secs, 10_000)
            } else {
                EmbeddingCache::new(0, 0)
            };
            let rate_limiter = RateLimiter::new(&config.rate_limit);

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
                .build()
                .map_err(|e| {
                    EmbeddingError::ConfigError(format!("Failed to build HTTP client: {}", e))
                })?;

            Ok(Self {
                config,
                api_key,
                client,
                tokenizer,
                cache,
                rate_limiter,
                token_usage: Mutex::new(TokenUsage::default()),
            })
        }
    }

    /// Get the model name from config
    #[allow(clippy::missing_const_for_fn)]
    fn model_name(&self) -> &str {
        match &self.config.provider {
            crate::config::ProviderConfig::Jina { model, .. } => model.as_str(),
            _ => "jina-embeddings-v4",
        }
    }

    /// Get the task adapter from config
    #[allow(clippy::missing_const_for_fn)]
    fn task(&self) -> Option<&str> {
        match &self.config.provider {
            crate::config::ProviderConfig::Jina { task, .. } => task.as_deref(),
            _ => Some("retrieval.passage"),
        }
    }

    /// Get the API base URL
    #[allow(clippy::missing_const_for_fn)]
    fn api_base(&self) -> &str {
        match &self.config.provider {
            crate::config::ProviderConfig::Jina {
                api_base_url: Some(url),
                ..
            } => url.as_str(),
            _ => DEFAULT_API_BASE,
        }
    }

    /// Build a JSON request body for text inputs
    fn build_text_request_body(&self, texts: &[&str]) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": self.model_name(),
            "dimensions": self.config.dimension,
            "normalized": self.config.normalize,
            "embedding_type": "float",
            "input": texts,
        });

        if let Some(task) = self.task() {
            body["task"] = serde_json::Value::String(task.to_string());
        }

        body
    }

    /// Build a JSON request body for image inputs
    fn build_image_request_body(&self, image_base64: &str) -> serde_json::Value {
        // Wrap in data URI if not already
        let image_uri = if image_base64.starts_with("data:") {
            image_base64.to_string()
        } else {
            format!("data:image/png;base64,{image_base64}")
        };

        let mut body = serde_json::json!({
            "model": self.model_name(),
            "dimensions": self.config.dimension,
            "normalized": self.config.normalize,
            "embedding_type": "float",
            "input": [{"image": image_uri}],
        });

        if let Some(task) = self.task() {
            body["task"] = serde_json::Value::String(task.to_string());
        }

        body
    }

    /// Build a JSON request body for mixed inputs
    fn build_multimodal_request_body(&self, inputs: &[MultimodalInput<'_>]) -> serde_json::Value {
        let input_values: Vec<serde_json::Value> = inputs
            .iter()
            .map(|input| match input {
                MultimodalInput::Text(text) => serde_json::Value::String(text.to_string()),
                MultimodalInput::Image(base64) => {
                    let uri = if base64.starts_with("data:") {
                        base64.to_string()
                    } else {
                        format!("data:image/png;base64,{base64}")
                    };
                    serde_json::json!({"image": uri})
                }
            })
            .collect();

        let mut body = serde_json::json!({
            "model": self.model_name(),
            "dimensions": self.config.dimension,
            "normalized": self.config.normalize,
            "embedding_type": "float",
            "input": input_values,
        });

        if let Some(task) = self.task() {
            body["task"] = serde_json::Value::String(task.to_string());
        }

        body
    }

    /// Track token usage
    fn track_tokens(&self, tokens: usize) {
        let mut usage = self.token_usage.lock().unwrap();
        usage.add(&TokenUsage::new(tokens));
    }

    /// Make API call to Jina (stub without feature)
    #[cfg(not(feature = "jina"))]
    #[allow(clippy::unused_async)]
    async fn call_api(&self, _body: serde_json::Value) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "Jina feature not enabled. Compile with --features jina".to_string(),
        ))
    }

    /// Make API call to Jina with retry on 429 rate limit
    #[cfg(feature = "jina")]
    async fn call_api(&self, body: serde_json::Value) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct JinaResponse {
            data: Vec<JinaEmbeddingData>,
            usage: JinaUsage,
        }

        #[derive(Deserialize)]
        struct JinaEmbeddingData {
            embedding: Vec<f32>,
            index: usize,
        }

        #[derive(Deserialize)]
        struct JinaUsage {
            total_tokens: usize,
        }

        let url = format!("{}/v1/embeddings", self.api_base());
        let max_retries = 3u32;

        for attempt in 0..=max_retries {
            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await?;

            if response.status().as_u16() == 429 {
                if attempt < max_retries {
                    let delay = Duration::from_secs(2u64.pow(attempt) + 1);
                    tracing::debug!(attempt, delay_secs = ?delay, "Jina 429, backing off");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Err(EmbeddingError::RateLimitExceeded {
                    retry_after_secs: 10,
                });
            }

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response.text().await.unwrap_or_default();
                return Err(EmbeddingError::ApiError {
                    message: error_text,
                    status_code: Some(status),
                });
            }

            let jina_response: JinaResponse = response.json().await?;
            self.track_tokens(jina_response.usage.total_tokens);

            // Sort by index to maintain order
            let mut embeddings: Vec<_> = jina_response.data.into_iter().collect();
            embeddings.sort_by_key(|e| e.index);

            return Ok(embeddings.into_iter().map(|e| e.embedding).collect());
        }

        Err(EmbeddingError::RateLimitExceeded {
            retry_after_secs: 10,
        })
    }
}

#[async_trait]
impl EmbeddingService for JinaProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        let token_count = self.tokenizer.validate(text)?;

        // Check cache
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(text) {
                return Ok(cached);
            }
        }

        self.rate_limiter.wait_if_needed(token_count as u32).await;

        let body = self.build_text_request_body(&[text]);
        let embeddings = self.call_api(body).await?;
        let mut embedding =
            embeddings
                .into_iter()
                .next()
                .ok_or_else(|| EmbeddingError::ApiError {
                    message: "No embedding returned".to_string(),
                    status_code: None,
                })?;

        if self.config.normalize {
            Normalizer::normalize_in_place(&mut embedding)?;
        }

        self.rate_limiter.record(token_count as u32);

        if self.config.cache_enabled {
            let _ = self.cache.put(text, embedding.clone());
        }

        Ok(embedding)
    }

    async fn generate_query(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        let token_count = self.tokenizer.validate(text)?;

        // Check cache (query embeddings use a prefix to avoid collisions with passage embeddings)
        let cache_key = format!("query:{text}");
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        self.rate_limiter.wait_if_needed(token_count as u32).await;

        // Build request with retrieval.query task adapter
        let mut body = serde_json::json!({
            "model": self.model_name(),
            "dimensions": self.config.dimension,
            "normalized": self.config.normalize,
            "embedding_type": "float",
            "task": "retrieval.query",
            "input": [text],
        });

        // Ensure task is always retrieval.query regardless of config
        body["task"] = serde_json::Value::String("retrieval.query".to_string());

        let embeddings = self.call_api(body).await?;
        let mut embedding =
            embeddings
                .into_iter()
                .next()
                .ok_or_else(|| EmbeddingError::ApiError {
                    message: "No embedding returned".to_string(),
                    status_code: None,
                })?;

        if self.config.normalize {
            Normalizer::normalize_in_place(&mut embedding)?;
        }

        self.rate_limiter.record(token_count as u32);

        if self.config.cache_enabled {
            let _ = self.cache.put(&cache_key, embedding.clone());
        }

        Ok(embedding)
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.len() > MAX_BATCH_SIZE {
            return Err(EmbeddingError::ConfigError(format!(
                "Batch size too large: {} texts, maximum is {}",
                texts.len(),
                MAX_BATCH_SIZE
            )));
        }

        let mut total_tokens = 0;
        for text in texts {
            if text.is_empty() {
                return Err(EmbeddingError::EmptyText);
            }
            total_tokens += self.tokenizer.validate(text)?;
        }

        self.rate_limiter.wait_if_needed(total_tokens as u32).await;

        let body = self.build_text_request_body(texts);
        let mut embeddings = self.call_api(body).await?;

        if self.config.normalize {
            for emb in &mut embeddings {
                Normalizer::normalize_in_place(emb)?;
            }
        }

        self.rate_limiter.record(total_tokens as u32);

        Ok(embeddings)
    }

    async fn store(&self, _claim_id: Uuid, _embedding: &[f32]) -> Result<(), EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "JinaProvider doesn't support storage. Use EmbeddingRepository.".to_string(),
        ))
    }

    async fn get(&self, _claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "JinaProvider doesn't support retrieval. Use EmbeddingRepository.".to_string(),
        ))
    }

    async fn similar(
        &self,
        _embedding: &[f32],
        _k: usize,
        _min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "JinaProvider doesn't support similarity search. Use EmbeddingRepository.".to_string(),
        ))
    }

    fn dimension(&self) -> usize {
        self.config.dimension
    }

    fn token_usage(&self) -> TokenUsage {
        self.token_usage.lock().unwrap().clone()
    }

    fn reset_token_usage(&self) {
        let mut usage = self.token_usage.lock().unwrap();
        *usage = TokenUsage::default();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        #[cfg(feature = "jina")]
        {
            self.generate("health check").await?;
            Ok(())
        }
        #[cfg(not(feature = "jina"))]
        {
            Err(EmbeddingError::ProviderUnavailable {
                provider: "Jina (feature not enabled)".to_string(),
            })
        }
    }

    fn supports_multimodal(&self) -> bool {
        true
    }

    fn as_multimodal(&self) -> Option<&dyn MultimodalEmbeddingService> {
        Some(self)
    }
}

#[async_trait]
impl MultimodalEmbeddingService for JinaProvider {
    async fn generate_from_image(&self, image_base64: &str) -> Result<Vec<f32>, EmbeddingError> {
        if image_base64.is_empty() {
            return Err(EmbeddingError::InvalidImageData {
                reason: "Empty image data".to_string(),
            });
        }

        let body = self.build_image_request_body(image_base64);
        let embeddings = self.call_api(body).await?;

        let mut embedding =
            embeddings
                .into_iter()
                .next()
                .ok_or_else(|| EmbeddingError::ApiError {
                    message: "No embedding returned for image".to_string(),
                    status_code: None,
                })?;

        if self.config.normalize {
            Normalizer::normalize_in_place(&mut embedding)?;
        }

        Ok(embedding)
    }

    async fn batch_generate_multimodal(
        &self,
        inputs: &[MultimodalInput<'_>],
    ) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if inputs.is_empty() {
            return Ok(vec![]);
        }

        if inputs.len() > MAX_BATCH_SIZE {
            return Err(EmbeddingError::ConfigError(format!(
                "Batch size too large: {} inputs, maximum is {}",
                inputs.len(),
                MAX_BATCH_SIZE
            )));
        }

        let body = self.build_multimodal_request_body(inputs);
        let mut embeddings = self.call_api(body).await?;

        if self.config.normalize {
            for emb in &mut embeddings {
                Normalizer::normalize_in_place(emb)?;
            }
        }

        Ok(embeddings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jina_provider_creation_without_feature() {
        let config = EmbeddingConfig::jina(1536);
        let result = JinaProvider::new(config, "test-key".to_string());

        // Without the "jina" feature, creation should fail gracefully
        #[cfg(not(feature = "jina"))]
        assert!(result.is_err());

        // With the "jina" feature, creation should succeed
        #[cfg(feature = "jina")]
        assert!(result.is_ok());
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_provider_dimension() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();
        assert_eq!(provider.dimension(), 1536);
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_provider_supports_multimodal() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();
        assert!(provider.supports_multimodal());
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_provider_as_multimodal_returns_some() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();
        assert!(
            provider.as_multimodal().is_some(),
            "JinaProvider should return Some from as_multimodal()"
        );
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_text_request_format() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();

        let body = provider.build_text_request_body(&["hello world"]);

        assert_eq!(body["model"], "jina-embeddings-v4");
        assert_eq!(body["dimensions"], 1536);
        assert_eq!(body["normalized"], true);
        assert_eq!(body["embedding_type"], "float");
        assert_eq!(body["task"], "retrieval.passage");
        assert_eq!(body["input"][0], "hello world");
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_image_request_format() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();

        let body = provider.build_image_request_body("iVBORw0KGgoAAAANS");

        assert_eq!(body["model"], "jina-embeddings-v4");
        assert_eq!(body["dimensions"], 1536);

        let image_input = &body["input"][0]["image"];
        assert_eq!(
            image_input.as_str().unwrap(),
            "data:image/png;base64,iVBORw0KGgoAAAANS"
        );
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_image_request_preserves_data_uri() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();

        let body = provider.build_image_request_body("data:image/jpeg;base64,/9j/4AAQ");

        let image_input = &body["input"][0]["image"];
        assert_eq!(
            image_input.as_str().unwrap(),
            "data:image/jpeg;base64,/9j/4AAQ"
        );
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_dimension_parameter() {
        let config = EmbeddingConfig::jina(768);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();

        let body = provider.build_text_request_body(&["test"]);
        assert_eq!(body["dimensions"], 768);
    }

    #[cfg(feature = "jina")]
    #[test]
    fn test_jina_multimodal_request_format() {
        let config = EmbeddingConfig::jina(1536);
        let provider = JinaProvider::new(config, "test-key".to_string()).unwrap();

        let inputs = vec![
            MultimodalInput::Text("some text"),
            MultimodalInput::Image("iVBORw0KGgoAAAANS"),
        ];

        let body = provider.build_multimodal_request_body(&inputs);

        assert_eq!(body["input"][0], "some text");
        assert_eq!(
            body["input"][1]["image"].as_str().unwrap(),
            "data:image/png;base64,iVBORw0KGgoAAAANS"
        );
    }
}
