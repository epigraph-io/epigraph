//! `OpenAI` embedding provider
//!
//! Implements the `EmbeddingService` trait using `OpenAI`'s embedding API.
//! Requires the `openai` feature flag.
//!
//! # Security Properties
//!
//! 1. **Request Timeout**: All API calls have a timeout to prevent `DoS`
//! 2. **Connection Timeout**: Connection establishment is time-bounded
//! 3. **API Key Safety**: API key is never logged or exposed in error messages
//! 4. **Rate Limiting**: Respects API quotas to prevent throttling

use async_trait::async_trait;
use std::sync::Mutex;
#[cfg(feature = "openai")]
use std::time::Duration;
use uuid::Uuid;

use crate::cache::EmbeddingCache;
use crate::config::EmbeddingConfig;
use crate::errors::EmbeddingError;
use crate::normalizer::Normalizer;
use crate::rate_limiter::RateLimiter;
use crate::service::{EmbeddingService, SimilarClaim, TokenUsage};
use crate::tokenizer::Tokenizer;

// ============================================================================
// Security Constants
// ============================================================================

/// Request timeout in seconds for `OpenAI` API calls.
/// Prevents `DoS` from hanging connections or slow responses.
/// 30 seconds is sufficient for embedding generation even with batches.
#[cfg(feature = "openai")]
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Connection timeout in seconds for establishing connection to `OpenAI`.
/// Prevents waiting indefinitely for unreachable endpoints.
#[cfg(feature = "openai")]
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum number of texts in a single batch request.
/// Prevents memory exhaustion from oversized batch requests.
const MAX_BATCH_SIZE: usize = 2048;

/// `OpenAI` embedding provider
///
/// Uses the `OpenAI` API for generating embeddings.
/// Supports caching, rate limiting, and automatic retry.
pub struct OpenAiProvider {
    /// Configuration
    config: EmbeddingConfig,
    /// API key for authentication
    #[allow(dead_code)]
    api_key: String,
    /// HTTP client
    #[cfg(feature = "openai")]
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

impl OpenAiProvider {
    /// Create a new `OpenAI` provider
    ///
    /// # Arguments
    /// * `config` - Embedding configuration
    /// * `api_key` - `OpenAI` API key
    ///
    /// # Returns
    /// * `Ok(OpenAiProvider)` - Successfully created provider
    /// * `Err(EmbeddingError)` - If configuration is invalid
    ///
    /// # Security
    ///
    /// The HTTP client is configured with:
    /// - Request timeout to prevent `DoS` from slow responses
    /// - Connection timeout to prevent waiting for unreachable endpoints
    /// - API key is stored but never logged
    pub fn new(config: EmbeddingConfig, api_key: String) -> Result<Self, EmbeddingError> {
        let tokenizer = Tokenizer::new(config.max_tokens);
        let cache = if config.cache_enabled {
            EmbeddingCache::new(config.cache_ttl_secs, 10_000)
        } else {
            EmbeddingCache::new(0, 0)
        };
        let rate_limiter = RateLimiter::new(&config.rate_limit);

        // Build HTTP client with security-focused timeouts
        #[cfg(feature = "openai")]
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                EmbeddingError::ConfigError(format!("Failed to build HTTP client: {e}"))
            })?;

        Ok(Self {
            config,
            api_key,
            #[cfg(feature = "openai")]
            client,
            tokenizer,
            cache,
            rate_limiter,
            token_usage: Mutex::new(TokenUsage::default()),
        })
    }

    /// Track token usage
    #[cfg(feature = "openai")]
    fn track_tokens(&self, tokens: usize) {
        let mut usage = self.token_usage.lock().unwrap();
        usage.add(&TokenUsage::new(tokens));
    }

    /// Make API call (stub - requires openai feature)
    #[cfg(not(feature = "openai"))]
    #[allow(clippy::unused_async)]
    async fn call_api(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "OpenAI feature not enabled. Compile with --features openai".to_string(),
        ))
    }

    /// Make API call to `OpenAI`
    #[cfg(feature = "openai")]
    async fn call_api(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize)]
        struct EmbeddingRequest<'a> {
            model: &'a str,
            input: Vec<&'a str>,
        }

        #[derive(Deserialize)]
        struct EmbeddingResponse {
            data: Vec<EmbeddingData>,
            usage: ApiUsage,
        }

        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
            index: usize,
        }

        #[derive(Deserialize)]
        struct ApiUsage {
            total_tokens: usize,
        }

        let model = match &self.config.provider {
            crate::config::ProviderConfig::OpenAi { model, .. } => model.as_str(),
            _ => "text-embedding-3-small",
        };

        let request = EmbeddingRequest {
            model,
            input: texts.to_vec(),
        };

        let response = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            if status == 429 {
                return Err(EmbeddingError::RateLimitExceeded {
                    retry_after_secs: 60,
                });
            }
            let error_text = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::ApiError {
                message: error_text,
                status_code: Some(status),
            });
        }

        let embedding_response: EmbeddingResponse = response.json().await?;

        // Track token usage
        self.track_tokens(embedding_response.usage.total_tokens);

        // Sort by index to maintain order
        let mut embeddings: Vec<_> = embedding_response.data.into_iter().collect();
        embeddings.sort_by_key(|e| e.index);

        Ok(embeddings.into_iter().map(|e| e.embedding).collect())
    }
}

#[async_trait]
impl EmbeddingService for OpenAiProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        // Validate and count tokens
        let token_count = self.tokenizer.validate(text)?;

        // Check cache
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(text) {
                return Ok(cached);
            }
        }

        // Check rate limit
        self.rate_limiter.wait_if_needed(token_count as u32).await;

        // Call API
        let embeddings = self.call_api(&[text]).await?;
        let mut embedding =
            embeddings
                .into_iter()
                .next()
                .ok_or_else(|| EmbeddingError::ApiError {
                    message: "No embedding returned".to_string(),
                    status_code: None,
                })?;

        // Normalize if configured
        if self.config.normalize {
            Normalizer::normalize_in_place(&mut embedding)?;
        }

        // Record rate limit usage
        self.rate_limiter.record(token_count as u32);

        // Cache result
        if self.config.cache_enabled {
            let _ = self.cache.put(text, embedding.clone());
        }

        Ok(embedding)
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        // Validate batch size (DoS prevention)
        if texts.len() > MAX_BATCH_SIZE {
            return Err(EmbeddingError::ConfigError(format!(
                "Batch size too large: {} texts, maximum is {}",
                texts.len(),
                MAX_BATCH_SIZE
            )));
        }

        // Validate all texts
        let mut total_tokens = 0;
        for text in texts {
            if text.is_empty() {
                return Err(EmbeddingError::EmptyText);
            }
            total_tokens += self.tokenizer.validate(text)?;
        }

        // Check rate limit
        self.rate_limiter.wait_if_needed(total_tokens as u32).await;

        // Check cache for all texts
        let mut results = Vec::with_capacity(texts.len());
        let mut uncached_texts = Vec::new();
        let mut uncached_indices = Vec::new();

        for (i, text) in texts.iter().enumerate() {
            if self.config.cache_enabled {
                if let Some(cached) = self.cache.get(text) {
                    results.push(Some(cached));
                    continue;
                }
            }
            results.push(None);
            uncached_texts.push(*text);
            uncached_indices.push(i);
        }

        // Call API for uncached texts
        if !uncached_texts.is_empty() {
            let new_embeddings = self.call_api(&uncached_texts).await?;

            for (i, embedding) in uncached_indices.into_iter().zip(new_embeddings) {
                let mut embedding = embedding;
                if self.config.normalize {
                    Normalizer::normalize_in_place(&mut embedding)?;
                }

                // Cache the result
                if self.config.cache_enabled {
                    let _ = self.cache.put(texts[i], embedding.clone());
                }

                results[i] = Some(embedding);
            }
        }

        // Record rate limit usage
        self.rate_limiter.record(total_tokens as u32);

        // Unwrap all results
        results
            .into_iter()
            .map(|opt| {
                opt.ok_or_else(|| EmbeddingError::ApiError {
                    message: "Missing embedding in batch result".to_string(),
                    status_code: None,
                })
            })
            .collect()
    }

    async fn store(&self, _claim_id: Uuid, _embedding: &[f32]) -> Result<(), EmbeddingError> {
        // OpenAI provider doesn't handle storage directly
        // Use EmbeddingRepository for database operations
        Err(EmbeddingError::ConfigError(
            "OpenAiProvider doesn't support storage. Use EmbeddingRepository.".to_string(),
        ))
    }

    async fn get(&self, _claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "OpenAiProvider doesn't support retrieval. Use EmbeddingRepository.".to_string(),
        ))
    }

    async fn similar(
        &self,
        _embedding: &[f32],
        _k: usize,
        _min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        Err(EmbeddingError::ConfigError(
            "OpenAiProvider doesn't support similarity search. Use EmbeddingRepository."
                .to_string(),
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
        // Try to generate a small embedding
        #[cfg(feature = "openai")]
        {
            self.generate("health check").await?;
            Ok(())
        }
        #[cfg(not(feature = "openai"))]
        {
            Err(EmbeddingError::ProviderUnavailable {
                provider: "OpenAI (feature not enabled)".to_string(),
            })
        }
    }
}
