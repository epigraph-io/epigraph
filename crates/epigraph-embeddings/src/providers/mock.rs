//! Mock embedding provider for testing
//!
//! Provides deterministic embeddings based on text content,
//! useful for unit testing without external API dependencies.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

use crate::cache::EmbeddingCache;
use crate::config::EmbeddingConfig;
use crate::errors::EmbeddingError;
use crate::normalizer::Normalizer;
use crate::service::{
    EmbeddingService, MultimodalEmbeddingService, MultimodalInput, SimilarClaim, TokenUsage,
};
use crate::tokenizer::Tokenizer;

/// Mock embedding provider for testing
///
/// Generates deterministic embeddings based on text hash.
/// Useful for testing embedding-dependent code without API calls.
pub struct MockProvider {
    /// Configuration
    config: EmbeddingConfig,
    /// Tokenizer for validation
    tokenizer: Tokenizer,
    /// Cache for embeddings
    cache: EmbeddingCache,
    /// In-memory storage for embeddings (simulates database)
    storage: RwLock<HashMap<Uuid, Vec<f32>>>,
    /// Token usage tracking
    token_usage: Mutex<TokenUsage>,
    /// Whether to simulate API failures
    simulate_failures: bool,
    /// Counter for API calls (to trigger failures)
    call_count: Mutex<usize>,
    /// Failure rate (0.0 = no failures, 1.0 = always fail)
    failure_rate: f32,
}

impl MockProvider {
    /// Create a new mock provider
    #[must_use]
    pub fn new(config: EmbeddingConfig) -> Self {
        let tokenizer = Tokenizer::new(config.max_tokens);
        let cache = EmbeddingCache::new(config.cache_ttl_secs, 10_000);

        Self {
            config,
            tokenizer,
            cache,
            storage: RwLock::new(HashMap::new()),
            token_usage: Mutex::new(TokenUsage::default()),
            simulate_failures: false,
            call_count: Mutex::new(0),
            failure_rate: 0.0,
        }
    }

    /// Create a mock provider that simulates failures
    #[must_use]
    pub const fn with_failures(mut self, failure_rate: f32) -> Self {
        self.simulate_failures = true;
        self.failure_rate = failure_rate;
        self
    }

    /// Generate a deterministic embedding from text
    ///
    /// Uses a simple hash-based approach to create reproducible vectors.
    fn generate_deterministic(&self, text: &str) -> Vec<f32> {
        let mut embedding = vec![0.0f32; self.config.dimension];

        // Use text bytes to seed the embedding
        for (i, byte) in text.bytes().enumerate() {
            let idx = i % self.config.dimension;
            // Create variation based on byte value and position
            embedding[idx] += (f32::from(byte) - 128.0) / 256.0;
            // Add some cross-dimensional influence
            let other_idx = (idx + byte as usize) % self.config.dimension;
            embedding[other_idx] += f32::from(byte) / 512.0;
        }

        // Normalize to unit vector
        if self.config.normalize {
            if let Ok(normalized) = Normalizer::normalize(&embedding) {
                return normalized;
            }
        }

        embedding
    }

    /// Check if this call should fail (based on failure rate)
    fn should_fail(&self) -> bool {
        if !self.simulate_failures {
            return false;
        }

        let mut count = self.call_count.lock().unwrap_or_else(|e| e.into_inner());
        *count += 1;

        // Simple deterministic "randomness" based on call count
        let pseudo_random = (*count as f32 * 0.618_034).fract();
        pseudo_random < self.failure_rate
    }

    /// Track token usage
    fn track_tokens(&self, text: &str) {
        let tokens = self.tokenizer.count_tokens(text);
        let mut usage = self.token_usage.lock().unwrap_or_else(|e| e.into_inner());
        usage.add(&TokenUsage::new(tokens));
    }
}

#[async_trait]
impl EmbeddingService for MockProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        // Validate empty text
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        // Validate token length
        self.tokenizer.validate(text)?;

        // Check for simulated failure
        if self.should_fail() {
            return Err(EmbeddingError::ApiError {
                message: "Simulated API failure".to_string(),
                status_code: Some(500),
            });
        }

        // Check cache
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(text) {
                return Ok(cached);
            }
        }

        // Track token usage
        self.track_tokens(text);

        // Generate embedding
        let embedding = self.generate_deterministic(text);

        // Cache the result
        if self.config.cache_enabled {
            let _ = self.cache.put(text, embedding.clone());
        }

        Ok(embedding)
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        // Validate all texts first
        for text in texts {
            if text.is_empty() {
                return Err(EmbeddingError::EmptyText);
            }
            self.tokenizer.validate(text)?;
        }

        // Check for simulated failure
        if self.should_fail() {
            return Err(EmbeddingError::ApiError {
                message: "Simulated batch API failure".to_string(),
                status_code: Some(500),
            });
        }

        // Generate embeddings
        let mut results = Vec::with_capacity(texts.len());
        for text in texts {
            let embedding = self.generate(text).await?;
            results.push(embedding);
        }

        Ok(results)
    }

    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        if embedding.len() != self.config.dimension {
            return Err(EmbeddingError::DimensionMismatch {
                expected: self.config.dimension,
                actual: embedding.len(),
            });
        }

        let mut storage = self
            .storage
            .write()
            .map_err(|e| EmbeddingError::DatabaseError(format!("Lock error: {e}")))?;

        storage.insert(claim_id, embedding.to_vec());
        Ok(())
    }

    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        let storage = self
            .storage
            .read()
            .map_err(|e| EmbeddingError::DatabaseError(format!("Lock error: {e}")))?;

        storage
            .get(&claim_id)
            .cloned()
            .ok_or(EmbeddingError::NotFound { claim_id })
    }

    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        if embedding.len() != self.config.dimension {
            return Err(EmbeddingError::DimensionMismatch {
                expected: self.config.dimension,
                actual: embedding.len(),
            });
        }

        let storage = self
            .storage
            .read()
            .map_err(|e| EmbeddingError::DatabaseError(format!("Lock error: {e}")))?;

        let mut similarities: Vec<SimilarClaim> = storage
            .iter()
            .map(|(claim_id, stored_embedding)| {
                let similarity = Normalizer::cosine_similarity(embedding, stored_embedding);
                SimilarClaim::new(*claim_id, similarity)
            })
            .filter(|s| s.similarity >= min_similarity)
            .collect();

        // Sort by similarity descending and take top k
        similarities.sort_unstable_by(|a, b| b.similarity.total_cmp(&a.similarity));
        similarities.truncate(k);

        Ok(similarities)
    }

    fn dimension(&self) -> usize {
        self.config.dimension
    }

    fn token_usage(&self) -> TokenUsage {
        self.token_usage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn reset_token_usage(&self) {
        let mut usage = self.token_usage.lock().unwrap_or_else(|e| e.into_inner());
        *usage = TokenUsage::default();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        if self.simulate_failures && self.failure_rate >= 1.0 {
            return Err(EmbeddingError::ProviderUnavailable {
                provider: "MockProvider".to_string(),
            });
        }
        Ok(())
    }
}

/// Builder for `MockProvider` with fallback support
pub struct MockProviderWithFallback {
    primary: Arc<MockProvider>,
    fallback: Option<Arc<MockProvider>>,
}

impl MockProviderWithFallback {
    /// Create a new provider with fallback
    #[must_use]
    pub fn new(primary: MockProvider, fallback: Option<MockProvider>) -> Self {
        Self {
            primary: Arc::new(primary),
            fallback: fallback.map(Arc::new),
        }
    }
}

#[async_trait]
impl EmbeddingService for MockProviderWithFallback {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        match self.primary.generate(text).await {
            Ok(embedding) => Ok(embedding),
            Err(e) if self.fallback.is_some() => {
                tracing::warn!("Primary provider failed, using fallback: {}", e);
                self.fallback.as_ref().unwrap().generate(text).await
            }
            Err(e) => Err(e),
        }
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        match self.primary.batch_generate(texts).await {
            Ok(embeddings) => Ok(embeddings),
            Err(e) if self.fallback.is_some() => {
                tracing::warn!("Primary provider failed, using fallback: {}", e);
                self.fallback.as_ref().unwrap().batch_generate(texts).await
            }
            Err(e) => Err(e),
        }
    }

    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        self.primary.store(claim_id, embedding).await
    }

    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        self.primary.get(claim_id).await
    }

    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        self.primary.similar(embedding, k, min_similarity).await
    }

    fn dimension(&self) -> usize {
        self.primary.dimension()
    }

    fn token_usage(&self) -> TokenUsage {
        self.primary.token_usage()
    }

    fn reset_token_usage(&self) {
        self.primary.reset_token_usage();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        self.primary.health_check().await
    }
}

/// Mock multimodal provider for testing image+text embedding
///
/// Wraps a `MockProvider` and adds multimodal support. Image inputs
/// produce deterministic embeddings based on the image data hash,
/// and `as_multimodal()` returns `Some(self)`.
pub struct MockMultimodalProvider {
    inner: MockProvider,
    /// Count of `generate_from_image` calls (for test assertions)
    image_call_count: Mutex<usize>,
}

impl MockMultimodalProvider {
    /// Create a new mock multimodal provider
    #[must_use]
    pub fn new(config: EmbeddingConfig) -> Self {
        Self {
            inner: MockProvider::new(config),
            image_call_count: Mutex::new(0),
        }
    }

    /// Get the number of times `generate_from_image` was called
    #[allow(clippy::missing_panics_doc)]
    pub fn image_call_count(&self) -> usize {
        *self
            .image_call_count
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl EmbeddingService for MockMultimodalProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.generate(text).await
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.inner.batch_generate(texts).await
    }

    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError> {
        self.inner.store(claim_id, embedding).await
    }

    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        self.inner.get(claim_id).await
    }

    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        self.inner.similar(embedding, k, min_similarity).await
    }

    fn dimension(&self) -> usize {
        self.inner.dimension()
    }

    fn token_usage(&self) -> TokenUsage {
        self.inner.token_usage()
    }

    fn reset_token_usage(&self) {
        self.inner.reset_token_usage();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        self.inner.health_check().await
    }

    fn supports_multimodal(&self) -> bool {
        true
    }

    fn as_multimodal(&self) -> Option<&dyn MultimodalEmbeddingService> {
        Some(self)
    }
}

#[async_trait]
impl MultimodalEmbeddingService for MockMultimodalProvider {
    async fn generate_from_image(&self, image_base64: &str) -> Result<Vec<f32>, EmbeddingError> {
        if image_base64.is_empty() {
            return Err(EmbeddingError::InvalidImageData {
                reason: "Empty image data".to_string(),
            });
        }

        *self
            .image_call_count
            .lock()
            .unwrap_or_else(|e| e.into_inner()) += 1;

        // Generate deterministic embedding from image data hash
        let dim = self.inner.dimension();
        let hash = image_base64.as_bytes().iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(31).wrapping_add(u64::from(b))
        });

        let mut embedding = Vec::with_capacity(dim);
        let mut h = hash;
        for _ in 0..dim {
            h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            embedding.push(((h >> 33) as f32) / (u32::MAX as f32));
        }
        Ok(embedding)
    }

    async fn batch_generate_multimodal(
        &self,
        inputs: &[MultimodalInput<'_>],
    ) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            match input {
                MultimodalInput::Text(text) => results.push(self.generate(text).await?),
                MultimodalInput::Image(data) => results.push(self.generate_from_image(data).await?),
            }
        }
        Ok(results)
    }
}
