//! Local embedding provider
//!
//! Provides embedding generation using a local model.
//! This is a stub implementation for fallback when API is unavailable.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::cache::EmbeddingCache;
use crate::config::EmbeddingConfig;
use crate::errors::EmbeddingError;
use crate::normalizer::Normalizer;
use crate::service::{EmbeddingService, SimilarClaim, TokenUsage};
use crate::tokenizer::Tokenizer;

/// Local embedding provider
///
/// Uses a local model for embedding generation.
/// Useful as a fallback when the API is unavailable.
pub struct LocalProvider {
    /// Configuration
    config: EmbeddingConfig,
    /// Tokenizer for validation
    tokenizer: Tokenizer,
    /// Cache for embeddings
    cache: EmbeddingCache,
    /// In-memory storage for embeddings
    storage: RwLock<HashMap<Uuid, Vec<f32>>>,
    /// Token usage tracking
    token_usage: Mutex<TokenUsage>,
    /// Whether the local model is available
    model_available: bool,
}

impl LocalProvider {
    /// Create a new local provider
    ///
    /// # Arguments
    /// * `config` - Embedding configuration
    ///
    /// # Returns
    /// * `Ok(LocalProvider)` - Successfully created provider
    /// * `Err(EmbeddingError)` - If model cannot be loaded
    pub fn new(config: EmbeddingConfig) -> Result<Self, EmbeddingError> {
        let tokenizer = Tokenizer::new(config.max_tokens);
        let cache = EmbeddingCache::new(config.cache_ttl_secs, 10_000);

        // In a real implementation, this would load the local model
        // For now, we use a simple hash-based approach
        let model_available = true;

        Ok(Self {
            config,
            tokenizer,
            cache,
            storage: RwLock::new(HashMap::new()),
            token_usage: Mutex::new(TokenUsage::default()),
            model_available,
        })
    }

    /// Generate embedding using local model (stub implementation)
    ///
    /// In a real implementation, this would use a local model like
    /// sentence-transformers or a custom ONNX model.
    fn generate_local(&self, text: &str) -> Vec<f32> {
        let mut embedding = vec![0.0f32; self.config.dimension];

        // Simple hash-based embedding (deterministic for testing)
        // This is NOT a real embedding - just for fallback/testing
        let mut hash: u64 = 0;
        for (i, byte) in text.bytes().enumerate() {
            // Simple mixing function
            hash = hash.wrapping_mul(31).wrapping_add(u64::from(byte));

            // Distribute across dimensions
            let idx = (i * 17 + byte as usize) % self.config.dimension;
            embedding[idx] += ((hash % 1000) as f32 - 500.0) / 1000.0;
        }

        // Normalize
        if self.config.normalize {
            if let Ok(normalized) = Normalizer::normalize(&embedding) {
                return normalized;
            }
        }

        embedding
    }

    /// Track token usage
    fn track_tokens(&self, text: &str) {
        let tokens = self.tokenizer.count_tokens(text);
        let mut usage = self.token_usage.lock().unwrap_or_else(|e| e.into_inner());
        usage.add(&TokenUsage::new(tokens));
    }
}

#[async_trait]
impl EmbeddingService for LocalProvider {
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.is_empty() {
            return Err(EmbeddingError::EmptyText);
        }

        if !self.model_available {
            return Err(EmbeddingError::LocalModelError(
                "Local model not available".to_string(),
            ));
        }

        // Validate token length
        self.tokenizer.validate(text)?;

        // Check cache
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(text) {
                return Ok(cached);
            }
        }

        // Track usage
        self.track_tokens(text);

        // Generate embedding
        let embedding = self.generate_local(text);

        // Cache result
        if self.config.cache_enabled {
            let _ = self.cache.put(text, embedding.clone());
        }

        Ok(embedding)
    }

    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
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
            .map(|(claim_id, stored)| {
                let sim = Normalizer::cosine_similarity(embedding, stored);
                SimilarClaim::new(*claim_id, sim)
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
        self.token_usage.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn reset_token_usage(&self) {
        let mut usage = self.token_usage.lock().unwrap_or_else(|e| e.into_inner());
        *usage = TokenUsage::default();
    }

    async fn health_check(&self) -> Result<(), EmbeddingError> {
        if self.model_available {
            Ok(())
        } else {
            Err(EmbeddingError::ProviderUnavailable {
                provider: "LocalProvider".to_string(),
            })
        }
    }
}
