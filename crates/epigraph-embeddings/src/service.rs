//! Core embedding service trait and types
//!
//! Defines the main interface for embedding generation and storage.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::EmbeddingError;

/// Token usage statistics for embedding API calls
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Total tokens used in the request
    pub total_tokens: usize,

    /// Prompt tokens (for embedding, this equals total)
    pub prompt_tokens: usize,
}

impl TokenUsage {
    /// Create new token usage record
    #[must_use]
    pub const fn new(total_tokens: usize) -> Self {
        Self {
            total_tokens,
            prompt_tokens: total_tokens,
        }
    }

    /// Add usage from another record
    pub const fn add(&mut self, other: &Self) {
        self.total_tokens += other.total_tokens;
        self.prompt_tokens += other.prompt_tokens;
    }
}

/// Result of a similarity search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarClaim {
    /// The claim ID
    pub claim_id: Uuid,

    /// Cosine similarity score (0.0 to 1.0)
    pub similarity: f32,

    /// Distance (1.0 - similarity for cosine distance)
    pub distance: f32,
}

impl SimilarClaim {
    /// Create a new similar claim result
    #[must_use]
    pub fn new(claim_id: Uuid, similarity: f32) -> Self {
        Self {
            claim_id,
            similarity,
            distance: 1.0 - similarity,
        }
    }
}

/// Main trait for embedding generation and storage
///
/// This trait defines the complete interface for working with embeddings
/// in the `EpiGraph` system. Implementations may use different backends
/// (`OpenAI`, local models, etc.) but must conform to this interface.
#[async_trait]
pub trait EmbeddingService: Send + Sync {
    /// Generate an embedding for the given text
    ///
    /// # Arguments
    /// * `text` - The text to embed
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The embedding vector
    /// * `Err(EmbeddingError::EmptyText)` - If the text is empty
    /// * `Err(EmbeddingError::TextTooLong)` - If the text exceeds max tokens
    ///
    /// # Example
    /// ```rust,ignore
    /// let embedding = service.generate("The Earth orbits the Sun").await?;
    /// assert_eq!(embedding.len(), 1536);
    /// ```
    async fn generate(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;

    /// Generate embeddings for multiple texts in a single batch
    ///
    /// # Arguments
    /// * `texts` - Slice of texts to embed
    ///
    /// # Returns
    /// * `Ok(Vec<Vec<f32>>)` - Vector of embeddings in same order as input
    /// * `Err(EmbeddingError)` - If any text fails to embed
    ///
    /// Implementations should optimize batch calls to minimize API requests.
    async fn batch_generate(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError>;

    /// Store an embedding for a claim in the database
    ///
    /// # Arguments
    /// * `claim_id` - The claim's UUID
    /// * `embedding` - The embedding vector to store
    ///
    /// # Returns
    /// * `Ok(())` - Successfully stored
    /// * `Err(EmbeddingError::DimensionMismatch)` - If embedding has wrong dimension
    async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<(), EmbeddingError>;

    /// Retrieve a stored embedding for a claim
    ///
    /// # Arguments
    /// * `claim_id` - The claim's UUID
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The stored embedding
    /// * `Err(EmbeddingError::NotFound)` - If no embedding exists for this claim
    async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError>;

    /// Find claims with similar embeddings
    ///
    /// Uses cosine similarity to find the k most similar claims.
    ///
    /// # Arguments
    /// * `embedding` - The query embedding
    /// * `k` - Maximum number of results to return
    /// * `min_similarity` - Minimum similarity threshold (0.0 to 1.0)
    ///
    /// # Returns
    /// * `Ok(Vec<SimilarClaim>)` - Similar claims sorted by similarity (descending)
    async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError>;

    /// Get the configured embedding dimension
    fn dimension(&self) -> usize;

    /// Get token usage statistics
    ///
    /// Returns cumulative token usage since the service was created.
    fn token_usage(&self) -> TokenUsage;

    /// Reset token usage counter
    fn reset_token_usage(&self);

    /// Check if the service is healthy and can accept requests
    async fn health_check(&self) -> Result<(), EmbeddingError>;

    /// Generate an embedding optimized for search queries.
    ///
    /// For asymmetric retrieval models (e.g., Jina v4), this uses the query
    /// task adapter instead of the passage adapter. For symmetric models
    /// (e.g., `OpenAI`), this is identical to `generate()`.
    async fn generate_query(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        self.generate(text).await
    }

    /// Check if this provider supports multimodal (image) embedding.
    ///
    /// Returns `true` for providers that implement `MultimodalEmbeddingService`.
    /// Text-only providers return `false` (the default).
    fn supports_multimodal(&self) -> bool {
        false
    }

    /// Attempt to use this service as a multimodal embedding service.
    ///
    /// Returns `None` for text-only providers (the default). Multimodal
    /// providers (e.g., `JinaProvider`) override this to return `Some(self)`,
    /// enabling callers to access `generate_from_image()` and
    /// `batch_generate_multimodal()` without a separate service reference.
    fn as_multimodal(&self) -> Option<&dyn MultimodalEmbeddingService> {
        None
    }
}

/// Input type for multimodal embedding generation
#[derive(Debug, Clone)]
pub enum MultimodalInput<'a> {
    /// Text input for embedding
    Text(&'a str),
    /// Base64-encoded image data for embedding
    Image(&'a str),
}

/// Extension trait for providers that support multimodal (image+text) embedding.
///
/// Providers implementing this trait can generate embeddings from both text and
/// images (e.g., Jina Embeddings v4). The text and image embeddings live in the
/// same vector space, enabling cross-modal similarity search.
#[async_trait]
pub trait MultimodalEmbeddingService: EmbeddingService {
    /// Generate an embedding from a base64-encoded image
    ///
    /// # Arguments
    /// * `image_base64` - Base64-encoded image data (PNG, JPEG, etc.)
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The embedding vector (same dimensionality as text embeddings)
    /// * `Err(EmbeddingError::InvalidImageData)` - If the image data is invalid
    async fn generate_from_image(&self, image_base64: &str) -> Result<Vec<f32>, EmbeddingError>;

    /// Generate embeddings from mixed text and image inputs in a single batch
    ///
    /// # Arguments
    /// * `inputs` - Slice of text and/or image inputs
    ///
    /// # Returns
    /// * `Ok(Vec<Vec<f32>>)` - Vector of embeddings in same order as input
    async fn batch_generate_multimodal(
        &self,
        inputs: &[MultimodalInput<'_>],
    ) -> Result<Vec<Vec<f32>>, EmbeddingError>;
}

/// Extension trait for embedding service utilities
pub trait EmbeddingServiceExt: EmbeddingService {
    /// Generate and store an embedding for a claim in one operation
    ///
    /// This is a convenience method that combines `generate` and `store`.
    fn generate_and_store(
        &self,
        claim_id: Uuid,
        text: &str,
    ) -> impl std::future::Future<Output = Result<Vec<f32>, EmbeddingError>> + Send;
}

impl<T: EmbeddingService> EmbeddingServiceExt for T {
    async fn generate_and_store(
        &self,
        claim_id: Uuid,
        text: &str,
    ) -> Result<Vec<f32>, EmbeddingError> {
        let embedding = self.generate(text).await?;
        self.store(claim_id, &embedding).await?;
        Ok(embedding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EmbeddingConfig;
    use crate::providers::MockProvider;

    #[test]
    fn test_mock_provider_does_not_support_multimodal() {
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        assert!(
            !provider.supports_multimodal(),
            "MockProvider (text-only) should not support multimodal"
        );
    }

    #[test]
    fn test_mock_provider_as_multimodal_returns_none() {
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        assert!(
            provider.as_multimodal().is_none(),
            "Text-only MockProvider should return None from as_multimodal()"
        );
    }

    #[test]
    fn test_multimodal_provider_as_multimodal_returns_some() {
        use crate::providers::MockMultimodalProvider;

        let config = EmbeddingConfig::local(64);
        let provider = MockMultimodalProvider::new(config);
        assert!(
            provider.supports_multimodal(),
            "MockMultimodalProvider should report multimodal support"
        );
        assert!(
            provider.as_multimodal().is_some(),
            "MockMultimodalProvider should return Some from as_multimodal()"
        );
    }

    #[tokio::test]
    async fn test_figure_embedding_uses_multimodal_when_available() {
        use crate::providers::MockMultimodalProvider;
        use std::sync::Arc;

        let config = EmbeddingConfig::local(64);
        let provider = Arc::new(MockMultimodalProvider::new(config));
        let service: Arc<dyn EmbeddingService> = provider.clone();

        // Simulate figure evidence embedding dispatch
        let image_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAH";

        let embedding = if let Some(multimodal) = service.as_multimodal() {
            multimodal.generate_from_image(image_base64).await.unwrap()
        } else {
            service.generate("fallback caption").await.unwrap()
        };

        assert_eq!(embedding.len(), 64);
        assert_eq!(
            provider.image_call_count(),
            1,
            "generate_from_image should have been called"
        );
    }

    #[tokio::test]
    async fn test_figure_embedding_falls_back_to_caption() {
        use std::sync::Arc;

        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        let service: Arc<dyn EmbeddingService> = Arc::new(provider);

        // Simulate figure evidence embedding dispatch with text-only provider
        let caption = "STM topography image of germanene on Al(111)";

        let embedding = if let Some(multimodal) = service.as_multimodal() {
            multimodal
                .generate_from_image("some_image_data")
                .await
                .unwrap()
        } else {
            // Falls back to embedding caption text
            service.generate(caption).await.unwrap()
        };

        assert_eq!(
            embedding.len(),
            64,
            "Fallback should produce correct dimension"
        );
        // Verify it's a text embedding (not an image one) — MockProvider generates
        // deterministic embeddings from text, so this confirms the text path was used.
        let caption_embedding = service.generate(caption).await.unwrap();
        assert_eq!(
            embedding, caption_embedding,
            "Should match direct text embedding"
        );
    }
}
