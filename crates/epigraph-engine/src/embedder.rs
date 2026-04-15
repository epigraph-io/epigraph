//! Embedding trait and OpenAI implementation.
//!
//! Provides a generic `Embedder` trait for converting text into vector
//! representations, plus a concrete `OpenAiEmbedder` that calls the
//! OpenAI embeddings API.

use async_trait::async_trait;

/// Errors that can occur during embedding.
#[derive(Debug, thiserror::Error)]
pub enum EmbedError {
    /// The HTTP request itself failed (network, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// The response could not be parsed into the expected shape.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// The API returned a non-success status code.
    #[error("API error: {status} {message}")]
    ApiError {
        /// HTTP status code.
        status: u16,
        /// Error message from the API body.
        message: String,
    },
}

/// A provider that turns text into a fixed-dimensional f32 vector.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embed a single text string, returning a vector of `dimensions()` floats.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError>;

    /// The number of dimensions produced by this embedder.
    fn dimensions(&self) -> usize;
}

// ---------------------------------------------------------------------------
// OpenAI implementation
// ---------------------------------------------------------------------------

/// Calls the OpenAI `/v1/embeddings` endpoint.
pub struct OpenAiEmbedder {
    api_key: String,
    model: String,
    dimensions: usize,
    client: reqwest::Client,
}

impl OpenAiEmbedder {
    /// Create an embedder using `text-embedding-3-small` (1536 dimensions).
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            model: "text-embedding-3-small".to_string(),
            dimensions: 1536,
            client: reqwest::Client::new(),
        }
    }

    /// Create an embedder with a custom model name and dimension count.
    #[must_use]
    pub fn with_model(api_key: String, model: String, dimensions: usize) -> Self {
        Self {
            api_key,
            model,
            dimensions,
            client: reqwest::Client::new(),
        }
    }
}

/// Minimal types mirroring the OpenAI embeddings response.
mod api {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub(super) struct EmbeddingResponse {
        pub data: Vec<EmbeddingData>,
    }

    #[derive(Deserialize)]
    pub(super) struct EmbeddingData {
        pub embedding: Vec<f32>,
    }
}

#[async_trait]
impl Embedder for OpenAiEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let body = serde_json::json!({
            "input": text,
            "model": self.model,
        });

        let response = self
            .client
            .post("https://api.openai.com/v1/embeddings")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| EmbedError::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            return Err(EmbedError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let parsed: api::EmbeddingResponse = response
            .json()
            .await
            .map_err(|e| EmbedError::InvalidResponse(e.to_string()))?;

        parsed
            .data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .ok_or_else(|| EmbedError::InvalidResponse("empty data array".to_string()))
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial embedder that always returns a fixed vector, useful in tests.
    pub struct MockEmbedder {
        vector: Vec<f32>,
    }

    impl MockEmbedder {
        pub fn new(dimensions: usize) -> Self {
            Self {
                vector: vec![0.1; dimensions],
            }
        }

        pub fn with_vector(vector: Vec<f32>) -> Self {
            Self { vector }
        }
    }

    #[async_trait]
    impl Embedder for MockEmbedder {
        async fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedError> {
            Ok(self.vector.clone())
        }

        fn dimensions(&self) -> usize {
            self.vector.len()
        }
    }

    #[tokio::test]
    async fn mock_embedder_returns_correct_dimensions() {
        let embedder = MockEmbedder::new(1536);
        let vec = embedder.embed("hello world").await.unwrap();
        assert_eq!(vec.len(), embedder.dimensions());
        assert_eq!(vec.len(), 1536);
    }

    #[tokio::test]
    async fn mock_embedder_custom_vector() {
        let custom = vec![1.0, 2.0, 3.0];
        let embedder = MockEmbedder::with_vector(custom.clone());
        let result = embedder.embed("anything").await.unwrap();
        assert_eq!(result, custom);
        assert_eq!(embedder.dimensions(), 3);
    }

    #[tokio::test]
    async fn mock_embedder_is_send_sync() {
        // Compile-time proof that the trait object is Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockEmbedder>();
    }

    #[test]
    fn openai_embedder_defaults() {
        let e = OpenAiEmbedder::new("sk-test".to_string());
        assert_eq!(e.dimensions(), 1536);
    }

    #[test]
    fn openai_embedder_custom_model() {
        let e = OpenAiEmbedder::with_model(
            "sk-test".to_string(),
            "text-embedding-3-large".to_string(),
            3072,
        );
        assert_eq!(e.dimensions(), 3072);
    }
}
