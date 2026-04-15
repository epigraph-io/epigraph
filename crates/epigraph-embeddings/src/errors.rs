//! Error types for the embedding service
//!
//! All errors in this crate use `thiserror` for ergonomic error handling
//! and clear error messages that aid debugging.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during embedding operations
#[derive(Error, Debug)]
pub enum EmbeddingError {
    /// The input text was empty
    #[error("Cannot generate embedding for empty text")]
    EmptyText,

    /// The input text exceeded the maximum token limit
    #[error("Text exceeds maximum token limit: {actual} > {max}")]
    TextTooLong {
        /// Actual number of tokens in the text
        actual: usize,
        /// Maximum allowed tokens
        max: usize,
    },

    /// The embedding dimension does not match expected
    #[error("Embedding dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch {
        /// Expected dimension
        expected: usize,
        /// Actual dimension received
        actual: usize,
    },

    /// API rate limit exceeded
    #[error("Rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        /// Seconds to wait before retrying
        retry_after_secs: u64,
    },

    /// API request failed
    #[error("API request failed: {message}")]
    ApiError {
        /// Error message from the API
        message: String,
        /// Optional HTTP status code
        status_code: Option<u16>,
    },

    /// Network error during API call
    #[error("Network error: {0}")]
    NetworkError(String),

    /// The embedding was not found in the database
    #[error("Embedding not found for claim {claim_id}")]
    NotFound {
        /// The claim ID that was not found
        claim_id: Uuid,
    },

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// Normalization failed (e.g., zero vector)
    #[error("Cannot normalize zero vector")]
    NormalizationError,

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Local model error
    #[error("Local model error: {0}")]
    LocalModelError(String),

    /// Provider not available (for fallback scenarios)
    #[error("Provider not available: {provider}")]
    ProviderUnavailable {
        /// Name of the unavailable provider
        provider: String,
    },

    /// Invalid image data (e.g., not valid base64 or unsupported format)
    #[error("Invalid image data: {reason}")]
    InvalidImageData {
        /// Description of why the image data is invalid
        reason: String,
    },

    /// Batch operation partially failed
    #[error("Batch operation failed for {failed_count}/{total_count} items")]
    PartialBatchFailure {
        /// Number of failed items
        failed_count: usize,
        /// Total number of items in batch
        total_count: usize,
        /// Indices of failed items
        failed_indices: Vec<usize>,
    },
}

#[cfg(feature = "db")]
impl From<sqlx::Error> for EmbeddingError {
    fn from(err: sqlx::Error) -> Self {
        Self::DatabaseError(err.to_string())
    }
}

#[cfg(any(feature = "openai", feature = "jina"))]
impl From<reqwest::Error> for EmbeddingError {
    fn from(err: reqwest::Error) -> Self {
        Self::NetworkError(err.to_string())
    }
}
