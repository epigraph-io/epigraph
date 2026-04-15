use thiserror::Error;

/// Errors that can occur during the ingestion pipeline.
#[derive(Debug, Error)]
pub enum IngestError {
    #[error("invalid document: {0}")]
    InvalidDocument(String),

    #[error("path resolution failed for '{path}': {reason}")]
    PathResolution { path: String, reason: String },

    #[error("persistence error: {0}")]
    Persistence(String),

    #[error("dedup error: {0}")]
    Dedup(String),

    #[error("embedding error: {0}")]
    Embedding(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
