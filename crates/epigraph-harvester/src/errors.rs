//! Error types for the harvester crate

use thiserror::Error;

/// Errors that can occur in harvester operations
#[derive(Error, Debug)]
pub enum HarvesterError {
    /// Failed to connect to gRPC server
    #[error("Connection to harvester server at {url} failed: {reason}")]
    ConnectionFailed { url: String, reason: String },

    /// Extraction process failed
    #[error("Extraction failed for fragment {fragment_id}: {reason}")]
    ExtractionFailed { fragment_id: String, reason: String },

    /// Document fragmentation failed
    #[error("Fragmentation failed: {reason}")]
    FragmentationFailed { reason: String },

    /// Received invalid response from server
    #[error("Invalid response from harvester: {reason}")]
    InvalidResponse { reason: String },

    /// Operation timed out
    #[error("Operation {operation} timed out")]
    Timeout { operation: String },

    /// gRPC transport error
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    /// gRPC status error
    #[error("gRPC status error: {0}")]
    Status(#[from] tonic::Status),

    /// Invalid content hash
    #[error("Invalid content hash: expected {expected} bytes, got {actual}")]
    InvalidContentHash { expected: usize, actual: usize },

    /// Invalid confidence value
    #[error("Invalid confidence value {value}: must be in [0.0, 1.0]")]
    InvalidConfidence { value: f64 },

    /// Missing required field
    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

impl HarvesterError {
    /// Check if this error is retry-able
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ConnectionFailed { .. } | Self::Timeout { .. } | Self::Transport(_)
        )
    }
}
