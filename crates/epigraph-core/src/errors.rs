//! Error types for epigraph-core
//!
//! Follows the principle of explicit, contextual errors over generic `Box<dyn Error>`.

use thiserror::Error;
use uuid::Uuid;

/// Core error type for epigraph-core operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CoreError {
    /// Label validation failed
    #[error("Invalid label '{value}': {reason}")]
    InvalidLabel { value: String, reason: String },

    /// Truth value out of bounds [0.0, 1.0]
    #[error("Truth value {value} out of bounds [0.0, 1.0]")]
    InvalidTruthValue { value: f64 },

    /// Link strength out of bounds [0.0, 1.0]
    #[error("Link strength {value} out of bounds [0.0, 1.0]")]
    InvalidLinkStrength { value: f64 },

    /// Property type mismatch
    #[error("Property '{key}' type mismatch: expected {expected}, got {actual}")]
    PropertyTypeMismatch {
        key: String,
        expected: String,
        actual: String,
    },

    /// Required property missing
    #[error("Required property '{key}' missing on {entity_type}")]
    MissingProperty { key: String, entity_type: String },

    /// Node not found in graph
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),

    /// Edge not found in graph
    #[error("Edge not found: {0}")]
    EdgeNotFound(Uuid),

    /// Cycle detected in reasoning graph
    #[error("Cycle detected: {from} -> {to} would create a cycle")]
    CycleDetected { from: Uuid, to: Uuid },

    /// Invalid edge: source and target cannot be the same
    #[error("Self-referential edge not allowed: node {0}")]
    SelfReferentialEdge(Uuid),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    JsonError(String),
}

impl From<serde_json::Error> for CoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err.to_string())
    }
}
