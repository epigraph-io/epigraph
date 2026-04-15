//! Engine error types

use thiserror::Error;
use uuid::Uuid;

/// Errors from the epistemic engine
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Cycle detected in the reasoning DAG
    #[error("Cycle detected in reasoning graph: {path:?}")]
    CycleDetected { path: Vec<Uuid> },

    /// Referenced node not found
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),

    /// Invalid evidence configuration
    #[error("Invalid evidence: {reason}")]
    InvalidEvidence { reason: String },

    /// Truth value computation failed
    #[error("Truth computation failed: {reason}")]
    TruthComputationFailed { reason: String },

    /// Reputation computation failed
    #[error("Reputation computation failed: {reason}")]
    ReputationComputationFailed { reason: String },
}
