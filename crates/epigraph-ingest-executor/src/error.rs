//! Error type for the ingest executor.

use thiserror::Error;

/// Errors that can be raised while executing a workflow ingest plan.
///
/// Callers (MCP and API handlers) map this into their own error type
/// (`McpError`, `ApiError`, etc.) at the wrapper boundary.
#[derive(Error, Debug)]
pub enum IngestExecutorError {
    /// Raw `sqlx` error from inline queries (UPDATE / SELECT COUNT(*)).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Repository-layer error from `epigraph_db`.
    #[error("repository error: {0}")]
    Repository(#[from] epigraph_db::DbError),

    /// Failed to look up or create an agent (system or author).
    #[error("agent creation failed: {0}")]
    AgentCreation(String),

    /// Failed to insert the workflow row.
    #[error("workflow row insert failed: {0}")]
    WorkflowInsert(String),

    /// Plan structure violated an executor invariant.
    #[error("plan inconsistency: {0}")]
    PlanInconsistency(String),
}
