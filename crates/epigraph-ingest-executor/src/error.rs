//! Surface-neutral error type for the ingest executor.

use thiserror::Error;

/// Failure cases when applying an ingest plan to the kernel DB. Each
/// surface (MCP, HTTP) maps these into its own user-facing error.
#[derive(Debug, Error)]
pub enum IngestError {
    /// Underlying DB layer returned an error during plan application.
    #[error("ingest db error: {0}")]
    Db(#[from] epigraph_db::DbError),

    /// Raw sqlx error from a query the executor runs directly (the
    /// idempotency edge-count check, `claims.properties` UPDATE, etc.).
    #[error("ingest sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Domain-layer error (e.g., truth-value out of range when building a
    /// `TruthValue`). Should be very rare; surfaced for completeness.
    #[error("ingest core error: {0}")]
    Core(#[from] epigraph_core::CoreError),
}
