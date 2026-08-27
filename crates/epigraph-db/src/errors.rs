//! Database error types

use thiserror::Error;
use uuid::Uuid;

/// Database operation errors
#[derive(Error, Debug)]
pub enum DbError {
    /// Failed to connect to the database
    #[error("Failed to connect to database: {source}")]
    ConnectionFailed {
        #[source]
        source: sqlx::Error,
    },

    /// Query execution failed
    #[error("Query failed: {source}")]
    QueryFailed {
        #[source]
        source: sqlx::Error,
    },

    /// Entity not found
    #[error("{entity} with ID {id} not found")]
    NotFound { entity: String, id: Uuid },

    /// Duplicate key constraint violation
    #[error("Duplicate {entity} already exists")]
    DuplicateKey { entity: String },

    /// Foreign-key constraint violation (SQLSTATE 23503).
    ///
    /// A referencing row named a parent row that does not exist. Distinguished
    /// from `QueryFailed` because it is a CLIENT error, not a server fault:
    /// `groups.created_by_agent_id` FKs to `agents`, so a token whose
    /// `agent_id` claim names a deleted (or never-created) agent must surface
    /// as 403, not 500. `constraint` is the PostgreSQL constraint name when the
    /// driver reports one.
    #[error("Foreign key constraint {constraint} violated")]
    ForeignKeyViolation { constraint: String },

    /// Invalid data provided
    #[error("Invalid data: {reason}")]
    InvalidData { reason: String },

    /// Migration failed
    #[error("Migration failed: {source}")]
    MigrationFailed {
        #[source]
        source: sqlx::Error,
    },

    /// JSON serialization/deserialization error
    #[error("JSON error: {source}")]
    JsonError {
        #[source]
        source: serde_json::Error,
    },

    /// Core domain error
    #[error("Domain error: {source}")]
    CoreError {
        #[source]
        source: epigraph_core::CoreError,
    },
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            // Check for unique constraint violations
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => Self::DuplicateKey {
                entity: "entity".to_string(),
            },
            // 23503. Kept alongside the unique-violation arm so every repo gets
            // the classification for free; without it a bad FK is a 500.
            sqlx::Error::Database(db_err) if db_err.is_foreign_key_violation() => {
                Self::ForeignKeyViolation {
                    constraint: db_err.constraint().unwrap_or("<unnamed>").to_string(),
                }
            }
            // All other database errors become QueryFailed
            other => Self::QueryFailed { source: other },
        }
    }
}

impl From<serde_json::Error> for DbError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError { source: err }
    }
}

impl From<epigraph_core::CoreError> for DbError {
    fn from(err: epigraph_core::CoreError) -> Self {
        Self::CoreError { source: err }
    }
}
