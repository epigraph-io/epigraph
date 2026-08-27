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

    /// Filesystem I/O failed while reading or writing content-addressed blob
    /// bytes.
    ///
    /// Distinct from [`DbError::InvalidData`] on purpose: a disk-full or
    /// permission failure is a server fault (500), not a caller fault (400).
    /// A *missing* blob file is not this variant — it is
    /// `NotFound { entity: "blob_content", .. }`, so the route surfaces 404.
    #[error("Blob I/O failed: {message}")]
    Io { message: String },
}

impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            // Check for unique constraint violations
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => Self::DuplicateKey {
                entity: "entity".to_string(),
            },
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
