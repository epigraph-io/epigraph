//! Database error types

use thiserror::Error;
use uuid::Uuid;

/// SQLSTATE 23514, `check_violation`.
///
/// Spelled once, here, because it is also the ERRCODE the tenancy trigger arms
/// in `migrations/070_tenancy_triggers.sql` and `migrations/072_edge_co_ownership.sql`
/// raise deliberately, and a second literal would be a place for the two to
/// drift.
const CHECK_VIOLATION: &str = "23514";

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

    /// CHECK constraint violation (SQLSTATE 23514).
    ///
    /// A CLIENT error for the same reason `ForeignKeyViolation` is: the row the
    /// caller asked for is not a row this schema can hold. Without this arm it
    /// falls through to [`Self::QueryFailed`] and the caller gets a bare 500
    /// reading "A database error occurred".
    ///
    /// PR-13 added it for the tenancy CHECKs on `edges` and `claims` —
    /// `edges_co_owner_shape` (migration 072), `edges_group_needs_real_group`
    /// and `claims_visibility_check` (062). Note what it is NOT, because a
    /// stale comment here would be worse than none: migration 070's arm (b)
    /// raised 23514 for "edge spans groups % and %; writer is not a member of
    /// both", and **migration 072 removes that RAISE** — a cross-group edge is
    /// now expressible and is stamped, not rejected. So 23514 on the edge write
    /// path now means malformed tenancy, not an authorization refusal.
    /// Write-side *authorization* is PR-16's, and will not arrive as 23514.
    ///
    /// It is ALSO raised by `migrations/071_ownership_compat_shim.sql`, and
    /// that source is why `message` below is not optional. 071's shim refuses
    /// to transcribe an `ownership` row into `(group, G)` when G has no live
    /// members — *"that group has no live members and the row would be
    /// unreadable by everyone, including its owner"* — via
    /// `RAISE ... USING ERRCODE = '23514'`. That is server state a client
    /// cannot know, on the `ownership` write path, and it reports NO constraint
    /// name. Classifying it by SQLSTATE is right; discarding its text is not.
    ///
    /// `constraint` is the PostgreSQL constraint name when the driver reports
    /// one. A `RAISE ... USING ERRCODE = '23514'` from plpgsql reports none,
    /// so `<unnamed>` is a normal value here, not a bug — and it is exactly why
    /// `message` exists.
    ///
    /// `message` is the driver's primary message, carried verbatim, and it is
    /// in `Display` deliberately: `epigraph-mcp/src/errors.rs::internal_error`
    /// renders a `DbError` with `to_string()`, so without this field an
    /// operator calling `assign_ownership` would see `Check constraint
    /// <unnamed> violated` and nothing else where 071's message used to be.
    /// The HTTP layer makes its own disclosure decision and deliberately does
    /// NOT put `message` in the response body — see `epigraph-api/src/errors.rs`.
    #[error("Check constraint {constraint} violated: {message}")]
    CheckViolation { constraint: String, message: String },

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
            // 23514. `sqlx` has no `is_check_violation()` helper, so the code
            // is read off the driver directly. Matched AFTER the two helpers
            // above so their classification is unchanged.
            sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some(CHECK_VIOLATION) => {
                Self::CheckViolation {
                    constraint: db_err.constraint().unwrap_or("<unnamed>").to_string(),
                    // Captured HERE, at construction. `QueryFailed` keeps the
                    // driver error as `#[source]` and gets the message for
                    // free; a struct variant with no `source` discards it
                    // permanently unless it is copied out now.
                    message: db_err.message().to_string(),
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
