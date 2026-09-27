//! The audit trail of the administrative cascade (migration 117).
//!
//! A supersede, a dedup or a match-candidate retirement is the CALLER's act,
//! written with the caller's authority. What follows it -- re-pointing and
//! retracting other writers' edges, moving and invalidating their edge-keyed
//! BBAs, re-deriving belief -- runs on the server's privileged maintenance
//! connection (`epigraph_engine::admin_cascade`). Every such cascade leaves one
//! `security_events` row, and so does every cascade that could not run:
//!
//! * [`EVENT_APPLIED`]: written on the maintenance connection after the
//!   cascade, naming the triggering principal, the cause, and what it touched
//!   (counts and ids). `success` is false when the cascade reported errors.
//! * [`EVENT_DEFERRED`]: written when the server has no maintenance connection
//!   (or could not use it). The caller's act still commits; the row is how an
//!   operator finds the cascades to replay. Written on the CALLER's session,
//!   so 077's `security_events_append` admits it only when `agent_id` is the
//!   session principal (or NULL): callers pass the principal they stamped.
//!
//! The id is minted here and bound, rather than read back with `RETURNING`: a
//! session may append a row it cannot read (see
//! `SecurityEventRepository::log_conn`).

use crate::errors::DbError;
use uuid::Uuid;

/// `security_events.event_type` of an administrative cascade that ran.
pub const EVENT_APPLIED: &str = "cascade.admin_applied";

/// `security_events.event_type` of a cascade that did not run.
pub const EVENT_DEFERRED: &str = "cascade.deferred";

/// Append one cascade audit row and return its id.
///
/// # Errors
/// `DbError::QueryFailed` if the INSERT is refused or fails.
pub async fn record<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    event_type: &'static str,
    agent_id: Option<Uuid>,
    success: bool,
    details: &serde_json::Value,
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO security_events (id, event_type, agent_id, success, details) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(event_type)
    .bind(agent_id)
    .bind(success)
    .bind(details)
    .execute(executor)
    .await?;
    Ok(id)
}
