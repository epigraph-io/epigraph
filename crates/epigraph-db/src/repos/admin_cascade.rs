//! The audit trail of the administrative cascade (migration 117).
//!
//! A supersede, a dedup or a match-candidate retirement is the CALLER's act,
//! written with the caller's authority. What follows it -- re-pointing and
//! retracting other writers' edges, moving and invalidating their edge-keyed
//! BBAs, re-deriving belief -- runs on the server's privileged maintenance
//! connection (`epigraph_engine::admin_cascade`). Every such cascade leaves one
//! `security_events` row, and so does every cascade that could not run:
//!
//! * [`EVENT_APPLIED`]: written on the maintenance connection in the repair's
//!   own transaction, naming the triggering principal, the cause, and what the
//!   repair touched (counts and ids).
//! * [`EVENT_DEFERRED`]: written when the server has no maintenance connection
//!   (or could not use it). The caller's act still commits, in the SAME
//!   transaction as this row; the row is how the replay
//!   (`epigraph_engine::admin_cascade::replay_deferred`) finds the cascades to
//!   run. Written on the CALLER's session through [`record_deferral`], which
//!   calls 117's `epigraph_record_cascade_deferral` definer: the database
//!   attributes the row to the session principal and admits it only for an
//!   act that session made. A non-privileged session cannot INSERT any
//!   `cascade.*` row itself (117's `security_events_cascade_privileged`), so
//!   every row the replay reads was written by that definer or by a
//!   privileged session.
//! * [`EVENT_FAILED`]: the repair started on the maintenance connection and
//!   failed; nothing of it committed. Replayable like a deferral.
//! * [`EVENT_BELIEF`]: the belief re-derivation after an applied repair.
//!
//! The [`EVENT_APPLIED`] row is written INSIDE the repair's transaction, so an
//! applied cross-owner repair never exists without its audit row.
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

/// `security_events.event_type` of a cascade whose repair started on the
/// maintenance connection and failed (rolled back). Like a deferral, it is
/// replayable: the repair is idempotent and re-verifies the committed act.
pub const EVENT_FAILED: &str = "cascade.admin_failed";

/// `security_events.event_type` of the belief re-derivation that follows an
/// applied repair. Written after the repair's own [`EVENT_APPLIED`] row has
/// committed (the belief cascade is best-effort and runs per claim), and
/// names that row in `details.applied_event_id`.
pub const EVENT_BELIEF: &str = "cascade.belief_rederived";

/// Record a deferred cascade on the CALLER's session, through 117's
/// `epigraph_record_cascade_deferral` definer, and return the row's id.
///
/// The definer builds the row itself: `agent_id` is the session principal
/// (a different `agent_id` is refused, CX02), `created_at` is the time of the
/// write, and the act must be one the session made -- the subject (and, for a
/// supersede, its successor; for a consolidation, every source) written by the
/// session, a dedup's canonical public or written by it (CX03). Call it inside
/// the act's own transaction, after the act.
///
/// # Errors
/// `DbError::QueryFailed` if the definer refuses or the call fails; nothing is
/// recorded.
#[allow(clippy::too_many_arguments)]
pub async fn record_deferral<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    cause: &str,
    agent_id: Option<Uuid>,
    subject_id: Uuid,
    object_id: Option<Uuid>,
    sources: &[Uuid],
    oauth: Option<&serde_json::Value>,
    reason: &str,
) -> Result<Uuid, DbError> {
    let id: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_record_cascade_deferral($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(cause)
    .bind(agent_id)
    .bind(subject_id)
    .bind(object_id)
    .bind(sources)
    .bind(oauth)
    .bind(reason)
    .fetch_one(executor)
    .await?;
    Ok(id)
}

/// Append one cascade audit row and return its id.
///
/// On a non-privileged session 117 refuses every `cascade.*` row this writes;
/// a request path records its deferral with [`record_deferral`] instead. The
/// maintenance connection writes the applied, failed, belief and retired rows
/// through this.
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

/// The deferred or failed cascades still to replay, oldest first, ONE row per
/// (cause, subject) -- its oldest [`EVENT_DEFERRED`] / [`EVENT_FAILED`] row --
/// up to `limit` cascades, for every cascade with no [`EVENT_APPLIED`] row for
/// the same cause and subject written at or after that row. Returns
/// `(event id, details)`.
///
/// One row per cascade, so a cascade that keeps failing (a replay that fails
/// again writes one more [`EVENT_FAILED`] row each run) occupies one slot of
/// `limit` however many runs it has failed, and cannot crowd newer deferrals
/// out of the window.
///
/// Runs on the maintenance connection (the replay's): `security_events` is
/// append-only for application sessions, which cannot read other principals'
/// rows.
///
/// # Errors
/// `DbError::QueryFailed` on a failed query.
pub async fn pending_replays<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    limit: i64,
) -> Result<Vec<(Uuid, serde_json::Value)>, DbError> {
    let rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT p.id, p.details FROM ( \
             SELECT DISTINCT ON (d.details->>'cause', d.details->'trigger'->>'subject_id') \
                    d.id, d.details, d.created_at \
               FROM security_events d \
              WHERE d.event_type IN ($1, $2) \
                AND NOT EXISTS ( \
                    SELECT 1 FROM security_events a \
                     WHERE a.event_type = $3 \
                       AND a.details->>'cause' = d.details->>'cause' \
                       AND a.details->'trigger'->>'subject_id' = \
                           d.details->'trigger'->>'subject_id' \
                       AND a.created_at >= d.created_at) \
              ORDER BY d.details->>'cause', d.details->'trigger'->>'subject_id', \
                       d.created_at, d.id) p \
          ORDER BY p.created_at, p.id \
          LIMIT $4",
    )
    .bind(EVENT_DEFERRED)
    .bind(EVENT_FAILED)
    .bind(EVENT_APPLIED)
    .bind(limit)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}
