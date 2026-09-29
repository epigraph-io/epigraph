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
//! * [`EVENT_RETIRED`]: an operator retired a pending cascade that will not
//!   replay ([`retire_pending`]); it answers the pending rows like an applied
//!   one.
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

/// `security_events.event_type` of a pending cascade an operator retired
/// instead of replaying (its act was undone, say, so its repair can never
/// verify). Written on the maintenance connection only.
pub const EVENT_RETIRED: &str = "cascade.retired";

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

/// The pending cascades, keyed and counted. `open` is every
/// [`EVENT_DEFERRED`] / [`EVENT_FAILED`] row with no [`EVENT_APPLIED`] or
/// [`EVENT_RETIRED`] row for the same cause and subject at or after it (the
/// rows the next applied row for that cascade closes); `pend` keeps one per
/// (cause, subject), its oldest; `counted` adds the number of [`EVENT_FAILED`]
/// rows written for that cascade since. Binds: `$1` deferred, `$2` failed,
/// `$3` applied, `$4` retired.
///
/// The subject is compared NORMALISED (lower case, hex digits only, a
/// `urn:uuid:` prefix dropped): the replay parses it as a UUID, which accepts
/// every such spelling, so a textual comparison would leave a cascade whose
/// rows spell the subject differently pending forever. The normaliser is total,
/// so a malformed row cannot abort the window the way a `::uuid` cast would.
const PENDING_CTE: &str = "\
    WITH ev AS ( \
        SELECT e.id, e.event_type, e.details, e.created_at, \
               e.details->>'cause' AS cause, \
               regexp_replace(lower(e.details->'trigger'->>'subject_id'), \
                              '^urn:uuid:|[^0-9a-f]', '', 'g') AS subj \
          FROM security_events e \
         WHERE e.event_type IN ($1, $2, $3, $4)), \
    open AS ( \
        SELECT d.id, d.details, d.created_at, d.cause, d.subj \
          FROM ev d \
         WHERE d.event_type IN ($1, $2) \
           AND NOT EXISTS (SELECT 1 FROM ev a \
                            WHERE a.event_type IN ($3, $4) \
                              AND a.cause IS NOT DISTINCT FROM d.cause \
                              AND a.subj IS NOT DISTINCT FROM d.subj \
                              AND a.created_at >= d.created_at)), \
    pend AS ( \
        SELECT DISTINCT ON (o.cause, o.subj) o.id, o.details, o.created_at, o.cause, o.subj \
          FROM open o \
         ORDER BY o.cause, o.subj, o.created_at, o.id), \
    counted AS ( \
        SELECT p.id, p.details, p.created_at, \
               (SELECT count(*) FROM ev f \
                 WHERE f.event_type = $2 \
                   AND f.cause IS NOT DISTINCT FROM p.cause \
                   AND f.subj IS NOT DISTINCT FROM p.subj \
                   AND f.created_at >= p.created_at) AS failures \
          FROM pend p) ";

/// One pending cascade: the row to replay, its details, and how many times
/// its repair has failed since it was deferred.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingReplay {
    /// The oldest pending `cascade.deferred` / `cascade.admin_failed` row.
    pub event_id: Uuid,
    /// That row's `details` (the trigger the replay rebuilds).
    pub details: serde_json::Value,
    /// `cascade.admin_failed` rows written for this cascade since that row.
    pub failures: i64,
}

/// The pending cascades to replay now: those that have failed fewer than
/// `max_failures` times, FEWEST FAILURES FIRST and then oldest first, up to
/// `limit` cascades.
///
/// One entry per (cause, subject), and a cascade that keeps failing moves
/// behind every cascade that has failed less, then leaves the window at
/// `max_failures` ([`stuck_replays`] lists it for an operator, who retires it
/// with [`retire_pending`]). So neither one cascade nor many that can never
/// verify hold newer deferrals out of the window.
///
/// Runs on the maintenance connection (the replay's): application sessions
/// cannot read other principals' rows.
///
/// # Errors
/// `DbError::QueryFailed` on a failed query.
pub async fn pending_replays<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    limit: i64,
    max_failures: i64,
) -> Result<Vec<PendingReplay>, DbError> {
    let sql = format!(
        "{PENDING_CTE} SELECT id, details, failures FROM counted \
          WHERE failures < $5 ORDER BY failures, created_at, id LIMIT $6"
    );
    let rows: Vec<(Uuid, serde_json::Value, i64)> = sqlx::query_as(&sql)
        .bind(EVENT_DEFERRED)
        .bind(EVENT_FAILED)
        .bind(EVENT_APPLIED)
        .bind(EVENT_RETIRED)
        .bind(max_failures)
        .bind(limit)
        .fetch_all(executor)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(event_id, details, failures)| PendingReplay {
            event_id,
            details,
            failures,
        })
        .collect())
}

/// The pending cascades held out of the replay window: those that have failed
/// `max_failures` times or more, oldest first. An operator reads why (the
/// failed rows' `details.reason`) and retires each with [`retire_pending`].
///
/// # Errors
/// `DbError::QueryFailed` on a failed query.
pub async fn stuck_replays<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    max_failures: i64,
) -> Result<Vec<PendingReplay>, DbError> {
    let sql = format!(
        "{PENDING_CTE} SELECT id, details, failures FROM counted \
          WHERE failures >= $5 ORDER BY created_at, id"
    );
    let rows: Vec<(Uuid, serde_json::Value, i64)> = sqlx::query_as(&sql)
        .bind(EVENT_DEFERRED)
        .bind(EVENT_FAILED)
        .bind(EVENT_APPLIED)
        .bind(EVENT_RETIRED)
        .bind(max_failures)
        .fetch_all(executor)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(event_id, details, failures)| PendingReplay {
            event_id,
            details,
            failures,
        })
        .collect())
}

/// The replay backlog at a glance (operator decision D9's staleness check,
/// `replay_deferred_cascades --report-only`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PendingSummary {
    /// Pending cascades still inside the replay window (failed fewer than
    /// `max_failures` times).
    pub pending: i64,
    /// Pending cascades held out as stuck (failed `max_failures` times or
    /// more) until an operator retires them.
    pub stuck: i64,
    /// Seconds since the oldest unanswered `cascade.deferred` /
    /// `cascade.admin_failed` row of any pending cascade, stuck ones included;
    /// `None` when nothing is pending.
    pub oldest_age_s: Option<i64>,
}

/// [`PendingSummary`] over the same pending set [`pending_replays`] and
/// [`stuck_replays`] read (the one `PENDING_CTE`). A read: it writes nothing.
///
/// # Errors
/// `DbError::QueryFailed` on a failed query.
pub async fn pending_summary<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    max_failures: i64,
) -> Result<PendingSummary, DbError> {
    let sql = format!(
        "{PENDING_CTE} SELECT count(*) FILTER (WHERE failures < $5), \
                              count(*) FILTER (WHERE failures >= $5), \
                              floor(extract(epoch FROM now() - min(created_at)))::bigint \
                         FROM counted"
    );
    let (pending, stuck, oldest_age_s): (i64, i64, Option<i64>) = sqlx::query_as(&sql)
        .bind(EVENT_DEFERRED)
        .bind(EVENT_FAILED)
        .bind(EVENT_APPLIED)
        .bind(EVENT_RETIRED)
        .bind(max_failures)
        .fetch_one(executor)
        .await?;
    Ok(PendingSummary {
        pending,
        stuck,
        oldest_age_s,
    })
}

/// The claims every OPEN `edge_retract` row of `edge` recorded as its
/// `sources` (the `open` set of [`PENDING_CTE`]: the rows the next applied row
/// for the edge closes), distinct and sorted.
///
/// Two acts on one edge before a replay record two deferrals, and the replay
/// runs only the oldest one's trigger; its applied row then closes both. The
/// replay re-derives this union, so the second act's claims are not lost.
/// Every row read here was written by 120's deferral definer, which derives the
/// sources from the session's own BBA rows, or by the maintenance connection:
/// no caller names them.
///
/// Maintenance connection only (an application session cannot read other
/// principals' audit rows). Run it in the replay's transaction after the edge
/// row is locked, so an act in flight on the edge has committed its deferral.
///
/// # Errors
/// `DbError::QueryFailed` on a failed query.
pub async fn open_edge_retract_sources<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    edge: Uuid,
) -> Result<Vec<Uuid>, DbError> {
    let sql = format!(
        "{PENDING_CTE} \
         SELECT DISTINCT s.v::uuid \
           FROM open o \
          CROSS JOIN LATERAL jsonb_array_elements_text( \
                CASE WHEN jsonb_typeof(o.details->'trigger'->'sources') = 'array' \
                     THEN o.details->'trigger'->'sources' ELSE '[]'::jsonb END) AS s(v) \
          WHERE o.cause = 'edge_retract' \
            AND s.v ~* '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$' \
            AND o.subj = regexp_replace(lower($5::text), '^urn:uuid:|[^0-9a-f]', '', 'g') \
          ORDER BY 1"
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(EVENT_DEFERRED)
        .bind(EVENT_FAILED)
        .bind(EVENT_APPLIED)
        .bind(EVENT_RETIRED)
        .bind(edge)
        .fetch_all(executor)
        .await?)
}

/// Retire the pending cascade that the `cascade.deferred` /
/// `cascade.admin_failed` row `event_id` belongs to, without replaying it: an
/// [`EVENT_RETIRED`] row carrying that row's cause and trigger, the operator's
/// label and reason. The cascade then leaves the pending set like an applied
/// one; a later deferral of the same (cause, subject) is pending again.
/// Returns the new row's id.
///
/// Maintenance connection only: 117 refuses a `cascade.*` row from any other
/// session.
///
/// # Errors
/// `DbError::NotFound` when `event_id` is not a deferred or failed cascade
/// row; `DbError::QueryFailed` on a failed or refused statement.
pub async fn retire_pending<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    event_id: Uuid,
    retired_by: &str,
    reason: &str,
) -> Result<Uuid, DbError> {
    let id = Uuid::new_v4();
    let done = sqlx::query(
        "INSERT INTO security_events (id, event_type, agent_id, success, details) \
         SELECT $1, $2, NULL, true, \
                jsonb_build_object('cause', d.details->'cause', \
                                   'trigger', d.details->'trigger', \
                                   'migration', 117, \
                                   'outcome', 'retired_by_operator', \
                                   'retired_event_id', d.id, \
                                   'retired_by', $4::text, \
                                   'reason', $5::text) \
           FROM security_events d \
          WHERE d.id = $3 AND d.event_type IN ($6, $7)",
    )
    .bind(id)
    .bind(EVENT_RETIRED)
    .bind(event_id)
    .bind(retired_by)
    .bind(reason)
    .bind(EVENT_DEFERRED)
    .bind(EVENT_FAILED)
    .execute(executor)
    .await?;
    if done.rows_affected() == 0 {
        return Err(DbError::NotFound {
            entity: "pending cascade row".to_string(),
            id: event_id,
        });
    }
    Ok(id)
}
