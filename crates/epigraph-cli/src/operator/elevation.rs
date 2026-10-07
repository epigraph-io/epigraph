//! `end-elevation` and `list-elevations`: the operator's break-glass verbs
//! for elevation sessions, from the maintenance DSN (migration 125's
//! `epigraph_end_elevation`, whose privileged arm ends any person's session).
//!
//! The person ends their own session over the API (`POST
//! /api/v1/elevation/end`); a revoked role assignment, registration, refresh
//! family, client or confirming passkey ends it by trigger. This is the
//! operator's direct verb for the case none of those fit: sessions to stop
//! NOW without taking anything else away from the person. `--session` ends
//! one; `--person` ends every un-ended session of that person (one per
//! refresh family). Each end is recorded on the row (`ended_reason =
//! 'ended'`, `ended_by` = the maintenance login) and audited by 125's session
//! audit (`platform.elevation_ended`), which carries the required `--reason`
//! as `operator_reason` (stamped in the transaction setting
//! `epigraph.elevation_end_reason`, which the audit reads only for a
//! privileged ender); a session already past its expiry is ended `expired`.
//!
//! One transaction, committed under `--apply` and rolled back otherwise (its
//! audit rows with it), so a dry run says what would happen and leaves nothing.
//!
//! `list-elevations` reads the rows directly (the maintenance DSN reads every
//! session). `--live` filters by the row's own columns (un-ended, unexpired);
//! it does not evaluate the per-statement liveness re-checks, which a
//! privileged login is never answered by anyway.

use chrono::{DateTime, Utc};
use epigraph_db::{ElevationCeremony, EndReason};
use sqlx::PgConnection;
use uuid::Uuid;

/// What `end-elevation` ends.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// One session, by id.
    Session(Uuid),
    /// Every un-ended session of this person.
    Person(Uuid),
}

/// End the target's sessions, recording `reason`. One `(session, ended)` per
/// session tried: `ended` is `false` when there was nothing to end (unknown,
/// or already ended). A person with no un-ended session yields no entry.
///
/// # Errors
/// A blank reason; the definer call fails (for example on a DSN that is not
/// privileged, where the definer ends only the stamped principal's own
/// session and answers `false` instead).
pub async fn end(
    conn: &mut PgConnection,
    target: Target,
    reason: &str,
    apply: bool,
) -> anyhow::Result<Vec<(Uuid, bool)>> {
    let reason = reason.trim();
    anyhow::ensure!(!reason.is_empty(), "--reason must say why");
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    sqlx::query("SELECT set_config('epigraph.elevation_end_reason', $1, true)")
        .bind(reason)
        .execute(&mut *tx)
        .await?;
    let sessions: Vec<Uuid> = match target {
        Target::Session(id) => vec![id],
        Target::Person(person) => {
            sqlx::query_scalar(
                "SELECT id FROM public.elevation_sessions \
                  WHERE person_agent_id = $1 AND ended_at IS NULL \
                  ORDER BY started_at, id",
            )
            .bind(person)
            .fetch_all(&mut *tx)
            .await?
        }
    };
    let mut outcomes = Vec::with_capacity(sessions.len());
    for session in sessions {
        let ended = ElevationCeremony::end(&mut tx, session, EndReason::Ended).await?;
        outcomes.push((session, ended));
    }
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcomes)
}

/// One elevation session as `list-elevations` prints it.
#[derive(Debug, sqlx::FromRow)]
pub struct ElevationRow {
    pub id: Uuid,
    pub person_agent_id: Uuid,
    pub mode: String,
    pub family_id: Uuid,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub ended_reason: Option<String>,
    pub ended_by: Option<String>,
}

/// Elevation sessions, newest first; only `person`'s when given; only
/// un-ended, unexpired ones when `live`.
///
/// # Errors
/// The read fails.
pub async fn list(
    conn: &mut PgConnection,
    person: Option<Uuid>,
    live: bool,
) -> anyhow::Result<Vec<ElevationRow>> {
    let rows = sqlx::query_as::<_, ElevationRow>(
        "SELECT id, person_agent_id, mode, family_id, reason, started_at, expires_at, \
                ended_at, ended_reason, ended_by \
           FROM public.elevation_sessions \
          WHERE ($1::uuid IS NULL OR person_agent_id = $1) \
            AND (NOT $2 OR (ended_at IS NULL AND expires_at > now())) \
          ORDER BY started_at DESC, id",
    )
    .bind(person)
    .bind(live)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}

/// One tab-separated line per session: its id, person, mode, family, state
/// (`live-until=<expiry>`, `expired-unended`, or `ended=<reason>` with when
/// and by whom), when it started, and the person's stated reason.
#[must_use]
pub fn describe(row: &ElevationRow) -> String {
    let state = match (&row.ended_at, &row.ended_reason) {
        (Some(at), reason) => format!(
            "ended={}\tended_at={}\tended_by={}",
            reason.as_deref().unwrap_or("-"),
            at.to_rfc3339(),
            row.ended_by.as_deref().unwrap_or("-"),
        ),
        (None, _) if row.expires_at <= Utc::now() => {
            format!(
                "expired-unended\texpires_at={}",
                row.expires_at.to_rfc3339()
            )
        }
        (None, _) => format!("live-until={}", row.expires_at.to_rfc3339()),
    };
    format!(
        "{}\tperson={}\tmode={}\tfamily={}\t{}\tstarted_at={}\treason={:?}",
        row.id,
        row.person_agent_id,
        row.mode,
        row.family_id,
        state,
        row.started_at.to_rfc3339(),
        row.reason,
    )
}
