//! `end-elevation`: end one live elevation session now, from the maintenance
//! DSN (migration 125's `epigraph_end_elevation`, whose privileged arm ends
//! any person's session).
//!
//! The person ends their own session over the API (`POST
//! /api/v1/elevation/end`); a revoked role assignment, registration, refresh
//! family, client or confirming passkey ends it by trigger. This is the
//! operator's direct verb for the case none of those fit: a session to stop
//! NOW without taking anything else away from the person. The end is recorded
//! on the row (`ended_reason = 'ended'`, `ended_by` = the maintenance login)
//! and audited by 125's session audit (`platform.elevation_ended`); a session
//! already past its expiry is ended `expired`.
//!
//! One transaction, committed under `--apply` and rolled back otherwise (its
//! audit row with it), so a dry run says what would happen and leaves nothing.

use epigraph_db::{ElevationCeremony, EndReason};
use sqlx::PgConnection;
use uuid::Uuid;

/// End `session` (any person's). `true` when a live (un-ended) session was
/// ended; `false` when there was nothing to end (unknown, or already ended).
///
/// # Errors
/// The definer call fails (for example on a DSN that is not privileged, where
/// the definer ends only the stamped principal's own session and answers
/// `false` instead).
pub async fn end(conn: &mut PgConnection, session: Uuid, apply: bool) -> anyhow::Result<bool> {
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    let ended = ElevationCeremony::end(&mut tx, session, EndReason::Ended).await?;
    if apply {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(ended)
}
