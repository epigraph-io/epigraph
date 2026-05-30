//! Coordination primitives that keep the heavy nightly jobs (`cluster_graph`,
//! `theme_cluster_rebuild`) from stacking and grinding the database.
//!
//! Background: the cron fires ~60 s after *every* `epigraph-api` boot, the
//! queue had no dedup, and the runner has multiple workers — so each restart
//! could stack another full clustering run on top of one already in flight,
//! pegging CPU and saturating Postgres (incident 2026-05-29). These helpers
//! serialize runs and bound runaway queries.
//!
//! Two complementary mechanisms:
//! - [`run_serialized`] — a DB-wide advisory lock so at most one run of a
//!   given kind executes at a time, across workers AND processes.
//! - [`apply_job_connection_settings`] — a per-connection `statement_timeout`
//!   so a runaway query (or a backend orphaned by a hard-killed process)
//!   self-aborts instead of running for hours.

use crate::JobError;
use sqlx::{Connection, PgConnection, PgPool};
use std::future::Future;
use std::time::Duration;

/// DB-wide advisory-lock key serializing concurrent `cluster_graph` runs.
///
/// Advisory-lock keys must be globally unique within the database. Keep this
/// distinct from [`THEME_REBUILD_LOCK_KEY`] and any future key.
pub const CLUSTER_GRAPH_LOCK_KEY: i64 = 770_010;

/// DB-wide advisory-lock key serializing concurrent `theme_cluster_rebuild` runs.
pub const THEME_REBUILD_LOCK_KEY: i64 = 770_011;

/// Run `body` while holding the DB-wide advisory lock `lock_key`.
///
/// - If the lock is already held by another session (another run in
///   progress), this skips: `body` is NOT executed and `Ok(None)` is
///   returned (skip-on-contention — redundant runs become cheap no-ops).
/// - Otherwise `body` runs while the lock is held, and the lock is ALWAYS
///   released afterwards — even if `body` returns `Err` — so it can never
///   leak onto a pooled connection.
///
/// The lock is held on a dedicated connection checked out from `pool`; the
/// `body` may use `pool` for its own work on other connections.
///
/// # Deployment requirement (session pinning)
/// This uses a *session-scoped* advisory lock held on an idle connection for
/// the whole run, so `pool` MUST connect directly to Postgres — NOT through a
/// transaction-mode pooler (e.g. PgBouncer `pool_mode = transaction`), where
/// `pg_advisory_lock`/`pg_advisory_unlock` could land on different backends
/// and the lock would silently become a no-op. The lock connection also sits
/// idle while `body` runs, so the database's `idle_session_timeout` must be
/// `0` (disabled) or comfortably exceed the longest run, or Postgres may reap
/// the session and release the lock early. Verified for the deployment DB on
/// 2026-05-30 (no pooler; `idle_session_timeout = 0`).
///
/// # Errors
/// Returns `JobError::ProcessingFailed` if acquiring the connection or
/// taking the lock fails, or whatever error `body` returns.
pub async fn run_serialized<T, Fut>(
    pool: &PgPool,
    lock_key: i64,
    body: Fut,
) -> Result<Option<T>, JobError>
where
    Fut: Future<Output = Result<T, JobError>>,
{
    let mut lock_conn = pool.acquire().await.map_err(|e| JobError::ProcessingFailed {
        message: format!("advisory lock: failed to acquire connection: {e}"),
    })?;

    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_key)
        .fetch_one(&mut *lock_conn)
        .await
        .map_err(|e| JobError::ProcessingFailed {
            message: format!("advisory lock: pg_try_advisory_lock({lock_key}) failed: {e}"),
        })?;

    if !acquired {
        tracing::info!(lock_key, "advisory lock contended; skipping serialized run");
        return Ok(None);
    }

    // Run the body holding the lock, then release unconditionally.
    let result = body.await;

    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *lock_conn)
        .await;

    if let Err(e) = unlocked {
        // Releasing failed (e.g. the connection died). Detach it from the
        // pool and close it so the session ends and Postgres drops the lock,
        // rather than returning a lock-holding connection to the pool.
        tracing::error!(
            lock_key,
            error = %e,
            "failed to release advisory lock; closing connection to force release"
        );
        let raw: PgConnection = lock_conn.detach();
        let _ = raw.close().await;
    }

    result.map(Some)
}

/// Apply the standard per-connection settings for the background job pool.
///
/// Sets `statement_timeout` so any single statement a clustering run issues
/// is bounded; this also makes a backend orphaned by a hard-killed process
/// self-abort instead of grinding indefinitely. Intended for use in the job
/// pool's `after_connect` hook so every connection the jobs use is bounded.
///
/// # Errors
/// Returns `sqlx::Error` if the `SET` fails.
pub async fn apply_job_connection_settings(
    conn: &mut PgConnection,
    statement_timeout: Duration,
) -> Result<(), sqlx::Error> {
    // `SET` cannot be parameterized; the value is our own (not user input).
    let ms = statement_timeout.as_millis();
    sqlx::query(&format!("SET statement_timeout = {ms}"))
        .execute(conn)
        .await?;
    Ok(())
}
