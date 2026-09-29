//! Session advisory locks that keep each maintenance timer from overlapping
//! itself (operator decision D9, batch W12a).
//!
//! The replay of deferred cascades, the job-queue drain and the semantic
//! duplicate sweep each run as a scheduled or operator-run binary on the
//! maintenance DSN. systemd never overlaps a oneshot with itself, but an
//! operator running the bare binary beside the timer would, and two replays or
//! two drains racing over the same rows is the failure a lock rules out
//! cheaply. Each binary takes its OWN key, so a drain never blocks a replay.
//!
//! The lock is SESSION-level (`pg_try_advisory_lock`): it is held for as long
//! as the connection that took it stays open, which is the whole run of the
//! binary, and released when that connection closes (process exit included).
//! A caller keeps the connection it locked on for the whole run.
//!
//! The keys live here, in one place, so they cannot collide by accident;
//! `tests::the_three_keys_are_distinct` pins that.

use sqlx::PgConnection;

use crate::errors::DbError;

/// `replay_deferred_cascades` (the cascade replay timer).
pub const REPLAY_LOCK_KEY: i64 = 0x4550_4752_0119_0001;
/// `drain_jobs` (the job-queue drain timer).
pub const DRAIN_LOCK_KEY: i64 = 0x4550_4752_0119_0002;
/// `sweep_semantic_duplicates` (the operator's dedup sweep CLI).
pub const SWEEP_LOCK_KEY: i64 = 0x4550_4752_0119_0003;

/// Try to take the session advisory lock `key` on `conn` without waiting.
///
/// `Ok(true)`: taken, and held until `conn` closes or [`release`] runs.
/// `Ok(false)`: another session holds it; the caller should exit without
/// doing any work.
///
/// # Errors
/// `DbError::QueryFailed` if the statement fails.
pub async fn try_take(conn: &mut PgConnection, key: i64) -> Result<bool, DbError> {
    sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
}

/// Release the session advisory lock `key` on `conn`. Returns whether this
/// session held it.
///
/// # Errors
/// `DbError::QueryFailed` if the statement fails.
pub async fn release(conn: &mut PgConnection, key: i64) -> Result<bool, DbError> {
    sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .map_err(|source| DbError::QueryFailed { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_keys_are_distinct() {
        let keys = [REPLAY_LOCK_KEY, DRAIN_LOCK_KEY, SWEEP_LOCK_KEY];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "two maintenance binaries share an advisory lock key");
            }
        }
    }
}
