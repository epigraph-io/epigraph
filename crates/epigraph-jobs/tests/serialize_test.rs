//! Tests for `run_serialized` — the DB-wide advisory-lock wrapper that
//! serializes the heavy clustering jobs across workers AND processes.
//!
//! Contract:
//! - If the lock is already held (another run in progress), skip: the body
//!   does NOT run and `Ok(None)` is returned (skip-on-contention).
//! - Otherwise run the body holding the lock, and ALWAYS release the lock
//!   afterwards — even when the body errors — so it never leaks onto a
//!   pooled connection.

use epigraph_jobs::{run_serialized, JobError};
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const KEY: i64 = 770_001;

/// Count sessions currently holding the advisory lock for `KEY`.
/// For a single-bigint `pg_advisory_lock(v)` with `v < 2^31`, pg_locks
/// records classid=0, objid=v, objsubid=1.
async fn advisory_holders(pool: &PgPool, key: i64) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*)::int8 FROM pg_locks \
         WHERE locktype = 'advisory' AND classid::int8 = 0 \
           AND objid::int8 = $1 AND objsubid = 1",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("query pg_locks")
}

#[sqlx::test(migrations = "../../migrations")]
async fn skips_when_lock_already_held(pool: PgPool) {
    // Hold the lock on an independent session.
    let mut holder = pool.acquire().await.unwrap();
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(KEY)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    assert!(got, "test setup: holder should acquire the lock");

    let ran = Arc::new(AtomicBool::new(false));
    let ran_in_body = Arc::clone(&ran);
    let outcome: Option<()> = run_serialized(&pool, KEY, async move {
        ran_in_body.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
    .expect("run_serialized should not error on contention");

    assert!(
        outcome.is_none(),
        "must skip (return None) when the lock is held by another session"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "body must NOT execute when the lock is contended"
    );

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(KEY)
        .execute(&mut *holder)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn runs_body_and_releases_lock(pool: PgPool) {
    let ran = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&ran);
    let outcome: Option<u32> = run_serialized(&pool, KEY, async move {
        r.store(true, Ordering::SeqCst);
        Ok(7)
    })
    .await
    .unwrap();

    assert_eq!(
        outcome,
        Some(7),
        "body result is returned when lock acquired"
    );
    assert!(ran.load(Ordering::SeqCst), "body ran");
    assert_eq!(
        advisory_holders(&pool, KEY).await,
        0,
        "advisory lock must be released after a successful run"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn releases_lock_when_body_errors(pool: PgPool) {
    let outcome: Result<Option<()>, JobError> = run_serialized(&pool, KEY, async {
        Err(JobError::ProcessingFailed {
            message: "boom".into(),
        })
    })
    .await;

    assert!(
        matches!(outcome, Err(JobError::ProcessingFailed { .. })),
        "body error must propagate"
    );
    assert_eq!(
        advisory_holders(&pool, KEY).await,
        0,
        "advisory lock must be released even when the body errors"
    );
}
