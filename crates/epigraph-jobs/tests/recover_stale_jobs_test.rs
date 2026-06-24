//! Characterization tests for `PostgresJobQueue::recover_stale_jobs`.
//!
//! `recover_stale_jobs` already exists; the serialize-fix wires it into a
//! periodic reaper so a `running` row orphaned by a hard-killed process is
//! reset to `pending` (and re-run) rather than wedging the nightly forever.
//! These tests lock in the contract the reaper depends on: rows older than
//! the threshold are recovered; recent ones are left running.
//!
//! Threshold must exceed `statement_timeout` (45 min) so a legitimately
//! running job is never reset out from under itself — the reaper uses 90 min.

use epigraph_jobs::{JobState, PostgresJobQueue};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn insert_running_started_minutes_ago(pool: &PgPool, minutes: i32) {
    sqlx::query(
        "INSERT INTO jobs \
            (id, job_type, payload, state, retry_count, max_retries, \
             created_at, updated_at, started_at) \
         VALUES ($1, 'cluster_graph', '{}'::jsonb, 'running', 0, 1, \
                 NOW() - make_interval(mins => $2), NOW(), \
                 NOW() - make_interval(mins => $2))",
    )
    .bind(Uuid::new_v4())
    .bind(minutes)
    .execute(pool)
    .await
    .expect("insert running job");
}

#[sqlx::test(migrations = "../../migrations")]
async fn recovers_running_job_older_than_threshold(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    insert_running_started_minutes_ago(&pool, 120).await; // 2h ago

    let recovered = q
        .recover_stale_jobs(Duration::from_secs(90 * 60))
        .await
        .unwrap();

    assert_eq!(recovered, 1, "the 2h-old running job should be recovered");
    assert_eq!(q.count_by_state(JobState::Pending).await.unwrap(), 1);
    assert_eq!(q.count_by_state(JobState::Running).await.unwrap(), 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn leaves_recent_running_job_untouched(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    insert_running_started_minutes_ago(&pool, 5).await; // 5 min ago

    let recovered = q
        .recover_stale_jobs(Duration::from_secs(90 * 60))
        .await
        .unwrap();

    assert_eq!(recovered, 0, "a 5-min-old running job is not stale");
    assert_eq!(q.count_by_state(JobState::Running).await.unwrap(), 1);
}
