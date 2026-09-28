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

// ---------------------------------------------------------------------------
// The drain timer's counting reaper (operator decision D9).
// ---------------------------------------------------------------------------

async fn insert_running(pool: &PgPool, job_type: &str, retry_count: i32, max_retries: i32) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO jobs \
            (id, job_type, payload, state, retry_count, max_retries, \
             created_at, updated_at, started_at) \
         VALUES ($1, $2, '{}'::jsonb, 'running', $3, $4, \
                 NOW() - interval '3 hours', NOW(), NOW() - interval '2 hours')",
    )
    .bind(id)
    .bind(job_type)
    .bind(retry_count)
    .bind(max_retries)
    .execute(pool)
    .await
    .expect("insert running job");
    id
}

async fn row(pool: &PgPool, id: Uuid) -> (String, i32, Option<String>, bool) {
    sqlx::query_as(
        "SELECT state, retry_count, error_message, completed_at IS NOT NULL FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the job row")
}

async fn make_stale_again(pool: &PgPool, id: Uuid) {
    sqlx::query(
        "UPDATE jobs SET state = 'running', started_at = NOW() - interval '2 hours' WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("run it again");
}

/// A job killed on every attempt (the unit's start timeout, say) is reaped
/// with the attempt counted, so the kill loop ends at `max_retries`: two
/// counted resets, then the third reap fails the row itself, says why, and
/// stops. A recent `running` row is left alone throughout.
#[sqlx::test(migrations = "../../migrations")]
async fn a_counted_reap_bounds_a_job_killed_on_every_attempt(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    let looping = insert_running(&pool, "cluster_graph", 0, 3).await;
    insert_running_started_minutes_ago(&pool, 5).await;

    for attempt in 1..=2 {
        let reaped = q
            .reap_stale_jobs_counting_attempts(Duration::from_secs(90 * 60))
            .await
            .unwrap();
        assert_eq!(reaped.len(), 1, "attempt {attempt}: {reaped:?}");
        assert!(!reaped[0].failed, "attempt {attempt}: {reaped:?}");
        let (state, retries, _, done) = row(&pool, looping).await;
        assert_eq!(
            (state.as_str(), retries, done),
            ("pending", attempt, false),
            "attempt {attempt}: the reap must reset the row AND count the attempt"
        );
        make_stale_again(&pool, looping).await;
    }
    let reaped = q
        .reap_stale_jobs_counting_attempts(Duration::from_secs(90 * 60))
        .await
        .unwrap();
    assert_eq!(reaped.len(), 1, "{reaped:?}");
    assert!(
        reaped[0].failed,
        "the last attempt's reap must fail the row: {reaped:?}"
    );
    let (state, retries, err, done) = row(&pool, looping).await;
    assert_eq!((state.as_str(), retries, done), ("failed", 3, true));
    assert_eq!(err.as_deref(), Some(epigraph_jobs::REAPED_SPENT_MESSAGE));

    let again = q
        .reap_stale_jobs_counting_attempts(Duration::from_secs(90 * 60))
        .await
        .unwrap();
    assert!(again.is_empty(), "a failed row was reaped again: {again:?}");
    assert_eq!(q.count_by_state(JobState::Running).await.unwrap(), 1);
}

/// The reap is decided by the row's own attempt budget, not its type (review
/// W12a-D7). A one-attempt row (`max_retries = 1`, as
/// `PrivatizationRepository::enqueue_job_conn` enqueues every job it writes:
/// the privatization types AND the unseal's `embedding_generation`) is reset
/// WITHOUT counting, whatever its type, so it is re-delivered to its handler
/// instead of failed before it runs. The control: a privatization row with a
/// multi-attempt budget, on its last attempt, IS failed by the reap, so it is
/// the budget, not a type exemption, that keeps the one-attempt rows alive.
#[sqlx::test(migrations = "../../migrations")]
async fn a_one_attempt_row_is_reset_without_counting_whatever_its_type(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    let one_attempt = [
        insert_running(&pool, "privatization_apply", 0, 1).await,
        insert_running(&pool, "embedding_generation", 0, 1).await,
        insert_running(&pool, "cluster_graph", 0, 1).await,
    ];
    let spent = insert_running(&pool, "privatization_apply", 2, 3).await;

    let reaped = q
        .reap_stale_jobs_counting_attempts(Duration::from_secs(90 * 60))
        .await
        .unwrap();
    assert_eq!(reaped.len(), 4, "{reaped:?}");
    for id in one_attempt {
        let r = reaped.iter().find(|r| r.id == id).expect("reaped");
        assert!(
            !r.failed,
            "a one-attempt {} row was failed: {reaped:?}",
            r.job_type
        );
        let (state, retries, err, done) = row(&pool, id).await;
        assert_eq!(
            (state.as_str(), retries, err, done),
            ("pending", 0, None, false),
            "a one-attempt {} row must go back to pending with its attempt uncounted",
            r.job_type
        );
    }
    let r = reaped.iter().find(|r| r.id == spent).expect("reaped");
    assert!(r.failed, "{reaped:?}");
    let (state, retries, err, done) = row(&pool, spent).await;
    assert_eq!((state.as_str(), retries, done), ("failed", 3, true));
    assert_eq!(err.as_deref(), Some(epigraph_jobs::REAPED_SPENT_MESSAGE));
}
