//! `PostgresJobQueue::requeue_after` and the not-before time it writes
//! (`jobs.run_after`, migration 261, backlog 6cf042a9).
//!
//! The drain puts a retryable failure back to `pending` with
//! `run_after = now() + handler.backoff(..)`; the claims (`dequeue_of_types`,
//! the trait's `dequeue`) and `count_pending_of_types` must skip the row until
//! that time has come, and see it again once it has. Before 261 the drain wrote
//! no such time, so the next run re-claimed the row whatever the backoff said.

use epigraph_jobs::{Job, JobQueue, JobState, PostgresJobQueue};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

const TYPE: &str = "requeue_after_test";

fn types() -> Vec<String> {
    vec![TYPE.to_string()]
}

/// Enqueue a job of `TYPE`, claim it the way the drain does, and record a
/// failed attempt on it, as `JobRunner::process_job` does.
async fn claimed_and_failed(q: &PostgresJobQueue) -> Job {
    q.enqueue(Job::new(TYPE, serde_json::json!({})))
        .await
        .expect("enqueue");
    let mut job = q
        .dequeue_of_types(&types(), &[])
        .await
        .expect("dequeue")
        .expect("a pending job to claim");
    assert_eq!(job.state, JobState::Running, "CALIBRATION: the claim ran");
    job.retry_count += 1;
    job.error_message = Some("provider answered 429".to_string());
    job
}

/// Seconds from the database's `now()` to the row's `run_after`, and its state.
async fn wait_and_state(pool: &PgPool, id: Uuid) -> (f64, String, i32, Option<String>, bool) {
    sqlx::query_as(
        "SELECT extract(epoch FROM run_after - now())::float8, state, retry_count, \
                error_message, started_at IS NULL \
           FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("the job row")
}

/// Make the row due, as if its backoff had elapsed.
async fn backdate(pool: &PgPool, id: Uuid) {
    sqlx::query("UPDATE jobs SET run_after = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("back-date run_after");
}

/// A row requeued with a one-hour delay is `pending` with its attempt recorded
/// and `run_after` one hour out on the database clock; neither claim hands it
/// out and `count_pending_of_types` does not count it; once the time has come
/// both claims see it again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_requeued_row_is_not_claimed_or_counted_until_its_time(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    let job = claimed_and_failed(&q).await;
    let id: Uuid = job.id.into();

    let stored = q
        .requeue_after(&job, Duration::from_secs(3600))
        .await
        .expect("requeue");
    let (wait, state, retry_count, err, started_cleared) = wait_and_state(&pool, id).await;
    assert!(
        (3590.0..=3600.5).contains(&wait),
        "run_after is not one hour out on the database clock: {wait}s (stored {stored})"
    );
    assert_eq!(state, "pending");
    assert_eq!(retry_count, 1, "the failed attempt was not recorded");
    assert_eq!(err.as_deref(), Some("provider answered 429"));
    assert!(started_cleared, "started_at was left on a pending row");

    assert!(
        q.dequeue_of_types(&types(), &[])
            .await
            .expect("dequeue")
            .is_none(),
        "the drain's claim handed out a row whose backoff has not elapsed"
    );
    assert!(
        q.dequeue().await.is_none(),
        "the trait's claim handed out a row whose backoff has not elapsed"
    );
    assert_eq!(
        q.count_pending_of_types(&types(), &[])
            .await
            .expect("count"),
        0,
        "a row waiting out its backoff was counted as work the run could still do"
    );
    assert_eq!(
        q.count_by_state(JobState::Pending).await.expect("count"),
        1,
        "the deferred row is no longer pending"
    );

    backdate(&pool, id).await;
    assert_eq!(
        q.count_pending_of_types(&types(), &[])
            .await
            .expect("count"),
        1,
        "a row whose time has come is not counted"
    );
    let again = q.dequeue().await.expect("the trait's claim sees a due row");
    assert_eq!(again.id, job.id);
    // And the drain's claim, after putting it back once more.
    q.requeue_after(&again, Duration::from_secs(3600))
        .await
        .expect("requeue");
    backdate(&pool, id).await;
    let again = q
        .dequeue_of_types(&types(), &[])
        .await
        .expect("dequeue")
        .expect("the drain's claim sees a due row");
    assert_eq!(again.id, job.id);
}

/// A zero delay is due at once (nothing is over-blocked), and an absurd one
/// is clamped to `MAX_REQUEUE_DELAY` instead of failing the write.
#[sqlx::test(migrations = "../../migrations")]
async fn a_zero_delay_is_due_at_once_and_a_huge_one_is_clamped(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    let job = claimed_and_failed(&q).await;
    q.requeue_after(&job, Duration::ZERO)
        .await
        .expect("requeue");
    let again = q
        .dequeue_of_types(&types(), &[])
        .await
        .expect("dequeue")
        .expect("a zero backoff must be claimable at once");
    assert_eq!(again.id, job.id);

    q.requeue_after(&again, Duration::MAX)
        .await
        .expect("an absurd backoff is clamped, not an error");
    let (wait, state, ..) = wait_and_state(&pool, job.id.into()).await;
    let max = PostgresJobQueue::MAX_REQUEUE_DELAY.as_secs_f64();
    assert_eq!(state, "pending");
    assert!(
        (max - 10.0..=max + 0.5).contains(&wait),
        "the clamp did not hold: {wait}s"
    );
}

/// A deferred row is still `pending`: `enqueue_unique_pending` (the timer's
/// `enqueue_job --unique`) still sees it and adds no second job of its type.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deferred_row_still_blocks_a_unique_enqueue(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());
    let job = claimed_and_failed(&q).await;
    q.requeue_after(&job, Duration::from_secs(3600))
        .await
        .expect("requeue");
    let second = q
        .enqueue_unique_pending(Job::new(TYPE, serde_json::json!({})))
        .await
        .expect("enqueue unique");
    assert!(
        second.is_none(),
        "a unique enqueue stacked a second job behind a deferred one"
    );
}

/// Requeueing a job whose row is gone is an error, not a silent no-op.
#[sqlx::test(migrations = "../../migrations")]
async fn requeueing_a_missing_row_is_an_error(pool: PgPool) {
    let q = PostgresJobQueue::new(pool);
    let ghost = Job::new(TYPE, serde_json::json!({}));
    assert!(q.requeue_after(&ghost, Duration::ZERO).await.is_err());
}
