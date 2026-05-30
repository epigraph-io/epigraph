//! Tests for `JobQueue::enqueue_unique_pending` on `PostgresJobQueue`.
//!
//! Dedup contract: an enqueue is skipped iff a job of the SAME `job_type` is
//! already in the `pending` state. `running` (or terminal) jobs of that type
//! do NOT block a fresh enqueue, and the dedup is scoped per job type.
//!
//! These are the boot-storm guard: the nightly cron fires ~60 s after every
//! process start, so without dedup each API restart drops another pending
//! `cluster_graph` row that later runs concurrently.

use epigraph_jobs::{EpiGraphJob, Job, JobQueue, JobState, PostgresJobQueue};
use sqlx::PgPool;

fn cluster_job() -> Job {
    EpiGraphJob::ClusterGraph {
        resolution: 1.0,
        retain_runs: 3,
    }
    .into_job()
    .expect("serialize ClusterGraph job")
}

fn theme_job() -> Job {
    EpiGraphJob::ThemeClusterRebuild {
        max_themes: 50,
        min_claims_per_theme: 5,
        skip_if_unchanged: true,
    }
    .into_job()
    .expect("serialize ThemeClusterRebuild job")
}

#[sqlx::test(migrations = "../../migrations")]
async fn skips_enqueue_when_same_type_already_pending(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());

    let first = q
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("first enqueue ok");
    assert!(first.is_some(), "first enqueue should insert a pending row");

    let second = q
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("second enqueue ok");
    assert!(
        second.is_none(),
        "second enqueue must be skipped while one cluster_graph is pending"
    );

    assert_eq!(
        q.count_by_state(JobState::Pending).await.unwrap(),
        1,
        "exactly one pending cluster_graph row should exist"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn enqueues_when_only_running_of_same_type_exists(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());

    q.enqueue_unique_pending(cluster_job())
        .await
        .unwrap()
        .expect("first enqueue inserts");

    // Claim it: pending -> running.
    let claimed = q.dequeue().await.expect("a pending job to claim");
    assert_eq!(claimed.state, JobState::Running);

    let again = q
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("enqueue ok");
    assert!(
        again.is_some(),
        "a RUNNING cluster_graph must not block a fresh enqueue (only pending blocks)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn dedup_is_scoped_per_job_type(pool: PgPool) {
    let q = PostgresJobQueue::new(pool.clone());

    assert!(q
        .enqueue_unique_pending(cluster_job())
        .await
        .unwrap()
        .is_some());
    assert!(
        q.enqueue_unique_pending(theme_job())
            .await
            .unwrap()
            .is_some(),
        "a pending cluster_graph must not block a theme_cluster_rebuild enqueue"
    );

    assert_eq!(q.count_by_state(JobState::Pending).await.unwrap(), 2);
}
