//! `PostgresJobQueue::enqueue_unique_pending`: enqueue a job only when no job
//! of its type is already `pending`, atomically among its callers (the
//! operator CLI `enqueue_job --unique`, which a nightly timer runs).
//!
//! Pinned here:
//! * twice in a row: one pending row, and the second call answers `None`;
//! * the row it writes is the row `enqueue` would write for the same job;
//! * a pending job of ANOTHER type, or a non-pending job of the same type,
//!   does not block it;
//! * the check and the insert are serialized by a transaction-scoped advisory
//!   lock on the job type. The test holds that lock while it inserts a pending
//!   row it has not committed yet, starts the call, then commits: the call must
//!   wait for the lock and then see the committed row. Without the lock (or
//!   with the lock folded into the INSERT, whose snapshot would predate the
//!   wait) the call inserts a second pending row.

use std::time::Duration;

use epigraph_jobs::{EpiGraphJob, Job, JobQueue, PostgresJobQueue, ENQUEUE_UNIQUE_LOCK_CLASS};
use sqlx::PgPool;

fn cluster_job() -> Job {
    EpiGraphJob::ClusterGraph {
        resolution: 1.0,
        retain_runs: 3,
    }
    .into_job()
    .expect("serialize")
}

async fn pending_of(pool: &PgPool, job_type: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM jobs WHERE job_type = $1 AND state = 'pending'")
        .bind(job_type)
        .fetch_one(pool)
        .await
        .expect("count pending")
}

type RowShape = (
    String,
    serde_json::Value,
    String,
    i32,
    i32,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
);

async fn row(pool: &PgPool, id: uuid::Uuid) -> RowShape {
    sqlx::query_as(
        "SELECT job_type, payload, state, retry_count, max_retries, started_at, completed_at, \
         error_message FROM jobs WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read the row")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_unique_enqueue_of_a_pending_type_writes_nothing(pool: PgPool) {
    let queue = PostgresJobQueue::new(pool.clone());
    let first = queue
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("first enqueue");
    let first = first.expect("nothing pending: the first call enqueues");
    let second = queue
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("second enqueue");
    assert_eq!(second, None, "a cluster_graph job is already pending");
    assert_eq!(pending_of(&pool, "cluster_graph").await, 1);

    // The unique path writes the row the plain path writes.
    let plain = queue.enqueue(cluster_job()).await.expect("plain enqueue");
    let (u, p) = (
        row(&pool, first.as_uuid()).await,
        row(&pool, plain.as_uuid()).await,
    );
    assert_eq!(u, p);
    assert_eq!(u.0, "cluster_graph");
    assert_eq!(u.2, "pending");
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_a_pending_job_of_the_same_type_blocks(pool: PgPool) {
    let queue = PostgresJobQueue::new(pool.clone());
    // Another type pending: no effect.
    queue
        .enqueue(Job::new("data_cleanup", serde_json::json!({})))
        .await
        .expect("enqueue another type");
    // The same type, but completed and running: no effect either.
    for state in ["completed", "running"] {
        let id = queue.enqueue(cluster_job()).await.expect("seed");
        sqlx::query("UPDATE jobs SET state = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(state)
            .execute(&pool)
            .await
            .expect("move the seed out of pending");
    }
    let got = queue
        .enqueue_unique_pending(cluster_job())
        .await
        .expect("enqueue");
    assert!(got.is_some(), "no cluster_graph job was pending");
    assert_eq!(pending_of(&pool, "cluster_graph").await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_check_waits_for_a_concurrent_unique_enqueue_to_commit(pool: PgPool) {
    let queue = PostgresJobQueue::new(pool.clone());

    // A concurrent caller, mid-flight: it holds the lock for cluster_graph and
    // has inserted its pending row, but not committed it.
    let mut other = pool.begin().await.expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(ENQUEUE_UNIQUE_LOCK_CLASS)
        .bind("cluster_graph")
        .execute(&mut *other)
        .await
        .expect("take the lock");
    let job = cluster_job();
    sqlx::query(
        "INSERT INTO jobs (id, job_type, payload, state, retry_count, max_retries, \
         created_at, updated_at) VALUES ($1, $2, $3, 'pending', 0, 3, now(), now())",
    )
    .bind(job.id.as_uuid())
    .bind(&job.job_type)
    .bind(&job.payload)
    .execute(&mut *other)
    .await
    .expect("the concurrent caller's row");

    let racer = tokio::spawn({
        let queue = queue.clone();
        async move { queue.enqueue_unique_pending(cluster_job()).await }
    });
    // Long enough for the call to reach the lock and block on it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !racer.is_finished(),
        "the unique enqueue returned while another caller held the lock"
    );
    other.commit().await.expect("commit the concurrent caller");

    let got = tokio::time::timeout(Duration::from_secs(30), racer)
        .await
        .expect("the unique enqueue never returned")
        .expect("join")
        .expect("enqueue");
    assert_eq!(got, None, "it must see the row committed while it waited");
    assert_eq!(pending_of(&pool, "cluster_graph").await, 1);
}
