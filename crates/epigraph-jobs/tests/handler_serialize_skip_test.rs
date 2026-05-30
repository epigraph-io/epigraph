//! The clustering handlers must skip (no-op) when another run already holds
//! their advisory lock, rather than launching a second concurrent run.
//!
//! The skip path returns `{"skipped_locked": true}` — distinct from the theme
//! handler's existing corpus-unchanged `{"skipped": true}` — and must NOT
//! touch the result tables.

use epigraph_jobs::cluster_graph::ClusterGraphHandler;
use epigraph_jobs::theme_cluster_rebuild::ThemeClusterRebuildHandler;
use epigraph_jobs::{
    EpiGraphJob, JobHandler, CLUSTER_GRAPH_LOCK_KEY, THEME_REBUILD_LOCK_KEY,
};
use sqlx::PgPool;
use std::sync::Arc;

async fn hold_lock(pool: &PgPool, key: i64) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.unwrap();
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(got, "test setup: should acquire advisory lock {key}");
    conn
}

#[sqlx::test(migrations = "../../migrations")]
async fn cluster_graph_handler_skips_when_lock_held(pool: PgPool) {
    let _holder = hold_lock(&pool, CLUSTER_GRAPH_LOCK_KEY).await;

    let handler = ClusterGraphHandler::new(Arc::new(pool.clone()));
    let job = EpiGraphJob::ClusterGraph {
        resolution: 1.0,
        retain_runs: 3,
    }
    .into_job()
    .unwrap();

    let result = handler
        .handle(&job)
        .await
        .expect("handler should succeed as a no-op skip while lock is held");

    assert_eq!(
        result.output.get("skipped_locked").and_then(|v| v.as_bool()),
        Some(true),
        "output should mark a lock-contended skip"
    );
    let runs: i64 = sqlx::query_scalar("SELECT count(*)::int8 FROM graph_cluster_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(runs, 0, "no clustering run should execute while the lock is held");
}

#[sqlx::test(migrations = "../../migrations")]
async fn theme_rebuild_handler_skips_when_lock_held(pool: PgPool) {
    let _holder = hold_lock(&pool, THEME_REBUILD_LOCK_KEY).await;

    let handler = ThemeClusterRebuildHandler::new(Arc::new(pool.clone()));
    // skip_if_unchanged=false so the ONLY thing that can skip is the lock.
    let job = EpiGraphJob::ThemeClusterRebuild {
        max_themes: 50,
        min_claims_per_theme: 5,
        skip_if_unchanged: false,
    }
    .into_job()
    .unwrap();

    let result = handler
        .handle(&job)
        .await
        .expect("handler should succeed as a no-op skip while lock is held");

    assert_eq!(
        result.output.get("skipped_locked").and_then(|v| v.as_bool()),
        Some(true),
        "output should mark a lock-contended skip"
    );
    let themes: i64 = sqlx::query_scalar("SELECT count(*)::int8 FROM claim_themes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(themes, 0, "no theme rebuild should execute while the lock is held");
}
