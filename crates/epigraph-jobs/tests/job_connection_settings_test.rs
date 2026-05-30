//! Tests for `apply_job_connection_settings` — sets a per-connection
//! `statement_timeout` so a runaway clustering query (or an orphaned backend
//! left by a hard-killed process) self-aborts instead of grinding for hours.
//!
//! In production this runs in the job pool's `after_connect`, so every
//! connection the cluster jobs use is bounded.

use epigraph_jobs::apply_job_connection_settings;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "../../migrations")]
async fn sets_statement_timeout_on_connection(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    apply_job_connection_settings(&mut conn, Duration::from_secs(45 * 60))
        .await
        .expect("apply settings");

    let shown: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        shown, "45min",
        "statement_timeout should be set to 45 minutes"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn fresh_connection_has_no_statement_timeout(pool: PgPool) {
    // Control: proves the change above is meaningful (default is disabled).
    let mut conn = pool.acquire().await.unwrap();
    let shown: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(shown, "0", "a fresh connection has statement_timeout disabled");
}
