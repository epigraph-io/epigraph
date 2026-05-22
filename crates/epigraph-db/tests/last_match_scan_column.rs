//! Integration test for the `claims.last_match_scan_at` column (migration 036).
//!
//! Verifies that the column exists in `information_schema.columns`.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}

macro_rules! test_pool_or_skip {
    () => {{
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

#[sqlx::test(migrations = "../../migrations")]
async fn last_match_scan_at_column_exists(pool: PgPool) {

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM information_schema.columns
         WHERE table_schema='public' AND table_name='claims' AND column_name='last_match_scan_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("count query");

    assert_eq!(count.0, 1, "expected exactly one last_match_scan_at column");
}
