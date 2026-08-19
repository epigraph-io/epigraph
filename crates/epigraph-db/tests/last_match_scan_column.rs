//! Integration test for the `claims.last_match_scan_at` column (migration 036).
//!
//! Verifies that the column exists in `information_schema.columns`.

use sqlx::PgPool;

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
