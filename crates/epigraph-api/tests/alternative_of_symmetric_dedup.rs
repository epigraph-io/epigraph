#![cfg(feature = "db")]
//! Inserting alternative_of(A,B) and alternative_of(B,A) must produce
//! exactly one edge row (the second insertion is a dedup hit on the
//! symmetric uniqueness index from migration 042).
//!
//! Uses `#[sqlx::test]` so each run gets a fresh ephemeral DB with all
//! migrations applied — sidesteps shared-DB pollution and the
//! migration-038 checksum skew on `epigraph_db_repo_test`.

mod common;

use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn alternative_of_dedupes_under_endpoint_swap(pool: PgPool) {
    let a = common::seed_claim(&pool, "alt-dedup-A").await;
    let b = common::seed_claim(&pool, "alt-dedup-B").await;

    let _id1 = common::insert_edge(&pool, a, b, "claim", "claim", "alternative_of").await;

    // Reversed direction — should be rejected by the unique index, not
    // silently double-recorded.
    let res = sqlx::query(
        "INSERT INTO edges (source_id, target_id, source_type, target_type, relationship) \
         VALUES ($1, $2, 'claim', 'claim', 'alternative_of')",
    )
    .bind(b)
    .bind(a)
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "reversed alternative_of insert must hit unique index, got: {res:?}"
    );

    let cnt: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE relationship = 'alternative_of' \
         AND ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cnt.0, 1, "exactly one row, got {}", cnt.0);
}
