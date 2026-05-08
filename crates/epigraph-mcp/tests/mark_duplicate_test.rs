use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_marks_dup_only(pool: PgPool) {
    let canonical = seed_claim(&pool, "canonical", 0.5).await;
    let dup = seed_claim(&pool, "duplicate", 0.5).await;
    let server = build_test_server(pool.clone());

    epigraph_mcp::tools::supersede::mark_duplicate(
        &server,
        epigraph_mcp::types::MarkDuplicateParams {
            claim_id: dup.to_string(),
            canonical_id: canonical.to_string(),
            reason: None,
        },
    )
    .await
    .unwrap();

    let (sup, is_current): (Option<uuid::Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sup, Some(canonical));
    assert!(!is_current);

    let (canon_current,): (bool,) =
        sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(canonical)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(canon_current);
}
