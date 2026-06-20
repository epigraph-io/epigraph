use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_marks_old_and_links_new(pool: PgPool) {
    let old = seed_claim(&pool, "v1", 0.5).await;
    let server = build_test_server(pool.clone());
    let auth = admin_auth();

    let result = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: old.to_string(),
            content: "v2".into(),
            truth_value: 0.7,
            reason: "newer evidence".into(),
        },
        Some(&auth),
    )
    .await
    .unwrap();
    let json = first_text(&result);
    let new_id = parse_uuid_field(&json, "new_claim_id");

    let (old_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(old)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!old_current);

    let (sup,): (Option<uuid::Uuid>,) =
        sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1")
            .bind(new_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sup, Some(old));
}
