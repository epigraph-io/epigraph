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

/// Regression for backlog item router-c1cabe28: supersede_claim must null the
/// old claim's embedding in the same statement as the is_current=false flip.
/// The CHECK constraint `chk_deprecated_no_embedding` (migration 052) fires
/// per-statement; splitting the two assignments would violate it between them.
///
/// This test seeds an embedded claim, supersedes it via the MCP handler, then
/// asserts:
/// 1. The old claim's embedding is NULL.
/// 2. The new claim was created and is current.
///
/// If `embedding = NULL` is ever removed from the supersede UPDATE the test
/// will fail with a constraint violation before reaching the assertions.
#[sqlx::test(migrations = "../../migrations")]
async fn supersede_claim_nulls_embedding_on_superseded_claim(pool: PgPool) {
    // Seed an agent row so we can insert a claim with a real embedding.
    let agent_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind([0u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    // Insert the claim WITH a stub 1536-dim embedding so the constraint path
    // is exercised (is_current=true with embedding != NULL is valid; flipping
    // is_current=false without nulling is what breaks the constraint).
    let old_id = uuid::Uuid::new_v4();
    let stub_vec = {
        let mut v = vec!["0.0"; 1536];
        v[0] = "0.1";
        format!("[{}]", v.join(","))
    };
    sqlx::query(
        "INSERT INTO claims \
             (id, content, content_hash, agent_id, truth_value, is_current, embedding) \
         VALUES ($1, $2, $3, $4, 0.6, true, $5::vector)",
    )
    .bind(old_id)
    .bind("mcp-supersede-embedding-test")
    .bind(
        blake3::hash("mcp-supersede-embedding-test".as_bytes())
            .as_bytes()
            .as_slice(),
    )
    .bind(agent_id)
    .bind(stub_vec.as_str())
    .execute(&pool)
    .await
    .unwrap();

    let server = build_test_server(pool.clone());
    let auth = admin_auth();

    // Call the MCP supersede handler. If the handler fails to null the
    // embedding before flipping is_current=false this will surface as a
    // chk_deprecated_no_embedding constraint violation, not an assertion error.
    let result = epigraph_mcp::tools::supersede::supersede_claim(
        &server,
        epigraph_mcp::types::SupersedeClaimParams {
            claim_id: old_id.to_string(),
            content: "mcp-supersede-embedding-test-v2".into(),
            truth_value: 0.8,
            reason: "regression test for chk_deprecated_no_embedding".into(),
        },
        Some(&auth),
    )
    .await
    .expect("supersede_claim must succeed on an embedded claim");

    let json = first_text(&result);
    let new_id = parse_uuid_field(&json, "new_claim_id");

    // Old claim: is_current=false AND embedding=NULL.
    let (old_is_current, old_has_embedding): (bool, bool) = sqlx::query_as(
        "SELECT COALESCE(is_current, true), embedding IS NOT NULL FROM claims WHERE id = $1",
    )
    .bind(old_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(
        !old_is_current,
        "superseded claim {old_id} must have is_current = false"
    );
    assert!(
        !old_has_embedding,
        "superseded claim {old_id} embedding must be NULL \
         (chk_deprecated_no_embedding invariant)"
    );

    // New claim exists and is current.
    let new_is_current: bool =
        sqlx::query_scalar("SELECT COALESCE(is_current, true) FROM claims WHERE id = $1")
            .bind(new_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        new_is_current,
        "replacement claim {new_id} must be is_current = true"
    );
}
