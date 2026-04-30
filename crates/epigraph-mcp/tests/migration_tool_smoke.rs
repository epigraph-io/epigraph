//! End-to-end smoke for the migrate-flat-workflows tool against a real DB pool.
//! Exercises the same helper module the bin uses, without shelling out.

mod common;

use epigraph_mcp::{
    migrate_flat::{build_extraction, fetch_unmigrated, mark_legacy_and_supersede, FlatContent},
    tools::workflow_ingest,
};
use uuid::Uuid;

/// Helper: seed a minimal agent and return its id.
async fn seed_test_agent(pool: &sqlx::PgPool) -> Uuid {
    let agent_id = Uuid::new_v4();
    common::insert_test_agent(pool, agent_id).await;
    agent_id
}

/// Helper: seed a flat-JSON workflow claim and return its id.
async fn seed_flat_workflow(
    pool: &sqlx::PgPool,
    goal: &str,
    steps: &[&str],
    tags: &[&str],
) -> Uuid {
    let agent_id = seed_test_agent(pool).await;
    let content = serde_json::json!({
        "goal": goal,
        "steps": steps,
        "tags": tags,
    });
    let content_str = content.to_string();
    sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['workflow'], '{}'::jsonb) \
         RETURNING id",
    )
    .bind(&content_str)
    .bind(blake3::hash(content_str.as_bytes()).as_bytes().as_slice())
    .bind(agent_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn migrate_one_flat_workflow(pool: sqlx::PgPool) {
    let claim_id = seed_flat_workflow(&pool, "Test goal one", &["s1", "s2"], &["test"]).await;

    // Fetch + parse + build extraction (the bin's first pass).
    let rows = fetch_unmigrated(&pool, Some(10), Some(claim_id))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let parsed: FlatContent = serde_json::from_str(&rows[0].content).unwrap();
    let extraction = build_extraction(&parsed, "test-goal-one".to_string(), 0, None);

    // Ingest into hierarchical tables.
    let result = workflow_ingest::do_ingest_workflow_via_pool(&pool, &extraction)
        .await
        .unwrap();

    // workflow_id is a String — parse it as Uuid.
    let new_workflow_id: Uuid = result
        .workflow_id
        .parse()
        .expect("workflow_id is a valid UUID");

    // Mark legacy + supersede (the bin's second pass).
    mark_legacy_and_supersede(&pool, claim_id, new_workflow_id)
        .await
        .unwrap();

    // Old claim now carries 'legacy_flat'.
    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        labels.iter().any(|l| l == "legacy_flat"),
        "old claim should be labeled legacy_flat"
    );

    // workflows row exists.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM workflows WHERE canonical_name = 'test-goal-one'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // supersedes edge from new workflow to old claim.
    let supersedes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 AND relationship = 'supersedes'",
    )
    .bind(new_workflow_id)
    .bind(claim_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(supersedes, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn migrate_idempotent_skips_already_migrated(pool: sqlx::PgPool) {
    let claim_id = seed_flat_workflow(&pool, "Idempotent test", &["s1"], &[]).await;

    // First migration round.
    let rows1 = fetch_unmigrated(&pool, None, Some(claim_id)).await.unwrap();
    assert_eq!(rows1.len(), 1);

    let parsed: FlatContent = serde_json::from_str(&rows1[0].content).unwrap();
    let extraction = build_extraction(&parsed, "idempotent-test".to_string(), 0, None);
    let result = workflow_ingest::do_ingest_workflow_via_pool(&pool, &extraction)
        .await
        .unwrap();
    let new_workflow_id: Uuid = result
        .workflow_id
        .parse()
        .expect("workflow_id is a valid UUID");
    mark_legacy_and_supersede(&pool, claim_id, new_workflow_id)
        .await
        .unwrap();

    // Second pass: fetch_unmigrated must skip this claim now.
    let rows2 = fetch_unmigrated(&pool, None, Some(claim_id)).await.unwrap();
    assert_eq!(
        rows2.len(),
        0,
        "already-migrated claim should be filtered out"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn migrate_handles_unparseable_content(pool: sqlx::PgPool) {
    // Seed a claim with the 'workflow' label but malformed content.
    let agent_id = seed_test_agent(&pool).await;
    let claim_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties) \
         VALUES ($1, $2, $3, 0.5, ARRAY['workflow'], '{}'::jsonb) \
         RETURNING id",
    )
    .bind("not valid json at all")
    .bind(blake3::hash(b"not valid json at all").as_bytes().as_slice())
    .bind(agent_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    // fetch_unmigrated returns the row (it filters by label, not by parseability).
    let rows = fetch_unmigrated(&pool, None, Some(claim_id)).await.unwrap();
    assert_eq!(rows.len(), 1);

    // serde_json::from_str on the content fails — the bin's first-pass loop
    // catches this and continues. We verify the parse failure here.
    let parsed: Result<FlatContent, _> = serde_json::from_str(&rows[0].content);
    assert!(parsed.is_err(), "malformed content should fail to parse");
}
