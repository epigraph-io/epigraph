// Regression tests for the C-1 FK violation
// (mass_functions_perspective_id_fkey).
//
// Background: commit 355cf4f passed `evidence.id` as
// `mass_functions.perspective_id` to defeat the unique constraint on
// `(claim, frame, agent, perspective_id=NULL)`, but never inserted a row
// into `perspectives` for that id — every multi-evidence update path
// (report_workflow_outcome, update_with_evidence) hit FK violation.

use epigraph_db::{MassFunctionRepository, PerspectiveRepository};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool, key_byte: u8) -> sqlx::Result<Uuid> {
    let agent_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key) \
         VALUES ($1, decode(repeat($2, 32), 'hex'))",
    )
    .bind(agent_id)
    .bind(format!("{key_byte:02x}"))
    .execute(pool)
    .await?;
    Ok(agent_id)
}

async fn seed_claim(pool: &PgPool, agent_id: Uuid, hash_byte: u8) -> sqlx::Result<Uuid> {
    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'fk-regression-claim', decode(repeat($2, 32), 'hex'), $3)",
    )
    .bind(claim_id)
    .bind(format!("{hash_byte:02x}"))
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(claim_id)
}

async fn seed_frame(pool: &PgPool) -> sqlx::Result<Uuid> {
    let frame_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) \
         VALUES ($1, $2, ARRAY['TRUE','FALSE']::text[])",
    )
    .bind(frame_id)
    .bind(format!("fk-regression-{frame_id}"))
    .execute(pool)
    .await?;
    Ok(frame_id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn ensure_evidence_perspective_creates_row(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xAA).await?;
    let evidence_id = Uuid::new_v4();

    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_id, Some(agent_id))
        .await
        .expect("ensure_evidence_perspective should succeed");

    let row = PerspectiveRepository::get_by_id(&pool, evidence_id)
        .await
        .expect("get_by_id should succeed")
        .expect("perspective row should exist after ensure");
    assert_eq!(row.id, evidence_id);
    assert_eq!(row.name, "evidence_grounded");
    assert_eq!(row.owner_agent_id, Some(agent_id));
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn ensure_evidence_perspective_is_idempotent(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xBB).await?;
    let evidence_id = Uuid::new_v4();

    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_id, Some(agent_id))
        .await
        .expect("first call");
    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_id, Some(agent_id))
        .await
        .expect("second call should be a no-op, not a duplicate-key error");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM perspectives WHERE id = $1")
        .bind(evidence_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn mass_function_store_with_synthetic_perspective_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let agent_id = seed_agent(&pool, 0xCC).await?;
    let claim_id = seed_claim(&pool, agent_id, 0xCD).await?;
    let frame_id = seed_frame(&pool).await?;
    let evidence_id = Uuid::new_v4();
    let masses = json!({"TRUE": 0.7, "FALSE": 0.0, "{TRUE,FALSE}": 0.3});

    // Without ensure: storing with a non-existent perspective_id must fail.
    // Proves the FK is real and that the bug pre-fix wasn't a phantom.
    let bad = MassFunctionRepository::store_with_perspective(
        &pool,
        claim_id,
        frame_id,
        Some(agent_id),
        Some(evidence_id),
        &masses,
        None,
        Some("auto_wire"),
        Some(0.7),
        Some("observation"),
        "unknown",
        None,
    )
    .await;
    assert!(
        bad.is_err(),
        "store with unknown perspective_id should violate FK"
    );

    // With ensure: the FK is satisfied and the store succeeds.
    PerspectiveRepository::ensure_evidence_perspective(&pool, evidence_id, Some(agent_id))
        .await
        .expect("ensure should succeed");
    MassFunctionRepository::store_with_perspective(
        &pool,
        claim_id,
        frame_id,
        Some(agent_id),
        Some(evidence_id),
        &masses,
        None,
        Some("auto_wire"),
        Some(0.7),
        Some("observation"),
        "unknown",
        None,
    )
    .await
    .expect("store with materialized perspective should succeed");
    Ok(())
}
