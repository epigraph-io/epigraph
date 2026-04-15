//! Integration test: DB -> PropagationOrchestrator -> verify updated truth values.
//!
//! Exercises the full round-trip: insert claims and edges into PostgreSQL,
//! load them into the in-memory PropagationOrchestrator, propagate a truth
//! update through a 3-claim chain, then write the results back and verify
//! persistence via SELECT.

use engine_integration_tests::harness::*;
use epigraph_core::{AgentId, Claim, ClaimId, TruthValue};
use epigraph_engine::{EvidenceType, PropagationOrchestrator};
use sqlx::Row;

const PREFIX: &str = "[test-prop-db]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn propagation_persists_updated_truth_values() {
    let db = TestDb::setup().await;

    // --- Setup: create agent + 3 claims forming a chain: A supports B supports C ---
    let agent_uuid = create_test_agent(&db.pool).await;
    let claim_a_uuid =
        create_test_claim(&db.pool, agent_uuid, &format!("{PREFIX} root claim A"), 0.8).await;
    let claim_b_uuid = create_test_claim(
        &db.pool,
        agent_uuid,
        &format!("{PREFIX} dependent claim B"),
        0.5,
    )
    .await;
    let claim_c_uuid =
        create_test_claim(&db.pool, agent_uuid, &format!("{PREFIX} leaf claim C"), 0.5).await;

    create_test_edge(&db.pool, claim_a_uuid, claim_b_uuid, "supports").await;
    create_test_edge(&db.pool, claim_b_uuid, claim_c_uuid, "supports").await;

    // --- Load claims from DB into orchestrator ---
    let agent_id = AgentId::from_uuid(agent_uuid);
    let public_key = [0u8; 32]; // matches harness create_test_agent padding

    let claim_a_id = ClaimId::from_uuid(claim_a_uuid);
    let claim_b_id = ClaimId::from_uuid(claim_b_uuid);
    let claim_c_id = ClaimId::from_uuid(claim_c_uuid);

    let claim_a = Claim::new(
        format!("{PREFIX} root claim A"),
        agent_id,
        public_key,
        TruthValue::new(0.8).unwrap(),
    );
    // Override the auto-generated id to match the DB row
    let claim_a = rebuild_claim_with_id(claim_a_id, claim_a);

    let claim_b = Claim::new(
        format!("{PREFIX} dependent claim B"),
        agent_id,
        public_key,
        TruthValue::new(0.5).unwrap(),
    );
    let claim_b = rebuild_claim_with_id(claim_b_id, claim_b);

    let claim_c = Claim::new(
        format!("{PREFIX} leaf claim C"),
        agent_id,
        public_key,
        TruthValue::new(0.5).unwrap(),
    );
    let claim_c = rebuild_claim_with_id(claim_c_id, claim_c);

    let mut orch = PropagationOrchestrator::new();
    orch.register_claim(claim_a).expect("register claim A");
    orch.register_claim(claim_b).expect("register claim B");
    orch.register_claim(claim_c).expect("register claim C");

    // A supports B, B supports C
    orch.add_dependency(
        claim_a_id,
        claim_b_id,
        true, // supporting
        0.8,  // strength
        EvidenceType::Empirical,
        0.0, // age_days (fresh evidence)
    )
    .expect("add A->B dependency");

    orch.add_dependency(
        claim_b_id,
        claim_c_id,
        true,
        0.7,
        EvidenceType::Logical,
        0.0,
    )
    .expect("add B->C dependency");

    // --- Propagate: boost A's truth to 0.95 ---
    let updated = orch
        .update_and_propagate(claim_a_id, TruthValue::new(0.95).unwrap())
        .expect("propagation should succeed");

    // Both B and C should have been updated
    assert!(
        updated.contains(&claim_b_id),
        "Claim B should be in the updated set"
    );
    assert!(
        updated.contains(&claim_c_id),
        "Claim C should be in the updated set"
    );

    // Truth values should have increased from their initial 0.5
    let truth_b = orch.get_truth(claim_b_id).expect("claim B should exist");
    let truth_c = orch.get_truth(claim_c_id).expect("claim C should exist");

    assert!(
        truth_b.value() > 0.5,
        "Claim B truth should have increased from 0.5, got {}",
        truth_b.value()
    );
    assert!(
        truth_c.value() > 0.5,
        "Claim C truth should have increased from 0.5, got {}",
        truth_c.value()
    );

    // B should be >= C (closer to the high-truth source)
    assert!(
        truth_b.value() >= truth_c.value(),
        "B ({}) should be >= C ({}): closer to high-truth source",
        truth_b.value(),
        truth_c.value()
    );

    // --- Write updated truths back to DB ---
    sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
        .bind(truth_b.value())
        .bind(claim_b_uuid)
        .execute(&db.pool)
        .await
        .expect("write back truth B");

    sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
        .bind(truth_c.value())
        .bind(claim_c_uuid)
        .execute(&db.pool)
        .await
        .expect("write back truth C");

    // --- Verify persistence via SELECT ---
    let row_b = sqlx::query("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_b_uuid)
        .fetch_one(&db.pool)
        .await
        .expect("fetch claim B");
    let persisted_b: f64 = row_b.get("truth_value");

    let row_c = sqlx::query("SELECT truth_value FROM claims WHERE id = $1")
        .bind(claim_c_uuid)
        .fetch_one(&db.pool)
        .await
        .expect("fetch claim C");
    let persisted_c: f64 = row_c.get("truth_value");

    assert!(
        (persisted_b - truth_b.value()).abs() < 1e-9,
        "Persisted B ({}) should match orchestrator B ({})",
        persisted_b,
        truth_b.value()
    );
    assert!(
        (persisted_c - truth_c.value()).abs() < 1e-9,
        "Persisted C ({}) should match orchestrator C ({})",
        persisted_c,
        truth_c.value()
    );

    // --- Cleanup ---
    cleanup_test_data(&db.pool, PREFIX).await;
}

/// Rebuild a `Claim` with a specific `ClaimId` (the DB-assigned UUID).
///
/// `Claim::new` auto-generates an ID. We need the ID to match the row
/// already inserted by `create_test_claim`, so we reconstruct via `with_id`.
fn rebuild_claim_with_id(id: ClaimId, src: Claim) -> Claim {
    Claim::with_id(
        id,
        src.content,
        src.agent_id,
        src.public_key,
        src.content_hash,
        src.trace_id,
        src.signature,
        src.truth_value,
        src.created_at,
        src.updated_at,
    )
}
