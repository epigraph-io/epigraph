//! Integration test: DB → PropagationOrchestrator → propagate → DB.
//!
//! Inserts 3 claims (A supports B, B supports C) into Postgres, loads them
//! into a `PropagationOrchestrator` via `load_orchestrator_from_db`, runs
//! `update_and_propagate` against the loaded state, writes the resulting
//! truth values back, and verifies persistence via SELECT.
//!
//! This is a real DB→engine→DB round-trip: if the loader stops reading
//! truth_value (or stops creating dependents), the assertions on
//! orch state pre-propagation will catch it.

use engine_integration_tests::harness::*;
use epigraph_core::{ClaimId, TruthValue};
use sqlx::Row;

const PREFIX: &str = "[test-prop-db]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn propagation_persists_updated_truth_values() {
    let db = TestDb::setup().await;
    let _guard = PrefixGuard::new(&db.pool, PREFIX);

    // --- Setup: 3-claim chain A → B → C in DB ---
    let agent_uuid = create_test_agent(&db.pool).await;
    let claim_a_uuid =
        create_test_claim(&db.pool, agent_uuid, &format!("{PREFIX} root A"), 0.8).await;
    let claim_b_uuid =
        create_test_claim(&db.pool, agent_uuid, &format!("{PREFIX} mid B"), 0.5).await;
    let claim_c_uuid =
        create_test_claim(&db.pool, agent_uuid, &format!("{PREFIX} leaf C"), 0.5).await;

    create_test_edge(&db.pool, claim_a_uuid, claim_b_uuid, "supports").await;
    create_test_edge(&db.pool, claim_b_uuid, claim_c_uuid, "supports").await;

    // --- Load orchestrator FROM DB (the actual integration point) ---
    let mut orch = load_orchestrator_from_db(&db.pool, PREFIX).await;

    let claim_a_id = ClaimId::from_uuid(claim_a_uuid);
    let claim_b_id = ClaimId::from_uuid(claim_b_uuid);
    let claim_c_id = ClaimId::from_uuid(claim_c_uuid);

    // Pre-propagation sanity: orchestrator reflects DB state.
    // If the loader silently fails to read truth_value, this catches it.
    assert_eq!(
        orch.get_truth(claim_a_id).expect("A loaded").value(),
        0.8,
        "loader must read truth_value for A from DB"
    );
    assert_eq!(
        orch.get_truth(claim_b_id).expect("B loaded").value(),
        0.5,
        "loader must read truth_value for B from DB"
    );

    // --- Propagate: boost A's truth ---
    let updated = orch
        .update_and_propagate(claim_a_id, TruthValue::new(0.95).unwrap())
        .expect("propagation should succeed");
    assert!(updated.contains(&claim_b_id), "B updated");
    assert!(updated.contains(&claim_c_id), "C updated");

    let truth_b = orch.get_truth(claim_b_id).expect("B exists");
    let truth_c = orch.get_truth(claim_c_id).expect("C exists");
    assert!(truth_b.value() > 0.5, "B raised");
    assert!(truth_c.value() > 0.5, "C raised");
    assert!(
        truth_b.value() >= truth_c.value(),
        "B (closer to source) >= C"
    );

    // --- Write back and verify persistence ---
    for (uuid, value) in [
        (claim_b_uuid, truth_b.value()),
        (claim_c_uuid, truth_c.value()),
    ] {
        sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
            .bind(value)
            .bind(uuid)
            .execute(&db.pool)
            .await
            .expect("write back");
    }

    for (uuid, expected) in [
        (claim_b_uuid, truth_b.value()),
        (claim_c_uuid, truth_c.value()),
    ] {
        let row = sqlx::query("SELECT truth_value FROM claims WHERE id = $1")
            .bind(uuid)
            .fetch_one(&db.pool)
            .await
            .expect("fetch");
        let persisted: f64 = row.get("truth_value");
        assert!(
            (persisted - expected).abs() < 1e-9,
            "persisted {persisted} matches orchestrator {expected}"
        );
    }
}
