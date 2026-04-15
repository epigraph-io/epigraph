//! Integration tests: DB claims → ReputationCalculator → verify trust scores.
//!
//! Test 1: Load 5 claims from DB, build ClaimOutcome vector, compute reputation,
//!         verify trust > 0.5 for an agent with high-truth claims.
//!
//! Test 2: Create 2 claims with CONTRADICTS edge, verify ReasoningEngine detects
//!         the contradiction (conflict classification from DB data).

use engine_integration_tests::harness::*;
use epigraph_engine::reputation::{ClaimOutcome, ReputationCalculator};
use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use sqlx::Row;

const PREFIX: &str = "[test-trust-db]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn trust_computed_from_db_claims() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    // Insert 5 high-truth claims
    let mut claim_ids = Vec::new();
    for i in 0..5 {
        let id = create_test_claim(
            &db.pool,
            agent,
            &format!("{PREFIX} trust-claim-{i}"),
            0.8 + (i as f64) * 0.02, // 0.80, 0.82, 0.84, 0.86, 0.88
        )
        .await;
        claim_ids.push(id);
    }

    // Load truth values from DB, build ClaimOutcome vector
    let rows = sqlx::query("SELECT truth_value FROM claims WHERE content LIKE $1 ORDER BY content")
        .bind(format!("{PREFIX} trust-claim-%"))
        .fetch_all(&db.pool)
        .await
        .expect("Failed to load claims from DB");

    assert_eq!(rows.len(), 5, "Should have loaded 5 claims from DB");

    let outcomes: Vec<ClaimOutcome> = rows
        .iter()
        .map(|row| {
            let truth_value: f64 = row.get("truth_value");
            ClaimOutcome {
                truth_value,
                age_days: 5.0, // recent claims
                was_refuted: false,
            }
        })
        .collect();

    let calc = ReputationCalculator::new();
    let trust = calc.calculate(&outcomes).expect("reputation calculation");

    // 5 claims with truth 0.80..0.88, all recent, none refuted → trust > 0.5
    assert!(
        trust > 0.5,
        "Agent with high-truth claims should have trust > 0.5, got: {trust}"
    );

    // Also verify it's bounded below max (0.95) — only 5 claims, stability penalty applies
    assert!(
        trust <= 0.95,
        "Trust should be bounded by max_reputation, got: {trust}"
    );

    cleanup_test_data(&db.pool, PREFIX).await;
}

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn conflict_classified_from_db_contradicts_edge() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    // Create two claims with an imbalance in truth values
    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} strong-claim"), 0.9).await;
    let claim_b = create_test_claim(&db.pool, agent, &format!("{PREFIX} weak-claim"), 0.3).await;

    // Create a target claim that both relate to
    let target = create_test_claim(&db.pool, agent, &format!("{PREFIX} target-claim"), 0.6).await;

    // A supports target, B contradicts target
    create_test_edge(&db.pool, claim_a, target, "supports").await;
    create_test_edge(&db.pool, claim_b, target, "contradicts").await;

    // Load claims and edges from DB
    let claim_rows = sqlx::query("SELECT id, truth_value FROM claims WHERE content LIKE $1")
        .bind(format!("{PREFIX}%"))
        .fetch_all(&db.pool)
        .await
        .expect("load claims");

    let claims: Vec<ReasoningClaim> = claim_rows
        .iter()
        .map(|row| ReasoningClaim {
            id: row.get("id"),
            truth_value: row.get("truth_value"),
        })
        .collect();

    let edge_rows = sqlx::query(
        "SELECT e.source_id, e.target_id, e.relationship \
         FROM edges e \
         JOIN claims cs ON cs.id = e.source_id \
         WHERE cs.content LIKE $1",
    )
    .bind(format!("{PREFIX}%"))
    .fetch_all(&db.pool)
    .await
    .expect("load edges");

    let edges: Vec<ReasoningEdge> = edge_rows
        .iter()
        .map(|row| {
            let rel: String = row.get("relationship");
            ReasoningEdge {
                source_id: row.get("source_id"),
                target_id: row.get("target_id"),
                relationship: rel.to_lowercase(),
                strength: 0.8, // default strength for DB edges
            }
        })
        .collect();

    let result = ReasoningEngine::analyze(&claims, &edges);

    // Should detect at least one contradiction: A supports target while B refutes it
    assert!(
        !result.contradictions.is_empty(),
        "ReasoningEngine should detect contradiction from CONTRADICTS edge, got 0 contradictions"
    );

    // Verify the contradiction involves our target claim
    let found = result.contradictions.iter().any(|c| c.target == target);
    assert!(found, "Contradiction should involve the target claim");

    cleanup_test_data(&db.pool, PREFIX).await;
}
