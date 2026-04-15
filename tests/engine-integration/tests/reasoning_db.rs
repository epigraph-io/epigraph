//! Integration test: DB → ReasoningEngine → transitive support detection.
//!
//! Creates an A→B→C supports chain in PostgreSQL, loads claims and edges,
//! runs ReasoningEngine::analyze, and verifies transitive support from A to C.

use engine_integration_tests::harness::*;
use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use sqlx::Row;

const PREFIX: &str = "[test-reasoning-db]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn transitive_support_detected_from_db() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    // Create 3 claims forming a support chain: A → B → C
    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} root A"), 0.9).await;
    let claim_b = create_test_claim(&db.pool, agent, &format!("{PREFIX} mid B"), 0.7).await;
    let claim_c = create_test_claim(&db.pool, agent, &format!("{PREFIX} leaf C"), 0.6).await;

    create_test_edge(&db.pool, claim_a, claim_b, "supports").await;
    create_test_edge(&db.pool, claim_b, claim_c, "supports").await;

    // Load claims from DB
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

    // Load edges from DB
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
                strength: 0.8, // default edge strength
            }
        })
        .collect();

    assert_eq!(claims.len(), 3, "Should have 3 claims from DB");
    assert_eq!(edges.len(), 2, "Should have 2 edges from DB");

    let result = ReasoningEngine::analyze(&claims, &edges);

    // Verify transitive support: A → C (through B)
    let a_to_c = result
        .transitive_supports
        .iter()
        .find(|ts| ts.source == claim_a && ts.target == claim_c);

    assert!(
        a_to_c.is_some(),
        "ReasoningEngine should detect transitive support from A to C. \
         Found {} transitive supports total.",
        result.transitive_supports.len()
    );

    let chain = a_to_c.unwrap();

    // Chain strength should be 0.8 * 0.8 = 0.64 (product of edge strengths)
    let expected_strength = 0.8 * 0.8;
    assert!(
        (chain.chain_strength - expected_strength).abs() < 1e-9,
        "Chain strength should be {expected_strength}, got {}",
        chain.chain_strength
    );

    // Also verify direct supports are present: A→B and B→C
    assert!(
        result
            .transitive_supports
            .iter()
            .any(|ts| ts.source == claim_a && ts.target == claim_b),
        "Direct support A→B should be in transitive_supports"
    );
    assert!(
        result
            .transitive_supports
            .iter()
            .any(|ts| ts.source == claim_b && ts.target == claim_c),
        "Direct support B→C should be in transitive_supports"
    );

    cleanup_test_data(&db.pool, PREFIX).await;
}
