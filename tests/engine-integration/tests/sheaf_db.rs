//! Integration test: DB neighborhood → sheaf consistency via compute_expected_betp.
//!
//! Creates a center claim with 3 neighbors (2 supports, 1 contradicts),
//! loads from DB, computes expected BetP, and verifies it is in (0, 1).

use engine_integration_tests::harness::*;
use epigraph_engine::{compute_expected_betp, restriction_kind, RestrictionKind};
use sqlx::Row;

const PREFIX: &str = "[test-sheaf-db]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn sheaf_consistency_from_db_neighborhood() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    // Create center claim + 3 neighbors
    let center = create_test_claim(&db.pool, agent, &format!("{PREFIX} center"), 0.7).await;

    let supporter_1 =
        create_test_claim(&db.pool, agent, &format!("{PREFIX} supporter-1"), 0.8).await;

    let supporter_2 =
        create_test_claim(&db.pool, agent, &format!("{PREFIX} supporter-2"), 0.9).await;

    let contradictor =
        create_test_claim(&db.pool, agent, &format!("{PREFIX} contradictor"), 0.75).await;

    // supporter_1 supports center, supporter_2 supports center, contradictor contradicts center
    create_test_edge(&db.pool, supporter_1, center, "supports").await;
    create_test_edge(&db.pool, supporter_2, center, "supports").await;
    create_test_edge(&db.pool, contradictor, center, "contradicts").await;

    // Load the neighborhood from DB: neighbors are sources of edges pointing at center
    let neighbor_rows = sqlx::query(
        "SELECT c.id, c.truth_value, e.relationship \
         FROM edges e \
         JOIN claims c ON c.id = e.source_id \
         WHERE e.target_id = $1 AND c.content LIKE $2",
    )
    .bind(center)
    .bind(format!("{PREFIX}%"))
    .fetch_all(&db.pool)
    .await
    .expect("load neighbors");

    assert_eq!(
        neighbor_rows.len(),
        3,
        "Should have 3 neighbors (2 supports + 1 contradicts)"
    );

    // Build the (betp, RestrictionKind) tuples for compute_expected_betp
    let neighbors: Vec<(f64, RestrictionKind)> = neighbor_rows
        .iter()
        .map(|row| {
            let truth_value: f64 = row.get("truth_value");
            let relationship: String = row.get("relationship");
            let kind = restriction_kind(&relationship.to_lowercase());
            (truth_value, kind)
        })
        .collect();

    let expected_betp = compute_expected_betp(&neighbors);

    assert!(
        expected_betp.is_some(),
        "compute_expected_betp should return Some for 3 epistemic neighbors"
    );

    let betp = expected_betp.unwrap();

    // Expected BetP should be in (0, 1):
    // supporter_1 (0.8): Positive(0.8) → 0.8 * 0.8 = 0.64
    // supporter_2 (0.9): Positive(0.8) → 0.9 * 0.8 = 0.72
    // contradictor (0.75): Negative(0.9) → (1 - 0.75) * 0.9 = 0.225
    // average: (0.64 + 0.72 + 0.225) / 3 ≈ 0.528
    assert!(
        betp > 0.0 && betp < 1.0,
        "Expected BetP should be in (0, 1), got: {betp}"
    );

    // Verify approximate value
    let expected_approx = (0.8 * 0.8 + 0.9 * 0.8 + 0.25 * 0.9) / 3.0;
    assert!(
        (betp - expected_approx).abs() < 1e-9,
        "Expected BetP ≈ {expected_approx}, got: {betp}"
    );

    cleanup_test_data(&db.pool, PREFIX).await;
}
