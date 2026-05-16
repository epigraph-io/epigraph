//! Integration tests: DB claims → ReputationCalculator → verify trust scores.
//!
//! Test 1: Load 5 claims from DB, build ClaimOutcome vector, compute reputation,
//!         verify trust == 0.67 (deterministic from ReputationConfig::default()).
//!
//! Test 2: Create 2 claims with CONTRADICTS edge, verify ReasoningEngine detects
//!         exactly one contradiction naming the specific claim pair and target.

use engine_integration_tests::harness::*;
use epigraph_engine::reputation::{ClaimOutcome, ReputationCalculator};
use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use sqlx::Row;

const PREFIX: &str = "[test-trust-db]";

/// Trust computation from 5 high-truth recent claims yields a specific
/// expected reputation derived from `ReputationConfig::default()`.
///
/// With 5 claims of truth 0.80..0.88, age_days=5.0, was_refuted=false:
/// - recency factor per claim: 1/(1+5/30) = 6/7 (identical → weighted mean = arith mean = 0.84)
/// - combined = 0.84 (no historical claims)
/// - stability factor for n=5 < min_claims_for_stability=10:
///     progress = 5/10 = 0.5
///     stability = 0.5*0.84 + 0.5*0.5 = 0.67
/// - clamped to (0.1, 0.95) → 0.67
///
/// This locks the result; any change to ReputationConfig defaults or the
/// reputation algorithm trips this assertion.
#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn trust_computed_from_db_claims() {
    let db = TestDb::setup().await;
    let _guard = PrefixGuard::new(&db.pool, PREFIX);
    let agent = create_test_agent(&db.pool).await;

    let mut claim_ids = Vec::new();
    for i in 0..5 {
        let id = create_test_claim(
            &db.pool,
            agent,
            &format!("{PREFIX} trust-claim-{i}"),
            0.8 + (i as f64) * 0.02,
        )
        .await;
        claim_ids.push(id);
    }

    let rows = sqlx::query("SELECT truth_value FROM claims WHERE content LIKE $1 ORDER BY content")
        .bind(format!("{PREFIX} trust-claim-%"))
        .fetch_all(&db.pool)
        .await
        .expect("load claims");
    assert_eq!(rows.len(), 5);

    let outcomes: Vec<ClaimOutcome> = rows
        .iter()
        .map(|row| ClaimOutcome {
            truth_value: row.get::<f64, _>("truth_value"),
            age_days: 5.0,
            was_refuted: false,
        })
        .collect();

    let trust = ReputationCalculator::new()
        .calculate(&outcomes)
        .expect("reputation");

    let expected = 0.67;
    assert!(
        (trust - expected).abs() < 1e-9,
        "expected reputation == {expected} from defaults + hand-calculation; got {trust}. \
         If ReputationConfig defaults changed, update this expected value and \
         the doc-comment derivation."
    );
}

/// CONTRADICTS edge in DB produces a Contradiction record that names the
/// specific supporting + refuting claims and the shared target.
#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn conflict_classified_from_db_contradicts_edge() {
    let db = TestDb::setup().await;
    let _guard = PrefixGuard::new(&db.pool, PREFIX);
    let agent = create_test_agent(&db.pool).await;

    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} strong"), 0.9).await;
    let claim_b = create_test_claim(&db.pool, agent, &format!("{PREFIX} weak"), 0.3).await;
    let target = create_test_claim(&db.pool, agent, &format!("{PREFIX} target"), 0.6).await;

    create_test_edge(&db.pool, claim_a, target, "supports").await;
    create_test_edge(&db.pool, claim_b, target, "contradicts").await;

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
         FROM edges e JOIN claims cs ON cs.id = e.source_id \
         WHERE cs.content LIKE $1",
    )
    .bind(format!("{PREFIX}%"))
    .fetch_all(&db.pool)
    .await
    .expect("load edges");
    let edges: Vec<ReasoningEdge> = edge_rows
        .iter()
        .map(|row| ReasoningEdge {
            source_id: row.get("source_id"),
            target_id: row.get("target_id"),
            relationship: row.get::<String, _>("relationship").to_lowercase(),
            strength: 0.8,
        })
        .collect();

    let result = ReasoningEngine::analyze(&claims, &edges);

    // Exactly one contradiction, naming (claim_a as supporter, claim_b as refuter, target).
    // Contradiction.claim_a/claim_b ordering is not guaranteed by the engine, so
    // accept either order but require the *set* to match.
    assert_eq!(
        result.contradictions.len(),
        1,
        "expected exactly one contradiction, got {} ({:?})",
        result.contradictions.len(),
        result.contradictions
    );
    let c = &result.contradictions[0];
    let observed = std::collections::BTreeSet::from([c.claim_a, c.claim_b]);
    let expected = std::collections::BTreeSet::from([claim_a, claim_b]);
    assert_eq!(
        observed, expected,
        "contradiction must name claim_a and claim_b (got {:?})", c
    );
    assert_eq!(c.target, target, "target must match");
}
