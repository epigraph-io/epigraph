//! Integration test: auto-factor trigger + BP round-trip.
//!
//! Test 1: CORROBORATES edge insertion triggers auto_create_factor_from_edge (migration 044),
//!          factor is loaded from PG, run_bp() runs over it, beliefs update correctly.
//!
//! Test 2: Migration 068 supersession guard — inserting a CORROBORATES edge where one claim
//!          has is_current=false must NOT create a factor.

use engine_integration_tests::harness::*;
use epigraph_engine::{run_bp, BpConfig, FactorPotential};
use std::collections::HashMap;
use uuid::Uuid;

const PREFIX: &str = "[test-bp-factors]";

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn auto_factor_trigger_creates_factors_for_corroborates() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} claim A"), 0.6).await;
    let claim_b = create_test_claim(&db.pool, agent, &format!("{PREFIX} claim B"), 0.6).await;

    // Insert CORROBORATES edge — trigger should auto-create an evidential_support factor
    create_test_edge(&db.pool, claim_a, claim_b, "CORROBORATES").await;

    // Trigger stores variable_ids in sorted (smaller UUID first) order
    let (smaller, larger) = if claim_a < claim_b {
        (claim_a, claim_b)
    } else {
        (claim_b, claim_a)
    };

    let factor_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE variable_ids @> $1")
            .bind(&[smaller, larger][..])
            .fetch_one(&db.pool)
            .await
            .unwrap();

    assert_eq!(
        factor_count, 1,
        "Auto-factor trigger should create exactly one factor for CORROBORATES edge"
    );

    // Load the factor row to feed into run_bp
    let row: (String, serde_json::Value) =
        sqlx::query_as("SELECT factor_type, potential FROM factors WHERE variable_ids @> $1")
            .bind(&[smaller, larger][..])
            .fetch_one(&db.pool)
            .await
            .unwrap();

    assert_eq!(
        row.0, "evidential_support",
        "CORROBORATES edge should produce evidential_support factor, got: {}",
        row.0
    );

    // Migration 044 sets strength = 0.85 for CORROBORATES
    let strength = row
        .1
        .get("strength")
        .and_then(|s| s.as_f64())
        .unwrap_or(0.8);

    let mut priors = HashMap::new();
    priors.insert(claim_a, 0.6);
    priors.insert(claim_b, 0.6);

    let factor_id = Uuid::new_v4();
    let factors = vec![(
        factor_id,
        FactorPotential::EvidentialSupport { strength },
        vec![claim_a, claim_b],
    )];

    let config = BpConfig::default();
    let result = run_bp(&factors, &priors, &config);

    // Collect into HashMap for easy lookup
    let beliefs: HashMap<Uuid, f64> = result.updated_beliefs.into_iter().collect();

    let belief_a = *beliefs.get(&claim_a).unwrap_or(&0.0);
    let belief_b = *beliefs.get(&claim_b).unwrap_or(&0.0);

    // With symmetric CORROBORATES, beliefs converge to a common fixed point.
    // The BP blending formula (50% prior + 50% factor signal) means the fixed point
    // is slightly below 0.6 when strength < 1.0. We assert beliefs stay in (0.4, 0.8)
    // — i.e., BP does not collapse or explode them.
    assert!(
        belief_a > 0.4 && belief_a < 0.8,
        "Claim A belief should converge within (0.4, 0.8), got: {belief_a}"
    );
    assert!(
        belief_b > 0.4 && belief_b < 0.8,
        "Claim B belief should converge within (0.4, 0.8), got: {belief_b}"
    );
    // The two claims should end at the same belief (symmetric factor, identical priors)
    assert!(
        (belief_a - belief_b).abs() < 0.05,
        "Symmetric CORROBORATES should yield equal beliefs: a={belief_a}, b={belief_b}"
    );

    cleanup_test_data(&db.pool, PREFIX).await;
}

#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn superseded_claim_excluded_from_auto_factor() {
    let db = TestDb::setup().await;
    let agent = create_test_agent(&db.pool).await;

    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} current-claim"), 0.6).await;
    let claim_b =
        create_test_claim(&db.pool, agent, &format!("{PREFIX} superseded-claim"), 0.6).await;

    // Mark claim_b as superseded (is_current = false)
    sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
        .bind(claim_b)
        .execute(&db.pool)
        .await
        .unwrap();

    // Insert CORROBORATES edge — migration 068 guard should skip factor creation
    // because claim_b has is_current = false
    create_test_edge(&db.pool, claim_a, claim_b, "CORROBORATES").await;

    let factor_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM factors WHERE $1 = ANY(variable_ids)")
            .bind(claim_b)
            .fetch_one(&db.pool)
            .await
            .unwrap();

    assert_eq!(
        factor_count, 0,
        "Migration 068 guard should prevent factor creation for superseded claim"
    );

    cleanup_test_data(&db.pool, PREFIX).await;
}
