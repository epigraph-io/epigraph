//! Integration test: auto-factor trigger + BP round-trip.
//!
//! Test 1: CORROBORATES edge insertion triggers auto_create_factor_from_edge
//!          (`migrations/001_initial_schema.sql:67`), factor is loaded from
//!          PG with strength = 0.85 (`migrations/011_derived_from_uppercase_factor.sql:34`),
//!          run_bp() runs over it, beliefs update correctly.
//!
//! Test 2: supersession guard (`migrations/001_initial_schema.sql:82-85`) —
//!          inserting a CORROBORATES edge where one claim has is_current=false
//!          must NOT create a factor.

use engine_integration_tests::harness::*;
use epigraph_engine::{run_bp, BpConfig, FactorPotential};
use std::collections::HashMap;
use uuid::Uuid;

const PREFIX: &str = "[test-bp-factors]";

/// Trigger creates a CORROBORATES factor with strength == 0.85 and BP runs
/// over it without collapsing.
///
/// Setup: insert CORROBORATES edge between two `is_current = true` claims.
/// Migration `001_initial_schema.sql:67` (`auto_create_factor_from_edge`)
/// must fire and write a single `evidential_support` factor with
/// `potential.strength = 0.85` (per `edge_to_factor_type` row at
/// `migrations/011_derived_from_uppercase_factor.sql:34`).
///
/// Asserts:
/// 1. Exactly one factor created.
/// 2. factor_type == "evidential_support".
/// 3. potential.strength == 0.85 exactly (catches drift in
///    `edge_to_factor_type`'s CORROBORATES row).
/// 4. `run_bp` converges, beliefs stay near priors, both variables agree.
#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn auto_factor_trigger_creates_factors_for_corroborates() {
    let db = TestDb::setup().await;
    let _guard = PrefixGuard::new(&db.pool, PREFIX);
    let agent = create_test_agent(&db.pool).await;

    let claim_a = create_test_claim(&db.pool, agent, &format!("{PREFIX} claim A"), 0.6).await;
    let claim_b = create_test_claim(&db.pool, agent, &format!("{PREFIX} claim B"), 0.6).await;

    create_test_edge(&db.pool, claim_a, claim_b, "CORROBORATES").await;

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
    assert_eq!(factor_count, 1, "trigger must create exactly one factor");

    let row: (String, serde_json::Value) =
        sqlx::query_as("SELECT factor_type, potential FROM factors WHERE variable_ids @> $1")
            .bind(&[smaller, larger][..])
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(row.0, "evidential_support");

    let strength = row
        .1
        .get("strength")
        .and_then(|s| s.as_f64())
        .expect("trigger must write strength field");
    assert!(
        (strength - 0.85).abs() < 1e-9,
        "CORROBORATES strength must be 0.85 (per migrations/011_derived_from_uppercase_factor.sql:34), got {strength}"
    );

    // Run scalar BP over the loaded factor and verify it converges sensibly.
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

    assert!(
        result.converged,
        "BP must converge for a single symmetric factor (got {} iterations, max_change={})",
        result.iterations, result.max_change
    );

    let beliefs: HashMap<Uuid, f64> = result.updated_beliefs.into_iter().collect();
    let belief_a = *beliefs.get(&claim_a).expect("A belief");
    let belief_b = *beliefs.get(&claim_b).expect("B belief");

    // Symmetric inputs → symmetric outputs (tightened from 0.05 to 1e-6).
    assert!(
        (belief_a - belief_b).abs() < 1e-6,
        "symmetric CORROBORATES must yield equal beliefs (a={belief_a}, b={belief_b})"
    );

    // Beliefs should stay reasonably near the 0.6 prior — catches collapse
    // (→0) or explosion (→1), without back-deriving the exact fixed point.
    assert!(
        (belief_a - 0.6).abs() < 0.2,
        "belief drifted too far from prior 0.6: {belief_a}"
    );
}

/// supersession guard (`migrations/001_initial_schema.sql:82-85`) — inserting
/// a CORROBORATES edge where one claim has `is_current=false` must NOT
/// create a factor.
#[tokio::test]
#[ignore] // Requires DATABASE_URL pointing to live PostgreSQL
async fn superseded_claim_excluded_from_auto_factor() {
    let db = TestDb::setup().await;
    let _guard = PrefixGuard::new(&db.pool, PREFIX);
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

    // Insert CORROBORATES edge — supersession guard should skip factor creation
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
        "supersession guard must prevent factor creation for superseded claim"
    );
}
