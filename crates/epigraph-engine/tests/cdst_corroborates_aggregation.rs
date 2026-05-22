//! T17: CORROBORATES propagation through CDST BP.
//!
//! The matcher (T16) emits CORROBORATES edges with `properties.score`
//! reflecting per-pair confidence. The auto-factor trigger (migration 037)
//! turns each such edge into an `evidential_support` factor whose strength
//! IS the matcher's score. CDST BP then discounts the peer's mass by `1 -
//! strength` and combines via Dempster (existing `compute_cdst_factor_message`
//! handles this).
//!
//! This file tests two things:
//! 1. **CDST math** (in-memory): adding an `EvidentialSupport` factor between
//!    two supported claims raises the focal claim's BetP. Validates that
//!    the existing engine path is the one we want to drive.
//! 2. **Trigger wiring** (DB): inserting a CORROBORATES edge tagged with
//!    `source = cross_source_matcher` and `score = X` causes the factors
//!    table to receive a row with `potential.strength = X`. Validates
//!    migration 037.

use std::collections::{BTreeSet, HashMap};

use epigraph_ds::{FrameOfDiscernment, MassFunction};
use epigraph_engine::bp::FactorPotential;
use epigraph_engine::cdst_bp::{run_cdst_bp, CdstBpConfig};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

// ── In-memory CDST math ────────────────────────────────────────────────────

fn frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("binary", vec!["supported".into(), "unsupported".into()])
        .expect("binary frame")
}

const H_SUPPORTED: usize = 0;

fn supported(mass: f64) -> MassFunction {
    MassFunction::simple(frame(), BTreeSet::from([H_SUPPORTED]), mass).expect("simple mass")
}

#[test]
fn corroborates_factor_raises_focal_betp_in_cdst_bp() {
    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();

    // Both claims have moderate independent evidence for "supported".
    let evidence_a = supported(0.40);
    let evidence_b = supported(0.40);

    let mut evidence = HashMap::new();
    evidence.insert(claim_a, evidence_a.clone());
    evidence.insert(claim_b, evidence_b.clone());
    let initial = evidence.clone();

    let cfg = CdstBpConfig::default();

    // Run 1: no edge → no factor. Focal BetP just reflects the evidence.
    let report_no_edge = run_cdst_bp(&[], &initial, &evidence, &cfg);
    let betp_a_no_edge = report_no_edge
        .updated_betps
        .iter()
        .find(|(id, _)| *id == claim_a)
        .map(|(_, p)| *p)
        .unwrap_or(0.5);

    // Run 2: add a CORROBORATES-equivalent factor (evidential_support,
    // strength 0.85 — what migration-044/090 produced for CORROBORATES
    // before migration 037's score override). BetP should rise.
    let factor_id = Uuid::new_v4();
    let factors = vec![(
        factor_id,
        FactorPotential::EvidentialSupport { strength: 0.85 },
        vec![claim_a, claim_b],
    )];
    let report_with_edge = run_cdst_bp(&factors, &initial, &evidence, &cfg);
    let betp_a_with_edge = report_with_edge
        .updated_betps
        .iter()
        .find(|(id, _)| *id == claim_a)
        .map(|(_, p)| *p)
        .unwrap_or(0.5);

    assert!(
        betp_a_with_edge > betp_a_no_edge,
        "CORROBORATES factor must raise focal BetP: {betp_a_no_edge} → {betp_a_with_edge}"
    );
    // Sanity: still bounded above by certainty.
    assert!(betp_a_with_edge < 1.0);
}

#[test]
fn higher_corroborates_strength_yields_higher_betp_rise() {
    let claim_a = Uuid::new_v4();
    let claim_b = Uuid::new_v4();
    let mut evidence = HashMap::new();
    evidence.insert(claim_a, supported(0.40));
    evidence.insert(claim_b, supported(0.40));
    let initial = evidence.clone();
    let cfg = CdstBpConfig::default();

    let make_factors = |strength: f64| {
        vec![(
            Uuid::new_v4(),
            FactorPotential::EvidentialSupport { strength },
            vec![claim_a, claim_b],
        )]
    };
    let betp = |factors: &[(Uuid, FactorPotential, Vec<Uuid>)]| {
        run_cdst_bp(factors, &initial, &evidence, &cfg)
            .updated_betps
            .iter()
            .find(|(id, _)| *id == claim_a)
            .map(|(_, p)| *p)
            .unwrap_or(0.5)
    };

    let weak = betp(&make_factors(0.50));
    let medium = betp(&make_factors(0.85)); // pre-T17 constant
    let strong = betp(&make_factors(0.95)); // matcher score the trigger
                                            // would surface for a top pair

    assert!(
        weak < medium && medium < strong,
        "BetP should grow monotonically with corroborator strength: \
         weak={weak} medium={medium} strong={strong}"
    );
}

// ── DB trigger wiring (migration 037) ──────────────────────────────────────

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set");
                return;
            }
        }
    };
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("t17 {id}");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3, true)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn matcher_tagged_corroborates_edge_emits_factor_with_score_strength(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let edge_id = Uuid::new_v4();
    let score: f64 = 0.92;
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type,
                            relationship, properties)
         VALUES ($1, $2, 'claim', $3, 'claim', 'CORROBORATES', $4)",
    )
    .bind(edge_id)
    .bind(a)
    .bind(b)
    .bind(serde_json::json!({
        "source": "cross_source_matcher",
        "score": score,
        "matcher_run_id": Uuid::new_v4(),
    }))
    .execute(&pool)
    .await
    .expect("insert edge");

    // Trigger should have inserted exactly one factor with strength == score.
    let row: (String, serde_json::Value) = sqlx::query_as(
        "SELECT factor_type, potential FROM factors
         WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(edge_id)
    .fetch_one(&pool)
    .await
    .expect("factor row");
    assert_eq!(row.0, "evidential_support");
    let strength = row
        .1
        .get("strength")
        .and_then(|v| v.as_f64())
        .expect("strength");
    assert!(
        (strength - score).abs() < 1e-9,
        "expected factor strength {score}, got {strength}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn untagged_corroborates_edge_keeps_constant_strength(pool: PgPool) {
    // Regression guard: edges without the matcher marker MUST fall back to
    // edge_to_factor_type's constant (0.85) — otherwise existing CORROBORATES
    // edges from older code paths would silently change behavior.
    let agent = insert_agent(&pool).await;
    let a = insert_claim(&pool, agent).await;
    let b = insert_claim(&pool, agent).await;

    let edge_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type,
                            relationship, properties)
         VALUES ($1, $2, 'claim', $3, 'claim', 'CORROBORATES', $4)",
    )
    .bind(edge_id)
    .bind(a)
    .bind(b)
    .bind(serde_json::json!({"note": "manually added"}))
    .execute(&pool)
    .await
    .expect("insert edge");

    let row: (serde_json::Value,) = sqlx::query_as(
        "SELECT potential FROM factors
         WHERE properties->>'source_edge_id' = $1::text",
    )
    .bind(edge_id)
    .fetch_one(&pool)
    .await
    .expect("factor row");
    let strength = row
        .0
        .get("strength")
        .and_then(|v| v.as_f64())
        .expect("strength");
    assert!(
        (strength - 0.85).abs() < 1e-9,
        "untagged CORROBORATES should keep constant 0.85, got {strength}"
    );
}
