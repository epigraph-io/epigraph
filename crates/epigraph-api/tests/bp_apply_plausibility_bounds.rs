#![cfg(feature = "db")]

//! Regression for issue #139 covering the CDST BP apply path.
//!
//! `routes/computation.rs:621-630` writes `bel`, `pl` from
//! `result.updated_intervals` and `betp` from `result.updated_betps` directly
//! into `claims` without going through the centralized clamp helper.
//!
//! ## Outcome: PASSED (no red repro achievable)
//!
//! Per Task 3 of the plan, this test was intended to reproduce
//! `claims_plausibility_bounds` constraint violations via a 20-BBA drift seed
//! (`[0.05; 20].sum() == 1.0000000000000002`). It does not — and cannot —
//! because PR #149 pushed `.clamp(0.0, 1.0)` upstream into every value the BP
//! apply path receives:
//!
//! - `result.updated_intervals` is built by
//!   `epigraph_engine::cdst_bp::mass_to_interval`, which calls
//!   `epigraph_ds::measures::belief` and `plausibility`, both of which
//!   `.clamp(0.0, 1.0)` their results (measures.rs:39, :63).
//! - The clamped (bel, pl) pair is then passed to
//!   `EpistemicInterval::from_mass_components -> EpistemicInterval::new`, which
//!   re-clamps (epistemic_interval.rs:36-37).
//! - `result.updated_betps` is `pignistic_probability(m, H_SUPPORTED)`, which
//!   clamps internally before returning (measures.rs:129-134).
//!
//! Triple-clamped values reach the UPDATE statement at computation.rs:622, so
//! the CHECK constraint is satisfied. The test still exercises the path end to
//! end to assert this invariant going forward — if any future refactor moves
//! clamping out of the engine layer, this regression will surface.
//!
//! Task 4's helper migration of computation.rs:621/655 is therefore a
//! defense-in-depth refactor (centralizing the contract), not a bug fix; the
//! bug was already fixed at the engine layer in PR #149.

use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

mod common;

/// Frame fixture: binary frame matching `epigraph_engine::cdst_bp::BINARY_FRAME`
/// (`{"supported", "unsupported"}`). Stored in `frames` so `mass_functions.frame_id`
/// FK is satisfied. Idempotent across test runs.
async fn ensure_binary_frame(pool: &PgPool) -> Uuid {
    // Deterministic UUID so repeated test runs reuse the same row.
    let frame_id =
        Uuid::parse_str("00000000-0000-0000-0000-00000000bf01").expect("constant uuid");
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) \
         VALUES ($1, 'bp_apply_test_binary', ARRAY['supported','unsupported']::text[]) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(frame_id)
    .execute(pool)
    .await
    .expect("seed binary frame");
    frame_id
}

/// Seed a claim with explicit belief/plausibility/BetP. Mirrors the helper in
/// `crates/epigraph-mcp/tests/common/mod.rs::seed_claim_with_belief`.
async fn seed_claim_with_belief(
    pool: &PgPool,
    belief: f64,
    plausibility: f64,
    pignistic_prob: Option<f64>,
) -> Uuid {
    let agent_id = common::seed_system_agent(pool).await;
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims \
            (id, content, content_hash, agent_id, truth_value, \
             belief, plausibility, pignistic_prob, is_current, labels) \
         VALUES ($1, $2, $3, $4, 0.5, $5, $6, $7, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(format!("bp_apply drift seed {id}"))
    .bind(&hash)
    .bind(agent_id)
    .bind(belief)
    .bind(plausibility)
    .bind(pignistic_prob)
    .execute(pool)
    .await
    .expect("seed claim with belief");
    id
}

/// Seed `n` independent mass-function rows for `claim_id`, each carrying mass
/// `per_bba_mass` on `{supported}` and `1 - per_bba_mass` on `{unsupported}`.
///
/// The route at `computation.rs:567-581` combines all rows for a claim via
/// `adaptive_combine`. With `n=20` and `per_bba_mass=0.05`, the engine sees
/// 20 simple BBAs whose serial combination produces a drifted plausibility
/// that — pre-clamp — would land at `1.0 + 1 ULP`.
///
/// `source_strength` is set high (0.95) per-row so adaptive_combine treats each
/// fold as confident evidence; this maximizes the chance of accumulated
/// floating-point drift in the combined plausibility before the engine's
/// belief()/plausibility() functions clamp.
async fn seed_drifting_bbas(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    n: usize,
    per_bba_mass: f64,
) {
    // 0 = supported, 1 = unsupported (matches engine's BINARY_FRAME constants).
    let mut masses: BTreeMap<String, f64> = BTreeMap::new();
    masses.insert("0".to_string(), per_bba_mass);
    masses.insert("1".to_string(), 1.0 - per_bba_mass);
    let masses_json = serde_json::to_value(&masses).expect("serialize masses");

    for _ in 0..n {
        let mf_id = Uuid::new_v4();
        // Each row needs a distinct source_agent_id to bypass
        // mass_functions_unique_per_perspective (claim_id, frame_id, source_agent_id, perspective_id).
        let source_agent = common::seed_system_agent(pool).await;
        sqlx::query(
            "INSERT INTO mass_functions \
               (id, claim_id, frame_id, source_agent_id, masses, source_strength, evidence_type) \
             VALUES ($1, $2, $3, $4, $5, 0.95, 'empirical')",
        )
        .bind(mf_id)
        .bind(claim_id)
        .bind(frame_id)
        .bind(source_agent)
        .bind(&masses_json)
        .execute(pool)
        .await
        .expect("insert mass_function row");
    }
}

/// Seed an `evidential_support` factor connecting two claims. The CDST BP path
/// is only entered when `factors` is non-empty and >50% of variables have a
/// stored mass_function (see `computation.rs:541-555`).
async fn seed_evidential_support_factor(
    pool: &PgPool,
    frame_id: Uuid,
    claim_a: Uuid,
    claim_b: Uuid,
) {
    let factor_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO factors \
           (id, factor_type, variable_ids, potential, frame_id) \
         VALUES ($1, 'evidential_support', $2, $3, $4)",
    )
    .bind(factor_id)
    .bind(vec![claim_a, claim_b])
    .bind(json!({"strength": 0.8}))
    .bind(frame_id)
    .execute(pool)
    .await
    .expect("seed factor");
}

#[tokio::test(flavor = "multi_thread")]
async fn cdst_bp_apply_clamps_drifted_plausibility() {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL set");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("db pool");

    let frame_id = ensure_binary_frame(&pool).await;

    // The "drifting" claim — seeded at Pl=1.0 so any post-recompute write above
    // 1.0 trips claims_plausibility_bounds CHECK.
    let claim_drift = seed_claim_with_belief(&pool, 0.4, 1.0, Some(0.4)).await;

    // Companion claim so the factor has the 2 variables it requires
    // (factors_min_variables CHECK in migrations/001_initial_schema.sql:975).
    let claim_companion = seed_claim_with_belief(&pool, 0.5, 0.6, Some(0.55)).await;

    // 20 BBA rows on the drifting claim — combine path produces 1.0+1ULP raw Pl.
    seed_drifting_bbas(&pool, claim_drift, frame_id, 20, 0.05).await;

    // 1 BBA on companion so >50% coverage triggers the CDST branch in auto mode.
    seed_drifting_bbas(&pool, claim_companion, frame_id, 1, 0.6).await;

    seed_evidential_support_factor(&pool, frame_id, claim_drift, claim_companion).await;

    let (addr, _shutdown) = common::spawn_app(&url).await;
    let token = common::test_bearer_token_with_scopes(&["claims:write", "graph:read"]);

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/bp/propagate"))
        .bearer_auth(&token)
        .json(&json!({
            "frame_id": frame_id,
            "apply_updates": true,
            "mode": "cdst",
            "max_iterations": 5,
        }))
        .send()
        .await
        .expect("POST /api/v1/bp/propagate");

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();

    assert!(
        status.is_success(),
        "bp/propagate returned {status}: {body_text}"
    );

    // Even if HTTP 200, the apply path swallows sqlx errors into apply_failures.
    // A non-zero apply_failures with the drift seed in play would indicate
    // claims_plausibility_bounds (or another CHECK) tripped silently.
    let body: Value = serde_json::from_str(&body_text)
        .unwrap_or_else(|_| panic!("response not JSON: {body_text}"));

    // Confirm the CDST branch was actually taken — otherwise the test is
    // not exercising the surface we're auditing.
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(mode, "cdst", "expected CDST branch, got mode={mode}; body={body_text}");

    let applied = body.get("applied").and_then(|v| v.as_bool()).unwrap_or(false);
    assert!(applied, "expected applied=true; body={body_text}");

    let factors_count = body
        .get("factors_count")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    assert!(factors_count > 0, "no factors loaded; body={body_text}");

    let apply_failures = body
        .get("apply_failures")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    assert_eq!(
        apply_failures, 0,
        "bp/propagate apply_failures={apply_failures} body={body_text}"
    );

    // Drift assertion at the DB level: after apply, plausibility on the drifting
    // claim must be in [0, 1]. The claims_plausibility_bounds CHECK constraint
    // is what we are auditing; if the apply path ever wrote >1.0, the UPDATE
    // would have failed (silently incrementing apply_failures). This is a
    // belt-and-braces post-condition.
    let row: (f64, f64, Option<f64>) = sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1",
    )
    .bind(claim_drift)
    .fetch_one(&pool)
    .await
    .expect("read back drift claim");
    assert!(
        (0.0..=1.0).contains(&row.0),
        "belief escaped [0,1] after apply: {}",
        row.0
    );
    assert!(
        (0.0..=1.0).contains(&row.1),
        "plausibility escaped [0,1] after apply: {}",
        row.1
    );
    if let Some(betp) = row.2 {
        assert!(
            (0.0..=1.0).contains(&betp),
            "pignistic_prob escaped [0,1] after apply: {betp}"
        );
    }
}
