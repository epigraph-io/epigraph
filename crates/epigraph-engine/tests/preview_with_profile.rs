//! `edge_factor::preview_claim_belief_on_frame_with_profile`: the owner-frame
//! fold under a named GLOBAL profile, with the frame tier layered over it
//! exactly as the served fold layers it over the served profile (the R-173
//! calibration dry run folds every claim under the shipped calibration and
//! under the empty vocabulary through this one entry point).
//!
//! The oracle is hand arithmetic on one BBA, never a second engine call:
//! for a single BBA with masses only on singleton h and on the whole frame
//! (n hypotheses), discounted at reliability r,
//! `BetP(h) = r·m_h + (r·m_Θ + 1 − r)/n`, `Bel(h) = r·m_h`, `Pl(h) = 1`
//! when no mass sits on the other hypothesis.
//!
//! The discriminating case is a frame whose `belief_profile` patch changes a
//! reliability parameter the EMPTY profile falls back on
//! (`unknown_evidence_type_weight`). Only a fold that layers the frame tier
//! over the named base gives the patched value; an approximation that nulls
//! the row's evidence type and folds under the served profile gives the
//! unpatched 0.5, and one that ignores the base gives the served value.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{MassFunctionRepository, PgPool};
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_engine::edge_factor::{
    ensure_binary_frame, preview_claim_belief_on_frame, preview_claim_belief_on_frame_vacating,
    preview_claim_belief_on_frame_with_profile, recompute_claim_belief_on_frame,
};
use uuid::Uuid;

/// The frame patch: the unknown-type weight the empty vocabulary falls to.
const PATCHED_UNKNOWN_WEIGHT: f64 = 0.4;

fn empty_vocabulary() -> BeliefProfile {
    BeliefProfile::from_calibration(&CalibrationConfig::default_for_phase2_fallback())
}

/// `BetP(h)` of one discounted BBA `{h: m_h, Θ: m_t}` on an n-frame.
fn betp(r: f64, m_h: f64, m_t: f64, n: f64) -> f64 {
    r * m_h + (r * m_t + 1.0 - r) / n
}

async fn frame_with(pool: &PgPool, name: &str, properties: serde_json::Value) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses, properties) \
         VALUES ($1, ARRAY['TRUE','FALSE'], $2) RETURNING id",
    )
    .bind(name)
    .bind(properties)
    .fetch_one(pool)
    .await
    .expect("insert frame")
}

async fn one_row(pool: &PgPool, claim: Uuid, frame: Uuid, agent: Uuid, et: &str) {
    MassFunctionRepository::store_with_perspective(
        pool,
        claim,
        frame,
        Some(agent),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        None,
        Some(et),
        "cross",
        None,
    )
    .await
    .expect("store the BBA");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_named_base_profile_is_folded_under_with_the_frame_tier_over_it(pool: PgPool) {
    // PREMISE: the served calibration is the shipped one (the constants below
    // depend on it); the empty one has no evidence-type vocabulary.
    assert_eq!(
        BeliefProfile::served().evidence_type_weight("empirical"),
        1.0,
        "PREMISE: the served profile weighs empirical at 1.0 (embedded calibration.toml)"
    );
    assert!(!empty_vocabulary().evidence_type_weight_present("empirical"));

    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "r173-entry").await;
    let patched = frame_with(
        &pool,
        "r173 patched frame",
        serde_json::json!({"belief_profile": {"reliability": {
            "unknown_evidence_type_weight": PATCHED_UNKNOWN_WEIGHT}}}),
    )
    .await;
    let claim = fixture::seed_public_claim(&pool, agent, "r173 entry patched").await;
    one_row(&pool, claim, patched, agent, "empirical").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let empty = preview_claim_belief_on_frame_with_profile(
        &mut conn,
        &viewer,
        claim,
        patched,
        &empty_vocabulary(),
        |rows| rows,
    )
    .await
    .expect("fold under the empty vocabulary")
    .expect("the frame holds a row");
    // Empty base + the frame's patch: `empirical` resolves nowhere, there is
    // no stored strength, so the row weighs the PATCHED unknown-type weight.
    let want = betp(PATCHED_UNKNOWN_WEIGHT, 0.6, 0.4, 2.0);
    assert!(
        (empty.pignistic_prob - want).abs() < 1e-12,
        "BetP under the empty base on a patched frame: got {}, want {want} \
         (0.65 = the type-nulling approximation; 0.80 = the base ignored)",
        empty.pignistic_prob
    );
    assert!((empty.belief - PATCHED_UNKNOWN_WEIGHT * 0.6).abs() < 1e-12);

    let served = preview_claim_belief_on_frame_with_profile(
        &mut conn,
        &viewer,
        claim,
        patched,
        BeliefProfile::served(),
        |rows| rows,
    )
    .await
    .expect("fold under the served profile")
    .expect("the frame holds a row");
    assert!(
        (served.pignistic_prob - betp(1.0, 0.6, 0.4, 2.0)).abs() < 1e-12,
        "BetP under the served base: empirical weighs 1.0, the patch is not consulted"
    );

    // The served base IS the write: the real recompute writes that value.
    let plain = preview_claim_belief_on_frame(&mut conn, &viewer, claim, patched)
        .await
        .expect("plain preview")
        .expect("a value");
    assert_eq!(plain, served, "the served base is the plain preview");
    let (vac, vacated) = preview_claim_belief_on_frame_vacating(&mut conn, &viewer, claim, patched)
        .await
        .expect("vacating preview")
        .expect("a value");
    assert!(!vacated, "a fold of an admitted row is not a vacate");
    assert_eq!(vac, served);
    assert!(
        recompute_claim_belief_on_frame(&mut conn, &viewer, claim, patched)
            .await
            .expect("recompute")
    );
    let written: Option<f64> =
        sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
            .bind(claim)
            .fetch_one(&pool)
            .await
            .expect("read the cache");
    assert!(
        (written.expect("a cache") - served.pignistic_prob).abs() < 1e-12,
        "the write stores what the served-base preview predicted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_alias_spelled_row_resolves_under_the_shipped_base_only(pool: PgPool) {
    let (_scoped, viewer) = fixture::bypass(&pool).await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "r173-alias").await;
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary frame");
    let claim = fixture::seed_public_claim(&pool, agent, "r173 entry alias").await;
    // `observation` is an alias of `empirical` in the shipped calibration and
    // nothing in the empty one: no stored strength, so the unknown weight 0.5.
    one_row(&pool, claim, binary, agent, "observation").await;
    let empty_base = empty_vocabulary();
    let mut fold = Vec::new();
    for base in [&empty_base, BeliefProfile::served()] {
        fold.push(
            preview_claim_belief_on_frame_with_profile(
                &mut conn,
                &viewer,
                claim,
                binary,
                base,
                |r| r,
            )
            .await
            .expect("fold")
            .expect("a value")
            .pignistic_prob,
        );
    }
    assert!(
        (fold[0] - betp(0.5, 0.6, 0.4, 2.0)).abs() < 1e-12,
        "empty base: the alias resolves nowhere, so the unknown weight 0.5; got {}",
        fold[0]
    );
    assert!(
        (fold[1] - betp(1.0, 0.6, 0.4, 2.0)).abs() < 1e-12,
        "shipped base: the alias resolves to empirical 1.0; got {}",
        fold[1]
    );
    drop(conn);
}
