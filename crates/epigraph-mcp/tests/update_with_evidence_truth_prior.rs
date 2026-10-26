//! The first evidence update on a claim that carries a scalar `truth_value` but
//! NO binary-frame BBA must combine against that prior, not discard it
//! (backlog fc55465b, drain unit U026).
//!
//! # The defect
//!
//! `ds_auto::auto_wire_ds_update` combined only the BBAs stored for the claim.
//! A claim whose `truth_value` came from a path that writes no BBA (ingest-time
//! `calculate_initial_truth`, REST create, `seed_claim` here) has none, so the
//! combine saw the new evidence alone, and the supports=true monotonicity clamp
//! read its prior from `claims.pignistic_prob`, which is NULL on such a claim,
//! so it never fired. Reported in prod: a t=0.75 claim given supports=true
//! strength 0.7 fell to BetP 0.67; a t=0.75 claim given a weak challenge
//! (supports=false, 0.3) fell to 0.43.
//!
//! # The fix being pinned
//!
//! (B) Before the evidence BBA is stored, a claim with no binary-frame BBA gets
//! a SEED BBA whose pignistic probability is exactly its `truth_value`:
//! `m({TRUE}) = 2t-1, m(Θ) = 2-2t` for t > 0.5, mirrored onto `{FALSE}` for
//! t < 0.5, nothing at t = 0.5 (that seed would be vacuous). It is stored
//! undiscounted (`source_strength = 1.0`, `evidence_type = NULL`) under
//! `combination_method = 'truth_value_seed'`, attributed to the claim's author.
//! (A) The clamp's prior falls back to `truth_value` when `pignistic_prob` is
//! NULL, which covers the callers that do not seed.
//!
//! # How expected values are computed
//!
//! The evidence BBA's mass is `strength * load_evidence_type_weight(..)`, and
//! that weight depends on where the test process finds `calibration.toml`
//! (`CALIBRATION_PATH`, else the cwd, else 0.7). So the tool-level tests read
//! the evidence BBA this call STORED and compute the expected result from it
//! with [`dempster`], a three-line binary Dempster's rule written out here, not
//! borrowed from the code under test. The combine-time discount of an
//! `empirical` BBA is 1.0 under the repo calibration, and the seed is exempt
//! (reliability 1.0, pinned in `truth_value_seed_is_written_once`).

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_mcp::tools::ds_auto::{auto_wire_ds_update, ensure_binary_frame};
use epigraph_mcp::types::UpdateWithEvidenceParams;
use uuid::Uuid;

const EPS: f64 = 1e-9;

async fn run_update(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    strength: f64,
    supports: bool,
) -> serde_json::Value {
    let result = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        viewer,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            // Distinct per call: `evidence_content_hash_claim_unique` refuses
            // an identical second submission on the same claim.
            evidence_data: format!(
                "evidence strength={strength} supports={supports} nonce={}",
                Uuid::new_v4()
            ),
            source_url: None,
            supports,
            strength,
            labels: Vec::new(),
        },
        None,
    )
    .await
    .expect("update_with_evidence ok");
    first_text(&result)
}

fn num(json: &serde_json::Value, key: &str) -> f64 {
    json[key]
        .as_f64()
        .unwrap_or_else(|| panic!("missing numeric {key} in {json}"))
}

fn assert_no_warning(json: &serde_json::Value) {
    assert!(
        json.get("warning").is_none() || json["warning"].is_null(),
        "no 'supporting evidence decreased belief' warning may fire when the \
         prior is kept; got {json}"
    );
}

fn assert_ordered(json: &serde_json::Value) {
    let (bel, betp, pl) = (
        num(json, "belief"),
        num(json, "pignistic_prob"),
        num(json, "plausibility"),
    );
    assert!(
        bel <= betp + EPS && betp <= pl + EPS,
        "Bel <= BetP <= Pl must hold: {bel} / {betp} / {pl}"
    );
}

/// The `truth_value_seed` rows of a claim, as
/// `(masses, source_agent_id, source_strength, evidence_type, perspective_id,
/// evidence_id, frame name)`.
#[allow(clippy::type_complexity)]
async fn seed_rows(
    pool: &sqlx::PgPool,
    claim_id: Uuid,
) -> Vec<(
    serde_json::Value,
    Option<Uuid>,
    Option<f64>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    String,
)> {
    sqlx::query_as(
        "SELECT mf.masses, mf.source_agent_id, mf.source_strength, mf.evidence_type, \
                mf.perspective_id, mf.evidence_id, f.name \
           FROM mass_functions mf JOIN frames f ON f.id = mf.frame_id \
          WHERE mf.claim_id = $1 AND mf.combination_method = 'truth_value_seed'",
    )
    .bind(claim_id)
    .fetch_all(pool)
    .await
    .expect("read seed rows")
}

fn mass_at(masses: &serde_json::Value, key: &str) -> f64 {
    masses
        .get(key)
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}

/// A binary BBA as (m(TRUE), m(FALSE), m(Θ)).
type Bba = (f64, f64, f64);

/// Dempster's rule on the binary frame, normalised.
fn dempster(a: Bba, b: Bba) -> Bba {
    let k = a.0 * b.1 + a.1 * b.0;
    let t = a.0 * b.0 + a.0 * b.2 + a.2 * b.0;
    let f = a.1 * b.1 + a.1 * b.2 + a.2 * b.1;
    let th = a.2 * b.2;
    (t / (1.0 - k), f / (1.0 - k), th / (1.0 - k))
}

fn betp(m: Bba) -> f64 {
    m.0 + m.2 / 2.0
}

fn as_bba(masses: &serde_json::Value) -> Bba {
    (
        mass_at(masses, "0"),
        mass_at(masses, "1"),
        mass_at(masses, "0,1"),
    )
}

/// The BBA `update_with_evidence` stored for the evidence row in `json`.
async fn evidence_bba(pool: &sqlx::PgPool, json: &serde_json::Value) -> Bba {
    let evidence_id = parse_uuid_field(json, "evidence_id");
    let masses: serde_json::Value =
        sqlx::query_scalar("SELECT masses FROM mass_functions WHERE evidence_id = $1")
            .bind(evidence_id)
            .fetch_one(pool)
            .await
            .expect("the evidence's BBA");
    let m = as_bba(&masses);
    assert!(
        m.0 + m.1 > 0.0 && m.2 > 0.0,
        "fixture: a simple-support evidence BBA, got {masses}"
    );
    m
}

async fn author_of(pool: &sqlx::PgPool, claim_id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("claim author")
}

/// Reported repro 1 (962bcd65's shape): t = 0.85 seeds {T 0.7, Θ 0.3}, and
/// supporting evidence combines with it. Before the fix the prior was
/// discarded: the evidence stood alone (BetP 0.71 under the 0.7 fallback
/// weight, 0.80 under weight 1.0), below 0.85, with the spurious
/// "mathematically correct" warning.
#[sqlx::test(migrations = "../../migrations")]
async fn first_supporting_update_on_bba_less_claim_does_not_lower_betp_below_truth(
    pool: sqlx::PgPool,
) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: ingest-only claim, supported", 0.85).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.6, true).await;

    let got = num(&json, "pignistic_prob");
    assert!(
        got >= 0.85 - EPS,
        "supporting evidence must not lower BetP below the authored truth 0.85; got {got}"
    );
    // The prior is IN the combine, not only under the clamp: the clamp alone
    // would hold BetP at 0.85 but leave Bel at the evidence's own mass.
    let want = dempster((0.7, 0.0, 0.3), evidence_bba(&pool, &json).await);
    let bel = num(&json, "belief");
    assert!(
        (bel - want.0).abs() < EPS,
        "Bel must be the seed and the evidence combined ({}), got {bel}",
        want.0
    );
    assert!(
        (got - betp(want)).abs() < EPS,
        "BetP must be {}, got {got}",
        betp(want)
    );
    assert_ordered(&json);
    assert_no_warning(&json);
    assert!(
        (num(&json, "truth_after") - betp(want)).abs() < EPS,
        "truth_value follows the combined BetP: {json}"
    );
}

/// Reported repro 2 (9a89ca7e's shape): t = 0.75 seeds {T 0.5, Θ 0.5}, and a
/// weak challenge is combined against it. Before the fix the challenge stood
/// alone (BetP(T) = (1 - m(F))/2 < 0.5, Bel 0): a weak challenge erased the
/// prior.
#[sqlx::test(migrations = "../../migrations")]
async fn weak_challenge_on_bba_less_claim_does_not_erase_truth_prior(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: ingest-only claim, challenged", 0.75).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.3, false).await;

    let got = num(&json, "pignistic_prob");
    assert!(
        got > 0.5,
        "a weak challenge must not erase a 0.75 prior; got BetP {got}"
    );
    assert!(
        got < 0.75,
        "opposing evidence still lowers belief; got BetP {got}"
    );
    let want = dempster((0.5, 0.0, 0.5), evidence_bba(&pool, &json).await);
    assert!(
        (got - betp(want)).abs() < EPS,
        "BetP must be {}, got {got}",
        betp(want)
    );
    assert!(
        num(&json, "belief") > 0.0,
        "the prior's committed mass survives the challenge: {json}"
    );
    assert_ordered(&json);
}

/// The FALSE-leaning mirror: t = 0.2 seeds {F 0.6, Θ 0.4}. Weak support raises
/// BetP from 0.2 but leaves it FALSE-leaning; before the fix the support stood
/// alone and BetP jumped above 0.5.
#[sqlx::test(migrations = "../../migrations")]
async fn low_truth_seed_leans_false_and_weak_support_raises_it_modestly(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: ingest-only claim, low truth", 0.2).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.3, true).await;

    let got = num(&json, "pignistic_prob");
    assert!(
        got > 0.2 && got < 0.5,
        "weak support on a 0.2 prior raises it but stays FALSE-leaning; got {got}"
    );
    let want = dempster((0.0, 0.6, 0.4), evidence_bba(&pool, &json).await);
    assert!(
        (got - betp(want)).abs() < EPS,
        "BetP must be {}, got {got}",
        betp(want)
    );
    assert_ordered(&json);
    assert_no_warning(&json);

    let rows = seed_rows(&pool, claim_id).await;
    assert_eq!(rows.len(), 1, "one seed row");
    let masses = &rows[0].0;
    assert!(
        (mass_at(masses, "1") - 0.6).abs() < EPS && (mass_at(masses, "0,1") - 0.4).abs() < EPS,
        "t = 0.2 seeds m(FALSE) = 1-2t = 0.6, m(Θ) = 2t = 0.4; got {masses}"
    );
    assert_eq!(mass_at(masses, "0"), 0.0, "no TRUE mass: {masses}");
}

/// The seed is written exactly once, with the pignistic-preserving shape and
/// the exempt-reliability tagging every reader honours.
#[sqlx::test(migrations = "../../migrations")]
async fn truth_value_seed_is_written_once(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: seed idempotency", 0.75).await;
    let author = author_of(&pool, claim_id).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    run_update(&server, &viewer, claim_id, 0.6, true).await;
    let second = run_update(&server, &viewer, claim_id, 0.4, false).await;
    assert_ordered(&second);

    let rows = seed_rows(&pool, claim_id).await;
    assert_eq!(
        rows.len(),
        1,
        "exactly one truth_value_seed row after two updates"
    );
    let (masses, agent, strength, etype, persp, evidence, frame) = &rows[0];
    assert!(
        (mass_at(masses, "0") - 0.5).abs() < EPS && (mass_at(masses, "0,1") - 0.5).abs() < EPS,
        "t = 0.75 seeds m(TRUE) = 2t-1 = 0.5, m(Θ) = 2-2t = 0.5; got {masses}"
    );
    assert_eq!(mass_at(masses, "1"), 0.0, "no FALSE mass: {masses}");
    assert_eq!(
        frame, "binary_truth",
        "seeded on the canonical binary frame"
    );
    assert_eq!(*agent, Some(author), "the authored scalar is the author's");
    assert_eq!(*strength, Some(1.0), "stored undiscounted");
    assert_eq!(*etype, None, "no evidence_type: the exempt-reliability arm");
    assert_eq!(*persp, None, "no perspective");
    assert_eq!(*evidence, None, "no evidence row produced the seed");

    // Every reader discounts through `effective_source_strength`; the seed row
    // must come out of it at exactly 1.0, or its BetP would no longer be t.
    let mut conn = pool.acquire().await.expect("acquire");
    let all = MassFunctionRepository::get_for_claim_binary_frames(&mut *conn, &viewer, claim_id)
        .await
        .expect("binary-frame BBAs");
    assert_eq!(all.len(), 3, "seed + two evidence BBAs");
    let seed_row = all
        .iter()
        .find(|r| r.combination_method.as_deref() == Some("truth_value_seed"))
        .expect("the seed row");
    let calibration = epigraph_engine::calibration::CalibrationConfig::from_workspace_root()
        .expect("repo calibration.toml");
    let reliability =
        epigraph_engine::edge_factor::effective_source_strength(seed_row, None, None, &calibration);
    assert!(
        (reliability - 1.0).abs() < EPS,
        "the seed is read undiscounted; got reliability {reliability}"
    );
}

/// Negative control: a claim that already holds a binary-frame BBA — here on a
/// LEGACY two-hypothesis frame, not `binary_truth` — is never seeded. Its prior
/// already participates in the combine.
#[sqlx::test(migrations = "../../migrations")]
async fn no_seed_when_claim_already_has_a_binary_bba(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: already has a BBA", 0.85).await;
    let legacy = FrameRepository::create(
        &pool,
        &format!("legacy_validity_{}", Uuid::new_v4().simple()),
        Some("a legacy binary frame"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("legacy frame");
    MassFunctionRepository::store_with_perspective(
        &pool,
        claim_id,
        legacy.id,
        Some(seed_agent(&pool).await),
        None,
        &serde_json::json!({"0": 0.6, "0,1": 0.4}),
        None,
        None,
        None,
        Some("empirical"),
        "unknown",
        None,
    )
    .await
    .expect("store legacy BBA");
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.6, true).await;

    assert!(
        seed_rows(&pool, claim_id).await.is_empty(),
        "a claim with an existing binary-frame BBA must not be seeded"
    );
    // The existing BBA and the evidence alone; a seed on top would have
    // committed more mass to TRUE.
    let want = dempster((0.6, 0.0, 0.4), evidence_bba(&pool, &json).await);
    let bel = num(&json, "belief");
    assert!(
        (bel - want.0).abs() < EPS,
        "Bel is the existing BBA and the evidence only ({}), got {bel}",
        want.0
    );
    let got = num(&json, "pignistic_prob");
    assert!(
        (got - betp(want)).abs() < EPS,
        "BetP must be {}, got {got}",
        betp(want)
    );
}

/// t = 0.5 is the vacuous seed: nothing is written, and the result is the
/// evidence alone.
#[sqlx::test(migrations = "../../migrations")]
async fn truth_half_writes_no_seed(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: indifferent prior", 0.5).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.6, true).await;

    assert!(
        seed_rows(&pool, claim_id).await.is_empty(),
        "t = 0.5 writes no seed"
    );
    let want = evidence_bba(&pool, &json).await;
    assert!(
        (num(&json, "pignistic_prob") - betp(want)).abs() < EPS,
        "evidence-only combine ({}): {json}",
        betp(want)
    );
}

/// A truth_value of exactly 1.0 seeds a capped, NOT dogmatic, BBA
/// (m(TRUE) = 0.99, as `build_bba_on_index` caps evidence). A dogmatic seed
/// would absorb every later BBA under Dempster's rule: a strong refutation
/// would leave BetP at exactly 1.0.
#[sqlx::test(migrations = "../../migrations")]
async fn certain_truth_seed_is_capped_so_evidence_can_still_move_it(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: certain prior", 1.0).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);

    let json = run_update(&server, &viewer, claim_id, 0.9, false).await;

    let rows = seed_rows(&pool, claim_id).await;
    assert_eq!(rows.len(), 1, "t = 1.0 is seeded");
    assert!(
        (mass_at(&rows[0].0, "0") - 0.99).abs() < EPS,
        "the seed is capped at m(TRUE) = 0.99; got {}",
        rows[0].0
    );
    let got = num(&json, "pignistic_prob");
    assert!(
        got < 1.0 - 1e-6 && got > 0.5,
        "strong refutation moves a capped certain prior without erasing it; got {got}"
    );
    let want = dempster((0.99, 0.0, 0.01), evidence_bba(&pool, &json).await);
    assert!(
        (got - betp(want)).abs() < EPS,
        "BetP must be {}, got {got}",
        betp(want)
    );
    assert_ordered(&json);
}

/// (A), pinned on its own: a caller that does not seed (here a direct call
/// with `seed_truth_prior = false`, as `backfill_factors` makes) still gets a
/// clamp whose prior is the claim's `truth_value` when `pignistic_prob` is
/// NULL. Evidence alone is {T 0.6} → BetP 0.80; the clamp lifts it to
/// min(0.85, Pl = 1.0) = 0.85.
#[sqlx::test(migrations = "../../migrations")]
async fn clamp_prior_falls_back_to_truth_value_when_not_seeding(pool: sqlx::PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let claim_id = seed_claim(&pool, "fc55465b: unseeded clamp prior", 0.85).await;
    let mut conn = pool.acquire().await.expect("acquire");
    ensure_binary_frame(&mut conn, &viewer)
        .await
        .expect("binary_truth frame");

    let res = auto_wire_ds_update(
        &mut conn,
        &viewer,
        claim_id,
        seed_agent(&pool).await,
        0.6,
        1.0,
        true,
        Some("empirical"),
        None,
        false,
    )
    .await
    .expect("auto_wire_ds_update");

    assert!(
        seed_rows(&pool, claim_id).await.is_empty(),
        "seed_truth_prior = false writes no seed"
    );
    assert!(
        (res.belief - 0.6).abs() < EPS,
        "no seed: Bel is the evidence alone, got {}",
        res.belief
    );
    assert!(
        (res.pignistic_prob - 0.85).abs() < EPS,
        "the clamp's prior falls back to truth_value 0.85, got {}",
        res.pignistic_prob
    );
}
