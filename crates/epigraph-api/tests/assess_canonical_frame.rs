//! `POST /api/v1/claims/:id/assess` writes into the canonical `claim_validity`
//! frame under the one-frame-owns-the-cache rule (backlog 584369df, unit U027).
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `routes/assess.rs::assess_claim` had four defects these arms pin:
//!
//! 1. With no `frame_id` it find-or-created `paper_validity_<slug of
//!    source_url>` (or `research_validity`), so every distinct source minted a
//!    new 2-hypothesis frame. Prod carried 74 of them on 2026-10-05.
//! 2. The slug was cut with `&slug[..80]` on a `String` that keeps non-ASCII
//!    letters, so a multi-byte char straddling byte 80 PANICKED the handler.
//! 3. It wrote the claim's DS cache directly with `belief_frame_id: None`,
//!    NULLing the frame reference and replacing a `binary_truth`-owned cache
//!    with one paper frame's number (the clobber `recompute_claim_cached_belief`
//!    exists to prevent).
//! 4. The input BBA (agent NULL, perspective NULL) and the "combined result"
//!    row it stored afterwards share one `UNIQUE NULLS NOT DISTINCT` key, so
//!    the second overwrote the first and repeated calls never accumulated.
//!
//! # Harness
//!
//! There is deliberately NO `set_current_dir` here. Cargo runs integration
//! tests with the CRATE directory as cwd, and the handler used to load
//! calibration from the cwd-relative `calibration.toml`, which failed there;
//! it now resolves it like every other DS path. Every arm below is therefore
//! also a pin on that.
//!
//! The handler is invoked directly as an `async fn`, on the `#[sqlx::test]`
//! superuser pool, with the viewer of a seeded agent (the call's evidence
//! perspective records that principal, and `perspectives.owner_agent_id` is a
//! foreign key, so the nil-principal public viewer cannot call it). That is
//! deliberate: this file pins
//! the handler's FRAME and CACHE semantics, not its tenancy (the stamping of
//! `assess.rs`'s one raw-pool site is a separate change), so an RLS refusal
//! must not be able to make an arm pass or fail.

#![cfg(feature = "db")]

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::errors::ApiError;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest, AssessClaimResponse};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{public_viewer, seed_agent_with_group, seed_public_claim};

// ── fixture ──

fn request(supports: bool, confidence: f64, source_url: Option<&str>) -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": confidence,
        "supports": supports,
        "source_url": source_url,
    }))
    .expect("AssessClaimRequest deserializes")
}

fn request_on(frame: Uuid, supports: bool, confidence: f64) -> AssessClaimRequest {
    let mut req = request(supports, confidence, None);
    req.frame_id = Some(frame);
    req
}

/// `Viewer` is not `Clone`, so each call resolves its own viewer for `caller`.
async fn try_assess(
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    req: AssessClaimRequest,
) -> Result<AssessClaimResponse, ApiError> {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let Json(resp) = assess_claim(
        ViewerExtractor(viewer),
        State(state),
        Path(claim),
        Json(req),
    )
    .await?;
    Ok(resp)
}

async fn assess(
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    req: AssessClaimRequest,
) -> AssessClaimResponse {
    try_assess(pool, caller, claim, req)
        .await
        .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"))
}

async fn mass_function_count(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE claim_id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("count mass_functions")
}

async fn create_frame(pool: &PgPool, name: &str, hypotheses: &[&str]) -> Uuid {
    let hyps: Vec<String> = hypotheses.iter().map(|h| (*h).to_string()).collect();
    epigraph_db::FrameRepository::create(pool, name, None, &hyps)
        .await
        .unwrap_or_else(|e| panic!("create frame {name}: {e}"))
        .id
}

/// A public claim plus its author, who is also the assess caller.
async fn seed_claim(pool: &PgPool, content: &str) -> (Uuid, Viewer, Uuid) {
    let (agent, _group) = seed_agent_with_group(pool, "assess-canonical").await;
    let claim = seed_public_claim(pool, agent, content).await;
    (claim, public_viewer(pool).await, agent)
}

/// Give `claim` a `binary_truth` BBA (BetP(TRUE) = 0.85) and let the cache
/// rule write it, so `binary_truth` owns `claims.belief_frame_id`.
async fn seed_binary_truth_cache(pool: &PgPool, viewer: &Viewer, claim: Uuid) -> (Uuid, f64) {
    let mut conn = pool.acquire().await.expect("acquire");
    let binary = epigraph_engine::edge_factor::ensure_binary_frame(&mut conn, viewer)
        .await
        .expect("ensure binary_truth");
    epigraph_db::MassFunctionRepository::store_with_perspective(
        &mut *conn,
        claim,
        binary,
        None,
        None,
        &serde_json::json!({"0": 0.7, "0,1": 0.3}),
        None,
        Some("seed"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("seed binary_truth BBA");
    let written =
        epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, viewer, claim)
            .await
            .expect("recompute cache");
    assert!(
        written,
        "CALIBRATION: the seeded binary_truth cache must be written"
    );

    let (frame, betp) = cache(pool, claim).await;
    assert_eq!(
        frame,
        Some(binary),
        "CALIBRATION: binary_truth must own the cache before the assess call"
    );
    (binary, betp.expect("seeded BetP"))
}

async fn cache(pool: &PgPool, claim: Uuid) -> (Option<Uuid>, Option<f64>) {
    sqlx::query_as("SELECT belief_frame_id, pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read claim cache")
}

async fn frame_names(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT name FROM frames ORDER BY name")
        .fetch_all(pool)
        .await
        .expect("list frames")
}

async fn frame_name_of(pool: &PgPool, frame: Uuid) -> String {
    sqlx::query_scalar("SELECT name FROM frames WHERE id = $1")
        .bind(frame)
        .fetch_one(pool)
        .await
        .expect("frame name")
}

async fn rows_on(pool: &PgPool, claim: Uuid, frame: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT masses FROM mass_functions WHERE claim_id = $1 AND frame_id = $2 \
         ORDER BY created_at",
    )
    .bind(claim)
    .bind(frame)
    .fetch_all(pool)
    .await
    .expect("mass_functions on (claim, frame)")
}

// ── arms ──

/// Two assess calls with different `source_url`s and no `frame_id` must not
/// mint a frame per source: both land on the one `claim_validity` frame.
///
/// Main: two new `paper_validity_https___example_org_a/_b` frames appear.
#[sqlx::test(migrations = "../../migrations")]
async fn assess_without_frame_id_does_not_mint_a_frame_per_source(pool: PgPool) {
    let (claim, viewer, caller) = seed_claim(&pool, "assess mints no per-source frame").await;
    // binary_truth exists before the baseline, so the cache rule's own
    // get-or-create of it is not counted as a mint.
    seed_binary_truth_cache(&pool, &viewer, claim).await;
    let before = frame_names(&pool).await;

    let a = assess(
        &pool,
        caller,
        claim,
        request(true, 0.8, Some("https://example.org/a")),
    )
    .await;
    let b = assess(
        &pool,
        caller,
        claim,
        request(true, 0.8, Some("https://example.org/b")),
    )
    .await;

    let after = frame_names(&pool).await;
    let new: Vec<&String> = after.iter().filter(|n| !before.contains(n)).collect();
    assert!(
        new.iter().all(|n| n.as_str() == "claim_validity"),
        "assess minted frames other than claim_validity: {new:?}"
    );
    assert!(
        !after
            .iter()
            .any(|n| n.starts_with("paper_validity_") || n == "research_validity"),
        "a per-source assess frame exists: {after:?}"
    );
    assert_eq!(
        a.frame_id, b.frame_id,
        "both sources must land on one frame"
    );
    assert_eq!(frame_name_of(&pool, a.frame_id).await, "claim_validity");
}

/// The cache rule: a claim whose cache `binary_truth` owns keeps that owner and
/// is not lowered by a weak supporting assess on another frame.
///
/// Main: `belief_frame_id` becomes NULL and BetP becomes the single weak
/// paper-frame BBA's value.
#[sqlx::test(migrations = "../../migrations")]
async fn assess_does_not_repoint_or_lower_a_binary_truth_cache(pool: PgPool) {
    let (claim, viewer, caller) = seed_claim(&pool, "assess respects the binary_truth cache").await;
    let (binary, p0) = seed_binary_truth_cache(&pool, &viewer, claim).await;

    assess(
        &pool,
        caller,
        claim,
        request(true, 0.3, Some("https://example.org/weak")),
    )
    .await;

    let (frame, betp) = cache(&pool, claim).await;
    assert_eq!(
        frame,
        Some(binary),
        "assess re-pointed the cache away from binary_truth (to {frame:?})"
    );
    let betp = betp.expect("cache BetP");
    assert!(
        betp >= p0 - 1e-9,
        "a supporting assess lowered the cached BetP: {p0} -> {betp}"
    );
}

/// Each assess call is its own BBA row, so repeated calls accumulate instead of
/// the last one overwriting the first, and no combined row is stored beside
/// them. The stored rows are on the 3-way frame's key space: the 2-way BBA's
/// ignorance `{0,1}` is remapped onto Theta `{0,1,2}`, never left on
/// `{supported, refuted}`.
///
/// Main: ONE row, because the input BBA and the combined row share the
/// `(claim, frame, NULL agent, NULL perspective)` key.
#[sqlx::test(migrations = "../../migrations")]
async fn repeated_assess_calls_accumulate(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess accumulates").await;

    let first = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    let second = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    assert_eq!(first.frame_id, second.frame_id);

    let rows = rows_on(&pool, claim, second.frame_id).await;
    assert_eq!(
        rows.len(),
        2,
        "two assess calls must leave exactly two BBA rows on the frame, got {rows:?}"
    );
    for masses in &rows {
        let keys: Vec<&String> = masses.as_object().expect("masses object").keys().collect();
        assert!(
            !keys.iter().any(|k| k.as_str() == "0,1"),
            "the 2-way ignorance key `0,1` was stored on the 3-way frame: {masses}"
        );
        assert!(
            keys.iter().any(|k| k.as_str() == "0,1,2"),
            "the BBA's ignorance must land on Theta `0,1,2`: {masses}"
        );
    }

    // Both rows must be COMBINED, not merely stored: two independent supporting
    // BBAs raise the response BetP strictly. (Under a mutant that combines only
    // the current call's row, both rows exist and p2 == p1.)
    let p1 = first.pignistic_prob.expect("first BetP");
    let p2 = second.pignistic_prob.expect("second BetP");
    assert!(
        p2 > p1 + 1e-6,
        "a second supporting assess must raise the response BetP: {p1} -> {p2}"
    );
}

/// With no `binary_truth` BBA on the claim, assess's own `claim_validity` frame
/// becomes the cache owner and the cache is actually written.
///
/// Main: the cache is written with `belief_frame_id: None`, and the frame is a
/// `paper_validity_*` / `research_validity` one. Also kills a mutant that drops
/// the cache refresh altogether (the cache stays unowned).
#[sqlx::test(migrations = "../../migrations")]
async fn assess_records_claim_validity_as_cache_owner_without_binary_truth(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess owns an unowned cache").await;
    assert_eq!(
        cache(&pool, claim).await.0,
        None,
        "CALIBRATION: a fresh claim's cache has no owning frame"
    );

    let resp = assess(&pool, caller, claim, request(true, 0.8, None)).await;
    assert_eq!(frame_name_of(&pool, resp.frame_id).await, "claim_validity");

    let (frame, betp) = cache(&pool, claim).await;
    assert_eq!(
        frame,
        Some(resp.frame_id),
        "claim_validity must own the cache of a claim with no binary_truth BBA"
    );
    assert!(betp.is_some(), "the owner's recompute must write a BetP");
}

/// An explicit 2-hypothesis `frame_id` is used as given: the remap is the
/// identity there, so the stored row keeps the `0,1` ignorance key, and no
/// `claim_validity` frame is created. An unknown `frame_id` is a 404 that
/// writes nothing.
///
/// Passes on main too: this pins behaviour the change must PRESERVE (it kills
/// a mutant that ignores the explicit `frame_id`).
#[sqlx::test(migrations = "../../migrations")]
async fn explicit_frame_id_is_used_as_given(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess on an explicit frame").await;
    let frame = create_frame(&pool, "paper_validity_x", &["supported", "refuted"]).await;

    let resp = assess(&pool, caller, claim, request_on(frame, true, 0.8)).await;
    assert_eq!(resp.frame_id, frame, "the explicit frame_id must be used");
    let rows = rows_on(&pool, claim, frame).await;
    assert_eq!(rows.len(), 1, "one call, one row: {rows:?}");
    let keys: Vec<&String> = rows[0].as_object().expect("masses object").keys().collect();
    assert!(
        keys.iter().any(|k| k.as_str() == "0,1"),
        "on a 2-way frame the ignorance key stays `0,1`: {}",
        rows[0]
    );
    assert!(
        !frame_names(&pool)
            .await
            .iter()
            .any(|n| n == "claim_validity"),
        "an explicit frame_id must not create claim_validity"
    );

    let before = mass_function_count(&pool, claim).await;
    let missing = Uuid::new_v4();
    let err = try_assess(&pool, caller, claim, request_on(missing, true, 0.8))
        .await
        .expect_err("an unknown frame_id must be refused");
    assert!(
        matches!(&err, ApiError::NotFound { entity, .. } if entity == "frame"),
        "an unknown frame_id must be a frame 404, got {err:?}"
    );
    assert_eq!(
        mass_function_count(&pool, claim).await,
        before,
        "a refused call writes no BBA"
    );
}

/// A pre-existing `claim_validity` frame over the wrong hypotheses is refused,
/// not written into with 3-way-remapped masses.
///
/// Main: assess never looks at `claim_validity` and writes a BBA on a
/// per-source frame.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_validity_frame_over_other_hypotheses_is_refused(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess on a wrong claim_validity").await;
    create_frame(&pool, "claim_validity", &["supported", "unsupported"]).await;

    let result = try_assess(&pool, caller, claim, request(true, 0.8, None)).await;
    assert!(
        result.is_err(),
        "a claim_validity frame over other hypotheses must be refused"
    );
    assert_eq!(
        mass_function_count(&pool, claim).await,
        0,
        "a refused call writes no BBA"
    );
}

/// A `source_url` whose 80th byte falls inside a multi-byte char.
///
/// Main: panics with "byte index 80 is not a char boundary".
#[sqlx::test(migrations = "../../migrations")]
async fn non_ascii_source_url_does_not_panic(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess with a non-ASCII source").await;
    let url = format!("{}é", "a".repeat(79));
    assert_eq!(url.len(), 81, "CALIBRATION: `é` must straddle byte 80");

    let resp = assess(&pool, caller, claim, request(true, 0.6, Some(&url))).await;
    assert_eq!(resp.claim_id, claim);
}
