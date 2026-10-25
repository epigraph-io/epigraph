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
//!    the second overwrote the first. Ruling Q-U027F-2 (operator, 2026-10-22):
//!    ONE assessment per (claim, frame, owner), where the owner is the calling
//!    agent's operator or the agent itself. A repeat by any agent of the same
//!    human REPLACES that owner's row (a reversal is reported as a contest),
//!    and only different owners' assessments combine.
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
//! superuser pool, with the viewer of a seeded agent (the owner's assessment
//! slot perspective records the owner, and `perspectives.owner_agent_id` is a
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

/// The response BetP one `req` gives on a fresh claim assessed by a fresh agent:
/// what a call that REPLACES every earlier row of its owner must equal.
async fn single_call_betp(pool: &PgPool, req: AssessClaimRequest) -> f64 {
    let (claim, _viewer, caller) = seed_claim(pool, "assess single-call baseline").await;
    assess(pool, caller, claim, req)
        .await
        .pignistic_prob
        .expect("baseline BetP")
}

/// Link `agent` to human operator `operator` (migration 107), on the harness
/// connection.
async fn link_to_operator(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent to its operator");
    assert!(out.membership_live && out.link_live, "{out:?}");
}

/// Ruling Q-U027F-2: ONE assessment per (claim, frame, owner). A caller's
/// repeat REPLACES its own row instead of folding as independent evidence:
/// ten identical calls used to drive BetP towards 1. An identical repeat
/// leaves the BetP unchanged; a reversal leaves exactly the reversal's single
/// -call BetP. The stored row is on the 3-way frame's key space: the 2-way
/// BBA's ignorance `{0,1}` is remapped onto Theta `{0,1,2}`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_callers_repeat_assessment_replaces_its_own(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess replaces per caller").await;

    let first = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    let mut last = first.pignistic_prob.expect("first BetP");
    for _ in 0..4 {
        let again = assess(&pool, caller, claim, request(true, 0.9, None)).await;
        let p = again.pignistic_prob.expect("BetP");
        assert!(
            (p - last).abs() < 1e-9,
            "an identical repeat must not move the BetP: {last} -> {p}"
        );
        last = p;
        assert_eq!(
            again.replaced_assessments.len(),
            1,
            "{:?}",
            again.replaced_assessments
        );
        assert!(!again.replaced_assessments[0].contested);
    }
    let rows = rows_on(&pool, claim, first.frame_id).await;
    assert_eq!(rows.len(), 1, "one row per caller, got {rows:?}");
    let keys: Vec<&String> = rows[0].as_object().expect("masses object").keys().collect();
    assert!(!keys.iter().any(|k| k.as_str() == "0,1"), "{rows:?}");
    assert!(keys.iter().any(|k| k.as_str() == "0,1,2"), "{rows:?}");

    // A reversal by the same caller replaces, and is flagged as contesting
    // the caller's own earlier verdict.
    let reversed = assess(&pool, caller, claim, request(false, 0.6, None)).await;
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 1);
    let baseline = single_call_betp(&pool, request(false, 0.6, None)).await;
    let p = reversed.pignistic_prob.expect("reversed BetP");
    assert!(
        (p - baseline).abs() < 1e-9,
        "the reversal must replace, not fold: {p} vs single-call {baseline}"
    );
    assert_eq!(reversed.replaced_assessments.len(), 1);
    assert!(
        reversed.replaced_assessments[0].contested,
        "{:?}",
        reversed.replaced_assessments
    );
    assert_eq!(
        reversed.replaced_assessments[0].source_agent_id,
        Some(caller)
    );
}

/// Ruling Q-U027F-2, the owner half: different agents of the SAME human
/// replace each other (and a reversal is a contest), never aggregate. The
/// human's own assessment shares the slot too.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_of_one_human_replace_each_other_and_never_aggregate(pool: PgPool) {
    let (claim, _viewer, _author) = seed_claim(&pool, "assess one human").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "assess-human").await;
    let (one, _) = seed_agent_with_group(&pool, "assess-agent-one").await;
    let (two, _) = seed_agent_with_group(&pool, "assess-agent-two").await;
    link_to_operator(&pool, one, human).await;
    link_to_operator(&pool, two, human).await;

    let first = assess(&pool, one, claim, request(true, 0.9, None)).await;
    assert!(
        first.replaced_assessments.is_empty(),
        "{:?}",
        first.replaced_assessments
    );
    let second = assess(&pool, two, claim, request(true, 0.9, None)).await;
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 1);
    assert_eq!(second.replaced_assessments.len(), 1);
    assert_eq!(
        second.replaced_assessments[0].source_agent_id,
        Some(human),
        "the slot is the owner's"
    );
    assert!(!second.replaced_assessments[0].contested);
    assert!(
        (second.pignistic_prob.expect("BetP") - first.pignistic_prob.expect("BetP")).abs() < 1e-9,
        "a sibling's agreeing assessment must not add up"
    );

    let reversal = assess(&pool, one, claim, request(false, 0.6, None)).await;
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 1);
    assert_eq!(
        reversal.replaced_assessments[0].source_agent_id,
        Some(human)
    );
    assert!(
        reversal.replaced_assessments[0].contested,
        "a sibling's reversal is a contest"
    );

    let by_human = assess(&pool, human, claim, request(true, 0.7, None)).await;
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 1);
    assert_eq!(
        by_human.replaced_assessments[0].source_agent_id,
        Some(human)
    );
    let baseline = single_call_betp(&pool, request(true, 0.7, None)).await;
    assert!((by_human.pignistic_prob.expect("BetP") - baseline).abs() < 1e-9);
}

/// The assessment slot is assess's own: a BBA another writer stored for the
/// same agent on the same (claim, frame) with no perspective (the shape
/// `/frames/:id/evidence` writes) is neither overwritten nor reported as
/// replaced, and both still combine.
#[sqlx::test(migrations = "../../migrations")]
async fn the_assessment_slot_never_overwrites_another_writers_row(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess own slot").await;
    let first = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    let other = epigraph_db::MassFunctionRepository::store_with_perspective(
        &pool,
        claim,
        first.frame_id,
        Some(caller),
        None,
        &serde_json::json!({"0": 0.5, "0,1,2": 0.5}),
        None,
        Some("discount"),
        None,
        None,
        "unknown",
        None,
    )
    .await
    .expect("another writer's agent-keyed row");
    let again = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    assert!(
        again
            .replaced_assessments
            .iter()
            .all(|r| r.mass_function_id != other),
        "{:?}",
        again.replaced_assessments
    );
    assert_eq!(
        again.replaced_assessments.len(),
        1,
        "only assess's own slot"
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions WHERE id = $1")
        .bind(other)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(kept, 1, "the other writer's row survives");
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 2);
}

/// An agent whose sole oauth client is allowlisted to human `human` (migration
/// 149's third binding), as a maintenance session.
async fn allowlist_client_of(pool: &PgPool, agent: Uuid, human: Uuid) {
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, 'assess host', 'service', ARRAY['claims:write'], \
                 ARRAY['claims:write'], 'active', $3, 'Fixture Org', \
                 'fixture@example.invalid') RETURNING id",
    )
    .bind(format!("epigraph_assess_{agent}"))
    .bind(blake3::hash(agent.as_bytes()).as_bytes().as_slice())
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("the service client");
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::query("SET ROLE epigraph_maintenance")
        .execute(&mut *conn)
        .await
        .expect("maintenance role");
    sqlx::query("SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'assess')")
        .bind(client)
        .bind(human)
        .execute(&mut *conn)
        .await
        .expect("allow the client");
    sqlx::query("RESET ROLE")
        .execute(&mut *conn)
        .await
        .expect("reset role");
}

/// The owner is the caller's HUMAN across every binding of migration 149: an
/// agent whose client is allowlisted to the human shares the human's one slot
/// with the human and with the human's linked agent (no aggregation through
/// the allowlist binding).
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_client_shares_its_humans_one_slot(pool: PgPool) {
    let (claim, _viewer, _author) = seed_claim(&pool, "assess allowlist").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "assess-allow-human").await;
    let (linked, _) = seed_agent_with_group(&pool, "assess-allow-linked").await;
    let (service, _) = seed_agent_with_group(&pool, "assess-allow-service").await;
    link_to_operator(&pool, linked, human).await;
    allowlist_client_of(&pool, service, human).await;

    let first = assess(&pool, service, claim, request(true, 0.9, None)).await;
    assert_eq!(
        first.owner_agent_id,
        Some(human),
        "the allowlisted client acts for the human"
    );
    assert_eq!(first.assessed_by, Some(service));
    let second = assess(&pool, linked, claim, request(true, 0.9, None)).await;
    assert_eq!(second.owner_agent_id, Some(human));
    assert_eq!(second.replaced_assessments.len(), 1);
    assert_eq!(rows_on(&pool, claim, first.frame_id).await.len(), 1);
    assert!(
        (second.pignistic_prob.expect("BetP") - first.pignistic_prob.expect("BetP")).abs() < 1e-9,
        "one human does not aggregate through the allowlist binding"
    );
}

/// A caller whose only binding is a RETIRED operator link is refused: its own
/// slot would give its human a second assessment. Nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_with_only_a_retired_link_is_refused(pool: PgPool) {
    let (claim, _viewer, _author) = seed_claim(&pool, "assess retired link").await;
    let (human, _) = viewer_fixture::seed_human_operator(&pool, "assess-retired-human").await;
    let (retired, _) = seed_agent_with_group(&pool, "assess-retired-agent").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        let out = epigraph_db::AgentRepository::link_retired_agent(&mut conn, retired, human)
            .await
            .expect("a retired link");
        assert!(out.link_retired, "{out:?}");
    }
    let before = mass_function_count(&pool, claim).await;
    let err = try_assess(&pool, retired, claim, request(true, 0.9, None))
        .await
        .expect_err("a retired-only binding is refused");
    assert!(matches!(err, ApiError::Forbidden { .. }), "{err:?}");
    assert_eq!(
        mass_function_count(&pool, claim).await,
        before,
        "nothing written"
    );
    // Control: the human itself assesses.
    assess(&pool, human, claim, request(true, 0.9, None)).await;
}

/// `contested` is the DIRECTION of the verdict, not a BetP threshold: a weak
/// then a strong support is not a contest (a 0.5 BetP cut flags it on the
/// 3-way frame), and a weak refutation then a weak support is.
#[sqlx::test(migrations = "../../migrations")]
async fn contested_is_a_change_of_direction(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess direction").await;
    assess(&pool, caller, claim, request(true, 0.3, None)).await;
    let stronger = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    assert!(
        !stronger.replaced_assessments[0].contested,
        "same direction, stronger"
    );
    let prior = stronger.replaced_assessments[0]
        .prior_pignistic_prob
        .expect("the prior BetP");
    assert!(prior < stronger.pignistic_prob.expect("BetP"), "{prior}");

    let (claim2, _viewer, caller2) = seed_claim(&pool, "assess direction two").await;
    assess(&pool, caller2, claim2, request(false, 0.1, None)).await;
    let flipped = assess(&pool, caller2, claim2, request(true, 0.3, None)).await;
    assert!(
        flipped.replaced_assessments[0].contested,
        "weak refute then weak support"
    );
}

/// The slot is addressable only through assess: `/frames/:id/evidence` naming
/// an agent together with that agent's slot perspective is refused, and
/// nothing is written. Control: the same body with another perspective lands.
#[sqlx::test(migrations = "../../migrations")]
async fn another_route_cannot_write_into_an_assessment_slot(pool: PgPool) {
    use epigraph_api::routes::belief::{submit_evidence, SubmitEvidenceRequest};
    let (claim, _viewer, caller) = seed_claim(&pool, "assess slot forge").await;
    let first = assess(&pool, caller, claim, request(true, 0.9, None)).await;
    let slot = epigraph_db::repos::mass_function::assessment_slot_perspective(Some(caller));
    let body = |perspective: Uuid| -> SubmitEvidenceRequest {
        serde_json::from_value(serde_json::json!({
            "claim_id": claim, "agent_id": caller, "perspective_id": perspective,
            "masses": {"1": 0.9, "0,1,2": 0.1},
        }))
        .expect("evidence request")
    };
    let before = rows_on(&pool, claim, first.frame_id).await;
    let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
    let state = AppState::with_db(pool.clone(), ApiConfig::default());
    let err = submit_evidence(
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(first.frame_id),
        Json(body(slot)),
    )
    .await
    .expect_err("the assessment slot is refused");
    assert!(matches!(err, ApiError::ValidationError { .. }), "{err:?}");
    assert_eq!(
        rows_on(&pool, claim, first.frame_id).await,
        before,
        "nothing written"
    );

    let other = Uuid::new_v4();
    epigraph_db::PerspectiveRepository::ensure_evidence_perspective(&pool, other, Some(caller))
        .await
        .expect("another perspective");
    let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
    let scoped_state = AppState::with_scoped_pool(
        viewer_fixture::scoped_pool(&pool).await,
        ApiConfig::default(),
    );
    let _ = submit_evidence(
        ViewerExtractor(viewer),
        State(scoped_state),
        Path(first.frame_id),
        Json(body(other)),
    )
    .await
    .expect("control: another perspective lands");
    assert_eq!(
        rows_on(&pool, claim, first.frame_id).await.len(),
        before.len() + 1
    );
}

/// Ruling Q-U027F-2, the other half: assessments by DIFFERENT owners are
/// independent evidence and still combine. Two unrelated agents' supporting
/// rows both stay and raise the BetP strictly. (Under a mutant that combines
/// only the current call's row, both rows exist and p2 == p1.)
#[sqlx::test(migrations = "../../migrations")]
async fn assessments_by_different_owners_accumulate(pool: PgPool) {
    let (claim, _viewer, a) = seed_claim(&pool, "assess two owners").await;
    let (b, _) = seed_agent_with_group(&pool, "assess-other-owner").await;
    let first = assess(&pool, a, claim, request(true, 0.9, None)).await;
    let second = assess(&pool, b, claim, request(true, 0.9, None)).await;
    assert!(
        second.replaced_assessments.is_empty(),
        "{:?}",
        second.replaced_assessments
    );
    assert_eq!(rows_on(&pool, claim, second.frame_id).await.len(), 2);
    let p1 = first.pignistic_prob.expect("first BetP");
    let p2 = second.pignistic_prob.expect("second BetP");
    assert!(
        p2 > p1 + 1e-6,
        "two owners' supporting BBAs combine: {p1} -> {p2}"
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
        rows_on(&pool, claim, CANONICAL_CLAIM_VALIDITY)
            .await
            .is_empty(),
        "an explicit frame_id must not write into claim_validity"
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

/// The canonical `claim_validity` row over the wrong hypotheses (154 refuses
/// to seed or apply over one; modelled here by corrupting it in place) is
/// refused, not written into with 3-way-remapped masses.
///
/// Main: assess never looks at `claim_validity` and writes a BBA on a
/// per-source frame.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_validity_frame_over_other_hypotheses_is_refused(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess on a wrong claim_validity").await;
    sqlx::query("UPDATE frames SET hypotheses = ARRAY['supported','unsupported'] WHERE id = $1")
        .bind(CANONICAL_CLAIM_VALIDITY)
        .execute(&pool)
        .await
        .expect("corrupt the canonical row's axis");
    let perspectives_before: i64 = sqlx::query_scalar("SELECT count(*) FROM perspectives")
        .fetch_one(&pool)
        .await
        .expect("count perspectives");

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
    let perspectives_after: i64 = sqlx::query_scalar("SELECT count(*) FROM perspectives")
        .fetch_one(&pool)
        .await
        .expect("count perspectives");
    assert_eq!(
        perspectives_after, perspectives_before,
        "a refused call writes no evidence perspective"
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

// ── canonical frame by id (U027F) ──
//
// The canonical `claim_validity` frame is prod's row `8a594393`: public, owned
// by the nil (world) group, hypotheses `[supported, refuted, uncertain]`.
// Migration 154 seeds it on a fresh database. Resolving it BY NAME through the
// caller's viewer, with a create on a miss, let whoever named a frame
// `claim_validity` first decide what every later assess wrote into: a frame
// over other hypotheses refused every later caller (frames.name is UNIQUE, so
// the right one could never be created), and a frame with the right
// hypotheses but a non-canonical owner received everybody's evidence.

/// Prod's canonical `claim_validity` frame id. A literal here, not the crate
/// constant, so this file pins the VALUE.
const CANONICAL_CLAIM_VALIDITY: Uuid = Uuid::from_u128(0x8a59_4393_c343_4f1a_b942_5c5b_7862_f792);

/// Frames other than `binary_truth`, whose by-name get-or-create the cache
/// rule still runs (Q40, a separate unit).
async fn frames_besides_binary_truth(pool: &PgPool) -> Vec<String> {
    frame_names(pool)
        .await
        .into_iter()
        .filter(|n| n != "binary_truth")
        .collect()
}

/// With no `frame_id`, assess writes into the canonical row `8a594393`, and
/// never creates a frame to do it.
///
/// 9f2465e3: no row carries that id; the by-name get-or-create mints a
/// `claim_validity` frame under a random id.
#[sqlx::test(migrations = "../../migrations")]
async fn assess_lands_on_the_canonical_claim_validity_id(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess lands on 8a594393").await;
    let frames_before = frames_besides_binary_truth(&pool).await;

    let resp = assess(&pool, caller, claim, request(true, 0.8, None)).await;

    assert_eq!(
        resp.frame_id, CANONICAL_CLAIM_VALIDITY,
        "assess must write into the canonical claim_validity frame 8a594393"
    );
    let rows = rows_on(&pool, claim, CANONICAL_CLAIM_VALIDITY).await;
    assert_eq!(
        rows.len(),
        1,
        "the call's BBA must land on 8a594393: {rows:?}"
    );
    assert_eq!(
        frames_besides_binary_truth(&pool).await,
        frames_before,
        "assess must not create a frame to resolve claim_validity"
    );
}

/// Another caller naming a frame `claim_validity` (POST /frames does exactly
/// `FrameRepository::create`) over other hypotheses cannot make a later
/// caller's assess fail.
///
/// 9f2465e3: the attacker's create succeeds on a database with no
/// `claim_validity` yet, and the victim's assess errors with `frame
/// "claim_validity" exists over ["supported", "unsupported"]` from then on.
#[sqlx::test(migrations = "../../migrations")]
async fn a_frame_squatting_the_claim_validity_name_cannot_fail_another_callers_assess(
    pool: PgPool,
) {
    let (claim, _viewer, victim) = seed_claim(&pool, "assess after a name squat").await;
    // With 154's seed in place the canonical row already holds the UNIQUE
    // name, so the squat itself is refused: that is the SEED-side defence,
    // pinned here. (The resolver-side defence, ignoring any frame merely
    // NAMED claim_validity, is pinned by the owned-squatter arm below, which
    // removes the canonical row so the squat can land.)
    let squat = epigraph_db::FrameRepository::create(
        &pool,
        "claim_validity",
        Some("squatter"),
        &["supported".to_string(), "unsupported".to_string()],
    )
    .await;
    assert!(
        squat.is_err(),
        "the seeded canonical row must hold the name claim_validity, so a second \
         frame of that name is refused: {squat:?}"
    );

    let result = try_assess(&pool, victim, claim, request(true, 0.8, None)).await;
    let resp = result.unwrap_or_else(|e| {
        panic!("a frame another caller named claim_validity made this caller's assess fail: {e:?}")
    });
    assert_eq!(
        resp.frame_id, CANONICAL_CLAIM_VALIDITY,
        "the victim's evidence must land on the canonical frame"
    );
}

/// A `claim_validity` frame with the right hypotheses but NOT the canonical
/// row (another id, owned by the attacker's group) never receives assess's
/// evidence. Modelled with 8a594393 absent (a database the seed has not run
/// on): the squatter exists only because the canonical row does not. With the
/// canonical row missing, the intended behaviour is a refusal that writes
/// nothing; 154's pre-check refuses to seed over such a squatter.
///
/// 9f2465e3: the by-name lookup finds the squatter and stores the victim's BBA
/// on it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_validity_frame_owned_by_another_group_never_receives_assess_evidence(
    pool: PgPool,
) {
    let (claim, _viewer, victim) = seed_claim(&pool, "assess beside an owned squatter").await;
    let (_attacker, attacker_group) =
        viewer_fixture::seed_agent_with_group(&pool, "assess-squatter").await;
    sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(CANONICAL_CLAIM_VALIDITY)
        .execute(&pool)
        .await
        .expect("model a database without the canonical row");
    let squatter: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, description, hypotheses, visibility, owner_group_id) \
         VALUES ('claim_validity', 'squatter', ARRAY['supported','refuted','uncertain'], \
                 'public', $1) RETURNING id",
    )
    .bind(attacker_group)
    .fetch_one(&pool)
    .await
    .expect("CALIBRATION: a group-owned public claim_validity frame can be inserted");

    let result = try_assess(&pool, victim, claim, request(true, 0.8, None)).await;

    assert!(
        rows_on(&pool, claim, squatter).await.is_empty(),
        "assess stored the victim's BBA on the attacker-owned claim_validity frame {squatter}"
    );
    let err = match result {
        Ok(resp) => panic!(
            "with the canonical frame missing, assess must refuse; it answered on frame {}",
            resp.frame_id
        ),
        Err(e) => format!("{e:?}"),
    };
    assert!(
        err.contains(&CANONICAL_CLAIM_VALIDITY.to_string()),
        "the refusal must name the missing canonical frame, got: {err}"
    );
    assert_eq!(
        mass_function_count(&pool, claim).await,
        0,
        "with the canonical frame missing, assess must write nothing"
    );
}

async fn perspective_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM perspectives")
        .fetch_one(pool)
        .await
        .expect("count perspectives")
}

/// The canonical id under ANOTHER name is not the canonical frame: refused,
/// nothing written. (Only the resolver's NAME check sees this: the
/// hypotheses are still the canonical ones.)
///
/// 9f2465e3: assess resolves by name, finds no `claim_validity`, and creates
/// one under a random id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_renamed_canonical_row_is_refused(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess on a renamed canonical row").await;
    sqlx::query("UPDATE frames SET name = 'not_claim_validity' WHERE id = $1")
        .bind(CANONICAL_CLAIM_VALIDITY)
        .execute(&pool)
        .await
        .expect("rename the canonical row");
    let perspectives_before = perspective_count(&pool).await;

    let result = try_assess(&pool, caller, claim, request(true, 0.8, None)).await;

    assert!(
        result.is_err(),
        "the canonical id under another name must be refused, got frame {:?}",
        result.as_ref().map(|r| r.frame_id)
    );
    assert_eq!(
        mass_function_count(&pool, claim).await,
        0,
        "a refused call writes no BBA"
    );
    assert_eq!(
        perspective_count(&pool).await,
        perspectives_before,
        "a refused call writes no evidence perspective"
    );
}

/// With the canonical row absent and NO squatter, assess refuses and creates
/// nothing: neither a frame of its own nor the canonical id itself (seeding is
/// migration 154's job, never a request's).
///
/// 9f2465e3: the by-name get-or-create mints `claim_validity` under a random id
/// and the call succeeds.
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_canonical_row_is_never_created_at_request_time(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess with no canonical row").await;
    sqlx::query("DELETE FROM frames WHERE id = $1")
        .bind(CANONICAL_CLAIM_VALIDITY)
        .execute(&pool)
        .await
        .expect("model a database without the canonical row");
    let frames_before = frames_besides_binary_truth(&pool).await;

    let result = try_assess(&pool, caller, claim, request(true, 0.8, None)).await;

    assert!(
        result.is_err(),
        "with the canonical frame missing, assess must refuse, got frame {:?}",
        result.as_ref().map(|r| r.frame_id)
    );
    assert_eq!(
        frames_besides_binary_truth(&pool).await,
        frames_before,
        "assess must not create a frame when the canonical one is missing"
    );
    let canonical_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM frames WHERE id = $1")
        .bind(CANONICAL_CLAIM_VALIDITY)
        .fetch_one(&pool)
        .await
        .expect("count canonical rows");
    assert_eq!(
        canonical_rows, 0,
        "assess must not seed the canonical row itself"
    );
    assert_eq!(
        mass_function_count(&pool, claim).await,
        0,
        "a refused call writes no BBA"
    );
}

// ── the per-write refresh inherits the bulk recompute guard ──
//
// assess refreshes the claim's cache through
// `recompute_claim_cached_belief`, so it resolves the owner frame through the
// same guarded lookup as the bulk recomputers. These arms pin the two
// agent-visible consequences. Like the rest of this file they run on the
// superuser harness, where row security does not apply, so they pin the
// guard's SQL, not how row security filters it on an app connection.

/// Every cache column, as one comparable string.
async fn full_cache(pool: &PgPool, claim: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT row_to_json(x)::text FROM ( \
             SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing, \
                    belief_frame_id, classification \
               FROM claims WHERE id = $1) x",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the full cache")
}

/// A cache no fold in this file produces, recorded on `frame`.
async fn set_sentinel_cache(pool: &PgPool, claim: Uuid, frame: Option<Uuid>) -> String {
    sqlx::query(
        "UPDATE claims SET belief = 0.613, plausibility = 0.887, pignistic_prob = 0.741, \
                mass_on_empty = 0.017, mass_on_missing = 0.029, belief_frame_id = $2, \
                classification = 'sentinel' \
          WHERE id = $1",
    )
    .bind(claim)
    .bind(frame)
    .execute(pool)
    .await
    .expect("set the sentinel cache");
    full_cache(pool, claim).await
}

async fn decomposes_to(pool: &PgPool, parent: Uuid, child: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'decomposes_to')",
    )
    .bind(parent)
    .bind(child)
    .execute(pool)
    .await
    .expect("seed decomposes_to edge");
}

/// Assessing a (non-workflow) compound still stores the assessment row and
/// returns that frame's numbers, but leaves the compound's cache exactly as it
/// was. A standalone twin assessed the same way IS refreshed (calibration).
///
/// Base: the refresh refolds the compound's own rows into its cache.
#[sqlx::test(migrations = "../../migrations")]
async fn assessing_a_compound_stores_the_row_but_leaves_its_cache(pool: PgPool) {
    let (compound, _viewer, caller) = seed_claim(&pool, "assess a compound").await;
    let leaf = seed_public_claim(&pool, caller, "assess a compound: its leaf").await;
    decomposes_to(&pool, compound, leaf).await;
    let twin = seed_public_claim(&pool, caller, "assess a standalone twin").await;

    let twin_before = set_sentinel_cache(&pool, twin, None).await;
    assess(&pool, caller, twin, request(true, 0.8, None)).await;
    assert_ne!(
        full_cache(&pool, twin).await,
        twin_before,
        "CALIBRATION: assess refreshes a standalone's cache"
    );

    let before = set_sentinel_cache(&pool, compound, None).await;
    let rows_before = mass_function_count(&pool, compound).await;
    let resp = assess(&pool, caller, compound, request(true, 0.8, None)).await;

    assert_eq!(
        mass_function_count(&pool, compound).await,
        rows_before + 1,
        "the assessment row is still stored on a compound"
    );
    assert!(
        resp.pignistic_prob.is_some(),
        "the response still reports the frame's numbers"
    );
    assert_eq!(
        full_cache(&pool, compound).await,
        before,
        "assess must not refold a compound's own rows into its cache"
    );
}

/// The claim's earliest input is the ingest template on `research_validity`,
/// and its cache is recorded there. An assessment on a non-canonical frame
/// gives it its one real input. The refresh must hand the cache to the frame
/// that holds the real input, and the cache must equal that of a twin claim
/// with no template assessed the same way, not a refold of the template's
/// frame.
///
/// Base: the recorded `research_validity` frame keeps ownership (it still
/// holds an input) and the cache becomes the template's fold.
#[sqlx::test(migrations = "../../migrations")]
async fn an_assessment_moves_ownership_off_a_frame_holding_only_the_ingest_template(pool: PgPool) {
    let (claim, _viewer, caller) = seed_claim(&pool, "assess over an ingest template").await;
    let (ingest, _) = seed_agent_with_group(&pool, "assess-ingest").await;
    let rv: Uuid =
        match sqlx::query_scalar("SELECT id FROM frames WHERE name = 'research_validity'")
            .fetch_optional(&pool)
            .await
            .expect("look up research_validity")
        {
            Some(id) => id,
            None => create_frame(&pool, "research_validity", &["TRUE", "FALSE"]).await,
        };
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim)
    .bind(rv)
    .execute(&pool)
    .await
    .expect("assign the claim to research_validity");
    // The ingest template's shape: no method, source strength 0.3, 0.9 on Θ.
    sqlx::query(
        "INSERT INTO mass_functions \
           (claim_id, frame_id, source_agent_id, masses, conflict_k, combination_method, \
            source_strength, evidence_type, locality_tag, created_at) \
         VALUES ($1, $2, $3, '{\"0\": 0.1, \"0,1\": 0.9}'::jsonb, 0.0, NULL, 0.3, NULL, \
                 'unknown', now() - interval '1 hour')",
    )
    .bind(claim)
    .bind(rv)
    .bind(ingest)
    .execute(&pool)
    .await
    .expect("seed the ingest template row");
    set_sentinel_cache(&pool, claim, Some(rv)).await;

    let paper = create_frame(&pool, "paper_validity_x", &["supported", "refuted"]).await;
    let resp = assess(&pool, caller, claim, request_on(paper, true, 0.8)).await;
    assert_eq!(
        resp.frame_id, paper,
        "CALIBRATION: the explicit frame is used"
    );

    let (owner, betp) = cache(&pool, claim).await;
    assert_eq!(
        owner,
        Some(paper),
        "a frame holding only the ingest template kept the cache"
    );
    assert_ne!(betp, Some(0.741), "the refresh wrote the cache");

    let twin = seed_public_claim(&pool, caller, "assess with no ingest template").await;
    set_sentinel_cache(&pool, twin, Some(rv)).await;
    assess(&pool, caller, twin, request_on(paper, true, 0.8)).await;
    assert_eq!(
        full_cache(&pool, claim).await,
        full_cache(&pool, twin).await,
        "the cache must be the real frame's fold, exactly as on a twin with no template"
    );
}
