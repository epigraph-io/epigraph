#![cfg(feature = "db")]
//! Ruling R-36 (backlog fe3ec493) on `POST /api/v1/frames/:id/evidence`:
//! agents of one human replace or contest, never aggregate.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! The route keys each BBA by its caller and delegates the combine to the
//! shared recompute (`edge_factor::recompute_claim_belief_on_frame`), which
//! folded two sibling agents' agreeing BBAs as independent evidence
//! (Dempster's product).
//!
//! # The oracle
//!
//! The stronger sibling's BBA ALONE, through the same route, on a fresh claim:
//! the weaker sibling must add nothing, so the cached BetP equals it. A
//! control pins that an agent of no human still reinforces.
//!
//! The handler runs on the `#[sqlx::test]` superuser pools, as in
//! `assess_canonical_frame.rs`: this pins the fold, not tenancy.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::belief::{submit_evidence, SubmitEvidenceRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{scoped_pool, seed_agent_with_group, seed_human_operator, seed_public_claim};

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

async fn fresh_claim(pool: &PgPool, label: &str) -> Uuid {
    let (author, _) = seed_agent_with_group(pool, "same-human-frames-author").await;
    seed_public_claim(pool, author, &format!("{label} {}", Uuid::new_v4())).await
}

async fn submit(state: &AppState, pool: &PgPool, caller: Uuid, claim: Uuid, frame: Uuid, t: f64) {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: SubmitEvidenceRequest = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "reliability": 1.0,
        "masses": {"0": t, "0,1": 1.0 - t},
    }))
    .expect("request");
    let _created = submit_evidence(
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("submit_evidence failed: {e:?}"));
}

async fn cached_betp(pool: &PgPool, claim: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the cache")
        .expect("the route filled the cache")
}

#[sqlx::test(migrations = "../../migrations")]
async fn frames_evidence_by_two_agents_of_one_human_does_not_aggregate(pool: PgPool) {
    let state = state(&pool).await;
    let frame = epigraph_db::FrameRepository::create(
        &pool,
        "same_human_frames_evidence",
        None,
        &["h0".to_string(), "h1".to_string()],
    )
    .await
    .expect("frame")
    .id;
    let (human, _) = seed_human_operator(&pool, "same-human-frames").await;
    let (one, _) = seed_agent_with_group(&pool, "same-human-frames-one").await;
    let (two, _) = seed_agent_with_group(&pool, "same-human-frames-two").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let (stranger, _) = seed_agent_with_group(&pool, "same-human-frames-stranger").await;

    let baseline_claim = fresh_claim(&pool, "same-human frames baseline").await;
    submit(&state, &pool, two, baseline_claim, frame, 0.7).await;
    let baseline = cached_betp(&pool, baseline_claim).await;

    let claim = fresh_claim(&pool, "same-human frames siblings").await;
    submit(&state, &pool, one, claim, frame, 0.6).await;
    submit(&state, &pool, two, claim, frame, 0.7).await;
    let siblings = cached_betp(&pool, claim).await;
    assert!(
        (siblings - baseline).abs() < 1e-9,
        "two agents of one human must keep the stronger BBA ({baseline}), not aggregate: \
         got {siblings}"
    );

    // The human's OWN submission is a sibling of its agents too.
    let with_human = fresh_claim(&pool, "same-human frames with the human").await;
    submit(&state, &pool, human, with_human, frame, 0.6).await;
    submit(&state, &pool, two, with_human, frame, 0.7).await;
    let with_human = cached_betp(&pool, with_human).await;
    assert!(
        (with_human - baseline).abs() < 1e-9,
        "the human and its agent must not aggregate either: {with_human} vs {baseline}"
    );

    let control = fresh_claim(&pool, "same-human frames control").await;
    submit(&state, &pool, stranger, control, frame, 0.6).await;
    submit(&state, &pool, two, control, frame, 0.7).await;
    let independent = cached_betp(&pool, control).await;
    assert!(
        independent > baseline + 1e-3,
        "agents of different owners must still reinforce: {independent} vs {baseline}"
    );
}
