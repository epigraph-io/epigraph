#![cfg(feature = "db")]
//! Ruling R-36 (backlog fe3ec493) on `POST /api/v1/claims/:id/assess`'s own
//! fold: the independence analysis groups BBAs by the OWNER of their source
//! agent, so a sibling's row written through another route folds cautiously
//! with the owner's assessment slot.
//!
//! # What was wrong, measured at origin/main before this file
//!
//! `routes/independence.rs::analyze_independence` grouped rows by raw
//! `source_agent_id` and called `get_lca` with `mass_functions` row ids as if
//! they were claim ids. Lineage never relates two BBA rows, so every agent
//! folded as independent: the owner's slot (keyed by the human) and a sibling
//! agent's `/frames/:id/evidence` row on the same frame were multiplied.
//!
//! # The oracle
//!
//! The sibling's row carries EXACTLY the slot's masses. The cautious rule is
//! idempotent, so the assess response's BetP must equal the single-call value;
//! Dempster's product of two identical BBAs is strictly higher. A control
//! pins that a stranger's identical row still reinforces.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::assess::{assess_claim, AssessClaimRequest, AssessClaimResponse};
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

fn request() -> AssessClaimRequest {
    serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": 0.9,
        "supports": true,
    }))
    .expect("AssessClaimRequest deserializes")
}

async fn assess(state: &AppState, pool: &PgPool, caller: Uuid, claim: Uuid) -> AssessClaimResponse {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let Json(resp) = assess_claim(
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(claim),
        Json(request()),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp
}

/// `caller`'s `/frames/:id/evidence` row on (claim, frame) with `masses`.
async fn frames_row(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    frame: Uuid,
    masses: &serde_json::Value,
) {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: SubmitEvidenceRequest = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "reliability": 1.0,
        "masses": masses,
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

async fn slot_masses(pool: &PgPool, row: Uuid) -> serde_json::Value {
    sqlx::query_scalar("SELECT masses FROM mass_functions WHERE id = $1")
        .bind(row)
        .fetch_one(pool)
        .await
        .expect("the assessment slot row")
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_siblings_row_folds_cautiously_with_the_owners_assessment(pool: PgPool) {
    let state = state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "assess-owner-author").await;
    let (human, _) = seed_human_operator(&pool, "assess-owner-human").await;
    let (one, _) = seed_agent_with_group(&pool, "assess-owner-one").await;
    let (two, _) = seed_agent_with_group(&pool, "assess-owner-two").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let (stranger, _) = seed_agent_with_group(&pool, "assess-owner-stranger").await;

    let claim = seed_public_claim(&pool, author, "assess owner grouping: siblings").await;
    let first = assess(&state, &pool, one, claim).await;
    let single = first.pignistic_prob.expect("single-call BetP");
    let masses = slot_masses(&pool, first.mass_function_id).await;

    // The sibling restates the owner's assessment through another route.
    frames_row(&state, &pool, two, claim, first.frame_id, &masses).await;
    let again = assess(&state, &pool, one, claim).await;
    let folded = again.pignistic_prob.expect("BetP");
    assert!(
        (folded - single).abs() < 1e-9,
        "a sibling's identical row must not add up with the owner's slot: single-call \
         {single}, got {folded}"
    );

    // Control: the same identical row by an agent of no human reinforces.
    let control = seed_public_claim(&pool, author, "assess owner grouping: control").await;
    let c_first = assess(&state, &pool, one, control).await;
    let c_masses = slot_masses(&pool, c_first.mass_function_id).await;
    frames_row(
        &state,
        &pool,
        stranger,
        control,
        c_first.frame_id,
        &c_masses,
    )
    .await;
    let c_again = assess(&state, &pool, one, control).await;
    let independent = c_again.pignistic_prob.expect("BetP");
    assert!(
        independent > single + 1e-3,
        "an independent owner's identical row must still reinforce: {independent} vs {single}"
    );
}
