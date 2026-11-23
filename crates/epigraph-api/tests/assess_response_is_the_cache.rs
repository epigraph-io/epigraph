#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/assess` reports the value it leaves in the claim's
//! cache (backlog 735df6d7).
//!
//! # What was wrong
//!
//! The handler refreshed the cache through the engine
//! (`edge_factor::recompute_claim_cached_belief`) but computed its RESPONSE
//! with a fold of its own: the raw masses of its `'discount'` rows, with no
//! reliability discount, and with every row of a same-human sibling group in
//! one cautious reduction. The engine discounts each row by its effective
//! reliability (an untyped assessment row by the unknown-type weight) and
//! folds each agent's own rows first. So the value assess returned was not
//! the value then cached and served, for a single assessment as well as for
//! siblings with several rows.
//!
//! # The oracle
//!
//! The STORED cache after a separate, no-new-evidence recompute on a fresh
//! connection (what `recompute_beliefs` would leave), never a function the
//! response was itself computed from. The frame assess wrote on is the
//! cache's owner here (no `binary_truth` input), so the two must be equal.

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

const EPS: f64 = 1e-9;

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

async fn assess(state: &AppState, pool: &PgPool, caller: Uuid, claim: Uuid) -> AssessClaimResponse {
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: AssessClaimRequest = serde_json::from_value(serde_json::json!({
        "evidence_type": "empirical",
        "methodology": "instrumental",
        "confidence": 0.9,
        "supports": true,
    }))
    .expect("AssessClaimRequest deserializes");
    let Json(resp) = assess_claim(
        write_scope(),
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(claim),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("assess_claim failed: {e:?}"));
    resp
}

/// `caller`'s `/frames/:id/evidence` row on (claim, frame) under its own
/// perspective `perspective`, with `masses`.
async fn frames_row(
    state: &AppState,
    pool: &PgPool,
    caller: Uuid,
    claim: Uuid,
    frame: Uuid,
    masses: serde_json::Value,
) {
    let perspective: Uuid = sqlx::query_scalar(
        "INSERT INTO perspectives (name, owner_agent_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(format!("735df6d7-{}", Uuid::new_v4()))
    .bind(caller)
    .fetch_one(pool)
    .await
    .expect("seed perspective");
    let viewer = Viewer::resolve(pool, caller).await.expect("resolve caller");
    let request: SubmitEvidenceRequest = serde_json::from_value(serde_json::json!({
        "claim_id": claim,
        "perspective_id": perspective,
        "reliability": 1.0,
        "masses": masses,
    }))
    .expect("request");
    let _created = submit_evidence(
        write_scope(),
        ViewerExtractor(viewer),
        State(state.clone()),
        Path(frame),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("submit_evidence failed: {e:?}"));
}

async fn link(pool: &PgPool, agent: Uuid, human: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = epigraph_db::AgentRepository::link_operator(&mut conn, agent, human)
        .await
        .expect("link the agent to its human");
    assert!(out.link_live, "{out:?}");
}

/// The cache after a no-new-evidence recompute on a fresh connection:
/// `(belief, plausibility, pignistic_prob, belief_frame_id)`.
async fn recomputed_cache(
    pool: &PgPool,
    viewer_of: Uuid,
    claim: Uuid,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>) {
    let viewer = Viewer::resolve(pool, viewer_of).await.expect("resolve");
    let mut conn = pool.acquire().await.expect("acquire");
    epigraph_engine::edge_factor::recompute_claim_cached_belief(&mut conn, &viewer, claim)
        .await
        .expect("recompute");
    drop(conn);
    sqlx::query_as(
        "SELECT belief, plausibility, pignistic_prob, belief_frame_id FROM claims WHERE id = $1",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("read the cache")
}

fn assert_response_is_cache(
    resp: &AssessClaimResponse,
    cache: (Option<f64>, Option<f64>, Option<f64>, Option<Uuid>),
    what: &str,
) {
    assert_eq!(
        cache.3,
        Some(resp.frame_id),
        "{what}: PREMISE: the assessed frame owns the cache"
    );
    for (name, reported, cached) in [
        ("belief", resp.updated_belief, cache.0),
        ("plausibility", resp.updated_plausibility, cache.1),
        ("pignistic_prob", resp.pignistic_prob, cache.2),
    ] {
        let (r, c) = (
            reported.unwrap_or_else(|| panic!("{what}: response {name}")),
            cached.unwrap_or_else(|| panic!("{what}: cached {name}")),
        );
        assert!(
            (r - c).abs() < EPS,
            "{what}: the response's {name} {r} is not the cached {c}"
        );
    }
}

/// One assessment, by an agent bound to no human: the response is the cache.
#[sqlx::test(migrations = "../../migrations")]
async fn a_single_assessment_reports_the_cached_value(pool: PgPool) {
    let state = state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "735df6d7-single-author").await;
    let (caller, _) = seed_agent_with_group(&pool, "735df6d7-single-caller").await;
    let claim = seed_public_claim(&pool, author, "735df6d7 single assessment").await;

    let resp = assess(&state, &pool, caller, claim).await;
    let cache = recomputed_cache(&pool, caller, claim).await;
    assert_response_is_cache(&resp, cache, "single assessment");
}

/// Siblings with SEVERAL rows each: two agents of one human, one holding the
/// human's assessment slot, the other two `/frames/:id/evidence` rows that
/// disagree with each other. The engine folds the second agent's own rows
/// first and reduces the two agents cautiously; the response must be that.
#[sqlx::test(migrations = "../../migrations")]
async fn multi_row_siblings_report_the_cached_value(pool: PgPool) {
    let state = state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "735df6d7-sib-author").await;
    let (human, _) = seed_human_operator(&pool, "735df6d7-sib-human").await;
    let (one, _) = seed_agent_with_group(&pool, "735df6d7-sib-one").await;
    let (two, _) = seed_agent_with_group(&pool, "735df6d7-sib-two").await;
    link(&pool, one, human).await;
    link(&pool, two, human).await;
    let claim = seed_public_claim(&pool, author, "735df6d7 multi-row siblings").await;

    let first = assess(&state, &pool, one, claim).await;
    frames_row(
        &state,
        &pool,
        two,
        claim,
        first.frame_id,
        serde_json::json!({"0": 0.6, "0,1,2": 0.4}),
    )
    .await;
    frames_row(
        &state,
        &pool,
        two,
        claim,
        first.frame_id,
        serde_json::json!({"0": 0.2, "1": 0.3, "0,1,2": 0.5}),
    )
    .await;
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mass_functions WHERE claim_id = $1 AND frame_id = $2",
    )
    .bind(claim)
    .bind(first.frame_id)
    .fetch_one(&pool)
    .await
    .expect("count rows");
    assert_eq!(rows, 3, "PREMISE: the slot row and the sibling's two rows");

    let again = assess(&state, &pool, one, claim).await;
    let cache = recomputed_cache(&pool, one, claim).await;
    assert_response_is_cache(&again, cache, "multi-row siblings");
}

/// The `claims:write` scope the write handlers take as their first extractor
/// (backlog f00d75ab). A direct handler call stands in for the bearer
/// middleware, so it supplies the scope the route checks.
fn write_scope() -> epigraph_api::middleware::bearer::RequireScopeWrite {
    let principal = uuid::Uuid::new_v4();
    epigraph_api::middleware::bearer::RequireScopeWrite(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: principal,
            agent_id: Some(principal),
            owner_id: Some(principal),
            client_type: epigraph_api::middleware::ClientType::Service,
            scopes: vec!["claims:write".to_string()],
            jti: uuid::Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    )
}
