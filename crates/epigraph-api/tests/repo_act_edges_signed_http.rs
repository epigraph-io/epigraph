#![cfg(feature = "db")]
//! Signing at INSERT (backlog `dae795f8`) on the HTTP routes whose edges a
//! repository act writes: `POST /api/v1/claims/:id/supersede` (the act's
//! `supersedes` and the actor's `AUTHORED`), `POST /api/v1/claims/:id/dedup`
//! (the `same_as` identity edge), `POST /api/v1/workflows/steps/:id/evolve`
//! (the step edge), the match promotion of `POST
//! /api/v1/cross-source/candidates/:id/decide` (the matcher edge),
//! `POST /api/v1/analyses` (`concludes` and `interpreted_by`) and
//! `POST /api/v1/edges-staging/promote` (each promoted copy).
//!
//! Every edge each call wrote is attested at INSERT with the API's own key:
//! `signer_id` is the API's signer agent, never the caller, and
//! `EdgeSignatureRepository::verify_conn` reports it signed, valid as v1 and
//! matching its row. The handlers run on the production pool shape (`scoped`
//! and `db_pool` are separate `epigraph_app` pools), as
//! `workflow_edges_signed_http.rs` does.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::{Extension, Json};
use epigraph_api::edge_signer::{self, ApiEdgeSigner};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_crypto::{AgentSigner, SignatureScheme};
use epigraph_db::repos::EdgeSignatureRepository;
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::json;
use sqlx::PgPool;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, seed_agent_with_group, seed_evidence, seed_group_claim,
    seed_public_claim,
};

fn auth(agent: Uuid, scopes: &[&str]) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: epigraph_api::middleware::ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

fn writer(agent: Uuid) -> Option<Extension<AuthContext>> {
    auth(agent, &["claims:read", "claims:write"])
}

/// The app-role state, with a fresh API key attached; returns its signer agent.
async fn signed_state(pool: &PgPool) -> (AppState, Uuid) {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let signer = AgentSigner::generate();
    let signer_id = edge_signer::resolve_signer_agent(pool, &signer)
        .await
        .expect("resolve the API signer agent");
    let mut state = AppState::with_db(raw, ApiConfig::default())
        .with_edge_signer(Some(Arc::new(ApiEdgeSigner::new(signer, signer_id))));
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    (state, signer_id)
}

async fn viewer(pool: &PgPool, agent: Uuid) -> ViewerExtractor {
    ViewerExtractor(Viewer::resolve(pool, agent).await.expect("viewer"))
}

async fn edge_ids(pool: &PgPool) -> HashSet<Uuid> {
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM edges")
        .fetch_all(pool)
        .await
        .expect("edge ids")
        .into_iter()
        .collect()
}

/// Every edge written since `before` carries a verifying v1 attestation by
/// `signer` (not `caller`) over its row; returns their relationships.
async fn assert_new_edges_attested(
    pool: &PgPool,
    before: &HashSet<Uuid>,
    signer: Uuid,
    caller: Uuid,
    what: &str,
) -> BTreeSet<String> {
    let viewer = Viewer::resolve(pool, caller).await.expect("caller viewer");
    let edges: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, relationship::text FROM edges ORDER BY created_at, id")
            .fetch_all(pool)
            .await
            .expect("edges");
    let mut rels = BTreeSet::new();
    let mut conn = pool.acquire().await.expect("conn");
    for (id, rel) in edges.into_iter().filter(|(id, _)| !before.contains(id)) {
        let check = EdgeSignatureRepository::verify_conn(&mut conn, &viewer, id)
            .await
            .expect("verify")
            .unwrap_or_else(|| panic!("{what} {rel}: edge {id} not readable to the caller"));
        assert!(
            check.signed && check.signature_valid,
            "{what} {rel}: edge {id}: {check:?}"
        );
        assert_eq!(
            check.signature_scheme,
            Some(SignatureScheme::V1),
            "{what} {rel}"
        );
        assert_eq!(check.content_matches, Some(true), "{what} {rel}: {check:?}");
        assert_eq!(check.signer_id, Some(signer), "{what} {rel}: {check:?}");
        assert_ne!(
            check.signer_id,
            Some(caller),
            "{what} {rel}: the caller signed"
        );
        rels.insert(rel);
    }
    rels
}

fn require(rels: &BTreeSet<String>, must: &[&str], what: &str) {
    for rel in must {
        assert!(
            rels.contains(*rel),
            "{what}: no {rel} edge was written: {rels:?}"
        );
    }
}

/// The promote arm of the candidate decision writes its matcher edge signed.
#[sqlx::test(migrations = "../../migrations")]
async fn the_match_promotion_attests_its_edge_with_the_api_key(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "dae795f8-http-match").await;
    let (state, signer) = signed_state(&pool).await;
    let a = seed_public_claim(&pool, caller, "dae795f8 http: matched a").await;
    let b = seed_public_claim(&pool, caller, "dae795f8 http: matched b").await;
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let candidate: Uuid = sqlx::query_scalar(
        "INSERT INTO match_candidates (claim_a, claim_b, score, features, status) \
         VALUES ($1, $2, 0.95, '{}'::jsonb, 'pending') RETURNING id",
    )
    .bind(lo)
    .bind(hi)
    .fetch_one(&pool)
    .await
    .expect("candidate");

    let before = edge_ids(&pool).await;
    let _written = epigraph_api::routes::cross_source::decide_candidate(
        viewer(&pool, caller).await,
        State(state.clone()),
        writer(caller),
        Path(candidate),
        Json(epigraph_api::routes::cross_source::DecideCandidateRequest {
            verdict: "promote".into(),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("promote: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "promote").await;
    require(&rels, &["corroborates"], "promote");
}

/// The claim acts, each on the caller's own group-private claims. Supersede:
/// the `supersedes` edge and the actor's `AUTHORED`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_supersede_route_attests_its_edges_with_the_api_key(pool: PgPool) {
    let (caller, group) = seed_agent_with_group(&pool, "dae795f8-http-acts").await;
    let (state, signer) = signed_state(&pool).await;
    assert_ne!(signer, caller);

    let old = seed_group_claim(&pool, caller, group, "dae795f8 http: to be superseded").await;
    let before = edge_ids(&pool).await;
    let _written = epigraph_api::routes::versioning::supersede_claim(
        viewer(&pool, caller).await,
        State(state.clone()),
        writer(caller),
        Path(old),
        Json(
            serde_json::from_value(json!({
                "content": "dae795f8 http: the replacement",
                "truth_value": 0.7,
                "reason": "restated",
            }))
            .expect("supersede request"),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("supersede: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "supersede").await;
    require(&rels, &["supersedes", "AUTHORED"], "supersede");
}

/// The dedup mark's `same_as` identity edge.
#[sqlx::test(migrations = "../../migrations")]
async fn the_dedup_route_attests_its_identity_edge_with_the_api_key(pool: PgPool) {
    let (caller, group) = seed_agent_with_group(&pool, "dae795f8-http-dedup").await;
    let (state, signer) = signed_state(&pool).await;
    let dup = seed_group_claim(&pool, caller, group, "dae795f8 http: the duplicate").await;
    let canon = seed_group_claim(&pool, caller, group, "dae795f8 http: the canonical").await;
    let before = edge_ids(&pool).await;
    let _written = epigraph_api::routes::versioning::mark_duplicate(
        viewer(&pool, caller).await,
        State(state.clone()),
        writer(caller),
        Path(dup),
        Json(
            serde_json::from_value(json!({"canonical_id": canon, "reason": "same"}))
                .expect("dedup request"),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("mark_duplicate: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "mark_duplicate").await;
    require(&rels, &["same_as"], "mark_duplicate");
}

/// evolve_step's step edge (`revises`).
#[sqlx::test(migrations = "../../migrations")]
async fn the_evolve_step_route_attests_its_step_edge_with_the_api_key(pool: PgPool) {
    let (caller, group) = seed_agent_with_group(&pool, "dae795f8-http-evolve").await;
    let (state, signer) = signed_state(&pool).await;
    let parent = seed_group_claim(&pool, caller, group, "dae795f8 http: a step").await;
    let before = edge_ids(&pool).await;
    let _written = epigraph_api::routes::workflows::evolve_step(
        viewer(&pool, caller).await,
        State(state.clone()),
        writer(caller),
        Path(parent),
        Json(
            serde_json::from_value(json!({
                "parent_id": parent,
                "content": "dae795f8 http: a revised step",
                "edge_type": "revises",
            }))
            .expect("evolve request"),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("evolve_step: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "evolve_step").await;
    require(&rels, &["revises"], "evolve_step");
}

/// `POST /api/v1/analyses` writes its `concludes` and `interpreted_by` edges
/// signed.
#[sqlx::test(migrations = "../../migrations")]
async fn create_analysis_attests_its_edges_with_the_api_key(pool: PgPool) {
    let (caller, _) = seed_agent_with_group(&pool, "dae795f8-http-analysis").await;
    let (state, signer) = signed_state(&pool).await;
    let claim = seed_public_claim(&pool, caller, "dae795f8 http: concluded").await;
    let evidence = seed_evidence(&pool, claim, "document").await;

    let before = edge_ids(&pool).await;
    let _written = epigraph_api::routes::crud::create_analysis(
        State(state.clone()),
        writer(caller),
        Json(
            serde_json::from_value(json!({
                "analysis_type": "statistical",
                "method_description": "dae795f8 http: a method",
                "inference_path": "a -> b",
                "agent_id": caller,
                "input_evidence_ids": [evidence],
                "claim_ids": [claim],
            }))
            .expect("analysis request"),
        ),
    )
    .await
    .unwrap_or_else(|e| panic!("create_analysis: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "analysis").await;
    require(&rels, &["concludes", "interpreted_by"], "analysis");
}

async fn stage_approved(
    pool: &PgPool,
    src: Uuid,
    tgt: Uuid,
    rel: &str,
    props: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO edges_staging (source_id, target_id, relationship, properties, review_status) \
         VALUES ($1, $2, $3, $4, 'approved') RETURNING id",
    )
    .bind(src)
    .bind(tgt)
    .bind(rel)
    .bind(props)
    .fetch_one(pool)
    .await
    .expect("stage edge")
}

/// `POST /api/v1/edges-staging/promote`: each copy is attested with the API's
/// key, not the claims:admin caller's, in its canonical spelling; a copy a
/// unique index of `edges` refuses (a second matcher edge over a pair) is
/// skipped as the bulk copy's `ON CONFLICT DO NOTHING` skipped it, and every
/// selected row is still marked promoted.
#[sqlx::test(migrations = "../../migrations")]
async fn promote_staged_edges_attests_each_copy_with_the_api_key(pool: PgPool) {
    let (admin, _) = seed_agent_with_group(&pool, "dae795f8-http-staging").await;
    let (state, signer) = signed_state(&pool).await;
    let a = seed_public_claim(&pool, admin, "dae795f8 http: staged a").await;
    let b = seed_public_claim(&pool, admin, "dae795f8 http: staged b").await;
    let c = seed_public_claim(&pool, admin, "dae795f8 http: staged c").await;
    let matcher = json!({"source": "cross_source_matcher"});
    // An in-force matcher edge over (b, c) already exists, so the staged one
    // over (c, b) collides with migration 175's symmetric index.
    epigraph_db::EdgeRepository::create(
        &pool,
        b,
        "claim",
        c,
        "claim",
        "corroborates",
        Some(matcher.clone()),
        None,
        None,
    )
    .await
    .expect("existing matcher edge");
    let rows = [
        stage_approved(&pool, a, b, "supports", json!({"note": "ok"})).await,
        stage_approved(&pool, a, c, "CORROBORATES", json!({})).await,
        stage_approved(&pool, c, b, "corroborates", matcher).await,
    ];

    let before = edge_ids(&pool).await;
    let Json(out) = epigraph_api::routes::crud::promote_staged_edges(
        State(state.clone()),
        auth(admin, &["claims:admin"]),
        Json(epigraph_api::routes::crud::PromoteStagedEdgesRequest {
            edge_ids: Some(rows.to_vec()),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("promote_staged_edges: {e:?}"));
    assert_eq!(out["promoted_count"], 3, "{out}");
    let rels = assert_new_edges_attested(&pool, &before, signer, admin, "staged").await;
    assert_eq!(
        rels,
        BTreeSet::from(["supports".to_string(), "corroborates".to_string()]),
        "the two clean copies, the CORROBORATES one lower-cased"
    );
    assert_eq!(
        edge_ids(&pool).await.len(),
        before.len() + 2,
        "the colliding matcher copy was skipped"
    );
    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT review_status FROM edges_staging WHERE id = ANY($1) ORDER BY id",
    )
    .bind(&rows[..])
    .fetch_all(&pool)
    .await
    .expect("statuses");
    assert_eq!(
        statuses,
        vec!["promoted"; 3],
        "every selected row is marked"
    );
}
