#![cfg(feature = "db")]
//! Signing at INSERT (backlog `dae795f8`) on the HTTP routes whose edges a
//! repository act writes: the match promotion of `POST
//! /api/v1/cross-source/candidates/:id/decide` (the matcher edge).
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
use sqlx::PgPool;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_public_claim};

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
