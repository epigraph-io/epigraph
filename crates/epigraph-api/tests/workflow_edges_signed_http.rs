#![cfg(feature = "db")]
//! Signing at INSERT (backlog `dae795f8`) on the HTTP workflow writers: the edges
//! `POST /api/v1/workflows/ingest` and `POST /api/v1/workflows/steps` write
//! through `epigraph-ingest-executor` (the plan walk's `executes`, plan and
//! `variant_of` edges, the `AUTHORED` record of each created claim, and
//! `add_step`'s `executes`, `decomposes_to` and `step_follows`) are attested
//! at INSERT with the API's own key: `signer_id` = the API's signer agent,
//! never the caller, and `EdgeSignatureRepository::verify_conn` reports each
//! one signed, valid as v1 and matching its row.
//!
//! The handlers run on the production pool shape (`scoped` and `db_pool` are
//! separate `epigraph_app` pools), as `workflow_ingest_refuses_author_agent_id_http.rs`
//! does.

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::edge_signer::{self, ApiEdgeSigner};
use epigraph_api::middleware::bearer::ViewerExtractor;
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
    database_url_for, downgraded_pool, register_system_agent, seed_agent_with_group,
};

fn claims_writer(
    agent: Uuid,
) -> Option<axum::Extension<epigraph_api::middleware::bearer::AuthContext>> {
    Some(axum::Extension(
        epigraph_api::middleware::bearer::AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: Some(agent),
            owner_id: Some(agent),
            client_type: epigraph_api::middleware::ClientType::Agent,
            scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
            jti: Uuid::new_v4(),
            family_id: None,
            elevation_claim: None,
            elevation: None,
            admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
            delegated_by: None,
        },
    ))
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

async fn system_agent_registered(pool: &PgPool) {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(register_system_agent(pool, s).await);
}

/// A two-phase, two-steps-per-phase workflow with one named author.
fn extraction(canonical: &str, generation: u32) -> epigraph_ingest::workflow::WorkflowExtraction {
    let step = |s: &str| {
        json!({
            "compound": format!("dae795f8 http {canonical} g{generation}: {s}"),
            "rationale": "because",
            "operations": [format!("dae795f8 http {canonical} g{generation}: {s} op")],
            "generality": [1],
            "confidence": 0.8
        })
    };
    serde_json::from_value(json!({
        "source": {
            "canonical_name": canonical,
            "goal": format!("dae795f8 http signed workflow {canonical} g{generation}"),
            "generation": generation,
            "authors": [{"name": "An HTTP Signing Designer"}],
            "tags": []
        },
        "thesis": format!("dae795f8 http {canonical} g{generation}: the thesis"),
        "thesis_derivation": "TopDown",
        "phases": [
            {"title": "One", "summary": format!("dae795f8 http {canonical} g{generation}: one"),
             "steps": [step("first"), step("second")]},
            {"title": "Two", "summary": format!("dae795f8 http {canonical} g{generation}: two"),
             "steps": [step("third"), step("fourth")]}
        ],
        "relationships": []
    }))
    .expect("a well-formed extraction")
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

async fn ingest(pool: &PgPool, state: &AppState, caller: Uuid, canonical: &str, generation: u32) {
    let Json(_) = epigraph_api::routes::workflows::ingest_workflow(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("viewer")),
        State(state.clone()),
        claims_writer(caller),
        Json(epigraph_api::routes::workflows::IngestWorkflowRequest {
            extraction: extraction(canonical, generation),
            tenancy: None,
            embed: Some(false),
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("ingest {canonical} g{generation}: {e:?}"));
}

async fn add_step(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    canonical: &str,
    text: &str,
    position: Option<u32>,
) {
    let Json(_) = epigraph_api::routes::workflows::add_step(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("viewer")),
        State(state.clone()),
        claims_writer(caller),
        Json(epigraph_api::routes::workflows::AddStepRequest {
            canonical_name: canonical.to_string(),
            step_text: text.to_string(),
            position,
        }),
    )
    .await
    .unwrap_or_else(|e| panic!("add_step {text:?} at {position:?}: {e:?}"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_http_workflow_writers_attest_their_edges_with_the_api_key(pool: PgPool) {
    system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "dae795f8-http-wf-caller").await;
    let (state, signer) = signed_state(&pool).await;
    assert_ne!(signer, caller);

    let before = edge_ids(&pool).await;
    ingest(&pool, &state, caller, "dae795f8-http-wf", 0).await;
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "ingest g0").await;
    require(
        &rels,
        &[
            "executes",
            "decomposes_to",
            "step_follows",
            "phase_follows",
            "asserts",
            "AUTHORED",
        ],
        "ingest g0",
    );

    // An idempotent re-ingest writes nothing.
    let before = edge_ids(&pool).await;
    ingest(&pool, &state, caller, "dae795f8-http-wf", 0).await;
    assert_eq!(edge_ids(&pool).await, before, "a re-ingest wrote an edge");

    let before = edge_ids(&pool).await;
    ingest(&pool, &state, caller, "dae795f8-http-wf", 1).await;
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "ingest g1").await;
    require(&rels, &["variant_of", "executes", "AUTHORED"], "ingest g1");

    for (text, position) in [
        ("an http appended step", None),
        ("an http head step", Some(0)),
        ("an http mid-chain step", Some(2)),
    ] {
        let before = edge_ids(&pool).await;
        add_step(&pool, &state, caller, "dae795f8-http-wf", text, position).await;
        let what = format!("add_step {text}");
        let rels = assert_new_edges_attested(&pool, &before, signer, caller, &what).await;
        require(
            &rels,
            &["executes", "decomposes_to", "step_follows", "AUTHORED"],
            &what,
        );
    }
}

/// `POST /api/v1/workflows` (store_workflow) has its own authorship record
/// call beside the shared plan walk: every edge it writes is attested by the
/// API's key too.
#[sqlx::test(migrations = "../../migrations")]
async fn http_store_workflow_attests_its_edges_with_the_api_key(pool: PgPool) {
    system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "dae795f8-http-store-caller").await;
    let (state, signer) = signed_state(&pool).await;

    let before = edge_ids(&pool).await;
    let request: epigraph_api::routes::workflows::StoreWorkflowRequest =
        serde_json::from_value(json!({
            "goal": "dae795f8 http store: sign the stored workflow's edges",
            "steps": ["dae795f8 http store: first", "dae795f8 http store: second"],
            "prerequisites": null,
            "expected_outcome": null,
            "confidence": null,
            "tags": null
        }))
        .expect("a well-formed store request");
    let Json(_) = epigraph_api::routes::workflows::store_workflow(
        ViewerExtractor(Viewer::resolve(&pool, caller).await.expect("viewer")),
        State(state.clone()),
        claims_writer(caller),
        Json(request),
    )
    .await
    .unwrap_or_else(|e| panic!("store_workflow: {e:?}"));
    let rels = assert_new_edges_attested(&pool, &before, signer, caller, "store_workflow").await;
    require(
        &rels,
        &["executes", "decomposes_to", "step_follows", "AUTHORED"],
        "store_workflow",
    );
}
