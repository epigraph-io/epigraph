#![cfg(feature = "db")]
//! The REST workflow writers keep the caller's `tags`.
//!
//! `POST /api/v1/workflows` (`store_workflow`) takes `tags` and
//! `POST /api/v1/workflows/ingest` (`ingest_workflow`) takes `source.tags`.
//! Both used to hand them to `WorkflowSource.tags`, a field no ingest step
//! read, so the `workflows` row stored only the caller's metadata (for
//! `store_workflow`, just `prerequisites`) and the tags were unrecoverable.
//!
//! The tags are now recorded on the row as `metadata.tags` (trimmed, empties
//! dropped, de-duplicated in first-seen order), next to every metadata key the
//! caller supplied. The MCP twins are pinned in
//! `epigraph-mcp/tests/store_workflow_tags_persisted.rs`.
//!
//! The handlers run on the production pool shape (`scoped` and `db_pool` are
//! separate `epigraph_app` pools), as `workflow_rest_embeddings_stamped.rs`
//! does.
//!
//! # Verified to fail
//!
//! At origin/main 9af9db2a the three arms failed on the `metadata.tags`
//! assertion. With no caller `metadata.tags`, the stored metadata had no `tags`
//! key at all (only `prerequisites` and the submitter key); with a caller
//! `metadata.tags: ["legacy"]`, it stayed `["legacy"]` and every `source.tags`
//! entry was lost.

mod viewer_fixture;

use axum::extract::State;
use axum::Json;
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    database_url_for, downgraded_pool, register_system_agent, seed_agent_with_group,
};

/// The `AuthContext` the bearer middleware injects for a `claims:write` token
/// bound to `agent`: both workflow write routes require that scope.
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

/// An application-role `AppState`: `scoped` and `db_pool` are two separate
/// `epigraph_app` pools.
async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
        .load_entity_type_cache()
        .await
        .expect("load the entity-type cache");
    state
}

/// The system agent, created by the unarmed legacy resolver and registered as
/// the deploy order does (migration 148).
async fn system_agent_registered(pool: &PgPool) {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(register_system_agent(pool, s).await);
}

/// The stored `workflows.metadata` for this workflow. Read on the harness
/// superuser, so row security hides nothing.
async fn metadata_of(pool: &PgPool, body: &Value) -> Value {
    let workflow_id: Uuid = body["workflow_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("workflow_id in {body}"));
    sqlx::query_scalar("SELECT metadata FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .fetch_one(pool)
        .await
        .expect("the workflow row")
}

/// `POST /api/v1/workflows`: the tags land on the row, normalised, and the
/// `prerequisites` key the route writes is kept beside them.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_store_workflow_persists_tags(pool: PgPool) {
    system_agent_registered(&pool).await;
    let (caller, _) = seed_agent_with_group(&pool, "caller").await;
    let state = app_role_state(&pool).await;

    let tag = Uuid::new_v4();
    let req: epigraph_api::routes::workflows::StoreWorkflowRequest =
        serde_json::from_value(json!({
            "goal": format!("rest store tags goal {tag}"),
            "steps": [format!("rest store tags step {tag}")],
            "prerequisites": ["cargo installed"],
            "tags": ["deployment", " rust ", "", "deployment"]
        }))
        .expect("request");
    let Json(body) = epigraph_api::routes::workflows::store_workflow(
        ViewerExtractor(Viewer::resolve(&pool, caller).await.expect("viewer")),
        State(state),
        claims_writer(caller),
        Json(req),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("store_workflow answers 200");

    let meta = metadata_of(&pool, &body).await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["deployment", "rust"])),
        "POST /workflows must record its tags on the workflows row: {meta}"
    );
    assert_eq!(
        meta.get("prerequisites"),
        Some(&json!(["cargo installed"])),
        "the prerequisites key is kept beside the tags: {meta}"
    );
}

/// Runs `POST /api/v1/workflows/ingest` with `source.tags` and, when given, a
/// caller `source.metadata`, and returns the stored row's metadata.
async fn rest_ingest_and_read_metadata(
    pool: &PgPool,
    tags: Value,
    metadata: Option<Value>,
) -> Value {
    system_agent_registered(pool).await;
    let (caller, _) = seed_agent_with_group(pool, "caller").await;
    let state = app_role_state(pool).await;

    let tag = Uuid::new_v4();
    let mut source = json!({
        "canonical_name": format!("rest-ingest-tags-{tag}"),
        "goal": format!("rest ingest tags goal {tag}"),
        "generation": 0,
        "authors": [],
        "tags": tags,
    });
    if let Some(m) = metadata {
        source["metadata"] = m;
    }
    let extraction: epigraph_ingest::workflow::WorkflowExtraction = serde_json::from_value(json!({
        "source": source,
        "thesis": format!("rest ingest tags thesis {tag}"),
        "thesis_derivation": "TopDown",
        "phases": [{
            "title": "Phase One",
            "summary": format!("rest ingest tags phase {tag}"),
            "steps": [{
                "compound": format!("rest ingest tags step {tag}"),
                "rationale": "",
                "operations": [],
                "generality": [],
                "confidence": 0.8
            }]
        }],
        "relationships": []
    }))
    .expect("a well-formed extraction");

    let Json(body) = epigraph_api::routes::workflows::ingest_workflow(
        ViewerExtractor(Viewer::resolve(pool, caller).await.expect("viewer")),
        State(state),
        claims_writer(caller),
        Json(epigraph_api::routes::workflows::IngestWorkflowRequest {
            extraction,
            tenancy: None,
            embed: Some(false),
        }),
    )
    .await
    .map_err(|e| format!("{e:?}"))
    .expect("ingest_workflow answers 200");
    metadata_of(pool, &body).await
}

/// `POST /api/v1/workflows/ingest` with `source.tags` and no `metadata` (the
/// shape callers send): the row gains a `tags` key holding the normalised tags.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_ingest_workflow_persists_source_tags(pool: PgPool) {
    let meta =
        rest_ingest_and_read_metadata(&pool, json!(["rust", " deployment ", "rust", ""]), None)
            .await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["rust", "deployment"])),
        "POST /workflows/ingest must record source.tags on the workflows row: {meta}"
    );
}

/// Merge policy when the caller ALSO sent `metadata`: every caller key is kept,
/// and a caller `metadata.tags` array is extended with the `source.tags` it
/// lacks (its own entries first), never replaced.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_ingest_workflow_merges_source_tags_into_caller_metadata(pool: PgPool) {
    let meta = rest_ingest_and_read_metadata(
        &pool,
        json!(["rust", "deployment", "legacy"]),
        Some(json!({ "owner_team": "infra", "tags": ["legacy"] })),
    )
    .await;
    assert_eq!(
        meta.get("tags"),
        Some(&json!(["legacy", "rust", "deployment"])),
        "source.tags are merged into the caller's metadata.tags: {meta}"
    );
    assert_eq!(
        meta.get("owner_team"),
        Some(&json!("infra")),
        "the caller's own metadata keys are kept: {meta}"
    );
}
