#![cfg(feature = "db")]
//! `POST /api/v1/claims/:id/supersede` and `POST /api/v1/workflows/steps/:id/evolve`
//! embed the claim they insert (backlog 7628ab2c, the HTTP twins of the MCP
//! `supersede_claim` and `evolve_step`).
//!
//! Both handlers insert a new CURRENT claim (the replacement, or the new step
//! on `supersedes` and `revises` alike) on the caller's stamped transaction.
//! Before this fix neither embedded it: the request answered 201 / 200 and the
//! claim carried `embedding IS NULL`, invisible to recall.
//!
//! The arms run on an `AppState` whose `scoped` pool and raw `db_pool` are both
//! `epigraph_app` pools (no BYPASSRLS) with a mock embedder, as
//! `workflow_rest_embeddings_stamped.rs` does, so the stamped store's row
//! security is real. No orphan permissive `claims_privacy` policy is installed.
//!
//! # Verified to fail
//!
//! With the two `embed_committed_claim_as` calls removed
//! (`routes/versioning.rs::supersede_claim`, `routes/workflows.rs::evolve_step`),
//! every arm fails on its `embedding IS NOT NULL` assertion.

mod viewer_fixture;

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool, seed_agent_with_group, seed_group_claim};

/// An application-role `AppState` with a mock embedder.
async fn app_role_state_with_embedder(pool: &PgPool) -> AppState {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS: every arm here is vacuous"
    );
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
    let embedder: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    state.with_embedding_service(embedder)
}

fn writer_token(agent: Uuid) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type: ClientType::Agent,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }
}

async fn json_of(resp: axum::response::Response) -> (axum::http::StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!(String::from_utf8_lossy(&bytes)));
    (status, body)
}

/// `(is_current, embedding IS NOT NULL)` for `id`, read on the harness
/// superuser so row security hides nothing.
async fn current_and_embedded(pool: &PgPool, id: Uuid) -> (bool, bool) {
    sqlx::query_as("SELECT is_current, embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("the claim")
}

fn uuid_field(body: &serde_json::Value, key: &str) -> Uuid {
    body[key]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{key} in {body}"))
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_supersede_embeds_the_replacement_on_the_app_role(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "http-supersede-embed").await;
    let old = seed_group_claim(&pool, agent, group, "the melting point is 120 C").await;
    let state = app_role_state_with_embedder(&pool).await;
    let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");

    let req: epigraph_api::routes::versioning::SupersedeRequest =
        serde_json::from_value(serde_json::json!({
            "content": "the melting point is 121 C",
            "truth_value": 0.7,
            "reason": "embed test",
        }))
        .expect("request");
    let resp = epigraph_api::routes::versioning::supersede_claim(
        ViewerExtractor(viewer),
        State(state),
        Some(Extension(writer_token(agent))),
        Path(old),
        Json(req),
    )
    .await
    .into_response();
    let (status, body) = json_of(resp).await;
    assert!(
        status.is_success(),
        "the author supersedes: {status} {body}"
    );
    let new_id = uuid_field(&body, "new_claim_id");

    assert_eq!(
        current_and_embedded(&pool, old).await,
        (false, false),
        "calibration: the retired claim is retired and unembedded"
    );
    assert_eq!(
        current_and_embedded(&pool, new_id).await,
        (true, true),
        "the replacement is current AND embedded: {body}"
    );
    assert_eq!(body["embedded"], true, "the response reports it: {body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn http_evolve_step_embeds_the_new_step_on_supersedes_and_revises(pool: PgPool) {
    let (agent, group) = seed_agent_with_group(&pool, "http-evolve-embed").await;
    let state = app_role_state_with_embedder(&pool).await;

    for edge_type in ["supersedes", "revises"] {
        let parent = seed_group_claim(
            &pool,
            agent,
            group,
            &format!("G1: grind the sample ({edge_type})"),
        )
        .await;
        let viewer = Viewer::resolve(&pool, agent).await.expect("viewer");
        let req: epigraph_api::routes::workflows::EvolveStepRequest =
            serde_json::from_value(serde_json::json!({
                "parent_id": parent,
                "content": format!("G1 v2 ({edge_type})"),
                "edge_type": edge_type,
            }))
            .expect("request");
        let resp = epigraph_api::routes::workflows::evolve_step(
            ViewerExtractor(viewer),
            State(state.clone()),
            Some(Extension(writer_token(agent))),
            Path(parent),
            Json(req),
        )
        .await
        .into_response();
        let (status, body) = json_of(resp).await;
        assert!(
            status.is_success(),
            "{edge_type}: the author evolves its step: {status} {body}"
        );
        let new_id = uuid_field(&body, "claim_id");
        assert_eq!(
            current_and_embedded(&pool, parent).await.0,
            edge_type == "revises",
            "calibration: {edge_type} retires the parent only on supersedes"
        );
        assert_eq!(
            current_and_embedded(&pool, new_id).await,
            (true, true),
            "{edge_type}: the new step is current AND embedded: {body}"
        );
        assert_eq!(body["embedded"], true, "{edge_type}: {body}");
    }
}
