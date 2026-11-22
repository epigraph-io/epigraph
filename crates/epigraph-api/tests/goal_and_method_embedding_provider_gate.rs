#![cfg(feature = "db")]
//! Only the provider that owns the stored vector columns may fill the workflow
//! goal, behavioral-execution goal and method embedding columns (backlog
//! 21b7319a).
//!
//! `embedding_service_from_env` falls through OpenAI, Jina and a mock. Backlog
//! 211bd623 gated the claim and evidence writers on
//! `AppState::storing_embedding_service`; the goal and method writers kept
//! `embedding_service`, so an API process started without `OPENAI_API_KEY`
//! stored mock (or Jina-space) vectors into `behavioral_executions.goal_embedding`
//! and `methods.embedding`: a second vector space in an ANN column that
//! behavioral affinity and method search rank on, with no error anywhere.
//!
//! Each test drives one route twice over the SAME mock service: once with the
//! provider declared `Mock` (the column must stay NULL) and once declared
//! `OpenAi` (the column must be filled). The second arm is the calibration: it
//! proves the route reached its embed, so a NULL in the first arm is the gate
//! and not an early return.
//!
//! # Verified to fail
//!
//! With each handler's `storing_embedding_service()` put back to
//! `embedding_service()`, the `Mock` arm of its test fails and nothing else.
//! `workflows.goal_embedding` was already gated (by 211bd623); its test is a
//! regression pin, verified the same way against `store_workflow`.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::embedding_restore::EmbeddingProviderKind;
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const READ_WRITE: &[&str] = &["claims:read", "claims:write"];

/// The two arms: the declared provider and whether a vector may be stored.
const ARMS: [(EmbeddingProviderKind, bool); 2] = [
    (EmbeddingProviderKind::Mock, false),
    (EmbeddingProviderKind::OpenAi, true),
];

/// The test app over one mock embedding service, declared as `provider`.
async fn router(pool: &PgPool, provider: EmbeddingProviderKind) -> axum::Router {
    let url = viewer_fixture::database_url_for(pool).await;
    let scoped = epigraph_db::ScopedPool::connect_with_options(
        &url,
        epigraph_db::SessionGucMode::Session,
        epigraph_db::ScopedPoolOptions {
            max_connections: 4,
            ..Default::default()
        },
    )
    .await
    .expect("db connect");
    let service: std::sync::Arc<dyn EmbeddingService> =
        std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)));
    let state =
        epigraph_api::AppState::with_scoped_pool(scoped, epigraph_api::ApiConfig::default())
            .with_embedding_service(service)
            .with_embedding_provider(provider);
    epigraph_api::routes::create_router(state)
}

async fn post(router: &axum::Router, uri: &str, agent: Uuid, body: &Value) -> (StatusCode, Value) {
    let token = common::mint_token_with_agent(READ_WRITE, agent);
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("router");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

/// A public flat (`'workflow'`-labelled) workflow claim owned by `group`.
async fn seed_flat_workflow(pool: &PgPool, owner: Uuid, group: Uuid) -> Uuid {
    let content = json!({
        "goal": format!("provider gate flat workflow {}", Uuid::new_v4()),
        "steps": ["first step"],
    })
    .to_string();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, labels, properties) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, ARRAY['workflow'], \
                 '{\"generation\": 0, \"use_count\": 0, \"success_count\": 0, \
                   \"failure_count\": 0, \"avg_variance\": 0.0}'::jsonb)",
    )
    .bind(id)
    .bind(&content)
    .bind(blake3::hash(content.as_bytes()).as_bytes().to_vec())
    .bind(owner)
    .bind(group)
    .execute(pool)
    .await
    .expect("seed a flat workflow claim");
    id
}

/// `(rows, rows with a goal embedding)` of a workflow's behavioral executions.
async fn behavioral_goal_vectors(pool: &PgPool, workflow: Uuid) -> (i64, i64) {
    sqlx::query_as(
        "SELECT count(*), count(goal_embedding) FROM behavioral_executions WHERE workflow_id = $1",
    )
    .bind(workflow)
    .fetch_one(pool)
    .await
    .expect("behavioral rows")
}

/// `POST /api/v1/workflows`: a hierarchical workflow the agent can report on,
/// with the goal embedding the route stores on a row it created.
async fn store_workflow(router: &axum::Router, agent: Uuid, goal: &str) -> Uuid {
    let (status, out) = post(
        router,
        "/api/v1/workflows",
        agent,
        &json!({ "goal": goal, "steps": ["gate step one", "gate step two"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "store_workflow: {out}");
    Uuid::parse_str(out["workflow_id"].as_str().expect("workflow_id")).expect("uuid")
}

/// `workflows.goal_embedding` (regression pin: already gated).
#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_goal_vector_is_stored_only_from_the_owning_provider(pool: PgPool) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "goal-gate").await;
    for (provider, stores) in ARMS {
        let router = router(&pool, provider).await;
        let goal = format!("goal gate {provider:?} {}", Uuid::new_v4());
        let workflow = store_workflow(&router, agent, &goal).await;
        let embedded: bool =
            sqlx::query_scalar("SELECT goal_embedding IS NOT NULL FROM workflows WHERE id = $1")
                .bind(workflow)
                .fetch_one(&pool)
                .await
                .expect("workflow row");
        assert_eq!(embedded, stores, "{provider:?}: workflows.goal_embedding");
    }
}

/// `POST /api/v1/workflows/hierarchical/:id/outcome`: the goal vector on every
/// step row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_hierarchical_outcome_goal_vector_is_stored_only_from_the_owning_provider(
    pool: PgPool,
) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "hier-gate").await;
    for (provider, stores) in ARMS {
        let router = router(&pool, provider).await;
        let workflow =
            store_workflow(&router, agent, &format!("hier gate {}", Uuid::new_v4())).await;
        let (status, out) = post(
            &router,
            &format!("/api/v1/workflows/hierarchical/{workflow}/outcome"),
            agent,
            &json!({
                "success": true,
                "outcome_details": "provider gate",
                "goal_text": "ship the provider gate",
                "step_executions": [{
                    "step_index": 0,
                    "planned": "gate step one",
                    "actual": "done",
                    "deviated": false,
                }],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{provider:?}: {out}");
        assert_eq!(
            behavioral_goal_vectors(&pool, workflow).await,
            (1, i64::from(stores)),
            "{provider:?}: behavioral_executions.goal_embedding of the step row"
        );
    }
}

/// `POST /api/v1/workflows/:id/outcome` on a flat workflow claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_flat_outcome_goal_vector_is_stored_only_from_the_owning_provider(pool: PgPool) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "flat-gate").await;
    for (provider, stores) in ARMS {
        let router = router(&pool, provider).await;
        let workflow = seed_flat_workflow(&pool, agent, group).await;
        let (status, out) = post(
            &router,
            &format!("/api/v1/workflows/{workflow}/outcome"),
            agent,
            &json!({
                "success": true,
                "outcome_details": "provider gate",
                "quality": 1.0,
                "goal_text": "ship the provider gate",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{provider:?}: {out}");
        assert_eq!(
            behavioral_goal_vectors(&pool, workflow).await,
            (1, i64::from(stores)),
            "{provider:?}: behavioral_executions.goal_embedding"
        );
    }
}

/// `POST /api/v1/workflows/:id/behavioral-executions`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_recorded_execution_goal_vector_is_stored_only_from_the_owning_provider(pool: PgPool) {
    let (agent, group) = viewer_fixture::seed_agent_with_group(&pool, "record-gate").await;
    for (provider, stores) in ARMS {
        let router = router(&pool, provider).await;
        let workflow = seed_flat_workflow(&pool, agent, group).await;
        let (status, out) = post(
            &router,
            &format!("/api/v1/workflows/{workflow}/behavioral-executions"),
            agent,
            &json!({
                "goal_text": "ship the provider gate",
                "success": true,
                "step_beliefs": {},
                "tool_pattern": ["first step"],
                "quality": 0.9,
                "deviation_count": 0,
                "total_steps": 1,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{provider:?}: {out}");
        assert_eq!(
            out["embedded"],
            json!(stores),
            "{provider:?}: the response reports whether a vector was stored: {out}"
        );
        assert_eq!(
            behavioral_goal_vectors(&pool, workflow).await,
            (1, i64::from(stores)),
            "{provider:?}: behavioral_executions.goal_embedding"
        );
    }
}

/// `POST /api/v1/methods`: `methods.embedding`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_method_vector_is_stored_only_from_the_owning_provider(pool: PgPool) {
    let (agent, _) = viewer_fixture::seed_agent_with_group(&pool, "method-gate").await;
    for (provider, stores) in ARMS {
        let router = router(&pool, provider).await;
        let (status, out) = post(
            &router,
            "/api/v1/methods",
            agent,
            &json!({
                "name": format!("Provider gate spectroscopy {provider:?} {}", Uuid::new_v4()),
                "technique_type": "spectroscopy",
                "measures": "absorbance",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{provider:?}: {out}");
        let method = Uuid::parse_str(out["method_id"].as_str().expect("method_id")).expect("uuid");
        let embedded: bool =
            sqlx::query_scalar("SELECT embedding IS NOT NULL FROM methods WHERE id = $1")
                .bind(method)
                .fetch_one(&pool)
                .await
                .expect("method row");
        assert_eq!(embedded, stores, "{provider:?}: methods.embedding");
    }
}
