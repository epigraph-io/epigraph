#![cfg(feature = "db")]
//! The claim-inserting routes of `routes/conventions.rs` and
//! `routes/policies.rs` embed what they insert (CLAUDE.md, "Embedding policy":
//! every current, non-telemetry claim carries a vector, and a path that
//! inserts one embeds it post-commit, best-effort).
//!
//! `POST /api/v1/conventions`, `POST /api/v1/skills/share` and
//! `POST /api/v1/policy-challenges` each insert a current claim and used to
//! make no embedding call at all, so the row stayed `embedding IS NULL`:
//! invisible to dense recall and counted in the `live_missing` audit.
//!
//! Handlers are invoked directly, as `writer_owned_edges_http.rs` and
//! `claim_routes_bind_the_caller.rs` do, in the deployment shape each one
//! works in:
//!
//! * the two convention handlers write on the raw `db_pool`, so their state's
//!   raw pool is the harness superuser (a deployment on a privileged DSN);
//! * `create_challenge` writes on a transaction stamped with the caller, so it
//!   runs on the application role, as a human whose agent is the system agent.
//!
//! # Verified to fail
//!
//! With the three `embed_*` calls removed from the handlers, each test fails
//! on its "carries a vector" assertion and nothing else.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::conventions::{
    learn_convention, share_skill, LearnConventionRequest, ShareSkillRequest,
};
use epigraph_api::routes::policies::{create_challenge, CreateChallengeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_embeddings::{EmbeddingConfig, EmbeddingService, MockProvider};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
    seed_public_claim,
};

fn mock_embedder() -> std::sync::Arc<dyn EmbeddingService> {
    std::sync::Arc::new(MockProvider::new(EmbeddingConfig::openai(1536)))
}

async fn app_role_scoped(pool: &PgPool) -> ScopedPool {
    let url = database_url_for(pool).await;
    ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
        .await
        .expect("app-role ScopedPool")
}

/// A deployment on a privileged DSN: the raw `db_pool` is the harness
/// superuser, the stamped `ScopedPool` is the application role.
async fn privileged_raw_state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(app_role_scoped(pool).await);
    state.with_embedding_service(mock_embedder())
}

fn token(agent: Uuid, client_type: ClientType, scope: &str) -> Option<Extension<AuthContext>> {
    Some(Extension(AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type,
        scopes: vec![scope.to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
        delegated_by: None,
    }))
}

/// `(is_current, embedding IS NOT NULL)` for one claim, read as the superuser.
async fn current_and_embedded(pool: &PgPool, claim: Uuid) -> (bool, bool) {
    sqlx::query_as("SELECT is_current, embedding IS NOT NULL FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("read the claim")
}

#[sqlx::test(migrations = "../../migrations")]
async fn learn_convention_embeds_the_convention_claim(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    let (admin, _) = seed_agent_with_group(&pool, "convention-admin").await;
    let request: LearnConventionRequest = serde_json::from_value(serde_json::json!({
        "content": "Prefer explicit lifetimes in public signatures",
        "evidence": "three reviews asked for them",
    }))
    .expect("request");

    let (status, Json(created)) = learn_convention(
        State(state),
        token(admin, ClientType::Service, "claims:admin"),
        Json(request),
    )
    .await
    .expect("the convention is learned");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        current_and_embedded(&pool, created.claim_id).await,
        (true, true),
        "the convention claim is current and carries a vector"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn share_skill_embeds_the_shared_copy(pool: PgPool) {
    let state = privileged_raw_state(&pool).await;
    let (author, _) = seed_agent_with_group(&pool, "workflow-author").await;
    let (sharer, _) = seed_agent_with_group(&pool, "sharer").await;
    let workflow = seed_public_claim(&pool, author, "a workflow worth sharing").await;

    let (status, Json(shared)) = share_skill(
        ViewerExtractor(Viewer::resolve(&pool, sharer).await.expect("viewer")),
        State(state),
        Json(ShareSkillRequest {
            workflow_id: workflow,
        }),
    )
    .await
    .expect("the workflow is shared");
    assert_eq!(status, StatusCode::CREATED);
    assert_ne!(shared.shared_claim_id, workflow, "a new claim");
    assert_eq!(
        current_and_embedded(&pool, shared.shared_claim_id).await,
        (true, true),
        "the shared copy is current and carries a vector"
    );
}

/// `POST /api/v1/policy-challenges` as human A, whose live-linked agent is the
/// registered system agent, on the application role with operator binding
/// armed: the shape `claim_routes_bind_the_caller.rs` pins for this route.
#[sqlx::test(migrations = "../../migrations")]
async fn create_challenge_embeds_a_new_challenge_once(pool: PgPool) {
    let (a, a_group) = seed_human_operator(&pool, "human-a").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(viewer_fixture::register_system_agent(&pool, system).await);
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, system, a)
            .await
            .expect("system -> a");
    }
    let armed: bool = as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");

    let raw = downgraded_pool(&pool, "epigraph_app").await;
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(app_role_scoped(&pool).await);
    let state = state.with_embedding_service(mock_embedder());

    let host = format!("embed-{}.example", Uuid::new_v4());
    let create = || {
        let (pool, state, host) = (pool.clone(), state.clone(), host.clone());
        async move {
            let request: CreateChallengeRequest = serde_json::from_value(serde_json::json!({
                "host": host, "port": 443, "protocol": "https"
            }))
            .expect("request");
            let response = create_challenge(
                ViewerExtractor(Viewer::resolve(&pool, a).await.expect("viewer")),
                State(state),
                token(a, ClientType::Human, "claims:write"),
                Json(request),
            )
            .await
            .into_response();
            let status = response.status();
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .expect("body")
                .to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            (status, body)
        }
    };

    let (status, body) = create().await;
    assert_eq!(status, StatusCode::OK, "the linked human creates: {body}");
    let id: Uuid = body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("an id: {body}"));
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("the challenge row");
    assert_eq!(owner, a_group, "CALIBRATION: the challenge is in A's group");
    assert_eq!(
        current_and_embedded(&pool, id).await,
        (true, true),
        "the new challenge is current and carries a vector"
    );

    // A repeat creates nothing, so it must not re-embed: the vector it finds
    // is left alone (here: removed first, and still absent afterwards).
    sqlx::query("UPDATE claims SET embedding = NULL WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("clear the vector");
    let (status, body) = create().await;
    assert_eq!(status, StatusCode::OK, "the repeat: {body}");
    assert_eq!(body["id"].as_str(), Some(id.to_string().as_str()));
    assert_eq!(
        current_and_embedded(&pool, id).await,
        (true, false),
        "a repeat request does not embed"
    );
}
