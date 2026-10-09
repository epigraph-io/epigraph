#![cfg(feature = "db")]
//! Migration 148 through the REST surface: every route that writes as the
//! workflow-ingest system agent (`POST /api/v1/workflows`,
//! `POST /api/v1/workflows/steps`, `POST /api/v1/policy-challenges`) resolves
//! it from the `system_agents` registry, so after a key rotation it authors as
//! the REGISTERED agent and mints nothing, and on an armed database with no
//! registration it refuses before writing anything.
//!
//! The mutation each test kills is "this route still does its own key lookup":
//! a leftover copy of the pre-148 body in
//! `routes/workflows.rs::get_or_create_system_agent` (the one
//! `routes/policies.rs::create_challenge` calls) would, after the rotation,
//! miss the public-constant key and try to re-create it, which migration 148's
//! `agents` guard refuses, so the route fails.
//!
//! Handlers are invoked directly with the caller's `ViewerExtractor` on an
//! application-role `AppState`, as `claim_routes_bind_the_caller.rs` does; the
//! harness superuser seeds, rotates keys and arms.

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::policies::{create_challenge, CreateChallengeRequest};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode, SystemAgentRole};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, register_system_agent, seed_agent_with_group,
    seed_human_operator,
};

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

/// Arm as the maintenance role would.
async fn arm(pool: &PgPool) {
    let armed: bool = as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let armed: bool =
            sqlx::query_scalar("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
                .fetch_one(&mut *conn)
                .await
                .expect("arm");
        (conn, armed)
    })
    .await;
    assert!(armed, "the database arms");
}

/// A local copy, as in `claim_routes_bind_the_caller.rs` and
/// `operator_binding.rs` (the single-source lint governs fixture bodies only).
async fn link_live(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
}

fn token(agent: Uuid, client_type: ClientType) -> AuthContext {
    AuthContext {
        client_id: Uuid::new_v4(),
        agent_id: Some(agent),
        owner_id: Some(agent),
        client_type,
        scopes: vec!["claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Unarmed,
    }
}

async fn body_text(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count {table}: {e}"))
}

async fn k_holders(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(
            SystemAgentRole::WorkflowIngest
                .legacy_public_key()
                .as_slice(),
        )
        .fetch_one(pool)
        .await
        .expect("K holders")
}

async fn rotate(pool: &PgPool, agent: Uuid) {
    sqlx::query(
        "UPDATE agents SET public_key = decode(md5(random()::text) || md5(random()::text), 'hex') \
          WHERE id = $1",
    )
    .bind(agent)
    .execute(pool)
    .await
    .expect("rotate the agent's key");
}

/// S created by the unarmed legacy resolver (it holds the public-constant
/// key), registered through the real maintenance definer.
async fn legacy_system_agent_registered(pool: &PgPool) -> Uuid {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    assert!(register_system_agent(pool, s).await);
    s
}

async fn authors_of(pool: &PgPool, content: &str) -> Vec<(Uuid, Uuid)> {
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content = $1")
        .bind(content)
        .fetch_all(pool)
        .await
        .expect("read back")
}

async fn post_challenge(
    pool: &PgPool,
    state: &AppState,
    caller: Uuid,
    client_type: ClientType,
    host: &str,
) -> (StatusCode, String) {
    let viewer = Viewer::resolve(pool, caller).await.expect("viewer");
    let req: CreateChallengeRequest = serde_json::from_value(serde_json::json!({
        "host": host, "port": 443, "protocol": "https"
    }))
    .expect("request");
    let resp = create_challenge(
        ViewerExtractor(viewer),
        State(state.clone()),
        Some(Extension(token(caller, client_type))),
        Json(req),
    )
    .await
    .into_response();
    body_text(resp).await
}

fn challenge_content(host: &str) -> String {
    format!("Network access challenge: {host}:443 (https)")
}

/// `POST /api/v1/workflows` after a rotation: the step claim is S's and no
/// agent holds the public-constant key.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_workflow_ingest_after_rotation_authors_as_the_registered_agent(pool: PgPool) {
    let s = legacy_system_agent_registered(&pool).await;
    rotate(&pool, s).await;
    let (caller, _) = seed_agent_with_group(&pool, "caller").await;
    let state = app_role_state(&pool).await;
    let step = format!("rest post-rotation step {}", Uuid::new_v4());
    let req: epigraph_api::routes::workflows::StoreWorkflowRequest =
        serde_json::from_value(serde_json::json!({
            "goal": format!("rest registry goal {}", Uuid::new_v4()),
            "steps": [step],
        }))
        .expect("request");
    let r = epigraph_api::routes::workflows::store_workflow(
        ViewerExtractor(Viewer::resolve(&pool, caller).await.expect("viewer")),
        State(state),
        Json(req),
    )
    .await;
    let r = r.map(|_| ()).map_err(|e| format!("{e:?}"));
    r.expect("store_workflow after the rotation");
    let authors = authors_of(&pool, &step).await;
    assert_eq!(authors.len(), 1);
    assert_eq!(authors[0].0, s, "the step claim is the registered agent's");
    assert_eq!(k_holders(&pool).await, 0);
}

/// `POST /api/v1/policy-challenges` after a rotation, set up as
/// `claim_routes_bind_the_caller.rs::create_challenge_binds_the_authenticated_caller`
/// (S live-linked to human A, called AS A), unarmed and then armed. Kills the
/// policy route's resolver left as the pre-148 key lookup.
#[sqlx::test(migrations = "../../migrations")]
async fn policy_challenge_after_rotation_authors_as_the_registered_agent(pool: PgPool) {
    let (a, a_group) = seed_human_operator(&pool, "human-a").await;
    let s = legacy_system_agent_registered(&pool).await;
    link_live(&pool, s, a).await;
    rotate(&pool, s).await;
    let state = app_role_state(&pool).await;

    for armed in [false, true] {
        if armed {
            arm(&pool).await;
        }
        let host = format!("registry-{armed}-{}.example", Uuid::new_v4());
        let (status, body) = post_challenge(&pool, &state, a, ClientType::Human, &host).await;
        assert_eq!(status, StatusCode::OK, "armed={armed}: {body}");
        assert_eq!(
            authors_of(&pool, &challenge_content(&host)).await,
            vec![(s, a_group)],
            "armed={armed}: the challenge is the registered agent's, in A's group"
        );
        assert_eq!(k_holders(&pool).await, 0, "armed={armed}");
    }
}

/// Armed, nothing registered: the policy route refuses (500 naming the
/// registry) before writing a claim or an agent.
#[sqlx::test(migrations = "../../migrations")]
async fn policy_challenge_on_an_armed_unregistered_database_refuses_without_writing(pool: PgPool) {
    let (a, _) = seed_human_operator(&pool, "human-a").await;
    arm(&pool).await;
    let state = app_role_state(&pool).await;
    let (claims, agents) = (count(&pool, "claims").await, count(&pool, "agents").await);
    let host = format!("unregistered-{}.example", Uuid::new_v4());
    let (status, body) = post_challenge(&pool, &state, a, ClientType::Human, &host).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body.contains("system_agents"), "names the registry: {body}");
    assert_eq!(count(&pool, "claims").await, claims);
    assert_eq!(count(&pool, "agents").await, agents);
}

/// Armed, nothing registered: `POST /api/v1/workflows/steps` refuses (500
/// naming the registry) before writing anything.
#[sqlx::test(migrations = "../../migrations")]
async fn rest_add_step_on_an_armed_unregistered_database_refuses_without_writing(pool: PgPool) {
    let (a, _) = seed_human_operator(&pool, "human-a").await;
    arm(&pool).await;
    let state = app_role_state(&pool).await;
    let (claims, agents) = (count(&pool, "claims").await, count(&pool, "agents").await);
    let req: epigraph_api::routes::workflows::AddStepRequest =
        serde_json::from_value(serde_json::json!({
            "canonical_name": "no-such-workflow",
            "step_text": "a step",
        }))
        .expect("request");
    let r = epigraph_api::routes::workflows::add_step(
        State(state),
        Some(Extension(token(a, ClientType::Human))),
        Json(req),
    )
    .await;
    let (status, body) = body_text(r.into_response()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body.contains("system_agents"), "names the registry: {body}");
    assert_eq!(count(&pool, "claims").await, claims);
    assert_eq!(count(&pool, "agents").await, agents);
}
