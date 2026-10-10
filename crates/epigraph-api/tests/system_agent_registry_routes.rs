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
//!
//! Verified to fail: `routes/workflows.rs::get_or_create_system_agent` put back
//! to the pre-148 key lookup -> `policy_challenge_after_rotation_*` answers 500
//! (the re-mint is refused by the `agents` guard); the provenance refusal moved
//! from the pre-pass into the author loop ->
//! `provenance_refuses_an_author_naming_the_system_identity` finds the first
//! author's edges (a partial write); the pre-pass's legacy-key check run only
//! when something is registered -> the same test answers 200 in state (0).

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

// ── Author names and caller-supplied keys never reach a system agent ────────

const RESERVED_AUTHOR: &str = "Workflow-Ingest-System.";

/// A superuser `AppState`: `set_provenance` and `create_agent` run on the raw
/// pool, and no tenancy question is asked here.
fn superuser_state(pool: &PgPool) -> AppState {
    AppState::with_db(pool.clone(), ApiConfig::default())
}

async fn provenance(
    state: &AppState,
    claim: Uuid,
    authors: serde_json::Value,
) -> (StatusCode, String) {
    let req: epigraph_api::routes::provenance::ProvenanceRequest =
        serde_json::from_value(serde_json::json!({ "authors": authors })).expect("request");
    let r = epigraph_api::routes::provenance::set_provenance(
        State(state.clone()),
        axum::extract::Path(claim),
        Json(req),
    )
    .await;
    body_text(r.into_response()).await
}

async fn provenance_edges(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE relationship IN ('ATTRIBUTED_TO', 'AUTHORED') \
           AND (source_id = $1 OR target_id = $1)",
    )
    .bind(claim)
    .fetch_one(pool)
    .await
    .expect("provenance edges")
}

async fn agents_with_key(pool: &PgPool, key: &[u8; 32]) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_one(pool)
        .await
        .expect("agents by key")
}

fn name_key(name: &str) -> [u8; 32] {
    epigraph_crypto::did_key::did_key_for_author(None, name).1
}

/// `POST /api/v1/claims/:id/provenance` refuses (400, `field = authors`) a
/// request naming the system identity, from a PRE-PASS: the handler writes each
/// author's edges as it goes on the raw pool, so an in-loop refusal would have
/// committed the authors before it. Run in three states, in order: (0) S holds
/// K and NOTHING is registered (the legacy-key check is the only guard there);
/// (a) S registered; (b) S rotated. Kills: an in-loop guard (Ada's edges and
/// agent would exist); a guard keyed on `orcid.is_some()` (the empty-ORCID
/// request would pass); the legacy-key check missing or run only when
/// something is registered (state (0) adopts S with 200; (a) would hide it
/// behind the registered-id check, (b) behind the `agents` guard).
#[sqlx::test(migrations = "../../migrations")]
async fn provenance_refuses_an_author_naming_the_system_identity(pool: PgPool) {
    let s = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the unarmed fallback creates S")
    };
    let (owner, _) = seed_agent_with_group(&pool, "claim-owner").await;
    let state = superuser_state(&pool);
    let ada = serde_json::json!({ "name": "Ada Lovelace", "position": 0 });

    for phase in ["(0) unregistered", "(a) registered", "(b) rotated"] {
        let rotated = phase.starts_with("(b)");
        match &phase[..3] {
            "(0)" => {
                assert_eq!(
                    count(&pool, "system_agents").await,
                    0,
                    "CALIBRATION {phase}"
                );
                assert_eq!(k_holders(&pool).await, 1, "CALIBRATION {phase}");
            }
            "(a)" => assert!(register_system_agent(&pool, s).await),
            _ => rotate(&pool, s).await,
        }
        let claim = viewer_fixture::seed_public_claim(
            &pool,
            owner,
            &format!("provenance target {phase} {}", Uuid::new_v4()),
        )
        .await;

        let (status, body) = provenance(
            &state,
            claim,
            serde_json::json!([ada, { "name": RESERVED_AUTHOR, "position": 1 }]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{phase} (i): {body}");
        assert!(body.contains("authors"), "names the field: {body}");
        assert_eq!(
            provenance_edges(&pool, claim).await,
            0,
            "{phase}: no partial write"
        );
        assert_eq!(
            agents_with_key(&pool, &name_key("Ada Lovelace")).await,
            0,
            "{phase}: the first author was not created either"
        );

        let (status, body) = provenance(
            &state,
            claim,
            serde_json::json!([{ "name": RESERVED_AUTHOR, "orcid": "" }]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{phase} (ii) empty ORCID: {body}"
        );

        let (status, body) = provenance(
            &state,
            claim,
            serde_json::json!([{ "name": RESERVED_AUTHOR, "orcid": "0000-0002-1825-0097" }]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{phase} (iii) control: a real ORCID derives from the ORCID: {body}"
        );
        if rotated {
            assert_eq!(k_holders(&pool).await, 0, "no K holder minted");
        }
    }
}

/// An author whose name-derived key is the CURRENT key of the registered agent
/// (registered under a name-derived key, not the legacy one) is refused too.
/// Kills: the registered-agent check missing from the pre-pass.
#[sqlx::test(migrations = "../../migrations")]
async fn provenance_refuses_an_author_resolving_to_the_registered_agent(pool: PgPool) {
    let n: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name) VALUES ($1, 'Some Name') RETURNING id",
    )
    .bind(name_key("Some Name").as_slice())
    .fetch_one(&pool)
    .await
    .expect("an agent keyed by a name");
    assert!(register_system_agent(&pool, n).await);
    let (owner, _) = seed_agent_with_group(&pool, "claim-owner").await;
    let claim = viewer_fixture::seed_public_claim(&pool, owner, "provenance target N").await;
    let (status, body) = provenance(
        &superuser_state(&pool),
        claim,
        serde_json::json!([{ "name": "Ada Lovelace" }, { "name": "Some Name" }]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(provenance_edges(&pool, claim).await, 0);
}

/// `POST /api/v1/agents` refuses (400, `field = public_key`) the legacy
/// public-constant key, with and without a registration, before any insert
/// and before any OAuth client is provisioned. Without the refusal,
/// `create_or_get` would mint a K holder (unregistered) or hand back the
/// system agent itself (registered, a find-hit).
#[sqlx::test(migrations = "../../migrations")]
async fn post_agents_refuses_a_reserved_key(pool: PgPool) {
    let state = superuser_state(&pool);
    let k_hex = hex::encode(SystemAgentRole::WorkflowIngest.legacy_public_key());
    let (caller, _) = seed_agent_with_group(&pool, "agents-writer").await;
    let mut auth = token(caller, ClientType::Service);
    auth.scopes = vec!["agents:write".to_string()];

    for registered in [false, true] {
        if registered {
            legacy_system_agent_registered(&pool).await;
        }
        let (agents, clients) = (
            count(&pool, "agents").await,
            count(&pool, "oauth_clients").await,
        );
        let req: epigraph_api::routes::agents::CreateAgentRequest =
            serde_json::from_value(serde_json::json!({
                "public_key": k_hex, "display_name": "workflow-ingest-system"
            }))
            .expect("request");
        let r = epigraph_api::routes::agents::create_agent(
            State(state.clone()),
            Some(Extension(auth.clone())),
            Json(req),
        )
        .await;
        let (status, body) = body_text(r.into_response()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "registered={registered}: {body}"
        );
        assert!(body.contains("public_key"), "names the field: {body}");
        assert_eq!(
            count(&pool, "agents").await,
            agents,
            "registered={registered}"
        );
        assert_eq!(
            count(&pool, "oauth_clients").await,
            clients,
            "registered={registered}"
        );
    }
}
