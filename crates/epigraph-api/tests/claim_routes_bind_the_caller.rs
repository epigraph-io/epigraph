#![cfg(feature = "db")]
//! Migration 122 through the claim-writing HTTP handlers, on the APPLICATION
//! ROLE, in the shape a long-lived deployment may carry: `POST /api/v1/submit/packet` and
//! `POST /api/v1/policy-challenges` write a claim whose author comes from the
//! request (the packet's `claim.agent_id`) or is the shared system agent. The
//! claims trigger binds the session PRINCIPAL whenever it differs from the
//! author, so these handlers must write on a transaction stamped with the
//! caller's viewer; on the raw pool the trigger saw no principal and checked
//! only the author the request named.
//!
//! Every arm runs with the orphan permissive `claims_privacy` policy installed
//! (`FOR ALL USING (true)`, no `WITH CHECK`), standing in for the one a
//! long-lived deployment may carry and no migration creates: with it, row
//! security admits any claim INSERT, so what refuses a write here is the
//! trigger and nothing else.
//!
//! Handlers are invoked directly with the caller's `ViewerExtractor`, as
//! `own_claim_authority_http.rs` does; both pools of the `AppState` are the
//! application role.
//!
//! # Verified to fail
//!
//! 1. `submit.rs::persist_packet` and `policies.rs::create_challenge` reverted
//!    to a transaction on `state.db_pool` (the pre-fix handlers), the
//!    database's no-principal rule kept -> the LEGITIMATE controls fail: the
//!    human's own packet and challenge are refused OPL01 (an unstamped write),
//!    so the stamping is load-bearing.
//! 2. The same, with the no-principal rule also removed from migration 122 ->
//!    the unbound caller's challenge is written into A's group under the
//!    system identity; the unbound caller's packet claim passes the trigger as
//!    human A, and the request then fails only because this test schema has
//!    no orphan policy on `reasoning_traces` (the unstamped trace insert is
//!    refused by row security, rolling the claim back).

mod viewer_fixture;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use epigraph_api::middleware::bearer::{AuthContext, ViewerExtractor};
use epigraph_api::middleware::ClientType;
use epigraph_api::routes::policies::{create_challenge, CreateChallengeRequest};
use epigraph_api::routes::submit::{submit_packet, EpistemicPacket};
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_db::visibility::Viewer;
use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{
    as_role, database_url_for, downgraded_pool, seed_agent_with_group, seed_human_operator,
};

async fn app_role_state(pool: &PgPool) -> AppState {
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
    state
}

/// That deployment shape: the orphan permissive policy, then arming as the
/// maintenance role would.
async fn install_orphan_policy_and_arm(pool: &PgPool) {
    sqlx::query("CREATE POLICY claims_privacy ON claims FOR ALL USING (true)")
        .execute(pool)
        .await
        .expect("the orphan permissive policy");
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
    }
}

fn packet(author: Uuid, content: &str) -> EpistemicPacket {
    let evidence = format!("evidence for {content}");
    let evidence_hash = epigraph_crypto::ContentHasher::to_hex(
        &epigraph_crypto::ContentHasher::hash(evidence.as_bytes()),
    );
    serde_json::from_value(serde_json::json!({
        "claim": { "content": content, "initial_truth": 0.7, "agent_id": author },
        "evidence": [{
            "content_hash": evidence_hash,
            "evidence_type": {
                "type": "observation",
                "observed_at": chrono::Utc::now(),
                "method": "test",
                "location": null
            },
            "raw_content": evidence,
            "signature": null
        }],
        "reasoning_trace": {
            "methodology": "deductive",
            "inputs": [{"type": "evidence", "index": 0}],
            "confidence": 0.7,
            "explanation": "test",
            "signature": null
        },
        "signature": "0".repeat(128)
    }))
    .expect("a well-formed packet")
}

async fn body_text(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_packet(
    state: &AppState,
    viewer: Viewer,
    author: Uuid,
    content: &str,
) -> (StatusCode, String) {
    let resp = submit_packet(
        ViewerExtractor(viewer),
        State(state.clone()),
        Ok(Json(packet(author, content))),
    )
    .await;
    body_text(resp).await
}

async fn claims_with_content(pool: &PgPool, content: &str) -> Vec<(Uuid, Uuid)> {
    let hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());
    sqlx::query_as("SELECT agent_id, owner_group_id FROM claims WHERE content_hash = $1")
        .bind(hash.as_slice())
        .fetch_all(pool)
        .await
        .expect("read back")
}

/// Delta review SEC-D1 / DIS-D1: a packet is written as its caller, not as the
/// author its body names. An unbound caller and another human's caller naming
/// registered human A are refused (403) and write nothing; A itself, and A
/// naming its own live agent, succeed.
#[sqlx::test(migrations = "../../migrations")]
async fn submit_packet_binds_the_authenticated_caller(pool: PgPool) {
    let (a, a_group) = seed_human_operator(&pool, "human-a").await;
    let (b, _) = seed_human_operator(&pool, "human-b").await;
    let (x, _) = seed_agent_with_group(&pool, "a-agent-x").await;
    let (u, _) = seed_agent_with_group(&pool, "unbound-u").await;
    link_live(&pool, x, a).await;
    install_orphan_policy_and_arm(&pool).await;
    let state = app_role_state(&pool).await;

    for (caller, what) in [(u, "an unbound caller"), (b, "another human")] {
        let content = format!("packet by {what} naming human A {}", Uuid::new_v4());
        let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
        let (status, body) = post_packet(&state, viewer, a, &content).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{what} naming human A must be refused: {body}"
        );
        assert!(
            body.contains("OPL0"),
            "{what}: the refusal names its code: {body}"
        );
        assert!(
            claims_with_content(&pool, &content).await.is_empty(),
            "{what}: nothing may be written"
        );
    }

    // Controls: the human as itself, and naming its own live agent.
    for (author, what) in [(a, "A as itself"), (x, "A naming its agent X")] {
        let content = format!("packet by {what} {}", Uuid::new_v4());
        let viewer = Viewer::resolve(&pool, a).await.expect("viewer");
        let (status, body) = post_packet(&state, viewer, author, &content).await;
        assert_eq!(status, StatusCode::CREATED, "{what}: {body}");
        assert_eq!(
            claims_with_content(&pool, &content).await,
            vec![(author, a_group)],
            "{what}: one claim, attributed as named, owned by A's group"
        );
    }
}

/// Delta review DIS-D2: a policy challenge is authored by the shared system
/// agent; once that agent is live-linked to human A, an unbound caller must not
/// be able to put its text into A's group under the system identity. A itself
/// can.
#[sqlx::test(migrations = "../../migrations")]
async fn create_challenge_binds_the_authenticated_caller(pool: PgPool) {
    let (a, a_group) = seed_human_operator(&pool, "human-a").await;
    let (u, _) = seed_agent_with_group(&pool, "unbound-u").await;
    let system = {
        let mut conn = pool.acquire().await.expect("acquire");
        epigraph_ingest_executor::get_or_create_system_agent(&mut conn)
            .await
            .expect("the system agent")
    };
    link_live(&pool, system, a).await;
    install_orphan_policy_and_arm(&pool).await;
    let state = app_role_state(&pool).await;

    let challenge = |caller: Uuid, client_type: ClientType, host: String| {
        let pool = pool.clone();
        let state = state.clone();
        async move {
            let viewer = Viewer::resolve(&pool, caller).await.expect("viewer");
            let req: CreateChallengeRequest = serde_json::from_value(serde_json::json!({
                "host": host, "port": 443, "protocol": "https"
            }))
            .expect("request");
            let resp = create_challenge(
                ViewerExtractor(viewer),
                State(state),
                Some(Extension(token(caller, client_type))),
                Json(req),
            )
            .await
            .into_response();
            body_text(resp).await
        }
    };
    let rows = |host: String| {
        let pool = pool.clone();
        async move {
            let content = format!("Network access challenge: {host}:443 (https)");
            claims_with_content(&pool, &content).await
        }
    };

    let host = format!("unbound-{}.example", Uuid::new_v4());
    let (status, body) = challenge(u, ClientType::Service, host.clone()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unbound caller must not write through the system identity: {body}"
    );
    assert!(rows(host).await.is_empty(), "nothing may be written");

    let host = format!("human-{}.example", Uuid::new_v4());
    let (status, body) = challenge(a, ClientType::Human, host.clone()).await;
    assert_eq!(status, StatusCode::OK, "the linked human: {body}");
    assert_eq!(
        rows(host).await,
        vec![(system, a_group)],
        "the challenge is the system agent's, in A's group"
    );
}
