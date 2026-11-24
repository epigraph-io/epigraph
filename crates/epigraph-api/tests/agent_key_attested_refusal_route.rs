#![cfg(feature = "db")]
//! Backlog 3f5a18cd: `POST /api/v1/agents/:id/keys/rotate` and
//! `POST /api/v1/agents/:id/keys/:key_id/revoke` answer an APPLICATION
//! session's change to an attested signing key (refused by the database with
//! SQLSTATE 42501, AK02, migration 161) as a 403 naming the right path
//! (`routes::agent_keys::attested_key_refusal`), not as an opaque 500, and
//! write nothing.
//!
//! Through the full router (bearer middleware, scope check, caller check)
//! with both pools of the `AppState` on the APPLICATION ROLE: on the
//! superuser pool `#[sqlx::test]` hands out, `epigraph_bypass()` is true and
//! the guard admits every write, so the refusal is never reached (the
//! superuser-harness tests in `agent_mutation_auth_test.rs` rotate and revoke
//! successfully). The handlers write on `state.db_pool`, so that pool is the
//! one calibrated here. A non-attested key's revoke on the same state is the
//! positive control: the route works on the application role, and only the
//! attested refusal is a 403. All names are invented.

mod common;
mod viewer_fixture;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use epigraph_api::create_router;
use epigraph_api::state::{ApiConfig, AppState};
use epigraph_crypto::AgentSigner;
use epigraph_db::{ScopedPool, SessionGucMode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;
use viewer_fixture::{database_url_for, downgraded_pool};

/// The remedy the 403 names (`attested_key_refusal`).
const REMEDY: [&str; 3] = [
    "attested signing key",
    "host's identity registration",
    "maintenance session",
];

async fn app_role_state(pool: &PgPool) -> AppState {
    let url = database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let raw = downgraded_pool(pool, "epigraph_app").await;
    for (name, p) in [("scoped", scoped.inner()), ("raw", &raw)] {
        let bypass: bool = sqlx::query_scalar("SELECT public.epigraph_bypass()")
            .fetch_one(p)
            .await
            .expect("epigraph_bypass");
        assert!(
            !bypass,
            "CALIBRATION: the {name} pool must not be privileged"
        );
    }
    let mut state = AppState::with_db(raw, ApiConfig::default());
    state.scoped = Some(scoped);
    state
}

/// An LLM agent seeded the way derived identities are: `agents.public_key`
/// and one active, ATTESTED `signing` row are its key (seeded on the
/// superuser pool, as the host's identity registration would bind it).
/// Returns the agent, its signer and the key row.
async fn seed_attested_agent(pool: &PgPool) -> (Uuid, AgentSigner, Uuid) {
    let id = Uuid::new_v4();
    let signer = epigraph_crypto::keypair_from_llm_agent(
        "synthetic-model-1",
        &format!("synthetic system prompt {}", Uuid::new_v4()),
    );
    let pk = signer.public_key().to_vec();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type, key_kind) \
         VALUES ($1, $2, 'llm', 'derived')",
    )
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed agent");
    let key_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'signing', 'active', now())",
    )
    .bind(key_id)
    .bind(id)
    .bind(&pk)
    .execute(pool)
    .await
    .expect("seed the attested signing row (test superuser)");
    (id, signer, key_id)
}

/// A rotation body whose old-key and new-key signatures both verify over the
/// endpoint's canonical message ("rotate:" ‖ agent uuid bytes ‖ ":" ‖ new
/// public key), so the request passes every check before the database's.
fn valid_rotation_body(agent: Uuid, old: &AgentSigner, new: &AgentSigner) -> serde_json::Value {
    let new_pk = new.public_key();
    let mut msg = b"rotate:".to_vec();
    msg.extend_from_slice(agent.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&new_pk);
    serde_json::json!({
        "new_public_key": hex::encode(new_pk),
        "old_key_signature": hex::encode(old.sign(&msg)),
        "new_key_signature": hex::encode(new.sign(&msg)),
        "reason": "rotation test",
    })
}

type KeyRowSnapshot = (
    Uuid,
    Vec<u8>,
    String,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<String>,
    Option<Uuid>,
);

/// Every `agent_keys` column a rotate or revoke could change, for one agent.
async fn key_rows(pool: &PgPool, agent: Uuid) -> Vec<KeyRowSnapshot> {
    sqlx::query_as(
        "SELECT id, public_key, key_type::text, status::text, valid_until, \
                revocation_reason, revoked_by \
           FROM agent_keys WHERE agent_id = $1 ORDER BY id",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("read agent_keys")
}

async fn post(
    state: &AppState,
    agent: Uuid,
    uri: &str,
    body: &serde_json::Value,
) -> (StatusCode, String) {
    let token = common::mint_token_with_agent(&["agents:write"], agent);
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state.clone())
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn assert_attested_refusal(what: &str, status: StatusCode, text: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {text}");
    for phrase in REMEDY {
        assert!(text.contains(phrase), "{what}: no {phrase:?} in {text}");
    }
}

/// Since migration 239 (backlog 54018ca1) the rotation is ONE call of the
/// maintenance-only definer `epigraph_agent_key_rotate`, which the application
/// role may not execute: on the application role every rotation, attested or
/// not, is refused 42501 before the definer's AK02 gate runs, and the route
/// answers it as `KeyWriteRefusal::RolePrivilege` (a 403 that names the
/// maintenance session), not the attested-key text. Nothing is written either
/// way. Mutation: drop `.map_err(key_write_refusal)` from the rotation call ->
/// the 42501 surfaces as a 500 and this fails.
#[sqlx::test(migrations = "../../migrations")]
async fn rotating_an_attested_key_on_the_application_role_is_a_403_that_writes_nothing(
    pool: PgPool,
) {
    let state = app_role_state(&pool).await;
    let (agent, old, _) = seed_attested_agent(&pool).await;
    let new = AgentSigner::generate();
    let before = key_rows(&pool, agent).await;

    let (status, text) = post(
        &state,
        agent,
        &format!("/api/v1/agents/{agent}/keys/rotate"),
        &valid_rotation_body(agent, &old, &new),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "rotate: {text}");
    for phrase in [
        "agent-key rotation runs on a maintenance session",
        "nothing was written",
    ] {
        assert!(text.contains(phrase), "rotate: no {phrase:?} in {text}");
    }

    assert_eq!(key_rows(&pool, agent).await, before, "rotate wrote a key");
    let holding_new: i64 =
        sqlx::query_scalar("SELECT count(*) FROM agent_keys WHERE public_key = $1")
            .bind(new.public_key().as_slice())
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(holding_new, 0, "the new key was stored");
}

/// Mutation: drop `.map_err(attested_key_refusal)` from revoke's
/// `update_status` call -> a 500 and this fails. The positive control (an
/// `encryption` key of the same agent, revoked by the same caller on the same
/// state) proves the route revokes on the application role, so the 403 is
/// the attested refusal and not a blanket one.
#[sqlx::test(migrations = "../../migrations")]
async fn revoking_an_attested_key_on_the_application_role_is_a_403_that_writes_nothing(
    pool: PgPool,
) {
    let state = app_role_state(&pool).await;
    let (agent, _, key_id) = seed_attested_agent(&pool).await;
    let other_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_keys (id, agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, $3, 'encryption', 'active', now())",
    )
    .bind(other_id)
    .bind(agent)
    .bind(AgentSigner::generate().public_key().as_slice())
    .execute(&pool)
    .await
    .expect("seed a non-attested key");
    let before = key_rows(&pool, agent).await;
    let body = serde_json::json!({ "reason": "suspected exposure" });

    let (status, text) = post(
        &state,
        agent,
        &format!("/api/v1/agents/{agent}/keys/{key_id}/revoke"),
        &body,
    )
    .await;
    assert_attested_refusal("revoke", status, &text);
    assert_eq!(key_rows(&pool, agent).await, before, "revoke wrote a key");

    // Positive control: the non-attested key revokes on the same state.
    let (status, text) = post(
        &state,
        agent,
        &format!("/api/v1/agents/{agent}/keys/{other_id}/revoke"),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "positive control: {text}");
    let after = key_rows(&pool, agent).await;
    let status_of = |rows: &[KeyRowSnapshot], id: Uuid| {
        rows.iter()
            .find(|r| r.0 == id)
            .map(|r| r.3.clone())
            .expect("row")
    };
    assert_eq!(status_of(&after, other_id), "revoked");
    assert_eq!(
        status_of(&after, key_id),
        "active",
        "the attested key moved"
    );
}
