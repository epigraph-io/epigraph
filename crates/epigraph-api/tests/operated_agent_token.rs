//! Operated agents are stdio-only, enforced at TOKEN ISSUANCE (migration 102,
//! stage-2 brief A3).
//!
//! An operated agent holds a `writer` membership in its operator's personal
//! group, so the `Viewer` of any token minted for it can write the operator's
//! rows. `oauth::token::principal_agent_id` — the one choke point all four mint
//! sites share — therefore refuses an agent with a live ACTING operator link.
//! A link-time "has no OAuth client" check would not be enough: a client can be
//! approved after the link.
//!
//! Driven through the real `/oauth/token` route with a real Ed25519 assertion
//! (`client_credentials`, `urn:epigraph:ed25519`), against a `#[sqlx::test]`
//! database. Three agents, each with an ACTIVE agent-type OAuth client:
//!
//! * linked (acting) -> 403;
//! * CALIBRATION, unlinked, same client shape -> 200 with an access token, so
//!   the refusal is the link and not the fixture;
//! * retired link -> 200: a retired agent holds no membership, so its token
//!   carries no operator authority (documented behaviour, not a gap).

#[path = "viewer_fixture.rs"]
mod fixture;

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::AgentRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        allow_all_identities: true,
    }
}

/// An agent row whose public key is `key`'s, plus an ACTIVE agent-type OAuth
/// client for it (with the human owner client the `agents_must_have_owner`
/// check requires). Returns the agent id and the client id (hex public key).
async fn agent_with_active_client(pool: &PgPool, key: &SigningKey) -> (Uuid, String) {
    let public_key = key.verifying_key().to_bytes();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(public_key.to_vec())
        .execute(pool)
        .await
        .expect("agent row");
    let owner: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'owner', 'human', ARRAY['claims:read'], ARRAY['claims:read'], 'active') \
         RETURNING id",
    )
    .bind(format!("owner-{agent}"))
    .fetch_one(pool)
    .await
    .expect("owner client");
    let client_id = hex::encode(public_key);
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'operated-agent-test', 'agent', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $2, $3)",
    )
    .bind(&client_id)
    .bind(agent)
    .bind(owner)
    .execute(pool)
    .await
    .expect("agent client");
    (agent, client_id)
}

/// `timestamp(8B BE) || nonce(16B) || Ed25519(timestamp || nonce)`, base64.
fn assertion(key: &SigningKey) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(Uuid::new_v4().as_bytes());
    let sig = key.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, msg)
}

async fn assertion_grant(pool: &PgPool, client_id: &str, key: &SigningKey) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), config()));
    let body = json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion(key),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_cannot_mint_a_token_by_assertion(pool: PgPool) {
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;

    // CALIBRATION: an unlinked agent with the same client shape gets a token.
    let unlinked_key = SigningKey::from_bytes(&[0x41; 32]);
    let (_unlinked, unlinked_client) = agent_with_active_client(&pool, &unlinked_key).await;
    let (status, body) = assertion_grant(&pool, &unlinked_client, &unlinked_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: an unlinked agent's assertion grant must mint, or the refusal below proves \
         nothing: {body}"
    );
    assert!(body.get("access_token").is_some(), "{body}");

    // The operated agent: linked AFTER its client exists and is active.
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let (agent, client_id) = agent_with_active_client(&pool, &key).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent after its OAuth client was approved");
    drop(conn);
    let (status, body) = assertion_grant(&pool, &client_id, &key).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operated agent minted a token: its writer membership in the operator's group would \
         reach the HTTP surface: {body}"
    );
    assert!(
        body.to_string().contains("stdio-only") && body.to_string().contains(&operator.to_string()),
        "the refusal must say why and name the operator: {body}"
    );

    // A RETIRED link does not refuse: no membership, so no operator authority.
    let retired_key = SigningKey::from_bytes(&[0x43; 32]);
    let (retired, retired_client) = agent_with_active_client(&pool, &retired_key).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, retired, operator)
        .await
        .expect("retired link");
    drop(conn);
    let (status, body) = assertion_grant(&pool, &retired_client, &retired_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a retired agent holds no membership, so its token carries no operator authority: {body}"
    );
}
