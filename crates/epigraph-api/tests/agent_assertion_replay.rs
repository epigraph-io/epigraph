//! An agent's Ed25519 `client_credentials` assertion is single use (migration
//! 213, backlog 950696a1 step 1).
//!
//! The assertion is `timestamp || nonce || Ed25519(timestamp || nonce)` and is
//! accepted for 300 seconds after its timestamp. Before 213 nothing recorded
//! the nonce, so one captured assertion minted an access token and a 24-hour
//! refresh token as often as it was replayed inside that window. Driven
//! through the real `/oauth/token` route against a `#[sqlx::test]` database:
//!
//! * `client_credentials`: the same assertion twice -> 200, then 401 with no
//!   token; a FRESH assertion by the same client right after -> 200
//!   (calibration: the refusal is the replay, not the client's state); another
//!   client's assertion carrying the same nonce bytes -> 200 (the record is per
//!   client).
//! * the refresh grant, where an agent authenticates with the same assertion
//!   check: an assertion already spent on `client_credentials` -> 401, an
//!   assertion replayed after one successful refresh -> 401, and each refusal
//!   leaves the presented refresh token usable with a fresh assertion.
//!
//! The grants this file cannot see (the definer's EXECUTE grant to the
//! application role, the revoked table DML) are measured as `epigraph_app` in
//! `epigraph-db/tests/app_role_table_lockdown.rs`
//! (`assertion_nonces_are_consumed_once_through_the_definer`).

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use ed25519_dalek::{Signer, SigningKey};
use epigraph_api::{create_router, ApiConfig, AppState};
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

/// An agent row for `key` and an ACTIVE agent-type OAuth client for it (with
/// the human owner client the `agents_must_have_owner` check requires).
/// Returns the client's `client_id` (the hex public key).
async fn active_agent_client(pool: &PgPool, key: &SigningKey) -> String {
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
         VALUES ($1, 'assertion-replay-test', 'agent', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $2, $3)",
    )
    .bind(&client_id)
    .bind(agent)
    .bind(owner)
    .execute(pool)
    .await
    .expect("agent client");
    client_id
}

/// `timestamp(8B BE) || nonce(16B) || Ed25519(timestamp || nonce)`, base64,
/// with the given nonce.
fn assertion_with(key: &SigningKey, nonce: [u8; 16]) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(&nonce);
    let sig = key.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, msg)
}

fn fresh_assertion(key: &SigningKey) -> String {
    assertion_with(key, Uuid::new_v4().into_bytes())
}

fn credentials_grant(client_id: &str, assertion: &str) -> Value {
    json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion,
    })
}

fn refresh_grant(token: &str, client_id: &str, assertion: &str) -> Value {
    json!({
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion,
    })
}

async fn post_token(app: &Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn refresh_token_of(body: &Value) -> String {
    body["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("a refresh token: {body}"))
        .to_string()
}

/// Catches: a captured agent assertion minting a second access token (and a
/// second refresh chain) inside its freshness window.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_client_credentials_assertion_is_refused(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let nonce = Uuid::new_v4().into_bytes();
    let captured = assertion_with(&key, nonce);
    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first presentation mints: {body}"
    );
    assert!(body["access_token"].is_string(), "{body}");

    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the same assertion presented again inside its window must be refused: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert!(body.get("refresh_token").is_none(), "{body}");

    // Calibration: the client itself is fine; a fresh assertion mints.
    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh assertion by the same client still mints, so the refusal above \
         was the replay: {body}"
    );

    // The record is per client: another agent whose assertion happens to
    // carry the same nonce bytes is not refused.
    let other_key = SigningKey::from_bytes(&rand::random());
    let other_id = active_agent_client(&pool, &other_key).await;
    let (status, body) = post_token(
        &app,
        credentials_grant(&other_id, &assertion_with(&other_key, nonce)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another client's first use of the same nonce bytes is not a replay: {body}"
    );
}

/// Catches: the refresh grant, which authenticates an agent with the same
/// assertion check, accepting an assertion already spent (on either grant).
/// Each refusal happens before the chain is touched, so the presented refresh
/// token still refreshes with a fresh assertion.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_assertion_is_refused_on_the_refresh_grant(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let minted_with = fresh_assertion(&key);
    let (status, body) = post_token(&app, credentials_grant(&client_id, &minted_with)).await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    let r0 = refresh_token_of(&body);

    // The assertion spent on client_credentials cannot authenticate a refresh.
    let (status, body) = post_token(&app, refresh_grant(&r0, &client_id, &minted_with)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an assertion already spent on client_credentials is a replay on refresh: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");

    // r0 was left intact by that refusal.
    let refreshed_with = fresh_assertion(&key);
    let (status, body) = post_token(&app, refresh_grant(&r0, &client_id, &refreshed_with)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused replay left the chain usable: {body}"
    );
    let r1 = refresh_token_of(&body);

    // The assertion that just refreshed cannot refresh again.
    let (status, body) = post_token(&app, refresh_grant(&r1, &client_id, &refreshed_with)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an assertion replayed on a second refresh must be refused: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");

    let (status, body) =
        post_token(&app, refresh_grant(&r1, &client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "r1 still refreshes with a fresh assertion: {body}"
    );
}
