//! An agent's Ed25519 `client_credentials` assertion is single use (migration
//! 213, backlog 950696a1 step 1).
//!
//! The assertion is `timestamp || nonce || Ed25519(timestamp || nonce)` and is
//! accepted for 300 seconds after its timestamp. Before 213 nothing recorded
//! the nonce, so one captured assertion minted an access token and a 24-hour
//! refresh token as often as it was replayed inside that window. Driven
//! through the real `/oauth/token` route against a `#[sqlx::test]` database:
//!
//! * `client_credentials`: the same assertion twice -> 200, then 400
//!   `invalid_client` with no token; a FRESH assertion by the same client
//!   right after -> 200 (calibration: the refusal is the replay, not the
//!   client's state); another client's assertion carrying the same nonce
//!   bytes -> 200 (the record is per client).
//! * the refresh grant, where an agent authenticates with the same assertion
//!   check: an assertion already spent on `client_credentials` -> 400
//!   `invalid_client`, an assertion replayed after one successful refresh ->
//!   400 `invalid_client` (RFC 6749 section 5.2, backlog 31d799b3), and each
//!   refusal leaves the presented refresh token usable with a fresh assertion.
//!
//! Version 2 (backlog bada894d, 950696a1 step 2): the same 88 bytes, the
//! signature over `epigraph_crypto::oauth_assertion_message(issuer, ts,
//! nonce)`, bound to the server's published issuer. Tried first; a version-2
//! assertion for another issuer is refused; version 1 is accepted and counted
//! (one `security_events` row per accepted assertion) under the default
//! `EPIGRAPH_ASSERTION_V1=accept`, and refused under `refuse`; a version-2
//! assertion is single use like a version-1 one.
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

/// The issuer `config()` publishes (`public_base_url` without a trailing `/`).
const ISSUER: &str = "http://localhost:8080";

/// A VERSION-2 assertion for `issuer`: `timestamp(8B BE) || nonce(16B) ||
/// Ed25519(oauth_assertion_message(issuer, timestamp, nonce))`, base64.
fn v2_assertion_for(key: &SigningKey, issuer: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let nonce = Uuid::new_v4().into_bytes();
    let sig = key.sign(&epigraph_crypto::oauth_assertion_message(
        issuer, ts, &nonce,
    ));
    let mut wire = Vec::with_capacity(88);
    wire.extend_from_slice(&ts.to_be_bytes());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&sig.to_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, wire)
}

/// How many version-1 assertions by `client_id` were accepted and counted.
async fn v1_accepted_rows(pool: &PgPool, client_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM security_events \
          WHERE event_type = $1 AND details->>'client_id' = $2",
    )
    .bind(epigraph_api::oauth::assertion::V1_ACCEPTED_EVENT)
    .bind(client_id)
    .fetch_one(pool)
    .await
    .expect("count v1 rows")
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
        StatusCode::BAD_REQUEST,
        "the same assertion presented again inside its window must be refused: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
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
        StatusCode::BAD_REQUEST,
        "an assertion already spent on client_credentials is a replay on refresh: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");

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
        StatusCode::BAD_REQUEST,
        "an assertion replayed on a second refresh must be refused: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");

    let (status, body) =
        post_token(&app, refresh_grant(&r1, &client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "r1 still refreshes with a fresh assertion: {body}"
    );
}

/// Catches: the single-use record keyed by the `oauth_clients` ROW instead of
/// the signing key. `/oauth/register` takes an agent's `client_id` as given and
/// `hex::decode` accepts either case, so the lowercase and uppercase spellings
/// of one public key can be two client rows that verify the same signature. An
/// assertion spent on one must not mint again on the other.
#[sqlx::test(migrations = "../../migrations")]
async fn an_assertion_spent_on_one_spelling_of_a_key_is_refused_on_another(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let lower = active_agent_client(&pool, &key).await;
    let upper = lower.to_uppercase();
    assert_ne!(lower, upper, "the hex key has letters to case-fold");
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         SELECT $2, 'assertion-replay-test-upper', 'agent', allowed_scopes, granted_scopes, \
                'active', agent_id, owner_id \
           FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&lower)
    .bind(&upper)
    .execute(&pool)
    .await
    .expect("the uppercase spelling of the same key as a second active client");
    let app = create_router(AppState::with_db(pool.clone(), config()));

    // Calibration: the uppercase row authenticates on its own.
    let (status, body) = post_token(&app, credentials_grant(&upper, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the uppercase spelling mints with a fresh assertion: {body}"
    );

    let captured = fresh_assertion(&key);
    let (status, body) = post_token(&app, credentials_grant(&lower, &captured)).await;
    assert_eq!(status, StatusCode::OK, "first presentation: {body}");
    let (status, body) = post_token(&app, credentials_grant(&upper, &captured)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the same signed assertion replayed under the other spelling of the key: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
}

/// Backlog 57943a39: an agent client whose key is held by a `seed-derived`
/// agent (migration 230) is refused on BOTH grants that run the assertion
/// check. The key here is derived exactly as `ingest_literature` derived its
/// author keys, `BLAKE3("<doi>:<name>")` as the Ed25519 secret, so anyone who
/// knows the paper and the name can sign the assertion; the check verified the
/// signature under `client_id` and never read `agents.key_kind`.
///
/// Calibration on the SAME client: while the agent row is `ed25519` the
/// assertion mints (and yields a refresh chain), so the refusals after the
/// row is re-marked are a function of `key_kind`, not of the client or key.
#[sqlx::test(migrations = "../../migrations")]
async fn a_seed_derived_agent_key_cannot_authenticate(pool: PgPool) {
    let seed = blake3::hash(b"10.0000/example.0001:Ada Example");
    let key = SigningKey::from_bytes(seed.as_bytes());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "calibration: as an ed25519 row the key mints: {body}"
    );
    let refresh = refresh_token_of(&body);

    // The operator's repair: the row is marked for what its key is.
    sqlx::query("UPDATE agents SET key_kind = 'seed-derived' WHERE public_key = $1")
        .bind(key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("re-mark seed-derived");

    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "client_credentials minted for a seed-derived key: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");

    let (status, body) = post_token(
        &app,
        refresh_grant(&refresh, &client_id, &fresh_assertion(&key)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the refresh grant accepted a seed-derived key's assertion: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
}

/// The refusal is "anything but `ed25519`", not `seed-derived` only: the
/// unkeyed LLM identity (`BLAKE3("llm-agent:{model}:{prompt hash}")`) is
/// stored as `derived` (migration 161) and migration 230 could not re-mark it,
/// so its key is just as computable. Calibrated on the SAME client: it mints
/// while the row is `ed25519`, and is refused once the row is `derived`.
#[sqlx::test(migrations = "../../migrations")]
async fn a_derived_agent_key_cannot_authenticate(pool: PgPool) {
    let seed = blake3::hash(b"llm-agent:example-model:0000");
    let key = SigningKey::from_bytes(seed.as_bytes());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "calibration: as an ed25519 row the key mints: {body}"
    );

    sqlx::query("UPDATE agents SET key_kind = 'derived' WHERE public_key = $1")
        .bind(key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("mark derived");
    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "client_credentials minted for a derived (non-verifier) key: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
}

/// The refusal reads the kind of an agent that HOLDS the key; a key no agent
/// holds is not refused. That is every `/oauth/register` agent client: its own
/// key has no agents row (it is linked to a separate `derived` principal at
/// mint time), so a refusal that treated "no row" as "not a verifier" would
/// lock all of them out.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_client_whose_key_no_agent_holds_still_authenticates(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    // Detach the client from the fixture's agent row and drop the row, so the
    // key is held by no agent, as for a client `/oauth/register` created.
    sqlx::query("UPDATE oauth_clients SET agent_id = NULL WHERE client_id = $1")
        .bind(&client_id)
        .execute(&pool)
        .await
        .expect("detach client");
    sqlx::query("DELETE FROM agents WHERE public_key = $1")
        .bind(key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("drop agent row");
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an agent client whose key no agent holds must still mint: {body}"
    );
}

/// Catches: the token endpoint not verifying the version-2 message (bound to
/// its own issuer), and a version-2 assertion being replayable. The first
/// presentation mints and is not counted as version 1; the same assertion
/// again is refused like any replay.
#[sqlx::test(migrations = "../../migrations")]
async fn a_v2_assertion_mints_once_and_its_replay_is_refused(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let captured = v2_assertion_for(&key, ISSUER);
    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a v2 assertion for this issuer: {body}"
    );
    assert!(body["access_token"].is_string(), "{body}");
    assert_eq!(
        v1_accepted_rows(&pool, &client_id).await,
        0,
        "a v2 assertion is not counted as v1"
    );

    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the same v2 assertion replayed: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");

    // And on the refresh grant, which runs the same check.
    let (status, body) = post_token(
        &app,
        credentials_grant(&client_id, &v2_assertion_for(&key, ISSUER)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh = refresh_token_of(&body);
    let (status, body) = post_token(
        &app,
        refresh_grant(&refresh, &client_id, &v2_assertion_for(&key, ISSUER)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a v2 assertion refreshes: {body}");
}

/// Catches: an assertion signed for ANOTHER authorization server (another
/// issuer, or the connect URL instead of the published issuer) authenticating
/// here. Refused as `invalid_client`, under the default switch, with no
/// token; the same client then mints with an assertion for this issuer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_v2_assertion_for_another_issuer_is_refused(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    for other in [
        "https://other.example",
        "http://localhost:8080/",
        "http://localhost:8080/mcp",
    ] {
        let (status, body) = post_token(
            &app,
            credentials_grant(&client_id, &v2_assertion_for(&key, other)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a v2 assertion for {other} minted at {ISSUER}: {body}"
        );
        assert!(body.get("access_token").is_none(), "{body}");
        assert_eq!(body["error"], "invalid_client", "{body}");
    }

    let (status, body) = post_token(
        &app,
        credentials_grant(&client_id, &v2_assertion_for(&key, ISSUER)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "calibration: the same client mints with an assertion for this issuer: {body}"
    );
}

/// Catches: a version-1 assertion going uncounted, or counted more than once.
/// Under the default switch it mints and writes exactly one
/// `security_events` row naming the client; its replay is refused and adds no
/// row (the count is written after the nonce is spent).
#[sqlx::test(migrations = "../../migrations")]
async fn a_v1_assertion_is_accepted_and_counted_by_default(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));
    assert_eq!(v1_accepted_rows(&pool, &client_id).await, 0);

    let captured = fresh_assertion(&key);
    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(status, StatusCode::OK, "v1 is accepted by default: {body}");
    assert_eq!(
        v1_accepted_rows(&pool, &client_id).await,
        1,
        "one accepted v1 assertion, one row"
    );

    let (status, body) = post_token(&app, credentials_grant(&client_id, &captured)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "the v1 replay: {body}");
    assert_eq!(
        v1_accepted_rows(&pool, &client_id).await,
        1,
        "a refused replay is not counted"
    );

    let grant: String = sqlx::query_scalar(
        "SELECT details->>'grant_type' FROM security_events \
          WHERE event_type = $1 AND details->>'client_id' = $2",
    )
    .bind(epigraph_api::oauth::assertion::V1_ACCEPTED_EVENT)
    .bind(&client_id)
    .fetch_one(&pool)
    .await
    .expect("the row");
    assert_eq!(grant, "client_credentials");
}

/// Catches: `EPIGRAPH_ASSERTION_V1=refuse` not refusing. A version-1
/// assertion is then `invalid_client` on both grants (no token, no count),
/// while a version-2 assertion by the same client mints and refreshes.
#[sqlx::test(migrations = "../../migrations")]
async fn a_v1_assertion_is_refused_under_refuse(pool: PgPool) {
    let key = SigningKey::from_bytes(&rand::random());
    let client_id = active_agent_client(&pool, &key).await;
    let app = create_router(
        AppState::with_db(pool.clone(), config())
            .with_assertion_v1(epigraph_api::oauth::assertion::AssertionV1Policy::Refuse),
    );

    let (status, body) =
        post_token(&app, credentials_grant(&client_id, &fresh_assertion(&key))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a v1 assertion minted under refuse: {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");
    assert_eq!(body["error"], "invalid_client", "{body}");
    assert_eq!(v1_accepted_rows(&pool, &client_id).await, 0);

    let (status, body) = post_token(
        &app,
        credentials_grant(&client_id, &v2_assertion_for(&key, ISSUER)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "calibration: v2 mints: {body}");
    let refresh = refresh_token_of(&body);

    let (status, body) = post_token(
        &app,
        refresh_grant(&refresh, &client_id, &fresh_assertion(&key)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a v1 assertion refreshed under refuse: {body}"
    );
    assert_eq!(body["error"], "invalid_client", "{body}");

    let (status, body) = post_token(
        &app,
        refresh_grant(&refresh, &client_id, &v2_assertion_for(&key, ISSUER)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused v1 refresh left the chain usable for v2: {body}"
    );
}
