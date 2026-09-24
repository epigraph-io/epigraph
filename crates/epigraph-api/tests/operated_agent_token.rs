//! Operated agents are stdio-only, enforced at TOKEN ISSUANCE (migration 107,
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
//!
//! The REFRESH grant is covered on its own, because it is the arm where the
//! check's ORDER matters: the old refresh token is burned by rotation, so a
//! check that fails AFTER the burn cost the client its refresh chain.
//!
//! * an agent that is linked AFTER it minted -> its refresh is 403;
//! * the operated-agent check itself FAILS (the actor read made uncallable)
//!   -> 500, and the SAME refresh token still refreshes once the read is back:
//!   a failure to answer never burns the token.

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

async fn refresh_grant(pool: &PgPool, refresh_token: &str) -> (StatusCode, Value) {
    let app = create_router(AppState::with_db(pool.clone(), config()));
    let body = json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
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

/// Mint by assertion and return the refresh token.
async fn minted_refresh_token(pool: &PgPool, client_id: &str, key: &SigningKey) -> String {
    let (status, body) = assertion_grant(pool, client_id, key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PREMISE: the assertion grant mints: {body}"
    );
    body.get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("PREMISE: the assertion grant issues a refresh token: {body}"))
        .to_string()
}

/// The REFRESH arm refuses an agent linked after it minted (A3 in every grant
/// arm that yields an agent token, not only the assertion).
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_linked_after_minting_cannot_refresh(pool: PgPool) {
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let key = SigningKey::from_bytes(&[0x44; 32]);
    let (agent, client_id) = agent_with_active_client(&pool, &key).await;
    let refresh = minted_refresh_token(&pool, &client_id, &key).await;

    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent after it minted");
    drop(conn);

    let (status, body) = refresh_grant(&pool, &refresh).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operated agent refreshed a token: its writer membership in the operator's group \
         would reach the HTTP surface: {body}"
    );
    assert!(
        body.to_string().contains("stdio-only"),
        "the refusal must say why: {body}"
    );
}

/// A FAILURE of the operated-agent check (not a refusal) leaves the refresh
/// token intact.
///
/// Review's measurement: with `epigraph_operator_actor` renamed away, the
/// refresh returned 500 AFTER rotation had already revoked the token, and once
/// the function was back the same token was 401 "Invalid or expired refresh
/// token": an outage of the read (107 section 6 names a missing EXECUTE grant
/// one) cost every refreshing client its chain, and the loss outlived the
/// outage. The token must be burned only once the refresh is denied or about
/// to mint.
#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_operator_check_does_not_burn_the_refresh_token(pool: PgPool) {
    let key = SigningKey::from_bytes(&[0x45; 32]);
    let (_agent, client_id) = agent_with_active_client(&pool, &key).await;
    let refresh = minted_refresh_token(&pool, &client_id, &key).await;

    sqlx::query("ALTER FUNCTION public.epigraph_operator_actor(uuid) RENAME TO epigraph_operator_actor_gone")
        .execute(&pool)
        .await
        .expect("make the actor read uncallable");
    let (status, body) = refresh_grant(&pool, &refresh).await;
    sqlx::query("ALTER FUNCTION public.epigraph_operator_actor_gone(uuid) RENAME TO epigraph_operator_actor")
        .execute(&pool)
        .await
        .expect("restore the actor read");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "PREMISE: with the actor read gone the refresh cannot be answered: {body}"
    );

    let (status, body) = refresh_grant(&pool, &refresh).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refresh token was BURNED by a refresh that failed to answer: the client lost its \
         refresh chain to an outage of the operator read: {body}"
    );
    assert!(body.get("access_token").is_some(), "{body}");
}

/// A token minted BEFORE the agent was linked carries no HTTP authority after
/// it (stage-2 review: A3 is enforced at MINT, and `ViewerExtractor` resolves
/// the writable set from memberships on every request, so the pre-link token
/// would have carried the operator's group until it expired).
///
/// CALIBRATION: the same token, before the link, gets PAST the extractor on
/// `GET /api/v1/evidence` (a `ViewerExtractor` route) and into the handler.
/// This harness builds `AppState::with_db`, which carries no `ScopedPool`, so
/// the handler itself answers 500 "Failed to acquire a scoped connection"; that
/// handler-specific message is the proof the extractor produced a viewer. The
/// thing under test is the extractor, which runs before any handler code.
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_minted_before_the_link_is_refused_by_the_viewer(pool: PgPool) {
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let key = SigningKey::from_bytes(&[0x46; 32]);
    let (agent, client_id) = agent_with_active_client(&pool, &key).await;
    let app = create_router(AppState::with_db(pool.clone(), config()));

    let mint = json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion(&key),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(mint.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "PREMISE: the unlinked agent mints"
    );
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let minted: Value = serde_json::from_slice(&bytes).expect("json");
    let access = minted["access_token"]
        .as_str()
        .expect("access token")
        .to_string();

    let read = |app: axum::Router, access: String| async move {
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/evidence")
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    };

    let (status, body) = read(app.clone(), access.clone()).await;
    assert!(
        status != StatusCode::FORBIDDEN
            && status != StatusCode::UNAUTHORIZED
            && body.contains("scoped connection"),
        "CALIBRATION: before the link the token must pass the extractor and reach the handler, \
         or the refusal below proves nothing: {status} {body}"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent after its token was minted");
    drop(conn);

    let (status, body) = read(app, access).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token minted before the link still resolved a viewer: its writable set now carries \
         the operator's group on the HTTP surface: {body}"
    );
    assert!(
        body.contains("stdio-only"),
        "the refusal must say why: {body}"
    );
}
