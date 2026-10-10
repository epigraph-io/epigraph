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
//! * retired link -> 403, like an acting one: the refusal keys on the link
//!   RECORD, because a writer row that predates the retire would otherwise
//!   ride the token onto HTTP (review measured the retire leaving such a row
//!   live). The arm is calibrated by the same agent minting BEFORE the retire,
//!   and by the acting read saying "not acting" for it after, so the refusal is
//!   the record read and not the acting one.
//!
//! The REFRESH grant is covered on its own, because it is the arm where the
//! check's ORDER matters: the old refresh token is burned by rotation, so a
//! check that fails AFTER the burn cost the client its refresh chain.
//!
//! * an agent that is linked AFTER it minted -> its refresh is 403;
//! * the operated-agent check itself FAILS (the link-record read made uncallable)
//!   -> 500, and the SAME refresh token still refreshes once the read is back:
//!   a failure to answer never burns the token.
//!
//! The last two mint arms each get their own test through the same route, each
//! calibrated by the same flow minting for an unlinked agent:
//!
//! * `authorization_code`: a code whose `human` client is linked to an agent
//!   that becomes operated -> 403 naming the operator;
//! * the external-provider grant (`providers::provision::provision_external_user`):
//!   the first grant provisions the identity's client and agent (200); once
//!   that agent is operated, the next grant (the warm path) -> 403.

#[path = "viewer_fixture.rs"]
mod fixture;
mod oauth_providers;

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
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;

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

    // A RETIRED link refuses too. The acting read says "not acting" for a retired
    // link (the PREMISE below), so a refusal keyed on it minted here -- and a
    // writer row that predated the retire (review's measurement) then rode the
    // token onto HTTP. Keyed on the link record, the retired agent is refused
    // whatever its roster holds.
    let retired_key = SigningKey::from_bytes(&[0x43; 32]);
    let (retired, retired_client) = agent_with_active_client(&pool, &retired_key).await;
    let (status, body) = assertion_grant(&pool, &retired_client, &retired_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: the agent mints before it is retired: {body}"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, retired, operator)
        .await
        .expect("retired link");
    drop(conn);
    assert!(
        AgentRepository::operator_actor_pool(&pool, retired)
            .await
            .expect("actor read")
            .is_none(),
        "PREMISE: a retired link is never an acting one"
    );
    let (status, body) = assertion_grant(&pool, &retired_client, &retired_key).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a retired agent minted a token: the refusal keyed on the acting read, which says \
         'not acting' for a retired link: {body}"
    );
    assert!(
        body.to_string().contains(&operator.to_string()),
        "the refusal must name the operator: {body}"
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
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;
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
/// Review's measurement: with the operator read renamed away, the
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

    sqlx::query(
        "ALTER FUNCTION public.epigraph_operator_of_author(uuid) \
         RENAME TO epigraph_operator_of_author_gone",
    )
    .execute(&pool)
    .await
    .expect("make the link-record read uncallable");
    let (status, body) = refresh_grant(&pool, &refresh).await;
    sqlx::query(
        "ALTER FUNCTION public.epigraph_operator_of_author_gone(uuid) \
         RENAME TO epigraph_operator_of_author",
    )
    .execute(&pool)
    .await
    .expect("restore the link-record read");
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "PREMISE: with the link-record read gone the refresh cannot be answered: {body}"
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
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;
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

    // A RETIRED link is refused by the extractor too: its token was minted
    // before the retire, and the acting read says "not acting" for it.
    let retired_key = SigningKey::from_bytes(&[0x47; 32]);
    let (retired, retired_client) = agent_with_active_client(&pool, &retired_key).await;
    let (status, minted) = assertion_grant(&pool, &retired_client, &retired_key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PREMISE: the unlinked agent mints: {minted}"
    );
    let retired_access = minted["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    let app = create_router(AppState::with_db(pool.clone(), config()));
    let (status, body) = read(app.clone(), retired_access.clone()).await;
    assert!(
        body.contains("scoped connection"),
        "CALIBRATION: before the retire the token reaches the handler: {status} {body}"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, retired, operator)
        .await
        .expect("retire the agent after its token was minted");
    drop(conn);
    let (status, body) = read(app, retired_access).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a retired agent's pre-retire token still resolved a viewer: {body}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The two remaining mint arms (stage-2 still_open): `authorization_code` and
// the external-provider provision grant. Each goes through the real
// `/oauth/token` route, each is calibrated by the SAME flow succeeding for an
// unlinked agent, and each refuses only once the agent has an ACTING link.
// ─────────────────────────────────────────────────────────────────────────────

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "a-fixed-pkce-code-verifier-for-the-operated-agent-token-tests-0001";

/// A `human` OAuth client already linked to `agent` (the warm path of
/// `principal_agent_id`), and one fresh authorization code for it. Returns the
/// varchar client id and the raw code.
async fn human_client_with_code(pool: &PgPool, agent: Uuid) -> (String, String) {
    use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
    use sha2::{Digest, Sha256};

    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("operated_code_{unique}");
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id) \
         VALUES ($1, 'operated-code-test', 'human', ARRAY['claims:read'], \
                 ARRAY['claims:read'], 'active', $2) \
         RETURNING id",
    )
    .bind(&client_id)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("human client linked to the agent");
    let code = format!("code_{unique}");
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        Sha256::digest(VERIFIER.as_bytes()),
    );
    AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &client_id,
        row,
        REDIRECT_URI,
        &challenge,
        &["claims:read".to_string()],
        None,
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .expect("authorization code");
    (client_id, code)
}

async fn post_token(state: AppState, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let resp = create_router(state).oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn redeem(pool: &PgPool, client_id: &str, code: &str) -> (StatusCode, Value) {
    post_token(
        AppState::with_db(pool.clone(), config()),
        json!({
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": VERIFIER,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
        }),
    )
    .await
}

/// The AUTHORIZATION_CODE arm refuses a code whose client's agent is operated.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_cannot_redeem_an_authorization_code(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;

    // CALIBRATION: the same flow for an unlinked agent mints.
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    let (client_id, code) = human_client_with_code(&pool, unlinked).await;
    let (status, body) = redeem(&pool, &client_id, &code).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: an unlinked agent's authorization code must redeem, or the refusal below \
         proves nothing: {body}"
    );
    assert!(body.get("access_token").is_some(), "{body}");

    // The operated agent: its client and code exist; then it is linked.
    let (agent, _) = fixture::seed_agent_with_group(&pool, "operated").await;
    let (client_id, code) = human_client_with_code(&pool, agent).await;
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the agent after its code was issued");
    drop(conn);
    let (status, body) = redeem(&pool, &client_id, &code).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operated agent redeemed an authorization code: {body}"
    );
    assert!(
        body.to_string().contains("stdio-only") && body.to_string().contains(&operator.to_string()),
        "the refusal must say why and name the operator: {body}"
    );
}

/// The external-provider PROVISION arm (`providers::provision::provision_external_user`)
/// refuses once the provisioned identity's agent is operated. The first grant
/// provisions the client and its agent (the cold path; a brand-new agent is
/// never operated) and is the calibration; the agent is then linked, and the
/// next grant for the same identity takes the warm path and is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_cannot_mint_through_an_external_provider(pool: PgPool) {
    use epigraph_api::oauth::providers::{
        config::{ProviderConfig, ProviderFlow},
        google::GoogleProvider,
        jwks::JwksCache,
        ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
    };
    use std::sync::Arc;

    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;
    let fx = oauth_providers::fixtures::ProviderFixture::new().await;
    std::env::set_var("OPERATED_AGENT_TOKEN_GOOGLE_CLIENT_ID", "test-audience");
    std::env::set_var("OPERATED_AGENT_TOKEN_GOOGLE_CLIENT_SECRET", "test-secret");
    let cfg = ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: fx.jwks_url.clone(),
        audience: None,
        audience_env: Some("OPERATED_AGENT_TOKEN_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("OPERATED_AGENT_TOKEN_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("OPERATED_AGENT_TOKEN_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some("https://example/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
        allowed_emails: vec![],
        allowed_domains: vec![],
    };
    let provider = Arc::new(GoogleProvider::from_config(&cfg, JwksCache::new()).expect("provider"));
    let mut registry = ProviderRegistry::empty();
    registry
        .register(
            provider.clone() as Arc<dyn ExternalIdentityProvider>,
            Some(provider as Arc<dyn OidcRedirectFlow>),
        )
        .expect("register");
    let registry = Arc::new(registry);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let grant = || {
        json!({
            "grant_type": "google_id_token",
            "assertion": fx.sign(&json!({
                "iss": "https://accounts.google.com",
                "aud": "test-audience",
                "sub": "operated-sub-1",
                "email": "operated@example.com",
                "email_verified": true,
                "name": "operated",
                "iat": now,
                "exp": now + 600,
            })),
        })
    };
    let state = || AppState::with_db(pool.clone(), config()).with_providers(registry.clone());

    // CALIBRATION: the first grant provisions and mints.
    let (status, body) = post_token(state(), grant()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "CALIBRATION: the external grant must provision and mint, or the refusal below proves \
         nothing: {body}"
    );
    let agent: Uuid = sqlx::query_scalar(
        "SELECT agent_id FROM oauth_clients WHERE client_id = 'google:operated-sub-1'",
    )
    .fetch_one(&pool)
    .await
    .expect("PREMISE: the grant provisioned a client linked to an agent");

    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link the provisioned agent");
    drop(conn);
    let (status, body) = post_token(state(), grant()).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operated agent minted through the external-provider arm: {body}"
    );
    assert!(
        body.to_string().contains("stdio-only") && body.to_string().contains(&operator.to_string()),
        "the refusal must say why and name the operator: {body}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Migration 149: the author-binding allowlist binds an OAuth client's agent to
// a human WITHOUT making it operated. Every mint arm keys on the link record
// alone, so an allowlisted client keeps minting and keeps its viewer, and an
// operated agent is still refused whether or not it is allowlisted.
// ─────────────────────────────────────────────────────────────────────────────

/// A `service` OAuth client with a known secret, active, `agent_id` NULL until
/// its first mint (`identity_provisioning.rs`'s fixture). Returns
/// `(row id, client_id, secret)`.
async fn service_client(pool: &PgPool, name: &str) -> (Uuid, String, String) {
    let secret_bytes: [u8; 32] = *blake3::hash(name.as_bytes()).as_bytes();
    let secret = hex::encode(secret_bytes);
    let hash = blake3::hash(&secret_bytes);
    let client_id = format!("epigraph_{}", hex::encode(&secret_bytes[..16]));
    let row: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, client_type, \
                                    allowed_scopes, granted_scopes, status, agent_id, \
                                    legal_entity_name, legal_contact_email) \
         VALUES ($1, $2, $3, 'service', $4, $4, 'active', NULL, $3, 'ops@example.test') \
         RETURNING id",
    )
    .bind(&client_id)
    .bind(hash.as_bytes().as_slice())
    .bind(name)
    .bind(vec!["claims:read".to_string()])
    .fetch_one(pool)
    .await
    .expect("service client");
    (row, client_id, secret)
}

async fn secret_grant(pool: &PgPool, client_id: &str, secret: &str) -> (StatusCode, Value) {
    post_token(
        AppState::with_db(pool.clone(), config()),
        json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        }),
    )
    .await
}

/// The `oauth_clients.id` of the client whose `client_id` is `client_id`.
async fn client_row(pool: &PgPool, client_id: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(pool)
        .await
        .expect("client row")
}

/// The maintenance role allows `client` (row id) for `operator`.
async fn allow(pool: &PgPool, client: Uuid, operator: Uuid) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT * FROM public.epigraph_allow_author_binding_client($1, $2, 'test')")
            .bind(client)
            .bind(operator)
            .execute(&mut *conn)
            .await
            .expect("allow");
        (conn, ())
    })
    .await;
}

async fn binding_of(pool: &PgPool, agent: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT public.epigraph_author_binding($1)")
        .bind(agent)
        .fetch_one(pool)
        .await
        .expect("binding")
}

async fn agent_of_client(pool: &PgPool, client: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT agent_id FROM oauth_clients WHERE id = $1")
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("client agent")
}

/// `GET /api/v1/evidence` with `access`: `(status, body)`. Passing the viewer
/// extractor shows as the handler's own "scoped connection" 500 on this
/// harness (see `a_token_minted_before_the_link_is_refused_by_the_viewer`).
async fn evidence_read(pool: &PgPool, access: &str) -> (StatusCode, String) {
    let resp = create_router(AppState::with_db(pool.clone(), config()))
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
}

fn access_of(what: &str, status: StatusCode, body: &Value) -> String {
    assert_eq!(status, StatusCode::OK, "{what}: the grant mints: {body}");
    body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: an access token: {body}"))
        .to_string()
}

fn assert_viewer(what: &str, (status, body): (StatusCode, String)) {
    assert!(
        status != StatusCode::FORBIDDEN
            && status != StatusCode::UNAUTHORIZED
            && body.contains("scoped connection"),
        "{what}: the token must pass the viewer extractor: {status} {body}"
    );
}

/// An allowlisted client keeps minting on every grant arm (an agent client's
/// Ed25519 assertion, a service client's secret, and the refresh grant) and
/// its token keeps a viewer: the allowlist binds the agent, it does not make
/// it operated.
///
/// Verified to fail: `refuse_operated_agent` refusing a `client_allowlist`
/// agent -> 403 (measured on the assertion arm, which runs first).
#[sqlx::test(migrations = "../../migrations")]
async fn an_allowlisted_client_still_mints_and_keeps_its_viewer(pool: PgPool) {
    let (operator, _) = fixture::seed_human_operator(&pool, "operator").await;

    // (a) agent client, Ed25519 assertion.
    let key = SigningKey::from_bytes(&[0x51; 32]);
    let (agent, client_id) = agent_with_active_client(&pool, &key).await;
    allow(&pool, client_row(&pool, &client_id).await, operator).await;
    assert_eq!(
        binding_of(&pool, agent).await.as_deref(),
        Some("client_allowlist")
    );
    let (status, body) = assertion_grant(&pool, &client_id, &key).await;
    let access = access_of("(a) assertion", status, &body);
    assert_viewer("(a) assertion", evidence_read(&pool, &access).await);

    // (b) service client, client_secret: minted once first (the allowance
    // needs the client's agent, which the first mint provisions).
    let (row, service_id, secret) = service_client(&pool, "allowlisted-service").await;
    let (status, body) = secret_grant(&pool, &service_id, &secret).await;
    access_of("PREMISE: the first service mint", status, &body);
    let service_agent = agent_of_client(&pool, row).await;
    allow(&pool, row, operator).await;
    assert_eq!(
        binding_of(&pool, service_agent).await.as_deref(),
        Some("client_allowlist")
    );
    let (status, body) = secret_grant(&pool, &service_id, &secret).await;
    let access = access_of("(b) client_secret", status, &body);
    assert_viewer("(b) client_secret", evidence_read(&pool, &access).await);

    // (c) the refresh grant, from (b)'s refresh token.
    let refresh = body["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("PREMISE: the service mint issues a refresh token: {body}"))
        .to_string();
    let (status, body) = refresh_grant(&pool, &refresh).await;
    let access = access_of("(c) refresh", status, &body);
    assert_viewer("(c) refresh", evidence_read(&pool, &access).await);
}

/// Plant an `operator_links` row for `agent` past 107/122/149's guards
/// (replica mode skips user triggers), with real ids.
async fn plant_link(pool: &PgPool, agent: Uuid, operator: Uuid, group: Uuid, retired: bool) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .expect("replica");
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id, retired) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(agent)
    .bind(operator)
    .bind(group)
    .bind(retired)
    .execute(&mut *tx)
    .await
    .expect("plant a link");
    tx.commit().await.expect("commit");
}

/// The allowlist never lets an OPERATED agent mint: an allowlisted client
/// whose agent then holds a link (live to another human, or retired to its
/// own operator) is refused on every grant arm, naming the operator, and its
/// binding is the link's, never `client_allowlist`.
///
/// Verified to fail: an allowlist exemption in `refuse_operated_agent` -> 200.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_on_the_allowlist_still_cannot_mint(pool: PgPool) {
    let (operator, operator_group) = fixture::seed_human_operator(&pool, "operator").await;
    let (other, other_group) = fixture::seed_human_operator(&pool, "other").await;

    for (i, (retired, link_to, link_group)) in [
        (false, other, other_group),
        (true, operator, operator_group),
    ]
    .into_iter()
    .enumerate()
    {
        let expected_binding = if retired { None } else { Some("live_link") };
        let what = if retired { "retired" } else { "live" };

        // (a) agent client.
        let seed = u8::try_from(0x61 + i).expect("seed");
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (agent, client_id) = agent_with_active_client(&pool, &key).await;
        allow(&pool, client_row(&pool, &client_id).await, operator).await;
        plant_link(&pool, agent, link_to, link_group, retired).await;
        assert_eq!(
            binding_of(&pool, agent).await.as_deref(),
            expected_binding,
            "{what}"
        );
        let (status, body) = assertion_grant(&pool, &client_id, &key).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "(a) {what}: {body}");
        assert!(
            body.to_string().contains(&link_to.to_string()),
            "(a) {what}: {body}"
        );

        // (b) service client and (c) its refresh token, minted before the link.
        let (row, service_id, secret) =
            service_client(&pool, &format!("operated-allowlisted-{what}")).await;
        let (status, body) = secret_grant(&pool, &service_id, &secret).await;
        access_of("PREMISE: the first service mint", status, &body);
        let refresh = body["refresh_token"]
            .as_str()
            .unwrap_or_else(|| panic!("PREMISE: a refresh token: {body}"))
            .to_string();
        let service_agent = agent_of_client(&pool, row).await;
        allow(&pool, row, operator).await;
        plant_link(&pool, service_agent, link_to, link_group, retired).await;
        assert_eq!(
            binding_of(&pool, service_agent).await.as_deref(),
            expected_binding,
            "{what}"
        );
        let (status, body) = secret_grant(&pool, &service_id, &secret).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "(b) {what}: {body}");
        assert!(
            body.to_string().contains(&link_to.to_string()),
            "(b) {what}: {body}"
        );
        let (status, body) = refresh_grant(&pool, &refresh).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "(c) {what}: {body}");
        assert!(
            body.to_string().contains(&link_to.to_string()),
            "(c) {what}: {body}"
        );
    }
}
