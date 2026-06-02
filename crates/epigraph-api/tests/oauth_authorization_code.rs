use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

use epigraph_api::oauth::providers::ProviderRegistry;
use epigraph_api::{create_router, ApiConfig, AppState};

// Shared RSA/JWKS provider fixture (also used by oauth_redirect_flow.rs). We only
// need build_auth_url here (no network I/O), so a real GoogleProvider registered
// against a wiremock JWKS is the lightest way to make `redirect_flow("google")`
// resolve in the authorize handler without mocking the registry.
mod oauth_providers;

fn config() -> ApiConfig {
    ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
    }
}

fn app() -> axum::Router {
    if std::env::var("DATABASE_URL").is_err() {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://test_dummy:test_dummy@localhost/test_dummy",
        );
    }
    let state = AppState::new(config()).with_providers(Arc::new(ProviderRegistry::default()));
    create_router(state)
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn post_form(app: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
    use axum::http::header;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ── DB-backed authorization_code redeem tests ────────────────────────────────
//
// These run against a real Postgres test DB (migrations 001-049 applied,
// oauth_authorization_codes + oauth_clients present) and are #[ignore]'d so the
// default `cargo test` (which has no DB) stays green. Run them with:
//   DATABASE_URL=postgres://epigraph:epigraph@localhost:5432/epigraph_mcp_oauth_test \
//   cargo test -p epigraph-api --test oauth_authorization_code -- --ignored
//
// Each test seeds its own active 'human' oauth_client and a single authorization
// code with a UNIQUE client_id + raw code (UUID-suffixed) so concurrent runs and
// reruns never collide.

use base64::Engine as _;
use chrono::{Duration, Utc};
use epigraph_api::oauth::JwtConfig;
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "this-is-a-fixed-pkce-code-verifier-of-adequate-length-123456";

/// PKCE S256 challenge = base64url-no-pad(SHA256(verifier)) — must match the
/// computation the handler performs over the stored code_challenge.
fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Build the app with a REAL pool and capture the issuer's jwt_config so token
/// validation cannot drift from the secret the issuing AppState actually used.
async fn db_app() -> (axum::Router, PgPool, Arc<JwtConfig>) {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let state = AppState::with_db(pool.clone(), config())
        .with_providers(Arc::new(ProviderRegistry::default()));
    let jwt = state.jwt_config.clone();
    let app = create_router(state);
    (app, pool, jwt)
}

/// Seed a 'human' oauth_client with the given status and a fresh single-use
/// authorization code. Returns (varchar client_id used at /authorize, raw code).
/// `expires_at` lets callers seed an already-expired code for the expiry test;
/// `status` lets callers seed a non-active client for the status-gate test.
async fn seed_client_and_code(
    pool: &PgPool,
    scopes: &[String],
    expires_at: chrono::DateTime<Utc>,
    status: &str,
) -> (String, String) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("epigraph_test_{unique}");
    // Seed the client's granted_scopes as a STRICT SUPERSET of the code's scopes
    // (extra: evidence:read). handle_authorization_code mints the token from
    // row.scopes (the CODE), NOT the client's granted_scopes — unlike
    // client_credentials, which intersects. The happy-path assertion (token
    // scopes == code scopes) therefore isolates that property: a regression that
    // switched to client-granted scopes would surface the extra scope and fail.
    let mut client_scopes: Vec<String> = scopes.to_vec();
    if !client_scopes.iter().any(|s| s == "evidence:read") {
        client_scopes.push("evidence:read".to_string());
    }
    let oauth_client_uuid = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "Claude Connector Test",
        "human",
        &client_scopes, // allowed_scopes (superset)
        &client_scopes, // granted_scopes (superset — must NOT leak into the token)
        status,
        None,
        // owner_id: NULL. It is a self-FK to oauth_clients(id) (a random UUID
        // would violate oauth_clients_owner_id_fkey), and the agents_must_have_owner
        // CHECK only requires it for client_type='agent'. The token claims carry
        // owner_id through verbatim, so a 'human' client with NULL owner is valid here.
        None,
        None,
        None,
        None, // redirect_uris (irrelevant to the token redeem path)
    )
    .await
    .expect("seed oauth_client");

    let code_raw = format!("code_{unique}");
    let challenge = pkce_challenge(VERIFIER);
    AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code_raw.as_bytes()).as_bytes(),
        &client_id,
        oauth_client_uuid,
        REDIRECT_URI,
        &challenge,
        scopes,
        None,
        expires_at,
    )
    .await
    .expect("seed authorization_code");

    (client_id, code_raw)
}

fn token_body(grant_code: &str, verifier: &str, client_id: &str) -> String {
    format!(
        r#"{{"grant_type":"authorization_code","code":"{grant_code}","code_verifier":"{verifier}","redirect_uri":"{REDIRECT_URI}","client_id":"{client_id}"}}"#
    )
}

/// Same as `token_body` but OMITS `client_id` entirely — used to prove the
/// client-binding check is unconditional (RFC 9700 §4.1.3: client_id validation
/// in the authorization_code grant is a MUST).
fn token_body_no_client_id(grant_code: &str, verifier: &str) -> String {
    format!(
        r#"{{"grant_type":"authorization_code","code":"{grant_code}","code_verifier":"{verifier}","redirect_uri":"{REDIRECT_URI}"}}"#
    )
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_happy_path_issues_valid_jwt() {
    let scopes = vec!["claims:read".to_string(), "claims:write".to_string()];
    let (app, pool, jwt) = db_app().await;
    let (client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    let (status, body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "expected 200, body: {body}");
    let access_token = body["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token in {body}"));

    // The issued token must validate under the SAME jwt_config the AppState used,
    // carry aud=epigraph-api, and carry exactly the scopes seeded into the CODE
    // (handle_authorization_code uses row.scopes directly — no granted-scope
    // intersection, unlike client_credentials).
    let claims = jwt
        .validate_token(access_token)
        .expect("issued token must validate");
    assert_eq!(claims.aud, "epigraph-api");
    assert_eq!(
        claims.scopes, scopes,
        "token scopes must equal seeded code scopes"
    );
    assert_eq!(body["scope"], "claims:read claims:write");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_wrong_verifier_is_rejected() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    // Identical to happy path except the PKCE verifier is wrong → challenge
    // mismatch → 400. (One factor varied vs the happy path.)
    let (status, _body) =
        post_form(app, "/oauth/token", &token_body(&code, "wrong", &client_id)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_is_single_use() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    // First redeem succeeds (consume marks used_at atomically).
    let (status1, body1) = post_form(
        app.clone(),
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "first redeem must succeed, body: {body1}"
    );

    // Second redeem of the SAME code against the SAME pool/state → already used → 400.
    let (status2, _body2) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "reused code must be rejected"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_expired_is_rejected() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    // expires_at in the past → consume's `expires_at > now()` guard rejects it.
    let (client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() - Duration::hours(1), "active").await;

    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expired code must be rejected"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_suspended_client_is_forbidden() {
    // A valid, unexpired code with the correct PKCE verifier + redirect_uri +
    // client_id — the ONLY varied factor vs the happy path is that the per-user
    // oauth_client is 'suspended', not 'active'. Without the status gate the
    // handler would mint a fresh 1h access token + 30d refresh token for a
    // suspended client (a 30-day blast radius). With the gate it must 403, like
    // the sibling client_credentials/refresh_token handlers.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "suspended").await;

    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "suspended client must not redeem a valid code"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_omitted_client_id_is_rejected() {
    // Identical to the happy path in EVERY factor except one: the token request
    // OMITS `client_id`. The code is valid + unexpired, the PKCE verifier is
    // correct, the redirect_uri matches, and the client is 'active' — so the ONLY
    // thing that can drive a rejection is an unconditional client-binding check.
    //
    // Before the fix: `if let Some(cid) = req.client_id` skips the binding check
    // entirely when client_id is absent, so this redeems to a 200 token (a code
    // captured/replayed for the legitimate Claude client could be redeemed by any
    // caller that simply leaves client_id out). RFC 9700 §4.1.3 makes client_id
    // validation in the authorization_code grant a MUST → this must be 4xx.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (_client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body_no_client_id(&code, VERIFIER),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a token request that omits client_id must be rejected (RFC 9700 §4.1.3)"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_wrong_client_id_is_rejected() {
    // Regression coverage for the cross-client binding path: a code minted for
    // client A is redeemed with a present-but-wrong client_id (B). This path was
    // already rejected (the `if let Some(cid)` mismatch branch), so it is NOT the
    // RED→GREEN driver for the unconditional-binding fix — it guards against a
    // future regression that weakens the value-vs-row comparison. One factor
    // varied vs the happy path: client_id is wrong.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (_client_id, code) =
        seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, "epigraph_test_some_other_client"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a code minted for one client must not be redeemed with a different client_id"
    );
}

#[tokio::test]
async fn authorization_code_missing_code_is_invalid_request() {
    let (status, _body) = post_form(
        app(),
        "/oauth/token",
        r#"{"grant_type":"authorization_code","code_verifier":"x","redirect_uri":"https://claude.ai/api/mcp/auth_callback"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorization_server_metadata_has_required_fields() {
    let (status, body) = get_json(app(), "/.well-known/oauth-authorization-server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["issuer"], "https://test.example");
    assert_eq!(
        body["authorization_endpoint"],
        "https://test.example/oauth/authorize"
    );
    assert_eq!(body["token_endpoint"], "https://test.example/oauth/token");
    assert_eq!(
        body["registration_endpoint"],
        "https://test.example/oauth/register"
    );
    assert_eq!(body["response_types_supported"][0], "code");
    assert!(body["grant_types_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "authorization_code"));
    assert_eq!(body["code_challenge_methods_supported"][0], "S256");
}

#[tokio::test]
async fn protected_resource_metadata_points_at_this_as() {
    let (status, body) = get_json(app(), "/.well-known/oauth-protected-resource").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resource"], "https://test.example/mcp");
    assert_eq!(body["authorization_servers"][0], "https://test.example");
    // scopes_supported MUST advertise only the scopes a connector authorizing
    // through THIS AS can actually obtain AND use against /mcp. epigraph-mcp's
    // SCOPE_MAP codomain is {claims:read, claims:write, claims:admin}, but
    // claims:admin is unreachable here: no register.rs grant path (agent/service/
    // human) hands it out — it is provisioned only to the separate epigraph-admin
    // client out-of-band. Advertising it would (a) be a scope this AS's clients
    // can never get, and (b) break RFC 8414/9728 subset coherence (the AS doc's
    // scopes_supported omits claims:admin). So the resource doc must list exactly
    // the connector-reachable /mcp scopes: claims:read + claims:write. It must
    // NOT advertise claims:admin (unreachable) or analysis:belief (no MCP tool
    // requires it, not in SCOPE_MAP codomain).
    let scopes = body["scopes_supported"].as_array().unwrap();
    assert_eq!(
        scopes,
        &vec![Value::from("claims:read"), Value::from("claims:write"),],
        "scopes_supported must be exactly [claims:read, claims:write] — the \
         connector-reachable /mcp scopes; got: {scopes:?}"
    );
}

// ── /oauth/authorize entry-point (DB-free) ───────────────────────────────────
//
// PKCE is MANDATORY on the authorization endpoint (OAuth 2.1 / RFC 9700). The
// handler must reject a request that omits `code_challenge` BEFORE any DB
// round-trip, so this test runs against the dummy-pool `app()` with no DB.
#[tokio::test]
async fn authorize_without_pkce_is_rejected() {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/oauth/authorize?response_type=code&client_id=epigraph_x&redirect_uri=https://claude.ai/api/mcp/auth_callback&state=abc")
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── DB-seeded authorize → consent → mint → redeem integration tests ──────────
//
// These exercise the handlers from commit 5f02e3c against the real test DB
// (oauth_authorize_sessions + oauth_authorization_codes + oauth_clients), with
// Google's network legs avoided rather than mocked:
//   * /authorize only needs build_auth_url (pure string), so a real GoogleProvider
//     registered against a wiremock JWKS suffices.
//   * /authorize/consent reads the user + scopes from the server-side session row
//     (recorded by the Google callback) and never touches Google, so we seed an
//     ALREADY-transitioned session via the repo and drive consent directly. This
//     proves authorize→consent→mint→redeem end to end WITHOUT mocking the Google
//     callback (the callback leg is covered by manual E2E — see Task 10).
use epigraph_api::oauth::providers::config::{ProviderConfig, ProviderFlow};
use epigraph_api::oauth::providers::google::GoogleProvider;
use epigraph_api::oauth::providers::jwks::JwksCache;
use epigraph_db::repos::authorize_session::AuthorizeSessionRepository;
use oauth_providers::fixtures::ProviderFixture;

const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// A real GoogleProvider config pointed at the fixture's wiremock JWKS. Only
/// build_auth_url is exercised by /authorize (no network I/O), so the JWKS/token
/// endpoints are never hit. Mirrors the helper in oauth_redirect_flow.rs.
fn google_cfg(jwks_url: &str) -> ProviderConfig {
    std::env::set_var("AC_GOOGLE_CLIENT_ID", "test-google-audience");
    std::env::set_var("AC_GOOGLE_CLIENT_SECRET", "test-google-secret");
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec!["accounts.google.com".into()],
        jwks_url: jwks_url.into(),
        audience: None,
        audience_env: Some("AC_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("AC_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("AC_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some(GOOGLE_AUTH_ENDPOINT.into()),
        token_endpoint: Some("https://oauth2.googleapis.com/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
    }
}

/// db_app variant whose ProviderRegistry has a real 'google' redirect provider, so
/// the authorize handler's `redirect_flow("google")` resolves. Returns the fixture
/// too (its wiremock server must outlive the app).
async fn db_app_with_google() -> (axum::Router, PgPool, ProviderFixture) {
    let fx = ProviderFixture::new().await;
    let provider = Arc::new(
        GoogleProvider::from_config(&google_cfg(&fx.jwks_url), JwksCache::new())
            .expect("build GoogleProvider"),
    );
    let mut registry = ProviderRegistry::empty();
    registry
        .register(
            provider.clone() as Arc<dyn epigraph_api::oauth::providers::ExternalIdentityProvider>,
            Some(provider as Arc<dyn epigraph_api::oauth::providers::OidcRedirectFlow>),
        )
        .expect("register google");
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let state = AppState::with_db(pool.clone(), config()).with_providers(Arc::new(registry));
    let app = create_router(state);
    (app, pool, fx)
}

/// Seed an active 'human' oauth_client (returns its varchar client_id + UUID).
async fn seed_active_human_client(pool: &PgPool, scopes: &[String]) -> (String, Uuid) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("epigraph_test_{unique}");
    let uuid = OAuthClientRepository::create(
        pool,
        &client_id,
        None, // client_secret_hash
        "Claude Connector Consent Test",
        "human",
        scopes, // allowed_scopes
        scopes, // granted_scopes
        "active",
        None, // agent_id
        None, // owner_id (self-FK; NULL is valid for 'human')
        None, // legal_entity_name
        None, // legal_contact_email
        None, // redirect_uris (this helper's callers seed the column via SQL UPDATE)
    )
    .await
    .expect("seed oauth_client");
    (client_id, uuid)
}

/// GET that returns (status, Location header) — for redirect assertions.
async fn get_redirect(app: axum::Router, uri: &str) -> (StatusCode, Option<String>) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let loc = resp
        .headers()
        .get(axum::http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (status, loc)
}

/// POST application/x-www-form-urlencoded (the consent endpoint uses axum Form,
/// NOT JSON) and return (status, Location header).
async fn post_consent(app: axum::Router, body: &str) -> (StatusCode, Option<String>) {
    use axum::http::header;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize/consent")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    (status, loc)
}

/// Seed an authorize session ALREADY transitioned to consent: create() it keyed by
/// a throwaway Google-CSRF state, then transition_to_consent() to bind the resolved
/// user + granted scopes under a fresh unique consent nonce — exactly the row state
/// the Google callback leaves behind, but without invoking Google. Returns the
/// consent ticket (nonce). The session carries the claude redirect_uri, the PKCE
/// challenge over VERIFIER, and a known claude_state to round-trip.
async fn seed_consent_session(
    pool: &PgPool,
    client_id: &str,
    resolved_user: Uuid,
    granted_scopes: &[String],
    claude_state: &str,
) -> String {
    let unique = Uuid::new_v4().simple().to_string();
    let google_state = format!("gstate_{unique}");
    let consent_nonce = format!("consent_{unique}");
    AuthorizeSessionRepository::create(
        pool,
        &google_state,
        client_id,
        REDIRECT_URI,
        &pkce_challenge(VERIFIER),
        Some("claims:read"),
        Some(claude_state),
        "google-verifier-unused-here",
        Utc::now() + Duration::minutes(10),
    )
    .await
    .expect("seed authorize session");
    AuthorizeSessionRepository::transition_to_consent(
        pool,
        &google_state,
        &consent_nonce,
        resolved_user,
        granted_scopes,
    )
    .await
    .expect("transition session to consent")
    .expect("transition returns the rotated row");
    consent_nonce
}

/// Pull the `code` and `state` query params out of a redirect Location.
fn parse_redirect_params(loc: &str) -> std::collections::HashMap<String, String> {
    let q = loc.split_once('?').map(|(_, q)| q).unwrap_or("");
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn authorize_redirects_to_google() {
    // An active client whose redirect_uris contains exactly the claude callback.
    let (app, pool, _fx) = db_app_with_google().await;
    let scopes = vec!["claims:read".to_string()];
    let (client_id, _uuid) = seed_active_human_client(&pool, &scopes).await;
    // seed_active_human_client passes None for redirect_uris, so seed the column
    // directly here: the authorize handler validates the request's redirect_uri
    // against client.redirect_uris, which must contain the exact claude callback.
    // (The DCR path in register.rs now persists redirect_uris via create's new
    // parameter; this helper keeps the SQL UPDATE to stay independent of it.)
    sqlx::query("UPDATE oauth_clients SET redirect_uris = $2 WHERE client_id = $1")
        .bind(&client_id)
        .bind(&[REDIRECT_URI.to_string()][..])
        .execute(&pool)
        .await
        .expect("seed redirect_uris");

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={REDIRECT_URI}&code_challenge={}&code_challenge_method=S256&state=abc",
        pkce_challenge(VERIFIER)
    );
    let (status, loc) = get_redirect(app, &uri).await;

    assert!(
        status == StatusCode::SEE_OTHER || status == StatusCode::FOUND,
        "expected 303/302, got {status}"
    );
    let loc = loc.expect("redirect must carry a Location header");
    assert!(
        loc.starts_with(GOOGLE_AUTH_ENDPOINT),
        "Location must be the Google authorize URL, got: {loc}"
    );

    // A pending authorize session row must now exist for this client. The handler
    // keys it by a server-generated Google-CSRF state we don't see, so assert by
    // client_id (UUID-unique to this test, so the count is exactly 1).
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_authorize_sessions WHERE client_id = $1")
            .bind(&client_id)
            .fetch_one(&pool)
            .await
            .expect("count sessions");
    assert_eq!(
        count, 1,
        "authorize must persist exactly one pending session"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn consent_allow_mints_redeemable_code() {
    // End-to-end without Google: seed an active human client + an already-consented
    // session, POST Allow, follow the redirect's code, then redeem it at /oauth/token.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, jwt) = db_app().await;
    let (client_id, client_uuid) = seed_active_human_client(&pool, &scopes).await;
    let claude_state = "claude-roundtrip-state-xyz";
    let ticket = seed_consent_session(&pool, &client_id, client_uuid, &scopes, claude_state).await;

    let (status, loc) = post_consent(app.clone(), &format!("ticket={ticket}&decision=allow")).await;
    // axum's Redirect::to emits 303 See Other (the correct POST→GET redirect).
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "Allow must 303-redirect to the client redirect_uri"
    );
    let loc = loc.expect("Allow must carry a Location header");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "redirect must target the claude callback, got: {loc}"
    );
    let params = parse_redirect_params(&loc);
    let code = params.get("code").expect("redirect must carry a code");
    assert_eq!(
        params.get("state").map(String::as_str),
        Some(claude_state),
        "client's original state must round-trip"
    );

    // The minted code must be looked up under blake3(code_bytes) — the SAME hash the
    // redeem path computes. (This is what binds mint and redeem; a mismatch here is
    // a code that can never be redeemed.)
    let code_hash = blake3::hash(code.as_bytes());
    let row_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oauth_authorization_codes WHERE code_hash = $1)",
    )
    .bind(code_hash.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .expect("query code row");
    assert!(
        row_exists,
        "an authorization_code row must exist for blake3(code)"
    );

    // Redeem end-to-end: matching verifier + redirect_uri + client_id → 200 + JWT.
    let (rstatus, rbody) =
        post_form(app, "/oauth/token", &token_body(code, VERIFIER, &client_id)).await;
    assert_eq!(
        rstatus,
        StatusCode::OK,
        "redeem must succeed, body: {rbody}"
    );
    let access_token = rbody["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no access_token in {rbody}"));
    let claims = jwt
        .validate_token(access_token)
        .expect("issued token must validate");
    assert_eq!(claims.aud, "epigraph-api");
    assert_eq!(
        claims.scopes, scopes,
        "token scopes must equal the session's granted scopes"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn consent_deny_redirects_with_error() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, client_uuid) = seed_active_human_client(&pool, &scopes).await;
    let ticket = seed_consent_session(&pool, &client_id, client_uuid, &scopes, "deny-state").await;

    let (status, loc) = post_consent(app, &format!("ticket={ticket}&decision=deny")).await;

    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "Deny must 303-redirect back to the client"
    );
    let loc = loc.expect("Deny must carry a Location header");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "deny redirect must target the claude callback, got: {loc}"
    );
    let params = parse_redirect_params(&loc);
    assert_eq!(
        params.get("error").map(String::as_str),
        Some("access_denied"),
        "deny must carry error=access_denied, got: {loc}"
    );
    assert!(
        !params.contains_key("code"),
        "deny must NOT mint a code, got: {loc}"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn consent_control_byte_state_does_not_panic() {
    // Regression for the panic-on-attacker-input finding: axum's Query extractor
    // percent-DECODES the OAuth `state` before it lands in `claude_state`, so a client
    // that began /oauth/authorize with `state=%0A` makes the stored value a literal
    // control byte. The old `format!` + `Redirect::to` path fed that raw byte to
    // `HeaderValue::try_from`, whose `.expect()` PANICS. Seed the decoded value
    // directly (it is the exact row state the authorize step would leave) and assert a
    // clean 303 whose Location percent-encodes the byte instead of panicking.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, client_uuid) = seed_active_human_client(&pool, &scopes).await;
    // A literal newline (0x0A) — the post-percent-decode value of `state=%0A`.
    let evil_state = "before\nafter";
    let ticket = seed_consent_session(&pool, &client_id, client_uuid, &scopes, evil_state).await;

    // Deny path (does not mint a code, isolating the redirect construction).
    let (status, loc) = post_consent(app, &format!("ticket={ticket}&decision=deny")).await;

    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "control-byte state must produce a clean redirect, not a panic"
    );
    let loc = loc.expect("redirect must carry a Location header");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "redirect must still target the claude callback, got: {loc}"
    );
    // The byte must be percent-encoded in the Location (a valid header value), never
    // emitted raw. `%0A` is the encoding of the newline.
    assert!(
        loc.contains("state=before%0Aafter"),
        "control byte must be percent-encoded in the redirect, got: {loc}"
    );
    assert!(
        !loc.contains('\n'),
        "Location must not contain a raw control byte, got: {loc:?}"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn consent_ticket_is_single_use() {
    // take() deletes the session row, so a replayed ticket cannot mint a second code.
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, client_uuid) = seed_active_human_client(&pool, &scopes).await;
    let ticket =
        seed_consent_session(&pool, &client_id, client_uuid, &scopes, "single-use-state").await;

    let (status1, _loc1) =
        post_consent(app.clone(), &format!("ticket={ticket}&decision=allow")).await;
    assert_eq!(status1, StatusCode::SEE_OTHER, "first Allow must succeed");

    let (status2, _loc2) = post_consent(app, &format!("ticket={ticket}&decision=allow")).await;
    assert!(
        status2.is_client_error(),
        "a replayed consent ticket must be rejected (4xx), got {status2}"
    );
}

// ── RFC 7591 dynamic client registration (Task 9) ────────────────────────────

/// POST a JSON body to `uri` and return (status, parsed JSON body).
async fn post_json2(app: axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, Value) {
    use axum::http::header;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --include-ignored"]
async fn dcr_registration_returns_client_id_and_locks_redirect() {
    // A claude.ai-shaped DCR request (redirect_uris + response_types=[code], no
    // client_type) must create an ACTIVE public client and echo back the locked
    // redirect_uri verbatim per RFC 7591.
    let (app, _pool, _jwt) = db_app().await;
    let (status, body) = post_json2(
        app,
        "/oauth/register",
        serde_json::json!({
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "DCR must return 201, got {status}"
    );
    assert!(
        body["client_id"]
            .as_str()
            .expect("client_id present")
            .starts_with("epigraph_"),
        "client_id must be a generated epigraph_ id, got: {:?}",
        body["client_id"]
    );
    assert_eq!(
        body["redirect_uris"][0], "https://claude.ai/api/mcp/auth_callback",
        "the locked redirect_uri must be echoed back, got: {:?}",
        body["redirect_uris"]
    );
}

#[tokio::test]
async fn dcr_rejects_non_claude_redirect_host() {
    // A DCR carrying a redirect_uri whose host is NOT claude.ai/claude.com must be
    // rejected with 400 BEFORE any DB access (the host allowlist runs first), so this
    // runs DB-free under the dummy-DB `app()` like authorization_code_missing_code.
    let (status, _body) = post_json2(
        app(),
        "/oauth/register",
        serde_json::json!({
            "client_name": "Evil",
            "redirect_uris": ["https://evil.example/api/mcp/auth_callback"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-claude redirect host must be rejected with 400, got {status}"
    );
}
