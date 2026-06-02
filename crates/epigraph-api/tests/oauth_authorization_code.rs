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
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
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
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
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
    let (client_id, code) = seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

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
    assert_eq!(claims.scopes, scopes, "token scopes must equal seeded code scopes");
    assert_eq!(body["scope"], "claims:read claims:write");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_wrong_verifier_is_rejected() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, code) = seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    // Identical to happy path except the PKCE verifier is wrong → challenge
    // mismatch → 400. (One factor varied vs the happy path.)
    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, "wrong", &client_id),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_is_single_use() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    let (client_id, code) = seed_client_and_code(&pool, &scopes, Utc::now() + Duration::hours(1), "active").await;

    // First redeem succeeds (consume marks used_at atomically).
    let (status1, body1) = post_form(
        app.clone(),
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;
    assert_eq!(status1, StatusCode::OK, "first redeem must succeed, body: {body1}");

    // Second redeem of the SAME code against the SAME pool/state → already used → 400.
    let (status2, _body2) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;
    assert_eq!(status2, StatusCode::BAD_REQUEST, "reused code must be rejected");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL test DB; run with --ignored"]
async fn db_authorization_code_expired_is_rejected() {
    let scopes = vec!["claims:read".to_string()];
    let (app, pool, _jwt) = db_app().await;
    // expires_at in the past → consume's `expires_at > now()` guard rejects it.
    let (client_id, code) = seed_client_and_code(&pool, &scopes, Utc::now() - Duration::hours(1), "active").await;

    let (status, _body) = post_form(
        app,
        "/oauth/token",
        &token_body(&code, VERIFIER, &client_id),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "expired code must be rejected");
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

    let (status, _body) = post_form(app, "/oauth/token", &token_body(&code, VERIFIER, &client_id)).await;

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

    let (status, _body) =
        post_form(app, "/oauth/token", &token_body_no_client_id(&code, VERIFIER)).await;

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
    assert_eq!(
        body["authorization_servers"][0],
        "https://test.example"
    );
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
        &vec![
            Value::from("claims:read"),
            Value::from("claims:write"),
        ],
        "scopes_supported must be exactly [claims:read, claims:write] — the \
         connector-reachable /mcp scopes; got: {scopes:?}"
    );
}
