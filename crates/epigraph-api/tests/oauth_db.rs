//! DB-touching integration tests for the OAuth provider routes.
//!
//! These use `#[sqlx::test(migrations = "../../migrations")]` which spins up
//! a fresh per-test database — they require a live Postgres reachable via
//! `DATABASE_URL` and are skipped otherwise.

mod oauth_providers;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};

use oauth_providers::fixtures::ProviderFixture;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config() -> ApiConfig {
    ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    }
}

fn google_cfg(jwks_url: &str, auto_provision: bool, env_suffix: &str) -> ProviderConfig {
    let cid_var = format!("DB_TEST_GOOGLE_CLIENT_ID_{env_suffix}");
    let sec_var = format!("DB_TEST_GOOGLE_CLIENT_SECRET_{env_suffix}");
    std::env::set_var(&cid_var, "test-audience");
    std::env::set_var(&sec_var, "test-secret");
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: jwks_url.into(),
        audience: None,
        audience_env: Some(cid_var.clone()),
        client_id_env: Some(cid_var),
        client_secret_env: Some(sec_var),
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some("https://example/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision,
        default_scopes: vec!["claims:read".into(), "claims:write".into()],
    }
}

fn registry_with_google(provider: GoogleProvider) -> Arc<ProviderRegistry> {
    let mut r = ProviderRegistry::empty();
    let arc = Arc::new(provider);
    r.register(
        arc.clone() as Arc<dyn ExternalIdentityProvider>,
        Some(arc as Arc<dyn OidcRedirectFlow>),
    )
    .unwrap();
    Arc::new(r)
}

async fn post_json(app: axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn signed_jwt(fx: &ProviderFixture, sub: &str, email: &str) -> String {
    fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": sub,
        "email": email,
        "email_verified": true,
        "name": email,
        "iat": now(),
        "exp": now() + 600,
    }))
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_time_provisioning_creates_oauth_client(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, true, "PROVISION_OK"),
        JwksCache::new(),
    )
    .unwrap();
    let registry = registry_with_google(provider);
    let state = AppState::with_db(pool.clone(), config()).with_providers(registry);
    let app = create_router(state);

    let jwt = signed_jwt(&fx, "11223344", "alice@example.com");
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({"grant_type": "google_id_token", "assertion": jwt, "scope": "claims:read claims:write"}),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("access_token").is_some(),
        "expected access_token in body, got {body}"
    );
    assert_eq!(
        body.get("token_type").and_then(|v| v.as_str()),
        Some("Bearer")
    );

    // Verify the oauth_clients row.
    let row: (String, String, String, Vec<String>) = sqlx::query_as(
        "SELECT client_id, status, client_type, granted_scopes FROM oauth_clients WHERE client_id = $1",
    )
    .bind("google:11223344")
    .fetch_one(&pool)
    .await
    .expect("oauth_clients row should exist");

    assert_eq!(row.0, "google:11223344");
    assert_eq!(row.1, "active");
    assert_eq!(row.2, "human");
    assert!(row.3.contains(&"claims:read".to_string()));
    assert!(row.3.contains(&"claims:write".to_string()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn second_provisioning_is_idempotent(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, true, "IDEMPOTENT"),
        JwksCache::new(),
    )
    .unwrap();
    let registry = registry_with_google(provider);

    // First call.
    let state = AppState::with_db(pool.clone(), config()).with_providers(registry.clone());
    let app1 = create_router(state);
    let jwt1 = signed_jwt(&fx, "55667788", "bob@example.com");
    let (s1, _b1) = post_json(
        app1,
        "/oauth/token",
        json!({"grant_type": "google_id_token", "assertion": jwt1}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Second call (fresh JWT to avoid replay-cache hits, same sub).
    let state2 = AppState::with_db(pool.clone(), config()).with_providers(registry);
    let app2 = create_router(state2);
    let jwt2 = signed_jwt(&fx, "55667788", "bob@example.com");
    let (s2, _b2) = post_json(
        app2,
        "/oauth/token",
        json!({"grant_type": "google_id_token", "assertion": jwt2}),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // Exactly one row.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1")
        .bind("google:55667788")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count.0, 1,
        "second provisioning must not create a duplicate row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn auto_provision_disabled_returns_403(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, false, "AUTO_OFF"),
        JwksCache::new(),
    )
    .unwrap();
    let registry = registry_with_google(provider);
    let state = AppState::with_db(pool.clone(), config()).with_providers(registry);
    let app = create_router(state);

    let jwt = signed_jwt(&fx, "99000099", "carol@example.com");
    let (status, body) = post_json(
        app,
        "/oauth/token",
        json!({"grant_type": "google_id_token", "assertion": jwt}),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body: {body}");

    // No row should have been created.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM oauth_clients WHERE client_id = $1")
        .bind("google:99000099")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count.0, 0,
        "no oauth_clients row should be created when auto_provision=false"
    );
}
