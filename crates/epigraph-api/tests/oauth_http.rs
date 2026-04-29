//! HTTP-level integration tests for the OAuth provider routes.
//!
//! These tests exercise the router → registry → handler dispatch without
//! touching the database. They run against `AppState::new(config)` which uses
//! `connect_lazy` for the DB pool — DB queries are never issued because the
//! 4xx response is returned before any handler reaches a repository call.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

use epigraph_api::oauth::providers::{
    cloudflare_access::CloudflareAccessProvider, config::ProviderConfig, config::ProviderFlow,
    google::GoogleProvider, jwks::JwksCache, ExternalIdentityProvider, OidcRedirectFlow,
    ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};

fn ensure_database_url_for_lazy_pool() {
    if std::env::var("DATABASE_URL").is_err() {
        std::env::set_var(
            "DATABASE_URL",
            "postgres://test_dummy:test_dummy@localhost/test_dummy",
        );
    }
}

fn config() -> ApiConfig {
    ApiConfig {
        require_signatures: false,
        max_request_size: 1024 * 1024,
    }
}

fn google_cfg() -> ProviderConfig {
    std::env::set_var("HTTP_TEST_GOOGLE_CLIENT_ID", "test-aud");
    std::env::set_var("HTTP_TEST_GOOGLE_CLIENT_SECRET", "test-secret");
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: "https://example/jwks".into(),
        audience: None,
        audience_env: Some("HTTP_TEST_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("HTTP_TEST_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("HTTP_TEST_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some("https://example/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec![],
    }
}

fn cf_cfg() -> ProviderConfig {
    ProviderConfig {
        name: "cloudflare-access".into(),
        flow: ProviderFlow::Assertion,
        grant_type: "cloudflare_access_jwt".into(),
        issuer: "https://team.cloudflareaccess.com".into(),
        extra_issuers: vec![],
        jwks_url: "https://example/cf-jwks".into(),
        audience: Some("cf-aud".into()),
        audience_env: None,
        client_id_env: None,
        client_secret_env: None,
        auth_endpoint: None,
        token_endpoint: None,
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec![],
    }
}

fn registry_with(google: bool, cf: bool) -> Arc<ProviderRegistry> {
    let mut r = ProviderRegistry::empty();
    let jwks = JwksCache::new();
    if google {
        let g = GoogleProvider::from_config(&google_cfg(), jwks.clone()).unwrap();
        let arc = Arc::new(g);
        r.register(
            arc.clone() as Arc<dyn ExternalIdentityProvider>,
            Some(arc as Arc<dyn OidcRedirectFlow>),
        )
        .unwrap();
    }
    if cf {
        let c = CloudflareAccessProvider::from_config(&cf_cfg(), jwks).unwrap();
        r.register(Arc::new(c) as Arc<dyn ExternalIdentityProvider>, None)
            .unwrap();
    }
    Arc::new(r)
}

fn app(registry: Arc<ProviderRegistry>) -> axum::Router {
    ensure_database_url_for_lazy_pool();
    let state = AppState::new(config()).with_providers(registry);
    create_router(state)
}

async fn post_json(app: axum::Router, uri: &str, body: serde_json::Value) -> (StatusCode, Value) {
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

// ── /oauth/token tests ───────────────────────────────────────────────────

#[tokio::test]
async fn unknown_grant_type_returns_400() {
    let app = app(registry_with(true, false));
    let (status, body) = post_json(
        app,
        "/oauth/token",
        serde_json::json!({"grant_type": "totally_made_up_grant"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let msg = body
        .get("details")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("Unsupported grant_type"),
        "expected unsupported_grant_type message, got body: {body}"
    );
}

#[tokio::test]
async fn external_grant_with_no_assertion_returns_400() {
    let app = app(registry_with(true, false));
    let (status, body) = post_json(
        app,
        "/oauth/token",
        serde_json::json!({"grant_type": "google_id_token"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let msg = body
        .get("details")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("assertion"),
        "expected assertion-required message, got body: {body}"
    );
}

#[tokio::test]
async fn empty_registry_external_grant_returns_400() {
    let app = app(registry_with(false, false)); // empty registry
    let (status, _body) = post_json(
        app,
        "/oauth/token",
        serde_json::json!({"grant_type": "google_id_token", "id_token": "x"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── /oauth/{provider}/* tests ────────────────────────────────────────────

#[tokio::test]
async fn unknown_provider_returns_404() {
    let app = app(registry_with(true, false));
    let (status, _body) =
        post_json(app, "/oauth/nonexistent/auth-url", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn redirect_flow_on_assertion_provider_returns_400() {
    let app = app(registry_with(false, true)); // CF only (assertion-flow)
    let (status, body) = post_json(
        app,
        "/oauth/cloudflare-access/auth-url",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let msg = body
        .get("details")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("does not support redirect flow"),
        "expected does-not-support-redirect message, got body: {body}"
    );
}
