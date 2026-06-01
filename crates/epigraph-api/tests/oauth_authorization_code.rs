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
    // scopes_supported MUST reflect the scope values the /mcp resource actually
    // accepts — i.e. the codomain of epigraph-mcp's SCOPE_MAP {claims:read,
    // claims:write, claims:admin}. claims:admin gates mark_duplicate /
    // supersede_claim / update_partition, so a connector reading this doc must
    // learn it can request it; analysis:belief is required by NO MCP tool.
    let scopes = body["scopes_supported"].as_array().unwrap();
    assert!(
        scopes.iter().any(|v| v == "claims:admin"),
        "scopes_supported must advertise claims:admin (admin MCP tools need it); got: {scopes:?}"
    );
    assert!(
        !scopes.iter().any(|v| v == "analysis:belief"),
        "scopes_supported must NOT advertise analysis:belief (no MCP tool requires it); got: {scopes:?}"
    );
}
