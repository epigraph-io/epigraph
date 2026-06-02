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
