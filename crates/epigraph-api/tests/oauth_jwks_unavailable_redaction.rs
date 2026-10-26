//! An unreachable JWKS endpoint answers 503 with a fixed `service`, and the
//! fetch error stays on the server (backlog f238ec73).
//!
//! `ProviderError::JwksFetch(msg)` carries the fetcher's error. For the
//! production fetcher that is reqwest's transport error, which names the JWKS
//! URL, an operator-configured address. The device exchange
//! (`oauth/device.rs::exchange_endpoint`) and the external-assertion grant
//! (`oauth/token.rs::handle_external_grant`) interpolated it into the 503's
//! `service`. Each test drives one reachable arm over HTTP with a real
//! `GoogleProvider` whose JWKS URL nothing listens on; the arm that
//! `GoogleProvider::exchange_code` cannot reach is covered by the helper's
//! unit test (`oauth::providers::jwks_unavailable_tests`).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::Engine as _;
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

use epigraph_api::oauth::providers::config::{ProviderConfig, ProviderFlow};
use epigraph_api::oauth::providers::google::GoogleProvider;
use epigraph_api::oauth::providers::jwks::JwksCache;
use epigraph_api::oauth::providers::{
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};

/// A JWKS URL nothing listens on; reqwest's transport error names it.
const UNREACHABLE_JWKS: &str = "http://127.0.0.1:9/jwks-path-e3c1";
/// The text only the withheld fetch error carries.
const MARKER: &str = "jwks-path-e3c1";

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        // The allowlist gate is not under test; the request fails before it.
        allow_all_identities: true,
    }
}

fn google_cfg(token_endpoint: String) -> ProviderConfig {
    std::env::set_var("JW_GOOGLE_CLIENT_ID", "test-google-audience");
    std::env::set_var("JW_GOOGLE_CLIENT_SECRET", "test-google-secret");
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: UNREACHABLE_JWKS.into(),
        audience: None,
        audience_env: Some("JW_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("JW_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("JW_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".into()),
        token_endpoint: Some(token_endpoint),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
        allowed_emails: vec![],
        allowed_domains: vec![],
    }
}

fn app(pool: &PgPool, token_endpoint: String) -> axum::Router {
    let provider = Arc::new(
        GoogleProvider::from_config(&google_cfg(token_endpoint), JwksCache::new())
            .expect("build GoogleProvider"),
    );
    let mut registry = ProviderRegistry::empty();
    registry
        .register(
            provider.clone() as Arc<dyn ExternalIdentityProvider>,
            Some(provider as Arc<dyn OidcRedirectFlow>),
        )
        .expect("register google");
    create_router(AppState::with_db(pool.clone(), config()).with_providers(Arc::new(registry)))
}

/// A token whose header decodes and names a `kid`, so validation reaches the
/// JWKS fetch (the payload and signature are never read: the fetch fails
/// first).
fn token_with_a_kid() -> String {
    let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    format!(
        "{}.{}.{}",
        b64(r#"{"alg":"RS256","typ":"JWT","kid":"kid-e3c1"}"#),
        b64(r#"{"sub":"s"}"#),
        b64("sig")
    )
}

async fn send(app: axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// ONE captured line holds both the helper's message and the withheld text.
fn on_one_line(lines: &[&str]) -> Result<(), String> {
    lines
        .iter()
        .any(|l| l.contains("identity provider JWKS unavailable") && l.contains(MARKER))
        .then_some(())
        .ok_or_else(|| format!("no JWKS-unavailable warn line carries `{MARKER}`"))
}

fn assert_redacted_503(status: StatusCode, body: &str) {
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        !body.contains(MARKER) && !body.contains("127.0.0.1"),
        "the JWKS fetch error reached the client: {body}"
    );
    assert!(
        body.contains("the identity provider's signing keys are unavailable"),
        "the 503 carries the fixed service text: {body}"
    );
}

/// `POST /oauth/token` with the provider's assertion grant: the validate arm
/// of `handle_external_grant`.
#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn the_external_grant_withholds_the_jwks_fetch_error(pool: PgPool) {
    let app = app(&pool, "https://oauth2.googleapis.com/token".into());
    let body = serde_json::json!({
        "grant_type": "google_id_token",
        "assertion": token_with_a_kid(),
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (status, body) = send(app, req).await;
    assert_redacted_503(status, &body);
    logs_assert(on_one_line);
}

/// `POST /oauth/google/exchange`: the code exchange succeeds and the returned
/// id_token's validation cannot fetch the JWKS (the validate arm of
/// `exchange_endpoint`).
#[tracing_test::traced_test]
#[sqlx::test(migrations = "../../migrations")]
async fn the_device_exchange_withholds_the_jwks_fetch_error(pool: PgPool) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let idp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "id_token": token_with_a_kid() })),
        )
        .mount(&idp)
        .await;
    let app = app(&pool, format!("{}/token", idp.uri()));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/google/exchange")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "code": "google-code",
                "code_verifier": "this-is-a-fixed-pkce-code-verifier-of-adequate-length-123456",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = send(app, req).await;
    assert_redacted_503(status, &body);
    logs_assert(on_one_line);
}
