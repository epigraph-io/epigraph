//! The consent page rendered by `GET /oauth/callback` names the client that
//! started the authorization-code flow (`oauth_clients.client_name` of the
//! session's `client_id`), HTML-escaped. It used to say "Authorize Claude"
//! whatever the client was.
//!
//! These drive the real flow — register/seed → `/oauth/authorize` →
//! `/oauth/callback` → `/oauth/authorize/consent` — with Google's token
//! endpoint and JWKS served by the wiremock fixture. Each case gets its own
//! `#[sqlx::test]` database.

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
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_db::repos::oauth_client::OAuthClientRepository;

use oauth_providers::fixtures::ProviderFixture;

const CLAUDE_REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
const EXPLORER_REDIRECT: &str = "https://explorer.example.com/explorer/auth/callback";
const USER_EMAIL: &str = "reader@example.com";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config() -> ApiConfig {
    ApiConfig {
        // `require_packet_signatures`, not `require_signatures`: the field was
        // renamed on main, and `ApiConfig` is deliberately not
        // `#[non_exhaustive]` so every literal names every field.
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "http://localhost:8080".to_string(),
        allow_all_identities: false,
    }
}

/// A Google provider whose token endpoint is the fixture's wiremock server,
/// answering every code exchange with an id_token for `USER_EMAIL`.
async fn app_with_google(pool: &PgPool, fx: &ProviderFixture) -> axum::Router {
    std::env::set_var("CONSENT_TEST_GOOGLE_CLIENT_ID", "test-audience");
    std::env::set_var("CONSENT_TEST_GOOGLE_CLIENT_SECRET", "test-secret");
    let cfg = ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: fx.jwks_url.clone(),
        audience: None,
        audience_env: Some("CONSENT_TEST_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("CONSENT_TEST_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("CONSENT_TEST_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".into()),
        token_endpoint: Some(format!("{}/token", fx.mock_server.uri())),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
        // An EXPLICIT allowlist, not `allow_all_identities: true`. Since PR-02
        // an empty allowlist DENIES — `provision_external_user_client` refuses
        // with "provider has no identity allowlist and allow_all_identities is
        // false" — and this fixture predates that. Naming the one identity it
        // signs keeps the deny-by-default posture under test while letting the
        // flow reach the consent page, which is what this file is about.
        allowed_emails: vec![USER_EMAIL.into()],
        allowed_domains: vec![],
    };
    let id_token = fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "consent-page-subject",
        "email": USER_EMAIL,
        "email_verified": true,
        "name": USER_EMAIL,
        "iat": now(),
        "exp": now() + 600,
    }));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id_token": id_token })))
        .mount(&fx.mock_server)
        .await;

    let provider = Arc::new(GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap());
    let mut registry = ProviderRegistry::empty();
    registry
        .register(
            provider.clone() as Arc<dyn ExternalIdentityProvider>,
            Some(provider as Arc<dyn OidcRedirectFlow>),
        )
        .unwrap();
    create_router(AppState::with_db(pool.clone(), config()).with_providers(Arc::new(registry)))
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Option<String>, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        location,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// `/oauth/authorize` for `client_id`, then the Google state the handler keyed
/// the pending session by (it only ever appears in the Google redirect).
async fn authorize(app: &axum::Router, pool: &PgPool, client_id: &str, redirect: &str) -> String {
    let (status, location, body) = send(
        app,
        get(&format!(
            "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect}\
             &code_challenge=test-challenge&code_challenge_method=S256&state=client-state"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    assert!(location
        .unwrap()
        .starts_with("https://accounts.google.com/"));
    sqlx::query_scalar("SELECT state FROM oauth_authorize_sessions WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn callback(app: &axum::Router, google_state: &str) -> (StatusCode, String) {
    let (status, _, body) = send(
        app,
        get(&format!(
            "/oauth/callback?code=google-code&state={google_state}"
        )),
    )
    .await;
    (status, body)
}

/// The claude.ai path end to end: RFC 7591 registration with only
/// `client_name` + a claude.ai redirect, consent names "Claude" (its
/// registered name, no longer a hard-coded string), and Allow still redirects
/// back with a code.
#[sqlx::test(migrations = "../../migrations")]
async fn claude_ai_flow_names_its_registered_client_and_still_mints_a_code(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let app = app_with_google(&pool, &fx).await;

    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "client_name": "Claude",
                    "redirect_uris": [CLAUDE_REDIRECT],
                    "response_types": ["code"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "none",
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert!(status.is_success(), "register: {status} {body}");
    let registered: Value = serde_json::from_str(&body).unwrap();
    let client_id = registered["client_id"].as_str().unwrap().to_string();

    let google_state = authorize(&app, &pool, &client_id, CLAUDE_REDIRECT).await;
    let (status, page) = callback(&app, &google_state).await;
    assert_eq!(status, StatusCode::OK, "callback: {page}");
    assert!(page.contains("<title>Authorize Claude</title>"), "{page}");
    assert!(page.contains("<h1>Authorize Claude</h1>"), "{page}");
    assert!(page.contains(USER_EMAIL), "{page}");

    let ticket = page
        .split(r#"name="ticket" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("consent form carries a ticket");
    let (status, location, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri("/oauth/authorize/consent")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("ticket={ticket}&decision=allow")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "consent: {body}");
    let location = location.unwrap();
    assert!(location.starts_with(CLAUDE_REDIRECT), "{location}");
    assert!(location.contains("code="), "{location}");
    assert!(location.contains("state=client-state"), "{location}");
}

/// A client registered by an operator (the Explorer's route, since
/// `/oauth/register` only accepts claude.ai redirects) is named on the page,
/// with its name escaped, and nothing on the page says "Claude".
#[sqlx::test(migrations = "../../migrations")]
async fn consent_page_names_the_requesting_client_escaped(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let app = app_with_google(&pool, &fx).await;
    let scopes = vec!["claims:read".to_string()];
    OAuthClientRepository::create(
        &pool,
        "epigraph_explorer_test",
        None,
        r#"Explorer <b>beta</b> & "co""#,
        "human",
        &scopes,
        &scopes,
        "active",
        None,
        None,
        None,
        None,
        Some(&[EXPLORER_REDIRECT.to_string()][..]),
    )
    .await
    .unwrap();

    let google_state = authorize(&app, &pool, "epigraph_explorer_test", EXPLORER_REDIRECT).await;
    let (status, page) = callback(&app, &google_state).await;
    assert_eq!(status, StatusCode::OK, "callback: {page}");
    let escaped = "Explorer &lt;b&gt;beta&lt;/b&gt; &amp; &quot;co&quot;";
    assert!(
        page.contains(&format!("<title>Authorize {escaped}</title>")),
        "{page}"
    );
    assert!(
        page.contains(&format!("<h1>Authorize {escaped}</h1>")),
        "{page}"
    );
    assert!(
        !page.contains("<b>beta</b>"),
        "client name must be escaped: {page}"
    );
    assert!(!page.contains("Claude"), "no hard-coded client: {page}");
    assert!(page.contains(USER_EMAIL), "{page}");
}

/// A client suspended between `/oauth/authorize` and the Google callback is
/// refused before any user is provisioned, instead of being offered for
/// consent.
#[sqlx::test(migrations = "../../migrations")]
async fn callback_refuses_a_client_suspended_mid_flow(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let app = app_with_google(&pool, &fx).await;
    let scopes = vec!["claims:read".to_string()];
    OAuthClientRepository::create(
        &pool,
        "epigraph_suspended_test",
        None,
        "Suspended Client",
        "human",
        &scopes,
        &scopes,
        "active",
        None,
        None,
        None,
        None,
        Some(&[EXPLORER_REDIRECT.to_string()][..]),
    )
    .await
    .unwrap();
    let google_state = authorize(&app, &pool, "epigraph_suspended_test", EXPLORER_REDIRECT).await;

    sqlx::query("UPDATE oauth_clients SET status = 'suspended' WHERE client_id = $1")
        .bind("epigraph_suspended_test")
        .execute(&pool)
        .await
        .unwrap();

    let (status, body) = callback(&app, &google_state).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_client"), "{body}");
    assert!(!body.contains("Suspended Client"), "{body}");
    let provisioned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients WHERE client_id LIKE 'google:%'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        provisioned, 0,
        "no user is provisioned for a refused client"
    );
}
