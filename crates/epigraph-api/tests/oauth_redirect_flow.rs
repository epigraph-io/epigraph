//! Integration tests for the redirect-flow endpoints.

mod oauth_providers;

use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    OidcRedirectFlow,
};

use oauth_providers::fixtures::ProviderFixture;

fn google_cfg(jwks_url: &str, token_endpoint: &str) -> ProviderConfig {
    std::env::set_var("RT_GOOGLE_CLIENT_ID", "test-audience");
    std::env::set_var("RT_GOOGLE_CLIENT_SECRET", "test-secret");
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec!["accounts.google.com".into()],
        jwks_url: jwks_url.into(),
        audience: None,
        audience_env: Some("RT_GOOGLE_CLIENT_ID".into()),
        client_id_env: Some("RT_GOOGLE_CLIENT_ID".into()),
        client_secret_env: Some("RT_GOOGLE_CLIENT_SECRET".into()),
        auth_endpoint: Some("https://accounts.google.com/o/oauth2/v2/auth".into()),
        token_endpoint: Some(token_endpoint.into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
    }
}

#[tokio::test]
async fn build_auth_url_includes_pkce_challenge_and_redirect() {
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, "https://example/token"),
        JwksCache::new(),
    )
    .unwrap();

    let url = provider.build_auth_url("CSRF_STATE", "PKCE_CHALLENGE", "http://localhost:9999");
    // After percent-encoding (Task 6 fix): redirect_uri's `:`, `/` become %3A and %2F.
    assert!(url.contains("client_id=test-audience"), "url: {url}");
    assert!(
        url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A9999"),
        "url: {url}"
    );
    assert!(url.contains("code_challenge=PKCE_CHALLENGE"), "url: {url}");
    assert!(url.contains("response_type=code"), "url: {url}");
    assert!(
        url.contains("state=CSRF_STATE"),
        "state must propagate: {url}"
    );
}

#[tokio::test]
async fn exchange_code_propagates_id_token_from_idp() {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let fx = ProviderFixture::new().await;
    // Mock the token endpoint on the same wiremock server.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id_token": "the-id-token-value"})),
        )
        .mount(&fx.mock_server)
        .await;

    let token_endpoint = format!("{}/token", fx.mock_server.uri());
    let provider =
        GoogleProvider::from_config(&google_cfg(&fx.jwks_url, &token_endpoint), JwksCache::new())
            .unwrap();

    let id_token = provider
        .exchange_code("auth-code", "http://localhost:9999", "verifier")
        .await
        .unwrap();
    assert_eq!(id_token, "the-id-token-value");
}

#[tokio::test]
async fn exchange_code_propagates_idp_error() {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let fx = ProviderFixture::new().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&fx.mock_server)
        .await;

    let token_endpoint = format!("{}/token", fx.mock_server.uri());
    let provider =
        GoogleProvider::from_config(&google_cfg(&fx.jwks_url, &token_endpoint), JwksCache::new())
            .unwrap();

    let err = provider
        .exchange_code("auth-code", "http://localhost:9999", "verifier")
        .await
        .unwrap_err();
    let s = format!("{err:?}");
    assert!(s.contains("Upstream") || s.contains("invalid_grant"), "{s}");
}
