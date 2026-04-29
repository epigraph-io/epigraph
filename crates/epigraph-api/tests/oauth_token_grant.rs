//! Integration tests for external-grant token issuance via the provider trait.

mod oauth_providers;

use std::time::{SystemTime, UNIX_EPOCH};

use epigraph_api::oauth::providers::{
    cloudflare_access::CloudflareAccessProvider, config::ProviderConfig, config::ProviderFlow,
    google::GoogleProvider, jwks::JwksCache, ExternalIdentityProvider, ProviderError,
};
use serde_json::json;

use oauth_providers::fixtures::ProviderFixture;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn google_cfg(jwks_url: &str) -> ProviderConfig {
    ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec!["accounts.google.com".into()],
        jwks_url: jwks_url.into(),
        audience: Some("test-audience".into()),
        audience_env: None,
        client_id_env: None,
        client_secret_env: None,
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some("https://example/token".into()),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
    }
}

#[tokio::test]
async fn google_validate_accepts_signed_token() {
    let fx = ProviderFixture::new().await;
    std::env::set_var("TEST_GOOGLE_CLIENT_ID_OK", "test-audience");
    std::env::set_var("TEST_GOOGLE_CLIENT_SECRET_OK", "test-secret");
    let mut cfg = google_cfg(&fx.jwks_url);
    cfg.client_id_env = Some("TEST_GOOGLE_CLIENT_ID_OK".into());
    cfg.client_secret_env = Some("TEST_GOOGLE_CLIENT_SECRET_OK".into());
    let provider = GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap();

    let claims = json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "1234567890",
        "email": "alice@example.com",
        "email_verified": true,
        "name": "Alice",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = fx.sign(&claims);

    let id = provider.validate(&jwt).await.unwrap();
    assert_eq!(id.subject, "1234567890");
    assert_eq!(id.email.as_deref(), Some("alice@example.com"));
    assert!(id.email_verified);
}

#[tokio::test]
async fn google_validate_rejects_wrong_issuer() {
    let fx = ProviderFixture::new().await;
    std::env::set_var("TEST_GOOGLE_CLIENT_ID_ISS", "test-audience");
    std::env::set_var("TEST_GOOGLE_CLIENT_SECRET_ISS", "test-secret");
    let mut cfg = google_cfg(&fx.jwks_url);
    cfg.client_id_env = Some("TEST_GOOGLE_CLIENT_ID_ISS".into());
    cfg.client_secret_env = Some("TEST_GOOGLE_CLIENT_SECRET_ISS".into());
    let provider = GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap();

    let claims = json!({
        "iss": "https://attacker.example",
        "aud": "test-audience",
        "sub": "x",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = fx.sign(&claims);
    let err = provider.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidAssertion(_)));
}

#[tokio::test]
async fn google_validate_rejects_wrong_audience() {
    let fx = ProviderFixture::new().await;
    std::env::set_var("TEST_GOOGLE_CLIENT_ID_AUD", "test-audience");
    std::env::set_var("TEST_GOOGLE_CLIENT_SECRET_AUD", "test-secret");
    let mut cfg = google_cfg(&fx.jwks_url);
    cfg.client_id_env = Some("TEST_GOOGLE_CLIENT_ID_AUD".into());
    cfg.client_secret_env = Some("TEST_GOOGLE_CLIENT_SECRET_AUD".into());
    let provider = GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap();

    let claims = json!({
        "iss": "https://accounts.google.com",
        "aud": "different-audience",
        "sub": "x",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = fx.sign(&claims);
    let err = provider.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidAssertion(_)));
}

#[tokio::test]
async fn google_validate_rejects_expired() {
    let fx = ProviderFixture::new().await;
    std::env::set_var("TEST_GOOGLE_CLIENT_ID_EXP", "test-audience");
    std::env::set_var("TEST_GOOGLE_CLIENT_SECRET_EXP", "test-secret");
    let mut cfg = google_cfg(&fx.jwks_url);
    cfg.client_id_env = Some("TEST_GOOGLE_CLIENT_ID_EXP".into());
    cfg.client_secret_env = Some("TEST_GOOGLE_CLIENT_SECRET_EXP".into());
    let provider = GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap();

    let claims = json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "x",
        "iat": now() - 3600,
        "exp": now() - 600,
    });
    let jwt = fx.sign(&claims);
    let err = provider.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidAssertion(_)));
}

fn cf_cfg(jwks_url: &str) -> ProviderConfig {
    ProviderConfig {
        name: "cloudflare-access".into(),
        flow: ProviderFlow::Assertion,
        grant_type: "cloudflare_access_jwt".into(),
        issuer: "https://team.cloudflareaccess.com".into(),
        extra_issuers: vec![],
        jwks_url: jwks_url.into(),
        audience: Some("cf-aud-tag".into()),
        audience_env: None,
        client_id_env: None,
        client_secret_env: None,
        auth_endpoint: None,
        token_endpoint: None,
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
    }
}

#[tokio::test]
async fn cloudflare_validate_accepts_array_audience() {
    let fx = ProviderFixture::new().await;
    let provider =
        CloudflareAccessProvider::from_config(&cf_cfg(&fx.jwks_url), JwksCache::new()).unwrap();

    // Real CF tokens emit aud as an array.
    let claims = json!({
        "iss": "https://team.cloudflareaccess.com",
        "aud": ["cf-aud-tag"],
        "sub": "user-123",
        "email": "bob@example.com",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = fx.sign(&claims);
    let id = provider.validate(&jwt).await.unwrap();
    assert_eq!(id.subject, "user-123");
}

#[tokio::test]
async fn cloudflare_validate_rejects_wrong_aud() {
    let fx = ProviderFixture::new().await;
    let provider =
        CloudflareAccessProvider::from_config(&cf_cfg(&fx.jwks_url), JwksCache::new()).unwrap();
    let claims = json!({
        "iss": "https://team.cloudflareaccess.com",
        "aud": ["other-tag"],
        "sub": "user-123",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = fx.sign(&claims);
    let err = provider.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidAssertion(_)));
}

#[tokio::test]
async fn unknown_kid_triggers_refetch_then_fails() {
    let fx = ProviderFixture::new().await;
    let provider =
        CloudflareAccessProvider::from_config(&cf_cfg(&fx.jwks_url), JwksCache::new()).unwrap();

    // Sign with a kid the JWKS doesn't know.
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let mut rng = rand::thread_rng();
    let bogus_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = bogus_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .unwrap()
        .to_string();
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("nonexistent-kid".into());
    let claims = json!({
        "iss": "https://team.cloudflareaccess.com",
        "aud": ["cf-aud-tag"],
        "sub": "x",
        "iat": now(),
        "exp": now() + 600,
    });
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();

    let err = provider.validate(&jwt).await.unwrap_err();
    assert!(matches!(err, ProviderError::InvalidAssertion(_)));
}
