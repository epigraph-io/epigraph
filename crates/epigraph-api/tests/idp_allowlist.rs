#![cfg(feature = "db")]
//! PR-02 — the external-identity allowlist FAILS CLOSED.
//!
//! Before this, `provision_external_user_client` treated an empty provider
//! allowlist as allow-all, and `oauth::token::refresh_allowed` did the same
//! independently — so closing only one of them would have left every
//! already-provisioned client refreshing forever on an instance that had just
//! been locked down. Both are covered here, plus the production boot assertion.

mod oauth_providers;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use epigraph_api::oauth::providers::{
    build_registry,
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    provisioning_posture_is_safe, ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use oauth_providers::fixtures::ProviderFixture;

// =============================================================================
// FIXTURES
// =============================================================================

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn config(allow_all_identities: bool) -> ApiConfig {
    ApiConfig {
        allow_all_identities,
        ..ApiConfig::default()
    }
}

fn google_cfg(
    jwks_url: &str,
    env_suffix: &str,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
) -> ProviderConfig {
    let cid_var = format!("IDP_ALLOWLIST_GOOGLE_CLIENT_ID_{env_suffix}");
    let sec_var = format!("IDP_ALLOWLIST_GOOGLE_CLIENT_SECRET_{env_suffix}");
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
        auto_provision: true,
        default_scopes: vec!["claims:read".into()],
        allowed_emails,
        allowed_domains,
    }
}

fn registry(provider: GoogleProvider) -> Arc<ProviderRegistry> {
    let mut r = ProviderRegistry::empty();
    let arc = Arc::new(provider);
    r.register(
        arc.clone() as Arc<dyn ExternalIdentityProvider>,
        Some(arc as Arc<dyn OidcRedirectFlow>),
    )
    .unwrap();
    Arc::new(r)
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn client_count(pool: &PgPool, client_id: &str) -> i64 {
    let row: (i64,) = sqlx::query_as("SELECT count(*) FROM oauth_clients WHERE client_id = $1")
        .bind(client_id)
        .fetch_one(pool)
        .await
        .unwrap();
    row.0
}

// =============================================================================
// 1. A CONFIGURED ALLOWLIST EXCLUDES OUTSIDERS
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn identity_outside_allowed_domains_cannot_provision(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, "DOMAIN", vec![], vec!["example.com".into()]),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(false)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "mallory-1", "mallory@evil.test");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        client_count(&pool, "google:mallory-1").await,
        0,
        "the gate runs BEFORE get_by_client_id, so no client row may be created"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn identity_inside_allowed_domains_can_provision(pool: PgPool) {
    // The control case: the gate is not simply denying everything.
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(
            &fx.jwks_url,
            "DOMAIN_OK",
            vec![],
            vec!["example.com".into()],
        ),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(false)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "alice-1", "alice@example.com");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(client_count(&pool, "google:alice-1").await, 1);
}

// =============================================================================
// 2. AN EMPTY ALLOWLIST IS A DENY, NOT AN ALLOW
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn empty_allowlist_denies_when_allow_all_identities_is_false(pool: PgPool) {
    // THE INVERSION. This exact configuration used to provision anybody.
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, "EMPTY_CLOSED", vec![], vec![]),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(false)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "anyone-1", "anyone@anywhere.test");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(client_count(&pool, "google:anyone-1").await, 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn empty_allowlist_permits_when_allow_all_identities_is_true(pool: PgPool) {
    // The explicit operator opt-out still restores the old posture.
    let fx = ProviderFixture::new().await;
    let provider = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, "EMPTY_OPEN", vec![], vec![]),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(true)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "anyone-2", "anyone@anywhere.test");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(client_count(&pool, "google:anyone-2").await, 1);
}

// =============================================================================
// 3. REFRESH RE-RUNS THE GATE
// =============================================================================

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_is_refused_for_a_de_allowlisted_identity(pool: PgPool) {
    let fx = ProviderFixture::new().await;

    // Provision under an allowlist that admits the identity.
    let provider = GoogleProvider::from_config(
        &google_cfg(
            &fx.jwks_url,
            "DELIST_BEFORE",
            vec!["bob@example.com".into()],
            vec![],
        ),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(false)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "bob-1", "bob@example.com");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    // Now rebuild the app with bob REMOVED from the allowlist. The provision
    // gate never runs again for a client that already exists, so `refresh_allowed`
    // is the only thing standing between a de-authorized identity and an
    // indefinitely renewing 30-day refresh token.
    let delisted = GoogleProvider::from_config(
        &google_cfg(
            &fx.jwks_url,
            "DELIST_AFTER",
            vec!["carol@example.com".into()],
            vec![],
        ),
        JwksCache::new(),
    )
    .unwrap();
    let state2 = AppState::with_db(pool.clone(), config(false)).with_providers(registry(delisted));

    let (status, body) = post_json(
        create_router(state2),
        "/oauth/token",
        json!({ "grant_type": "refresh_token", "refresh_token": refresh }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn refresh_is_refused_once_the_allowlist_is_emptied(pool: PgPool) {
    // The specific hole `refresh_allowed`'s empty-list arm used to leave open:
    // an operator who locks the instance down by CLEARING the allowlist would,
    // before PR-02, have left every existing external client refreshing forever.
    let fx = ProviderFixture::new().await;

    let provider = GoogleProvider::from_config(
        &google_cfg(
            &fx.jwks_url,
            "EMPTIED_BEFORE",
            vec!["dave@example.com".into()],
            vec![],
        ),
        JwksCache::new(),
    )
    .unwrap();
    let state = AppState::with_db(pool.clone(), config(false)).with_providers(registry(provider));

    let jwt = signed_jwt(&fx, "dave-1", "dave@example.com");
    let (status, body) = post_json(
        create_router(state),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": jwt }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let refresh = body["refresh_token"].as_str().unwrap().to_string();

    let emptied = GoogleProvider::from_config(
        &google_cfg(&fx.jwks_url, "EMPTIED_AFTER", vec![], vec![]),
        JwksCache::new(),
    )
    .unwrap();
    let state2 = AppState::with_db(pool.clone(), config(false)).with_providers(registry(emptied));

    let (status, body) = post_json(
        create_router(state2),
        "/oauth/token",
        json!({ "grant_type": "refresh_token", "refresh_token": refresh }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// =============================================================================
// 4. THE PRODUCTION BOOT ASSERTION
// =============================================================================

/// All four corners of (empty allowlist × allow_all_identities × EPIGRAPH_ENV),
/// asserted over the predicate `build_registry` calls. Unit-level rather than
/// process-level: spawning a real server to observe a startup abort would make
/// this test a subprocess harness for one boolean.
///
/// This covers the PREDICATE only — see
/// [`build_registry_itself_refuses_an_unsafe_providers_toml`] for the wiring.
#[test]
fn the_provisioning_posture_predicate_covers_all_four_corners() {
    let listed = vec!["ops@example.com".to_string()];

    // production × empty × no opt-out -> REFUSE.
    let err = provisioning_posture_is_safe(&[], &[], true, false, "production")
        .expect_err("production + empty allowlist + no opt-out must refuse to boot");
    assert!(err.contains("EPIGRAPH_ALLOW_ALL_IDENTITIES"));

    // production × empty × opt-out -> boot.
    assert!(provisioning_posture_is_safe(&[], &[], true, true, "production").is_ok());

    // production × configured -> boot, opt-out irrelevant.
    assert!(provisioning_posture_is_safe(&listed, &[], true, false, "production").is_ok());
    assert!(provisioning_posture_is_safe(&listed, &[], true, true, "production").is_ok());

    // non-production × empty × no opt-out -> boot (warn only), so dev and CI
    // keep working without an allowlist — but the environment has to be
    // DECLARED. Unset ("") is production; see `env_is_production`.
    assert!(provisioning_posture_is_safe(&[], &[], true, false, "development").is_ok());
    assert!(provisioning_posture_is_safe(&[], &[], true, false, "ci").is_ok());
    assert!(
        provisioning_posture_is_safe(&[], &[], true, false, "").is_err(),
        "an UNSET EPIGRAPH_ENV must be treated as production — it is unset in every \
         deployment that exists today, which is the whole population this gate is for"
    );

    // auto_provision off -> the allowlist is moot everywhere.
    assert!(provisioning_posture_is_safe(&[], &[], false, false, "production").is_ok());
}

/// The wiring, not the predicate.
///
/// Deleting the `provisioning_posture_is_safe(...)` call from `build_registry`
/// leaves every assertion in the test above green: they exercise the extracted
/// predicate in isolation and never touch the function that is supposed to
/// consult it. The single most fragile thing about this gate is that
/// `build_registry` actually calls it — so call `build_registry`.
///
/// Deterministic because `env` is a PARAMETER. It used to be a
/// `std::env::var("EPIGRAPH_ENV")` inside the provider loop, which a test can
/// only reach by mutating process-global state that every other test in the
/// binary shares.
#[test]
fn build_registry_itself_refuses_an_unsafe_providers_toml() {
    // auto_provision with NO allowlist — the one unsafe shape.
    let toml = r#"
[[provider]]
name              = "google"
flow              = "redirect"
grant_type        = "google_id_token"
issuer            = "https://accounts.google.com"
jwks_url          = "https://www.googleapis.com/oauth2/v3/certs"
audience_env      = "GOOGLE_CLIENT_ID"
client_id_env     = "GOOGLE_CLIENT_ID"
client_secret_env = "GOOGLE_CLIENT_SECRET"
auth_endpoint     = "https://accounts.google.com/o/oauth2/v2/auth"
token_endpoint    = "https://oauth2.googleapis.com/token"
redirect_uri_env  = "EPIGRAPH_REDIRECT_URI"
auto_provision    = true
allowed_emails    = []
allowed_domains   = []
default_scopes    = ["claims:read"]
"#;

    let dir = std::env::temp_dir().join(format!(
        "epigraph-pr02-providers-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("providers.toml");
    std::fs::write(&path, toml).expect("write providers.toml");

    // Production (explicit) -> Err, and the message names the escape hatch and
    // the offending provider.
    // `.err().expect(..)` rather than `.expect_err(..)`: ProviderRegistry is
    // deliberately not Debug.
    let err = build_registry(&path, false, "production")
        .err()
        .expect("build_registry must refuse this providers.toml in production");
    assert!(
        err.contains("EPIGRAPH_ALLOW_ALL_IDENTITIES") && err.contains("google"),
        "unexpected error: {err}"
    );

    // Unset EPIGRAPH_ENV -> also Err. This is the case that matters: the
    // variable is introduced by PR-02, so it is unset everywhere today.
    assert!(
        build_registry(&path, false, "").is_err(),
        "an unset EPIGRAPH_ENV must refuse too"
    );

    // The two escape hatches must get PAST the posture gate. They do not
    // necessarily reach `Ok`: `GoogleProvider::from_config` resolves
    // `audience_env`/`client_id_env` from the process environment, which this
    // test deliberately does not set. So assert on WHICH error, not on success —
    // the posture message is the one thing that must be gone.
    for (allow_all, env, why) in [
        (
            true,
            "production",
            "allow_all_identities=true is the operator saying it out loud",
        ),
        (
            false,
            "development",
            "dev must keep running without an allowlist",
        ),
    ] {
        if let Err(e) = build_registry(&path, allow_all, env) {
            assert!(
                !e.contains("EPIGRAPH_ALLOW_ALL_IDENTITIES"),
                "{why}, but the posture gate still fired: {e}"
            );
        }
    }

    std::fs::remove_dir_all(&dir).ok();
}
