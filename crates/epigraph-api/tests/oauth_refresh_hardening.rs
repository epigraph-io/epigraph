#![cfg(feature = "db")]
//! Refresh-grant hardening (U002 follow-ups), end to end on a pool whose every
//! connection runs as the deployed application role.
//!
//! * The refresh grant's `invalid_scope` gate runs AFTER the mint chokepoint
//!   (`oauth::scopes::grantable`), so a `scope` naming only what the chokepoint
//!   strips is refused and the chain is kept (backlog a02bb75f).
//! * A refresh chain stores the CONSENTED scopes, not the chokepoint's output,
//!   so an arm-then-disarm of migration 128's switch is reversible for the
//!   chains minted while it was armed (backlog 35a89d3d).
//! * A confidential client (agent, service) authenticates on the refresh
//!   grant with the credential the `client_credentials` grant verifies, and a
//!   `client_id` on the request must be the chain's own (backlog 0306711a).
//! * An authorization-code chain is bound to the connector app that obtained
//!   it (migration 174): a suspended app keeps no live chain, and an operator
//!   can revoke one app's chains of one person (backlog 7a2111e6).
//!
//! Each test names the defect it catches.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::Engine as _;
use chrono::{Duration, Utc};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::{EpiGraphClaims, JwtConfig};
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "a11-fixed-pkce-code-verifier-of-adequate-length-0123456789";
const HELD: &[&str] = &["claims:read", "claims:admin"];

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        allow_all_identities: true,
    }
}

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

async fn url_for(pool: &PgPool) -> String {
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("current_database()");
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL");
    let prefix = base
        .split_once('?')
        .map_or(base.as_str(), |(a, _)| a)
        .trim_end_matches('/')
        .rsplit_once('/')
        .expect("DATABASE_URL must carry a database path")
        .0
        .to_string();
    format!("{prefix}/{db}")
}

/// A pool whose every connection is `epigraph_app`.
async fn app_role_pool(pool: &PgPool) -> PgPool {
    use sqlx::Executor;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET SESSION AUTHORIZATION epigraph_app")
                    .await?;
                Ok(())
            })
        })
        .connect(&url_for(pool).await)
        .await
        .expect("application-role pool")
}

/// Reads migration 128's switch on EVERY request: these tests arm and disarm
/// mid-run.
async fn state(pool: &PgPool) -> AppState {
    AppState::with_db(app_role_pool(pool).await, config())
        .with_admin_scope_arming_ttl(std::time::Duration::ZERO)
}

async fn post_token(app: &axum::Router, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Arm (or disarm) migration 128's switch, as the harness.
async fn set_armed(pool: &PgPool, armed: bool) {
    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement($1, 'oauth_refresh_hardening')",
    )
    .bind(armed)
    .execute(pool)
    .await
    .expect("set the switch");
}

/// The access token's scopes, sorted.
fn token_scopes(jwt: &JwtConfig, body: &Value) -> Vec<String> {
    let token = body["access_token"].as_str().expect("access_token");
    let claims: EpiGraphClaims = jwt.validate_token(token).expect("the token validates");
    let mut scopes = claims.scopes;
    scopes.sort();
    scopes
}

fn refresh_grant(token: &str) -> Value {
    json!({ "grant_type": "refresh_token", "refresh_token": token })
}

fn refresh_token_of(body: &Value) -> String {
    body["refresh_token"]
        .as_str()
        .unwrap_or_else(|| panic!("a refresh token: {body}"))
        .to_string()
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// An active client of `client_type` holding `scopes`, with no secret.
async fn client_row(pool: &PgPool, client_id: &str, client_type: &str, scopes: &[String]) -> Uuid {
    OAuthClientRepository::create(
        pool,
        client_id,
        None,
        "a11 client",
        client_type,
        scopes,
        scopes,
        "active",
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed client")
}

/// One authorization code: obtained by the connector app `app_client_id`,
/// for the per-user human client `human`, consented with `scopes`.
async fn code_for(pool: &PgPool, app_client_id: &str, human: Uuid, scopes: &[String]) -> String {
    let code = format!("code_{}", Uuid::new_v4().simple());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        app_client_id,
        human,
        REDIRECT_URI,
        &challenge,
        scopes,
        None,
        Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    code
}

fn code_grant(code: &str, client_id: &str) -> Value {
    json!({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": VERIFIER,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
    })
}

/// A human client that is its own connector (the single-row fixture the
/// older suites use), holding and consenting `HELD`. Returns its client_id
/// and one code.
async fn self_connector_code(pool: &PgPool) -> (String, String) {
    let client_id = format!("a11_{}", Uuid::new_v4().simple());
    let id = client_row(pool, &client_id, "human", &v(HELD)).await;
    let code = code_for(pool, &client_id, id, &v(HELD)).await;
    (client_id, code)
}

// ── a02bb75f: the invalid_scope gate runs after the chokepoint ───────────────

/// A refresh whose `scope` names only a scope the mint chokepoint strips (an
/// admin-only scope, with migration 128's switch armed) issues nothing: it is
/// `invalid_scope` in the RFC 6749 section 5.2 shape, and the chain is kept.
///
/// Catches: the emptiness gate testing the pre-chokepoint set only, which
/// answered 200 with an empty-scope token and rotated the chain.
#[sqlx::test(migrations = "../../migrations")]
async fn a_refresh_scope_naming_only_a_stripped_scope_is_invalid_scope_and_keeps_the_chain(
    pool: PgPool,
) {
    let (client_id, code) = self_connector_code(&pool).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    // Minted UNARMED, so the chain holds claims:admin whatever the store
    // rule; then armed.
    let (status, body) = post_token(&app, code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let r0 = refresh_token_of(&body);
    set_armed(&pool, true).await;

    let (status, body) = post_token(
        &app,
        json!({ "grant_type": "refresh_token", "refresh_token": r0, "scope": "claims:admin" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "scope=claims:admin issues nothing while armed: {body}"
    );
    assert_eq!(body["error"], "invalid_scope", "RFC 6749 5.2 shape: {body}");
    assert!(
        body.get("access_token").is_none(),
        "no token issued: {body}"
    );

    let (status, body) = post_token(&app, refresh_grant(&r0)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused request did not spend the presented token: {body}"
    );
    assert_eq!(token_scopes(&jwt, &body), v(&["claims:read"]));
}

// ── 35a89d3d: the chain stores the consent, not the chokepoint's output ──────

// The external grant's fixture (shared with the provider suites).
mod oauth_providers;

use std::sync::Arc;

use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use oauth_providers::fixtures::ProviderFixture;

/// An active SERVICE client holding `scopes`, with a fresh secret. Returns
/// `(client_id, secret hex)`.
async fn service_client(pool: &PgPool, scopes: &[String]) -> (String, String) {
    let secret: [u8; 32] = rand::random();
    let client_id = format!("a11_svc_{}", Uuid::new_v4().simple());
    OAuthClientRepository::create(
        pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "a11 service",
        "service",
        scopes,
        scopes,
        "active",
        None,
        None,
        Some("A11 Test Org"),
        Some("a11@example.com"),
        None,
    )
    .await
    .expect("service client");
    (client_id, hex::encode(secret))
}

fn service_grant(client_id: &str, secret: &str) -> Value {
    json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    })
}

fn service_refresh(token: &str, client_id: &str, secret: &str) -> Value {
    json!({
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_id": client_id,
        "client_secret": secret,
    })
}

/// A chain minted by the code exchange while armed gets `claims:admin` back
/// on its first refresh after a disarm (the consent is the chain's ceiling;
/// the chokepoint runs on every mint).
///
/// Catches: `handle_authorization_code` storing `grantable`'s output, which
/// lost the stripped scope from the chain for good.
#[sqlx::test(migrations = "../../migrations")]
async fn a_code_chain_minted_armed_regains_the_admin_scope_after_a_disarm(pool: PgPool) {
    let (client_id, code) = self_connector_code(&pool).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let (status, body) = post_token(&app, code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read"]),
        "PREMISE: armed, the exchange strips claims:admin"
    );
    let r0 = refresh_token_of(&body);

    set_armed(&pool, false).await;
    let (status, body) = post_token(&app, refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:admin", "claims:read"]),
        "the disarm is reversible for a chain minted while armed"
    );
}

/// The same for a service's `client_credentials` chain.
///
/// Catches: `handle_client_credentials` storing `grantable`'s output.
#[sqlx::test(migrations = "../../migrations")]
async fn a_client_credentials_chain_minted_armed_regains_the_admin_scope_after_a_disarm(
    pool: PgPool,
) {
    let (client_id, secret) = service_client(&pool, &v(HELD)).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let (status, body) = post_token(&app, service_grant(&client_id, &secret)).await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read"]),
        "PREMISE: armed, the grant strips claims:admin"
    );
    let r0 = refresh_token_of(&body);

    set_armed(&pool, false).await;
    let (status, body) = post_token(&app, service_refresh(&r0, &client_id, &secret)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:admin", "claims:read"]),
        "the disarm is reversible for a chain minted while armed"
    );
}

/// A google provider whose auto-provisioned clients hold `HELD`.
fn google_registry(fx: &ProviderFixture) -> Arc<ProviderRegistry> {
    let cid_var = "OAUTH_REFRESH_HARDENING_GOOGLE_CLIENT_ID".to_string();
    let sec_var = "OAUTH_REFRESH_HARDENING_GOOGLE_CLIENT_SECRET".to_string();
    std::env::set_var(&cid_var, "test-audience");
    std::env::set_var(&sec_var, "test-secret");
    let cfg = ProviderConfig {
        name: "google".into(),
        flow: ProviderFlow::Redirect,
        grant_type: "google_id_token".into(),
        issuer: "https://accounts.google.com".into(),
        extra_issuers: vec![],
        jwks_url: fx.jwks_url.clone(),
        audience: None,
        audience_env: Some(cid_var.clone()),
        client_id_env: Some(cid_var),
        client_secret_env: Some(sec_var),
        auth_endpoint: Some("https://example/auth".into()),
        token_endpoint: Some(format!("{}/token", fx.mock_server.uri())),
        redirect_uri: None,
        redirect_uri_env: None,
        auto_provision: true,
        default_scopes: v(HELD),
        allowed_emails: vec![],
        allowed_domains: vec![],
    };
    let provider = Arc::new(GoogleProvider::from_config(&cfg, JwksCache::new()).unwrap());
    let mut r = ProviderRegistry::empty();
    r.register(
        provider.clone() as Arc<dyn ExternalIdentityProvider>,
        Some(provider as Arc<dyn OidcRedirectFlow>),
    )
    .unwrap();
    Arc::new(r)
}

/// The same for an external provider's assertion grant (the shared
/// `provision_external_user` mint, which the redirect exchange also uses).
///
/// Catches: `provision_external_user` storing `grantable`'s output.
#[sqlx::test(migrations = "../../migrations")]
async fn an_external_grant_chain_minted_armed_regains_the_admin_scope_after_a_disarm(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    set_armed(&pool, true).await;
    let st = state(&pool).await.with_providers(google_registry(&fx));
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let now = Utc::now().timestamp();
    let id_token = fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": "a11-ext",
        "email": "a11-ext@example.com",
        "email_verified": true,
        "name": "a11-ext",
        "iat": now,
        "exp": now + 600,
    }));
    let (status, body) = post_token(
        &app,
        json!({ "grant_type": "google_id_token", "assertion": id_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "external grant: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:read"]),
        "PREMISE: armed, the grant strips claims:admin"
    );
    let r0 = refresh_token_of(&body);

    set_armed(&pool, false).await;
    let (status, body) = post_token(&app, refresh_grant(&r0)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_eq!(
        token_scopes(&jwt, &body),
        v(&["claims:admin", "claims:read"]),
        "the disarm is reversible for a chain minted while armed"
    );
}

// ── 0306711a: confidential clients authenticate on the refresh grant ─────────

use ed25519_dalek::{Signer, SigningKey};

/// An agent row for `key` with an ACTIVE agent client holding `claims:read`
/// (and the owner client `agents_must_have_owner` requires). Returns the
/// agent client's `client_id` (the hex public key).
async fn agent_client(pool: &PgPool, key: &SigningKey) -> String {
    let public_key = key.verifying_key().to_bytes();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(public_key.to_vec())
        .execute(pool)
        .await
        .expect("agent row");
    let owner = client_row(
        pool,
        &format!("owner-{agent}"),
        "human",
        &v(&["claims:read"]),
    )
    .await;
    let client_id = hex::encode(public_key);
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'a11-agent', 'agent', ARRAY['claims:read'], ARRAY['claims:read'], \
                 'active', $2, $3)",
    )
    .bind(&client_id)
    .bind(agent)
    .bind(owner)
    .execute(pool)
    .await
    .expect("agent client");
    client_id
}

/// `timestamp(8B BE) || nonce(16B) || Ed25519(timestamp || nonce)`, base64.
fn assertion(key: &SigningKey) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let mut msg = Vec::with_capacity(88);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(Uuid::new_v4().as_bytes());
    let sig = key.sign(&msg);
    msg.extend_from_slice(&sig.to_bytes());
    base64::engine::general_purpose::STANDARD.encode(msg)
}

fn agent_grant(client_id: &str, key: &SigningKey) -> Value {
    json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion(key),
    })
}

fn agent_refresh(token: &str, client_id: &str, key: &SigningKey) -> Value {
    json!({
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_id": client_id,
        "client_assertion_type": "urn:epigraph:ed25519",
        "client_assertion": assertion(key),
    })
}

/// A service chain refreshes only with the service's own secret. Without it,
/// with a wrong one, or under another client's id and secret, the refresh is
/// refused and the presented token is left intact (it then refreshes with
/// the right credential).
///
/// Catches: possession of the refresh token being the only authentication of
/// a confidential client on the refresh grant (RFC 6749 section 6).
#[sqlx::test(migrations = "../../migrations")]
async fn a_service_refresh_requires_the_services_own_secret(pool: PgPool) {
    let (client_id, secret) = service_client(&pool, &v(&["claims:read"])).await;
    let (other_id, other_secret) = service_client(&pool, &v(&["claims:read"])).await;
    let app = create_router(state(&pool).await);
    let (status, body) = post_token(&app, service_grant(&client_id, &secret)).await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    let r0 = refresh_token_of(&body);

    let wrong: [u8; 32] = rand::random();
    for (what, req) in [
        ("no credential", refresh_grant(&r0)),
        (
            "a wrong secret",
            service_refresh(&r0, &client_id, &hex::encode(wrong)),
        ),
        (
            "another client's id and secret",
            service_refresh(&r0, &other_id, &other_secret),
        ),
    ] {
        let (status, body) = post_token(&app, req).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
            "{what}: a service refresh must authenticate the service, got {status}: {body}"
        );
        assert!(body.get("access_token").is_none(), "{what}: {body}");
    }

    let (status, body) = post_token(&app, service_refresh(&r0, &client_id, &secret)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused requests left the chain intact: {body}"
    );
}

/// An agent chain refreshes only with a fresh assertion under the agent's own
/// key; the refused requests leave the presented token intact.
///
/// Catches: the agent arm of the same defect.
#[sqlx::test(migrations = "../../migrations")]
async fn an_agent_refresh_requires_an_assertion_under_the_agents_key(pool: PgPool) {
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let stranger = SigningKey::from_bytes(&[0x5b; 32]);
    let client_id = agent_client(&pool, &key).await;
    let app = create_router(state(&pool).await);
    let (status, body) = post_token(&app, agent_grant(&client_id, &key)).await;
    assert_eq!(status, StatusCode::OK, "client_credentials: {body}");
    let r0 = refresh_token_of(&body);

    for (what, req) in [
        ("no assertion", refresh_grant(&r0)),
        (
            "an assertion under another key",
            agent_refresh(&r0, &client_id, &stranger),
        ),
    ] {
        let (status, body) = post_token(&app, req).await;
        assert!(
            status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST,
            "{what}: an agent refresh must authenticate the agent, got {status}: {body}"
        );
        assert!(body.get("access_token").is_none(), "{what}: {body}");
    }

    let (status, body) = post_token(&app, agent_refresh(&r0, &client_id, &key)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused requests left the chain intact: {body}"
    );
}
