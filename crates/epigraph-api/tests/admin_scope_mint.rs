#![cfg(feature = "db")]
//! The mint chokepoint for admin-only scopes (elevation plan EL-9,
//! `oauth::scopes::grantable`): every grant the token endpoint serves follows
//! migration 128's switch.
//!
//! ARMED, a client that holds `claims:admin` gets a token without it, on EACH
//! grant: the authorization-code exchange, the refresh grant, the
//! client-credentials grant (agent and service), an external provider's
//! assertion grant and the browser redirect exchange (`/oauth/{provider}/exchange`,
//! the plan's "device" mint). Each grant is its own test, so a handler that
//! goes back to minting `client.granted_scopes` itself is named by exactly
//! one failure. UNARMED, every token keeps it and the database records one
//! `oauth.admin_scope_would_strip` event per client, naming the grant.
//!
//! Every request is served on a pool whose connections run as the deployed
//! application role, so the switch read and the measurement go through 128's
//! grants, not a superuser's. Each test names the mutation it catches.

mod oauth_providers;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::Engine as _;
use chrono::Duration;
use ed25519_dalek::{Signer, SigningKey};
use epigraph_api::oauth::providers::{
    config::{ProviderConfig, ProviderFlow},
    google::GoogleProvider,
    jwks::JwksCache,
    ExternalIdentityProvider, OidcRedirectFlow, ProviderRegistry,
};
use epigraph_api::{create_router, ApiConfig, AppState};
use epigraph_auth::{EpiGraphClaims, JwtConfig};
use epigraph_db::repos::authorization_code::AuthorizationCodeRepository;
use epigraph_db::repos::oauth_client::OAuthClientRepository;
use http_body_util::BodyExt;
use oauth_providers::fixtures::ProviderFixture;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const REDIRECT_URI: &str = "https://claude.ai/api/mcp/auth_callback";
const VERIFIER: &str = "el9-fixed-pkce-code-verifier-of-adequate-length-0123456789";
const HELD: &[&str] = &["claims:read", "claims:admin"];

fn config() -> ApiConfig {
    ApiConfig {
        require_packet_signatures: false,
        max_request_size: 1024 * 1024,
        public_base_url: "https://test.example".to_string(),
        allow_all_identities: true,
    }
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

async fn state(pool: &PgPool) -> AppState {
    AppState::with_db(app_role_pool(pool).await, config())
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

fn v(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_string()).collect()
}

/// Arm (or disarm) the switch, as the harness (superuser, a maintenance
/// session for 128's setter).
async fn set_armed(pool: &PgPool, armed: bool) {
    sqlx::query(
        "SELECT * FROM public.epigraph_set_admin_scope_enforcement($1, 'admin_scope_mint')",
    )
    .bind(armed)
    .execute(pool)
    .await
    .expect("set the switch");
}

/// The token's scopes, sorted, and the response's `scope`, split and sorted.
fn minted(jwt: &JwtConfig, body: &Value) -> (Vec<String>, Vec<String>) {
    let token = body["access_token"].as_str().expect("access_token");
    let claims: EpiGraphClaims = jwt
        .validate_token(token)
        .expect("the minted token validates");
    let mut scopes = claims.scopes;
    scopes.sort();
    let mut said: Vec<String> = body["scope"]
        .as_str()
        .unwrap_or_default()
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    said.sort();
    (scopes, said)
}

/// An armed mint: `claims:read` survives (so the strip is not "everything")
/// and `claims:admin` is gone from both the token and the response.
fn assert_stripped(jwt: &JwtConfig, body: &Value, what: &str) {
    let (token, said) = minted(jwt, body);
    assert_eq!(token, v(&["claims:read"]), "{what}: token scopes");
    assert_eq!(said, v(&["claims:read"]), "{what}: response scope");
}

/// An unarmed mint: both kept.
fn assert_kept(jwt: &JwtConfig, body: &Value, what: &str) {
    let (token, said) = minted(jwt, body);
    assert_eq!(
        token,
        v(&["claims:admin", "claims:read"]),
        "{what}: token scopes"
    );
    assert_eq!(
        said,
        v(&["claims:admin", "claims:read"]),
        "{what}: response scope"
    );
}

/// `(grant, scopes)` of every would-strip event naming `client`.
async fn would_strip(pool: &PgPool, client: Uuid) -> Vec<(String, Value)> {
    sqlx::query_as(
        "SELECT details->>'grant', details->'scopes' FROM security_events \
          WHERE event_type = 'oauth.admin_scope_would_strip' AND details->>'client' = $1",
    )
    .bind(client.to_string())
    .fetch_all(pool)
    .await
    .expect("would-strip events")
}

async fn granted_of(pool: &PgPool, client: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT granted_scopes FROM oauth_clients WHERE id = $1")
        .bind(client)
        .fetch_one(pool)
        .await
        .expect("granted_scopes")
}

// ── The authorization-code exchange and the refresh grant ────────────────────

/// An active human client holding `HELD`, plus one authorization code for it
/// consented with `HELD`. Returns `(row id, client_id, code)`.
async fn seed_code(pool: &PgPool) -> (Uuid, String, String) {
    let unique = Uuid::new_v4().simple().to_string();
    let client_id = format!("el9_{unique}");
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        None,
        "el9 connector",
        "human",
        &v(HELD),
        &v(HELD),
        "active",
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("seed client");
    let code = format!("code_{unique}");
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(VERIFIER.as_bytes()));
    AuthorizationCodeRepository::create(
        pool,
        blake3::hash(code.as_bytes()).as_bytes(),
        &client_id,
        id,
        REDIRECT_URI,
        &challenge,
        &v(HELD),
        None,
        chrono::Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("seed code");
    (id, client_id, code)
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

fn refresh_grant(token: &str) -> Value {
    json!({ "grant_type": "refresh_token", "refresh_token": token })
}

/// Armed, the code exchange mints without `claims:admin` although the code
/// was consented with it.
///
/// Catches: `handle_authorization_code` minting `row.scopes` (the code's
/// consented set) without the chokepoint.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_code_exchange_strips_admin_scopes(pool: PgPool) {
    let (_, client_id, code) = seed_code(&pool).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let (status, body) = post_json(
        create_router(st),
        "/oauth/token",
        code_grant(&code, &client_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    assert_stripped(&jwt, &body, "authorization_code");
}

/// Armed, the refresh grant mints without `claims:admin` although the
/// client's `granted_scopes` (which the refresh grant re-reads) still hold it.
///
/// Catches: `handle_refresh_token` minting `client.granted_scopes` without
/// the chokepoint.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_refresh_grant_strips_admin_scopes(pool: PgPool) {
    let (id, client_id, code) = seed_code(&pool).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let (status, body) =
        post_json(app.clone(), "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    let refresh = body["refresh_token"].as_str().expect("refresh").to_string();
    assert!(
        granted_of(&pool, id)
            .await
            .contains(&"claims:admin".to_string()),
        "PREMISE: the client still holds claims:admin"
    );
    let (status, body) = post_json(app, "/oauth/token", refresh_grant(&refresh)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_stripped(&jwt, &body, "refresh_token");
}

// ── The client-credentials grant ─────────────────────────────────────────────

/// An agent row for `key` with an ACTIVE agent client holding `HELD` (and the
/// human owner client `agents_must_have_owner` requires). Returns
/// `(row id, client_id)`.
async fn agent_client(pool: &PgPool, key: &SigningKey) -> (Uuid, String) {
    let public_key = key.verifying_key().to_bytes();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(public_key.to_vec())
        .execute(pool)
        .await
        .expect("agent row");
    let owner: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status) \
         VALUES ($1, 'owner', 'human', ARRAY['claims:read'], ARRAY['claims:read'], 'active') \
         RETURNING id",
    )
    .bind(format!("owner-{agent}"))
    .fetch_one(pool)
    .await
    .expect("owner client");
    let client_id = hex::encode(public_key);
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_clients (client_id, client_name, client_type, allowed_scopes, \
                                    granted_scopes, status, agent_id, owner_id) \
         VALUES ($1, 'el9-agent', 'agent', $2, $2, 'active', $3, $4) RETURNING id",
    )
    .bind(&client_id)
    .bind(v(HELD))
    .bind(agent)
    .bind(owner)
    .fetch_one(pool)
    .await
    .expect("agent client");
    (id, client_id)
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

/// Armed, an agent's client-credentials grant mints without `claims:admin`.
///
/// Catches: `handle_client_credentials` minting the requested/granted
/// intersection without the chokepoint (agent arm).
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_agent_client_credentials_grant_strips_admin_scopes(pool: PgPool) {
    let key = SigningKey::from_bytes(&[0x61; 32]);
    let (_, client_id) = agent_client(&pool, &key).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let (status, body) = post_json(
        create_router(st),
        "/oauth/token",
        agent_grant(&client_id, &key),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "agent grant: {body}");
    assert_stripped(&jwt, &body, "client_credentials (agent)");
}

/// An active SERVICE client holding `HELD`, with a secret. Returns
/// `(row id, client_id, secret hex)`.
async fn service_client(pool: &PgPool) -> (Uuid, String, String) {
    let secret: [u8; 32] = rand::random();
    let client_id = format!("el9_svc_{}", Uuid::new_v4().simple());
    let id = OAuthClientRepository::create(
        pool,
        &client_id,
        Some(blake3::hash(&secret).as_bytes()),
        "el9 service",
        "service",
        &v(HELD),
        &v(HELD),
        "active",
        None,
        None,
        Some("EL9 Test Org"),
        Some("el9@example.com"),
        None,
    )
    .await
    .expect("service client");
    (id, client_id, hex::encode(secret))
}

fn service_grant(client_id: &str, secret: &str) -> Value {
    json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    })
}

/// Armed, a service's client-credentials grant mints without `claims:admin`.
///
/// Catches: `handle_client_credentials` minting without the chokepoint
/// (service arm; the same handler as the agent arm, a separate fixture).
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_service_client_credentials_grant_strips_admin_scopes(pool: PgPool) {
    let (_, client_id, secret) = service_client(&pool).await;
    set_armed(&pool, true).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let (status, body) = post_json(
        create_router(st),
        "/oauth/token",
        service_grant(&client_id, &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "service grant: {body}");
    assert_stripped(&jwt, &body, "client_credentials (service)");
}

// ── External identity providers: the assertion grant and the redirect exchange

/// A google provider whose auto-provisioned clients hold `HELD` and whose
/// token endpoint is `fx`'s mock (`/token`).
fn google_registry(fx: &ProviderFixture, tag: &str) -> Arc<ProviderRegistry> {
    let cid_var = format!("ADMIN_SCOPE_MINT_{tag}_GOOGLE_CLIENT_ID");
    let sec_var = format!("ADMIN_SCOPE_MINT_{tag}_GOOGLE_CLIENT_SECRET");
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

fn id_token(fx: &ProviderFixture, subject: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    fx.sign(&json!({
        "iss": "https://accounts.google.com",
        "aud": "test-audience",
        "sub": subject,
        "email": format!("{subject}@example.com"),
        "email_verified": true,
        "name": subject,
        "iat": now,
        "exp": now + 600,
    }))
}

/// The provisioned client for `subject` (`google:<subject>`).
async fn provisioned(pool: &PgPool, subject: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM oauth_clients WHERE client_id = $1")
        .bind(format!("google:{subject}"))
        .fetch_one(pool)
        .await
        .expect("the provisioned client")
}

/// Armed, an external provider's assertion grant mints without
/// `claims:admin` for a client provisioned holding it.
///
/// Catches: `provision_external_user` minting without the chokepoint, as
/// reached from the token endpoint's provider grant.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_external_assertion_grant_strips_admin_scopes(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    set_armed(&pool, true).await;
    let st = state(&pool)
        .await
        .with_providers(google_registry(&fx, "EXT"));
    let jwt = st.jwt_config.clone();
    let (status, body) = post_json(
        create_router(st),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": id_token(&fx, "el9-ext") }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "external grant: {body}");
    let client = provisioned(&pool, "el9-ext").await;
    assert!(
        granted_of(&pool, client)
            .await
            .contains(&"claims:admin".to_string()),
        "PREMISE: the provisioned client holds claims:admin"
    );
    assert_stripped(&jwt, &body, "external assertion");
}

/// Mount the provider token endpoint: any code exchanges for `id_token`.
async fn mount_token_endpoint(fx: &ProviderFixture, id_token: &str) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id_token": id_token })))
        .mount(&fx.mock_server)
        .await;
}

fn exchange_body() -> Value {
    json!({
        "code": "el9-auth-code",
        "code_verifier": VERIFIER,
        "redirect_uri": "http://localhost:9999/callback",
    })
}

/// Armed, the browser redirect exchange (`POST /oauth/google/exchange`, the
/// plan's "device" mint) mints without `claims:admin`.
///
/// Catches: the exchange route's mint bypassing the chokepoint (its own
/// grant label, `device`, is what the unarmed test tells apart from the
/// assertion grant).
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_redirect_exchange_strips_admin_scopes(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    mount_token_endpoint(&fx, &id_token(&fx, "el9-dev")).await;
    set_armed(&pool, true).await;
    let st = state(&pool)
        .await
        .with_providers(google_registry(&fx, "DEV"));
    let jwt = st.jwt_config.clone();
    let (status, body) =
        post_json(create_router(st), "/oauth/google/exchange", exchange_body()).await;
    assert_eq!(status, StatusCode::OK, "redirect exchange: {body}");
    let client = provisioned(&pool, "el9-dev").await;
    assert!(
        granted_of(&pool, client)
            .await
            .contains(&"claims:admin".to_string()),
        "PREMISE: the provisioned client holds claims:admin"
    );
    assert_stripped(&jwt, &body, "redirect exchange");
}

// ── Unarmed: kept, and measured ──────────────────────────────────────────────

/// UNARMED (the shipped state), every grant keeps `claims:admin`, and the
/// database records exactly ONE would-strip event per client, naming the
/// grant that minted first and the admin-only scopes only (a second mint of
/// the same client inside the hour, here the refresh after the code
/// exchange, adds none).
///
/// Catches: the unarmed branch stripping; the measurement not recorded (or
/// recorded with the wrong grant label: the assertion grant and the redirect
/// exchange share `provision_external_user`, and each must say which it was);
/// the measurement naming non-admin scopes.
#[sqlx::test(migrations = "../../migrations")]
async fn unarmed_every_grant_keeps_admin_scopes_and_is_measured_once_per_client(pool: PgPool) {
    let fx = ProviderFixture::new().await;
    mount_token_endpoint(&fx, &id_token(&fx, "el9-u-dev")).await;
    let st = state(&pool)
        .await
        .with_providers(google_registry(&fx, "UNARMED"));
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let admin_only = json!(["claims:admin"]);

    // Code exchange, then refresh, on one client.
    let (code_client, client_id, code) = seed_code(&pool).await;
    let (status, body) =
        post_json(app.clone(), "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code grant: {body}");
    assert_kept(&jwt, &body, "authorization_code");
    let refresh = body["refresh_token"].as_str().expect("refresh").to_string();
    let (status, body) = post_json(app.clone(), "/oauth/token", refresh_grant(&refresh)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    assert_kept(&jwt, &body, "refresh_token");
    assert_eq!(
        would_strip(&pool, code_client).await,
        vec![("authorization_code".to_string(), admin_only.clone())],
        "one event for the client, from the first mint"
    );

    // A refresh on a fresh client (its refresh token seeded directly, so the
    // refresh grant is its first mint) records under its own label.
    let (refresh_client, _, _) = seed_code(&pool).await;
    let raw: [u8; 32] = rand::random();
    epigraph_db::repos::refresh_token::RefreshTokenRepository::create(
        &pool,
        blake3::hash(&raw).as_bytes(),
        refresh_client,
        &v(HELD),
        chrono::Utc::now() + Duration::days(1),
    )
    .await
    .expect("seed a refresh token");
    let (status, body) = post_json(
        app.clone(),
        "/oauth/token",
        refresh_grant(&hex::encode(raw)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "refresh_token");
    assert_eq!(
        would_strip(&pool, refresh_client).await,
        vec![("refresh_token".to_string(), admin_only.clone())]
    );

    // Agent and service client credentials.
    let key = SigningKey::from_bytes(&[0x62; 32]);
    let (agent, client_id) = agent_client(&pool, &key).await;
    let (status, body) =
        post_json(app.clone(), "/oauth/token", agent_grant(&client_id, &key)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "client_credentials (agent)");
    assert_eq!(
        would_strip(&pool, agent).await,
        vec![("client_credentials".to_string(), admin_only.clone())]
    );
    let (service, client_id, secret) = service_client(&pool).await;
    let (status, body) = post_json(
        app.clone(),
        "/oauth/token",
        service_grant(&client_id, &secret),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "client_credentials (service)");
    assert_eq!(
        would_strip(&pool, service).await,
        vec![("client_credentials".to_string(), admin_only.clone())]
    );

    // The external assertion grant and the redirect exchange.
    let (status, body) = post_json(
        app.clone(),
        "/oauth/token",
        json!({ "grant_type": "google_id_token", "assertion": id_token(&fx, "el9-u-ext") }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "external assertion");
    assert_eq!(
        would_strip(&pool, provisioned(&pool, "el9-u-ext").await).await,
        vec![("external_assertion".to_string(), admin_only.clone())]
    );
    let (status, body) = post_json(app, "/oauth/google/exchange", exchange_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "redirect exchange");
    assert_eq!(
        would_strip(&pool, provisioned(&pool, "el9-u-dev").await).await,
        vec![("device".to_string(), admin_only)]
    );
}

// ── Failure modes of the switch read ─────────────────────────────────────────

/// A switch the application role cannot READ (EXECUTE revoked) is not
/// "unarmed": the mint strips (fail closed). A database WITHOUT the switch
/// (128's function dropped) cannot have been armed: the mint keeps, and
/// records nothing.
///
/// Catches: the chokepoint treating every read error as unarmed (the revoked
/// read keeps `claims:admin`), and treating a missing switch as an error (the
/// dropped switch strips).
#[sqlx::test(migrations = "../../migrations")]
async fn an_unreadable_switch_strips_and_a_missing_one_keeps(pool: PgPool) {
    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION public.epigraph_admin_scopes_armed() FROM epigraph_app",
    )
    .execute(&pool)
    .await
    .expect("revoke");
    let (_, client_id, code) = seed_code(&pool).await;
    let st = state(&pool).await;
    let jwt = st.jwt_config.clone();
    let app = create_router(st);
    let (status, body) =
        post_json(app.clone(), "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_stripped(&jwt, &body, "unreadable switch");

    sqlx::query("DROP FUNCTION public.epigraph_admin_scopes_armed() CASCADE")
        .execute(&pool)
        .await
        .expect("drop the switch read");
    let (client, client_id, code) = seed_code(&pool).await;
    let (status, body) = post_json(app, "/oauth/token", code_grant(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_kept(&jwt, &body, "missing switch");
    assert!(
        would_strip(&pool, client).await.is_empty(),
        "a database without the switch records no measurement"
    );
}
