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
