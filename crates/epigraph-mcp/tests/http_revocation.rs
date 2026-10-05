//! A revoked access token is refused on the MCP HTTP transport (review finding
//! on epigraph#282, drain unit U003).
//!
//! `POST /oauth/revoke` on the HTTP API used to record a revoked access token
//! only in that API process's memory, and `bearer_auth_middleware` here never
//! consulted any revocation state: a revoked `claims:write` or `claims:admin`
//! token kept working on MCP (`:3101`, the production transport) until its
//! natural expiry. Migration 141 makes the revocation durable (a `jti`
//! denylist); this suite pins that the MCP middleware reads it.
//!
//! The listener is built the way `main.rs` builds a `--jwt-secret` one: the
//! real rmcp service behind `bearer_auth_middleware`, with the production
//! `DbAccessTokenRevocation`. Its pool runs as `epigraph_app`, the deployed
//! application role, so the suite also proves that role may read the denylist.
//!
//! Every refusal is preceded by a CONTROL showing the same token was admitted
//! before it was revoked, and the per-token test also shows a second token of
//! the same client stays admitted, so a middleware that refused everything (or
//! every token of the client) would fail.

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use epigraph_auth::JwtConfig;
use epigraph_db::RevokedAccessTokenRepository;
use epigraph_mcp::auth::{
    bearer_auth_middleware, AccessTokenRevocation, DbAccessTokenRevocation, McpAuthState,
};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "support/static_revocation.rs"]
mod static_revocation;

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";

/// A `claims:write` token for `client`: `(token, jti, exp)`.
fn mint(client: Uuid) -> (String, Uuid, chrono::DateTime<Utc>) {
    let cfg = JwtConfig::from_secret(SECRET);
    let (token, jti) = cfg
        .issue_access_token(
            client,
            vec!["claims:read".to_string(), "claims:write".to_string()],
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .expect("mint");
    let exp = cfg.validate_token(&token).expect("own token validates").exp;
    (
        token,
        jti,
        Utc.timestamp_opt(exp, 0)
            .single()
            .expect("exp is a timestamp"),
    )
}

/// The `--jwt-secret` listener over `pool`, with `revocation` in front.
async fn spawn_listener(pool: PgPool, revocation: Arc<dyn AccessTokenRevocation>) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        revocation,
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}/mcp")
}

fn initialize_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "http-revocation-test", "version": "0.1.0" }
        }
    })
}

/// POST `body` with `token`, on `session` when given. Returns the status, the
/// `WWW-Authenticate` header, and the session id the server assigned (if any).
/// The response body is dropped unread, which frees the connection.
async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> (u16, Option<String>, Option<String>) {
    let mut req = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    let resp = req.send().await.expect("POST");
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    (
        resp.status().as_u16(),
        header("www-authenticate"),
        header(SESSION_HEADER),
    )
}

fn assert_invalid_token(status: u16, challenge: Option<&str>, what: &str) {
    assert_eq!(status, 401, "{what}: the token must be refused");
    let challenge = challenge.unwrap_or_else(|| panic!("{what}: 401 without a challenge"));
    assert!(
        challenge.contains(r#"error="invalid_token""#),
        "{what}: the refusal is RFC 6750 invalid_token, got {challenge}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_access_token_is_refused_on_mcp(pool: PgPool) {
    let app_pool = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let url = spawn_listener(
        pool.clone(),
        Arc::new(DbAccessTokenRevocation::new(app_pool)),
    )
    .await;
    let http = reqwest::Client::new();
    let client_id = Uuid::new_v4();
    let (token, jti, exp) = mint(client_id);
    let (other, _, _) = mint(client_id);

    // CONTROL: before revocation the token opens a session.
    let (status, _, session) = post(&http, &url, &token, None, initialize_body()).await;
    assert_eq!(status, 200, "control: an unrevoked token is admitted");
    let session = session.expect("initialize assigns a session id");

    // Revoke it the way /oauth/revoke does.
    RevokedAccessTokenRepository::revoke(&pool, jti, client_id, exp)
        .await
        .expect("revoke");

    // A new session with the revoked token is refused...
    let (status, challenge, _) = post(&http, &url, &token, None, initialize_body()).await;
    assert_invalid_token(status, challenge.as_deref(), "initialize after revoke");

    // ...and so is the session it opened BEFORE the revocation: the check runs
    // per request, not once per session.
    let (status, challenge, _) = post(
        &http,
        &url,
        &token,
        Some(&session),
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;
    assert_invalid_token(
        status,
        challenge.as_deref(),
        "existing session after revoke",
    );

    // Per token, not per client: a second token of the same client still works.
    let (status, _, _) = post(&http, &url, &other, None, initialize_body()).await;
    assert_eq!(
        status, 200,
        "revoking one jti must not refuse the client's other tokens"
    );
}

/// A store that cannot answer fails CLOSED: a valid, unrevoked token is
/// refused with the same uniform `invalid_token`, never passed through.
#[tokio::test]
async fn an_unavailable_revocation_store_fails_closed() {
    // A dead pool: nothing below the middleware may be reached anyway.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");
    let http = reqwest::Client::new();
    let (token, _, _) = mint(Uuid::new_v4());

    // CONTROL: the same token, same listener shape, admitted when the store answers.
    let open = spawn_listener(pool.clone(), static_revocation::StaticRevocation::none()).await;
    let (status, _, _) = post(&http, &open, &token, None, initialize_body()).await;
    assert_eq!(status, 200, "control: the token is valid");

    let closed = spawn_listener(pool, static_revocation::StaticRevocation::unavailable()).await;
    let (status, challenge, _) = post(&http, &closed, &token, None, initialize_body()).await;
    assert_invalid_token(status, challenge.as_deref(), "store unavailable");
}
