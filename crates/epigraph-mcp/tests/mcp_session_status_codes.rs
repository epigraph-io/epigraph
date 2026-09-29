//! Session-lifecycle status codes on the MCP streamable-HTTP listener.
//!
//! The defect (rmcp 0.15.0, `transport/streamable_http_server/tower.rs`): a
//! request carrying an `Mcp-Session-Id` the in-memory session manager does not
//! know — which is EVERY client's session after a server restart — got
//! `401 Unauthorized: Session not found`. OAuth MCP clients read a 401 as an
//! invalid credential, discard the token and demand an interactive re-auth,
//! so agents could not reconnect. The MCP spec (2025-03-26 streamable HTTP)
//! requires 404, on which the client re-initializes with the token it holds.
//! Siblings: an ended session got a 500, a no-session non-initialize POST a 422.
//!
//! The listener is built through `epigraph_mcp::session_status::nest_mcp_service`
//! — the same function `main.rs` uses — wrapped by the real bearer-auth and
//! Host/Origin layers in production order, and served on an ephemeral socket.
//! The pool is lazy against an unreachable URL: nothing here reaches the DB.
//!
//! Load-bearing check: comment out the `.layer(...)` in `nest_mcp_service` and
//! the integration tests below fail with the old 401 / 500 / 422.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header::WWW_AUTHENTICATE, HeaderMap, HeaderValue, StatusCode};
use chrono::Duration as ChronoDuration;
use epigraph_auth::JwtConfig;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use epigraph_mcp::session_status::{
    rewrite_rmcp_session_status, rmcp_session_status_rewrite, MAX_INSPECTED_BODY,
    RMCP_EXPECT_INITIALIZE_BODY, RMCP_SESSION_NOT_FOUND_BODY,
};
use rmcp::transport::streamable_http_server::session::local::{
    create_local_session, LocalSessionManager, SessionConfig,
};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use uuid::Uuid;

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
const WRONG_SECRET: &[u8] = b"a-completely-different-32-byte-key!!xx";
const RESOURCE_METADATA_URL: &str = "https://mcp.example.test/.well-known/oauth-protected-resource";

const ACCEPT_POST: &str = "application/json, text/event-stream";
const ACCEPT_SSE: &str = "text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";

// ── Harness ───────────────────────────────────────────────────────────────

fn mint_token(secret: &[u8]) -> String {
    let (token, _) = JwtConfig::from_secret(secret)
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .unwrap();
    token
}

struct Server {
    url: String,
    /// The listener's own session manager, so a test can plant a session whose
    /// worker has ended (the 500 path) without waiting on timers.
    sessions: Arc<LocalSessionManager>,
}

/// Build the listener exactly as `main.rs` does for a `--jwt-secret` TCP
/// listener: rmcp service → `nest_mcp_service` (session-status rewrite,
/// innermost) → bearer auth → Host/Origin guard (outermost).
async fn spawn_server() -> Server {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    let sessions = Arc::new(LocalSessionManager::default());

    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            ))
        },
        sessions.clone(),
        StreamableHttpServerConfig::default(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let router = epigraph_mcp::session_status::nest_mcp_service(service)
        .layer(axum::middleware::from_fn_with_state(
            McpAuthState {
                jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
                resource_metadata_url: Some(RESOURCE_METADATA_URL.to_string()),
            },
            bearer_auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            epigraph_mcp::host_guard::HostAllowlist::for_tcp_listener(&addr.to_string(), &[]),
            epigraph_mcp::host_guard::host_guard_middleware,
        ));

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Server {
        url: format!("http://{addr}/mcp"),
        sessions,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

fn initialize_body() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "session-status-test", "version": "0.1.0"}
        }
    })
}

fn tools_list_body() -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
}

/// Read SSE chunks until a non-empty `data:` line or the deadline.
async fn read_sse_data(resp: &mut reqwest::Response) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut acc = String::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.push_str(&String::from_utf8_lossy(&bytes));
        if acc
            .lines()
            .any(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            break;
        }
    }
    acc
}

/// POST a JSON-RPC message with the given bearer and optional session id.
async fn post(
    c: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    session: Option<&str>,
    body: &serde_json::Value,
) -> reqwest::Response {
    let mut req = c
        .post(url)
        .header("Accept", ACCEPT_POST)
        .header("Content-Type", "application/json")
        .json(body);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST failed")
}

/// GET the standalone SSE stream for `session`.
async fn get_stream(
    c: &reqwest::Client,
    url: &str,
    token: &str,
    session: &str,
) -> reqwest::Response {
    c.get(url)
        .header("Accept", ACCEPT_SSE)
        .header("Authorization", format!("Bearer {token}"))
        .header(SESSION_HEADER, session)
        .send()
        .await
        .expect("GET failed")
}

/// Initialize a session; assert 200 + a session id + an initialize result.
async fn initialize(c: &reqwest::Client, url: &str, token: &str) -> String {
    let mut resp = post(c, url, Some(token), None, &initialize_body()).await;
    assert_eq!(resp.status(), StatusCode::OK, "initialize must succeed");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("initialize response carries Mcp-Session-Id")
        .to_str()
        .unwrap()
        .to_owned();
    let data = read_sse_data(&mut resp).await;
    assert!(
        data.contains("\"serverInfo\""),
        "initialize must return an InitializeResult, got: {data}"
    );
    session
}

/// The status of a response plus its body text, for failure messages.
async fn status_and_body(resp: reqwest::Response) -> (StatusCode, HeaderMap, String) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();
    (status, headers, body)
}

// ── Integration: the listener ────────────────────────────────────────────

#[tokio::test]
async fn initialize_succeeds() {
    let s = spawn_server().await;
    let session = initialize(&client(), &s.url, &mint_token(SECRET)).await;
    assert!(!session.is_empty());
}

/// THE recovery path. After a restart a client holds a never-issued (to this
/// process) session id and a still-valid bearer: it must get 404 — on POST and
/// on the GET stream — and a re-initialize with the SAME bearer must succeed.
#[tokio::test]
async fn unknown_session_gets_404_and_reinitialize_with_same_bearer_succeeds() {
    let s = spawn_server().await;
    let c = client();
    let token = mint_token(SECRET);
    let stale = Uuid::new_v4().to_string();

    let (status, headers, body) =
        status_and_body(post(&c, &s.url, Some(&token), Some(&stale), &tools_list_body()).await)
            .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "POST with an unknown session id must be 404 (was rmcp's 401), body: {body}"
    );
    assert!(
        !headers.contains_key(WWW_AUTHENTICATE),
        "a session 404 must not carry an auth challenge"
    );

    let (status, _, body) = status_and_body(get_stream(&c, &s.url, &token, &stale).await).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "GET stream with an unknown session id must be 404 (was rmcp's 401), body: {body}"
    );

    // Recovery: same bearer, fresh initialize, then the new session works.
    let fresh = initialize(&c, &s.url, &token).await;
    assert_ne!(fresh, stale);
    let resp = post(
        &c,
        &s.url,
        Some(&token),
        Some(&fresh),
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "the re-initialized session must accept traffic"
    );
}

/// A session the client itself terminated (DELETE) is unknown afterwards.
#[tokio::test]
async fn deleted_session_gets_404() {
    let s = spawn_server().await;
    let c = client();
    let token = mint_token(SECRET);
    let session = initialize(&c, &s.url, &token).await;

    let del = c
        .delete(&s.url)
        .header("Authorization", format!("Bearer {token}"))
        .header(SESSION_HEADER, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status(),
        StatusCode::ACCEPTED,
        "DELETE closes the session"
    );

    let (status, _, body) =
        status_and_body(post(&c, &s.url, Some(&token), Some(&session), &tools_list_body()).await)
            .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "POST on an ended session must be 404, body: {body}"
    );
}

/// A session still registered but whose worker has ended — the window between
/// a worker dying and rmcp's `close_session` cleanup. rmcp 0.15 answered 500
/// "Encounter an error when get session: Session error: Session service
/// terminated" (POST) and "… create standalone stream …" (GET).
#[tokio::test]
async fn session_whose_worker_ended_gets_404() {
    let s = spawn_server().await;
    let c = client();
    let token = mint_token(SECRET);

    let id = format!("ended-{}", Uuid::new_v4());
    let (handle, worker) = create_local_session(id.clone(), SessionConfig::default());
    s.sessions
        .sessions
        .write()
        .await
        .insert(id.clone().into(), handle);
    // The worker owns the receiving end of the handle's channel; dropping it
    // without spawning is exactly "the session service terminated".
    drop(worker);

    let (status, _, body) =
        status_and_body(post(&c, &s.url, Some(&token), Some(&id), &tools_list_body()).await).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "POST request on a terminated session must be 404 (was rmcp's 500), body: {body}"
    );
    assert!(
        body.contains("Session service terminated"),
        "the original rmcp body is kept, got: {body}"
    );

    let (status, _, body) = status_and_body(
        post(
            &c,
            &s.url,
            Some(&token),
            Some(&id),
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "POST notification on a terminated session must be 404 (was rmcp's 500), body: {body}"
    );

    let (status, _, body) = status_and_body(get_stream(&c, &s.url, &token, &id).await).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "GET stream on a terminated session must be 404 (was rmcp's 500), body: {body}"
    );
}

#[tokio::test]
async fn non_initialize_post_without_session_gets_400() {
    let s = spawn_server().await;
    let (status, _, body) = status_and_body(
        post(
            &client(),
            &s.url,
            Some(&mint_token(SECRET)),
            None,
            &tools_list_body(),
        )
        .await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "non-initialize POST without a session must be 400 (was rmcp's 422), body: {body}"
    );
    assert_eq!(body, RMCP_EXPECT_INITIALIZE_BODY, "body text is kept");
}

/// Our own authentication 401s are untouched and keep their RFC 9728
/// challenge — including when the request ALSO carries a stale session id,
/// where auth must win (a bad credential really is a re-auth).
#[tokio::test]
async fn missing_or_invalid_bearer_still_gets_401_with_challenge() {
    let s = spawn_server().await;
    let c = client();
    let stale = Uuid::new_v4().to_string();
    let bad = mint_token(WRONG_SECRET);

    for (label, token, session) in [
        ("missing bearer", None, None),
        ("invalid bearer", Some(bad.as_str()), None),
        (
            "invalid bearer + stale session",
            Some(bad.as_str()),
            Some(stale.as_str()),
        ),
        ("missing bearer + stale session", None, Some(stale.as_str())),
    ] {
        let (status, headers, body) =
            status_and_body(post(&c, &s.url, token, session, &tools_list_body()).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{label}: body {body}");
        let challenge = headers
            .get(WWW_AUTHENTICATE)
            .unwrap_or_else(|| panic!("{label}: 401 must carry WWW-Authenticate"))
            .to_str()
            .unwrap();
        assert!(
            challenge.starts_with("Bearer ") && challenge.contains("resource_metadata="),
            "{label}: challenge was {challenge}"
        );
    }
}

// ── Unit: the discriminator ──────────────────────────────────────────────

async fn body_bytes(resp: axum::response::Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 16).await.unwrap();
    (parts.status, parts.headers, bytes.to_vec())
}

#[tokio::test]
async fn discriminator_never_rewrites_our_auth_401s() {
    for url in [None, Some(RESOURCE_METADATA_URL)] {
        let (status, headers, body) =
            body_bytes(epigraph_mcp::auth::unauthorized(url, "invalid_token")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            rmcp_session_status_rewrite(status, &headers, &body),
            None,
            "auth::unauthorized({url:?}) must never be rewritten"
        );
    }
}

/// The header check does real work, not just the body match: rmcp's exact
/// body, but WITH a challenge, is treated as an auth 401 and left alone.
#[test]
fn discriminator_requires_absent_www_authenticate() {
    let mut challenged = HeaderMap::new();
    challenged.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    let body = RMCP_SESSION_NOT_FOUND_BODY.as_bytes();

    assert_eq!(
        rmcp_session_status_rewrite(StatusCode::UNAUTHORIZED, &challenged, body),
        None
    );
    assert_eq!(
        rmcp_session_status_rewrite(StatusCode::UNAUTHORIZED, &HeaderMap::new(), body),
        Some(StatusCode::NOT_FOUND)
    );
}

#[test]
fn discriminator_table() {
    let none = HeaderMap::new();
    let cases: &[(StatusCode, &str, Option<StatusCode>)] = &[
        // rewritten
        (StatusCode::UNAUTHORIZED, "Unauthorized: Session not found", Some(StatusCode::NOT_FOUND)),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Encounter an error when get session: Session error: Session service terminated",
            Some(StatusCode::NOT_FOUND),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Encounter an error when create standalone stream: Session error: Session service terminated",
            Some(StatusCode::NOT_FOUND),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Encounter an error when get session: Session not found: abc",
            Some(StatusCode::NOT_FOUND),
        ),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unexpected message, expect initialize request",
            Some(StatusCode::BAD_REQUEST),
        ),
        // left alone
        (StatusCode::UNAUTHORIZED, "Unauthorized", None),
        (StatusCode::UNAUTHORIZED, "Unauthorized: Session ID is required", None),
        (StatusCode::UNAUTHORIZED, "Unauthorized: Session not found (extra)", None),
        (StatusCode::INTERNAL_SERVER_ERROR, "Encounter an error when get service: boom", None),
        (StatusCode::INTERNAL_SERVER_ERROR, "Session service terminated", None),
        (StatusCode::UNPROCESSABLE_ENTITY, "Unexpected message, expect something else", None),
        (StatusCode::OK, "Unauthorized: Session not found", None),
        (StatusCode::FORBIDDEN, "Forbidden: Host not allowed", None),
    ];
    for (status, body, want) in cases {
        assert_eq!(
            rmcp_session_status_rewrite(*status, &none, body.as_bytes()),
            *want,
            "{status} {body:?}"
        );
    }
}

/// The buffering guard: a body larger than `MAX_INSPECTED_BODY` is passed
/// through unbuffered and untouched, even though its text WOULD match the 500
/// rule if it were read. (The same guard arm refuses a body with no exact size,
/// i.e. any stream; this crate has no `Stream` impl to hand to `Body::from_stream`
/// without a new dependency, so the oversize case stands in for it.)
#[tokio::test]
async fn oversized_body_is_never_buffered_or_rewritten() {
    use tower::ServiceExt;

    let body = format!(
        "Encounter an error when get session: Session service terminated{}",
        " ".repeat(usize::try_from(MAX_INSPECTED_BODY).unwrap())
    );
    assert_eq!(
        rmcp_session_status_rewrite(
            StatusCode::INTERNAL_SERVER_ERROR,
            &HeaderMap::new(),
            body.as_bytes()
        ),
        Some(StatusCode::NOT_FOUND),
        "precondition: the text alone would be rewritten"
    );

    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(move || async move { (StatusCode::INTERNAL_SERVER_ERROR, body) }),
        )
        .layer(axum::middleware::from_fn(rewrite_rmcp_session_status));

    let resp = app
        .oneshot(axum::http::Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
