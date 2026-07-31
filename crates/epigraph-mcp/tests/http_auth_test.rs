//! End-to-end test of the Bearer-auth + scope-guard pipeline on the MCP HTTP
//! transport. Asserts the four cases the issue cares about:
//! 1. No Authorization header → 401.
//! 2. Bad signature → 401.
//! 3. Valid token, wrong scope → JSON-RPC error citing the required scope.
//! 4. Valid token, right scope → auth pipeline passes (downstream DB failure
//!    is acceptable; the load-bearing assertion is "no auth-shaped error").
//!
//! Uses approach A (raw reqwest) for simplicity. Tests 1 and 2 do not need
//! a full MCP handshake — the Bearer middleware short-circuits before rmcp
//! ever sees the body. Tests 3 and 4 perform a complete handshake via three
//! sequential POSTs.
//!
//! Note: the pool is created with `connect_lazy` against a bogus URL so it
//! never opens a real connection. Auth rejection happens before any DB access
//! in the 401/403 cases. The 200-passes-auth case (test 4) will fail at the
//! DB layer, which is intentional — the test asserts the error is NOT
//! auth-shaped.

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use epigraph_auth::JwtConfig;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use uuid::Uuid;

// ── Constants ─────────────────────────────────────────────────────────────

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
const WRONG_SECRET: &[u8] = b"a-completely-different-32-byte-key!!xx";

// MCP requires these headers for POST /mcp.
const ACCEPT: &str = "application/json, text/event-stream";
const CONTENT_TYPE: &str = "application/json";
const SESSION_HEADER: &str = "Mcp-Session-Id";

// ── Helpers ────────────────────────────────────────────────────────────────

fn mint_token(secret: &[u8], scopes: &[&str]) -> String {
    let cfg = JwtConfig::from_secret(secret);
    let (token, _) = cfg
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .unwrap();
    token
}

/// Build the full axum router with bearer middleware around the MCP service.
/// Uses a lazy pool that never actually opens a DB connection.
async fn boot_router() -> axum::Router {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    // connect_lazy with a very short connect_timeout (100ms) so DB queries fail
    // fast. The 401/403 auth-rejection tests never touch the DB; test 4 is
    // allowed to fail at the DB layer — we just don't want it to hang for 30s.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");

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
    };

    axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(
            state,
            bearer_auth_middleware,
        ))
}

/// Bind an ephemeral TCP port and spawn the server. Returns the bound address.
async fn spawn_server() -> std::net::SocketAddr {
    let router = boot_router().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    // Brief yield so the spawned task reaches the accept loop.
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

/// Build a reqwest client WITHOUT a global timeout (we manage timeouts per-read).
/// A global timeout would abort before we can read incremental SSE chunks.
fn client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

/// Read SSE chunks until a non-empty `data:` line appears (the actual
/// JSON-RPC payload) or until the deadline elapses.
async fn read_sse_data(resp: &mut reqwest::Response, deadline: tokio::time::Instant) -> String {
    let mut accumulated = String::new();
    loop {
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    accumulated.push_str(text);
                }
                // Stop when we find a non-empty data line (skip priming `data: `).
                if accumulated
                    .lines()
                    .any(|l| l.starts_with("data:") && l.trim_end().len() > 5)
                {
                    break;
                }
            }
            // Stream closed or timed out — return what we have.
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(_)) => break,
        }
    }
    accumulated
}

/// Perform the full MCP handshake (initialize + notifications/initialized) and
/// return the session ID. Panics on unexpected failures.
async fn mcp_handshake(client: &reqwest::Client, url: &str, token: &str) -> String {
    let init_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "http-auth-test",
                "version": "0.1.0"
            }
        }
    });

    let mut resp = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .json(&init_body)
        .send()
        .await
        .expect("initialize POST failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "initialize should return 200 (auth passed)"
    );

    let session_id = resp
        .headers()
        .get(SESSION_HEADER)
        .unwrap_or_else(|| panic!("initialize response missing {SESSION_HEADER} header"))
        .to_str()
        .unwrap()
        .to_owned();

    // Consume the initialize SSE response until we get the actual result data.
    // This frees the connection so subsequent requests can proceed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let _ = read_sse_data(&mut resp, deadline).await;

    // Send notifications/initialized (a notification, not a request).
    let notif_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });

    let notif_resp = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .header(SESSION_HEADER, &session_id)
        .json(&notif_body)
        .send()
        .await
        .expect("notifications/initialized POST failed");

    assert_eq!(
        notif_resp.status().as_u16(),
        202,
        "notifications/initialized should return 202 Accepted"
    );

    session_id
}

/// POST a tools/call request and return the response body text.
///
/// Since rmcp responds with an open-ended SSE stream, we read the response
/// chunk-by-chunk until we accumulate a `data:` line (which carries the
/// JSON-RPC result/error) or until the stream closes / times out.
async fn call_tool(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session_id: &str,
    tool_name: &str,
    args: serde_json::Value,
) -> (u16, String) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": args
        }
    });

    let mut resp = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .header(SESSION_HEADER, session_id)
        .json(&body)
        .send()
        .await
        .expect("tools/call POST failed");

    let status = resp.status().as_u16();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let body_text = read_sse_data(&mut resp, deadline).await;
    (status, body_text)
}

// ─── Test 1: 401 missing header ────────────────────────────────────────────

#[tokio::test]
async fn missing_authorization_header_returns_401() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/mcp");

    // Send a valid MCP body but NO Authorization header. The Bearer middleware
    // must short-circuit before rmcp ever touches the body.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }
    });

    let resp = client()
        .post(&url)
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "missing Authorization header must yield 401"
    );
}

// ─── Test 2: 401 bad signature ─────────────────────────────────────────────

#[tokio::test]
async fn bad_signature_returns_401() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/mcp");

    // Token minted with a different secret — server must reject it.
    let token = mint_token(WRONG_SECRET, &["claims:read"]);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}
        }
    });

    let resp = client()
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .json(&body)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "token signed with wrong secret must yield 401"
    );
}

// ─── Test 3: wrong scope yields scope error ────────────────────────────────

#[tokio::test]
async fn wrong_scope_yields_scope_error() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/mcp");
    let c = client();

    // Token has claims:read but NOT claims:admin (required by mark_duplicate).
    let token = mint_token(SECRET, &["claims:read"]);

    let session_id = mcp_handshake(&c, &url, &token).await;

    let (_status, body) = call_tool(
        &c,
        &url,
        &token,
        &session_id,
        "mark_duplicate",
        serde_json::json!({
            "duplicate_id": "00000000-0000-0000-0000-000000000001",
            "canonical_id": "00000000-0000-0000-0000-000000000002"
        }),
    )
    .await;

    // The response is an SSE stream; parse all data: lines and look for
    // "claims:admin" in any of them.
    let found_scope_error = body
        .lines()
        .filter(|l| l.starts_with("data:"))
        .any(|l| l.contains("claims:admin"));

    assert!(
        found_scope_error,
        "expected 'claims:admin' in scope-error response, got: {body}"
    );
}

// ─── Test 4: right scope passes auth ──────────────────────────────────────

#[tokio::test]
async fn right_scope_passes_auth() {
    let addr = spawn_server().await;
    let url = format!("http://{addr}/mcp");
    let c = client();

    // Token has claims:read — the scope required by query_claims.
    let token = mint_token(SECRET, &["claims:read"]);

    let session_id = mcp_handshake(&c, &url, &token).await;

    let (_status, body) = call_tool(
        &c,
        &url,
        &token,
        &session_id,
        "query_claims",
        serde_json::json!({"query": "test"}),
    )
    .await;

    // Auth pipeline must have passed. The call WILL fail at the DB layer
    // (lazy pool, bogus URL) — but the error must NOT look like an auth
    // rejection. These strings appear only in the bearer/scope guard.
    let auth_strings = [
        "Unauthorized",
        "Forbidden",
        "Missing Authorization",
        "Invalid token",
        "claims:read", // scope guard reports the *required* scope on failure
        "auth context",
    ];
    for s in &auth_strings {
        assert!(
            !body.contains(s),
            "right-scope token must not produce auth error; found {s:?} in: {body}"
        );
    }
}

// ─── Test 5: --allow-unauthenticated-http actually allows tool calls ───────
// Backlog be2a3391: the flag started the HTTP listener but, because no
// AuthContext was injected, the per-tool scope gate 403'd every call with
// "no auth context" — so the listener accepted nothing. The fix injects a
// permissive context (auth::inject_unauthenticated_context); this test boots
// the router the way main.rs does for that flag and asserts a tool call is NOT
// auth-rejected.

/// MCP service wrapped in the permissive context-injection middleware
/// (no bearer auth) — mirrors main.rs's `--allow-unauthenticated-http` branch.
async fn boot_unauth_router() -> axum::Router {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };

    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors");
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

    axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn(
            epigraph_mcp::auth::inject_unauthenticated_context,
        ))
}

async fn spawn_unauth_server() -> std::net::SocketAddr {
    let router = boot_unauth_router().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn unauthenticated_http_passes_scope_gate() {
    let addr = spawn_unauth_server().await;
    let url = format!("http://{addr}/mcp");
    let c = client();

    // No real token; the inject middleware supplies a permissive context. The
    // handshake helper still sends a (now-ignored) Authorization header.
    let session_id = mcp_handshake(&c, &url, "unused-no-bearer").await;

    let (_status, body) = call_tool(
        &c,
        &url,
        "unused-no-bearer",
        &session_id,
        "query_claims",
        serde_json::json!({"query": "test"}),
    )
    .await;

    // The scope gate must NOT reject. The call WILL fail at the DB layer (lazy
    // bogus pool) — that's fine; we assert only that the failure is not
    // auth-shaped. Under the bug the body carried "no auth context" /
    // "requires scope 'claims:read'".
    let auth_strings = [
        "Unauthorized",
        "Forbidden",
        "no auth context",
        "requires scope",
    ];
    for s in &auth_strings {
        assert!(
            !body.contains(s),
            "--allow-unauthenticated-http must not auth-reject; found {s:?} in: {body}"
        );
    }
}

// ─── Tests 6-10: Host/Origin allowlist (DNS-rebinding guard) ──────────────
//
// The workspace pins rmcp 0.15, whose StreamableHttpServerConfig has no
// allowed_hosts/allowed_origins knob and which validates neither header (that
// landed in rmcp 1.4.0, CVE-2026-42559 class). A browser on the listener's host
// loading a hostile page whose DNS rebinds to 127.0.0.1:<port> could therefore
// reach /mcp and drive every tool. `host_guard` closes that at the header level.
//
// Driven through `tower::ServiceExt::oneshot` rather than a live socket: reqwest
// rewrites `Host` from the request URL, so a live-server test could not actually
// send the rebound header these cases turn on.

use epigraph_mcp::host_guard::{host_guard_middleware, HostAllowlist};
use tower::ServiceExt;

/// The name an operator would add for a reverse-proxied deployment (Caddy's
/// `reverse_proxy` forwards the client's original `Host`, so the public name
/// must be allowlisted or every proxied request 403s).
const PROXY_HOST: &str = "mcp.example.com";

/// Router shaped exactly like `main.rs`'s TCP branch: MCP service, then the
/// Bearer layer, then the Host guard applied LAST so it is OUTERMOST and runs
/// FIRST. The nesting order is load-bearing — a rebound request must be refused
/// on its headers before auth decides anything about it.
async fn boot_guarded_router() -> axum::Router {
    let allowlist = HostAllowlist::for_tcp_listener("127.0.0.1:3100", &[PROXY_HOST.to_string()]);
    boot_router()
        .await
        .layer(axum::middleware::from_fn_with_state(
            allowlist,
            host_guard_middleware,
        ))
}

/// A well-formed `initialize` POST with a caller-chosen `Host` (and optional
/// `Origin`) — i.e. exactly what a rebound browser tab would emit.
fn init_request(
    host: &str,
    origin: Option<&str>,
    bearer: Option<&str>,
) -> axum::http::Request<axum::body::Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "rebind-test", "version": "0.1"}
        }
    });
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", host)
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE);
    if let Some(origin) = origin {
        builder = builder.header("Origin", origin);
    }
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

async fn status_of(req: axum::http::Request<axum::body::Body>) -> u16 {
    boot_guarded_router()
        .await
        .oneshot(req)
        .await
        .expect("router is infallible")
        .status()
        .as_u16()
}

/// The attack, with a VALID credential: a rebound `Host` must be refused before
/// auth ever runs. Using a good token is what makes this test load-bearing —
/// with the guard removed this request returns 200 and a live MCP session, so a
/// 401-based assertion would not distinguish the fixed build from the broken one.
#[tokio::test]
async fn rebound_host_is_refused_even_with_a_valid_token() {
    let token = mint_token(SECRET, &["claims:read"]);
    assert_eq!(
        status_of(init_request("evil.example", None, Some(&token))).await,
        403,
        "a rebound Host must be refused outright, not handed a session"
    );
    // Fully-qualified spelling of the same name — the standard allowlist bypass.
    assert_eq!(
        status_of(init_request("evil.example.", None, Some(&token))).await,
        403
    );
}

/// The guard must not swallow the request pipeline: an allowlisted `Host`
/// reaches the Bearer layer, which then rejects the credential-less request with
/// 401 (NOT 403). This is the pairing that proves the 403 above came from the
/// Host check and that legitimate loopback traffic still flows.
#[tokio::test]
async fn allowlisted_hosts_fall_through_to_the_bearer_layer() {
    for host in ["127.0.0.1:3100", "localhost", "[::1]:3100", PROXY_HOST] {
        assert_eq!(
            status_of(init_request(host, None, None)).await,
            401,
            "allowlisted Host {host:?} must reach the auth layer, not be 403'd"
        );
    }
}

/// A hostile page reaching the listener carries its own `Origin` even when the
/// `Host` looks local (e.g. a proxy or a client that rewrites Host). The Origin
/// check is the second, independent gate.
#[tokio::test]
async fn hostile_origin_is_refused_under_an_allowlisted_host() {
    let token = mint_token(SECRET, &["claims:read"]);
    for origin in ["http://evil.example", "https://evil.example:8443", "null"] {
        assert_eq!(
            status_of(init_request("127.0.0.1:3100", Some(origin), Some(&token))).await,
            403,
            "Origin {origin:?} must be refused"
        );
    }
}

/// A legitimate local browser client (dev UI on :5173) must still be served, or
/// the guard breaks the localhost case it exists to protect.
#[tokio::test]
async fn allowlisted_origin_falls_through_to_the_bearer_layer() {
    assert_eq!(
        status_of(init_request(
            "127.0.0.1:3100",
            Some("http://localhost:5173"),
            None
        ))
        .await,
        401,
        "an allowlisted Origin must reach the auth layer, not be 403'd"
    );
}

/// A request with no `Host` at all (and no URI authority to fall back on) has
/// nothing to check, so it fails closed rather than defaulting to allowed.
#[tokio::test]
async fn request_without_a_host_header_is_refused() {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Accept", ACCEPT)
        .header("Content-Type", CONTENT_TYPE)
        .body(axum::body::Body::from("{}"))
        .unwrap();
    assert_eq!(status_of(req).await, 403);
}
