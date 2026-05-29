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
    let auth_strings = ["Unauthorized", "Forbidden", "no auth context", "requires scope"];
    for s in &auth_strings {
        assert!(
            !body.contains(s),
            "--allow-unauthenticated-http must not auth-reject; found {s:?} in: {body}"
        );
    }
}
