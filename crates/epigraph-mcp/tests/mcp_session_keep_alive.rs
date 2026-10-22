//! Session keep-alive on the MCP streamable-HTTP listener.
//!
//! rmcp 2.x ends a session when its worker sees no session event for
//! `SessionConfig::keep_alive` (default 5 minutes; rmcp 0.15 had no such
//! timer). The timer is re-armed only by an inbound HTTP event or by a message
//! from the handler, and an in-flight tool call produces neither until it
//! returns. So a single tool call that runs longer than `keep_alive` ends its
//! own session: the client's SSE stream closes with no result.
//!
//! Both tests use the production session manager
//! (`http_listener::session_manager`) on a paused tokio clock, so minutes of
//! virtual time pass instantly. The long-call test drives that session manager
//! directly, the way rmcp's HTTP service does: the HTTP layer's SSE keep-alive
//! comments reset their timer from the wall clock, which a paused tokio clock
//! running hours ahead turns into an endless burst of comments. The idle test
//! holds no stream open while time passes, so it runs over HTTP through
//! `http_listener::mcp_http_listener` + `session_status::nest_mcp_service`.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use epigraph_mcp::http_listener::{mcp_http_listener, SESSION_KEEP_ALIVE};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ServerCapabilities, ServerInfo,
};
use rmcp::transport::streamable_http_server::SessionManager;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt as _};
use tower::ServiceExt as _;

const LISTEN: &str = "127.0.0.1:3100";
const SESSION_HEADER: &str = "Mcp-Session-Id";

/// A tool call four times rmcp's 5-minute default keep-alive. Long tool calls
/// exist on this server (`backfill_embeddings` over thousands of claims,
/// `sweep_semantic_duplicates`, `recompute_beliefs`, federated calls that wait
/// on a downstream), and none of them sends progress notifications.
const LONG_CALL: Duration = Duration::from_secs(20 * 60);

/// Upper bound on any single response in virtual time, so a stream that never
/// ends fails the test instead of hanging it.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(6 * 60 * 60);

/// A server whose only tool sleeps for [`LONG_CALL`] and then answers.
struct SlowServer;

impl ServerHandler for SlowServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        tokio::time::sleep(LONG_CALL).await;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{} finished",
            request.name
        ))]))
    }
}

fn router() -> axum::Router {
    epigraph_mcp::session_status::nest_mcp_service(
        mcp_http_listener(LISTEN, &[], || Ok(SlowServer)).service,
    )
}

fn post(session: Option<&str>, body: &serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", LISTEN)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json");
    if let Some(id) = session {
        builder = builder.header(SESSION_HEADER, id);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

/// Most raw bytes read from one response, SSE keep-alive comments included.
/// A stream that keeps pinging without ever answering stops here.
const MAX_RAW_BYTES: usize = 1 << 20;

/// Send `req` and return `(status, session header, body)`. The body is read
/// until it carries a JSON-RPC response (`"id":`), the stream ends, it passes
/// [`MAX_RAW_BYTES`], or [`RESPONSE_DEADLINE`] of virtual time elapses. SSE
/// keep-alive comment lines are dropped from the returned text.
async fn send(router: &axum::Router, req: Request<Body>) -> (u16, Option<String>, String) {
    use axum::body::HttpBody;

    let resp = router.clone().oneshot(req).await.expect("infallible");
    let status = resp.status().as_u16();
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut body = resp.into_body();
    let mut text = String::new();
    let mut raw = 0usize;
    let _ = tokio::time::timeout(RESPONSE_DEADLINE, async {
        while let Some(frame) =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
        {
            let Ok(data) = frame.map(|f| f.into_data()) else {
                break;
            };
            let Ok(data) = data else { continue };
            raw += data.len();
            for line in String::from_utf8_lossy(&data).split_inclusive('\n') {
                if !line.starts_with(':') && !line.trim().is_empty() {
                    text.push_str(line);
                }
            }
            if text.contains("\"id\":") || raw > MAX_RAW_BYTES {
                break;
            }
        }
    })
    .await;
    (status, session, text)
}

/// `initialize` + `notifications/initialized`; returns the session id.
async fn open_session(router: &axum::Router) -> String {
    let (status, session, body) = send(
        router,
        post(
            None,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "keep-alive-test", "version": "0.1"}
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, 200, "initialize failed: {body}");
    let session = session.expect("initialize must return a session id");
    let (status, _, body) = send(
        router,
        post(
            Some(&session),
            &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        ),
    )
    .await;
    assert_eq!(status, 202, "notifications/initialized failed: {body}");
    session
}

fn tools_list() -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
}

fn client_message(value: serde_json::Value) -> rmcp::model::ClientJsonRpcMessage {
    serde_json::from_value(value).expect("a well-formed client message")
}

/// The defect: under rmcp's 5-minute default, the 20-minute call below ends its
/// own session at minute 5, and the stream closes without the result.
#[tokio::test(start_paused = true)]
async fn a_tool_call_longer_than_rmcps_default_keep_alive_returns_its_result() {
    use futures::StreamExt;

    let manager = Arc::new(epigraph_mcp::http_listener::session_manager());
    let (id, transport) = manager.create_session().await.expect("create session");
    // What `StreamableHttpService` does per session: serve the handler on the
    // session's transport, and close the session when the service ends.
    {
        let manager = manager.clone();
        let id = id.clone();
        tokio::spawn(async move {
            if let Ok(service) = SlowServer.serve(transport).await {
                let _ = service.waiting().await;
            }
            let _ = manager.close_session(&id).await;
        });
    }
    manager
        .initialize_session(
            &id,
            client_message(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "keep-alive-test", "version": "0.1"}
                }
            })),
        )
        .await
        .expect("initialize");
    manager
        .accept_message(
            &id,
            client_message(
                serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ),
        )
        .await
        .expect("notifications/initialized");

    let stream = manager
        .create_stream(
            &id,
            client_message(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "slow", "arguments": {}}
            })),
        )
        .await
        .expect("tools/call stream");
    let mut stream = std::pin::pin!(stream);
    let mut response = None;
    while let Ok(Some(event)) = tokio::time::timeout(RESPONSE_DEADLINE, stream.next()).await {
        let Some(message) = event.message else {
            continue;
        };
        let value = serde_json::to_value(&*message).expect("serializable");
        if value.get("id") == Some(&serde_json::json!(2)) {
            response = Some(value);
            break;
        }
    }
    let response = response.unwrap_or_else(|| {
        panic!("a {LONG_CALL:?} tool call must deliver its result; the stream closed without it")
    });
    assert!(
        response.to_string().contains("slow finished"),
        "unexpected tools/call response: {response}"
    );
    assert!(
        manager.has_session(&id).await.unwrap_or(false),
        "the session must survive the long call"
    );
}

/// An idle session still expires (the bound on abandoned sessions stays), but
/// only after [`SESSION_KEEP_ALIVE`], and the client sees the spec's 404 (so it
/// re-initializes) rather than a 401 or 500.
#[tokio::test(start_paused = true)]
async fn an_idle_session_lives_past_rmcps_default_and_then_gets_404() {
    let router = router();
    let session = open_session(&router).await;

    // Idle well past rmcp's 5-minute default: still served.
    tokio::time::sleep(LONG_CALL).await;
    let (status, _, body) = send(&router, post(Some(&session), &tools_list())).await;
    assert_eq!(
        status, 200,
        "a session idle for {LONG_CALL:?} must still be served: {body}"
    );

    // Idle past the listener's keep-alive: gone, with 404 and no challenge.
    tokio::time::sleep(SESSION_KEEP_ALIVE + Duration::from_secs(60)).await;
    let resp = router
        .clone()
        .oneshot(post(Some(&session), &tools_list()))
        .await
        .expect("infallible");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "an expired session must get 404 so the client re-initializes"
    );
    assert!(
        !resp.headers().contains_key("www-authenticate"),
        "an expired session is not an auth failure"
    );

    // Re-initializing works.
    let fresh = open_session(&router).await;
    assert_ne!(fresh, session);
}
