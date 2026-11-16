//! A CONTROLLABLE downstream extension MCP for the federation tests.
//!
//! `federation_gateway_test.rs` keeps its own fixed one-tool stub. This one
//! exists for the properties that need the downstream to CHANGE under a
//! running gateway: a tool list that grows and shrinks, a process that goes
//! away and comes back, a `tools/list` or `tools/call` that never answers, a
//! `tools/call` that answers with an MCP error, and a bearer the downstream
//! refuses.
//!
//! The behaviour is driven by [`StubControl`], shared between the test and
//! every session the stub serves:
//!
//! - `tools`: the names `tools/list` advertises, read on every list;
//! - `alive = false`: every HTTP request gets `503`, as if the process were
//!   gone (new dials fail, and so does a request on an existing session);
//! - `hang_list = true`: `tools/list` never answers;
//! - a request whose bearer is [`REJECTED_BEARER`] gets `401`.
//!
//! Tool behaviour is keyed by name: [`HANG_TOOL`] never answers,
//! [`FAIL_TOOL`] answers with [`fail_error`], and any other name echoes
//! `stub handled `<name>``.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};

/// A tool whose `tools/call` never answers.
pub const HANG_TOOL: &str = "hang_forever";
/// A tool whose `tools/call` answers with [`fail_error`].
pub const FAIL_TOOL: &str = "always_fails";
/// A bearer the stub answers with `401`, at `initialize` as on every request.
pub const REJECTED_BEARER: &str = "a-token-this-downstream-refuses";

/// The MCP error [`FAIL_TOOL`] answers with: a non-default code, a message
/// and structured `data`, so a test can tell "passed through as-is" from
/// "re-wrapped" on every field.
#[must_use]
pub fn fail_error() -> ErrorData {
    ErrorData::invalid_params(
        "stub refused: widget 42 is out of range (max 7)",
        Some(serde_json::json!({ "widget": 42, "max": 7 })),
    )
}

/// What the test controls. See the module doc.
pub struct StubControl {
    pub tools: Mutex<Vec<String>>,
    pub alive: AtomicBool,
    pub hang_list: AtomicBool,
}

impl StubControl {
    pub fn set_tools(&self, names: &[&str]) {
        *self.tools.lock().unwrap() = names.iter().map(|n| (*n).to_string()).collect();
    }
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
    }
    pub fn set_hang_list(&self, hang: bool) {
        self.hang_list.store(hang, Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct ControlledStub {
    control: Arc<StubControl>,
}

impl ServerHandler for ControlledStub {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        if self.control.hang_list.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let schema = serde_json::json!({ "type": "object", "properties": {} });
        let obj = Arc::new(schema.as_object().cloned().unwrap_or_default());
        let names = self.control.tools.lock().unwrap().clone();
        Ok(ListToolsResult::with_all_items(
            names
                .into_iter()
                .map(|n| Tool::new(n, "controlled stub tool", obj.clone()))
                .collect(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match request.name.as_ref() {
            HANG_TOOL => {
                std::future::pending::<()>().await;
                unreachable!()
            }
            FAIL_TOOL => Err(fail_error()),
            other => Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "stub handled `{other}`"
            ))])
            .into()),
        }
    }
}

async fn gate(
    control: Arc<StubControl>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !control.alive.load(Ordering::SeqCst) {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let rejected = format!("Bearer {REJECTED_BEARER}");
    if req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(rejected.as_str())
    {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

/// Serve a controlled stub advertising `tools` on an ephemeral loopback port.
/// Returns the bound `host:port` and the control handle.
pub async fn spawn_controlled_stub(tools: &[&str]) -> (String, Arc<StubControl>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    (addr, serve_controlled_stub(listener, tools))
}

/// As [`spawn_controlled_stub`], on a caller-chosen `host:port`: brings an
/// extension up on the address a gateway already failed to reach.
pub async fn spawn_controlled_stub_on(addr: &str, tools: &[&str]) -> Arc<StubControl> {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    serve_controlled_stub(listener, tools)
}

/// A loopback `host:port` nothing listens on: bound, then released.
pub async fn dead_addr() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("127.0.0.1:{port}")
}

fn serve_controlled_stub(listener: tokio::net::TcpListener, tools: &[&str]) -> Arc<StubControl> {
    let control = Arc::new(StubControl {
        tools: Mutex::new(tools.iter().map(|n| (*n).to_string()).collect()),
        alive: AtomicBool::new(true),
        hang_list: AtomicBool::new(false),
    });

    let for_service = control.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(ControlledStub {
                control: for_service.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let for_gate = control.clone();
    let router: Router =
        Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(move |req, next| {
                let control = for_gate.clone();
                gate(control, req, next)
            }));
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    control
}
