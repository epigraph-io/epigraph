//! Integration tests for the MCP federation gateway's client + registry
//! (`epigraph_mcp::federation`), exercised against a **stub** downstream
//! streamable-HTTP MCP server stood up on `127.0.0.1:0`.
//!
//! No database is touched: the gateway's federation layer is a pure MCP client
//! over rmcp's streamable-HTTP transport, so it can be tested end-to-end against
//! a tiny hand-rolled `ServerHandler` — we never construct an
//! `EpiGraphMcpFull` (which needs a pool).
//!
//! What is asserted:
//! - `list_federated_tools()` surfaces the stub's tool (with optional prefix);
//! - `invoke()` proxies a `tools/call` and returns the stub's result;
//! - the **caller's bearer** reaches the stub (`Authorization: Bearer <token>`),
//!   captured by a test-side middleware that mirrors production's
//!   `bearer_auth_middleware`;
//! - two extensions exporting the SAME effective tool name make `build()` fail
//!   with a collision, while a distinct `prefix=` on one is the escape hatch;
//! - an unreachable address degrades gracefully (empty tools, healthy=false, no
//!   panic) instead of taking the gateway down.

use std::sync::{Arc, Mutex};

use axum::Router;
use epigraph_mcp::federation::config::ExtensionConfig;
use epigraph_mcp::federation::FederationRegistry;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ListToolsResult, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};

/// Shared slot the capture middleware writes the last-seen `Authorization`
/// header into. Cloned into both the middleware and the assertion.
type AuthSlot = Arc<Mutex<Option<String>>>;

/// A minimal downstream MCP server exposing exactly one tool named `tool_name`.
/// `call_tool` echoes a fixed payload so the gateway-side test can assert the
/// proxied result round-tripped. `get_info` advertises the tools capability,
/// without which `initialize` / `list_tools` would not behave.
#[derive(Clone)]
struct StubServer {
    tool_name: String,
}

impl ServerHandler for StubServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = serde_json::json!({ "type": "object", "properties": {} });
        let obj = schema.as_object().cloned().unwrap_or_default();
        Ok(ListToolsResult {
            tools: vec![Tool::new(
                self.tool_name.clone(),
                "stub downstream tool",
                Arc::new(obj),
            )],
            meta: None,
            next_cursor: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        // Echo the tool name so the gateway test can confirm the DOWNSTREAM
        // (un-prefixed) name arrived, proving prefix stripping on the proxy path.
        Ok(CallToolResult::success(vec![Content::text(format!(
            "stub handled `{}`",
            request.name
        ))]))
    }
}

/// Capture middleware: records the incoming `Authorization` header into `slot`,
/// then forwards. This is the test-side analogue of production's
/// `bearer_auth_middleware` — it asserts the token arrived *over HTTP*, without
/// coupling to rmcp's internal request-context plumbing.
async fn capture_auth(
    slot: AuthSlot,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(value) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        *slot.lock().unwrap() = Some(value.to_string());
    }
    next.run(req).await
}

/// Stand up a stub MCP server exposing one tool, on an ephemeral loopback port.
/// Returns the bound `host:port` (as the registry's `addr` form) and the auth
/// slot the capture middleware writes into.
async fn spawn_stub(tool_name: &str) -> (String, AuthSlot) {
    let slot: AuthSlot = Arc::new(Mutex::new(None));
    let tool_name = tool_name.to_string();

    let service = StreamableHttpService::new(
        move || {
            Ok(StubServer {
                tool_name: tool_name.clone(),
            })
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let slot_for_mw = slot.clone();
    let router: Router =
        Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(move |req, next| {
                let slot = slot_for_mw.clone();
                capture_auth(slot, req, next)
            }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (format!("127.0.0.1:{}", addr.port()), slot)
}

fn cfg(name: &str, addr: &str, prefix: Option<&str>) -> ExtensionConfig {
    ExtensionConfig {
        name: name.to_string(),
        addr: addr.to_string(),
        scope: format!("{name}:tools"),
        prefix: prefix.map(str::to_string),
    }
}

#[tokio::test]
async fn lists_and_invokes_stub_tool_forwarding_caller_bearer() {
    let (addr, slot) = spawn_stub("ping").await;
    let registry = FederationRegistry::build(vec![cfg("episcience", &addr, None)], "discovery-tok")
        .await
        .expect("build should succeed against a reachable stub");

    // list_federated_tools surfaces the stub's single tool.
    let tools = registry.list_federated_tools();
    assert_eq!(tools.len(), 1, "expected exactly the stub's one tool");
    assert_eq!(tools[0].name.as_ref(), "ping");

    // route + required_scope resolve to the owning extension.
    assert!(registry.route("ping").is_some());
    assert_eq!(registry.required_scope("ping"), Some("episcience:tools"));
    assert!(registry.route("nonexistent").is_none());

    // invoke() proxies the call and returns the stub's result.
    let caller_token = "caller-bearer-xyz";
    let result = registry
        .invoke("ping", caller_token, None)
        .await
        .expect("invoke should proxy to the stub");
    let text = result.content[0]
        .as_text()
        .expect("stub returns text content")
        .text
        .clone();
    assert_eq!(
        text, "stub handled `ping`",
        "downstream should receive the un-prefixed tool name"
    );

    // The CALLER's bearer reached the stub as `Authorization: Bearer <token>`
    // (rmcp's reqwest client prepends `Bearer ` via `.bearer_auth`).
    let seen = slot
        .lock()
        .unwrap()
        .clone()
        .expect("stub saw an Authorization header");
    assert_eq!(seen, format!("Bearer {caller_token}"));
}

#[tokio::test]
async fn prefix_is_applied_to_effective_name_and_stripped_on_invoke() {
    let (addr, _slot) = spawn_stub("ping").await;
    let registry = FederationRegistry::build(
        vec![cfg("episcience", &addr, Some("episcience__"))],
        "discovery-tok",
    )
    .await
    .unwrap();

    // Advertised (effective) name carries the prefix.
    let tools = registry.list_federated_tools();
    assert_eq!(tools[0].name.as_ref(), "episcience__ping");
    assert!(registry.route("episcience__ping").is_some());
    // The bare downstream name is NOT a gateway route.
    assert!(registry.route("ping").is_none());

    // Invoking the prefixed name strips the prefix before forwarding, so the
    // stub sees the bare `ping`.
    let result = registry
        .invoke("episcience__ping", "tok", None)
        .await
        .unwrap();
    let text = result.content[0].as_text().unwrap().text.clone();
    assert_eq!(text, "stub handled `ping`");
}

#[tokio::test]
async fn colliding_tool_names_across_extensions_fail_build() {
    // Two DISTINCT stubs (distinct ports) both exporting `dup`, neither
    // prefixed -> same effective name -> build() must error.
    let (addr_a, _a) = spawn_stub("dup").await;
    let (addr_b, _b) = spawn_stub("dup").await;

    // `FederationRegistry` is not `Debug` (it holds live rmcp sessions), so
    // match rather than `expect_err`.
    let result = FederationRegistry::build(
        vec![cfg("ext_a", &addr_a, None), cfg("ext_b", &addr_b, None)],
        "discovery-tok",
    )
    .await;
    let err = match result {
        Ok(_) => panic!("colliding effective tool names must fail build"),
        Err(e) => e,
    };

    let msg = err.to_string();
    assert!(
        msg.contains("dup"),
        "collision error should name the tool: {msg}"
    );
    assert!(
        msg.contains("ext_a") && msg.contains("ext_b"),
        "collision error should name both extensions: {msg}"
    );
}

#[tokio::test]
async fn prefix_resolves_collision_between_extensions() {
    // Same two stubs both exporting `dup`, but one prefixed -> distinct
    // effective names -> build() succeeds and both are routable.
    let (addr_a, _a) = spawn_stub("dup").await;
    let (addr_b, _b) = spawn_stub("dup").await;

    let registry = FederationRegistry::build(
        vec![
            cfg("ext_a", &addr_a, None),
            cfg("ext_b", &addr_b, Some("b__")),
        ],
        "discovery-tok",
    )
    .await
    .expect("distinct prefixes must resolve the collision");

    assert!(registry.route("dup").is_some());
    assert!(registry.route("b__dup").is_some());
    assert_eq!(registry.list_federated_tools().len(), 2);
}

#[tokio::test]
async fn unreachable_extension_degrades_gracefully() {
    // Bind :0 to reserve a port, then DROP the listener so the port is closed:
    // guaranteed connection-refused, deterministic, fast.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let dead_addr = format!("127.0.0.1:{port}");

    let registry = FederationRegistry::build(vec![cfg("ghost", &dead_addr, None)], "discovery-tok")
        .await
        .expect("an unreachable extension must NOT fail the whole build");

    // No tools routed; the gateway stands, just without this extension.
    assert!(
        registry.list_federated_tools().is_empty(),
        "unreachable extension contributes no tools"
    );
    assert!(registry.route("anything").is_none());
    assert!(
        !registry.is_empty(),
        "the extension is still mounted (unhealthy)"
    );
}

#[tokio::test]
async fn absent_extensions_yield_empty_registry() {
    let registry = FederationRegistry::build(vec![], "discovery-tok")
        .await
        .unwrap();
    assert!(registry.is_empty());
    assert!(registry.list_federated_tools().is_empty());
}
