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
//!   panic) instead of taking the gateway down;
//! - a `reconnect_tick` REVIVES an extension that was down at build time — the
//!   boot race that left episcience unroutable in production for hours — and is
//!   a no-op against one that is still down or already healthy.

use std::sync::{Arc, Mutex};

use axum::Router;
use epigraph_mcp::federation::config::ExtensionConfig;
use epigraph_mcp::federation::{FederationRegistry, SharedFederation};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ListToolsResult, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{ErrorData, RoleServer, ServerHandler};

/// Shared slot the capture middleware writes the last-seen request HEADERS
/// into. Cloned into both the middleware and the assertion.
///
/// **Widened by PR-10** from a single `Option<String>` holding `Authorization`.
/// The federation clause PR-10 was handed — "`epigraph-mcp/src/federation/`
/// forwards the `Viewer` group set as a header" — was REJECTED (see
/// `no_group_or_identity_header_is_forwarded_to_the_downstream`), and the
/// property that replaces it is a statement about what the gateway does NOT
/// send. A capture that only ever looked at one header could not make it.
type AuthSlot = Arc<Mutex<Option<axum::http::HeaderMap>>>;

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
    *slot.lock().unwrap() = Some(req.headers().clone());
    next.run(req).await
}

/// Stand up a stub MCP server exposing one tool, on an ephemeral loopback port.
/// Returns the bound `host:port` (as the registry's `addr` form) and the auth
/// slot the capture middleware writes into.
async fn spawn_stub(tool_name: &str) -> (String, AuthSlot) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    (addr, serve_stub(listener, tool_name))
}

/// As [`spawn_stub`], but binds a caller-chosen `host:port`. Used by the
/// reconnect test to bring an extension up on the exact address the gateway
/// already failed to reach.
async fn spawn_stub_on(addr: &str, tool_name: &str) -> AuthSlot {
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    serve_stub(listener, tool_name)
}

/// Serve the stub + capture middleware on an already-bound listener. Binding is
/// the caller's job so a test can reserve a port, release it, and later reclaim
/// exactly that port.
fn serve_stub(listener: tokio::net::TcpListener, tool_name: &str) -> AuthSlot {
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

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    slot
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
        .expect("stub saw request headers");
    assert_eq!(
        seen.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some(format!("Bearer {caller_token}").as_str())
    );
}

/// **PR-10's federation clause, rejected with evidence.**
///
/// The plan's *Files* line asks that `epigraph-mcp/src/federation/` "forward
/// the `Viewer` group set as a header". That was not implemented, and this test
/// is the record of why — an unimplemented clause with a reason and a guard is
/// worth more than a clause implemented because it was written down.
///
/// 1. **It is redundant.** `client::invoke_once` already forwards the CALLER'S
///    OWN bearer verbatim (`connect(addr, Some(caller_token))` →
///    `.bearer_auth(token)`), and `server.rs::call_tool` refuses a federated
///    call outright when there is no raw caller token to forward ("federated
///    tools are unavailable over stdio"). The downstream therefore validates
///    the real principal and derives its own `Viewer` from its own
///    `group_memberships`. That is the model
///    `docs/superpowers/specs/2026-07-23-mcp-federation-gateway-design.md`
///    states: "single credential, single token across both hops".
///
/// 2. **It is a regression risk.** A gateway-asserted group set is an
///    *assertion the downstream must trust*. The moment anything downstream
///    reads it for authorization, read authority is being materialised from a
///    request header — which is exactly the shape
///    `epigraph-db/tests/no_anonymous_viewer.rs` exists to prevent, and a
///    strictly weaker control than a token the downstream can validate.
///    `ExtensionConfig` has no field in which such a contract could even be
///    declared (`name` / `addr` / `scope` / `prefix`).
///
/// So the invariant asserted here is the inverse of the plan's clause: the
/// gateway sends the caller's credential and **no identity or group assertion
/// of its own**. If someone later adds one, this test is what tells them it was
/// a decision and not an oversight.
#[tokio::test]
async fn no_group_or_identity_header_is_forwarded_to_the_downstream() {
    let (addr, slot) = spawn_stub("ping").await;
    let registry = FederationRegistry::build(vec![cfg("episcience", &addr, None)], "discovery-tok")
        .await
        .expect("build should succeed against a reachable stub");

    registry
        .invoke("ping", "caller-bearer-xyz", None)
        .await
        .expect("invoke should proxy to the stub");

    let seen = slot
        .lock()
        .unwrap()
        .clone()
        .expect("stub saw request headers");

    // Nothing that names a principal, a group, or a tenancy decision.
    for banned in [
        "x-epigraph-groups",
        "x-epigraph-group-ids",
        "x-epigraph-viewer",
        "x-epigraph-agent-id",
        "x-epigraph-principal",
        "x-epigraph-owner-group-id",
        "x-epigraph-visibility",
        "x-forwarded-user",
    ] {
        assert!(
            seen.get(banned).is_none(),
            "the gateway forwarded `{banned}`. A downstream that trusts a \
             gateway-asserted identity or group set derives read authority from \
             an untrusted header; forward the caller's own bearer instead, which \
             the downstream can validate."
        );
    }

    // …and the positive control: the caller's credential DID arrive, so the
    // absence above is "we send only the token", not "we sent nothing".
    assert_eq!(
        seen.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer caller-bearer-xyz")
    );
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
async fn reconnect_tick_revives_an_extension_that_was_down_at_boot() {
    // Reproduce production's boot race deterministically: reserve a port, drop
    // the listener so the gateway's build-time dial is refused, then bring the
    // extension up on that exact port afterwards.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let addr = format!("127.0.0.1:{port}");

    let federation = SharedFederation::new(
        FederationRegistry::build(vec![cfg("episcience", &addr, None)], "discovery-tok")
            .await
            .expect("an unreachable extension must not fail the build"),
    );

    // Baseline: mounted, but contributing nothing.
    assert!(!federation.is_empty(), "the extension is mounted");
    assert!(
        federation.list_federated_tools().is_empty(),
        "an unhealthy mount routes no tools"
    );
    assert!(federation.route_config("ping").is_none());

    // A tick while the extension is STILL down must be a quiet no-op — not a
    // panic, and not a spurious promotion.
    federation.reconnect_tick().await;
    assert!(
        federation.list_federated_tools().is_empty(),
        "ticking against a dead extension must not promote it"
    );

    // The extension finally comes up, on the same address.
    let slot = spawn_stub_on(&addr, "ping").await;
    federation.reconnect_tick().await;

    // It is now advertised...
    let tools = federation.list_federated_tools();
    assert_eq!(tools.len(), 1, "reconnect should route the stub's one tool");
    assert_eq!(tools[0].name.as_ref(), "ping");
    assert_eq!(
        federation.route_config("ping").map(|c| c.scope),
        Some("episcience:tools".to_string()),
        "the revived route must carry the extension's configured scope gate"
    );

    // ...and actually callable end-to-end, with the caller's bearer forwarded.
    // Listing alone would pass even if the routing map were updated but the
    // session were not, so assert the round-trip.
    let result = federation
        .invoke("ping", "caller-after-revival", None)
        .await
        .expect("a revived extension must be invocable");
    assert_eq!(
        result.content[0].as_text().unwrap().text,
        "stub handled `ping`"
    );
    let seen = slot
        .lock()
        .unwrap()
        .clone()
        .expect("the revived stub saw request headers");
    assert_eq!(
        seen.get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer caller-after-revival"),
        "the caller's bearer must reach the revived downstream"
    );
}

#[tokio::test]
async fn reconnect_tick_leaves_healthy_extensions_untouched() {
    let (addr, _slot) = spawn_stub("ping").await;
    let federation = SharedFederation::new(
        FederationRegistry::build(vec![cfg("episcience", &addr, None)], "discovery-tok")
            .await
            .unwrap(),
    );
    assert_eq!(federation.list_federated_tools().len(), 1);

    // Ticking a fully-healthy registry must not duplicate routes or drop them.
    federation.reconnect_tick().await;

    let tools = federation.list_federated_tools();
    assert_eq!(
        tools.len(),
        1,
        "a healthy extension must not be re-mounted or duplicated by a tick"
    );
    assert_eq!(tools[0].name.as_ref(), "ping");
    assert!(federation.route_config("ping").is_some());
}

#[tokio::test]
async fn absent_extensions_yield_empty_registry() {
    let registry = FederationRegistry::build(vec![], "discovery-tok")
        .await
        .unwrap();
    assert!(registry.is_empty());
    assert!(registry.list_federated_tools().is_empty());
}
