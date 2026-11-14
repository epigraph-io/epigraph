//! The federation gateway as a CALLER sees it: the manifest `EpiGraphMcpFull`
//! lists, and what a federated `tools/call` answers, against a controllable
//! stub downstream (`support/federation_stub.rs`).
//!
//! No database: the server runs on a lazy pool that points at a port nothing
//! listens on, as in `http_auth_test.rs`. Nothing asserted here reads it;
//! `emit_tool_invoked` is best-effort and only logs when it cannot publish.

#[path = "support/federation_stub.rs"]
mod stub;

use std::collections::HashSet;
use std::sync::Arc;

use epigraph_mcp::federation::config::ExtensionConfig;
use epigraph_mcp::federation::{FederationRegistry, SharedFederation};
use epigraph_mcp::EpiGraphMcpFull;

fn cfg(name: &str, addr: &str) -> ExtensionConfig {
    epigraph_mcp::federation::config::parse_extensions(Some(&format!(
        "{name}=tcp:{addr};scope={name}:tools"
    )))
    .expect("a well-formed test entry")
    .remove(0)
}

fn dead_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/invalid")
        .expect("connect_lazy never errors")
}

fn server_with(federation: SharedFederation) -> EpiGraphMcpFull {
    let pool = dead_pool();
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    EpiGraphMcpFull::new_shared_with_federation(pool, signer, embedder, false, federation, None)
}

/// An `AuthContext` as the bearer middleware builds it from a real token: a
/// client id and a token id, so not principal-less.
fn bearer_context() -> epigraph_auth::AuthContext {
    epigraph_auth::AuthContext {
        client_id: uuid::Uuid::new_v4(),
        agent_id: Some(uuid::Uuid::new_v4()),
        owner_id: None,
        client_type: epigraph_auth::ClientType::Service,
        scopes: vec!["ext:tools".to_string()],
        jti: uuid::Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
        delegated_by: None,
    }
}

async fn mounted_server(tool: &str) -> EpiGraphMcpFull {
    let (addr, _control) = stub::spawn_controlled_stub(&[tool]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub");
    server_with(SharedFederation::new(registry))
}

fn names(tools: &[rmcp::model::Tool]) -> HashSet<String> {
    tools.iter().map(|t| t.name.to_string()).collect()
}

// ── Backlog b6559e75: a federated tool is listed only where it can be called ──

/// Over stdio there is no bearer to forward, so `call_tool` refuses every
/// federated call. The manifest must not list one.
///
/// Mutation: make `manifest_for` extend with the federated tools
/// unconditionally (the pre-fix code) -> `federated_probe` is listed and this
/// fails.
#[tokio::test]
async fn the_stdio_manifest_lists_no_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let stdio = names(&server.manifest_for(false, None).await);
    assert!(
        !stdio.contains("federated_probe"),
        "a stdio caller cannot call a federated tool, so it must not be listed one"
    );
    assert!(
        stdio.contains("submit_claim"),
        "CALIBRATION: the kernel tools are still listed over stdio"
    );
}

/// The positive control: a bearer caller over HTTP is listed the federated
/// tool. Without it, the stdio assertion above would also pass if the registry
/// had mounted nothing.
#[tokio::test]
async fn the_http_manifest_of_a_bearer_caller_lists_the_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let auth = bearer_context();
    let http = names(&server.manifest_for(true, Some(&auth)).await);
    assert!(
        http.contains("federated_probe"),
        "a bearer caller over HTTP can call the federated tool and is listed it"
    );
}

/// The unauthenticated listener injects a principal-less context and carries
/// no token, so its callers can call no federated tool either.
///
/// Mutation: reduce `lists_federated_tools` to `http` -> listed, fails.
#[tokio::test]
async fn the_unauthenticated_listener_lists_no_federated_tool() {
    let server = mounted_server("federated_probe").await;
    let principal_less = epigraph_mcp::auth::unauthenticated_context(
        Some(uuid::Uuid::new_v4()),
        epigraph_mcp::auth::UnauthenticatedWrites::Refused,
    );
    let listed = names(&server.manifest_for(true, Some(&principal_less)).await);
    assert!(
        !listed.contains("federated_probe"),
        "a principal-less caller has no bearer to forward and must not be listed \
         a federated tool"
    );
}

// ── Backlog 7ea4bd74: what a failed federated call answers ──────────────────
//
// Driven over HTTP through the bearer layer and the real `call_tool`, because
// the defect was in `call_tool`'s mapping (`.map_err(internal_error)`), which
// redacted every failure, the downstream's own designed refusals included.

const SECRET: &[u8] = b"this-secret-is-at-least-32-bytes-long!!";
const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";

#[path = "support/static_revocation.rs"]
mod static_revocation;

fn mint_token(scopes: &[&str]) -> String {
    let cfg = epigraph_auth::JwtConfig::from_secret(SECRET);
    let (token, _) = cfg
        .issue_access_token(
            uuid::Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "service",
            None,
            None,
            chrono::Duration::minutes(5),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .unwrap();
    token
}

/// The gateway behind the bearer layer, serving `federation`. Returns its URL.
async fn spawn_gateway(federation: SharedFederation) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let pool = dead_pool();
    let signer = Arc::new(epigraph_crypto::AgentSigner::generate());
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    let service = StreamableHttpService::new(
        move || {
            Ok(EpiGraphMcpFull::new_shared_with_federation(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
                federation.clone(),
                None,
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        revocation: static_revocation::StaticRevocation::none(),
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    format!("http://{addr}/mcp")
}

async fn read_sse_data(resp: &mut reqwest::Response, within: std::time::Duration) -> String {
    let deadline = tokio::time::Instant::now() + within;
    let mut acc = String::new();
    loop {
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(bytes))) => {
                acc.push_str(&String::from_utf8_lossy(&bytes));
                if acc
                    .lines()
                    .any(|l| l.starts_with("data:") && l.trim_end().len() > 5)
                {
                    return acc;
                }
            }
            _ => return acc,
        }
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST")
}

async fn handshake(client: &reqwest::Client, url: &str, token: &str) -> String {
    let mut resp = post(
        client,
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "federation-dispatch", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "initialize");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .unwrap()
        .to_owned();
    let _ = read_sse_data(&mut resp, std::time::Duration::from_secs(5)).await;
    let notif = post(
        client,
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

/// Call `tool` through the gateway as a caller holding `ext:tools`, and return
/// the JSON-RPC `error` object of the answer (panics if there is none).
async fn call_for_error(url: &str, tool: &str, within: std::time::Duration) -> serde_json::Value {
    let client = reqwest::Client::new();
    let token = mint_token(&["ext:tools"]);
    let session = handshake(&client, url, &token).await;
    let mut resp = post(
        &client,
        url,
        &token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}
        }),
    )
    .await;
    let body = read_sse_data(&mut resp, within).await;
    let data = body
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_else(|| panic!("no JSON-RPC answer within {within:?}:\n{body}"));
    let answer: serde_json::Value = serde_json::from_str(data).expect("JSON-RPC answer");
    answer
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got {answer}"))
}

/// The downstream's own MCP error reaches the caller unchanged: code, message
/// and data.
///
/// Mutation: map the federated call's error with `internal_error` again (the
/// pre-fix code) -> the caller reads "internal error; the detail is in the
/// server log" with code -32603, and this fails.
#[tokio::test]
async fn a_downstream_mcp_error_reaches_the_caller_unchanged() {
    let (addr, _control) = stub::spawn_controlled_stub(&[stub::FAIL_TOOL]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub");
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let error = call_for_error(&url, stub::FAIL_TOOL, std::time::Duration::from_secs(10)).await;
    let expected = stub::fail_error();
    assert_eq!(
        error["code"].as_i64(),
        Some(i64::from(expected.code.0)),
        "the downstream's code is kept: {error}"
    );
    assert_eq!(
        error["message"].as_str(),
        Some(expected.message.as_ref()),
        "the downstream's message is kept: {error}"
    );
    assert_eq!(
        error["data"],
        expected.data.unwrap(),
        "the downstream's data is kept: {error}"
    );
}

/// An extension that cannot be reached is named as unavailable, and its
/// address is not: the address is deployment topology.
///
/// Mutation: as above -> the caller reads only "internal error", and this
/// fails.
#[tokio::test]
async fn an_unreachable_extension_is_answered_as_unavailable_by_name() {
    let (addr, control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub");
    let url = spawn_gateway(SharedFederation::new(registry)).await;
    // Mounted healthy, then gone: the per-call dial fails.
    control.set_alive(false);

    let error = call_for_error(&url, "federated_probe", std::time::Duration::from_secs(15)).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("extension 'ext' unavailable"),
        "the caller must be told which extension is unavailable: {error}"
    );
    assert!(
        message.contains("federated_probe"),
        "and which tool it called: {error}"
    );
    assert!(
        !message.contains(&addr) && !message.contains("127.0.0.1"),
        "the extension's address must not reach the caller: {error}"
    );
}

/// The caller of a tool that never answers is told so at the extension's
/// bound, and warned that the call may still run.
///
/// Mutation: drop the `tokio::time::timeout` in `client::invoke_once` -> no
/// answer arrives within the 15 s read, and this fails.
#[tokio::test]
async fn a_call_that_never_answers_is_answered_at_the_extensions_bound() {
    let (addr, _control) = stub::spawn_controlled_stub(&[stub::HANG_TOOL]).await;
    let configs = epigraph_mcp::federation::config::parse_extensions(Some(&format!(
        "ext=tcp:{addr};scope=ext:tools;call_timeout_secs=1"
    )))
    .expect("a well-formed test entry");
    let registry = FederationRegistry::build(configs, "discovery-tok")
        .await
        .expect("build against a reachable stub");
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let error = call_for_error(&url, stub::HANG_TOOL, std::time::Duration::from_secs(15)).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("extension 'ext' gave no answer within 1 s"),
        "the caller must be told the extension did not answer in time: {error}"
    );
    assert!(
        message.contains("may still complete"),
        "and that the call may have run anyway: {error}"
    );
}
