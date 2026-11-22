//! The federation gateway as a CALLER sees it: the manifest `EpiGraphMcpFull`
//! lists, and what a federated `tools/call` answers, against a controllable
//! stub downstream (`support/federation_stub.rs`).
//!
//! No database, except the delegated-run-token case: the server runs on a
//! lazy pool that points at a port nothing listens on, as in
//! `http_auth_test.rs`. Nothing asserted there reads it; `emit_tool_invoked`
//! is best-effort and only logs when it cannot publish. A delegated token is
//! checked for a LIVE delegation before any other gate, which is a database
//! read, so that one case is a `#[sqlx::test]` on a fresh database.

#[path = "support/federation_stub.rs"]
mod stub;

#[path = "support/token_exchange_endpoint.rs"]
mod tx;

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

// ── What a failed federated call answers, end to end ─────────────────────────
//
// Driven over HTTP through the bearer layer and the real `call_tool`, so the
// answer is the one `call_tool` maps (`errors::federated_call_error`), not one
// a unit test builds by hand. The operator ruled on 2026-11-16: a downstream's
// INTERNAL error is redacted; its parameter refusals, an unreachable extension
// and a call that never answers are answered as main's design answers them.

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
    spawn_gateway_on(federation, dead_pool(), epigraph_db::RunTokens::Off).await
}

/// [`spawn_gateway`] on `pool`, with the delegated-run-token switch as given.
async fn spawn_gateway_on(
    federation: SharedFederation,
    pool: sqlx::PgPool,
    run_tokens: epigraph_db::RunTokens,
) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
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
            )
            .with_run_tokens(run_tokens))
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

/// Call `tool` with `arguments` through the gateway as the bearer of
/// `token`, on a fresh session; the JSON-RPC answer.
async fn call_as(
    url: &str,
    token: &str,
    tool: &str,
    arguments: serde_json::Value,
    within: std::time::Duration,
) -> serde_json::Value {
    let client = reqwest::Client::new();
    let session = handshake(&client, url, token).await;
    let mut resp = post(
        &client,
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}
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
    serde_json::from_str(data).expect("JSON-RPC answer")
}

/// Call `tool` through the gateway as a caller holding `ext:tools`, and return
/// the JSON-RPC `error` object of the answer (panics if there is none).
async fn call_for_error(url: &str, tool: &str, within: std::time::Duration) -> serde_json::Value {
    let token = mint_token(&["ext:tools"]);
    let answer = call_as(url, &token, tool, serde_json::json!({}), within).await;
    answer
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("expected a JSON-RPC error, got {answer}"))
}

/// A downstream's INTERNAL error reaches the caller redacted: still `-32603`,
/// naming the extension and the tool, without the downstream's message (where
/// a downstream that does not redact puts its driver text) or its data.
///
/// Mutation: drop the `INTERNAL_ERROR` arm in `federated_call_error` -> the
/// stub's "stub_private_table" reaches the caller, and this fails.
#[tokio::test]
async fn a_downstream_internal_error_is_redacted_and_names_the_extension() {
    let (addr, _control) = stub::spawn_controlled_stub(&[stub::INTERNAL_FAIL_TOOL]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(tx::spawn_token_endpoint(SECRET, &["ext"]).await.exchange());
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let error = call_for_error(
        &url,
        stub::INTERNAL_FAIL_TOOL,
        std::time::Duration::from_secs(10),
    )
    .await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("stub_private_table") && !message.contains("database"),
        "a downstream's internal error text must not reach the caller: {error}"
    );
    assert!(
        message.contains("internal error in extension `ext`")
            && message.contains(stub::INTERNAL_FAIL_TOOL),
        "the caller is told which extension and tool failed: {error}"
    );
    assert_eq!(
        error["code"].as_i64(),
        Some(-32603),
        "still an internal error: {error}"
    );
    assert!(error["data"].is_null(), "no downstream data: {error}");
}

/// The control for the redaction: a downstream's PARAMETER refusal still
/// reaches the caller unchanged, code, message and data, because it is the
/// extension's designed answer to this caller's own call.
///
/// Mutation: redact every `Downstream` answer -> the caller reads the
/// gateway's text with code -32603, and this fails.
#[tokio::test]
async fn a_downstream_parameter_refusal_reaches_the_caller_unchanged() {
    let (addr, _control) = stub::spawn_controlled_stub(&[stub::FAIL_TOOL]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(tx::spawn_token_endpoint(SECRET, &["ext"]).await.exchange());
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

/// An extension that cannot be reached is named as unavailable, with the
/// tool, and its address is not: the address is deployment topology.
#[tokio::test]
async fn an_unreachable_extension_is_answered_as_unavailable_by_name() {
    let (addr, control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(tx::spawn_token_endpoint(SECRET, &["ext"]).await.exchange());
    let url = spawn_gateway(SharedFederation::new(registry)).await;
    // Mounted healthy, then gone: the per-call dial fails.
    control.set_alive(false);

    let error = call_for_error(&url, "federated_probe", std::time::Duration::from_secs(15)).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("extension `ext` is unavailable") && message.contains("federated_probe"),
        "the caller must be told which extension is unavailable and which tool: {error}"
    );
    assert!(
        !message.contains(&addr) && !message.contains("127.0.0.1"),
        "the extension's address must not reach the caller: {error}"
    );
}

/// A call that never answers is answered at the gateway's bound, and the
/// caller is warned that it may still have run.
#[tokio::test]
async fn a_call_that_never_answers_is_answered_at_the_gateways_bound() {
    let (addr, _control) = stub::spawn_controlled_stub(&[stub::HANG_TOOL]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_call_timeout(std::time::Duration::from_secs(1))
        .with_token_exchange(tx::spawn_token_endpoint(SECRET, &["ext"]).await.exchange());
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let error = call_for_error(&url, stub::HANG_TOOL, std::time::Duration::from_secs(15)).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("extension `ext` did not answer"),
        "the caller must be told the extension did not answer in time: {error}"
    );
    assert!(
        message.contains("may still have run"),
        "and that the call may have run anyway: {error}"
    );
}

/// A call whose token exchange the kernel REFUSES (the extension is not one
/// of its configured audiences) is answered as that, naming the extension,
/// the tool and the RFC error, and is not run downstream: the gateway has no
/// fallback to the caller's own bearer (backlog c9b82fae).
///
/// Mutation: route `FederationError::Exchange` to the generic `Request` arm
/// in `federated_call_error` -> the caller reads "the request to extension
/// ... failed" without the cause, and this fails.
#[tokio::test]
async fn a_refused_token_exchange_is_answered_by_name_and_not_run() {
    let (addr, _control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(
            tx::spawn_token_endpoint(SECRET, &["not-ext"])
                .await
                .exchange(),
        );
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let error = call_for_error(&url, "federated_probe", std::time::Duration::from_secs(15)).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("could not obtain a token for extension `ext`")
            && message.contains("invalid_target")
            && message.contains("`federated_probe` was not run"),
        "the caller must be told the exchange was refused, for which extension and tool: {error}"
    );
}

/// The kernel's MCP surface refuses an extension-audience token (backlog
/// c9b82fae): the token a gateway forwards to an extension cannot be replayed
/// at the gateway itself. Same key, same principal, same scopes; only `aud`
/// differs, and the subject it was exchanged from is admitted (control).
#[tokio::test]
async fn the_gateways_own_bearer_layer_refuses_an_extension_audience_token() {
    let url = spawn_gateway(SharedFederation::empty()).await;
    let caller = mint_token(&["ext:tools"]);
    let exchanged = epigraph_auth::JwtConfig::from_secret(SECRET)
        .exchange_token(&caller, "ext", &["ext".to_string()], None)
        .expect("exchange")
        .token;
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "aud-check", "version": "0"}}
    });
    let client = reqwest::Client::new();
    assert_eq!(
        post(&client, &url, &caller, None, initialize.clone())
            .await
            .status()
            .as_u16(),
        200,
        "CONTROL: the kernel token is admitted"
    );
    assert_eq!(
        post(&client, &url, &exchanged, None, initialize)
            .await
            .status()
            .as_u16(),
        401,
        "an extension-audience token must not be admitted on a kernel route"
    );
}

// ── Backlog 19159ac2: the federation branch of `call_tool`, end to end ──────
//
// An allowed call, a scope refusal and a delegated-token refusal, through
// the bearer layer and the real `call_tool` against the recording stub. Each
// asserts what reached the downstream (the stub's `calls`) and the kernel's
// token endpoint (`subjects`), not only what the caller was answered.

/// An allowed federated call reaches the extension with the caller's
/// arguments exactly as sent, under an exchanged extension-audience token
/// (never the caller's own bearer), and the extension's result comes back to
/// the caller unchanged.
///
/// Mutation: pass `None` for the arguments to `federation.invoke` in
/// `call_tool` -> the stub records no arguments and echoes `{}`, and this
/// fails.
#[tokio::test]
async fn an_allowed_federated_call_forwards_the_arguments_and_returns_the_result() {
    let (addr, control) = stub::spawn_controlled_stub(&[stub::ECHO_TOOL]).await;
    let endpoint = tx::spawn_token_endpoint(SECRET, &["ext"]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(endpoint.exchange());
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let caller = mint_token(&["ext:tools"]);
    let arguments = serde_json::json!({
        "widget": 42,
        "label": "forwarded as sent",
        "nested": {"ids": [1, 2, 3], "flag": true}
    });
    let answer = call_as(
        &url,
        &caller,
        stub::ECHO_TOOL,
        arguments.clone(),
        std::time::Duration::from_secs(10),
    )
    .await;

    let result = answer
        .get("result")
        .unwrap_or_else(|| panic!("an allowed call is answered with a result: {answer}"));
    assert_ne!(result["isError"], serde_json::json!(true), "{answer}");
    let echoed: serde_json::Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("the stub's text block: {answer}")),
    )
    .expect("the stub echoes JSON");
    assert_eq!(
        echoed, arguments,
        "the caller gets the extension's result, which echoes what it was sent: {answer}"
    );

    let calls = control.calls();
    assert_eq!(
        calls.len(),
        1,
        "exactly one call reached the stub: {calls:?}"
    );
    assert_eq!(calls[0].name, stub::ECHO_TOOL);
    assert_eq!(
        calls[0].arguments.clone().map(serde_json::Value::Object),
        Some(arguments),
        "the extension received the caller's arguments unchanged"
    );
    let forwarded = calls[0]
        .bearer
        .as_deref()
        .expect("the call carried a bearer");
    assert_ne!(
        forwarded, caller,
        "the caller's own bearer must never reach an extension"
    );
    epigraph_auth::JwtConfig::from_secret(SECRET)
        .validate_token_for_audience(forwarded, "ext")
        .expect("the extension receives a token whose audience is its own name");
    assert_eq!(
        *endpoint.subjects.lock().unwrap(),
        vec![caller],
        "the caller's bearer went to the kernel's exchange, once"
    );
}

/// A caller without the extension's scope is refused by name and scope, and
/// nothing reaches the extension or the token endpoint: the caller's bearer
/// never leaves the gateway. The same gateway admits a caller WITH the scope
/// (calibration: the refusal is the scope, not an unreachable stub).
///
/// Mutation: remove the `enforce_federated_scope` call in `call_tool`'s
/// federation branch -> the scopeless call is exchanged and reaches the stub,
/// and this fails.
#[tokio::test]
async fn a_caller_without_the_extensions_scope_is_refused_and_nothing_is_forwarded() {
    let (addr, control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    let endpoint = tx::spawn_token_endpoint(SECRET, &["ext"]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(endpoint.exchange());
    let url = spawn_gateway(SharedFederation::new(registry)).await;

    let answer = call_as(
        &url,
        &mint_token(&["claims:read"]),
        "federated_probe",
        serde_json::json!({}),
        std::time::Duration::from_secs(10),
    )
    .await;
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("federated tool 'federated_probe' requires scope 'ext:tools'"),
        "refused for the extension's scope: {answer}"
    );
    assert!(
        control.calls().is_empty(),
        "nothing reached the extension: {:?}",
        control.calls()
    );
    assert!(
        endpoint.subjects.lock().unwrap().is_empty(),
        "the refused caller's bearer was not sent to the exchange either"
    );

    let admitted = call_as(
        &url,
        &mint_token(&["ext:tools"]),
        "federated_probe",
        serde_json::json!({}),
        std::time::Duration::from_secs(10),
    )
    .await;
    assert!(
        admitted.get("result").is_some(),
        "CALIBRATION: a caller with the scope reaches the extension: {admitted}"
    );
    assert_eq!(control.calls().len(), 1, "CALIBRATION: one call reached it");
}

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

/// A signed `agent` token for `principal` (`sub` = `client`) carrying
/// `scopes`, delegated by `delegated_by` when given.
fn agent_token(
    client: uuid::Uuid,
    principal: uuid::Uuid,
    delegated_by: Option<uuid::Uuid>,
    scopes: &[&str],
) -> String {
    epigraph_auth::JwtConfig::from_secret(SECRET)
        .issue_access_token(
            client,
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(principal),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding {
                delegated_by,
                ..epigraph_auth::AccessTokenBinding::NONE
            },
        )
        .expect("mint")
        .0
}

/// A DELEGATED run token is refused at a federated tool even when its
/// delegation is live and it holds the extension's scope, and its bearer
/// reaches neither the extension nor the token endpoint. The extension's
/// scope is inside the delegated ceiling and the run-token switch is on, so
/// the dispatch check admits the token and the federation branch is what
/// refuses it. The same principal's token without `dlg` reaches the extension
/// (calibration).
///
/// Mutation: remove the `delegated_by.is_some()` arm of
/// `enforce_federated_scope` -> the token passes the scope check and is sent
/// to the exchange, and this fails.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_run_token_is_refused_at_a_federated_tool_and_nothing_is_forwarded(
    pool: sqlx::PgPool,
) {
    let d = delegation::live_delegation(&pool, "federated-dlg").await;
    let (addr, control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    let endpoint = tx::spawn_token_endpoint(SECRET, &["ext"]).await;
    let config = epigraph_mcp::federation::config::parse_extensions(Some(&format!(
        "ext=tcp:{addr};scope=claims:read"
    )))
    .expect("a well-formed test entry")
    .remove(0);
    let registry = FederationRegistry::build(vec![config], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(endpoint.exchange());
    let url = spawn_gateway_on(
        SharedFederation::new(registry),
        pool.clone(),
        epigraph_db::RunTokens::On,
    )
    .await;

    let dlg = agent_token(
        d.delegator_client,
        d.principal,
        Some(d.delegator),
        &["claims:read"],
    );
    let answer = call_as(
        &url,
        &dlg,
        "federated_probe",
        serde_json::json!({}),
        std::time::Duration::from_secs(15),
    )
    .await;
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message
            .contains("federated tool 'federated_probe' is unavailable to a delegated run token"),
        "refused by the federation branch as a delegated token (not as a dead \
         delegation or an out-of-ceiling scope): {answer}"
    );
    assert!(
        control.calls().is_empty(),
        "nothing reached the extension: {:?}",
        control.calls()
    );
    assert!(
        endpoint.subjects.lock().unwrap().is_empty(),
        "the delegated bearer was not sent to the exchange"
    );

    let plain = agent_token(d.delegator_client, d.principal, None, &["claims:read"]);
    let admitted = call_as(
        &url,
        &plain,
        "federated_probe",
        serde_json::json!({}),
        std::time::Duration::from_secs(15),
    )
    .await;
    assert!(
        admitted.get("result").is_some(),
        "CALIBRATION: the same principal without `dlg` reaches the extension: {admitted}"
    );
    assert_eq!(control.calls().len(), 1, "CALIBRATION: one call reached it");
}

// ── Backlog e3614de6: a relayed result answers in the CALLER's revision ──────
//
// Prod 2026-11-21: claude.ai, on protocol 2026-07-28, called episcience's
// `list_syntheses` through the gateway and rejected the answer: "Invalid
// result for tools/call: missing required resultType". episcience-mcp speaks
// 2025-03-26, whose results carry no `resultType`, and the gateway relayed the
// result as it came.

/// The tool the legacy stub serves, named after the prod call.
const LEGACY_TOOL: &str = "list_syntheses";

/// The JSON-RPC answer in an HTTP reply body, JSON or SSE.
fn json_rpc_answer(body: &str) -> serde_json::Value {
    let data = if body.trim_start().starts_with('{') {
        body.trim()
    } else {
        body.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or_else(|| panic!("no JSON-RPC answer in:\n{body}"))
    };
    serde_json::from_str(data).expect("JSON-RPC answer")
}

/// Call `tool` as a `2026-07-28` client does: no `initialize`, no session,
/// the revision and capabilities in the request's `_meta` and in the
/// SEP-2243 headers. Returns the JSON-RPC answer.
async fn call_as_2026_07_28(url: &str, token: &str, tool: &str) -> serde_json::Value {
    let mut resp = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .send()
        .await
        .expect("POST");
    assert_eq!(resp.status().as_u16(), 200, "2026-07-28 tools/call");
    json_rpc_answer(&read_sse_data(&mut resp, std::time::Duration::from_secs(10)).await)
}

/// Call `tool` as a session client on `2024-11-05` (the `initialize`
/// handshake). Returns the JSON-RPC answer.
async fn call_as_legacy_session(url: &str, token: &str, tool: &str) -> serde_json::Value {
    let client = reqwest::Client::new();
    let session = handshake(&client, url, token).await;
    let mut resp = post(
        &client,
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}
        }),
    )
    .await;
    json_rpc_answer(&read_sse_data(&mut resp, std::time::Duration::from_secs(10)).await)
}

/// What the legacy stub answers a client that dials it DIRECTLY: the
/// negotiated revision and the `tools/call` result.
async fn direct_legacy_answer(addr: &str) -> (String, rmcp::model::CallToolResult) {
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransport;
    let transport = StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client = rmcp::serve_client((), transport)
        .await
        .expect("dial the legacy stub");
    let negotiated = client
        .peer()
        .peer_info()
        .expect("handshake result")
        .protocol_version
        .to_string();
    let result = client
        .peer()
        .call_tool(rmcp::model::CallToolRequestParams::new(LEGACY_TOOL))
        .await
        .expect("direct call");
    (negotiated, result)
}

async fn legacy_gateway() -> (String, String) {
    let (addr, _control) = stub::spawn_legacy_stub(&[LEGACY_TOOL]).await;
    let registry = FederationRegistry::build(vec![cfg("ext", &addr)], "discovery-tok")
        .await
        .expect("build against a reachable stub")
        .with_token_exchange(tx::spawn_token_endpoint(SECRET, &["ext"]).await.exchange());
    (addr, spawn_gateway(SharedFederation::new(registry)).await)
}

/// A `2026-07-28` caller of a tool whose extension speaks `2025-03-26` gets a
/// result WITH `resultType: "complete"` (the value an absent field means in
/// the extension's revision), and the extension's content unchanged.
///
/// Mutation: relay the downstream result as it came (`Ok(Ok(result)) =>
/// Ok(result)` in `invoke_once`, the pre-fix code) -> the answer has no
/// `resultType` and this fails, as claude.ai did.
#[tokio::test]
async fn a_2026_07_28_caller_gets_result_type_from_a_2025_03_26_extension() {
    let (addr, url) = legacy_gateway().await;

    // CALIBRATION: the stub really is a 2025-03-26 server whose result carries
    // no `resultType`, so the gateway has one to fill in.
    let (negotiated, direct) = direct_legacy_answer(&addr).await;
    assert_eq!(
        negotiated,
        stub::LEGACY_PROTOCOL.to_string(),
        "CALIBRATION: the stub speaks only 2025-03-26"
    );
    assert!(
        direct.result_type.is_none(),
        "CALIBRATION: a 2025-03-26 result carries no resultType: {direct:?}"
    );
    let direct_content = serde_json::to_value(&direct.content).unwrap();
    assert_eq!(
        direct_content,
        serde_json::json!([{"type": "text", "text": format!("stub handled `{LEGACY_TOOL}`")}]),
        "CALIBRATION: the stub's echo"
    );

    let answer = call_as_2026_07_28(&url, &mint_token(&["ext:tools"]), LEGACY_TOOL).await;
    let result = answer
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {answer}"));
    assert_eq!(
        result.get("resultType").and_then(serde_json::Value::as_str),
        Some("complete"),
        "a 2026-07-28 caller must get resultType on a relayed result \
         (missing required resultType): {answer}"
    );
    assert_eq!(
        result["content"], direct_content,
        "the extension's content is relayed unchanged: {answer}"
    );
    assert_ne!(
        result.get("isError"),
        Some(&serde_json::Value::Bool(true)),
        "a successful call: {answer}"
    );
}

/// The other side of "the caller's revision": a session caller on an
/// older revision is answered in its own shape, WITHOUT `resultType`, and
/// with the same content. Guards against a fix that adds the field past
/// rmcp's legacy-peer strip.
#[tokio::test]
async fn a_legacy_session_caller_gets_no_result_type_from_the_same_relay() {
    let (addr, url) = legacy_gateway().await;
    let (_, direct) = direct_legacy_answer(&addr).await;

    let answer = call_as_legacy_session(&url, &mint_token(&["ext:tools"]), LEGACY_TOOL).await;
    let result = answer
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {answer}"));
    assert!(
        result.get("resultType").is_none(),
        "a pre-2026-07-28 caller keeps the legacy shape: {answer}"
    );
    assert_eq!(
        result["content"],
        serde_json::to_value(&direct.content).unwrap(),
        "the extension's content is relayed unchanged: {answer}"
    );
}
