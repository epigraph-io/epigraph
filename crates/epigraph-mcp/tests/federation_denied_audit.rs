//! Backlog b6559e75: a federated call refused for want of a bearer is AUDITED,
//! like every other federated refusal.
//!
//! `call_tool`'s federation branch has three refusals: an elevated request,
//! a caller without the extension's scope, and a caller with no raw bearer to
//! forward downstream. The first two emitted `tool.invoked` with
//! `denied:<ext>:<tool>`; the third returned without a trace. It is reachable
//! over HTTP on the unauthenticated listener: its principal-less context holds
//! every `:read` scope and comes with no token, so an extension configured
//! with a `:read` scope admits the caller through (a) and refuses it at (b).
//!
//! Driven through the router `main` builds for that listener
//! (`listener_principal`, `inject_unauthenticated_context`, the real
//! `call_tool`), against a real stub downstream, on a fresh database.
//!
//! Mutation: delete the `emit_tool_invoked` in the missing-bearer branch ->
//! no `denied:` event, and this fails.

#[path = "viewer_fixture.rs"]
mod fixture;
#[path = "support/federation_stub.rs"]
mod stub;

use std::sync::Arc;
use std::time::Duration;

use epigraph_crypto::AgentSigner;
use epigraph_mcp::auth::{ServerPrincipalSource, UnauthenticatedWrites};
use epigraph_mcp::federation::{FederationRegistry, SharedFederation};
use epigraph_mcp::unauthenticated_reader::listener_principal;
use sqlx::PgPool;

const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";

async fn spawn(pool: PgPool, federation: SharedFederation) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let signer = Arc::new(AgentSigner::from_bytes(&[0x6B; 32]).expect("signer"));
    let scoped = fixture::scoped_pool(&pool).await;
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let make = {
        let (pool, signer, embedder, scoped, federation) = (
            pool.clone(),
            signer.clone(),
            embedder.clone(),
            scoped.clone(),
            federation.clone(),
        );
        move || {
            epigraph_mcp::EpiGraphMcpFull::new_shared_with_federation(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
                federation.clone(),
                None,
            )
            .with_scoped_pool(scoped.clone())
        }
    };
    let server = Arc::new(make());
    let principal = listener_principal(
        UnauthenticatedWrites::Refused,
        server as Arc<dyn ServerPrincipalSource>,
        pool.clone(),
    )
    .await;
    let service = StreamableHttpService::new(
        move || Ok(make()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(
            principal,
            epigraph_mcp::auth::inject_unauthenticated_context,
        ),
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

async fn read_sse_data(resp: &mut reqwest::Response) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
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
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = client
        .post(url)
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST")
}

async fn handshake(client: &reqwest::Client, url: &str) -> String {
    let mut resp = post(
        client,
        url,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "federation-denied-audit", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "initialize");
    let session = resp
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = read_sse_data(&mut resp).await;
    let notif = post(
        client,
        url,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

async fn tool_invoked_count(pool: &PgPool, tool: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE event_type = 'tool.invoked' AND payload->>'tool' = $1",
    )
    .bind(tool)
    .fetch_one(pool)
    .await
    .expect("count tool.invoked events")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_federated_call_refused_for_want_of_a_bearer_is_audited(pool: PgPool) {
    let (addr, _control) = stub::spawn_controlled_stub(&["federated_probe"]).await;
    // A `:read` scope: the principal-less context holds it, so the scope gate
    // admits the caller and the missing-bearer refusal is what answers.
    let configs = epigraph_mcp::federation::config::parse_extensions(Some(&format!(
        "ext=tcp:{addr};scope=claims:read"
    )))
    .expect("a well-formed test entry");
    let federation = SharedFederation::new(
        FederationRegistry::build(configs, "discovery-tok")
            .await
            .expect("build against a reachable stub"),
    );
    assert!(
        federation.route_config("federated_probe").is_some(),
        "CALIBRATION: the stub's tool is routed"
    );
    let url = spawn(pool.clone(), federation).await;

    let client = reqwest::Client::new();
    let session = handshake(&client, &url).await;
    let mut resp = post(
        &client,
        &url,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "federated_probe", "arguments": {}}
        }),
    )
    .await;
    let body = read_sse_data(&mut resp).await;
    assert!(
        body.contains("no Bearer token to forward"),
        "CALIBRATION: the call reached the missing-bearer refusal:\n{body}"
    );

    assert_eq!(
        tool_invoked_count(&pool, "denied:ext:federated_probe").await,
        1,
        "the missing-bearer refusal must leave a `denied:<ext>:<tool>` audit event, \
         as the scope and elevation refusals beside it do"
    );
    assert_eq!(
        tool_invoked_count(&pool, "ext:federated_probe").await,
        0,
        "the refused call must not be audited as an invocation"
    );
}
