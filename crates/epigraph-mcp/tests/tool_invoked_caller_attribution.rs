//! Backlog 8c4908d6: the `tool.invoked` audit event of an MCP HTTP call names
//! the CALLER, not the gateway.
//!
//! `emit_tool_invoked` recorded `actor_id = self.agent_id()`, the server's own
//! signer agent, on every transport, while the same call's writes are
//! authored by the caller's agent (batch H-b). Driven over the real HTTP
//! path: a `--jwt-secret`-shaped listener (rmcp service behind
//! `bearer_auth_middleware`) and the real `call_tool`, on a fresh database.
//!
//! On the old code the first test fails: the event's actor is the server's
//! agent (asserted present, so the calibration is not vacuous), not the
//! caller's.

#[path = "viewer_fixture.rs"]
mod fixture;
#[path = "support/static_revocation.rs"]
mod static_revocation;

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use epigraph_auth::JwtConfig;
use epigraph_crypto::AgentSigner;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &[u8] = b"tool-invoked-caller-attribution-test-secret-0123456789";
const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";
/// The server's signer, so the test can name the gateway's agent.
const SERVER_KEY: [u8; 32] = [0x8C; 32];

async fn spawn_listener(pool: PgPool) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let signer = Arc::new(AgentSigner::from_bytes(&SERVER_KEY).expect("signer"));
    let scoped = fixture::scoped_pool(&pool).await;
    let embedder = Arc::new(
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone()),
    );
    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            )
            .with_scoped_pool(scoped.clone()))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        // Not this test's subject.
        revocation: static_revocation::StaticRevocation::none(),
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, bearer_auth_middleware),
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

/// A `claims:read` token for `client`, naming `agent` when given.
fn mint(client: Uuid, agent: Option<Uuid>) -> String {
    JwtConfig::from_secret(SECRET)
        .issue_access_token(
            client,
            vec!["claims:read".to_string()],
            "agent",
            None,
            agent,
            ChronoDuration::minutes(5),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
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
    http: &reqwest::Client,
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = http
        .post(url)
        .bearer_auth(token)
        .header("Accept", ACCEPT)
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header(SESSION_HEADER, s);
    }
    req.send().await.expect("POST")
}

/// Initialize a session with `token` and call `system_stats` on it.
async fn call_system_stats(url: &str, token: &str) -> String {
    let http = reqwest::Client::new();
    let mut resp = post(
        &http,
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "tool-invoked-attribution", "version": "0"}}
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
        &http,
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    let mut resp = post(
        &http,
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "system_stats", "arguments": {}}
        }),
    )
    .await;
    read_sse_data(&mut resp).await
}

/// `(actor_id, payload)` of every `system_stats` tool.invoked event.
async fn system_stats_events(pool: &PgPool) -> Vec<(Option<Uuid>, serde_json::Value)> {
    sqlx::query_as(
        "SELECT actor_id, payload FROM events \
          WHERE event_type = 'tool.invoked' AND payload->>'tool' = 'system_stats' \
          ORDER BY created_at",
    )
    .fetch_all(pool)
    .await
    .expect("tool.invoked events")
}

async fn agent_with_key(pool: &PgPool, key: &[u8; 32]) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(key.as_slice())
        .fetch_optional(pool)
        .await
        .expect("agent by key")
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_http_calls_tool_invoked_event_names_the_caller_not_the_gateway(pool: PgPool) {
    let caller = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(caller)
        .bind(caller.as_bytes().repeat(2))
        .execute(&pool)
        .await
        .expect("seed the caller's agent");
    let client = Uuid::new_v4();
    let url = spawn_listener(pool.clone()).await;

    let body = call_system_stats(&url, &mint(client, Some(caller))).await;
    let events = system_stats_events(&pool).await;
    assert_eq!(
        events.len(),
        1,
        "one dispatch, one event: {events:?}\n{body}"
    );
    let (actor, payload) = &events[0];

    let server_agent = AgentSigner::from_bytes(&SERVER_KEY)
        .expect("signer")
        .public_key();
    let gateway = agent_with_key(&pool, &server_agent).await;
    assert!(
        gateway.is_some(),
        "CALIBRATION: the dispatch resolved the gateway's own agent (the old actor)"
    );
    assert_eq!(
        *actor,
        Some(caller),
        "the event must name the caller's agent, not the gateway's ({gateway:?})"
    );
    assert_eq!(payload["transport"], "http", "{payload}");
    assert_eq!(payload["client_id"], client.to_string(), "{payload}");
    assert!(
        payload.get("jti").is_none() && payload.get("token_jti").is_none(),
        "the token id stays out of the broadly readable event log: {payload}"
    );
}

/// A token that names no agent (a service client) is recorded with a NULL
/// actor and its client id: never silently attributed to the gateway.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_without_an_agent_is_not_attributed_to_the_gateway(pool: PgPool) {
    let client = Uuid::new_v4();
    let url = spawn_listener(pool.clone()).await;
    let body = call_system_stats(&url, &mint(client, None)).await;
    let events = system_stats_events(&pool).await;
    assert_eq!(events.len(), 1, "{events:?}\n{body}");
    let (actor, payload) = &events[0];
    assert_eq!(*actor, None, "{payload}");
    assert_eq!(payload["client_id"], client.to_string(), "{payload}");
}
