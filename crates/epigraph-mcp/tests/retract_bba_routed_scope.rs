//! MCP `retract_bba` (ruling R-79) through the server's REAL tool-call path:
//! a streamable-HTTP listener behind the production bearer middleware, a
//! signed token, `initialize`, then `tools/call`. The tool tests in
//! `retract_bba_app_role.rs` call the tool function directly, past
//! `call_tool`'s scope gate and the read-only check, so this file is what
//! pins that a `claims:read` token cannot retract over MCP (the HTTP twin
//! pins its 403 in `epigraph-api/tests/bba_retract_route.rs`).
//!
//! A read-only token is refused naming `claims:write`, with nothing written
//! (the row stays live, no audit row); the same principal with
//! `claims:write` retracts the same row through the same path (the
//! calibration: the refusal is the scope, not a malformed call).
//!
//! Verified to fail with `scope_map`'s `retract_bba` entry lowered to
//! `claims:read` (the read-only call retracts the row).

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

const SECRET: &[u8] = b"retract-bba-routed-scope-test-secret-32-bytes!!!";

/// A streamable-HTTP MCP listener behind the production bearer middleware,
/// serving sessions cloned from one template the way `main` does, on the
/// application role. Its URL.
async fn listener(pool: &PgPool) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    let scoped = fixture::scoped_pool(pool).await;
    let app = fixture::downgraded_pool(pool, "epigraph_app").await;
    let revocation = Arc::new(epigraph_mcp::auth::DbAccessTokenRevocation::new(
        app.clone(),
    ));
    let signer = Arc::new(AgentSigner::from_bytes(&[0x7c; 32]).expect("signer"));
    let embedder = Arc::new(McpEmbedder::new(app.clone(), None).with_scoped_pool(scoped.clone()));
    let template =
        EpiGraphMcpFull::new_shared(app, signer, embedder, false).with_scoped_pool(scoped);
    let sessions = SessionFactory::new(template);
    let service = StreamableHttpService::new(
        move || Ok(sessions.session()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
        revocation,
    };
    let router = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(state, epigraph_mcp::auth::bearer_auth_middleware),
    );
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = tcp.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(tcp, router).await.expect("serve");
    });
    format!("http://{addr}/mcp")
}

/// A signed `agent` token for `principal` carrying exactly `scopes`.
fn token(principal: Uuid, scopes: &[&str]) -> String {
    epigraph_auth::JwtConfig::from_secret(SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            scopes.iter().map(|s| (*s).to_string()).collect(),
            "agent",
            None,
            Some(principal),
            chrono::Duration::minutes(15),
            epigraph_auth::AccessTokenBinding::NONE,
        )
        .expect("mint")
        .0
}

async fn post(
    url: &str,
    token: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> reqwest::Response {
    let mut req = reqwest::Client::new()
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);
    if let Some(s) = session {
        req = req.header("Mcp-Session-Id", s);
    }
    req.send().await.expect("POST")
}

/// The first SSE `data:` payload of `resp`, parsed.
async fn data(mut resp: reqwest::Response) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut acc = String::new();
    while let Ok(Ok(Some(bytes))) = tokio::time::timeout_at(deadline, resp.chunk()).await {
        acc.push_str(&String::from_utf8_lossy(&bytes));
        if let Some(line) = acc
            .lines()
            .find(|l| l.starts_with("data:") && l.trim_end().len() > 5)
        {
            return serde_json::from_str(line.trim_start_matches("data:").trim())
                .unwrap_or_else(|e| panic!("SSE data is JSON ({e}): {line}"));
        }
    }
    panic!("no SSE data: {acc}");
}

/// `initialize`, `notifications/initialized`, then one `tools/call`; the
/// JSON-RPC answer of the call.
async fn call(
    url: &str,
    token: &str,
    tool: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    let init = post(
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "retract-bba-routed", "version": "0"}}
        }),
    )
    .await;
    assert_eq!(init.status().as_u16(), 200, "initialize");
    let session = init
        .headers()
        .get("Mcp-Session-Id")
        .expect("session header")
        .to_str()
        .expect("ascii")
        .to_owned();
    let _ = data(init).await;
    let notif = post(
        url,
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    data(
        post(
            url,
            token,
            Some(&session),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}
            }),
        )
        .await,
    )
    .await
}

/// `(retracted?, retract audit rows)` of one BBA, on the harness pool.
async fn state(pool: &PgPool, id: Uuid) -> (bool, i64) {
    sqlx::query_as(
        "SELECT (SELECT retracted_at IS NOT NULL FROM mass_functions WHERE id = $1), \
                (SELECT count(*) FROM security_events \
                  WHERE event_type = 'mass_functions.retract' \
                    AND details->>'mass_function_id' = $1::text)",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("state")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_read_only_token_cannot_retract_a_bba_through_dispatch(pool: PgPool) {
    let (owner, group) = fixture::seed_agent_with_group(&pool, "r79-routed-owner").await;
    // A public claim owned by the owner's own group, so the owner's BBA on it
    // is the owner's to retract.
    let claim = Uuid::new_v4();
    let hash: Vec<u8> = claim.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'r79 routed claim', $2, 0.5, $3, true, 'public', $4)",
    )
    .bind(claim)
    .bind(&hash)
    .bind(owner)
    .bind(group)
    .execute(&pool)
    .await
    .expect("seed the owner's public claim");
    let frame: Uuid = sqlx::query_scalar(
        "INSERT INTO frames (name, hypotheses) VALUES ($1, ARRAY['h0','h1']::text[]) RETURNING id",
    )
    .bind(format!("r79-routed-{}", Uuid::new_v4()))
    .fetch_one(&pool)
    .await
    .expect("seed frame");
    let bba: Uuid = sqlx::query_scalar(
        "INSERT INTO mass_functions (claim_id, frame_id, source_agent_id, masses) \
         VALUES ($1, $2, $3, '{\"0\": 0.7, \"0,1\": 0.3}'::jsonb) RETURNING id",
    )
    .bind(claim)
    .bind(frame)
    .bind(owner)
    .fetch_one(&pool)
    .await
    .expect("seed the owner's BBA");
    let args = serde_json::json!({"mass_function_id": bba, "reason": "routed retraction"});

    let url = listener(&pool).await;
    let refused = call(
        &url,
        &token(owner, &["claims:read"]),
        "retract_bba",
        args.clone(),
    )
    .await;
    let error = refused
        .get("error")
        .unwrap_or_else(|| panic!("a read-only token must be refused: {refused}"));
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("requires scope 'claims:write'"),
        "the scope gate's refusal: {refused}"
    );
    assert_eq!(
        state(&pool, bba).await,
        (false, 0),
        "a refused call retracts nothing and writes no audit row"
    );

    let admitted = call(
        &url,
        &token(owner, &["claims:read", "claims:write"]),
        "retract_bba",
        args,
    )
    .await;
    let text = admitted["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("CALIBRATION: a claims:write token is served: {admitted}"));
    let body: serde_json::Value = serde_json::from_str(text).expect("the tool's JSON reply");
    assert_eq!(body["status"], "retracted", "CALIBRATION: {body}");
    assert_eq!(state(&pool, bba).await, (true, 1));
}
