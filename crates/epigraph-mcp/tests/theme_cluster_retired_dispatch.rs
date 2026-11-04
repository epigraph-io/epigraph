//! The retired MCP `theme_cluster` tool (backlog a0ed0180, ruling R-29 as
//! revised 2026-10-26), driven through the server's REAL tool-call path: a
//! streamable-HTTP listener behind the production bearer middleware, a signed
//! token, `initialize`, then `tools/call`. So `call_tool`'s scope gate, the
//! router's parameter deserialization and the tool body all run, as they do
//! for the scheduled `theme-maintenance` prompt whose fallback still calls
//! `theme_cluster` (`docs/ops/theme-v2-promotion-runbook.md`). That call path
//! is the reason the name stays registered at all, so it is the clause under
//! test here; `theme_kmeans_retired.rs` pins the served text.
//!
//! What a stale call must get: the retirement refusal (`INVALID_REQUEST`,
//! `data.status = "retired"`, a message naming `scripts/maintain_themes.py`),
//! even when it carries the old k-means arguments, under a `claims:read`-only
//! token (the tool's scope was lowered from `claims:write` because it writes
//! nothing), and no change to `claim_themes` or to a claim's `theme_id`.
//!
//! Verified to fail against each of (uncommitted probes, one run each):
//! `server.rs::theme_cluster` returning `Ok(CallToolResult::success(..))`
//! (the call is served); `#[serde(deny_unknown_fields)]` on
//! `RetiredThemeClusterParams` (the old arguments get a "failed to deserialize
//! parameters: unknown field" tool error instead of the refusal); `scope_map`
//! putting `theme_cluster` back under `claims:write` (the scope gate refuses
//! the read-only token). The scope refusal carries the SAME code, -32600, so
//! the code alone does not tell it apart: `data.status` does.

use epigraph_crypto::AgentSigner;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

const SECRET: &[u8] = b"theme-cluster-retired-dispatch-test-secret-32b!!";

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
                       "clientInfo": {"name": "theme-cluster-retired", "version": "0"}}
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

/// `(claim_themes rows, the seeded claim's theme_id)`.
async fn theme_state(pool: &PgPool, claim: Uuid) -> (i64, Option<Uuid>) {
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM claim_themes")
        .fetch_one(pool)
        .await
        .expect("count claim_themes");
    let theme: Option<Uuid> = sqlx::query_scalar("SELECT theme_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("theme_id");
    (rows, theme)
}

/// The scheduled fallback's stale call, with the old k-means arguments
/// (`wipe_first` would have deleted every theme), under a read-only token, is
/// answered with the retirement refusal and changes nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_stale_theme_cluster_call_is_refused_through_dispatch_and_writes_nothing(pool: PgPool) {
    let (agent, _) = fixture::seed_agent_with_group(&pool, "theme-cluster-retired").await;
    let theme: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ('auto-0 seeded theme', 'kept across a stale call', 1) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("seed a theme");
    let claim =
        fixture::seed_public_claim(&pool, agent, "a claim assigned to the seeded theme").await;
    sqlx::query("UPDATE claims SET theme_id = $2 WHERE id = $1")
        .bind(claim)
        .bind(theme)
        .execute(&pool)
        .await
        .expect("assign the claim to the theme");
    let before = theme_state(&pool, claim).await;
    assert_eq!(before, (1, Some(theme)), "fixture shape");

    let url = listener(&pool).await;
    let answer = call(
        &url,
        &token(agent, &["claims:read"]),
        "theme_cluster",
        serde_json::json!({"wipe_first": true, "label_prefix": "auto", "k_max": 16}),
    )
    .await;

    let error = answer
        .get("error")
        .unwrap_or_else(|| panic!("the call must be refused, not served: {answer}"));
    assert_eq!(
        error["code"],
        serde_json::json!(-32600),
        "INVALID_REQUEST: {answer}"
    );
    // The scope gate's refusal is also -32600; only the retirement answer
    // carries this `data`.
    assert_eq!(
        error["data"]["status"], "retired",
        "the retirement refusal, not the scope gate's: {answer}"
    );
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("retired") && message.contains("maintain_themes.py"),
        "the refusal names the replacement: {answer}"
    );
    assert_eq!(
        theme_state(&pool, claim).await,
        before,
        "a refused call deletes no theme and reassigns no claim"
    );
}
