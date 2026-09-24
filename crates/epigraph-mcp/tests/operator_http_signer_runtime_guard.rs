//! An HTTP listener refuses every tool call while its signer agent has an
//! operator link — checked PER CALL, not only at startup (review findings F3 /
//! F13).
//!
//! `operator::refuse_operated_http_signer` stops a listener from STARTING as a
//! linked signer, but it runs once. Every write re-reads the operator records,
//! so a link recorded after the listener started (a stdio process under the same
//! key with `EPIGRAPH_OPERATOR_ID` set, or an operator recording a retired link)
//! would take effect at once and stay live until the next restart: every OAuth
//! caller's claims authored into, or owned by, the operator's group.
//! `server::call_tool` therefore calls `operator::refuse_linked_http_signer` on
//! every HTTP call.
//!
//! This drives the REAL `call_tool` over the streamable-HTTP transport with the
//! bearer middleware in front (the harness `http_auth_test.rs` uses), against a
//! `#[sqlx::test]` database:
//!
//! 1. CALIBRATION — the signer is unlinked, and a tool call is not refused;
//! 2. the signer is linked AFTER the listener started (acting link in one test,
//!    retired link in the other);
//! 3. the very next call on the SAME session is refused, naming the link.

#[path = "viewer_fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use epigraph_auth::JwtConfig;
use epigraph_crypto::AgentSigner;
use epigraph_mcp::auth::{bearer_auth_middleware, McpAuthState};
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &[u8] = b"runtime-guard-test-secret-at-least-32-bytes!!";
const ACCEPT: &str = "application/json, text/event-stream";
const SESSION_HEADER: &str = "Mcp-Session-Id";
const REFUSAL: &str = "has an operator link to";
const OPERATOR_REFUSAL: &str = "is the operator of linked agents";

fn token() -> String {
    let (token, _) = JwtConfig::from_secret(SECRET)
        .issue_access_token(
            Uuid::new_v4(),
            vec!["claims:read".to_string()],
            "service",
            None,
            None,
            ChronoDuration::minutes(5),
        )
        .expect("mint");
    token
}

/// The router `main` builds for `--listen --jwt-secret`, over `pool`, signing
/// as `signer`, bound to an ephemeral port.
async fn spawn_listener(pool: PgPool, signer: AgentSigner) -> String {
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    let signer = Arc::new(signer);
    let embedder = Arc::new(epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None));
    let service = StreamableHttpService::new(
        move || {
            Ok(epigraph_mcp::EpiGraphMcpFull::new_shared(
                pool.clone(),
                signer.clone(),
                embedder.clone(),
                false,
            ))
        },
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = McpAuthState {
        jwt_config: Arc::new(JwtConfig::from_secret(SECRET)),
        resource_metadata_url: None,
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
                       "clientInfo": {"name": "runtime-guard-test", "version": "0"}}
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
        token,
        Some(&session),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
    session
}

async fn call(client: &reqwest::Client, url: &str, token: &str, session: &str, id: u32) -> String {
    let mut resp = post(
        client,
        url,
        token,
        Some(session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "get_claim",
                       "arguments": {"claim_id": Uuid::new_v4().to_string()}}
        }),
    )
    .await;
    read_sse_data(&mut resp).await
}

#[derive(Clone, Copy)]
enum LinkKind {
    Acting,
    Retired,
    /// The signer becomes some OTHER agent's operator (102 section 9).
    Operator,
}

async fn a_link_recorded_after_startup_refuses_the_next_call(pool: PgPool, kind: LinkKind) {
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let seed = match kind {
        LinkKind::Acting => 0x71,
        LinkKind::Retired => 0x72,
        LinkKind::Operator => 0x73,
    };
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let public_key = signer.public_key();
    let url = spawn_listener(pool.clone(), signer).await;
    let client = reqwest::Client::new();
    let token = token();
    let session = handshake(&client, &url, &token).await;

    // 1. CALIBRATION: unlinked signer, the call is dispatched (the tool's own
    //    answer — not-found for a random claim id — is irrelevant).
    let before = call(&client, &url, &token, &session, 2).await;
    assert!(
        before.contains("data:") && !before.contains(REFUSAL),
        "CALIBRATION: an unlinked signer's call must not be refused, or the refusal below \
         proves nothing:\n{before}"
    );

    // 2. Link the signer AFTER startup, as a later stdio process or an operator
    //    recording a retired link would.
    let signer_agent: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(public_key.to_vec())
        .fetch_one(&pool)
        .await
        .expect("the listener registered its signer agent on the first call");
    let mut conn = pool.acquire().await.expect("acquire");
    match kind {
        LinkKind::Acting => {
            epigraph_db::AgentRepository::link_operator(&mut conn, signer_agent, operator)
                .await
                .expect("acting link");
        }
        LinkKind::Retired => {
            epigraph_db::AgentRepository::link_retired_agent(&mut conn, signer_agent, operator)
                .await
                .expect("retired link");
        }
        LinkKind::Operator => {
            let operated: Uuid = sqlx::query_scalar(
                "INSERT INTO agents (id, public_key, agent_type) \
                 VALUES (gen_random_uuid(), $1, 'system') RETURNING id",
            )
            .bind(vec![0x74u8; 32])
            .fetch_one(&pool)
            .await
            .expect("an agent for the signer to operate");
            epigraph_db::AgentRepository::link_retired_agent(&mut conn, operated, signer_agent)
                .await
                .expect("link an agent with the SIGNER as its operator");
        }
    }
    drop(conn);

    // 3. The next call on the same session is refused, naming why.
    let after = call(&client, &url, &token, &session, 3).await;
    let refused = match kind {
        LinkKind::Acting | LinkKind::Retired => {
            after.contains(REFUSAL) && after.contains(&operator.to_string())
        }
        LinkKind::Operator => {
            after.contains(OPERATOR_REFUSAL) && after.contains(&signer_agent.to_string())
        }
    };
    assert!(
        refused,
        "an HTTP listener kept serving after its signer was linked, or became an operator: \
         every caller's claims would be authored into, or owned by, the operator's group (or, \
         unauthenticated, every caller would own the linked agents' claims) until a \
         restart:\n{after}"
    );
}

/// The signer becomes some other agent's OPERATOR after startup (102 section
/// 9): on an unauthenticated transport every caller IS the signer, so the
/// listener must refuse rather than hand every caller the operator arm.
#[sqlx::test(migrations = "../../migrations")]
async fn a_signer_that_becomes_an_operator_after_startup_refuses_the_next_http_call(pool: PgPool) {
    a_link_recorded_after_startup_refuses_the_next_call(pool, LinkKind::Operator).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_acting_link_recorded_after_startup_refuses_the_next_http_call(pool: PgPool) {
    a_link_recorded_after_startup_refuses_the_next_call(pool, LinkKind::Acting).await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_recorded_after_startup_refuses_the_next_http_call(pool: PgPool) {
    a_link_recorded_after_startup_refuses_the_next_call(pool, LinkKind::Retired).await;
}
