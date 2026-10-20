//! A delegated run token on the MCP HTTP surface.
//!
//! Three sites read a token's `dlg` claim here:
//!
//! * `tools::viewer::request_viewer` admits an OPERATED principal only through
//!   a live delegation, and then the viewer carries the operator's group;
//! * `require_owner_or_admin` gives a live delegation the ACTOR arm (stdio
//!   parity: an agent acting for its operator over another of the operator's
//!   agents' claims), which a plain HTTP token never gets;
//! * every FEDERATED tool refuses a `dlg` token, so a delegated bearer is never
//!   forwarded to an extension.
//!
//! The delegation's liveness rules are in the API twin of this file
//! (`epigraph-api/tests/delegated_run_token_viewer.rs`); this file pins that
//! the MCP sites apply the same check, per request, through a session cloned
//! from the listener's template (so a switch the clone dropped would show).

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use delegation::Delegation;
use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::RunTokens;
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::claims::resolve_backlog_item;
use epigraph_mcp::tools::viewer::request_viewer;
use epigraph_mcp::types::ResolveBacklogItemParams;
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use sqlx::PgPool;
use uuid::Uuid;

#[path = "viewer_fixture.rs"]
mod fixture;

/// One HTTP session of a declared-signer listener with a stamped pool and the
/// run-token switch as given, cloned from the template the way `main` serves
/// every session.
async fn session(pool: &PgPool, seed: u8, run_tokens: RunTokens) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let template = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(run_tokens);
    SessionFactory::new(template).session()
}

/// The bearer context of an `agent`-type token for `principal`, `sub` =
/// `client`, carrying `dlg = delegated_by`.
fn auth(client: Uuid, principal: Uuid, delegated_by: Option<Uuid>, scopes: &[&str]) -> AuthContext {
    AuthContext {
        client_id: client,
        agent_id: Some(principal),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        delegated_by,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
    }
}

fn dlg(d: &Delegation, scopes: &[&str]) -> AuthContext {
    auth(d.delegator_client, d.principal, Some(d.delegator), scopes)
}

/// A live delegation resolves a viewer whose WRITABLE set holds the
/// operator's group (the authority the link confers), and it is the
/// delegation that admits: the same context without `dlg` is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_for_a_live_linked_agent_resolves_a_viewer_with_the_operator_group(
    pool: PgPool,
) {
    let d = delegation::live_delegation(&pool, "mcp-admit").await;
    let server = session(&pool, 0x71, RunTokens::On).await;

    let viewer = request_viewer(&server, Some(&dlg(&d, &["claims:read"])))
        .await
        .expect("a live delegation must resolve a viewer");
    assert!(
        viewer.writable_groups().contains(&d.operator_group),
        "the delegated viewer must carry the operator's group as writable: {:?}",
        viewer.writable_groups()
    );

    let plain = auth(d.delegator_client, d.principal, None, &["claims:read"]);
    let err = request_viewer(&server, Some(&plain))
        .await
        .expect_err("CALIBRATION: without `dlg` the operated principal gets no viewer");
    assert!(err.message.contains("stdio-only"), "{}", err.message);
}

/// The same context is refused by a session whose listener did not read the
/// switch on (the default), and by one after the principal's link retired.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_is_refused_with_the_switch_off_and_after_the_link_retires(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-refuse").await;
    let on = session(&pool, 0x72, RunTokens::On).await;
    let off = session(&pool, 0x73, RunTokens::Off).await;
    let ctx = dlg(&d, &["claims:read"]);

    request_viewer(&on, Some(&ctx))
        .await
        .expect("CALIBRATION: switch on, live delegation");
    request_viewer(&off, Some(&ctx))
        .await
        .expect_err("switch off: a delegated token gets no viewer");

    delegation::retire_link(&pool, d.principal).await;
    request_viewer(&on, Some(&ctx))
        .await
        .expect_err("the link retired: the next call gets no viewer");
}

/// An unlinked principal cannot be delegated to: a `dlg` context for it gets
/// no viewer, although its own context without `dlg` does.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_for_an_unlinked_agent_gets_no_viewer(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-unlinked").await;
    let (unlinked, _) = delegation::agent_with_group(&pool, "mcp-unlinked-principal").await;
    let server = session(&pool, 0x74, RunTokens::On).await;

    request_viewer(
        &server,
        Some(&auth(d.delegator_client, unlinked, None, &["claims:read"])),
    )
    .await
    .expect("CALIBRATION: the unlinked agent's own token resolves a viewer");
    request_viewer(
        &server,
        Some(&auth(
            d.delegator_client,
            unlinked,
            Some(d.delegator),
            &["claims:read"],
        )),
    )
    .await
    .expect_err("a dlg token for an unlinked principal must get no viewer");
}

/// A `('public', owner)` claim authored by `author`, labelled `backlog`.
async fn backlog_claim(pool: &PgPool, author: Uuid, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY['backlog'], true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("delegated ownership claim {id}"))
    .bind(hash)
    .bind(author)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

/// `resolve_backlog_item` on `target` as `ctx`, with the principal's own
/// viewer resolved on the harness pool (as `operator_ownership.rs` does), so
/// the OWNERSHIP gate is what decides, not the viewer extractor.
async fn resolve(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    target: Uuid,
    ctx: &AuthContext,
) -> Result<(), String> {
    let viewer = epigraph_db::Viewer::resolve(pool, ctx.agent_id.expect("principal"))
        .await
        .expect("the principal's viewer");
    resolve_backlog_item(
        server,
        &viewer,
        ResolveBacklogItemParams {
            original_id: target.to_string(),
            resolution_content: format!("resolved {target}"),
            methodology: None,
            basis_claim_ids: Vec::new(),
        },
        Some(ctx),
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

async fn labels(pool: &PgPool, claim: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels")
}

/// The ACTOR arm over HTTP. A delegated principal acts for its operator over a
/// SIBLING agent's claim (both linked to the same operator), as it would over
/// stdio; a plain HTTP context for the same principal never does (operated
/// agents are refused the actor arm over HTTP). Once the delegation stops
/// being live (the delegator suspended), the actor arm closes again.
#[sqlx::test(migrations = "../../migrations")]
async fn the_actor_arm_is_admitted_for_a_dlg_token_and_not_for_a_plain_one(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-actor").await;
    let sibling = delegation::linked_principal(&pool, d.operator, "mcp-actor-sibling").await;
    let server = session(&pool, 0x75, RunTokens::On).await;
    let scopes = ["claims:read", "claims:write"];

    let first = backlog_claim(&pool, sibling, d.operator_group).await;
    resolve(&server, &pool, first, &dlg(&d, &scopes))
        .await
        .expect("a live delegation must act for its operator over a sibling's claim");
    assert!(
        labels(&pool, first).await.contains(&"resolved".to_string()),
        "the admitted retirement must land"
    );

    let second = backlog_claim(&pool, sibling, d.operator_group).await;
    let plain = auth(d.delegator_client, d.principal, None, &scopes);
    let err = resolve(&server, &pool, second, &plain)
        .await
        .expect_err("CALIBRATION: a plain HTTP token is never an actor");
    assert!(
        err.contains("claims:admin"),
        "the ownership gate refused: {err}"
    );

    delegation::set_client_status(&pool, d.delegator_client, "suspended").await;
    let err = resolve(&server, &pool, second, &dlg(&d, &scopes))
        .await
        .expect_err("the delegator suspended: the next call must not act");
    assert!(
        err.contains("claims:admin"),
        "the ownership gate refused: {err}"
    );
    assert!(
        !labels(&pool, second)
            .await
            .contains(&"resolved".to_string()),
        "a refused retirement wrote"
    );
}

/// Every federated tool refuses a delegated token, BEFORE its bearer could be
/// forwarded downstream, whatever scope it carries. Calibration: the same
/// context without `dlg` passes the same gate.
#[test]
fn a_federated_tool_is_refused_for_a_dlg_token() {
    let principal = Uuid::new_v4();
    let client = Uuid::new_v4();
    let scopes = ["ext:read"];
    EpiGraphMcpFull::enforce_federated_scope(
        Some(&auth(client, principal, None, &scopes)),
        "ext_tool",
        "ext:read",
    )
    .expect("CALIBRATION: a plain token with the extension's scope passes");
    let err = EpiGraphMcpFull::enforce_federated_scope(
        Some(&auth(client, principal, Some(Uuid::new_v4()), &scopes)),
        "ext_tool",
        "ext:read",
    )
    .expect_err("a delegated token must never reach a federated tool");
    assert!(err.message.contains("delegated"), "{}", err.message);
}

// ─────────────────────────────────────────────────────────────────────────────
// The whole chain on the real HTTP listener: a SIGNED token carrying `dlg`,
// through `auth::bearer_auth_middleware` (`claims.into()`), `call_tool` and a
// tool's `request_viewer`, on application-role pools as `main` wires them. The
// tests above build `AuthContext` by hand, so none of them would notice a
// layer between the JWT and the tool that dropped the claim.
// ─────────────────────────────────────────────────────────────────────────────

const CHAIN_SECRET: &[u8] = b"delegated-run-token-chain-test-secret-32-bytes!!";

/// A streamable-HTTP MCP listener behind the production bearer middleware,
/// with the run-token switch as given. Its URL.
async fn listener(pool: &PgPool, run_tokens: RunTokens) -> String {
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
    let signer = Arc::new(AgentSigner::from_bytes(&[0x76; 32]).expect("signer"));
    let embedder = Arc::new(McpEmbedder::new(app.clone(), None).with_scoped_pool(scoped.clone()));
    let template = EpiGraphMcpFull::new_shared(app, signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(run_tokens);
    let sessions = SessionFactory::new(template);
    let service = StreamableHttpService::new(
        move || Ok(sessions.session()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let state = epigraph_mcp::auth::McpAuthState {
        jwt_config: Arc::new(epigraph_auth::JwtConfig::from_secret(CHAIN_SECRET)),
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

/// A signed `agent` token for `principal`, `sub` = `client`, `dlg` as given.
fn signed(client: Uuid, principal: Uuid, delegated_by: Option<Uuid>) -> String {
    epigraph_auth::JwtConfig::from_secret(CHAIN_SECRET)
        .issue_access_token(
            client,
            vec!["claims:read".to_string()],
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

/// `tools/call get_claim {claim}` on a fresh session; the JSON-RPC answer.
async fn get_claim(url: &str, token: &str, claim: Uuid) -> serde_json::Value {
    let init = post(
        url,
        token,
        None,
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "delegated-chain-test", "version": "0"}}
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
    let resp = post(
        url,
        token,
        Some(&session),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "get_claim", "arguments": {"claim_id": claim.to_string()}}
        }),
    )
    .await;
    data(resp).await
}

/// A signed delegated token reaches a tool on a listener built ON, and is
/// refused as a delegation (not as a plain operated principal) on one built
/// OFF; the same principal's token without `dlg` is refused as operated. So
/// the claim survives every layer between the JWT and the tool.
#[sqlx::test(migrations = "../../migrations")]
async fn a_signed_dlg_token_reaches_a_tool_through_the_real_http_listener(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-chain").await;
    let claim = fixture::seed_public_claim(&pool, d.operator, "delegated chain claim").await;
    let on = listener(&pool, RunTokens::On).await;
    let off = listener(&pool, RunTokens::Off).await;
    let dlg_token = signed(d.delegator_client, d.principal, Some(d.delegator));

    let admitted = get_claim(&on, &dlg_token, claim).await;
    assert!(
        admitted.get("error").is_none()
            && admitted["result"]["isError"] != serde_json::json!(true)
            && admitted.to_string().contains(&claim.to_string()),
        "switch on: the delegated token must read the claim: {admitted}"
    );

    let refused = get_claim(&off, &dlg_token, claim).await;
    assert!(
        refused.to_string().contains("delegation is not live"),
        "switch off: refused as a delegation, so the `dlg` claim reached the tool: {refused}"
    );

    let plain = get_claim(&on, &signed(d.delegator_client, d.principal, None), claim).await;
    assert!(
        plain.to_string().contains("stdio-only"),
        "CALIBRATION: without `dlg` the operated principal is refused: {plain}"
    );
}
