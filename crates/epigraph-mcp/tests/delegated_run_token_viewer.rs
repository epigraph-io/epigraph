//! A delegated run token on the MCP HTTP surface.
//!
//! `call_tool` checks a token's `dlg` claim FIRST, on every tool call (the
//! delegated scope ceiling, then the delegation's liveness), whether or not
//! the tool resolves a viewer; the sites below reuse that answer:
//!
//! * `tools::viewer::request_viewer` admits an OPERATED principal only through
//!   a live delegation, and then the viewer is the principal's own membership
//!   set, which carries the operator's group;
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

/// A delegated viewer is the PRINCIPAL's own membership set, nothing more: the
/// delegator's memberships never ride along. The delegator here also writes a
/// third group; the delegated viewer holds exactly the groups the principal's
/// own viewer holds (its personal group and the operator's group).
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_viewer_never_gains_memberships_beyond_the_agents_own(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-memberships").await;
    let (_, elsewhere) = delegation::agent_with_group(&pool, "mcp-memberships-elsewhere").await;
    delegation::membership(&pool, elsewhere, d.delegator, "writer").await;
    let server = session(&pool, 0x78, RunTokens::On).await;

    let delegated = request_viewer(&server, Some(&dlg(&d, &["claims:read"])))
        .await
        .expect("a live delegation resolves a viewer");
    let own = epigraph_db::Viewer::resolve(&pool, d.principal)
        .await
        .expect("the principal's own viewer");
    let set = |groups: Option<&[Uuid]>| -> std::collections::BTreeSet<Uuid> {
        groups.unwrap_or_default().iter().copied().collect()
    };
    assert_eq!(
        set(delegated.group_bind()),
        set(own.group_bind()),
        "readable groups: exactly the principal's own"
    );
    assert_eq!(
        set(Some(delegated.writable_groups())),
        set(Some(own.writable_groups())),
        "writable groups: exactly the principal's own"
    );
    assert!(
        set(Some(delegated.writable_groups())).contains(&d.operator_group),
        "PREMISE: the principal writes the operator's group"
    );
    assert!(
        !set(delegated.group_bind()).contains(&elsewhere),
        "the delegator's other group must not reach the delegated viewer"
    );
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

/// The `claims:admin` arm of the ownership gate never runs for a delegated
/// token, whatever it carries and with the admin-scope switch UNARMED (the
/// switch state in which a standing `claims:admin` is honoured). The target is
/// authored by an UNRELATED agent but owned by the operator's group, so only
/// the admin arm could admit it. Calibration: the same principal's context
/// without `dlg` and with the same scopes is admitted through that arm.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claims_admin_arm_never_runs_for_a_dlg_token(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-admin-arm").await;
    let (stranger, _) = delegation::agent_with_group(&pool, "mcp-admin-arm-stranger").await;
    let server = session(&pool, 0x77, RunTokens::On).await;
    let scopes = ["claims:read", "claims:write", "claims:admin"];
    let unarmed = |mut ctx: AuthContext| {
        ctx.admin_scopes = epigraph_auth::AdminScopePosture::Unarmed;
        ctx
    };

    let first = backlog_claim(&pool, stranger, d.operator_group).await;
    resolve(
        &server,
        &pool,
        first,
        &unarmed(auth(d.delegator_client, d.principal, None, &scopes)),
    )
    .await
    .expect("CALIBRATION: a plain context with claims:admin passes the admin arm");

    let second = backlog_claim(&pool, stranger, d.operator_group).await;
    let err = resolve(&server, &pool, second, &unarmed(dlg(&d, &scopes)))
        .await
        .expect_err("a delegated token must never pass the claims:admin arm");
    assert!(
        err.contains("requires claims:admin scope or ownership"),
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

/// A signed `agent` token for `principal`, `sub` = `client`, `dlg` as given,
/// carrying `claims:read`.
fn signed(client: Uuid, principal: Uuid, delegated_by: Option<Uuid>) -> String {
    signed_with(client, principal, delegated_by, &["claims:read"])
}

/// [`signed`] with the given scopes.
fn signed_with(
    client: Uuid,
    principal: Uuid,
    delegated_by: Option<Uuid>,
    scopes: &[&str],
) -> String {
    epigraph_auth::JwtConfig::from_secret(CHAIN_SECRET)
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

/// One streamable-HTTP MCP session (one `Mcp-Session-Id`) under one bearer,
/// kept open across calls the way a long-running client keeps it.
struct McpSession {
    url: String,
    token: String,
    id: String,
    next: std::sync::atomic::AtomicU64,
}

impl McpSession {
    /// `initialize` + `notifications/initialized`.
    async fn open(url: &str, token: &str) -> Self {
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
        let id = init
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
            Some(&id),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        assert_eq!(notif.status().as_u16(), 202, "notifications/initialized");
        Self {
            url: url.to_owned(),
            token: token.to_owned(),
            id,
            next: std::sync::atomic::AtomicU64::new(2),
        }
    }

    /// `tools/call {tool} {arguments}` on this session; the JSON-RPC answer.
    async fn call(&self, tool: &str, arguments: serde_json::Value) -> serde_json::Value {
        let n = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let resp = post(
            &self.url,
            &self.token,
            Some(&self.id),
            serde_json::json!({
                "jsonrpc": "2.0", "id": n, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}
            }),
        )
        .await;
        data(resp).await
    }
}

/// `tools/call get_claim {claim}` on a fresh session; the JSON-RPC answer.
async fn get_claim(url: &str, token: &str, claim: Uuid) -> serde_json::Value {
    McpSession::open(url, token)
        .await
        .call(
            "get_claim",
            serde_json::json!({"claim_id": claim.to_string()}),
        )
        .await
}

/// The call succeeded (no JSON-RPC error, no tool error).
fn succeeded(answer: &serde_json::Value) -> bool {
    answer.get("error").is_none() && answer["result"]["isError"] != serde_json::json!(true)
}

/// The call was refused AS A DELEGATION that is not live, not by any other
/// gate (the operated-principal refusal a skipped check would fall to).
fn assert_dead(what: &str, answer: &serde_json::Value) {
    let text = answer.to_string();
    assert!(
        !succeeded(answer)
            && text.contains("delegation is not live")
            && !text.contains("stdio-only"),
        "{what}: refused as a delegation that is not live: {answer}"
    );
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

/// `frames` rows named `name`.
async fn frames_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM frames WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("count frames")
}

/// The delegation is checked at DISPATCH, on every tool call, not only where
/// a tool resolves a viewer. `create_frame` resolves none and writes: a live
/// delegation writes its frame; after the principal's link retires, the NEXT
/// call on the same session is refused and writes nothing; a listener built
/// OFF refuses it outright.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dead_delegation_is_refused_at_a_tool_that_resolves_no_viewer(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-viewerless").await;
    let on = listener(&pool, RunTokens::On).await;
    let off = listener(&pool, RunTokens::Off).await;
    let token = signed_with(
        d.delegator_client,
        d.principal,
        Some(d.delegator),
        &["claims:read", "claims:write"],
    );
    let frame = |name: &str| serde_json::json!({"name": name, "hypotheses": ["held", "not_held"]});
    let live_name = format!("delegated-frame-live-{}", Uuid::new_v4());
    let dead_name = format!("delegated-frame-dead-{}", Uuid::new_v4());

    let session = McpSession::open(&on, &token).await;
    let admitted = session.call("create_frame", frame(&live_name)).await;
    assert!(
        succeeded(&admitted) && frames_named(&pool, &live_name).await == 1,
        "CALIBRATION: a live delegation writes its frame: {admitted}"
    );

    delegation::retire_link(&pool, d.principal).await;
    assert_dead(
        "the link retired: the next call on the same session",
        &session.call("create_frame", frame(&dead_name)).await,
    );
    assert_dead(
        "a listener built OFF",
        &McpSession::open(&off, &token)
            .await
            .call("create_frame", frame(&dead_name))
            .await,
    );
    assert_eq!(
        frames_named(&pool, &dead_name).await,
        0,
        "a refused call wrote a frame"
    );
}

/// One long-lived session, one token: each way of ending the delegation
/// refuses the NEXT `tools/call` on that same session, at a tool that resolves
/// a viewer (`get_claim`) and at one that resolves none (`create_frame`), and
/// restoring it admits the call after. So no layer between the bearer and the
/// tool (the session manager, the middleware, the dispatch) caches the answer
/// per session. The allowance revoke is final, so it is last.
#[sqlx::test(migrations = "../../migrations")]
async fn a_long_lived_session_refuses_the_next_call_after_each_revocation(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-long-lived").await;
    let claim = fixture::seed_public_claim(&pool, d.operator, "long-lived session claim").await;
    let on = listener(&pool, RunTokens::On).await;
    let session = McpSession::open(
        &on,
        &signed_with(
            d.delegator_client,
            d.principal,
            Some(d.delegator),
            &["claims:read", "claims:write"],
        ),
    )
    .await;
    let read = || {
        session.call(
            "get_claim",
            serde_json::json!({"claim_id": claim.to_string()}),
        )
    };
    let admitted = |what: &str, answer: serde_json::Value| {
        assert!(
            succeeded(&answer) && answer.to_string().contains(&claim.to_string()),
            "{what}: the call must read the claim: {answer}"
        );
    };
    let refused = |what: &'static str| {
        let session = &session;
        let pool = &pool;
        async move {
            assert_dead(what, &read().await);
            let name = format!("long-lived-dead-{}", Uuid::new_v4());
            assert_dead(
                what,
                &session
                    .call(
                        "create_frame",
                        serde_json::json!({"name": name, "hypotheses": ["held", "not_held"]}),
                    )
                    .await,
            );
            assert_eq!(
                frames_named(pool, &name).await,
                0,
                "{what}: a refused call wrote"
            );
        }
    };
    admitted("CALIBRATION: before any revocation", read().await);

    delegation::revoke_membership(&pool, d.delegator, d.operator_group).await;
    refused("the delegator's writer row revoked").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 1, 'writer')",
    )
    .bind(d.operator_group)
    .bind(d.delegator)
    .execute(&pool)
    .await
    .expect("restore the delegator's writer row");
    admitted("the delegator's writer row restored", read().await);

    delegation::retire_link(&pool, d.principal).await;
    refused("the principal's link retired").await;
    sqlx::query("UPDATE operator_links SET retired = false WHERE agent_id = $1")
        .bind(d.principal)
        .execute(&pool)
        .await
        .expect("un-retire the link");
    admitted("the link restored", read().await);

    delegation::revoke_allowance(&pool, d.delegator_client).await;
    refused("the allowance revoked").await;
}

/// A delegated token carrying ANY scope outside the delegated ceiling is
/// refused at dispatch, before any tool, with a reason naming the ceiling.
/// Calibration: the same live delegation with `claims:read` alone reads.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dlg_token_with_a_scope_outside_the_ceiling_is_refused_at_dispatch(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "mcp-ceiling").await;
    let claim = fixture::seed_public_claim(&pool, d.operator, "ceiling claim").await;
    let on = listener(&pool, RunTokens::On).await;
    let inside = get_claim(
        &on,
        &signed(d.delegator_client, d.principal, Some(d.delegator)),
        claim,
    )
    .await;
    assert!(
        succeeded(&inside),
        "CALIBRATION: within the ceiling: {inside}"
    );
    for extra in ["claims:admin", "groups:admin", "agents:write"] {
        let answer = get_claim(
            &on,
            &signed_with(
                d.delegator_client,
                d.principal,
                Some(d.delegator),
                &["claims:read", extra],
            ),
            claim,
        )
        .await;
        let text = answer.to_string();
        assert!(
            !succeeded(&answer) && text.contains("scope ceiling") && text.contains(extra),
            "a delegated token carrying {extra} must be refused at dispatch: {answer}"
        );
    }
}
