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
