//! The DELEGATE arm of `require_owner_or_admin` (operator ruling R-183): an
//! agent whose LIVE operator link names a claim's AUTHOR is admitted to that
//! author's claims wherever the author itself is admitted by identity.
//!
//! Before R-183 the ownership gate had two operator arms (migration 107): the
//! operator over its linked agents' claims, and an agent acting for the
//! operator over its operator's OTHER agents' claims. An agent did not own a
//! claim its operator authored directly. The delegate arm closes exactly that
//! case, one hop, through the caller's ACTING link
//! (`AgentRepository::operator_actor`: not retired, and a live writer
//! membership of the operator's own group). Over HTTP it runs only for a
//! delegated run token whose delegation is live, as the actor arm does.
//!
//! The gate's decision depends on authorship and the link records, never on
//! RLS, so the superuser harness observes it faithfully (as
//! `operator_ownership.rs` does); every admission is asserted by its committed
//! effect and every refusal by the gate's own text.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

use epigraph_auth::{AuthContext, ClientType};
use epigraph_crypto::AgentSigner;
use epigraph_db::{AgentRepository, RunTokens};
use epigraph_mcp::embed::McpEmbedder;
use epigraph_mcp::tools::claims::resolve_backlog_item;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::{ResolveBacklogItemParams, SupersedeClaimParams};
use epigraph_mcp::{EpiGraphMcpFull, SessionFactory};
use sqlx::PgPool;
use uuid::Uuid;

/// The stdio gate's refusal for a declared signer (before and after R-183).
const STDIO_REFUSAL: &str = "cannot retire it";
/// The HTTP gate's refusal (before and after R-183).
const HTTP_REFUSAL: &str = "requires claims:admin scope or ownership";

/// A declared-signer stdio server with a stamped pool, and its agent id.
async fn stdio_server(pool: &PgPool, seed: u8) -> (EpiGraphMcpFull, Uuid) {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let server =
        EpiGraphMcpFull::new(pool.clone(), signer, embedder, false).with_scoped_pool(scoped);
    let id = server.server_agent_id().await.expect("server agent id");
    (server, id)
}

/// One HTTP session of a declared-signer listener with run tokens on.
async fn http_session(pool: &PgPool, seed: u8) -> EpiGraphMcpFull {
    let scoped = fixture::scoped_pool(pool).await;
    let signer = AgentSigner::from_bytes(&[seed; 32]).expect("signer");
    let embedder = McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    let template = EpiGraphMcpFull::new(pool.clone(), signer, embedder, false)
        .with_scoped_pool(scoped)
        .with_run_tokens(RunTokens::On);
    SessionFactory::new(template).session()
}

fn auth(client: Uuid, principal: Uuid, delegated_by: Option<Uuid>) -> AuthContext {
    AuthContext {
        client_id: client,
        agent_id: Some(principal),
        owner_id: None,
        client_type: ClientType::Agent,
        scopes: vec!["claims:read".to_string(), "claims:write".to_string()],
        jti: Uuid::new_v4(),
        family_id: None,
        elevation_claim: None,
        elevation: None,
        delegated_by,
        admin_scopes: epigraph_auth::AdminScopePosture::Armed,
    }
}

fn dlg(d: &delegation::Delegation) -> AuthContext {
    auth(d.delegator_client, d.principal, Some(d.delegator))
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) {
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link");
    assert!(out.membership_live && out.link_live, "{out:?}");
}

async fn acting_operator(pool: &PgPool, agent: Uuid) -> Option<Uuid> {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::operator_actor(&mut conn, agent)
        .await
        .expect("operator_actor")
        .map(|l| l.operator_id)
}

/// A `('public', owner)` claim authored by `author`, labelled `backlog`.
async fn claim(pool: &PgPool, author: Uuid, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY['backlog'], true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("delegate-ownership claim {id}"))
    .bind(hash)
    .bind(author)
    .bind(owner)
    .execute(pool)
    .await
    .expect("seed claim");
    id
}

async fn is_current(pool: &PgPool, claim: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("is_current")
}

async fn is_resolved(pool: &PgPool, claim: Uuid) -> bool {
    let labels: Vec<String> = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("labels");
    labels.contains(&"resolved".to_string())
}

/// `supersede_claim` on stdio.
async fn supersede_stdio(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    target: Uuid,
) -> Result<(), String> {
    supersede_claim(
        server,
        &fixture::public_viewer(pool).await,
        SupersedeClaimParams {
            claim_id: target.to_string(),
            content: format!("replacement for {target}"),
            truth_value: 0.7,
            reason: "delegate-ownership test".to_string(),
        },
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

/// `resolve_backlog_item` on `target`, on stdio (`ctx: None`) or as `ctx`
/// with its principal's own viewer resolved on the harness pool, so the
/// ownership gate decides, not the viewer extractor.
async fn resolve(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    target: Uuid,
    ctx: Option<&AuthContext>,
) -> Result<(), String> {
    let viewer = match ctx.and_then(|c| c.agent_id) {
        Some(principal) => epigraph_db::Viewer::resolve(pool, principal)
            .await
            .expect("the principal's viewer"),
        None => fixture::public_viewer(pool).await,
    };
    resolve_backlog_item(
        server,
        &viewer,
        ResolveBacklogItemParams {
            original_id: target.to_string(),
            resolution_content: format!("resolved {target}"),
            methodology: None,
            basis_claim_ids: Vec::new(),
        },
        ctx,
    )
    .await
    .map(|_| ())
    .map_err(|e| e.message.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// RED: the delegate arm
// ─────────────────────────────────────────────────────────────────────────────

/// stdio: an agent live-linked to a human may supersede and resolve the
/// human's OWN claims (R-183). Before, it was refused: the human has no link
/// record of its own, so no operator arm matched.
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_delegate_owns_its_operators_own_claims_on_stdio(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "delegate-stdio-operator").await;
    let (server, me) = stdio_server(&pool, 0x61).await;
    link(&pool, me, p).await;

    let c1 = claim(&pool, p, p_g).await;
    supersede_stdio(&server, &pool, c1)
        .await
        .expect("a live delegate supersedes its operator's own claim");
    assert!(!is_current(&pool, c1).await, "the supersede committed");

    let c2 = claim(&pool, p, p_g).await;
    resolve(&server, &pool, c2, None)
        .await
        .expect("a live delegate resolves its operator's own backlog item");
    assert!(is_resolved(&pool, c2).await, "the resolution committed");
}

/// HTTP: a delegated run token whose delegation is live is admitted over the
/// operator's own claim; the same principal without `dlg` is not (an operated
/// agent's plain HTTP context never gets an actor-side arm).
#[sqlx::test(migrations = "../../migrations")]
async fn a_live_delegated_token_owns_the_operators_own_claims_over_http(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "delegate-http").await;
    let server = http_session(&pool, 0x62).await;

    let first = claim(&pool, d.operator, d.operator_group).await;
    resolve(&server, &pool, first, Some(&dlg(&d)))
        .await
        .expect("a live delegated token resolves its operator's own backlog item");
    assert!(is_resolved(&pool, first).await, "the resolution committed");

    let second = claim(&pool, d.operator, d.operator_group).await;
    let plain = auth(d.delegator_client, d.principal, None);
    let err = resolve(&server, &pool, second, Some(&plain))
        .await
        .expect_err("a plain HTTP context for an operated agent is no delegate");
    assert!(
        err.contains(HTTP_REFUSAL),
        "the ownership gate refused: {err}"
    );
    assert!(!is_resolved(&pool, second).await, "the refusal wrote");
}

// ─────────────────────────────────────────────────────────────────────────────
// GUARDS
// ─────────────────────────────────────────────────────────────────────────────

/// Refused by the stdio gate, nothing written.
async fn assert_stdio_refused(server: &EpiGraphMcpFull, pool: &PgPool, target: Uuid, what: &str) {
    let err = supersede_stdio(server, pool, target)
        .await
        .expect_err(&format!("{what}: must be refused"));
    assert!(
        err.contains(STDIO_REFUSAL),
        "{what}: the gate refused: {err}"
    );
    assert!(is_current(pool, target).await, "{what}: the refusal wrote");
}

/// A retired link (its writer membership still live), a revoked membership
/// under a not-retired link, a link to another human, and no link: none owns
/// the human's claim.
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_live_link_to_the_author_is_a_delegate(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "delegate-guard-operator").await;
    let (q, _) = delegation::human_operator(&pool, "delegate-guard-other").await;

    let (retired_server, retired) = stdio_server(&pool, 0x63).await;
    link(&pool, retired, p).await;
    delegation::retire_link(&pool, retired).await;
    let (revoked_server, revoked) = stdio_server(&pool, 0x64).await;
    link(&pool, revoked, p).await;
    delegation::revoke_membership(&pool, revoked, p_g).await;
    let (other_server, other) = stdio_server(&pool, 0x65).await;
    link(&pool, other, q).await;
    let (unlinked_server, unlinked) = stdio_server(&pool, 0x66).await;

    assert_eq!(acting_operator(&pool, retired).await, None, "PREMISE");
    assert_eq!(acting_operator(&pool, revoked).await, None, "PREMISE");
    assert_eq!(acting_operator(&pool, other).await, Some(q), "PREMISE");
    assert_eq!(acting_operator(&pool, unlinked).await, None, "PREMISE");

    for (server, what) in [
        (&retired_server, "a retired link"),
        (&revoked_server, "a revoked link membership"),
        (&other_server, "a link to another human"),
        (&unlinked_server, "no link"),
    ] {
        let c = claim(&pool, p, p_g).await;
        assert_stdio_refused(server, &pool, c, what).await;
    }
}

/// HTTP: a live delegation for ANOTHER human's agent does not own this
/// human's claim.
#[sqlx::test(migrations = "../../migrations")]
async fn a_delegated_token_for_another_humans_agent_owns_nothing_here(pool: PgPool) {
    let d = delegation::live_delegation(&pool, "delegate-http-other").await;
    let (p, p_g) = delegation::human_operator(&pool, "delegate-http-not-mine").await;
    let server = http_session(&pool, 0x67).await;
    let c = claim(&pool, p, p_g).await;
    let err = resolve(&server, &pool, c, Some(&dlg(&d)))
        .await
        .expect_err("a delegate of another human owns nothing here");
    assert!(
        err.contains(HTTP_REFUSAL),
        "the ownership gate refused: {err}"
    );
    assert!(!is_resolved(&pool, c).await);
}

/// ONE hop: an agent operated by an agent operated by the human owns none of
/// the human's claims. The link verb refuses to build such a chain, so the
/// fixture writes it directly (triggers off, superuser).
#[sqlx::test(migrations = "../../migrations")]
async fn a_two_hop_chain_owns_nothing(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "delegate-chain-operator").await;
    let (b, b_g) = delegation::agent_with_group(&pool, "delegate-chain-middle").await;
    link(&pool, b, p).await;
    let (server, a) = stdio_server(&pool, 0x68).await;
    {
        use sqlx::Executor;
        let mut tx = pool.begin().await.expect("begin");
        tx.execute("SET LOCAL session_replication_role = replica")
            .await
            .expect("triggers off for the forged chain");
        sqlx::query(
            "INSERT INTO operator_links (agent_id, operator_id, operator_group_id, retired) \
             VALUES ($1, $2, $3, false)",
        )
        .bind(a)
        .bind(b)
        .bind(b_g)
        .execute(&mut *tx)
        .await
        .expect("forge a -> b");
        sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(b_g)
        .bind(a)
        .execute(&mut *tx)
        .await
        .expect("a writes b's group");
        tx.commit().await.expect("commit the forged chain");
    }
    assert_eq!(
        acting_operator(&pool, a).await,
        Some(b),
        "PREMISE: a acts for b"
    );
    assert_eq!(
        acting_operator(&pool, b).await,
        Some(p),
        "PREMISE: b acts for p"
    );
    let c = claim(&pool, p, p_g).await;
    assert_stdio_refused(&server, &pool, c, "a two-hop chain").await;
}
