//! The ownership gate's LINK arms against a concurrent link retire (backlog
//! 9a5bc055), on the application role.
//!
//! `require_owner_or_admin` admits a caller whose ACTING operator link names
//! the claim's author (the delegate arm) or the author's operator (the actor
//! arm). The act then writes on its own stamped transaction. Before this fix
//! the gate read that link on the server's pool, outside the act's
//! transaction, so an operator could retire the link between the gate's read
//! and the act's commit, and the act still landed with authority the agent no
//! longer held.
//!
//! The race is made deterministic with a second session. It opens 191's
//! retire verb (`epigraph_retire_operator_link`, with the membership revoke)
//! and holds it UNCOMMITTED, so the act's gate starts while the link is still
//! committed as live. The test waits until the act has either finished or is
//! waiting on a lock, then commits the retire, then awaits the act:
//!
//! * now: the gate re-reads the link on the act's transaction under 107's
//!   link advisory lock (shared). It waits for the retire, re-reads the
//!   retired link, and the act is refused with nothing written;
//! * before: the gate read the live link on the pool and the act committed,
//!   either before the retire or right after it.
//!
//! The MCP server runs on `epigraph_app` (a downgraded login, no BYPASSRLS),
//! so the lock statement's privilege and the stamped writes are the
//! production ones. The fixture rows and the retire session use the
//! harness's superuser pool, which 191 admits as a maintenance session.

#[path = "viewer_fixture.rs"]
mod fixture;

#[path = "../../epigraph-db/tests/support/delegation_fixture.rs"]
mod delegation;

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use epigraph_db::{AgentRepository, ScopedPool, SessionGucMode};
use epigraph_mcp::server::EpiGraphMcpFull;
use epigraph_mcp::tools::supersede::supersede_claim;
use epigraph_mcp::types::SupersedeClaimParams;
use sqlx::PgPool;
use uuid::Uuid;

/// The stdio gate's refusal for a declared signer.
const STDIO_REFUSAL: &str = "cannot retire it";

/// A declared-signer stdio server whose pools are `epigraph_app`, and its agent.
async fn app_role_server(pool: &PgPool) -> (EpiGraphMcpFull, Uuid) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app");
    assert!(!bypassrls, "CALIBRATION: epigraph_app holds no BYPASSRLS");
    let url = fixture::database_url_for(pool).await;
    let scoped =
        ScopedPool::connect_downgraded_for_tests(&url, SessionGucMode::Session, "epigraph_app")
            .await
            .expect("app-role ScopedPool");
    let plain = fixture::downgraded_pool(pool, "epigraph_app").await;
    let server = common::build_scoped_test_server(plain, scoped);
    let agent = server.server_agent_id().await.expect("server agent");
    (server, agent)
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

/// A current `('public', owner)` claim authored by `author`.
async fn claim(pool: &PgPool, author: Uuid, owner: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, labels, \
                             is_current, visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, ARRAY['backlog'], true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("link-retire race claim {id}"))
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

/// Claims that name `claim` as the one they supersede.
async fn replacements(pool: &PgPool, claim: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM claims WHERE supersedes = $1")
        .bind(claim)
        .fetch_one(pool)
        .await
        .expect("replacements")
}

/// Sessions of this database waiting on a lock they have not been granted.
async fn lock_waiters(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
          WHERE NOT l.granted AND a.datname = current_database()",
    )
    .fetch_one(pool)
    .await
    .expect("pg_locks")
}

/// Supersede `target` on `server` (stdio: no `AuthContext`) while a retire of
/// `retiring`'s operator link is held open on another session, committing the
/// retire once the act has finished or is waiting on a lock. Returns the act's
/// outcome.
async fn supersede_racing_a_retire(
    server: &EpiGraphMcpFull,
    pool: &PgPool,
    target: Uuid,
    retiring: Uuid,
) -> Result<(), String> {
    let mut retire = pool.begin().await.expect("begin the retire");
    let (outcome, revoked): (String, i32) = sqlx::query_as(
        "SELECT outcome, memberships_revoked \
           FROM public.epigraph_retire_operator_link($1, 'link-retire race test', true)",
    )
    .bind(retiring)
    .fetch_one(&mut *retire)
    .await
    .expect("the retire verb");
    assert_eq!(
        (outcome.as_str(), revoked),
        ("retired", 1),
        "PREMISE: the retire retires the live link and revokes its writer row"
    );
    assert!(
        acting_operator(pool, retiring).await.is_some(),
        "PREMISE: the retire is not committed, so the link still reads as acting"
    );

    let viewer = fixture::public_viewer(pool).await;
    let done = AtomicBool::new(false);
    let act = async {
        let out = supersede_claim(
            server,
            &viewer,
            SupersedeClaimParams {
                claim_id: target.to_string(),
                content: format!("replacement for {target}"),
                truth_value: 0.7,
                reason: "link-retire race test".to_string(),
            },
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.message.to_string());
        done.store(true, Ordering::SeqCst);
        out
    };
    let commit_the_retire = async {
        for _ in 0..200 {
            if done.load(Ordering::SeqCst) || lock_waiters(pool).await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        retire.commit().await.expect("commit the retire");
    };
    let (out, ()) = tokio::join!(act, commit_the_retire);
    out
}

/// The DELEGATE arm: the stdio server's agent is live-linked to a human and
/// supersedes the human's own claim while the human retires that link.
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_retired_during_a_delegate_act_refuses_it(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "race-delegate-operator").await;
    let (server, me) = app_role_server(&pool).await;
    link(&pool, me, p).await;
    assert_eq!(acting_operator(&pool, me).await, Some(p), "PREMISE");

    let c = claim(&pool, p, p_g).await;
    let err = supersede_racing_a_retire(&server, &pool, c, me)
        .await
        .expect_err("an act admitted on a link retired before it committed must be refused");
    assert!(
        err.contains(STDIO_REFUSAL),
        "the ownership gate refused: {err}"
    );
    assert_eq!(
        acting_operator(&pool, me).await,
        None,
        "the retire committed"
    );
    assert!(
        is_current(&pool, c).await,
        "the refused act retired the claim"
    );
    assert_eq!(
        replacements(&pool, c).await,
        0,
        "the refused act wrote a replacement"
    );
}

/// The ACTOR arm: the stdio server's agent and another agent are both linked
/// to one human; the server's agent supersedes the other agent's claim while
/// the human retires the server agent's link.
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_retired_during_an_actor_act_refuses_it(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "race-actor-operator").await;
    let sibling = delegation::linked_principal(&pool, p, "race-actor-sibling").await;
    let (server, me) = app_role_server(&pool).await;
    link(&pool, me, p).await;
    assert_eq!(acting_operator(&pool, me).await, Some(p), "PREMISE");

    let c = claim(&pool, sibling, p_g).await;
    let err = supersede_racing_a_retire(&server, &pool, c, me)
        .await
        .expect_err("an act admitted on a link retired before it committed must be refused");
    assert!(
        err.contains(STDIO_REFUSAL),
        "the ownership gate refused: {err}"
    );
    assert_eq!(
        acting_operator(&pool, me).await,
        None,
        "the retire committed"
    );
    assert!(
        is_current(&pool, c).await,
        "the refused act retired the claim"
    );
    assert_eq!(
        replacements(&pool, c).await,
        0,
        "the refused act wrote a replacement"
    );
}

/// CALIBRATION for both races: with no retire in flight, the same act on the
/// same fixture is admitted and commits, so the refusals above are the
/// retire's doing, not the fixture's.
#[sqlx::test(migrations = "../../migrations")]
async fn without_a_retire_the_same_acts_commit(pool: PgPool) {
    let (p, p_g) = delegation::human_operator(&pool, "race-calibration-operator").await;
    let sibling = delegation::linked_principal(&pool, p, "race-calibration-sibling").await;
    let (server, me) = app_role_server(&pool).await;
    link(&pool, me, p).await;
    let viewer = fixture::public_viewer(&pool).await;
    for (author, arm) in [(p, "delegate"), (sibling, "actor")] {
        let c = claim(&pool, author, p_g).await;
        supersede_claim(
            &server,
            &viewer,
            SupersedeClaimParams {
                claim_id: c.to_string(),
                content: format!("replacement for {c}"),
                truth_value: 0.7,
                reason: "link-retire race calibration".to_string(),
            },
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("the {arm} arm admits the act: {}", e.message));
        assert!(!is_current(&pool, c).await, "the {arm} act committed");
    }
}
