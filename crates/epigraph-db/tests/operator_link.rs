//! Migration 102: operator links, the grant that authorizes them, the
//! never-revive rule, and the authoring path that reads them.
//!
//! # Why most arms here run as `epigraph_app` through SET SESSION AUTHORIZATION
//!
//! `#[sqlx::test]` connects as `epigraph`: superuser, `BYPASSRLS`, table owner.
//! On that connection every grant check and every row-security policy is
//! skipped, so "the call is refused" and "the write succeeds" are both
//! unobservable. The properties below are about GRANTS and POLICIES, so each
//! reaches a genuinely non-bypassing role with `SET SESSION AUTHORIZATION`
//! (`fixture::as_role`), which changes `session_user` — the value
//! `epigraph_bypass()` reads. `SET LOCAL ROLE` leaves `session_user` alone and
//! would pass for the wrong reason.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, ClaimRepository, GroupMembershipRepository, Viewer};
use sqlx::PgPool;
use uuid::Uuid;

const INSUFFICIENT_PRIVILEGE: &str = "42501";

fn hash32(id: Uuid) -> Vec<u8> {
    id.as_bytes().iter().copied().cycle().take(32).collect()
}

/// An agent row with NO personal group — the shape of an operator whose group
/// `epigraph_link_operator` has to create.
async fn seed_bare_agent(pool: &PgPool) -> Uuid {
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(agent)
        .bind(hash32(agent))
        .execute(pool)
        .await
        .expect("seed agent");
    agent
}

async fn link(pool: &PgPool, agent: Uuid, operator: Uuid) -> epigraph_db::OperatorLinkOutcome {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("link on the privileged harness connection")
}

async fn operator_group(pool: &PgPool, operator: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text")
        .bind(operator)
        .fetch_one(pool)
        .await
        .expect("operator personal group")
}

/// `(role, revoked, epoch)` for every membership row of `agent` in `group`.
async fn membership_rows(pool: &PgPool, group: Uuid, agent: Uuid) -> Vec<(String, bool, i32)> {
    sqlx::query_as(
        "SELECT role::text, revoked_at IS NOT NULL, epoch FROM group_memberships \
          WHERE group_id = $1 AND agent_id = $2 ORDER BY epoch",
    )
    .bind(group)
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("read memberships")
}

fn owner_of(decl: epigraph_core::TenancyDecl) -> Uuid {
    match decl {
        epigraph_core::TenancyDecl::Declared { owner_group_id, .. } => owner_group_id,
        epigraph_core::TenancyDecl::Inherited => panic!("default_decl_for_author declared nothing"),
    }
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

async fn assert_app_role_is_not_bypassing(pool: &PgPool) {
    let bypassrls: bool =
        sqlx::query_scalar("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'epigraph_app'")
            .fetch_one(pool)
            .await
            .expect("read epigraph_app's rolbypassrls");
    assert!(
        !bypassrls,
        "epigraph_app holds BYPASSRLS, so every arm in this file is vacuous. Fix the role, not \
         the test."
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint 1: only a privileged connection can create the link.
// ─────────────────────────────────────────────────────────────────────────────

/// `epigraph_app` cannot execute `epigraph_link_operator`: the call raises
/// 42501 and writes nothing. `epigraph_maintenance` CAN, on the same rows —
/// the calibration that stops a function that refuses everyone from passing.
///
/// This is the whole of the trust basis: `EPIGRAPH_OPERATOR_ID` only DECLARES a
/// link, and the privilege of the connection AUTHORIZES it. If the app role
/// could call this, any process on the request DSN could enrol itself as a
/// writer in any agent's personal group.
#[sqlx::test(migrations = "../../migrations")]
async fn epigraph_app_cannot_execute_link_operator(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let operator = seed_bare_agent(&pool).await;
    let agent = seed_bare_agent(&pool).await;

    let (session_user, refused) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let who: String = sqlx::query_scalar("SELECT session_user::text")
            .fetch_one(&mut *conn)
            .await
            .expect("session_user");
        let r = sqlx::query("SELECT * FROM public.epigraph_link_operator($1, $2)")
            .bind(agent)
            .bind(operator)
            .execute(&mut *conn)
            .await;
        (conn, (who, r))
    })
    .await;
    assert_eq!(
        session_user, "epigraph_app",
        "the refusal must be observed from a session whose session_user IS the app role"
    );
    let err = refused.expect_err(
        "epigraph_app executed epigraph_link_operator. 102 must REVOKE EXECUTE from PUBLIC and \
         from epigraph_app, or the request DSN can enrol any agent in any operator's group",
    );
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "the refusal must be a permission denial, not some other error: {err}"
    );

    let (edges, groups): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'OPERATED_BY'), \
                (SELECT count(*) FROM groups WHERE did_key = 'did:epigraph:personal:' || $2::text)",
    )
    .bind(agent)
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!((edges, groups), (0, 0), "a refused call must write nothing");

    // CALIBRATION: the maintenance role, on the same pair, succeeds.
    let ok = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_operator(&mut conn, agent, operator).await;
        (conn, r)
    })
    .await
    .expect("epigraph_maintenance must be able to link — else the refusal above proves nothing");
    assert!(ok.membership_created && ok.membership_live && ok.edge_created);
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint 3: recorded once, role writer, never revive.
// ─────────────────────────────────────────────────────────────────────────────

/// First link: the operator's group is created BY THE OPERATOR, the operator
/// is its admin, the agent is a `writer` (never `admin`), and the edge exists.
/// A second call is a no-op.
#[sqlx::test(migrations = "../../migrations")]
async fn link_creates_a_writer_membership_in_a_group_the_operator_created(pool: PgPool) {
    let operator = seed_bare_agent(&pool).await;
    let agent = seed_bare_agent(&pool).await;

    let first = link(&pool, agent, operator).await;
    assert!(first.group_created && first.membership_created && first.edge_created);
    let group = operator_group(&pool, operator).await;
    assert_eq!(first.operator_group_id, group);

    let creator: Uuid = sqlx::query_scalar("SELECT created_by_agent_id FROM groups WHERE id = $1")
        .bind(group)
        .fetch_one(&pool)
        .await
        .expect("creator");
    assert_eq!(
        creator, operator,
        "the group must be created BY THE OPERATOR: 077/092's creator arm gives the creator \
         enrol and key-epoch rights, which would make the agent's writer row admin-equivalent"
    );
    assert_eq!(
        membership_rows(&pool, group, operator).await,
        vec![("admin".to_string(), false, 0)]
    );
    assert_eq!(
        membership_rows(&pool, group, agent).await,
        vec![("writer".to_string(), false, 0)],
        "the agent is a WRITER, never admin, so it cannot manage the operator's group"
    );

    let again = link(&pool, agent, operator).await;
    assert!(!again.group_created && !again.membership_created && !again.edge_created);
    assert!(again.membership_live);
    let edges: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
            AND relationship = 'OPERATED_BY'",
    )
    .bind(agent)
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("count edges");
    assert_eq!(edges, 1, "the edge is recorded once");
}

/// link → revoke → re-link leaves the membership REVOKED. Two arms, because
/// two guards carry the rule and each is load-bearing for a different shape:
///
/// * ARM A — the revoked row is at epoch 0, where a re-link would insert. Both
///   the no-history check and `ON CONFLICT DO NOTHING` stop it; 077's
///   `DO UPDATE SET revoked_at = NULL, role = 'admin'` (issue #493) would
///   revive it as admin.
/// * ARM B — the revoked row is at a DIFFERENT epoch. The composite UNIQUE is
///   per-epoch and the partial live index ignores revoked rows, so no conflict
///   fires: only the no-history check stops a fresh epoch-0 writer row.
#[sqlx::test(migrations = "../../migrations")]
async fn link_revoke_relink_stays_revoked(pool: PgPool) {
    let operator = seed_bare_agent(&pool).await;

    // ARM A.
    let agent_a = seed_bare_agent(&pool).await;
    link(&pool, agent_a, operator).await;
    let group = operator_group(&pool, operator).await;
    GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group, agent_a)
        .await
        .expect("the operator revokes the agent through the production revoke path");
    assert_eq!(
        membership_rows(&pool, group, agent_a).await,
        vec![("writer".to_string(), true, 0)]
    );

    let relinked = link(&pool, agent_a, operator).await;
    assert!(
        !relinked.membership_live && !relinked.membership_created,
        "re-link must report the revocation, not undo it: {relinked:?}"
    );
    assert_eq!(
        membership_rows(&pool, group, agent_a).await,
        vec![("writer".to_string(), true, 0)],
        "ARM A: a revoked membership was REVIVED by a re-link. This is issue #493's shape: an \
         operator who revokes an agent would see it restored on the agent's next restart"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    assert_eq!(
        AgentRepository::operator_of(&mut conn, agent_a)
            .await
            .expect("operator_of"),
        None,
        "a revoked membership ends the link for authoring and ownership"
    );
    drop(conn);

    // ARM B.
    let agent_b = seed_bare_agent(&pool).await;
    link(&pool, agent_b, operator).await;
    GroupMembershipRepository::revoke_member_unless_last_admin(&pool, group, agent_b)
        .await
        .expect("revoke");
    sqlx::query("UPDATE group_memberships SET epoch = 3 WHERE group_id = $1 AND agent_id = $2")
        .bind(group)
        .bind(agent_b)
        .execute(&pool)
        .await
        .expect("move the revoked history row to another epoch");

    let relinked = link(&pool, agent_b, operator).await;
    assert!(!relinked.membership_live, "{relinked:?}");
    assert_eq!(
        membership_rows(&pool, group, agent_b).await,
        vec![("writer".to_string(), true, 3)],
        "ARM B: a re-link inserted a FRESH live row beside the revoked history. ON CONFLICT alone \
         cannot stop this (no constraint fires across epochs); the no-history check must"
    );
}

/// A second, DIFFERENT live operator is refused loudly rather than added or
/// silently replacing the first; a self-link is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_operator_and_a_self_link_are_refused(pool: PgPool) {
    let op_j = seed_bare_agent(&pool).await;
    let op_k = seed_bare_agent(&pool).await;
    let agent = seed_bare_agent(&pool).await;
    link(&pool, agent, op_j).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let err = AgentRepository::link_operator(&mut conn, agent, op_k)
        .await
        .expect_err("a second live operator must be refused");
    assert!(
        err.to_string().contains("already has a live link"),
        "the refusal must say why: {err}"
    );
    let err = AgentRepository::link_operator(&mut conn, agent, agent)
        .await
        .expect_err("self-link must be refused");
    assert!(err.to_string().contains("its own operator"), "{err}");
    assert_eq!(
        AgentRepository::operator_of(&mut conn, agent)
            .await
            .expect("operator_of")
            .map(|l| l.operator_id),
        Some(op_j)
    );
}

/// An HTTP server's auth-lineage `OPERATED_BY` edge (no membership) is NOT a
/// link. Without the membership conjunct every shared HTTP signer would read as
/// operated by the last OAuth principal that called it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_auth_lineage_edge_alone_is_not_an_operator_link(pool: PgPool) {
    let (principal, _) = fixture::seed_agent_with_group(&pool, "principal").await;
    let signer = seed_bare_agent(&pool).await;
    epigraph_db::EdgeRepository::create_if_not_exists(
        &pool,
        signer,
        "agent",
        principal,
        "agent",
        "OPERATED_BY",
        None,
        None,
        None,
    )
    .await
    .expect("lineage edge, as record_auth_lineage writes it");

    let mut conn = pool.acquire().await.expect("acquire");
    assert!(AgentRepository::operator_links(&mut conn, signer)
        .await
        .expect("links")
        .is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Constraint 4 and the authoring path.
// ─────────────────────────────────────────────────────────────────────────────

/// On an UNSTAMPED `epigraph_app` session, `default_decl_for_author` for an
/// operated agent returns the OPERATOR's group — and writes nothing.
///
/// On that session `groups_tenancy` hides every row, so a read-first lookup is
/// blind and a read-then-mint helper becomes an unconditional re-mint. The
/// operator lookup must therefore go through a SECURITY DEFINER read. The
/// row counts are the half the superuser harness can never see: a mint there
/// is invisible because the read it follows is not blind.
#[sqlx::test(migrations = "../../migrations")]
async fn operator_lookup_works_on_an_unstamped_app_session_and_mints_nothing(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent, own_group) = fixture::seed_agent_with_group(&pool, "agent").await;
    link(&pool, agent, operator).await;
    let op_group = operator_group(&pool, operator).await;

    let counts = |pool: PgPool| async move {
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT (SELECT count(*) FROM groups), (SELECT count(*) FROM group_memberships)",
        )
        .fetch_one(&pool)
        .await
        .expect("counts")
    };
    let before = counts(pool.clone()).await;

    let decl = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let blind: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
        )
        .bind(operator)
        .fetch_optional(&mut *conn)
        .await
        .expect("inline read");
        assert_eq!(
            blind, None,
            "PREMISE: an inline groups read on an unstamped app session must be blind, or this \
             test cannot tell a definer read from an ordinary one"
        );
        let d = ClaimRepository::default_decl_for_author(&mut conn, agent).await;
        (conn, d)
    })
    .await
    .expect("default_decl_for_author on an unstamped app session");

    assert_eq!(
        owner_of(decl),
        op_group,
        "an operated agent's new claims must be owned by the OPERATOR's personal group (its own \
         is {own_group})"
    );
    assert_eq!(
        counts(pool.clone()).await,
        before,
        "the lookup wrote groups/memberships: a read-then-mint on a blind session"
    );
}

/// An operated agent, stamped from ITS OWN viewer, can write a claim owned by
/// the operator's group AND the claim-derived rows (trace, evidence) as
/// `epigraph_app`. An agent with NO link, stamped from its own viewer, is
/// refused the same writes — the refusal path is unchanged.
///
/// The GUCs come from a real `Viewer::resolve` on the SUPERUSER pool (resolve
/// first, downgrade second), so the writable set is the one the writer
/// membership actually produces — not a hand-typed group id.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agent_writes_claim_derived_rows_into_the_operator_group(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent, _) = fixture::seed_agent_with_group(&pool, "agent").await;
    let (unlinked, _) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    link(&pool, agent, operator).await;
    let op_group = operator_group(&pool, operator).await;

    let agent_viewer = Viewer::resolve(&pool, agent).await.expect("resolve agent");
    let unlinked_viewer = Viewer::resolve(&pool, unlinked)
        .await
        .expect("resolve unlinked");
    assert!(
        agent_viewer.writable_groups().contains(&op_group),
        "the writer membership must put the operator's group in the agent's writable set"
    );
    assert!(!unlinked_viewer.writable_groups().contains(&op_group));

    let (linked_result, unlinked_result) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            let linked = write_claim_trace_evidence(&mut conn, &agent_viewer, agent).await;
            let unlinked =
                write_claim_trace_evidence_into(&mut conn, &unlinked_viewer, unlinked, op_group)
                    .await;
            (conn, (linked, unlinked))
        })
        .await;

    let claim = linked_result.expect(
        "an operated agent stamped from its own viewer must write the claim, its trace and its \
         evidence into the operator's group as epigraph_app",
    );
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(claim)
        .fetch_one(&pool)
        .await
        .expect("owner");
    assert_eq!(owner, op_group);
    let (traces, evidence): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM reasoning_traces WHERE claim_id = $1 AND owner_group_id = $2), \
                (SELECT count(*) FROM evidence WHERE claim_id = $1 AND owner_group_id = $2)",
    )
    .bind(claim)
    .bind(op_group)
    .fetch_one(&pool)
    .await
    .expect("derived rows");
    assert_eq!((traces, evidence), (1, 1));

    let err = unlinked_result.expect_err(
        "an agent with NO operator link wrote into the operator's group: the writer membership \
         must be what confers this, not the stamp",
    );
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );
}

async fn set_gucs_from(conn: &mut sqlx::PgConnection, v: &Viewer) {
    let join = |ids: Option<&[Uuid]>| {
        ids.unwrap_or(&[])
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    sqlx::query(
        "SELECT set_config('epigraph.group_ids', $1, false), \
                set_config('epigraph.writable_group_ids', $2, false), \
                set_config('epigraph.principal_id', $3, false)",
    )
    .bind(join(v.group_bind()))
    .bind(join(v.writable_bind()))
    .bind(v.principal().map(|p| p.to_string()).unwrap_or_default())
    .execute(&mut *conn)
    .await
    .expect("stamp GUCs");
}

/// The claim is owned by whatever `default_decl_for_author` chooses.
async fn write_claim_trace_evidence(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    author: Uuid,
) -> Result<Uuid, sqlx::Error> {
    set_gucs_from(conn, viewer).await;
    let decl = ClaimRepository::default_decl_for_author(conn, author)
        .await
        .expect("decl");
    write_claim_trace_evidence_into(conn, viewer, author, owner_of(decl)).await
}

async fn write_claim_trace_evidence_into(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    author: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    set_gucs_from(conn, viewer).await;
    let claim = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, 'operated agent claim', $2, 0.8, $3, true, 'public', $4)",
    )
    .bind(claim)
    .bind(hash32(claim))
    .bind(author)
    .bind(group)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO reasoning_traces (claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, 'deductive', 0.9, 'operated agent trace')",
    )
    .bind(claim)
    .execute(&mut *conn)
    .await?;
    let ev = Uuid::new_v4();
    sqlx::query("INSERT INTO evidence (claim_id, evidence_type, content_hash) VALUES ($1, 'observation', $2)")
        .bind(claim)
        .bind(hash32(ev))
        .execute(&mut *conn)
        .await?;
    Ok(claim)
}
