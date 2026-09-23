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
    assert!(ok.membership_created && ok.membership_live && ok.edge_created && ok.link_live);
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
    assert!(again.membership_live && again.link_live);
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
        AgentRepository::operator_actor(&mut conn, agent_a)
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

/// `link_live` reports what the authoring and ownership paths will actually
/// read, not merely that a membership row is live.
///
/// The review's probe: link `Y`, change its membership role to `reader`,
/// re-link. The membership is still live, so the old `membership_live` said
/// "linked" and the startup log said the agent authored into the operator's
/// group — while the actor read returned nothing and it did not.
#[sqlx::test(migrations = "../../migrations")]
async fn link_live_reports_the_link_the_authoring_path_reads(pool: PgPool) {
    let operator = seed_bare_agent(&pool).await;
    let y = seed_bare_agent(&pool).await;
    let first = link(&pool, y, operator).await;
    assert!(first.link_live, "a fresh link is live: {first:?}");

    let group = operator_group(&pool, operator).await;
    sqlx::query(
        "UPDATE group_memberships SET role = 'reader' WHERE group_id = $1 AND agent_id = $2",
    )
    .bind(group)
    .bind(y)
    .execute(&pool)
    .await
    .expect("demote the membership to reader");

    let relinked = link(&pool, y, operator).await;
    assert!(
        relinked.membership_live,
        "PREMISE: the membership row is still live: {relinked:?}"
    );
    assert!(
        !relinked.link_live,
        "a reader membership is not a link; link_live must say so: {relinked:?}"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    assert_eq!(
        AgentRepository::operator_actor(&mut conn, y)
            .await
            .expect("operator_of"),
        None,
        "and the authoring path agrees"
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
        err.to_string().contains("already has a link"),
        "the refusal must say why: {err}"
    );
    let err = AgentRepository::link_operator(&mut conn, agent, agent)
        .await
        .expect_err("self-link must be refused");
    assert!(err.to_string().contains("its own operator"), "{err}");
    assert_eq!(
        AgentRepository::operator_actor(&mut conn, agent)
            .await
            .expect("operator_of")
            .map(|l| l.operator_id),
        Some(op_j)
    );

    // Single hop, from both ends. `agent -> op_j` exists, so:
    // (a) op_j, an operator, cannot itself be operated (the review's order:
    //     link(X, O) then link(O, P) would build X -> O -> P);
    let op_p = seed_bare_agent(&pool).await;
    let err = AgentRepository::link_operator(&mut conn, op_j, op_p)
        .await
        .expect_err("an agent that already operates others must not become operated");
    assert!(
        err.to_string().contains("already operates other agents"),
        "{err}"
    );
    assert!(
        AgentRepository::operator_actor(&mut conn, op_j)
            .await
            .expect("links of op_j")
            .is_none(),
        "the refused link must leave op_j unoperated"
    );
    let p_group: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM groups WHERE did_key = 'did:epigraph:personal:' || $1::text",
    )
    .bind(op_p)
    .fetch_optional(&pool)
    .await
    .expect("p group");
    if let Some(g) = p_group {
        assert!(
            membership_rows(&pool, g, op_j).await.is_empty(),
            "the refused link enrolled op_j in P's group"
        );
    }
    // (b) and the reverse order stays refused: `agent`, operated, cannot be
    //     an operator.
    let downstream = seed_bare_agent(&pool).await;
    let err = AgentRepository::link_operator(&mut conn, downstream, agent)
        .await
        .expect_err("an operated agent must not become an operator");
    assert!(err.to_string().contains("is itself operated"), "{err}");
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
    assert!(AgentRepository::operator_actor(&mut conn, signer)
        .await
        .expect("links")
        .is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// The link record is definer-only (review finding: the link was forgeable).
// ─────────────────────────────────────────────────────────────────────────────

/// An `epigraph_app` session CANNOT forge a link, even though it can still
/// write both halves of what used to count as one.
///
/// Replays the review's attacks as `epigraph_app`, stamped exactly as
/// `Viewer::resolve` stamps an ordinary principal:
///
/// * (1b) principal `O` writes a `writer` row for agent `X` into `O`'s own
///   personal group AND an `X --OPERATED_BY--> O` edge;
/// * (4) the HTTP-signer variant: `record_auth_lineage` has already written
///   `S --OPERATED_BY--> P` (as it does for every OAuth caller), and `P`'s
///   session adds only the membership.
///
/// Both writes still SUCCEED (asserted, so the premise cannot rot into a
/// vacuous pass), and neither agent reads as operated: the authority is the
/// `operator_links` row, which only a definer frame can write.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_session_cannot_forge_a_link_from_an_edge_and_a_membership(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (o, o_group) = fixture::seed_agent_with_group(&pool, "forger-o").await;
    let x = seed_bare_agent(&pool).await;
    let (p, p_group) = fixture::seed_agent_with_group(&pool, "forger-p").await;
    let signer = seed_bare_agent(&pool).await;
    epigraph_db::EdgeRepository::create_if_not_exists(
        &pool,
        signer,
        "agent",
        p,
        "agent",
        "OPERATED_BY",
        None,
        None,
        None,
    )
    .await
    .expect("lineage edge, exactly as record_auth_lineage writes it");

    let o_viewer = Viewer::resolve(&pool, o).await.expect("resolve O");
    let p_viewer = Viewer::resolve(&pool, p).await.expect("resolve P");

    let (attack_1b, attack_4) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs_from(&mut conn, &o_viewer).await;
        let mem = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(o_group)
        .bind(x)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        let edge = sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
             VALUES ($1, 'agent', $2, 'agent', 'OPERATED_BY')",
        )
        .bind(x)
        .bind(o)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());

        set_gucs_from(&mut conn, &p_viewer).await;
        let signer_mem = sqlx::query(
            "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
             VALUES ($1, $2, ''::bytea, 0, 'writer')",
        )
        .bind(p_group)
        .bind(signer)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        (conn, ((mem, edge), signer_mem))
    })
    .await;

    let (mem, edge) = attack_1b;
    assert_eq!(
        (mem.expect("1b membership"), edge.expect("1b edge")),
        (1, 1),
        "PREMISE: an app session can still write both halves of the old link shape; if it \
         cannot, this test no longer replays the attack"
    );
    assert_eq!(
        attack_4.expect("attack 4 membership"),
        1,
        "PREMISE (attack 4)"
    );

    let mut conn = pool.acquire().await.expect("acquire");
    assert!(
        AgentRepository::operator_actor(&mut conn, x)
            .await
            .expect("links of X")
            .is_none(),
        "attack 1b: an edge plus a membership written by O's own session made O the operator \
         of X. The link must require an operator_links row only a definer can write"
    );
    assert!(
        AgentRepository::operator_actor(&mut conn, signer)
            .await
            .expect("links of the signer")
            .is_none(),
        "attack 4: one membership row made the shared HTTP signer 'operated by' its caller"
    );
}

/// `operator_links` itself refuses an app-session INSERT through its POLICY,
/// not only through the REVOKE. The test grants the app role every table
/// privilege first (`fixture::grant_app_privileges`), so the refusal observed
/// is the row-security one; the REVOKE is asserted separately, before that
/// grant, because 077's `ALTER DEFAULT PRIVILEGES` would otherwise hand the
/// app role INSERT on a new table.
#[sqlx::test(migrations = "../../migrations")]
async fn operator_links_refuses_an_app_insert_by_policy_and_by_grant(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let app_may_insert: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('epigraph_app', 'public.operator_links', 'INSERT')",
    )
    .fetch_one(&pool)
    .await
    .expect("privilege probe");
    assert!(
        !app_may_insert,
        "102 must REVOKE ALL on operator_links FROM epigraph_app: 077's default privileges \
         grant it INSERT on every new table"
    );

    let (o, o_group) = fixture::seed_agent_with_group(&pool, "forger").await;
    let x = seed_bare_agent(&pool).await;
    let o_viewer = Viewer::resolve(&pool, o).await.expect("resolve O");
    fixture::grant_app_privileges(&pool, "epigraph_app").await;

    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs_from(&mut conn, &o_viewer).await;
        let r = sqlx::query(
            "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
             VALUES ($1, $2, $3)",
        )
        .bind(x)
        .bind(o)
        .bind(o_group)
        .execute(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    let err = refused.expect_err(
        "an app session inserted an operator_links row: with the grant in place, the INSERT \
         policy is the only thing between the request DSN and a forged link",
    );
    assert!(
        err.to_string().contains("row-level security"),
        "the refusal must come from the row-security policy, not from a missing grant: {err}"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM operator_links")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0);
}

/// Personal-group squatting (review attack 2f): a group that merely CARRIES an
/// operator's `did:epigraph:personal:<operator>` key, created by someone else,
/// is not the operator's group.
///
/// Principal `Z`, on `epigraph_app` stamped as itself, pre-creates
/// `did:epigraph:personal:D` for an operator `D` that has no personal group yet
/// (`groups_tenancy`'s creator WITH CHECK admits it — asserted as the premise).
/// Linking an agent to `D` must then REFUSE, rather than enrol the agent as a
/// writer in `Z`'s group. The second arm is defense in depth for the read: a
/// link record pointing at a squatted group (written here on the superuser
/// harness, since no in-tree path can) still reads as no link.
#[sqlx::test(migrations = "../../migrations")]
async fn a_squatted_personal_group_is_not_the_operators(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (z, _) = fixture::seed_agent_with_group(&pool, "squatter").await;
    let d = seed_bare_agent(&pool).await;
    let e = seed_bare_agent(&pool).await;
    let z_viewer = Viewer::resolve(&pool, z).await.expect("resolve Z");

    let squat = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        set_gucs_from(&mut conn, &z_viewer).await;
        let r = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
             VALUES ('squat', 'did:epigraph:personal:' || $1::text, ''::bytea, 'personal', $2) \
             RETURNING id",
        )
        .bind(d)
        .bind(z)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await;
    let squatted = squat.expect(
        "PREMISE: an app session can pre-create a group carrying another agent's personal \
         did_key; if it cannot, this test no longer replays the attack",
    );

    let mut conn = pool.acquire().await.expect("acquire");
    let err = AgentRepository::link_operator(&mut conn, e, d)
        .await
        .expect_err(
            "linking to an operator whose did_key is squatted must be refused, not enrol the \
             agent in the squatter's group",
        );
    assert!(
        err.to_string()
            .contains("not a personal group created by that operator"),
        "{err}"
    );
    assert!(
        membership_rows(&pool, squatted, e).await.is_empty(),
        "the refused link enrolled the agent in the squatter's group"
    );

    // Defense in depth: a link record naming the squatted group reads as none.
    sqlx::query(
        "INSERT INTO operator_links (agent_id, operator_id, operator_group_id) \
         VALUES ($1, $2, $3)",
    )
    .bind(e)
    .bind(d)
    .bind(squatted)
    .execute(&pool)
    .await
    .expect("out-of-band link row on the superuser harness");
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(squatted)
    .bind(e)
    .execute(&pool)
    .await
    .expect("membership in the squatted group");
    assert!(
        AgentRepository::operator_actor(&mut conn, e)
            .await
            .expect("links")
            .is_none(),
        "epigraph_operator_actor accepted a group the operator did not create"
    );
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

// ─────────────────────────────────────────────────────────────────────────────
// Retired links (migration 102 section 7): the operator owns a retired
// identity's claims, and the identity gains ZERO write authority.
// ─────────────────────────────────────────────────────────────────────────────

async fn link_retired(
    pool: &PgPool,
    agent: Uuid,
    operator: Uuid,
) -> epigraph_db::RetiredLinkOutcome {
    let mut conn = pool.acquire().await.expect("acquire");
    AgentRepository::link_retired_agent(&mut conn, agent, operator)
        .await
        .expect("retired link on the privileged harness connection")
}

async fn link_row(pool: &PgPool, agent: Uuid) -> Option<(Uuid, bool)> {
    sqlx::query_as("SELECT operator_id, retired FROM operator_links WHERE agent_id = $1")
        .bind(agent)
        .fetch_optional(pool)
        .await
        .expect("operator_links row")
}

/// `epigraph_app` cannot execute `epigraph_link_retired_agent` (42501, nothing
/// written); `epigraph_maintenance` can, on the same pair.
#[sqlx::test(migrations = "../../migrations")]
async fn epigraph_app_cannot_execute_link_retired_agent(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (operator, _) = fixture::seed_agent_with_group(&pool, "operator").await;
    let retired = seed_bare_agent(&pool).await;

    let refused = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        let r = sqlx::query("SELECT * FROM public.epigraph_link_retired_agent($1, $2)")
            .bind(retired)
            .bind(operator)
            .execute(&mut *conn)
            .await;
        (conn, r)
    })
    .await;
    let err = refused.expect_err(
        "epigraph_app executed epigraph_link_retired_agent: 102 must REVOKE EXECUTE from PUBLIC \
         and from epigraph_app",
    );
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );
    assert_eq!(
        link_row(&pool, retired).await,
        None,
        "a refused call writes nothing"
    );

    // CALIBRATION.
    let ok = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, retired, operator).await;
        (conn, r)
    })
    .await
    .expect("epigraph_maintenance must be able to record a retired link");
    assert!(ok.link_created && ok.link_retired && ok.edge_created && !ok.membership_live);
}

/// The retired link writes the record (retired) and the graph edge, creates NO
/// membership, and is idempotent.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_records_the_row_and_edge_and_no_membership(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired").await;

    let first = link_retired(&pool, retired, operator).await;
    assert_eq!(first.operator_group_id, op_group);
    assert!(
        first.link_created && first.link_retired && first.edge_created,
        "{first:?}"
    );
    assert!(!first.membership_live && !first.group_created, "{first:?}");
    assert_eq!(link_row(&pool, retired).await, Some((operator, true)));
    assert!(
        membership_rows(&pool, op_group, retired).await.is_empty(),
        "a retired link must create NO membership in the operator's group"
    );

    let again = link_retired(&pool, retired, operator).await;
    assert!(
        !again.link_created && again.link_retired && !again.edge_created,
        "a second call is a no-op: {again:?}"
    );
    let (links, edges): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM operator_links WHERE agent_id = $1), \
                (SELECT count(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
                    AND relationship = 'OPERATED_BY')",
    )
    .bind(retired)
    .bind(operator)
    .fetch_one(&pool)
    .await
    .expect("counts");
    assert_eq!((links, edges), (1, 1));
}

/// A2's security test, as `epigraph_app` with the session stamped from the
/// RETIRED agent's own `Viewer::resolve`:
///
/// * its writable set does NOT include the operator's group, and a write owned
///   by that group is refused (42501);
/// * it is not an ACTOR: `epigraph_operator_actor` returns nothing;
/// * and the authoring default for it is its OWN personal group, which it can
///   write — so a retired identity that runs again still works, in its own lane.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_agent_gains_no_write_authority(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (retired, own_group) = fixture::seed_agent_with_group(&pool, "retired").await;
    link_retired(&pool, retired, operator).await;

    let viewer = Viewer::resolve(&pool, retired)
        .await
        .expect("resolve retired");
    assert!(
        !viewer.writable_groups().contains(&op_group),
        "a retired agent's writable set must not include the operator's group"
    );

    let (actor, decl, into_operator, into_own) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            set_gucs_from(&mut conn, &viewer).await;
            let actor = AgentRepository::operator_actor(&mut conn, retired)
                .await
                .expect("operator_of on an app session");
            let decl = ClaimRepository::default_decl_for_author(&mut conn, retired)
                .await
                .expect("default decl");
            let into_operator =
                write_claim_trace_evidence_into(&mut conn, &viewer, retired, op_group).await;
            let into_own = write_claim_trace_evidence(&mut conn, &viewer, retired).await;
            (conn, (actor, decl, into_operator, into_own))
        })
        .await;

    assert!(
        actor.is_none(),
        "a retired link must never read as an acting link: {actor:?}"
    );
    assert_eq!(
        owner_of(decl),
        own_group,
        "a retired agent authors into its OWN personal group"
    );
    let err = into_operator.expect_err(
        "a retired agent wrote a row owned by the operator's group: a retired identity's key may \
         be public, so it must hold no write authority there",
    );
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{err}"
    );
    into_own.expect("a retired identity that runs again can still write in its own lane");
}

/// `epigraph_link_operator` NEVER promotes a retired link: a retired identity
/// that runs again with `EPIGRAPH_OPERATOR_ID` set gets no membership and is
/// reported as retired.
#[sqlx::test(migrations = "../../migrations")]
async fn link_operator_never_promotes_a_retired_link(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let retired = seed_bare_agent(&pool).await;
    link_retired(&pool, retired, operator).await;

    let out = link(&pool, retired, operator).await;
    assert!(
        out.link_retired && !out.link_live && !out.membership_created && !out.membership_live,
        "link_operator promoted a retired link: {out:?}"
    );
    assert!(
        membership_rows(&pool, op_group, retired).await.is_empty(),
        "link_operator gave a retired identity a membership in the operator's group"
    );
    assert_eq!(link_row(&pool, retired).await, Some((operator, true)));
}

/// The retired link's refusals, and its hands-off rule for an existing
/// membership: a self-link, a missing agent, an operator that is itself
/// operated, and an agent linked to a different operator are refused; an
/// agent whose ACTOR link was revoked keeps its row and its revoked
/// membership exactly as they were.
#[sqlx::test(migrations = "../../migrations")]
async fn link_retired_agent_refuses_and_never_touches_a_membership(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (other_op, _) = fixture::seed_agent_with_group(&pool, "other-operator").await;
    let mut conn = pool.acquire().await.expect("acquire");

    let err = AgentRepository::link_retired_agent(&mut conn, operator, operator)
        .await
        .expect_err("self-link");
    assert!(err.to_string().contains("its own operator"), "{err}");

    let err = AgentRepository::link_retired_agent(&mut conn, Uuid::new_v4(), operator)
        .await
        .expect_err("missing agent");
    assert!(err.to_string().contains("does not exist"), "{err}");

    let operated = seed_bare_agent(&pool).await;
    link_retired(&pool, operated, operator).await;
    let err =
        AgentRepository::link_retired_agent(&mut conn, seed_bare_agent(&pool).await, operated)
            .await
            .expect_err("an operator that is itself operated");
    assert!(err.to_string().contains("is itself operated"), "{err}");

    let err = AgentRepository::link_retired_agent(&mut conn, operated, other_op)
        .await
        .expect_err("an agent linked to a different operator");
    assert!(err.to_string().contains("already has a link"), "{err}");

    // An ACTOR whose membership the operator revoked: the retired call leaves
    // the actor row and the revoked membership exactly as they were.
    let former_actor = seed_bare_agent(&pool).await;
    link(&pool, former_actor, operator).await;
    GroupMembershipRepository::revoke_member_unless_last_admin(&pool, op_group, former_actor)
        .await
        .expect("revoke");
    let out = link_retired(&pool, former_actor, operator).await;
    assert!(
        !out.link_created && !out.link_retired && !out.membership_live,
        "{out:?}"
    );
    assert_eq!(link_row(&pool, former_actor).await, Some((operator, false)));
    assert_eq!(
        membership_rows(&pool, op_group, former_actor).await,
        vec![("writer".to_string(), true, 0)],
        "the retired link must never revive or otherwise touch an existing membership"
    );
}

/// A retired row stays NOT-an-actor even if a live membership appears beside
/// it. The operator's own session can enrol any agent in the operator's group
/// (group_memberships_tenancy's creator/admin arm, replayed in
/// `an_app_session_cannot_forge_a_link_from_an_edge_and_a_membership`), so the
/// `NOT retired` conjunct in `epigraph_operator_actor` — not the absence of a
/// membership — is what keeps a retired identity from acting for its operator.
#[sqlx::test(migrations = "../../migrations")]
async fn a_retired_link_with_a_membership_is_still_not_an_actor(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let retired = seed_bare_agent(&pool).await;
    link_retired(&pool, retired, operator).await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'writer')",
    )
    .bind(op_group)
    .bind(retired)
    .execute(&pool)
    .await
    .expect("an out-of-band writer row beside the retired link");

    let mut conn = pool.acquire().await.expect("acquire");
    assert!(
        AgentRepository::operator_actor(&mut conn, retired)
            .await
            .expect("operator_of")
            .is_none(),
        "a retired link must never read as an acting link, membership or not"
    );
}

/// A1: the two reads answer two different questions.
///
/// * `operator_of_author` — "whose are this author's claims?" — names the
///   operator for an ACTING agent, a RETIRED agent and a REVOKED agent alike:
///   the record alone decides it, so an operator keeps ownership of what an
///   agent wrote after retiring or revoking it.
/// * `operator_actor` — "may this agent act for an operator?" — names it for
///   the acting agent ONLY.
#[sqlx::test(migrations = "../../migrations")]
async fn the_author_read_and_the_actor_read_answer_different_questions(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let acting = seed_bare_agent(&pool).await;
    let retired = seed_bare_agent(&pool).await;
    let revoked = seed_bare_agent(&pool).await;
    let unlinked = seed_bare_agent(&pool).await;
    link(&pool, acting, operator).await;
    link_retired(&pool, retired, operator).await;
    link(&pool, revoked, operator).await;
    GroupMembershipRepository::revoke_member_unless_last_admin(&pool, op_group, revoked)
        .await
        .expect("revoke");

    let mut conn = pool.acquire().await.expect("acquire");
    for (agent, want_retired) in [(acting, false), (retired, true), (revoked, false)] {
        let author = AgentRepository::operator_of_author(&mut conn, agent)
            .await
            .expect("author read")
            .unwrap_or_else(|| panic!("the author read must name the operator for {agent}"));
        assert_eq!(
            (author.operator_id, author.operator_group_id, author.retired),
            (operator, op_group, want_retired)
        );
    }
    assert_eq!(
        AgentRepository::operator_of_author(&mut conn, unlinked)
            .await
            .expect("author read"),
        None
    );

    assert_eq!(
        AgentRepository::operator_actor(&mut conn, acting)
            .await
            .expect("actor read")
            .map(|l| l.operator_id),
        Some(operator)
    );
    for agent in [retired, revoked, unlinked] {
        assert_eq!(
            AgentRepository::operator_actor(&mut conn, agent)
                .await
                .expect("actor read"),
            None,
            "only an acting link may act"
        );
    }
}

/// Migration 103 (review attack 2c): an operated WRITER cannot make itself an
/// admin of its operator's group by rewriting the group's creator.
///
/// As `epigraph_app`, stamped from the operated agent's own `Viewer::resolve`
/// (so the operator group is in its writable set):
///
/// * rewriting the operator group's `created_by_agent_id` to itself — the one
///   UPDATE `groups_tenancy`'s WITH CHECK admits on that row, and the review's
///   exact attack — is refused by 103's trigger, and so is the follow-on
///   enrolment of a third agent;
/// * rewriting `did_key` or `kind` on a group the agent legitimately created
///   (its own personal group, where the WITH CHECK passes) is refused by the
///   trigger too;
/// * CALIBRATION in the same session: an ordinary-column update of that same
///   own group succeeds, so the refusal is about the identity columns, not the
///   row or the role.
///
/// Every refusal is asserted to be the TRIGGER's (its message), not the RLS
/// policy's, which also raises 42501.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_writer_cannot_rewrite_its_operator_groups_identity(pool: PgPool) {
    assert_app_role_is_not_bypassing(&pool).await;
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (a, a_group) = fixture::seed_agent_with_group(&pool, "operated-writer").await;
    let z = seed_bare_agent(&pool).await;
    link(&pool, a, operator).await;
    let viewer = Viewer::resolve(&pool, a).await.expect("resolve A");
    assert!(
        viewer.writable_groups().contains(&op_group),
        "PREMISE: the operated writer can write rows the operator's group owns"
    );

    let (creator, did, kind, ordinary, enrol) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            set_gucs_from(&mut conn, &viewer).await;
            let creator = sqlx::query("UPDATE groups SET created_by_agent_id = $2 WHERE id = $1")
                .bind(op_group)
                .bind(a)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected());
            let enrol = sqlx::query(
                "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, \
                                                role) \
                 VALUES ($1, $2, ''::bytea, 0, 'writer')",
            )
            .bind(op_group)
            .bind(z)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
            let did = sqlx::query(
                "UPDATE groups SET did_key = 'did:epigraph:personal:' || $2::text WHERE id = $1",
            )
            .bind(a_group)
            .bind(z)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
            let kind = sqlx::query("UPDATE groups SET kind = 'community' WHERE id = $1")
                .bind(a_group)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected());
            let ordinary = sqlx::query("UPDATE groups SET updated_at = now() WHERE id = $1")
                .bind(a_group)
                .execute(&mut *conn)
                .await
                .map(|r| r.rows_affected());
            (conn, (creator, did, kind, ordinary, enrol))
        })
        .await;

    for (what, result) in [
        ("the operator group's created_by_agent_id", creator),
        ("its own group's did_key", did),
        ("its own group's kind", kind),
    ] {
        let err = result.expect_err(&format!(
            "an app session rewrote {what}: 092's creator arm makes a creator admin-equivalent"
        ));
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{what}: {err}"
        );
        assert!(
            err.to_string()
                .contains("immutable outside a maintenance session"),
            "{what}: the refusal must be migration 103's trigger, not the RLS policy: {err}"
        );
    }
    assert_eq!(
        ordinary.expect("CALIBRATION: an ordinary-column update of its own group must succeed"),
        1
    );
    assert!(
        enrol.is_err(),
        "the operated writer enrolled a third agent in the operator's group"
    );

    let (creator_after, kind_after): (Uuid, String) =
        sqlx::query_as("SELECT created_by_agent_id, kind::text FROM groups WHERE id = $1")
            .bind(op_group)
            .fetch_one(&pool)
            .await
            .expect("group after");
    assert_eq!((creator_after, kind_after.as_str()), (operator, "personal"));
    assert!(membership_rows(&pool, op_group, z).await.is_empty());
}

/// Review finding (consolidate ignored the operator link): an operated agent
/// that merges public claims owned by its operator's group gets a merged claim
/// owned by the OPERATOR's group — the same authoring default every other
/// write path uses — not by its own personal group.
///
/// CALIBRATION in the same test: an unlinked agent's all-public merge still
/// lands in its own personal group, so the arm is the operator link and not a
/// change to the default.
#[sqlx::test(migrations = "../../migrations")]
async fn an_operated_agents_merge_is_owned_by_the_operator_group(pool: PgPool) {
    let (operator, op_group) = fixture::seed_agent_with_group(&pool, "operator").await;
    let (agent, own_group) = fixture::seed_agent_with_group(&pool, "operated").await;
    let (unlinked, unlinked_group) = fixture::seed_agent_with_group(&pool, "unlinked").await;
    link(&pool, agent, operator).await;

    async fn public_claim(pool: &PgPool, author: Uuid, owner: Uuid, content: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.6, $4, true, 'public', $5)",
        )
        .bind(id)
        .bind(content)
        .bind(hash32(id))
        .bind(author)
        .bind(owner)
        .execute(pool)
        .await
        .expect("seed public claim");
        id
    }

    let s1 = public_claim(&pool, agent, op_group, "operated source alpha").await;
    let s2 = public_claim(&pool, agent, op_group, "operated source beta").await;
    let merged = ClaimRepository::consolidate(
        &pool,
        &[s1, s2],
        "operated merge of alpha and beta",
        0.7,
        epigraph_db::ConsolidateMode::Merge,
        "operator-link consolidate test",
        agent,
    )
    .await
    .expect("consolidate by the operated agent")
    .merged_id;

    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(merged)
        .fetch_one(&pool)
        .await
        .expect("merged owner");
    assert_eq!(
        owner, op_group,
        "an operated agent's merged claim must be owned by its operator's group, not by its \
         own ({own_group}); otherwise a model bump splits the job's work across groups again"
    );

    // CALIBRATION: unlinked actor, all-public sources -> its own group, as before.
    let u1 = public_claim(&pool, unlinked, unlinked_group, "unlinked source alpha").await;
    let u2 = public_claim(&pool, unlinked, unlinked_group, "unlinked source beta").await;
    let merged = ClaimRepository::consolidate(
        &pool,
        &[u1, u2],
        "unlinked merge of alpha and beta",
        0.7,
        epigraph_db::ConsolidateMode::Merge,
        "operator-link consolidate calibration",
        unlinked,
    )
    .await
    .expect("consolidate by an unlinked agent")
    .merged_id;
    let owner: Uuid = sqlx::query_scalar("SELECT owner_group_id FROM claims WHERE id = $1")
        .bind(merged)
        .fetch_one(&pool)
        .await
        .expect("merged owner");
    assert_eq!(owner, unlinked_group);
}
