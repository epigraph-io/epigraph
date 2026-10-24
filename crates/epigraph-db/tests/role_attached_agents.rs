//! Migration 166: an agent attached to a role writes only while a human holds
//! that role, and only while the agent's own linked human is that holder.
//!
//! # What is under test
//!
//! * `role_agents` records which agents belong to which role. It is
//!   append-only and maintenance-written (`epigraph_attach_agent_to_role` /
//!   `epigraph_detach_agent_from_role`, each audited); the application role
//!   reads no row and writes none.
//! * A claim written or authored by an agent with a LIVE attachment is refused
//!   `ROL01` unless, at the statement's clock, the role has a live human
//!   holder AND the agent's live-linked human is that holder. The check sits in
//!   the operator-binding path (the claims trigger's writer-scope and
//!   attribution checks), so no write path skips it.
//! * "A run in progress finishes, but its writes after the end are refused":
//!   a write inside an OPEN transaction after the assignment's `valid_to`
//!   passes is refused, because the check reads `clock_timestamp()`, not the
//!   transaction's start.
//! * `epigraph_role_agent_may_run(agent)` answers the host and epigraph-mcp
//!   without exposing the roster. Both the application role and the identity
//!   attestor can EXECUTE it.
//! * A succession registered by the attestor copies the parent's live
//!   attachments to the child, once.
//! * POSITIVE CONTROL throughout: an agent with no attachment writes exactly as
//!   before, during the same gap that refuses an attached agent.
//!
//! # Why the writes run as `epigraph_app`
//!
//! `#[sqlx::test]` connects as a superuser, and a superuser session is a
//! PRIVILEGED session (`epigraph_bypass()`), which ROL01 exempts on purpose
//! (the custodial maintenance path). So every refusal here is measured on a
//! connection whose `session_user` is the application role, stamped with the
//! principal and groups `ScopedPool` would stamp. Fixture rows are seeded on
//! the superuser connection.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::AgentRepository;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

const ROL01: &str = "ROL01";
const INSUFFICIENT_PRIVILEGE: &str = "42501";
const ATTESTOR: &str = "epigraph_identity_attestor";
const ROLE: &str = "role:test-curator";
const OTHER_ROLE: &str = "role:test-steward";

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

fn assert_rol01<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>, what: &str) {
    assert_eq!(
        code_of(r).as_deref(),
        Some(ROL01),
        "{what}: expected ROL01, got {r:?}"
    );
}

/// A synthetic catalog role, with the role node 123 requires for every role.
async fn seed_role(pool: &PgPool, key: &str) {
    let node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name, agent_type, role, labels) \
         VALUES ($1, uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()), $2, 'role', \
                 'custom', ARRAY['role'])",
    )
    .bind(node)
    .bind(key)
    .execute(pool)
    .await
    .expect("role node");
    sqlx::query(
        "INSERT INTO platform_roles (key, elevates, reads_audit, role_node_id, description) \
         VALUES ($1, false, false, $2, 'test role')",
    )
    .bind(key)
    .bind(node)
    .execute(pool)
    .await
    .expect("platform role");
}

/// Arm the operator binding as the maintenance role would (the production
/// state every refusal below is measured in, unless a test says otherwise).
async fn arm(pool: &PgPool) {
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
            .fetch_one(&mut *conn)
            .await
            .expect("the maintenance role arms");
        (conn, ())
    })
    .await;
}

/// A registered human with its personal group.
async fn human(pool: &PgPool, label: &str) -> (Uuid, Uuid) {
    fixture::seed_human_operator(pool, label).await
}

/// An agent live-linked to `operator`.
async fn agent_of(pool: &PgPool, operator: Uuid, label: &str) -> Uuid {
    let (agent, _) = fixture::seed_agent_with_group(pool, label).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let out = AgentRepository::link_operator(&mut conn, agent, operator)
        .await
        .expect("live link");
    assert!(out.link_live, "the fixture link must be live");
    agent
}

/// Grant `role` to `holder`, live from a few seconds ago (a host whose clock
/// steps backward must still see it live), until `valid_to_secs` from now.
async fn grant(pool: &PgPool, role: &str, holder: Uuid, valid_to_secs: Option<f64>) -> Uuid {
    sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '5 seconds', \
                CASE WHEN $3::float8 IS NULL THEN NULL \
                     ELSE now() + make_interval(secs => $3::float8) END, \
                NULL, 'test grant')",
    )
    .bind(role)
    .bind(holder)
    .bind(valid_to_secs)
    .fetch_one(pool)
    .await
    .expect("grant role")
}

async fn end_assignment(pool: &PgPool, assignment: Uuid) {
    let ended: bool = sqlx::query_scalar(
        "SELECT public.epigraph_end_role_assignment($1, 'test handover', NULL::uuid)",
    )
    .bind(assignment)
    .fetch_one(pool)
    .await
    .expect("end assignment");
    assert!(ended);
}

/// Attach `agent` to `role` through the maintenance definer, live from a few
/// seconds ago.
async fn attach(pool: &PgPool, role: &str, agent: Uuid) -> Uuid {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                                                         NULL, 'test attach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role attaches");
        (conn, id)
    })
    .await
}

async fn detach(pool: &PgPool, role: &str, agent: Uuid) -> i32 {
    let role = role.to_string();
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let n: i32 = sqlx::query_scalar(
            "SELECT public.epigraph_detach_agent_from_role($1, $2, 'test detach')",
        )
        .bind(&role)
        .bind(agent)
        .fetch_one(&mut *conn)
        .await
        .expect("the maintenance role detaches");
        (conn, n)
    })
    .await
}

/// A `('public', group)` claim by `author`, on whatever connection `exec` is.
async fn insert_claim<'e, E>(exec: E, author: Uuid, group: Uuid) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let hash = id.as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5)",
    )
    .bind(id)
    .bind(format!("role agent probe {id}"))
    .bind(hash)
    .bind(author)
    .bind(group)
    .execute(exec)
    .await?;
    Ok(id)
}

async fn stamp(conn: &mut sqlx::PgConnection, principal: Uuid, groups: &[Uuid]) {
    let set = groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(
        "SELECT set_config('epigraph.principal_id', $1, false), \
                set_config('epigraph.group_ids', $2, false), \
                set_config('epigraph.writable_group_ids', $2, false)",
    )
    .bind(principal.to_string())
    .bind(&set)
    .execute(&mut *conn)
    .await
    .expect("stamp");
}

async fn unstamp(conn: &mut sqlx::PgConnection) {
    sqlx::query(
        "SELECT set_config('epigraph.principal_id', '', false), \
                set_config('epigraph.group_ids', '', false), \
                set_config('epigraph.writable_group_ids', '', false)",
    )
    .execute(&mut *conn)
    .await
    .expect("unstamp");
}

/// One claim by `author` into `group`, on an `epigraph_app` connection stamped
/// as `writer` with `group` readable and writable.
async fn write_as(
    pool: &PgPool,
    writer: Uuid,
    author: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, writer, &[group]).await;
        let r = insert_claim(&mut *conn, author, group).await;
        unstamp(&mut conn).await;
        (conn, r)
    })
    .await
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct MayRun {
    may_run: bool,
    role: Option<String>,
    holder: Option<Uuid>,
    reason: String,
}

async fn may_run_as(pool: &PgPool, role: &str, agent: Uuid) -> Result<MayRun, sqlx::Error> {
    fixture::as_role(pool, role, |mut conn| async move {
        let r = sqlx::query_as::<_, MayRun>(
            "SELECT may_run, role, holder, reason FROM public.epigraph_role_agent_may_run($1)",
        )
        .bind(agent)
        .fetch_one(&mut *conn)
        .await;
        (conn, r)
    })
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// The write refusal
// ─────────────────────────────────────────────────────────────────────────────

/// The ruling's core: with no human holding the role, an attached agent's
/// claim is refused ROL01; once its linked human holds the role, the same
/// write lands. POSITIVE CONTROL in the same gap: an unattached agent of the
/// same human writes. A human naming its attached agent as the AUTHOR is
/// refused alike (the attribution arm), and writes as itself.
///
/// Verified to fail: the role check removed from `epigraph_require_writer_scope`
/// lets the gap write land.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_agent_writes_only_while_its_human_holds_the_role(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let unattached = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    // The gap: nobody holds the role.
    let gap = write_as(&pool, attached, attached, h_group).await;
    assert_rol01(&gap, "an attached agent in a gap");
    let text = gap.expect_err("refused").to_string();
    assert!(
        text.contains(ROLE),
        "the refusal must name the role: {text}"
    );
    let named = write_as(&pool, h, attached, h_group).await;
    assert_rol01(
        &named,
        "a human naming its attached agent as author in a gap",
    );
    write_as(&pool, unattached, unattached, h_group)
        .await
        .expect("POSITIVE CONTROL: an unattached agent of the same human writes in the gap");
    write_as(&pool, h, h, h_group)
        .await
        .expect("POSITIVE CONTROL: the human writes as itself in the gap");

    // The linked human takes the role: the same writes land.
    grant(&pool, ROLE, h, None).await;
    write_as(&pool, attached, attached, h_group)
        .await
        .expect("the attached agent writes while its human holds the role");
    write_as(&pool, h, attached, h_group)
        .await
        .expect("the holder names its attached agent as author");
}

/// "A run in progress finishes, but every write it makes after the end is
/// refused." The assignment's `valid_to` passes while a transaction is OPEN:
/// its first write lands, its write after `valid_to` is refused, and so is a
/// fresh transaction's.
///
/// Verified to fail: `clock_timestamp()` replaced by `now()` in the write
/// check (the open transaction's second write lands, because `now()` is the
/// transaction's start).
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_after_the_assignment_ends_is_refused_mid_run(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    attach(&pool, ROLE, attached).await;
    // A window long enough for the setup and the first write on a slow
    // runner; the sleep below is measured on the DATABASE's clock (a test
    // host's clock may step backward), with margin.
    let assignment = grant(&pool, ROLE, h, Some(8.0)).await;
    arm(&pool).await;

    let other = pool.clone();
    let (first, after) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, attached, &[h_group]).await;
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("begin");
        let first = insert_claim(&mut *conn, attached, h_group).await;
        let left = seconds_left(&other, "role_assignments", assignment).await;
        tokio::time::sleep(std::time::Duration::from_secs_f64(left + 1.5)).await;
        let after = insert_claim(&mut *conn, attached, h_group).await;
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
        unstamp(&mut conn).await;
        (conn, (first, after))
    })
    .await;
    assert!(
        first.is_ok(),
        "the write inside the window lands: {first:?}"
    );
    assert_rol01(
        &after,
        "a write in the same open transaction after valid_to",
    );
    let fresh = write_as(&pool, attached, attached, h_group).await;
    assert_rol01(&fresh, "a fresh transaction after valid_to");
}

/// After a handover (H1's assignment ended, H2 granted), an agent still linked
/// to H1 is refused: the role HAS a holder, but not the agent's human. CONTROL:
/// an agent linked to H2 and attached to the same role writes.
///
/// Verified to fail: the "linked human is the holder" test weakened to "the
/// role has some live holder" lets the H1 agent write after the handover.
#[sqlx::test(migrations = "../../migrations")]
async fn after_a_handover_an_agent_of_the_previous_holder_is_refused(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h1, h1_group) = human(&pool, "holder-1").await;
    let (h2, h2_group) = human(&pool, "holder-2").await;
    let old = agent_of(&pool, h1, "curator-old").await;
    let new = agent_of(&pool, h2, "curator-new").await;
    attach(&pool, ROLE, old).await;
    attach(&pool, ROLE, new).await;
    let a1 = grant(&pool, ROLE, h1, None).await;
    arm(&pool).await;

    write_as(&pool, old, old, h1_group)
        .await
        .expect("before the handover H1's agent writes");
    assert_rol01(
        &write_as(&pool, new, new, h2_group).await,
        "H2's agent before H2 holds the role",
    );

    end_assignment(&pool, a1).await;
    grant(&pool, ROLE, h2, None).await;

    assert_rol01(
        &write_as(&pool, old, old, h1_group).await,
        "an agent linked to the previous holder after the handover",
    );
    write_as(&pool, new, new, h2_group)
        .await
        .expect("CONTROL: an agent linked to the new holder writes");
}

/// POSITIVE CONTROL for the whole rule: agents with no live attachment are
/// unaffected, including an agent whose attachment was DETACHED, an agent
/// whose attachment has not started, and an agent of a human holding no role
/// at all; an attachment to another role does not leak.
#[sqlx::test(migrations = "../../migrations")]
async fn agents_without_a_live_attachment_are_unaffected(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    seed_role(&pool, OTHER_ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let detached = agent_of(&pool, h, "detached").await;
    let future = agent_of(&pool, h, "future").await;
    let other = agent_of(&pool, h, "other-role").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, detached).await;
    assert_eq!(detach(&pool, ROLE, detached).await, 1, "one row detached");
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        sqlx::query(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() + interval '1 hour', \
                                                         NULL, 'starts later')",
        )
        .bind(ROLE)
        .bind(future)
        .fetch_one(&mut *conn)
        .await
        .expect("a future attachment");
        (conn, ())
    })
    .await;
    attach(&pool, OTHER_ROLE, other).await;
    grant(&pool, OTHER_ROLE, h, None).await;
    arm(&pool).await;

    for (agent, what) in [
        (detached, "a detached agent"),
        (future, "an agent whose attachment has not started"),
        (other, "an agent of another role its human holds"),
        (plain, "an agent never attached"),
    ] {
        write_as(&pool, agent, agent, h_group)
            .await
            .unwrap_or_else(|e| panic!("{what} must write: {e}"));
    }
}

/// ROL01 is keyed on the operator binding's ARMING, like OPL02 (the claims
/// trigger checks nothing on an unarmed database), and the valve does not
/// relieve it: the valve relieves OPL01 only. A PRIVILEGED session (the
/// maintenance role, the custodial path) is exempt, as it is from OPL02.
#[sqlx::test(migrations = "../../migrations")]
async fn rol01_is_keyed_on_arming_survives_the_valve_and_spares_a_privileged_session(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    attach(&pool, ROLE, attached).await;

    write_as(&pool, attached, attached, h_group)
        .await
        .expect("an unarmed database enforces nothing in the binding path");
    arm(&pool).await;
    assert_rol01(&write_as(&pool, attached, attached, h_group).await, "armed");
    let valve = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, attached, &[h_group]).await;
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', 'off', false)")
            .execute(&mut *conn)
            .await
            .expect("valve");
        let r = insert_claim(&mut *conn, attached, h_group).await;
        sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
            .execute(&mut *conn)
            .await
            .expect("valve reset");
        unstamp(&mut conn).await;
        (conn, r)
    })
    .await;
    assert_rol01(&valve, "with the valve off");

    let privileged = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = insert_claim(&mut *conn, attached, h_group).await;
        (conn, r)
    })
    .await;
    assert!(
        privileged.is_ok(),
        "a privileged session is exempt: {privileged:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The record: who writes it, and what it audits
// ─────────────────────────────────────────────────────────────────────────────

/// The application role cannot write `role_agents` (INSERT, UPDATE, DELETE are
/// permission denials), cannot call the attach / detach definers, and reads no
/// row of it even when rows exist. CALIBRATION: the maintenance role attaches,
/// and each attach and detach writes one `platform.` audit row.
#[sqlx::test(migrations = "../../migrations")]
async fn the_app_role_cannot_write_role_agents_directly(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let other = agent_of(&pool, h, "other").await;
    let row = attach(&pool, ROLE, attached).await;

    let (insert, update, delete, attach_fn, detach_fn, visible) =
        fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
            stamp(&mut conn, h, &[]).await;
            let insert = sqlx::query(
                "INSERT INTO role_agents (role, agent_id, reason) VALUES ($1, $2, 'forged')",
            )
            .bind(ROLE)
            .bind(other)
            .execute(&mut *conn)
            .await;
            let update = sqlx::query(
                "UPDATE role_agents SET detached_at = now(), detached_by = session_user, \
                        detach_reason = 'forged' WHERE id = $1",
            )
            .bind(row)
            .execute(&mut *conn)
            .await;
            let delete = sqlx::query("DELETE FROM role_agents WHERE id = $1")
                .bind(row)
                .execute(&mut *conn)
                .await;
            let attach_fn = sqlx::query(
                "SELECT public.epigraph_attach_agent_to_role($1, $2, NULL, NULL, 'forged')",
            )
            .bind(ROLE)
            .bind(other)
            .execute(&mut *conn)
            .await;
            let detach_fn =
                sqlx::query("SELECT public.epigraph_detach_agent_from_role($1, $2, 'forged')")
                    .bind(ROLE)
                    .bind(attached)
                    .execute(&mut *conn)
                    .await;
            let visible: Result<i64, _> = sqlx::query_scalar("SELECT count(*) FROM role_agents")
                .fetch_one(&mut *conn)
                .await;
            unstamp(&mut conn).await;
            (
                conn,
                (insert, update, delete, attach_fn, detach_fn, visible),
            )
        })
        .await;
    for (what, code) in [
        ("INSERT", code_of(&insert)),
        ("UPDATE", code_of(&update)),
        ("DELETE", code_of(&delete)),
        ("attach definer", code_of(&attach_fn)),
        ("detach definer", code_of(&detach_fn)),
    ] {
        assert_eq!(
            code.as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "the app role's {what} on role_agents must be a permission denial"
        );
    }
    assert_eq!(
        visible.expect("the app role may SELECT the table"),
        0,
        "the app role reads no attachment row"
    );

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_agents WHERE id = $1 AND detached_at IS NULL",
    )
    .bind(row)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(live, 1, "the refused writes changed nothing");

    assert_eq!(detach(&pool, ROLE, attached).await, 1);
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM security_events \
          WHERE event_type LIKE 'platform.role_agent_%' AND agent_id = $1 ORDER BY event_type",
    )
    .bind(attached)
    .fetch_all(&pool)
    .await
    .expect("audit");
    assert_eq!(
        audit,
        vec![
            "platform.role_agent_attached".to_string(),
            "platform.role_agent_detached".to_string()
        ]
    );
}

/// `role_agents` is append-only on every role, the maintenance role and the
/// superuser included: the one change a row takes is its detach (stamped
/// `now()` by the detaching login, with a reason), a detached row is final,
/// and no row is deleted. A human, or a role node, is never attached:
/// agents only.
#[sqlx::test(migrations = "../../migrations")]
async fn role_agents_is_append_only_and_attaches_agents_only(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let row = attach(&pool, ROLE, attached).await;

    let rewrite =
        sqlx::query("UPDATE role_agents SET valid_to = now() + interval '1 day' WHERE id = $1")
            .bind(row)
            .execute(&pool)
            .await;
    assert!(rewrite.is_err(), "a window is never rewritten: {rewrite:?}");
    let delete = sqlx::query("DELETE FROM role_agents WHERE id = $1")
        .bind(row)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "a row is never deleted: {delete:?}");
    let backdated = sqlx::query(
        "INSERT INTO role_agents (role, agent_id, valid_from, reason) \
         VALUES ($1, $2, now() - interval '1 day', 'backdated')",
    )
    .bind(ROLE)
    .bind(agent_of(&pool, h, "backdated").await)
    .execute(&pool)
    .await;
    assert!(backdated.is_err(), "an attachment is never back-dated");
    let overlap =
        sqlx::query("INSERT INTO role_agents (role, agent_id, reason) VALUES ($1, $2, 'twice')")
            .bind(ROLE)
            .bind(attached)
            .execute(&pool)
            .await;
    assert!(overlap.is_err(), "one live attachment per (role, agent)");
    let human_row =
        sqlx::query("INSERT INTO role_agents (role, agent_id, reason) VALUES ($1, $2, 'a human')")
            .bind(ROLE)
            .bind(h)
            .execute(&pool)
            .await;
    assert!(human_row.is_err(), "a human is never attached as an agent");

    assert_eq!(detach(&pool, ROLE, attached).await, 1);
    let reopen = sqlx::query(
        "UPDATE role_agents SET detached_at = NULL, detached_by = NULL, detach_reason = NULL \
          WHERE id = $1",
    )
    .bind(row)
    .execute(&pool)
    .await;
    assert!(reopen.is_err(), "a detached row is final: {reopen:?}");
    assert_eq!(
        detach(&pool, ROLE, attached).await,
        0,
        "a second detach ends nothing"
    );
    // CALIBRATION: after the detach the agent can be attached again.
    attach(&pool, ROLE, attached).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// The question the host and epigraph-mcp ask
// ─────────────────────────────────────────────────────────────────────────────

/// `epigraph_role_agent_may_run` answers the application role and the
/// identity attestor (the host), and its answers track the write rule:
/// unattached -> may run; a gap -> no holder; the holder's agent -> may run,
/// naming its own human; an agent of a previous holder -> not the holder, and
/// the current holder is NOT disclosed to it.
#[sqlx::test(migrations = "../../migrations")]
async fn may_run_answers_the_app_role_and_the_attestor(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h1, _) = human(&pool, "holder-1").await;
    let (h2, _) = human(&pool, "holder-2").await;
    let plain = agent_of(&pool, h1, "plain").await;
    let a1 = agent_of(&pool, h1, "curator-1").await;
    attach(&pool, ROLE, a1).await;

    for caller in ["epigraph_app", ATTESTOR] {
        assert_eq!(
            may_run_as(&pool, caller, plain).await.expect(caller),
            MayRun {
                may_run: true,
                role: None,
                holder: None,
                reason: "unattached".into()
            },
            "{caller}: an unattached agent"
        );
        assert_eq!(
            may_run_as(&pool, caller, a1).await.expect(caller),
            MayRun {
                may_run: false,
                role: Some(ROLE.into()),
                holder: None,
                reason: "no_holder".into()
            },
            "{caller}: a gap"
        );
    }
    let g1 = grant(&pool, ROLE, h1, None).await;
    for caller in ["epigraph_app", ATTESTOR] {
        assert_eq!(
            may_run_as(&pool, caller, a1).await.expect(caller),
            MayRun {
                may_run: true,
                role: Some(ROLE.into()),
                holder: Some(h1),
                reason: "held".into()
            },
            "{caller}: the holder's agent"
        );
    }
    end_assignment(&pool, g1).await;
    grant(&pool, ROLE, h2, None).await;
    for caller in ["epigraph_app", ATTESTOR] {
        assert_eq!(
            may_run_as(&pool, caller, a1).await.expect(caller),
            MayRun {
                may_run: false,
                role: Some(ROLE.into()),
                holder: None,
                reason: "not_holder".into()
            },
            "{caller}: an agent of the previous holder"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Succession
// ─────────────────────────────────────────────────────────────────────────────

fn random32() -> Vec<u8> {
    [
        Uuid::new_v4().as_bytes().as_slice(),
        Uuid::new_v4().as_bytes().as_slice(),
    ]
    .concat()
}

/// Register an identity on the attestor role; returns the agent id.
async fn register(pool: &PgPool, pubkey: &[u8], parent: Option<Uuid>, group: &str) -> Uuid {
    let pubkey = pubkey.to_vec();
    let hash = blake3::hash(&pubkey).to_hex().to_string();
    let group = group.to_string();
    fixture::as_role(pool, ATTESTOR, |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                 $1, $2, 'test-model-166', $3, $4, NULL, $5)",
        )
        .bind(&pubkey)
        .bind(parent)
        .bind(&hash)
        .bind(&group)
        .bind(json!({"in_prompt": {}}))
        .fetch_one(&mut *conn)
        .await
        .expect("the attestor registers the identity");
        (conn, id)
    })
    .await
}

async fn live_attachments(pool: &PgPool, agent: Uuid) -> Vec<(String, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT role, inherited_from FROM role_agents \
          WHERE agent_id = $1 AND detached_at IS NULL ORDER BY role",
    )
    .bind(agent)
    .fetch_all(pool)
    .await
    .expect("attachments")
}

/// A succession the attestor registers copies the parent's live attachments
/// to the child (so a LEARNED.md edit does not detach an agent from its
/// role), records which row it came from, and does it once: the same
/// registration again copies nothing and still succeeds. A DETACHED parent
/// attachment is not copied. The child is then held to the rule: refused in
/// the gap.
///
/// Verified to fail: the copy block removed from the registration.
#[sqlx::test(migrations = "../../migrations")]
async fn a_succession_copies_the_parents_live_attachments_once(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    seed_role(&pool, OTHER_ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let parent_key = random32();
    let parent = register(&pool, &parent_key, None, "g-166").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    let kept = attach(&pool, ROLE, parent).await;
    attach(&pool, OTHER_ROLE, parent).await;
    assert_eq!(detach(&pool, OTHER_ROLE, parent).await, 1);

    let child_key = random32();
    let child = register(&pool, &child_key, Some(parent), "g-166").await;
    assert_eq!(
        live_attachments(&pool, child).await,
        vec![(ROLE.to_string(), Some(kept))],
        "the child carries the parent's live attachment, and only that one"
    );
    let again = register(&pool, &child_key, Some(parent), "g-166").await;
    assert_eq!(again, child);
    assert_eq!(
        live_attachments(&pool, child).await.len(),
        1,
        "a repeat registration copies nothing"
    );

    arm(&pool).await;
    assert_rol01(
        &write_as(&pool, child, child, h_group).await,
        "the successor in a gap",
    );
    grant(&pool, ROLE, h, None).await;
    write_as(&pool, child, child, h_group)
        .await
        .expect("the successor writes while its human holds the role");
}

// ─────────────────────────────────────────────────────────────────────────────
// The Rust surface
// ─────────────────────────────────────────────────────────────────────────────

/// ROL01 reaches callers as the named `DbError::RoleHolderRequired`, in the
/// write-authority refusal set every write surface maps to a denial, and
/// `AgentRepository::role_agent_may_run` answers on an application-role pool
/// exactly as the SQL does.
#[sqlx::test(migrations = "../../migrations")]
async fn rol01_is_named_and_the_repository_asks_may_run(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    let named = epigraph_db::DbError::from(
        write_as(&pool, attached, attached, h_group)
            .await
            .expect_err("a gap write is refused"),
    );
    assert!(
        matches!(named, epigraph_db::DbError::RoleHolderRequired { .. })
            && named.is_write_authority_refusal(),
        "ROL01 must map to RoleHolderRequired: {named:?}"
    );

    let app = fixture::downgraded_pool(&pool, "epigraph_app").await;
    let gap = AgentRepository::role_agent_may_run(&app, attached)
        .await
        .expect("the app role asks");
    assert!(!gap.may_run && gap.reason == "no_holder" && gap.role.as_deref() == Some(ROLE));
    let free = AgentRepository::role_agent_may_run(&app, plain)
        .await
        .expect("the app role asks");
    assert!(free.may_run && free.reason == "unattached" && free.role.is_none());
    grant(&pool, ROLE, h, None).await;
    let held = AgentRepository::role_agent_may_run(&app, attached)
        .await
        .expect("the app role asks");
    assert!(held.may_run && held.holder == Some(h) && held.reason == "held");
}

// ─────────────────────────────────────────────────────────────────────────────
// Review round: snapshots, lineage and ownership
// ─────────────────────────────────────────────────────────────────────────────

/// One claim by `agent` on an `epigraph_app` connection stamped as `agent`,
/// inside a transaction at `isolation`. After the transaction's snapshot is
/// taken, `end_between` (an assignment) is ended on ANOTHER connection and
/// committed. Always rolled back.
async fn write_in_txn(
    pool: &PgPool,
    agent: Uuid,
    group: Uuid,
    isolation: &'static str,
    end_between: Option<Uuid>,
) -> Result<Uuid, sqlx::Error> {
    let other = pool.clone();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, agent, &[group]).await;
        sqlx::query(&format!("BEGIN ISOLATION LEVEL {isolation}"))
            .execute(&mut *conn)
            .await
            .expect("begin");
        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .expect("the transaction's snapshot");
        if let Some(assignment) = end_between {
            end_assignment(&other, assignment).await;
        }
        let r = insert_claim(&mut *conn, agent, group).await;
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
        unstamp(&mut conn).await;
        (conn, r)
    })
    .await
}

/// A transaction that is not READ COMMITTED judges every statement against
/// its FIRST snapshot, so an assignment ended (revoked) by a handover after
/// that snapshot would still read as live for as long as the transaction
/// stays open: the "run in progress" would keep writing after the end. So an
/// attached agent writes only under READ COMMITTED (as 123's CUS06 refuses a
/// grant under REPEATABLE READ). POSITIVE CONTROLS: the same agent writes under
/// READ COMMITTED, and an unattached agent writes under REPEATABLE READ and
/// SERIALIZABLE.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_agent_writes_only_on_a_fresh_snapshot(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    let assignment = grant(&pool, ROLE, h, None).await;
    arm(&pool).await;

    write_in_txn(&pool, attached, h_group, "READ COMMITTED", None)
        .await
        .expect("CONTROL: the holder's agent writes under READ COMMITTED");
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        write_in_txn(&pool, plain, h_group, level, None)
            .await
            .unwrap_or_else(|e| panic!("CONTROL: an unattached agent writes under {level}: {e}"));
        assert_rol01(
            &write_in_txn(&pool, attached, h_group, level, None).await,
            &format!("an attached agent under {level}"),
        );
    }
    // The case the rule exists for: the assignment ends after the snapshot.
    assert_rol01(
        &write_in_txn(
            &pool,
            attached,
            h_group,
            "REPEATABLE READ",
            Some(assignment),
        )
        .await,
        "a REPEATABLE READ run whose holder's assignment ended after its snapshot",
    );
}

/// A detach is final, and a repeat registration naming the same parent does
/// not undo it: the succession copy skips a parent row the child already
/// inherited, detached or not. CONTROL: a NEW child of the same parent is
/// still copied.
#[sqlx::test(migrations = "../../migrations")]
async fn a_repeat_registration_does_not_reattach_a_detached_child(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let parent = register(&pool, &random32(), None, "g-166-detach").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    let row = attach(&pool, ROLE, parent).await;
    let child_key = random32();
    let child = register(&pool, &child_key, Some(parent), "g-166-detach").await;
    assert_eq!(
        live_attachments(&pool, child).await,
        vec![(ROLE.to_string(), Some(row))]
    );
    assert_eq!(detach(&pool, ROLE, child).await, 1, "the child is detached");

    let again = register(&pool, &child_key, Some(parent), "g-166-detach").await;
    assert_eq!(again, child);
    assert_eq!(
        live_attachments(&pool, child).await,
        Vec::<(String, Option<Uuid>)>::new(),
        "a repeat registration re-attached a child an operator detached"
    );

    let second = register(&pool, &random32(), Some(parent), "g-166-detach").await;
    assert_eq!(
        live_attachments(&pool, second).await,
        vec![(ROLE.to_string(), Some(row))],
        "CONTROL: a new child of the attached parent is copied"
    );
}

/// An identity changes whenever its prompt files or model do, so the identity
/// an operator attaches may already have registered successors (the one that
/// runs now). Attaching it attaches every registered successor down its
/// lineage too, each naming the row it came from; otherwise the running
/// identity would write in a gap unrefused. CONTROL: an agent outside the
/// lineage is untouched, and the newest identity writes once its human holds
/// the role.
#[sqlx::test(migrations = "../../migrations")]
async fn attaching_an_identity_attaches_its_registered_successors(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let parent = register(&pool, &random32(), None, "g-166-lineage").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    let child = register(&pool, &random32(), Some(parent), "g-166-lineage").await;
    let newest = register(&pool, &random32(), Some(child), "g-166-lineage").await;
    let outside = agent_of(&pool, h, "outside").await;

    let row = attach(&pool, ROLE, parent).await;
    assert_eq!(
        live_attachments(&pool, child).await,
        vec![(ROLE.to_string(), Some(row))],
        "the registered successor is attached with the ancestor"
    );
    let newest_rows = live_attachments(&pool, newest).await;
    assert_eq!(
        newest_rows.len(),
        1,
        "the newest identity in the lineage is attached: {newest_rows:?}"
    );
    assert!(live_attachments(&pool, outside).await.is_empty());

    arm(&pool).await;
    assert_rol01(
        &write_as(&pool, newest, newest, h_group).await,
        "the newest identity of an attached lineage, in a gap",
    );
    write_as(&pool, outside, outside, h_group)
        .await
        .expect("CONTROL: an agent outside the lineage writes in the gap");
    grant(&pool, ROLE, h, None).await;
    write_as(&pool, newest, newest, h_group)
        .await
        .expect("the newest identity writes while its human holds the role");
}

/// The gate reads `role_agents` (FORCEd: a maintenance session or a
/// maintenance-owned definer frame only). Under any other owner it would see
/// no attachment and read every agent as unattached: ROL01 would never fire
/// and epigraph-mcp would boot in a gap. It fails CLOSED instead: every write
/// in the binding path and every may-run question is refused until the owner
/// is restored. CONTROL: restoring the owner restores both answers.
#[sqlx::test(migrations = "../../migrations")]
async fn a_misowned_gate_fails_closed(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    for stmt in [
        "ALTER FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz) OWNER TO epigraph_app",
        // So the refusal measured is the gate's own, not a missing grant: the
        // owner change rewrites the gate's ACL (the maintenance-owned callers
        // lose EXECUTE), and the new owner must be able to run what it calls.
        "GRANT EXECUTE ON FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz) \
         TO epigraph_maintenance",
        "GRANT EXECUTE ON FUNCTION public.epigraph_human_of(uuid, boolean), \
                public.epigraph_live_role_assignment(uuid, text, timestamptz) TO epigraph_app",
    ] {
        sqlx::query(stmt).execute(&pool).await.expect(stmt);
    }
    assert_rol01(
        &write_as(&pool, attached, attached, h_group).await,
        "an attached agent under a misowned gate",
    );
    assert_rol01(
        &write_as(&pool, plain, plain, h_group).await,
        "any agent under a misowned gate (the gate cannot tell)",
    );
    assert!(
        may_run_as(&pool, "epigraph_app", plain).await.is_err(),
        "the may-run question is refused under a misowned gate"
    );

    sqlx::query(
        "ALTER FUNCTION public.epigraph_role_agent_gate(uuid, timestamptz) \
         OWNER TO epigraph_maintenance",
    )
    .execute(&pool)
    .await
    .expect("restore the owner");
    write_as(&pool, plain, plain, h_group)
        .await
        .expect("CONTROL: with the owner restored an unattached agent writes");
    assert_rol01(
        &write_as(&pool, attached, attached, h_group).await,
        "CONTROL: with the owner restored the attached agent is refused in the gap",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Review round: pins on arms that already hold
// ─────────────────────────────────────────────────────────────────────────────

/// A claim by `author` superseding `supersedes`, on whatever connection `exec` is.
async fn insert_successor<'e, E>(
    exec: E,
    author: Uuid,
    group: Uuid,
    supersedes: Uuid,
) -> Result<Uuid, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let hash = id.as_bytes().repeat(2);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id, supersedes) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'public', $5, $6)",
    )
    .bind(id)
    .bind(format!("role agent restatement {id}"))
    .bind(hash)
    .bind(author)
    .bind(group)
    .bind(supersedes)
    .execute(exec)
    .await?;
    Ok(id)
}

/// The WRITER arm. An attached agent in a gap that stamps itself as the
/// writer but names another author of the same human (an unattached sibling,
/// or the human itself) is refused: the check on the writer, not only on the
/// author, is what stops it laundering its writes through an unattached
/// identity. CONTROLS in the same gap: the sibling writes as itself and the
/// human names the sibling; after the grant both of the attached writer's
/// claims land.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attached_writer_cannot_launder_through_another_author(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let sibling = agent_of(&pool, h, "sibling").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    write_as(&pool, sibling, sibling, h_group)
        .await
        .expect("CONTROL: the unattached sibling writes as itself in the gap");
    write_as(&pool, h, sibling, h_group)
        .await
        .expect("CONTROL: the human names its unattached agent in the gap");
    assert_rol01(
        &write_as(&pool, attached, sibling, h_group).await,
        "an attached writer naming an unattached sibling",
    );
    assert_rol01(
        &write_as(&pool, attached, h, h_group).await,
        "an attached writer naming its human",
    );

    grant(&pool, ROLE, h, None).await;
    write_as(&pool, attached, sibling, h_group)
        .await
        .expect("the holder's agent names its sibling");
    write_as(&pool, attached, h, h_group)
        .await
        .expect("the holder's agent names its human");
}

/// Workflow ingest writes every row as the shared system identity, so the
/// claims trigger never sees the real caller: ROL01 on the caller is reached
/// only through the Rust preflight `AgentRepository::require_writer_authority`.
/// In a gap it refuses an attached caller as `DbError::RoleHolderRequired`.
/// CONTROLS: an unattached caller passes in the same gap, and the attached
/// caller passes once its human holds the role.
///
/// Verified to fail: `epigraph_require_writer_scope` dropped from the
/// preflight's statement.
#[sqlx::test(migrations = "../../migrations")]
async fn the_workflow_caller_preflight_refuses_a_role_agent_in_a_gap(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let system = agent_of(&pool, h, "shared-system").await;
    let attached = agent_of(&pool, h, "curator").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    let check = |caller: Uuid| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                stamp(&mut conn, system, &[h_group]).await;
                let r = AgentRepository::require_writer_authority(
                    &mut conn,
                    system,
                    Some(caller),
                    h_group,
                )
                .await;
                unstamp(&mut conn).await;
                (conn, r)
            })
            .await
        }
    };
    let gap = check(attached).await;
    assert!(
        matches!(gap, Err(epigraph_db::DbError::RoleHolderRequired { .. })),
        "an attached workflow caller in a gap: expected RoleHolderRequired, got {gap:?}"
    );
    check(plain)
        .await
        .expect("CONTROL: an unattached caller passes in the gap");
    grant(&pool, ROLE, h, None).await;
    check(attached)
        .await
        .expect("the attached caller passes while its human holds the role");
}

/// EVERY live attachment must be held, not any one: an agent attached to two
/// roles, only one of which its human holds, is refused and the answer names
/// the unheld role. Once its human holds both, it writes.
///
/// Verified to fail: the gate admitting the agent at its first HELD
/// attachment.
#[sqlx::test(migrations = "../../migrations")]
async fn every_live_attachment_must_be_held(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    seed_role(&pool, OTHER_ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let agent = agent_of(&pool, h, "two-roles").await;
    attach(&pool, ROLE, agent).await;
    attach(&pool, OTHER_ROLE, agent).await;
    grant(&pool, ROLE, h, None).await;
    arm(&pool).await;

    let refused = write_as(&pool, agent, agent, h_group).await;
    assert_rol01(&refused, "an agent whose second role has no holder");
    let text = refused.expect_err("refused").to_string();
    assert!(text.contains(OTHER_ROLE), "names the unheld role: {text}");
    assert_eq!(
        may_run_as(&pool, "epigraph_app", agent).await.expect("ask"),
        MayRun {
            may_run: false,
            role: Some(OTHER_ROLE.into()),
            holder: None,
            reason: "no_holder".into()
        }
    );

    grant(&pool, OTHER_ROLE, h, None).await;
    write_as(&pool, agent, agent, h_group)
        .await
        .expect("both roles held: the agent writes");
    assert_eq!(
        may_run_as(&pool, "epigraph_app", agent).await.expect("ask"),
        MayRun {
            may_run: true,
            role: Some(ROLE.into()),
            holder: Some(h),
            reason: "held".into()
        }
    );
}

/// The realistic handover: an operator ends the assignment from ANOTHER
/// connection while the run's (READ COMMITTED) transaction is open. The run's
/// next write in that same transaction is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn an_assignment_ended_elsewhere_refuses_the_open_runs_next_write(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    attach(&pool, ROLE, attached).await;
    let assignment = grant(&pool, ROLE, h, None).await;
    arm(&pool).await;

    let other = pool.clone();
    let (first, after) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, attached, &[h_group]).await;
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("begin");
        let first = insert_claim(&mut *conn, attached, h_group).await;
        end_assignment(&other, assignment).await;
        let after = insert_claim(&mut *conn, attached, h_group).await;
        sqlx::query("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
        unstamp(&mut conn).await;
        (conn, (first, after))
    })
    .await;
    assert!(first.is_ok(), "the write before the end lands: {first:?}");
    assert_rol01(
        &after,
        "the open run's write after the assignment was ended elsewhere",
    );
}

/// One restatement of `retired` (author `author`) by an `epigraph_app` session
/// stamped as `writer`.
async fn restate_as(
    pool: &PgPool,
    writer: Uuid,
    author: Uuid,
    group: Uuid,
    retired: Uuid,
) -> Result<Uuid, sqlx::Error> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, writer, &[group]).await;
        let r = insert_successor(&mut *conn, author, group, retired).await;
        unstamp(&mut conn).await;
        (conn, r)
    })
    .await
}

/// A restatement of a RETIRED claim inherits its author, and the attribution
/// check is relieved of ROL01 on that inherited author ONLY when the author
/// identity is itself retired (a retired operator link and no live one: it
/// can never run again, so naming it is its human's act) or the session is
/// privileged. Otherwise the inherited author is an attached agent that may
/// run again, and naming it after its role lapsed is a write presented as
/// that agent's in the gap: refused, whoever writes it. So, after the lapse:
/// * the attached agent restating its own retired claim is refused (the
///   writer arm);
/// * an UNATTACHED sibling of the same human restating it, author = the
///   attached agent, is refused (the inherited author arm);
/// * the human restating it is refused alike;
/// * CONTROL: the sibling restating a retired claim whose author is a
///   genuinely RETIRED identity attached to the same role lands;
/// * CONTROL: a privileged session restating the attached agent's claim lands;
/// * CONTROL: the human naming the agent on a FRESH claim is refused.
///
/// Verified to fail: the author check in `epigraph_require_attributable`
/// skipped whenever `p_inherited` is true (the sibling's and the human's
/// restatements land).
#[sqlx::test(migrations = "../../migrations")]
async fn a_restatement_names_an_attached_author_only_while_held_unless_it_is_retired(
    pool: PgPool,
) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let sibling = agent_of(&pool, h, "sibling").await;
    let (gone, _) = fixture::seed_agent_with_group(&pool, "retired-curator").await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, gone, h).await;
        (conn, r)
    })
    .await
    .expect("a retired link");
    attach(&pool, ROLE, attached).await;
    attach(&pool, ROLE, gone).await;
    // The retired identity's claim, written before arming (once armed, its
    // retired link binds it to no human, so even the privileged pool's fresh
    // claim is refused OPL01).
    let gone_claim = insert_claim(&pool, gone, h_group)
        .await
        .expect("the retired identity's claim (unarmed setup)");
    let assignment = grant(&pool, ROLE, h, None).await;
    arm(&pool).await;

    let mut retired = Vec::new();
    for _ in 0..4 {
        retired.push(
            write_as(&pool, attached, attached, h_group)
                .await
                .expect("written while held"),
        );
    }
    for id in retired.iter().chain(std::iter::once(&gone_claim)) {
        sqlx::query("UPDATE claims SET is_current = false WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("retire the predecessor (privileged setup)");
    }
    end_assignment(&pool, assignment).await;

    assert_rol01(
        &restate_as(&pool, attached, attached, h_group, retired[0]).await,
        "the attached agent restating its retired claim after the lapse",
    );
    assert_rol01(
        &restate_as(&pool, sibling, attached, h_group, retired[1]).await,
        "an unattached sibling restating the attached agent's claim after the lapse",
    );
    assert_rol01(
        &restate_as(&pool, h, attached, h_group, retired[2]).await,
        "the human restating the attached agent's claim after the lapse",
    );
    restate_as(&pool, sibling, gone, h_group, gone_claim)
        .await
        .expect("CONTROL: a retired identity's claim is restated in the gap");
    insert_successor(&pool, attached, h_group, retired[3])
        .await
        .expect("CONTROL: a privileged session restates the attached agent's claim");
    assert_rol01(
        &write_as(&pool, h, attached, h_group).await,
        "CONTROL: the human naming the agent on a fresh claim in the gap",
    );
}

/// An attached agent whose link is not LIVE has no human to hold the role,
/// so it may not run, even while the human it was once linked to holds the
/// role. CONTROL: a live-linked agent attached to the same role may run.
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_agent_without_a_live_link_may_not_run(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let (retired, _) = fixture::seed_agent_with_group(&pool, "retired-curator").await;
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let r = AgentRepository::link_retired_agent(&mut conn, retired, h).await;
        (conn, r)
    })
    .await
    .expect("a retired link");
    let live = agent_of(&pool, h, "live-curator").await;
    attach(&pool, ROLE, retired).await;
    attach(&pool, ROLE, live).await;
    grant(&pool, ROLE, h, None).await;

    for caller in ["epigraph_app", ATTESTOR] {
        let answer = may_run_as(&pool, caller, retired).await.expect(caller);
        assert!(
            !answer.may_run && answer.holder.is_none() && answer.role.as_deref() == Some(ROLE),
            "{caller}: a retired-linked attached agent: {answer:?}"
        );
        assert_eq!(
            may_run_as(&pool, caller, live).await.expect(caller),
            MayRun {
                may_run: true,
                role: Some(ROLE.into()),
                holder: Some(h),
                reason: "held".into()
            },
            "{caller}: CONTROL, the live-linked agent"
        );
    }
}

/// Seconds until `valid_to` of `table` row `id` by the DATABASE's clock (a
/// test host's clock may step backward).
async fn seconds_left(pool: &PgPool, table: &str, id: Uuid) -> f64 {
    sqlx::query_scalar(&format!(
        "SELECT GREATEST(extract(epoch FROM valid_to - clock_timestamp()), 0)::float8 \
           FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("seconds left")
}

/// A BOUNDED attachment refuses only inside its window: in a gap the agent is
/// refused while the attachment is live, and writes (and may run, as
/// unattached) once its `valid_to` has passed.
#[sqlx::test(migrations = "../../migrations")]
async fn a_bounded_attachment_frees_the_agent_when_it_ends(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let row = fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(
            "SELECT public.epigraph_attach_agent_to_role($1, $2, now() - interval '5 seconds', \
                    now() + interval '6 seconds', 'bounded')",
        )
        .bind(ROLE)
        .bind(attached)
        .fetch_one(&mut *conn)
        .await
        .expect("a bounded attachment");
        (conn, id)
    })
    .await;
    arm(&pool).await;

    assert_rol01(
        &write_as(&pool, attached, attached, h_group).await,
        "inside a bounded attachment's window, in a gap",
    );
    let left = seconds_left(&pool, "role_agents", row).await;
    tokio::time::sleep(std::time::Duration::from_secs_f64(left + 1.5)).await;
    write_as(&pool, attached, attached, h_group)
        .await
        .expect("after the attachment ends the agent is unattached and writes");
    assert_eq!(
        may_run_as(&pool, "epigraph_app", attached)
            .await
            .expect("ask")
            .reason,
        "unattached"
    );
}

/// The succession copy keeps the parent's window: a bounded parent row's
/// `valid_to`, and a not-yet-started parent row's own `valid_from` (a live
/// row starts at the registration instead).
#[sqlx::test(migrations = "../../migrations")]
async fn a_succession_copy_keeps_the_parents_window(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    seed_role(&pool, OTHER_ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let parent = register(&pool, &random32(), None, "g-166-window").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    fixture::as_role(&pool, "epigraph_maintenance", |mut conn| async move {
        for (role, from, to) in [
            (
                ROLE,
                "now() - interval '5 seconds'",
                "now() + interval '1 hour'",
            ),
            (
                OTHER_ROLE,
                "now() + interval '1 hour'",
                "now() + interval '2 hours'",
            ),
        ] {
            sqlx::query(&format!(
                "SELECT public.epigraph_attach_agent_to_role($1, $2, {from}, {to}, 'window')"
            ))
            .bind(role)
            .bind(parent)
            .fetch_one(&mut *conn)
            .await
            .expect("attach with a window");
        }
        (conn, ())
    })
    .await;
    let child = register(&pool, &random32(), Some(parent), "g-166-window").await;

    // (role, same valid_to, same valid_from, starts no earlier than the parent)
    let rows: Vec<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT c.role, c.valid_to IS NOT DISTINCT FROM p.valid_to, \
                c.valid_from = p.valid_from, c.valid_from >= p.valid_from \
           FROM role_agents c JOIN role_agents p ON p.id = c.inherited_from \
          WHERE c.agent_id = $1 ORDER BY c.role",
    )
    .bind(child)
    .fetch_all(&pool)
    .await
    .expect("copies");
    assert_eq!(
        rows,
        vec![
            (ROLE.to_string(), true, false, true),
            (OTHER_ROLE.to_string(), true, true, true),
        ],
        "a live row is copied from the registration to the parent's end; a future \
         row keeps its own start and end"
    );
}

/// Attach `agent` to `role` from `from` to `to` (SQL expressions), through the
/// maintenance definer.
async fn attach_window(pool: &PgPool, role: &str, agent: Uuid, from: &str, to: &str) -> Uuid {
    let role = role.to_string();
    let sql = format!(
        "SELECT public.epigraph_attach_agent_to_role($1, $2, {from}, {to}, 'test window')"
    );
    fixture::as_role(pool, "epigraph_maintenance", |mut conn| async move {
        let id: Uuid = sqlx::query_scalar(&sql)
            .bind(&role)
            .bind(agent)
            .fetch_one(&mut *conn)
            .await
            .expect("the maintenance role attaches with a window");
        (conn, id)
    })
    .await
}

/// What of `parent_row`'s window, from now on, `agent`'s un-detached
/// attachments to the same role leave UNCOVERED (`{}` when none), and how many
/// of those attachments name `parent_row` in `inherited_from`.
async fn uncovered_by(pool: &PgPool, parent_row: Uuid, agent: Uuid) -> (String, i64) {
    sqlx::query_as(
        "SELECT (tstzmultirange(tstzrange(GREATEST(now(), p.valid_from), p.valid_to)) \
                 - COALESCE((SELECT range_agg(tstzrange(c.valid_from, c.valid_to)) \
                               FROM role_agents c \
                              WHERE c.agent_id = $2 AND c.role = p.role \
                                AND c.detached_at IS NULL), \
                            '{}'::tstzmultirange))::text, \
                (SELECT count(*) FROM role_agents c \
                  WHERE c.agent_id = $2 AND c.inherited_from = p.id) \
           FROM role_agents p WHERE p.id = $1",
    )
    .bind(parent_row)
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("coverage")
}

/// The succession copy covers the parent's WHOLE window: a child that already
/// holds its own attachment to the role for a short stretch INSIDE the
/// parent's window inherits every part of the parent's window that stretch
/// leaves uncovered (one row per gap: here before and after it), so its own
/// short row never ends its coverage early. CONTROL: a repeat registration
/// copies nothing more.
///
/// Verified to fail: the copy skipping a parent row whenever the child has
/// ANY overlapping row (the child keeps only its own hour, and is
/// unattached, so unconstrained, for the rest of the parent's window).
#[sqlx::test(migrations = "../../migrations")]
async fn a_succession_copy_fills_every_gap_in_the_childs_own_window(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let parent = register(&pool, &random32(), None, "g-166-gaps").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    let child_key = random32();
    let child = register(&pool, &child_key, None, "g-166-gaps").await;
    let parent_row = attach(&pool, ROLE, parent).await;
    attach_window(
        &pool,
        ROLE,
        child,
        "now() + interval '1 hour'",
        "now() + interval '2 hours'",
    )
    .await;

    assert_eq!(register(&pool, &child_key, Some(parent), "g-166-gaps").await, child);
    assert_eq!(
        uncovered_by(&pool, parent_row, child).await,
        ("{}".to_string(), 2),
        "the child's own hour leaves two gaps in the parent's window; both are copied"
    );
    register(&pool, &child_key, Some(parent), "g-166-gaps").await;
    assert_eq!(
        uncovered_by(&pool, parent_row, child).await.1,
        2,
        "CONTROL: a repeat registration copies nothing more"
    );
}

/// Attaching an identity attaches its registered successors over the WHOLE
/// attached window, under the same rule as the succession copy: a successor
/// that already holds its own short attachment to the role inside that window
/// is attached for every part of the window its row leaves uncovered.
///
/// Verified to fail: the lineage copy skipping a successor whenever it has
/// ANY overlapping row.
#[sqlx::test(migrations = "../../migrations")]
async fn attaching_an_identity_fills_every_gap_in_a_successors_own_window(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let parent = register(&pool, &random32(), None, "g-166-lineage-gaps").await;
    {
        let mut conn = pool.acquire().await.expect("acquire");
        AgentRepository::link_operator(&mut conn, parent, h)
            .await
            .expect("link the parent");
    }
    let child = register(&pool, &random32(), Some(parent), "g-166-lineage-gaps").await;
    attach_window(
        &pool,
        ROLE,
        child,
        "now() + interval '1 hour'",
        "now() + interval '2 hours'",
    )
    .await;

    let parent_row = attach(&pool, ROLE, parent).await;
    assert_eq!(
        uncovered_by(&pool, parent_row, child).await,
        ("{}".to_string(), 2),
        "the successor's own hour leaves two gaps in the attached window; both are attached"
    );
}

/// The identity attestor runs the registration (whose succession copy writes
/// `role_agents` in a maintenance-owned definer frame) but cannot write the
/// table itself, nor call the attach / detach verbs.
#[sqlx::test(migrations = "../../migrations")]
async fn the_attestor_cannot_write_role_agents_directly(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, _) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let other = agent_of(&pool, h, "other").await;
    let row = attach(&pool, ROLE, attached).await;

    let (insert, update, delete, attach_fn, detach_fn) =
        fixture::as_role(&pool, ATTESTOR, |mut conn| async move {
            let insert = sqlx::query(
                "INSERT INTO role_agents (role, agent_id, reason) VALUES ($1, $2, 'forged')",
            )
            .bind(ROLE)
            .bind(other)
            .execute(&mut *conn)
            .await;
            let update = sqlx::query(
                "UPDATE role_agents SET detached_at = now(), detached_by = session_user, \
                        detach_reason = 'forged' WHERE id = $1",
            )
            .bind(row)
            .execute(&mut *conn)
            .await;
            let delete = sqlx::query("DELETE FROM role_agents WHERE id = $1")
                .bind(row)
                .execute(&mut *conn)
                .await;
            let attach_fn = sqlx::query(
                "SELECT public.epigraph_attach_agent_to_role($1, $2, NULL, NULL, 'forged')",
            )
            .bind(ROLE)
            .bind(other)
            .execute(&mut *conn)
            .await;
            let detach_fn =
                sqlx::query("SELECT public.epigraph_detach_agent_from_role($1, $2, 'forged')")
                    .bind(ROLE)
                    .bind(attached)
                    .execute(&mut *conn)
                    .await;
            (conn, (insert, update, delete, attach_fn, detach_fn))
        })
        .await;
    for (what, code) in [
        ("INSERT", code_of(&insert)),
        ("UPDATE", code_of(&update)),
        ("DELETE", code_of(&delete)),
        ("attach definer", code_of(&attach_fn)),
        ("detach definer", code_of(&detach_fn)),
    ] {
        assert_eq!(
            code.as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "the attestor's {what} on role_agents must be a permission denial"
        );
    }
    assert_eq!(
        live_attachments(&pool, attached).await,
        vec![(ROLE.to_string(), None)],
        "the refused writes changed nothing"
    );
    assert!(live_attachments(&pool, other).await.is_empty());
}

/// With NO principal stamped and the valve off (OPL01 relieved), the claims
/// trigger checks the author alone, and ROL01 still applies to it. CONTROL:
/// an unattached author on the same session writes.
#[sqlx::test(migrations = "../../migrations")]
async fn with_no_principal_and_the_valve_off_the_author_is_still_checked(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    let plain = agent_of(&pool, h, "plain").await;
    attach(&pool, ROLE, attached).await;
    arm(&pool).await;

    let write = |author: Uuid| {
        let pool = pool.clone();
        async move {
            fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
                sqlx::query(
                    "SELECT set_config('epigraph.principal_id', '', false), \
                            set_config('epigraph.group_ids', $1, false), \
                            set_config('epigraph.writable_group_ids', $1, false), \
                            set_config('epigraph.operator_link_enforcement', 'off', false)",
                )
                .bind(h_group.to_string())
                .execute(&mut *conn)
                .await
                .expect("no principal, valve off");
                let r = insert_claim(&mut *conn, author, h_group).await;
                sqlx::query("SELECT set_config('epigraph.operator_link_enforcement', '', false)")
                    .execute(&mut *conn)
                    .await
                    .expect("valve reset");
                unstamp(&mut conn).await;
                (conn, r)
            })
            .await
        }
    };
    assert_rol01(
        &write(attached).await,
        "an attached author with no principal and the valve off",
    );
    write(plain)
        .await
        .expect("CONTROL: an unattached author on the same session writes");
}

/// THE CURRENT LIMIT, PINNED, NOT ENDORSED. The ruling refuses every write a
/// run makes after its holder's assignment ends. ROL01 sits in the claims
/// operator-binding path, so it refuses a claim INSERT, a re-open and a
/// re-attribution; it does NOT (yet) refuse an attached agent's same-author
/// retire of its own claim or an UPDATE of a claim's truth value or labels
/// (the claims trigger never runs the binding checks for those), nor its
/// evidence, edge, belief or membership writes. Extending the refusal is
/// open follow-up work; that change is expected to turn the "still admitted"
/// assertions below into refusals, and this test with them.
#[sqlx::test(migrations = "../../migrations")]
async fn after_the_end_claim_inserts_are_refused_and_claim_updates_are_not_yet(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (h, h_group) = human(&pool, "holder").await;
    let attached = agent_of(&pool, h, "curator").await;
    attach(&pool, ROLE, attached).await;
    let assignment = grant(&pool, ROLE, h, None).await;
    arm(&pool).await;
    let to_retire = write_as(&pool, attached, attached, h_group)
        .await
        .expect("written while held");
    let to_patch = write_as(&pool, attached, attached, h_group)
        .await
        .expect("written while held");
    end_assignment(&pool, assignment).await;

    assert_rol01(
        &write_as(&pool, attached, attached, h_group).await,
        "a new claim after the end",
    );
    let (retire, patch, reopen) = fixture::as_role(&pool, "epigraph_app", |mut conn| async move {
        stamp(&mut conn, attached, &[h_group]).await;
        let retire = sqlx::query(
            "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL \
              WHERE id = $1",
        )
        .bind(to_retire)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        let patch = sqlx::query(
            "UPDATE claims SET truth_value = 0.9, \
                    labels = array_append(COALESCE(labels, '{}'), 'after-the-end') \
              WHERE id = $1",
        )
        .bind(to_patch)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected());
        let reopen = sqlx::query("UPDATE claims SET is_current = true WHERE id = $1")
            .bind(to_retire)
            .execute(&mut *conn)
            .await
            .map(|r| r.rows_affected());
        unstamp(&mut conn).await;
        (conn, (retire, patch, reopen))
    })
    .await;
    assert_eq!(
        retire.as_ref().ok(),
        Some(&1),
        "LIMIT: a same-author retire after the end is still admitted: {retire:?}"
    );
    assert_eq!(
        patch.as_ref().ok(),
        Some(&1),
        "LIMIT: a truth/labels update after the end is still admitted: {patch:?}"
    );
    assert_rol01(&reopen, "a re-open after the end (checked as an insert)");
}

/// 161's registration adopts a never-registered identity only while it is
/// FRESH, and an attachment is a reference into `agents`, so attaching an
/// identity BEFORE the host first registers it makes that registration abort
/// `AID09`, naming `role_agents` (fail closed: the identity stays refused).
/// The handover order is register first, then attach. CONTROL: the same
/// shape without the attachment is adopted.
#[sqlx::test(migrations = "../../migrations")]
async fn an_attachment_before_the_first_registration_aborts_it(pool: PgPool) {
    seed_role(&pool, ROLE).await;
    let (early, _) = fixture::seed_agent_with_group(&pool, "attached-early").await;
    let (fresh, _) = fixture::seed_agent_with_group(&pool, "fresh").await;
    attach(&pool, ROLE, early).await;

    let try_register = |agent: Uuid| {
        let pool = pool.clone();
        async move {
            let key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM agents WHERE id = $1")
                .bind(agent)
                .fetch_one(&pool)
                .await
                .expect("key");
            let hash = blake3::hash(&key).to_hex().to_string();
            fixture::as_role(&pool, ATTESTOR, |mut conn| async move {
                let r: Result<Uuid, _> = sqlx::query_scalar(
                    "SELECT agent_id FROM public.epigraph_register_agent_identity( \
                         $1, NULL, 'test-model-166', $2, 'g-166-early', NULL, $3)",
                )
                .bind(&key)
                .bind(&hash)
                .bind(json!({"in_prompt": {}}))
                .fetch_one(&mut *conn)
                .await;
                (conn, r)
            })
            .await
        }
    };
    let refused = try_register(early).await;
    assert_eq!(code_of(&refused).as_deref(), Some("AID09"), "{refused:?}");
    let text = refused.expect_err("refused").to_string();
    assert!(text.contains("role_agents"), "names the binding: {text}");
    assert_eq!(
        try_register(fresh)
            .await
            .expect("CONTROL: a fresh identity is adopted"),
        fresh
    );
}
