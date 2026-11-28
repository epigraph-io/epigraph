//! Migration 361: the DIRECT-membership arm of the claims-path writer scope
//! (122's arm of `epigraph_require_writer_scope`, OPL02, armed only) admits a
//! write only under READ COMMITTED, and the custodian answer
//! (`epigraph_is_instance_admin`) is decided at the statement's clock and, on
//! a read-write transaction, only under READ COMMITTED (backlog e39af056).
//!
//! The arm reads `group_memberships` (and the human registration and operator
//! link behind `epigraph_human_of`) through the transaction's snapshot. Under
//! REPEATABLE READ or SERIALIZABLE that snapshot is the transaction's first,
//! so a membership REVOKED, or DEMOTED to reader, by another session after it
//! (committed) is still read as a live writer row, and the writer keeps
//! writing into the group until its transaction ends. SERIALIZABLE does not
//! save it: the revoke touches no row the write reads for update.
//!
//! An AGENT under either level is already refused ROL01 (166), so the hole is
//! a HUMAN writing through its own membership. What is pinned, each refusal
//! next to a control that shows the same shape lands when the refused
//! condition is absent:
//!
//! * a human whose direct writer membership is revoked, or demoted to reader,
//!   by another session after its REPEATABLE READ / SERIALIZABLE transaction
//!   took its snapshot is refused OPL02 at its next write (it lands on 256's
//!   body, which `the_361_undo_restores_256s_writer_scope` re-measures);
//! * under those levels the direct arm admits nothing, revoked or not, the
//!   personal group included (the level decides, as 256 decides the derived
//!   arm);
//! * CONTROLS: the same human under READ COMMITTED writes through the arm,
//!   and is refused at the first statement after the revoke or the demotion;
//!   a privileged session is exempt at every level; unarmed, nothing changes;
//! * the CUSTODIAN half of e39af056: a principal holding
//!   role:platform-custodian whose assignment is ENDED, or whose `valid_to`
//!   ELAPSES, mid-transaction is refused its next cross-group write under
//!   each of the three levels, because 123's exemption is the privileged
//!   session alone. The same test re-bodies the exemption to 122's form (the
//!   custodian principal arm): over 361's `epigraph_is_instance_admin` the
//!   ended / elapsed custodian is still refused, and over 123's (at `now()`,
//!   any level) it WRITES, so the pin discriminates;
//! * where the custodian answer IS a write admission (239's AK03 admin arm,
//!   admin-scope switch unarmed): a custodian ended or elapsed mid-
//!   transaction changes no other agent's key at any level; a live one does
//!   under READ COMMITTED, does not on a read-write REPEATABLE READ /
//!   SERIALIZABLE transaction, and is still answered true on a read-only
//!   one; on 123's body each refused case is admitted;
//! * the undo runbook restores 256's writer scope and 123's custodian answer
//!   byte for byte, twice.
//!
//! Every write that matters runs on a session whose `session_user` is the
//! deployed application role (`SET SESSION AUTHORIZATION`), never the harness
//! superuser, so grants and row security are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::Viewer;
use sqlx::{Executor, PgPool};
use std::time::Duration;
use uuid::Uuid;

const OPL02: &str = "OPL02";
const CUSTODIAN: &str = "role:platform-custodian";

/// The words of 361's refusal, which no other OPL02 carries.
const DIRECT_ONLY_UNDER_RC: &str = "a write through a direct membership is admitted only under \
                                    READ COMMITTED";
/// The words of 122/123's human OPL02 refusal.
const HUMAN_SCOPE: &str = "a human writes only where it writes";

/// md5 of `prosrc` of 256's body of `epigraph_require_writer_scope`, the
/// body 361 re-states and its undo restores.
const BODY_256: &str = "9693498b3365ddfa8f97d4ead83b2ee6";

const RR: &str = "REPEATABLE READ";
const SER: &str = "SERIALIZABLE";
const RC: &str = "READ COMMITTED";

/// How long a bounded custodian assignment lives after its grant: wide
/// enough that the writer's snapshot is always taken inside the window on a
/// loaded test host (the mutation case needs the assignment live at the
/// transaction's `now()`), short enough to keep the test quick.
const ELAPSE_MS: u64 = 4000;

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(|c| c.to_string())
}

fn code_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> Option<String> {
    r.as_ref().err().and_then(sqlstate)
}

fn message_of<T: std::fmt::Debug>(r: &Result<T, sqlx::Error>) -> String {
    r.as_ref()
        .err()
        .and_then(|e| e.as_database_error().map(|d| d.message().to_string()))
        .unwrap_or_default()
}

/// `Err` with SQLSTATE `code` whose message carries `fragment`.
fn assert_refused<T: std::fmt::Debug>(
    r: &Result<T, sqlx::Error>,
    code: &str,
    fragment: &str,
    what: &str,
) {
    assert_eq!(code_of(r).as_deref(), Some(code), "{what}: {r:?}");
    let msg = message_of(r);
    assert!(
        msg.contains(fragment),
        "{what}: expected the refusal to say {fragment:?}, got {msg:?}"
    );
}

/// A connection whose `session_user` is `epigraph_maintenance`.
async fn maint(pool: &PgPool) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
    let mut conn = pool.acquire().await.expect("acquire");
    conn.execute("SET SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .expect("downgrade to the maintenance role");
    conn
}

async fn reset(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    conn.execute("RESET SESSION AUTHORIZATION")
        .await
        .expect("reset session authorization");
}

/// A keyless team group made by migration 164's verb, administered by a
/// human of its own.
async fn team_group(pool: &PgPool, name: &str) -> Uuid {
    let (admin, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let mut c = maint(pool).await;
    let g: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind("direct writer scope test")
        .fetch_one(&mut *c)
        .await
        .expect("create the team group");
    reset(c).await;
    g
}

/// `group-member add` as the operator CLI calls it (164's verb).
async fn add_member(pool: &PgPool, group: Uuid, agent: Uuid, role: &str) {
    let mut c = maint(pool).await;
    let (_, applied): (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT out_membership_id, out_applied \
           FROM public.epigraph_team_group_add_member($1, $2, $3, $4)",
    )
    .bind(group)
    .bind(agent)
    .bind(role)
    .bind("direct writer scope test")
    .fetch_one(&mut *c)
    .await
    .expect("add the member");
    reset(c).await;
    assert!(applied, "PREMISE: the membership was added");
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// What another session changes, and commits, while the writer's
/// transaction is open (or, for `Elapse`, what the clock does).
#[derive(Clone, Copy, Debug)]
enum Change {
    Nothing,
    /// `group-member remove` of `(group, agent)` (164's verb).
    Revoke(Uuid, Uuid),
    /// `group-member set-role` of `(group, agent)` to `reader`.
    Demote(Uuid, Uuid),
    /// `epigraph_end_role_assignment` of the assignment.
    EndAssignment(Uuid),
    /// Wait until the statement clock is past this many milliseconds from
    /// the change point (a bounded assignment's `valid_to` elapses).
    Elapse(u64),
}

/// Apply it on a maintenance session (its own transaction, committed).
async fn apply(pool: &PgPool, change: Change) {
    match change {
        Change::Nothing => {}
        Change::Revoke(group, agent) => {
            let mut c = maint(pool).await;
            let (_, applied, prior): (Option<Uuid>, bool, Option<String>) = sqlx::query_as(
                "SELECT out_membership_id, out_applied, out_prior_role \
                   FROM public.epigraph_team_group_remove_member($1, $2, $3)",
            )
            .bind(group)
            .bind(agent)
            .bind("direct writer scope test revoke")
            .fetch_one(&mut *c)
            .await
            .expect("revoke the membership");
            reset(c).await;
            assert!(applied, "PREMISE: a live membership was revoked");
            assert_eq!(prior.as_deref(), Some("writer"), "PREMISE: it was a writer");
        }
        Change::Demote(group, agent) => {
            let mut c = maint(pool).await;
            let (_, applied, prior): (Option<Uuid>, bool, Option<String>) = sqlx::query_as(
                "SELECT out_membership_id, out_applied, out_prior_role \
                   FROM public.epigraph_team_group_set_member_role($1, $2, 'reader', $3)",
            )
            .bind(group)
            .bind(agent)
            .bind("direct writer scope test demote")
            .fetch_one(&mut *c)
            .await
            .expect("demote the membership");
            reset(c).await;
            assert!(applied, "PREMISE: the membership was demoted");
            assert_eq!(prior.as_deref(), Some("writer"), "PREMISE: it was a writer");
        }
        Change::EndAssignment(id) => {
            let mut c = maint(pool).await;
            let ended: bool =
                sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, $2)")
                    .bind(id)
                    .bind("direct writer scope test end")
                    .fetch_one(&mut *c)
                    .await
                    .expect("end the assignment");
            reset(c).await;
            assert!(ended, "PREMISE: the assignment was live and is ended now");
        }
        Change::Elapse(ms) => tokio::time::sleep(Duration::from_millis(ms)).await,
    }
}

/// One `('group', group)` claim authored by `author` on `conn` as it stands.
async fn insert_group_claim(
    conn: &mut sqlx::PgConnection,
    author: Uuid,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, 0.5, $4, true, 'group', $5)",
    )
    .bind(id)
    .bind(format!("direct writer scope probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(group)
    .execute(conn)
    .await
    .map(|_| id)
}

/// The writer's run. On one `epigraph_app` session stamped as `principal`'s
/// resolved viewer (resolved BEFORE anything changes, as the request path
/// stamps it once), with `group` added to the stamped read and write sets
/// (the GUCs are application-settable, so row security does not decide and
/// the writer scope is what is measured), one transaction at `isolation`:
///
/// 1. `first`, if given: an INSERT into it, which must land (a positive
///    control that the transaction could write at all);
/// 2. a plain read, which takes the transaction's snapshot when (1) did not;
/// 3. `change` is applied and committed on ANOTHER session;
/// 4. the probe: an INSERT authored by `principal` into `group`.
///
/// Rolled back. Returns the probe's result.
async fn write_across(
    pool: &PgPool,
    principal: Uuid,
    isolation: &str,
    first: Option<Uuid>,
    change: Change,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let viewer = Viewer::resolve(pool, principal).await.expect("resolve");
    let join = |s: &[Uuid]| {
        s.iter()
            .chain(std::iter::once(&group))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let read = join(viewer.group_bind().unwrap_or_default());
    let write = join(viewer.writable_groups());
    let isolation = isolation.to_string();
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $3, false)",
        )
        .bind(principal.to_string())
        .bind(&read)
        .bind(&write)
        .execute(&mut *conn)
        .await
        .expect("stamp");
        // The level is one of three test-local literals, never caller data.
        conn.execute(format!("BEGIN ISOLATION LEVEL {isolation}").as_str())
            .await
            .expect("begin");
        if let Some(first) = first {
            insert_group_claim(&mut conn, principal, first)
                .await
                .unwrap_or_else(|e| {
                    panic!("POSITIVE CONTROL: the first write ({isolation}) lands: {e}")
                });
        }
        let level: String = sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
            .fetch_one(&mut *conn)
            .await
            .expect("read the level (takes the snapshot)");
        assert_eq!(
            level.to_uppercase(),
            isolation,
            "PREMISE: the transaction runs at the level under test"
        );
        apply(pool, change).await;
        let probe = insert_group_claim(&mut conn, principal, group).await;
        conn.execute("ROLLBACK").await.expect("rollback");
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *conn)
        .await
        .expect("unstamp");
        (conn, probe)
    })
    .await
}

/// A registered human with a direct WRITER row in a fresh team group, and
/// its personal group.
struct Member {
    human: Uuid,
    personal: Uuid,
    group: Uuid,
}

async fn member(pool: &PgPool, label: &str) -> Member {
    let (human, personal) = fixture::seed_human_operator(pool, &format!("{label}-h")).await;
    let group = team_group(pool, &format!("Synthetic {label} Team")).await;
    add_member(pool, group, human, "writer").await;
    Member {
        human,
        personal,
        group,
    }
}

/// THE DEFECT. Armed, a human with a direct writer row opens a REPEATABLE
/// READ or SERIALIZABLE transaction; another session revokes the row, or
/// demotes it to reader, and commits; the human's next write into the group
/// is refused OPL02 (361). On 256's body it LANDS, because the direct arm
/// reads the revoked row through the transaction's older snapshot (the undo
/// test below re-measures that). CONTROL: under READ COMMITTED the same
/// sequence, with a write through the arm before the change that lands, is
/// refused at the write after it by the existing human refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_a_membership_revoked_mid_transaction_refuses_the_rr_and_serializable_writer(
    pool: PgPool,
) {
    arm(&pool).await;
    for (n, isolation) in [RR, SER].into_iter().enumerate() {
        for demote in [false, true] {
            let m = member(&pool, &format!("Revoke {n} {demote}")).await;
            let change = if demote {
                Change::Demote(m.group, m.human)
            } else {
                Change::Revoke(m.group, m.human)
            };
            let r = write_across(&pool, m.human, isolation, None, change, m.group).await;
            assert_refused(
                &r,
                OPL02,
                DIRECT_ONLY_UNDER_RC,
                &format!("{isolation}, {change:?} mid-transaction"),
            );
        }
    }

    for demote in [false, true] {
        let m = member(&pool, &format!("Revoke RC {demote}")).await;
        let change = if demote {
            Change::Demote(m.group, m.human)
        } else {
            Change::Revoke(m.group, m.human)
        };
        let r = write_across(&pool, m.human, RC, Some(m.group), change, m.group).await;
        assert_refused(
            &r,
            OPL02,
            HUMAN_SCOPE,
            &format!("CONTROL: READ COMMITTED, the write after {change:?} (the first landed)"),
        );
    }
}

/// Under REPEATABLE READ or SERIALIZABLE the direct arm admits NOTHING, even
/// while the membership is live, the human's own personal group included:
/// the test is decided on the level, because an older snapshot cannot tell a
/// live row from one revoked since. CONTROLS, each the same shape with the
/// refused condition absent: under READ COMMITTED both writes land; a
/// privileged session stamped as the human is exempt at every level; and
/// before the binding is armed the same REPEATABLE READ writes land.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_direct_arm_admits_only_under_read_committed(pool: PgPool) {
    let m = member(&pool, "Level").await;

    // Unarmed: the writer scope returns at its first line, at any level.
    for isolation in [RR, SER] {
        for g in [m.group, m.personal] {
            write_across(&pool, m.human, isolation, None, Change::Nothing, g)
                .await
                .unwrap_or_else(|e| panic!("CONTROL: unarmed, {isolation} lands: {e}"));
        }
    }

    arm(&pool).await;
    for g in [m.group, m.personal] {
        write_across(&pool, m.human, RC, None, Change::Nothing, g)
            .await
            .unwrap_or_else(|e| {
                panic!("CONTROL: READ COMMITTED, the member writes its group {g}: {e}")
            });
    }
    for isolation in [RR, SER] {
        for g in [m.group, m.personal] {
            let r = write_across(&pool, m.human, isolation, None, Change::Nothing, g).await;
            assert_refused(
                &r,
                OPL02,
                DIRECT_ONLY_UNDER_RC,
                &format!("{isolation}, nothing revoked, group {g}"),
            );
        }
    }

    // A privileged session (the maintenance role) stamped as the human is
    // exempt (`epigraph_operator_scope_exempt`), at any level.
    for isolation in [RC, RR, SER] {
        let mut c = maint(&pool).await;
        c.execute(format!("BEGIN ISOLATION LEVEL {isolation}").as_str())
            .await
            .expect("begin");
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
            .bind(m.human.to_string())
            .execute(&mut *c)
            .await
            .expect("stamp");
        insert_group_claim(&mut c, m.human, m.group)
            .await
            .unwrap_or_else(|e| {
                panic!("CONTROL: {isolation}, a privileged session is exempt: {e}")
            });
        c.execute("ROLLBACK").await.expect("rollback");
        reset(c).await;
    }
}

/// Grant `role:platform-custodian` to `holder` with no grantor (the fixture
/// keeps at most one live custodian at a time, so the 123 grantor rule
/// admits it), from 30 s ago until `valid_to_ms` milliseconds from now on
/// the statement clock, or open-ended.
async fn grant_custodian(pool: &PgPool, holder: Uuid, valid_to_ms: Option<i64>) -> Uuid {
    let mut c = maint(pool).await;
    let id: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now() - interval '30 seconds', \
                CASE WHEN $3::bigint IS NULL THEN NULL \
                     ELSE clock_timestamp() + $3::bigint * interval '1 millisecond' END, \
                NULL, 'direct writer scope custodian test')",
    )
    .bind(CUSTODIAN)
    .bind(holder)
    .bind(valid_to_ms)
    .fetch_one(&mut *c)
    .await
    .expect("grant role:platform-custodian");
    reset(c).await;
    id
}

/// The custodian half of e39af056. Each case: a fresh human K granted
/// role:platform-custodian, and another human's personal group G that K
/// holds no membership in. On an `epigraph_app` session stamped as K (G in
/// its stamped sets), one transaction at the level takes its snapshot while
/// K's assignment is live; then the assignment is ENDED on another session
/// (committed), or its `valid_to` ELAPSES; K's next write into G is refused
/// OPL02 by the human refusal, under READ COMMITTED, REPEATABLE READ and
/// SERIALIZABLE alike. 123's exemption is `epigraph_bypass()` alone, so
/// holding the role relieves nothing, ended or not.
///
/// THE PIN DISCRIMINATES: the exemption re-bodied to 122's form (a
/// privileged session OR `epigraph_is_instance_admin(principal)`, which
/// reads the assignment through the snapshot at `now()`), the ended
/// REPEATABLE READ / SERIALIZABLE custodian and the elapsed READ COMMITTED
/// custodian each WRITE.
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodian_ended_or_elapsed_mid_transaction_is_relieved_of_nothing(pool: PgPool) {
    let (_, foreign) = fixture::seed_human_operator(&pool, "custodian-foreign").await;
    arm(&pool).await;

    // `Some(ms)` = bounded, elapsing `ms` after the grant; `None` = ended.
    let run = |label: String, isolation: &'static str, elapse: Option<u64>| {
        let pool = pool.clone();
        async move {
            let (k, _) = fixture::seed_human_operator(&pool, &label).await;
            let (assignment, change) = match elapse {
                None => {
                    let a = grant_custodian(&pool, k, None).await;
                    (a, Change::EndAssignment(a))
                }
                Some(ms) => {
                    let a = grant_custodian(&pool, k, Some(i64::try_from(ms).unwrap())).await;
                    (a, Change::Elapse(ms + 500))
                }
            };
            let live: bool = sqlx::query_scalar(
                "SELECT public.epigraph_live_role_assignment($1, $2, clock_timestamp()) = $3",
            )
            .bind(k)
            .bind(CUSTODIAN)
            .bind(assignment)
            .fetch_one(&pool)
            .await
            .expect("live");
            assert!(live, "PREMISE: K holds the custodian role when it begins");
            let r = write_across(&pool, k, isolation, None, change, foreign).await;
            if elapse.is_none() {
                return r;
            }
            // Bounded: confirm it did elapse, and end nothing else (the
            // next case grants with no grantor, so no custodian may be live).
            let still: Option<Uuid> = sqlx::query_scalar(
                "SELECT public.epigraph_live_role_assignment($1, $2, clock_timestamp())",
            )
            .bind(k)
            .bind(CUSTODIAN)
            .fetch_one(&pool)
            .await
            .expect("live after");
            assert_eq!(still, None, "PREMISE: the assignment elapsed");
            r
        }
    };

    for isolation in [RC, RR, SER] {
        for elapse in [None, Some(ELAPSE_MS)] {
            let what = format!(
                "{isolation}, custodian {} mid-transaction",
                if elapse.is_some() { "elapsed" } else { "ended" }
            );
            let r = run(format!("k-{isolation}-{elapse:?}"), isolation, elapse).await;
            assert_refused(&r, OPL02, HUMAN_SCOPE, &what);
        }
    }

    // The mutation: 122's exemption (the custodian principal arm). Over
    // 361's `epigraph_is_instance_admin` (the statement's clock, and READ
    // COMMITTED or read-only) even that exemption relieves the ended or
    // elapsed custodian of nothing.
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_operator_scope_exempt() \
         RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER \
         SET search_path = public, pg_temp AS $$ \
             SELECT public.epigraph_bypass() \
                 OR public.epigraph_is_instance_admin(public.epigraph_principal_id()) $$",
    )
    .execute(&pool)
    .await
    .expect("re-body the exemption to 122's form");
    for (isolation, elapse) in [(RR, None), (SER, None), (RC, Some(ELAPSE_MS))] {
        let r = run(format!("e-{isolation}-{elapse:?}"), isolation, elapse).await;
        assert_refused(
            &r,
            OPL02,
            HUMAN_SCOPE,
            &format!(
                "122's exemption over 361's custodian answer, {isolation}, custodian {} \
                 mid-transaction",
                if elapse.is_some() { "elapsed" } else { "ended" }
            ),
        );
    }
    // And with 123's custodian answer (`now()`, any level) under it, the
    // ended / elapsed custodian WRITES: the pin above discriminates.
    sqlx::raw_sql(BODY_123_IS_INSTANCE_ADMIN)
        .execute(&pool)
        .await
        .expect("re-body the custodian answer to 123's form");
    for (isolation, elapse) in [(RR, None), (SER, None), (RC, Some(ELAPSE_MS))] {
        let r = run(format!("m-{isolation}-{elapse:?}"), isolation, elapse).await;
        assert!(
            r.is_ok(),
            "MUTATION: with 122's exemption over 123's custodian answer the {isolation} \
             custodian {} mid-transaction writes (so the pin above discriminates): {r:?}",
            if elapse.is_some() { "elapsed" } else { "ended" }
        );
    }
}

/// 123's `epigraph_is_instance_admin`, byte for byte (the custodian answer at
/// the transaction's `now()`, through its snapshot, at any level): the body
/// 361 re-states, and the one `361-undo.sql` restores.
const BODY_123_IS_INSTANCE_ADMIN: &str = "\
CREATE OR REPLACE FUNCTION public.epigraph_is_instance_admin(p_agent uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp AS $$
    SELECT COALESCE(
        p_agent IS NOT NULL
        AND (p_agent = public.epigraph_principal_id() OR public.epigraph_bypass())
        AND public.epigraph_holds_role(p_agent, 'role:platform-custodian', now()),
        false)
$$";

/// md5 of 123's `prosrc` for `epigraph_is_instance_admin`.
const ADMIN_123: &str = "e72b915989c3a98801e795d4eb53b769";

async fn instance_admin_md5(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT md5(prosrc) FROM pg_proc \
          WHERE oid = 'public.epigraph_is_instance_admin(uuid)'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("the custodian answer")
}

/// `(owner, provolatile, proacl, proconfig)` of `epigraph_is_instance_admin`.
async fn instance_admin_catalog(
    pool: &PgPool,
) -> (String, String, Option<String>, Option<Vec<String>>) {
    sqlx::query_as(
        "SELECT r.rolname::text, p.provolatile::text, p.proacl::text, p.proconfig \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = 'public.epigraph_is_instance_admin(uuid)'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("catalog row")
}

const AK03: &str = "AK03";

/// End `assignment` on a maintenance session if it is still live (the
/// fixture grants with no grantor, which 123 admits only while no other
/// custodian is live).
async fn end_if_live(pool: &PgPool, holder: Uuid, assignment: Uuid) {
    let live: Option<Uuid> = sqlx::query_scalar(
        "SELECT public.epigraph_live_role_assignment($1, $2, clock_timestamp())",
    )
    .bind(holder)
    .bind(CUSTODIAN)
    .fetch_one(pool)
    .await
    .expect("live");
    if live == Some(assignment) {
        apply(pool, Change::EndAssignment(assignment)).await;
    }
}

/// One active `encryption` key of a fresh software agent (not an attested
/// key type, so 161's AK02 does not decide first), seeded on the harness.
async fn foreign_key(pool: &PgPool) -> Uuid {
    let owner = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'software_agent')",
    )
    .bind(owner)
    .bind(Uuid::new_v4().as_bytes().repeat(2))
    .execute(pool)
    .await
    .expect("seed the key's agent");
    sqlx::query_scalar(
        "INSERT INTO agent_keys (agent_id, public_key, key_type, status, valid_from) \
         VALUES ($1, $2, 'encryption', 'active', now() - interval '1 day') RETURNING id",
    )
    .bind(owner)
    .bind(Uuid::new_v4().as_bytes().repeat(2))
    .fetch_one(pool)
    .await
    .expect("seed the key")
}

/// The custodian's run against 239's admin arm (AK03, admin-scope switch
/// unarmed: `epigraph_is_instance_admin(principal)` decides). On one
/// `epigraph_app` session stamped as `principal`, one transaction at
/// `isolation` (`READ ONLY` appended when `read_only`):
///
/// 1. a plain read takes the transaction's snapshot;
/// 2. `change` is applied and committed on ANOTHER session;
/// 3. the probe: read-write, `epigraph_agent_key_set_status(key, 'revoked')`
///    (another agent's key); read-only, `epigraph_is_instance_admin(principal)`,
///    returned as `Ok(answer)`.
///
/// Rolled back. Read-write returns `Ok(true)` when the change was admitted.
async fn key_change_across(
    pool: &PgPool,
    principal: Uuid,
    isolation: &'static str,
    read_only: bool,
    change: Change,
    key: Uuid,
) -> Result<bool, sqlx::Error> {
    fixture::as_role(pool, "epigraph_app", |mut conn| async move {
        sqlx::query("SELECT set_config('epigraph.principal_id', $1, false)")
            .bind(principal.to_string())
            .execute(&mut *conn)
            .await
            .expect("stamp");
        let mode = if read_only { " READ ONLY" } else { "" };
        // Test-local literals, never caller data.
        conn.execute(format!("BEGIN ISOLATION LEVEL {isolation}{mode}").as_str())
            .await
            .expect("begin");
        let level: String = sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
            .fetch_one(&mut *conn)
            .await
            .expect("read the level (takes the snapshot)");
        assert_eq!(
            level.to_uppercase(),
            isolation,
            "PREMISE: the transaction runs at the level under test"
        );
        apply(pool, change).await;
        let probe = if read_only {
            sqlx::query_scalar::<_, bool>("SELECT public.epigraph_is_instance_admin($1)")
                .bind(principal)
                .fetch_one(&mut *conn)
                .await
        } else {
            sqlx::query(
                "SELECT * FROM public.epigraph_agent_key_set_status($1, 'revoked', 'test', NULL)",
            )
            .bind(key)
            .fetch_all(&mut *conn)
            .await
            .map(|rows| !rows.is_empty())
        };
        conn.execute("ROLLBACK").await.expect("rollback");
        sqlx::query("SELECT set_config('epigraph.principal_id', '', false)")
            .execute(&mut *conn)
            .await
            .expect("unstamp");
        (conn, probe)
    })
    .await
}

/// THE CUSTODIAN HALF, where it is a write admission (361 section 1b).
/// While the admin-scope switch is unarmed, 239's key definer admits a
/// change to ANOTHER agent's key for `epigraph_is_instance_admin(principal)`.
/// Each case: a fresh human K granted role:platform-custodian, stamped on an
/// `epigraph_app` session; one transaction takes its snapshot while K's
/// assignment is live; the assignment is then ENDED on another session
/// (committed), or its `valid_to` ELAPSES; K's key change is refused AK03
/// under READ COMMITTED, REPEATABLE READ and SERIALIZABLE.
///
/// PINNED WITH IT: a LIVE custodian is admitted under READ COMMITTED (the
/// control), refused on a read-write REPEATABLE READ / SERIALIZABLE
/// transaction (the level decides, not the old snapshot), and still answered
/// true on a REPEATABLE READ READ ONLY one (which can write nothing).
///
/// THE PIN DISCRIMINATES: with 123's body restored (`now()`, any level) the
/// ended REPEATABLE READ / SERIALIZABLE custodian, the elapsed READ
/// COMMITTED one and the live REPEATABLE READ one are each ADMITTED.
#[sqlx::test(migrations = "../../migrations")]
async fn a_custodian_ended_or_elapsed_mid_transaction_changes_no_foreign_key(pool: PgPool) {
    let key = foreign_key(&pool).await;
    let armed: bool = sqlx::query_scalar("SELECT public.epigraph_admin_scopes_armed()")
        .fetch_one(&pool)
        .await
        .expect("the admin-scope switch");
    assert!(!armed, "PREMISE: the admin-scope switch is unarmed");

    // `None`: live throughout (no change); `Some(None)`: ended;
    // `Some(Some(ms))`: bounded, elapsing `ms` after the grant.
    let run =
        |label: String, isolation: &'static str, read_only: bool, end: Option<Option<u64>>| {
            let pool = pool.clone();
            async move {
                let (k, _) = fixture::seed_human_operator(&pool, &label).await;
                let (assignment, change) = match end {
                    None => (grant_custodian(&pool, k, None).await, Change::Nothing),
                    Some(None) => {
                        let a = grant_custodian(&pool, k, None).await;
                        (a, Change::EndAssignment(a))
                    }
                    Some(Some(ms)) => {
                        let a = grant_custodian(&pool, k, Some(i64::try_from(ms).unwrap())).await;
                        (a, Change::Elapse(ms + 500))
                    }
                };
                let r = key_change_across(&pool, k, isolation, read_only, change, key).await;
                if let Some(Some(_)) = end {
                    let still: Option<Uuid> = sqlx::query_scalar(
                        "SELECT public.epigraph_live_role_assignment($1, $2, clock_timestamp())",
                    )
                    .bind(k)
                    .bind(CUSTODIAN)
                    .fetch_one(&pool)
                    .await
                    .expect("live after");
                    assert_eq!(still, None, "PREMISE: the assignment elapsed");
                }
                end_if_live(&pool, k, assignment).await;
                r
            }
        };
    let what = |end: Option<Option<u64>>| match end {
        None => "live",
        Some(None) => "ended",
        Some(Some(_)) => "elapsed",
    };

    // The defect's cases, at every level: refused.
    for isolation in [RC, RR, SER] {
        for end in [Some(None), Some(Some(ELAPSE_MS))] {
            let r = run(format!("ak-{isolation}-{end:?}"), isolation, false, end).await;
            assert_refused(
                &r,
                "42501",
                AK03,
                &format!("{isolation}, custodian {} mid-transaction", what(end)),
            );
        }
    }
    // CONTROL: a live custodian under READ COMMITTED changes the key.
    let r = run("ak-live-rc".into(), RC, false, None).await;
    assert!(
        matches!(r, Ok(true)),
        "CONTROL: a live READ COMMITTED custodian changes another agent's key: {r:?}"
    );
    // A live custodian on a read-write REPEATABLE READ / SERIALIZABLE
    // transaction: refused (the level decides).
    for isolation in [RR, SER] {
        let r = run(format!("ak-live-{isolation}"), isolation, false, None).await;
        assert_refused(
            &r,
            "42501",
            AK03,
            &format!("{isolation} read-write, live custodian"),
        );
    }
    // A read-only REPEATABLE READ transaction keeps the answer (it can write
    // nothing; its reads are the snapshot's).
    let r = run("ak-live-rr-ro".into(), RR, true, None).await;
    assert!(
        matches!(r, Ok(true)),
        "a live custodian on a REPEATABLE READ READ ONLY transaction is an instance admin: {r:?}"
    );

    // The mutation: 123's body.
    sqlx::raw_sql(BODY_123_IS_INSTANCE_ADMIN)
        .execute(&pool)
        .await
        .expect("re-body the custodian answer to 123's form");
    for (isolation, end) in [
        (RR, Some(None)),
        (SER, Some(None)),
        (RC, Some(Some(ELAPSE_MS))),
        (RR, None),
    ] {
        let r = run(format!("ak-m-{isolation}-{end:?}"), isolation, false, end).await;
        assert!(
            matches!(r, Ok(true)),
            "MUTATION: on 123's body the {isolation} custodian {} mid-transaction changes \
             another agent's key (so the pins above discriminate): {r:?}",
            what(end)
        );
    }
    let status: String = sqlx::query_scalar("SELECT status::text FROM agent_keys WHERE id = $1")
        .bind(key)
        .fetch_one(&pool)
        .await
        .expect("key status");
    assert_eq!(status, "active", "every probe was rolled back");
}

fn repo_text(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

async fn writer_scope_md5(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT md5(prosrc) FROM pg_proc \
          WHERE oid = 'public.epigraph_require_writer_scope(uuid, uuid)'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("the writer scope")
}

/// `(owner, provolatile, proacl, proconfig)` of the writer scope: what
/// `CREATE OR REPLACE` must keep.
async fn writer_scope_catalog(
    pool: &PgPool,
) -> (String, String, Option<String>, Option<Vec<String>>) {
    sqlx::query_as(
        "SELECT r.rolname::text, p.provolatile::text, p.proacl::text, p.proconfig \
           FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner \
          WHERE p.oid = 'public.epigraph_require_writer_scope(uuid, uuid)'::regprocedure",
    )
    .fetch_one(pool)
    .await
    .expect("catalog row")
}

/// `docs/runbooks/361-undo.sql` restores 256's writer scope and 123's
/// `epigraph_is_instance_admin` byte for byte (owner, volatility, grants and
/// search path kept), and a second run changes nothing. (What 123's custodian
/// answer admits is re-measured by the AK03 test's mutation.) On the restored body the defect is back: a REPEATABLE READ or
/// SERIALIZABLE member whose membership is revoked, or demoted, mid-
/// transaction WRITES (the measurement that 361 is what refuses it). Over a
/// foreign body both 361 and its undo refuse 55000 and leave it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_361_undo_restores_256s_writer_scope(pool: PgPool) {
    let undo = repo_text("docs/runbooks/361-undo.sql");
    let migration = repo_text("migrations/361_direct_writer_scope_read_committed.sql");
    let at_361 = writer_scope_md5(&pool).await;
    assert_ne!(
        at_361, BODY_256,
        "CALIBRATION: 361 re-bodied the writer scope"
    );
    let catalog = writer_scope_catalog(&pool).await;
    let admin_at_361 = instance_admin_md5(&pool).await;
    assert_ne!(
        admin_at_361, ADMIN_123,
        "CALIBRATION: 361 re-bodied the custodian answer"
    );
    let admin_catalog = instance_admin_catalog(&pool).await;

    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_256, "256's body");
    assert_eq!(writer_scope_catalog(&pool).await, catalog, "catalog kept");
    assert_eq!(instance_admin_md5(&pool).await, ADMIN_123, "123's body");
    assert_eq!(
        instance_admin_catalog(&pool).await,
        admin_catalog,
        "custodian answer's catalog kept"
    );
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_256, "idempotent");
    assert_eq!(instance_admin_md5(&pool).await, ADMIN_123, "idempotent");

    arm(&pool).await;
    // Every case the first test refuses, measured on 256's body: each lands.
    for (n, isolation) in [RR, SER].into_iter().enumerate() {
        for demote in [false, true] {
            let m = member(&pool, &format!("Undo {n} {demote}")).await;
            let change = if demote {
                Change::Demote(m.group, m.human)
            } else {
                Change::Revoke(m.group, m.human)
            };
            write_across(&pool, m.human, isolation, None, change, m.group)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "on 256's body the {isolation} member writes after {change:?} \
                         (the defect): {e}"
                    )
                });
        }
    }

    // 361 re-applies over 256's body and refuses a foreign one, as does the
    // undo (which opens its own transaction: end it on the same connection).
    sqlx::raw_sql(&migration)
        .execute(&pool)
        .await
        .expect("361 re-applies over 256's body");
    assert_eq!(writer_scope_md5(&pool).await, at_361, "361's body again");
    assert_eq!(
        instance_admin_md5(&pool).await,
        admin_at_361,
        "361's custodian answer again"
    );
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION public.epigraph_require_writer_scope(p_agent uuid, \
                                                                    p_group uuid) \
         RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER \
         SET search_path = public, pg_temp AS $$ BEGIN RETURN; END $$",
    )
    .execute(&pool)
    .await
    .expect("re-body the function");
    let foreign = writer_scope_md5(&pool).await;
    let r = sqlx::raw_sql(&migration).execute(&pool).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("55000"),
        "361 over a foreign body: {r:?}"
    );
    let mut conn = pool.acquire().await.expect("acquire");
    let r = sqlx::raw_sql(&undo).execute(&mut *conn).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some("55000"),
        "undo over a foreign body: {r:?}"
    );
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut *conn)
        .await
        .expect("end the undo's transaction");
    drop(conn);
    assert_eq!(
        writer_scope_md5(&pool).await,
        foreign,
        "neither replaced it"
    );
}
