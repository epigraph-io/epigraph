//! Migration 310: the DIRECT-membership arm of the claims-path writer scope
//! (122's arm of `epigraph_require_writer_scope`, OPL02, armed only) admits a
//! write only under READ COMMITTED (backlog e39af056).
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
//!   body, which `the_310_undo_restores_256s_writer_scope` re-measures);
//! * under those levels the direct arm admits nothing, revoked or not, the
//!   personal group included (the level decides, as 256 decides the derived
//!   arm);
//! * CONTROLS: the same human under READ COMMITTED writes through the arm,
//!   and is refused at the first statement after the revoke or the demotion;
//!   a privileged session is exempt at every level; unarmed, nothing changes;
//! * the undo runbook restores 256's body byte for byte, twice.
//!
//! Every write that matters runs on a session whose `session_user` is the
//! deployed application role (`SET SESSION AUTHORIZATION`), never the harness
//! superuser, so grants and row security are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::Viewer;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

const OPL02: &str = "OPL02";

/// The words of 310's refusal, which no other OPL02 carries.
const DIRECT_ONLY_UNDER_RC: &str = "a write through a direct membership is admitted only under \
                                    READ COMMITTED";
/// The words of 122/123's human OPL02 refusal.
const HUMAN_SCOPE: &str = "a human writes only where it writes";

/// md5 of `prosrc` of 256's body of `epigraph_require_writer_scope`, the
/// body 310 re-states and its undo restores.
const BODY_256: &str = "9693498b3365ddfa8f97d4ead83b2ee6";

const RR: &str = "REPEATABLE READ";
const SER: &str = "SERIALIZABLE";
const RC: &str = "READ COMMITTED";

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
/// transaction is open.
#[derive(Clone, Copy, Debug)]
enum Change {
    Nothing,
    /// `group-member remove` of `(group, agent)` (164's verb).
    Revoke(Uuid, Uuid),
    /// `group-member set-role` of `(group, agent)` to `reader`.
    Demote(Uuid, Uuid),
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
/// is refused OPL02 (310). On 256's body it LANDS, because the direct arm
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

/// `docs/runbooks/310-undo.sql` restores 256's body byte for byte (owner,
/// volatility, grants and search path kept), and a second run changes
/// nothing. On the restored body the defect is back: a REPEATABLE READ or
/// SERIALIZABLE member whose membership is revoked, or demoted, mid-
/// transaction WRITES (the measurement that 310 is what refuses it). Over a
/// foreign body both 310 and its undo refuse 55000 and leave it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_310_undo_restores_256s_writer_scope(pool: PgPool) {
    let undo = repo_text("docs/runbooks/310-undo.sql");
    let migration = repo_text("migrations/310_direct_writer_scope_read_committed.sql");
    let at_310 = writer_scope_md5(&pool).await;
    assert_ne!(
        at_310, BODY_256,
        "CALIBRATION: 310 re-bodied the writer scope"
    );
    let catalog = writer_scope_catalog(&pool).await;

    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_256, "256's body");
    assert_eq!(writer_scope_catalog(&pool).await, catalog, "catalog kept");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_256, "idempotent");

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

    // 310 re-applies over 256's body and refuses a foreign one, as does the
    // undo (which opens its own transaction: end it on the same connection).
    sqlx::raw_sql(&migration)
        .execute(&pool)
        .await
        .expect("310 re-applies over 256's body");
    assert_eq!(writer_scope_md5(&pool).await, at_310, "310's body again");
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
        "310 over a foreign body: {r:?}"
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
