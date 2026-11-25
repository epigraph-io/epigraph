//! Migration 256: the role-DERIVED arm of the claims-path writer scope
//! (165's arm of `epigraph_require_writer_scope`, OPL02, armed only) admits a
//! write only under READ COMMITTED.
//!
//! The arm reads `role_assignments` and `group_role_bindings` through the
//! transaction's snapshot. Under REPEATABLE READ or SERIALIZABLE that
//! snapshot is the transaction's first, so an assignment or a binding ENDED
//! by another session after it (an UPDATE that sets the end, committed) is
//! still read as live, and the writer keeps writing into the role's group
//! until its transaction ends. `clock_timestamp()` closes the elapsed
//! `valid_to` case only; an early end is a visibility question.
//! SERIALIZABLE does not save it: the end touches no row the write reads
//! for update, so no serialization failure is raised.
//!
//! An AGENT under either level is already refused ROL01 (166: every agent
//! that could be attached writes only under READ COMMITTED), so the hole is
//! a HUMAN role holder writing through its binding. What is pinned, each
//! refusal next to a control that shows the same shape lands when the
//! refused condition is absent:
//!
//! * a human whose assignment, or whose group's binding, is ended by another
//!   session after its REPEATABLE READ / SERIALIZABLE transaction took its
//!   snapshot is refused OPL02 at its next write (it lands on 166's body,
//!   which `the_256_undo_restores_166s_writer_scope` re-measures);
//! * under those levels the derived arm admits nothing, ended or not (the
//!   test is decided on the isolation level, not on what the old snapshot
//!   says, exactly as 166's ROL01 is);
//! * CONTROLS: the same human under READ COMMITTED writes through the arm,
//!   and is refused at the first statement after the end (the per-statement
//!   snapshot); a privileged session is exempt as before. (Under
//!   REPEATABLE READ the human's own personal group, 122's direct arm, is
//!   refused too since 310: `direct_writer_scope_read_committed.rs`.)
//! * the undo runbook restores 166's body byte for byte, twice (after
//!   310's undo, which restores 256's body first).
//!
//! Every write that matters runs on a session whose `session_user` is the
//! deployed application role (`SET SESSION AUTHORIZATION`), never the harness
//! superuser, so grants and row security are what is measured.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{AgentRepository, Viewer};
use sqlx::{Executor, PgPool};
use uuid::Uuid;

/// A synthetic, non-elevating role key.
const ROLE: &str = "role:rc-team-member";

const OPL02: &str = "OPL02";
const ROL01: &str = "ROL01";

/// The words of 256's refusal, which no other OPL02 carries.
const DERIVED_ONLY_UNDER_RC: &str = "a write through a role binding is admitted only under READ \
                                     COMMITTED";
/// The words of 310's direct-arm refusal.
const DIRECT_ONLY_UNDER_RC: &str = "a write through a direct membership is admitted only under \
                                    READ COMMITTED";
/// The words of 122/123's human OPL02 refusal.
const HUMAN_SCOPE: &str = "a human writes only where it writes";

/// md5 of `prosrc` of 166's body of `epigraph_require_writer_scope`, the
/// body 256 re-states and its undo restores.
const BODY_166: &str = "a7c9d5d196c1d45022df6f91e263bf14";

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
/// human of its own (so the role holders below hold no direct row in it).
async fn team_group(pool: &PgPool, name: &str) -> Uuid {
    let (admin, _) = fixture::seed_human_operator(pool, &format!("{name}-owner")).await;
    let mut c = maint(pool).await;
    let g: Uuid = sqlx::query_scalar("SELECT public.epigraph_create_team_group($1, $2, $3)")
        .bind(name)
        .bind(admin)
        .bind("derived writer scope test")
        .fetch_one(&mut *c)
        .await
        .expect("create the team group");
    reset(c).await;
    g
}

/// Define `ROLE` (non-elevating) on a maintenance session; no binding.
async fn define_role(pool: &PgPool) {
    let anchor = team_group(pool, "Synthetic RC Anchor Team").await;
    let mut c = maint(pool).await;
    sqlx::query_scalar::<_, Uuid>(
        "SELECT public.epigraph_define_group_role($1, $2, $3, 'reader', false, $4)",
    )
    .bind(ROLE)
    .bind("synthetic team role")
    .bind(anchor)
    .bind("derived writer scope test")
    .fetch_one(&mut *c)
    .await
    .expect("define the role");
    reset(c).await;
}

/// A new team group with `ROLE` bound to it at `writer`, agents included.
/// Returns `(group, binding)`.
async fn bound_group(pool: &PgPool, name: &str) -> (Uuid, Uuid) {
    let group = team_group(pool, name).await;
    let mut c = maint(pool).await;
    let binding: Uuid =
        sqlx::query_scalar("SELECT public.epigraph_bind_group_role($1, $2, 'writer', true, $3)")
            .bind(ROLE)
            .bind(group)
            .bind("derived writer scope test")
            .fetch_one(&mut *c)
            .await
            .expect("bind the role");
    reset(c).await;
    (group, binding)
}

/// Grant `ROLE` to `holder`, open-ended, from now (123's definer, no grantor).
async fn grant(pool: &PgPool, holder: Uuid) -> Uuid {
    let mut c = maint(pool).await;
    let id: Uuid = sqlx::query_scalar(
        "SELECT public.epigraph_grant_role($1, $2, now(), NULL, NULL, 'derived writer scope test')",
    )
    .bind(ROLE)
    .bind(holder)
    .fetch_one(&mut *c)
    .await
    .expect("grant the role");
    reset(c).await;
    id
}

async fn arm(pool: &PgPool) {
    let mut c = maint(pool).await;
    sqlx::query("SELECT armed_now FROM public.epigraph_arm_operator_binding()")
        .fetch_one(&mut *c)
        .await
        .expect("the maintenance role arms");
    reset(c).await;
}

/// What another session ends, and commits, while the writer's transaction
/// is open.
#[derive(Clone, Copy, Debug)]
enum Ending {
    Nothing,
    Assignment(Uuid),
    Binding(Uuid),
}

/// End it on a maintenance session (its own transaction, committed).
async fn end(pool: &PgPool, ending: Ending) {
    let mut c = maint(pool).await;
    match ending {
        Ending::Nothing => {}
        Ending::Assignment(id) => {
            let ended: bool =
                sqlx::query_scalar("SELECT public.epigraph_end_role_assignment($1, $2)")
                    .bind(id)
                    .bind("derived writer scope test end")
                    .fetch_one(&mut *c)
                    .await
                    .expect("end the assignment");
            assert!(ended, "PREMISE: the assignment was live and is ended now");
        }
        Ending::Binding(id) => {
            let ended: bool =
                sqlx::query_scalar("SELECT public.epigraph_end_group_role_binding($1, $2)")
                    .bind(id)
                    .bind("derived writer scope test end")
                    .fetch_one(&mut *c)
                    .await
                    .expect("end the binding");
            assert!(ended, "PREMISE: the binding was live and is ended now");
        }
    }
    reset(c).await;
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
    .bind(format!("derived writer scope probe {id}"))
    .bind(id.as_bytes().repeat(2))
    .bind(author)
    .bind(group)
    .execute(conn)
    .await
    .map(|_| id)
}

/// The writer's run. On one `epigraph_app` session stamped as `principal`'s
/// resolved viewer (resolved BEFORE anything ends, as the request path
/// stamps it once), one transaction at `isolation`:
///
/// 1. `first`, if given: an INSERT into it, which must land (a positive
///    control that the transaction could write at all);
/// 2. a plain read, which takes the transaction's snapshot when (1) did not;
/// 3. on ANOTHER session, `ending` is ended and committed;
/// 4. the probe: an INSERT authored by `principal` into `group`.
///
/// Rolled back. Returns the probe's result.
async fn write_across_an_end(
    pool: &PgPool,
    principal: Uuid,
    isolation: &str,
    first: Option<Uuid>,
    ending: Ending,
    group: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let viewer = Viewer::resolve(pool, principal).await.expect("resolve");
    let join = |s: &[Uuid]| {
        s.iter()
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
        end(pool, ending).await;
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

/// A registered human holding a live, open-ended assignment of `ROLE`, a
/// fresh group bound to `ROLE`, and the human's personal group.
struct Holder {
    human: Uuid,
    personal: Uuid,
    group: Uuid,
    binding: Uuid,
    assignment: Uuid,
}

async fn holder(pool: &PgPool, label: &str) -> Holder {
    let (human, personal) = fixture::seed_human_operator(pool, &format!("{label}-h")).await;
    let (group, binding) = bound_group(pool, &format!("Synthetic {label} Team")).await;
    let assignment = grant(pool, human).await;
    Holder {
        human,
        personal,
        group,
        binding,
        assignment,
    }
}

/// THE DEFECT. Armed, a human role holder opens a REPEATABLE READ or
/// SERIALIZABLE transaction; another session ends its assignment, or its
/// group's binding, and commits; the holder's next write into the role's
/// group is refused OPL02 (256). On 166's body it LANDS, because the derived
/// arm reads the ended row through the transaction's older snapshot (the
/// undo test below re-measures that). CONTROL: under READ COMMITTED the same
/// sequence, with a write through the arm before the end that lands, is
/// refused at the write after the end by the existing refusal.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_an_end_committed_mid_transaction_refuses_the_rr_and_serializable_writer(
    pool: PgPool,
) {
    define_role(&pool).await;
    arm(&pool).await;
    for (n, isolation) in [RR, SER].into_iter().enumerate() {
        for end_binding in [false, true] {
            let h = holder(&pool, &format!("End {n} {end_binding}")).await;
            let ending = if end_binding {
                Ending::Binding(h.binding)
            } else {
                Ending::Assignment(h.assignment)
            };
            let r = write_across_an_end(&pool, h.human, isolation, None, ending, h.group).await;
            assert_refused(
                &r,
                OPL02,
                DERIVED_ONLY_UNDER_RC,
                &format!("{isolation}, {ending:?} ended mid-transaction"),
            );
        }
    }

    let h = holder(&pool, "End RC").await;
    let r = write_across_an_end(
        &pool,
        h.human,
        RC,
        Some(h.group),
        Ending::Assignment(h.assignment),
        h.group,
    )
    .await;
    assert_refused(
        &r,
        OPL02,
        HUMAN_SCOPE,
        "CONTROL: READ COMMITTED, the write after the end (the first landed)",
    );
}

/// Under REPEATABLE READ or SERIALIZABLE the derived arm admits NOTHING,
/// even while the assignment and binding are live: the test is decided on
/// the level, because an older snapshot cannot tell a live row from one
/// ended since (166's ROL01 rule for agents, applied to the arm).
/// CONTROLS, each the same shape with the refused condition absent: the same
/// holder under READ COMMITTED writes through the arm and into its own
/// personal group (122's direct arm, which since 310 admits only under READ
/// COMMITTED too, refused with its own words); a privileged session stamped
/// as the holder is exempt; and an agent of the holder under REPEATABLE READ
/// was already refused ROL01 before 256 reached it.
#[sqlx::test(migrations = "../../migrations")]
async fn armed_the_derived_arm_admits_only_under_read_committed(pool: PgPool) {
    define_role(&pool).await;
    arm(&pool).await;
    let h = holder(&pool, "Level").await;

    write_across_an_end(&pool, h.human, RC, None, Ending::Nothing, h.group)
        .await
        .expect("CONTROL: READ COMMITTED, the holder writes through its binding");
    write_across_an_end(&pool, h.human, RC, None, Ending::Nothing, h.personal)
        .await
        .expect("CONTROL: READ COMMITTED, the holder writes its own personal group");
    for isolation in [RR, SER] {
        let r =
            write_across_an_end(&pool, h.human, isolation, None, Ending::Nothing, h.group).await;
        assert_refused(
            &r,
            OPL02,
            DERIVED_ONLY_UNDER_RC,
            &format!("{isolation}, nothing ended"),
        );
        // 310: the direct arm (the personal group) is refused under this
        // level as well, by its own refusal, not the derived arm's.
        let r =
            write_across_an_end(&pool, h.human, isolation, None, Ending::Nothing, h.personal).await;
        assert_refused(
            &r,
            OPL02,
            DIRECT_ONLY_UNDER_RC,
            &format!("{isolation}, the holder's own personal group (310)"),
        );
    }

    // A privileged session (the maintenance role) stamped as the holder is
    // exempt (`epigraph_operator_scope_exempt`), at any level.
    let mut c = maint(&pool).await;
    c.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .expect("begin");
    sqlx::query("SELECT set_config('epigraph.principal_id', $1, true)")
        .bind(h.human.to_string())
        .execute(&mut *c)
        .await
        .expect("stamp");
    insert_group_claim(&mut c, h.human, h.group)
        .await
        .expect("CONTROL: a privileged session is exempt from the writer scope");
    c.execute("ROLLBACK").await.expect("rollback");
    reset(c).await;

    // An agent of the holder: 166 already refuses it ROL01 under REPEATABLE
    // READ, before the derived arm is reached.
    let (agent, _) = fixture::seed_agent_with_group(&pool, "level-agent").await;
    let mut conn = pool.acquire().await.expect("acquire");
    let link = AgentRepository::link_operator(&mut conn, agent, h.human)
        .await
        .expect("link the agent");
    assert!(link.link_live, "PREMISE: a live link: {link:?}");
    drop(conn);
    write_across_an_end(&pool, agent, RC, None, Ending::Nothing, h.group)
        .await
        .expect("CONTROL: READ COMMITTED, the holder's agent writes through the binding");
    let r = write_across_an_end(&pool, agent, RR, None, Ending::Nothing, h.group).await;
    assert_eq!(
        code_of(&r).as_deref(),
        Some(ROL01),
        "an agent under REPEATABLE READ is refused by 166 first: {r:?}"
    );
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

/// After `docs/runbooks/310-undo.sql` puts 256's body back (310 re-states
/// the function over 256's),
/// `docs/runbooks/256-undo.sql` restores 166's body byte for byte (owner,
/// volatility, grants and search path kept), and a second run changes
/// nothing. On the restored body the defect is back: a REPEATABLE READ or
/// SERIALIZABLE holder whose assignment, or whose group's binding, is ended
/// mid-transaction WRITES (the measurement that 256 is what refuses it). Over a foreign body both 256 and its undo
/// refuse 55000 and leave it.
#[sqlx::test(migrations = "../../migrations")]
async fn the_256_undo_restores_166s_writer_scope(pool: PgPool) {
    let undo = repo_text("docs/runbooks/256-undo.sql");
    let migration = repo_text("migrations/256_derived_writer_scope_read_committed.sql");
    sqlx::raw_sql(&repo_text("docs/runbooks/310-undo.sql"))
        .execute(&pool)
        .await
        .expect("310's undo applies first");
    let at_256 = writer_scope_md5(&pool).await;
    assert_ne!(
        at_256, BODY_166,
        "CALIBRATION: 256 re-bodied the writer scope"
    );
    let catalog = writer_scope_catalog(&pool).await;

    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("the undo applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_166, "166's body");
    assert_eq!(writer_scope_catalog(&pool).await, catalog, "catalog kept");
    sqlx::raw_sql(&undo)
        .execute(&pool)
        .await
        .expect("a second run applies");
    assert_eq!(writer_scope_md5(&pool).await, BODY_166, "idempotent");

    define_role(&pool).await;
    arm(&pool).await;
    // Every case the first test refuses, measured on 166's body: each lands.
    for (n, isolation) in [RR, SER].into_iter().enumerate() {
        for end_binding in [false, true] {
            let h = holder(&pool, &format!("Undo {n} {end_binding}")).await;
            let ending = if end_binding {
                Ending::Binding(h.binding)
            } else {
                Ending::Assignment(h.assignment)
            };
            write_across_an_end(&pool, h.human, isolation, None, ending, h.group)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "on 166's body the {isolation} holder writes after {ending:?} ended \
                         (the defect): {e}"
                    )
                });
        }
    }

    // 256 re-applies over 166's body and refuses a foreign one, as does the
    // undo (which opens its own transaction: end it on the same connection).
    sqlx::raw_sql(&migration)
        .execute(&pool)
        .await
        .expect("256 re-applies over 166's body");
    assert_eq!(writer_scope_md5(&pool).await, at_256, "256's body again");
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
        "256 over a foreign body: {r:?}"
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
