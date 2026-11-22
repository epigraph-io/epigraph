//! Migration 241: the `--allow-unauthenticated-http` reader agent is a
//! reserved row that never holds a live group membership (backlogs 37844e1d,
//! 14a38166).
//!
//! The reader (`epigraph-mcp/src/unauthenticated_reader.rs`) reads PUBLIC
//! rows only and its listener fails closed when it holds a membership. Before
//! 241 any `groups:admin` holder could add it to a group and so close every
//! read-only listener (37844e1d), and anyone able to create an agent could
//! create its row first (14a38166).
//!
//! What is pinned:
//! * an `epigraph_app` session stamped as a group's admin cannot add the
//!   reader to that group, in any role, through the repository call
//!   `POST /api/v1/groups/:id/members` makes, while the same session adds
//!   another agent (calibration: the refusal is 241's, not RLS or a grant);
//! * no other role or path gives it a live row either: a superuser INSERT,
//!   077's personal-group definer (a definer frame, which 109's guards let
//!   through), and a superuser UPDATE moving a live row's `agent_id` onto it
//!   (which 109's identity guard lets through);
//! * the key is the reserved row's alone: an `epigraph_app` INSERT, a
//!   superuser INSERT and a key UPDATE of another row are refused with 241's
//!   own error (RDR01, never the unique constraint's 23505), while another key
//!   inserts (calibration);
//! * a database that already holds the reader row (and a live membership of
//!   it) migrates: the row is adopted, the legacy membership can still be
//!   rotated and revoked, and cannot be revived;
//! * `docs/runbooks/241-undo.sql` removes the refusal, twice over.
//!
//! Verified to fail: with 241 reduced to its row INSERT (no triggers), all
//! five original tests fail on their refusal assertions (the key test on 23505
//! instead of RDR01); with a `epigraph_definer_bypass()` exemption added to
//! the membership trigger, the definer probe and the revival refusal fail;
//! with the UPDATE early return keyed on `OLD.revoked_at` alone (no
//! `agent_id` check), the identity-move test fails.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_db::{DbError, GroupMembershipRepository};
use sqlx::PgPool;
use uuid::Uuid;

/// `READER_PUBLIC_KEY` in `epigraph-mcp/src/unauthenticated_reader.rs`
/// (epigraph-db cannot depend on epigraph-mcp; the MCP suite pins that the
/// listener resolves exactly the row 241 created under this key).
const READER_KEY: &[u8; 32] = b"epigraph-mcp:unauthenticated-rdr";

const UNDO_241: &str = include_str!("../../../docs/runbooks/241-undo.sql");

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn up_to(max: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= max)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

async fn reader_id(pool: &PgPool) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM agents WHERE public_key = $1")
        .bind(READER_KEY.as_slice())
        .fetch_optional(pool)
        .await
        .expect("reader lookup")
}

async fn live_memberships(pool: &PgPool, agent: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM group_memberships WHERE agent_id = $1 AND revoked_at IS NULL",
    )
    .bind(agent)
    .fetch_one(pool)
    .await
    .expect("membership count")
}

async fn plain_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .expect("seed agent");
    id
}

/// The driver error under a repository or raw-query failure.
fn db_error(err: &sqlx::Error) -> (String, String) {
    match err {
        sqlx::Error::Database(db) => (
            db.code().map(|c| c.to_string()).unwrap_or_default(),
            db.message().to_string(),
        ),
        other => panic!("expected a database error, got {other:?}"),
    }
}

fn assert_refused(err: &sqlx::Error, tag: &str) {
    let (code, message) = db_error(err);
    assert_eq!(code, "42501", "{tag} must refuse with 42501: {message}");
    assert!(message.starts_with(tag), "expected {tag}, got: {message}");
}

/// `POST /api/v1/groups/:id/members`' write, as `epigraph_app` stamped the way
/// `ScopedPool::begin_as` stamps the admin's connection.
async fn add_as_admin(
    pool: &PgPool,
    admin: Uuid,
    group: Uuid,
    agent: Uuid,
    role: &'static str,
) -> Result<Uuid, DbError> {
    fixture::as_role(pool, "epigraph_app", |mut c| async move {
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', $1, false), \
                    set_config('epigraph.group_ids', $2, false), \
                    set_config('epigraph.writable_group_ids', $2, false)",
        )
        .bind(admin.to_string())
        .bind(group.to_string())
        .execute(&mut *c)
        .await
        .expect("stamp");
        let out =
            GroupMembershipRepository::add_member_conn(&mut c, group, agent, b"", 0, role).await;
        sqlx::query(
            "SELECT set_config('epigraph.principal_id', '', false), \
                    set_config('epigraph.group_ids', '', false), \
                    set_config('epigraph.writable_group_ids', '', false)",
        )
        .execute(&mut *c)
        .await
        .expect("unstamp");
        (c, out)
    })
    .await
}

/// 37844e1d's DONE: a `groups:admin` holder on the application role cannot add
/// the reader to its group, in any of the three roles.
#[sqlx::test(migrations = "../../migrations")]
async fn a_group_admin_on_the_app_role_cannot_add_the_reader_to_its_group(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let reader = reader_id(&pool).await.expect("241 creates the reader row");
    let (admin, group) = fixture::seed_agent_with_group(&pool, "rdr-admin").await;

    // CALIBRATION: the same stamped session admits another agent, so the
    // refusal below is not row security, a grant or a stamp the test got wrong.
    let other = plain_agent(&pool).await;
    add_as_admin(&pool, admin, group, other, "reader")
        .await
        .expect("CALIBRATION: the group's admin adds another agent");
    assert_eq!(live_memberships(&pool, other).await, 1);

    for role in ["reader", "writer", "admin"] {
        let err = add_as_admin(&pool, admin, group, reader, role)
            .await
            .expect_err("the reader must not join a group");
        let DbError::QueryFailed { source } = &err else {
            panic!("expected the driver's refusal, got {err:?}");
        };
        assert_refused(source, "RDR02");
    }
    assert_eq!(live_memberships(&pool, reader).await, 0);
}

/// No escape hatch. 077's personal-group definer, which the application role
/// may EXECUTE, runs in a SECURITY DEFINER frame where 109's guards step aside
/// (`epigraph_definer_bypass()`); it is refused, called as `epigraph_app`.
/// A superuser INSERT (a maintenance member, `epigraph_bypass()`) is refused
/// too. A revoked row is inert and admitted.
#[sqlx::test(migrations = "../../migrations")]
async fn no_role_and_no_definer_gives_the_reader_a_live_membership(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let reader = reader_id(&pool).await.expect("241 creates the reader row");
    let (_, group) = fixture::seed_agent_with_group(&pool, "rdr-super").await;

    // CALIBRATION: the app role reaches the definer and it provisions an
    // ordinary agent's personal group.
    let other = plain_agent(&pool).await;
    let (calibration, err) = fixture::as_role(&pool, "epigraph_app", |mut c| async move {
        let calibration = sqlx::query("SELECT public.epigraph_ensure_personal_group($1)")
            .bind(other)
            .execute(&mut *c)
            .await;
        let err = sqlx::query("SELECT public.epigraph_ensure_personal_group($1)")
            .bind(reader)
            .execute(&mut *c)
            .await;
        (c, (calibration, err))
    })
    .await;
    calibration.expect("CALIBRATION: the app role provisions another agent's personal group");
    assert_eq!(live_memberships(&pool, other).await, 1);
    assert_refused(
        &err.expect_err("the personal-group definer must not provision the reader"),
        "RDR02",
    );
    assert_eq!(live_memberships(&pool, reader).await, 0);

    let err = sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(reader)
    .execute(&pool)
    .await
    .expect_err("a superuser insert is refused too");
    assert_refused(&err, "RDR02");
    assert_eq!(live_memberships(&pool, reader).await, 0);

    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role, \
         revoked_at) VALUES ($1, $2, ''::bytea, 0, 'reader', now())",
    )
    .bind(group)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("a revoked row grants nothing and is admitted");
    assert_eq!(live_memberships(&pool, reader).await, 0);
}

/// No escape through an identity move either. 109's
/// `group_memberships_identity_immutable` lets a maintenance session (here a
/// superuser, `epigraph_bypass()`) change a live row's `agent_id`; moving a
/// live row ONTO the reader is refused, while the same move onto another
/// agent passes (calibration: 109 admits the move, so the refusal is 241's).
#[sqlx::test(migrations = "../../migrations")]
async fn a_maintenance_update_cannot_move_a_live_membership_onto_the_reader(pool: PgPool) {
    let reader = reader_id(&pool).await.expect("241 creates the reader row");
    let (_, group) = fixture::seed_agent_with_group(&pool, "rdr-move").await;
    let first = plain_agent(&pool).await;
    let second = plain_agent(&pool).await;
    let membership: Uuid = sqlx::query_scalar(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader') RETURNING id",
    )
    .bind(group)
    .bind(first)
    .fetch_one(&pool)
    .await
    .expect("a live membership of an ordinary agent");

    // CALIBRATION: the maintenance session moves the live row to another agent.
    sqlx::query("UPDATE group_memberships SET agent_id = $2 WHERE id = $1")
        .bind(membership)
        .bind(second)
        .execute(&pool)
        .await
        .expect("CALIBRATION: 109 admits a maintenance identity move");
    assert_eq!(live_memberships(&pool, second).await, 1);

    let err = sqlx::query("UPDATE group_memberships SET agent_id = $2 WHERE id = $1")
        .bind(membership)
        .bind(reader)
        .execute(&pool)
        .await
        .expect_err("a live row must not be moved onto the reader");
    assert_refused(&err, "RDR02");
    assert_eq!(live_memberships(&pool, reader).await, 0);
    assert_eq!(
        live_memberships(&pool, second).await,
        1,
        "the refused move leaves the row where it was"
    );
}

/// 14a38166's DONE: the key is reserved. The refusal is 241's own (RDR01),
/// not the unique constraint's: the reserved row exists, so a bare 23505
/// would pass a looser assertion with no trigger at all.
#[sqlx::test(migrations = "../../migrations")]
async fn the_reader_key_is_reserved_on_every_role(pool: PgPool) {
    fixture::grant_app_privileges(&pool, "epigraph_app").await;
    let (name, n): (Option<String>, i64) = sqlx::query_as(
        "SELECT display_name, (SELECT count(*) FROM agents WHERE public_key = $1) \
           FROM agents WHERE public_key = $1",
    )
    .bind(READER_KEY.as_slice())
    .fetch_one(&pool)
    .await
    .expect("241 creates exactly one reader row");
    assert_eq!(
        (name.as_deref(), n),
        (Some("mcp-unauthenticated-reader"), 1)
    );

    let insert = "INSERT INTO agents (public_key, display_name) VALUES ($1, 'squatter')";
    let app = fixture::as_role(&pool, "epigraph_app", |mut c| async move {
        let calibration = sqlx::query(insert)
            .bind([0x24_u8; 32].as_slice())
            .execute(&mut *c)
            .await;
        let squat = sqlx::query(insert)
            .bind(READER_KEY.as_slice())
            .execute(&mut *c)
            .await;
        (c, (calibration, squat))
    })
    .await;
    app.0
        .expect("CALIBRATION: the application role creates an agent with another key");
    assert_refused(
        &app.1.expect_err("the app role cannot take the key"),
        "RDR01",
    );

    // Even with the reserved row gone, the key stays reserved (the trigger,
    // not the row, holds it): delete it inside a transaction and try again.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("DELETE FROM agents WHERE public_key = $1")
        .bind(READER_KEY.as_slice())
        .execute(&mut *tx)
        .await
        .expect("delete the reserved row (rolled back)");
    let err = sqlx::query(insert)
        .bind(READER_KEY.as_slice())
        .execute(&mut *tx)
        .await
        .expect_err("a superuser insert of the key is refused, row or no row");
    assert_refused(&err, "RDR01");
    tx.rollback().await.expect("rollback");

    let other = plain_agent(&pool).await;
    let err = sqlx::query("UPDATE agents SET public_key = $1 WHERE id = $2")
        .bind(READER_KEY.as_slice())
        .bind(other)
        .execute(&pool)
        .await
        .expect_err("another row cannot move onto the key");
    assert_refused(&err, "RDR01");

    // The reserved row itself stays updatable where its key does not change.
    sqlx::query(
        "UPDATE agents SET public_key = public_key, updated_at = now() WHERE public_key = $1",
    )
    .bind(READER_KEY.as_slice())
    .execute(&pool)
    .await
    .expect("an update that keeps the reserved row's key passes");
}

/// A deployed database already holds the reader row (the pre-241 listener
/// made it on first boot) and possibly a live membership of it. 241 applies
/// over it: the row is adopted (same id, untouched), the legacy row can still
/// be rotated and revoked, and it can never be revived.
#[sqlx::test(migrations = false)]
async fn a_pre_existing_reader_row_is_adopted_and_its_legacy_membership_only_revoked(pool: PgPool) {
    migrate(&pool, &up_to(240)).await;
    let reader = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, display_name) \
         VALUES ($1, $2, 'mcp-unauthenticated-reader')",
    )
    .bind(reader)
    .bind(READER_KEY.as_slice())
    .execute(&pool)
    .await
    .expect("the row the pre-241 listener created");
    let (_, group) = fixture::seed_agent_with_group(&pool, "rdr-legacy").await;
    let membership: Uuid = sqlx::query_scalar(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader') RETURNING id",
    )
    .bind(group)
    .bind(reader)
    .fetch_one(&pool)
    .await
    .expect("a membership granted before 241");

    migrate(&pool, &MIGRATOR).await;
    assert_eq!(reader_id(&pool).await, Some(reader), "241 adopts the row");
    assert_eq!(
        live_memberships(&pool, reader).await,
        1,
        "241 rewrites no row"
    );

    sqlx::query(
        "UPDATE group_memberships SET epoch = 1, wrapped_key_share = '\\x00' WHERE id = $1",
    )
    .bind(membership)
    .execute(&pool)
    .await
    .expect("a key rotation of a live legacy row is not wedged");
    sqlx::query("UPDATE group_memberships SET revoked_at = now() WHERE id = $1")
        .bind(membership)
        .execute(&pool)
        .await
        .expect("revoking the legacy row stays open");
    assert_eq!(live_memberships(&pool, reader).await, 0);

    let err = sqlx::query("UPDATE group_memberships SET revoked_at = NULL WHERE id = $1")
        .bind(membership)
        .execute(&pool)
        .await
        .expect_err("a revoked row of the reader cannot be revived");
    assert_refused(&err, "RDR02");
}

async fn run_undo(pool: &PgPool) {
    let mut conn = pool.acquire().await.expect("acquire");
    sqlx::raw_sql(UNDO_241)
        .execute(&mut *conn)
        .await
        .expect("241-undo.sql");
}

async fn triggers_241(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE tgname IN \
         ('agents_reserve_unauthenticated_reader_key', \
          'group_memberships_refuse_unauthenticated_reader')",
    )
    .fetch_one(pool)
    .await
    .expect("trigger count")
}

/// `docs/runbooks/241-undo.sql` drops both triggers and both functions, run
/// twice; after it the membership is admitted again and the reader row stays.
#[sqlx::test(migrations = "../../migrations")]
async fn the_241_undo_removes_the_refusal_and_keeps_the_row(pool: PgPool) {
    assert_eq!(triggers_241(&pool).await, 2, "241's triggers exist at head");
    let reader = reader_id(&pool).await.expect("241 creates the reader row");

    run_undo(&pool).await;
    run_undo(&pool).await;
    assert_eq!(triggers_241(&pool).await, 0);
    let fns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_proc WHERE proname IN \
         ('epigraph_agents_reserve_unauthenticated_reader_key', \
          'epigraph_group_memberships_refuse_unauthenticated_reader')",
    )
    .fetch_one(&pool)
    .await
    .expect("function count");
    assert_eq!(fns, 0);
    assert_eq!(
        reader_id(&pool).await,
        Some(reader),
        "the undo keeps the row"
    );

    let (_, group) = fixture::seed_agent_with_group(&pool, "rdr-undo").await;
    sqlx::query(
        "INSERT INTO group_memberships (group_id, agent_id, wrapped_key_share, epoch, role) \
         VALUES ($1, $2, ''::bytea, 0, 'reader')",
    )
    .bind(group)
    .bind(reader)
    .execute(&pool)
    .await
    .expect("after the undo the membership is admitted, as before 241");
}
