//! Migration 350 (backlog cfaa5065): `epigraph_identity_attestor_faults()`
//! names every non-superuser that can make itself the attestor, not only one
//! that can act as it now. 161's check asked only for USAGE or SET, so it
//! passed a role holding ADMIN OPTION alone (on PostgreSQL 16 such a grant
//! confers neither, but its holder can grant the role to itself) and any
//! non-superuser CREATEROLE role (which can grant itself the attestor).
//!
//! Every role and grant staged here lives in ONE transaction that is rolled
//! back: roles are cluster-wide, and a committed one would make 251, 257 and
//! 350 refuse in every database migrating beside these tests.

use sqlx::{PgConnection, PgPool};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

const ATTESTOR: &str = "epigraph_identity_attestor";
const M350: &str =
    include_str!("../../../migrations/350_identity_attestor_isolation_admin_createrole.sql");

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

/// Run `migrator` on one connection and reset it: 001's pg_dump header leaves
/// session-level SETs behind.
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

async fn faults(conn: &mut PgConnection) -> Vec<String> {
    sqlx::query_scalar("SELECT public.epigraph_identity_attestor_faults()")
        .fetch_one(conn)
        .await
        .expect("faults")
}

async fn pg16(conn: &mut PgConnection) -> bool {
    sqlx::query_scalar("SELECT current_setting('server_version_num')::integer >= 160000")
        .fetch_one(conn)
        .await
        .expect("server version")
}

/// A grant of the attestor that carries ADMIN OPTION and nothing else.
fn admin_only_grant(pg16: bool, grantee: &str) -> String {
    if pg16 {
        format!("GRANT {ATTESTOR} TO {grantee} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
    } else {
        format!("GRANT {ATTESTOR} TO {grantee} WITH ADMIN OPTION")
    }
}

fn suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned())
}

/// At head the check names an ADMIN-only holder of the attestor (as a member
/// and as an ADMIN OPTION holder) and a non-superuser CREATEROLE role, and
/// nothing on a clean cluster. CONTROL: a SUPERUSER holding ADMIN OPTION is not
/// named (it can do anything already), and with the grant revoked the check
/// passes again.
///
/// Verified to fail on the old code: with 350 replaced by a no-op (head is
/// 161's body on 271's path), and with 350 re-stating 161's USAGE / SET arm
/// but keeping its migrate-time raise, the ADMIN-only holder is not named.
#[sqlx::test(migrations = "../../migrations")]
async fn the_check_names_an_admin_option_holder_and_a_createrole_role(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire");
    let clean = faults(&mut conn).await;
    let pg16 = pg16(&mut conn).await;
    let s = suffix();
    let admin_only = format!("t350_admin_{s}");
    let creator = format!("t350_createrole_{s}");
    let sup = format!("t350_super_{s}");

    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    sqlx::query(&format!("CREATE ROLE {admin_only} NOLOGIN NOINHERIT"))
        .execute(&mut *tx)
        .await
        .expect("create the admin-only role");
    sqlx::query(&admin_only_grant(pg16, &admin_only))
        .execute(&mut *tx)
        .await
        .expect("grant the attestor with ADMIN OPTION only");
    // On 16 the grant gives neither USAGE nor SET: 161's arm cannot see it.
    let (usage, set): (bool, bool) = sqlx::query_as(
        "SELECT pg_has_role($1::regrole, $2::regrole, 'USAGE'), \
                pg_has_role($1::regrole, $2::regrole, 'SET')",
    )
    .bind(&admin_only)
    .bind(ATTESTOR)
    .fetch_one(&mut *tx)
    .await
    .expect("membership options");
    let with_admin = faults(&mut tx).await;
    sqlx::query(&format!("REVOKE {ATTESTOR} FROM {admin_only}"))
        .execute(&mut *tx)
        .await
        .expect("revoke it again");
    let revoked = faults(&mut tx).await;

    sqlx::query(&format!("CREATE ROLE {creator} NOLOGIN CREATEROLE"))
        .execute(&mut *tx)
        .await
        .expect("create a CREATEROLE role");
    let with_creator = faults(&mut tx).await;
    sqlx::query(&format!("DROP ROLE {creator}"))
        .execute(&mut *tx)
        .await
        .expect("drop it again");

    sqlx::query(&format!("CREATE ROLE {sup} NOLOGIN SUPERUSER"))
        .execute(&mut *tx)
        .await
        .expect("create a superuser role");
    sqlx::query(&format!("GRANT {ATTESTOR} TO {sup} WITH ADMIN OPTION"))
        .execute(&mut *tx)
        .await
        .expect("grant the attestor to the superuser");
    let with_super = faults(&mut tx).await;
    tx.rollback()
        .await
        .expect("rollback: the roles are never committed");

    assert!(clean.is_empty(), "a migrated database is clean: {clean:?}");
    if pg16 {
        assert!(
            !usage && !set,
            "CALIBRATION: an ADMIN-only grant confers neither USAGE nor SET on 16"
        );
    }
    assert!(
        with_admin.contains(&format!("{admin_only} holds ADMIN OPTION on {ATTESTOR}")),
        "an ADMIN OPTION holder is named: {with_admin:?}"
    );
    assert!(
        with_admin.contains(&format!("{admin_only} is a member of {ATTESTOR}")),
        "an ADMIN-only holder is named as a member: {with_admin:?}"
    );
    assert!(
        revoked.is_empty(),
        "CONTROL: revoked, it passes: {revoked:?}"
    );
    assert_eq!(
        with_creator,
        vec![format!(
            "{creator} is a non-superuser CREATEROLE role (it can grant itself {ATTESTOR})"
        )],
        "a non-superuser CREATEROLE role is named, once"
    );
    assert!(
        with_super.is_empty(),
        "CONTROL: a superuser holding ADMIN OPTION is not named: {with_super:?}"
    );
}

/// 161's own case still holds at head: a role that can act as the attestor
/// (a fresh role granted it with the default options, so INHERIT and SET) is
/// named, once, as a member and as nothing else.
///
/// The grantee is a fresh role, not `epigraph_app`: the MEMBER arm follows
/// memberships through other roles, and other tests commit logins into
/// `epigraph_app` (cluster-wide), which would be named beside it. Only the
/// lines that name the fresh role are compared.
///
/// Verified to fail: with 350's MEMBER arm deleted, the default grant (no
/// ADMIN OPTION) leaves no line naming the role.
#[sqlx::test(migrations = "../../migrations")]
async fn a_role_that_can_act_as_the_attestor_is_still_named(pool: PgPool) {
    let mut conn = pool.acquire().await.expect("acquire");
    let member = format!("t350_member_{}", suffix());
    let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
    sqlx::query(&format!("CREATE ROLE {member} NOLOGIN"))
        .execute(&mut *tx)
        .await
        .expect("create the member (rolled back)");
    sqlx::query(&format!("GRANT {ATTESTOR} TO {member}"))
        .execute(&mut *tx)
        .await
        .expect("grant (rolled back)");
    let found = faults(&mut tx).await;
    tx.rollback().await.expect("rollback");
    let naming: Vec<&String> = found.iter().filter(|f| f.contains(&member)).collect();
    assert_eq!(
        naming,
        vec![&format!("{member} is a member of {ATTESTOR}")],
        "the member is named, once, as a member: {found:?}"
    );
}

/// 350 refuses to apply (55000, nothing changed) over an attestor that an
/// ADMIN-only holder or a non-superuser CREATEROLE role could become, and
/// applies on a clean cluster. Each refusal is staged on a database at 349 in
/// a transaction that is rolled back.
///
/// Verified to fail: 350 re-stating 161's USAGE / SET arm but keeping its
/// migrate-time raise -> the ADMIN-only staging applies; 350 replaced by a
/// no-op -> the same.
#[sqlx::test(migrations = false)]
async fn migration_350_refuses_an_attestor_that_is_not_isolated(pool: PgPool) {
    migrate(&pool, &up_to(349)).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let pg16 = pg16(&mut conn).await;
    let s = suffix();

    for (case, setup) in [
        (
            "ADMIN-only holder",
            vec![
                format!("CREATE ROLE t350m_admin_{s} NOLOGIN NOINHERIT"),
                admin_only_grant(pg16, &format!("t350m_admin_{s}")),
            ],
        ),
        (
            "CREATEROLE role",
            vec![format!(
                "CREATE ROLE t350m_createrole_{s} NOLOGIN CREATEROLE"
            )],
        ),
    ] {
        let mut tx = sqlx::Connection::begin(&mut *conn).await.expect("begin");
        for stmt in &setup {
            sqlx::query(stmt)
                .execute(&mut *tx)
                .await
                .unwrap_or_else(|e| panic!("{case}: {stmt}: {e}"));
        }
        let err = sqlx::raw_sql(M350).execute(&mut *tx).await.expect_err(case);
        tx.rollback().await.expect("rollback");
        assert_eq!(sqlstate(&err).as_deref(), Some("55000"), "{case}: {err}");
        assert!(
            err.to_string().contains("is not isolated"),
            "{case}: refused by the isolation check, not the precondition: {err}"
        );
    }

    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
    drop(conn);
    migrate(&pool, &up_to(350)).await;
    let mut conn = pool.acquire().await.expect("acquire");
    let at_350 = faults(&mut conn).await;
    assert!(at_350.is_empty(), "a clean cluster migrates: {at_350:?}");
}

/// The function's catalog row: md5 of the body, path, owner, ACL, comment.
async fn function_row(
    pool: &PgPool,
) -> (String, Option<Vec<String>>, String, String, Option<String>) {
    sqlx::query_as(
        "SELECT md5(p.prosrc), p.proconfig, p.proowner::regrole::text, \
                COALESCE(p.proacl::text, '-'), obj_description(p.oid, 'pg_proc') \
           FROM pg_proc p \
          WHERE p.oid = to_regprocedure('public.epigraph_identity_attestor_faults()')",
    )
    .fetch_one(pool)
    .await
    .expect("the function exists")
}

/// `docs/runbooks/350-undo.sql` returns the function to exactly what it was
/// at 349 (161's body on 271's path, the same owner, ACL and no comment), and
/// a second run changes nothing. The body md5 is the one 350's precondition
/// and 271-undo pin.
#[sqlx::test(migrations = false)]
async fn the_350_undo_restores_the_function_at_349(pool: PgPool) {
    migrate(&pool, &up_to(349)).await;
    let before = function_row(&pool).await;
    assert_eq!(
        before.0, "31cac2063a345bfff500e75b4095c4fa",
        "CALIBRATION: 161's body at 349"
    );
    migrate(&pool, &up_to(350)).await;
    let through = function_row(&pool).await;
    assert_ne!(through.0, before.0, "CALIBRATION: 350 re-bodies it");
    assert_eq!(
        through.1,
        Some(vec!["search_path=pg_catalog, pg_temp".to_string()]),
        "350's path"
    );
    assert_eq!(
        (&through.2, &through.3),
        (&before.2, &before.3),
        "350 keeps the owner and the ACL"
    );

    let undo = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/runbooks/350-undo.sql"),
    )
    .expect("350-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        assert_eq!(
            function_row(&pool).await,
            before,
            "after the {run} run the function is the one at 349"
        );
    }
}
