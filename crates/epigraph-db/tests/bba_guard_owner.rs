//! Migration 251 (backlog 6bdac68f): the retracted-BBA guards are owned by
//! `epigraph_bba_guard_owner`, a NOLOGIN role no login can act as.
//!
//! What a maintenance session can no longer do is pinned where the guards are
//! tested: `mass_function_purge_guard.rs` (d) refuses its forged purge grant
//! and the delete that would follow, and `bba_retract.rs`
//! (`a_maintenance_login_cannot_clear_a_retraction_but_the_definer_still_can`)
//! refuses its forged clear. Both run on a REAL NOSUPERUSER maintenance login
//! (`support/maintenance_login.rs`). This file pins the migration itself: the
//! role's isolation and what it owns at head, the fault check calibrated on a
//! role that is NOT isolated, the guard body before and after, the
//! precondition, and the undo.
//!
//! Roles are cluster-wide and the tests of every crate migrate in parallel on
//! one cluster, so nothing here grants `epigraph_bba_guard_owner` to anything
//! outside a transaction that is rolled back.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

#[path = "support/maintenance_login.rs"]
mod login;

use sqlx::migrate::Migrator;
use sqlx::{Connection, Executor, PgPool};
use std::borrow::Cow;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

const OWNER: &str = "epigraph_bba_guard_owner";
const GUARD_FN: &str = "public.epigraph_mass_function_retract_guard()";
const GRANT_TABLE: &str = "public.mass_function_purge_grants";
/// `md5(prosrc)` of 184's body of the guard, measured on a database migrated
/// to the last migration before 251 (`the_guard_body_before_251_is_184s`).
const MD5_184_GUARD: &str = "be48455cec9bc897f0f13473129c52ff";
const GUARD_CONFIG: &str = "search_path=pg_catalog, public";

/// The three definers 251 re-owns, with whether the application role keeps
/// EXECUTE on each.
const DEFINERS: &[(&str, bool)] = &[
    ("public.epigraph_mf_purge_granted(uuid)", true),
    ("public.epigraph_purge_mass_functions(uuid[], text)", false),
    (
        "public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)",
        true,
    ),
];

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel} must exist: {e}"))
}

async fn faults(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT public.epigraph_bba_guard_owner_faults()")
        .fetch_one(pool)
        .await
        .expect("251 creates the faults function")
}

async fn guard_facts(pool: &PgPool) -> (String, Vec<String>, String) {
    sqlx::query_as(
        "SELECT md5(p.prosrc), COALESCE(p.proconfig, ARRAY[]::text[]), p.prosrc FROM pg_proc p \
          WHERE p.oid = $1::regprocedure",
    )
    .bind(GUARD_FN)
    .fetch_one(pool)
    .await
    .expect("the retract guard exists")
}

async fn owner_of(pool: &PgPool, sig: &str) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_userbyid(p.proowner)::text FROM pg_proc p WHERE p.oid = $1::regprocedure",
    )
    .bind(sig)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{sig}: {e}"))
}

async fn applied(pool: &PgPool, version: i64) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
        .bind(version)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Every migration below 251, then reset (001's pg_dump header leaves
/// session-level SETs behind).
async fn migrate_below_251(pool: &PgPool) {
    let below = Migrator {
        migrations: Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < 251)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    };
    let mut conn = pool.acquire().await.expect("acquire");
    below.run(&mut *conn).await.expect("migrate below 251");
    conn.execute("RESET ALL").await.expect("RESET ALL");
}

async fn migrate_rest(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = pool.acquire().await.expect("acquire");
    let r = MIGRATOR.run(&mut *conn).await;
    conn.execute("RESET ALL").await.expect("RESET ALL");
    r
}

/// The measurement behind [`MD5_184_GUARD`]: below 251 the guard is 184's
/// body on 184's path (no later migration re-bodied it; 228 only re-created
/// one of its triggers).
#[sqlx::test(migrations = false)]
async fn the_guard_body_before_251_is_184s(pool: PgPool) {
    migrate_below_251(&pool).await;
    let (md5, config, _) = guard_facts(&pool).await;
    assert_eq!(md5, MD5_184_GUARD, "md5(prosrc) of the guard below 251");
    assert_eq!(config, vec![GUARD_CONFIG.to_string()]);
    // Below 251 the three definers are still the maintenance role's.
    for (sig, _) in DEFINERS {
        assert_eq!(owner_of(&pool, sig).await, "epigraph_maintenance", "{sig}");
    }
}

/// At head: the role is sound (no fault), owns exactly the three definers,
/// which the maintenance role (and, for two of them, the application role)
/// may still EXECUTE; no non-superuser role but the owner holds any privilege
/// on the grant table; the guard's clear arm names the owner and nothing else
/// changed in the guard's settings.
#[sqlx::test(migrations = "../../migrations")]
async fn at_head_the_owner_is_isolated_and_owns_the_guard_definers(pool: PgPool) {
    assert_eq!(faults(&pool).await, Vec::<String>::new(), "no fault");

    let role: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, \
                pg_has_role(oid, 'epigraph_maintenance', 'USAGE') \
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(OWNER)
    .fetch_one(&pool)
    .await
    .expect("251 creates the role");
    assert_eq!(
        role,
        (false, false, false, false, false, true),
        "NOLOGIN, no attribute, inherits epigraph_maintenance"
    );
    // No role but a superuser can act as it (SET or USAGE), whatever any
    // parallel test database has created on the cluster.
    let actors: Vec<String> = sqlx::query_scalar(
        "SELECT r.rolname::text FROM pg_roles r \
          WHERE r.rolname <> $1 AND NOT r.rolsuper \
            AND (pg_has_role(r.oid, $1, 'USAGE') OR pg_has_role(r.oid, $1, 'SET'))",
    )
    .bind(OWNER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        actors.is_empty(),
        "roles that can act as {OWNER}: {actors:?}"
    );

    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT p.oid::regprocedure::text FROM pg_proc p \
          WHERE pg_get_userbyid(p.proowner) = $1 ORDER BY 1",
    )
    .bind(OWNER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        owned,
        vec![
            "epigraph_mf_purge_granted(uuid)".to_string(),
            "epigraph_purge_mass_functions(uuid[],text)".to_string(),
            "epigraph_unretract_mass_function(uuid,text,uuid,uuid)".to_string(),
        ],
        "{OWNER} owns exactly the three guard definers"
    );
    for (sig, app) in DEFINERS {
        for (role, expected) in [
            ("epigraph_maintenance", true),
            ("epigraph_app", *app),
            ("public", false),
        ] {
            let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(role)
                .bind(sig)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(can, expected, "{role} EXECUTE {sig}");
        }
    }

    // The grant table: the owner holds exactly what its two definers use; no
    // other non-superuser role of the cluster holds anything, the maintenance
    // role included. A later `GRANT ... ON ALL TABLES ... TO
    // epigraph_maintenance` would reopen the residual and fails here. The
    // predefined `pg_*` roles are left out (`pg_read_all_data` reads every
    // table, `pg_write_all_data` writes every table): granting either to a
    // login is an operator act docs/deploy.md's audit for 251 covers.
    for (privilege, expected) in [
        ("SELECT", true),
        ("INSERT", true),
        ("DELETE", true),
        ("UPDATE", false),
        ("TRUNCATE", false),
        ("REFERENCES", false),
        ("TRIGGER", false),
    ] {
        let held: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
            .bind(OWNER)
            .bind(GRANT_TABLE)
            .bind(privilege)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(held, expected, "{OWNER} {privilege} on {GRANT_TABLE}");
        let others: Vec<String> = sqlx::query_scalar(
            "SELECT r.rolname::text FROM pg_roles r \
              WHERE NOT r.rolsuper AND r.rolname <> $1 AND r.rolname NOT LIKE 'pg\\_%' \
                AND NOT pg_has_role(r.oid, \
                        (SELECT relowner FROM pg_class WHERE oid = $2::regclass), 'USAGE') \
                AND has_table_privilege(r.oid, $2::regclass, $3) \
              ORDER BY 1",
        )
        .bind(OWNER)
        .bind(GRANT_TABLE)
        .bind(privilege)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            others.is_empty(),
            "non-superuser roles holding {privilege} on {GRANT_TABLE}: {others:?}"
        );
    }

    let (md5, config, src) = guard_facts(&pool).await;
    assert_ne!(md5, MD5_184_GUARD, "251 re-bodied the guard");
    assert_eq!(config, vec![GUARD_CONFIG.to_string()], "184's path kept");
    assert!(
        src.contains("current_user = 'epigraph_bba_guard_owner'::name"),
        "the clear arm names the owner: {src}"
    );
    assert_eq!(
        src.matches("epigraph_definer_bypass()").count(),
        1,
        "only the mark arm still reads the definer bypass: {src}"
    );
}

/// The fault check is calibrated: on a role that IS reachable it names the
/// way. A LOGIN granted the owner (USAGE), a NOLOGIN role granted it SET-only
/// with a login behind it, and the owner given LOGIN are each reported. All in
/// one transaction that is rolled back, so no other database of the cluster
/// ever sees them.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fault_check_names_every_way_to_act_as_the_owner(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let (direct, middle, behind) = (
        format!("t63_direct_{tag}"),
        format!("t63_middle_{tag}"),
        format!("t63_behind_{tag}"),
    );
    for sql in [
        format!("CREATE ROLE {direct} LOGIN NOSUPERUSER"),
        format!("GRANT {OWNER} TO {direct}"),
        format!("CREATE ROLE {middle} NOLOGIN NOSUPERUSER NOINHERIT"),
        format!("GRANT {OWNER} TO {middle} WITH INHERIT FALSE, SET TRUE"),
        format!("CREATE ROLE {behind} LOGIN NOSUPERUSER IN ROLE {middle}"),
        format!("ALTER ROLE {OWNER} LOGIN"),
    ] {
        tx.execute(sql.as_str())
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
    let found: Vec<String> =
        sqlx::query_scalar("SELECT unnest(public.epigraph_bba_guard_owner_faults())")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    for want in [
        format!("{direct} can act as {OWNER}"),
        format!("{middle} can act as {OWNER}"),
        format!("{behind} can act as {OWNER}"),
        format!("{OWNER} can LOGIN"),
    ] {
        assert!(found.contains(&want), "missing {want:?} in {found:?}");
    }
    assert_eq!(faults(&pool).await, Vec::<String>::new(), "rolled back");
}

/// 251 refuses (55000, nothing changed) when an existing owner role is not
/// isolated: here a login can act as it. In one rolled-back transaction.
#[sqlx::test(migrations = false)]
async fn migration_251_refuses_an_owner_a_login_can_act_as(pool: PgPool) {
    migrate_below_251(&pool).await;
    let m251 = repo_file("migrations/251_retracted_bba_guard_owner.sql");
    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(OWNER)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    if !exists {
        tx.execute(
            format!("CREATE ROLE {OWNER} NOLOGIN INHERIT IN ROLE epigraph_maintenance").as_str(),
        )
        .await
        .expect("create the owner inside the transaction");
    }
    let login = format!("t63_reach_{}", uuid::Uuid::new_v4().simple());
    tx.execute(format!("CREATE ROLE {login} LOGIN NOSUPERUSER IN ROLE {OWNER}").as_str())
        .await
        .expect("a login that can act as the owner");
    tx.execute("SAVEPOINT m251").await.unwrap();
    let r = sqlx::raw_sql(&m251).execute(&mut *tx).await;
    tx.execute("ROLLBACK TO SAVEPOINT m251").await.unwrap();
    let owner_after = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_userbyid(proowner)::text FROM pg_proc \
          WHERE oid = 'public.epigraph_purge_mass_functions(uuid[], text)'::regprocedure",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    let e = r.expect_err("251 must refuse an owner a login can act as");
    let db = e.as_database_error().expect("a database error");
    assert_eq!(db.code().as_deref(), Some("55000"), "{e}");
    assert!(db.message().contains("not isolated"), "{e}");
    assert!(
        db.message()
            .contains(&format!("{login} can act as {OWNER}")),
        "{e}"
    );
    assert_eq!(owner_after, "epigraph_maintenance", "nothing was re-owned");
    assert!(!applied(&pool, 251).await);
}

/// 251 refuses (55000, nothing changed) over a guard body that is not 184's,
/// and over 184's body on another path; it applies over 184's.
#[sqlx::test(migrations = false)]
async fn migration_251_refuses_to_apply_over_another_guard_body(pool: PgPool) {
    migrate_below_251(&pool).await;
    let original: String = sqlx::query_scalar("SELECT pg_get_functiondef($1::regprocedure)")
        .bind(GUARD_FN)
        .fetch_one(&pool)
        .await
        .unwrap();
    let edited = original.replacen("BEGIN", "BEGIN\n    -- another migration's edit", 1);
    assert_ne!(edited, original);
    pool.execute(edited.as_str())
        .await
        .expect("re-body the guard");

    let assert_refused = |r: Result<(), sqlx::migrate::MigrateError>, what: &str| {
        let e = r.expect_err(&format!("251 must refuse {what}"));
        let code = match &e {
            sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(db))
            | sqlx::migrate::MigrateError::ExecuteMigration(sqlx::Error::Database(db), _) => {
                db.code().map(|c| c.to_string())
            }
            _ => None,
        };
        assert_eq!(code.as_deref(), Some("55000"), "{what}: {e}");
        assert!(format!("{e}").contains("251:"), "{what}: {e}");
    };
    assert_refused(migrate_rest(&pool).await, "a body other than 184's");
    assert!(!applied(&pool, 251).await);
    assert_eq!(
        owner_of(&pool, DEFINERS[1].0).await,
        "epigraph_maintenance",
        "the refused migration re-owned nothing"
    );

    pool.execute(original.as_str())
        .await
        .expect("restore 184's body");
    pool.execute(format!("ALTER FUNCTION {GUARD_FN} SET search_path = public, pg_temp").as_str())
        .await
        .unwrap();
    assert_refused(migrate_rest(&pool).await, "184's body on another path");
    assert!(!applied(&pool, 251).await);

    pool.execute(
        format!("ALTER FUNCTION {GUARD_FN} SET search_path = pg_catalog, public").as_str(),
    )
    .await
    .unwrap();
    migrate_rest(&pool)
        .await
        .expect("251 applies over 184's body");
    assert!(applied(&pool, 251).await);
    assert_eq!(owner_of(&pool, DEFINERS[1].0).await, OWNER);
}

/// `docs/runbooks/251-undo.sql` restores 184's guard (its md5), re-owns the
/// three definers to the maintenance role with their EXECUTE grants, gives the
/// maintenance role 194's privileges on the grant table back (so a
/// maintenance login can write a grant again: the residual is back, which is
/// what undoing means), and drops the faults function; it runs twice; and
/// 251's own text then applies again over the undone state.
#[sqlx::test(migrations = "../../migrations")]
async fn the_251_undo_restores_184s_guard_and_the_maintenance_ownership(pool: PgPool) {
    let undo = repo_file("docs/runbooks/251-undo.sql");
    let m251 = repo_file("migrations/251_retracted_bba_guard_owner.sql");
    for _ in 0..2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .expect("the undo runs");
    }
    let (md5, config, _) = guard_facts(&pool).await;
    assert_eq!(md5, MD5_184_GUARD, "184's guard body is restored");
    assert_eq!(config, vec![GUARD_CONFIG.to_string()]);
    for (sig, app) in DEFINERS {
        assert_eq!(owner_of(&pool, sig).await, "epigraph_maintenance", "{sig}");
        for (role, expected) in [("epigraph_maintenance", true), ("epigraph_app", *app)] {
            let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(role)
                .bind(sig)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(can, expected, "{role} EXECUTE {sig} after the undo");
        }
    }
    let gone: Option<String> = sqlx::query_scalar(
        "SELECT to_regprocedure('public.epigraph_bba_guard_owner_faults()')::text",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(gone.is_none(), "the undo drops the faults function");
    let (role, login) = login::maintenance_login(&pool, "t63undo").await;
    let mut tx = login.begin().await.unwrap();
    let wrote = sqlx::query(
        "INSERT INTO public.mass_function_purge_grants (mf_id, reason) VALUES (gen_random_uuid(), 'undone')",
    )
    .execute(&mut *tx)
    .await;
    drop(tx);
    login::drop_login(&pool, &role, login).await;
    wrote.expect("after the undo the maintenance role writes grants again (194's posture)");

    sqlx::raw_sql(&format!("BEGIN;\n{m251}\nCOMMIT;"))
        .execute(&pool)
        .await
        .expect("251 re-applies after its undo");
    assert_eq!(faults(&pool).await, Vec::<String>::new());
    for (sig, _) in DEFINERS {
        assert_eq!(owner_of(&pool, sig).await, OWNER, "{sig}");
    }
    let maint_insert: bool =
        sqlx::query_scalar("SELECT has_table_privilege('epigraph_maintenance', $1, 'INSERT')")
            .bind(GRANT_TABLE)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !maint_insert,
        "the re-apply revokes the maintenance role's INSERT again"
    );
}
