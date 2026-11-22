//! Migration 251 (backlog 6bdac68f): no session deletes or un-retracts a
//! retracted BBA without a ledger row it cannot remove, and the only code that
//! runs as the ledger's owner (`epigraph_bba_guard_owner`, NOLOGIN) is three
//! small functions that touch nothing but the ledger.
//!
//! What sessions can no longer do is pinned where the guards are tested:
//! `mass_function_purge_guard.rs` (d: a forged grant and the delete after it;
//! d4: a maintenance login's own grant leaves a ledger row it cannot remove),
//! and `bba_retract.rs` (a forged clear; and
//! `no_session_runs_its_own_code_as_the_ledger_owner`, the attack class that
//! runs a session's own code inside a privileged body). This file pins the
//! migration itself: what runs as the owner and what it holds at head (the
//! catalog side of that attack class), the fault check calibrated on every
//! way the owner or the ledger could be reached, the bodies before and after,
//! the preconditions and the refusals, and the undo.
//!
//! Roles are cluster-wide and the tests of every crate migrate in parallel on
//! one cluster, so nothing here grants `epigraph_bba_guard_owner`, or makes a
//! CREATEROLE role, outside a transaction that is rolled back.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended.

#[path = "support/maintenance_login.rs"]
mod login;

use sqlx::migrate::Migrator;
use sqlx::{Connection, Executor, PgPool};
use std::borrow::Cow;
use std::collections::BTreeSet;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

const OWNER: &str = "epigraph_bba_guard_owner";
const LEDGER: &str = "public.mass_function_purge_grants";
const RETRACT_GUARD: &str = "public.epigraph_mass_function_retract_guard()";
const DELETE_GUARD: &str = "public.mass_functions_retracted_delete_guard()";
const PURGE: &str = "public.epigraph_purge_mass_functions(uuid[], text)";
const UNRETRACT: &str = "public.epigraph_unretract_mass_function(uuid, text, uuid, uuid)";
const GRANTED: &str = "public.epigraph_mf_purge_granted(uuid)";
const GRANT_FN: &str = "public.epigraph_mf_guard_grant(text, uuid[], text, uuid)";
const CONSUME_FN: &str = "public.epigraph_mf_guard_consume(text, uuid, jsonb)";
const OWNER_PATH: &str = "search_path=pg_catalog, pg_temp";

/// The five bodies 251 re-states, as a database at 250 holds them:
/// `(signature, md5(prosrc), proconfig)`, measured by
/// `the_bodies_before_251_are_the_ones_it_restates`.
const BEFORE_251: &[(&str, &str, &[&str])] = &[
    (
        RETRACT_GUARD,
        "be48455cec9bc897f0f13473129c52ff",
        &["search_path=pg_catalog, public"],
    ),
    (
        DELETE_GUARD,
        "baf4285cd182aed1493a90a5eefef454",
        &["search_path=pg_catalog, pg_temp"],
    ),
    (
        GRANTED,
        "2ac6c54699fcbb785e624a377997247b",
        &["search_path=pg_catalog, pg_temp"],
    ),
    (
        PURGE,
        "85e75b8d2da5a4a1a97496c7303d0c83",
        &["search_path=pg_catalog, pg_temp"],
    ),
    (
        UNRETRACT,
        "3f0369e03257d9be2c1d62644c334c60",
        &[
            "search_path=pg_catalog, public, pg_temp",
            "epigraph.mf_unretract_id=",
        ],
    ),
];

/// The three functions the owner owns, and who may EXECUTE each:
/// `(signature, maintenance, application)`.
const OWNED: &[(&str, bool, bool)] = &[
    (GRANT_FN, true, false),
    (CONSUME_FN, true, true),
    (GRANTED, true, true),
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

/// `(md5(prosrc), proconfig, prosrc, owner, prosecdef)` of one function.
async fn facts<'e, E>(e: E, sig: &str) -> (String, Vec<String>, String, String, bool)
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as(
        "SELECT md5(p.prosrc), COALESCE(p.proconfig, ARRAY[]::text[]), p.prosrc, \
                pg_get_userbyid(p.proowner)::text, p.prosecdef \
           FROM pg_proc p WHERE p.oid = $1::regprocedure",
    )
    .bind(sig)
    .fetch_one(e)
    .await
    .unwrap_or_else(|err| panic!("{sig}: {err}"))
}

async fn applied(pool: &PgPool, version: i64) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
        .bind(version)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn ledger_has_kind<'e, E>(e: E) -> bool
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_attribute \
                         WHERE attrelid = 'public.mass_function_purge_grants'::regclass \
                           AND attname = 'kind' AND NOT attisdropped)",
    )
    .fetch_one(e)
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

/// The `public.<name>` tokens of a body.
fn public_names(src: &str) -> BTreeSet<String> {
    src.match_indices("public.")
        .map(|(i, _)| {
            src[i + "public.".len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect()
}

/// The measurement behind [`BEFORE_251`]: below 251 the five bodies are
/// 184's, 190's paths and 194's, the definers and the helper the maintenance
/// role's.
#[sqlx::test(migrations = false)]
async fn the_bodies_before_251_are_the_ones_it_restates(pool: PgPool) {
    migrate_below_251(&pool).await;
    for (sig, md5, config) in BEFORE_251 {
        let (got_md5, got_config, _, owner, _) = facts(&pool, sig).await;
        assert_eq!(&got_md5, md5, "md5(prosrc) of {sig} below 251");
        assert_eq!(got_config, *config, "proconfig of {sig} below 251");
        if [PURGE, UNRETRACT, GRANTED].contains(sig) {
            assert_eq!(owner, "epigraph_maintenance", "{sig}");
        }
    }
    let maint_insert: bool =
        sqlx::query_scalar("SELECT has_table_privilege('epigraph_maintenance', $1, 'INSERT')")
            .bind(LEDGER)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(maint_insert, "below 251 the maintenance role writes grants");
}

/// At head, what runs as the owner is exactly three definers on
/// `pg_catalog, pg_temp` whose bodies name no `public` object but the ledger,
/// and the ledger runs nothing (no trigger, no row security, defaults and
/// checks in `pg_catalog`). So no session can get its own code, or a function
/// it may `ALTER`, to run as the owner. The role is sound, the guards consume
/// grants, the definers stay the maintenance role's and write their grants
/// through the ledger function.
#[sqlx::test(migrations = "../../migrations")]
async fn at_head_only_the_ledger_functions_run_as_the_owner(pool: PgPool) {
    assert_eq!(faults(&pool).await, Vec::<String>::new(), "no fault");

    let role: (bool, bool, bool, bool, bool, bool) = sqlx::query_as(
        "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication \
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(OWNER)
    .fetch_one(&pool)
    .await
    .expect("251 creates the role");
    assert_eq!(role, (false, false, false, false, false, false), "{OWNER}");
    let memberships: Vec<String> = sqlx::query_scalar(
        "SELECT roleid::regrole::text FROM pg_auth_members WHERE member = $1::regrole",
    )
    .bind(OWNER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        memberships.is_empty(),
        "{OWNER} holds no role: {memberships:?}"
    );

    // Everything the owner owns in this database.
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT pg_describe_object(d.classid, d.objid, d.objsubid) FROM pg_shdepend d \
          WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = $1::regrole \
            AND d.deptype = 'o' \
            AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())) \
          ORDER BY 1",
    )
    .bind(OWNER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        owned,
        vec![
            "function epigraph_mf_guard_consume(text,uuid,jsonb)".to_string(),
            "function epigraph_mf_guard_grant(text,uuid[],text,uuid)".to_string(),
            "function epigraph_mf_purge_granted(uuid)".to_string(),
        ],
        "{OWNER} owns exactly the ledger's three functions"
    );
    for (sig, maint, app) in OWNED {
        let (_, config, src, owner, secdef) = facts(&pool, sig).await;
        assert_eq!(owner, OWNER, "{sig}");
        assert!(secdef, "{sig} is SECURITY DEFINER");
        assert_eq!(config, vec![OWNER_PATH.to_string()], "{sig}");
        assert_eq!(
            public_names(&src),
            BTreeSet::from(["mass_function_purge_grants".to_string()]),
            "{sig} names no public object but the ledger (so nothing it calls is a function \
             another role owns): {src}"
        );
        for (role, expected) in [
            ("epigraph_maintenance", *maint),
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

    // The ledger runs nothing as its writer.
    let triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger WHERE tgrelid = $1::regclass AND NOT tgisinternal",
    )
    .bind(LEDGER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(triggers.is_empty(), "triggers on the ledger: {triggers:?}");
    let rls: (bool, bool) = sqlx::query_as(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass",
    )
    .bind(LEDGER)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rls, (false, false), "no row security on the ledger");
    let outside_catalog: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.oid::regprocedure::text FROM pg_depend d \
           JOIN pg_proc p ON p.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass \
           LEFT JOIN pg_attrdef ad ON d.classid = 'pg_attrdef'::regclass AND ad.oid = d.objid \
           LEFT JOIN pg_constraint co ON d.classid = 'pg_constraint'::regclass AND co.oid = d.objid \
          WHERE COALESCE(ad.adrelid, co.conrelid) = $1::regclass \
            AND p.pronamespace <> 'pg_catalog'::regnamespace",
    )
    .bind(LEDGER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        outside_catalog.is_empty(),
        "the ledger's defaults and checks call functions outside pg_catalog: {outside_catalog:?}"
    );

    // The guards consume; the retract guard's path lists pg_temp last.
    let (_, config, src, _, secdef) = facts(&pool, RETRACT_GUARD).await;
    assert!(!secdef);
    assert_eq!(
        config,
        vec!["search_path=pg_catalog, public, pg_temp".to_string()],
        "the INVOKER retract guard searches pg_temp last"
    );
    assert!(
        src.contains(
            "public.epigraph_mf_guard_consume('unretract', OLD.id, pg_catalog.to_jsonb(OLD))"
        ),
        "{src}"
    );
    assert!(
        !src.contains("mf_unretract_id"),
        "the marker is not read: {src}"
    );
    let (_, config, src, _, _) = facts(&pool, DELETE_GUARD).await;
    assert_eq!(config, vec![OWNER_PATH.to_string()]);
    assert!(
        src.contains("public.epigraph_mf_guard_consume('purge', OLD.id, pg_catalog.to_jsonb(OLD))"),
        "{src}"
    );

    // The definers stay the maintenance role's and grant through the ledger.
    for (sig, kind) in [(PURGE, "'purge'"), (UNRETRACT, "'unretract'")] {
        let (_, _, src, owner, _) = facts(&pool, sig).await;
        assert_eq!(owner, "epigraph_maintenance", "{sig}");
        assert!(
            src.contains(&format!("public.epigraph_mf_guard_grant({kind}")),
            "{sig}: {src}"
        );
        assert!(
            !src.contains("INSERT INTO public.mass_function_purge_grants")
                && !src.contains("DELETE FROM public.mass_function_purge_grants")
                && !src.contains("set_config('epigraph.mf_unretract_id'"),
            "{sig} writes no grant and sets no marker itself: {src}"
        );
    }
}

/// The fault check is calibrated: each way the owner or the ledger could be
/// reached is named. All in one transaction that is rolled back, so no other
/// database of the cluster ever sees them.
#[sqlx::test(migrations = "../../migrations")]
async fn the_fault_check_names_every_way_to_reach_the_owner(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let r = |what: &str| format!("t63_{what}_{tag}");
    let (direct, middle, behind, admin, creator, writer, all_data) = (
        r("direct"),
        r("middle"),
        r("behind"),
        r("admin"),
        r("creator"),
        r("writer"),
        r("alldata"),
    );
    for sql in [
        format!("CREATE ROLE {direct} LOGIN NOSUPERUSER"),
        format!("GRANT {OWNER} TO {direct}"),
        format!("CREATE ROLE {middle} NOLOGIN NOSUPERUSER NOINHERIT"),
        format!("GRANT {OWNER} TO {middle} WITH INHERIT FALSE, SET TRUE"),
        format!("CREATE ROLE {behind} LOGIN NOSUPERUSER IN ROLE {middle}"),
        // PostgreSQL 16's ADMIN-only grant: neither INHERIT nor SET, yet its
        // holder may GRANT the role to itself with SET and then act as it.
        format!("CREATE ROLE {admin} LOGIN NOSUPERUSER"),
        format!("GRANT {OWNER} TO {admin} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE"),
        format!("CREATE ROLE {creator} LOGIN NOSUPERUSER CREATEROLE"),
        format!("CREATE ROLE {writer} LOGIN NOSUPERUSER"),
        format!("GRANT INSERT ON {LEDGER} TO {writer}"),
        format!("CREATE ROLE {all_data} LOGIN NOSUPERUSER IN ROLE pg_write_all_data"),
        format!("ALTER ROLE {OWNER} LOGIN"),
        format!("GRANT epigraph_maintenance TO {OWNER}"),
        format!("GRANT DELETE ON {LEDGER} TO {OWNER}"),
        format!("ALTER TABLE {LEDGER} ENABLE ROW LEVEL SECURITY"),
        "CREATE FUNCTION public.t63_extra() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RETURN NEW; END $$"
            .to_string(),
        format!("ALTER FUNCTION public.t63_extra() OWNER TO {OWNER}"),
        format!(
            "CREATE TRIGGER t63_on_ledger BEFORE INSERT ON {LEDGER} \
             FOR EACH ROW EXECUTE FUNCTION public.t63_extra()"
        ),
        format!("ALTER FUNCTION {CONSUME_FN} SECURITY INVOKER"),
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
        format!("{direct} is a member of {OWNER}"),
        format!("{middle} is a member of {OWNER}"),
        format!("{behind} is a member of {OWNER}"),
        format!("{admin} is a member of {OWNER}"),
        format!("{admin} holds ADMIN OPTION on {OWNER}"),
        format!("{creator} is a non-superuser CREATEROLE role"),
        format!("{writer} can write {LEDGER}"),
        format!("{all_data} can write {LEDGER}"),
        format!("{OWNER} can LOGIN"),
        format!("{OWNER} is a member of epigraph_maintenance"),
        format!("{OWNER} may UPDATE, DELETE or TRUNCATE {LEDGER}"),
        format!("row security is enabled on {LEDGER}"),
        format!("trigger t63_on_ledger on {LEDGER}"),
        format!("{OWNER} owns function public.t63_extra()"),
        format!("{CONSUME_FN} is not SECURITY DEFINER on search_path pg_catalog, pg_temp"),
    ] {
        assert!(found.contains(&want), "missing {want:?} in {found:#?}");
    }
    assert_eq!(faults(&pool).await, Vec::<String>::new(), "rolled back");
}

/// 251 refuses (55000, nothing changed) when the owner is reachable; here by
/// the ADMIN-only grant alone, which the first fix's check missed. In one
/// rolled-back transaction.
#[sqlx::test(migrations = false)]
async fn migration_251_refuses_an_owner_an_admin_grant_reaches(pool: PgPool) {
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
        tx.execute(format!("CREATE ROLE {OWNER} NOLOGIN").as_str())
            .await
            .expect("create the owner inside the transaction");
    }
    let admin = format!("t63_admin_{}", uuid::Uuid::new_v4().simple());
    tx.execute(format!("CREATE ROLE {admin} LOGIN NOSUPERUSER").as_str())
        .await
        .unwrap();
    tx.execute(
        format!("GRANT {OWNER} TO {admin} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE").as_str(),
    )
    .await
    .expect("an ADMIN-only grant");
    tx.execute("SAVEPOINT m251").await.unwrap();
    let r = sqlx::raw_sql(&m251).execute(&mut *tx).await;
    tx.execute("ROLLBACK TO SAVEPOINT m251").await.unwrap();
    let shape_after = ledger_has_kind(&mut *tx).await;
    let (_, _, _, granted_owner, _) = facts(&mut *tx, GRANTED).await;
    tx.rollback().await.unwrap();

    let e = r.expect_err("251 must refuse an owner an ADMIN-only grant reaches");
    let db = e.as_database_error().expect("a database error");
    assert_eq!(db.code().as_deref(), Some("55000"), "{e}");
    assert!(db.message().contains("not isolated"), "{e}");
    assert!(
        db.message()
            .contains(&format!("{admin} holds ADMIN OPTION on {OWNER}")),
        "{e}"
    );
    assert!(
        !shape_after,
        "nothing was changed: the ledger keeps 194's shape"
    );
    assert_eq!(
        granted_owner, "epigraph_maintenance",
        "nothing was re-owned"
    );
    assert!(!applied(&pool, 251).await);
}

/// An earlier draft of this change made the owner a member of
/// `epigraph_maintenance`; on a cluster where that draft ran, 251 revokes the
/// membership and applies sound. In one rolled-back transaction.
#[sqlx::test(migrations = false)]
async fn migration_251_revokes_the_maintenance_membership_an_earlier_draft_granted(pool: PgPool) {
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
        tx.execute(format!("CREATE ROLE {OWNER} NOLOGIN").as_str())
            .await
            .unwrap();
    }
    tx.execute(format!("GRANT epigraph_maintenance TO {OWNER}").as_str())
        .await
        .expect("the earlier draft's membership");
    sqlx::raw_sql(&m251)
        .execute(&mut *tx)
        .await
        .expect("251 applies over the earlier draft's role");
    let member: bool =
        sqlx::query_scalar("SELECT pg_has_role($1, 'epigraph_maintenance', 'MEMBER')")
            .bind(OWNER)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let found: Vec<String> =
        sqlx::query_scalar("SELECT unnest(public.epigraph_bba_guard_owner_faults())")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    assert!(!member, "the membership is revoked");
    assert!(found.is_empty(), "{found:?}");
}

/// 251 refuses (55000, nothing changed) over any of the five bodies it
/// re-states when that body is not the one at 250, and over one on another
/// path; it applies over the bodies at 250.
#[sqlx::test(migrations = false)]
async fn migration_251_refuses_to_apply_over_another_body(pool: PgPool) {
    migrate_below_251(&pool).await;

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

    for (sig, _, _) in BEFORE_251 {
        let original: String = sqlx::query_scalar("SELECT pg_get_functiondef($1::regprocedure)")
            .bind(sig)
            .fetch_one(&pool)
            .await
            .unwrap();
        let edited = original.replacen("BEGIN", "BEGIN\n    -- another migration's edit", 1);
        assert_ne!(edited, original, "{sig}");
        pool.execute(edited.as_str()).await.expect("re-body");
        assert_refused(migrate_rest(&pool).await, &format!("another body of {sig}"));
        assert!(!applied(&pool, 251).await);
        assert!(!ledger_has_kind(&pool).await, "nothing was changed");
        pool.execute(original.as_str()).await.expect("restore");
    }

    pool.execute(
        format!("ALTER FUNCTION {RETRACT_GUARD} SET search_path = public, pg_temp").as_str(),
    )
    .await
    .unwrap();
    assert_refused(migrate_rest(&pool).await, "184's guard on another path");
    assert!(!applied(&pool, 251).await);
    pool.execute(
        format!("ALTER FUNCTION {RETRACT_GUARD} SET search_path = pg_catalog, public").as_str(),
    )
    .await
    .unwrap();

    migrate_rest(&pool)
        .await
        .expect("251 applies over the bodies at 250");
    assert!(applied(&pool, 251).await);
    assert_eq!(faults(&pool).await, Vec::<String>::new());
}

/// `docs/runbooks/251-undo.sql` puts back the five bodies at 250 (their md5
/// and paths), 194's ledger shape, key and grants (so a maintenance login
/// writes a grant again: the residual is back, which is what undoing means),
/// the helper's maintenance ownership, and drops 251's three new functions;
/// it runs twice, over a ledger holding rows 194's key could not hold; and
/// 251's own text then applies again over the undone state.
#[sqlx::test(migrations = "../../migrations")]
async fn the_251_undo_restores_the_bodies_and_the_grant_table(pool: PgPool) {
    let undo = repo_file("docs/runbooks/251-undo.sql");
    let m251 = repo_file("migrations/251_retracted_bba_guard_owner.sql");

    // Two grants of one id in one transaction and an unretract grant: rows
    // 194's (mf_id, xact_id) key cannot hold.
    let mut tx = pool.begin().await.unwrap();
    tx.execute("SET LOCAL SESSION AUTHORIZATION epigraph_maintenance")
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4();
    for kind in ["purge", "purge", "unretract"] {
        sqlx::query("SELECT public.epigraph_mf_guard_grant($1, ARRAY[$2]::uuid[], 'undo', NULL)")
            .bind(kind)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();

    for _ in 0..2 {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .expect("the undo runs");
    }
    for (sig, md5, config) in BEFORE_251 {
        let (got_md5, got_config, _, owner, _) = facts(&pool, sig).await;
        assert_eq!(&got_md5, md5, "{sig} is restored");
        assert_eq!(got_config, *config, "{sig} path");
        if [PURGE, UNRETRACT, GRANTED].contains(sig) {
            assert_eq!(owner, "epigraph_maintenance", "{sig}");
        }
    }
    for (role, sig, expected) in [
        ("epigraph_maintenance", GRANTED, true),
        ("epigraph_app", GRANTED, true),
        ("epigraph_maintenance", PURGE, true),
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role)
            .bind(sig)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(can, expected, "{role} EXECUTE {sig} after the undo");
    }
    for sig in [
        GRANT_FN,
        CONSUME_FN,
        "public.epigraph_bba_guard_owner_faults()",
    ] {
        let gone: Option<String> = sqlx::query_scalar("SELECT to_regprocedure($1)::text")
            .bind(sig)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(gone.is_none(), "the undo drops {sig}");
    }
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = $1::regclass \
            AND attnum > 0 AND NOT attisdropped ORDER BY attnum",
    )
    .bind(LEDGER)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(columns, vec!["mf_id", "xact_id", "granted_by", "reason"]);
    let key: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = $1::regclass AND contype = 'p'",
    )
    .bind(LEDGER)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key, "PRIMARY KEY (mf_id, xact_id)");
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mass_function_purge_grants WHERE mf_id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kept, 1, "one purge grant per (id, transaction) is kept");

    let (role, login) = login::maintenance_login(&pool, "t63undo").await;
    let mut tx = login.begin().await.unwrap();
    let wrote = sqlx::query(
        "INSERT INTO public.mass_function_purge_grants (mf_id, reason) \
         VALUES (gen_random_uuid(), 'undone')",
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
    let maint_insert: bool =
        sqlx::query_scalar("SELECT has_table_privilege('epigraph_maintenance', $1, 'INSERT')")
            .bind(LEDGER)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !maint_insert,
        "the re-apply revokes the maintenance role's INSERT again"
    );
}
