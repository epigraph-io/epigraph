//! A database that stopped at the PRODUCTION head and then applied the rest
//! must end in the SAME schema as a fresh 001 -> head install.
//!
//! # Why this exists
//!
//! sqlx applies every pending version in ascending order. A migration numbered
//! BELOW a version production has already applied would therefore run on
//! production AFTER it, while a fresh install runs it BEFORE: two orders, and
//! nothing that says they converge. The operator-ownership branch hit exactly
//! that — authored as 102-104 while batch F shipped 105/106 to production — and
//! renumbered to 107-109 (migrations/README.md, "Why 107-109"). This test pins
//! the property the renumber restored, and keeps pinning it for whatever lands
//! next: it migrates one database to [`PRODUCTION_HEAD`], then to head, and
//! compares it with a second database migrated straight to head.
//!
//! # What is compared
//!
//! Catalog state by NAME, never by OID: policies (command, roles, permissive,
//! USING, WITH CHECK), every non-system function (identity arguments, body,
//! SECURITY DEFINER, `proconfig`, owner, ACL), every relation's kind, owner, ACL
//! and RLS/FORCE flags, columns (type, default, nullability), constraints
//! (`pg_get_constraintdef`), indexes (`pg_get_indexdef`), triggers
//! (`pg_get_triggerdef` plus `tgenabled`), and the `_sqlx_migrations` version and
//! checksum list. The comparison is CALIBRATED in-test: a stray GRANT and a
//! disabled trigger on one side must both show up in the diff.
//!
//! # What it cannot prove
//!
//! It compares two databases this suite built. Production also carries state no
//! migration created (the orphan `claims_privacy` / `evidence_privacy` /
//! `edges_privacy` policies, the dropped 013 constraint, and roles or grants
//! made by hand), and that drift is outside anything a throwaway can model.
//!
//! Uses the non-macro `sqlx::query` forms so the offline `.sqlx/` cache is not
//! extended for one test.

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use std::borrow::Cow;
use std::collections::BTreeSet;

/// The last version production has applied: `main` at a3fbc4ce (#498 + #499,
/// batch F), which shipped 105 and 106. Raise it when production moves.
const PRODUCTION_HEAD: i64 = 106;

/// How many migration files at or below [`PRODUCTION_HEAD`] production has
/// applied (measured: `_sqlx_migrations` after `sqlx migrate run
/// --target-version 106` of `main` a3fbc4ce holds 95 rows). A NEW file numbered
/// at or below the production head changes this count, and is exactly the
/// hazard this test exists for: production would apply it AFTER versions it
/// already has, while a fresh install applies it before them. Raise it only
/// together with [`PRODUCTION_HEAD`].
const ON_PRODUCTION: usize = 95;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// The embedded migrator, cut at `max` (inclusive).
fn up_to(max: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
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

/// One text line per catalog fact, keyed by name. Sorted and de-duplicated by
/// the set, so the order the catalog returns rows in cannot matter.
async fn snapshot(pool: &PgPool) -> BTreeSet<String> {
    const QUERIES: &[(&str, &str)] = &[
        (
            "policy",
            "SELECT format('%s.%s %s cmd=%s permissive=%s roles=%s using=%s check=%s',
                    schemaname, tablename, policyname, cmd, permissive, roles::text,
                    coalesce(qual, '-'), coalesce(with_check, '-'))
               FROM pg_policies",
        ),
        (
            "function",
            "SELECT format('%s.%s(%s) definer=%s config=%s owner=%s acl=%s volatile=%s body=%s',
                    n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
                    p.prosecdef, coalesce(p.proconfig::text, '-'),
                    pg_get_userbyid(p.proowner), coalesce(p.proacl::text, '-'),
                    p.provolatile, md5(p.prosrc))
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND n.nspname NOT LIKE 'pg_toast%'",
        ),
        (
            "relation",
            "SELECT format('%s.%s kind=%s owner=%s acl=%s rls=%s force=%s',
                    n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner),
                    coalesce(c.relacl::text, '-'), c.relrowsecurity, c.relforcerowsecurity)
               FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
                AND n.nspname NOT LIKE 'pg_toast%'",
        ),
        (
            "column",
            "SELECT format('%s.%s.%s type=%s default=%s nullable=%s',
                    table_schema, table_name, column_name, data_type,
                    coalesce(column_default, '-'), is_nullable)
               FROM information_schema.columns
              WHERE table_schema NOT IN ('pg_catalog', 'information_schema')",
        ),
        (
            "constraint",
            "SELECT format('%s %s %s', conrelid::regclass::text, conname, pg_get_constraintdef(oid))
               FROM pg_constraint
              WHERE connamespace NOT IN ('pg_catalog'::regnamespace,
                                         'information_schema'::regnamespace)",
        ),
        (
            "index",
            "SELECT format('%s.%s %s', schemaname, indexname, indexdef)
               FROM pg_indexes
              WHERE schemaname NOT IN ('pg_catalog', 'information_schema')",
        ),
        (
            "trigger",
            "SELECT format('%s enabled=%s', pg_get_triggerdef(t.oid), t.tgenabled)
               FROM pg_trigger t WHERE NOT t.tgisinternal",
        ),
        (
            "extension",
            "SELECT format('%s %s', extname, extversion) FROM pg_extension",
        ),
        (
            "migration",
            "SELECT format('%s %s %s', version, success, encode(checksum, 'hex'))
               FROM _sqlx_migrations",
        ),
    ];
    let mut out = BTreeSet::new();
    for (kind, sql) in QUERIES {
        let rows: Vec<String> = sqlx::query_scalar(sql)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|e| panic!("snapshot {kind}: {e}"));
        assert!(!rows.is_empty(), "snapshot {kind} read nothing");
        out.extend(rows.into_iter().map(|r| format!("{kind} {r}")));
    }
    out
}

fn diff(a: &BTreeSet<String>, b: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        a.difference(b).cloned().collect(),
        b.difference(a).cloned().collect(),
    )
}

async fn head(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
        .fetch_one(pool)
        .await
        .expect("head")
}

#[sqlx::test(migrations = false)]
async fn an_upgrade_from_the_production_head_equals_a_fresh_install(pool: PgPool) {
    let tree_head = MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migrations");
    assert!(
        tree_head > PRODUCTION_HEAD,
        "PREMISE: the tree must carry migrations production has not applied \
         (tree head {tree_head}, production head {PRODUCTION_HEAD}); raise PRODUCTION_HEAD \
         only when production moves"
    );
    let at_or_below: Vec<i64> = MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .filter(|v| *v <= PRODUCTION_HEAD)
        .collect();
    assert_eq!(
        at_or_below.len(),
        ON_PRODUCTION,
        "the tree carries {} migrations at or below the production head {PRODUCTION_HEAD}, and \
         production has applied {ON_PRODUCTION}. A migration numbered at or below a version \
         production already has runs there AFTER that version but on a fresh install BEFORE \
         it: renumber it above {PRODUCTION_HEAD} (migrations/README.md, \"Why 107-109\"). \
         Versions: {at_or_below:?}",
        at_or_below.len()
    );

    // The UPGRADE path, on this test's own database: stop at production's
    // head, exactly as production is, then apply every pending version.
    up_to(PRODUCTION_HEAD)
        .run(&pool)
        .await
        .expect("migrate 001 -> production head");
    assert_eq!(head(&pool).await, PRODUCTION_HEAD);
    MIGRATOR
        .run(&pool)
        .await
        .expect("migrate production head -> tree head");
    assert_eq!(head(&pool).await, tree_head);

    // The FRESH path, on a sibling database on the same cluster (same roles,
    // which the migrations' `IF EXISTS (… pg_roles …)` blocks read).
    // A fresh name, not `<current>_fresh`: sqlx's test database names already
    // sit at NAMEDATALEN (63), so a suffix is truncated back onto the current
    // database's own name (measured: "cannot drop the currently open
    // database"). `*_test`, like every throwaway on the test cluster.
    let fresh_name = format!("upgrade_equiv_{}_test", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{fresh_name}\""))
        .execute(&pool)
        .await
        .expect("create the fresh sibling");
    let opts: PgConnectOptions = pool
        .connect_options()
        .as_ref()
        .clone()
        .database(&fresh_name);
    let fresh = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(opts)
        .await
        .expect("connect to the fresh sibling");
    MIGRATOR
        .run(&fresh)
        .await
        .expect("migrate the fresh sibling 001 -> tree head");

    let upgraded = snapshot(&pool).await;
    let installed = snapshot(&fresh).await;
    let (only_upgraded, only_fresh) = diff(&upgraded, &installed);

    // CALIBRATION: two known differences on the fresh side must both surface.
    sqlx::query("GRANT INSERT ON public.operator_links TO PUBLIC")
        .execute(&fresh)
        .await
        .expect("calibration grant");
    sqlx::query(
        "ALTER TABLE public.group_memberships \
         DISABLE TRIGGER group_memberships_no_retired_writer",
    )
    .execute(&fresh)
    .await
    .expect("calibration trigger");
    let perturbed = snapshot(&fresh).await;
    let (_, cal) = diff(&installed, &perturbed);
    let seen_grant = cal
        .iter()
        .any(|l| l.starts_with("relation public.operator_links "));
    let seen_trigger = cal
        .iter()
        .any(|l| l.starts_with("trigger ") && l.contains("group_memberships_no_retired_writer"));

    fresh.close().await;
    sqlx::query(&format!("DROP DATABASE \"{fresh_name}\" WITH (FORCE)"))
        .execute(&pool)
        .await
        .expect("drop the fresh sibling");

    assert!(
        seen_grant && seen_trigger,
        "CALIBRATION: the snapshot must see a stray grant ({seen_grant}) and a disabled \
         trigger ({seen_trigger}); it saw {cal:#?}"
    );
    assert!(
        only_upgraded.is_empty() && only_fresh.is_empty(),
        "a database upgraded from the production head ({PRODUCTION_HEAD}) differs from a fresh \
         install.\nONLY ON THE UPGRADED DATABASE: {only_upgraded:#?}\nONLY ON THE FRESH \
         DATABASE: {only_fresh:#?}"
    );
    assert!(
        upgraded.len() > 1000,
        "PREMISE: the snapshot covers the schema ({} facts)",
        upgraded.len()
    );
}
