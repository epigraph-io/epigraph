//! `docs/runbooks/217-undo.sql`, the rollback of migration 217 (factors
//! written by the database's own triggers, backlog a2c5f714).
//!
//! [`the_217_undo_returns_the_catalog_below_217`]: on a database migrated
//! through 217, the undo leaves the `public` catalog (functions with their
//! whole definition, owner and ACL; triggers; the table and column ACLs of
//! `factors`) exactly as it was below 217, and a second run changes nothing.
//! Because functions are compared by `md5(pg_get_functiondef)`, this pins
//! that the undo restores 038's mint and 001's clear byte for byte, as
//! SECURITY INVOKER bodies with no pinned `search_path`.
//!
//! ACLs are compared as sets of entries with a NULL ACL read as its default
//! (`acldefault`), and an empty column ACL as none: granting back what a
//! REVOKE took leaves the same privileges in a different array order, which
//! is not a difference anyone can observe.

use sqlx::PgPool;
use std::collections::BTreeSet;

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

async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                               FROM unnest(COALESCE(p.proacl, acldefault('f', p.proowner))) x), \
                            '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname || ' ' || t.tgfoid::regprocedure::text \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'acl factors ' || COALESCE((SELECT string_agg(x::text, ',' ORDER BY x::text) \
                                              FROM unnest(c.relacl) x), '-') \
           FROM pg_class c WHERE c.oid = 'public.factors'::regclass \
         UNION ALL \
         SELECT 'colacl factors.' || a.attname || ' ' || \
                (SELECT string_agg(x::text, ',' ORDER BY x::text) FROM unnest(a.attacl) x) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.factors'::regclass AND a.attnum > 0 \
            AND NOT a.attisdropped AND cardinality(a.attacl) > 0",
    )
    .fetch_all(pool)
    .await
    .expect("catalog");
    rows.into_iter().collect()
}

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The undo returns the catalog to what it was below 217, and is idempotent.
/// Mutation: the undo's re-statement of 038's mint edited by one character, or
/// its owner step dropped -> the mint's entry differs from the one below 217.
#[sqlx::test(migrations = false)]
async fn the_217_undo_returns_the_catalog_below_217(pool: PgPool) {
    migrate(&pool, &up_to(216)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(217)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        4,
        "CALIBRATION: 217 re-states two functions, narrows the factors ACL and adds one \
         column grant: {added:?}"
    );
    assert_eq!(
        removed.len(),
        3,
        "CALIBRATION: 217 changes the two functions and the factors ACL: {removed:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("colacl factors.frame_id epigraph_app=w/")),
        "CALIBRATION: 217 grants epigraph_app UPDATE on frame_id: {added:?}"
    );

    let undo = repo_file("docs/runbooks/217-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 217"
        );
    }
}
