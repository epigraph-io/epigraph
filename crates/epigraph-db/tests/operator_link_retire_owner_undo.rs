//! `docs/runbooks/257-undo.sql`, the rollback of migration 257 (the retire
//! verb's dedicated owner role; backlog 9cec11f7).
//!
//! [`the_257_undo_returns_the_catalog_below_257`]: on a database migrated to
//! head, the undo leaves the `public` functions (whole definition, owner and
//! ACL), the triggers and policies, and `operator_links`' table and column
//! ACLs exactly as they were below 257, and a second run changes nothing.
//! The function entries compare `pg_get_functiondef` by md5, so this also
//! pins that the undo restores 191's bodies byte for byte, and the verb's
//! owner and grants.

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

/// Functions (definition md5, owner, ACL), policies, triggers, and the
/// table and column ACLs of `operator_links`.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || CASE WHEN p.prokind IN ('f', 'p') THEN md5(pg_get_functiondef(p.oid)) \
                        ELSE md5(p.prosrc) END \
                || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname || ' ' || t.tgtype::text \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'acl operator_links ' || COALESCE(c.relacl::text, '-') \
           FROM pg_class c WHERE c.oid = 'public.operator_links'::regclass \
         UNION ALL \
         SELECT 'acl operator_links.' || a.attname || ' ' || COALESCE(a.attacl::text, '-') \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.operator_links'::regclass AND a.attnum > 0 \
            AND NOT a.attisdropped",
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

/// The undo returns the catalog to what it was below 257, and is idempotent.
///
/// Verified to fail: the undo's `ALTER FUNCTION .. OWNER TO
/// epigraph_maintenance` dropped -> the verb's entry keeps 257's owner and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_257_undo_returns_the_catalog_below_257(pool: PgPool) {
    migrate(&pool, &up_to(256)).await;
    let before = catalog(&pool).await;
    // Through 257 only, not the whole migrator: a later migration that adds a
    // public function, policy or trigger would otherwise show up in the
    // post-undo diff and fail this test for a reason that is not 257's.
    migrate(&pool, &up_to(257)).await;
    let through = catalog(&pool).await;
    let added: Vec<&String> = through.difference(&before).collect();
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("fn epigraph_retire_operator_link(")
                && e.contains("epigraph_operator_link_retirer")),
        "CALIBRATION: 257 re-owns the verb: {added:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("fn epigraph_operator_links_retire_only()")),
        "CALIBRATION: 257 re-bodies the guard: {added:?}"
    );

    let undo = repo_file("docs/runbooks/257-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 257"
        );
    }
}
