//! `docs/runbooks/209-undo.sql`, the rollback of migration 209 (an agent's
//! private default; the operator's setter).
//!
//! [`the_209_undo_returns_the_catalog_below_209`]: on a database migrated
//! through 209, the undo leaves the `public` catalog (relations, columns,
//! functions with body, owner and ACL, policies, triggers, constraints)
//! exactly as it was below 209, and a second run changes nothing. Because the
//! catalog compares function bodies by md5, this also pins that the undo
//! restores 206's `epigraph_set_default_group` body byte for byte, which 209
//! re-states.

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

/// The `public` catalog by name: relations, `agents` columns, functions (body,
/// owner and ACL), policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col agents.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.agents'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text || ' ' \
                || COALESCE(p.proacl::text, '-') \
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'pol ' || c.relname || '.' || pol.polname \
           FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid \
          WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'trg ' || c.relname || '.' || t.tgname \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE NOT t.tgisinternal AND c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname \
           FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
          WHERE c.relnamespace = 'public'::regnamespace",
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

/// The undo returns the catalog to what it was below 209, and is idempotent.
/// Mutation: the undo's re-statement of 206's setter dropped, or edited by one
/// character -> the setter's body md5 differs from the one below 209 and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_209_undo_returns_the_catalog_below_209(pool: PgPool) {
    migrate(&pool, &up_to(208)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(209)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        5,
        "CALIBRATION: 209 adds its column, its CHECK, two functions, and re-states 206's \
         setter: {added:?}"
    );
    assert!(
        added
            .iter()
            .any(|e| e.starts_with("fn epigraph_set_default_group(p_group uuid)")),
        "CALIBRATION: 209 re-states 206's setter: {added:?}"
    );
    assert_eq!(
        removed.len(),
        1,
        "CALIBRATION: the only entry 209 changes is 206's setter body: {removed:?}"
    );

    let undo = repo_file("docs/runbooks/209-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 209"
        );
    }
}
