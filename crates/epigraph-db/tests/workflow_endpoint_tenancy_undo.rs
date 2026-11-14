//! `docs/runbooks/219-undo.sql`, the rollback of migration 219 (a workflow
//! endpoint contributes its own tenancy to an edge's meet; the `evolve_step`
//! hidden-executor check).
//!
//! [`the_219_undo_returns_the_catalog_below_219`]: on a database migrated
//! through 219, the undo leaves the `public` catalog (relations, columns,
//! functions with their whole definition, owner and ACL, policies, triggers,
//! constraints) exactly as it was below 219, and a second run changes nothing.
//! Because functions are compared by the md5 of `pg_get_functiondef`, this
//! pins that the undo restores 070's `epigraph_node_tenancy` and 168's
//! `epigraph_propagate_tenancy` byte for byte (body, SECURITY DEFINER, pinned
//! `search_path`), with their owner and ACL.

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
/// owner and ACL), policies, triggers and constraints (the shape of
/// `agent_default_private_undo.rs`). A function is hashed
/// by its whole definition (`pg_get_functiondef`: SECURITY DEFINER, the pinned
/// `search_path`, volatility and body), not its body alone, so an undo that
/// restored 206's body without its definer attributes would be caught.
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

/// The undo returns the catalog to what it was below 219, and is idempotent.
/// Mutation: one character of the undo's re-statement of 168's propagation
/// body changed -> that function's md5 differs from the one below 219 and is
/// named in the diff.
#[sqlx::test(migrations = false)]
async fn the_219_undo_returns_the_catalog_below_219(pool: PgPool) {
    migrate(&pool, &up_to(218)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(219)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    let removed: BTreeSet<&String> = before.difference(&through).collect();
    assert_eq!(
        added.len(),
        3,
        "CALIBRATION: 219 re-states two functions and adds one: {added:?}"
    );
    for name in [
        "fn epigraph_node_tenancy(",
        "fn epigraph_propagate_tenancy(",
        "fn epigraph_step_lineage_has_hidden_executor(",
    ] {
        assert!(
            added.iter().any(|e| e.starts_with(name)),
            "CALIBRATION: 219 changes {name}: {added:?}"
        );
    }
    assert_eq!(
        removed.len(),
        2,
        "CALIBRATION: the only entries 219 changes are the two re-stated bodies: {removed:?}"
    );

    let undo = repo_file("docs/runbooks/219-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 219"
        );
    }
}
