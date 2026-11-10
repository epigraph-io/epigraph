//! `docs/runbooks/206-undo.sql`, the rollback of migration 206 (claim
//! visibility controls).
//!
//! * [`the_206_undo_returns_the_catalog_below_206`]: on a database migrated
//!   through 206, the undo leaves the `public` catalog (relations, functions
//!   with body, owner and ACL, policies, triggers, constraints) exactly as it
//!   was below 206, and a second run changes nothing.
//! * [`the_206_undo_drops_every_function_206_creates`]: every function the
//!   migration creates has its `DROP FUNCTION IF EXISTS` in the undo, by the
//!   signature the migration grants, so a function added to 206 later cannot
//!   be left out of its rollback unnoticed.

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

/// The `public` catalog by name: relations, functions (body, owner and ACL),
/// policies, triggers and constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
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
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The undo returns the catalog to what it was below 206, and is idempotent.
/// Mutation: any one of its five DROPs removed -> that function is left behind
/// and named in the diff.
#[sqlx::test(migrations = false)]
async fn the_206_undo_returns_the_catalog_below_206(pool: PgPool) {
    migrate(&pool, &up_to(205)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(206)).await;
    let through_206 = catalog(&pool).await;
    let added: BTreeSet<&String> = through_206.difference(&before).collect();
    assert_eq!(
        added.len(),
        5,
        "CALIBRATION: 206 adds exactly its five functions: {added:?}"
    );
    assert!(
        before.is_subset(&through_206),
        "CALIBRATION: 206 changes nothing that existed below it"
    );

    let undo = repo_file("docs/runbooks/206-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 206"
        );
    }
}

/// Every `CREATE OR REPLACE FUNCTION public.<name>(<args>)` in migration 206
/// has `DROP FUNCTION IF EXISTS public.<name>(<args>)` in the undo, with the
/// same argument types, and the undo drops nothing else.
#[test]
fn the_206_undo_drops_every_function_206_creates() {
    let migration = repo_file("migrations/206_claim_visibility_controls.sql");
    let undo = repo_file("docs/runbooks/206-undo.sql");

    // The signatures 206 grants (its section 6 names each one with its
    // argument types).
    let mut created = BTreeSet::new();
    let mut rest = migration.as_str();
    while let Some(i) = rest.find("GRANT EXECUTE ON FUNCTION public.") {
        let after = &rest[i + "GRANT EXECUTE ON FUNCTION ".len()..];
        let end = after.find(')').expect("a closing parenthesis");
        let sig: String = after[..=end]
            .replace('\'', "")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("( ", "(");
        created.insert(sig);
        rest = &after[end..];
    }
    let names = migration.matches("CREATE OR REPLACE FUNCTION public.").count();
    assert_eq!(
        (created.len(), names),
        (5, 5),
        "CALIBRATION: 206 creates five functions and grants each: {created:?}"
    );

    let dropped: BTreeSet<String> = undo
        .lines()
        .filter_map(|l| l.trim().strip_prefix("DROP FUNCTION IF EXISTS "))
        .map(|s| s.trim_end_matches(';').to_string())
        .collect();
    assert_eq!(
        dropped, created,
        "206-undo.sql drops exactly the functions 206 creates, by signature"
    );
}
