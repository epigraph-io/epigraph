//! Migration 160: the elevation stack's final-review corrections, as a FILE.
//!
//! Each section's behaviour is pinned where its subject lives
//! (`pending_admin_acts.rs` for the completion guard). This file pins what
//! the migration as a whole promises: its undo returns the catalog to the
//! head before it, and every function it re-bodies is restored by that undo.

use sqlx::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The head before 160.
const BEFORE_160: i64 = 144;

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
/// session-level SETs behind (viewer_fixture::db_at_122_then_head).
async fn migrate(pool: &PgPool, migrator: &sqlx::migrate::Migrator) {
    let mut conn = pool.acquire().await.expect("acquire");
    migrator.run(&mut *conn).await.expect("migrate");
    sqlx::query("RESET ALL")
        .execute(&mut *conn)
        .await
        .expect("RESET ALL");
}

/// Relations, functions (body, owner and ACL), policies, triggers and
/// constraints in `public`, by name.
async fn catalog(pool: &PgPool) -> std::collections::BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'fn ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ') ' \
                || md5(p.prosrc) || ' ' || p.proowner::regrole::text || ' ' \
                || coalesce(p.proacl::text, '-') \
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

fn read(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// `docs/runbooks/160-undo.sql`, applied to a database that went 144 -> 160,
/// returns its catalog (every function body, owner and ACL included) to the
/// same database's at 144. A second run changes nothing.
///
/// Verified to fail: the undo's restoration of 124's completion guard
/// removed -> 160's body (md5) is left behind.
#[sqlx::test(migrations = false)]
async fn the_160_rollback_returns_the_catalog_to_144(pool: PgPool) {
    migrate(&pool, &up_to(BEFORE_160)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(160)).await;
    assert_ne!(
        catalog(&pool).await,
        before,
        "CALIBRATION: 160 changed the catalog"
    );
    for run in 1..=2 {
        sqlx::raw_sql(&read("docs/runbooks/160-undo.sql"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the undo script applies (run {run}): {e}"));
    }
    let after = catalog(&pool).await;
    let left: Vec<&String> = after.difference(&before).collect();
    let lost: Vec<&String> = before.difference(&after).collect();
    assert!(
        left.is_empty() && lost.is_empty(),
        "the catalog is not 144's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
}

/// The functions a SQL text defines in `public` (`CREATE OR REPLACE
/// FUNCTION public.<name>`), sorted, deduplicated.
fn functions_in(sql: &str) -> Vec<String> {
    let needle = "CREATE OR REPLACE FUNCTION public.";
    let mut out: Vec<String> = sql
        .match_indices(needle)
        .map(|(i, _)| {
            sql[i + needle.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Every function 160 re-bodies is restored by its undo, and the undo
/// restores nothing else.
///
/// Verified to fail: a function re-bodied by 160 and left out of the undo
/// (named here).
#[test]
fn every_160_function_is_restored_by_its_undo() {
    let migration = functions_in(&read("migrations/160_elevation_final_review.sql"));
    let undo = functions_in(&read("docs/runbooks/160-undo.sql"));
    assert!(!migration.is_empty(), "CALIBRATION: 160 defines functions");
    assert_eq!(
        migration, undo,
        "160 re-bodies exactly what its undo restores"
    );
}
