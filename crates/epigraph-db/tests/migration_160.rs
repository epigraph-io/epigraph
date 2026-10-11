//! Migration 160: the elevation stack's final-review corrections, as a FILE.
//!
//! Each section's behaviour is pinned where its subject lives
//! (`pending_admin_acts.rs` for the completion guard). This file pins what
//! the migration as a whole promises: its undo returns the catalog to the
//! head before it, and every function it re-bodies is restored by that undo.

use sqlx::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// The head before 160: the highest migration below it, read from the
/// migrator so a later-merged predecessor (148, 149) moves it.
fn before_160() -> i64 {
    MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .filter(|v| *v < 160)
        .max()
        .expect("a migration precedes 160")
}

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

/// `docs/runbooks/160-undo.sql`, applied to a database that went from the
/// head before 160 to 160, returns its catalog (every function body, owner and
/// ACL included) to the same database's before 160. A second run changes
/// nothing.
///
/// Verified to fail: the undo's restoration of 124's completion guard
/// removed -> 160's body (md5) is left behind.
#[sqlx::test(migrations = false)]
async fn the_160_rollback_returns_the_catalog_to_the_head_before_it(pool: PgPool) {
    migrate(&pool, &up_to(before_160())).await;
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
        "the catalog is not the pre-160 head's after the undo; left behind: {left:?}; lost: {lost:?}"
    );
}

/// 160-undo leaves a gate 132-undo closed CLOSED (final review F2-COR-01):
/// the kill switch (132-undo, run FIRST) restores 125's `SELECT false`, and
/// 160-undo, run after it (twice: it is idempotent), restores 132's readiness
/// test only over 160's own body, so elevation stays closed. Calibration:
/// the gate is open at 160 (the recorder is installed and maintenance-owned).
///
/// Verified to fail with 160-undo restoring 132's gate unconditionally (the
/// code before this test): the gate reads true again after 160-undo.
#[sqlx::test(migrations = false)]
async fn the_160_undo_leaves_a_gate_132_undo_closed_closed(pool: PgPool) {
    migrate(&pool, &up_to(160)).await;
    let ready = |pool: PgPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT public.epigraph_elevated_access_ready()")
            .fetch_one(&pool)
            .await
            .expect("the gate")
    };
    assert!(ready(pool.clone()).await, "CALIBRATION: open at 160");
    sqlx::raw_sql(&read("docs/runbooks/132-undo.sql"))
        .execute(&pool)
        .await
        .expect("132-undo applies");
    assert!(
        !ready(pool.clone()).await,
        "CALIBRATION: 132-undo closes it"
    );
    for run in 1..=2 {
        sqlx::raw_sql(&read("docs/runbooks/160-undo.sql"))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("160-undo applies (run {run}): {e}"));
        assert!(
            !ready(pool.clone()).await,
            "160-undo run {run} left the closed gate closed"
        );
    }
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

/// The functions 160 CREATES, with the statement its undo drops each with.
/// (`epigraph_complete_passkey_enrollment` keeps 124's seven-argument form;
/// 160 adds the nine-argument overload.)
const NEW_IN_160: &[(&str, &str)] = &[
    (
        "epigraph_person_authenticators_registration_fixed",
        "DROP FUNCTION IF EXISTS public.epigraph_person_authenticators_registration_fixed();",
    ),
    (
        "epigraph_complete_passkey_enrollment",
        "DROP FUNCTION IF EXISTS public.epigraph_complete_passkey_enrollment(\n    \
         uuid, bytea, jsonb, uuid, text, boolean, boolean, jsonb, jsonb);",
    ),
];

/// Every function 160 re-bodies is restored by its undo, every function it
/// creates is dropped by it, and the undo restores nothing else.
///
/// Verified to fail: a function re-bodied by 160 and left out of the undo
/// (named here); the new overload's DROP removed from the undo.
#[test]
fn every_160_function_is_restored_or_dropped_by_its_undo() {
    let migration_sql = read("migrations/160_elevation_final_review.sql");
    let undo_sql = read("docs/runbooks/160-undo.sql");
    let rebodied: Vec<String> = functions_in(&migration_sql)
        .into_iter()
        .filter(|f| !NEW_IN_160.iter().any(|(n, _)| n == f))
        .collect();
    assert!(!rebodied.is_empty(), "CALIBRATION: 160 re-bodies functions");
    assert_eq!(
        rebodied,
        functions_in(&undo_sql),
        "160 re-bodies exactly what its undo restores"
    );
    for (name, drop) in NEW_IN_160 {
        assert!(undo_sql.contains(drop), "the undo drops 160's new {name}");
    }
}
