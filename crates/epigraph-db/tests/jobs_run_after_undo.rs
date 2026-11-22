//! `docs/runbooks/261-undo.sql`, the rollback of migration 261 (the drain's
//! not-before time on `jobs`, backlog 6cf042a9).
//!
//! On a database migrated through 261, the undo leaves the `public` catalog
//! (relations, `jobs` columns with type, nullability and default, and
//! constraints) exactly as it was below 261, and a second run changes nothing.

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
        "SELECT 'rel ' || c.relname || ' ' || c.relkind::text \
           FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace \
         UNION ALL \
         SELECT 'col jobs.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
                || ' ' || a.attnotnull::text || ' ' \
                || COALESCE(pg_get_expr(d.adbin, d.adrelid), '-') \
           FROM pg_attribute a \
           LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
          WHERE a.attrelid = 'public.jobs'::regclass AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'con ' || c.relname || '.' || k.conname || ' ' || pg_get_constraintdef(k.oid) \
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

/// The undo returns the catalog to what it was below 261, and is idempotent.
/// The baseline is 260, not the highest migration on the branch that added
/// 261: slots below it may land later, and must not count as 261's change.
#[sqlx::test(migrations = false)]
async fn the_261_undo_returns_the_catalog_below_261(pool: PgPool) {
    migrate(&pool, &up_to(260)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(261)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    assert_eq!(
        added,
        BTreeSet::from([&"col jobs.run_after timestamp with time zone false -".to_string()]),
        "CALIBRATION: 261 adds exactly its nullable, default-less column"
    );
    assert!(
        before.difference(&through).next().is_none(),
        "CALIBRATION: 261 removes nothing"
    );

    let undo = repo_file("docs/runbooks/261-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 261"
        );
    }
}
