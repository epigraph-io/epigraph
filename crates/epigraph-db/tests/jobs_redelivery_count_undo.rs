//! `docs/runbooks/220-undo.sql`, the rollback of migration 220 (the crash
//! re-delivery counter on `jobs`, backlog 1320b4e3).
//!
//! On a database migrated through 220, the undo leaves the `public` catalog
//! (relations, `jobs` columns with type, nullability and default, and
//! constraints) exactly as it was below 220, and a second run changes nothing.

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

/// The undo returns the catalog to what it was below 220, and is idempotent.
#[sqlx::test(migrations = false)]
async fn the_220_undo_returns_the_catalog_below_220(pool: PgPool) {
    migrate(&pool, &up_to(219)).await;
    let before = catalog(&pool).await;
    migrate(&pool, &up_to(220)).await;
    let through = catalog(&pool).await;
    let added: BTreeSet<&String> = through.difference(&before).collect();
    assert_eq!(
        added,
        BTreeSet::from([
            &"col jobs.redelivery_count integer true 0".to_string(),
            &"con jobs.jobs_redelivery_count_non_negative CHECK ((redelivery_count >= 0))"
                .to_string(),
        ]),
        "CALIBRATION: 220 adds exactly its column and its CHECK"
    );
    assert!(
        before.difference(&through).next().is_none(),
        "CALIBRATION: 220 removes nothing"
    );

    let undo = repo_file("docs/runbooks/220-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 220"
        );
    }
}
