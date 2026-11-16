//! Migration 222 (`cluster_centroids.umap_centroid vector(32)`, backlog
//! 58452334) and its undo, `docs/runbooks/222-undo.sql`.
//!
//! [`migration_222_backfills_padded_rows_and_its_undo_restores_the_catalog`]:
//! on a database migrated below 222 that holds a padded 32-d centroid (the
//! only shape `scripts/cluster_claims.py` wrote) and a row with a non-zero
//! tail, 222 backfills the first into a vector(32) and leaves the second NULL;
//! a post-222 row may leave `centroid` NULL but not both columns; the undo
//! re-pads that row, returns the catalog to what it was below 222, and a
//! second run changes nothing.

use sqlx::PgPool;
use std::collections::BTreeSet;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

fn below(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version < version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .migrations
                .iter()
                .filter(|m| m.version <= version)
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

/// `cluster_centroids` by name: columns (type, nullability, comment) and
/// constraints.
async fn catalog(pool: &PgPool) -> BTreeSet<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT 'col ' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) \
                || CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END \
                || ' comment=' || COALESCE(col_description(a.attrelid, a.attnum), '-') \
           FROM pg_attribute a \
          WHERE a.attrelid = 'public.cluster_centroids'::regclass \
            AND a.attnum > 0 AND NOT a.attisdropped \
         UNION ALL \
         SELECT 'con ' || k.conname || ' ' || pg_get_constraintdef(k.oid) \
           FROM pg_constraint k WHERE k.conrelid = 'public.cluster_centroids'::regclass",
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

/// A pgvector literal of `len` elements: `head` first, then `tail_at` set to
/// 1 when given, the rest zero.
fn vector_literal(head: &[f32], len: usize, tail_at: Option<usize>) -> String {
    let mut v = vec![0.0_f32; len];
    v[..head.len()].copy_from_slice(head);
    if let Some(i) = tail_at {
        v[i] = 1.0;
    }
    format!(
        "[{}]",
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn insert_padded(pool: &PgPool, cluster_id: i32, centroid: &str) {
    sqlx::query(
        "INSERT INTO cluster_centroids (cluster_run_id, cluster_id, centroid) \
         VALUES ('00000000-0000-0000-0000-000000000222', $1, $2::vector)",
    )
    .bind(cluster_id)
    .bind(centroid)
    .execute(pool)
    .await
    .expect("insert a pre-222 row");
}

#[sqlx::test(migrations = false)]
async fn migration_222_backfills_padded_rows_and_its_undo_restores_the_catalog(pool: PgPool) {
    migrate(&pool, &below(222)).await;
    let before = catalog(&pool).await;
    let head: Vec<f32> = (1..=32).map(|i| i as f32 / 64.0).collect();
    insert_padded(&pool, 0, &vector_literal(&head, 1536, None)).await;
    // Element 41 set: not a padded 32-d centroid.
    insert_padded(&pool, 1, &vector_literal(&head, 1536, Some(40))).await;

    migrate(&pool, &through(222)).await;
    let after_222 = catalog(&pool).await;
    assert!(
        after_222
            .iter()
            .any(|e| e.starts_with("col umap_centroid vector(32) comment=")),
        "222 adds a nullable vector(32): {after_222:?}"
    );
    assert!(
        after_222
            .iter()
            .any(|e| e.starts_with("col centroid vector(1536) comment=")),
        "222 makes the legacy column nullable: {after_222:?}"
    );

    let backfilled: Vec<(i32, Option<i32>, bool)> = sqlx::query_as(
        "SELECT cluster_id, vector_dims(umap_centroid), \
                COALESCE(umap_centroid::real[] = (centroid::real[])[1:32], false) \
           FROM cluster_centroids ORDER BY cluster_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        backfilled,
        vec![(0, Some(32), true), (1, None, false)],
        "the padded row gets its first 32 elements; the non-zero tail is not truncated"
    );

    // A post-222 row stores only umap_centroid; a row with neither is refused.
    sqlx::query(
        "INSERT INTO cluster_centroids (cluster_run_id, cluster_id, umap_centroid) \
         VALUES ('00000000-0000-0000-0000-000000000222', 2, $1::vector)",
    )
    .bind(vector_literal(&head, 32, None))
    .execute(&pool)
    .await
    .expect("a post-222 row without the padded column");
    let refused = sqlx::query(
        "INSERT INTO cluster_centroids (cluster_run_id, cluster_id) \
         VALUES ('00000000-0000-0000-0000-000000000222', 3)",
    )
    .execute(&pool)
    .await
    .expect_err("a row with no centroid at all");
    assert!(
        refused
            .to_string()
            .contains("cluster_centroids_has_a_centroid"),
        "{refused}"
    );

    // Re-applying 222's body changes nothing (the file is idempotent).
    sqlx::raw_sql(&repo_file(
        "migrations/222_cluster_centroids_umap_centroid.sql",
    ))
    .execute(&pool)
    .await
    .expect("222 re-applies");
    assert_eq!(catalog(&pool).await, after_222);

    let undo = repo_file("docs/runbooks/222-undo.sql");
    for run in ["first", "second"] {
        sqlx::raw_sql(&undo)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("the {run} run of the undo applies: {e}"));
        let after = catalog(&pool).await;
        assert_eq!(
            after.symmetric_difference(&before).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "after the {run} run the catalog is exactly the one below 222"
        );
    }
    // The post-222 row was re-padded into the shape a pre-222 reader slices.
    let repadded: (i32, bool, bool) = sqlx::query_as(
        "SELECT vector_dims(centroid), \
                (centroid::real[])[1:32] = $1::vector::real[], \
                NOT EXISTS (SELECT 1 FROM unnest((centroid::real[])[33:1536]) t(x) WHERE x <> 0) \
           FROM cluster_centroids WHERE cluster_id = 2",
    )
    .bind(vector_literal(&head, 32, None))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(repadded, (1536, true, true));
}
