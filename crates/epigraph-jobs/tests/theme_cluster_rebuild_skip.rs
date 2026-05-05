//! Integration tests for the scheduled `theme_cluster_rebuild` job.
//!
//! Two tests:
//! - `theme_rebuild_skips_when_corpus_unchanged` — exercises the
//!   skip-check shortcut: theme.updated_at >= max(claim.{created,updated})_at
//! - `theme_rebuild_runs_when_corpus_changed` — flips the relation and
//!   asserts the rebuild actually creates themes via shared k-means.

use epigraph_jobs::theme_cluster_rebuild::ThemeClusterRebuildHandler;
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a single agent row used by all seeded claims.  Returns its id.
async fn seed_agent(pool: &PgPool, label: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
         RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

/// Insert `n` claims with NO embeddings.  The skip-path test uses this —
/// it never invokes the helper, so embeddings are irrelevant.
async fn seed_claims_without_embeddings(pool: &PgPool, n: usize) {
    let agent_id = seed_agent(pool, "rebuild-skip-test").await;
    for i in 0..n {
        let content = format!("plain-{}-{}", i, Uuid::new_v4());
        sqlx::query(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
             VALUES ($1, sha256($1::bytea), 0.5, $2)",
        )
        .bind(&content)
        .bind(agent_id)
        .execute(pool)
        .await
        .expect("seed claim (no embedding)");
    }
}

/// Insert one row into `claim_themes` and return its id.  Setting
/// `claim_count` here is fine — the skip-path test asserts theme rows are
/// untouched, not that the count is meaningful.
async fn seed_theme(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ('preexisting', 'seeded by test', 0) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed theme")
}

/// Like [`seed_theme`] but explicitly sets `created_at` and `updated_at`
/// to `NOW() + INTERVAL '1 hour'`.  Used by the skip-path test to force
/// `theme.updated_at > MAX(claim.{created,updated}_at)` deterministically
/// — `tokio::sleep` between inserts is racy on loaded CI runners because
/// `NOW()` resolves at transaction start with microsecond precision.
async fn seed_theme_in_future(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count, created_at, updated_at) \
         VALUES ('preexisting', 'seeded by test', 0, NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 hour') \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed theme in future")
}

/// Total rows in `claim_themes`.
async fn count_themes(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*)::int8 FROM claim_themes")
        .fetch_one(pool)
        .await
        .expect("count themes")
}

/// Insert `n` claims with cluster-biased 1536d embeddings, mirroring the
/// pattern used by the existing 3072d test in routes/crud.rs.  Three
/// clusters, ~n/3 claims each, distinct first-3 dims so k-means has work
/// to do.  When `bump_timestamps` is true, `created_at` and `updated_at`
/// are set to `NOW() + INTERVAL '1 hour'` so the skip-check deterministi-
/// cally observes `theme.updated_at < MAX(claim.{created,updated}_at)`.
async fn seed_claims_with_embeddings(pool: &PgPool, n: usize, bump_timestamps: bool) {
    let agent_id = seed_agent(pool, "rebuild-run-test").await;
    let per_cluster = n / 3;
    for cluster in 0..3 {
        let base = cluster as f32 * 0.1;
        for i in 0..per_cluster {
            let inner: Vec<String> = (0..1536)
                .map(|j| {
                    let bias = if j == cluster { 1.0 } else { 0.0 };
                    let jitter = ((i + j) as f32) * 1e-7;
                    format!("{}", base + bias + jitter)
                })
                .collect();
            let pgvec = format!("[{}]", inner.join(","));
            let content = format!("rebuild-c{}-i{}-{}", cluster, i, Uuid::new_v4());
            let sql = if bump_timestamps {
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, created_at, updated_at) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 hour')"
            } else {
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector)"
            };
            sqlx::query(sql)
                .bind(&content)
                .bind(agent_id)
                .bind(&pgvec)
                .execute(pool)
                .await
                .expect("seed 1536d claim");
        }
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn theme_rebuild_skips_when_corpus_unchanged(pool: PgPool) {
    // is_corpus_unchanged returns true when theme.updated_at >=
    // MAX(claim.{created,updated}_at).  We seed claims at NOW() and the
    // theme at NOW() + 1h so the relation holds without depending on
    // wall-clock ordering between consecutive INSERTs (PostgreSQL NOW()
    // resolves at transaction start with microsecond precision; on a
    // loaded CI runner two back-to-back INSERTs can resolve identically).
    seed_claims_without_embeddings(&pool, 8).await;
    let _theme_id = seed_theme_in_future(&pool).await;

    let count_before = count_themes(&pool).await;
    let summary = ThemeClusterRebuildHandler::handle_direct(&pool, 50, 1, true)
        .await
        .expect("handle_direct on skip path");
    let count_after = count_themes(&pool).await;

    assert!(summary.skipped, "skip path returned skipped=false");
    assert_eq!(
        summary.themes_created, 0,
        "skip path must not create themes"
    );
    assert_eq!(
        count_before, count_after,
        "skip path leaves themes untouched"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn theme_rebuild_runs_when_corpus_changed(pool: PgPool) {
    // Inverse of the skip-path test: theme at NOW(), claims explicitly
    // at NOW() + 1h so MAX(claim.{created,updated}_at) > theme.updated_at
    // and the skip-check fails deterministically.
    let _theme_id = seed_theme(&pool).await;
    seed_claims_with_embeddings(&pool, 12, true).await;

    let summary = ThemeClusterRebuildHandler::handle_direct(&pool, 8, 2, true)
        .await
        .expect("handle_direct on rebuild path");

    assert!(!summary.skipped, "rebuild was incorrectly skipped");
    assert!(
        summary.themes_created > 0,
        "rebuild produced no themes (summary={summary:?})"
    );
}
