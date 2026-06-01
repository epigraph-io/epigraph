//! Integration test for the assign-all phase in ThemeClusterRebuildHandler.

use epigraph_db::ClaimThemeRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (public_key, display_name, agent_type, labels) \
         VALUES (sha256(gen_random_uuid()::text::bytea), 'assign-all-test', 'system', ARRAY['test']) \
         RETURNING id",
    )
    .fetch_one(pool)
    .await
    .expect("seed agent")
}

async fn seed_unthemed_claims(pool: &PgPool, n: usize) {
    let agent_id = seed_agent(pool).await;
    let per_cluster = n / 3;
    for cluster in 0..3 {
        let base = cluster as f32 * 0.5;
        for i in 0..per_cluster {
            let inner: Vec<String> = (0..1536)
                .map(|j| {
                    let bias = if j == cluster { 1.0_f32 } else { 0.0_f32 };
                    let jitter = ((i + j) as f32) * 1e-7;
                    format!("{}", base + bias + jitter)
                })
                .collect();
            let pgvec = format!("[{}]", inner.join(","));
            let content = format!("assign-all-c{}-i{}-{}", cluster, i, Uuid::new_v4());
            sqlx::query(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector)",
            )
            .bind(&content)
            .bind(agent_id)
            .bind(&pgvec)
            .execute(pool)
            .await
            .expect("seed unthemed claim");
        }
    }
}

async fn seed_theme_with_centroid(pool: &PgPool, label: &str, cluster: usize) -> Uuid {
    let base = cluster as f32 * 0.5;
    let inner: Vec<String> = (0..1536)
        .map(|j| {
            let bias = if j == cluster { 1.0_f32 } else { 0.0_f32 };
            format!("{}", base + bias)
        })
        .collect();
    let centroid_str = format!("[{}]", inner.join(","));

    let theme_id: Uuid = sqlx::query_scalar(
        "INSERT INTO claim_themes (label, description, claim_count) \
         VALUES ($1, 'test theme', 0) RETURNING id",
    )
    .bind(label)
    .fetch_one(pool)
    .await
    .expect("insert theme");

    sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
        .bind(theme_id)
        .bind(&centroid_str)
        .execute(pool)
        .await
        .expect("set centroid");

    theme_id
}

#[sqlx::test(migrations = "../../migrations")]
async fn assign_all_themes_every_claim_with_embedding(pool: PgPool) {
    seed_unthemed_claims(&pool, 90).await;
    seed_theme_with_centroid(&pool, "theme-a", 0).await;
    seed_theme_with_centroid(&pool, "theme-b", 1).await;
    seed_theme_with_centroid(&pool, "theme-c", 2).await;

    let unthemed_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM claims WHERE theme_id IS NULL AND embedding IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count unthemed before");
    assert_eq!(unthemed_before, 90, "pre-condition: 90 unthemed claims");

    let mut total: i64 = 0;
    loop {
        let batch = ClaimThemeRepository::assign_unthemed_batch(&pool, 20)
            .await
            .expect("assign batch");
        if batch == 0 {
            break;
        }
        total += batch;
    }

    let unthemed_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM claims WHERE theme_id IS NULL AND embedding IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("count unthemed after");

    assert_eq!(unthemed_after, 0, "assign-all must leave zero unthemed claims");
    assert_eq!(total, 90, "total assigned must equal claims seeded");
}

#[sqlx::test(migrations = "../../migrations")]
async fn assign_all_skips_claims_without_embeddings(pool: PgPool) {
    let agent_id = seed_agent(&pool).await;
    sqlx::query(
        "INSERT INTO claims (content, content_hash, truth_value, agent_id) \
         VALUES ('no-embed', sha256('no-embed'::bytea), 0.5, $1)",
    )
    .bind(agent_id)
    .execute(&pool)
    .await
    .expect("seed no-embed claim");

    seed_theme_with_centroid(&pool, "theme-x", 0).await;

    let batch = ClaimThemeRepository::assign_unthemed_batch(&pool, 100)
        .await
        .expect("assign batch");

    assert_eq!(batch, 0, "claims without embeddings must not be assigned");
}
