//! Integration test for CompoundNbhdBlocker.

use epigraph_engine::matching::blocker::{compound_nbhd::CompoundNbhdBlocker, Blocker};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

async fn try_test_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&pool).await.expect("test DB migrations failed — likely a description/version mismatch with existing _sqlx_migrations; use a fresh DB");
    Some(pool)
}
macro_rules! test_pool_or_skip {
    () => {
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set");
                return;
            }
        }
    };
}

async fn insert_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agents (id, public_key, created_at, updated_at)
         VALUES ($1, sha256($1::text::bytea), NOW(), NOW())",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("agent");
    id
}

async fn insert_claim(pool: &PgPool, agent: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let content = format!("claim {}", id);
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id)
         VALUES ($1, $2, sha256($2::bytea), 0.5, $3)",
    )
    .bind(id)
    .bind(&content)
    .bind(agent)
    .execute(pool)
    .await
    .expect("claim");
    id
}

async fn insert_cluster_row(pool: &PgPool, claim_id: Uuid, cluster_id: i32, cluster_run_id: Uuid) {
    sqlx::query(
        "INSERT INTO claim_clusters (claim_id, cluster_id, cluster_run_id,
                                     centroid_distance, second_centroid_dist,
                                     boundary_ratio, silhouette_score)
         VALUES ($1, $2, $3, 0.0, 0.0, 0.0, 0.0)",
    )
    .bind(claim_id)
    .bind(cluster_id)
    .bind(cluster_run_id)
    .execute(pool)
    .await
    .expect("claim_clusters");
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_co_cluster_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let seed = insert_claim(&pool, agent).await;
    let other1 = insert_claim(&pool, agent).await;
    let other2 = insert_claim(&pool, agent).await;

    let cluster_run_id = Uuid::new_v4();
    let cluster_id = 42_i32;
    insert_cluster_row(&pool, seed, cluster_id, cluster_run_id).await;
    insert_cluster_row(&pool, other1, cluster_id, cluster_run_id).await;
    insert_cluster_row(&pool, other2, cluster_id, cluster_run_id).await;

    let b = CompoundNbhdBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.expect("candidates");

    let p1 = if seed < other1 {
        (seed, other1)
    } else {
        (other1, seed)
    };
    let p2 = if seed < other2 {
        (seed, other2)
    } else {
        (other2, seed)
    };
    assert!(pairs.contains(&p1), "expected pair {:?} in {:?}", p1, pairs);
    assert!(pairs.contains(&p2), "expected pair {:?} in {:?}", p2, pairs);
    for (a, b) in &pairs {
        assert!(a < b, "pair not canonical: ({a}, {b})");
        assert_ne!(a, b, "self-pair found");
    }
}
