//! Integration test for ThemeClusterBlocker.

use epigraph_engine::matching::blocker::{theme_cluster::ThemeClusterBlocker, Blocker};
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

async fn insert_theme(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claim_themes (id, label, description)
         VALUES ($1, 'biology', '')",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("theme");
    id
}

async fn assign_theme(pool: &PgPool, claim_id: Uuid, theme_id: Uuid) {
    sqlx::query("UPDATE claims SET theme_id = $1 WHERE id = $2")
        .bind(theme_id)
        .bind(claim_id)
        .execute(pool)
        .await
        .expect("assign theme");
}

#[sqlx::test(migrations = "../../migrations")]
async fn returns_co_theme_candidates(pool: PgPool) {
    let agent = insert_agent(&pool).await;
    let seed = insert_claim(&pool, agent).await;
    let other = insert_claim(&pool, agent).await;
    // insert a third claim without a theme — should not appear
    let _unrelated = insert_claim(&pool, agent).await;

    let theme = insert_theme(&pool).await;
    assign_theme(&pool, seed, theme).await;
    assign_theme(&pool, other, theme).await;

    let b = ThemeClusterBlocker::new(50);
    let pairs = b.candidates(&pool, &[seed]).await.expect("candidates");

    let expected = if seed < other {
        (seed, other)
    } else {
        (other, seed)
    };
    assert!(
        pairs.contains(&expected),
        "expected pair {:?} in {:?}",
        expected,
        pairs
    );
    for (a, b) in &pairs {
        assert!(a < b, "pair not canonical: ({a}, {b})");
        assert_ne!(a, b, "self-pair found");
    }
}
