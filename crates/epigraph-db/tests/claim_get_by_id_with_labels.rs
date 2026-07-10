//! Integration tests for `ClaimRepository::get_by_id_with_labels`.
//!
//! Regression coverage for the `get_claim` TOCTOU race: the old MCP handler
//! fetched a claim's core fields and its labels via two separate,
//! unsynchronized queries (`get_by_id` then `get_labels`), so a concurrent
//! `update_labels` between the two round trips could return labels
//! inconsistent with the claim row already read. `get_by_id_with_labels`
//! reads both from a single SQL statement, which is inherently consistent
//! under Postgres MVCC.

use epigraph_core::{AgentId, Claim, TruthValue};
use epigraph_db::ClaimRepository;
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
    sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
    Some(pool)
}

macro_rules! test_pool_or_skip {
    () => {{
        match try_test_pool().await {
            Some(p) => p,
            None => {
                eprintln!("Skipping DB test: DATABASE_URL not set or unreachable");
                return;
            }
        }
    }};
}

async fn insert_test_agent(pool: &PgPool, agent_id: Uuid) {
    sqlx::query(
        r#"INSERT INTO agents (id, public_key, created_at, updated_at)
           VALUES ($1, sha256($1::text::bytea), NOW(), NOW())
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("upsert agent");
}

fn make_claim(content: &str, agent_id: Uuid) -> Claim {
    Claim::new(
        content.to_string(),
        AgentId::from_uuid(agent_id),
        [0u8; 32],
        TruthValue::new(0.5).unwrap(),
    )
}

#[tokio::test]
async fn get_by_id_with_labels_returns_none_when_no_row() {
    let pool = test_pool_or_skip!();

    let found = ClaimRepository::get_by_id_with_labels(&pool, epigraph_core::ClaimId::new())
        .await
        .expect("query call");

    assert!(found.is_none(), "expected None, got {:?}", found.is_some());
}

#[tokio::test]
async fn get_by_id_with_labels_matches_separate_calls() {
    let pool = test_pool_or_skip!();
    let agent_id = Uuid::new_v4();
    insert_test_agent(&pool, agent_id).await;

    let claim = make_claim(&format!("atomic read {}", Uuid::new_v4()), agent_id);
    let created = ClaimRepository::create(&pool, &claim)
        .await
        .expect("create");

    ClaimRepository::update_labels(
        &pool,
        created.id.as_uuid(),
        &["backlog".to_string(), "atomic".to_string()],
        &[],
    )
    .await
    .expect("seed labels");

    let (via_new, labels_via_new) = ClaimRepository::get_by_id_with_labels(&pool, created.id)
        .await
        .expect("get_by_id_with_labels")
        .expect("claim exists");

    let via_old = ClaimRepository::get_by_id(&pool, created.id)
        .await
        .expect("get_by_id")
        .expect("claim exists");
    let labels_via_old = ClaimRepository::get_labels(&pool, created.id)
        .await
        .expect("get_labels");

    assert_eq!(via_new.id, via_old.id);
    assert_eq!(via_new.content, via_old.content);
    assert_eq!(via_new.agent_id, via_old.agent_id);
    assert_eq!(via_new.is_current, via_old.is_current);
    assert_eq!(via_new.supersedes, via_old.supersedes);

    let mut new_sorted = labels_via_new.clone();
    new_sorted.sort();
    let mut old_sorted = labels_via_old.clone();
    old_sorted.sort();
    assert_eq!(new_sorted, old_sorted);
    assert_eq!(new_sorted, vec!["atomic".to_string(), "backlog".to_string()]);
}
