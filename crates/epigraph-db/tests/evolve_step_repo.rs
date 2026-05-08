use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let pk: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query("INSERT INTO agents (id, public_key, agent_type) VALUES ($1, $2, 'system')")
        .bind(id)
        .bind(&pk)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str, truth: f64) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, $4, $5, true, ARRAY[]::text[])",
    )
    .bind(id)
    .bind(content)
    .bind(&hash)
    .bind(truth)
    .bind(agent)
    .execute(pool)
    .await
    .unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_supersedes_flips_parent(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent step", 0.7).await;
    let res = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "child",
        "supersedes",
        Some("better"),
        2,
        agent,
    )
    .await
    .unwrap();

    let (parent_current,): (bool,) =
        sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(parent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!parent_current);

    let (child_lineage, child_props): (Option<Uuid>, serde_json::Value) =
        sqlx::query_as("SELECT step_lineage_id, properties FROM claims WHERE id = $1")
            .bind(res.new_claim_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(child_lineage, Some(res.step_lineage_id));
    assert_eq!(child_props["level"].as_i64(), Some(2));
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_revises_keeps_parent_current(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "branch",
        "revises",
        None,
        2,
        agent,
    )
    .await
    .unwrap();
    let (parent_current,): (bool,) =
        sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
            .bind(parent)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(parent_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn evolve_step_rejects_bad_edge_type(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let parent = seed_claim(&pool, agent, "parent", 0.7).await;
    let err = ClaimRepository::evolve_step(
        &pool,
        ClaimId::from_uuid(parent),
        "x",
        "merges",
        None,
        2,
        agent,
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("supersedes"), "{err:?}");
}
