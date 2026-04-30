// crates/epigraph-db/tests/edge_validation_tests.rs

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn validate_edge_reference_has_one_overload(pool: PgPool) -> sqlx::Result<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_proc WHERE proname = 'validate_edge_reference'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        count, 1,
        "expected exactly one validate_edge_reference overload, found {count}"
    );
    Ok(())
}

async fn seed_agent_and_claim(
    pool: &PgPool,
    agent_byte: u8,
    claim_byte: u8,
) -> sqlx::Result<(Uuid, Uuid)> {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode($2, 'hex'))")
        .bind(agent_id)
        .bind(format!("{:02x}", agent_byte).repeat(32))
        .execute(pool)
        .await?;

    let claim_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'cleanup-test', decode($2, 'hex'), $3)",
    )
    .bind(claim_id)
    .bind(format!("{:02x}", claim_byte).repeat(32))
    .bind(agent_id)
    .execute(pool)
    .await?;

    Ok((agent_id, claim_id))
}

#[sqlx::test(migrations = "../../migrations")]
async fn perspective_edge_with_valid_fk_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xA1, 0x41).await?;
    let perspective_id = Uuid::new_v4();
    sqlx::query("INSERT INTO perspectives (id, name) VALUES ($1, 'cleanup-test')")
        .bind(perspective_id)
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'perspective', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(perspective_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn community_edge_with_valid_fk_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xA2, 0x42).await?;
    let community_id = Uuid::new_v4();
    sqlx::query("INSERT INTO communities (id, name) VALUES ($1, 'cleanup-test')")
        .bind(community_id)
        .execute(&pool)
        .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'community', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(community_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn context_edge_with_valid_fk_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xA3, 0x43).await?;
    let context_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO contexts (id, name, context_type) \
         VALUES ($1, 'cleanup-test', 'cleanup-test')",
    )
    .bind(context_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'context', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(context_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn frame_edge_with_valid_fk_succeeds(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xA4, 0x44).await?;
    let frame_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO frames (id, name, hypotheses) \
         VALUES ($1, 'cleanup-test', ARRAY['h1','h2']::text[])",
    )
    .bind(frame_id)
    .execute(&pool)
    .await?;
    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'frame', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(frame_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn perspective_edge_with_bogus_uuid_fails(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xB1, 0x51).await?;
    let bogus = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'perspective', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(bogus)
    .bind(claim_id)
    .execute(&pool)
    .await;
    assert!(
        result.is_err(),
        "edge with non-existent perspective should be rejected"
    );
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn community_edge_with_bogus_uuid_fails(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xB2, 0x52).await?;
    let bogus = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'community', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(bogus)
    .bind(claim_id)
    .execute(&pool)
    .await;
    assert!(result.is_err());
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn context_edge_with_bogus_uuid_fails(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xB3, 0x53).await?;
    let bogus = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'context', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(bogus)
    .bind(claim_id)
    .execute(&pool)
    .await;
    assert!(result.is_err());
    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn frame_edge_with_bogus_uuid_fails(pool: PgPool) -> sqlx::Result<()> {
    let (_, claim_id) = seed_agent_and_claim(&pool, 0xB4, 0x54).await?;
    let bogus = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'frame', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(bogus)
    .bind(claim_id)
    .execute(&pool)
    .await;
    assert!(result.is_err());
    Ok(())
}
