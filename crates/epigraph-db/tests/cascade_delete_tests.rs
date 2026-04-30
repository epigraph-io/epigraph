// crates/epigraph-db/tests/cascade_delete_tests.rs

use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_task_cascades_to_edges(pool: PgPool) -> sqlx::Result<()> {
    let task_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO agents (id, public_key) \
         VALUES ($1, decode(repeat('00', 32), 'hex'))",
    )
    .bind(agent_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'cascade-test-claim', decode(repeat('11', 32), 'hex'), $2)",
    )
    .bind(claim_id)
    .bind(agent_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO tasks (id, description, task_type) \
         VALUES ($1, 'cascade-test', 'cascade-test')",
    )
    .bind(task_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'task', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(task_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;

    let edges_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 OR target_id = $1",
    )
    .bind(task_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(edges_before, 1, "edge should exist before delete");

    sqlx::query("DELETE FROM tasks WHERE id = $1")
        .bind(task_id)
        .execute(&pool)
        .await?;

    let edges_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 OR target_id = $1",
    )
    .bind(task_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(edges_after, 0, "cascade trigger should have removed orphan edges");

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_event_cascades_to_edges(pool: PgPool) -> sqlx::Result<()> {
    let event_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode(repeat('00', 32), 'hex'))")
        .bind(agent_id)
        .execute(&pool)
        .await?;

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'cascade-test-claim', decode(repeat('22', 32), 'hex'), $2)",
    )
    .bind(claim_id)
    .bind(agent_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO events (id, event_type, graph_version) \
         VALUES ($1, 'cascade-test', 0)",
    )
    .bind(event_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'event', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(event_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;

    sqlx::query("DELETE FROM events WHERE id = $1")
        .bind(event_id)
        .execute(&pool)
        .await?;

    let edges_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 OR target_id = $1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(edges_after, 0);

    Ok(())
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_workflow_cascades_to_edges(pool: PgPool) -> sqlx::Result<()> {
    let workflow_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();

    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, decode(repeat('00', 32), 'hex'))")
        .bind(agent_id)
        .execute(&pool)
        .await?;

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, 'cascade-test-claim', decode(repeat('33', 32), 'hex'), $2)",
    )
    .bind(claim_id)
    .bind(agent_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO workflows (id, canonical_name, goal) \
         VALUES ($1, 'cascade-test', 'cascade-test')",
    )
    .bind(workflow_id)
    .execute(&pool)
    .await?;

    sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'claim', 'TEST_EDGE')",
    )
    .bind(workflow_id)
    .bind(claim_id)
    .execute(&pool)
    .await?;

    sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(workflow_id)
        .execute(&pool)
        .await?;

    let edges_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 OR target_id = $1",
    )
    .bind(workflow_id)
    .fetch_one(&pool)
    .await?;
    assert_eq!(edges_after, 0);

    Ok(())
}
