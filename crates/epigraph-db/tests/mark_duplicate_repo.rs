use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, DbError};
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

async fn seed_claim(pool: &PgPool, agent: Uuid, content: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash: Vec<u8> = id.as_bytes().iter().copied().cycle().take(32).collect();
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels) \
         VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[])"
    ).bind(id).bind(content).bind(&hash).bind(agent)
    .execute(pool).await.unwrap();
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_happy_path(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();

    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sup, Some(canonical));
    assert!(!is_current);

    // Canonical untouched.
    let (canon_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(canon_current);
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_already_superseded(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let other_canonical = seed_claim(&pool, agent, "other").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;

    // First mark — succeeds.
    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();
    // Second mark to a different canonical — must fail.
    let err = ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(other_canonical),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("already superseded"), "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_self(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim = seed_claim(&pool, agent, "self").await;
    let err = ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(claim),
        ClaimId::from_uuid(claim),
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{err:?}").contains("dup == canonical"), "{err:?}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_rejects_missing_canonical(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let dup = seed_claim(&pool, agent, "dup").await;
    let bogus = Uuid::new_v4();
    let err =
        ClaimRepository::mark_duplicate(&pool, ClaimId::from_uuid(dup), ClaimId::from_uuid(bogus))
            .await
            .err()
            .unwrap();
    assert!(matches!(err, DbError::NotFound { .. }), "{err:?}");
}
