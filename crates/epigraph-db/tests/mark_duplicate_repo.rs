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

async fn seed_edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
         VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', $3, '{}'::jsonb, NOW())",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .execute(pool)
    .await
    .unwrap();
}

async fn edge_count(pool: &PgPool, source: Uuid, target: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2")
        .bind(source)
        .bind(target)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_migrates_edges_to_canonical(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Incoming: a third claim supports the dup.
    seed_edge(&pool, third, dup, "supports").await;
    // Outgoing: the dup supports the third claim.
    seed_edge(&pool, dup, third, "supports").await;
    // Self-loop hazard: an edge already between dup and canonical. Redirecting its
    // source to canonical would create a canonical->canonical self-loop.
    seed_edge(&pool, dup, canonical, "related").await;

    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .unwrap();

    // Incoming edge migrated: third -> dup became third -> canonical.
    assert_eq!(
        edge_count(&pool, third, canonical).await,
        1,
        "incoming edge not migrated"
    );
    assert_eq!(
        edge_count(&pool, third, dup).await,
        0,
        "incoming edge left dangling at dup"
    );
    // Outgoing edge migrated: dup -> third became canonical -> third.
    assert_eq!(
        edge_count(&pool, canonical, third).await,
        1,
        "outgoing edge not migrated"
    );
    assert_eq!(
        edge_count(&pool, dup, third).await,
        0,
        "outgoing edge left dangling at dup"
    );
    // Self-loop guard: the dup<->canonical edge must NOT become canonical->canonical.
    assert_eq!(
        edge_count(&pool, canonical, canonical).await,
        0,
        "created a self-loop"
    );
}

/// Regression test for backlog 2905150e: mark_duplicate returned HTTP 500
/// "Duplicate entity already exists" when dup and canonical already shared
/// a graph edge via a third claim (diamond pattern).
///
/// Scenario: `third →[CORROBORATES]→ dup` AND `third →[CORROBORATES]→ canonical`
/// both exist.  Migrating the dup-edge would produce a second
/// `third →[CORROBORATES]→ canonical`, tripping `idx_edges_unique_triple_non_authored`
/// and rolling back the transaction before `is_current` was flipped.
///
/// The fix pre-deletes dup-edges whose migrated triple already exists on
/// canonical, so the UPDATE only touches survivors.  Verify both the incoming
/// (target=dup) and outgoing (source=dup) diamond cases.
#[sqlx::test(migrations = "../../migrations")]
async fn mark_duplicate_with_shared_neighbor_edge_succeeds(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let canonical = seed_claim(&pool, agent, "canonical").await;
    let dup = seed_claim(&pool, agent, "duplicate").await;
    let third = seed_claim(&pool, agent, "third").await;

    // Diamond — incoming: third already points at both dup and canonical with same relationship.
    seed_edge(&pool, third, dup, "CORROBORATES").await;
    seed_edge(&pool, third, canonical, "CORROBORATES").await;

    // Diamond — outgoing: dup and canonical both point at third with same relationship.
    seed_edge(&pool, dup, third, "supports").await;
    seed_edge(&pool, canonical, third, "supports").await;

    // Before the fix this would return Err(DuplicateKey) / HTTP 500.
    ClaimRepository::mark_duplicate(
        &pool,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .expect("mark_duplicate must succeed even when dup and canonical share a neighbour edge");

    // dup must be retired.
    let (sup, is_current): (Option<Uuid>, bool) =
        sqlx::query_as("SELECT supersedes, is_current FROM claims WHERE id = $1")
            .bind(dup)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sup,
        Some(canonical),
        "dup.supersedes should point at canonical"
    );
    assert!(
        !is_current,
        "dup must not be is_current after mark_duplicate"
    );

    // canonical must still be current.
    let (canon_current,): (bool,) = sqlx::query_as("SELECT is_current FROM claims WHERE id = $1")
        .bind(canonical)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(canon_current, "canonical must remain is_current");

    // The canonical→third edge should exist (either migrated or pre-existing).
    assert_eq!(
        edge_count(&pool, canonical, third).await,
        1,
        "canonical should have exactly one outgoing 'supports' edge to third"
    );
    // The third→canonical edge should exist exactly once.
    assert_eq!(
        edge_count(&pool, third, canonical).await,
        1,
        "canonical should have exactly one incoming 'CORROBORATES' edge from third"
    );
    // No dangling edges on dup.
    assert_eq!(
        edge_count(&pool, dup, third).await,
        0,
        "dup should have no remaining outgoing edges to third"
    );
    assert_eq!(
        edge_count(&pool, third, dup).await,
        0,
        "dup should have no remaining incoming edges from third"
    );
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
