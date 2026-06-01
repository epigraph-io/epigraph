//! `EdgeRepository` integration tests.

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn create_if_not_exists_is_idempotent(pool: PgPool) {
    // Set up real source (paper) and target (claim) so the edge-validation
    // trigger doesn't reject the insert.
    let paper_id = PaperRepository::get_or_create(&pool, "10.1234/idem", Some("Idempotency"), None)
        .await
        .expect("create paper");

    let agent = make_agent(Some("a"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim = make_claim(agent_row.id, "the claim", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim).await.unwrap();
    let claim_id: uuid::Uuid = claim_row.id.into();

    let (row1, was_created1) = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .expect("first call inserts");
    assert!(was_created1, "first call must report was_created=true");

    let (row2, was_created2) = EdgeRepository::create_if_not_exists(
        &pool,
        paper_id,
        "paper",
        claim_id,
        "claim",
        "asserts",
        Some(serde_json::json!({"different": "props"})),
        None,
        None,
    )
    .await
    .expect("second call returns existing");

    assert_eq!(row1.id, row2.id, "second call must return existing edge id");
    assert!(
        !was_created2,
        "second call must report was_created=false on dedup hit"
    );
    // Dedup hit must return the STORED properties, not the new request's.
    assert_eq!(
        row2.properties,
        serde_json::json!({}),
        "dedup hit must surface stored properties (empty), not the second call's"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_if_not_exists_distinguishes_by_relationship(pool: PgPool) {
    let paper_id = PaperRepository::get_or_create(&pool, "10.1234/rel", Some("Relationship"), None)
        .await
        .expect("create paper");

    let agent = make_agent(Some("b"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim = make_claim(agent_row.id, "another", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim).await.unwrap();
    let claim_id: uuid::Uuid = claim_row.id.into();

    let (row_a, _) = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .unwrap();

    let (row_b, _) = EdgeRepository::create_if_not_exists(
        &pool,
        paper_id,
        "paper",
        claim_id,
        "claim",
        "processed_by",
        None,
        None,
        None,
    )
    .await
    .unwrap();

    assert_ne!(
        row_a.id, row_b.id,
        "different relationship → different edge"
    );
}

/// Count edges incident on either of two claims for a given relationship,
/// in EITHER direction. The matcher treats CORROBORATES as symmetric, so this
/// is the metric that proves bidirectional dedup.
async fn incident_edge_count(pool: &PgPool, a: uuid::Uuid, b: uuid::Uuid, rel: &str) -> i64 {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE relationship = $3
           AND ((source_id = $1 AND target_id = $2)
             OR (source_id = $2 AND target_id = $1))",
    )
    .bind(a)
    .bind(b)
    .bind(rel)
    .fetch_one(pool)
    .await
    .expect("count edges");
    count
}

/// LOAD-BEARING: `create_symmetric_if_absent` dedups in BOTH directions.
///
/// The forward call (A→B) inserts one CORROBORATES edge. The crucial assertion
/// is the REVERSE call (B→A, same relationship): it must return `false` and
/// must NOT add a second edge. A same-direction-only implementation would
/// insert the reverse edge (returning `true`, count → 2); this is the only
/// assertion that distinguishes symmetric dedup from a plain
/// `(source,target,relationship)` check, so it is the heart of the refactor.
#[sqlx::test(migrations = "../../migrations")]
async fn reverse_direction_dedup_returns_false(pool: PgPool) {
    let agent = make_agent(Some("sym"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim_a = make_claim(agent_row.id, "claim A for symmetric dedup", 0.5);
    let claim_b = make_claim(agent_row.id, "claim B for symmetric dedup", 0.5);
    let a: uuid::Uuid = ClaimRepository::create(&pool, &claim_a).await.unwrap().id.into();
    let b: uuid::Uuid = ClaimRepository::create(&pool, &claim_b).await.unwrap().id.into();

    let props = serde_json::json!({"source": "cross_source_matcher", "score": 0.91});

    // Forward A→B: first edge of this relationship → inserts.
    let inserted = EdgeRepository::create_symmetric_if_absent(&pool, a, b, "CORROBORATES", props.clone())
        .await
        .expect("forward insert");
    assert!(inserted, "first call must insert and return true");
    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "exactly one CORROBORATES edge after the forward call"
    );

    // Reverse B→A, same relationship: the symmetric existence check must see
    // the existing (a→b) edge and SKIP. Returns false; count stays 1.
    let inserted_reverse =
        EdgeRepository::create_symmetric_if_absent(&pool, b, a, "CORROBORATES", props.clone())
            .await
            .expect("reverse call runs");
    assert!(
        !inserted_reverse,
        "REVERSE-direction call must dedup (return false) — symmetric, not directional"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "reverse call must NOT add a second edge — count stays exactly 1"
    );
}

/// Different relationships between the same pair are distinct edges — the
/// dedup is scoped to `relationship`, not just the endpoints.
#[sqlx::test(migrations = "../../migrations")]
async fn create_symmetric_if_absent_distinguishes_by_relationship(pool: PgPool) {
    let agent = make_agent(Some("symrel"));
    let agent_row = AgentRepository::create(&pool, &agent).await.unwrap();
    let claim_a = make_claim(agent_row.id, "claim A for rel discrimination", 0.5);
    let claim_b = make_claim(agent_row.id, "claim B for rel discrimination", 0.5);
    let a: uuid::Uuid = ClaimRepository::create(&pool, &claim_a).await.unwrap().id.into();
    let b: uuid::Uuid = ClaimRepository::create(&pool, &claim_b).await.unwrap().id.into();

    let props = serde_json::json!({"source": "cross_source_matcher"});

    let first = EdgeRepository::create_symmetric_if_absent(&pool, a, b, "CORROBORATES", props.clone())
        .await
        .expect("corroborates insert");
    assert!(first, "CORROBORATES must insert");

    // A→B with a DIFFERENT relationship is a different edge → must insert.
    let second = EdgeRepository::create_symmetric_if_absent(&pool, a, b, "contradicts", props.clone())
        .await
        .expect("contradicts insert");
    assert!(second, "contradicts is a distinct relationship → must insert");

    assert_eq!(
        incident_edge_count(&pool, a, b, "CORROBORATES").await,
        1,
        "one CORROBORATES edge"
    );
    assert_eq!(
        incident_edge_count(&pool, a, b, "contradicts").await,
        1,
        "one contradicts edge"
    );
    let total: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM edges
         WHERE (source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total.0, 2, "two distinct edges total (one per relationship)");
}
