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
