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

    let id1 = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .expect("first call inserts");

    let id2 = EdgeRepository::create_if_not_exists(
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

    assert_eq!(id1, id2, "second call must return existing edge id");
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

    let id_a = EdgeRepository::create_if_not_exists(
        &pool, paper_id, "paper", claim_id, "claim", "asserts", None, None, None,
    )
    .await
    .unwrap();

    let id_b = EdgeRepository::create_if_not_exists(
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

    assert_ne!(id_a, id_b, "different relationship → different edge");
}
