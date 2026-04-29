//! `PaperRepository` integration tests.

mod helpers;

use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, PaperRepository, PgPool};
use helpers::{make_agent, make_claim};

#[sqlx::test(migrations = "../../migrations")]
async fn get_or_create_inserts_then_returns_existing(pool: PgPool) {
    let doi = "10.1234/test-paper-1";
    let id1 = PaperRepository::get_or_create(&pool, doi, Some("Title 1"), Some("Journal X"))
        .await
        .expect("first insert");

    // Second call with the same DOI should return the same id (UNIQUE on doi).
    let id2 = PaperRepository::get_or_create(&pool, doi, Some("Title 1 updated"), None)
        .await
        .expect("second insert");
    assert_eq!(id1, id2, "same DOI must return same paper id");

    // The conflict path updated the title.
    let row = PaperRepository::find_by_doi(&pool, doi)
        .await
        .expect("find_by_doi")
        .expect("paper row");
    assert_eq!(row.id, id1);
    assert_eq!(row.title.as_deref(), Some("Title 1 updated"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_by_doi_returns_none_for_unknown(pool: PgPool) {
    let result = PaperRepository::find_by_doi(&pool, "10.0000/does-not-exist")
        .await
        .expect("find_by_doi");
    assert!(result.is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn has_processed_by_edge_reflects_pipeline_property(pool: PgPool) {
    let paper_id =
        PaperRepository::get_or_create(&pool, "10.1234/has-pbe", Some("Has-PBE Paper"), None)
            .await
            .expect("create paper");

    // No edge yet → false.
    assert!(!PaperRepository::has_processed_by_edge(
        &pool,
        paper_id,
        "hierarchical_extraction_v1"
    )
    .await
    .expect("query has_processed_by_edge"));

    // Edges enforce target existence via trigger_validate_edge_refs, so we
    // create a real agent + claim to use as the edge target.
    let agent = make_agent(Some("test-agent"));
    let agent_row = AgentRepository::create(&pool, &agent)
        .await
        .expect("create agent");
    let claim = make_claim(agent_row.id, "test claim", 0.5);
    let claim_row = ClaimRepository::create(&pool, &claim)
        .await
        .expect("create claim");

    EdgeRepository::create(
        &pool,
        paper_id,
        "paper",
        claim_row.id.into(),
        "claim",
        "processed_by",
        Some(serde_json::json!({"pipeline": "hierarchical_extraction_v1"})),
        None,
        None,
    )
    .await
    .expect("create edge");

    assert!(PaperRepository::has_processed_by_edge(
        &pool,
        paper_id,
        "hierarchical_extraction_v1"
    )
    .await
    .expect("query has_processed_by_edge"));

    // Different pipeline string → still false.
    assert!(!PaperRepository::has_processed_by_edge(&pool, paper_id, "other_pipeline_v1")
        .await
        .expect("query has_processed_by_edge"));
}
