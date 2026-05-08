use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn submit_claim_attaches_labels_when_provided(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let result = epigraph_mcp::tools::claims::submit_claim(
        &server,
        epigraph_mcp::types::SubmitClaimParams {
            content: "labeled claim".into(),
            methodology: "deductive_logic".into(),
            evidence_data: "ev".into(),
            evidence_type: "logical".into(),
            confidence: 0.8,
            source_url: None,
            reasoning: None,
            labels: vec!["backlog".into(), "test-tag".into()],
        },
    )
    .await
    .unwrap();
    let json = first_text(&result);
    let claim_id = parse_uuid_field(&json, "claim_id");

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(labels.contains(&"backlog".to_string()));
    assert!(labels.contains(&"test-tag".to_string()));
}
