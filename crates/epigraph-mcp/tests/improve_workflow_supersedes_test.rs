use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn improve_workflow_writes_supersedes_edge_and_labels_variant(pool: PgPool) {
    let parent = seed_workflow_claim(&pool, "parent goal", &["s1"]).await;
    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::workflows::improve_workflow(
        &server,
        epigraph_mcp::types::ImproveWorkflowParams {
            parent_workflow_id: parent.to_string(),
            change_rationale: "tighter".into(),
            steps: Some(vec!["s1.refined".into()]),
            goal: None,
            prerequisites: None,
            expected_outcome: None,
            tags: None,
        },
    )
    .await
    .unwrap();

    let json = first_text(&result);
    let variant_id = parse_uuid_field(&json, "variant_id");

    // Edge must be 'supersedes', not 'variant_of'.
    let rel: Option<String> = sqlx::query_scalar(
        "SELECT relationship FROM edges WHERE source_id = $1 AND target_id = $2",
    )
    .bind(variant_id)
    .bind(parent)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert_eq!(rel.as_deref(), Some("supersedes"));

    // Variant must carry the 'workflow' label so cascade can find it.
    let (labels,): (Vec<String>,) =
        sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
            .bind(variant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        labels.contains(&"workflow".into()),
        "improve_workflow variants must carry the 'workflow' label"
    );
}
