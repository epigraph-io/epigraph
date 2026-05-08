use sqlx::PgPool;
mod common;
use common::*;

/// Verify that the BFS cascade in `deprecate_workflow` handles a diamond DAG
/// correctly: no node is processed twice and all 4 claims are deprecated.
///
/// Diamond shape:
///   A → root (variant_of)
///   B → root (variant_of)
///   C → A    (variant_of)
///   C → B    (variant_of)
///
/// Without a visited-set, C would be enqueued twice (once from A, once from B)
/// and appear twice in `deprecated_ids`.
#[sqlx::test(migrations = "../../migrations")]
async fn deprecate_workflow_diamond_dag_no_duplicates(pool: PgPool) {
    let root = seed_workflow_claim(&pool, "root workflow", &["step1"]).await;
    let a = seed_workflow_claim(&pool, "variant A", &["step1"]).await;
    let b = seed_workflow_claim(&pool, "variant B", &["step1"]).await;
    let c = seed_workflow_claim(&pool, "variant C", &["step1"]).await;

    // Diamond edges: source → target (variant_of means source is a variant of target)
    insert_claim_edge(&pool, a, root, "variant_of").await;
    insert_claim_edge(&pool, b, root, "variant_of").await;
    insert_claim_edge(&pool, c, a, "variant_of").await;
    insert_claim_edge(&pool, c, b, "variant_of").await;

    let server = build_test_server(pool.clone());
    let result = epigraph_mcp::tools::workflows::deprecate_workflow(
        &server,
        epigraph_mcp::types::DeprecateWorkflowParams {
            workflow_id: root.to_string(),
            reason: "diamond test".into(),
            cascade: Some(true),
        },
    )
    .await
    .unwrap();

    // Parse the response JSON
    let body = first_text(&result);
    let deprecated_raw: Vec<String> = body["deprecated_ids"]
        .as_array()
        .expect("deprecated_ids must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // All 4 IDs must appear exactly once — use a HashSet to check for uniqueness
    let deprecated_set: std::collections::HashSet<String> =
        deprecated_raw.iter().cloned().collect();

    assert_eq!(
        deprecated_raw.len(),
        deprecated_set.len(),
        "deprecated_ids contains duplicates: {:?}",
        deprecated_raw
    );

    let expected_ids: std::collections::HashSet<String> =
        [root, a, b, c].iter().map(|id| id.to_string()).collect();

    assert_eq!(
        deprecated_set, expected_ids,
        "deprecated_ids does not match expected set"
    );

    // Verify DB state: all 4 claims have is_current=false and truth_value≈0.05
    for id in [root, a, b, c] {
        let (truth, is_current): (f64, bool) =
            sqlx::query_as("SELECT truth_value, is_current FROM claims WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            (truth - 0.05).abs() < 1e-9,
            "claim {id} truth_value should be 0.05, got {truth}"
        );
        assert!(!is_current, "claim {id} is_current should be false");
    }
}
