use sqlx::PgPool;
mod common;
use common::*;

#[sqlx::test(migrations = "../../migrations")]
async fn patch_claim_applies_trace_props_labels_atomically(pool: PgPool) {
    let id = seed_claim_with_labels(&pool, "x", &["alpha"]).await;
    let server = build_test_server(pool.clone());

    // reasoning_traces.reasoning_type CHECK constraint: must be one of
    // 'deductive', 'inductive', 'abductive', 'analogical', 'statistical'.
    let trace = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO reasoning_traces (id, claim_id, reasoning_type, confidence, explanation) \
         VALUES ($1, $2, 'deductive', 0.5, 'test')",
    )
    .bind(trace)
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    epigraph_mcp::tools::claims::patch_claim(
        &server,
        epigraph_mcp::types::PatchClaimParams {
            claim_id: id.to_string(),
            trace_id: Some(trace.to_string()),
            properties: Some(serde_json::json!({"key": "val"})),
            add_labels: vec!["beta".into()],
            remove_labels: vec!["alpha".into()],
        },
    )
    .await
    .unwrap();

    let (after_trace, labels, props): (Option<uuid::Uuid>, Vec<String>, serde_json::Value) =
        sqlx::query_as(
            "SELECT trace_id, COALESCE(labels, ARRAY[]::text[]), COALESCE(properties, '{}'::jsonb) \
             FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(after_trace, Some(trace));
    assert!(labels.contains(&"beta".into()) && !labels.contains(&"alpha".into()));
    assert_eq!(props.get("key").and_then(|v| v.as_str()), Some("val"));
}
