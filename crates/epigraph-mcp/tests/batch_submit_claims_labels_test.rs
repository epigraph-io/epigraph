use sqlx::PgPool;
mod common;
use common::*;

/// Regression for backlog 9e15d187: `batch_submit_claims` dropped per-entry
/// `labels`, unlike `submit_claim`. The batch path hard-coded `labels: vec![]`
/// when delegating to `submit_claim`, so a `BatchClaimEntry` carrying
/// `labels: ["capability-registry"]` lost its label at ingest — breaking
/// label-at-ingest flows (e.g. weekly-capability-audit). This pins the fix:
/// labels supplied on a batch entry must survive to the persisted claim.
#[sqlx::test(migrations = "../../migrations")]
async fn batch_submit_claims_attaches_per_entry_labels(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let content = "batched claim carrying a label";
    let result = epigraph_mcp::tools::batch::batch_submit_claims(
        &server,
        epigraph_mcp::types::BatchSubmitClaimsParams {
            claims: vec![epigraph_mcp::types::BatchClaimEntry {
                content: content.into(),
                evidence_data: "ev".into(),
                evidence_type: "logical".into(),
                confidence: Some(0.8),
                labels: vec!["capability-registry".into()],
            }],
        },
    )
    .await
    .unwrap();

    // The batch response reports counts, not per-entry claim_ids; confirm the
    // single entry submitted cleanly before asserting on its persisted labels.
    let summary = first_text(&result);
    assert_eq!(
        summary.get("submitted").and_then(|v| v.as_i64()),
        Some(1),
        "expected exactly one submitted claim, got {summary}"
    );
    assert_eq!(
        summary.get("errors").and_then(|v| v.as_i64()),
        Some(0),
        "expected no batch errors, got {summary}"
    );

    let (labels,): (Vec<String>,) =
        sqlx::query_as("SELECT labels FROM claims WHERE content = $1 AND is_current = true")
            .bind(content)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        labels.contains(&"capability-registry".to_string()),
        "batch entry label was dropped; persisted labels = {labels:?}"
    );
}
