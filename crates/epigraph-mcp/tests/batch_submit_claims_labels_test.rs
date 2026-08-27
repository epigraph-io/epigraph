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
            // Backlog 4b48ffb5: the coverage contract has no opt-in. `None`
            // here is not "off" — it is the implicit default, `exhaustive`
            // over this batch's own entries. The assertions below prove it.
            coverage: None,
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

    // Backlog 4b48ffb5: this pre-existing test is also the proof that the
    // coverage checker runs on the DEFAULT path. No flag was passed, no config
    // key exists, and the batch still comes back with a counted verdict over a
    // declared denominator read off its own payload.
    assert_eq!(
        summary.get("declared").and_then(|v| v.as_i64()),
        Some(1),
        "declared_total must default to the entry count, got {summary}"
    );
    assert_eq!(
        summary.get("coverage_standard").and_then(|v| v.as_str()),
        Some("exhaustive"),
        "the default standard must be exhaustive, got {summary}"
    );
    assert_eq!(
        summary.get("coverage_verdict").and_then(|v| v.as_str()),
        Some("satisfied"),
        "one distinct claim against a declared 1 must satisfy, got {summary}"
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
