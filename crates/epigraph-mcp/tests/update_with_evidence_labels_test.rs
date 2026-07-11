//! Regression for backlog claim f14592cb-17a7-4e33-a41d-fa1ddd57d3a1
//! ("`update_with_evidence` dedup-match never updates labels").
//!
//! `update_with_evidence` is the write path an upstream pipeline (e.g. the
//! norcal-rfp weekly reviewer) calls when it resolves a dedup match — the
//! claim already exists from a prior cycle, so instead of `submit_claim`
//! creating a duplicate, the caller re-asserts evidence against the
//! existing `claim_id`. That re-assertion should also be able to carry the
//! current cycle's label (e.g. a run-tag like `norcal-rfp-2026-07-05`) and
//! have it added to the claim's label array — additive, alongside whatever
//! labels the claim already carries from its original creation cycle.
//!
//! Before this fix, `UpdateWithEvidenceParams` had no `labels` field at
//! all, so any run-tag the caller intended to attach was silently dropped:
//! the claim retained only its original creation-time labels forever. That
//! breaks the reviewer's `query_claims_by_label([RUN_TAG])` discovery step
//! for claims that predate the current week but are still relevant.
//!
//! `submit_claim` and `memorize` already handle this correctly on their
//! dedup-hit branch (see `claims.rs::submit_claim`, `memory.rs::memorize`):
//! both call `ClaimRepository::update_labels(pool, claim_id, &labels, &[])`
//! unconditionally when labels are non-empty, which is additive because
//! `update_labels` unions the new labels into the existing array via
//! `array_agg(DISTINCT ...)`. `update_with_evidence` was the odd one out.

use sqlx::PgPool;
mod common;
use common::*;

use epigraph_mcp::types::UpdateWithEvidenceParams;

#[sqlx::test(migrations = "../../migrations")]
async fn update_with_evidence_adds_labels_without_dropping_existing(pool: PgPool) {
    let claim_id =
        seed_claim_with_labels(&pool, "norcal-rfp weekly claim", &["norcal-rfp-2026-06-29"]).await;
    let server = build_test_server(pool.clone());

    let result = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        UpdateWithEvidenceParams {
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Re-confirmed in this week's norcal-rfp cycle.".into(),
            source_url: None,
            supports: true,
            strength: 0.7,
            labels: vec!["norcal-rfp-2026-07-05".into()],
        },
    )
    .await;
    assert!(result.is_ok(), "update_with_evidence failed: {result:?}");

    let (labels,): (Vec<String>,) = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(
        labels.contains(&"norcal-rfp-2026-06-29".to_string()),
        "original creation-cycle label must survive the dedup-match write; got {labels:?}"
    );
    assert!(
        labels.contains(&"norcal-rfp-2026-07-05".to_string()),
        "current-cycle run-tag label must be added on the dedup-match write; got {labels:?}"
    );
}
