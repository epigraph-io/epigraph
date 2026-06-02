//! Regression for backlog b3d12e2a: adding SUPPORTING evidence dropped BetP
//! (observed 0.848 -> 0.716) because the ingestion initial-cache writer
//! (ds_auto::auto_wire_ds_batch -> wire_single_batch_entry) wrote the cache
//! from the RAW, undiscounted BBA, while the first update_with_evidence
//! re-discounted every row by effective_source_strength. This test seeds a
//! claim, writes its DS cache through the ingestion batch path with a
//! HARD-discounting evidence_type ('circumstantial' -> 0.4 reliability), reads
//! the cached BetP, then adds one SUPPORTING evidence and asserts the cached
//! BetP did not decrease.
//!
//! ON ORIGIN/MAIN THIS TEST FAILS: BetP0 is the raw m({TRUE}) (no discount),
//! BetP1 is the discounted recombine, BetP1 < BetP0. After Fix(1) the initial
//! cache is itself the discounted recombine, so adding support is monotonic.

mod common;
use common::*;

use epigraph_mcp::tools::ds_auto::{auto_wire_ds_batch, BatchDsEntry};
use epigraph_mcp::types::UpdateWithEvidenceParams;

/// Read the persisted `claims.pignistic_prob` (the canonical BetP belief-order
/// field per the pignistic-not-Bayesian invariant) directly via raw SQL. Raw
/// SQL is acceptable in tests; the no-raw-SQL invariant governs production
/// claim mutation only. Reading via the Claim struct is impossible here — the
/// belief scalars are not surfaced on `epigraph_core::Claim`.
async fn cached_betp(pool: &sqlx::PgPool, claim_id: uuid::Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("query pignistic_prob")
        .expect("pignistic_prob populated by DS writer")
}

#[sqlx::test(migrations = "../../migrations")]
async fn adding_supporting_evidence_does_not_drop_cached_betp(pool: sqlx::PgPool) {
    let agent = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, "b3d12e2a monotonicity regression claim", 0.5).await;

    // 1. Write initial DS cache via the REAL ingestion batch writer, tagged with
    //    a hard-discounting evidence_type so raw-vs-discounted diverge starkly.
    let (_frame_id, wired) = auto_wire_ds_batch(
        &pool,
        &[BatchDsEntry {
            claim_id,
            confidence: 0.9,
            weight: 0.9,
            evidence_type: Some("circumstantial".to_string()),
        }],
        agent,
    )
    .await
    .expect("auto_wire_ds_batch");
    assert_eq!(wired, 1, "batch writer must wire the one entry");

    let betp0 = cached_betp(&pool, claim_id).await;

    // 2. Add a SUPPORTING evidence through the canonical update path.
    let server = build_test_server(pool.clone());
    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        UpdateWithEvidenceParams {
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Independent supporting observation.".into(),
            source_url: None,
            supports: true,
            strength: 0.8,
        },
    )
    .await;
    assert!(res.is_ok(), "update_with_evidence failed: {res:?}");

    let betp1 = cached_betp(&pool, claim_id).await;

    // 3. The invariant: a SUPPORTING source must never lower cached BetP.
    assert!(
        betp1 >= betp0 - 1e-9,
        "adding supporting evidence dropped cached BetP: before={betp0}, after={betp1} \
         (writer-mismatch regression — initial cache was undiscounted)"
    );
}
