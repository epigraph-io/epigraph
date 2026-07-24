//! Regression for backlog 30bfbb19: `update_with_evidence(supports=true)` drops
//! BetP on claims whose existing BBAs live on a legacy frame other than
//! "binary_truth".
//!
//! Root cause: `auto_wire_ds_update` called `get_for_claim_frame(binary_truth)`
//! which only returned BBAs on the new frame, missing all legacy BBAs. The
//! combination of 1 new BBA produced a lower BetP than the combination of
//! the many pre-existing legacy BBAs.
//!
//! Fix: use `get_for_claim` (all frames) and filter to binary-compatible BBAs.
//! This test seeds a claim, writes 5 strong supporting BBAs on a separate
//! legacy binary frame, computes their combined BetP (betp0), then adds one
//! more supporting BBA via `update_with_evidence` and asserts betp1 >= betp0.

#[macro_use]
mod common;
use common::*;

use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::calibration::CalibrationConfig;
use epigraph_mcp::{tools::ds_auto::effective_source_strength, types::UpdateWithEvidenceParams};
use std::collections::BTreeSet;
use uuid::Uuid;

async fn cached_betp(pool: &sqlx::PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("query pignistic_prob")
        .expect("pignistic_prob populated")
}

#[tokio::test]
async fn cross_frame_supporting_evidence_does_not_drop_betp() {
    let pool = test_pool_or_skip!();

    let claim_id = seed_claim(
        &pool,
        "30bfbb19 cross-frame BetP monotonicity regression",
        0.5,
    )
    .await;

    // 1. Create a legacy binary frame with a unique name to avoid collisions
    //    across runs on the shared test DB.
    let legacy_frame_name = format!("test_legacy_binary_{}", &Uuid::new_v4().to_string()[..8]);
    let legacy_frame_id = FrameRepository::create(
        &pool,
        &legacy_frame_name,
        Some("Legacy binary frame for cross-frame BetP regression test"),
        &["TRUE".to_string(), "FALSE".to_string()],
    )
    .await
    .expect("create legacy frame")
    .id;

    FrameRepository::assign_claim(&pool, claim_id, legacy_frame_id, Some(0))
        .await
        .expect("assign claim to legacy frame");

    // 2. Write 5 strong supporting BBAs on the legacy frame (5 different agents
    //    to avoid ON CONFLICT overwrite on the unique key).
    //    BBA: m({TRUE})=0.85, m(Θ)=0.15, source_strength=0.7
    let bba_masses = serde_json::json!({"0": 0.85, "0,1": 0.15});

    for _ in 0..5 {
        let agent = seed_agent(&pool).await;
        MassFunctionRepository::store_with_perspective(
            &pool,
            claim_id,
            legacy_frame_id,
            Some(agent),
            None, // perspective_id: each (claim,frame,agent,NULL) is unique
            &bba_masses,
            None,
            Some("auto_wire"),
            Some(0.7), // source_strength; NULL evidence_type → used verbatim
            None,      // NULL evidence_type → effective_source_strength takes stored α=0.7
            "unknown",
            None,
        )
        .await
        .expect("store legacy BBA");
    }

    // 3. Compute BetP from those 5 legacy BBAs (betp0).
    //    This is the ground-truth "before adding new evidence" BetP that the
    //    combination must not decrease. Uses the same combination path as
    //    auto_wire_ds_update so the comparison is apples-to-apples.
    let legacy_frame = FrameOfDiscernment::new(
        legacy_frame_name.clone(),
        vec!["TRUE".to_string(), "FALSE".to_string()],
    )
    .expect("construct legacy frame");

    let calibration = CalibrationConfig::default_for_phase2_fallback();
    let legacy_rows = MassFunctionRepository::get_for_claim_frame(&pool, claim_id, legacy_frame_id)
        .await
        .expect("get legacy BBAs");
    assert_eq!(legacy_rows.len(), 5, "should have exactly 5 legacy BBAs");

    let mut mass_fns = Vec::with_capacity(legacy_rows.len());
    for row in &legacy_rows {
        let mf = MassFunction::from_json_masses(legacy_frame.clone(), &row.masses)
            .expect("parse legacy BBA");
        let alpha = effective_source_strength(row, None, None, &calibration);
        let discounted = combination::discount(&mf, alpha).expect("discount BBA");
        mass_fns.push(discounted);
    }
    let (legacy_combined, _) =
        combination::combine_multiple(&mass_fns, 0.9).expect("combine 5 legacy BBAs");

    let true_fe = FocalElement::positive(BTreeSet::from([0_usize]));
    let betp0 = measures::pignistic_probability(&legacy_combined, 0);

    // Write betp0 to claims so the baseline is visible in the DB.
    MassFunctionRepository::update_claim_belief(
        &pool,
        claim_id,
        measures::belief(&legacy_combined, &true_fe),
        measures::plausibility(&legacy_combined, &true_fe),
        legacy_combined.mass_of_conflict(),
        Some(betp0),
        legacy_combined.mass_of_missing(),
    )
    .await
    .expect("write initial belief from legacy BBAs");

    let stored_betp0 = cached_betp(&pool, claim_id).await;
    assert!(
        (stored_betp0 - betp0).abs() < 1e-9,
        "stored betp0={stored_betp0:.6} should equal computed betp0={betp0:.6}"
    );

    // 4. Add a SUPPORTING evidence via the canonical update path (writes to binary_truth).
    let server = build_test_server(pool.clone());
    let res = epigraph_mcp::tools::claims::update_with_evidence(
        &server,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: "empirical".into(),
            evidence_data: "Independent empirical observation supporting the claim.".into(),
            source_url: None,
            supports: true,
            strength: 0.9,
            labels: vec![],
        },
    )
    .await;
    assert!(res.is_ok(), "update_with_evidence failed: {res:?}");

    let betp1 = cached_betp(&pool, claim_id).await;

    // 5. Invariant: adding SUPPORTING evidence must not lower BetP.
    //    Without the fix, auto_wire_ds_update only sees the 1 new BBA on
    //    binary_truth (ignoring the 5 legacy BBAs), giving BetP ≈ 0.90 which
    //    is lower than betp0 ≈ 0.994 from the 5-BBA combination.
    assert!(
        betp1 >= betp0 - 1e-9,
        "update_with_evidence dropped BetP below legacy-frame baseline: \
         betp0={betp0:.6} (from 5 legacy BBAs on {legacy_frame_name}), \
         betp1={betp1:.6} (after empirical support on binary_truth)"
    );
}
