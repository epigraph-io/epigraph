//! Regression for backlog 30bfbb19 (branch: 1c1360bb): update_with_evidence
//! with supports=true was lowering BetP on claims with existing multi-evidence BBAs.
//!
//! Root cause: legacy BBAs (written before the current `build_binary_bba` path)
//! carry BOTH m({0}) > 0 AND m({1}) > 0 (mixed focal elements) and NULL
//! evidence_type.  When a new pure-support BBA is combined with these, the
//! conflict K is high enough that Inagaki redistribution sends mass to the
//! missing element and reduces pignistic_prob — even though the new evidence
//! is labelled supports=true.
//!
//! Fix: `auto_wire_ds_update` now reads the current pignistic_prob before
//! combining and clamps: if supports=true, final_betp = max(combined, prior).
//!
//! These tests seed claims with the ACTUAL legacy BBA format observed in
//! production (c98b6dec, adf396a8) and verify the clamp holds.

mod common;
use common::*;

use epigraph_mcp::tools::ds_auto::{auto_wire_ds_batch, BatchDsEntry};
use epigraph_mcp::types::UpdateWithEvidenceParams;
use sqlx::PgPool;
use uuid::Uuid;

async fn cached_betp(pool: &PgPool, claim_id: Uuid) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .expect("query pignistic_prob")
        .expect("pignistic_prob populated by DS writer")
}

async fn add_evidence(
    server: &epigraph_mcp::EpiGraphMcpFull,
    pool: &PgPool,
    claim_id: Uuid,
    supports: bool,
    strength: f64,
    evidence_type: &str,
    note: &str,
) -> f64 {
    let res = epigraph_mcp::tools::claims::update_with_evidence(
        server,
        UpdateWithEvidenceParams {
            canonical_name: None,
            step_index: None,
            claim_id: claim_id.to_string(),
            evidence_type: evidence_type.to_string(),
            evidence_data: note.to_string(),
            source_url: None,
            supports,
            strength,
            labels: vec![],
        },
    )
    .await;
    assert!(
        res.is_ok(),
        "update_with_evidence({supports}, {strength}) failed: {res:?}"
    );
    cached_betp(pool, claim_id).await
}

/// Seed the binary frame and return its id (creates it if absent).
async fn get_or_create_binary_frame(pool: &PgPool) -> Uuid {
    epigraph_mcp::tools::ds_auto::ensure_binary_frame(pool)
        .await
        .expect("ensure_binary_frame")
}

/// Insert a legacy mixed-format BBA directly into mass_functions.
///
/// Production claims (e.g. c98b6dec) have BBAs written by an older code path
/// that produced `{"0": X, "1": Y, "~": Z, "0,1": W}` with NULL evidence_type
/// and source_strength = 0.255.  `build_binary_bba` no longer produces this
/// format; only pure-support or pure-oppose BBAs are generated today.
///
/// Each call seeds its own agent so that the UNIQUE (claim_id, frame_id,
/// source_agent_id, perspective_id NULLS NOT DISTINCT) constraint is
/// satisfied when inserting multiple BBAs for the same claim.
async fn insert_legacy_mixed_bba(pool: &PgPool, claim_id: Uuid, frame_id: Uuid) {
    let agent_id = seed_agent(pool).await;

    // Masses mirror the production c98b6dec BBAs exactly:
    //   m({0}) = 0.41508535   (TRUE — supporting focal element)
    //   m({1}) = 0.02598169   (FALSE — opposing focal element)
    //   m({~}) = 0.07         (complement/missing)
    //   m({0,1}) = 0.48893296 (Theta — ignorance)
    // source_strength=0.255, evidence_type=NULL, locality_tag=intra_self_cite
    let masses = serde_json::json!({
        "0":   0.41508535069130836_f64,
        "1":   0.0259816929959808_f64,
        "~":   0.07_f64,
        "0,1": 0.4889329563127107_f64
    });
    sqlx::query(
        "INSERT INTO mass_functions \
         (id, claim_id, frame_id, source_agent_id, masses, conflict_k, \
          combination_method, source_strength, evidence_type, locality_tag) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4::jsonb, 0.0, \
                 'auto_wire', 0.255, NULL, 'intra_self_cite')",
    )
    .bind(claim_id)
    .bind(frame_id)
    .bind(agent_id)
    .bind(&masses)
    .execute(pool)
    .await
    .expect("insert legacy mixed BBA");
}

/// Regression: supports=true must not lower BetP when legacy mixed-format
/// BBAs are already present.
///
/// Reproduces the exact production state of c98b6dec at the time the bug was
/// filed: 4 legacy mixed BBAs (NULL evidence_type, mixed m({0})+m({1})),
/// combined with a new pure-support BBA.  Before the fix, this dropped BetP.
/// After the fix (monotonicity clamp), BetP must be non-decreasing.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_never_lowers_betp_with_legacy_mixed_bbas(pool: PgPool) {
    let claim_id = seed_claim(&pool, "1c1360bb regression: legacy mixed BBA scenario", 0.5).await;

    let frame_id = get_or_create_binary_frame(&pool).await;

    // Assign the claim to the binary frame (needed before inserting mass_functions).
    sqlx::query(
        "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
         VALUES ($1, $2, 0) ON CONFLICT DO NOTHING",
    )
    .bind(claim_id)
    .bind(frame_id)
    .execute(&pool)
    .await
    .expect("assign claim to frame");

    // Seed 4 legacy mixed BBAs — mirror of c98b6dec production state.
    // Each insert_legacy_mixed_bba call creates its own agent to satisfy the
    // UNIQUE (claim_id, frame_id, source_agent_id, perspective_id) constraint.
    for _ in 0..4 {
        insert_legacy_mixed_bba(&pool, claim_id, frame_id).await;
    }

    let server = build_test_server(pool.clone());

    // Set an initial pignistic_prob to simulate the pre-bug state (~0.88).
    // auto_wire_ds_update will read this before combining and clamp against it.
    sqlx::query("UPDATE claims SET pignistic_prob = 0.88 WHERE id = $1")
        .bind(claim_id)
        .execute(&pool)
        .await
        .expect("set initial pignistic_prob");

    let betp_before = cached_betp(&pool, claim_id).await;

    // Add strong supporting evidence — the operation that caused the drop in the
    // original bug report (c98b6dec 0.883→0.725, strength ≈ 0.92-0.95).
    let betp_after = add_evidence(
        &server,
        &pool,
        claim_id,
        true,
        0.93,
        "empirical",
        "Strong empirical confirmation (strength=0.93, bug-report scenario).",
    )
    .await;

    assert!(
        betp_after >= betp_before - 1e-9,
        "Bug 1c1360bb: adding supports=true strength=0.93 to legacy mixed BBAs lowered BetP: \
         before={betp_before:.6} after={betp_after:.6}"
    );
}

/// Variant: clean BBAs (no mixed masses) + opposing + new strong support.
///
/// Tests that the monotone property also holds for the clean-BBA scenario
/// that was the prior regression target (b3d12e2a).
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_never_lowers_betp_with_opposing_bbas(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim_id = seed_claim(
        &pool,
        "1c1360bb regression: clean BBAs + opposing scenario",
        0.5,
    )
    .await;

    let (_frame_id, wired) = auto_wire_ds_batch(
        &pool,
        &[
            BatchDsEntry {
                claim_id,
                confidence: 0.80,
                weight: 0.9,
                evidence_type: Some("empirical".to_string()),
            },
            BatchDsEntry {
                claim_id,
                confidence: 0.75,
                weight: 0.9,
                evidence_type: Some("empirical".to_string()),
            },
            BatchDsEntry {
                claim_id,
                confidence: 0.82,
                weight: 0.9,
                evidence_type: Some("empirical".to_string()),
            },
        ],
        agent,
    )
    .await
    .expect("auto_wire_ds_batch");
    assert_eq!(wired, 3);

    let server = build_test_server(pool.clone());

    // Add opposing evidence to create conflict.
    add_evidence(
        &server,
        &pool,
        claim_id,
        false,
        0.60,
        "circumstantial",
        "Counter-evidence observation.",
    )
    .await;

    let betp_before = cached_betp(&pool, claim_id).await;

    let betp_after = add_evidence(
        &server,
        &pool,
        claim_id,
        true,
        0.93,
        "empirical",
        "Strong empirical confirmation (strength=0.93).",
    )
    .await;

    assert!(
        betp_after >= betp_before - 1e-9,
        "Bug 1c1360bb (clean variant): adding supports=true strength=0.93 lowered BetP: \
         before={betp_before:.6} after={betp_after:.6}"
    );
}

/// Two opposing BBAs: tests deeper conflict regime.
#[sqlx::test(migrations = "../../migrations")]
async fn supporting_evidence_never_lowers_betp_two_opposing(pool: PgPool) {
    let agent = seed_agent(&pool).await;
    let claim_id = seed_claim(&pool, "1c1360bb variant-2opp regression claim", 0.5).await;

    let (_frame_id, _wired) = auto_wire_ds_batch(
        &pool,
        &[
            BatchDsEntry {
                claim_id,
                confidence: 0.85,
                weight: 0.9,
                evidence_type: Some("empirical".to_string()),
            },
            BatchDsEntry {
                claim_id,
                confidence: 0.80,
                weight: 0.9,
                evidence_type: Some("empirical".to_string()),
            },
        ],
        agent,
    )
    .await
    .expect("batch 2 supports");

    let server = build_test_server(pool.clone());

    add_evidence(
        &server,
        &pool,
        claim_id,
        false,
        0.65,
        "circumstantial",
        "Counter A.",
    )
    .await;
    add_evidence(
        &server,
        &pool,
        claim_id,
        false,
        0.55,
        "circumstantial",
        "Counter B.",
    )
    .await;

    let betp_before = cached_betp(&pool, claim_id).await;

    let betp_after = add_evidence(
        &server,
        &pool,
        claim_id,
        true,
        0.95,
        "empirical",
        "Strong empirical confirmation (strength=0.95).",
    )
    .await;

    assert!(
        betp_after >= betp_before - 1e-9,
        "Bug 1c1360bb variant: 2-opposing + strong support lowered BetP: \
         {betp_before:.6} → {betp_after:.6}"
    );
}
