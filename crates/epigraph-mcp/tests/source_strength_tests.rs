//! Verify auto_wire_ds_update stores source_strength = evidence-type weight
//! (not the agent confidence). The SciFact discount path uses source_strength
//! as Shafer's reliability multiplier; conflating it with agent confidence
//! double-discounts the BBA (the mass shape already encodes confidence).
//!
//! Sheaf cohomology stagnation (h1 frozen at the obstruction-rich extreme)
//! is the visible symptom of the prior conflation.

#[macro_use]
mod common;

use epigraph_mcp::tools;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_agent_and_claim(pool: &PgPool) -> (Uuid, Uuid) {
    let agent_id = Uuid::new_v4();
    let claim_id = Uuid::new_v4();
    // Derive unique public_key + content_hash from the UUIDs so re-runs
    // against a persistent test DB don't collide on previous fixtures.
    sqlx::query("INSERT INTO agents (id, public_key) VALUES ($1, $2)")
        .bind(agent_id)
        .bind(agent_id.as_bytes().repeat(2))
        .execute(pool)
        .await
        .expect("seed agent");
    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(claim_id)
    .bind(format!("source-strength regression {claim_id}"))
    .bind(claim_id.as_bytes().repeat(2))
    .bind(agent_id)
    .execute(pool)
    .await
    .expect("seed claim");
    (agent_id, claim_id)
}

/// Seed an evidence row tied to `claim_id` so the test can pass its id as
/// `auto_wire_ds_update`'s `evidence_id` argument. Phase 3 (#197) added
/// `mass_functions.evidence_id` with `REFERENCES evidence(id)`; a
/// caller-fabricated UUID will violate that FK at insert time.
async fn seed_evidence(pool: &PgPool, claim_id: Uuid) -> Uuid {
    let evidence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO evidence (id, content_hash, evidence_type, claim_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(evidence_id)
    .bind(evidence_id.as_bytes().repeat(2))
    .bind("testimony")
    .bind(claim_id)
    .execute(pool)
    .await
    .expect("seed evidence row");
    evidence_id
}

#[tokio::test]
async fn auto_wire_ds_update_stores_weight_as_source_strength() {
    let pool = test_pool_or_skip!();
    let (agent_id, claim_id) = seed_agent_and_claim(&pool).await;

    // Confidence and weight differ so we can tell which one was stored.
    let confidence = 0.95;
    let weight = 0.6;
    let evidence_id = seed_evidence(&pool, claim_id).await;

    tools::ds_auto::auto_wire_ds_update(
        &pool,
        claim_id,
        agent_id,
        confidence,
        weight,
        true, // supports
        Some("testimony"),
        Some(evidence_id),
    )
    .await
    .expect("auto_wire_ds_update");

    let stored: (Option<f64>, Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT source_strength, evidence_type, evidence_id \
           FROM mass_functions \
          WHERE claim_id = $1 AND perspective_id = $2",
    )
    .bind(claim_id)
    .bind(evidence_id)
    .fetch_one(&pool)
    .await
    .expect("fetch BBA");

    let stored_strength = stored.0.expect("source_strength must be set");
    assert!(
        (stored_strength - weight).abs() < f64::EPSILON,
        "source_strength should be the evidence-type weight ({weight}), got {stored_strength}"
    );
    assert!(
        (stored_strength - confidence).abs() > 0.01,
        "source_strength must NOT equal confidence ({confidence}); confidence is encoded in BBA shape"
    );
    assert_eq!(stored.1.as_deref(), Some("testimony"));
    // Phase 3 (issue #197): auto_wire_ds_update must pipe its evidence_id
    // parameter through to mass_functions.evidence_id as the FK to the
    // evidence row that produced this BBA. Without this, the linking
    // script (scripts/link_mass_function_evidence.py) is the only path to
    // recover per-BBA provenance — and only on a best-effort basis.
    assert_eq!(
        stored.2,
        Some(evidence_id),
        "Phase 3: evidence_id parameter must round-trip into mass_functions.evidence_id"
    );
}

/// Phase 2 (issue #197): recalibration through the MCP `auto_wire_ds_update`
/// callsite of `effective_source_strength`. Mirrors the engine-side
/// recalibration canary in `intra_source_discount_regression.rs`.
///
/// The ds_auto path writes `locality_tag = "unknown"`, so a vanilla call
/// chain would not see the intra factor applied. To exercise the intra
/// branch of the helper through this entry point, the test:
///   1. Calls `auto_wire_ds_update` twice with intra-cohort tags.
///   2. Promotes the just-written rows to `locality_tag = 'intra_self_cite'`
///      via raw SQL (Phase 1c will eventually derive this from the linked
///      evidence row's DOI vs the claim's asserting paper — backlog
///      claim 7b934e58).
///   3. Sets the per-frame `intra_evidence_locality_factor` to a value
///      far from the calibration default.
///   4. Calls `auto_wire_ds_update` a third time (this triggers the
///      combine path) and asserts BetP reflects the override.
///   5. Changes the override and triggers another combine; asserts BetP
///      shifts again, proving the helper reads the current factor on
///      every combine call.
#[tokio::test]
async fn auto_wire_ds_update_recalibration_flows_through_combine() {
    let pool = test_pool_or_skip!();
    let (agent_id, claim_id) = seed_agent_and_claim(&pool).await;

    // Two intra-cohort evidence rows: empirical (calibrated weight 1.0).
    // Distinct evidence_ids → distinct perspective rows → no upsert
    // collisions on (claim, frame, agent, perspective).
    let ev_a = seed_evidence(&pool, claim_id).await;
    let ev_b = seed_evidence(&pool, claim_id).await;
    let ev_c = seed_evidence(&pool, claim_id).await;

    tools::ds_auto::auto_wire_ds_update(
        &pool,
        claim_id,
        agent_id,
        0.9,  // confidence
        1.0,  // weight
        true, // supports
        Some("empirical"),
        Some(ev_a),
    )
    .await
    .expect("first update");

    tools::ds_auto::auto_wire_ds_update(
        &pool,
        claim_id,
        agent_id,
        0.9,
        1.0,
        true,
        Some("empirical"),
        Some(ev_b),
    )
    .await
    .expect("second update");

    // Promote both to intra. Phase 1c will derive this automatically
    // (backlog claim 7b934e58); for now we set it directly so the helper
    // exercises its intra branch.
    let promoted = sqlx::query(
        "UPDATE mass_functions SET locality_tag = 'intra_self_cite' \
         WHERE claim_id = $1 AND locality_tag = 'unknown'",
    )
    .bind(claim_id)
    .execute(&pool)
    .await
    .expect("promote to intra_self_cite")
    .rows_affected();
    assert_eq!(
        promoted, 2,
        "expected 2 rows promoted to intra, got {promoted}"
    );

    // Resolve binary_truth so we can set its per-frame factor.
    let frame_id =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM frames WHERE name = 'binary_truth'")
            .fetch_one(&pool)
            .await
            .expect("binary_truth frame id");

    // Per-frame factor 0.9 (very weak discount). Use direct SQL via the
    // FrameRepository pattern — we don't have a direct dep on epigraph_db
    // FrameRepository from this test file but the SQL is trivial.
    sqlx::query(
        "UPDATE frames SET properties = properties || jsonb_build_object('intra_evidence_locality_factor', 0.9) WHERE id = $1",
    )
    .bind(frame_id)
    .execute(&pool)
    .await
    .expect("set per-frame factor to 0.9");

    // Third update — triggers a combine which reads the helper, which
    // reads the current per-frame factor and applies it to BOTH the new
    // BBA and the two existing intra-tagged rows (we promote AFTER the
    // call too to make sure THIS row goes through the helper as intra).
    tools::ds_auto::auto_wire_ds_update(
        &pool,
        claim_id,
        agent_id,
        0.9,
        1.0,
        true,
        Some("empirical"),
        Some(ev_c),
    )
    .await
    .expect("third update");
    // Promote the third row too (it was inserted under unknown).
    sqlx::query(
        "UPDATE mass_functions SET locality_tag = 'intra_self_cite' \
         WHERE claim_id = $1 AND locality_tag = 'unknown'",
    )
    .bind(claim_id)
    .execute(&pool)
    .await
    .expect("promote new row to intra_self_cite");

    // Trigger a combine to surface BetP under the current (0.9) factor.
    // We can use a fresh call to auto_wire_ds_update with an additional
    // ev_id, but a cleaner path is to call recompute_claim_belief_binary
    // directly on the engine API.
    epigraph_engine::edge_factor::recompute_claim_belief_binary(&pool, claim_id)
        .await
        .expect("recompute under factor 0.9");

    let betp_weak: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("fetch BetP under 0.9");

    // Push the factor the other way (0.05 — near-total discount).
    sqlx::query(
        "UPDATE frames SET properties = properties || jsonb_build_object('intra_evidence_locality_factor', 0.05) WHERE id = $1",
    )
    .bind(frame_id)
    .execute(&pool)
    .await
    .expect("set per-frame factor to 0.05");

    epigraph_engine::edge_factor::recompute_claim_belief_binary(&pool, claim_id)
        .await
        .expect("recompute under factor 0.05");

    let betp_strong: f64 = sqlx::query_scalar("SELECT pignistic_prob FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_one(&pool)
        .await
        .expect("fetch BetP under 0.05");

    eprintln!(
        "[auto_wire_ds_update_recalibration_flows_through_combine] weak (0.9) BetP = {betp_weak}, \
         strong-discount (0.05) BetP = {betp_strong}"
    );
    assert!(
        betp_weak > betp_strong + 0.05,
        "Phase 2: per-frame factor recalibration MUST flow through the auto_wire_ds_update combine \
         path without any DB rewrite of source_strength. weak={betp_weak}, strong={betp_strong}"
    );
}
