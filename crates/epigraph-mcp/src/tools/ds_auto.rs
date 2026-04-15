//! Auto-wiring of CDST (Calibrated Dempster-Shafer) evidence for claims.
//!
//! Every claim-creating or claim-updating tool calls into this module after
//! persisting the claim. DS is the primary belief authority — `update_with_evidence`
//! propagates errors. `submit_claim` treats DS as best-effort (claim is already persisted).
//!
//! Each BBA is Shafer-discounted by its `source_strength` before combination to
//! prevent runaway confirmation (C2) and dilution attacks (C3).

use std::collections::BTreeSet;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::{FrameRepository, MassFunctionRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

/// Probability value in [0.0, 1.0]. Currently f64 for codebase consistency.
/// Future: may migrate to f32 or bounded newtype for memory optimization.
/// Changing this alias + recompiling will flag every callsite.
pub type Prob = f64;

/// Result of auto-wiring DS evidence for a single claim.
#[derive(Debug)]
#[allow(dead_code)] // mass_on_conflict/missing retained for diagnostics
pub struct DsAutoResult {
    pub belief: Prob,
    pub plausibility: Prob,
    pub pignistic_prob: Prob,
    pub mass_on_conflict: Prob,
    pub mass_on_missing: Prob,
    pub frame_id: Uuid,
}

/// Entry for batch DS wiring (used by `do_ingest`).
pub struct BatchDsEntry {
    pub claim_id: Uuid,
    pub confidence: f64,
    pub weight: f64,
}

/// Canonical binary frame name.
const BINARY_FRAME_NAME: &str = "binary_truth";
/// Hypotheses for the canonical binary frame.
const BINARY_HYPOTHESES: [&str; 2] = ["TRUE", "FALSE"];

/// Get-or-create the canonical `binary_truth` frame.
///
/// Handles race conditions: get → create → fallback get.
pub async fn ensure_binary_frame(pool: &PgPool) -> Result<Uuid, String> {
    // Fast path: frame already exists
    if let Some(row) = FrameRepository::get_by_name(pool, BINARY_FRAME_NAME)
        .await
        .map_err(|e| format!("get_by_name: {e}"))?
    {
        return Ok(row.id);
    }

    // Create it
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    match FrameRepository::create(
        pool,
        BINARY_FRAME_NAME,
        Some("Canonical binary frame: {TRUE, FALSE}"),
        &hyps,
    )
    .await
    {
        Ok(row) => Ok(row.id),
        Err(_) => {
            // Race: another connection created it first — re-fetch
            FrameRepository::get_by_name(pool, BINARY_FRAME_NAME)
                .await
                .map_err(|e| format!("fallback get_by_name: {e}"))?
                .map(|r| r.id)
                .ok_or_else(|| "binary_truth frame missing after create attempt".to_string())
        }
    }
}

/// Build a simple BBA for a binary frame.
///
/// - `supports = true`  → m({TRUE}) = confidence * weight, m(Θ) = remainder
/// - `supports = false` → m({FALSE}) = confidence * weight, m(Θ) = remainder
fn build_binary_bba(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    supports: bool,
) -> Result<MassFunction, String> {
    let mass = (confidence * weight).clamp(0.01, 0.99);
    let idx = usize::from(!supports); // 0=TRUE, 1=FALSE
    MassFunction::simple(frame.clone(), BTreeSet::from([idx]), mass)
        .map_err(|e| format!("build BBA: {e}"))
}

/// Serialize a `MassFunction` to JSON for DB storage.
fn mass_to_json(mf: &MassFunction) -> Result<serde_json::Value, String> {
    let map: std::collections::HashMap<String, f64> = mf
        .masses()
        .iter()
        .map(|(fe, m)| (focal_to_key(fe), *m))
        .collect();
    serde_json::to_value(map).map_err(|e| format!("serialize BBA: {e}"))
}

/// Convert a `FocalElement` to a string key for JSON serialization.
fn focal_to_key(fe: &FocalElement) -> String {
    if fe.is_conflict() {
        return String::new();
    }
    let indices: Vec<String> = fe.subset.iter().map(ToString::to_string).collect();
    if fe.complement {
        format!("~{}", indices.join(","))
    } else {
        indices.join(",")
    }
}

/// Construct a `FrameOfDiscernment` for the binary frame.
fn binary_frame() -> Result<FrameOfDiscernment, String> {
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    FrameOfDiscernment::new(BINARY_FRAME_NAME.to_string(), hyps)
        .map_err(|e| format!("binary frame: {e}"))
}

/// Compute Bel/Pl/BetP for hypothesis 0 (TRUE) from a combined mass function.
fn compute_measures(combined: &MassFunction) -> (Prob, Prob, Prob, Prob, Prob) {
    let target = FocalElement::positive(BTreeSet::from([0_usize])); // TRUE
    let bel = measures::belief(combined, &target);
    let pl = measures::plausibility(combined, &target);
    let betp = measures::pignistic_probability(combined, 0);
    let conflict = combined.mass_of_conflict();
    let missing = combined.mass_of_missing();
    (bel, pl, betp, conflict, missing)
}

/// Parse a stored BBA row back into a `MassFunction`.
fn parse_stored_bba(
    frame: &FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<MassFunction, String> {
    MassFunction::from_json_masses(frame.clone(), masses_json)
        .map_err(|e| format!("parse stored BBA: {e}"))
}

/// Auto-wire DS for a **new** claim.
///
/// Creates a BBA, assigns the claim to the binary frame, computes Bel/Pl/BetP,
/// and updates the claim's DS columns.
pub async fn auto_wire_ds_for_claim(
    pool: &PgPool,
    claim_id: Uuid,
    agent_id: Uuid,
    confidence: f64,
    weight: f64,
    supports: bool,
    evidence_type: Option<&str>, // NEW: evidence classification tag
) -> Result<DsAutoResult, String> {
    let frame_id = ensure_binary_frame(pool).await?;
    let frame = binary_frame()?;

    // Build BBA
    let bba = build_binary_bba(&frame, confidence, weight, supports)?;
    let masses_json = mass_to_json(&bba)?;

    // Assign claim to binary frame (hypothesis_index=0 → TRUE)
    FrameRepository::assign_claim(pool, claim_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;

    // Store BBA (perspective_id=NULL for auto-wired)
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent_id),
        None, // no perspective
        &masses_json,
        None,
        Some("auto_wire"),
        Some(confidence), // source_strength
        evidence_type,    // evidence_type
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // C-2: Apply reliability discount before computing measures so that initial
    // pignistic probability respects source strength, not just raw BBA mass.
    let reliability = confidence.clamp(0.0, 1.0);
    let discounted =
        combination::discount(&bba, reliability).map_err(|e| format!("discount: {e}"))?;
    let (bel, pl, betp, conflict, missing) = compute_measures(&discounted);

    // Update claim DS columns
    MassFunctionRepository::update_claim_belief(
        pool,
        claim_id,
        bel,
        pl,
        conflict,
        Some(betp),
        missing,
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    Ok(DsAutoResult {
        belief: bel,
        plausibility: pl,
        pignistic_prob: betp,
        mass_on_conflict: conflict,
        mass_on_missing: missing,
        frame_id,
    })
}

/// Auto-wire DS for an **evidence update** on an existing claim.
///
/// Stores a new BBA, retrieves all BBAs, discounts each by its source_strength
/// (Shafer's reliability discounting), combines via `combine_multiple()`,
/// and updates the claim's DS columns.
///
/// `evidence_id` is passed as `perspective_id` so that each evidence submission
/// gets its own BBA row rather than upsert-overwriting the previous one on the
/// unique constraint (claim_id, frame_id, agent_id, perspective_id=NULL).
#[allow(clippy::too_many_arguments)]
pub async fn auto_wire_ds_update(
    pool: &PgPool,
    claim_id: Uuid,
    agent_id: Uuid,
    confidence: f64,
    weight: f64,
    supports: bool,
    evidence_type_str: Option<&str>, // NEW: evidence classification tag
    evidence_id: Option<Uuid>,       // C-1: used as perspective_id to separate BBAs
) -> Result<DsAutoResult, String> {
    let frame_id = ensure_binary_frame(pool).await?;
    let frame = binary_frame()?;

    // Build BBA for this evidence
    let bba = build_binary_bba(&frame, confidence, weight, supports)?;
    let masses_json = mass_to_json(&bba)?;

    // Ensure assignment exists
    FrameRepository::assign_claim(pool, claim_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;

    // Store BBA — use evidence_id as perspective_id so each evidence submission
    // gets its own row instead of upsert-overwriting on (claim, frame, agent, NULL).
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent_id),
        evidence_id, // C-1: unique perspective per evidence prevents overwrite
        &masses_json,
        None,
        Some("auto_wire"),
        Some(confidence),  // source_strength
        evidence_type_str, // evidence_type
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // Retrieve all BBAs and combine WITH reliability discount
    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;

    let combined = if all_rows.len() <= 1 {
        // Single BBA — still apply discount
        let reliability = all_rows
            .first()
            .and_then(|r| r.source_strength)
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);
        let mf = parse_stored_bba(&frame, &all_rows[0].masses)?;
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?
    } else {
        // Multiple BBAs — discount each by its stored source_strength, then combine
        let mut mass_fns = Vec::with_capacity(all_rows.len());
        for row in &all_rows {
            let mf = parse_stored_bba(&frame, &row.masses)?;
            // NULL source_strength → 1.0 (no discount for historical BBAs without metadata)
            let reliability = row.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);
            let discounted =
                combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
            mass_fns.push(discounted);
        }
        let (combined, _reports) = combination::combine_multiple(&mass_fns, 0.9)
            .map_err(|e| format!("combine_multiple: {e}"))?;
        combined
    };

    let (bel, pl, betp, conflict, missing) = compute_measures(&combined);

    MassFunctionRepository::update_claim_belief(
        pool,
        claim_id,
        bel,
        pl,
        conflict,
        Some(betp),
        missing,
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    Ok(DsAutoResult {
        belief: bel,
        plausibility: pl,
        pignistic_prob: betp,
        mass_on_conflict: conflict,
        mass_on_missing: missing,
        frame_id,
    })
}

/// Auto-wire DS for a **batch** of new claims (used by ingestion).
///
/// Gets the frame once, then wires each claim sequentially. Individual
/// failures are logged and skipped.
pub async fn auto_wire_ds_batch(
    pool: &PgPool,
    entries: &[BatchDsEntry],
    agent_id: Uuid,
) -> Result<(Uuid, usize), String> {
    if entries.is_empty() {
        return Err("empty batch".to_string());
    }

    let frame_id = ensure_binary_frame(pool).await?;
    let frame = binary_frame()?;
    let mut wired = 0_usize;

    for entry in entries {
        if let Err(e) = wire_single_batch_entry(pool, &frame, frame_id, entry, agent_id).await {
            tracing::warn!(
                claim_id = %entry.claim_id,
                "ds_auto batch skip: {e}"
            );
            continue;
        }
        wired += 1;
    }

    Ok((frame_id, wired))
}

/// Wire a single claim in a batch context (frame already resolved).
async fn wire_single_batch_entry(
    pool: &PgPool,
    frame: &FrameOfDiscernment,
    frame_id: Uuid,
    entry: &BatchDsEntry,
    agent_id: Uuid,
) -> Result<(), String> {
    let bba = build_binary_bba(frame, entry.confidence, entry.weight, true)?;
    let masses_json = mass_to_json(&bba)?;

    FrameRepository::assign_claim(pool, entry.claim_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;

    MassFunctionRepository::store_with_perspective(
        pool,
        entry.claim_id,
        frame_id,
        Some(agent_id),
        None,
        &masses_json,
        None,
        Some("auto_wire"),
        Some(entry.confidence), // source_strength
        None,                   // evidence_type (not available in batch)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    let (bel, pl, betp, conflict, missing) = compute_measures(&bba);

    MassFunctionRepository::update_claim_belief(
        pool,
        entry.claim_id,
        bel,
        pl,
        conflict,
        Some(betp),
        missing,
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    Ok(())
}
