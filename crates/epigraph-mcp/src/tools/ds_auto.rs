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

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

// Edge-factor auto-wire moved to `epigraph_engine::edge_factor` so the HTTP
// route layer can share a single algorithm. Re-export keeps the existing
// MCP call sites (`tools::ingestion`, `tools::workflows`) working unchanged.
//
// Phase 2 (issue #197) re-exports `effective_source_strength` so the local
// `auto_wire_ds_update` combine loop below can call it without an extra
// `use` and so external integration tests can import via the MCP crate.
pub use epigraph_engine::edge_factor::{
    auto_wire_ds_for_edge, auto_wire_edge_if_epistemic, effective_source_strength,
    EdgeFactorOutcome,
};

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

/// Entry for batch DS wiring (used by `do_ingest_document`).
pub struct BatchDsEntry {
    pub claim_id: Uuid,
    pub confidence: f64,
    pub weight: f64,
    /// Canonical evidence-type tag from the extraction plan, stored on the BBA
    /// so `effective_source_strength` (global) and the frame function
    /// (per-perspective) can key reliability on it. `None` → untagged BBA
    /// (falls back to the stored `source_strength` / α = 1.0).
    pub evidence_type: Option<String>,
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

/// Small fixed opposing mass assigned to the NON-primary singleton so that a
/// supporting BBA is no longer a pure simple-support function. With this mass
/// present, Θ no longer absorbs ALL non-primary mass, so Pl(primary) < 1.0 and
/// plausibility can contract as refuting evidence accumulates. Value is the
/// `default` methodology profile's `base_against` from calibration.toml
/// (`default = [0.50, 0.08, 0.42]`), the documented no-methodology constant.
/// We do NOT adopt V2's `base_support*type_weight*confidence` primary-mass
/// formula (see build_default_bba_directed): build_binary_bba receives no
/// methodology, and changing the primary scale would move every auto-wired
/// claim's BetP. Model (against-mass on the opposing singleton) is ported from
/// V2 epigraph-nano/src/cdst.rs::build_default_bba_directed; the magnitude is
/// the calibrated `default` base_against. (backlog b3d12e2a, Fix 2)
const BINARY_BBA_BASE_AGAINST: f64 = 0.08;

/// Build a directed BBA for a binary frame.
///
/// - `supports = true`  → m({TRUE}) = confidence*weight (clamped),
///   m({FALSE}) = base_against, m(Θ) = remainder
/// - `supports = false` → m({FALSE}) = confidence*weight (clamped),
///   m({TRUE}) = base_against, m(Θ) = remainder
///
/// The small {opposing} mass makes Pl(primary) < 1.0 (was identically 1.0 with
/// the previous simple-support shape). base_against is held below the theta
/// remainder so the mass sums to exactly 1.0.
fn build_binary_bba(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    supports: bool,
) -> Result<MassFunction, String> {
    let m_primary = (confidence * weight).clamp(0.01, 0.99);
    // Reserve headroom: never let against-mass eat into primary; theta absorbs
    // the rest. (1.0 - m_primary) is in [0.01, 0.99], so base_against fits.
    let m_against = BINARY_BBA_BASE_AGAINST.min((1.0 - m_primary - 1e-6).max(0.0));
    let m_theta = (1.0 - m_primary - m_against).max(0.0);

    let primary_idx = usize::from(!supports); // 0=TRUE supports, 1=FALSE refutes
    let opposing_idx = usize::from(supports); // the other singleton

    let mut masses: std::collections::BTreeMap<FocalElement, f64> =
        std::collections::BTreeMap::new();
    masses.insert(FocalElement::positive(BTreeSet::from([primary_idx])), m_primary);
    if m_against > 1e-10 {
        masses.insert(FocalElement::positive(BTreeSet::from([opposing_idx])), m_against);
    }
    if m_theta > 1e-10 {
        masses.insert(FocalElement::theta(frame), m_theta);
    }
    MassFunction::new(frame.clone(), masses).map_err(|e| format!("build BBA: {e}"))
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

    // Store BBA (perspective_id=NULL for auto-wired). source_strength is the
    // evidence-type reliability weight (used as Shafer's reliability discount
    // at combination time). Agent confidence is already encoded in the BBA's
    // mass shape (mass = confidence * weight, clamped); using `confidence`
    // here would double-discount.
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent_id),
        None, // no perspective
        &masses_json,
        None,
        Some("auto_wire"),
        Some(weight),  // source_strength = evidence-type reliability
        evidence_type, // evidence_type
        "unknown",     // ds_auto single-evidence path; locality lives on edge_factor (issue #197)
        None, // no evidence row in scope on the new-claim initial-write path (issue #197 Phase 3)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // BetP-drop fix (backlog b3d12e2a): previously this path discounted by
    // `confidence`, while the batch writer applied NO discount and the
    // update/recompute paths discount by `effective_source_strength` — three
    // writers, three answers for the same stored BBA. Unify onto the SAME
    // discount authority (`effective_source_strength`) so the new-claim initial
    // cache matches the first `update_with_evidence` and `recompute_beliefs`.
    //
    // We re-read the row we just stored and compute its discounted single-BBA
    // measures inline, mirroring the `all_rows.len() <= 1` branch of
    // `auto_wire_ds_update` below. (Honest cost: this duplicates the
    // calibration-load block rather than calling the engine `recombine` fn —
    // `recompute_claim_belief_on_frame` returns `bool`, not the measures, so it
    // cannot hand back the scalars this fn must return in DsAutoResult. The
    // shared invariant is the discount AUTHORITY, not a single code path.)
    //
    // NOTE: because submit_claim persists `truth_value = clamped(ds.pignistic_prob)`,
    // this also shifts the new-claim persisted truth_value from a confidence-based
    // value to the evidence-type-discounted BetP — a deliberate, correctness-positive
    // change in persisted truth, not only in cached BetP.
    let calibration = epigraph_engine::calibration::CalibrationConfig::from_workspace_root()
        .unwrap_or_else(|_| {
            epigraph_engine::calibration::CalibrationConfig::default_for_phase2_fallback()
        });
    let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
        .await
        .ok()
        .flatten();
    let per_frame_evidence_weights =
        FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
            .await
            .ok()
            .flatten();

    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    let row = all_rows
        .first()
        .ok_or_else(|| "no BBA row after store_with_perspective".to_string())?;
    let reliability = effective_source_strength(
        row,
        per_frame_intra,
        per_frame_evidence_weights.as_ref(),
        &calibration,
    );
    let mf = parse_stored_bba(&frame, &row.masses)?;
    let discounted = combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
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

    // Materialize a synthetic perspective with id=evidence_id so the
    // mass_functions.perspective_id FK is satisfied. Without this, every
    // multi-evidence update path (report_workflow_outcome, update_with_evidence)
    // failed with mass_functions_perspective_id_fkey since C-1 (355cf4f).
    if let Some(persp_id) = evidence_id {
        PerspectiveRepository::ensure_evidence_perspective(pool, persp_id, Some(agent_id))
            .await
            .map_err(|e| format!("ensure_evidence_perspective: {e}"))?;
    }

    // Store BBA — use evidence_id as perspective_id so each evidence submission
    // gets its own row instead of upsert-overwriting on (claim, frame, agent, NULL).
    // source_strength = evidence-type reliability weight (used for Shafer
    // discount at combination time); agent confidence is already in the
    // BBA mass shape, storing it here too would double-discount.
    MassFunctionRepository::store_with_perspective(
        pool,
        claim_id,
        frame_id,
        Some(agent_id),
        evidence_id, // C-1: unique perspective per evidence prevents overwrite
        &masses_json,
        None,
        Some("auto_wire"),
        Some(weight),      // source_strength = evidence-type reliability
        evidence_type_str, // evidence_type
        "unknown",         // ds_auto evidence path; locality not derived here (issue #197)
        evidence_id, // Phase 3: the FK to the evidence row that produced this BBA (issue #197)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // Retrieve all BBAs and combine WITH reliability discount
    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;

    // Phase 2 (issue #197): the combine path no longer trusts the
    // stored `source_strength` as the authority. The Phase 2 helper
    // derives reliability dynamically from (`evidence_type`,
    // `locality_tag`, per-frame factor, calibration). Calibration I/O
    // failure falls back to the synthetic config (intra 0.3, every
    // evidence_type → 0.5 unknown) which mirrors the pre-Phase-2
    // hardcodes. See effective_source_strength docs in
    // `epigraph_engine::edge_factor` for the full fallback chain.
    let calibration = epigraph_engine::calibration::CalibrationConfig::from_workspace_root()
        .unwrap_or_else(|_| {
            epigraph_engine::calibration::CalibrationConfig::default_for_phase2_fallback()
        });
    let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
        .await
        .ok()
        .flatten();

    // Phase 4 (issue #197): per-frame evidence-type weight override map.
    // When set, its keyed entries win over the global calibration table
    // at Tier 1 of `effective_source_strength`. Loaded once above the
    // combine loop. On any DB error we fall through to `None`.
    let per_frame_evidence_weights =
        FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
            .await
            .ok()
            .flatten();

    let combined = if all_rows.len() <= 1 {
        // Single BBA — still apply discount
        let r = all_rows
            .first()
            .expect("len <= 1 with non-empty check: store_with_perspective wrote one");
        let reliability = effective_source_strength(
            r,
            per_frame_intra,
            per_frame_evidence_weights.as_ref(),
            &calibration,
        );
        let mf = parse_stored_bba(&frame, &r.masses)?;
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?
    } else {
        // Multiple BBAs — discount each via the helper, then combine.
        let mut mass_fns = Vec::with_capacity(all_rows.len());
        for row in &all_rows {
            let mf = parse_stored_bba(&frame, &row.masses)?;
            let reliability = effective_source_strength(
                row,
                per_frame_intra,
                per_frame_evidence_weights.as_ref(),
                &calibration,
            );
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
        Some(entry.weight), // source_strength = methodology weight (legacy fallback when evidence_type is None)
        entry.evidence_type.as_deref(), // evidence_type → effective_source_strength / frame function
        "unknown",                      // batch ds_auto path; no per-entry locality (issue #197)
        None, // batch path predates per-claim evidence rows (issue #197 Phase 3)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    // BetP-drop fix (backlog b3d12e2a): the initial cache MUST be written
    // through the same discount authority every other writer uses. Calling
    // compute_measures(&bba) on the raw, UNDISCOUNTED BBA here recorded an
    // inflated m({TRUE})/BetP; the first `update_with_evidence` then re-read
    // all rows, re-discounted this one by `effective_source_strength`
    // (e.g. statistical=0.9, circumstantial=0.4, unknown=0.5) and recombined
    // from scratch, dropping the cached BetP even though a SUPPORTING source
    // was just added (observed 0.848 -> 0.716). Routing through the canonical
    // recombine makes the initial cache agree with auto_wire_ds_update and
    // recompute_beliefs. `recompute_claim_belief_on_frame` re-reads the row we
    // just stored, applies `effective_source_strength`, and writes Bel/Pl/BetP
    // (and, on the binary frame, classification) via update_claim_belief.
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(pool, entry.claim_id, frame_id)
        .await
        .map_err(|e| format!("recompute initial cache: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod build_binary_bba_shape_tests {
    use super::*;
    use epigraph_ds::measures;

    fn frame() -> FrameOfDiscernment {
        binary_frame().expect("binary frame")
    }

    #[test]
    fn supporting_bba_has_plausibility_true_below_one() {
        // Backlog b3d12e2a Fix(2): a supporting BBA must NOT be a pure
        // simple-support function (which pins Pl(TRUE)=1.0). With base_against
        // mass on {FALSE}, Pl(TRUE) = m({TRUE}) + m(theta) < 1.0.
        let f = frame();
        let bba = build_binary_bba(&f, /*confidence*/ 0.85, /*weight*/ 0.9, /*supports*/ true)
            .expect("build supporting BBA");
        let true_el = FocalElement::positive(std::collections::BTreeSet::from([0_usize]));
        let pl_true = measures::plausibility(&bba, &true_el);
        let bel_true = measures::belief(&bba, &true_el);
        assert!(
            pl_true < 1.0 - 1e-9,
            "Pl(TRUE) must be < 1.0 after Fix(2); got {pl_true} (simple-support regression)"
        );
        // Bel(TRUE) = mass on subsets of {TRUE} = m({TRUE}) only; the directed
        // shape must NOT change the primary support mass (SciFact calibration
        // guard). m_primary = (0.85*0.9).clamp(0.01,0.99) = 0.765.
        assert!(
            (bel_true - 0.765).abs() < 1e-6,
            "Bel(TRUE) must remain the primary support mass 0.765; got {bel_true}"
        );
        // The opposing singleton {FALSE} must now carry the base_against mass.
        let false_el = FocalElement::positive(std::collections::BTreeSet::from([1_usize]));
        let m_false = bba.mass_of(&false_el);
        assert!(
            (m_false - 0.08).abs() < 1e-9,
            "m({{FALSE}}) must equal base_against 0.08; got {m_false}"
        );
    }

    #[test]
    fn high_confidence_support_does_not_underflow_against_or_theta() {
        // Edge: confidence*weight clamps to 0.99, leaving only 0.01 for
        // against+theta. base_against must shrink to fit so MassFunction::new
        // (which validates sum==1.0) does not reject the BBA.
        let f = frame();
        let bba = build_binary_bba(&f, 1.0, 1.0, true).expect("clamped high-confidence BBA");
        let total: f64 = [
            FocalElement::positive(std::collections::BTreeSet::from([0_usize])),
            FocalElement::positive(std::collections::BTreeSet::from([1_usize])),
            FocalElement::theta(&f),
        ]
        .iter()
        .map(|e| bba.mass_of(e))
        .sum();
        assert!((total - 1.0).abs() < 1e-9, "masses must sum to 1.0; got {total}");
    }
}
