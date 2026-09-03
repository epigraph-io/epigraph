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
    /// Declared labeled axis to place this claim on (issue #222). `None` → the
    /// canonical binary `{TRUE, FALSE}` frame, i.e. today's behaviour.
    pub axis: Option<epigraph_ingest::common::plan::PlannedAxis>,
}

/// Canonical binary frame name.
const BINARY_FRAME_NAME: &str = "binary_truth";
/// Hypotheses for the canonical binary frame.
const BINARY_HYPOTHESES: [&str; 2] = ["TRUE", "FALSE"];

/// Get-or-create the canonical `binary_truth` frame.
///
/// Handles race conditions: get → create → fallback get.
pub async fn ensure_binary_frame(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<Uuid, String> {
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    ensure_axis_frame(
        pool,
        viewer,
        BINARY_FRAME_NAME,
        &hyps,
        Some("Canonical binary frame: {TRUE, FALSE}"),
    )
    .await
}

/// Get-or-create a frame by name over `hypotheses` — the generalization of
/// [`ensure_binary_frame`] to any declared labeled axis (issue #222).
///
/// Frames dedupe by NAME (the DB has a unique index on it), so an existing frame
/// under this name is reused. Its stored hypotheses must match `hypotheses`
/// exactly, including order: the index a label resolves to is positional, so
/// reusing a same-named frame with a different list would silently place claims
/// on a different hypothesis than the caller declared. That mismatch is an error.
///
/// Handles the create race the same way as before: get → create → fallback get.
pub async fn ensure_axis_frame(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    name: &str,
    hypotheses: &[String],
    description: Option<&str>,
) -> Result<Uuid, String> {
    // Fast path: frame already exists — verify the axis agrees before reuse.
    if let Some(row) = FrameRepository::get_by_name(pool, viewer, name)
        .await
        .map_err(|e| format!("get_by_name: {e}"))?
    {
        if row.hypotheses != hypotheses {
            return Err(format!(
                "frame {name:?} already exists over {:?}, but this claim declares {hypotheses:?}; \
                 a frame name denotes one ordered axis (issue #222)",
                row.hypotheses
            ));
        }
        return Ok(row.id);
    }

    match FrameRepository::create(pool, name, description, hypotheses).await {
        Ok(row) => Ok(row.id),
        Err(_) => {
            // Race: another connection created it first — re-fetch and re-verify.
            let row = FrameRepository::get_by_name(pool, viewer, name)
                .await
                .map_err(|e| format!("fallback get_by_name: {e}"))?
                .ok_or_else(|| format!("frame {name:?} missing after create attempt"))?;
            if row.hypotheses != hypotheses {
                return Err(format!(
                    "frame {name:?} was concurrently created over {:?}, but this claim declares \
                     {hypotheses:?}",
                    row.hypotheses
                ));
            }
            Ok(row.id)
        }
    }
}

/// Build a simple-support BBA for a binary frame: `m({primary}) =
/// (confidence*weight).clamp(0.01, 0.99)`, with the remainder on Θ.
///
/// NOTE (backlog b3d12e2a): an earlier Fix(2) added a fixed `base_against`
/// opposing-singleton mass to make `Pl(primary) < 1.0`. That was reverted —
/// it flipped weakly-supported claims (where `confidence*weight < base_against`)
/// to `contradicted` (regression in `classify_test::high_ignorance_*`), and
/// nothing consumes the plausibility headroom today. The reported BetP-drop bug
/// is fixed by the writer discount-authority unification (Fix(1)), not by this
/// shape change. Reintroduce a directed shape only with a bound that keeps the
/// opposing mass strictly below the primary mass, and only when a real consumer
/// of `Pl(primary) < 1.0` exists.
fn build_binary_bba(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    supports: bool,
) -> Result<MassFunction, String> {
    let idx = usize::from(!supports); // 0=TRUE, 1=FALSE
    build_bba_on_index(frame, confidence, weight, idx)
}

/// Simple-support BBA placing `m({idx}) = (confidence*weight).clamp(0.01, 0.99)`
/// with the remainder on Θ — [`build_binary_bba`] generalized to any hypothesis
/// index on any frame (issue #222).
///
/// Same mass SHAPE as the binary case, just aimed at the declared label instead
/// of TRUE/FALSE, so all the discounting and combination behaviour downstream is
/// unchanged.
fn build_bba_on_index(
    frame: &FrameOfDiscernment,
    confidence: f64,
    weight: f64,
    idx: usize,
) -> Result<MassFunction, String> {
    let mass = (confidence * weight).clamp(0.01, 0.99);
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

/// Construct a `FrameOfDiscernment` for a declared axis (issue #222).
fn axis_frame(name: &str, hypotheses: &[String]) -> Result<FrameOfDiscernment, String> {
    FrameOfDiscernment::new(name.to_string(), hypotheses.to_vec())
        .map_err(|e| format!("axis frame {name:?}: {e}"))
}

/// Compute Bel/Pl/BetP for hypothesis 0 (TRUE) from a combined mass function.
fn compute_measures(combined: &MassFunction) -> (Prob, Prob, Prob, Prob, Prob) {
    compute_measures_on_index(combined, 0)
}

/// Compute Bel/Pl/BetP for an arbitrary hypothesis index (issue #222).
///
/// On the binary frame `idx` is 0 and this is exactly [`compute_measures`]. On a
/// declared axis it must be the index the claim asserts — reporting Bel(index 0)
/// for a claim placed on `moderate` would cache a belief about `ineffective`.
/// This matches how the read side already behaves:
/// `epigraph_engine::belief_query` targets the claim's stored
/// `claim_frames.hypothesis_index`.
fn compute_measures_on_index(
    combined: &MassFunction,
    idx: usize,
) -> (Prob, Prob, Prob, Prob, Prob) {
    let target = FocalElement::positive(BTreeSet::from([idx]));
    let bel = measures::belief(combined, &target);
    let pl = measures::plausibility(combined, &target);
    let betp = measures::pignistic_probability(combined, idx);
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

/// The evidential content of one auto-wire call.
///
/// Bundled rather than passed positionally because `confidence` and `weight`
/// are adjacent bare `f64`s: `(.., confidence, 0.6, true, None)` compiles just
/// as happily with the two transposed, and the result is a silently
/// mis-weighted BBA rather than an error. Named fields make that a compile
/// error. (Adding `viewer` for tenancy also pushed this to 8 arguments and
/// tripped `clippy::too_many_arguments`, but the count is the symptom.)
#[derive(Debug, Clone, Copy)]
pub struct DsAutoInput<'a> {
    /// Belief mass for the supported hypothesis, in `[0, 1]`.
    pub confidence: f64,
    /// Source-reliability discount applied to the BBA, in `[0, 1]`.
    pub weight: f64,
    /// Whether the evidence supports (`true`) or opposes (`false`) the claim.
    pub supports: bool,
    /// Evidence classification tag, when the caller has one.
    pub evidence_type: Option<&'a str>,
}

/// Auto-wire DS for a **new** claim.
///
/// Creates a BBA, assigns the claim to the binary frame, computes Bel/Pl/BetP,
/// and updates the claim's DS columns.
pub async fn auto_wire_ds_for_claim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    agent_id: Uuid,
    input: DsAutoInput<'_>,
) -> Result<DsAutoResult, String> {
    let DsAutoInput {
        confidence,
        weight,
        supports,
        evidence_type,
    } = input;
    let frame_id = ensure_binary_frame(pool, viewer).await?;
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

    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, viewer, claim_id, frame_id)
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
    let discounted =
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
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
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    agent_id: Uuid,
    confidence: f64,
    weight: f64,
    supports: bool,
    evidence_type_str: Option<&str>, // NEW: evidence classification tag
    evidence_id: Option<Uuid>,       // C-1: used as perspective_id to separate BBAs
) -> Result<DsAutoResult, String> {
    let frame_id = ensure_binary_frame(pool, viewer).await?;
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

    // Retrieve BBAs from ALL 2-hypothesis frames for this claim. The DB JOIN
    // on frames ensures we only include frames with exactly 2 hypotheses —
    // a BBA from a 3+-hypothesis frame whose focal elements happen to use only
    // indices 0 and 1 would be semantically wrong when parsed as binary_frame()
    // ({0,1} in a ternary frame ≠ Theta on binary). Cross-frame retrieval
    // prevents frame-fragmentation loss: BBAs written to legacy binary frames
    // (e.g. "research_validity") are included so update_with_evidence combines
    // the full evidence history rather than starting fresh from just the new
    // BBA — the root cause of the BetP drop in backlog 30bfbb19
    // (claims c98b6dec, adf396a8: 0.883→0.725, 0.834→0.733).
    let all_rows = MassFunctionRepository::get_for_claim_binary_frames(pool, viewer, claim_id)
        .await
        .map_err(|e| format!("get_for_claim_binary_frames: {e}"))?;

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

    // Read current pignistic_prob for monotonicity clamp.  Supporting evidence
    // must never lower BetP: high-conflict K between legacy mixed-format BBAs
    // (m({0})>0 AND m({1})>0) and a new pure-support BBA can push mass to
    // missing via Inagaki redistribution and reduce pignistic_prob even when
    // supports=true.  We bound the result from below by the pre-addition value.
    let prior_betp: Option<f64> = {
        // PR-09: a per-id belief oracle over a caller-supplied uuid, so it
        // is filtered rather than exempted. `unwrap_or(None)` already
        // treats "no row" as "no prior", so an invisible claim degrades to
        // the same answer a nonexistent one gives — no new failure mode.
        let sql = viewer.splice(
            "SELECT c.pignistic_prob FROM claims c \
                 WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Option<f64>>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_optional(pool).await.ok().flatten().flatten()
    };

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

    let (bel, pl, mut betp, conflict, missing) = compute_measures(&combined);

    // Monotonicity clamp: supports=true evidence must not lower pignistic_prob.
    if supports {
        if let Some(prior) = prior_betp {
            if betp < prior {
                betp = prior;
            }
        }
    }

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
/// Resolves the binary frame once and each declared axis frame once (cached by
/// name), then wires each claim sequentially. Individual failures are logged and
/// skipped.
///
/// The returned `Uuid` is the `binary_truth` frame — the batch's default frame,
/// and what `ds_frame_id` on the ingest response has always meant. Claims placed
/// on a declared axis (issue #222) are wired on their own frame; read those back
/// per claim via `claim_frames` rather than from this single id.
pub async fn auto_wire_ds_batch(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    entries: &[BatchDsEntry],
    agent_id: Uuid,
) -> Result<(Uuid, usize), String> {
    if entries.is_empty() {
        return Err("empty batch".to_string());
    }

    let binary_frame_id = ensure_binary_frame(pool, viewer).await?;
    let binary = binary_frame()?;
    // Axis frames resolved on first use, keyed by frame name. Keeps a sweep of N
    // atoms on one axis to a single get-or-create round trip, as the binary path
    // has always had.
    let mut axis_frames: std::collections::HashMap<String, (Uuid, FrameOfDiscernment)> =
        std::collections::HashMap::new();
    let mut wired = 0_usize;

    for entry in entries {
        let resolved = match &entry.axis {
            None => Ok((binary_frame_id, binary.clone(), 0_usize)),
            Some(axis) => match axis_frames.get(&axis.frame) {
                Some((id, frame)) => Ok((*id, frame.clone(), axis.hypothesis_index)),
                None => match ensure_axis_frame(pool, viewer, &axis.frame, &axis.hypotheses, None)
                    .await
                {
                    Err(e) => Err(e),
                    Ok(id) => match axis_frame(&axis.frame, &axis.hypotheses) {
                        Err(e) => Err(e),
                        Ok(frame) => {
                            axis_frames.insert(axis.frame.clone(), (id, frame.clone()));
                            Ok((id, frame, axis.hypothesis_index))
                        }
                    },
                },
            },
        };
        let (frame_id, frame, idx) = match resolved {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    claim_id = %entry.claim_id,
                    "ds_auto batch skip (axis frame): {e}"
                );
                continue;
            }
        };

        if let Err(e) =
            wire_single_batch_entry(pool, viewer, &frame, frame_id, idx, entry, agent_id).await
        {
            tracing::warn!(
                claim_id = %entry.claim_id,
                "ds_auto batch skip: {e}"
            );
            continue;
        }
        wired += 1;
    }

    Ok((binary_frame_id, wired))
}

/// Wire a single claim in a batch context (frame already resolved).
///
/// `hypothesis_index` is the hypothesis the claim asserts — 0 (TRUE) on the
/// binary frame, or the declared label's index on an axis (issue #222). It is
/// both the BBA's focal element and the `claim_frames.hypothesis_index` the
/// belief readers target.
async fn wire_single_batch_entry(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    frame: &FrameOfDiscernment,
    frame_id: Uuid,
    hypothesis_index: usize,
    entry: &BatchDsEntry,
    agent_id: Uuid,
) -> Result<(), String> {
    let bba = build_bba_on_index(frame, entry.confidence, entry.weight, hypothesis_index)?;
    let masses_json = mass_to_json(&bba)?;

    let idx_i32 = i32::try_from(hypothesis_index)
        .map_err(|_| format!("hypothesis_index {hypothesis_index} out of range"))?;
    FrameRepository::assign_claim(pool, entry.claim_id, frame_id, Some(idx_i32))
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
    epigraph_engine::edge_factor::recompute_claim_belief_on_frame(
        pool,
        viewer,
        entry.claim_id,
        frame_id,
    )
    .await
    .map_err(|e| format!("recompute initial cache: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn potency_frame() -> FrameOfDiscernment {
        axis_frame(
            "anxiolytic_potency",
            &[
                "ineffective".to_string(),
                "mild".to_string(),
                "moderate".to_string(),
                "strong".to_string(),
            ],
        )
        .expect("4-hypothesis frame")
    }

    /// The generalized builder must reproduce the binary builder exactly on the
    /// binary frame — the backward-compatibility guarantee for issue #222.
    #[test]
    fn binary_builder_is_the_index_builder_at_0_and_1() {
        let frame = binary_frame().expect("binary frame");
        for (supports, idx) in [(true, 0_usize), (false, 1_usize)] {
            let via_binary = build_binary_bba(&frame, 0.8, 0.9, supports).expect("binary BBA");
            let via_index = build_bba_on_index(&frame, 0.8, 0.9, idx).expect("indexed BBA");
            assert_eq!(
                mass_to_json(&via_binary).expect("json"),
                mass_to_json(&via_index).expect("json"),
                "supports={supports} must equal index {idx}"
            );
        }
    }

    /// Mass lands on the DECLARED hypothesis, with the remainder on Θ — the same
    /// simple-support shape the binary path uses, just aimed elsewhere.
    #[test]
    fn axis_bba_places_mass_on_the_declared_index() {
        let frame = potency_frame();
        let bba = build_bba_on_index(&frame, 0.8, 0.9, 2).expect("BBA on 'moderate'");
        let expected = (0.8_f64 * 0.9).clamp(0.01, 0.99);

        let on_moderate = bba.mass_of(&FocalElement::positive(BTreeSet::from([2_usize])));
        assert!(
            (on_moderate - expected).abs() < 1e-12,
            "m({{moderate}}) = {on_moderate}, want {expected}"
        );
        // Nothing on the sibling hypotheses: a claim placed on `moderate` asserts
        // nothing about `mild` or `strong` beyond the shared ignorance mass.
        for other in [0_usize, 1, 3] {
            let m = bba.mass_of(&FocalElement::positive(BTreeSet::from([other])));
            assert!(m.abs() < 1e-12, "unexpected mass {m} on hypothesis {other}");
        }
        let theta = bba.mass_of(&FocalElement::theta(&frame));
        assert!(
            (theta - (1.0 - expected)).abs() < 1e-12,
            "remainder must sit on Theta, got {theta}"
        );
    }

    /// The crux of the correctness argument: measures must be read at the
    /// declared index. Reading index 0 for a claim placed on `moderate` reports
    /// belief in `ineffective`.
    #[test]
    fn measures_at_the_declared_index_differ_from_index_zero() {
        let frame = potency_frame();
        let bba = build_bba_on_index(&frame, 0.9, 1.0, 2).expect("BBA on 'moderate'");

        let (bel_at_2, _, betp_at_2, _, _) = compute_measures_on_index(&bba, 2);
        let (bel_at_0, _, betp_at_0, _, _) = compute_measures_on_index(&bba, 0);

        assert!(
            (bel_at_2 - 0.9).abs() < 1e-12,
            "Bel(moderate) should be the asserted mass, got {bel_at_2}"
        );
        assert!(
            bel_at_0.abs() < 1e-12,
            "Bel(ineffective) must be 0 — nothing was asserted about it, got {bel_at_0}"
        );
        assert!(
            betp_at_2 > betp_at_0,
            "BetP(moderate)={betp_at_2} must exceed BetP(ineffective)={betp_at_0}"
        );
    }

    /// `compute_measures` (the binary entry point) must stay identical to the
    /// generalized form at index 0, so no existing caller changes behaviour.
    #[test]
    fn compute_measures_is_index_zero() {
        let frame = binary_frame().expect("binary frame");
        let bba = build_binary_bba(&frame, 0.7, 0.8, true).expect("BBA");
        assert_eq!(compute_measures(&bba), compute_measures_on_index(&bba, 0));
    }

    /// Every hypothesis on the axis is reachable, including the last index —
    /// guards an off-by-one in the label→index resolution.
    #[test]
    fn every_hypothesis_index_is_addressable() {
        let frame = potency_frame();
        for idx in 0..4_usize {
            let bba = build_bba_on_index(&frame, 0.6, 1.0, idx).expect("BBA");
            let (bel, _, _, _, _) = compute_measures_on_index(&bba, idx);
            assert!((bel - 0.6).abs() < 1e-12, "index {idx} gave Bel {bel}");
        }
    }

    /// An index outside the frame is a construction error, not a silent
    /// placement on some other hypothesis.
    #[test]
    fn out_of_range_index_is_an_error() {
        let frame = potency_frame();
        assert!(build_bba_on_index(&frame, 0.5, 1.0, 4).is_err());
    }

    /// Division of responsibility: `FrameOfDiscernment::new` only rejects an
    /// EMPTY frame (and silently dedupes), so the "at least 2 distinct
    /// hypotheses" contract is enforced upstream by
    /// `epigraph_ingest::document::axis` validation, not here. This pins that
    /// split so a future reader does not assume the DS layer guards it.
    #[test]
    fn axis_frame_rejects_only_the_empty_frame() {
        assert!(axis_frame("empty", &[]).is_err());
        // A degenerate 1-hypothesis frame is accepted at this layer...
        assert!(axis_frame("solo", &["only".to_string()]).is_ok());
        // ...and rejected by the ingest-side validator that callers go through.
        let decl = epigraph_ingest::document::schema::AxisDeclaration {
            frame: "solo".to_string(),
            hypotheses: vec!["only".to_string()],
            label: "only".to_string(),
        };
        let para = epigraph_ingest::document::schema::Paragraph {
            text: "p".to_string(),
            span: None,
            atoms: vec!["a".to_string()],
            generality: Vec::new(),
            confidence: 0.8,
            methodology: None,
            evidence_type: None,
            axis: Some(decl),
            axis_labels: Vec::new(),
            page: None,
            instruments_used: Vec::new(),
            reagents_involved: Vec::new(),
            conditions: Vec::new(),
        };
        let section = epigraph_ingest::document::schema::Section {
            title: "s".to_string(),
            heading_span: None,
            axis: None,
            paragraphs: vec![],
        };
        assert!(
            epigraph_ingest::document::axis::resolve_paragraph_axes(&para, &section).is_err(),
            "the ingest-side validator must reject a 1-hypothesis axis"
        );
    }

    /// Mass is clamped into [0.01, 0.99] on an axis exactly as on the binary
    /// frame, so a 0-confidence or 1.0-confidence claim stays combinable.
    #[test]
    fn axis_mass_is_clamped_like_the_binary_path() {
        let frame = potency_frame();
        let lo = build_bba_on_index(&frame, 0.0, 1.0, 1).expect("BBA");
        let hi = build_bba_on_index(&frame, 1.0, 1.0, 1).expect("BBA");
        let m = |b: &MassFunction| b.mass_of(&FocalElement::positive(BTreeSet::from([1_usize])));
        assert!((m(&lo) - 0.01).abs() < 1e-12, "got {}", m(&lo));
        assert!((m(&hi) - 0.99).abs() < 1e-12, "got {}", m(&hi));
    }
}
