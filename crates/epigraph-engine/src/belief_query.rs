//! Library-level `get_belief` function.
//!
//! Lifted from `epigraph-mcp/src/tools/ds.rs` so episcience and other crates
//! can call it with `(pool, claim_id, frame_id)` without spawning MCP-over-stdio.
//!
//! The MCP handler in `tools/ds.rs` becomes a thin adapter that delegates here
//! and shapes the result into a `CallToolResult`.

use std::collections::BTreeSet;

use epigraph_core::ClaimId;
use epigraph_db::{
    ClaimRepository, FrameRepository, MassFunctionRepository, MassFunctionRow,
    PerspectiveRepository, PgPool,
};
use epigraph_ds::{combination, FocalElement, FrameOfDiscernment, MassFunction};
use thiserror::Error;

use crate::calibration::CalibrationConfig;
use crate::edge_factor::{
    effective_source_strength, effective_source_strength_with_perspective, PerspectiveReliability,
};
use uuid::Uuid;

/// Errors from the library-level `get_belief` function.
#[derive(Debug, Error)]
pub enum BeliefQueryError {
    /// Database access failed.
    #[error("database error: {0}")]
    Db(#[from] epigraph_db::DbError),

    /// Dempster-Shafer computation failed (e.g. total conflict, empty frame).
    #[error("DS computation error: {0}")]
    Ds(#[from] epigraph_ds::DsError),

    /// Failed to parse mass function JSON (returned as `String` by `from_json_masses`).
    #[error("failed to parse mass function: {0}")]
    ParseMasses(String),

    /// The requested frame does not exist.
    #[error("frame {0} not found")]
    FrameNotFound(Uuid),

    /// The requested claim does not exist.
    #[error("claim {0} not found")]
    ClaimNotFound(Uuid),
}

/// Result of a belief query.
///
/// Mirrors the fields returned by the MCP `get_belief` tool.
#[derive(Debug, Clone, PartialEq)]
pub struct BeliefInterval {
    /// Dempster-Shafer belief (lower bound on probability).
    pub belief: f64,
    /// Dempster-Shafer plausibility (upper bound on probability).
    pub plausibility: f64,
    /// Pignistic probability (BetP) — use this for ordering claims.
    pub pignistic_prob: f64,
    /// Mass on the conflict focal element.
    pub mass_on_conflict: f64,
    /// Mass on the missing focal element.
    pub mass_on_missing: f64,
    /// `true` when the result was computed from a specific frame; `false` for
    /// the unframed cached fallback.
    pub framed: bool,
    /// Short string describing how the value was derived.
    ///
    /// Possible values: `"recomputed"`, `"no_bbas"`, `"cached"`.
    pub source: String,
}

impl BeliefInterval {
    /// Default returned when the frame exists but has no BBAs for this claim.
    pub fn empty_frame(hypothesis_count: usize) -> Self {
        Self {
            belief: 0.0,
            plausibility: 1.0,
            pignistic_prob: 1.0 / hypothesis_count as f64,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            framed: true,
            source: "no_bbas".to_string(),
        }
    }

    /// Default returned when no frame is specified and the claim has no DS data.
    pub fn cached_from_truth(truth_value: f64) -> Self {
        Self {
            belief: truth_value,
            plausibility: 1.0,
            pignistic_prob: truth_value,
            mass_on_conflict: 0.0,
            mass_on_missing: 0.0,
            framed: false,
            source: "cached".to_string(),
        }
    }
}

/// Query belief for `claim_id`, optionally scoped to `frame_id`.
///
/// - If `frame_id` is `Some`, live-recomputes Bel/Pl/BetP from stored BBAs
///   using Dempster's combination rule (mirrors the MCP framed path).
/// - If `frame_id` is `None`, returns the cached DS columns from the claim row
///   (mirrors the MCP unframed path).
///
/// # Errors
///
/// Returns `BeliefQueryError::FrameNotFound` when `frame_id` is specified but
/// the frame does not exist.  Returns `BeliefQueryError::ClaimNotFound` when
/// the claim does not exist (unframed path only).
pub async fn get_belief(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Option<Uuid>,
) -> Result<BeliefInterval, BeliefQueryError> {
    if let Some(frame_id) = frame_id {
        // ── Framed path: live recomputation from stored BBAs ──────────────
        let frame_row = FrameRepository::get_by_id(pool, frame_id)
            .await?
            .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;

        let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

        let assignment = FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
        let hypothesis_index = assignment.and_then(|a| a.hypothesis_index).unwrap_or(0) as usize;

        let all_bbas =
            MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;

        if all_bbas.is_empty() {
            return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
        }

        // Discount each BBA by its calibrated reliability (evidence-type weight
        // × locality, via `effective_source_strength`) before combining, so the
        // framed read agrees with the cached `claims.pignistic_prob` that the
        // recompute path writes. `perspective = None` → global calibration.
        let combined = recompute_framed_belief(pool, frame_id, &frame, &all_bbas, None)
            .await?
            .expect("all_bbas is non-empty so combination yields Some");

        let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
        let bel = epigraph_ds::measures::belief(&combined, &target);
        let pl = epigraph_ds::measures::plausibility(&combined, &target);
        let betp = epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index);

        return Ok(BeliefInterval {
            belief: bel,
            plausibility: pl,
            pignistic_prob: betp,
            mass_on_conflict: combined.mass_of_conflict(),
            mass_on_missing: combined.mass_of_missing(),
            framed: true,
            source: "recomputed".to_string(),
        });
    }

    // ── Unframed path: cached DS columns from claim row ───────────────────
    let claim = ClaimRepository::get_by_id(pool, ClaimId::from_uuid(claim_id))
        .await?
        .ok_or(BeliefQueryError::ClaimNotFound(claim_id))?;

    Ok(BeliefInterval::cached_from_truth(claim.truth_value.value()))
}

/// Compute a **perspective-scoped** belief on demand — the "frame function".
///
/// This is `get_belief`'s framed path re-weighted from one observer's
/// viewpoint: every stored BBA on `(claim, frame)` is Shafer-discounted by its
/// reliability *for this perspective* before combination, where the perspective
/// may override both the evidence-type weight (`source_reliability`) and the
/// locality factor (`locality_reliability`) on top of the per-frame / global
/// calibration tiers. Because it recomputes from the labelled BBAs, it works
/// regardless of how the evidence was ingested — no cache, no write-path
/// dependency. A perspective with neither map (or an absent perspective)
/// expresses no opinion, so the result reduces exactly to the global
/// `get_belief`.
///
/// # Errors
/// `FrameNotFound` if `frame_id` is absent; `ParseMasses`/`Ds` on malformed or
/// uncombinable BBAs; `Db` on query failure.
pub async fn get_perspective_belief(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<BeliefInterval, BeliefQueryError> {
    let frame_row = FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;
    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

    let assignment = FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
    let hypothesis_index = assignment.and_then(|a| a.hypothesis_index).unwrap_or(0) as usize;

    let all_bbas = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;
    if all_bbas.is_empty() {
        return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
    }

    // The perspective's frame-function config: source-reliability (evidence
    // type) + locality-reliability (pathway). Absent/empty → no opinion → the
    // computation reduces to the global `get_belief`.
    let perspective = PerspectiveRepository::get_by_id(pool, perspective_id)
        .await?
        .map(|p| PerspectiveReliability {
            source_reliability: p.source_reliability().unwrap_or_default(),
            locality_reliability: p.locality_reliability().unwrap_or_default(),
        })
        .unwrap_or_default();

    let combined = recompute_framed_belief(pool, frame_id, &frame, &all_bbas, Some(&perspective))
        .await?
        .expect("all_bbas is non-empty so combination yields Some");

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    Ok(BeliefInterval {
        belief: epigraph_ds::measures::belief(&combined, &target),
        plausibility: epigraph_ds::measures::plausibility(&combined, &target),
        pignistic_prob: epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index),
        mass_on_conflict: combined.mass_of_conflict(),
        mass_on_missing: combined.mass_of_missing(),
        framed: true,
        source: "recomputed_perspective".to_string(),
    })
}

/// The per-frame reliability inputs a framed-belief combination needs, resolved
/// ONCE per `(frame)` and reused across every claim on a page.
///
/// Hoisting these out of the per-claim combine is what eliminates the lensed
/// recall N+1: the perspective row, the two per-frame override lookups, and the
/// calibration config are frame/perspective-scoped, not claim-scoped, so a
/// 20-hit page previously re-resolved all four 20 times. [`FramedBeliefContext`]
/// captures them so the batch path resolves them once (see
/// [`get_perspective_belief_batch`]) and the pure combine
/// ([`combine_framed_bbas`]) touches the DB zero more times.
struct FramedBeliefContext {
    calibration: CalibrationConfig,
    per_frame_intra: Option<f64>,
    per_frame_weights: Option<std::collections::HashMap<String, f64>>,
    perspective: Option<PerspectiveReliability>,
}

impl FramedBeliefContext {
    /// Resolve the frame-scoped reliability inputs from the DB exactly once.
    ///
    /// Per-frame loads are best-effort: a DB error there falls back to global
    /// calibration (`.ok().flatten()`) rather than failing the read — matching
    /// the pre-refactor `recompute_framed_belief` semantics exactly. When
    /// `perspective_id` is `Some`, the perspective row is resolved and an
    /// unknown/empty perspective reduces to no opinion (`unwrap_or_default`),
    /// so a lensed read over an un-configured observer equals the global read.
    async fn resolve(
        pool: &PgPool,
        frame_id: Uuid,
        perspective_id: Option<Uuid>,
    ) -> Result<Self, BeliefQueryError> {
        let calibration = CalibrationConfig::from_workspace_root()
            .unwrap_or_else(|_| CalibrationConfig::default_for_phase2_fallback());
        let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
            .await
            .ok()
            .flatten();
        let per_frame_weights =
            FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
                .await
                .ok()
                .flatten();
        let perspective = match perspective_id {
            Some(pid) => Some(
                PerspectiveRepository::get_by_id(pool, pid)
                    .await?
                    .map(|p| PerspectiveReliability {
                        source_reliability: p.source_reliability().unwrap_or_default(),
                        locality_reliability: p.locality_reliability().unwrap_or_default(),
                    })
                    .unwrap_or_default(),
            ),
            None => None,
        };
        Ok(Self {
            calibration,
            per_frame_intra,
            per_frame_weights,
            perspective,
        })
    }
}

/// Combine a claim's stored BBAs into one mass function — the pure (no-DB) core
/// shared by the single-claim and batch framed-belief paths.
///
/// Each BBA is discounted by its effective reliability (the
/// `effective_source_strength` tier chain: per-frame override → global
/// calibration → stored `source_strength`, with locality applied; the
/// perspective overrides sit at the top when present) before the SAME adaptive
/// combination rule the recompute/write path uses (`combine_multiple`). All
/// reliability inputs arrive pre-resolved in `ctx`, so this function issues no
/// queries — the caller resolves `ctx` once and calls this per claim.
///
/// Returns `Ok(None)` only when `rows` is empty.
fn combine_framed_bbas(
    frame: &FrameOfDiscernment,
    rows: &[MassFunctionRow],
    ctx: &FramedBeliefContext,
) -> Result<Option<MassFunction>, BeliefQueryError> {
    if rows.is_empty() {
        return Ok(None);
    }

    let mut mass_fns: Vec<MassFunction> = Vec::with_capacity(rows.len());
    for row in rows {
        let mf = MassFunction::from_json_masses(frame.clone(), &row.masses)
            .map_err(BeliefQueryError::ParseMasses)?;
        let alpha = match ctx.perspective.as_ref() {
            Some(p) => effective_source_strength_with_perspective(
                row,
                ctx.per_frame_intra,
                ctx.per_frame_weights.as_ref(),
                &ctx.calibration,
                p,
            ),
            None => effective_source_strength(
                row,
                ctx.per_frame_intra,
                ctx.per_frame_weights.as_ref(),
                &ctx.calibration,
            ),
        };
        mass_fns.push(combination::discount(&mf, alpha).map_err(BeliefQueryError::Ds)?);
    }

    // Combine via the SAME adaptive rule the recompute/write path uses
    // (`combine_multiple`: canonical sort + per-step Dempster/Conjunctive/
    // Yager/Inagaki selection by conflict). Matching it — not a plain Dempster
    // fold — is what makes this compute-on-read result reproduce the recompute
    // path's combination for the same discounted BBAs.
    let (combined, _reports) =
        combination::combine_multiple(&mass_fns, 0.9).map_err(BeliefQueryError::Ds)?;
    Ok(Some(combined))
}

/// Recompute the combined mass function for a framed claim, discounting each
/// stored BBA by its effective reliability before Dempster combination.
///
/// This is the single-claim path both `get_belief` (perspective = `None`) and
/// `get_perspective_belief` use. It resolves the frame-scoped reliability
/// context ([`FramedBeliefContext::resolve`]) once, then delegates the actual
/// combination to the pure [`combine_framed_bbas`]. The batch path
/// ([`get_perspective_belief_batch`]) resolves the SAME context once and reuses
/// it across a whole page — that is the N+1 fix; both paths share
/// `combine_framed_bbas`, so their values are identical.
///
/// Returns `Ok(None)` only when `rows` is empty.
async fn recompute_framed_belief(
    pool: &PgPool,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    rows: &[MassFunctionRow],
    perspective: Option<&PerspectiveReliability>,
) -> Result<Option<MassFunction>, BeliefQueryError> {
    if rows.is_empty() {
        return Ok(None);
    }

    // Preserve the pre-refactor semantics: this path is only reached with an
    // already-resolved `PerspectiveReliability` (or `None`), so build the
    // context from the per-frame/calibration loads plus the passed reliability
    // rather than re-resolving the perspective row.
    let calibration = CalibrationConfig::from_workspace_root()
        .unwrap_or_else(|_| CalibrationConfig::default_for_phase2_fallback());
    let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
        .await
        .ok()
        .flatten();
    let per_frame_weights = FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
        .await
        .ok()
        .flatten();
    let ctx = FramedBeliefContext {
        calibration,
        per_frame_intra,
        per_frame_weights,
        perspective: perspective.cloned(),
    };

    combine_framed_bbas(frame, rows, &ctx)
}

/// Batch sibling of [`get_perspective_belief`]: compute the lensed belief for a
/// whole page of claims under one `(frame, perspective)` lens, resolving the
/// perspective row + per-frame overrides + calibration **exactly once** for the
/// entire page instead of once per claim.
///
/// This is the fix for the lensed-recall N+1 (backlog
/// `9e33ddf7-53cb-4a5f-bcd3-1396f55c0f99`): the per-hit `recall`/`memory` loops
/// previously called [`get_perspective_belief`] once per hit, and each call
/// re-resolved the same frame row, perspective row, and per-frame override rows
/// from the DB. Here [`FramedBeliefContext::resolve`] runs once; only the
/// per-claim frame-assignment and BBA fetches (genuinely claim-scoped) remain in
/// the loop, and the combine ([`combine_framed_bbas`]) is pure.
///
/// Degrade-not-fail is preserved at the item level: the result is a per-claim
/// `Result`, so a single malformed claim's error is isolated and the caller can
/// warn + serve a null lens for that claim without aborting the page (spec §8).
/// A hard `Err` on the whole call means only that the frame or a page-level
/// resolution failed. Each `Ok(BeliefInterval)` is byte-identical to the value
/// [`get_perspective_belief`] would return for that claim.
///
/// # Errors
/// `FrameNotFound` if `frame_id` is absent; `Db` on a page-level query failure.
pub async fn get_perspective_belief_batch(
    pool: &PgPool,
    claim_ids: &[Uuid],
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<Vec<(Uuid, Result<BeliefInterval, BeliefQueryError>)>, BeliefQueryError> {
    let frame_row = FrameRepository::get_by_id(pool, frame_id)
        .await?
        .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;
    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

    // Resolve perspective + per-frame overrides + calibration ONCE per page.
    // This is the hoist that removes the N+1.
    let ctx = FramedBeliefContext::resolve(pool, frame_id, Some(perspective_id)).await?;

    let mut out = Vec::with_capacity(claim_ids.len());
    for &claim_id in claim_ids {
        out.push((
            claim_id,
            perspective_belief_for_claim(pool, claim_id, frame_id, &frame, &ctx).await,
        ));
    }
    Ok(out)
}

/// Compute one claim's lensed belief given an already-resolved
/// [`FramedBeliefContext`]. Only the frame-assignment and BBA fetches here are
/// claim-scoped; everything else was hoisted into `ctx`. Mirrors the tail of
/// [`get_perspective_belief`] exactly so the two produce identical intervals.
async fn perspective_belief_for_claim(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    ctx: &FramedBeliefContext,
) -> Result<BeliefInterval, BeliefQueryError> {
    let assignment = FrameRepository::get_claim_assignment(pool, claim_id, frame_id).await?;
    let hypothesis_index = assignment.and_then(|a| a.hypothesis_index).unwrap_or(0) as usize;

    let all_bbas = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id).await?;
    if all_bbas.is_empty() {
        return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
    }

    let combined = combine_framed_bbas(frame, &all_bbas, ctx)?
        .expect("all_bbas is non-empty so combination yields Some");

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    Ok(BeliefInterval {
        belief: epigraph_ds::measures::belief(&combined, &target),
        plausibility: epigraph_ds::measures::plausibility(&combined, &target),
        pignistic_prob: epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index),
        mass_on_conflict: combined.mass_of_conflict(),
        mass_on_missing: combined.mass_of_missing(),
        framed: true,
        source: "recomputed_perspective".to_string(),
    })
}

// The frame-function reliability composition (perspective × per-frame ×
// calibration, at both the evidence-type and locality tiers) is unit-tested at
// its source in `edge_factor::tests` (effective_source_strength_with_perspective).
// The full DB chain — get_perspective_belief vs get_belief over stored BBAs —
// is covered by the `perspective_frame_function` sqlx integration test.
