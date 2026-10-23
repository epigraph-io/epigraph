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

use crate::belief_profile::{overrides_in, BeliefProfile, FrameTier, PerspectiveTier};
use crate::edge_factor::{effective_source_strength_profiled, PerspectiveReliability};
use epigraph_db::FrameRow;
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
///   (mirrors the MCP unframed path). When no DS write has ever populated those
///   columns, falls back to reconstructing an interval from `truth_value`, reported
///   with the same `source: "cached"`.
///
/// # Errors
///
/// Returns `BeliefQueryError::FrameNotFound` when `frame_id` is specified but
/// the frame does not exist.  Returns `BeliefQueryError::ClaimNotFound` when
/// the claim does not exist (unframed path only).
pub async fn get_belief(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Option<Uuid>,
) -> Result<BeliefInterval, BeliefQueryError> {
    if let Some(frame_id) = frame_id {
        // ── Framed path: live recomputation from stored BBAs ──────────────
        let frame_row = FrameRepository::get_by_id(pool, viewer, frame_id)
            .await?
            .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;

        let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

        let assignment =
            FrameRepository::get_claim_assignment(pool, viewer, claim_id, frame_id).await?;
        let hypothesis_index = crate::edge_factor::resolve_hypothesis_index(
            assignment.and_then(|a| a.hypothesis_index),
            frame.hypothesis_count(),
        );

        let all_bbas =
            MassFunctionRepository::get_for_claim_frame(pool, viewer, claim_id, frame_id).await?;

        if all_bbas.is_empty() {
            return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
        }

        // Discount each BBA by its calibrated reliability (evidence-type weight
        // × locality, via the resolved belief profile) before combining, so the
        // framed read agrees with the cached `claims.pignistic_prob` that the
        // recompute path writes. No perspective → the served profile with this
        // frame's overrides, exactly what the recompute resolves.
        let (combined, fold_conflict) =
            recompute_framed_belief(pool, viewer, &frame_row, &frame, &all_bbas, None)
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
            mass_on_conflict: fold_conflict,
            mass_on_missing: combined.mass_of_missing(),
            framed: true,
            source: "recomputed".to_string(),
        });
    }

    // ── Unframed path: cached DS columns from claim row ───────────────────
    //
    // Backlog 152d9af6. This previously returned
    // `BeliefInterval::cached_from_truth(claim.truth_value)` unconditionally, so the
    // persisted DS columns were never read and plausibility was always the hardcoded
    // 1.0. Both the MCP tool schema and the doc comment above already promised the
    // cached columns, and `link_epistemic`'s readback already consulted them via
    // `ClaimRepository::get_belief_columns` — so the two channels disagreed, and a
    // claim moved by epistemic edges reported its pre-edge truth_value here while
    // reporting the edge-derived value there.
    let cols =
        ClaimRepository::get_belief_columns(pool, viewer, ClaimId::from_uuid(claim_id)).await?;

    // A claim row must exist even when its DS columns are NULL, so absence of the row
    // — not absence of the columns — is what ClaimNotFound means.
    let Some(cols) = cols else {
        return Err(BeliefQueryError::ClaimNotFound(claim_id));
    };

    // `belief` and `plausibility` together are the load-bearing pair: a DS write sets
    // both, so requiring both prevents reporting a half-written row as authoritative.
    if let (Some(belief), Some(plausibility)) = (cols.belief, cols.plausibility) {
        return Ok(BeliefInterval {
            belief,
            plausibility,
            // BetP is derived, and older rows predate the column being populated;
            // fall back to belief rather than to truth_value, which is the scalar this
            // whole read path exists to stop conflating with the DS state.
            pignistic_prob: cols.pignistic_prob.unwrap_or(belief),
            mass_on_conflict: cols.mass_on_empty.unwrap_or(0.0),
            mass_on_missing: cols.mass_on_missing.unwrap_or(0.0),
            framed: false,
            source: "cached".to_string(),
        });
    }

    // No DS state has ever been written for this claim. Fall back to the truth_value
    // reconstruction rather than reporting zeros — a belief of 0.0 would make an
    // unassessed claim indistinguishable from a refuted one.
    let claim = ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(claim_id))
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
/// `FrameNotFound` if `frame_id` is absent; `ClaimNotFound` if `claim_id` names
/// no claim row (checked only when the claim carries no BBAs in this frame —
/// see below); `ParseMasses`/`Ds` on malformed or uncombinable BBAs; `Db` on
/// query failure.
pub async fn get_perspective_belief(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<BeliefInterval, BeliefQueryError> {
    let frame_row = FrameRepository::get_by_id(pool, viewer, frame_id)
        .await?
        .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;
    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

    let assignment =
        FrameRepository::get_claim_assignment(pool, viewer, claim_id, frame_id).await?;
    let hypothesis_index = crate::edge_factor::resolve_hypothesis_index(
        assignment.and_then(|a| a.hypothesis_index),
        frame.hypothesis_count(),
    );

    let all_bbas =
        MassFunctionRepository::get_for_claim_frame(pool, viewer, claim_id, frame_id).await?;
    if all_bbas.is_empty() {
        // An empty BBA set is ambiguous on its own: it is equally the signature
        // of a real claim with no evidence in this frame AND of a `claim_id`
        // that names nothing at all, so without this probe a typo'd UUID
        // returns a byte-identical `empty_frame` body and the caller cannot
        // tell the two apart. Probe ONLY on this branch — `mass_functions
        // .claim_id` is `REFERENCES claims(id)`, so a non-empty BBA set already
        // proves the claim row exists — which keeps the evidence-bearing path
        // at zero extra queries.
        if ClaimRepository::get_by_id(pool, viewer, ClaimId::from_uuid(claim_id))
            .await?
            .is_none()
        {
            return Err(BeliefQueryError::ClaimNotFound(claim_id));
        }
        return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
    }

    // The perspective's frame-function config: its `belief_profile` override
    // object, source-reliability (evidence type) and locality-reliability
    // (pathway). Absent/empty → no opinion → the computation reduces to the
    // global `get_belief`.
    let (combined, fold_conflict) = recompute_framed_belief(
        pool,
        viewer,
        &frame_row,
        &frame,
        &all_bbas,
        Some(perspective_id),
    )
    .await?
    .expect("all_bbas is non-empty so combination yields Some");

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    Ok(BeliefInterval {
        belief: epigraph_ds::measures::belief(&combined, &target),
        plausibility: epigraph_ds::measures::plausibility(&combined, &target),
        pignistic_prob: epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index),
        mass_on_conflict: fold_conflict,
        mass_on_missing: combined.mass_of_missing(),
        framed: true,
        source: "recomputed_perspective".to_string(),
    })
}

/// The lens a framed-belief combination runs under: one resolved
/// [`BeliefProfile`], resolved ONCE per `(frame, perspective)` and reused
/// across every claim on a page.
///
/// The profile carries every parameter the fold reads (the served profile,
/// then the frame tier, then the perspective tier; see
/// [`crate::belief_profile`]). Hoisting the resolution out of the per-claim
/// combine is what eliminates the lensed recall N+1: the perspective row, the
/// per-frame override lookups and the calibration are frame/perspective-scoped,
/// not claim-scoped. [`get_perspective_belief_batch`] resolves the context
/// once and the pure combine ([`combine_framed_bbas`]) touches the DB zero
/// more times.
#[derive(Debug, Clone)]
pub struct FramedBeliefContext {
    profile: BeliefProfile,
}

impl FramedBeliefContext {
    /// A context over an already-resolved profile.
    #[must_use]
    pub fn new(profile: BeliefProfile) -> Self {
        Self { profile }
    }

    /// The resolved profile every fold under this context reads.
    #[must_use]
    pub fn profile(&self) -> &BeliefProfile {
        &self.profile
    }

    /// BLAKE3 hash of the resolved profile (see
    /// [`BeliefProfile::profile_hash`]): what a belief read under this
    /// context reports as its profile identity.
    #[must_use]
    pub fn profile_hash(&self) -> String {
        self.profile.profile_hash()
    }

    /// Resolve the lens from the DB exactly once.
    ///
    /// Per-frame loads are best-effort: a DB error there falls back to the
    /// tier below (`.ok().flatten()`) rather than failing the read, matching
    /// the recompute path. The frame's generic override object comes from the
    /// `frame_row` the caller already holds. When `perspective_id` is `Some`,
    /// the perspective row is resolved and an unknown perspective reduces to
    /// no opinion, so a lensed read over an un-configured observer equals the
    /// global read.
    async fn resolve(
        pool: &PgPool,
        viewer: &epigraph_db::visibility::Viewer,
        frame_row: &FrameRow,
        perspective_id: Option<Uuid>,
    ) -> Result<Self, BeliefQueryError> {
        let frame_id = frame_row.id;
        let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
            .await
            .ok()
            .flatten();
        let per_frame_weights =
            FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
                .await
                .ok()
                .flatten();
        let (perspective, perspective_overrides) = match perspective_id {
            Some(pid) => match PerspectiveRepository::get_by_id(pool, viewer, pid).await? {
                Some(p) => (
                    PerspectiveReliability {
                        source_reliability: p.source_reliability().unwrap_or_default(),
                        locality_reliability: p.locality_reliability().unwrap_or_default(),
                    },
                    p.properties.as_ref().and_then(overrides_in).cloned(),
                ),
                None => (PerspectiveReliability::default(), None),
            },
            None => (PerspectiveReliability::default(), None),
        };
        let profile = BeliefProfile::served().resolve(
            FrameTier {
                overrides: overrides_in(&frame_row.properties),
                intra_evidence_locality_factor: per_frame_intra,
                evidence_type_weights: per_frame_weights.as_ref(),
            },
            PerspectiveTier {
                overrides: perspective_overrides.as_ref(),
                reliability: Some(&perspective),
            },
        );
        Ok(Self { profile })
    }
}

/// Combine a claim's stored BBAs into one mass function — the pure (no-DB) core
/// shared by the single-claim and batch framed-belief paths.
///
/// Each BBA is discounted by its effective reliability under the context's
/// profile ([`effective_source_strength_profiled`]: perspective → per-frame →
/// profile tables → stored `source_strength` → unknown-type weight, with
/// locality applied) before the SAME combination the recompute/write path
/// uses ([`crate::source_dependence::combine_with_source_dependence`], with
/// the profile's conflict threshold). The rows' source keys arrive in
/// `source_keys` (one per row, from
/// [`crate::source_dependence::source_keys_for_rows`]), so this function
/// issues no queries.
///
/// Returns `Ok(None)` only when `rows` is empty.
///
/// # Errors
/// `ParseMasses` on a malformed stored BBA; `Ds` when discounting or the fold
/// fails.
pub fn combine_framed_bbas(
    frame: &FrameOfDiscernment,
    rows: &[MassFunctionRow],
    source_keys: Vec<Option<crate::source_dependence::SourceKey>>,
    ctx: &FramedBeliefContext,
) -> Result<Option<(MassFunction, f64)>, BeliefQueryError> {
    if rows.is_empty() {
        return Ok(None);
    }
    debug_assert_eq!(rows.len(), source_keys.len(), "one source key per row");

    let mut items = Vec::with_capacity(rows.len());
    for (row, key) in rows.iter().zip(source_keys) {
        let mf = MassFunction::from_json_masses(frame.clone(), &row.masses)
            .map_err(BeliefQueryError::ParseMasses)?;
        let alpha = effective_source_strength_profiled(row, &ctx.profile);
        items.push((
            key,
            combination::discount(&mf, alpha).map_err(BeliefQueryError::Ds)?,
        ));
    }

    // Combine via the SAME function the recompute/write path uses: same-source
    // repeats (one agent re-reading one `source_url`) are folded cautiously
    // into one, then everything is Dempster-folded (`combine_multiple`). Using
    // that one function is what makes this compute-on-read result reproduce
    // the cached value for the same stored BBAs (backlog 4c42c0bf); a plain
    // `combine_multiple` here served the inflated same-source value while the
    // cache held the honest one.
    //
    // The conflict is reported the same way the recompute caches it
    // (`edge_factor::compute_combined_belief` -> `claims.mass_on_empty`): the
    // fold's `aggregate_conflict`, because Dempster normalises it out of the
    // combined mass. A single BBA is not folded; its own empty-set mass is
    // the conflict.
    let (combined, conflict) = crate::source_dependence::combine_with_source_dependence(
        items,
        ctx.profile.combination.conflict_threshold,
    )
    .map_err(BeliefQueryError::Ds)?;
    Ok(Some((combined, conflict)))
}

/// Recompute the combined mass function for a framed claim, discounting each
/// stored BBA by its effective reliability before Dempster combination.
///
/// This is the single-claim path both `get_belief` (perspective = `None`) and
/// `get_perspective_belief` use. It resolves the lens
/// ([`FramedBeliefContext::resolve`]) once, then delegates the actual
/// combination to the pure [`combine_framed_bbas`]. The batch path
/// ([`get_perspective_belief_batch`]) resolves the SAME context once and reuses
/// it across a whole page — that is the N+1 fix; both paths share
/// `combine_framed_bbas`, so their values are identical.
///
/// Returns `Ok(None)` only when `rows` is empty.
async fn recompute_framed_belief(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    frame_row: &FrameRow,
    frame: &FrameOfDiscernment,
    rows: &[MassFunctionRow],
    perspective_id: Option<Uuid>,
) -> Result<Option<(MassFunction, f64)>, BeliefQueryError> {
    if rows.is_empty() {
        return Ok(None);
    }
    let ctx = FramedBeliefContext::resolve(pool, viewer, frame_row, perspective_id).await?;
    let source_keys = crate::source_dependence::source_keys_for_rows(pool, viewer, rows).await?;
    combine_framed_bbas(frame, rows, source_keys, &ctx)
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
    viewer: &epigraph_db::visibility::Viewer,
    claim_ids: &[Uuid],
    frame_id: Uuid,
    perspective_id: Uuid,
) -> Result<Vec<(Uuid, Result<BeliefInterval, BeliefQueryError>)>, BeliefQueryError> {
    let frame_row = FrameRepository::get_by_id(pool, viewer, frame_id)
        .await?
        .ok_or(BeliefQueryError::FrameNotFound(frame_id))?;
    let frame = FrameOfDiscernment::new(frame_row.name.clone(), frame_row.hypotheses.clone())?;

    // Resolve perspective + per-frame overrides + calibration ONCE per page.
    // This is the hoist that removes the N+1.
    let ctx = FramedBeliefContext::resolve(pool, viewer, &frame_row, Some(perspective_id)).await?;

    let mut out = Vec::with_capacity(claim_ids.len());
    for &claim_id in claim_ids {
        out.push((
            claim_id,
            perspective_belief_for_claim(pool, viewer, claim_id, frame_id, &frame, &ctx).await,
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
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    ctx: &FramedBeliefContext,
) -> Result<BeliefInterval, BeliefQueryError> {
    let assignment =
        FrameRepository::get_claim_assignment(pool, viewer, claim_id, frame_id).await?;
    let hypothesis_index = crate::edge_factor::resolve_hypothesis_index(
        assignment.and_then(|a| a.hypothesis_index),
        frame.hypothesis_count(),
    );

    let all_bbas =
        MassFunctionRepository::get_for_claim_frame(pool, viewer, claim_id, frame_id).await?;
    if all_bbas.is_empty() {
        return Ok(BeliefInterval::empty_frame(frame.hypothesis_count()));
    }

    // Claim-scoped like the BBA fetch above (one query, skipped when no row
    // can carry a source key), so the page-level hoist is unchanged.
    let source_keys =
        crate::source_dependence::source_keys_for_rows(pool, viewer, &all_bbas).await?;
    let (combined, fold_conflict) = combine_framed_bbas(frame, &all_bbas, source_keys, ctx)?
        .expect("all_bbas is non-empty so combination yields Some");

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    Ok(BeliefInterval {
        belief: epigraph_ds::measures::belief(&combined, &target),
        plausibility: epigraph_ds::measures::plausibility(&combined, &target),
        pignistic_prob: epigraph_ds::measures::pignistic_probability(&combined, hypothesis_index),
        mass_on_conflict: fold_conflict,
        mass_on_missing: combined.mass_of_missing(),
        framed: true,
        source: "recomputed_perspective".to_string(),
    })
}

// The frame-function reliability composition (perspective × per-frame ×
// profile, at both the evidence-type and locality tiers) is unit-tested at
// its source (`effective_source_strength_unit`, `belief_profile_golden`).
// The full DB chain — get_perspective_belief vs get_belief over stored BBAs —
// is covered by the `perspective_frame_function` sqlx integration test.
