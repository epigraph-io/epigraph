//! Edge-factor materialization for the CDST factor graph.
//!
//! Treats an epistemic edge `A —[rel]→ B` as a factor on `B`'s belief: reads
//! `A`'s stored `EpistemicInterval`, applies the relationship's transmission
//! factor (per `RestrictionKind` + `RestrictionProfile`), materializes the
//! restricted interval as a CDST `MassFunction` on the canonical `binary_truth`
//! frame, persists it keyed by `edge_id` (perspective_id), and re-combines
//! all of the target's stored BBAs into its (Bel, Pl, BetP) columns.
//!
//! Lives in `epigraph-engine` (not `epigraph-mcp`) so both the MCP edge-creation
//! path and the HTTP `POST /api/v1/edges` path can share a single algorithm.
//! The `auto_wire_edge_if_epistemic` wrapper adds the standard gates
//! (claim→claim, plus "no BBA has ever been materialized for this edge yet" —
//! NOT simply `was_created`, see that function's doc comment for why) for use
//! at edge-creation call sites.

use sqlx::PgPool;
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

use epigraph_db::{
    FrameRepository, MassFunctionRepository, MassFunctionRow, PerspectiveRepository,
};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

use crate::calibration::CalibrationConfig;
use crate::epistemic_interval::{
    restrict_epistemic_frame_evidence, restrict_epistemic_negative, restrict_epistemic_positive,
    EpistemicInterval,
};
use crate::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};

const BINARY_FRAME_NAME: &str = "binary_truth";
const BINARY_HYPOTHESES: [&str; 2] = ["TRUE", "FALSE"];

/// Outcome of an edge-factor auto-wire pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeFactorOutcome {
    /// Source claim has no stored interval — nothing to propagate.
    SourceFactorless,
    /// Relationship maps to `RestrictionKind::Neutral` — not an epistemic edge.
    NonEpistemic,
    /// Restriction produced a vacuous interval (no information transfer).
    Vacuous,
    /// BBA materialized and target belief recomputed.
    Wired,
}

/// Auto-wire DS for an **epistemic edge** treated as a factor on the target claim.
///
/// Returns `Ok(EdgeFactorOutcome::SourceFactorless)` when the source has no
/// stored interval (NULL belief/plausibility on `claims` row); the caller can
/// retry later once the source acquires a BBA. Returns `NonEpistemic` if the
/// relationship maps to a `RestrictionKind::Neutral` (cheap short-circuit
/// before any DB query).
pub async fn auto_wire_ds_for_edge(
    pool: &PgPool,
    edge_id: Uuid,
    edge_signer_agent_id: Uuid,
    source_id: Uuid,
    target_id: Uuid,
    relationship: &str,
) -> Result<EdgeFactorOutcome, String> {
    let restriction =
        restriction_kind_with_profile(relationship, &RestrictionProfile::scientific());
    if matches!(restriction, RestrictionKind::Neutral) {
        return Ok(EdgeFactorOutcome::NonEpistemic);
    }

    let source_row: Option<(Option<f64>, Option<f64>, Option<f64>)> =
        sqlx::query_as("SELECT belief, plausibility, open_world_mass FROM claims WHERE id = $1")
            .bind(source_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("fetch source interval: {e}"))?;
    let Some((Some(bel), Some(pl), ow_opt)) = source_row else {
        return Ok(EdgeFactorOutcome::SourceFactorless);
    };
    let source_interval =
        EpistemicInterval::new(bel, pl, ow_opt.unwrap_or((pl - bel).max(0.0) * 0.5));

    // Extract the restriction transmission factor `f`. This is the baseline
    // per-BBA reliability before locality composition. (`f` is ALSO folded
    // into the BBA mass shape via `restrict_epistemic_*` — that shape and
    // the stored source_strength are independent Dempster-Shafer levers:
    // the shape encodes WHAT the supporter says about the target, and
    // source_strength encodes HOW reliable the supporter is.)
    let transmission_factor: f64 = match restriction {
        RestrictionKind::Positive(f)
        | RestrictionKind::Negative(f)
        | RestrictionKind::FrameEvidence(f) => f,
        RestrictionKind::Neutral => unreachable!(),
    };
    let restricted = match restriction {
        RestrictionKind::Positive(f) => restrict_epistemic_positive(&source_interval, f),
        RestrictionKind::Negative(f) => restrict_epistemic_negative(&source_interval, f),
        RestrictionKind::FrameEvidence(f) => {
            restrict_epistemic_frame_evidence(&source_interval, source_interval.betp(), f)
        }
        RestrictionKind::Neutral => unreachable!(),
    };

    if restricted.width() >= 0.999 && restricted.bel < 0.01 {
        return Ok(EdgeFactorOutcome::Vacuous);
    }

    // Locality-aware reliability discount, evidence-mediated.
    //
    // Detection: the source claim has ≥1 evidence row whose
    // `properties->>'doi'` matches the doi of the paper that asserts the
    // target claim. Equivalent semantic: "the supporter is supported by
    // data from the target's own paper", so its contribution is
    // correlated with the target's self-evidence and is not an
    // independent observation.
    //
    // Composition: source_strength = transmission_factor * locality_factor
    // (intra: factor < 1.0, cross: factor = 1.0). This preserves the
    // pre-#185 transmission-factor signal and adds the locality discount
    // multiplicatively, so a logical/intra BBA at f=0.7 with intra
    // factor 0.3 lands at 0.21 instead of nuking to 0.25 unconditionally.
    //
    // Only the source claim's evidence is inspected here. The target
    // claim's own evidence (which may also be intra-source-self-cite by
    // construction) is the concern of the backfill script
    // (`scripts/backfill_intra_source_evidence_discount.py`); for new
    // edge-write paths, the source's provenance is the only signal we
    // need to decide whether THIS edge's contribution is correlated.
    let is_intra: bool = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
              FROM evidence e
              JOIN edges ed_asserts
                ON ed_asserts.target_id = $2
               AND ed_asserts.relationship = 'asserts'
               AND ed_asserts.source_type = 'paper'
              JOIN papers p
                ON p.id = ed_asserts.source_id
               AND p.doi = e.properties->>'doi'
             WHERE e.claim_id = $1
               AND e.properties ? 'doi'
        )
        "#,
    )
    .bind(source_id)
    .bind(target_id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("intra-source evidence lookup: {e}"))?;
    // Resolution order for the intra-evidence locality factor:
    //   1. Per-frame override (frames.properties->>'intra_evidence_locality_factor').
    //      Lets operators tune locality discounting per epistemic context
    //      (binary_truth vs textbook_veracity_* vs research_validity etc.)
    //      without code releases. Set via FrameRepository::set_property.
    //   2. Global default from calibration.toml.
    //   3. Hardcoded fallback 0.3 if calibration.toml is unreadable.
    //
    // Edge BBAs all land on the binary_truth frame today (see ensure_binary_frame
    // below); if a future edge_factor path writes to a different frame, the
    // per-frame override naturally follows because we look up by frame_id.
    let frame_id = ensure_binary_frame(pool).await?;
    let per_frame_factor = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
        .await
        .map_err(|e| format!("per-frame locality factor lookup: {e}"))?;
    // Single calibration load for both the locality fallback AND the
    // Phase 2 canonical-key alias resolution below. Cheap on the local
    // filesystem; failure is recoverable (the helper's
    // `default_for_phase2_fallback` mirrors the pre-Phase-2 hardcodes).
    let calibration = crate::calibration::CalibrationConfig::from_workspace_root().ok();
    let intra_factor = per_frame_factor.unwrap_or_else(|| {
        calibration
            .as_ref()
            .map(|c| c.evidence_locality.intra_evidence_locality_factor)
            .unwrap_or(0.3)
    });
    let locality_factor = if is_intra { intra_factor } else { 1.0 };
    let source_strength = transmission_factor * locality_factor;

    let frame = binary_frame()?;
    let bba = restricted
        .to_mass_function(&frame)
        .map_err(|e| format!("interval_to_bba: {e}"))?;
    let masses_json = mass_to_json(&bba)?;

    FrameRepository::assign_claim(pool, target_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;
    PerspectiveRepository::ensure_edge_perspective(pool, edge_id, Some(edge_signer_agent_id))
        .await
        .map_err(|e| format!("ensure_edge_perspective: {e}"))?;

    // Phase 1a (issue #197): persist the locality classification we just
    // computed into a dedicated column. The current combine path still reads
    // `source_strength` (which is already composed with `locality_factor`
    // above); the tag is metadata so the backfill script and Phase 2 combine
    // path can stop inferring typing from the numeric value-set.
    //
    // Phase 2 (issue #197) vocabulary expansion: DOI-match implies the
    // self-cite case; non-DOI-match intra detection would land here as
    // 'intra_methodological_overlap' once a future Phase 3+ heuristic
    // adds it. Helper treats anything starting with "intra" as intra.
    let locality_tag = if is_intra { "intra_self_cite" } else { "cross" };

    // Phase 2 (issue #197) canonical-key write: resolve the raw
    // relationship string (e.g. "supports") through
    // `evidence_type_aliases` to the canonical SciFact-calibrated key
    // (`"derived_support"`). This lets the Phase 2 helper's tier 2
    // path resolve a real calibrated weight instead of falling
    // through to the 0.5 unknown-key sentinel. Source-of-truth is
    // `calibration.toml`'s `[evidence_type_aliases]` — adding a new
    // relationship is a TOML edit, not a Rust edit. Calibration load
    // failure (calibration.toml missing) is rare on production; the
    // fallback below stores the raw relationship verbatim and the
    // helper's path-3 source_strength bridge keeps the math correct.
    let stored_evidence_type: String = calibration
        .as_ref()
        .and_then(|c| {
            let lower = relationship.to_lowercase();
            c.evidence_type_aliases.get(&lower).cloned()
        })
        .unwrap_or_else(|| relationship.to_string());

    MassFunctionRepository::store_with_perspective(
        pool,
        target_id,
        frame_id,
        Some(edge_signer_agent_id),
        Some(edge_id),
        &masses_json,
        None,
        Some("edge_factor"),
        Some(source_strength),
        Some(stored_evidence_type.as_str()),
        locality_tag,
        None, // edge_factor BBA: derived from an EDGE, not an evidence row (issue #197 Phase 3)
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    recompute_combined_belief(pool, target_id, frame_id, &frame).await?;
    Ok(EdgeFactorOutcome::Wired)
}

/// Fire `auto_wire_ds_for_edge` from an edge-creation call site, gated on
/// whether the edge connects two claim nodes AND (was just created OR has
/// never been wired).
///
/// The `was_created` flag alone is not sufficient: an edge can be written
/// durably while its source claim is "factorless" (no belief interval yet —
/// see [`EdgeFactorOutcome::SourceFactorless`]), and later re-asserted via
/// the same call site once the source acquires belief. That re-assertion
/// hits `was_created=false` (the edge already exists) but must still attempt
/// wiring — otherwise the wake-up is a permanent no-op (backlog claim
/// 8ef5cf61-7382-43a4-85cb-565d76ba3f06). So the real gate is "has a BBA
/// EVER been materialized for this edge_id" (checked via
/// `MassFunctionRepository::exists_for_perspective`, since edge-factor BBAs
/// are persisted keyed by `perspective_id = edge_id`): skip only when one
/// already exists, regardless of `was_created`. This makes the wake-up
/// idempotent — once wired, further re-hits on the same edge are no-ops
/// again, matching the pre-fix behavior for the common (believed-source)
/// case.
///
/// Best-effort: failures are logged at `warn` and swallowed. Returns `None`
/// when sources/targets aren't claims, a BBA already exists for this edge,
/// or the auto-wire call failed. Returns `Some(outcome)` when the trigger
/// fired.
#[allow(clippy::too_many_arguments)]
pub async fn auto_wire_edge_if_epistemic(
    pool: &PgPool,
    was_created: bool,
    edge_id: Uuid,
    source_id: Uuid,
    source_type: &str,
    target_id: Uuid,
    target_type: &str,
    relationship: &str,
    agent_id: Uuid,
) -> Option<EdgeFactorOutcome> {
    if source_type != "claim" || target_type != "claim" {
        return None;
    }
    if !was_created {
        match MassFunctionRepository::exists_for_perspective(pool, edge_id).await {
            Ok(true) => return None,
            Ok(false) => {} // never wired — attempt the wake-up below
            Err(e) => {
                tracing::warn!(
                    edge = %edge_id,
                    "edge auto-wire wake-up check failed: {e}",
                );
                return None;
            }
        }
    }
    match auto_wire_ds_for_edge(pool, edge_id, agent_id, source_id, target_id, relationship).await {
        Ok(outcome) => Some(outcome),
        Err(e) => {
            tracing::warn!(
                edge = %edge_id,
                target = %target_id,
                relationship = %relationship,
                "edge auto-wire failed: {e}",
            );
            None
        }
    }
}

/// Re-fetch all BBAs on (claim, binary frame), discount by source_strength,
/// combine, and write the resulting Bel/Pl/BetP/conflict/missing to the
/// claim's row. Public so other belief-recompute paths (e.g. HTTP
/// `propagate_to_dependents`) can share the cascade.
pub async fn recompute_claim_belief_binary(pool: &PgPool, claim_id: Uuid) -> Result<bool, String> {
    let frame_id = ensure_binary_frame(pool).await?;
    recompute_claim_belief_on_frame(pool, claim_id, frame_id).await
}

/// Generalized variant of [`recompute_claim_belief_binary`] for any frame.
///
/// Used by operator one-shots (e.g.
/// `epigraph-cli/src/bin/recompute_claim_belief.rs`) that need to refresh
/// the cached BetP after a direct mutation to `mass_functions.source_strength`
/// landed on a non-binary frame (research_validity, textbook_veracity_*, ...).
/// The `claims.{belief, plausibility, pignistic_prob, ...}` columns are
/// frame-agnostic scalars — last writer wins — so for claims with BBAs
/// across multiple frames, the caller is responsible for ordering
/// per-frame recomputes deterministically.
///
/// Returns `Ok(false)` if the claim has no BBAs on `frame_id`.
///
/// # Errors
/// String error if the frame row can't be loaded, the frame's hypothesis
/// list can't be parsed into a `FrameOfDiscernment`, or any DS combination
/// step fails.
pub async fn recompute_claim_belief_on_frame(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
) -> Result<bool, String> {
    let row = FrameRepository::get_by_id(pool, frame_id)
        .await
        .map_err(|e| format!("frame get_by_id: {e}"))?
        .ok_or_else(|| format!("frame {frame_id} not found"))?;
    let frame = FrameOfDiscernment::new(row.name.clone(), row.hypotheses.clone())
        .map_err(|e| format!("build frame {}: {e}", row.name))?;
    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    if all_rows.is_empty() {
        return Ok(false);
    }
    recompute_combined_belief(pool, claim_id, frame_id, &frame).await?;
    Ok(true)
}

/// Compute the effective Shafer reliability discount for a single BBA
/// at combine time.
///
/// Phase 2 of issue #197: stop reading the persisted
/// `mass_functions.source_strength` column as the authority for
/// per-row discount weight, and derive it dynamically from the
/// `evidence_type` + `locality_tag` columns the Phase 1a write path
/// populates. Recalibration — both global (`calibration.toml`'s
/// `evidence_locality.intra_evidence_locality_factor`) and per-frame
/// (`frames.properties->>'intra_evidence_locality_factor'`) — flows
/// through to combined BetP without rewriting any BBA row.
///
/// Phase 4 of issue #197: extend the lookup chain with a per-frame
/// evidence-type weight override map. Operators can set a per-frame
/// `evidence_type_weights` JSONB property; when present and containing
/// the BBA's lowercased `evidence_type`, the override wins over the
/// global `[evidence_type_weights]` table. **Strict-key, no alias
/// resolution at Tier 1** (Q9 locked decision in Phase 4 spec § 5):
/// if the operator writes `{"observation": 1.0}`, that affects rows
/// literally tagged `"observation"`, not also `"empirical"`.
///
/// # Inputs
/// * `row` — the persisted BBA. The helper inspects
///   `row.evidence_type`, `row.locality_tag`, and (for the legacy
///   fallback) `row.source_strength`. The `source_strength` column is
///   not the authority but it is kept as a migration-compat cache:
///   * for the pre-Phase-1a population where `evidence_type IS NULL`,
///     the helper returns the stored value unchanged (preserving the
///     5202ded backfill semantics).
///   * for rows whose `evidence_type` is non-NULL but does not resolve
///     to any calibrated key (e.g. legacy `"CORROBORATES"` tags that
///     were written before the Phase 2 alias-table refresh), the
///     helper falls back to the stored value as a Phase-1c bridge.
/// * `per_frame_intra_factor` — pre-loaded by the caller via
///   `FrameRepository::get_intra_evidence_locality_factor`. Pre-loading
///   avoids a DB round-trip per row in a multi-BBA combine. `None`
///   means "no per-frame override; use the global calibration value".
/// * `per_frame_evidence_weights` (Phase 4) — pre-loaded by the caller
///   via `FrameRepository::get_per_frame_evidence_type_weights`. Map
///   keys are already lowercased by the repo accessor. `None` means
///   "no per-frame override; use the global calibration table".
/// * `calibration` — pre-loaded `&CalibrationConfig`. The caller
///   resolves the load + fallback; the helper does not do I/O.
///
/// # Output
/// `f64` clamped to `[0.0, 1.0]`.
///
/// # Fallback chain (first match wins)
/// 1. `evidence_type IS NULL` AND `source_strength IS NOT NULL` →
///    return the stored value clamped. This is the pre-Phase-1a
///    legacy cohort (5202ded backfill populated `source_strength`
///    only, never `evidence_type`).
/// 2. **Phase 4 Tier 1** — `evidence_type IS NOT NULL` AND
///    `per_frame_evidence_weights.get(et.to_lowercase()) = Some(w)`
///    → compose `w` with locality (same locality discount Tier 3
///    applies), clamp to `[0.0, 1.0]`. Strict-key: no alias
///    resolution against `calibration.evidence_type_aliases`.
/// 3. `evidence_type IS NOT NULL` AND
///    `calibration.evidence_type_weight_present(et)` → look up the
///    calibrated weight, compose with locality:
///    * `locality_tag.starts_with("intra")` → `weight * intra_factor`
///      where `intra_factor` is the per-frame override (if any), else
///      the global calibration value.
///    * otherwise → `weight` (no discount).
/// 4. `evidence_type IS NOT NULL` AND not calibrated AND
///    `source_strength IS NOT NULL` → return the stored value clamped.
///    Path-1 sentinel from Phase 2 spec § 4: an `evidence_type` like
///    `"CORROBORATES"` that's neither a canonical key nor an alias
///    falls back to the write-time cache.
/// 5. Both `evidence_type` and `source_strength` NULL → return `0.5`
///    (the unknown-key calibration fallback).
pub fn effective_source_strength(
    row: &MassFunctionRow,
    per_frame_intra_factor: Option<f64>,
    per_frame_evidence_weights: Option<&HashMap<String, f64>>,
    calibration: &CalibrationConfig,
) -> f64 {
    // Step (1): legacy null-evidence_type cohort. The 5202ded backfill
    // populated `source_strength` on these rows without setting
    // `evidence_type`; we honor the stored value verbatim until Phase
    // 1c (backlog claim 7b934e58) derives `evidence_type` from the
    // linked evidence rows.
    if row.evidence_type.is_none() {
        if let Some(ss) = row.source_strength {
            return ss.clamp(0.0, 1.0);
        }
        // Step (5): everything NULL → unknown-key 0.5 fallback.
        return 0.5;
    }

    // SAFETY: just matched `Some` above.
    let evidence_type = row.evidence_type.as_deref().unwrap_or("");

    // Helper closure: compose a base weight with the locality discount.
    // Used by both Tier 1 (Phase 4 per-frame override) and Tier 2 (Phase
    // 2 global calibration). Keeps the locality semantics identical
    // across both tiers — an operator who writes `{"empirical": 0.5}`
    // expects the same `intra` discount to apply on top of 0.5 as it
    // would have applied to the global 1.0.
    let compose_with_locality = |base: f64| -> f64 {
        let intra_factor = per_frame_intra_factor
            .unwrap_or(calibration.evidence_locality.intra_evidence_locality_factor);
        let locality_factor = if row.locality_tag.starts_with("intra") {
            intra_factor
        } else {
            1.0
        };
        (base * locality_factor).clamp(0.0, 1.0)
    };

    // Step (2) — Phase 4 Tier 1: per-frame override strict-key lookup.
    // Map keys are already lowercased by the repo accessor; lowercase
    // the BBA's evidence_type to match. NO alias resolution at this
    // tier — see Q9 locked decision in Phase 4 spec § 5.
    if let Some(map) = per_frame_evidence_weights {
        let key = evidence_type.to_lowercase();
        if let Some(&w) = map.get(&key) {
            return compose_with_locality(w);
        }
    }

    // Step (3): evidence_type resolves to a calibrated weight (direct
    // or via the alias table). Compose with locality. Any locality_tag
    // starting with "intra" — current values: 'intra_self_cite',
    // 'intra_methodological_overlap' (Phase 2 vocabulary expansion);
    // historical 'intra' rows are migrated to 'intra_self_cite' in
    // the same PR — applies the intra discount. Everything else
    // ('cross', 'unknown', or any future tag we haven't taught the
    // helper) gets the un-discounted base weight.
    if calibration.evidence_type_weight_present(evidence_type) {
        let base = calibration.get_evidence_type_weight(evidence_type);
        return compose_with_locality(base);
    }

    // Step (4): evidence_type was set but isn't a calibrated key (path
    // 1 sentinel from Phase 2 spec § 4). The legacy `source_strength`
    // cache preserves write-time semantics; without it we drop to the
    // 0.5 unknown-key fallback.
    if let Some(ss) = row.source_strength {
        return ss.clamp(0.0, 1.0);
    }
    0.5
}

/// A querying perspective's reliability overrides — the "frame function"
/// config. Both maps are keyed lowercase and override, respectively, the
/// evidence-type base weight and the locality factor for that observer. Empty
/// maps mean "no opinion" (fall through to per-frame / global calibration).
#[derive(Debug, Clone, Default)]
pub struct PerspectiveReliability {
    /// `evidence_type` → base reliability weight ∈ [0,1].
    pub source_reliability: HashMap<String, f64>,
    /// `locality_tag` → locality factor ∈ [0,1].
    pub locality_reliability: HashMap<String, f64>,
}

impl PerspectiveReliability {
    /// `true` when neither map has any entry — the perspective expresses no
    /// reliability opinion and is treated identically to the global
    /// (no-perspective) computation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_reliability.is_empty() && self.locality_reliability.is_empty()
    }
}

/// Per-BBA reliability for a **specific querying perspective** — the same tier
/// chain as [`effective_source_strength`] with the perspective inserted as the
/// highest-priority tier at *both* the evidence-type weight and the locality
/// factor.
///
/// Resolution per BBA:
/// - **base weight** = `perspective.source_reliability[evidence_type]`
///   → per-frame override → global calibration weight → stored `source_strength`
///   → 0.5.
/// - **locality factor** = `perspective.locality_reliability[locality_tag]`
///   → (per-frame ∨ global intra factor, applied when the tag is `intra*`)
///   → 1.0.
/// - result = `base × locality`, clamped.
///
/// When the perspective has no override touching this BBA (no matching
/// evidence-type key *and* no matching locality key), the result is exactly
/// [`effective_source_strength`] — so a no-opinion perspective reproduces the
/// global belief. Nothing is hardwired: every weight comes from config
/// (perspective JSONB → frame properties → `calibration.toml`).
#[must_use]
pub fn effective_source_strength_with_perspective(
    row: &MassFunctionRow,
    per_frame_intra_factor: Option<f64>,
    per_frame_evidence_weights: Option<&HashMap<String, f64>>,
    calibration: &CalibrationConfig,
    perspective: &PerspectiveReliability,
) -> f64 {
    let etype = row.evidence_type.as_deref().map(str::to_lowercase);
    let locality_key = row.locality_tag.to_lowercase();

    let persp_base = etype
        .as_ref()
        .and_then(|t| perspective.source_reliability.get(t))
        .copied();
    let persp_locality = perspective.locality_reliability.get(&locality_key).copied();

    // No override touches this BBA → identical to the global computation.
    if persp_base.is_none() && persp_locality.is_none() {
        return effective_source_strength(
            row,
            per_frame_intra_factor,
            per_frame_evidence_weights,
            calibration,
        );
    }

    // Base evidence-type weight: perspective → per-frame → calibration →
    // stored source_strength → 0.5.
    let base = persp_base
        .or_else(|| {
            etype
                .as_ref()
                .and_then(|t| per_frame_evidence_weights.and_then(|m| m.get(t)).copied())
        })
        .or_else(|| {
            etype
                .as_ref()
                .filter(|t| calibration.evidence_type_weight_present(t))
                .map(|t| calibration.get_evidence_type_weight(t))
        })
        .or(row.source_strength)
        .unwrap_or(0.5);

    // Locality factor: perspective → legacy intra logic (per-frame ∨ global
    // intra factor when the tag is intra*, else 1.0).
    let locality = persp_locality.unwrap_or_else(|| {
        if locality_key.starts_with("intra") {
            per_frame_intra_factor
                .unwrap_or(calibration.evidence_locality.intra_evidence_locality_factor)
        } else {
            1.0
        }
    });

    (base * locality).clamp(0.0, 1.0)
}

/// Phase 4 (issue #197) Q8: warn on per-frame evidence-type override
/// keys that aren't in calibration's known vocabulary.
///
/// "Known vocabulary" = canonical key in `calibration.evidence_type_weights`
/// ∪ alias in `calibration.evidence_type_aliases` ∪ a small allow-list of
/// relationship-vocab strings the `auto_wire_ds_for_edge` write path may
/// emit before they're added to `evidence_type_aliases`. Operators may
/// legitimately register weights for future evidence types not yet in
/// calibration.toml; this is a log signal for typos, not a hard reject.
fn warn_on_unknown_evidence_type_keys(
    frame_id: Uuid,
    map: &HashMap<String, f64>,
    calibration: &CalibrationConfig,
) {
    const RELATIONSHIP_VOCAB_ALLOWLIST: &[&str] = &[
        "supports",
        "corroborates",
        "refutes",
        "supersedes",
        "derived_support",
        "derived_refute",
        "derived_supersession",
    ];
    for key in map.keys() {
        // Map keys are already lowercased by the repo accessor; calibration
        // accessors also lowercase internally. evidence_type_weight_present
        // covers both canonical-key and alias resolution in one call.
        if calibration.evidence_type_weight_present(key) {
            continue;
        }
        if RELATIONSHIP_VOCAB_ALLOWLIST.contains(&key.as_str()) {
            continue;
        }
        tracing::warn!(
            %frame_id,
            key = %key,
            "per-frame evidence_type_weights override key is not in calibration vocabulary; \
             possibly a typo (entry is still applied at Tier 1 strict-key)"
        );
    }
}

async fn recompute_combined_belief(
    pool: &PgPool,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
) -> Result<(), String> {
    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    if all_rows.is_empty() {
        return Ok(());
    }

    // Phase 2 (issue #197): the combine path no longer trusts the
    // stored `source_strength` as the authority. Instead we compute
    // each BBA's effective reliability discount dynamically from
    // (`evidence_type`, `locality_tag`, per-frame factor, calibration).
    // Recalibration — e.g. changing `intra_evidence_locality_factor`
    // in `calibration.toml` or via a per-frame override — flows through
    // to combined BetP without any DB rewrite.
    //
    // The load is hoisted above the loop to avoid a per-row I/O cost
    // for the multi-BBA branch. Calibration I/O failure is recoverable
    // (per CalibrationConfig::from_workspace_root docs); we fall back
    // to the synthetic config that mirrors the pre-Phase-2 hardcodes.
    let calibration = CalibrationConfig::from_workspace_root()
        .unwrap_or_else(|_| CalibrationConfig::default_for_phase2_fallback());
    let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(pool, frame_id)
        .await
        .ok()
        .flatten();

    // Phase 4 (issue #197): per-frame evidence-type weight override map.
    // When set, its keyed entries win over the global calibration
    // table at Tier 1 of `effective_source_strength`. Loaded once above
    // the combine loop. On any DB error we fall through to `None`
    // (silently no-ops at Tier 1) rather than failing the whole combine
    // — recalibration overrides are operator-facing knobs, not
    // load-bearing for the BetP write.
    let per_frame_evidence_weights =
        FrameRepository::get_per_frame_evidence_type_weights(pool, frame_id)
            .await
            .ok()
            .flatten();

    // Vocabulary warn-log (Q8 locked: loose validation at set_property,
    // warn-log at read-site). Iterate the override map's keys and warn
    // on any that don't resolve to a known evidence-type vocabulary
    // entry: canonical calibration key, calibration alias, or one of
    // the relationship-vocab strings the auto-wire write path emits.
    // Surfaces operator typos in operational logs without blocking the
    // write.
    if let Some(ref map) = per_frame_evidence_weights {
        warn_on_unknown_evidence_type_keys(frame_id, map, &calibration);
    }

    let combined = if all_rows.len() == 1 {
        let r = &all_rows[0];
        let mf = parse_stored_bba(frame, &r.masses)?;
        let reliability = effective_source_strength(
            r,
            per_frame_intra,
            per_frame_evidence_weights.as_ref(),
            &calibration,
        );
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?
    } else {
        let mut mass_fns = Vec::with_capacity(all_rows.len());
        for row in &all_rows {
            let mf = parse_stored_bba(frame, &row.masses)?;
            let reliability = effective_source_strength(
                row,
                per_frame_intra,
                per_frame_evidence_weights.as_ref(),
                &calibration,
            );
            let d =
                combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
            mass_fns.push(d);
        }
        let (c, _) = combination::combine_multiple(&mass_fns, 0.9)
            .map_err(|e| format!("combine_multiple: {e}"))?;
        c
    };

    let target = FocalElement::positive(BTreeSet::from([0_usize]));
    let bel = measures::belief(&combined, &target);
    let pl = measures::plausibility(&combined, &target);
    let betp = measures::pignistic_probability(&combined, 0);
    let conflict = combined.mass_of_conflict();
    let missing = combined.mass_of_missing();

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

    // CDST classification — a verdict on the COMBINED belief via the
    // deterministic BetP 7-rule cascade. Defined only on the canonical binary
    // {TRUE, FALSE} frame (supported = idx 0, contradicted = idx 1); other
    // frames write the frame-agnostic belief scalars above but leave
    // `claims.classification` untouched. Thresholds come from `calibration`
    // (operator-tunable, same load as the discount path).
    if frame.id == BINARY_FRAME_NAME {
        let thresholds = &calibration.classifier_thresholds;
        // theta = closed-world full-frame ignorance m({0,1}); the open-world
        // missing mass is excluded (Smets TBM), matching the legacy
        // `compute_betp` the cascade was calibrated against. `betp` (above) is
        // pignistic(idx 0) = betp_supported.
        let theta = combined.mass_of(&FocalElement::positive(BTreeSet::from([0_usize, 1_usize])));
        let betp_unsup = measures::pignistic_probability(&combined, 1);
        // has_opposing: does any single source BBA lean toward contradiction?
        // Post-#197 a `refutes`/`contradicts` edge auto-wires a Negative-leaning
        // BBA on the target, so edge-borne AND directly-submitted opposition both
        // surface here as a per-BBA betp_unsup — this replaces (and subsumes) the
        // legacy CONTRADICTS-edge query, which only saw edge-borne opposition.
        let has_opposing = all_rows.iter().any(|row| {
            parse_stored_bba(frame, &row.masses)
                .map(|bba| {
                    measures::pignistic_probability(&bba, 1) > thresholds.has_opposing_threshold
                })
                .unwrap_or(false)
        });
        let label = crate::classifier::classify(
            conflict,
            theta,
            betp,
            betp_unsup,
            has_opposing,
            thresholds,
        );
        MassFunctionRepository::update_claim_classification(pool, claim_id, &label.to_string())
            .await
            .map_err(|e| format!("update_claim_classification: {e}"))?;
    }

    Ok(())
}

/// Get-or-create the canonical `binary_truth` frame.
pub async fn ensure_binary_frame(pool: &PgPool) -> Result<Uuid, String> {
    if let Some(row) = FrameRepository::get_by_name(pool, BINARY_FRAME_NAME)
        .await
        .map_err(|e| format!("get_by_name: {e}"))?
    {
        return Ok(row.id);
    }
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
        Err(_) => FrameRepository::get_by_name(pool, BINARY_FRAME_NAME)
            .await
            .map_err(|e| format!("fallback get_by_name: {e}"))?
            .map(|r| r.id)
            .ok_or_else(|| "binary_truth frame missing after create attempt".to_string()),
    }
}

fn binary_frame() -> Result<FrameOfDiscernment, String> {
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    FrameOfDiscernment::new(BINARY_FRAME_NAME.to_string(), hyps)
        .map_err(|e| format!("binary frame: {e}"))
}

fn mass_to_json(mf: &MassFunction) -> Result<serde_json::Value, String> {
    let map: HashMap<String, f64> = mf
        .masses()
        .iter()
        .map(|(fe, m)| (focal_to_key(fe), *m))
        .collect();
    serde_json::to_value(map).map_err(|e| format!("serialize BBA: {e}"))
}

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

fn parse_stored_bba(
    frame: &FrameOfDiscernment,
    masses_json: &serde_json::Value,
) -> Result<MassFunction, String> {
    MassFunction::from_json_masses(frame.clone(), masses_json)
        .map_err(|e| format!("parse stored BBA: {e}"))
}
