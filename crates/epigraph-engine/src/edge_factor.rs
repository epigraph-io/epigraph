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

use sqlx::Acquire;
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

use epigraph_db::{
    EdgeRepository, FrameRepository, MassFunctionRepository, MassFunctionRow, PerspectiveRepository,
};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

use crate::belief_profile::{BeliefProfile, FrameTier, PerspectiveTier};
use crate::calibration::CalibrationConfig;
use crate::epistemic_interval::{
    restrict_epistemic_frame_evidence, restrict_epistemic_negative, restrict_epistemic_positive,
    EpistemicInterval,
};
use crate::sheaf::{restriction_kind_with_profile, RestrictionKind, RestrictionProfile};

const BINARY_FRAME_NAME: &str = "binary_truth";
// belief-profile: allow-literal (array length of a fixed hypothesis list)
const BINARY_HYPOTHESES: [&str; 2] = ["TRUE", "FALSE"];

/// The canonical claim-assessment frame's name. It replaced the per-source
/// `paper_validity_<slug>` frames `POST /claims/:id/assess` used to mint.
pub const CLAIM_VALIDITY_FRAME_NAME: &str = "claim_validity";
/// The canonical `claim_validity` frame's fixed id: prod's row (public, nil
/// world group), seeded on every other database by migration 154. It is
/// resolved by THIS id, never by name: `frames.name` is UNIQUE and any caller
/// can create a frame of any name, so a by-name lookup lets the first one to
/// name a frame `claim_validity` decide what every assess writes into.
pub const CLAIM_VALIDITY_FRAME_ID: Uuid =
    // belief-profile: allow-literal (a frame's fixed id, not a parameter)
    Uuid::from_u128(0x8a59_4393_c343_4f1a_b942_5c5b_7862_f792);
/// `claim_validity`'s ordered axis: 0 = supported, 1 = refuted, 2 = uncertain.
// belief-profile: allow-literal (array length of a fixed hypothesis list)
pub const CLAIM_VALIDITY_HYPOTHESES: [&str; 3] = ["supported", "refuted", "uncertain"];

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
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
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
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| format!("fetch source interval: {e}"))?;
    let Some((Some(bel), Some(pl), ow_opt)) = source_row else {
        return Ok(EdgeFactorOutcome::SourceFactorless);
    };
    // Write-time constants come from the served (default) profile.
    let profile = BeliefProfile::served();
    let source_interval = EpistemicInterval::new(
        bel,
        pl,
        ow_opt.unwrap_or((pl - bel).max(0.0) * profile.edge_factor.open_world_fraction_default),
    );

    // Extract the restriction transmission factor `f`. This is the baseline
    // per-BBA reliability before locality composition. (`f` is ALSO folded
    // into the BBA mass shape via `restrict_epistemic_*` — that shape and
    // the stored source_strength are independent Dempster-Shafer levers:
    // the shape encodes WHAT the supporter says about the target, and
    // source_strength encodes HOW reliable the supporter is. For a Negative
    // edge the shape is mutual exclusion: only the contradictor's belief
    // arrives, as mass on the target being FALSE, so the BBA never puts mass
    // on TRUE and a disbelieved contradictor writes a near-vacuous BBA.)
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

    if restricted.width() >= profile.edge_factor.vacuous_width
        && restricted.bel < profile.edge_factor.vacuous_belief
    {
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
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("intra-source evidence lookup: {e}"))?;
    // Resolution order for the intra-evidence locality factor:
    //   1. Per-frame override (frames.properties->>'intra_evidence_locality_factor').
    //      Lets operators tune locality discounting per epistemic context
    //      (binary_truth vs textbook_veracity_* vs research_validity etc.)
    //      without code releases. Set via FrameRepository::set_property.
    //   2. The served belief profile (calibration.toml, then the built-in
    //      default when calibration.toml is unreadable).
    //
    // Edge BBAs all land on the binary_truth frame today (see ensure_binary_frame
    // below); if a future edge_factor path writes to a different frame, the
    // per-frame override naturally follows because we look up by frame_id.
    let frame_row = ensure_binary_frame_row(&mut *conn, viewer).await?;
    let frame_id = frame_row.id;
    let per_frame_factor =
        FrameRepository::get_intra_evidence_locality_factor(&mut *conn, frame_id)
            .await
            .map_err(|e| format!("per-frame locality factor lookup: {e}"))?;
    let intra_factor =
        per_frame_factor.unwrap_or(profile.reliability.intra_evidence_locality_factor);
    let locality_factor = if is_intra {
        intra_factor
    } else {
        profile.reliability.cross_locality_factor
    };
    let source_strength = transmission_factor * locality_factor;

    let frame = binary_frame()?;
    let bba = restricted
        .to_mass_function(&frame)
        .map_err(|e| format!("interval_to_bba: {e}"))?;
    let masses_json = mass_to_json(&bba)?;

    FrameRepository::assign_claim(&mut *conn, target_id, frame_id, Some(0))
        .await
        .map_err(|e| format!("assign_claim: {e}"))?;
    PerspectiveRepository::ensure_edge_perspective(&mut *conn, edge_id, Some(edge_signer_agent_id))
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
    // relationship string (e.g. "supports") through the served profile's
    // `evidence_type_aliases` (filled from `calibration.toml`) to the
    // canonical SciFact-calibrated key (`"derived_support"`), so the fold
    // resolves a real calibrated weight instead of the unknown-type weight,
    // and a profile override of the alias reaches edge-written rows exactly
    // as it reaches raw-typed ones. See [`edge_evidence_type`].
    let stored_evidence_type = edge_evidence_type(relationship, profile);

    MassFunctionRepository::store_with_perspective(
        &mut *conn,
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

    recompute_combined_belief(
        &mut *conn,
        viewer,
        target_id,
        frame_id,
        &frame,
        crate::belief_profile::overrides_in(&frame_row.properties),
    )
    .await?;
    Ok(EdgeFactorOutcome::Wired)
}

/// The evidence type an edge-factor BBA for `relationship` is stored under:
/// the relationship's alias in `profile`'s alias table (matched
/// case-insensitively), else the relationship verbatim.
///
/// Storing the alias the fold would resolve anyway keeps a relationship's
/// weight the same whether its row carries the canonical key or the raw
/// relationship, under any profile whose alias table this is.
#[must_use]
pub fn edge_evidence_type(relationship: &str, profile: &BeliefProfile) -> String {
    profile
        .reliability
        .evidence_type_aliases
        .get(&relationship.to_lowercase())
        .cloned()
        .unwrap_or_else(|| relationship.to_string())
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
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
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
    // SAVEPOINT, because this function SWALLOWS every error below and its callers
    // now hand it a transaction. Inside a PostgreSQL transaction a failed statement
    // aborts the whole transaction, so swallowing does not preserve
    // "best-effort" — it DEFERS the failure to `COMMIT`, which PostgreSQL then
    // answers with `ROLLBACK` and no error at all. `link_epistemic` would report
    // `belief_wired: false` (correct) while also silently discarding the edge its
    // caller's transaction had written (not correct). Rolling back to a savepoint
    // keeps both properties: the wiring lands or is undone alone, and the outer
    // transaction stays usable either way.
    //
    // Opened BEFORE the two gate reads below, not after them: they swallow their
    // errors too (`None` on `Err`), so a failed read outside the savepoint would
    // abort the caller's transaction exactly as a failed write would. The first
    // revision opened it after them.
    let mut sp = match conn.begin().await {
        Ok(sp) => sp,
        Err(e) => {
            tracing::warn!(
                edge = %edge_id,
                "edge auto-wire skipped: could not open a savepoint, so the caller's \
                 transaction is already unusable: {e}",
            );
            return None;
        }
    };
    // A retracted edge must never be woken back into a BBA. Without this, a
    // recompute after retirement re-derives from the closed edge and undoes the
    // retraction silently — the failure mode that makes soft retraction useless
    // and is why retirement resorted to DELETE. Fail CLOSED on a lookup error:
    // re-wiring an edge we cannot prove is live is the worse outcome.
    let proceed = match EdgeRepository::is_in_force(&mut *sp, edge_id).await {
        Ok(true) => true,
        Ok(false) => false,
        Err(e) => {
            tracing::warn!(
                edge = %edge_id,
                "edge auto-wire skipped: in-force check failed: {e}",
            );
            false
        }
    };
    let proceed = proceed
        && (was_created
            || match MassFunctionRepository::exists_for_perspective(&mut *sp, viewer, edge_id).await
            {
                Ok(true) => false,
                Ok(false) => true, // never wired — attempt the wake-up below
                Err(e) => {
                    tracing::warn!(
                        edge = %edge_id,
                        "edge auto-wire wake-up check failed: {e}",
                    );
                    false
                }
            });
    if !proceed {
        // Roll back rather than release: a failed read leaves the savepoint
        // aborted, and rolling it back is what restores the caller's
        // transaction. On the Ok(false) arms it is equally correct — nothing
        // was written.
        if let Err(e) = sp.rollback().await {
            tracing::warn!(edge = %edge_id, "savepoint rollback failed: {e}");
        }
        return None;
    }
    match auto_wire_ds_for_edge(
        &mut sp,
        viewer,
        edge_id,
        agent_id,
        source_id,
        target_id,
        relationship,
    )
    .await
    {
        Ok(outcome) => match sp.commit().await {
            Ok(()) => Some(outcome),
            Err(e) => {
                tracing::warn!(
                    edge = %edge_id,
                    "edge auto-wire computed but its savepoint could not be released: {e}",
                );
                None
            }
        },
        Err(e) => {
            tracing::warn!(
                edge = %edge_id,
                target = %target_id,
                relationship = %relationship,
                "edge auto-wire failed: {e}; rolled back to savepoint",
            );
            if let Err(e) = sp.rollback().await {
                tracing::warn!(edge = %edge_id, "savepoint rollback failed: {e}");
            }
            None
        }
    }
}

/// Re-fetch all BBAs on (claim, binary frame), discount by source_strength,
/// combine, and write the resulting Bel/Pl/BetP/conflict/missing to the
/// claim's row. Public so other belief-recompute paths (e.g. HTTP
/// `propagate_to_dependents`) can share the cascade.
pub async fn recompute_claim_belief_binary(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<bool, String> {
    let frame_id = ensure_binary_frame(&mut *conn, viewer).await?;
    recompute_claim_belief_on_frame(&mut *conn, viewer, claim_id, frame_id).await
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
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
) -> Result<bool, String> {
    let row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
        .await
        .map_err(|e| format!("frame get_by_id: {e}"))?
        .ok_or_else(|| format!("frame {frame_id} not found"))?;
    let frame = FrameOfDiscernment::new(row.name.clone(), row.hypotheses.clone())
        .map_err(|e| format!("build frame {}: {e}", row.name))?;
    let all_rows =
        MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, claim_id, frame_id)
            .await
            .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    if all_rows.is_empty() {
        return Ok(false);
    }
    recompute_combined_belief(
        &mut *conn,
        viewer,
        claim_id,
        frame_id,
        &frame,
        crate::belief_profile::overrides_in(&row.properties),
    )
    .await?;
    Ok(true)
}

/// Write-free variant of [`recompute_claim_belief_on_frame`]: loads the frame
/// and every BBA on (claim, frame), runs the identical discount+combine
/// pipeline as [`recompute_combined_belief`], and returns the resulting
/// scalars instead of writing them to `claims`.
///
/// Added for `epigraph-cli/src/bin/recompute_betp.rs`'s `--dry-run` mode: it
/// needs to show "recomputed value if we wrote it" without mutating state.
/// `recompute_claim_belief_on_frame` cannot be reused directly for that —
/// each `epigraph-db` repo call borrows its own pooled connection, so
/// wrapping the call in a caller-side transaction and rolling back does NOT
/// prevent the write (the write lands on a different connection than the one
/// the rollback applies to). Splitting the pure compute out of the write is
/// the only reliable way to preview without a DB side effect.
///
/// Returns `Ok(None)` if the claim has no BBAs on `frame_id` (mirrors
/// `recompute_claim_belief_on_frame`'s `Ok(false)`).
///
/// # Errors
/// Same failure modes as [`recompute_claim_belief_on_frame`].
pub async fn preview_claim_belief_on_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
) -> Result<Option<CombinedBeliefPreview>, String> {
    let row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
        .await
        .map_err(|e| format!("frame get_by_id: {e}"))?
        .ok_or_else(|| format!("frame {frame_id} not found"))?;
    let frame = FrameOfDiscernment::new(row.name.clone(), row.hypotheses.clone())
        .map_err(|e| format!("build frame {}: {e}", row.name))?;
    compute_combined_belief(
        &mut *conn,
        viewer,
        claim_id,
        frame_id,
        &frame,
        crate::belief_profile::overrides_in(&row.properties),
    )
    .await
}

/// [`preview_claim_belief_on_frame`] over the frame's stored rows as `adjust`
/// leaves them: the same discount + combine pipeline, on rows the caller
/// filtered or edited in memory. Writes nothing and changes no stored row.
///
/// Added for `recompute_betp`'s drift decomposition (SPEC §10.4), whose
/// stages are counterfactual folds of the owner frame: without the ingest
/// template's rows (2), or with the `evidence_type` a manifest names reset to
/// its pre-backfill value (1'). `None` when no row is left.
///
/// # Errors
/// Same failure modes as [`preview_claim_belief_on_frame`].
pub async fn preview_claim_belief_on_frame_adjusted<F>(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    adjust: F,
) -> Result<Option<CombinedBeliefPreview>, String>
where
    F: FnOnce(Vec<MassFunctionRow>) -> Vec<MassFunctionRow>,
{
    let row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
        .await
        .map_err(|e| format!("frame get_by_id: {e}"))?
        .ok_or_else(|| format!("frame {frame_id} not found"))?;
    let frame = FrameOfDiscernment::new(row.name.clone(), row.hypotheses.clone())
        .map_err(|e| format!("build frame {}: {e}", row.name))?;
    let stored =
        MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, claim_id, frame_id)
            .await
            .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    compute_combined_belief_over(
        conn,
        viewer,
        claim_id,
        frame_id,
        &frame,
        crate::belief_profile::overrides_in(&row.properties),
        adjust(stored),
    )
    .await
}

/// Pure result of combining every BBA on a (claim, frame) pair: the same
/// scalars [`recompute_combined_belief`] writes to `claims`, plus the CDST
/// classification label when the frame is the canonical binary frame.
#[derive(Debug, Clone, PartialEq)]
pub struct CombinedBeliefPreview {
    pub belief: f64,
    pub plausibility: f64,
    pub pignistic_prob: f64,
    pub conflict_k: f64,
    pub missing_mass: f64,
    /// CDST classification label, only computed on the canonical binary
    /// frame (mirrors the `frame.id == BINARY_FRAME_NAME` gate in
    /// `recompute_combined_belief`).
    pub classification: Option<String>,
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
    // Kept for callers that hold a calibration rather than a profile. It
    // resolves a profile per call, so fold loops use
    // [`effective_source_strength_profiled`] with a profile resolved once.
    let profile = BeliefProfile::from_calibration(calibration).resolve(
        FrameTier {
            overrides: None,
            intra_evidence_locality_factor: per_frame_intra_factor,
            evidence_type_weights: per_frame_evidence_weights,
        },
        PerspectiveTier::default(),
    );
    global_source_strength(row, &profile)
}

/// The global (no perspective opinion on this BBA) branch of
/// [`effective_source_strength_profiled`]: the chain documented on
/// [`effective_source_strength`], with every constant read from `profile`
/// (the per-frame tier lives in `profile.lens.frame_evidence_type_weights` and
/// in the resolved `intra_evidence_locality_factor`).
fn global_source_strength(row: &MassFunctionRow, profile: &BeliefProfile) -> f64 {
    let r = &profile.reliability;
    // Step (1): legacy null-evidence_type cohort. The 5202ded backfill
    // populated `source_strength` on these rows without setting
    // `evidence_type`; we honor the stored value verbatim until Phase
    // 1c (backlog claim 7b934e58) derives `evidence_type` from the
    // linked evidence rows.
    if row.evidence_type.is_none() {
        if let Some(ss) = row.source_strength {
            return ss.clamp(0.0, 1.0);
        }
        // Step (5): everything NULL → the unknown-key fallback weight.
        return r.unknown_evidence_type_weight;
    }

    // SAFETY: just matched `Some` above.
    let evidence_type = row.evidence_type.as_deref().unwrap_or("");

    // Helper closure: compose a base weight with the locality discount.
    // Used by both Tier 1 (Phase 4 per-frame override) and Tier 2 (Phase
    // 2 global calibration). Keeps the locality semantics identical
    // across both tiers — an operator who writes `{"empirical": 0.5}`
    // expects the same `intra` discount to apply on top of 0.5 as it
    // would have applied to the global 1.0. The intra factor arrives
    // resolved (per-frame override ∨ profile).
    let compose_with_locality = |base: f64| -> f64 {
        let locality_factor = if row.locality_tag.starts_with("intra") {
            r.intra_evidence_locality_factor
        } else {
            r.cross_locality_factor
        };
        (base * locality_factor).clamp(0.0, 1.0)
    };

    // Step (2) — Phase 4 Tier 1: per-frame override strict-key lookup.
    // Map keys are already lowercased by the repo accessor; lowercase
    // the BBA's evidence_type to match. NO alias resolution at this
    // tier — see Q9 locked decision in Phase 4 spec § 5.
    if let Some(&w) = profile
        .lens
        .frame_evidence_type_weights
        .get(&evidence_type.to_lowercase())
    {
        return compose_with_locality(w);
    }

    // Step (3): evidence_type resolves to a calibrated weight (direct
    // or via the alias table). Compose with locality. Any locality_tag
    // starting with "intra" — current values: 'intra_self_cite',
    // 'intra_methodological_overlap' (Phase 2 vocabulary expansion);
    // historical 'intra' rows are migrated to 'intra_self_cite' in
    // the same PR — applies the intra discount. Everything else
    // ('cross', 'unknown', or any future tag we haven't taught the
    // helper) gets the cross factor.
    if profile.evidence_type_weight_present(evidence_type) {
        let base = profile.evidence_type_weight(evidence_type);
        return compose_with_locality(base);
    }

    // Step (4): evidence_type was set but isn't a calibrated key (path
    // 1 sentinel from Phase 2 spec § 4). The legacy `source_strength`
    // cache preserves write-time semantics; without it we drop to the
    // unknown-key fallback weight.
    if let Some(ss) = row.source_strength {
        return ss.clamp(0.0, 1.0);
    }
    r.unknown_evidence_type_weight
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
    // Calibration-holding entry point; resolves a profile per call (see
    // [`effective_source_strength`]).
    let profile = BeliefProfile::from_calibration(calibration).resolve(
        FrameTier {
            overrides: None,
            intra_evidence_locality_factor: per_frame_intra_factor,
            evidence_type_weights: per_frame_evidence_weights,
        },
        PerspectiveTier {
            overrides: None,
            reliability: Some(perspective),
        },
    );
    effective_source_strength_profiled(row, &profile)
}

/// Per-BBA reliability under a resolved [`BeliefProfile`]: the tier chain of
/// [`effective_source_strength_with_perspective`] with every constant, every
/// table and every lens map read from the profile.
///
/// - **base weight** = `lens.perspective_source_reliability[evidence_type]`
///   → `lens.frame_evidence_type_weights` → the profile's evidence-type
///   weights (aliases resolved) → stored `source_strength` → the unknown-type
///   weight.
/// - **locality factor** = `lens.perspective_locality_reliability[locality_tag]`
///   → the resolved intra factor when the tag is `intra*` → the cross factor.
/// - result = `base × locality`, clamped.
///
/// When the perspective maps have no entry touching this BBA, the result is
/// the global chain documented on [`effective_source_strength`], so a profile
/// without a perspective opinion reproduces the global belief.
#[must_use]
pub fn effective_source_strength_profiled(row: &MassFunctionRow, profile: &BeliefProfile) -> f64 {
    let lens = &profile.lens;
    let r = &profile.reliability;
    let etype = row.evidence_type.as_deref().map(str::to_lowercase);
    let locality_key = row.locality_tag.to_lowercase();

    let persp_base = etype
        .as_ref()
        .and_then(|t| lens.perspective_source_reliability.get(t))
        .copied();
    let persp_locality = lens
        .perspective_locality_reliability
        .get(&locality_key)
        .copied();

    // No override touches this BBA → identical to the global computation.
    if persp_base.is_none() && persp_locality.is_none() {
        return global_source_strength(row, profile);
    }

    // Base evidence-type weight: perspective → per-frame → profile table →
    // stored source_strength → unknown-type weight.
    let base = persp_base
        .or_else(|| {
            etype
                .as_ref()
                .and_then(|t| lens.frame_evidence_type_weights.get(t))
                .copied()
        })
        .or_else(|| {
            etype
                .as_ref()
                .filter(|t| profile.evidence_type_weight_present(t))
                .map(|t| profile.evidence_type_weight(t))
        })
        .or(row.source_strength)
        .unwrap_or(r.unknown_evidence_type_weight);

    // Locality factor: perspective → resolved intra factor when the tag is
    // intra*, else the cross factor.
    let locality = persp_locality.unwrap_or_else(|| {
        if locality_key.starts_with("intra") {
            r.intra_evidence_locality_factor
        } else {
            r.cross_locality_factor
        }
    });

    (base * locality).clamp(0.0, 1.0)
}

/// Relationship-vocab strings the `auto_wire_ds_for_edge` write path may emit
/// as a BBA's `evidence_type` before they are added to
/// `calibration.evidence_type_aliases`. Part of the known vocabulary.
const RELATIONSHIP_VOCAB_ALLOWLIST: &[&str] = &[
    "supports",
    "corroborates",
    "refutes",
    "supersedes",
    "derived_support",
    "derived_refute",
    "derived_supersession",
];

/// The evidence-type vocabulary check: is `key` a canonical key in
/// `calibration.evidence_type_weights`, an alias in
/// `calibration.evidence_type_aliases`, or one of the relationship-vocab
/// strings the edge auto-wire emits?
///
/// Case-insensitive, like the calibration accessors it delegates to. NOTE that
/// the reliability OVERRIDE maps that consume such keys (a frame's
/// `evidence_type_weights`, a perspective's `source_reliability`) are looked up
/// STRICT-KEY against the BBA's lowercased `evidence_type`, so a known key
/// spelled with capitals is still one those maps can never match; callers that
/// validate an override map must check the spelling as well.
///
/// A key outside this vocabulary is not rejected anywhere: an unknown
/// `evidence_type` on a BBA with no stored `source_strength` falls through
/// [`effective_source_strength`]'s chain to the 0.5 unknown-type weight.
#[must_use]
pub fn is_known_evidence_type_key(key: &str, calibration: &CalibrationConfig) -> bool {
    calibration.evidence_type_weight_present(key)
        || RELATIONSHIP_VOCAB_ALLOWLIST.contains(&key.to_lowercase().as_str())
}

/// [`is_known_evidence_type_key`] against a belief profile's weight and alias
/// tables: the vocabulary the fold under `profile` actually resolves. Write
/// surfaces and the recompute's warn-log use this with the profile the combine
/// folds under, so a `[belief_profiles]` override that adds or removes a
/// weight moves the verdict with the combine.
#[must_use]
pub fn is_known_evidence_type_key_in(key: &str, profile: &BeliefProfile) -> bool {
    profile.evidence_type_weight_present(key)
        || RELATIONSHIP_VOCAB_ALLOWLIST.contains(&key.to_lowercase().as_str())
}

/// Phase 4 (issue #197) Q8: warn on per-frame evidence-type override
/// keys that aren't in the known vocabulary of the profile the combine folds
/// under.
///
/// "Known vocabulary" = canonical key in the profile's `evidence_type_weights`
/// ∪ alias in its `evidence_type_aliases` (both filled from
/// `calibration.toml`, then the profile tiers) ∪ a small allow-list of
/// relationship-vocab strings the `auto_wire_ds_for_edge` write path may
/// emit before they're added to `evidence_type_aliases`. Operators may
/// legitimately register weights for future evidence types not yet in
/// calibration.toml; this is a log signal for typos, not a hard reject.
///
/// The vocabulary test itself is [`is_known_evidence_type_key_in`], public so the
/// MCP write surfaces that accept these keys can return the same verdict to
/// the caller as a warning instead of only logging it (backlog 86ee2d30).
fn warn_on_unknown_evidence_type_keys(
    frame_id: Uuid,
    map: &HashMap<String, f64>,
    profile: &BeliefProfile,
) {
    for key in map.keys() {
        // Map keys are already lowercased by the repo accessor.
        if is_known_evidence_type_key_in(key, profile) {
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

/// Which hypothesis of a frame a claim's belief there is ABOUT, from its stored
/// `claim_frames.hypothesis_index`: the stored index when it names one of the
/// frame's `hypothesis_count` hypotheses, otherwise 0.
///
/// THE shared rule for every reader of a (claim, frame) BBA set (backlog
/// 45cbaef4, G6): the cache writer ([`compute_combined_belief`]) and the three
/// framed readers in `belief_query` (`get_belief`, `get_perspective_belief`,
/// `get_perspective_belief_batch`). They used to disagree on exactly the rows
/// this function exists for. The writer clamped as here; the readers did
/// `unwrap_or(0) as usize`, so a NEGATIVE index wrapped to `usize::MAX` and an
/// index past the end addressed no hypothesis at all — Bel = Pl = BetP = 0 on
/// the framed read, beside a cached belief about hypothesis 0.
///
/// Why 0 and not "no hypothesis", measured against the frame's semantics: a
/// frame is an ordered list of mutually exclusive hypotheses addressed by
/// 0-based index, so an index outside `[0, hypothesis_count)` names nothing.
/// Reporting Bel = Pl = 0 for it would state "this claim is certainly false"
/// about a claim whose only defect is a bad pointer — a confident answer
/// nothing supports. 0 is instead the value every path already uses when the
/// pointer is ABSENT (no assignment row, or a NULL column), and it is TRUE on
/// the canonical binary frame, where almost every claim lives. A bad pointer is
/// treated like a missing one. The column is `integer` with no CHECK
/// (migration 001), so such rows can exist; `submit_ds_evidence` now warns
/// when it is asked to store one.
#[must_use]
pub fn resolve_hypothesis_index(stored: Option<i32>, hypothesis_count: usize) -> usize {
    stored
        .and_then(|i| usize::try_from(i).ok())
        .filter(|i| *i < hypothesis_count)
        .unwrap_or(0)
}

/// Pure compute half of the combine pipeline: load every BBA on (claim,
/// frame), discount + combine, and derive the resulting Bel/Pl/BetP/
/// conflict/missing scalars (plus the CDST classification label on the
/// binary frame). Does not touch the database beyond the read-only loads
/// (`mass_functions`, calibration, per-frame overrides).
///
/// Factored out of [`recompute_combined_belief`] so
/// [`preview_claim_belief_on_frame`] can share the exact same combine
/// pipeline (same calibration lookups, same reliability derivation, same
/// classifier) without also performing the `UPDATE claims ...` write —
/// see that function's doc comment for why a caller-side rolled-back
/// transaction can't substitute for this split.
///
/// `frame_overrides` is the frame's `belief_profile` object, taken from the
/// frame row the caller already loaded under `viewer` (every caller loads it
/// before combining and stops when the frame is invisible), so the frame tier
/// costs no query here and always comes from the same visible row as the
/// per-frame keys.
async fn compute_combined_belief(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    frame_overrides: Option<&serde_json::Value>,
) -> Result<Option<CombinedBeliefPreview>, String> {
    let all_rows =
        MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, claim_id, frame_id)
            .await
            .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    compute_combined_belief_over(
        conn,
        viewer,
        claim_id,
        frame_id,
        frame,
        frame_overrides,
        all_rows,
    )
    .await
}

/// [`compute_combined_belief`] over the given rows of (claim, frame) instead
/// of the stored ones, under the same frame tier (`frame_overrides`). `None`
/// when `all_rows` is empty.
async fn compute_combined_belief_over(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    frame_overrides: Option<&serde_json::Value>,
    all_rows: Vec<MassFunctionRow>,
) -> Result<Option<CombinedBeliefPreview>, String> {
    // Ruling R-22: what this fold computes is the claim's CACHED belief (or a
    // preview of it), which everyone who can read the claim is served, so it
    // folds only the BBAs whose every source is at least as widely readable
    // as the claim (`crate::derivation_scope`). Filtered before anything
    // reads the rows: the classification's `has_opposing` below iterates them
    // too.
    let all_rows = crate::derivation_scope::retain_for_cache(&mut *conn, all_rows)
        .await
        .map_err(|e| format!("derivation scope read: {e}"))?;
    if all_rows.is_empty() {
        return Ok(None);
    }

    let profile = fold_profile(&mut *conn, frame_id, frame_overrides).await;

    // Discount each BBA, then combine. Same-source BBAs (one agent re-reading
    // one `source_url`) are folded cautiously into one before the Dempster
    // fold (backlog 4c42c0bf, `crate::source_dependence`), and so are the
    // agreeing BBAs of sibling agents of one human (ruling R-36); the write
    // path `ds_auto::auto_wire_ds_update` uses the same function, so a
    // recompute cannot re-inflate what the write left honest.
    //
    // `fold_conflict` is the conflict the fold SAW. Since U025 every
    // `combine_multiple` step is Dempster, which normalises conflict out of
    // the combined mass (`combined.mass_of_conflict()` is 0), so the
    // multi-BBA arm takes it from the per-step reports via
    // `aggregate_conflict` (= the TBM empty-set mass, order-independent).
    // A single (or single-source) BBA is not folded: its own empty-set mass
    // is the conflict.
    let sources = crate::source_dependence::bba_sources_for_rows(&mut *conn, viewer, &all_rows)
        .await
        .map_err(|e| format!("BBA source read: {e}"))?;
    let mut items = Vec::with_capacity(all_rows.len());
    for (row, key) in all_rows.iter().zip(sources) {
        let mf = parse_stored_bba(frame, &row.masses)?;
        let reliability = effective_source_strength_profiled(row, &profile);
        let d = combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?;
        items.push((key, d));
    }
    let (combined, fold_conflict) = crate::source_dependence::combine_with_owner_dependence(
        items,
        profile.combination.conflict_threshold,
    )
    .map_err(|e| format!("combine_multiple: {e}"))?;

    // has_opposing: does any single source BBA lean toward contradiction?
    // Post-#197 a `refutes`/`contradicts` edge auto-wires a Negative-leaning
    // BBA on the target, so edge-borne AND directly-submitted opposition both
    // surface here as a per-BBA betp_unsup — this replaces (and subsumes) the
    // legacy CONTRADICTS-edge query, which only saw edge-borne opposition.
    // Only the binary frame's classification reads it.
    let opposing_threshold = profile.classifier.thresholds().has_opposing_threshold;
    let has_opposing = all_rows.iter().any(|row| {
        parse_stored_bba(frame, &row.masses)
            .map(|bba| measures::pignistic_probability(&bba, 1) > opposing_threshold)
            .unwrap_or(false)
    });

    preview_of_combined(
        conn,
        viewer,
        claim_id,
        frame_id,
        frame,
        &profile,
        &combined,
        fold_conflict,
        has_opposing,
    )
    .await
    .map(Some)
}

/// The belief profile the combine of (claim, `frame_id`) folds under: the
/// served (default) profile, then this frame's tier (its `belief_profile`
/// object, `frame_overrides`, and the per-frame keys read here).
async fn fold_profile(
    conn: &mut sqlx::PgConnection,
    frame_id: Uuid,
    frame_overrides: Option<&serde_json::Value>,
) -> BeliefProfile {
    // Phase 2 (issue #197): the combine path no longer trusts the
    // stored `source_strength` as the authority. Instead we compute
    // each BBA's effective reliability discount dynamically from
    // (`evidence_type`, `locality_tag`, per-frame factor, calibration).
    // Recalibration — e.g. changing `intra_evidence_locality_factor`
    // in `calibration.toml` or via a per-frame override — flows through
    // to combined BetP without any DB rewrite.
    //
    // Every reliability input is resolved ONCE, above the loop, into a
    // belief profile: the served (default) profile, then this frame's tier
    // (its `belief_profile` object and the per-frame keys below).
    let per_frame_intra = FrameRepository::get_intra_evidence_locality_factor(&mut *conn, frame_id)
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
        FrameRepository::get_per_frame_evidence_type_weights(&mut *conn, frame_id)
            .await
            .ok()
            .flatten();

    let profile = BeliefProfile::served().resolve(
        FrameTier {
            overrides: frame_overrides,
            intra_evidence_locality_factor: per_frame_intra,
            evidence_type_weights: per_frame_evidence_weights.as_ref(),
        },
        PerspectiveTier::default(),
    );

    // Vocabulary warn-log (Q8 locked: loose validation at set_property,
    // warn-log at read-site). Iterate the override map's keys and warn
    // on any that don't resolve to a known evidence-type vocabulary
    // entry of the profile this combine folds under: canonical key, alias, or one of
    // the relationship-vocab strings the auto-wire write path emits.
    // Surfaces operator typos in operational logs without blocking the
    // write.
    if let Some(ref map) = per_frame_evidence_weights {
        warn_on_unknown_evidence_type_keys(frame_id, map, &profile);
    }

    profile
}

/// The cached scalars (and the binary frame's classification) of `combined`,
/// the fold of the claim's BBAs on `frame` with conflict `conflict`, about the
/// hypothesis the claim is assigned on that frame. `has_opposing`: some
/// single folded BBA leans toward contradiction.
#[allow(clippy::too_many_arguments)]
async fn preview_of_combined(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    profile: &BeliefProfile,
    combined: &MassFunction,
    conflict: f64,
    has_opposing: bool,
) -> Result<CombinedBeliefPreview, String> {
    // Which hypothesis these cached scalars are ABOUT. On the canonical binary
    // frame this is 0 (TRUE) for every claim, so the binary path is unchanged.
    // On a multi-hypothesis frame — a declared labeled axis (issue #222), or any
    // claim `submit_ds_evidence` assigned a non-zero index — hardcoding 0 cached
    // Bel/Pl/BetP for the WRONG hypothesis: "Bel(ineffective)" for a claim
    // placed on "moderate". The read side (`belief_query::get_belief`,
    // `get_perspective_belief`, `get_perspective_belief_batch`) has always
    // targeted the claim's stored `claim_frames.hypothesis_index`; this makes the
    // cache writer agree with it, so a `recompute_beliefs` can no longer
    // overwrite an axis claim's cache with a belief about index 0.
    //
    // Resolved by `resolve_hypothesis_index`, the ONE rule every reader of a
    // BBA shares (backlog 45cbaef4): see its doc for why.
    let hypothesis_index = resolve_hypothesis_index(
        FrameRepository::get_claim_assignment(&mut *conn, viewer, claim_id, frame_id)
            .await
            .map_err(|e| format!("get_claim_assignment: {e}"))?
            .and_then(|a| a.hypothesis_index),
        frame.hypothesis_count(),
    );

    let target = FocalElement::positive(BTreeSet::from([hypothesis_index]));
    let bel = measures::belief(combined, &target);
    let pl = measures::plausibility(combined, &target);
    let betp = measures::pignistic_probability(combined, hypothesis_index);
    let missing = combined.mass_of_missing();

    // CDST classification — a verdict on the COMBINED belief via the
    // deterministic BetP 7-rule cascade. Defined only on the canonical binary
    // {TRUE, FALSE} frame (supported = idx 0, contradicted = idx 1); other
    // frames leave classification unset. Thresholds come from the resolved
    // profile (operator-tunable, same resolution as the discount path).
    let classification = if frame.id == BINARY_FRAME_NAME {
        let thresholds = &profile.classifier.thresholds();
        // theta = closed-world full-frame ignorance m({0,1}); the open-world
        // missing mass is excluded (Smets TBM), matching the legacy
        // `compute_betp` the cascade was calibrated against.
        let theta = combined.mass_of(&FocalElement::positive(BTreeSet::from([0_usize, 1_usize])));
        // The cascade is defined on (betp_supported, betp_unsupported) = (idx 0,
        // idx 1) specifically, so take idx 0 explicitly rather than reusing the
        // assignment-targeted `betp` above. They are the same value for every
        // normal binary claim (assigned index 0); they differ only for a claim
        // deliberately assigned index 1 on the binary frame, where feeding
        // pignistic(1) in as "supported" would invert the verdict.
        let betp_supported = measures::pignistic_probability(combined, 0);
        let betp_unsup = measures::pignistic_probability(combined, 1);
        let label = crate::classifier::classify(
            conflict,
            theta,
            betp_supported,
            betp_unsup,
            has_opposing,
            thresholds,
        );
        Some(label.to_string())
    } else {
        None
    };

    Ok(CombinedBeliefPreview {
        belief: bel,
        plausibility: pl,
        pignistic_prob: betp,
        conflict_k: conflict,
        missing_mass: missing,
        classification,
    })
}

/// Write half of the combine pipeline: run [`compute_combined_belief`] and
/// persist the result to `claims.{belief, plausibility, pignistic_prob,
/// conflict_k, missing_mass}` (and `classification` on the binary frame).
/// No-ops (does not write) when the claim has no BBAs on `frame_id`.
async fn recompute_combined_belief(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    frame: &FrameOfDiscernment,
    frame_overrides: Option<&serde_json::Value>,
) -> Result<(), String> {
    let Some(preview) = compute_combined_belief(
        &mut *conn,
        viewer,
        claim_id,
        frame_id,
        frame,
        frame_overrides,
    )
    .await?
    else {
        return Ok(());
    };

    let written = MassFunctionRepository::update_claim_belief(
        &mut *conn,
        claim_id,
        epigraph_db::CachedBelief {
            belief: preview.belief,
            plausibility: preview.plausibility,
            mass_on_empty: preview.conflict_k,
            pignistic_prob: Some(preview.pignistic_prob),
            mass_on_missing: preview.missing_mass,
            belief_frame_id: Some(frame_id),
        },
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;

    // The verdict belongs to the cache it describes: when the cache was not
    // written (a non-owner on a frame the claim's cache does not carry,
    // migration 114), neither is its classification.
    if let (true, Some(label)) = (written, preview.classification) {
        MassFunctionRepository::update_claim_classification(&mut *conn, claim_id, &label, frame_id)
            .await
            .map_err(|e| format!("update_claim_classification: {e}"))?;
    }

    Ok(())
}

/// Recompute a claim's cached DS scalars, letting exactly ONE frame own them.
///
/// Backlog 696d3a1c. `recompute_claim_belief_on_frame` persists nothing per-frame —
/// it writes only the five SHARED `claims.{belief, plausibility, mass_on_empty,
/// pignistic_prob, mass_on_missing}` columns plus `claims.classification`. Callers
/// that looped over every frame a claim has BBAs on therefore wrote that one cache
/// repeatedly, and the last frame processed won.
///
/// `list_frames_for_claim` orders `BY f.name`, and the canonical `binary_truth`
/// frame sorts FIRST (b < c < f < p < t). So the edge-derived belief that
/// `auto_wire_ds_for_edge` writes there was reliably clobbered by any
/// `claim_validity`, `paper_validity_*` or `textbook_veracity_*` frame the claim
/// also carried — usually one holding the pre-edge intrinsic assessment. That is
/// what silently reverted every `contradicts`/`refutes` edge written since the
/// previous recompute, and it reported `errors: []` while doing it.
///
/// ## What this function is, and what it is NOT
///
/// It is NOT an assertion that a claim has one frame. Multi-frame claims are
/// intended and already first-class: `claim_frames` is keyed
/// `PRIMARY KEY (claim_id, frame_id)`, and the same claim legitimately carries
/// different beliefs in different contexts.
///
/// The actual defect is narrower and lives in the schema: `claims` holds SIX
/// belief columns — `belief`, `plausibility`, `mass_on_empty`, `pignistic_prob`,
/// `mass_on_missing`, `open_world_mass` — and NO frame reference. So a
/// denormalized single-valued cache is being asked to summarize N frames. The
/// clobber was the symptom of that, not of multi-frame itself.
///
/// This function does not resolve the modeling error. It makes the cache
/// deterministic and non-destructive by designating ONE frame as the summarized
/// one, so the cached scalars stop silently reverting edge-derived belief.
///
/// **Per-frame belief is not lost and never was.** It is recomputed on demand from
/// `mass_functions` by the framed `get_belief` path, which is correct today. The
/// cache is a performance artifact for the unframed read; the framed read is the
/// source of truth for any specific context.
///
/// ## Which frame owns the cache
///
/// [`MassFunctionRepository::cache_owner_frame_for_claim`] decides, among the
/// frames holding the claim's combine inputs (cached combination rows are
/// excluded, as the combine itself excludes them):
///
/// 1. `binary_truth`, when the claim has an input on it. It is what the
///    edge-wiring path writes and what unframed `get_belief` serves.
/// 2. Else `claim_validity`, when the claim has an input on it.
/// 3. Else the frame the cache already records (`claims.belief_frame_id`),
///    while that frame still holds an input.
/// 4. Else the first-writer frame: the frame holding the claim's earliest
///    input, ties broken by frame id.
///
/// No other frame name plays a part. Once the cache records an owner, an input
/// on another non-canonical frame, whenever it is written, does not move it; a
/// canonical frame does, as soon as the claim has an input there. If the
/// recorded owner no longer holds an input, ownership falls through to the
/// first writer. The claim row records the owner in `belief_frame_id`, so the
/// number is self-describing rather than an anonymous one-of-N.
///
/// The owner is always a frame this recompute can fold, and every
/// non-compound claim with a non-template input the viewer can see has one
/// (a workflow-rooted compound counts as non-compound here). A claim with no
/// owner is left exactly as it was (`Ok(false)`): that covers a claim whose
/// only inputs are ingest template rows (`epigraph_db::repos::mass_function::ingest_template_predicate`),
/// whose cache a bulk recompute would otherwise replace with the template's
/// near-vacuous fold, and a non-procedural compound (an in-force
/// `decomposes_to` out-edge, not under a workflow root), whose belief is a
/// query over its leaves rather than a fold of its own BBAs. So this function
/// never makes a claim's cache emptier than it was. Every caller inherits
/// both, including the per-write `routes::assess` refresh.
///
/// Resolving the owner is a read: this function creates no frame. (It used to
/// get-or-create `binary_truth` here only to compare ids.)
/// `cdst_maintenance::recompute_beliefs` takes the same two steps itself so it
/// can report the owner it targeted.
///
/// Returns whether the cache was written.
pub async fn recompute_claim_cached_belief(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
) -> Result<bool, String> {
    let Some(owner) =
        MassFunctionRepository::cache_owner_frame_for_claim(&mut *conn, viewer, claim_id)
            .await
            .map_err(|e| format!("cache_owner_frame_for_claim: {e}"))?
    else {
        return Ok(false);
    };

    recompute_claim_belief_on_frame(&mut *conn, viewer, claim_id, owner).await
}

/// Why the single atom-cache writer is called (SPEC §4.2, "Empty fold").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheWriteCause {
    /// An ordinary write or recompute.
    Organic,
    /// A lifecycle act (a hide, a retraction, an edge withdrawal or a dedup
    /// cascade) removed rows of the atom. The argument is what the atom's AEF
    /// input was BEFORE the act ([`aef_input_before`]): only an atom that had
    /// AEF input and lost all of it is vacated. Removing rows that were never
    /// AEF input (the ingest template, a cached combination, a row of a frame
    /// the fold does not read) vacates nothing.
    EvidenceRemoved(AefInputBefore),
}

/// Whether an atom had AEF input before a lifecycle act, as read by
/// [`aef_input_before`], the only way to build one. The writer's empty-fold
/// rule turns on it: once the rows are gone, the database cannot tell "lost
/// its AEF input" (vacated, ruling O24) from "never had any" (the residue,
/// left untouched, SPEC §4.2 and §10.5), so the caller reads it first, in the
/// same transaction, with the reader the writer folds with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AefInputBefore {
    claim_id: Uuid,
    had_input: bool,
}

impl AefInputBefore {
    /// The atom this was read for.
    #[must_use]
    pub const fn claim_id(&self) -> Uuid {
        self.claim_id
    }

    /// The atom had at least one AEF input row (in [`AxiomMode::Display`],
    /// as the writer folds it).
    ///
    /// [`AxiomMode::Display`]: crate::atom_items::AxiomMode::Display
    #[must_use]
    pub const fn had_input(&self) -> bool {
        self.had_input
    }
}

/// Read, BEFORE a lifecycle act, whether `claim_id` has AEF input as
/// [`recompute_atom_cache_with`] would fold it under `settings`: the
/// [`crate::atom_items::AxiomMode::Display`] rows `viewer` can see. Pass the
/// result as [`CacheWriteCause::EvidenceRemoved`] to the write after the act.
///
/// # Errors
/// A database read.
pub async fn aef_input_before(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    settings: AtomCacheSettings,
) -> Result<AefInputBefore, String> {
    let rows = crate::atom_items::atom_axiom_rows_under(
        &mut *conn,
        viewer,
        &[claim_id],
        crate::atom_items::AxiomMode::Display,
        &crate::belief_query::FramedBeliefContext::global(),
        settings.compound_source_edges,
    )
    .await?;
    Ok(AefInputBefore {
        claim_id,
        had_input: rows.get(&claim_id).is_some_and(|r| !r.is_empty()),
    })
}

/// The fold a call site used before the single atom-cache writer, which it
/// keeps wherever the AEF does not cover the claim (`EPIGRAPH_ATOM_FOLD`
/// scope, procedural and rule claims).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LegacyFold {
    /// [`recompute_claim_cached_belief`]: the cache-owner frame rule.
    OwnerFrame,
    /// [`recompute_claim_belief_on_frame`] on this frame.
    Frame(Uuid),
}

/// The switches [`recompute_atom_cache_with`] runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomCacheSettings {
    /// `EPIGRAPH_ATOM_FOLD`.
    pub fold: crate::atom_items::AtomFoldMode,
    /// `EPIGRAPH_COMPOUND_SOURCE_EDGES`.
    pub compound_source_edges: crate::atom_items::CompoundSourceEdges,
    /// Ruling O24: an atom whose AEF input a lifecycle act removed gets an
    /// explicit vacuous cache (logged), instead of keeping its old one.
    pub vacate_on_evidence_removal: bool,
}

impl AtomCacheSettings {
    /// This process's settings: the two flags as read at startup, and O24 as
    /// ruled.
    #[must_use]
    pub fn current() -> Self {
        Self {
            fold: crate::atom_items::AtomFoldMode::current(),
            compound_source_edges: crate::atom_items::CompoundSourceEdges::current(),
            vacate_on_evidence_removal: true,
        }
    }
}

/// What [`recompute_atom_cache`] did.
#[derive(Debug, Clone, PartialEq)]
pub enum AtomCacheOutcome {
    /// The claim is a compound: nothing was written.
    CompoundSkipped,
    /// The claim is not visible to the viewer: nothing was written.
    NotVisible,
    /// The legacy fold ran; `written` is what it reported.
    Legacy { written: bool },
    /// The AEF ran and its value was offered to the cache; `written` is
    /// whether the cache took it (a non-owner on a frame other than the
    /// recorded one does not write, migration 114).
    Folded {
        interval: crate::atom_items::EvidencedInterval,
        written: bool,
    },
    /// The AEF input is empty and the cache was left as it was.
    KeptEmpty,
    /// The AEF input is empty after a lifecycle act, and the cache was set
    /// to an explicit vacuous value (ruling O24); `written` as for `Folded`.
    Vacated { written: bool },
}

/// Process-wide count behind [`compound_cache_write_skipped`].
static COMPOUND_CACHE_WRITE_SKIPPED: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// How many times [`recompute_atom_cache`] refused to write a compound's cache
/// in this process (the `compound_cache_write_skipped` counter, SPEC §4.2).
#[must_use]
pub fn compound_cache_write_skipped() -> u64 {
    COMPOUND_CACHE_WRITE_SKIPPED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The single atom-cache writer (SPEC §4.2), under this process's
/// [`AtomCacheSettings::current`]. See [`recompute_atom_cache_with`].
///
/// The SPEC names it `recompute_atom_cache(conn, viewer, claim_id)`. It also
/// takes the call's `cause` (only the caller knows whether a lifecycle act
/// just removed the atom's evidence, which the empty-fold rule turns on) and
/// the `legacy` fold the call site used before, which it keeps wherever the
/// AEF does not cover the claim.
///
/// # Errors
/// A database read or write, or a fold that fails.
pub async fn recompute_atom_cache(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    cause: CacheWriteCause,
    legacy: LegacyFold,
) -> Result<AtomCacheOutcome, String> {
    recompute_atom_cache_with(
        conn,
        viewer,
        claim_id,
        cause,
        legacy,
        AtomCacheSettings::current(),
    )
    .await
}

/// [`recompute_atom_cache`] under explicit settings.
///
/// By the claim's role ([`epigraph_db::repos::claim_role::roles_batch`]):
///
/// * **compound**: nothing is written, under every mode and whatever the
///   `legacy` fold, and [`compound_cache_write_skipped`] counts it. A
///   compound's belief is a query over its leaves.
/// * **standalone** under `aef_standalone` or `aef`, and **leaf atom** under
///   `aef`: the AEF. The cache becomes
///   [`crate::atom_items::atom_fold`] of the claim's
///   [`crate::atom_items::AxiomMode::Display`] rows under no lens, stamped
///   `binary_truth`, with its classification.
/// * everything else (any role under `legacy`, a leaf under
///   `aef_standalone`, a procedural or rule claim): the `legacy` fold,
///   exactly as the call site ran it before.
///
/// **Empty fold** under the AEF: after [`CacheWriteCause::EvidenceRemoved`]
/// whose [`AefInputBefore`] says the atom HAD AEF input, and when ruling O24
/// is on, the cache is set to an explicit vacuous value (Bel 0, Pl 1, BetP
/// .5, `binary_truth`); when the cache took it, the atom is logged on the
/// evidence-removal vacate list (target `epigraph::atom_cache::vacate`).
/// Otherwise the cache is left as it is: an atom that never had AEF input
/// (the residue) is served from its old cache, and is vacated only through
/// the operator accept list (SPEC §10.5). **No arm ever NULLs a cache.**
///
/// **Viewer.** Every arm folds what `viewer` can see and offers it to the one
/// global `claims` cache, exactly as the legacy writers do, under the
/// migration-114 non-owner rule. That holds for the empty-fold decision too:
/// a viewer who cannot see an atom's remaining group-private rows sees an
/// empty fold. Which viewer each lifecycle site writes as is chosen where the
/// site is wired (PR-5b1), as `retraction_cascade` chooses it today.
///
/// **Row security.** The role is read without a splice, which makes "a
/// compound is never written" hold on a connection that bypasses row
/// security. On an application session `edges` row security can hide a
/// compound's whole decomposition, and the compound then reads as a
/// standalone (the `claim_role` module doc). Per-request call sites must not
/// be wired until that is closed (PR-5b1).
///
/// # Errors
/// A database read or write, a fold that fails, or a
/// [`CacheWriteCause::EvidenceRemoved`] read for another claim.
pub async fn recompute_atom_cache_with(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    cause: CacheWriteCause,
    legacy: LegacyFold,
    settings: AtomCacheSettings,
) -> Result<AtomCacheOutcome, String> {
    use crate::atom_items::{atom_axiom_rows_under, atom_fold_under, AtomFoldMode, AxiomMode};
    use epigraph_db::repos::claim_role::{roles_batch, ClaimRole};

    if let CacheWriteCause::EvidenceRemoved(before) = cause {
        if before.claim_id != claim_id {
            return Err(format!(
                "recompute_atom_cache: the AEF input read before the act is for claim {}, \
                 not {claim_id}",
                before.claim_id
            ));
        }
    }
    let roles = roles_batch(&mut *conn, viewer, &[claim_id])
        .await
        .map_err(|e| format!("roles_batch: {e}"))?;
    let Some(role) = roles.get(&claim_id).copied() else {
        return Ok(AtomCacheOutcome::NotVisible);
    };
    let aef = match role {
        ClaimRole::Compound { .. } => {
            COMPOUND_CACHE_WRITE_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                claim = %claim_id,
                counter = "compound_cache_write_skipped",
                "the atom-cache writer leaves a compound's cache alone"
            );
            return Ok(AtomCacheOutcome::CompoundSkipped);
        }
        ClaimRole::Standalone => {
            matches!(
                settings.fold,
                AtomFoldMode::AefStandalone | AtomFoldMode::Aef
            )
        }
        ClaimRole::Atom => settings.fold == AtomFoldMode::Aef,
        ClaimRole::Procedural | ClaimRole::Rule => false,
    };
    if !aef {
        let written = match legacy {
            LegacyFold::OwnerFrame => recompute_claim_cached_belief(conn, viewer, claim_id).await?,
            LegacyFold::Frame(frame_id) => {
                recompute_claim_belief_on_frame(conn, viewer, claim_id, frame_id).await?
            }
        };
        return Ok(AtomCacheOutcome::Legacy { written });
    }

    let ctx = crate::belief_query::FramedBeliefContext::global();
    // The classifier reads the same profile the fold runs under.
    let thresholds = ctx.profile().classifier.thresholds();
    let rows = atom_axiom_rows_under(
        &mut *conn,
        viewer,
        &[claim_id],
        AxiomMode::Display,
        &ctx,
        settings.compound_source_edges,
    )
    .await?
    .remove(&claim_id)
    .unwrap_or_default();

    if rows.is_empty() {
        let lost_input = matches!(cause, CacheWriteCause::EvidenceRemoved(b) if b.had_input);
        if lost_input && settings.vacate_on_evidence_removal {
            let written = write_atom_cache(
                conn,
                viewer,
                claim_id,
                &crate::atom_items::EvidencedInterval::unproven(),
                false,
                &thresholds,
            )
            .await?;
            if written {
                tracing::warn!(
                    target: "epigraph::atom_cache::vacate",
                    claim = %claim_id,
                    "evidence-removal vacate: a lifecycle act emptied the atom's AEF input; \
                     explicit vacuous cache (basis unproven)"
                );
            } else {
                tracing::info!(
                    claim = %claim_id,
                    "evidence-removal vacate not taken by the cache (non-owner write on \
                     another recorded frame); the cache is unchanged"
                );
            }
            return Ok(AtomCacheOutcome::Vacated { written });
        }
        return Ok(AtomCacheOutcome::KeptEmpty);
    }

    let interval = atom_fold_under(&rows, ctx.profile())?;
    let has_opposing = rows.iter().any(|r| {
        measures::pignistic_probability(r.coarse(), 1) > thresholds.has_opposing_threshold
    });
    let written =
        write_atom_cache(conn, viewer, claim_id, &interval, has_opposing, &thresholds).await?;
    Ok(AtomCacheOutcome::Folded { interval, written })
}

/// What [`vacate_atom_cache`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacateOutcome {
    /// The explicit vacuous cache was offered; `written` is whether the
    /// cache took it (as for [`AtomCacheOutcome::Folded`]).
    Vacated { written: bool },
    /// The claim is not visible to the viewer: nothing was written.
    NotVisible,
    /// The claim is a compound: nothing was written, and
    /// [`compound_cache_write_skipped`] counts it.
    Compound,
    /// A procedural or rule claim, whose cache is not an atom's: nothing
    /// was written.
    NotAnAtom,
    /// The claim is not current (superseded or marked a duplicate): it is
    /// no atom of the corpus, so nothing was written.
    NotCurrent,
    /// The atom has AEF input, so it is not residue: vacating it would
    /// erase an evidence-backed value. Nothing was written.
    HasAefInput,
}

/// The accepted-vacate write (SPEC §10.5): give a RESIDUE atom (a standalone
/// or leaf with no AEF input) the explicit vacuous cache (Bel 0, Pl 1, BetP
/// .5, stamped `binary_truth`), which reads back as `unproven`. Never NULL.
///
/// The caller decides WHICH atoms (only ids on an operator-accepted list);
/// this function refuses every claim the vacate is not for, whatever the
/// list says ([`vacate_refusal`]). The PR-0 guard keeps every bulk recompute
/// from writing this value, so this is the one bulk path to it.
///
/// # Errors
/// A database read or write.
pub async fn vacate_atom_cache(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    compound_source_edges: crate::atom_items::CompoundSourceEdges,
) -> Result<VacateOutcome, String> {
    if let Some(refused) =
        vacate_refusal(&mut *conn, viewer, claim_id, compound_source_edges).await?
    {
        if refused == VacateOutcome::Compound {
            COMPOUND_CACHE_WRITE_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Ok(refused);
    }
    let ctx = crate::belief_query::FramedBeliefContext::global();
    // The classifier reads the same profile the fold runs under.
    let thresholds = ctx.profile().classifier.thresholds();
    let written = write_atom_cache(
        conn,
        viewer,
        claim_id,
        &crate::atom_items::EvidencedInterval::unproven(),
        false,
        &thresholds,
    )
    .await?;
    Ok(VacateOutcome::Vacated { written })
}

/// Why [`vacate_atom_cache`] refuses `claim_id` (the outcome it returns
/// without writing), or `None` when it would write the vacuous cache. The
/// ONE refusal ladder: the vacate and its dry run both read it. Writes
/// nothing.
///
/// Refused: a claim the viewer cannot see, a claim that is not current, a
/// compound, a procedural or rule claim, and an atom with AEF input (read as
/// the single atom-cache writer reads it, under `compound_source_edges`).
///
/// # Errors
/// A database read.
pub async fn vacate_refusal(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    compound_source_edges: crate::atom_items::CompoundSourceEdges,
) -> Result<Option<VacateOutcome>, String> {
    use epigraph_db::repos::claim_role::{roles_batch, ClaimRole};

    let roles = roles_batch(&mut *conn, viewer, &[claim_id])
        .await
        .map_err(|e| format!("roles_batch: {e}"))?;
    let Some(role) = roles.get(&claim_id).copied() else {
        return Ok(Some(VacateOutcome::NotVisible));
    };
    let current: Option<bool> = sqlx::query_scalar("SELECT is_current FROM claims WHERE id = $1")
        .bind(claim_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| format!("is_current: {e}"))?;
    match current {
        None => return Ok(Some(VacateOutcome::NotVisible)),
        Some(false) => return Ok(Some(VacateOutcome::NotCurrent)),
        Some(true) => {}
    }
    match role {
        ClaimRole::Compound { .. } => return Ok(Some(VacateOutcome::Compound)),
        ClaimRole::Procedural | ClaimRole::Rule => return Ok(Some(VacateOutcome::NotAnAtom)),
        ClaimRole::Standalone | ClaimRole::Atom => {}
    }
    let ctx = crate::belief_query::FramedBeliefContext::global();
    let has_input = crate::atom_items::atom_axiom_rows_under(
        &mut *conn,
        viewer,
        &[claim_id],
        crate::atom_items::AxiomMode::Display,
        &ctx,
        compound_source_edges,
    )
    .await?
    .get(&claim_id)
    .is_some_and(|rows| !rows.is_empty());
    Ok(has_input.then_some(VacateOutcome::HasAefInput))
}

/// Write an AEF value to the claim's cache, stamped `binary_truth`, and its
/// classification when the cache took it. Returns whether it did.
async fn write_atom_cache(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    claim_id: Uuid,
    interval: &crate::atom_items::EvidencedInterval,
    has_opposing: bool,
    thresholds: &crate::calibration::ClassifierThresholds,
) -> Result<bool, String> {
    let binary = ensure_binary_frame(&mut *conn, viewer).await?;
    let written = MassFunctionRepository::update_claim_belief(
        &mut *conn,
        claim_id,
        epigraph_db::CachedBelief {
            belief: interval.belief(),
            plausibility: interval.plausibility(),
            mass_on_empty: interval.mass_on_conflict(),
            pignistic_prob: Some(interval.pignistic_prob()),
            mass_on_missing: interval.mass_on_missing(),
            belief_frame_id: Some(binary),
        },
    )
    .await
    .map_err(|e| format!("update_claim_belief: {e}"))?;
    if written {
        let label = crate::classifier::classify(
            interval.mass_on_conflict(),
            interval.theta(),
            interval.pignistic_prob(),
            interval.pignistic_false(),
            has_opposing,
            thresholds,
        );
        MassFunctionRepository::update_claim_classification(
            &mut *conn,
            claim_id,
            &label.to_string(),
            binary,
        )
        .await
        .map_err(|e| format!("update_claim_classification: {e}"))?;
    }
    Ok(written)
}

/// Get-or-create the canonical `binary_truth` frame.
pub async fn ensure_binary_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<Uuid, String> {
    ensure_binary_frame_row(conn, viewer).await.map(|r| r.id)
}

/// [`ensure_binary_frame`], returning the frame row (its `properties` carry
/// the frame tier of the belief profile).
async fn ensure_binary_frame_row(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<epigraph_db::FrameRow, String> {
    if let Some(row) = FrameRepository::get_by_name(&mut *conn, viewer, BINARY_FRAME_NAME)
        .await
        .map_err(|e| format!("get_by_name: {e}"))?
    {
        return Ok(row);
    }
    let hyps: Vec<String> = BINARY_HYPOTHESES.iter().map(|s| (*s).to_string()).collect();
    // Under its own SAVEPOINT because the failure below is swallowed into a
    // fallback read, and callers hand this a transaction: an unsavepointed
    // `23505` (a lost first-creation race, or a same-named frame the viewer
    // cannot see) would abort the caller's transaction, fail the fallback with
    // `25P02`, and turn the caller's COMMIT into a silent ROLLBACK. Same shape
    // and reason as `epigraph_mcp::tools::ds_auto::ensure_axis_frame`.
    let mut sp = conn
        .begin()
        .await
        .map_err(|e| format!("binary_truth: could not open a savepoint for the create: {e}"))?;
    let created = FrameRepository::create(
        &mut *sp,
        BINARY_FRAME_NAME,
        Some("Canonical binary frame: {TRUE, FALSE}"),
        &hyps,
    )
    .await;
    match created {
        Ok(row) => {
            sp.commit().await.map_err(|e| {
                format!("binary_truth: could not release the create savepoint: {e}")
            })?;
            Ok(row)
        }
        Err(_) => {
            sp.rollback()
                .await
                .map_err(|e| format!("binary_truth: could not roll back the failed create: {e}"))?;
            FrameRepository::get_by_name(&mut *conn, viewer, BINARY_FRAME_NAME)
                .await
                .map_err(|e| format!("fallback get_by_name: {e}"))?
                .ok_or_else(|| "binary_truth frame missing after create attempt".to_string())
        }
    }
}

/// Resolve the canonical `claim_validity` frame, [`CLAIM_VALIDITY_FRAME_ID`],
/// and return its id. Never creates a frame.
///
/// The row is checked before it is used: its name must be
/// [`CLAIM_VALIDITY_FRAME_NAME`] and its ordered hypotheses
/// [`CLAIM_VALIDITY_HYPOTHESES`] (a frame denotes one ordered axis, as in
/// `epigraph_mcp::tools::ds_auto::ensure_axis_frame`). A missing or different
/// row is an error, so a caller refuses before it writes anything. A frame
/// some caller NAMED `claim_validity` under another id is never consulted.
///
/// # Errors
/// A DB failure; the row absent or invisible to `viewer` (migration 154 seeds
/// it); or a row with that id whose name or hypotheses are not the canonical
/// ones.
pub async fn resolve_claim_validity_frame(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<Uuid, String> {
    let row = FrameRepository::get_by_id(&mut *conn, viewer, CLAIM_VALIDITY_FRAME_ID)
        .await
        .map_err(|e| format!("claim_validity: get_by_id: {e}"))?
        .ok_or_else(|| {
            format!(
                "the canonical claim_validity frame {CLAIM_VALIDITY_FRAME_ID} is missing \
                 (migration 154 seeds it); refusing to create one at request time"
            )
        })?;
    if row.name != CLAIM_VALIDITY_FRAME_NAME
        || row
            .hypotheses
            .iter()
            .map(String::as_str)
            .ne(CLAIM_VALIDITY_HYPOTHESES)
    {
        return Err(format!(
            "frame {CLAIM_VALIDITY_FRAME_ID} is {:?} over {:?}, not the canonical \
             {CLAIM_VALIDITY_FRAME_NAME:?} over {CLAIM_VALIDITY_HYPOTHESES:?}",
            row.name, row.hypotheses
        ));
    }
    Ok(row.id)
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
