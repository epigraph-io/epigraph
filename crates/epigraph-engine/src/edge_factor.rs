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
//! (was_created + claim→claim) for use at edge-creation call sites.

use sqlx::PgPool;
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

use epigraph_db::{FrameRepository, MassFunctionRepository, PerspectiveRepository};
use epigraph_ds::{combination, measures, FocalElement, FrameOfDiscernment, MassFunction};

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

    let (restricted, source_strength) = match restriction {
        RestrictionKind::Positive(f) => (restrict_epistemic_positive(&source_interval, f), f),
        RestrictionKind::Negative(f) => (restrict_epistemic_negative(&source_interval, f), f),
        RestrictionKind::FrameEvidence(f) => (
            restrict_epistemic_frame_evidence(&source_interval, source_interval.betp(), f),
            f,
        ),
        RestrictionKind::Neutral => unreachable!(),
    };

    if restricted.width() >= 0.999 && restricted.bel < 0.01 {
        return Ok(EdgeFactorOutcome::Vacuous);
    }

    let frame_id = ensure_binary_frame(pool).await?;
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
        Some(relationship),
    )
    .await
    .map_err(|e| format!("store BBA: {e}"))?;

    recompute_combined_belief(pool, target_id, frame_id, &frame).await?;
    Ok(EdgeFactorOutcome::Wired)
}

/// Fire `auto_wire_ds_for_edge` from an edge-creation call site, gated on
/// whether the edge was newly created and connects two claim nodes.
///
/// Best-effort: failures are logged at `warn` and swallowed. Returns `None`
/// when the edge wasn't newly created, sources/targets aren't claims, or the
/// auto-wire call failed. Returns `Some(outcome)` when the trigger fired.
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
    if !was_created || source_type != "claim" || target_type != "claim" {
        return None;
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
    let frame = binary_frame()?;
    let all_rows = MassFunctionRepository::get_for_claim_frame(pool, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    if all_rows.is_empty() {
        return Ok(false);
    }
    recompute_combined_belief(pool, claim_id, frame_id, &frame).await?;
    Ok(true)
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

    let combined = if all_rows.len() == 1 {
        let r = &all_rows[0];
        let mf = parse_stored_bba(frame, &r.masses)?;
        let reliability = r.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);
        combination::discount(&mf, reliability).map_err(|e| format!("discount: {e}"))?
    } else {
        let mut mass_fns = Vec::with_capacity(all_rows.len());
        for row in &all_rows {
            let mf = parse_stored_bba(frame, &row.masses)?;
            let reliability = row.source_strength.unwrap_or(1.0).clamp(0.0, 1.0);
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
