//! CDST Sheaf: interval-aware sheaf cohomology with decomposed open-world ignorance.
//!
//! Extends the scalar sheaf (`sheaf.rs`) with full `EpistemicInterval` sections,
//! Hausdorff-distance inconsistency, and a 3-component H¹ decomposition:
//! - **conflict_h1**: Bel/Pl disagreement (classical belief conflict)
//! - **ignorance_h1**: closed-world ignorance width mismatch
//! - **open_world_h1**: open-world mass spread (frame incompleteness)

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::epistemic_interval::{
    restrict_epistemic_frame_evidence, restrict_epistemic_negative, restrict_epistemic_positive,
    EpistemicInterval,
};
use crate::sheaf::{restriction_kind_from_properties, RestrictionKind, RestrictionProfile};

// ── Obstruction taxonomy ──────────────────────────────────────────────────

/// The dominant reason why a sheaf edge is inconsistent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ObstructionKind {
    /// Bel/Pl intervals point in opposite directions: a genuine contradiction.
    BeliefConflict,
    /// Open-world mass is diverging across an edge (frame uncertainty spreading).
    OpenWorldSpread,
    /// Open-world mass on the source could be reduced by closing the frame
    /// at the (already narrow/certain) target.
    FrameClosureOpportunity,
    /// Ignorance width mismatch: one side knows more than the other but the
    /// belief centroids agree — epistemic staleness without contradiction.
    IgnoranceDrift,
}

// ── Section ───────────────────────────────────────────────────────────────

/// Interval-aware sheaf section for a single node.
#[derive(Debug, Clone)]
pub struct CdstSheafSection {
    pub node_id: Uuid,

    // Scalar backward-compat fields
    pub local_betp: f64,
    pub expected_betp: f64,
    pub consistency_radius: f64,

    // Interval fields
    pub local_interval: EpistemicInterval,
    pub expected_interval: EpistemicInterval,

    /// Hausdorff distance between local and expected intervals.
    pub interval_inconsistency: f64,

    // Open-world decomposition
    pub open_world_local: f64,
    pub open_world_expected: f64,

    /// |width_local − width_expected|
    pub ignorance_inconsistency: f64,

    pub neighbor_count: usize,
}

// ── Obstruction ───────────────────────────────────────────────────────────

/// An inconsistent edge in the CDST sheaf.
#[derive(Debug, Clone)]
pub struct CdstSheafObstruction {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,

    pub source_interval: EpistemicInterval,
    pub target_interval: EpistemicInterval,
    pub expected_interval: EpistemicInterval,

    /// Total Hausdorff distance between target and expected intervals.
    pub interval_inconsistency: f64,
    /// Component attributable to Bel/Pl belief conflict.
    pub conflict_component: f64,
    /// Component attributable to closed-world ignorance width mismatch.
    pub ignorance_component: f64,
    /// Component attributable to open-world mass divergence.
    pub open_world_component: f64,

    pub obstruction_kind: ObstructionKind,
}

// ── Cohomology ────────────────────────────────────────────────────────────

/// CDST sheaf first cohomology with decomposed H¹.
#[derive(Debug, Clone)]
pub struct CdstSheafCohomology {
    /// Number of consistent edges (inconsistency ≤ threshold).
    pub h0: usize,
    /// Total interval inconsistency across all edges.
    pub h1: f64,
    /// h1 / edge_count.
    pub h1_normalized: f64,
    pub edge_count: usize,

    // Decomposed H¹ components
    pub conflict_h1: f64,
    pub ignorance_h1: f64,
    pub open_world_h1: f64,

    /// Obstructions above threshold, sorted by interval_inconsistency DESC.
    pub obstructions: Vec<CdstSheafObstruction>,

    // Counts by kind
    pub belief_conflict_count: usize,
    pub open_world_spread_count: usize,
    pub frame_closure_count: usize,
    pub ignorance_drift_count: usize,
}

// ── Frame Evidence Proposal ───────────────────────────────────────────────

/// Proposal to reduce open-world mass at a target claim via frame evidence.
#[derive(Debug, Clone)]
pub struct FrameEvidenceProposal {
    pub target_claim_id: Uuid,
    pub evidence_source_id: Uuid,
    /// UUIDs of claims that bound the closed frame.
    pub scope_boundary: Vec<Uuid>,
    /// Proposed fractional reduction of open_world mass (in [0, 1]).
    pub proposed_reduction: f64,
    /// Confidence in the proposal (in [0, 1]).
    pub confidence: f64,
    pub scope_description: String,
}

// ── Core Functions ────────────────────────────────────────────────────────

/// Classify the dominant source of an edge obstruction.
///
/// Priority logic:
/// 1. If `conflict_component` is the largest → `BeliefConflict`
/// 2. If `open_world_component` is the largest AND the source has high
///    open-world mass AND the target is narrow (certain) →
///    `FrameClosureOpportunity`
/// 3. If `open_world_component` is the largest otherwise → `OpenWorldSpread`
/// 4. Otherwise → `IgnoranceDrift`
pub fn classify_obstruction(
    source_interval: &EpistemicInterval,
    target_interval: &EpistemicInterval,
    conflict_component: f64,
    ignorance_component: f64,
    open_world_component: f64,
    frame_closure_width_max: f64,
) -> ObstructionKind {
    let max = conflict_component
        .max(ignorance_component)
        .max(open_world_component);

    if (conflict_component - max).abs() < 1e-12 && max > 0.0 {
        ObstructionKind::BeliefConflict
    } else if (open_world_component - max).abs() < 1e-12 && max > 0.0 {
        if source_interval.open_world > target_interval.open_world
            && target_interval.is_narrow(frame_closure_width_max)
        {
            ObstructionKind::FrameClosureOpportunity
        } else {
            ObstructionKind::OpenWorldSpread
        }
    } else {
        ObstructionKind::IgnoranceDrift
    }
}

/// Compute the expected interval at a node from its neighbors' restricted intervals.
///
/// Each neighbor interval is restricted through its edge's `RestrictionKind`:
/// - `Positive(f)` → `restrict_epistemic_positive`
/// - `Negative(f)` → `restrict_epistemic_negative`
/// - `FrameEvidence(f)` → `restrict_epistemic_frame_evidence` using neighbor's
///   BetP as the evidence truth
/// - `Neutral` → skipped
///
/// Returns `None` when all neighbors are `Neutral`.
pub fn compute_cdst_expected(
    neighbors: &[(EpistemicInterval, RestrictionKind)],
) -> Option<EpistemicInterval> {
    let mut bel_sum = 0.0f64;
    let mut pl_sum = 0.0f64;
    let mut ow_sum = 0.0f64;
    let mut count = 0usize;

    for (interval, kind) in neighbors {
        match kind {
            RestrictionKind::Positive(factor) => {
                let r = restrict_epistemic_positive(interval, *factor);
                bel_sum += r.bel;
                pl_sum += r.pl;
                ow_sum += r.open_world;
                count += 1;
            }
            RestrictionKind::Negative(factor) => {
                let r = restrict_epistemic_negative(interval, *factor);
                bel_sum += r.bel;
                pl_sum += r.pl;
                ow_sum += r.open_world;
                count += 1;
            }
            RestrictionKind::FrameEvidence(factor) => {
                // Use the neighbor's own BetP as the evidence truth.
                let neighbor_betp = interval.betp();
                let r = restrict_epistemic_frame_evidence(interval, neighbor_betp, *factor);
                bel_sum += r.bel;
                pl_sum += r.pl;
                ow_sum += r.open_world;
                count += 1;
            }
            RestrictionKind::Neutral => {}
        }
    }

    if count == 0 {
        return None;
    }

    let n = count as f64;
    let bel = (bel_sum / n).clamp(0.0, 1.0);
    let pl = (pl_sum / n).clamp(0.0, 1.0);
    // open_world is clamped to the resulting width by EpistemicInterval::new
    let ow = ow_sum / n;
    Some(EpistemicInterval::new(bel, pl, ow))
}

/// Build a CDST sheaf section for a single node.
pub fn compute_cdst_section(
    node_id: Uuid,
    local_interval: EpistemicInterval,
    neighbors: &[(EpistemicInterval, RestrictionKind)],
) -> CdstSheafSection {
    let expected = compute_cdst_expected(neighbors);
    let expected_interval = expected.unwrap_or(local_interval);

    let interval_inconsistency = local_interval.hausdorff_distance(&expected_interval);
    let local_betp = local_interval.betp();
    let expected_betp = expected_interval.betp();

    let neighbor_count = neighbors
        .iter()
        .filter(|(_, k)| !matches!(k, RestrictionKind::Neutral))
        .count();

    CdstSheafSection {
        node_id,
        local_betp,
        expected_betp,
        consistency_radius: (local_betp - expected_betp).abs(),
        local_interval,
        expected_interval,
        interval_inconsistency,
        open_world_local: local_interval.open_world,
        open_world_expected: expected_interval.open_world,
        ignorance_inconsistency: (local_interval.width() - expected_interval.width()).abs(),
        neighbor_count,
    }
}

/// Compute the interval inconsistency for a single directed edge and classify it.
///
/// The expected interval is computed by applying the restriction map for
/// `relationship` to `source_interval`.  The obstruction components are:
/// - `interval_inconsistency` / `conflict_component`: for `contradicts` / frame-
///   evidence / neutral, the symmetric Bel/Pl distance (Hausdorff); for
///   `supports` (Positive), the directional floor *shortfall* — only the target
///   sitting below the corroborated `expected` floor on bel/pl counts, so over-
///   support is benign corroboration and contributes 0 to both fields and to H¹.
/// - `open_world_component`: |source_ow − expected_ow|
/// - `ignorance_component`: |width_target − width_expected|
pub fn compute_cdst_edge_inconsistency(
    source_id: Uuid,
    target_id: Uuid,
    source_interval: EpistemicInterval,
    target_interval: EpistemicInterval,
    relationship: &str,
    profile: &RestrictionProfile,
) -> CdstSheafObstruction {
    compute_cdst_edge_inconsistency_with_properties(
        source_id,
        target_id,
        source_interval,
        target_interval,
        relationship,
        &serde_json::Value::Null,
        profile,
    )
}

/// CDST-native variant: reads cdst_bel/cdst_pl from edge properties when available.
pub fn compute_cdst_edge_inconsistency_with_properties(
    source_id: Uuid,
    target_id: Uuid,
    source_interval: EpistemicInterval,
    target_interval: EpistemicInterval,
    relationship: &str,
    edge_properties: &serde_json::Value,
    profile: &RestrictionProfile,
) -> CdstSheafObstruction {
    let kind = restriction_kind_from_properties(relationship, edge_properties, profile);

    let expected_interval = match kind {
        RestrictionKind::Positive(factor) => restrict_epistemic_positive(&source_interval, factor),
        RestrictionKind::Negative(factor) => restrict_epistemic_negative(&source_interval, factor),
        RestrictionKind::FrameEvidence(factor) => {
            let neighbor_betp = source_interval.betp();
            restrict_epistemic_frame_evidence(&source_interval, neighbor_betp, factor)
        }
        RestrictionKind::Neutral => target_interval,
    };

    // For a `supports` edge the expected interval is a one-sided FLOOR — the
    // target should be AT LEAST this strongly believed AND plausible
    // (`restrict_epistemic_positive` sets `expected.bel = source.bel * factor`
    // and `expected.pl = 1-(1-source.pl)*factor`). Only UNDER-support — the
    // target sitting *below* that corroborated floor on bel OR pl — is a genuine
    // conflict; a strongly corroborated hub that *exceeds* a discounted weak
    // supporter is benign corroboration, not contradiction.
    //
    // So the Positive arm is directional for BOTH twin fields: `interval_
    // inconsistency` (which `compute_cdst_cohomology` filters/sorts/sums to form
    // H¹, and which the MCP `sheaf_cohomology` tool surfaces as `edge_
    // inconsistency`) and `conflict_component` are each the floor *shortfall*.
    // Keeping them equal preserves the twin-field equality origin/main has for
    // supports edges; zeroing only `conflict_component` (the prior fix) left the
    // over-support obstruction listed under `interval_inconsistency` so H¹ never
    // dropped and the nightly conflict-resolution scan re-observed it forever.
    //
    // contradicts / frame-evidence / neutral are NOT one-sided floors, so they
    // keep the symmetric Bel/Pl distance: `interval_inconsistency` stays the
    // Hausdorff distance and `conflict_component` its (equal) symmetric form.
    let (interval_inconsistency, conflict_component) = match kind {
        RestrictionKind::Positive(_) => {
            // Floor shortfall: only mass BELOW the corroborated floor on either
            // endpoint is inconsistency; over-support contributes 0.
            let below = (expected_interval.bel - target_interval.bel)
                .max(0.0)
                .max((expected_interval.pl - target_interval.pl).max(0.0));
            (below, below)
        }
        _ => {
            let hausdorff = target_interval.hausdorff_distance(&expected_interval);
            let t_bel = target_interval.bel;
            let t_pl = target_interval.pl;
            let e_bel = expected_interval.bel;
            let e_pl = expected_interval.pl;
            let symmetric = (t_bel - e_bel).abs().max((t_pl - e_pl).abs());
            (hausdorff, symmetric)
        }
    };

    // Open-world component: divergence in open-world mass
    let open_world_component = (target_interval.open_world - expected_interval.open_world).abs();

    // Ignorance component: width mismatch (closed-world ignorance)
    let ignorance_component = (target_interval.width() - expected_interval.width()).abs();

    // Use default frame_closure_width_max = 0.2
    let obstruction_kind = classify_obstruction(
        &source_interval,
        &target_interval,
        conflict_component,
        ignorance_component,
        open_world_component,
        0.2,
    );

    CdstSheafObstruction {
        source_id,
        target_id,
        relationship: relationship.to_string(),
        source_interval,
        target_interval,
        expected_interval,
        interval_inconsistency,
        conflict_component,
        ignorance_component,
        open_world_component,
        obstruction_kind,
    }
}

/// Compute CDST H¹ cohomology from a list of edge obstructions.
///
/// Obstructions are sorted by `interval_inconsistency` DESC.
/// Edges with inconsistency ≤ `threshold` contribute to h0 (consistent).
/// H¹ is decomposed into conflict, ignorance, and open-world components.
pub fn compute_cdst_cohomology(
    obstructions: Vec<CdstSheafObstruction>,
    threshold: f64,
) -> CdstSheafCohomology {
    let edge_count = obstructions.len();

    let h1: f64 = obstructions.iter().map(|o| o.interval_inconsistency).sum();
    let conflict_h1: f64 = obstructions.iter().map(|o| o.conflict_component).sum();
    let ignorance_h1: f64 = obstructions.iter().map(|o| o.ignorance_component).sum();
    let open_world_h1: f64 = obstructions.iter().map(|o| o.open_world_component).sum();

    let h0 = obstructions
        .iter()
        .filter(|o| o.interval_inconsistency <= threshold)
        .count();

    let h1_normalized = if edge_count > 0 {
        h1 / edge_count as f64
    } else {
        0.0
    };

    let mut belief_conflict_count = 0usize;
    let mut open_world_spread_count = 0usize;
    let mut frame_closure_count = 0usize;
    let mut ignorance_drift_count = 0usize;

    for o in &obstructions {
        match o.obstruction_kind {
            ObstructionKind::BeliefConflict => belief_conflict_count += 1,
            ObstructionKind::OpenWorldSpread => open_world_spread_count += 1,
            ObstructionKind::FrameClosureOpportunity => frame_closure_count += 1,
            ObstructionKind::IgnoranceDrift => ignorance_drift_count += 1,
        }
    }

    // Keep only obstructions above threshold, sorted DESC
    let mut above_threshold: Vec<CdstSheafObstruction> = obstructions
        .into_iter()
        .filter(|o| o.interval_inconsistency > threshold)
        .collect();

    above_threshold.sort_by(|a, b| {
        b.interval_inconsistency
            .partial_cmp(&a.interval_inconsistency)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    CdstSheafCohomology {
        h0,
        h1,
        h1_normalized,
        edge_count,
        conflict_h1,
        ignorance_h1,
        open_world_h1,
        obstructions: above_threshold,
        belief_conflict_count,
        open_world_spread_count,
        frame_closure_count,
        ignorance_drift_count,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: scientific profile
    fn sci() -> RestrictionProfile {
        RestrictionProfile::scientific()
    }

    // ── classify_obstruction tests ────────────────────────────────────────

    #[test]
    fn test_classify_belief_conflict() {
        // conflict_component > ignorance and open_world → BeliefConflict
        let src = EpistemicInterval::new(0.7, 0.9, 0.1);
        let tgt = EpistemicInterval::new(0.1, 0.3, 0.1);
        let kind = classify_obstruction(&src, &tgt, 0.6, 0.1, 0.05, 0.2);
        assert_eq!(kind, ObstructionKind::BeliefConflict);
    }

    #[test]
    fn test_classify_open_world_spread() {
        // open_world_component dominates; target is NOT narrow → OpenWorldSpread
        let src = EpistemicInterval::new(0.3, 0.7, 0.3);
        let tgt = EpistemicInterval::new(0.2, 0.8, 0.1); // wide target
                                                         // source.open_world (0.3) > target.open_world (0.1) — spread outward
                                                         // but target is NOT narrow (width=0.6 > 0.2)
        let kind = classify_obstruction(&src, &tgt, 0.05, 0.1, 0.4, 0.2);
        assert_eq!(kind, ObstructionKind::OpenWorldSpread);
    }

    #[test]
    fn test_classify_frame_closure() {
        // open_world_component dominates AND source has high OW AND target is narrow
        let src = EpistemicInterval::new(0.5, 0.8, 0.25); // high OW
        let tgt = EpistemicInterval::new(0.78, 0.82, 0.01); // narrow, certain
                                                            // source.open_world (0.25) > target.open_world (0.01) and target.is_narrow(0.2)
        let kind = classify_obstruction(&src, &tgt, 0.05, 0.1, 0.4, 0.2);
        assert_eq!(kind, ObstructionKind::FrameClosureOpportunity);
    }

    #[test]
    fn test_classify_ignorance_drift() {
        // ignorance_component is the largest
        let src = EpistemicInterval::new(0.5, 0.7, 0.1);
        let tgt = EpistemicInterval::new(0.52, 0.68, 0.1);
        let kind = classify_obstruction(&src, &tgt, 0.02, 0.3, 0.05, 0.2);
        assert_eq!(kind, ObstructionKind::IgnoranceDrift);
    }

    // ── compute_cdst_section tests ────────────────────────────────────────

    #[test]
    fn test_cdst_section_propagates_open_world() {
        // A neighbor with high open_world via Positive restriction should appear
        // in the expected interval's open_world.
        let node_id = Uuid::new_v4();
        let local = EpistemicInterval::new(0.5, 0.8, 0.1);
        let neighbor_interval = EpistemicInterval::new(0.6, 0.9, 0.25);
        let neighbors = vec![(neighbor_interval, RestrictionKind::Positive(0.8))];
        let section = compute_cdst_section(node_id, local, &neighbors);

        // restrict_epistemic_positive passes open_world through unchanged
        assert!(
            (section.expected_interval.open_world - 0.25).abs() < 1e-9,
            "expected_interval.open_world should equal neighbor's ow (0.25), got {}",
            section.expected_interval.open_world
        );
        assert!(section.open_world_expected > 0.0);
    }

    // ── compute_cdst_cohomology tests ────────────────────────────────────

    #[test]
    fn test_cdst_cohomology_decomposes_h1() {
        // conflict_h1 + ignorance_h1 + open_world_h1 should approximately equal h1
        // (they are independent components, not always additive, but for this
        // construction they should be close when one component dominates).
        let src = Uuid::new_v4();
        let tgt = Uuid::new_v4();

        let obstructions = vec![CdstSheafObstruction {
            source_id: src,
            target_id: tgt,
            relationship: "supports".to_string(),
            source_interval: EpistemicInterval::new(0.8, 0.95, 0.1),
            target_interval: EpistemicInterval::new(0.2, 0.4, 0.1),
            expected_interval: EpistemicInterval::new(0.64, 0.84, 0.1),
            interval_inconsistency: 0.44,
            conflict_component: 0.44,
            ignorance_component: 0.0,
            open_world_component: 0.0,
            obstruction_kind: ObstructionKind::BeliefConflict,
        }];

        let coh = compute_cdst_cohomology(obstructions, 0.05);

        assert!((coh.h1 - 0.44).abs() < 1e-9);
        assert!((coh.conflict_h1 - 0.44).abs() < 1e-9);
        assert!(coh.ignorance_h1 < 1e-9);
        assert!(coh.open_world_h1 < 1e-9);
        assert_eq!(coh.belief_conflict_count, 1);
    }

    // ── compute_cdst_edge_inconsistency tests ────────────────────────────

    #[test]
    fn test_cdst_edge_inconsistency_support() {
        // Consistent support: source strong, target follows
        // source: [0.7, 0.9, 0.1], relationship: "supports", factor 0.8
        // expected: bel = 0.7*0.8 = 0.56, pl = 1-(1-0.9)*0.8 = 0.92, ow=0.1
        // target: [0.6, 0.9, 0.1] — close to expected
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let source = EpistemicInterval::new(0.7, 0.9, 0.1);
        let target = EpistemicInterval::new(0.6, 0.9, 0.1);

        let obs =
            compute_cdst_edge_inconsistency(src_id, tgt_id, source, target, "supports", &sci());

        // hausdorff between [0.6, 0.9] and expected [0.56, 0.92]:
        // max(|0.6-0.56|, |0.9-0.92|) = max(0.04, 0.02) = 0.04
        assert!(
            obs.interval_inconsistency < 0.1,
            "Expected small inconsistency for close intervals, got {}",
            obs.interval_inconsistency
        );
    }

    #[test]
    fn test_cdst_edge_inconsistency_stale() {
        // Stale support: source is strong but target is very low
        // source: [0.8, 0.95, 0.1], target: [0.1, 0.2, 0.1]
        // expected bel = 0.8*0.8=0.64, pl = 1-(1-0.95)*0.8=0.96, ow=0.1
        // hausdorff = max(|0.1-0.64|, |0.2-0.96|) = max(0.54, 0.76) = 0.76
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let source = EpistemicInterval::new(0.8, 0.95, 0.1);
        let target = EpistemicInterval::new(0.1, 0.2, 0.1);

        let obs =
            compute_cdst_edge_inconsistency(src_id, tgt_id, source, target, "supports", &sci());

        assert!(
            obs.interval_inconsistency > 0.5,
            "Expected high inconsistency for stale support, got {}",
            obs.interval_inconsistency
        );
        assert!(
            matches!(obs.obstruction_kind, ObstructionKind::BeliefConflict),
            "Stale support should classify as BeliefConflict, got {:?}",
            obs.obstruction_kind
        );
    }

    // ── directional supports-edge conflict (backlog 69b43e94) ─────────────

    #[test]
    fn test_supports_over_support_is_benign() {
        // A WEAK supporter (bel≈0.50) on a `supports` edge into a STRONG,
        // independently corroborated hub (bel≈0.98). The discounted floor
        // (expected.bel = 0.50 * 0.80 = 0.40) sits FAR below the hub. This is
        // corroboration, not conflict: the hub merely exceeds the floor.
        //
        // BEFORE the directional fix BOTH twin fields used the symmetric
        // Hausdorff distance:
        //   max(|0.98 - 0.40|, |1.0 - 0.68|) = max(0.58, 0.32) = 0.58,
        // which spuriously inflated conflict-K on every belief hub each nightly
        // scan AND — because `interval_inconsistency` is what
        // `compute_cdst_cohomology` filters/sums into H¹ and the MCP tool
        // surfaces as `edge_inconsistency` — kept the over-support obstruction
        // permanently listed so H¹ never dropped and the conflict-resolution
        // scan re-observed it forever. AFTER the fix the Positive arm is
        // directional on BOTH fields and only the (here zero) UNDER-support
        // shortfall counts:
        //   below = (0.40-0.98).max(0).max((0.68-1.0).max(0)) = 0.0.
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let weak_source = EpistemicInterval::new(0.50, 0.60, 0.0);
        let strong_hub = EpistemicInterval::new(0.98, 1.0, 0.0);

        let obs = compute_cdst_edge_inconsistency(
            src_id,
            tgt_id,
            weak_source,
            strong_hub,
            "supports",
            &sci(),
        );

        // Sanity: the symmetric distance we are REPLACING would have been 0.58.
        let symmetric_before = (strong_hub.bel - obs.expected_interval.bel)
            .abs()
            .max((strong_hub.pl - obs.expected_interval.pl).abs());
        assert!(
            (symmetric_before - 0.58).abs() < 1e-9,
            "regression baseline: symmetric conflict should be 0.58, got {symmetric_before}"
        );

        // AFTER: over-support contributes ~no conflict mass …
        assert!(
            obs.conflict_component < 0.05,
            "over-support must be benign corroboration; conflict_component={} (was {symmetric_before} symmetric)",
            obs.conflict_component
        );
        // … AND no inconsistency mass: this is the load-bearing assertion. The
        // scan and H¹ key on `interval_inconsistency`, so it MUST also drop to 0
        // (was 0.58) for the edge to leave the sheaf-cohomology obstruction set.
        assert!(
            obs.interval_inconsistency < 0.05,
            "over-support must also be sheaf-consistent; interval_inconsistency={} (was {symmetric_before} symmetric)",
            obs.interval_inconsistency
        );
        // Twin fields stay equal for supports edges, as origin/main has them.
        assert!(
            (obs.interval_inconsistency - obs.conflict_component).abs() < 1e-12,
            "supports twin fields must be equal: interval={} conflict={}",
            obs.interval_inconsistency,
            obs.conflict_component
        );
    }

    #[test]
    fn test_supports_over_support_drops_from_cohomology() {
        // The load-bearing, cohomology-LEVEL proof that the re-observe loop
        // closes. A weak supporter [0.50,0.60] supports a strong hub [0.98,1.0]
        // over a `supports` edge. Build the one-edge sheaf, run
        // `compute_cdst_cohomology`, and assert the over-support edge is treated
        // as CONSISTENT: it lands in h0, is ABSENT from the returned obstruction
        // list, and contributes 0 to H¹. (It still classifies as IgnoranceDrift
        // from the width mismatch — but with interval_inconsistency = 0 that
        // never reaches the obstruction set, which is exactly the point.)
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let weak_source = EpistemicInterval::new(0.50, 0.60, 0.0);
        let strong_hub = EpistemicInterval::new(0.98, 1.0, 0.0);

        let obs = compute_cdst_edge_inconsistency(
            src_id,
            tgt_id,
            weak_source,
            strong_hub,
            "supports",
            &sci(),
        );

        let coh = compute_cdst_cohomology(vec![obs], 0.05);

        assert_eq!(coh.edge_count, 1, "one edge in the sheaf");
        assert_eq!(
            coh.h0, 1,
            "over-support edge must be consistent (h0), got h0={}",
            coh.h0
        );
        assert!(
            coh.obstructions.is_empty(),
            "over-support edge must be ABSENT from the obstruction list, got {} obstructions",
            coh.obstructions.len()
        );
        assert!(
            coh.h1 < 1e-9,
            "over-support must contribute 0 to H¹, got h1={}",
            coh.h1
        );
        assert!(
            coh.conflict_h1 < 1e-9,
            "over-support must contribute 0 to conflict_h1, got {}",
            coh.conflict_h1
        );
        assert_eq!(
            coh.belief_conflict_count, 0,
            "over-support must NOT be a belief conflict, got count={}",
            coh.belief_conflict_count
        );
    }

    #[test]
    fn test_supports_under_support_still_flags() {
        // A STRONG supporter into a WEAK target: the target sits well below the
        // corroborated floor (expected.bel = 0.90 * 0.80 = 0.72, target = 0.10).
        // This is a real conflict and must still produce non-trivial conflict.
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let strong_source = EpistemicInterval::new(0.90, 1.0, 0.0);
        let weak_target = EpistemicInterval::new(0.10, 0.30, 0.0);

        let obs = compute_cdst_edge_inconsistency(
            src_id,
            tgt_id,
            strong_source,
            weak_target,
            "supports",
            &sci(),
        );

        // The floor shortfall is the MAX over both endpoints:
        //   expected.bel = 0.90*0.80 = 0.72, target.bel = 0.10 → bel shortfall 0.62
        //   expected.pl  = 1-(1-1.0)*0.80 = 1.0, target.pl = 0.30 → pl shortfall 0.70
        //   below = max(0.62, 0.70) = 0.70.
        // (The pl shortfall dominates; the prior bel-only formula pinned 0.62.
        // Still a real conflict, still classifies BeliefConflict — the metric is
        // merely corrected to the larger, true endpoint shortfall.)
        assert!(
            obs.conflict_component > 0.0,
            "under-support must still flag a conflict, got {}",
            obs.conflict_component
        );
        assert!(
            (obs.conflict_component - 0.70).abs() < 1e-9,
            "under-support shortfall should be max(0.72-0.10, 1.0-0.30)=0.70, got {}",
            obs.conflict_component
        );
        // Twin field equality for supports edges.
        assert!(
            (obs.interval_inconsistency - obs.conflict_component).abs() < 1e-12,
            "supports twin fields must be equal: interval={} conflict={}",
            obs.interval_inconsistency,
            obs.conflict_component
        );
    }

    #[test]
    fn test_contradicts_conflict_unchanged() {
        // The Negative (contradicts) arm must keep the symmetric Bel/Pl distance
        // unchanged by this fix. Pin the exact pre-fix value.
        //
        // contradicts → Negative(0.90); restrict_epistemic_negative on
        // source [0.80, 0.95] gives expected bel = (1-0.95)*0.90 = 0.045,
        // pl = 1 - 0.80*0.90 = 0.28. Against target [0.70, 0.90]:
        //   conflict = max(|0.70-0.045|, |0.90-0.28|) = max(0.655, 0.62) = 0.655.
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let source = EpistemicInterval::new(0.80, 0.95, 0.0);
        let target = EpistemicInterval::new(0.70, 0.90, 0.0);

        let obs =
            compute_cdst_edge_inconsistency(src_id, tgt_id, source, target, "contradicts", &sci());

        assert!(
            (obs.conflict_component - 0.655).abs() < 1e-9,
            "contradicts conflict must stay symmetric at 0.655, got {}",
            obs.conflict_component
        );
    }
}
