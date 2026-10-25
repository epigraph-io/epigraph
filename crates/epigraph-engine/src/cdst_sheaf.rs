//! CDST Sheaf: interval-aware sheaf cohomology with decomposed open-world ignorance.
//!
//! Extends the scalar sheaf (`sheaf.rs`) with full `EpistemicInterval` sections,
//! Hausdorff-distance inconsistency, and a 3-component H¹ decomposition:
//! - **conflict_h1**: Bel/Pl disagreement (classical belief conflict)
//! - **ignorance_h1**: closed-world ignorance width mismatch
//! - **open_world_h1**: open-world mass spread (frame incompleteness)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::epistemic_interval::{
    restrict_epistemic_frame_evidence, restrict_epistemic_negative, restrict_epistemic_positive,
    EpistemicInterval,
};
use crate::sheaf::{
    restriction_kind_from_properties, restriction_kind_with_profile, RestrictionKind,
    RestrictionProfile,
};

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
    /// BetP of `expected_interval` (all-neighbour average; display only).
    pub expected_betp: f64,
    /// Node inconsistency: the max of the Positive-group Bel-floor shortfall,
    /// the Negative-group BetP-ceiling excess and the FrameEvidence-group
    /// `|local_betp − expected_betp|`. Equals `|local_betp − expected_betp|`
    /// only for a FrameEvidence-only node. See [`compute_cdst_section`].
    pub consistency_radius: f64,

    // Interval fields
    pub local_interval: EpistemicInterval,
    /// All-neighbour average of the restricted neighbour intervals.
    pub expected_interval: EpistemicInterval,

    /// The max of the Positive-group Bel-floor shortfall, the Negative-group
    /// Bel-ceiling excess and the Hausdorff distance to the FrameEvidence
    /// group's expected interval.
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
///
/// The neighbours are scored in three groups:
/// - **Positive** (`supports`-like) neighbours are a one-sided Bel FLOOR, the
///   node twin of the Positive arm of
///   [`compute_cdst_edge_inconsistency_with_properties`]: each supporter
///   commits the node to at least `restrict_epistemic_positive(n, f).bel`, so
///   the binding floor is the MAX over supporters and only the node's bel
///   sitting below it counts. Over-support (a hub corroborated above a weak
///   supporter's discounted floor) is benign and scores 0. With this, a
///   Positive-only node's radius equals its worst incoming supports-edge
///   shortfall.
/// - **Negative** (`contradicts` / `refutes`) neighbours are a one-sided
///   CEILING (mutual exclusion, U075), scored on each field's own side:
///   - `interval_inconsistency` uses the Bel ceiling, the node twin of the
///     Negative arm of [`compute_cdst_edge_inconsistency_with_properties`]:
///     each contradicter caps the node at
///     `restrict_epistemic_negative(n, f).pl = 1 − n.bel·f`, the binding
///     ceiling is the MIN over contradicters, and only the node's bel above
///     it counts. A Negative-only node's `interval_inconsistency` equals its
///     worst contradicts-edge excess.
///   - `consistency_radius` uses the BetP ceiling `min(1 − n.betp·f)` and
///     scores `(local_betp − ceiling)+`, the same term as the scalar twin
///     `sheaf::compute_section` (the 2026-10-14 U075 ruling: the radius gets
///     "its own one-sided term on the BetP side"). A wide node whose bel is
///     under the Bel ceiling can still have its BetP above the BetP ceiling.
///     (The Positive radius is a Bel floor, #578/#581; the asymmetry is the
///     ruling's.)
///
///   A disbelieved contradicter (low `n.bel`, low `n.betp`) imposes almost no
///   ceiling on either side, so a believed node is not flagged by it, and two
///   disbelieved claims are consistent.
/// - **FrameEvidence** neighbours keep the symmetric metric over their own
///   average: Hausdorff distance for `interval_inconsistency` and
///   `|local_betp − expected_betp|` for `consistency_radius`. A node with only
///   such neighbours is scored exactly as before.
///
/// `consistency_radius` and `interval_inconsistency` are each the max of the
/// three groups' terms (0 for an empty group); the Positive term is Bel-based
/// and enters both fields, the Negative term is Bel-based for
/// `interval_inconsistency` and BetP-based for `consistency_radius`. `expected_interval` / `expected_betp`
/// stay the all-neighbour average for display, so the radius is
/// `|local_betp − expected_betp|` only for a FrameEvidence-only node.
pub fn compute_cdst_section(
    node_id: Uuid,
    local_interval: EpistemicInterval,
    neighbors: &[(EpistemicInterval, RestrictionKind)],
) -> CdstSheafSection {
    let expected = compute_cdst_expected(neighbors);
    let expected_interval = expected.unwrap_or(local_interval);

    let local_betp = local_interval.betp();
    let expected_betp = expected_interval.betp();

    // Positive group: max Bel floor over supporters, one-sided shortfall.
    let positive_shortfall = neighbors
        .iter()
        .filter_map(|(interval, kind)| match kind {
            RestrictionKind::Positive(factor) => {
                Some(restrict_epistemic_positive(interval, *factor).bel)
            }
            _ => None,
        })
        .reduce(f64::max)
        .map_or(0.0, |floor| (floor - local_interval.bel).max(0.0));

    // Negative group: min ceiling over contradicters, one-sided excess. The
    // Bel ceiling scores interval_inconsistency; the BetP ceiling (the scalar
    // twin's term) scores consistency_radius.
    let negative_ceilings = neighbors
        .iter()
        .filter_map(|(interval, kind)| match kind {
            RestrictionKind::Negative(factor) => Some((
                restrict_epistemic_negative(interval, *factor).pl,
                interval.betp().mul_add(-factor, 1.0),
            )),
            _ => None,
        })
        .reduce(|(a_bel, a_betp), (b_bel, b_betp)| (a_bel.min(b_bel), a_betp.min(b_betp)));
    let (negative_bel_excess, negative_betp_excess) =
        negative_ceilings.map_or((0.0, 0.0), |(bel_ceiling, betp_ceiling)| {
            (
                (local_interval.bel - bel_ceiling).max(0.0),
                (local_betp - betp_ceiling).max(0.0),
            )
        });

    // FrameEvidence group: the symmetric metric over the group's own average.
    // Order-preserving filter, so a node whose only neighbours are
    // FrameEvidence (and Neutral) gets bit-for-bit the pre-split values.
    let frame_evidence: Vec<(EpistemicInterval, RestrictionKind)> = neighbors
        .iter()
        .filter(|(_, k)| matches!(k, RestrictionKind::FrameEvidence(_)))
        .copied()
        .collect();
    let (fe_hausdorff, fe_radius) =
        compute_cdst_expected(&frame_evidence).map_or((0.0, 0.0), |e| {
            (
                local_interval.hausdorff_distance(&e),
                (local_betp - e.betp()).abs(),
            )
        });

    let interval_inconsistency = positive_shortfall
        .max(negative_bel_excess)
        .max(fe_hausdorff);
    let consistency_radius = positive_shortfall.max(negative_betp_excess).max(fe_radius);

    let neighbor_count = neighbors
        .iter()
        .filter(|(_, k)| !matches!(k, RestrictionKind::Neutral))
        .count();

    CdstSheafSection {
        node_id,
        local_betp,
        expected_betp,
        consistency_radius,
        local_interval,
        expected_interval,
        interval_inconsistency,
        open_world_local: local_interval.open_world,
        open_world_expected: expected_interval.open_world,
        ignorance_inconsistency: (local_interval.width() - expected_interval.width()).abs(),
        neighbor_count,
    }
}

/// One `(claim, neighbour)` row of a node's epistemic neighbourhood, as a
/// DB consumer reads it (one row per incident edge, from each endpoint's
/// side).
#[derive(Debug, Clone)]
pub struct NeighborRow {
    /// The claim whose section this row contributes to.
    pub claim_id: Uuid,
    /// The claim's own interval (first-seen row per claim wins).
    pub local: EpistemicInterval,
    /// The interval at the other end of the edge.
    pub neighbor: EpistemicInterval,
    /// The edge relationship (case-insensitive).
    pub relationship: String,
    /// `true` when `claim_id` is the edge's SOURCE (the edge points away from
    /// it), `false` when it is the target.
    pub outgoing: bool,
}

/// Directional positive relationships: `src -[rel]-> dst` constrains `dst`
/// (a floor from its supporter) but says nothing about `src`, so the row read
/// from the source's side (`outgoing`) is skipped by [`build_cdst_sections`].
///
/// `corroborates` is NOT here: it is symmetric (idempotent on the unordered
/// pair), so both sides keep it. Negative kinds and `frame_validates` keep
/// both sides too: mutual exclusion is symmetric, so each end of a
/// `contradicts` edge is capped by the other (U075; U080). `informs` and
/// `supersedes` are left out because the neighbourhood query
/// (`SheafRepository::get_claim_neighbor_betp_pairs`) never returns them;
/// adding them is a separate change.
pub const DIRECTIONAL_POSITIVE_RELATIONSHIPS: &[&str] =
    &["supports", "elaborates", "specializes", "generalizes"];

fn is_directional_positive(relationship: &str) -> bool {
    DIRECTIONAL_POSITIVE_RELATIONSHIPS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(relationship))
}

/// Group neighbourhood rows by claim and build one CDST section per claim, in
/// first-seen claim order. Restriction kinds come from `profile`.
///
/// Direction rule: an `outgoing` row of a [`DIRECTIONAL_POSITIVE_RELATIONSHIPS`]
/// edge is skipped (a supporter is not constrained by its target), but the
/// claim still gets a section, with `neighbor_count` 0 if nothing else
/// reaches it.
pub fn build_cdst_sections(
    rows: &[NeighborRow],
    profile: &RestrictionProfile,
) -> Vec<CdstSheafSection> {
    let mut order: Vec<Uuid> = Vec::new();
    let mut groups: HashMap<Uuid, (EpistemicInterval, Vec<(EpistemicInterval, RestrictionKind)>)> =
        HashMap::new();
    for row in rows {
        let entry = groups.entry(row.claim_id).or_insert_with(|| {
            order.push(row.claim_id);
            (row.local, Vec::new())
        });
        if row.outgoing && is_directional_positive(&row.relationship) {
            continue;
        }
        entry.1.push((
            row.neighbor,
            restriction_kind_with_profile(&row.relationship, profile),
        ));
    }
    order
        .into_iter()
        .filter_map(|id| {
            groups
                .remove(&id)
                .map(|(local, neighbors)| compute_cdst_section(id, local, &neighbors))
        })
        .collect()
}

/// Compute the interval inconsistency for a single directed edge and classify it.
///
/// The expected interval is computed by applying the restriction map for
/// `relationship` to `source_interval`.  The obstruction components are:
/// - `interval_inconsistency` / `conflict_component`: for frame-evidence /
///   neutral, the symmetric Bel/Pl distance (Hausdorff); for `contradicts` /
///   `refutes` (Negative, mutual exclusion), the directional ceiling *excess*
///   `max(0, target.bel − expected.pl)` with `expected.pl = 1 − source.bel·f`
///   (two disbelieved claims are consistent); for `supports` (Positive), the
///   directional floor *shortfall*
///   `max(0, expected.bel − target.bel)` — only the target's bel sitting below
///   the corroborated `expected` bel floor counts (plausibility is neither a
///   floor nor a ceiling), so over-support is benign corroboration and
///   contributes 0 to both fields and to H¹.
/// - `open_world_component`: |source_ow − expected_ow|
/// - `ignorance_component`: |width_target − width_expected|; for `contradicts`
///   / `refutes` (a ceiling, not an estimate) the target's plausibility above
///   the ceiling, `max(0, target.pl − expected.pl)`, and 0 once its bel
///   breaches the ceiling (that breach is a belief conflict)
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

    // For a `supports` edge the expected interval is a one-sided FLOOR on
    // BELIEF only — a supporter commits the target to AT LEAST
    // `expected.bel = source.bel * factor` (`restrict_epistemic_positive`).
    // Only UNDER-support — the target's bel sitting *below* that corroborated
    // floor — is a genuine conflict; a strongly corroborated hub that *exceeds*
    // a discounted weak supporter is benign corroboration, not contradiction.
    //
    // Plausibility is deliberately NOT a floor. `expected.pl = 1-(1-source.pl)
    // *factor` RISES toward 1 as the edge weakens, so a pl floor would demand
    // MORE of the target the weaker the support, impose the maximal constraint
    // pl_t >= 1 for a vacuous (factor -> 0) message, and flag every pl < 1
    // target of a pl_s = 1.0 supporter (backlog b3476233; the pl half of
    // 6c5dcca5). Nor is it a ceiling: "target more plausible than its doubted
    // supporter" is exactly the over-support case above (denying the
    // antecedent), see `test_supports_over_support_is_benign`.
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
    // A `contradicts` / `refutes` edge is the dual: mutual exclusion ("not
    // both true", `restrict_epistemic_negative`) gives the target a one-sided
    // CEILING `expected.pl = 1 − source.bel·f` and no floor (`expected.bel` is
    // always 0). Only the target's bel sitting ABOVE the ceiling is a genuine
    // conflict; two disbelieved claims linked by contradicts are consistent.
    // A symmetric distance against `[0, ceiling]` would instead flag every
    // believed target of every weak contradictor. Both twin fields are the
    // excess, as for the Positive floor.
    //
    // frame-evidence / neutral are neither floors nor ceilings, so they keep
    // the symmetric Bel/Pl distance: `interval_inconsistency` stays the
    // Hausdorff distance and `conflict_component` its (equal) symmetric form.
    let (interval_inconsistency, conflict_component) = match kind {
        RestrictionKind::Positive(_) => {
            // Bel-floor shortfall: only belief BELOW the corroborated floor is
            // inconsistency; over-support contributes 0.
            let below = (expected_interval.bel - target_interval.bel).max(0.0);
            (below, below)
        }
        RestrictionKind::Negative(_) => {
            // Bel-over-ceiling excess: only belief ABOVE the contradictor-
            // permitted ceiling is inconsistency.
            let over = (target_interval.bel - expected_interval.pl).max(0.0);
            (over, over)
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

    // Ignorance component: width mismatch (closed-world ignorance) — except
    // for the Negative ceiling. Mutual exclusion's expected interval
    // `[0, 1 − source.bel·f]` is a constraint, not an estimate whose width is
    // anyone's ignorance: a width mismatch against it would charge ~0.85 to
    // every believed target of a weak contradicter and outrank genuine
    // ceiling breaches (relabelling them IgnoranceDrift). For a contradicts
    // edge the ignorance is the part of the target's plausibility that
    // reaches above the ceiling while its bel stays under it (the pair's
    // consistency then turns on resolving the target's ignorance); once the
    // bel breaches the ceiling the breach is a belief conflict, not ignorance.
    let ignorance_component = match kind {
        RestrictionKind::Negative(_) => {
            if target_interval.bel > expected_interval.pl {
                0.0
            } else {
                (target_interval.pl - expected_interval.pl).max(0.0)
            }
        }
        _ => (target_interval.width() - expected_interval.width()).abs(),
    };

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
        // in the expected interval's open_world — discounted by the edge's
        // transmission factor, like every other mass component.
        let node_id = Uuid::new_v4();
        let local = EpistemicInterval::new(0.5, 0.8, 0.1);
        let neighbor_interval = EpistemicInterval::new(0.6, 0.9, 0.25);
        let neighbors = vec![(neighbor_interval, RestrictionKind::Positive(0.8))];
        let section = compute_cdst_section(node_id, local, &neighbors);

        // restrict_epistemic_positive Shafer-discounts open_world by the
        // factor: 0.25 * 0.8 = 0.20.
        assert!(
            (section.expected_interval.open_world - 0.20).abs() < 1e-9,
            "expected_interval.open_world should be neighbor ow * factor (0.20), got {}",
            section.expected_interval.open_world
        );
        assert!(section.open_world_expected > 0.0);
    }

    #[test]
    fn test_cdst_section_over_supported_hub_has_zero_radius() {
        // I043: a hub at [0.98, 1.0] with one supporter at BetP 0.5 is
        // corroborated ABOVE its supporter's discounted floor. A supports edge
        // is a one-sided Bel floor (bel_n * f = 0.40), so over-support is
        // benign, exactly as the edge path's Positive arm scores it.
        // The old symmetric metric gave radius |0.99 - 0.50| = 0.49 and
        // Hausdorff max(|0.98 - 0.40|, |1.0 - 0.60|) = 0.58.
        let hub = EpistemicInterval::new(0.98, 1.0, 0.0);
        let supporter = EpistemicInterval::new(0.5, 0.5, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            hub,
            &[(supporter, RestrictionKind::Positive(0.8))],
        );
        assert!(
            s.consistency_radius < 1e-9,
            "over-supported hub must have radius 0, got {}",
            s.consistency_radius
        );
        assert!(
            s.interval_inconsistency < 1e-9,
            "over-supported hub must have interval_inconsistency 0, got {}",
            s.interval_inconsistency
        );
        assert_eq!(s.neighbor_count, 1);
    }

    #[test]
    fn test_cdst_section_under_supported_node_still_flags() {
        // Local [0.10, 0.90] under a supporter at [0.90, 0.90], f = 0.8:
        // Bel floor = 0.72, local bel 0.10 -> shortfall 0.62.
        // (A BetP floor would give 0.72 - 0.50 = 0.22; the old symmetric
        // metric gave |0.50 - 0.82| = 0.32. 0.62 pins the Bel floor that
        // U029 settled on for the edge.)
        let local = EpistemicInterval::new(0.10, 0.90, 0.0);
        let supporter = EpistemicInterval::new(0.90, 0.90, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[(supporter, RestrictionKind::Positive(0.8))],
        );
        assert!(
            (s.consistency_radius - 0.62).abs() < 1e-9,
            "under-support shortfall should be 0.62, got {}",
            s.consistency_radius
        );
        assert!(
            (s.interval_inconsistency - 0.62).abs() < 1e-9,
            "interval_inconsistency should equal the Bel shortfall 0.62, got {}",
            s.interval_inconsistency
        );
    }

    #[test]
    fn test_cdst_section_floor_is_max_over_supporters() {
        // Local [0.50, 0.60]; supporters [0.9, 0.9] (floor 0.72) and
        // [0.1, 0.1] (floor 0.08), both f = 0.8. Each supporter independently
        // commits the node to at least its floor, so the binding floor is the
        // MAX (0.72): radius 0.22. A mean floor (0.40) would hide it (0), and
        // the old symmetric metric gave |0.55 - 0.50| = 0.05.
        let local = EpistemicInterval::new(0.50, 0.60, 0.0);
        let strong = EpistemicInterval::new(0.9, 0.9, 0.0);
        let weak = EpistemicInterval::new(0.1, 0.1, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[
                (strong, RestrictionKind::Positive(0.8)),
                (weak, RestrictionKind::Positive(0.8)),
            ],
        );
        assert!(
            (s.consistency_radius - 0.22).abs() < 1e-9,
            "binding floor is the max over supporters: expected 0.22, got {}",
            s.consistency_radius
        );
        assert_eq!(s.neighbor_count, 2);
    }

    #[test]
    fn test_cdst_section_positive_radius_equals_worst_supports_edge() {
        // Node and edge must agree: for a Positive-only node the node radius is
        // its worst incoming supports-edge shortfall, as scored by the
        // independent edge path (compute_cdst_edge_inconsistency).
        let node = EpistemicInterval::new(0.30, 0.70, 0.0);
        let supporters = [
            EpistemicInterval::new(0.60, 0.80, 0.0),
            EpistemicInterval::new(0.85, 0.95, 0.0),
            EpistemicInterval::new(0.20, 0.40, 0.0),
        ];
        let node_id = Uuid::new_v4();
        let neighbors: Vec<_> = supporters
            .iter()
            .map(|s| (*s, RestrictionKind::Positive(sci().supports)))
            .collect();
        let section = compute_cdst_section(node_id, node, &neighbors);
        let worst_edge = supporters
            .iter()
            .map(|s| {
                compute_cdst_edge_inconsistency(
                    Uuid::new_v4(),
                    node_id,
                    *s,
                    node,
                    "supports",
                    &sci(),
                )
                .interval_inconsistency
            })
            .fold(0.0f64, f64::max);
        // 0.85 * 0.8 - 0.30 = 0.38
        assert!(
            (worst_edge - 0.38).abs() < 1e-9,
            "edge path gave {worst_edge}"
        );
        assert!(
            (section.consistency_radius - worst_edge).abs() < 1e-12,
            "node radius {} must equal the worst supports-edge shortfall {}",
            section.consistency_radius,
            worst_edge
        );
        assert!((section.interval_inconsistency - worst_edge).abs() < 1e-12);
    }

    #[test]
    fn test_cdst_section_negative_only_scores_over_ceiling() {
        // U080 / I143 node, re-pinned by U075: a Negative-only node is scored
        // on the mutual-exclusion CEILING, not a symmetric distance. Two
        // believed claims that contradict each other still flag.
        // Local [0.80, 0.95], contradicter [0.80, 0.95], f = 0.9:
        // - interval_inconsistency, Bel side: ceiling 1 - 0.80*0.9 = 0.28,
        //   excess 0.80 - 0.28 = 0.52;
        // - consistency_radius, BetP side: ceiling 1 - 0.875*0.9 = 0.2125,
        //   excess 0.875 - 0.2125 = 0.6625.
        // (The complement law's symmetric metric gave radius 0.7125 and
        // Hausdorff 0.755.)
        let local = EpistemicInterval::new(0.80, 0.95, 0.0);
        let neighbors = vec![(
            EpistemicInterval::new(0.80, 0.95, 0.0),
            RestrictionKind::Negative(0.9),
        )];
        let s = compute_cdst_section(Uuid::new_v4(), local, &neighbors);
        assert!(
            (s.consistency_radius - 0.6625).abs() < 1e-9,
            "got {}",
            s.consistency_radius
        );
        assert!(
            (s.interval_inconsistency - 0.52).abs() < 1e-9,
            "got {}",
            s.interval_inconsistency
        );
    }

    #[test]
    fn test_cdst_section_mixed_disbelieved_contradicter_leaves_floor_shortfall() {
        // Local [0.50, 0.60]; supporter [0.9, 0.9] Positive(0.8) -> shortfall
        // 0.22; contradicter [0.1, 0.1] Negative(0.9) -> ceiling
        // 1 - 0.1*0.9 = 0.91, and 0.50 is under it -> 0. So both fields are
        // max(0.22, 0) = 0.22. (Under the complement law the disbelieved
        // contradicter restricted to [0.81, 0.91] and its symmetric distance
        // 0.31 dominated.)
        let local = EpistemicInterval::new(0.50, 0.60, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[
                (
                    EpistemicInterval::new(0.9, 0.9, 0.0),
                    RestrictionKind::Positive(0.8),
                ),
                (
                    EpistemicInterval::new(0.1, 0.1, 0.0),
                    RestrictionKind::Negative(0.9),
                ),
            ],
        );
        assert!(
            (s.consistency_radius - 0.22).abs() < 1e-9,
            "mixed node radius should be max(0.22, 0) = 0.22, got {}",
            s.consistency_radius
        );
        assert!((s.interval_inconsistency - 0.22).abs() < 1e-9);
        // expected_betp stays the all-neighbour average for display:
        // restricted [0.72, 0.92] and [0, 0.91] -> [0.36, 0.915], BetP 0.6375.
        assert!(
            (s.expected_betp - 0.6375).abs() < 1e-9,
            "got {}",
            s.expected_betp
        );
    }

    #[test]
    fn test_cdst_section_mixed_floor_shortfall_dominates_negative_distance() {
        // The other direction of the mixed-node max: an under-supported node
        // must not hide its floor shortfall behind a small Negative distance.
        // Local [0.10, 0.20], BetP 0.15.
        // Supporter [0.9, 0.9] Positive(0.8): floor 0.72 -> shortfall 0.62.
        // Contradicter [0.9, 0.9] Negative(0.9): ceiling 1 - 0.9*0.9 = 0.19,
        // and 0.10 is under it -> 0.
        // max(0.62, 0) = 0.62. (The old all-neighbour average
        // [0.405, 0.555], BetP 0.48, gave |0.15 - 0.48| = 0.33.)
        let local = EpistemicInterval::new(0.10, 0.20, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[
                (
                    EpistemicInterval::new(0.9, 0.9, 0.0),
                    RestrictionKind::Positive(0.8),
                ),
                (
                    EpistemicInterval::new(0.9, 0.9, 0.0),
                    RestrictionKind::Negative(0.9),
                ),
            ],
        );
        assert!(
            (s.consistency_radius - 0.62).abs() < 1e-9,
            "mixed node radius should be max(0.62, 0) = 0.62, got {}",
            s.consistency_radius
        );
        assert!(
            (s.interval_inconsistency - 0.62).abs() < 1e-9,
            "mixed node interval_inconsistency should be max(0.62, 0) = 0.62, got {}",
            s.interval_inconsistency
        );
    }

    #[test]
    fn test_cdst_section_frame_evidence_only_unchanged() {
        // FrameEvidence neighbours (frame_validates) keep the symmetric metric
        // bit-for-bit, like Negative ones. FE passes bel/pl through:
        // neighbour [0.20, 0.40] -> restricted [0.20, 0.40], BetP 0.30;
        // local [0.80, 0.90], BetP 0.85 -> radius 0.55;
        // Hausdorff max(|0.80-0.20|, |0.90-0.40|) = 0.60.
        let local = EpistemicInterval::new(0.80, 0.90, 0.0);
        let neighbors = vec![(
            EpistemicInterval::new(0.20, 0.40, 0.0),
            RestrictionKind::FrameEvidence(0.8),
        )];
        let s = compute_cdst_section(Uuid::new_v4(), local, &neighbors);
        let expected = compute_cdst_expected(&neighbors).unwrap();
        assert_eq!(
            s.consistency_radius.to_bits(),
            (local.betp() - expected.betp()).abs().to_bits(),
            "FrameEvidence-only radius must stay |local_betp - expected_betp|"
        );
        assert_eq!(
            s.interval_inconsistency.to_bits(),
            local.hausdorff_distance(&expected).to_bits(),
            "FrameEvidence-only interval_inconsistency must stay the Hausdorff distance"
        );
        assert!(
            (s.consistency_radius - 0.55).abs() < 1e-9,
            "got {}",
            s.consistency_radius
        );
        assert!(
            (s.interval_inconsistency - 0.60).abs() < 1e-9,
            "got {}",
            s.interval_inconsistency
        );
    }

    #[test]
    fn test_cdst_section_mixed_positive_and_frame_evidence() {
        // FrameEvidence neighbours belong to the symmetric group, not the
        // floor group, and are NOT dropped from it.
        // Local [0.80, 0.90]; supporter [0.5, 0.5] Positive(0.8): floor 0.40,
        // shortfall 0. FE neighbour [0.20, 0.40]: symmetric distance
        // |0.85 - 0.30| = 0.55, Hausdorff 0.60. max(0, 0.55) = 0.55.
        // (The old all-neighbour average [0.30, 0.50], BetP 0.40, gave
        // |0.85 - 0.40| = 0.45; dropping FE from the group would give 0.)
        let local = EpistemicInterval::new(0.80, 0.90, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[
                (
                    EpistemicInterval::new(0.5, 0.5, 0.0),
                    RestrictionKind::Positive(0.8),
                ),
                (
                    EpistemicInterval::new(0.20, 0.40, 0.0),
                    RestrictionKind::FrameEvidence(0.8),
                ),
            ],
        );
        assert!(
            (s.consistency_radius - 0.55).abs() < 1e-9,
            "FE neighbour must set the symmetric term 0.55, got {}",
            s.consistency_radius
        );
        assert!(
            (s.interval_inconsistency - 0.60).abs() < 1e-9,
            "got {}",
            s.interval_inconsistency
        );
        assert_eq!(s.neighbor_count, 2);
    }

    // ── Negative ceiling (mutual exclusion, U075) ─────────────────────────

    #[test]
    fn test_cdst_section_disbelieved_pair_is_consistent() {
        // Both claims disbelieved and linked by contradicts: "not both true"
        // holds, so there is nothing to flag. Local [0.20, 0.40]; contradicter
        // [0.05, 0.20] at f = 0.9 caps the node at pl = 1 − 0.05·0.9 = 0.955,
        // and 0.20 ≤ 0.955. (The complement law expected [0.72, 0.955]:
        // Hausdorff 0.555, radius |0.30 − 0.8375| = 0.5375.)
        let local = EpistemicInterval::new(0.20, 0.40, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[(
                EpistemicInterval::new(0.05, 0.20, 0.0),
                RestrictionKind::Negative(0.9),
            )],
        );
        assert!(
            s.interval_inconsistency < 1e-9,
            "disbelieved pair interval_inconsistency must be 0, got {}",
            s.interval_inconsistency
        );
        assert!(
            s.consistency_radius < 1e-9,
            "disbelieved pair consistency_radius must be 0, got {}",
            s.consistency_radius
        );
    }

    #[test]
    fn test_cdst_section_weak_contradicter_does_not_flag_believed_node() {
        // A believed node [0.80, 0.90] under a weak contradicter [0.05, 0.20]
        // at f = 0.9: ceiling 0.955, 0.80 ≤ 0.955, so 0 on BOTH fields. A
        // symmetric metric over the mutual-exclusion expectation [0, 0.955]
        // would give 0.80 here (every believed target of every weak
        // contradicter flagged); the complement law gave Hausdorff 0.08.
        let local = EpistemicInterval::new(0.80, 0.90, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[(
                EpistemicInterval::new(0.05, 0.20, 0.0),
                RestrictionKind::Negative(0.9),
            )],
        );
        assert!(
            s.interval_inconsistency < 1e-9,
            "interval_inconsistency must be 0, got {}",
            s.interval_inconsistency
        );
        assert!(
            s.consistency_radius < 1e-9,
            "consistency_radius must be 0, got {}",
            s.consistency_radius
        );
    }

    #[test]
    fn test_cdst_section_negative_matches_worst_edge_and_scalar_twin() {
        // Node and edge must agree, the dual of
        // test_cdst_section_positive_radius_equals_worst_supports_edge: for a
        // Negative-only node `interval_inconsistency` is its worst
        // contradicts-edge Bel excess over the ceiling, as scored by the
        // independent edge path, and `consistency_radius` is the BetP-side
        // excess, as scored by the independent scalar twin
        // `sheaf::compute_section` on the same BetPs.
        let node = EpistemicInterval::new(0.60, 0.80, 0.0);
        let contradicters = [
            EpistemicInterval::new(0.30, 0.50, 0.0),
            EpistemicInterval::new(0.55, 0.70, 0.0),
            EpistemicInterval::new(0.05, 0.20, 0.0),
        ];
        let node_id = Uuid::new_v4();
        let neighbors: Vec<_> = contradicters
            .iter()
            .map(|c| (*c, RestrictionKind::Negative(sci().contradicts)))
            .collect();
        let section = compute_cdst_section(node_id, node, &neighbors);
        let worst_edge = contradicters
            .iter()
            .map(|c| {
                compute_cdst_edge_inconsistency(
                    Uuid::new_v4(),
                    node_id,
                    *c,
                    node,
                    "contradicts",
                    &sci(),
                )
                .interval_inconsistency
            })
            .fold(0.0f64, f64::max);
        // Binding Bel ceiling: 1 − 0.55·0.9 = 0.505, so 0.60 − 0.505 = 0.095.
        assert!(
            (worst_edge - 0.095).abs() < 1e-9,
            "edge path gave {worst_edge}"
        );
        assert!(
            (section.interval_inconsistency - worst_edge).abs() < 1e-12,
            "node interval_inconsistency {} must equal the worst contradicts-edge excess {}",
            section.interval_inconsistency,
            worst_edge
        );
        // Binding BetP ceiling: 1 − 0.625·0.9 = 0.4375, so 0.70 − 0.4375 =
        // 0.2625.
        let scalar_neighbors: Vec<_> = contradicters
            .iter()
            .map(|c| (c.betp(), RestrictionKind::Negative(sci().contradicts)))
            .collect();
        let scalar = crate::sheaf::compute_section(
            node_id,
            node.betp(),
            node.bel,
            node.pl,
            &scalar_neighbors,
        );
        assert!(
            (scalar.consistency_radius - 0.2625).abs() < 1e-9,
            "scalar twin gave {}",
            scalar.consistency_radius
        );
        assert!(
            (section.consistency_radius - scalar.consistency_radius).abs() < 1e-12,
            "node radius {} must equal the scalar twin's BetP-ceiling excess {}",
            section.consistency_radius,
            scalar.consistency_radius
        );
    }

    #[test]
    fn test_cdst_section_negative_radius_flags_wide_node_on_betp_ceiling() {
        // The radius is a BetP-side quantity (U075 ruling: "its own one-sided
        // term on the BetP side"), so a WIDE node whose bel is under the Bel
        // ceiling but whose BetP is above the BetP ceiling is flagged on the
        // radius only. Node [0.20, 0.90] (BetP 0.55), contradicter
        // [0.60, 0.70] (BetP 0.65) at f = 0.9:
        // - Bel side: ceiling 1 − 0.60·0.9 = 0.46, bel 0.20 under it -> 0;
        // - BetP side: ceiling 1 − 0.65·0.9 = 0.415, BetP 0.55 -> 0.135.
        let s = compute_cdst_section(
            Uuid::new_v4(),
            EpistemicInterval::new(0.20, 0.90, 0.0),
            &[(
                EpistemicInterval::new(0.60, 0.70, 0.0),
                RestrictionKind::Negative(0.9),
            )],
        );
        assert!(
            s.interval_inconsistency < 1e-9,
            "interval_inconsistency must be 0 (bel under the Bel ceiling), got {}",
            s.interval_inconsistency
        );
        assert!(
            (s.consistency_radius - 0.135).abs() < 1e-9,
            "consistency_radius must be the BetP-ceiling excess 0.135, got {}",
            s.consistency_radius
        );
    }

    #[test]
    fn test_cdst_section_negative_and_frame_evidence_scored_separately() {
        // Negative neighbours are a ceiling, FrameEvidence ones keep the
        // symmetric metric over their OWN average: the two must not be
        // averaged together. Local [0.80, 0.90]; FE neighbour [0.80, 0.90]
        // (distance 0) and a weak contradicter [0.05, 0.20] at f = 0.9
        // (ceiling 0.955, not binding). Expected 0 on both fields; averaging
        // the FE and Negative restrictions ([0.40, 0.9275]) would give 0.40.
        let local = EpistemicInterval::new(0.80, 0.90, 0.0);
        let s = compute_cdst_section(
            Uuid::new_v4(),
            local,
            &[
                (
                    EpistemicInterval::new(0.80, 0.90, 0.0),
                    RestrictionKind::FrameEvidence(0.8),
                ),
                (
                    EpistemicInterval::new(0.05, 0.20, 0.0),
                    RestrictionKind::Negative(0.9),
                ),
            ],
        );
        assert!(
            s.interval_inconsistency < 1e-9,
            "got {}",
            s.interval_inconsistency
        );
        assert!(s.consistency_radius < 1e-9, "got {}", s.consistency_radius);
        assert_eq!(s.neighbor_count, 2);
    }

    // ── build_cdst_sections tests ────────────────────────────────────────

    fn weak() -> EpistemicInterval {
        EpistemicInterval::new(0.1, 0.2, 0.0)
    }
    fn strong() -> EpistemicInterval {
        EpistemicInterval::new(0.95, 1.0, 0.0)
    }

    /// Both endpoint rows of one edge `src -[rel]-> dst`, as the
    /// neighbourhood query returns them.
    fn edge_rows(
        src: (Uuid, EpistemicInterval),
        dst: (Uuid, EpistemicInterval),
        rel: &str,
    ) -> [NeighborRow; 2] {
        [
            NeighborRow {
                claim_id: src.0,
                local: src.1,
                neighbor: dst.1,
                relationship: rel.to_string(),
                outgoing: true,
            },
            NeighborRow {
                claim_id: dst.0,
                local: dst.1,
                neighbor: src.1,
                relationship: rel.to_string(),
                outgoing: false,
            },
        ]
    }

    fn section_of(sections: &[CdstSheafSection], id: Uuid) -> &CdstSheafSection {
        sections
            .iter()
            .find(|s| s.node_id == id)
            .unwrap_or_else(|| panic!("no section for {id}"))
    }

    #[test]
    fn test_build_sections_skips_outgoing_supports() {
        // A supporter is not constrained by its target: the SOURCE side of a
        // directional positive edge contributes no neighbour.
        // a (weak) supports b (strong): read from a's side, b would impose a
        // floor 0.95 * 0.8 = 0.76 on a -> a spurious 0.66 (04b7055e's case).
        // c (strong) supports d (weak): d is genuinely under-supported, 0.66.
        let (a, b, c, d) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let mut rows = Vec::new();
        rows.extend(edge_rows((a, weak()), (b, strong()), "supports"));
        rows.extend(edge_rows((c, strong()), (d, weak()), "supports"));
        let sections = build_cdst_sections(&rows, &sci());
        assert_eq!(sections.len(), 4, "every claim with a row gets a section");

        let sa = section_of(&sections, a);
        assert_eq!(sa.neighbor_count, 0, "a supports-edge source has no floor");
        assert!(
            sa.consistency_radius < 1e-9,
            "weak supporter must not be penalised by its strong target, got {}",
            sa.consistency_radius
        );
        let sc = section_of(&sections, c);
        assert_eq!(sc.neighbor_count, 0);
        assert!(sc.consistency_radius < 1e-9);

        let sb = section_of(&sections, b);
        assert_eq!(sb.neighbor_count, 1);
        assert!(
            sb.consistency_radius < 1e-9,
            "over-supported target is benign"
        );
        let sd = section_of(&sections, d);
        assert_eq!(sd.neighbor_count, 1);
        assert!(
            (sd.consistency_radius - 0.66).abs() < 1e-9,
            "under-supported target must still flag 0.66, got {}",
            sd.consistency_radius
        );
    }

    #[test]
    fn test_build_sections_skips_every_directional_positive_kind_case_insensitively() {
        for rel in ["elaborates", "specializes", "generalizes", "Supports"] {
            let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
            let rows = edge_rows((a, weak()), (b, strong()), rel);
            let sections = build_cdst_sections(&rows, &sci());
            let sa = section_of(&sections, a);
            assert_eq!(sa.neighbor_count, 0, "{rel}: source must be skipped");
            assert!(
                sa.consistency_radius < 1e-9,
                "{rel}: got {}",
                sa.consistency_radius
            );
            assert_eq!(section_of(&sections, b).neighbor_count, 1, "{rel}");
        }
    }

    #[test]
    fn test_build_sections_keeps_both_sides_of_symmetric_kinds() {
        // corroborates is symmetric (unordered pair): the weak side IS
        // constrained by the strong side, 0.95 * 0.8 - 0.1 = 0.66.
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let sections = build_cdst_sections(
            &edge_rows((a, weak()), (b, strong()), "corroborates"),
            &sci(),
        );
        let sa = section_of(&sections, a);
        assert_eq!(sa.neighbor_count, 1);
        assert!(
            (sa.consistency_radius - 0.66).abs() < 1e-9,
            "got {}",
            sa.consistency_radius
        );
        assert_eq!(section_of(&sections, b).neighbor_count, 1);

        // Negative kinds are kept on the source side too (U080): mutual
        // exclusion caps each end by the other (U075). [0.80, 0.95] vs
        // [0.80, 0.95], local bel 0.80:
        // - contradicts f = 0.9: Bel ceiling 1 - 0.80*0.9 = 0.28 -> 0.52;
        //   BetP ceiling 1 - 0.875*0.9 = 0.2125 -> radius 0.6625.
        // - refutes f = 0.8 (Q2: treated symmetric): Bel ceiling
        //   1 - 0.80*0.8 = 0.36 -> 0.44; BetP ceiling 1 - 0.875*0.8 = 0.30
        //   -> radius 0.575.
        let iv = EpistemicInterval::new(0.80, 0.95, 0.0);
        for (rel, want_interval, want_radius) in
            [("contradicts", 0.52, 0.6625), ("refutes", 0.44, 0.575)]
        {
            let (e, f) = (Uuid::new_v4(), Uuid::new_v4());
            let sections = build_cdst_sections(&edge_rows((e, iv), (f, iv), rel), &sci());
            for id in [e, f] {
                let s = section_of(&sections, id);
                assert_eq!(s.neighbor_count, 1, "{rel}: both sides must be kept");
                assert!(
                    (s.interval_inconsistency - want_interval).abs() < 1e-9,
                    "{rel}: expected interval_inconsistency {want_interval}, got {}",
                    s.interval_inconsistency
                );
                assert!(
                    (s.consistency_radius - want_radius).abs() < 1e-9,
                    "{rel}: expected radius {want_radius}, got {}",
                    s.consistency_radius
                );
            }
        }

        // frame_validates keeps both sides: FE passes bel/pl through, so
        // [0.80, 0.90] (BetP 0.85) and [0.20, 0.40] (BetP 0.30) each score
        // |0.85 - 0.30| = 0.55 against the other.
        let (e, f) = (Uuid::new_v4(), Uuid::new_v4());
        let sections = build_cdst_sections(
            &edge_rows(
                (e, EpistemicInterval::new(0.80, 0.90, 0.0)),
                (f, EpistemicInterval::new(0.20, 0.40, 0.0)),
                "frame_validates",
            ),
            &sci(),
        );
        for id in [e, f] {
            let s = section_of(&sections, id);
            assert_eq!(
                s.neighbor_count, 1,
                "frame_validates: both sides must be kept"
            );
            assert!(
                (s.consistency_radius - 0.55).abs() < 1e-9,
                "frame_validates: expected 0.55, got {}",
                s.consistency_radius
            );
        }
    }

    #[test]
    fn test_build_sections_uses_the_given_profile() {
        // Regulatory supports factor 0.95: floor 0.95 * 0.95 = 0.9025 on d.
        let (c, d) = (Uuid::new_v4(), Uuid::new_v4());
        let sections = build_cdst_sections(
            &edge_rows((c, strong()), (d, weak()), "supports"),
            &RestrictionProfile::regulatory(),
        );
        let sd = section_of(&sections, d);
        assert!(
            (sd.consistency_radius - 0.8025).abs() < 1e-9,
            "regulatory floor shortfall should be 0.8025, got {}",
            sd.consistency_radius
        );
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
        // supports is a bel floor: shortfall = 0.64-0.1 = 0.54
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let source = EpistemicInterval::new(0.8, 0.95, 0.1);
        let target = EpistemicInterval::new(0.1, 0.2, 0.1);

        let obs =
            compute_cdst_edge_inconsistency(src_id, tgt_id, source, target, "supports", &sci());

        assert!(
            (obs.interval_inconsistency - 0.54).abs() < 1e-9,
            "stale support shortfall should be the bel shortfall 0.64-0.1=0.54, got {}",
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
        //   below = (0.40-0.98).max(0) = 0.0
        // (pl is not a floor; b3476233).
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
        // Clamped to exactly 0, never negative: a signed shortfall would
        // SUBTRACT mass from H¹ for every over-supported hub.
        assert!(
            obs.interval_inconsistency.abs() < 1e-9,
            "over-support shortfall must be exactly 0 (not negative), got {}",
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
            coh.h1.abs() < 1e-9,
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

        // The floor is on bel only:
        //   expected.bel = 0.90*0.80 = 0.72, target.bel = 0.10 → shortfall 0.62.
        // expected.pl = 1-(1-1.0)*0.80 = 1.0 is NOT a floor: it rises toward 1
        // as the edge weakens (and is 1.0 for every factor when pl_s = 1.0), so
        // the former pl shortfall 1.0-0.30 = 0.70 measured nothing about this
        // edge (backlog b3476233).
        assert!(
            obs.conflict_component > 0.0,
            "under-support must still flag a conflict, got {}",
            obs.conflict_component
        );
        assert!(
            (obs.conflict_component - 0.62).abs() < 1e-9,
            "under-support shortfall should be the bel shortfall 0.72-0.10=0.62, got {}",
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

    // ── supports-edge floor coherence (backlog b3476233) ──────────────────
    //
    // `restrict_epistemic_positive` gives expected.pl = 1-(1-pl_s)*f, which
    // RISES toward 1 as the edge weakens (f → 0). A floor on pl therefore
    // demands MORE of the target the weaker the support, and a vacuous message
    // (f → 0) would impose the maximal constraint pl_t ≥ 1. Only the bel floor
    // (bel_s*f, falling to 0 as f → 0) is a coherent "at least" constraint.

    #[test]
    fn test_supports_full_plausibility_source_does_not_flag_target_above_bel_floor() {
        // pl_s == 1.0 is the degenerate case behind ~97% of positive
        // obstructions >= 0.15 in the 2026-09-17 replay: expected.pl = 1.0 for
        // every factor, so ANY target with pl < 1 was flagged.
        let s = Uuid::new_v4();
        let t = Uuid::new_v4();
        let source = EpistemicInterval::new(0.50, 1.0, 0.0);
        // bel 0.50 is above the floor 0.50*0.80 = 0.40; pl 0.60 < 1.
        let target = EpistemicInterval::new(0.50, 0.60, 0.0);

        let obs = compute_cdst_edge_inconsistency(s, t, source, target, "supports", &sci());

        assert!(
            obs.interval_inconsistency.abs() < 1e-9,
            "target above the bel floor must not be flagged by a pl=1 supporter, got {}",
            obs.interval_inconsistency
        );
        assert!(
            obs.conflict_component.abs() < 1e-9,
            "conflict_component must also be 0, got {}",
            obs.conflict_component
        );
    }

    #[test]
    fn test_supports_full_plausibility_source_drops_from_cohomology() {
        // Cohomology-level twin of the edge test above: the live symptom of
        // b3476233 was pl_s = 1.0 supporter edges landing in the obstruction
        // set (and so in reconcile clusters) at the 0.15 threshold. A target
        // that clears the bel floor must be absent from obstructions and H¹.
        let s = Uuid::new_v4();
        let t = Uuid::new_v4();
        let source = EpistemicInterval::new(0.50, 1.0, 0.0);
        let target = EpistemicInterval::new(0.50, 0.60, 0.0);

        let obs = compute_cdst_edge_inconsistency(s, t, source, target, "supports", &sci());
        let coh = compute_cdst_cohomology(vec![obs], 0.15);

        assert_eq!(coh.edge_count, 1, "one edge in the sheaf");
        assert!(
            coh.obstructions.is_empty(),
            "a pl=1 supporter of a target above the bel floor must not be an obstruction at 0.15, got {:?}",
            coh.obstructions
                .iter()
                .map(|o| o.interval_inconsistency)
                .collect::<Vec<_>>()
        );
        assert!(
            coh.h1.abs() < 1e-9,
            "it must contribute exactly 0 to H¹, got h1={}",
            coh.h1
        );
    }

    #[test]
    fn test_supports_weaker_edge_never_demands_more() {
        // Same source/target; `elaborates` (f=0.60) is a weaker positive edge
        // than `supports` (f=0.80), so it must never impose a larger shortfall.
        let s = Uuid::new_v4();
        let t = Uuid::new_v4();
        let source = EpistemicInterval::new(0.50, 0.90, 0.0);
        let target = EpistemicInterval::new(0.50, 0.90, 0.0);

        let inc = |rel: &str| {
            compute_cdst_edge_inconsistency(s, t, source, target, rel, &sci())
                .interval_inconsistency
        };
        let sup = inc("supports");
        let ela = inc("elaborates");

        assert!(
            ela <= sup + 1e-12,
            "weaker edge demanded more: elaborates={ela} > supports={sup}"
        );
        // Target bel 0.50 clears both bel floors (0.40, 0.30): no shortfall.
        assert!(sup.abs() < 1e-9, "supports shortfall must be 0, got {sup}");
        assert!(
            ela.abs() < 1e-9,
            "elaborates shortfall must be 0, got {ela}"
        );

        // A target BETWEEN the two bel floors (0.30 < 0.35 < 0.40) keeps the
        // ordering check meaningful on the fixed code: the stronger edge has a
        // real shortfall, the weaker one none.
        let between = EpistemicInterval::new(0.35, 0.90, 0.0);
        let inc_between = |rel: &str| {
            compute_cdst_edge_inconsistency(s, t, source, between, rel, &sci())
                .interval_inconsistency
        };
        let sup_b = inc_between("supports");
        let ela_b = inc_between("elaborates");
        assert!(
            ela_b <= sup_b + 1e-12,
            "weaker edge demanded more: elaborates={ela_b} > supports={sup_b}"
        );
        assert!(
            (sup_b - 0.05).abs() < 1e-9,
            "supports shortfall should be the bel shortfall 0.40-0.35=0.05, got {sup_b}"
        );
        assert!(
            ela_b.abs() < 1e-9,
            "elaborates bel floor 0.30 is cleared by 0.35: shortfall must be 0, got {ela_b}"
        );
    }

    #[test]
    fn test_supports_shortfall_monotone_in_factor_and_vanishes_at_zero() {
        // Sweep the transmission factor directly via the CDST edge properties
        // (`cdst_pl > 0.5` → Positive(cdst_bel)). The shortfall must be
        // non-increasing as f falls, and tend to 0 as the message goes vacuous.
        let s = Uuid::new_v4();
        let t = Uuid::new_v4();
        let source = EpistemicInterval::new(0.80, 0.90, 0.0);
        // Below the bel floor for strong edges (0.80*0.99 = 0.792 > 0.30), above
        // it for weak ones (0.80*0.30 = 0.24 < 0.30), so the sweep is non-trivial.
        let target = EpistemicInterval::new(0.30, 0.50, 0.0);

        let factors = [0.99, 0.90, 0.80, 0.60, 0.50, 0.40, 0.30, 0.10, 0.01];
        let shortfalls: Vec<f64> = factors
            .iter()
            .map(|&f| {
                let props = serde_json::json!({ "cdst_bel": f, "cdst_pl": 0.95 });
                compute_cdst_edge_inconsistency_with_properties(
                    s,
                    t,
                    source,
                    target,
                    "supports",
                    &props,
                    &sci(),
                )
                .interval_inconsistency
            })
            .collect();

        assert!(
            shortfalls.iter().all(|&x| x >= 0.0),
            "a shortfall is never negative (all: {shortfalls:?})"
        );
        for (w, f) in shortfalls.windows(2).zip(factors.windows(2)) {
            assert!(
                w[1] <= w[0] + 1e-12,
                "shortfall rose as factor fell {}→{}: {}→{} (all: {shortfalls:?})",
                f[0],
                f[1],
                w[0],
                w[1]
            );
        }
        // Strong edge: genuine bel shortfall 0.80*0.99 - 0.30 = 0.492.
        assert!(
            (shortfalls[0] - 0.492).abs() < 1e-9,
            "f=0.99 shortfall should be the bel shortfall 0.492, got {}",
            shortfalls[0]
        );
        // Near-vacuous edge imposes (almost) no constraint.
        let last = *shortfalls.last().unwrap();
        assert!(
            last.abs() < 1e-9,
            "f=0.01 (near-vacuous) must impose no shortfall, got {last} (all: {shortfalls:?})"
        );
    }

    #[test]
    fn test_contradicts_believed_pair_flags_bel_over_ceiling() {
        // A believed pair linked by contradicts is a real conflict and must
        // still flag, on the mutual-exclusion ceiling (U075).
        //
        // contradicts → Negative(0.90); restrict_epistemic_negative on
        // source [0.80, 0.95] gives expected [0, 1 - 0.80*0.90] = [0, 0.28].
        // Target [0.70, 0.90] sits 0.70 - 0.28 = 0.42 above the ceiling, on
        // both twin fields. (The complement law's symmetric distance gave
        // max(|0.70-0.045|, |0.90-0.28|) = 0.655.)
        let src_id = Uuid::new_v4();
        let tgt_id = Uuid::new_v4();
        let source = EpistemicInterval::new(0.80, 0.95, 0.0);
        let target = EpistemicInterval::new(0.70, 0.90, 0.0);

        let obs =
            compute_cdst_edge_inconsistency(src_id, tgt_id, source, target, "contradicts", &sci());

        assert!(
            (obs.conflict_component - 0.42).abs() < 1e-9,
            "contradicts conflict should be the ceiling excess 0.42, got {}",
            obs.conflict_component
        );
        assert!(
            (obs.interval_inconsistency - 0.42).abs() < 1e-9,
            "contradicts interval_inconsistency should be 0.42, got {}",
            obs.interval_inconsistency
        );
    }

    #[test]
    fn test_contradicts_between_two_disbelieved_claims_is_consistent() {
        // Mutual exclusion ("not both true") is satisfied by two disbelieved
        // claims. Source [0.05, 0.20] at f = 0.90 caps the target at
        // pl = 0.955; target [0.20, 0.40] sits under it, so both twin fields
        // are 0. The complement law expected [0.72, 0.955] and scored
        // max(|0.20 − 0.72|, |0.40 − 0.955|) = 0.555 on both (backlog I014's
        // "low-BetP sources triggering high edge inconsistency").
        let obs = compute_cdst_edge_inconsistency(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EpistemicInterval::new(0.05, 0.20, 0.0),
            EpistemicInterval::new(0.20, 0.40, 0.0),
            "contradicts",
            &sci(),
        );
        assert!(
            obs.interval_inconsistency < 1e-9,
            "interval_inconsistency must be 0, got {}",
            obs.interval_inconsistency
        );
        assert!(
            obs.conflict_component < 1e-9,
            "conflict_component must be 0, got {}",
            obs.conflict_component
        );
        // Nor is the pair an ignorance obstruction: the target's whole
        // interval sits under the ceiling. (A width mismatch against the
        // permissive [0, 0.955] gave |0.20 − 0.955| = 0.755, which every such
        // edge added to ignorance_h1.)
        assert!(
            obs.ignorance_component < 1e-9,
            "ignorance_component must be 0, got {}",
            obs.ignorance_component
        );
    }

    // ── Negative-arm ignorance and classification (U075) ──────────────────

    #[test]
    fn test_contradicts_weak_contradicter_adds_no_ignorance_to_believed_target() {
        // A believed target [0.80, 0.90] under a weak contradicter
        // [0.05, 0.20] at f = 0.9 is consistent: ceiling 0.955 sits above its
        // whole interval. It must add nothing to ignorance_h1 either; a width
        // mismatch against [0, 0.955] gave |0.10 − 0.955| = 0.855 per edge.
        let obs = compute_cdst_edge_inconsistency(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EpistemicInterval::new(0.05, 0.20, 0.0),
            EpistemicInterval::new(0.80, 0.90, 0.0),
            "contradicts",
            &sci(),
        );
        assert!(
            obs.interval_inconsistency < 1e-9,
            "got {}",
            obs.interval_inconsistency
        );
        assert!(
            obs.ignorance_component < 1e-9,
            "ignorance_component must be 0, got {}",
            obs.ignorance_component
        );
    }

    #[test]
    fn test_contradicts_ceiling_breach_is_a_belief_conflict() {
        // A moderately believed contradicter [0.50, 0.60] at f = 0.9 caps the
        // target at 1 − 0.50·0.9 = 0.55. Target [0.75, 0.85] sits 0.20 above
        // it: a genuine breach, labelled BeliefConflict. A width mismatch
        // against [0, 0.55] (|0.10 − 0.55| = 0.45) would outrank the 0.20
        // conflict and mislabel it IgnoranceDrift.
        let obs = compute_cdst_edge_inconsistency(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EpistemicInterval::new(0.50, 0.60, 0.0),
            EpistemicInterval::new(0.75, 0.85, 0.0),
            "contradicts",
            &sci(),
        );
        assert!(
            (obs.interval_inconsistency - 0.20).abs() < 1e-9,
            "got {}",
            obs.interval_inconsistency
        );
        assert!(
            obs.ignorance_component < 1e-9,
            "a breached ceiling carries no ignorance term, got {}",
            obs.ignorance_component
        );
        assert_eq!(obs.obstruction_kind, ObstructionKind::BeliefConflict);

        // Even a small breach by a wide target stays a BeliefConflict:
        // [0.60, 0.99] is 0.05 over the ceiling.
        let wide = compute_cdst_edge_inconsistency(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EpistemicInterval::new(0.50, 0.60, 0.0),
            EpistemicInterval::new(0.60, 0.99, 0.0),
            "contradicts",
            &sci(),
        );
        assert!((wide.conflict_component - 0.05).abs() < 1e-9);
        assert_eq!(wide.obstruction_kind, ObstructionKind::BeliefConflict);
    }

    #[test]
    fn test_contradicts_target_spanning_the_ceiling_is_ignorance() {
        // Target [0.20, 0.90] under contradicter [0.60, 0.70] at f = 0.9
        // (ceiling 0.46): its bel is under the ceiling (no conflict), but its
        // plausibility reaches 0.44 above it. Whether the pair is consistent
        // depends on resolving the target's ignorance, so the edge is
        // IgnoranceDrift with ignorance_component 0.90 − 0.46 = 0.44.
        let obs = compute_cdst_edge_inconsistency(
            Uuid::new_v4(),
            Uuid::new_v4(),
            EpistemicInterval::new(0.60, 0.70, 0.0),
            EpistemicInterval::new(0.20, 0.90, 0.0),
            "contradicts",
            &sci(),
        );
        assert!(
            obs.interval_inconsistency < 1e-9,
            "got {}",
            obs.interval_inconsistency
        );
        assert!(
            (obs.ignorance_component - 0.44).abs() < 1e-9,
            "got {}",
            obs.ignorance_component
        );
        assert_eq!(obs.obstruction_kind, ObstructionKind::IgnoranceDrift);
    }

    // ── relationship spelling ─────────────────────────────────────────────

    /// The sheaf pair queries return `edges.relationship` as stored, and
    /// writers store both `supports` and `SUPPORTS` (likewise the other
    /// epistemic names). Every consumer passes that string straight to
    /// `compute_cdst_edge_inconsistency`, so the restriction lookup must fold
    /// case: an upper- or mixed-case epistemic edge must restrict exactly like
    /// its lower-case spelling, never as `Neutral` (which would make the edge
    /// count toward H⁰ but never become an obstruction).
    #[test]
    fn test_edge_inconsistency_folds_relationship_case() {
        let src = EpistemicInterval::new(0.9, 0.9, 0.0);
        let tgt = EpistemicInterval::new(0.1, 0.2, 0.0);
        let run = |rel: &str| {
            compute_cdst_edge_inconsistency(Uuid::nil(), Uuid::nil(), src, tgt, rel, &sci())
        };

        // Control: a non-epistemic relationship is Neutral, whose expected
        // interval IS the target. The guard below depends on this.
        assert_eq!(
            run("DERIVED_FROM").expected_interval,
            tgt,
            "control: an unknown relationship restricts as Neutral (expected = target)"
        );

        for lower in [
            "supports",
            "refutes",
            "contradicts",
            "corroborates",
            "elaborates",
            "specializes",
            "generalizes",
            "frame_validates",
        ] {
            let base = run(lower);
            assert_ne!(
                base.expected_interval, tgt,
                "{lower}: the lower-case spelling must not restrict as Neutral, \
                 otherwise the comparisons below are vacuous"
            );

            let mut mixed: String = lower.to_string();
            mixed[..1].make_ascii_uppercase();
            for spelling in [lower.to_ascii_uppercase(), mixed] {
                let got = run(&spelling);
                assert_eq!(
                    got.expected_interval, base.expected_interval,
                    "{spelling} must restrict like {lower}"
                );
                for (field, a, b) in [
                    (
                        "interval_inconsistency",
                        got.interval_inconsistency,
                        base.interval_inconsistency,
                    ),
                    (
                        "conflict_component",
                        got.conflict_component,
                        base.conflict_component,
                    ),
                    (
                        "ignorance_component",
                        got.ignorance_component,
                        base.ignorance_component,
                    ),
                    (
                        "open_world_component",
                        got.open_world_component,
                        base.open_world_component,
                    ),
                ] {
                    assert!(
                        (a - b).abs() < 1e-12,
                        "{spelling} vs {lower}: {field} {a} != {b}"
                    );
                }
                assert_eq!(
                    got.obstruction_kind, base.obstruction_kind,
                    "{spelling} vs {lower}: obstruction kind"
                );
            }
        }
    }
}
