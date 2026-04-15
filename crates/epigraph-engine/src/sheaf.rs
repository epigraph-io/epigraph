//! Sheaf-theoretic consistency for the knowledge graph.
//!
//! A presheaf assigns epistemic states to nodes. A sheaf requires
//! that local assignments are globally consistent (the gluing axiom).
//! This module provides the pure math: restriction maps, sections,
//! and consistency radii. DB integration is in epigraph-db / nano.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How an edge relationship transmits belief.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RestrictionKind {
    /// Source belief supports target. Factor: transmission strength.
    Positive(f64),
    /// Source belief opposes target. Factor: opposition strength.
    Negative(f64),
    /// Frame evidence: only affects open_world component, not Bel/Pl.
    FrameEvidence(f64),
    /// No epistemic transmission (structural edge only).
    Neutral,
}

/// Domain-specific restriction map profiles.
///
/// Different epistemic domains have different transmission characteristics.
/// See `epigraph-nano/src/sheaf.rs` for the canonical implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestrictionProfile {
    pub name: String,
    pub supports: f64,
    pub elaborates: f64,
    pub generalizes: f64,
    pub refutes: f64,
    pub contradicts: f64,
    /// Weak positive transmission for evidence that is present but ambiguous.
    /// SciFact calibration (2026-03-24): claims with 0.5 ≤ betp < 0.9 or theta > 0.7
    /// have evidence that leans positive but isn't strong enough for `supports`.
    /// This factor keeps them in the factor graph with attenuated influence.
    #[serde(default = "default_informs")]
    pub informs: f64,
}

fn default_informs() -> f64 {
    0.30
}

impl RestrictionProfile {
    pub fn scientific() -> Self {
        Self {
            name: "scientific".into(),
            supports: 0.80,
            elaborates: 0.60,
            generalizes: 0.50,
            refutes: 0.80,
            contradicts: 0.90,
            informs: 0.30,
        }
    }
    pub fn regulatory() -> Self {
        Self {
            name: "regulatory".into(),
            supports: 0.95,
            elaborates: 0.85,
            generalizes: 0.70,
            refutes: 0.95,
            contradicts: 0.97,
            informs: 0.40,
        }
    }
}

/// Classify an edge relationship using the default (scientific) profile.
pub fn restriction_kind(relationship: &str) -> RestrictionKind {
    restriction_kind_with_profile(relationship, &RestrictionProfile::scientific())
}

/// CDST-native restriction: derive transmission factor from edge properties
/// instead of fixed profile constants. Falls back to label-based lookup if
/// no CDST interval is stored on the edge.
///
/// When `cdst_bel` and `cdst_pl` are present in edge properties:
/// - bel >= 0.5 → Positive(bel): evidence strength IS the transmission factor
/// - pl <= 0.5  → Negative(1 - pl): evidence opposition IS the factor
/// - otherwise  → Positive(bel): weak positive, naturally attenuated by low bel
pub fn restriction_kind_from_properties(
    relationship: &str,
    properties: &serde_json::Value,
    profile: &RestrictionProfile,
) -> RestrictionKind {
    // If the edge carries a CDST interval, use it directly
    if let (Some(bel), Some(pl)) = (
        properties.get("cdst_bel").and_then(|v| v.as_f64()),
        properties.get("cdst_pl").and_then(|v| v.as_f64()),
    ) {
        return if pl <= 0.5 {
            // Evidence rules out support → negative restriction
            RestrictionKind::Negative((1.0 - pl).clamp(0.01, 0.99))
        } else {
            // Evidence supports (strongly or weakly) → positive restriction
            // bel IS the factor: high bel = strong transmission, low bel = weak
            RestrictionKind::Positive(bel.clamp(0.01, 0.99))
        };
    }
    // Fallback: label-based lookup with profile constants
    restriction_kind_with_profile(relationship, profile)
}

/// Classify an edge relationship using a specific domain profile.
pub fn restriction_kind_with_profile(
    relationship: &str,
    profile: &RestrictionProfile,
) -> RestrictionKind {
    match relationship.to_ascii_lowercase().as_str() {
        "supports" | "corroborates" => RestrictionKind::Positive(profile.supports),
        "elaborates" | "specializes" => RestrictionKind::Positive(profile.elaborates),
        "generalizes" => RestrictionKind::Positive(profile.generalizes),
        "refutes" => RestrictionKind::Negative(profile.refutes),
        "contradicts" => RestrictionKind::Negative(profile.contradicts),
        "supersedes" => RestrictionKind::Negative(profile.contradicts),
        "informs" => RestrictionKind::Positive(profile.informs),
        "frame_validates" => RestrictionKind::FrameEvidence(profile.supports),
        _ => RestrictionKind::Neutral,
    }
}

/// A sheaf section at a single node.
#[derive(Debug, Clone)]
pub struct SheafSection {
    pub node_id: Uuid,
    /// Actual pignistic probability at this node.
    pub local_betp: f64,
    /// Expected BetP from neighborhood restriction maps.
    pub expected_betp: f64,
    /// |local - expected|: how inconsistent this node is.
    pub consistency_radius: f64,
    /// Number of epistemic neighbors contributing.
    pub neighbor_count: usize,
    /// DS belief at this node.
    pub local_belief: f64,
    /// DS plausibility at this node.
    pub local_plausibility: f64,
}

/// Compute expected BetP from neighbors' beliefs and edge types.
///
/// For each neighbor with `Positive(factor)`, the expected contribution
/// is `neighbor_betp * factor`. For `Negative(factor)`, it's
/// `(1.0 - neighbor_betp) * factor`. Neutral neighbors are ignored.
///
/// Returns `None` if there are no epistemic (non-neutral) neighbors.
pub fn compute_expected_betp(neighbors: &[(f64, RestrictionKind)]) -> Option<f64> {
    let mut sum = 0.0;
    let mut count = 0usize;

    for &(neighbor_betp, kind) in neighbors {
        match kind {
            RestrictionKind::Positive(factor) => {
                sum += neighbor_betp * factor;
                count += 1;
            }
            RestrictionKind::Negative(factor) => {
                sum += (1.0 - neighbor_betp) * factor;
                count += 1;
            }
            RestrictionKind::FrameEvidence(_) => {} // CDST path only
            RestrictionKind::Neutral => {}
        }
    }

    if count == 0 {
        None
    } else {
        Some(sum / count as f64)
    }
}

/// Build a sheaf section for a single node.
pub fn compute_section(
    node_id: Uuid,
    local_betp: f64,
    local_belief: f64,
    local_plausibility: f64,
    neighbors: &[(f64, RestrictionKind)],
) -> SheafSection {
    let expected = compute_expected_betp(neighbors);
    let consistency_radius = expected.map_or(0.0, |e| (local_betp - e).abs());
    let neighbor_count = neighbors
        .iter()
        .filter(|(_, k)| {
            !matches!(
                k,
                RestrictionKind::Neutral | RestrictionKind::FrameEvidence(_)
            )
        })
        .count();

    SheafSection {
        node_id,
        local_betp,
        expected_betp: expected.unwrap_or(local_betp),
        consistency_radius,
        neighbor_count,
        local_belief,
        local_plausibility,
    }
}

/// First sheaf cohomology: global belief inconsistency measure.
#[derive(Debug, Clone)]
pub struct SheafCohomology {
    /// Number of consistent edges (inconsistency below threshold).
    pub h0: usize,
    /// Total inconsistency across all epistemic edges.
    pub h1: f64,
    /// h1 / edge_count (average per-edge inconsistency).
    pub h1_normalized: f64,
    /// Total number of epistemic edges analyzed.
    pub edge_count: usize,
    /// Edges where belief is inconsistent, sorted by inconsistency DESC.
    pub obstructions: Vec<SheafObstruction>,
}

/// An edge where belief is inconsistent.
#[derive(Debug, Clone)]
pub struct SheafObstruction {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub source_betp: f64,
    pub target_betp: f64,
    pub expected_target_betp: f64,
    pub edge_inconsistency: f64,
}

/// Compute per-edge inconsistency via the restriction map.
///
/// For `Positive(factor)`: expected target ≥ source × factor.
/// For `Negative(factor)`: expected target ≤ 1 - (source × factor).
/// For `Neutral`: 0.
pub fn compute_edge_inconsistency(
    source_betp: f64,
    target_betp: f64,
    relationship: &str,
) -> (f64, f64) {
    match restriction_kind(relationship) {
        RestrictionKind::Positive(factor) => {
            let expected = source_betp * factor;
            if target_betp < expected {
                (expected - target_betp, expected)
            } else {
                (0.0, expected)
            }
        }
        RestrictionKind::Negative(factor) => {
            let expected = 1.0 - (source_betp * factor);
            if target_betp > expected {
                (target_betp - expected, expected)
            } else {
                (0.0, expected)
            }
        }
        RestrictionKind::FrameEvidence(_) => (0.0, target_betp),
        RestrictionKind::Neutral => (0.0, target_betp),
    }
}

/// Compute H¹ from a list of obstructions.
///
/// Sorts obstructions by inconsistency DESC and separates h0 (consistent)
/// from h1 (total inconsistency).
pub fn compute_cohomology(
    obstructions: &mut Vec<SheafObstruction>,
    threshold: f64,
) -> SheafCohomology {
    obstructions.sort_by(|a, b| {
        b.edge_inconsistency
            .partial_cmp(&a.edge_inconsistency)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let edge_count = obstructions.len();
    let h1: f64 = obstructions.iter().map(|o| o.edge_inconsistency).sum();
    let h0 = obstructions
        .iter()
        .filter(|o| o.edge_inconsistency <= threshold)
        .count();
    let h1_normalized = if edge_count > 0 {
        h1 / edge_count as f64
    } else {
        0.0
    };

    // Only keep obstructions above threshold
    obstructions.retain(|o| o.edge_inconsistency > threshold);

    SheafCohomology {
        h0,
        h1,
        h1_normalized,
        edge_count,
        obstructions: obstructions.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restriction_kind_classification() {
        assert!(matches!(
            restriction_kind("supports"),
            RestrictionKind::Positive(f) if (f - 0.8).abs() < 1e-9
        ));
        assert!(matches!(
            restriction_kind("contradicts"),
            RestrictionKind::Negative(f) if (f - 0.9).abs() < 1e-9
        ));
        assert!(matches!(
            restriction_kind("derived_from"),
            RestrictionKind::Neutral
        ));
        assert!(matches!(
            restriction_kind("corroborates"),
            RestrictionKind::Positive(_)
        ));
        assert!(matches!(
            restriction_kind("refutes"),
            RestrictionKind::Negative(_)
        ));
    }

    #[test]
    fn test_compute_expected_betp_positive() {
        // Two supporters with BetP=0.8, factor=0.8 each
        let neighbors = vec![
            (0.8, RestrictionKind::Positive(0.8)),
            (0.8, RestrictionKind::Positive(0.8)),
        ];
        let expected = compute_expected_betp(&neighbors).unwrap();
        // Each contributes 0.8 * 0.8 = 0.64, avg = 0.64
        assert!((expected - 0.64).abs() < 1e-9);
    }

    #[test]
    fn test_compute_expected_betp_mixed() {
        // One supporter (BetP=0.9, factor=0.8) and one contradictor (BetP=0.8, factor=0.9)
        let neighbors = vec![
            (0.9, RestrictionKind::Positive(0.8)),
            (0.8, RestrictionKind::Negative(0.9)),
        ];
        let expected = compute_expected_betp(&neighbors).unwrap();
        // Positive: 0.9 * 0.8 = 0.72
        // Negative: (1 - 0.8) * 0.9 = 0.18
        // Avg: (0.72 + 0.18) / 2 = 0.45
        assert!((expected - 0.45).abs() < 1e-9);
    }

    #[test]
    fn test_compute_expected_betp_neutral_only() {
        let neighbors = vec![(0.5, RestrictionKind::Neutral)];
        assert!(compute_expected_betp(&neighbors).is_none());
    }

    #[test]
    fn test_section_zero_radius_when_consistent() {
        let id = Uuid::new_v4();
        // Node BetP=0.64, one supporter with BetP=0.8
        // Expected: 0.8 * 0.8 = 0.64 → radius = 0
        let section = compute_section(id, 0.64, 0.5, 0.8, &[(0.8, RestrictionKind::Positive(0.8))]);
        assert!(section.consistency_radius < 1e-9);
        assert_eq!(section.neighbor_count, 1);
    }

    #[test]
    fn test_section_high_radius_when_stale() {
        let id = Uuid::new_v4();
        // Node BetP=0.9 but supporter has BetP=0.3
        // Expected: 0.3 * 0.8 = 0.24 → radius = |0.9 - 0.24| = 0.66
        let section = compute_section(id, 0.9, 0.7, 0.95, &[(0.3, RestrictionKind::Positive(0.8))]);
        assert!((section.consistency_radius - 0.66).abs() < 1e-9);
    }

    #[test]
    fn test_section_no_epistemic_neighbors() {
        let id = Uuid::new_v4();
        let section = compute_section(id, 0.7, 0.5, 0.9, &[]);
        assert!(section.consistency_radius < 1e-9);
        assert_eq!(section.neighbor_count, 0);
    }

    // ── Cohomology tests (B.1) ──

    #[test]
    fn test_edge_inconsistency_consistent_support() {
        // Source BetP=0.8 supports target BetP=0.7
        // Expected: 0.8 * 0.8 = 0.64. Target 0.7 >= 0.64 → inconsistency = 0
        let (inc, _) = compute_edge_inconsistency(0.8, 0.7, "supports");
        assert!(inc < 1e-9);
    }

    #[test]
    fn test_edge_inconsistency_stale_support() {
        // Source BetP=0.9 supports target BetP=0.3
        // Expected: 0.9 * 0.8 = 0.72. Target 0.3 < 0.72 → inconsistency = 0.42
        let (inc, _) = compute_edge_inconsistency(0.9, 0.3, "supports");
        assert!((inc - 0.42).abs() < 1e-9);
    }

    #[test]
    fn test_edge_inconsistency_contradiction() {
        // Source BetP=0.9 contradicts target BetP=0.8
        // Expected: 1 - 0.9*0.9 = 0.19. Target 0.8 > 0.19 → inconsistency = 0.61
        let (inc, _) = compute_edge_inconsistency(0.9, 0.8, "contradicts");
        assert!((inc - 0.61).abs() < 1e-9);
    }

    #[test]
    fn test_cohomology_zero_for_consistent_graph() {
        let mut obstructions = vec![SheafObstruction {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            relationship: "supports".into(),
            source_betp: 0.8,
            target_betp: 0.7,
            expected_target_betp: 0.64,
            edge_inconsistency: 0.0,
        }];
        let coh = compute_cohomology(&mut obstructions, 0.05);
        assert!(coh.h1 < 1e-9);
        assert_eq!(coh.h0, 1);
        assert!(coh.obstructions.is_empty());
    }

    #[test]
    fn test_cohomology_positive_for_inconsistent_graph() {
        let mut obstructions = vec![
            SheafObstruction {
                source_id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                relationship: "supports".into(),
                source_betp: 0.9,
                target_betp: 0.3,
                expected_target_betp: 0.72,
                edge_inconsistency: 0.42,
            },
            SheafObstruction {
                source_id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                relationship: "supports".into(),
                source_betp: 0.7,
                target_betp: 0.6,
                expected_target_betp: 0.56,
                edge_inconsistency: 0.0,
            },
        ];
        let coh = compute_cohomology(&mut obstructions, 0.05);
        assert!((coh.h1 - 0.42).abs() < 1e-9);
        assert_eq!(coh.h0, 1); // One consistent edge
        assert_eq!(coh.obstructions.len(), 1); // One obstruction above threshold
        assert_eq!(coh.edge_count, 2);
    }
}
