//! Decorated cospans for compositional sub-graph inference.
//!
//! A decorated cospan is a subgraph with explicit boundary nodes.
//! Two cospans sharing boundary nodes can be composed (glued).
//! The boundary inconsistency measures how well the regions agree
//! about shared claims.

use std::collections::HashMap;
use uuid::Uuid;

/// A subgraph with boundary and interior nodes, each decorated with beliefs.
#[derive(Debug, Clone)]
pub struct DecoratedCospan {
    pub interior_ids: Vec<Uuid>,
    pub boundary_ids: Vec<Uuid>,
    pub beliefs: HashMap<Uuid, f64>,
}

/// Result of composing two cospans.
#[derive(Debug, Clone)]
pub struct CompositionResult {
    pub beliefs: HashMap<Uuid, f64>,
    pub boundary_inconsistency: f64,
    pub consistent: bool,
    pub boundary_size: usize,
}

/// Compose two cospans by gluing along shared boundary.
/// At shared nodes, takes the average. Reports max inconsistency.
pub fn compose_cospans(
    left: &DecoratedCospan,
    right: &DecoratedCospan,
    consistency_threshold: f64,
) -> CompositionResult {
    let mut combined = left.beliefs.clone();
    let mut max_inconsistency: f64 = 0.0;
    let mut boundary_count = 0;

    // Find shared boundary nodes
    for &bid in &right.boundary_ids {
        if let Some(&left_belief) = left.beliefs.get(&bid) {
            if let Some(&right_belief) = right.beliefs.get(&bid) {
                let diff = (left_belief - right_belief).abs();
                max_inconsistency = max_inconsistency.max(diff);
                boundary_count += 1;
                // Average at boundary
                combined.insert(bid, (left_belief + right_belief) / 2.0);
            }
        }
    }

    // Also check left boundary against right
    for &bid in &left.boundary_ids {
        if combined.contains_key(&bid) {
            continue; // Already processed
        }
        if let Some(&left_belief) = left.beliefs.get(&bid) {
            if let Some(&right_belief) = right.beliefs.get(&bid) {
                let diff = (left_belief - right_belief).abs();
                max_inconsistency = max_inconsistency.max(diff);
                boundary_count += 1;
                combined.insert(bid, (left_belief + right_belief) / 2.0);
            }
        }
    }

    // Merge right's non-shared nodes
    for (&id, &belief) in &right.beliefs {
        combined.entry(id).or_insert(belief);
    }

    CompositionResult {
        beliefs: combined,
        boundary_inconsistency: max_inconsistency,
        consistent: max_inconsistency <= consistency_threshold,
        boundary_size: boundary_count,
    }
}

// ── CDST-native cospan types ──────────────────────────────────────────────────

use crate::epistemic_interval::EpistemicInterval;

/// A subgraph decorated with EpistemicIntervals (CDST-aware).
#[derive(Debug, Clone)]
pub struct CdstDecoratedCospan {
    pub interior_ids: Vec<Uuid>,
    pub boundary_ids: Vec<Uuid>,
    pub intervals: HashMap<Uuid, EpistemicInterval>,
}

/// Detail about a single shared boundary node after composition.
#[derive(Debug, Clone)]
pub struct BoundaryDetail {
    pub node_id: Uuid,
    pub left_interval: EpistemicInterval,
    pub right_interval: EpistemicInterval,
    pub combined_interval: EpistemicInterval,
    pub hausdorff_distance: f64,
    pub open_world_max: f64,
}

/// Result of composing two CDST cospans.
#[derive(Debug, Clone)]
pub struct CdstCompositionResult {
    pub intervals: HashMap<Uuid, EpistemicInterval>,
    pub boundary_inconsistency: f64, // max Hausdorff
    pub consistent: bool,
    pub boundary_size: usize,
    pub boundary_details: Vec<BoundaryDetail>,
}

/// Compose two CDST cospans by gluing along shared boundary nodes.
///
/// At each shared boundary node:
/// - `bel` is averaged
/// - `pl` is averaged
/// - `open_world` takes the max (most conservative about frame completeness)
///
/// Reports the maximum Hausdorff distance across shared boundary nodes.
/// `consistent = max_hausdorff <= consistency_threshold`.
pub fn compose_cdst_cospans(
    left: &CdstDecoratedCospan,
    right: &CdstDecoratedCospan,
    consistency_threshold: f64,
) -> CdstCompositionResult {
    let mut combined = left.intervals.clone();
    let mut max_hausdorff: f64 = 0.0;
    let mut boundary_details: Vec<BoundaryDetail> = Vec::new();

    // Collect the set of shared boundary node IDs (in right's boundary that also appear in left).
    // Use a HashSet to avoid duplicate processing.
    let mut processed: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

    for &bid in &right.boundary_ids {
        if processed.contains(&bid) {
            continue;
        }
        if let (Some(&left_iv), Some(&right_iv)) =
            (left.intervals.get(&bid), right.intervals.get(&bid))
        {
            if left.boundary_ids.contains(&bid) || left.interior_ids.contains(&bid) {
                // This is a truly shared node — glue it
                let combined_bel = (left_iv.bel + right_iv.bel) / 2.0;
                let combined_pl = (left_iv.pl + right_iv.pl) / 2.0;
                let combined_ow = left_iv.open_world.max(right_iv.open_world);
                let combined_iv = EpistemicInterval::new(combined_bel, combined_pl, combined_ow);

                let hdist = left_iv.hausdorff_distance(&right_iv);
                max_hausdorff = max_hausdorff.max(hdist);

                boundary_details.push(BoundaryDetail {
                    node_id: bid,
                    left_interval: left_iv,
                    right_interval: right_iv,
                    combined_interval: combined_iv,
                    hausdorff_distance: hdist,
                    open_world_max: combined_ow,
                });

                combined.insert(bid, combined_iv);
                processed.insert(bid);
            }
        }
    }

    // Also check left boundary nodes that appear in right
    for &bid in &left.boundary_ids {
        if processed.contains(&bid) {
            continue;
        }
        if let (Some(&left_iv), Some(&right_iv)) =
            (left.intervals.get(&bid), right.intervals.get(&bid))
        {
            if right.boundary_ids.contains(&bid) || right.interior_ids.contains(&bid) {
                let combined_bel = (left_iv.bel + right_iv.bel) / 2.0;
                let combined_pl = (left_iv.pl + right_iv.pl) / 2.0;
                let combined_ow = left_iv.open_world.max(right_iv.open_world);
                let combined_iv = EpistemicInterval::new(combined_bel, combined_pl, combined_ow);

                let hdist = left_iv.hausdorff_distance(&right_iv);
                max_hausdorff = max_hausdorff.max(hdist);

                boundary_details.push(BoundaryDetail {
                    node_id: bid,
                    left_interval: left_iv,
                    right_interval: right_iv,
                    combined_interval: combined_iv,
                    hausdorff_distance: hdist,
                    open_world_max: combined_ow,
                });

                combined.insert(bid, combined_iv);
                processed.insert(bid);
            }
        }
    }

    let boundary_size = boundary_details.len();

    // Merge right's non-shared intervals
    for (&id, &iv) in &right.intervals {
        combined.entry(id).or_insert(iv);
    }

    CdstCompositionResult {
        intervals: combined,
        boundary_inconsistency: max_hausdorff,
        consistent: max_hausdorff <= consistency_threshold,
        boundary_size,
        boundary_details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_consistent() {
        let shared = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let left = DecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![shared],
            beliefs: HashMap::from([(a, 0.8), (shared, 0.7)]),
        };
        let right = DecoratedCospan {
            interior_ids: vec![b],
            boundary_ids: vec![shared],
            beliefs: HashMap::from([(b, 0.6), (shared, 0.72)]),
        };

        let result = compose_cospans(&left, &right, 0.1);
        assert!(result.consistent, "Small diff should be consistent");
        assert_eq!(result.boundary_size, 1);
        assert!((result.boundary_inconsistency - 0.02).abs() < 1e-9);
        // Shared node should be averaged
        let avg = result.beliefs.get(&shared).unwrap();
        assert!((avg - 0.71).abs() < 1e-9);
    }

    #[test]
    fn test_compose_inconsistent() {
        let shared = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let left = DecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![shared],
            beliefs: HashMap::from([(a, 0.9), (shared, 0.9)]),
        };
        let right = DecoratedCospan {
            interior_ids: vec![b],
            boundary_ids: vec![shared],
            beliefs: HashMap::from([(b, 0.3), (shared, 0.2)]),
        };

        let result = compose_cospans(&left, &right, 0.3);
        assert!(!result.consistent, "Large diff should be inconsistent");
        assert!((result.boundary_inconsistency - 0.7).abs() < 1e-9);
    }

    #[test]
    fn test_compose_no_shared_boundary() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();

        let left = DecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![b],
            beliefs: HashMap::from([(a, 0.8), (b, 0.7)]),
        };
        let right = DecoratedCospan {
            interior_ids: vec![c],
            boundary_ids: vec![d],
            beliefs: HashMap::from([(c, 0.6), (d, 0.5)]),
        };

        let result = compose_cospans(&left, &right, 0.1);
        assert!(
            result.consistent,
            "No shared boundary → trivially consistent"
        );
        assert_eq!(result.boundary_size, 0);
        assert_eq!(result.beliefs.len(), 4);
    }

    // ── CDST cospan tests ────────────────────────────────────────────────────

    #[test]
    fn test_cdst_compose_consistent() {
        let shared = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Left and right agree closely on the shared boundary node.
        let left_iv = EpistemicInterval::new(0.6, 0.8, 0.05);
        let right_iv = EpistemicInterval::new(0.62, 0.82, 0.04);

        let left = CdstDecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(a, EpistemicInterval::certain(0.9)), (shared, left_iv)]),
        };
        let right = CdstDecoratedCospan {
            interior_ids: vec![b],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(b, EpistemicInterval::certain(0.5)), (shared, right_iv)]),
        };

        let result = compose_cdst_cospans(&left, &right, 0.1);
        assert!(
            result.consistent,
            "Small Hausdorff diff should be consistent"
        );
        assert_eq!(result.boundary_size, 1);

        // Hausdorff = max(|0.6-0.62|, |0.8-0.82|) = 0.02
        assert!(
            (result.boundary_inconsistency - 0.02).abs() < 1e-9,
            "Expected Hausdorff ~0.02, got {}",
            result.boundary_inconsistency
        );

        // Combined bel = (0.6+0.62)/2 = 0.61
        let combined = result.intervals.get(&shared).unwrap();
        assert!((combined.bel - 0.61).abs() < 1e-9);
        // Combined pl = (0.8+0.82)/2 = 0.81
        assert!((combined.pl - 0.81).abs() < 1e-9);
        // open_world = max(0.05, 0.04) = 0.05
        assert!((combined.open_world - 0.05).abs() < 1e-9);

        // detail recorded correctly
        assert_eq!(result.boundary_details.len(), 1);
        assert_eq!(result.boundary_details[0].node_id, shared);
    }

    #[test]
    fn test_cdst_compose_inconsistent() {
        let shared = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Left strongly believes; right strongly disbelieves.
        let left_iv = EpistemicInterval::new(0.85, 0.95, 0.02);
        let right_iv = EpistemicInterval::new(0.05, 0.20, 0.03);

        let left = CdstDecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(a, EpistemicInterval::certain(0.9)), (shared, left_iv)]),
        };
        let right = CdstDecoratedCospan {
            interior_ids: vec![b],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(b, EpistemicInterval::certain(0.1)), (shared, right_iv)]),
        };

        // Hausdorff = max(|0.85-0.05|, |0.95-0.20|) = max(0.80, 0.75) = 0.80
        let result = compose_cdst_cospans(&left, &right, 0.3);
        assert!(
            !result.consistent,
            "Large Hausdorff diff should be inconsistent"
        );
        assert!((result.boundary_inconsistency - 0.80).abs() < 1e-9);
    }

    #[test]
    fn test_cdst_compose_no_shared_boundary() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();

        let left = CdstDecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![b],
            intervals: HashMap::from([
                (a, EpistemicInterval::certain(0.8)),
                (b, EpistemicInterval::new(0.6, 0.9, 0.1)),
            ]),
        };
        let right = CdstDecoratedCospan {
            interior_ids: vec![c],
            boundary_ids: vec![d],
            intervals: HashMap::from([
                (c, EpistemicInterval::certain(0.4)),
                (d, EpistemicInterval::new(0.3, 0.7, 0.2)),
            ]),
        };

        let result = compose_cdst_cospans(&left, &right, 0.1);
        assert!(
            result.consistent,
            "No shared boundary → trivially consistent"
        );
        assert_eq!(result.boundary_size, 0);
        assert_eq!(result.boundary_inconsistency, 0.0);
        assert_eq!(result.intervals.len(), 4);
        assert!(result.boundary_details.is_empty());
    }

    #[test]
    fn test_cdst_compose_open_world_propagates() {
        // Verify open_world takes the max at the shared boundary node.
        let shared = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Left has low OW, right has high OW — combined should take max.
        let left_iv = EpistemicInterval::new(0.5, 0.7, 0.05);
        let right_iv = EpistemicInterval::new(0.5, 0.7, 0.18);

        let left = CdstDecoratedCospan {
            interior_ids: vec![a],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(a, EpistemicInterval::certain(0.6)), (shared, left_iv)]),
        };
        let right = CdstDecoratedCospan {
            interior_ids: vec![b],
            boundary_ids: vec![shared],
            intervals: HashMap::from([(b, EpistemicInterval::certain(0.4)), (shared, right_iv)]),
        };

        let result = compose_cdst_cospans(&left, &right, 0.1);
        assert!(result.consistent);
        let combined = result.intervals.get(&shared).unwrap();
        // open_world should be max(0.05, 0.18) = 0.18
        assert!(
            (combined.open_world - 0.18).abs() < 1e-9,
            "open_world should be max(0.05, 0.18) = 0.18, got {}",
            combined.open_world
        );
        // bel and pl are averaged: (0.5+0.5)/2 = 0.5, (0.7+0.7)/2 = 0.7
        assert!((combined.bel - 0.5).abs() < 1e-9);
        assert!((combined.pl - 0.7).abs() < 1e-9);
    }
}
