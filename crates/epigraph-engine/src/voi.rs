//! Value-of-Information (VOI) computation for hypothesis assessment.
//!
//! VOI = mean(belief_gap_i * similarity_i) for neighbors within search radius.
//! Higher VOI means the hypothesis is in a region of high ignorance where
//! new evidence would have high impact.

/// A neighbor claim with its belief interval and similarity to the hypothesis.
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub belief: f64,
    pub plausibility: f64,
    pub similarity: f64,
}

/// VOI computation result.
#[derive(Debug, Clone)]
pub struct VoiResult {
    pub score: f64,
    pub neighbor_count: usize,
    pub avg_belief_gap: f64,
    pub ignorance_breakdown: IgnoranceBreakdown,
}

/// Breakdown of ignorance types in the neighborhood.
#[derive(Debug, Clone)]
pub struct IgnoranceBreakdown {
    /// Count of neighbors with high open-world ignorance (m(~) > 0.10)
    pub high_open_world: usize,
    /// Count of neighbors with high frame ignorance (m(Theta) > 0.15)
    pub high_frame_ignorance: usize,
}

/// Compute VOI from a set of neighbors.
///
/// VOI = mean(belief_gap_i * similarity_i) where belief_gap = plausibility - belief.
/// Returns 0.0 if no neighbors (understudied region — may still be valuable).
pub fn compute_voi(neighbors: &[Neighbor]) -> VoiResult {
    if neighbors.is_empty() {
        return VoiResult {
            score: 0.0,
            neighbor_count: 0,
            avg_belief_gap: 0.0,
            ignorance_breakdown: IgnoranceBreakdown {
                high_open_world: 0,
                high_frame_ignorance: 0,
            },
        };
    }

    let mut total_weighted_gap = 0.0;
    let mut total_gap = 0.0;

    for n in neighbors {
        let gap = (n.plausibility - n.belief).max(0.0);
        total_weighted_gap += gap * n.similarity;
        total_gap += gap;
    }

    let n = neighbors.len() as f64;

    VoiResult {
        score: total_weighted_gap / n,
        neighbor_count: neighbors.len(),
        avg_belief_gap: total_gap / n,
        ignorance_breakdown: IgnoranceBreakdown {
            high_open_world: neighbors
                .iter()
                .filter(|n| (n.plausibility - n.belief) > 0.5)
                .count(),
            high_frame_ignorance: neighbors
                .iter()
                .filter(|n| {
                    let gap = n.plausibility - n.belief;
                    gap > 0.15 && gap <= 0.5
                })
                .count(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_neighborhood_returns_zero() {
        let result = compute_voi(&[]);
        assert_eq!(result.score, 0.0);
        assert_eq!(result.neighbor_count, 0);
    }

    #[test]
    fn high_ignorance_high_similarity_gives_high_voi() {
        let neighbors = vec![
            Neighbor {
                belief: 0.3,
                plausibility: 0.9,
                similarity: 0.95,
            },
            Neighbor {
                belief: 0.2,
                plausibility: 0.8,
                similarity: 0.90,
            },
        ];
        let result = compute_voi(&neighbors);
        assert!(
            result.score > 0.4,
            "High ignorance + high similarity → high VOI: {}",
            result.score
        );
        assert_eq!(result.neighbor_count, 2);
    }

    #[test]
    fn low_ignorance_gives_low_voi() {
        let neighbors = vec![
            Neighbor {
                belief: 0.85,
                plausibility: 0.90,
                similarity: 0.95,
            },
            Neighbor {
                belief: 0.80,
                plausibility: 0.85,
                similarity: 0.90,
            },
        ];
        let result = compute_voi(&neighbors);
        assert!(
            result.score < 0.10,
            "Low ignorance → low VOI: {}",
            result.score
        );
    }

    #[test]
    fn low_similarity_reduces_voi() {
        let high_sim = vec![Neighbor {
            belief: 0.3,
            plausibility: 0.9,
            similarity: 0.95,
        }];
        let low_sim = vec![Neighbor {
            belief: 0.3,
            plausibility: 0.9,
            similarity: 0.30,
        }];
        let r_high = compute_voi(&high_sim);
        let r_low = compute_voi(&low_sim);
        assert!(r_high.score > r_low.score);
    }

    #[test]
    fn voi_normalized_by_count() {
        let one = vec![Neighbor {
            belief: 0.3,
            plausibility: 0.9,
            similarity: 0.95,
        }];
        let three = vec![
            Neighbor {
                belief: 0.3,
                plausibility: 0.9,
                similarity: 0.95,
            },
            Neighbor {
                belief: 0.85,
                plausibility: 0.90,
                similarity: 0.90,
            },
            Neighbor {
                belief: 0.80,
                plausibility: 0.85,
                similarity: 0.85,
            },
        ];
        let r1 = compute_voi(&one);
        let r3 = compute_voi(&three);
        assert!(r3.score < r1.score);
    }
}
