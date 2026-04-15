//! Submodular diverse selection for retrieval (xMemory-inspired)
//!
//! Given candidate items with query similarities and a neighborhood graph,
//! greedily selects a subset that maximizes coverage of the graph while
//! maintaining relevance to the query.
//!
//! Based on xMemory Equation 4:
//! i* = argmax_{i in V\R} [ alpha * coverage_gain(i) + (1-alpha) * similarity(q,i) ]

/// Greedy submodular selection balancing coverage and relevance.
///
/// # Arguments
/// * `neighbors` - Neighborhood graph: neighbors[i] = indices of i's neighbors
/// * `similarities` - Query-to-candidate similarity scores (normalized 0..1)
/// * `budget` - Maximum number of items to select
/// * `alpha` - Coverage vs relevance tradeoff (0.0 = pure relevance, 1.0 = pure coverage)
///
/// # Returns
/// Indices of selected items in selection order.
pub fn diverse_select(
    neighbors: &[Vec<usize>],
    similarities: &[f32],
    budget: usize,
    alpha: f32,
) -> Vec<usize> {
    let n = neighbors.len();
    if n == 0 || budget == 0 {
        return vec![];
    }

    let mut selected: Vec<usize> = Vec::with_capacity(budget);
    let mut covered: Vec<bool> = vec![false; n];

    for _ in 0..budget {
        let mut best_idx = None;
        let mut best_score = f32::NEG_INFINITY;

        for i in 0..n {
            // Skip already selected
            if covered[i] && selected.contains(&i) {
                continue;
            }
            if selected.contains(&i) {
                continue;
            }

            // Coverage gain: count newly covered nodes
            let mut new_coverage = if !covered[i] { 1u32 } else { 0 };
            for &nb in &neighbors[i] {
                if !covered[nb] {
                    new_coverage += 1;
                }
            }

            // Normalize coverage gain by max possible (neighborhood size + 1)
            let max_coverage = (neighbors[i].len() + 1) as f32;
            let coverage_score = new_coverage as f32 / max_coverage.max(1.0);

            // Combined score
            let sim = similarities.get(i).copied().unwrap_or(0.0);
            let score = alpha * coverage_score + (1.0 - alpha) * sim;

            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }

        match best_idx {
            Some(idx) => {
                selected.push(idx);
                covered[idx] = true;
                for &nb in &neighbors[idx] {
                    covered[nb] = true;
                }
            }
            None => break,
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diverse_select_covers_all_neighborhoods() {
        // 6 candidates in 2 clusters: {0,1,2} and {3,4,5}
        // Neighbors: 0->{1,2}, 1->{0,2}, 2->{0,1}, 3->{4,5}, 4->{3,5}, 5->{3,4}
        let neighbors: Vec<Vec<usize>> = vec![
            vec![1, 2],
            vec![0, 2],
            vec![0, 1],
            vec![4, 5],
            vec![3, 5],
            vec![3, 4],
        ];
        let similarities = vec![0.9, 0.8, 0.7, 0.6, 0.5, 0.4];
        let result = diverse_select(&neighbors, &similarities, 2, 0.5);
        // Should pick one from each cluster
        assert_eq!(result.len(), 2);
        let has_cluster_a = result.iter().any(|&r| r <= 2);
        let has_cluster_b = result.iter().any(|&r| r >= 3);
        assert!(
            has_cluster_a && has_cluster_b,
            "Should cover both clusters: {result:?}"
        );
    }

    #[test]
    fn test_diverse_select_respects_budget() {
        let neighbors: Vec<Vec<usize>> = vec![vec![1], vec![0], vec![3], vec![2]];
        let similarities = vec![0.9, 0.8, 0.7, 0.6];
        let result = diverse_select(&neighbors, &similarities, 3, 0.5);
        assert!(result.len() <= 3);
    }

    #[test]
    fn test_diverse_select_empty_input() {
        let result = diverse_select(&[], &[], 5, 0.5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_diverse_select_pure_relevance() {
        // alpha=0: pure relevance, should pick highest similarity
        let neighbors: Vec<Vec<usize>> = vec![vec![1], vec![0], vec![3], vec![2]];
        let similarities = vec![0.1, 0.2, 0.9, 0.8];
        let result = diverse_select(&neighbors, &similarities, 1, 0.0);
        assert_eq!(result, vec![2]); // highest similarity
    }

    #[test]
    fn test_diverse_select_pure_coverage() {
        // alpha=1: pure coverage, should maximize covered set
        let neighbors: Vec<Vec<usize>> = vec![
            vec![1, 2, 3], // covers 4 nodes
            vec![0],       // covers 2 nodes
            vec![0],       // covers 2 nodes
            vec![0],       // covers 2 nodes
        ];
        let similarities = vec![0.1, 0.9, 0.9, 0.9];
        let result = diverse_select(&neighbors, &similarities, 1, 1.0);
        assert_eq!(result, vec![0]); // most coverage despite lowest similarity
    }
}
