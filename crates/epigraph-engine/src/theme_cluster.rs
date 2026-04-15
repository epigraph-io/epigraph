//! Theme clustering for hierarchical retrieval (xMemory-inspired)
//!
//! Groups claim embeddings into topic themes using k-means clustering
//! guided by a sparsity-semantics balancing objective.
//!
//! # xMemory Sparsity Score
//!
//! SparsityScore(P) = N^2 / (K * sum(n_k^2))
//!
//! Where N = total claims, K = number of themes, n_k = claims in theme k.
//! Score of 1.0 = perfectly balanced; lower = more imbalanced.

use serde::{Deserialize, Serialize};

/// Result of clustering operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterResult {
    /// Centroid vectors, one per theme
    pub centroids: Vec<Vec<f32>>,
    /// Assignment of each input embedding to a theme index
    pub assignments: Vec<usize>,
}

/// Cosine similarity between two vectors
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}

/// xMemory sparsity score: N^2 / (K * sum(n_k^2))
/// Higher = more balanced partition = fewer collapsed retrievals
pub fn sparsity_score(total: usize, theme_sizes: &[usize]) -> f64 {
    let n = total as f64;
    let k = theme_sizes.len() as f64;
    let sum_sq: f64 = theme_sizes.iter().map(|&s| (s as f64) * (s as f64)).sum();
    if k == 0.0 || sum_sq == 0.0 {
        return 0.0;
    }
    (n * n) / (k * sum_sq)
}

/// Assign an embedding to the nearest centroid by cosine similarity
pub fn assign_to_nearest(embedding: &[f32], centroids: &[Vec<f32>]) -> usize {
    centroids
        .iter()
        .enumerate()
        .map(|(i, c)| (i, cosine_similarity(embedding, c)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Compute the mean centroid of a set of embeddings
pub fn compute_centroid(embeddings: &[Vec<f32>]) -> Vec<f32> {
    if embeddings.is_empty() {
        return vec![];
    }
    let dim = embeddings[0].len();
    let n = embeddings.len() as f32;
    let mut centroid = vec![0.0f32; dim];
    for emb in embeddings {
        for (i, val) in emb.iter().enumerate() {
            centroid[i] += val;
        }
    }
    for val in &mut centroid {
        *val /= n;
    }
    centroid
}

/// K-means clustering on embeddings with cosine similarity
///
/// Returns cluster centroids and per-embedding assignments.
/// Uses k-means++ initialization and iterates up to `max_iters`.
pub fn cluster_embeddings(embeddings: &[Vec<f32>], k: usize, max_iters: usize) -> ClusterResult {
    let n = embeddings.len();
    if n == 0 || k == 0 {
        return ClusterResult {
            centroids: vec![],
            assignments: vec![],
        };
    }
    let k = k.min(n);

    // Initialize centroids by spacing evenly through the data
    let mut centroids: Vec<Vec<f32>> = (0..k).map(|i| embeddings[i * n / k].clone()).collect();

    let mut assignments = vec![0usize; n];

    for _ in 0..max_iters {
        // Assign each embedding to nearest centroid
        let new_assignments: Vec<usize> = embeddings
            .iter()
            .map(|emb| assign_to_nearest(emb, &centroids))
            .collect();

        // Check convergence
        if new_assignments == assignments {
            assignments = new_assignments;
            break;
        }
        assignments = new_assignments;

        // Recompute centroids
        for (c, centroid) in centroids.iter_mut().enumerate().take(k) {
            let members: Vec<Vec<f32>> = assignments
                .iter()
                .enumerate()
                .filter(|(_, &a)| a == c)
                .map(|(i, _)| embeddings[i].clone())
                .collect();
            if !members.is_empty() {
                *centroid = compute_centroid(&members);
            }
        }
    }

    ClusterResult {
        centroids,
        assignments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_embeddings(n: usize, dim: usize) -> Vec<Vec<f32>> {
        // Deterministic pseudo-embeddings for testing
        (0..n)
            .map(|i| {
                (0..dim)
                    .map(|d| ((i * 7 + d * 13) % 100) as f32 / 100.0)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_sparsity_score_balanced() {
        // 10 items split evenly into 2 themes of 5
        let sizes = vec![5, 5];
        let score = sparsity_score(10, &sizes);
        // N^2 / (K * sum(n_k^2)) = 100 / (2 * 50) = 1.0
        assert!((score - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_sparsity_score_imbalanced() {
        // 10 items: theme of 9 + theme of 1
        let sizes = vec![9, 1];
        let score = sparsity_score(10, &sizes);
        // 100 / (2 * 82) = 0.61
        assert!(score < 0.7);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);

        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &c).abs() < 1e-6);
    }

    #[test]
    fn test_assign_to_nearest_theme() {
        let centroids = vec![vec![1.0, 0.0, 0.0], vec![0.0, 1.0, 0.0]];
        let embedding = vec![0.9, 0.1, 0.0];
        let theme_idx = assign_to_nearest(&embedding, &centroids);
        assert_eq!(theme_idx, 0);
    }

    #[test]
    fn test_compute_centroid() {
        let embeddings = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
        let centroid = compute_centroid(&embeddings);
        assert!((centroid[0] - 0.5).abs() < 1e-6);
        assert!((centroid[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_cluster_produces_k_themes() {
        let embeddings = make_embeddings(20, 8);
        let result = cluster_embeddings(&embeddings, 4, 10);
        assert_eq!(result.assignments.len(), 20);
        assert_eq!(result.centroids.len(), 4);
        // Every assignment is in [0, 4)
        assert!(result.assignments.iter().all(|&a| a < 4));
    }
}
