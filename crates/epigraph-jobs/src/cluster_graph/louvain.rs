//! Minimal Louvain community detection over an undirected weighted graph.
//!
//! v1: unsigned, single-level (no community aggregation pass). This is enough
//! for the visualizer's nightly job at the scales we care about (≤ ~10⁵
//! nodes, sparse). If quality at scale is insufficient, add a
//! community-aggregation outer loop here without changing the public API.

use std::collections::HashMap;

use rand::{seq::SliceRandom, SeedableRng};
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub struct LouvainInput {
    pub node_count: usize,
    /// (a, b, w) — undirected, a != b. Self-loops are ignored.
    pub edges: Vec<(u32, u32, f64)>,
    pub resolution: f64,
}

#[derive(Debug, Clone)]
pub struct LouvainResult {
    /// `assignments[node_id]` = community id (0-based, dense).
    pub assignments: Vec<u32>,
    pub modularity: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum LouvainError {
    #[error("invalid edge: node id {node} >= node_count {node_count}")]
    InvalidEdge { node: u32, node_count: usize },
}

pub fn louvain(input: &LouvainInput) -> Result<LouvainResult, LouvainError> {
    let n = input.node_count;
    if n == 0 {
        return Ok(LouvainResult { assignments: Vec::new(), modularity: 0.0 });
    }

    // Build adjacency: adj[node] -> Vec<(neighbor, weight)>.
    let mut adj: Vec<Vec<(u32, f64)>> = vec![Vec::new(); n];
    let mut total_weight: f64 = 0.0;
    for &(a, b, w) in &input.edges {
        if (a as usize) >= n {
            return Err(LouvainError::InvalidEdge { node: a, node_count: n });
        }
        if (b as usize) >= n {
            return Err(LouvainError::InvalidEdge { node: b, node_count: n });
        }
        if a == b { continue; } // ignore self-loops
        adj[a as usize].push((b, w));
        adj[b as usize].push((a, w));
        total_weight += w;
    }
    let two_m = 2.0 * total_weight;
    if two_m == 0.0 {
        // No edges: every node is its own community.
        let assignments: Vec<u32> = (0..n as u32).collect();
        return Ok(LouvainResult { assignments, modularity: 0.0 });
    }

    // Each node starts in its own community.
    let mut comm: Vec<u32> = (0..n as u32).collect();

    // k_i = sum of weights incident to node i.
    let k: Vec<f64> = adj.iter()
        .map(|nbrs| nbrs.iter().map(|(_, w)| *w).sum())
        .collect();

    // Σ_tot[c] = sum of k_i for i in community c (initially k_i for each node).
    let mut sigma_tot: HashMap<u32, f64> = (0..n as u32).map(|i| (i, k[i as usize])).collect();

    // Stable seed for deterministic test runs.
    let mut rng = StdRng::seed_from_u64(0x10A4_017E_13BC_0DEFu64);
    let resolution = input.resolution;

    // Single-level greedy modularity optimization.
    // Sweep through nodes in random order; move each to the neighbor community
    // that maximizes Δmodularity. Repeat until a sweep produces no moves.
    let mut order: Vec<usize> = (0..n).collect();
    let mut moved = true;
    let mut iter = 0u32;
    while moved && iter < 32 {
        moved = false;
        order.shuffle(&mut rng);
        for &i in &order {
            // Remove i from its current community for the calculation.
            let ci = comm[i];
            let ki = k[i];
            let st_ci = *sigma_tot.get(&ci).unwrap_or(&0.0) - ki;
            sigma_tot.insert(ci, st_ci);
            comm[i] = u32::MAX; // sentinel: not in any community

            // Build map: neighbor community -> sum of weights from i into that community.
            let mut k_i_in: HashMap<u32, f64> = HashMap::new();
            for &(j, w) in &adj[i] {
                if (j as usize) == i { continue; }
                let cj = comm[j as usize];
                if cj == u32::MAX { continue; }
                *k_i_in.entry(cj).or_insert(0.0) += w;
            }

            // Score candidate communities: ci itself + every neighbor community.
            // Δmod for moving i into c: k_i_in[c] / m  -  resolution * k_i * Σ_tot[c] / (2 m^2)
            let mut best_c = ci;
            let mut best_delta = 0.0_f64;
            // Always allow staying in ci.
            for &c in std::iter::once(&ci).chain(k_i_in.keys()) {
                let kin = *k_i_in.get(&c).unwrap_or(&0.0);
                let st = *sigma_tot.get(&c).unwrap_or(&0.0);
                let delta = (kin / total_weight)
                    - resolution * (ki * st) / (2.0 * total_weight * total_weight);
                if delta > best_delta + 1e-12 {
                    best_delta = delta;
                    best_c = c;
                }
            }

            // Place i into best_c.
            comm[i] = best_c;
            let st = *sigma_tot.get(&best_c).unwrap_or(&0.0) + ki;
            sigma_tot.insert(best_c, st);
            if best_c != ci {
                moved = true;
            }
        }
        iter += 1;
    }

    // Densify community ids (0-based contiguous).
    let mut remap: HashMap<u32, u32> = HashMap::new();
    let assignments: Vec<u32> = comm.iter().map(|c| {
        let next = remap.len() as u32;
        *remap.entry(*c).or_insert(next)
    }).collect();

    // Compute modularity for diagnostic output.
    let modularity = compute_modularity(&adj, &assignments, total_weight, resolution);
    Ok(LouvainResult { assignments, modularity })
}

fn compute_modularity(
    adj: &[Vec<(u32, f64)>],
    assignments: &[u32],
    total_weight: f64,
    resolution: f64,
) -> f64 {
    if total_weight == 0.0 { return 0.0; }
    let n = adj.len();
    let mut k = vec![0.0_f64; n];
    for (i, nbrs) in adj.iter().enumerate() {
        k[i] = nbrs.iter().map(|(_, w)| *w).sum();
    }
    let mut q = 0.0_f64;
    for i in 0..n {
        for &(j, w) in &adj[i] {
            if assignments[i] == assignments[j as usize] {
                q += w - resolution * k[i] * k[j as usize] / (2.0 * total_weight);
            }
        }
    }
    q / (2.0 * total_weight)
}
