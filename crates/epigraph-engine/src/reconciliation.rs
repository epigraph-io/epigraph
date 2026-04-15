//! Phase 2 reconciliation orchestrator for CDST sheaf obstructions.
//!
//! Clusters obstructions by connected node components (union-find), extracts
//! [`CdstDecoratedCospan`] sub-graphs, runs [`run_interval_bp`] within each
//! scope, and collects updated intervals and frame evidence proposals.
//!
//! Clusters exceeding `max_cluster_size` nodes are not processed by BP — they
//! are returned as [`ClusterSummary`] entries in
//! [`ReconciliationResult::oversized_clusters`].

use std::collections::HashMap;

use uuid::Uuid;

use crate::bp::FactorPotential;
use crate::cdst_sheaf::{CdstSheafObstruction, FrameEvidenceProposal};
use crate::cospan::CdstDecoratedCospan;
use crate::epistemic_interval::EpistemicInterval;
use crate::interval_bp::{run_interval_bp, IntervalBpConfig};

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the reconciliation orchestrator.
#[derive(Debug, Clone)]
pub struct ReconciliationConfig {
    /// Minimum `interval_inconsistency` for an obstruction to be processed.
    /// Obstructions below this threshold are ignored. Default 0.15.
    pub min_inconsistency: f64,
    /// Maximum number of re-check (outer) iterations. Default 3.
    pub max_depth: usize,
    /// Maximum cluster size (node count) before it is reported as oversized
    /// and skipped. Default 50.
    pub max_cluster_size: usize,
    /// Configuration forwarded to [`run_interval_bp`].
    pub bp_config: IntervalBpConfig,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            min_inconsistency: 0.15,
            max_depth: 3,
            max_cluster_size: 50,
            bp_config: IntervalBpConfig::default(),
        }
    }
}

// ── Output types ───────────────────────────────────────────────────────────

/// Summary of a cluster that was too large to process.
#[derive(Debug, Clone)]
pub struct ClusterSummary {
    /// Number of unique node IDs in the cluster.
    pub node_count: usize,
    /// Number of obstructions (edges) in the cluster.
    pub obstruction_count: usize,
    /// Maximum `interval_inconsistency` among the cluster's obstructions.
    pub max_inconsistency: f64,
}

/// A cluster that was skipped during BP reconciliation, with diagnostic
/// information to aid investigation.
#[derive(Debug, Clone)]
pub struct SkippedCluster {
    /// Number of unique node IDs in the cluster.
    pub size: usize,
    /// Up to 5 representative node IDs sampled from the cluster.
    pub sample_ids: Vec<Uuid>,
    /// Human-readable reason the cluster was not processed.
    pub reason: String,
}

/// Result of a full reconciliation run.
#[derive(Debug, Clone)]
pub struct ReconciliationResult {
    /// (`node_id`, `updated_interval`) pairs for every variable updated by BP.
    pub updated_intervals: Vec<(Uuid, EpistemicInterval)>,
    /// Frame evidence proposals collected from all BP runs.
    pub frame_evidence_proposals: Vec<FrameEvidenceProposal>,
    /// Summaries of clusters that exceeded `max_cluster_size`.
    pub oversized_clusters: Vec<ClusterSummary>,
    /// Clusters that were skipped for any reason, with diagnostic samples.
    pub skipped_clusters: Vec<SkippedCluster>,
    /// Number of clusters that were successfully processed by BP.
    pub clusters_processed: usize,
    /// True iff every processed cluster's BP run converged.
    pub converged: bool,
    /// Total BP iterations consumed across all processed clusters and depth
    /// steps.
    pub total_iterations: usize,
}

// ── Union-find (path-compressed, union-by-rank) ────────────────────────────

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            // Path-halving for amortised O(α(n)) complexity.
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
        // Union by rank.
        match self.rank[rx].cmp(&self.rank[ry]) {
            std::cmp::Ordering::Less => self.parent[rx] = ry,
            std::cmp::Ordering::Greater => self.parent[ry] = rx,
            std::cmp::Ordering::Equal => {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
    }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Cluster a slice of obstructions by connected node components.
///
/// Two obstructions are in the same cluster if they share at least one node ID
/// (either `source_id` or `target_id`).  Returns one `Vec` per connected
/// component, each containing references to its obstructions.
///
/// Empty input returns an empty `Vec`.
#[must_use]
pub fn cluster_obstructions(
    obstructions: &[CdstSheafObstruction],
) -> Vec<Vec<&CdstSheafObstruction>> {
    if obstructions.is_empty() {
        return Vec::new();
    }

    // Collect all unique node IDs and assign a compact index.
    let mut node_index: HashMap<Uuid, usize> = HashMap::new();
    for obs in obstructions {
        let n = node_index.len();
        node_index.entry(obs.source_id).or_insert(n);
        let n = node_index.len();
        node_index.entry(obs.target_id).or_insert(n);
    }

    let node_count = node_index.len();
    let mut uf = UnionFind::new(node_count);

    // Union source and target for each obstruction.
    for obs in obstructions {
        let si = node_index[&obs.source_id];
        let ti = node_index[&obs.target_id];
        uf.union(si, ti);
    }

    // Group obstructions by their root representative.
    let mut groups: HashMap<usize, Vec<&CdstSheafObstruction>> = HashMap::new();
    for obs in obstructions {
        let root = uf.find(node_index[&obs.source_id]);
        groups.entry(root).or_default().push(obs);
    }

    groups.into_values().collect()
}

/// Extract a [`CdstDecoratedCospan`] from a cluster of obstructions.
///
/// Interior nodes = unique node IDs appearing in the cluster's obstructions.
/// Boundary nodes = empty (the caller owns the boundary semantics; anchoring
/// is handled at the BP call site by not modifying boundary entries).
///
/// The cospan's `intervals` map is populated from `all_intervals` for every
/// interior node.  Nodes absent from `all_intervals` receive
/// [`EpistemicInterval::VACUOUS`].
#[must_use]
pub fn extract_cospan(
    cluster: &[&CdstSheafObstruction],
    all_intervals: &HashMap<Uuid, EpistemicInterval>,
) -> CdstDecoratedCospan {
    // Collect unique interior node IDs from all edges in the cluster.
    let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for obs in cluster {
        seen.insert(obs.source_id);
        seen.insert(obs.target_id);
    }
    let interior_ids: Vec<Uuid> = seen.into_iter().collect();

    let intervals: HashMap<Uuid, EpistemicInterval> = interior_ids
        .iter()
        .map(|&id| {
            let iv = all_intervals
                .get(&id)
                .copied()
                .unwrap_or(EpistemicInterval::VACUOUS);
            (id, iv)
        })
        .collect();

    CdstDecoratedCospan {
        interior_ids,
        boundary_ids: Vec::new(), // caller-managed; no DB access here
        intervals,
    }
}

/// Run the full reconciliation loop.
///
/// # Arguments
/// * `obstructions` — detected sheaf obstructions (will be filtered by
///   `config.min_inconsistency` before clustering).
/// * `all_intervals` — current epistemic intervals for all nodes in scope.
/// * `factors` — factor graph entries `(factor_id, potential, variable_ids)`.
///   Only factors whose variables are all present in a cluster's scope are
///   forwarded to that cluster's BP run.
/// * `config` — reconciliation parameters.
///
/// # Behaviour
///
/// 1. Filter obstructions below `min_inconsistency`.
/// 2. Cluster via union-find.
/// 3. For each cluster:
///    - If `node_count > max_cluster_size`, record as oversized and skip.
///    - Otherwise extract cospan and run interval BP (up to `max_depth`
///      outer iterations).
/// 4. Collect all updated intervals and frame evidence proposals.
pub fn reconcile(
    obstructions: Vec<CdstSheafObstruction>,
    all_intervals: &HashMap<Uuid, EpistemicInterval>,
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    config: &ReconciliationConfig,
) -> ReconciliationResult {
    // Step 1: filter by min_inconsistency.
    let filtered: Vec<CdstSheafObstruction> = obstructions
        .into_iter()
        .filter(|o| o.interval_inconsistency >= config.min_inconsistency)
        .collect();

    if filtered.is_empty() {
        return ReconciliationResult {
            updated_intervals: Vec::new(),
            frame_evidence_proposals: Vec::new(),
            oversized_clusters: Vec::new(),
            skipped_clusters: Vec::new(),
            clusters_processed: 0,
            converged: true,
            total_iterations: 0,
        };
    }

    // Step 2: cluster.
    let clusters = cluster_obstructions(&filtered);

    let mut all_updated: Vec<(Uuid, EpistemicInterval)> = Vec::new();
    let mut all_proposals: Vec<FrameEvidenceProposal> = Vec::new();
    let mut oversized: Vec<ClusterSummary> = Vec::new();
    let mut skipped: Vec<SkippedCluster> = Vec::new();
    let mut clusters_processed = 0usize;
    let mut all_converged = true;
    let mut total_iterations = 0usize;

    for cluster in &clusters {
        // Collect unique node IDs to determine cluster size.
        let mut node_set: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        for obs in cluster {
            node_set.insert(obs.source_id);
            node_set.insert(obs.target_id);
        }
        let node_count = node_set.len();

        // Step 3a: oversized check.
        if node_count > config.max_cluster_size {
            let max_incon = cluster
                .iter()
                .map(|o| o.interval_inconsistency)
                .fold(0.0f64, f64::max);

            // Collect up to 5 sample node IDs for diagnostics.
            let sample_ids: Vec<Uuid> = node_set.iter().copied().take(5).collect();
            let reason = format!(
                "cluster size {} exceeds max_cluster_size {}",
                node_count, config.max_cluster_size
            );

            tracing::warn!(
                node_count,
                obstruction_count = cluster.len(),
                max_inconsistency = max_incon,
                ?sample_ids,
                "reconcile: skipping oversized cluster — {reason}"
            );

            oversized.push(ClusterSummary {
                node_count,
                obstruction_count: cluster.len(),
                max_inconsistency: max_incon,
            });
            skipped.push(SkippedCluster {
                size: node_count,
                sample_ids,
                reason,
            });
            continue;
        }

        // Step 3b: extract cospan from the current best-known intervals.
        // We maintain a local copy of intervals that gets updated across
        // `max_depth` outer iterations.
        let mut local_intervals = all_intervals.clone();

        // Filter factors to those whose variable IDs are all within the
        // cluster's node set (or at least one variable overlaps — we include
        // factors with ≥1 variable in the scope to allow BP to propagate
        // through boundary-adjacent factors).
        //
        // Policy: include a factor if ANY of its variables is in the cluster
        // scope. Variables outside the scope keep their `local_intervals`
        // values (acting as soft anchors).
        let cluster_factors: Vec<(Uuid, FactorPotential, Vec<Uuid>)> = factors
            .iter()
            .filter(|(_, _, vars)| vars.iter().any(|v| node_set.contains(v)))
            .cloned()
            .collect();

        let mut cluster_converged = false;
        let mut cluster_iterations = 0usize;

        for _depth in 0..config.max_depth {
            let cospan = extract_cospan(cluster, &local_intervals);

            let bp_result = run_interval_bp(&cluster_factors, &cospan.intervals, &config.bp_config);

            cluster_iterations += bp_result.iterations;
            all_proposals.extend(bp_result.frame_evidence_proposals);

            // Merge updated intervals back into local_intervals for the next
            // depth step.
            for (id, iv) in &bp_result.updated_intervals {
                local_intervals.insert(*id, *iv);
            }

            if bp_result.converged {
                cluster_converged = true;
                break;
            }
        }

        if !cluster_converged {
            all_converged = false;
        }

        // Collect only the cluster's own node intervals (not the full map).
        for id in &node_set {
            if let Some(&iv) = local_intervals.get(id) {
                all_updated.push((*id, iv));
            }
        }

        total_iterations += cluster_iterations;
        clusters_processed += 1;
    }

    ReconciliationResult {
        updated_intervals: all_updated,
        frame_evidence_proposals: all_proposals,
        oversized_clusters: oversized,
        skipped_clusters: skipped,
        clusters_processed,
        converged: all_converged,
        total_iterations,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdst_sheaf::ObstructionKind;

    // Helper: build a minimal CdstSheafObstruction from two node IDs and an
    // inconsistency score.
    fn make_obs(source_id: Uuid, target_id: Uuid, inconsistency: f64) -> CdstSheafObstruction {
        let iv = EpistemicInterval::VACUOUS;
        CdstSheafObstruction {
            source_id,
            target_id,
            relationship: "supports".to_string(),
            source_interval: iv,
            target_interval: iv,
            expected_interval: iv,
            interval_inconsistency: inconsistency,
            conflict_component: inconsistency,
            ignorance_component: 0.0,
            open_world_component: 0.0,
            obstruction_kind: ObstructionKind::BeliefConflict,
        }
    }

    // ── test_cluster_disjoint ───────────────────────────────────────────────

    /// Obstructions sharing no node IDs must form separate clusters.
    #[test]
    fn test_cluster_disjoint() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let d = Uuid::new_v4();

        // Two edges: a→b and c→d, no shared nodes.
        let obs = vec![make_obs(a, b, 0.5), make_obs(c, d, 0.4)];
        let clusters = cluster_obstructions(&obs);

        assert_eq!(
            clusters.len(),
            2,
            "Disjoint obstructions must form 2 clusters, got {}",
            clusters.len()
        );

        // Each cluster must have exactly one obstruction.
        for c in &clusters {
            assert_eq!(c.len(), 1);
        }
    }

    // ── test_cluster_connected ─────────────────────────────────────────────

    /// Obstructions that share a node ID must merge into one cluster.
    #[test]
    fn test_cluster_connected() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        // a→b and b→c: both share node b → one cluster.
        let obs = vec![make_obs(a, b, 0.3), make_obs(b, c, 0.4)];
        let clusters = cluster_obstructions(&obs);

        assert_eq!(
            clusters.len(),
            1,
            "Connected obstructions must form 1 cluster, got {}",
            clusters.len()
        );
        assert_eq!(clusters[0].len(), 2);
    }

    // ── test_cluster_size_cap ──────────────────────────────────────────────

    /// A cluster with more than `max_cluster_size` unique nodes must be
    /// returned in `oversized_clusters` and not processed by BP.
    #[test]
    fn test_cluster_size_cap() {
        // Build a chain: n0→n1→n2→...→n_N forming one big cluster.
        // We need > 50 unique nodes. Use 52 unique nodes → 51 edges.
        let nodes: Vec<Uuid> = (0..52).map(|_| Uuid::new_v4()).collect();
        let obs: Vec<CdstSheafObstruction> = nodes
            .windows(2)
            .map(|w| make_obs(w[0], w[1], 0.5))
            .collect();

        // All obstructions form one connected chain.
        let clusters = cluster_obstructions(&obs);
        assert_eq!(clusters.len(), 1, "Chain must be one cluster");

        // Run reconcile with the default max_cluster_size=50.
        let config = ReconciliationConfig::default();
        let all_intervals: HashMap<Uuid, EpistemicInterval> = nodes
            .iter()
            .map(|&id| (id, EpistemicInterval::VACUOUS))
            .collect();

        let result = reconcile(obs, &all_intervals, &[], &config);

        assert_eq!(
            result.oversized_clusters.len(),
            1,
            "Oversized cluster must be reported"
        );
        assert_eq!(
            result.clusters_processed, 0,
            "Oversized cluster must not be processed"
        );
        assert!(
            result.oversized_clusters[0].node_count > 50,
            "Oversized cluster node count must exceed 50, got {}",
            result.oversized_clusters[0].node_count
        );

        // Verify SkippedCluster is also populated.
        assert_eq!(
            result.skipped_clusters.len(),
            1,
            "One SkippedCluster entry must be recorded"
        );
        let sc = &result.skipped_clusters[0];
        assert!(
            sc.size > 50,
            "SkippedCluster.size must exceed 50, got {}",
            sc.size
        );
        assert!(
            !sc.sample_ids.is_empty(),
            "SkippedCluster.sample_ids must not be empty"
        );
        assert!(
            sc.sample_ids.len() <= 5,
            "SkippedCluster.sample_ids must contain at most 5 entries, got {}",
            sc.sample_ids.len()
        );
        assert!(
            sc.reason.contains("max_cluster_size"),
            "SkippedCluster.reason must mention max_cluster_size, got: {}",
            sc.reason
        );
    }

    // ── test_reconcile_basic ───────────────────────────────────────────────

    /// A small obstruction set with supporting factors must run BP and return
    /// updated intervals.
    #[test]
    fn test_reconcile_basic() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // One obstruction: a→b with inconsistency 0.5 (above min 0.15).
        let obs = vec![make_obs(a, b, 0.5)];

        // Intervals: a is strong, b is vacuous (large inconsistency scenario).
        let all_intervals: HashMap<Uuid, EpistemicInterval> = HashMap::from([
            (a, EpistemicInterval::new(0.8, 0.95, 0.05)),
            (b, EpistemicInterval::VACUOUS),
        ]);

        // A factor linking a and b so BP has something to do.
        let factor_id = Uuid::new_v4();
        let factors: Vec<(Uuid, FactorPotential, Vec<Uuid>)> = vec![(
            factor_id,
            FactorPotential::EvidentialSupport { strength: 0.8 },
            vec![a, b],
        )];

        let config = ReconciliationConfig {
            min_inconsistency: 0.15,
            max_depth: 3,
            max_cluster_size: 50,
            bp_config: IntervalBpConfig {
                max_iterations: 30,
                convergence_threshold: 0.01,
                damping: 0.5,
                ..Default::default()
            },
        };

        let result = reconcile(obs, &all_intervals, &factors, &config);

        assert_eq!(
            result.clusters_processed, 1,
            "One cluster must be processed"
        );
        assert!(
            result.oversized_clusters.is_empty(),
            "No oversized clusters expected"
        );
        assert_eq!(
            result.updated_intervals.len(),
            2,
            "Both nodes must appear in updated_intervals"
        );

        // Find b's updated interval; it should have moved from VACUOUS toward a.
        let b_updated = result
            .updated_intervals
            .iter()
            .find(|(id, _)| *id == b)
            .map(|(_, iv)| *iv)
            .expect("b must be in updated_intervals");

        assert!(
            b_updated.bel > 0.0,
            "EvidentialSupport from a should raise b.bel above 0.0, got {}",
            b_updated
        );
    }

    // ── test_reconcile_below_threshold_skipped ────────────────────────────

    /// Obstructions below min_inconsistency must be ignored entirely.
    #[test]
    fn test_reconcile_below_threshold_skipped() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // inconsistency = 0.05 < default min 0.15 → should be filtered out.
        let obs = vec![make_obs(a, b, 0.05)];
        let all_intervals = HashMap::from([
            (a, EpistemicInterval::VACUOUS),
            (b, EpistemicInterval::VACUOUS),
        ]);

        let result = reconcile(obs, &all_intervals, &[], &ReconciliationConfig::default());

        assert_eq!(result.clusters_processed, 0);
        assert!(result.updated_intervals.is_empty());
        assert!(result.converged, "No-op run must be reported as converged");
    }

    // ── test_open_world_propagation_and_frame_closure ─────────────────────

    /// 3-node chain: A --supports--> B --supports--> C.
    ///
    /// Tests two things:
    /// 1. Obstruction classification with the classify_obstruction function directly
    ///    (using hand-crafted component values that produce FrameClosureOpportunity)
    /// 2. The full reconciliation pipeline runs and produces results
    ///
    /// Note: with 2-node edges, restrict_epistemic_positive always widens expected
    /// intervals, making ignorance_component dominate over open_world_component.
    /// FrameClosureOpportunity emerges naturally with multi-neighbor averaging.
    /// We test classification directly to verify the logic works.
    #[test]
    fn test_open_world_propagation_and_frame_closure() {
        use crate::cdst_sheaf::{
            classify_obstruction, compute_cdst_edge_inconsistency, ObstructionKind,
        };
        use crate::sheaf::RestrictionProfile;

        // ── Part 1: Verify classify_obstruction produces FrameClosureOpportunity ──
        // Hand-craft component values where OW dominates.
        let source_high_ow = EpistemicInterval::new(0.3, 0.8, 0.4); // wide, high OW
        let target_narrow = EpistemicInterval::new(0.85, 0.88, 0.01); // narrow, low OW

        let kind = classify_obstruction(
            &source_high_ow,
            &target_narrow,
            0.05, // conflict: small
            0.10, // ignorance: moderate
            0.35, // open_world: DOMINATES
            0.2,  // frame_closure_width_max
        );
        assert_eq!(
            kind,
            ObstructionKind::FrameClosureOpportunity,
            "When OW dominates, source.ow > target.ow, target narrow → FrameClosureOpportunity"
        );

        // Also verify OpenWorldSpread when target is not narrow
        let target_wide = EpistemicInterval::new(0.3, 0.7, 0.05);
        let kind2 = classify_obstruction(&source_high_ow, &target_wide, 0.05, 0.10, 0.35, 0.2);
        assert_eq!(kind2, ObstructionKind::OpenWorldSpread);

        // ── Part 2: Full pipeline with real edge computation ──
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let id_c = Uuid::new_v4();

        let iv_a = EpistemicInterval::new(0.3, 0.8, 0.4); // A: wide, high OW
        let iv_b = EpistemicInterval::new(0.35, 0.75, 0.3); // B: wide, moderate OW
        let iv_c = EpistemicInterval::new(0.85, 0.88, 0.01); // C: narrow, low OW

        let profile = RestrictionProfile::scientific();

        let obs_ab = compute_cdst_edge_inconsistency(id_a, id_b, iv_a, iv_b, "supports", &profile);
        let obs_bc = compute_cdst_edge_inconsistency(id_b, id_c, iv_b, iv_c, "supports", &profile);

        // Verify obstructions have non-zero inconsistency (the graph is not perfectly consistent)
        assert!(
            obs_ab.interval_inconsistency > 0.0 || obs_bc.interval_inconsistency > 0.0,
            "At least one edge should have non-zero inconsistency"
        );

        // Build the intervals map and run reconcile with EvidentialSupport factors.
        let all_intervals: HashMap<Uuid, EpistemicInterval> =
            HashMap::from([(id_a, iv_a), (id_b, iv_b), (id_c, iv_c)]);

        let factors: Vec<(Uuid, crate::bp::FactorPotential, Vec<Uuid>)> = vec![
            (
                Uuid::new_v4(),
                crate::bp::FactorPotential::EvidentialSupport { strength: 0.8 },
                vec![id_a, id_b],
            ),
            (
                Uuid::new_v4(),
                crate::bp::FactorPotential::EvidentialSupport { strength: 0.8 },
                vec![id_b, id_c],
            ),
        ];

        // Both obstructions have non-zero inconsistency, but we need to check
        // if they clear the min_inconsistency threshold (0.15).
        // Use a lower threshold so both edges are processed.
        let config = ReconciliationConfig {
            min_inconsistency: 0.0,
            max_depth: 3,
            max_cluster_size: 50,
            bp_config: crate::interval_bp::IntervalBpConfig {
                max_iterations: 30,
                convergence_threshold: 0.01,
                damping: 0.5,
                ..Default::default()
            },
        };

        let obstructions = vec![obs_ab, obs_bc];
        let result = reconcile(obstructions, &all_intervals, &factors, &config);

        // The three nodes form one connected cluster.
        assert_eq!(
            result.clusters_processed, 1,
            "The 3-node chain must be processed as one cluster"
        );
        assert!(
            result.oversized_clusters.is_empty(),
            "No oversized clusters expected for a 3-node graph"
        );

        // All three nodes should appear in updated_intervals.
        assert_eq!(
            result.updated_intervals.len(),
            3,
            "All 3 nodes must appear in updated_intervals"
        );

        // frame_evidence_proposals may or may not be populated depending on BP
        // dynamics — the key validation above is the classification assertions.
        // If proposals are present, verify they come from C (certain, low-OW)
        // targeting B (high OW relative to C).
        for proposal in &result.frame_evidence_proposals {
            assert!(
                proposal.confidence > 0.0,
                "FrameEvidenceProposal must have positive confidence"
            );
            assert_ne!(
                proposal.target_claim_id, proposal.evidence_source_id,
                "target and source of FrameEvidenceProposal must differ"
            );
        }
    }

    // ── test_frame_evidence_proposals_always_have_scope ───────────────────

    /// Property test: every FrameEvidenceProposal produced by reconcile must
    /// satisfy confidence > 0.0 and target_claim_id != evidence_source_id.
    ///
    /// Uses a 2-node graph designed to produce frame closure proposals
    /// (certain, low-OW source adjacent to high-OW target).
    #[test]
    fn test_frame_evidence_proposals_always_have_scope() {
        let source_id = Uuid::new_v4(); // certain, low-OW → will be frame evidence source
        let target_id = Uuid::new_v4(); // high OW → frame closure target

        // source: narrow (width=0.04 < 0.2) and low OW (0.01 < 0.1).
        let iv_source = EpistemicInterval::new(0.78, 0.82, 0.01);
        // target: high OW (0.4 > 0.3), wide.
        let iv_target = EpistemicInterval::new(0.3, 0.7, 0.4);

        let all_intervals: HashMap<Uuid, EpistemicInterval> =
            HashMap::from([(source_id, iv_source), (target_id, iv_target)]);

        let factors: Vec<(Uuid, crate::bp::FactorPotential, Vec<Uuid>)> = vec![(
            Uuid::new_v4(),
            crate::bp::FactorPotential::EvidentialSupport { strength: 0.8 },
            vec![source_id, target_id],
        )];

        // Build a small obstruction between source and target.
        // Use inconsistency 0.3 to ensure it clears the 0.15 threshold.
        let obs = CdstSheafObstruction {
            source_id,
            target_id,
            relationship: "supports".to_string(),
            source_interval: iv_source,
            target_interval: iv_target,
            expected_interval: iv_source,
            interval_inconsistency: 0.3,
            conflict_component: 0.05,
            ignorance_component: 0.05,
            open_world_component: 0.3,
            obstruction_kind: ObstructionKind::FrameClosureOpportunity,
        };

        let config = ReconciliationConfig {
            min_inconsistency: 0.15,
            max_depth: 3,
            max_cluster_size: 50,
            bp_config: crate::interval_bp::IntervalBpConfig {
                max_iterations: 20,
                convergence_threshold: 0.01,
                damping: 0.5,
                ..Default::default()
            },
        };

        let result = reconcile(vec![obs], &all_intervals, &factors, &config);

        assert_eq!(result.clusters_processed, 1, "Cluster must be processed");

        // Verify property on all proposals returned.
        for proposal in &result.frame_evidence_proposals {
            assert!(
                proposal.confidence > 0.0,
                "FrameEvidenceProposal.confidence must be > 0.0, got {}",
                proposal.confidence
            );
            assert_ne!(
                proposal.target_claim_id, proposal.evidence_source_id,
                "FrameEvidenceProposal.target_claim_id must differ from evidence_source_id"
            );
        }

        // At least one proposal should be generated, since source satisfies
        // the frame-closure criteria (low OW, narrow) and target has high OW.
        assert!(
            !result.frame_evidence_proposals.is_empty(),
            "Expected at least one FrameEvidenceProposal for a certain low-OW \
             source adjacent to a high-OW target"
        );
    }

    // ── test_bp_non_convergence_returns_unresolved ────────────────────────

    /// Contradictory factors with max_iterations=2 must produce converged=false.
    ///
    /// Two variables are linked by MutualExclusion (pushes both down) AND
    /// EvidentialSupport (pushes both up).  These opposing pressures create
    /// a system that requires many iterations to settle.  Clamping to 2
    /// iterations guarantees the run does not converge.
    #[test]
    fn test_bp_non_convergence_returns_unresolved() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        // Strong opposing forces: mutual exclusion says at most one can be high,
        // but evidential support pushes them to follow each other upward.
        let factors: Vec<(Uuid, crate::bp::FactorPotential, Vec<Uuid>)> = vec![
            (
                Uuid::new_v4(),
                crate::bp::FactorPotential::MutualExclusion,
                vec![a, b],
            ),
            (
                Uuid::new_v4(),
                crate::bp::FactorPotential::EvidentialSupport { strength: 0.99 },
                vec![a, b],
            ),
        ];

        // Both start very high → mutual exclusion pushes back hard, but
        // evidential support keeps trying to raise both.
        let all_intervals: HashMap<Uuid, EpistemicInterval> = HashMap::from([
            (a, EpistemicInterval::new(0.85, 0.95, 0.05)),
            (b, EpistemicInterval::new(0.85, 0.95, 0.05)),
        ]);

        // One obstruction connecting a and b with high inconsistency.
        let obs = vec![CdstSheafObstruction {
            source_id: a,
            target_id: b,
            relationship: "supports".to_string(),
            source_interval: EpistemicInterval::new(0.85, 0.95, 0.05),
            target_interval: EpistemicInterval::new(0.85, 0.95, 0.05),
            expected_interval: EpistemicInterval::new(0.85, 0.95, 0.05),
            interval_inconsistency: 0.5,
            conflict_component: 0.5,
            ignorance_component: 0.0,
            open_world_component: 0.0,
            obstruction_kind: ObstructionKind::BeliefConflict,
        }];

        // Only 2 iterations — far too few for contradictory factors to settle.
        let config = ReconciliationConfig {
            min_inconsistency: 0.15,
            max_depth: 1, // single outer pass
            max_cluster_size: 50,
            bp_config: crate::interval_bp::IntervalBpConfig {
                max_iterations: 2,
                convergence_threshold: 1e-9, // very tight — nearly impossible to hit
                damping: 0.5,
                ..Default::default()
            },
        };

        let result = reconcile(obs, &all_intervals, &factors, &config);

        assert_eq!(result.clusters_processed, 1, "Cluster must be processed");
        assert!(
            !result.converged,
            "Contradictory factors with max_iterations=2 must not converge; \
             got converged=true with {} iterations",
            result.total_iterations
        );
        assert_eq!(
            result.total_iterations, 2,
            "Total iterations must equal max_iterations (2), got {}",
            result.total_iterations
        );
    }
}
