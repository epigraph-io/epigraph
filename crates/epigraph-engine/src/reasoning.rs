//! Ascent-based Datalog reasoning engine for symbolic graph analysis.
//!
//! Performs graph-level symbolic reasoning over claims and edges:
//! transitive inference chains, contradiction detection, evidence
//! aggregation across paths, corroboration amplification, and
//! belief revision analysis.
//!
//! The reasoning engine is **read-only** — it consumes graph data and
//! produces analytical insights but never mutates truth values or edges.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use uuid::Uuid;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

/// A claim loaded into the reasoning engine.
#[derive(Debug, Clone)]
pub struct ReasoningClaim {
    pub id: Uuid,
    pub truth_value: f64,
}

/// An edge loaded into the reasoning engine.
#[derive(Debug, Clone)]
pub struct ReasoningEdge {
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// Relationship type string — matched against well-known names:
    /// `"supports"`, `"refutes"` / `"contradicts"`, `"elaborates"`,
    /// `"specializes"` / `"refines"`, `"generalizes"`, `"challenges"`,
    /// `"corroborates"`, `"co_evidenced"`.
    pub relationship: String,
    pub strength: f64,
}

// ---------------------------------------------------------------------------
// Internal: f64 wrapper for Ascent compatibility
// ---------------------------------------------------------------------------

/// Bit-exact equality wrapper for f64.
///
/// Ascent relations require `Clone + Eq + Hash` on all column types.
/// Raw f64 doesn't satisfy these, so we wrap it with bit-level equality.
/// This is safe for our bounded `[0.0, 1.0]` strength values (no NaN).
#[derive(Clone, Copy, Debug)]
struct Strength(f64);

impl PartialEq for Strength {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for Strength {}

impl Hash for Strength {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

// ---------------------------------------------------------------------------
// Ascent Datalog program
// ---------------------------------------------------------------------------

/// Clippy/rustc lints suppressed for macro-generated code.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unreachable_pub,
    unused,
    missing_docs
)]
mod datalog {
    use super::Strength;
    use ascent::aggregators::count;
    use ascent::ascent;
    use uuid::Uuid;

    ascent! {
        pub struct EpiGraphReasoning;

        // == Input relations (populated before run) ===========================

        relation claim(Uuid, Strength);
        relation supports(Uuid, Uuid, Strength);
        relation refutes(Uuid, Uuid, Strength);
        relation elaborates(Uuid, Uuid, Strength);
        relation specializes(Uuid, Uuid, Strength);
        relation generalizes(Uuid, Uuid, Strength);
        relation challenges(Uuid, Uuid, Strength);
        relation corroborates(Uuid, Uuid, Strength);
        relation co_evidenced(Uuid, Uuid, Strength);

        // == Derived: general edge (union of all typed edges) =================

        relation edge(Uuid, Uuid);
        edge(a, b) <-- supports(a, b, _);
        edge(a, b) <-- refutes(a, b, _);
        edge(a, b) <-- elaborates(a, b, _);
        edge(a, b) <-- specializes(a, b, _);
        edge(a, b) <-- generalizes(a, b, _);
        edge(a, b) <-- challenges(a, b, _);
        edge(a, b) <-- corroborates(a, b, _);
        edge(a, b) <-- co_evidenced(a, b, _);

        // == Derived: reachability (transitive closure) =======================

        relation reachable(Uuid, Uuid);
        reachable(a, b) <-- edge(a, b);
        reachable(a, c) <-- edge(a, b), reachable(b, c);

        // == Corroboration-amplified support ==================================
        //    If E2 corroborates E1, and E1 supports claim C,
        //    then E2 also supports C (with decayed strength).
        //    Injected directly into `supports` so it participates in all
        //    downstream reasoning (transitive chains, contradictions, etc.)

        supports(e2, c, Strength(cs.0 * s.0)) <--
            corroborates(e2, e1, cs),
            supports(e1, c, s),
            if cs.0 * s.0 > 0.1 && e2 != c;

        // == Co-evidence bidirectional ========================================
        //    co_evidenced edges are stored with a < b; make them symmetric.

        relation co_evidenced_bidi(Uuid, Uuid, Strength);
        co_evidenced_bidi(a, b, s) <-- co_evidenced(a, b, s);
        co_evidenced_bidi(b, a, s) <-- co_evidenced(a, b, s);

        // == Co-evidence amplified support ====================================
        //    If claims A and B share evidence, and X supports A,
        //    then X has indirect support for B. Kept in a separate
        //    relation (not injected into supports) because shared
        //    evidence implies relatedness, not support transfer.

        relation co_evidence_support(Uuid, Uuid, Strength);
        co_evidence_support(x, b, Strength(s.0 * ce.0)) <--
            supports(x, a, s),
            co_evidenced_bidi(a, b, ce),
            if s.0 * ce.0 > 0.1 && x != b && a != b;

        // == Transitive support with strength decay ===========================
        //    Each hop multiplies strengths; chains below 0.1 are pruned.
        //    Self-loops (a == c) are excluded.

        relation transitive_support(Uuid, Uuid, Strength);
        transitive_support(a, b, s) <--
            supports(a, b, s), if a != b;
        transitive_support(a, c, Strength(s.0 * t.0)) <--
            supports(a, b, s),
            transitive_support(b, c, t),
            if s.0 * t.0 > 0.1 && a != c;

        // == Contradiction detection ==========================================

        relation contradiction(Uuid, Uuid, Uuid, Strength, Strength);
        contradiction(a, b, target, s1, s2) <--
            supports(a, target, s1),
            refutes(b, target, s2),
            if s1.0 > 0.3 && s2.0 > 0.3;

        // == Elaboration chains ===============================================

        relation elaboration_chain(Uuid, Uuid);
        elaboration_chain(a, b) <-- elaborates(a, b, _);
        elaboration_chain(a, b) <-- specializes(a, b, _);
        elaboration_chain(a, c) <--
            elaboration_chain(a, b), elaboration_chain(b, c);

        // == Co-support (support clusters) ====================================

        relation co_support(Uuid, Uuid, Uuid);
        co_support(a, b, target) <--
            supports(a, target, _),
            supports(b, target, _),
            if a < b;

        // == Indirect challenges ==============================================

        relation indirect_challenge(Uuid, Uuid);
        indirect_challenge(challenger, target) <--
            challenges(challenger, mid, _),
            transitive_support(mid, target, s),
            if s.0 > 0.2;

        // == Corroboration chains =============================================
        //    Transitive closure over corroborates edges.

        relation corroboration_chain(Uuid, Uuid);
        corroboration_chain(a, b) <-- corroborates(a, b, _);
        corroboration_chain(a, c) <--
            corroborates(a, b, _), corroboration_chain(b, c);

        // == Evidence counting (aggregation) ==================================
        //    Number of distinct supporters per claim target.

        relation evidence_count(Uuid, usize);
        evidence_count(target, cnt) <--
            claim(target, _),
            agg cnt = count() in supports(_, target, _);

        // == Unsupported claim detection (negation) ===========================
        //    Claims that have zero incoming support edges.

        relation has_support(Uuid);
        has_support(c) <-- supports(_, c, _);

        relation unsupported(Uuid);
        unsupported(c) <-- claim(c, _), !has_support(c);
    }
}

use datalog::EpiGraphReasoning;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// A transitive support relationship discovered through chain analysis.
#[derive(Debug)]
pub struct TransitiveSupport {
    pub source: Uuid,
    pub target: Uuid,
    /// Product of edge strengths along the chain.
    pub chain_strength: f64,
}

/// A contradiction: two claims that support and refute the same target.
#[derive(Debug)]
pub struct Contradiction {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub target: Uuid,
    pub support_strength: f64,
    pub refute_strength: f64,
}

/// A cluster of claims that jointly support a target.
#[derive(Debug)]
pub struct SupportCluster {
    pub target: Uuid,
    pub supporters: Vec<Uuid>,
}

/// An indirect challenge propagated through support chains.
#[derive(Debug)]
pub struct IndirectChallenge {
    pub challenger: Uuid,
    pub target: Uuid,
}

/// Statistics about the reasoning analysis.
#[derive(Debug)]
pub struct ReasoningStats {
    pub claims_loaded: usize,
    pub edges_loaded: usize,
    pub transitive_supports_found: usize,
    pub contradictions_found: usize,
    pub components: usize,
    pub corroboration_chains_found: usize,
    pub co_evidence_supports_found: usize,
    pub unsupported_claims_found: usize,
}

/// Complete results from a reasoning engine analysis.
#[derive(Debug)]
pub struct ReasoningResult {
    pub transitive_supports: Vec<TransitiveSupport>,
    pub contradictions: Vec<Contradiction>,
    pub elaboration_chains: Vec<(Uuid, Uuid)>,
    pub support_clusters: Vec<SupportCluster>,
    pub indirect_challenges: Vec<IndirectChallenge>,
    pub connected_components: Vec<Vec<Uuid>>,
    pub corroboration_chains: Vec<(Uuid, Uuid)>,
    pub co_evidence_supports: Vec<TransitiveSupport>,
    pub evidence_weights: Vec<(Uuid, usize)>,
    pub unsupported_claims: Vec<Uuid>,
    pub stats: ReasoningStats,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Symbolic reasoning engine backed by Ascent Datalog.
///
/// Performs read-only graph analysis: transitive support chains,
/// contradiction detection, elaboration chains, support clustering,
/// indirect challenges, corroboration amplification, evidence
/// counting, and unsupported claim detection.
pub struct ReasoningEngine;

impl ReasoningEngine {
    /// Load claims and edges, run Datalog to fixed point, return results.
    #[must_use]
    pub fn analyze(claims: &[ReasoningClaim], edges: &[ReasoningEdge]) -> ReasoningResult {
        let claims_loaded = claims.len();
        let edges_loaded = edges.len();

        let mut prog = EpiGraphReasoning::default();

        // Populate input relations
        prog.claim = claims
            .iter()
            .map(|c| (c.id, Strength(c.truth_value)))
            .collect();

        Self::dispatch_edges(&mut prog, edges);

        // Run Datalog to fixed point
        prog.run();

        // Extract results
        Self::extract_results(&prog, claims_loaded, edges_loaded)
    }

    /// Dispatch edges into typed Ascent input relations.
    fn dispatch_edges(prog: &mut EpiGraphReasoning, edges: &[ReasoningEdge]) {
        for e in edges {
            let tuple = (e.source_id, e.target_id, Strength(e.strength));
            match e.relationship.as_str() {
                "supports" => prog.supports.push(tuple),
                "refutes" | "contradicts" => prog.refutes.push(tuple),
                "elaborates" => prog.elaborates.push(tuple),
                "specializes" | "refines" => prog.specializes.push(tuple),
                "generalizes" => prog.generalizes.push(tuple),
                "challenges" => prog.challenges.push(tuple),
                "corroborates" => prog.corroborates.push(tuple),
                "co_evidenced" => prog.co_evidenced.push(tuple),
                _ => {
                    tracing::warn!(relationship = %e.relationship, "Unknown relationship type in reasoning graph — skipped");
                }
            }
        }
    }

    /// Convert Ascent program output into structured results.
    fn extract_results(
        prog: &EpiGraphReasoning,
        claims_loaded: usize,
        edges_loaded: usize,
    ) -> ReasoningResult {
        let transitive_supports: Vec<TransitiveSupport> = prog
            .transitive_support
            .iter()
            .map(|(src, tgt, s)| TransitiveSupport {
                source: *src,
                target: *tgt,
                chain_strength: s.0,
            })
            .collect();

        let contradictions: Vec<Contradiction> = prog
            .contradiction
            .iter()
            .map(|(a, b, target, s1, s2)| Contradiction {
                claim_a: *a,
                claim_b: *b,
                target: *target,
                support_strength: s1.0,
                refute_strength: s2.0,
            })
            .collect();

        let elaboration_chains: Vec<(Uuid, Uuid)> = prog
            .elaboration_chain
            .iter()
            .map(|(a, b)| (*a, *b))
            .collect();

        let support_clusters = Self::build_clusters(&prog.co_support);

        let indirect_challenges: Vec<IndirectChallenge> = prog
            .indirect_challenge
            .iter()
            .map(|(c, t)| IndirectChallenge {
                challenger: *c,
                target: *t,
            })
            .collect();

        let corroboration_chains: Vec<(Uuid, Uuid)> = prog
            .corroboration_chain
            .iter()
            .map(|(a, b)| (*a, *b))
            .collect();

        let co_evidence_supports: Vec<TransitiveSupport> = prog
            .co_evidence_support
            .iter()
            .map(|(src, tgt, s)| TransitiveSupport {
                source: *src,
                target: *tgt,
                chain_strength: s.0,
            })
            .collect();

        let evidence_weights: Vec<(Uuid, usize)> = prog
            .evidence_count
            .iter()
            .map(|(id, cnt)| (*id, *cnt))
            .collect();

        let unsupported_claims: Vec<Uuid> = prog.unsupported.iter().map(|(id,)| *id).collect();

        let all_nodes: HashSet<Uuid> = prog.claim.iter().map(|(id, _)| *id).collect();
        let connected_components = Self::build_components(&all_nodes, &prog.reachable);

        let stats = ReasoningStats {
            claims_loaded,
            edges_loaded,
            transitive_supports_found: transitive_supports.len(),
            contradictions_found: contradictions.len(),
            components: connected_components.len(),
            corroboration_chains_found: corroboration_chains.len(),
            co_evidence_supports_found: co_evidence_supports.len(),
            unsupported_claims_found: unsupported_claims.len(),
        };

        ReasoningResult {
            transitive_supports,
            contradictions,
            elaboration_chains,
            support_clusters,
            indirect_challenges,
            connected_components,
            corroboration_chains,
            co_evidence_supports,
            evidence_weights,
            unsupported_claims,
            stats,
        }
    }

    /// Check if adding `new_edge` would introduce a new contradiction.
    ///
    /// Returns the first new contradiction found, if any.
    #[must_use]
    pub fn would_contradict(
        claims: &[ReasoningClaim],
        edges: &[ReasoningEdge],
        new_edge: &ReasoningEdge,
    ) -> Option<Contradiction> {
        // Snapshot existing contradictions
        let baseline = Self::analyze(claims, edges);
        let existing: HashSet<(Uuid, Uuid, Uuid)> = baseline
            .contradictions
            .iter()
            .map(|c| (c.claim_a, c.claim_b, c.target))
            .collect();

        // Analyze with the new edge included
        let mut edges_with: Vec<ReasoningEdge> = edges.to_vec();
        edges_with.push(new_edge.clone());

        let result = Self::analyze(claims, &edges_with);

        result
            .contradictions
            .into_iter()
            .find(|c| !existing.contains(&(c.claim_a, c.claim_b, c.target)))
    }

    /// Group co-support pairs into per-target clusters.
    fn build_clusters(co_support: &[(Uuid, Uuid, Uuid)]) -> Vec<SupportCluster> {
        let mut target_supporters: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
        for &(a, b, target) in co_support {
            let entry = target_supporters.entry(target).or_default();
            entry.insert(a);
            entry.insert(b);
        }
        let mut clusters: Vec<SupportCluster> = target_supporters
            .into_iter()
            .map(|(target, supporters)| {
                let mut supporters: Vec<Uuid> = supporters.into_iter().collect();
                supporters.sort();
                SupportCluster { target, supporters }
            })
            .collect();
        clusters.sort_by_key(|c| c.target);
        clusters
    }

    /// Compute undirected connected components from directed reachability.
    fn build_components(nodes: &HashSet<Uuid>, reachable: &[(Uuid, Uuid)]) -> Vec<Vec<Uuid>> {
        // Build undirected adjacency from directed reachability
        let mut adj: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
        for &node in nodes {
            adj.entry(node).or_default();
        }
        for &(a, b) in reachable {
            // Only track adjacency for nodes we know about
            if nodes.contains(&a) && nodes.contains(&b) {
                adj.entry(a).or_default().insert(b);
                adj.entry(b).or_default().insert(a);
            }
        }

        // DFS to find components
        let mut visited = HashSet::new();
        let mut components = Vec::new();

        // Process nodes in sorted order for deterministic output
        let mut sorted_nodes: Vec<Uuid> = nodes.iter().copied().collect();
        sorted_nodes.sort();

        for node in sorted_nodes {
            if visited.contains(&node) {
                continue;
            }
            let mut component = Vec::new();
            let mut stack = vec![node];
            while let Some(n) = stack.pop() {
                if visited.insert(n) {
                    component.push(n);
                    if let Some(neighbors) = adj.get(&n) {
                        for &neighbor in neighbors {
                            if !visited.contains(&neighbor) {
                                stack.push(neighbor);
                            }
                        }
                    }
                }
            }
            component.sort();
            components.push(component);
        }

        components
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers
    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn claim(n: u128, truth: f64) -> ReasoningClaim {
        ReasoningClaim {
            id: id(n),
            truth_value: truth,
        }
    }

    fn edge(src: u128, tgt: u128, rel: &str, strength: f64) -> ReasoningEdge {
        ReasoningEdge {
            source_id: id(src),
            target_id: id(tgt),
            relationship: rel.to_string(),
            strength,
        }
    }

    // 1. Linear chain: A→B→C produces transitive_support(A, C)
    #[test]
    fn test_linear_chain_transitive_support() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 2, "supports", 0.9), edge(2, 3, "supports", 0.8)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(
            result
                .transitive_supports
                .iter()
                .any(|ts| { ts.source == id(1) && ts.target == id(3) }),
            "Expected transitive support from 1 to 3"
        );

        let chain = result
            .transitive_supports
            .iter()
            .find(|ts| ts.source == id(1) && ts.target == id(3))
            .unwrap();
        let expected = 0.9 * 0.8;
        assert!(
            (chain.chain_strength - expected).abs() < 1e-10,
            "Expected chain strength {expected}, got {}",
            chain.chain_strength
        );
    }

    // 2. Contradiction: A supports X, B refutes X
    #[test]
    fn test_contradiction_detection() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.5)];
        let edges = vec![edge(1, 3, "supports", 0.8), edge(2, 3, "refutes", 0.7)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert_eq!(
            result.contradictions.len(),
            1,
            "Expected exactly one contradiction"
        );
        let c = &result.contradictions[0];
        assert_eq!(c.claim_a, id(1));
        assert_eq!(c.claim_b, id(2));
        assert_eq!(c.target, id(3));
    }

    // 3. Diamond graph: A→B, A→C, B→D, C→D
    #[test]
    fn test_diamond_graph_transitive_supports() {
        let claims = vec![claim(1, 0.9), claim(2, 0.8), claim(3, 0.7), claim(4, 0.6)];
        let edges = vec![
            edge(1, 2, "supports", 0.9),
            edge(1, 3, "supports", 0.8),
            edge(2, 4, "supports", 0.7),
            edge(3, 4, "supports", 0.6),
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        let to_4: Vec<&TransitiveSupport> = result
            .transitive_supports
            .iter()
            .filter(|ts| ts.source == id(1) && ts.target == id(4))
            .collect();

        assert_eq!(to_4.len(), 2, "Expected two transitive paths from 1 to 4");

        let strengths: HashSet<u64> = to_4.iter().map(|ts| ts.chain_strength.to_bits()).collect();
        assert!(strengths.contains(&(0.9_f64 * 0.7).to_bits()));
        assert!(strengths.contains(&(0.8_f64 * 0.6).to_bits()));
    }

    // 4. Elaboration chain
    #[test]
    fn test_elaboration_chain() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 2, "elaborates", 0.5), edge(2, 3, "elaborates", 0.5)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(result.elaboration_chains.contains(&(id(1), id(3))));
    }

    // 5. Self-loops filtered
    #[test]
    fn test_no_self_loop_transitive_support() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7)];
        let edges = vec![edge(1, 1, "supports", 0.9), edge(1, 2, "supports", 0.8)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(
            !result
                .transitive_supports
                .iter()
                .any(|ts| ts.source == ts.target),
            "Self-loop transitive supports should be filtered out"
        );
    }

    // 6. Strength decay threshold
    #[test]
    fn test_strength_decay_threshold() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6), claim(4, 0.5)];
        let edges = vec![
            edge(1, 2, "supports", 0.4),
            edge(2, 3, "supports", 0.4),
            edge(3, 4, "supports", 0.4),
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(result
            .transitive_supports
            .iter()
            .any(|ts| ts.source == id(1) && ts.target == id(3)));
        assert!(!result
            .transitive_supports
            .iter()
            .any(|ts| ts.source == id(1) && ts.target == id(4)));
    }

    // 7. Empty graph
    #[test]
    fn test_empty_graph() {
        let result = ReasoningEngine::analyze(&[], &[]);

        assert!(result.transitive_supports.is_empty());
        assert!(result.contradictions.is_empty());
        assert!(result.elaboration_chains.is_empty());
        assert!(result.support_clusters.is_empty());
        assert!(result.indirect_challenges.is_empty());
        assert!(result.connected_components.is_empty());
        assert!(result.corroboration_chains.is_empty());
        assert!(result.co_evidence_supports.is_empty());
        assert!(result.unsupported_claims.is_empty());
        assert_eq!(result.stats.claims_loaded, 0);
        assert_eq!(result.stats.edges_loaded, 0);
    }

    // 8. Co-support detection
    #[test]
    fn test_co_support_detection() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.8), edge(2, 3, "supports", 0.7)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert_eq!(result.support_clusters.len(), 1);
        let cluster = &result.support_clusters[0];
        assert_eq!(cluster.target, id(3));
        assert!(cluster.supporters.contains(&id(1)));
        assert!(cluster.supporters.contains(&id(2)));
    }

    // 9. Indirect challenge propagation
    #[test]
    fn test_indirect_challenge() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 2, "challenges", 0.9), edge(2, 3, "supports", 0.8)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(result
            .indirect_challenges
            .iter()
            .any(|ic| ic.challenger == id(1) && ic.target == id(3)));
    }

    // 10. Connected components
    #[test]
    fn test_connected_components() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6), claim(4, 0.5)];
        let edges = vec![edge(1, 2, "supports", 0.8), edge(2, 3, "supports", 0.7)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert_eq!(result.connected_components.len(), 2);
        let sizes: HashSet<usize> = result.connected_components.iter().map(Vec::len).collect();
        assert!(sizes.contains(&3));
        assert!(sizes.contains(&1));
    }

    // 11. would_contradict detects new contradiction
    #[test]
    fn test_would_contradict() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.8)];
        let new_edge = edge(2, 3, "refutes", 0.7);

        let contradiction = ReasoningEngine::would_contradict(&claims, &edges, &new_edge);
        assert!(contradiction.is_some());
        assert_eq!(contradiction.unwrap().target, id(3));
    }

    // 12. would_contradict returns None when no new contradiction
    #[test]
    fn test_would_not_contradict() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.8)];
        let new_edge = edge(2, 3, "supports", 0.7);

        assert!(ReasoningEngine::would_contradict(&claims, &edges, &new_edge).is_none());
    }

    // 13. Weak edges don't trigger contradiction
    #[test]
    fn test_weak_edges_no_contradiction() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.2), edge(2, 3, "refutes", 0.2)];

        let result = ReasoningEngine::analyze(&claims, &edges);
        assert!(result.contradictions.is_empty());
    }

    // 14. "contradicts" maps to refutes
    #[test]
    fn test_contradicts_maps_to_refutes() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.8), edge(2, 3, "contradicts", 0.7)];

        let result = ReasoningEngine::analyze(&claims, &edges);
        assert_eq!(result.contradictions.len(), 1);
    }

    // 15. "refines" maps to specializes
    #[test]
    fn test_refines_maps_to_specializes() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 2, "refines", 0.5), edge(2, 3, "elaborates", 0.5)];

        let result = ReasoningEngine::analyze(&claims, &edges);
        assert!(result.elaboration_chains.contains(&(id(1), id(3))));
    }

    // 16. Stats are accurate
    #[test]
    fn test_stats_accuracy() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![
            edge(1, 2, "supports", 0.9),
            edge(2, 3, "supports", 0.8),
            edge(1, 3, "refutes", 0.7),
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);
        assert_eq!(result.stats.claims_loaded, 3);
        assert_eq!(result.stats.edges_loaded, 3);
        assert!(result.stats.transitive_supports_found > 0);
    }

    // === New tests for corroboration, co-evidence, aggregation, negation ===

    // 17. Corroboration amplifies support
    #[test]
    fn test_corroboration_amplifies_support() {
        // E1 supports claim C, E2 corroborates E1 → E2 should also support C
        let claims = vec![claim(10, 0.8), claim(20, 0.7), claim(30, 0.6)];
        let edges = vec![
            edge(10, 30, "supports", 0.8),     // E1 supports C
            edge(20, 10, "corroborates", 0.7), // E2 corroborates E1
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        // E2 (20) should now transitively support C (30) via corroboration injection
        assert!(
            result
                .transitive_supports
                .iter()
                .any(|ts| ts.source == id(20) && ts.target == id(30)),
            "Corroboration should create transitive support from E2 to C"
        );
    }

    // 18. Corroboration chain
    #[test]
    fn test_corroboration_chain() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![
            edge(1, 2, "corroborates", 0.7),
            edge(2, 3, "corroborates", 0.6),
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(
            result.corroboration_chains.contains(&(id(1), id(3))),
            "Expected transitive corroboration chain from 1 to 3"
        );
    }

    // 19. Co-evidence support
    #[test]
    fn test_co_evidence_support() {
        // X supports A, A and B are co-evidenced → X has co_evidence_support for B
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![
            edge(1, 2, "supports", 0.8),     // X supports A
            edge(2, 3, "co_evidenced", 0.6), // A and B co-evidenced
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        assert!(
            result
                .co_evidence_supports
                .iter()
                .any(|ts| ts.source == id(1) && ts.target == id(3)),
            "Co-evidence should create indirect support from X to B"
        );
    }

    // 20. Unsupported claim detection
    #[test]
    fn test_unsupported_claims() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![
            edge(1, 2, "supports", 0.8), // only claim 2 is supported
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        // Claims 1 and 3 have no incoming support
        assert!(result.unsupported_claims.contains(&id(1)));
        assert!(result.unsupported_claims.contains(&id(3)));
        assert!(!result.unsupported_claims.contains(&id(2)));
    }

    // 21. Evidence count aggregation
    #[test]
    fn test_evidence_count() {
        let claims = vec![claim(1, 0.8), claim(2, 0.7), claim(3, 0.6)];
        let edges = vec![edge(1, 3, "supports", 0.8), edge(2, 3, "supports", 0.7)];

        let result = ReasoningEngine::analyze(&claims, &edges);

        // Claim 3 has 2 supporters
        let weight = result
            .evidence_weights
            .iter()
            .find(|(uid, _)| *uid == id(3));
        assert!(weight.is_some());
        assert_eq!(weight.unwrap().1, 2);
    }

    // 22. Corroboration creates new contradictions
    #[test]
    fn test_corroboration_contradiction_amplification() {
        // E1 supports target, refuter refutes target
        // E2 corroborates E1 → E2 also supports target → new contradiction with refuter
        let claims = vec![
            claim(1, 0.8), // E1
            claim(2, 0.7), // refuter
            claim(3, 0.6), // target
            claim(4, 0.9), // E2
        ];
        let edges = vec![
            edge(1, 3, "supports", 0.8),
            edge(2, 3, "refutes", 0.7),
            edge(4, 1, "corroborates", 0.7), // E2 corroborates E1
        ];

        let result = ReasoningEngine::analyze(&claims, &edges);

        // Should have at least 2 contradictions: (E1, refuter, target) AND (E2, refuter, target)
        assert!(
            result.contradictions.len() >= 2,
            "Corroboration should amplify contradictions, got {}",
            result.contradictions.len()
        );
        assert!(
            result
                .contradictions
                .iter()
                .any(|c| c.claim_a == id(4) && c.target == id(3)),
            "E2 should be in contradiction with refuter via corroboration"
        );
    }
}
