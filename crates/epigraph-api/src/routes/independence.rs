//! Provenance-independence analysis for BBA combination (G1, G11)
//!
//! When multiple agents submit evidence (BBAs) for the same claim,
//! Dempster's rule assumes independence. If agents share a common
//! provenance ancestor (detected via LCA), their BBAs must be
//! combined cautiously (Denoeux min-rule) before standard combination.

use epigraph_ds::mass::MassFunction;
use uuid::Uuid;

/// Result of provenance independence analysis
#[derive(Debug, Clone)]
pub struct IndependenceAnalysis {
    /// Groups of BBAs that share provenance (each group gets cautious_combine)
    pub dependent_groups: Vec<Vec<MassFunction>>,
    /// BBAs with no shared provenance (get standard combine_multiple)
    pub independent: Vec<MassFunction>,
    /// Audit trail of LCA findings
    pub lca_findings: Vec<LcaFinding>,
}

/// Record of a discovered shared ancestor between two agents
#[derive(Debug, Clone)]
pub struct LcaFinding {
    pub agent_a: Option<Uuid>,
    pub agent_b: Option<Uuid>,
    pub ancestor_id: Uuid,
    pub total_depth: i32,
}

impl IndependenceAnalysis {
    /// Shortcut: treat all BBAs as independent (for single-BBA or bypass cases)
    pub fn all_independent(masses: Vec<MassFunction>) -> Self {
        Self {
            dependent_groups: vec![],
            independent: masses,
            lca_findings: vec![],
        }
    }
}

// ============================================================================
// Union-Find for transitive dependency grouping
// ============================================================================

/// Simple union-find (disjoint set) for grouping dependent agents
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

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return;
        }
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

/// Build `IndependenceAnalysis` from a pre-computed dependency adjacency.
///
/// This is the pure logic, separated from DB access for testability.
/// `agent_indices` maps agent positions to their BBAs.
/// `dependent_pairs` lists pairs of agent indices that share provenance.
pub fn build_analysis(
    agent_masses: &[Vec<MassFunction>],
    dependent_pairs: &[(usize, usize)],
    lca_findings: Vec<LcaFinding>,
) -> IndependenceAnalysis {
    let n = agent_masses.len();
    if n == 0 {
        return IndependenceAnalysis::all_independent(vec![]);
    }

    let mut uf = UnionFind::new(n);
    for &(a, b) in dependent_pairs {
        uf.union(a, b);
    }

    // Group agents by their root
    let mut groups: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for i in 0..n {
        groups.entry(uf.find(i)).or_default().push(i);
    }

    let mut dependent_groups = Vec::new();
    let mut independent = Vec::new();

    for (_root, members) in groups {
        // Collect all BBAs from the group's agents
        let group_masses: Vec<MassFunction> = members
            .iter()
            .flat_map(|&idx| agent_masses[idx].clone())
            .collect();

        if members.len() == 1 {
            // Single agent = independent
            independent.extend(group_masses);
        } else {
            // Multiple agents sharing provenance = dependent group
            dependent_groups.push(group_masses);
        }
    }

    IndependenceAnalysis {
        dependent_groups,
        independent,
        lca_findings,
    }
}

/// Analyze provenance independence of a set of BBAs.
///
/// Groups BBAs by source_agent_id, then for each pair of agent groups,
/// calls get_lca() on representative claims. If LCA exists within max_depth,
/// the pair is marked as dependent. Uses union-find for transitive closure.
#[cfg(feature = "db")]
pub async fn analyze_independence(
    pool: &sqlx::PgPool,
    rows: &[(Uuid, Option<Uuid>, MassFunction)],
    max_lca_depth: i32,
) -> Result<IndependenceAnalysis, crate::errors::ApiError> {
    use std::collections::HashMap;

    // Group BBAs by source_agent_id
    let mut agent_groups: HashMap<Option<Uuid>, Vec<MassFunction>> = HashMap::new();
    for (_, agent_id, mass) in rows {
        agent_groups
            .entry(*agent_id)
            .or_default()
            .push(mass.clone());
    }

    let agents: Vec<Option<Uuid>> = agent_groups.keys().copied().collect();
    let agent_masses: Vec<Vec<MassFunction>> = agents
        .iter()
        .map(|a| agent_groups.get(a).cloned().unwrap_or_default())
        .collect();

    if agents.len() <= 1 {
        let all: Vec<MassFunction> = agent_masses.into_iter().flatten().collect();
        return Ok(IndependenceAnalysis::all_independent(all));
    }

    // For each pair of agents, find a representative claim and check LCA
    // Representative claim = first claim_id from each agent's submissions
    let mut agent_rep_claims: HashMap<Option<Uuid>, Uuid> = HashMap::new();
    for (_, agent_id, _) in rows {
        agent_rep_claims.entry(*agent_id).or_insert_with(|| {
            rows.iter()
                .find(|(_, a, _)| a == agent_id)
                .map(|(id, _, _)| *id)
                .unwrap_or_else(Uuid::nil)
        });
    }

    let mut dependent_pairs = Vec::new();
    let mut lca_findings = Vec::new();

    for i in 0..agents.len() {
        for j in (i + 1)..agents.len() {
            let claim_a = agent_rep_claims
                .get(&agents[i])
                .copied()
                .unwrap_or_else(Uuid::nil);
            let claim_b = agent_rep_claims
                .get(&agents[j])
                .copied()
                .unwrap_or_else(Uuid::nil);

            if let Some(lca) =
                epigraph_db::LineageRepository::get_lca(pool, claim_a, claim_b, Some(max_lca_depth))
                    .await
                    .map_err(|e| crate::errors::ApiError::DatabaseError {
                        message: format!("LCA query failed: {e}"),
                    })?
            {
                dependent_pairs.push((i, j));
                lca_findings.push(LcaFinding {
                    agent_a: agents[i],
                    agent_b: agents[j],
                    ancestor_id: lca.ancestor_id,
                    total_depth: lca.total_depth,
                });
            }
        }
    }

    Ok(build_analysis(
        &agent_masses,
        &dependent_pairs,
        lca_findings,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ds::frame::FrameOfDiscernment;
    use epigraph_ds::mass::MassFunction;

    fn make_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("test", vec!["H0".to_string(), "H1".to_string()]).unwrap()
    }

    fn make_bba(h0_mass: f64, h1_mass: f64) -> MassFunction {
        let frame = make_frame();
        let mut masses = std::collections::BTreeMap::new();
        masses.insert("0".to_string(), h0_mass);
        masses.insert("1".to_string(), h1_mass);
        masses.insert("0,1".to_string(), 1.0 - h0_mass - h1_mass);
        MassFunction::from_json_masses(frame, &serde_json::json!(masses)).unwrap()
    }

    #[test]
    fn test_all_independent_shortcut() {
        let masses = vec![make_bba(0.6, 0.1), make_bba(0.3, 0.4)];
        let analysis = IndependenceAnalysis::all_independent(masses.clone());
        assert!(analysis.dependent_groups.is_empty());
        assert_eq!(analysis.independent.len(), 2);
        assert!(analysis.lca_findings.is_empty());
    }

    #[test]
    fn test_independent_bbas_no_dependent_pairs() {
        // Two agents, no shared provenance → all independent
        let agent_masses = vec![vec![make_bba(0.6, 0.1)], vec![make_bba(0.3, 0.4)]];
        let analysis = build_analysis(&agent_masses, &[], vec![]);
        assert!(analysis.dependent_groups.is_empty());
        assert_eq!(analysis.independent.len(), 2);
    }

    #[test]
    fn test_dependent_bbas_grouped() {
        // Two agents sharing LCA → grouped together
        let agent_masses = vec![vec![make_bba(0.6, 0.1)], vec![make_bba(0.3, 0.4)]];
        let finding = LcaFinding {
            agent_a: Some(Uuid::nil()),
            agent_b: Some(Uuid::nil()),
            ancestor_id: Uuid::nil(),
            total_depth: 2,
        };
        let analysis = build_analysis(&agent_masses, &[(0, 1)], vec![finding]);
        assert_eq!(analysis.dependent_groups.len(), 1);
        assert_eq!(analysis.dependent_groups[0].len(), 2);
        assert!(analysis.independent.is_empty());
        assert_eq!(analysis.lca_findings.len(), 1);
    }

    #[test]
    fn test_mixed_dependence() {
        // 3 agents: 0+1 dependent, 2 independent
        let agent_masses = vec![
            vec![make_bba(0.6, 0.1)],
            vec![make_bba(0.3, 0.4)],
            vec![make_bba(0.5, 0.2)],
        ];
        let analysis = build_analysis(&agent_masses, &[(0, 1)], vec![]);
        assert_eq!(analysis.dependent_groups.len(), 1);
        assert_eq!(analysis.dependent_groups[0].len(), 2);
        assert_eq!(analysis.independent.len(), 1);
    }

    #[test]
    fn test_single_agent_is_independent() {
        let agent_masses = vec![vec![make_bba(0.6, 0.1)]];
        let analysis = build_analysis(&agent_masses, &[], vec![]);
        assert!(analysis.dependent_groups.is_empty());
        assert_eq!(analysis.independent.len(), 1);
    }
}
