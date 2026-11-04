//! Same-human dependence analysis for BBA combination (G1, G11; ruling R-36)
//!
//! When multiple agents submit evidence (BBAs) for the same claim,
//! Dempster's rule assumes independence. Agents that act for the SAME human
//! are not independent sources: ruling Q-U027F-2 says they replace or
//! contest, never aggregate, and ruling R-36 applies that to every
//! BBA-combining path. Their BBAs are therefore reduced by Denoeux's cautious
//! rule (`epigraph_engine::source_dependence::cautious_reduce`, built on
//! `epigraph_ds::combination::cautious_rule`) before standard combination.
//! The older min-commonality `combination::cautious_combine` is not used: it
//! drops open-world mass, which every default-shaped assessment carries.
//!
//! The owner of an agent is the live human it resolves to (migration 149's
//! `epigraph_human_of(agent, true)`), else the agent itself, exactly as
//! `/claims/:id/assess` keys its owner slot. This replaced a provenance-LCA
//! test that passed `mass_functions` row ids to `get_lca` (which walks claim
//! lineage), so it never found a shared ancestor and every agent folded as
//! independent.

use epigraph_ds::mass::MassFunction;
use uuid::Uuid;

/// Result of the same-human dependence analysis
#[derive(Debug, Clone)]
pub struct IndependenceAnalysis {
    /// Groups of BBAs written by sibling agents of one owner (each group is
    /// reduced by `source_dependence::cautious_reduce`)
    pub dependent_groups: Vec<Vec<MassFunction>>,
    /// BBAs whose owner has no other agent among the rows (get standard
    /// combine_multiple)
    pub independent: Vec<MassFunction>,
    /// Audit trail: which owners' agents were grouped
    pub owner_findings: Vec<OwnerFinding>,
}

/// Record of agents found to act for one owner
#[derive(Debug, Clone)]
pub struct OwnerFinding {
    /// The live human the agents act for (or the agent itself)
    pub owner_id: Uuid,
    /// The distinct source agents grouped under it, in row order
    pub agents: Vec<Uuid>,
}

impl IndependenceAnalysis {
    /// Shortcut: treat all BBAs as independent (for single-BBA or bypass cases)
    pub fn all_independent(masses: Vec<MassFunction>) -> Self {
        Self {
            dependent_groups: vec![],
            independent: masses,
            owner_findings: vec![],
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
/// `agent_masses` holds each agent's BBAs, by agent position.
/// `dependent_pairs` lists pairs of agent positions that act for one owner.
pub fn build_analysis(
    agent_masses: &[Vec<MassFunction>],
    dependent_pairs: &[(usize, usize)],
    owner_findings: Vec<OwnerFinding>,
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
            // Multiple agents of one owner = dependent group
            dependent_groups.push(group_masses);
        }
    }

    IndependenceAnalysis {
        dependent_groups,
        independent,
        owner_findings,
    }
}

/// Analyze the same-human dependence of a set of BBAs.
///
/// Groups BBAs by `source_agent_id`, resolves each agent's owner in one
/// batched read (`AgentRepository::humans_of`, live bindings only), and marks
/// every pair of distinct agents with the same owner as dependent. A row with
/// no source agent is its own (independent) group.
#[cfg(feature = "db")]
pub async fn analyze_independence(
    pool: &sqlx::PgPool,
    rows: &[(Uuid, Option<Uuid>, MassFunction)],
) -> Result<IndependenceAnalysis, crate::errors::ApiError> {
    // Group BBAs by source_agent_id, in row order.
    let mut agents: Vec<Option<Uuid>> = Vec::new();
    let mut agent_masses: Vec<Vec<MassFunction>> = Vec::new();
    for (_, agent_id, mass) in rows {
        match agents.iter().position(|a| a == agent_id) {
            Some(i) => agent_masses[i].push(mass.clone()),
            None => {
                agents.push(*agent_id);
                agent_masses.push(vec![mass.clone()]);
            }
        }
    }

    if agents.len() <= 1 {
        let all: Vec<MassFunction> = agent_masses.into_iter().flatten().collect();
        return Ok(IndependenceAnalysis::all_independent(all));
    }

    let known: Vec<Uuid> = agents.iter().flatten().copied().collect();
    let humans = epigraph_db::AgentRepository::humans_of(pool, &known, true)
        .await
        .map_err(|e| crate::errors::ApiError::DatabaseError {
            message: format!("owner lookup failed: {e}"),
        })?;
    let owner_of = |agent: Option<Uuid>| agent.map(|a| humans.get(&a).copied().unwrap_or(a));

    let mut dependent_pairs = Vec::new();
    let mut owner_findings: Vec<OwnerFinding> = Vec::new();
    for i in 0..agents.len() {
        let Some(owner) = owner_of(agents[i]) else {
            continue;
        };
        // The first earlier agent of the same owner, if any: one union per
        // agent is enough for the transitive closure.
        if let Some(j) = (0..i).find(|&j| owner_of(agents[j]) == Some(owner)) {
            dependent_pairs.push((j, i));
            let agent_i = agents[i].expect("an owner implies an agent");
            match owner_findings.iter_mut().find(|f| f.owner_id == owner) {
                Some(f) => f.agents.push(agent_i),
                None => owner_findings.push(OwnerFinding {
                    owner_id: owner,
                    agents: vec![agents[j].expect("an owner implies an agent"), agent_i],
                }),
            }
        }
    }

    Ok(build_analysis(
        &agent_masses,
        &dependent_pairs,
        owner_findings,
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
        assert!(analysis.owner_findings.is_empty());
    }

    #[test]
    fn test_independent_bbas_no_dependent_pairs() {
        // Two agents of different owners → all independent
        let agent_masses = vec![vec![make_bba(0.6, 0.1)], vec![make_bba(0.3, 0.4)]];
        let analysis = build_analysis(&agent_masses, &[], vec![]);
        assert!(analysis.dependent_groups.is_empty());
        assert_eq!(analysis.independent.len(), 2);
    }

    #[test]
    fn test_dependent_bbas_grouped() {
        // Two agents of one owner → grouped together
        let agent_masses = vec![vec![make_bba(0.6, 0.1)], vec![make_bba(0.3, 0.4)]];
        let finding = OwnerFinding {
            owner_id: Uuid::nil(),
            agents: vec![Uuid::from_u128(1), Uuid::from_u128(2)],
        };
        let analysis = build_analysis(&agent_masses, &[(0, 1)], vec![finding]);
        assert_eq!(analysis.dependent_groups.len(), 1);
        assert_eq!(analysis.dependent_groups[0].len(), 2);
        assert!(analysis.independent.is_empty());
        assert_eq!(analysis.owner_findings.len(), 1);
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
