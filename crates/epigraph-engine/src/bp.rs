//! Loopy belief propagation over the factor graph.
//!
//! Variables are claims (with pignistic probabilities).
//! Factors are constraints (mutual exclusion, evidential support, etc.).
//! Messages flow between factors and variables until convergence.

use std::collections::HashMap;
use uuid::Uuid;

/// Known factor potential types (parsed from JSONB).
#[derive(Debug, Clone)]
pub enum FactorPotential {
    /// Variables should sum to at most 1 (competing hypotheses).
    MutualExclusion,
    /// Symmetric bidirectional support with equal strength both ways.
    EvidentialSupport { strength: f64 },
    /// Asymmetric support: source_var's truth influences the other variable
    /// with forward_strength, and the other variable's truth influences
    /// source_var with reverse_strength.
    DirectionalSupport {
        source_var: Uuid,
        forward_strength: f64,
        reverse_strength: f64,
    },
    /// General conditional probability table (key: joint assignment string).
    ConditionalDependence { table: HashMap<String, f64> },
    /// Temporal ordering: first variable's truth should precede second's.
    TemporalOrdering { threshold: f64 },
    /// Shared experimental evidence: hypotheses sharing an analysis node
    /// receive correlated belief updates proportional to strength.
    SharedEvidence { strength: f64 },
}

impl FactorPotential {
    /// Parse a factor potential from database fields.
    pub fn from_db(factor_type: &str, potential: &serde_json::Value) -> Option<Self> {
        match factor_type {
            "mutual_exclusion" => Some(Self::MutualExclusion),
            "evidential_support" => {
                let strength = potential
                    .get("strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.8);
                Some(Self::EvidentialSupport { strength })
            }
            "directional_support" => {
                let source_var = potential
                    .get("source_var")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Uuid>().ok())?;
                let forward_strength = potential
                    .get("forward_strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5);
                let reverse_strength = potential
                    .get("reverse_strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.15);
                Some(Self::DirectionalSupport {
                    source_var,
                    forward_strength,
                    reverse_strength,
                })
            }
            "conditional_dependence" => {
                let table = potential
                    .as_object()?
                    .iter()
                    .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
                    .collect();
                Some(Self::ConditionalDependence { table })
            }
            "temporal_ordering" => {
                let threshold = potential
                    .get("threshold")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5);
                Some(Self::TemporalOrdering { threshold })
            }
            "shared_evidence" => {
                let strength = potential
                    .get("strength")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.7);
                Some(Self::SharedEvidence { strength })
            }
            _ => None,
        }
    }
}

/// Configuration for belief propagation.
#[derive(Debug, Clone)]
pub struct BpConfig {
    pub max_iterations: usize,
    pub convergence_threshold: f64,
    pub damping: f64,
}

impl Default for BpConfig {
    fn default() -> Self {
        Self {
            max_iterations: 20,
            convergence_threshold: 0.01,
            damping: 0.5,
        }
    }
}

/// Result of a belief propagation run.
#[derive(Debug, Clone)]
pub struct BpResult {
    pub iterations: usize,
    pub converged: bool,
    pub max_change: f64,
    pub updated_beliefs: Vec<(Uuid, f64)>,
    pub messages_sent: usize,
}

/// Compute factor-to-variable message for a single factor.
fn compute_factor_message(
    potential: &FactorPotential,
    factor_vars: &[Uuid],
    target_var: Uuid,
    beliefs: &HashMap<Uuid, f64>,
) -> f64 {
    match potential {
        FactorPotential::MutualExclusion => {
            // Message to target = product of (1 - belief_i) for all other variables
            let mut product = 1.0;
            for &var in factor_vars {
                if var != target_var {
                    let b = beliefs.get(&var).copied().unwrap_or(0.5);
                    product *= 1.0 - b;
                }
            }
            product
        }
        FactorPotential::EvidentialSupport { strength } => {
            // Symmetric: both variables influence each other equally.
            if factor_vars.len() >= 2 {
                let other = if target_var == factor_vars[0] {
                    factor_vars[1]
                } else {
                    factor_vars[0]
                };
                let other_belief = beliefs.get(&other).copied().unwrap_or(0.5);
                strength * other_belief
            } else {
                0.5
            }
        }
        FactorPotential::DirectionalSupport {
            source_var,
            forward_strength,
            reverse_strength,
        } => {
            if factor_vars.len() >= 2 {
                let strength = if target_var == *source_var {
                    *reverse_strength
                } else {
                    *forward_strength
                };
                if strength < 1e-9 {
                    return 0.5;
                }
                let other = if target_var == factor_vars[0] {
                    factor_vars[1]
                } else {
                    factor_vars[0]
                };
                let other_belief = beliefs.get(&other).copied().unwrap_or(0.5);
                strength * other_belief
            } else {
                0.5
            }
        }
        FactorPotential::ConditionalDependence { table } => {
            // Directed dependency: factor_vars[0] is source, factor_vars[1] is target.
            //
            // Message to target  = source_belief * source_weight + target_prior * (1 - source_weight)
            //   — the source pulls the target's belief toward itself, weighted by the
            //     mean conditional probability derived from the CPT table entries.
            //     This is a proper weighted-average marginalization over the source state.
            //
            // Message to source  = source prior
            //   — in a directed A→B dependency the source is not influenced by the target.
            //
            // Message to any other variable = its prior (factor is not about that variable).
            if factor_vars.len() < 2 {
                return beliefs.get(&target_var).copied().unwrap_or(0.5);
            }
            let source_var = factor_vars[0];
            let dep_target_var = factor_vars[1];

            if target_var == dep_target_var {
                // Derive source_weight from the CPT table: use the mean of all table
                // values as an aggregate conditional strength.  Falls back to 0.5 when
                // the table is empty (uninformative prior).
                let source_weight = if table.is_empty() {
                    0.5
                } else {
                    let sum: f64 = table.values().sum();
                    (sum / table.len() as f64).clamp(0.0, 1.0)
                };
                let source_belief = beliefs.get(&source_var).copied().unwrap_or(0.5);
                let target_prior = beliefs.get(&dep_target_var).copied().unwrap_or(0.5);
                source_belief * source_weight + target_prior * (1.0 - source_weight)
            } else if target_var == source_var {
                // Source is not influenced by its dependents in a directed graph.
                beliefs.get(&source_var).copied().unwrap_or(0.5)
            } else {
                // Variable not part of this factor's directed relationship.
                beliefs.get(&target_var).copied().unwrap_or(0.5)
            }
        }
        FactorPotential::TemporalOrdering { threshold } => {
            // If first variable's belief > threshold, second should also be high
            if factor_vars.len() >= 2 && target_var == factor_vars[1] {
                let first_belief = beliefs.get(&factor_vars[0]).copied().unwrap_or(0.5);
                if first_belief > *threshold {
                    first_belief
                } else {
                    0.5
                }
            } else {
                0.5
            }
        }
        FactorPotential::SharedEvidence { strength } => {
            // Symmetric positive correlation: if one hypothesis is supported
            // by shared evidence, the other receives proportional signal.
            if factor_vars.len() >= 2 {
                let other = if target_var == factor_vars[0] {
                    factor_vars[1]
                } else {
                    factor_vars[0]
                };
                let other_belief = beliefs.get(&other).copied().unwrap_or(0.5);
                strength * other_belief
            } else {
                0.5
            }
        }
    }
}

/// Run one BP iteration. Returns max belief change.
///
/// `priors` are the original evidence-derived beliefs (anchors).
/// The update blends the geometric mean of factor messages with the prior,
/// preventing cascade collapse on dense graphs.
pub fn bp_iteration(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    current_beliefs: &mut HashMap<Uuid, f64>,
    priors: &HashMap<Uuid, f64>,
    messages_f2v: &mut HashMap<(Uuid, Uuid), f64>,
    damping: f64,
) -> (f64, usize) {
    let mut max_change: f64 = 0.0;
    let mut msg_count = 0;

    // Factor → variable messages
    for (factor_id, potential, vars) in factors {
        for &var in vars {
            let msg = compute_factor_message(potential, vars, var, current_beliefs);
            messages_f2v.insert((*factor_id, var), msg);
            msg_count += 1;
        }
    }

    // Variable update: aggregate incoming factor messages
    // For each variable, collect all factor messages targeting it
    let mut var_messages: HashMap<Uuid, Vec<f64>> = HashMap::new();
    for ((_, var), &msg) in messages_f2v.iter() {
        var_messages.entry(*var).or_default().push(msg);
    }

    for (var, msgs) in &var_messages {
        let old = current_beliefs.get(var).copied().unwrap_or(0.5);
        let prior = priors.get(var).copied().unwrap_or(0.5);

        // Geometric mean of incoming factor messages (degree-invariant).
        let n = msgs.len() as f64;
        let log_sum: f64 = msgs.iter().map(|m| m.max(1e-12).ln()).sum();
        let factor_signal = (log_sum / n).exp().clamp(0.01, 0.99);

        // Blend: 50% prior anchor + 50% factor signal.
        // This prevents cascade collapse while allowing inter-claim
        // consistency to adjust beliefs away from pure evidence.
        let raw_new = 0.5 * prior + 0.5 * factor_signal;
        let dampened = damping * old + (1.0 - damping) * raw_new;
        let new_belief = dampened.clamp(0.01, 0.99);

        let change = (new_belief - old).abs();
        max_change = max_change.max(change);
        current_beliefs.insert(*var, new_belief);
    }

    (max_change, msg_count)
}

/// Run loopy BP to convergence.
pub fn run_bp(
    factors: &[(Uuid, FactorPotential, Vec<Uuid>)],
    initial_beliefs: &HashMap<Uuid, f64>,
    config: &BpConfig,
) -> BpResult {
    if factors.is_empty() {
        return BpResult {
            iterations: 0,
            converged: true,
            max_change: 0.0,
            updated_beliefs: initial_beliefs.iter().map(|(&k, &v)| (k, v)).collect(),
            messages_sent: 0,
        };
    }

    let mut beliefs = initial_beliefs.clone();
    let mut messages_f2v: HashMap<(Uuid, Uuid), f64> = HashMap::new();
    let mut total_messages = 0;
    let mut last_max_change = 0.0;

    for iter in 0..config.max_iterations {
        let (max_change, msg_count) = bp_iteration(
            factors,
            &mut beliefs,
            initial_beliefs,
            &mut messages_f2v,
            config.damping,
        );
        total_messages += msg_count;
        last_max_change = max_change;

        if max_change < config.convergence_threshold {
            return BpResult {
                iterations: iter + 1,
                converged: true,
                max_change,
                updated_beliefs: beliefs.into_iter().collect(),
                messages_sent: total_messages,
            };
        }
    }

    BpResult {
        iterations: config.max_iterations,
        converged: false,
        max_change: last_max_change,
        updated_beliefs: beliefs.into_iter().collect(),
        messages_sent: total_messages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutual_exclusion_two_variables() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let factors = vec![(Uuid::new_v4(), FactorPotential::MutualExclusion, vec![a, b])];
        // Both start high — should be pushed down
        let beliefs = HashMap::from([(a, 0.8), (b, 0.8)]);
        let config = BpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.3,
        };
        let result = run_bp(&factors, &beliefs, &config);
        let final_a = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == a)
            .unwrap()
            .1;
        let final_b = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == b)
            .unwrap()
            .1;
        // With mutual exclusion, both should decrease from 0.8
        assert!(
            final_a < 0.8 || final_b < 0.8,
            "Mutual exclusion should reduce at least one belief: a={}, b={}",
            final_a,
            final_b
        );
    }

    #[test]
    fn test_evidential_support() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::EvidentialSupport { strength: 0.9 },
            vec![a, b],
        )];
        // A is high, B starts at 0.5 — B should increase toward A
        let beliefs = HashMap::from([(a, 0.9), (b, 0.5)]);
        let config = BpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.5,
        };
        let result = run_bp(&factors, &beliefs, &config);
        let final_a = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == a)
            .unwrap()
            .1;
        let final_b = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == b)
            .unwrap()
            .1;
        // With evidential support, A and B should converge toward similar values
        assert!(
            (final_a - final_b).abs() < 0.3,
            "Evidential support should bring beliefs closer: a={}, b={}",
            final_a,
            final_b
        );
    }

    #[test]
    fn test_empty_factor_graph() {
        let beliefs = HashMap::from([(Uuid::new_v4(), 0.5)]);
        let config = BpConfig::default();
        let result = run_bp(&[], &beliefs, &config);
        assert!(result.converged);
        assert_eq!(result.iterations, 0);
    }

    #[test]
    fn test_convergence_detection() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::EvidentialSupport { strength: 0.5 },
            vec![a, b],
        )];
        // Consistent beliefs — should converge fast
        let beliefs = HashMap::from([(a, 0.5), (b, 0.5)]);
        let config = BpConfig {
            max_iterations: 100,
            convergence_threshold: 0.01,
            damping: 0.5,
        };
        let result = run_bp(&factors, &beliefs, &config);
        assert!(result.converged, "Should converge for consistent input");
        assert!(
            result.iterations < 100,
            "Should converge in fewer than max iterations"
        );
    }

    #[test]
    fn test_factor_potential_from_db() {
        // Mutual exclusion
        let me = FactorPotential::from_db("mutual_exclusion", &serde_json::json!({}));
        assert!(matches!(me, Some(FactorPotential::MutualExclusion)));

        // Evidential support
        let es =
            FactorPotential::from_db("evidential_support", &serde_json::json!({"strength": 0.75}));
        assert!(
            matches!(es, Some(FactorPotential::EvidentialSupport { strength }) if (strength - 0.75).abs() < 1e-9)
        );

        // Unknown type
        let unk = FactorPotential::from_db("unknown_type", &serde_json::json!({}));
        assert!(unk.is_none());
    }

    #[test]
    fn test_shared_evidence_positive_correlation() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::SharedEvidence { strength: 0.7 },
            vec![a, b],
        )];
        let beliefs = HashMap::from([(a, 0.8), (b, 0.3)]);
        let config = BpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.5,
        };
        let result = run_bp(&factors, &beliefs, &config);
        let final_b = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == b)
            .unwrap()
            .1;
        assert!(
            final_b > 0.3,
            "SharedEvidence should pull B toward A: got {}",
            final_b
        );
    }

    #[test]
    fn test_shared_evidence_from_db() {
        let se =
            FactorPotential::from_db("shared_evidence", &serde_json::json!({"strength": 0.65}));
        assert!(
            matches!(se, Some(FactorPotential::SharedEvidence { strength }) if (strength - 0.65).abs() < 1e-9)
        );
    }

    #[test]
    fn test_conditional_dependence_belief_moves_toward_source() {
        // A→B directed dependency: A has high belief (0.9), B starts low (0.2).
        // The CPT table encodes P(B=1 | A=1) = 0.8, giving source_weight = 0.8.
        // Expected: after BP B's belief should increase above its prior of 0.2.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let table = HashMap::from([("1_1".to_string(), 0.8_f64)]);
        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::ConditionalDependence { table },
            vec![a, b],
        )];
        let beliefs = HashMap::from([(a, 0.9), (b, 0.2)]);
        let config = BpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.5,
        };
        let result = run_bp(&factors, &beliefs, &config);

        let final_a = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == a)
            .unwrap()
            .1;
        let final_b = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == b)
            .unwrap()
            .1;

        // B's belief must increase from its prior of 0.2 because A (the source) has
        // high belief and the conditional weight is 0.8.
        assert!(
            final_b > 0.2,
            "ConditionalDependence: B's belief should rise toward A; got b={}",
            final_b
        );
        // A's belief (the source) must not be inflated by B — the dependency is directed.
        // A started at 0.9; it should not exceed its prior by more than a small damping margin.
        assert!(
            final_a <= 0.9 + 0.05,
            "ConditionalDependence: source A should not be inflated by target; got a={}",
            final_a
        );
    }

    #[test]
    fn test_conditional_dependence_uninformative_table_is_neutral() {
        // When the table is empty the source_weight defaults to 0.5, giving a
        // symmetric blend — B should still move off its prior toward A.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let table: HashMap<String, f64> = HashMap::new();
        let factors = vec![(
            Uuid::new_v4(),
            FactorPotential::ConditionalDependence { table },
            vec![a, b],
        )];
        // A is high, B is at prior 0.5.  With source_weight=0.5 the message is
        // 0.9*0.5 + 0.5*0.5 = 0.7, which should push B above 0.5.
        let beliefs = HashMap::from([(a, 0.9), (b, 0.5)]);
        let config = BpConfig {
            max_iterations: 50,
            convergence_threshold: 0.001,
            damping: 0.5,
        };
        let result = run_bp(&factors, &beliefs, &config);
        let final_b = result
            .updated_beliefs
            .iter()
            .find(|(id, _)| *id == b)
            .unwrap()
            .1;
        assert!(
            final_b > 0.5,
            "Uninformative ConditionalDependence with high source should still lift target; got b={}",
            final_b
        );
    }
}
