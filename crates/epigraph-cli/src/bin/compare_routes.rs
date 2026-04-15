//! Comparative Graph Reasoning Analysis
//!
//! Runs the Ascent reasoning engine against 4 database variants
//! (baseline + 3 evidence-promotion routes) and computes information
//! entropy metrics to identify the most informative architecture.
//!
//! # Usage
//! ```bash
//! cargo run --bin compare_routes
//! ```

use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

struct DbConfig {
    name: &'static str,
    url: String,
    /// Whether to load evidence as graph nodes
    load_evidence_nodes: bool,
    /// Whether to load evidence→claim and evidence→evidence edges
    load_evidence_edges: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
struct RouteMetrics {
    name: String,
    // Raw counts
    nodes: usize,
    claim_nodes: usize,
    evidence_nodes: usize,
    input_edges: usize,
    // Ascent-derived (original)
    transitive_supports: usize,
    indirect_transitive_supports: usize,
    contradictions: usize,
    elaboration_chains: usize,
    support_clusters: usize,
    indirect_challenges: usize,
    connected_components: usize,
    largest_component: usize,
    // Ascent-derived (extended: corroboration, co-evidence, aggregation, negation)
    corroboration_chains: usize,
    co_evidence_supports: usize,
    max_evidence_weight: usize,
    mean_evidence_weight: f64,
    unsupported_claims: usize,
    // Information metrics
    edge_type_entropy: f64,
    strength_entropy: f64,
    degree_entropy: f64,
    derived_fact_density: f64,
    connectivity_ratio: f64,
    // Timing
    analysis_ms: u128,
}

fn shannon_entropy(counts: &[usize]) -> f64 {
    let total: usize = counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total_f = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f;
            -p * p.log2()
        })
        .sum()
}

async fn load_and_analyze(config: &DbConfig) -> Result<RouteMetrics, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&config.url)
        .await?;

    // Load claims
    let claim_rows = sqlx::query("SELECT id, truth_value FROM claims")
        .fetch_all(&pool)
        .await?;

    let mut claims: Vec<ReasoningClaim> = claim_rows
        .iter()
        .map(|row| ReasoningClaim {
            id: row.get("id"),
            truth_value: row.get("truth_value"),
        })
        .collect();

    let claim_count = claims.len();
    let mut evidence_count = 0;

    // Load evidence nodes if applicable (Route C)
    if config.load_evidence_nodes {
        let has_table: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'evidence_nodes')",
        )
        .fetch_one(&pool)
        .await?;

        if has_table {
            let ev_rows = sqlx::query("SELECT id, truth_value FROM evidence_nodes")
                .fetch_all(&pool)
                .await?;

            evidence_count = ev_rows.len();
            for row in &ev_rows {
                claims.push(ReasoningClaim {
                    id: row.get("id"),
                    truth_value: row.get("truth_value"),
                });
            }
        }
    }

    // Load edges — always load claim→claim
    let edge_query = if config.load_evidence_edges {
        // Load ALL edges (claim→claim, evidence→claim, evidence→evidence)
        "SELECT source_id, target_id, relationship, properties FROM edges"
    } else {
        // Only claim→claim
        "SELECT source_id, target_id, relationship, properties FROM edges \
         WHERE source_type = 'claim' AND target_type = 'claim'"
    };

    let edge_rows = sqlx::query(edge_query).fetch_all(&pool).await?;

    let edges: Vec<ReasoningEdge> = edge_rows
        .iter()
        .map(|row| {
            let properties: serde_json::Value = row.get("properties");
            let strength = properties
                .get("strength")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            ReasoningEdge {
                source_id: row.get("source_id"),
                target_id: row.get("target_id"),
                relationship: row.get("relationship"),
                strength,
            }
        })
        .collect();

    pool.close().await;

    // Compute edge type distribution for entropy
    let mut edge_type_counts: HashMap<String, usize> = HashMap::new();
    for e in &edges {
        *edge_type_counts.entry(e.relationship.clone()).or_default() += 1;
    }
    let edge_type_entropy =
        shannon_entropy(&edge_type_counts.values().copied().collect::<Vec<_>>());

    // Compute strength distribution entropy (10 buckets)
    let mut strength_buckets = [0usize; 10];
    for e in &edges {
        let bucket = (e.strength * 10.0).min(9.0) as usize;
        strength_buckets[bucket] += 1;
    }
    let strength_entropy = shannon_entropy(&strength_buckets);

    // Compute degree distribution entropy
    let mut in_degree: HashMap<Uuid, usize> = HashMap::new();
    let mut out_degree: HashMap<Uuid, usize> = HashMap::new();
    for e in &edges {
        *out_degree.entry(e.source_id).or_default() += 1;
        *in_degree.entry(e.target_id).or_default() += 1;
    }
    let mut degree_counts: HashMap<usize, usize> = HashMap::new();
    let all_nodes: HashSet<Uuid> = claims.iter().map(|c| c.id).collect();
    for node in &all_nodes {
        let total_deg = in_degree.get(node).unwrap_or(&0) + out_degree.get(node).unwrap_or(&0);
        *degree_counts.entry(total_deg).or_default() += 1;
    }
    let degree_entropy = shannon_entropy(&degree_counts.values().copied().collect::<Vec<_>>());

    // Track which (source,target) pairs are direct support edges
    let direct_support_pairs: HashSet<(Uuid, Uuid)> = edges
        .iter()
        .filter(|e| e.relationship == "supports")
        .map(|e| (e.source_id, e.target_id))
        .collect();

    // Run reasoning engine
    let start = std::time::Instant::now();
    let result = ReasoningEngine::analyze(&claims, &edges);
    let analysis_ms = start.elapsed().as_millis();

    // Count indirect transitive supports (not direct edges)
    let indirect_ts = result
        .transitive_supports
        .iter()
        .filter(|ts| !direct_support_pairs.contains(&(ts.source, ts.target)))
        .count();

    let total_derived = result.transitive_supports.len()
        + result.contradictions.len()
        + result.elaboration_chains.len()
        + result.indirect_challenges.len()
        + result.corroboration_chains.len()
        + result.co_evidence_supports.len();
    let node_count = claims.len();
    let derived_fact_density = if node_count > 0 {
        total_derived as f64 / node_count as f64
    } else {
        0.0
    };

    let max_evidence_weight = result
        .evidence_weights
        .iter()
        .map(|(_, w)| *w)
        .max()
        .unwrap_or(0);
    let mean_evidence_weight = if result.evidence_weights.is_empty() {
        0.0
    } else {
        result
            .evidence_weights
            .iter()
            .map(|(_, w)| *w as f64)
            .sum::<f64>()
            / result.evidence_weights.len() as f64
    };

    let largest_component = result
        .connected_components
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0);

    let connectivity_ratio = if node_count > 0 {
        largest_component as f64 / node_count as f64
    } else {
        0.0
    };

    Ok(RouteMetrics {
        name: config.name.to_string(),
        nodes: node_count,
        claim_nodes: claim_count,
        evidence_nodes: evidence_count,
        input_edges: edges.len(),
        transitive_supports: result.transitive_supports.len(),
        indirect_transitive_supports: indirect_ts,
        contradictions: result.contradictions.len(),
        elaboration_chains: result.elaboration_chains.len(),
        support_clusters: result.support_clusters.len(),
        indirect_challenges: result.indirect_challenges.len(),
        connected_components: result.connected_components.len(),
        largest_component,
        corroboration_chains: result.corroboration_chains.len(),
        co_evidence_supports: result.co_evidence_supports.len(),
        max_evidence_weight,
        mean_evidence_weight,
        unsupported_claims: result.unsupported_claims.len(),
        edge_type_entropy,
        strength_entropy,
        degree_entropy,
        derived_fact_density,
        connectivity_ratio,
        analysis_ms,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let base = "postgresql://epigraph:epigraph@localhost:5432";

    let configs = vec![
        DbConfig {
            name: "Baseline (claims only)",
            url: format!("{base}/epigraph"),
            load_evidence_nodes: false,
            load_evidence_edges: false,
        },
        DbConfig {
            name: "Route A (edge-linked evidence)",
            url: format!("{base}/epigraph_route_a"),
            load_evidence_nodes: false,
            load_evidence_edges: true,
        },
        DbConfig {
            name: "Route B (cross-claim links)",
            url: format!("{base}/epigraph_route_b"),
            load_evidence_nodes: false,
            load_evidence_edges: true,
        },
        DbConfig {
            name: "Route C (full graph promotion)",
            url: format!("{base}/epigraph_route_c"),
            load_evidence_nodes: true,
            load_evidence_edges: true,
        },
    ];

    println!("=== EpiGraph Evidence Architecture Comparison ===\n");

    let mut all_metrics: Vec<RouteMetrics> = Vec::new();

    for config in &configs {
        println!("Analyzing: {} ...", config.name);
        match load_and_analyze(config).await {
            Ok(metrics) => {
                println!(
                    "  {} nodes, {} edges, {} transitive supports -> {}ms",
                    metrics.nodes,
                    metrics.input_edges,
                    metrics.transitive_supports,
                    metrics.analysis_ms
                );
                all_metrics.push(metrics);
            }
            Err(e) => {
                println!("  ERROR: {e}");
            }
        }
    }

    // ===================================================================
    // COMPARATIVE REPORT
    // ===================================================================

    println!("\n{}", "=".repeat(90));
    println!("  COMPARATIVE RESULTS");
    println!("{}\n", "=".repeat(90));

    // Header
    println!(
        "{:<32} {:>8} {:>8} {:>8} {:>10} {:>10}",
        "Route", "Nodes", "Edges", "Comps", "Trans.Sup", "Time(ms)"
    );
    println!("{}", "-".repeat(90));
    for m in &all_metrics {
        println!(
            "{:<32} {:>8} {:>8} {:>8} {:>10} {:>10}",
            m.name,
            m.nodes,
            m.input_edges,
            m.connected_components,
            m.transitive_supports,
            m.analysis_ms
        );
    }

    println!("\n{}", "=".repeat(90));
    println!("  DERIVED FACTS COMPARISON");
    println!("{}\n", "=".repeat(90));

    println!(
        "{:<32} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Route", "Indirect", "Contrad.", "Elab.Ch", "Clusters", "Ind.Chall"
    );
    println!("{}", "-".repeat(90));
    for m in &all_metrics {
        println!(
            "{:<32} {:>10} {:>10} {:>10} {:>10} {:>10}",
            m.name,
            m.indirect_transitive_supports,
            m.contradictions,
            m.elaboration_chains,
            m.support_clusters,
            m.indirect_challenges
        );
    }

    println!("\n{}", "=".repeat(90));
    println!("  EXTENDED REASONING (corroboration, co-evidence, aggregation)");
    println!("{}\n", "=".repeat(90));

    println!(
        "{:<32} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Route", "Corrob.Ch", "CoEv.Sup", "MaxEvWt", "MeanEvWt", "Unsupport"
    );
    println!("{}", "-".repeat(90));
    for m in &all_metrics {
        println!(
            "{:<32} {:>10} {:>10} {:>10} {:>10.2} {:>10}",
            m.name,
            m.corroboration_chains,
            m.co_evidence_supports,
            m.max_evidence_weight,
            m.mean_evidence_weight,
            m.unsupported_claims
        );
    }

    println!("\n{}", "=".repeat(90));
    println!("  INFORMATION ENTROPY METRICS");
    println!("{}\n", "=".repeat(90));

    println!(
        "{:<32} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "Route", "EdgeType H", "Strength H", "Degree H", "Density", "Connect%"
    );
    println!("{}", "-".repeat(90));
    for m in &all_metrics {
        println!(
            "{:<32} {:>12.4} {:>12.4} {:>12.4} {:>12.2} {:>11.1}%",
            m.name,
            m.edge_type_entropy,
            m.strength_entropy,
            m.degree_entropy,
            m.derived_fact_density,
            m.connectivity_ratio * 100.0
        );
    }

    // ===================================================================
    // FIND WINNER
    // ===================================================================

    println!("\n{}", "=".repeat(90));
    println!("  ANALYSIS");
    println!("{}\n", "=".repeat(90));

    if all_metrics.len() >= 2 {
        // Rank by composite information score
        // Includes original metrics + new corroboration/co-evidence contributions
        let mut scored: Vec<(usize, f64)> = all_metrics
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let score = m.edge_type_entropy * 2.0              // diversity of relationship types
                    + m.degree_entropy * 1.5                       // structural complexity
                    + m.derived_fact_density.ln().max(0.0)         // log-scaled reasoning productivity
                    + m.contradictions as f64 * 0.5                // contradiction detection
                    + m.connectivity_ratio * 3.0                   // graph coherence
                    + (m.corroboration_chains as f64).ln().max(0.0) * 1.0  // corroboration depth
                    + (m.co_evidence_supports as f64).ln().max(0.0) * 1.0; // co-evidence reasoning
                (i, score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        println!("  Composite information score (higher = more informative):\n");
        for (rank, (idx, score)) in scored.iter().enumerate() {
            let m = &all_metrics[*idx];
            let marker = if rank == 0 { " <-- WINNER" } else { "" };
            println!("    {}. [{:.3}] {}{}", rank + 1, score, m.name, marker);
        }

        let winner = &all_metrics[scored[0].0];
        let baseline = &all_metrics[0];

        println!("\n  Winner: {}", winner.name);
        println!("\n  vs Baseline:");
        println!(
            "    Transitive supports:  {} -> {} ({:.1}x)",
            baseline.transitive_supports,
            winner.transitive_supports,
            winner.transitive_supports as f64 / baseline.transitive_supports.max(1) as f64
        );
        println!(
            "    Contradictions:       {} -> {} ({:+})",
            baseline.contradictions,
            winner.contradictions,
            winner.contradictions as i64 - baseline.contradictions as i64
        );
        println!(
            "    Edge type entropy:    {:.4} -> {:.4} ({:+.4})",
            baseline.edge_type_entropy,
            winner.edge_type_entropy,
            winner.edge_type_entropy - baseline.edge_type_entropy
        );
        println!(
            "    Degree entropy:       {:.4} -> {:.4} ({:+.4})",
            baseline.degree_entropy,
            winner.degree_entropy,
            winner.degree_entropy - baseline.degree_entropy
        );
        println!(
            "    Connectivity:         {:.1}% -> {:.1}%",
            baseline.connectivity_ratio * 100.0,
            winner.connectivity_ratio * 100.0
        );

        // What did the winner reveal that the baseline missed?
        println!("\n  What the winner reveals that baseline cannot:");
        if winner.evidence_nodes > 0 {
            println!(
                "    - {} evidence nodes participating in graph reasoning",
                winner.evidence_nodes
            );
        }
        if winner.indirect_transitive_supports > baseline.indirect_transitive_supports {
            println!(
                "    - {} additional indirect support chains (vs {} baseline)",
                winner.indirect_transitive_supports - baseline.indirect_transitive_supports,
                baseline.indirect_transitive_supports
            );
        }
        if winner.contradictions > baseline.contradictions {
            println!(
                "    - {} new contradictions detected",
                winner.contradictions - baseline.contradictions
            );
        }
        if winner.support_clusters > baseline.support_clusters {
            println!(
                "    - {} additional support clusters",
                winner.support_clusters - baseline.support_clusters
            );
        }
        if winner.corroboration_chains > baseline.corroboration_chains {
            println!(
                "    - {} corroboration chains (vs {} baseline)",
                winner.corroboration_chains, baseline.corroboration_chains
            );
        }
        if winner.co_evidence_supports > baseline.co_evidence_supports {
            println!(
                "    - {} co-evidence support links (vs {} baseline)",
                winner.co_evidence_supports, baseline.co_evidence_supports
            );
        }
        if winner.unsupported_claims < baseline.unsupported_claims {
            println!(
                "    - {} fewer unsupported claims ({} -> {})",
                baseline.unsupported_claims - winner.unsupported_claims,
                baseline.unsupported_claims,
                winner.unsupported_claims
            );
        }
    }

    println!("\n=== Comparison Complete ===");

    Ok(())
}
