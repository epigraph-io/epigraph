//! Graph Reasoning Analysis CLI
//!
//! Connects to the EpiGraph development database, loads all claims and
//! claim-to-claim edges, runs the Ascent Datalog reasoning engine, and
//! prints a comprehensive analysis report.
//!
//! # Usage
//!
//! ```bash
//! DATABASE_URL=postgresql://epigraph:epigraph@localhost:5432/epigraph \
//!   cargo run --bin analyze_graph
//! ```

use epigraph_engine::{ReasoningClaim, ReasoningEdge, ReasoningEngine};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://epigraph:epigraph@localhost:5432/epigraph".to_string());

    println!("=== EpiGraph Reasoning Engine Analysis ===\n");
    println!("Connecting to database...");

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;

    // -----------------------------------------------------------------------
    // Load claims
    // -----------------------------------------------------------------------
    let claim_rows =
        sqlx::query("SELECT id, content, truth_value FROM claims ORDER BY truth_value DESC")
            .fetch_all(&pool)
            .await?;

    let mut claim_contents: HashMap<Uuid, String> = HashMap::new();
    let claims: Vec<ReasoningClaim> = claim_rows
        .iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            let content: String = row.get("content");
            let truth_value: f64 = row.get("truth_value");
            claim_contents.insert(id, content);
            ReasoningClaim { id, truth_value }
        })
        .collect();

    println!("  Loaded {} claims", claims.len());

    // -----------------------------------------------------------------------
    // Load claim-to-claim edges
    // -----------------------------------------------------------------------
    let edge_rows = sqlx::query(
        "SELECT source_id, target_id, relationship, properties \
         FROM edges \
         WHERE source_type = 'claim' AND target_type = 'claim' \
         ORDER BY relationship",
    )
    .fetch_all(&pool)
    .await?;

    let edges: Vec<ReasoningEdge> = edge_rows
        .iter()
        .map(|row| {
            let source_id: Uuid = row.get("source_id");
            let target_id: Uuid = row.get("target_id");
            let relationship: String = row.get("relationship");
            let properties: serde_json::Value = row.get("properties");
            let strength = properties
                .get("strength")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            ReasoningEdge {
                source_id,
                target_id,
                relationship,
                strength,
            }
        })
        .collect();

    println!("  Loaded {} edges", edges.len());

    // -----------------------------------------------------------------------
    // Load evidence counts per claim
    // -----------------------------------------------------------------------
    let evidence_rows =
        sqlx::query("SELECT claim_id, COUNT(*) AS cnt FROM evidence GROUP BY claim_id")
            .fetch_all(&pool)
            .await?;

    let evidence_counts: HashMap<Uuid, i64> = evidence_rows
        .iter()
        .map(|row| {
            let claim_id: Uuid = row.get("claim_id");
            let cnt: i64 = row.get("cnt");
            (claim_id, cnt)
        })
        .collect();

    // -----------------------------------------------------------------------
    // Load agent info
    // -----------------------------------------------------------------------
    let agent_rows = sqlx::query(
        "SELECT a.id, COALESCE(a.display_name, 'unnamed') AS name, COUNT(c.id) AS claim_count \
         FROM agents a LEFT JOIN claims c ON c.agent_id = a.id \
         GROUP BY a.id, a.display_name ORDER BY claim_count DESC",
    )
    .fetch_all(&pool)
    .await?;

    let agent_names: HashMap<Uuid, String> = agent_rows
        .iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            let name: String = row.get("name");
            (id, name)
        })
        .collect();

    // Map claims to agents
    let claim_agent_rows = sqlx::query("SELECT id, agent_id FROM claims")
        .fetch_all(&pool)
        .await?;
    let claim_agents: HashMap<Uuid, Uuid> = claim_agent_rows
        .iter()
        .map(|row| {
            let id: Uuid = row.get("id");
            let agent_id: Uuid = row.get("agent_id");
            (id, agent_id)
        })
        .collect();

    pool.close().await;

    // -----------------------------------------------------------------------
    // Run reasoning engine
    // -----------------------------------------------------------------------
    println!("\nRunning Ascent Datalog reasoning engine...");
    let start = std::time::Instant::now();
    let result = ReasoningEngine::analyze(&claims, &edges);
    let elapsed = start.elapsed();
    println!("  Analysis completed in {elapsed:?}\n");

    // -----------------------------------------------------------------------
    // Helper closures
    // -----------------------------------------------------------------------
    let label = |id: &Uuid| -> String {
        let content = claim_contents
            .get(id)
            .map(|s: &String| {
                if s.len() > 80 {
                    format!("{}...", &s[..77])
                } else {
                    s.clone()
                }
            })
            .unwrap_or_else(|| "???".to_string());
        let short_id = &id.to_string()[..8];
        format!("[{short_id}] {content}")
    };

    let agent_label = |claim_id: &Uuid| -> String {
        claim_agents
            .get(claim_id)
            .and_then(|aid| agent_names.get(aid))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    };

    // ===================================================================
    // REPORT
    // ===================================================================

    println!("{}", "=".repeat(60));
    println!("  SECTION 1: OVERVIEW STATISTICS");
    println!("{}\n", "=".repeat(60));

    let stats = &result.stats;
    println!("  Claims loaded:              {}", stats.claims_loaded);
    println!("  Edges loaded:               {}", stats.edges_loaded);
    println!(
        "  Transitive supports found:  {}",
        stats.transitive_supports_found
    );
    println!(
        "  Contradictions found:        {}",
        stats.contradictions_found
    );
    println!("  Connected components:        {}", stats.components);
    println!(
        "  Elaboration chains:          {}",
        result.elaboration_chains.len()
    );
    println!(
        "  Support clusters:            {}",
        result.support_clusters.len()
    );
    println!(
        "  Indirect challenges:         {}",
        result.indirect_challenges.len()
    );

    // ===================================================================
    println!("\n{}", "=".repeat(60));
    println!("  SECTION 2: CONTRADICTIONS");
    println!("{}\n", "=".repeat(60));

    if result.contradictions.is_empty() {
        println!("  No contradictions detected.");
    } else {
        println!(
            "  Found {} contradiction(s):\n",
            result.contradictions.len()
        );
        for (i, c) in result.contradictions.iter().enumerate() {
            println!("  --- Contradiction #{} ---", i + 1);
            println!("    SUPPORTER:  {}", label(&c.claim_a));
            println!(
                "      (agent: {}, strength: {:.2})",
                agent_label(&c.claim_a),
                c.support_strength
            );
            println!("    REFUTER:    {}", label(&c.claim_b));
            println!(
                "      (agent: {}, strength: {:.2})",
                agent_label(&c.claim_b),
                c.refute_strength
            );
            println!("    TARGET:     {}", label(&c.target));
            println!(
                "    Evidence for supporter: {} item(s)",
                evidence_counts.get(&c.claim_a).unwrap_or(&0)
            );
            println!(
                "    Evidence for refuter:   {} item(s)",
                evidence_counts.get(&c.claim_b).unwrap_or(&0)
            );
            println!();
        }
    }

    // ===================================================================
    println!("{}", "=".repeat(60));
    println!("  SECTION 3: STRONGEST TRANSITIVE SUPPORT CHAINS");
    println!("{}\n", "=".repeat(60));

    let mut ts_sorted: Vec<_> = result.transitive_supports.iter().collect();
    ts_sorted.sort_by(|a, b| b.chain_strength.partial_cmp(&a.chain_strength).unwrap());

    // Only show indirect (not direct) supports in top chains
    let direct_edges: std::collections::HashSet<(Uuid, Uuid)> = edges
        .iter()
        .filter(|e| e.relationship == "supports")
        .map(|e| (e.source_id, e.target_id))
        .collect();

    let indirect_chains: Vec<_> = ts_sorted
        .iter()
        .filter(|ts| !direct_edges.contains(&(ts.source, ts.target)))
        .collect();

    println!(
        "  {} total transitive supports ({} indirect, {} direct)\n",
        ts_sorted.len(),
        indirect_chains.len(),
        ts_sorted.len() - indirect_chains.len()
    );

    println!("  Top 15 strongest INDIRECT transitive support chains:");
    for (i, ts) in indirect_chains.iter().take(15).enumerate() {
        println!(
            "    {}. [{:.3}] {} --> {}",
            i + 1,
            ts.chain_strength,
            label(&ts.source),
            label(&ts.target),
        );
    }

    // Chain depth analysis
    println!("\n  Strength distribution of all transitive supports:");
    let mut strength_buckets = [0usize; 10]; // 0.0-0.1, 0.1-0.2, ..., 0.9-1.0
    for ts in &result.transitive_supports {
        let bucket = (ts.chain_strength * 10.0).min(9.0) as usize;
        strength_buckets[bucket] += 1;
    }
    for (i, &count) in strength_buckets.iter().enumerate() {
        if count > 0 {
            let low = i as f64 / 10.0;
            let high = (i + 1) as f64 / 10.0;
            let bar = "#".repeat(count.min(60));
            println!("    [{low:.1}-{high:.1}): {count:>4} {bar}");
        }
    }

    // ===================================================================
    println!("\n{}", "=".repeat(60));
    println!("  SECTION 4: SUPPORT CLUSTERS (CO-EVIDENCE)");
    println!("{}\n", "=".repeat(60));

    let mut clusters_sorted: Vec<_> = result.support_clusters.iter().collect();
    clusters_sorted.sort_by(|a, b| b.supporters.len().cmp(&a.supporters.len()));

    println!(
        "  {} target(s) have multiple supporters\n",
        clusters_sorted.len()
    );
    for (i, cluster) in clusters_sorted.iter().take(10).enumerate() {
        println!(
            "  --- Cluster #{} ({} supporters) ---",
            i + 1,
            cluster.supporters.len()
        );
        println!("    TARGET: {}", label(&cluster.target));
        for s in &cluster.supporters {
            let ev = evidence_counts.get(s).unwrap_or(&0);
            println!("      <- {} ({} evidence)", label(s), ev);
        }
        println!();
    }

    // ===================================================================
    println!("{}", "=".repeat(60));
    println!("  SECTION 5: ELABORATION CHAINS");
    println!("{}\n", "=".repeat(60));

    // Find the deepest elaboration chains (transitive, not direct)
    let direct_elab: std::collections::HashSet<(Uuid, Uuid)> = edges
        .iter()
        .filter(|e| e.relationship == "elaborates" || e.relationship == "specializes")
        .map(|e| (e.source_id, e.target_id))
        .collect();

    let indirect_elabs: Vec<_> = result
        .elaboration_chains
        .iter()
        .filter(|(a, b)| !direct_elab.contains(&(*a, *b)))
        .collect();

    println!(
        "  {} total elaboration paths ({} indirect, {} direct)\n",
        result.elaboration_chains.len(),
        indirect_elabs.len(),
        result.elaboration_chains.len() - indirect_elabs.len()
    );

    // Show some indirect chains
    println!("  Sample indirect elaboration chains (up to 10):");
    for (i, (src, tgt)) in indirect_elabs.iter().take(10).enumerate() {
        println!("    {}. {} ==> {}", i + 1, label(src), label(tgt));
    }

    // ===================================================================
    println!("\n{}", "=".repeat(60));
    println!("  SECTION 6: INDIRECT CHALLENGES");
    println!("{}\n", "=".repeat(60));

    if result.indirect_challenges.is_empty() {
        println!("  No indirect challenges detected.");
    } else {
        println!(
            "  {} indirect challenge(s):\n",
            result.indirect_challenges.len()
        );
        for (i, ic) in result.indirect_challenges.iter().enumerate() {
            println!("  {}. CHALLENGER: {}", i + 1, label(&ic.challenger));
            println!("     TARGET:     {}", label(&ic.target));
            println!("     (challenger agent: {})", agent_label(&ic.challenger));
            println!();
        }
    }

    // ===================================================================
    println!("{}", "=".repeat(60));
    println!("  SECTION 7: CONNECTED COMPONENTS");
    println!("{}\n", "=".repeat(60));

    let mut components_sorted: Vec<Vec<Uuid>> = result.connected_components.to_vec();
    components_sorted.sort_by_key(|b| std::cmp::Reverse(b.len()));

    println!("  {} connected component(s)\n", components_sorted.len());
    for (i, comp) in components_sorted.iter().enumerate() {
        if comp.len() > 1 {
            println!("  Component #{} ({} claims):", i + 1, comp.len());

            // Show a sample of claims in each component
            let sample_size = comp.len().min(5);
            for id in &comp[..sample_size] {
                let truth = claims
                    .iter()
                    .find(|c| c.id == *id)
                    .map(|c| c.truth_value)
                    .unwrap_or(0.0);
                println!("    [{:.2}] {}", truth, label(id));
            }
            if comp.len() > sample_size {
                println!("    ... and {} more claims", comp.len() - sample_size);
            }
            println!();
        } else {
            // Summarize isolated nodes
            if i == components_sorted.len() - 1 || components_sorted[i + 1].len() > 1 {
                // Count remaining singletons
                let singleton_count = components_sorted[i..]
                    .iter()
                    .filter(|c| c.len() == 1)
                    .count();
                if singleton_count > 0 {
                    println!("  + {} isolated claim(s) (no edges)", singleton_count);
                }
                break;
            }
        }
    }

    // ===================================================================
    println!("\n{}", "=".repeat(60));
    println!("  SECTION 8: MOST INFLUENTIAL CLAIMS");
    println!("{}\n", "=".repeat(60));

    // Claims that appear most as sources in transitive support
    let mut source_influence: HashMap<Uuid, usize> = HashMap::new();
    let mut target_dependence: HashMap<Uuid, usize> = HashMap::new();
    for ts in &result.transitive_supports {
        *source_influence.entry(ts.source).or_default() += 1;
        *target_dependence.entry(ts.target).or_default() += 1;
    }

    let mut influence_ranked: Vec<_> = source_influence.iter().collect();
    influence_ranked.sort_by(|a, b| b.1.cmp(a.1));

    println!("  Top 10 most influential claims (support others transitively):");
    for (i, (id, count)) in influence_ranked.iter().take(10).enumerate() {
        let truth = claims
            .iter()
            .find(|c| c.id == **id)
            .map(|c| c.truth_value)
            .unwrap_or(0.0);
        let ev = evidence_counts.get(id).unwrap_or(&0);
        println!(
            "    {}. [{:.2} truth, {} evidence, {} outbound] {}",
            i + 1,
            truth,
            ev,
            count,
            label(id),
        );
    }

    println!("\n  Top 10 most dependent claims (supported by others transitively):");
    let mut dep_ranked: Vec<_> = target_dependence.iter().collect();
    dep_ranked.sort_by(|a, b| b.1.cmp(a.1));
    for (i, (id, count)) in dep_ranked.iter().take(10).enumerate() {
        let truth = claims
            .iter()
            .find(|c| c.id == **id)
            .map(|c| c.truth_value)
            .unwrap_or(0.0);
        println!(
            "    {}. [{:.2} truth, {} inbound] {}",
            i + 1,
            truth,
            count,
            label(id),
        );
    }

    // ===================================================================
    println!("\n{}", "=".repeat(60));
    println!("  SECTION 9: GRAPH HEALTH METRICS");
    println!("{}\n", "=".repeat(60));

    let largest_component = components_sorted.first().map(|c| c.len()).unwrap_or(0);
    let connectivity_ratio = if claims.is_empty() {
        0.0
    } else {
        largest_component as f64 / claims.len() as f64
    };

    let avg_evidence = if claims.is_empty() {
        0.0
    } else {
        evidence_counts.values().sum::<i64>() as f64 / claims.len() as f64
    };

    let claims_in_contradiction: std::collections::HashSet<Uuid> = result
        .contradictions
        .iter()
        .flat_map(|c| [c.claim_a, c.claim_b, c.target])
        .collect();

    println!(
        "  Graph connectivity:          {:.1}% ({}/{} claims in largest component)",
        connectivity_ratio * 100.0,
        largest_component,
        claims.len()
    );
    println!("  Average evidence per claim:   {avg_evidence:.1}");
    println!(
        "  Claims in contradictions:     {} ({:.1}%)",
        claims_in_contradiction.len(),
        claims_in_contradiction.len() as f64 / claims.len() as f64 * 100.0
    );
    println!("  Elaboration depth (indirect): {}", indirect_elabs.len());
    println!(
        "  Support fan-out (max):        {}",
        influence_ranked.first().map(|(_, c)| **c).unwrap_or(0)
    );
    println!(
        "  Support fan-in (max):         {}",
        dep_ranked.first().map(|(_, c)| **c).unwrap_or(0)
    );

    // Epistemic health: are high-influence claims well-evidenced?
    println!("\n  Epistemic Health Check:");
    let mut under_evidenced = 0;
    for (id, count) in influence_ranked.iter().take(20) {
        let ev = *evidence_counts.get(id).unwrap_or(&0);
        if ev < 3 && **count > 5 {
            under_evidenced += 1;
            println!(
                "    WARNING: High-influence claim with only {} evidence: {}",
                ev,
                label(id),
            );
        }
    }
    if under_evidenced == 0 {
        println!("    All high-influence claims have adequate evidence coverage.");
    }

    println!("\n=== Analysis Complete ===");

    Ok(())
}
