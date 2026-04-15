//! LLM-based experimental protocol generation.
//!
//! Loads a hypothesis claim, its linked experiments and methods, and semantically
//! similar grounded neighbor claims, then calls Claude CLI to generate a structured
//! experimental protocol in markdown format.
//!
//! Usage: protocol_gen <hypothesis_id> [--output docs/protocols/YYYY-MM-DD-name.md]

use clap::Parser;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "protocol_gen",
    about = "Generate experimental protocol from hypothesis"
)]
struct Args {
    /// Hypothesis claim UUID
    hypothesis_id: Uuid,

    /// Output file path for the protocol markdown
    #[arg(long, default_value = "docs/protocols/generated-protocol.md")]
    output: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    if let Err(e) = run(args).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let pool = epigraph_cli::db_connect().await?;

    // 1. Load hypothesis claim
    let hypothesis: (String, serde_json::Value) =
        sqlx::query_as("SELECT content, properties FROM claims WHERE id = $1")
            .bind(args.hypothesis_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| format!("Hypothesis {}: {e}", args.hypothesis_id))?;

    let (statement, properties) = hypothesis;
    tracing::info!("Hypothesis: {statement}");

    // 2. Load experiments and methods with evidence scores
    let experiments =
        epigraph_db::ExperimentRepository::get_for_hypothesis(&pool, args.hypothesis_id).await?;
    tracing::info!("Found {} experiments", experiments.len());

    let mut method_context = Vec::new();
    for exp in &experiments {
        if let Some(method_ids) = &exp.method_ids {
            for mid in method_ids {
                if let Some(method) = epigraph_db::MethodRepository::get(&pool, *mid).await? {
                    let evidence =
                        epigraph_db::MethodRepository::get_evidence_strength(&pool, method.id)
                            .await
                            .ok();
                    let score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);
                    method_context.push(serde_json::json!({
                        "name": method.name,
                        "technique_type": method.technique_type,
                        "typical_conditions": method.typical_conditions,
                        "measures": method.measures,
                        "limitations": method.limitations,
                        "evidence_score": score,
                        "source_claim_count": method.source_claim_ids.len(),
                    }));
                }
            }
        }
    }

    // 3. Load neighborhood claims (semantically similar, grounded, within search radius)
    let search_radius: f64 = properties
        .get("search_radius")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.3);

    let neighbor_claims: Vec<(String, f64)> = sqlx::query_as(
        r#"
        SELECT c.content, c.truth_value
        FROM claims c
        JOIN edges e ON e.target_id = c.id AND e.target_type = 'claim'
            AND e.source_type IN ('paper', 'evidence', 'analysis')
        WHERE c.embedding IS NOT NULL
          AND c.id != $1
          AND c.truth_value IS NOT NULL
          AND 1 - (c.embedding <=> (SELECT embedding FROM claims WHERE id = $1)) >= $2
        ORDER BY 1 - (c.embedding <=> (SELECT embedding FROM claims WHERE id = $1)) DESC
        LIMIT 20
        "#,
    )
    .bind(args.hypothesis_id)
    .bind(search_radius)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    tracing::info!(
        "Found {} neighbor claims (threshold={search_radius})",
        neighbor_claims.len()
    );

    // 4. Build prompt for Claude
    let prompt = format!(
        r##"You are an experimental protocol designer for a scientific knowledge graph system.

Generate a detailed experimental protocol for testing this hypothesis:
"{statement}"

Research question: {research_question}

Available methods and their evidence:
{methods_json}

Related claims from the knowledge graph (grounded in literature):
{neighbors_json}

Return a JSON object with this exact structure:
{{
  "protocol_markdown": "# Experimental Protocol\n\n## Overview\n...",
  "critical_gaps": ["list of methods with evidence_score < 0.5"],
  "methods_used": [{{"name": "method name", "evidence_score": 0.88}}],
  "estimated_duration_days": 16
}}

The protocol_markdown should include:
1. Overview with hypothesis statement
2. Materials and equipment list with specific concentrations, catalog numbers
3. Phase-by-phase procedure (6 phases recommended) with timing
4. Measurement parameters with expected ranges and error budgets
5. Controls (positive and negative)
6. Evidence traceability table (method → evidence score → source papers)
7. Critical gaps section for any method with evidence_score < 0.5
8. Expected outcomes with quantitative predictions
9. Failure modes and contingencies

IMPORTANT: Return ONLY the JSON object. No markdown wrapping, no explanation."##,
        statement = statement,
        research_question = properties
            .get("research_question")
            .and_then(|v| v.as_str())
            .unwrap_or("Not specified"),
        methods_json = serde_json::to_string_pretty(&method_context)?,
        neighbors_json = serde_json::to_string_pretty(
            &neighbor_claims
                .iter()
                .take(10)
                .map(|(c, t)| serde_json::json!({"content": c, "truth_value": t}))
                .collect::<Vec<_>>()
        )?,
    );

    // 5. Call Claude via Anthropic API
    use epigraph_cli::enrichment::llm_client::create_llm_client;

    let client = create_llm_client("anthropic").map_err(|e| e.to_string())?;
    tracing::info!("Calling Anthropic API for protocol generation...");

    let response = client
        .complete_json(&prompt)
        .await
        .map_err(|e| format!("LLM error: {e}"))?;

    // 6. Extract protocol_markdown and other fields
    let protocol_md = response
        .get("protocol_markdown")
        .and_then(|v| v.as_str())
        .ok_or("Response missing 'protocol_markdown' field")?;

    let critical_gaps = response
        .get("critical_gaps")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // 7. Write output file
    let output_path = std::path::Path::new(&args.output);
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output_path, protocol_md)?;
    tracing::info!("Protocol written to {}", args.output);

    // 8. Update most recent experiment's protocol column
    if let Some(exp) = experiments.first() {
        sqlx::query("UPDATE experiments SET protocol = $1 WHERE id = $2")
            .bind(protocol_md)
            .bind(exp.id)
            .execute(&pool)
            .await
            .ok();
        tracing::info!("Updated experiment {} protocol column", exp.id);
    }

    // 9. Report summary
    println!("Protocol generated: {}", args.output);
    println!("Methods used: {}", method_context.len());
    if !critical_gaps.is_empty() {
        println!("\nCritical gaps (evidence_score < 0.5):");
        for gap in &critical_gaps {
            println!("  - {gap}");
        }
        println!("\nRun method-search to fill gaps before starting the experiment.");
    }

    Ok(())
}
