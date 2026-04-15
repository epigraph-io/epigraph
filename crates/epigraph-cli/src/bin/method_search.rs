//! Web search for experimental method evidence.
//!
//! Usage: method_search <hypothesis_id> [--gaps-only] [--gap "PEG-silane SAM on HfO2"]

use clap::Parser;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "method_search",
    about = "Search web for method evidence to fill gaps"
)]
struct Args {
    /// Hypothesis claim UUID
    hypothesis_id: Uuid,

    /// Only process methods with evidence_score < 0.3
    #[arg(long)]
    gaps_only: bool,

    /// Search for a specific gap description instead of auto-detecting
    #[arg(long)]
    gap: Option<String>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let exit_code = match run(args).await {
        Ok(all_filled) => {
            if all_filled {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    };
    std::process::exit(exit_code);
}

/// Returns true if all gaps filled, false if gaps remain.
async fn run(args: Args) -> Result<bool, Box<dyn std::error::Error>> {
    let pool = epigraph_cli::db_connect().await?;

    // 1. Load hypothesis
    let (statement,): (String,) = sqlx::query_as("SELECT content FROM claims WHERE id = $1")
        .bind(args.hypothesis_id)
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("Hypothesis {}: {e}", args.hypothesis_id))?;

    // 2. Load methods for hypothesis's experiments
    let experiments =
        epigraph_db::ExperimentRepository::get_for_hypothesis(&pool, args.hypothesis_id).await?;

    let mut gaps: Vec<(Uuid, String, f64)> = Vec::new(); // (method_id, description, evidence_score)

    for exp in &experiments {
        if let Some(method_ids) = &exp.method_ids {
            for mid in method_ids {
                if let Some(method) = epigraph_db::MethodRepository::get(&pool, *mid).await? {
                    let evidence =
                        epigraph_db::MethodRepository::get_evidence_strength(&pool, method.id)
                            .await
                            .ok();
                    let score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);

                    let is_gap = method.source_claim_ids.is_empty() || score < 0.3;
                    if is_gap || (!args.gaps_only && args.gap.is_some()) {
                        gaps.push((method.id, method.name.clone(), score));
                    }
                }
            }
        }
    }

    if gaps.is_empty() {
        println!(
            "No evidence gaps found for hypothesis {}",
            args.hypothesis_id
        );
        return Ok(true);
    }

    println!("Found {} gap(s) to fill:", gaps.len());
    for (_, name, score) in &gaps {
        println!("  - {name} (evidence: {score:.3})");
    }

    // 3. Search for each gap
    use epigraph_cli::enrichment::llm_client::create_llm_client;

    let client = create_llm_client("anthropic").map_err(|e| e.to_string())?;

    let mut all_filled = true;

    for (method_id, method_name, _score) in &gaps {
        let gap_desc = args
            .gap
            .clone()
            .unwrap_or_else(|| format!("{method_name} for {statement}"));

        let prompt = format!(
            r#"Search for published papers about: {gap_desc}
Context: This method is part of an experimental protocol for: {statement}

Return a JSON array of discovered claims. Each claim object:
{{
  "content": "One-sentence quantitative claim from the paper",
  "doi": "10.xxxx/yyyy or null",
  "journal": "Journal name",
  "year": 2024,
  "truth_value": 0.85,
  "is_preprint": false,
  "protocol_parameters": {{
    "concentration": "2 mM",
    "temperature": "25°C"
  }}
}}

Focus on: specific concentrations, temperatures, thicknesses, performance metrics, and protocol parameters.
Only include claims with quantitative data.
Return 3-8 claims."#,
        );

        tracing::info!("Searching for: {gap_desc}");
        let response = match client.complete_json(&prompt).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Web search failed for {method_name}: {e}");
                all_filled = false;
                continue;
            }
        };

        // Parse claims array (response might be the array directly or wrapped)
        let claims = if response.is_array() {
            response.as_array().unwrap().clone()
        } else if let Some(arr) = response.get("claims").and_then(|v| v.as_array()) {
            arr.clone()
        } else {
            eprintln!("Unexpected response format for {method_name}: not a JSON array");
            all_filled = false;
            continue;
        };

        // 4. Ingest claims
        let mut ingested = 0;
        for claim in &claims {
            let content = match claim.get("content").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => continue,
            };

            // Compute content_hash via BLAKE3 (matches all other claims in the DB)
            let content_hash = epigraph_crypto::ContentHasher::hash(content.as_bytes());

            // Check for duplicates
            let exists: Option<(i64,)> =
                sqlx::query_as("SELECT 1 FROM claims WHERE content_hash = $1")
                    .bind(content_hash.as_slice())
                    .fetch_optional(&pool)
                    .await?;

            if exists.is_some() {
                tracing::info!(
                    "Duplicate claim skipped: {}",
                    &content[..content.len().min(60)]
                );
                continue;
            }

            let truth_value = claim
                .get("truth_value")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.85);
            let is_preprint = claim
                .get("is_preprint")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tv = if is_preprint {
                truth_value.min(0.78)
            } else {
                truth_value
            };

            let doi = claim.get("doi").and_then(|v| v.as_str());
            let journal = claim.get("journal").and_then(|v| v.as_str());
            let year = claim.get("year").and_then(|v| v.as_i64());

            // Insert claim
            let claim_id: (Uuid,) = sqlx::query_as(
                r#"
                INSERT INTO claims (content, content_hash, truth_value, labels, properties)
                VALUES ($1, $2, $3, ARRAY['experimental', 'web_search'], $4)
                RETURNING id
                "#,
            )
            .bind(content)
            .bind(content_hash.as_slice())
            .bind(tv)
            .bind(serde_json::json!({
                "source": "web_search",
                "doi": doi,
                "journal": journal,
                "year": year,
                "protocol_parameters": claim.get("protocol_parameters"),
            }))
            .fetch_one(&pool)
            .await?;

            // Create SUPPORTS edge from claim to hypothesis
            sqlx::query(
                r#"
                INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
                VALUES ($1, 'claim', $2, 'claim', 'SUPPORTS', '{}')
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(claim_id.0)
            .bind(args.hypothesis_id)
            .execute(&pool)
            .await
            .ok();

            // Update method's source_claim_ids
            sqlx::query(
                "UPDATE methods SET source_claim_ids = source_claim_ids || ARRAY[$1] WHERE id = $2",
            )
            .bind(claim_id.0)
            .bind(method_id)
            .execute(&pool)
            .await
            .ok();

            ingested += 1;
        }

        println!("  {method_name}: ingested {ingested} new claims");
    }

    // 5. Report updated evidence scores
    println!("\nUpdated evidence scores:");
    for (method_id, method_name, old_score) in &gaps {
        let evidence = epigraph_db::MethodRepository::get_evidence_strength(&pool, *method_id)
            .await
            .ok();
        let new_score = evidence.map(|e| e.avg_belief).unwrap_or(0.0);
        let filled = if new_score >= 0.3 { "FILLED" } else { "GAP" };
        println!("  {method_name}: {old_score:.3} → {new_score:.3} [{filled}]");
        if new_score < 0.3 {
            all_filled = false;
        }
    }

    Ok(all_filled)
}
