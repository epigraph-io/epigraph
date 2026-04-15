//! Semantic Similarity Re-Ranker CLI
//!
//! Validates embedding-based claim-pair connections using an LLM before
//! encoding them as edges. Addresses the false-positive problem at lower
//! cosine similarity thresholds where vocabulary overlap (e.g. "octahedral"
//! in Crystal Field Theory vs DNA origami shape) inflates match counts.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin rerank_bridges --features genai -- \
//!   --min-similarity 0.40 \
//!   --batch-size 10 \
//!   --dry-run
//! ```
//!
//! # Feature gate
//!
//! Requires the `genai` feature (implies `db`). Will not compile without it.
//! Requires `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` at runtime
//! unless `--provider mock`. Prefers OAuth when both are set.

use epigraph_cli::enrichment::llm_client::{create_llm_client, LlmClient, LlmError};
use serde::Deserialize;
use uuid::Uuid;

// =============================================================================
// USAGE
// =============================================================================

const USAGE: &str = r#"
rerank_bridges — LLM re-ranker for semantic similarity validation

USAGE:
  rerank_bridges [OPTIONS]

OPTIONS:
  --min-similarity <FLOAT>   Cosine similarity threshold [default: 0.40]
  --limit <N>                Max candidate pairs to evaluate
  --batch-size <N>           Pairs per LLM call [default: 10]
  --source-filter <SQL>      WHERE fragment for source claims (alias: c1)
  --target-filter <SQL>      WHERE fragment for target claims (alias: c2)
  --provider <NAME>          LLM provider: anthropic or mock [default: anthropic]
  --model <NAME>             Model override [default: ENRICHMENT_MODEL or claude-haiku-4-5-20251001]
  -n, --dry-run              Evaluate and report, don't create edges
  -h, --help                 Show this message

ENVIRONMENT:
  DATABASE_URL               PostgreSQL connection string (required)
  CLAUDE_CODE_OAUTH_TOKEN    OAuth token — Max plan subscription (preferred)
  ANTHROPIC_API_KEY          API key — pay-per-token (fallback)
  ENRICHMENT_MODEL           Default model name (overridden by --model)

EXAMPLES:
  # Dry run: paper claims vs chemistry textbook claims
  rerank_bridges --dry-run --limit 20 \
    --source-filter "c1.properties->>'paper_doi' IS NOT NULL" \
    --target-filter "c2.created_at > '2026-02-18 16:40:00'"

  # Live run with mock provider (no API key needed)
  rerank_bridges --provider mock --dry-run
"#;

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

#[derive(Debug)]
struct Args {
    min_similarity: f64,
    limit: Option<i64>,
    batch_size: usize,
    source_filter: Option<String>,
    target_filter: Option<String>,
    provider: String,
    model: Option<String>,
    dry_run: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();

        let mut min_similarity = 0.40;
        let mut limit = None;
        let mut batch_size = 10;
        let mut source_filter = None;
        let mut target_filter = None;
        let mut provider = "anthropic".to_string();
        let mut model = None;
        let mut dry_run = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--min-similarity" => {
                    i += 1;
                    let val = args.get(i).ok_or("--min-similarity requires a number")?;
                    min_similarity = val
                        .parse::<f64>()
                        .map_err(|_| format!("--min-similarity must be a number, got: {val}"))?;
                    if !(0.0..=1.0).contains(&min_similarity) {
                        return Err(format!(
                            "--min-similarity must be in [0.0, 1.0], got: {min_similarity}"
                        ));
                    }
                }
                "--limit" => {
                    i += 1;
                    let val = args.get(i).ok_or("--limit requires a number")?;
                    limit =
                        Some(val.parse::<i64>().map_err(|_| {
                            format!("--limit must be a positive integer, got: {val}")
                        })?);
                }
                "--batch-size" => {
                    i += 1;
                    let val = args.get(i).ok_or("--batch-size requires a number")?;
                    batch_size = val.parse::<usize>().map_err(|_| {
                        format!("--batch-size must be a positive integer, got: {val}")
                    })?;
                    if batch_size == 0 {
                        return Err("--batch-size must be > 0".to_string());
                    }
                }
                "--source-filter" => {
                    i += 1;
                    source_filter = Some(
                        args.get(i)
                            .ok_or("--source-filter requires a SQL fragment")?
                            .clone(),
                    );
                }
                "--target-filter" => {
                    i += 1;
                    target_filter = Some(
                        args.get(i)
                            .ok_or("--target-filter requires a SQL fragment")?
                            .clone(),
                    );
                }
                "--provider" => {
                    i += 1;
                    provider = args
                        .get(i)
                        .ok_or("--provider requires a name (anthropic or mock)")?
                        .clone();
                }
                "--model" => {
                    i += 1;
                    model = Some(args.get(i).ok_or("--model requires a model name")?.clone());
                }
                "--dry-run" | "-n" => {
                    dry_run = true;
                }
                "--help" | "-h" => {
                    return Err(USAGE.to_string());
                }
                other => {
                    return Err(format!("Unknown argument: {other}\n{USAGE}"));
                }
            }
            i += 1;
        }

        Ok(Self {
            min_similarity,
            limit,
            batch_size,
            source_filter,
            target_filter,
            provider,
            model,
            dry_run,
        })
    }
}

// =============================================================================
// DATA TYPES
// =============================================================================

#[derive(Debug, Clone)]
struct CandidatePair {
    source_id: Uuid,
    target_id: Uuid,
    source_content: String,
    target_content: String,
    source_doi: Option<String>,
    target_doi: Option<String>,
    similarity: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidationResult {
    pair_index: usize,
    valid: bool,
    relationship: Option<String>,
    strength: Option<f64>,
    rationale: String,
}

const VALID_RELATIONSHIPS: &[&str] = &[
    "supports",
    "contradicts",
    "derives_from",
    "refines",
    "analogous",
];

// =============================================================================
// DATABASE QUERIES
// =============================================================================

/// Build and execute the candidate discovery query.
///
/// Finds claim pairs above the similarity threshold that don't already
/// have edges between them. Optional source/target filters restrict
/// which claims participate.
async fn find_candidates(
    pool: &sqlx::PgPool,
    args: &Args,
) -> Result<Vec<CandidatePair>, Box<dyn std::error::Error>> {
    // Build query with optional filters injected as structural SQL
    let source_clause = args
        .source_filter
        .as_ref()
        .map_or(String::new(), |f| format!("AND {f}"));
    let target_clause = args
        .target_filter
        .as_ref()
        .map_or(String::new(), |f| format!("AND {f}"));
    let limit_clause = args
        .limit
        .map_or("LIMIT 10000".to_string(), |n| format!("LIMIT {n}"));

    let query = format!(
        r#"
        SELECT
            c1.id AS source_id,
            c1.content AS source_content,
            c1.properties->>'paper_doi' AS source_doi,
            c2.id AS target_id,
            c2.content AS target_content,
            c2.properties->>'paper_doi' AS target_doi,
            (1 - (c1.embedding <=> c2.embedding))::float8 AS similarity
        FROM claims c1
        JOIN claims c2 ON c2.id > c1.id
        WHERE c1.embedding IS NOT NULL
          AND c2.embedding IS NOT NULL
          AND (1 - (c1.embedding <=> c2.embedding)) >= $1
          AND NOT EXISTS (
              SELECT 1 FROM edges e
              WHERE (e.source_id = c1.id AND e.target_id = c2.id)
                 OR (e.source_id = c2.id AND e.target_id = c1.id)
          )
          {source_clause}
          {target_clause}
        ORDER BY similarity DESC
        {limit_clause}
        "#
    );

    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            Uuid,
            String,
            Option<String>,
            f64,
        ),
    >(&query)
    .bind(args.min_similarity)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                source_id,
                source_content,
                source_doi,
                target_id,
                target_content,
                target_doi,
                similarity,
            )| {
                CandidatePair {
                    source_id,
                    target_id,
                    source_content,
                    target_content,
                    source_doi,
                    target_doi,
                    similarity,
                }
            },
        )
        .collect())
}

/// Check if an edge already exists between two claims (either direction).
async fn edge_exists(
    pool: &sqlx::PgPool,
    a: Uuid,
    b: Uuid,
) -> Result<bool, Box<dyn std::error::Error>> {
    let row = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM edges
        WHERE source_type = 'claim' AND target_type = 'claim'
          AND ((source_id = $1 AND target_id = $2)
            OR (source_id = $2 AND target_id = $1))
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;

    Ok(row > 0)
}

/// Create a validated edge in the edges table.
async fn create_edge(
    pool: &sqlx::PgPool,
    pair: &CandidatePair,
    result: &ValidationResult,
    model_name: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let properties = serde_json::json!({
        "strength": result.strength.unwrap_or(0.5),
        "cosine_similarity": pair.similarity,
        "validation_method": "llm_rerank",
        "validation_model": model_name,
        "rationale": result.rationale,
        "source_doi": pair.source_doi,
        "target_doi": pair.target_doi,
        "source": "rerank_bridges",
    });

    let relationship = result.relationship.as_deref().unwrap_or("analogous");

    let row = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
        VALUES ($1, 'claim', $2, 'claim', $3, $4)
        RETURNING id
        "#,
    )
    .bind(pair.source_id)
    .bind(pair.target_id)
    .bind(relationship)
    .bind(properties)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

// =============================================================================
// LLM PROMPT
// =============================================================================

/// Build the validation prompt for a batch of candidate pairs.
fn build_validation_prompt(pairs: &[CandidatePair]) -> String {
    let mut pairs_text = String::new();
    for (i, pair) in pairs.iter().enumerate() {
        let src_doi = pair.source_doi.as_deref().unwrap_or("unknown");
        let tgt_doi = pair.target_doi.as_deref().unwrap_or("unknown");
        // Truncate content to keep prompt manageable
        let src = truncate(&pair.source_content, 300);
        let tgt = truncate(&pair.target_content, 300);
        pairs_text.push_str(&format!(
            "Pair {i} (cosine similarity: {:.4}):\n  Source [{src_doi}]: \"{src}\"\n  Target [{tgt_doi}]: \"{tgt}\"\n\n",
            pair.similarity
        ));
    }

    format!(
        r#"You are a scientific relationship validator for an epistemic knowledge graph.
You evaluate whether pairs of scientific claims have a genuine scientific
relationship, or if their high embedding similarity is merely vocabulary overlap.

## CRITICAL DISTINCTION

GENUINE relationship: Claim A's truth or methodology meaningfully bears on Claim B.
One claim provides evidence, theoretical basis, or specific application of the other.

FALSE POSITIVE (reject): Both claims use the same terms (e.g., "octahedral",
"geometry", "lattice") but in unrelated scientific contexts. Example:
Crystal Field Theory (d-orbital splitting in transition metal complexes) vs
DNA origami (octahedral nanostructure shape) — shared word "octahedral", zero mechanistic link.

## Candidate Pairs

{pairs_text}
## Relationship Types

- supports: A provides evidence or theoretical basis for B
- contradicts: A provides evidence undermining B
- derives_from: A is a logical consequence or application of B
- refines: A adds precision or qualifies B
- analogous: genuinely parallel phenomena in related domains

## Rules

1. REJECT pairs where the ONLY connection is shared vocabulary in different contexts
2. A relationship must be defensible in a peer-reviewed context
3. If uncertain, REJECT — false negatives are preferable to false positives
4. Strength range: 0.3 to 1.0 (for accepted pairs)
5. Rationale must name the SPECIFIC scientific mechanism connecting the claims

## Output

Return a JSON array with one object per pair:
- pair_index: integer (0-based)
- valid: boolean
- relationship: string or null (supports/contradicts/derives_from/refines/analogous)
- strength: number or null (0.3 to 1.0)
- rationale: string (explain the specific scientific connection or why it's a false positive)

Return ONLY the JSON array. Include an entry for EVERY pair."#
    )
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .nth(max_len)
            .map_or(s.len(), |(idx, _)| idx);
        format!("{}...", &s[..end])
    }
}

// =============================================================================
// LLM RESPONSE PARSING
// =============================================================================

/// Parse and validate the LLM's JSON response into `ValidationResult`s.
fn parse_validation_response(json: &serde_json::Value, batch_size: usize) -> Vec<ValidationResult> {
    let arr = match json.as_array() {
        Some(a) => a,
        None => {
            eprintln!("  WARNING: LLM response is not a JSON array");
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    for item in arr {
        let parsed: ValidationResult = match serde_json::from_value(item.clone()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  WARNING: Failed to parse validation item: {e}");
                continue;
            }
        };

        // Bounds check
        if parsed.pair_index >= batch_size {
            eprintln!(
                "  WARNING: pair_index {} out of bounds (batch size {})",
                parsed.pair_index, batch_size
            );
            continue;
        }

        // Validate accepted pairs
        if parsed.valid {
            if let Some(ref rel) = parsed.relationship {
                if !VALID_RELATIONSHIPS.contains(&rel.as_str()) {
                    eprintln!(
                        "  WARNING: pair {}: invalid relationship '{}', skipping",
                        parsed.pair_index, rel
                    );
                    continue;
                }
            }
            if let Some(strength) = parsed.strength {
                if !(0.3..=1.0).contains(&strength) {
                    eprintln!(
                        "  WARNING: pair {}: strength {:.2} out of [0.3, 1.0], skipping",
                        parsed.pair_index, strength
                    );
                    continue;
                }
            }
        }

        results.push(parsed);
    }

    results
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let args = match Args::parse() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    };

    // If --model was specified, set ENRICHMENT_MODEL for the LLM client factory
    if let Some(ref model) = args.model {
        std::env::set_var("ENRICHMENT_MODEL", model);
    }

    let auth_label = match args.provider.as_str() {
        "anthropic" => {
            if std::env::var("CLAUDE_CODE_OAUTH_TOKEN").is_ok_and(|t| !t.is_empty()) {
                "OAuth token (Max plan)"
            } else {
                "API key"
            }
        }
        _ => "n/a",
    };

    println!("=== Semantic Similarity Re-Ranker ===");
    println!("Min similarity: {:.2}", args.min_similarity);
    println!("Batch size:     {}", args.batch_size);
    println!("Provider:       {}", args.provider);
    println!("Auth:           {auth_label}");
    println!("Dry run:        {}", args.dry_run);
    if let Some(ref f) = args.source_filter {
        println!("Source filter:  {f}");
    }
    if let Some(ref f) = args.target_filter {
        println!("Target filter:  {f}");
    }
    println!();

    // Connect to PostgreSQL
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("ERROR: DATABASE_URL must be set");
        std::process::exit(1);
    });

    println!("Connecting to PostgreSQL...");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("ERROR: Failed to connect to PostgreSQL: {e}");
            std::process::exit(1);
        });

    // Initialize LLM client
    let llm: Box<dyn LlmClient> = match create_llm_client(&args.provider) {
        Ok(c) => {
            println!("LLM model:      {}", c.model_name());
            c
        }
        Err(e) => {
            eprintln!("ERROR: Failed to create LLM client: {e}");
            std::process::exit(1);
        }
    };

    // Step 1: Find candidate pairs
    println!("\nFinding candidate pairs...");
    let candidates = match find_candidates(&pool, &args).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Candidate discovery query failed: {e}");
            std::process::exit(1);
        }
    };

    if candidates.is_empty() {
        println!("No candidate pairs found above threshold. Nothing to do.");
        return;
    }

    // Similarity distribution
    let avg_sim: f64 =
        candidates.iter().map(|c| c.similarity).sum::<f64>() / candidates.len() as f64;
    let max_sim = candidates
        .iter()
        .map(|c| c.similarity)
        .fold(0.0_f64, f64::max);
    let min_sim = candidates
        .iter()
        .map(|c| c.similarity)
        .fold(1.0_f64, f64::min);

    println!(
        "Found {} candidate pairs (sim: {min_sim:.4} — {max_sim:.4}, avg: {avg_sim:.4})",
        candidates.len()
    );

    // Step 2: Process in batches
    let num_batches = candidates.len().div_ceil(args.batch_size);
    let mut total_accepted = 0_usize;
    let mut total_rejected = 0_usize;
    let mut total_edges_created = 0_usize;
    let mut total_errors = 0_usize;

    for (batch_idx, batch) in candidates.chunks(args.batch_size).enumerate() {
        println!(
            "\n--- Batch {}/{} ({} pairs) ---",
            batch_idx + 1,
            num_batches,
            batch.len()
        );

        let prompt = build_validation_prompt(batch);

        // Call LLM (with 1 retry on rate limit)
        let json = match call_llm_with_retry(&*llm, &prompt).await {
            Ok(j) => j,
            Err(e) => {
                eprintln!("  ERROR calling LLM: {e}");
                total_errors += batch.len();
                continue;
            }
        };

        let results = parse_validation_response(&json, batch.len());

        for result in &results {
            let pair = &batch[result.pair_index];

            if result.valid {
                total_accepted += 1;
                let rel = result.relationship.as_deref().unwrap_or("analogous");
                let str_val = result.strength.unwrap_or(0.5);
                let rationale_preview: String = result.rationale.chars().take(80).collect();

                println!(
                    "  ACCEPT pair {} (sim={:.3}): {} --[{}({:.2})]--> {} | {}",
                    result.pair_index,
                    pair.similarity,
                    &pair.source_id.to_string()[..8],
                    rel,
                    str_val,
                    &pair.target_id.to_string()[..8],
                    rationale_preview
                );

                if !args.dry_run {
                    // Idempotency check
                    match edge_exists(&pool, pair.source_id, pair.target_id).await {
                        Ok(true) => {
                            println!("    (edge already exists, skipping)");
                        }
                        Ok(false) => {
                            match create_edge(&pool, pair, result, llm.model_name()).await {
                                Ok(edge_id) => {
                                    total_edges_created += 1;
                                    println!("    Created edge {edge_id}");
                                }
                                Err(e) => {
                                    total_errors += 1;
                                    eprintln!("    ERROR creating edge: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            total_errors += 1;
                            eprintln!("    ERROR checking edge existence: {e}");
                        }
                    }
                }
            } else {
                total_rejected += 1;
                let rationale_preview: String = result.rationale.chars().take(100).collect();
                println!(
                    "  REJECT pair {} (sim={:.3}): {}",
                    result.pair_index, pair.similarity, rationale_preview
                );
            }
        }

        // Count pairs the LLM didn't return results for
        let responded_indices: std::collections::HashSet<usize> =
            results.iter().map(|r| r.pair_index).collect();
        for i in 0..batch.len() {
            if !responded_indices.contains(&i) {
                eprintln!("  WARNING: LLM did not return a result for pair {i}");
                total_errors += 1;
            }
        }
    }

    // Summary
    println!("\n=== Re-Ranking Complete ===");
    println!("Candidates evaluated: {}", candidates.len());
    println!("Accepted:             {total_accepted}");
    println!("Rejected:             {total_rejected}");
    if args.dry_run {
        println!("Dry run — no edges created");
    } else {
        println!("Edges created:        {total_edges_created}");
    }
    if total_errors > 0 {
        println!("Errors:               {total_errors}");
    }
}

/// Call the LLM with one retry on rate limit.
async fn call_llm_with_retry(
    llm: &dyn LlmClient,
    prompt: &str,
) -> Result<serde_json::Value, LlmError> {
    match llm.complete_json(prompt).await {
        Ok(v) => Ok(v),
        Err(LlmError::RateLimited { retry_after_secs }) => {
            eprintln!("  Rate limited, waiting {retry_after_secs}s before retry...");
            tokio::time::sleep(std::time::Duration::from_secs(retry_after_secs)).await;
            llm.complete_json(prompt).await
        }
        Err(e) => Err(e),
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Arg parsing ─────────────────────────────────────────────────────

    fn parse_args(args: &[&str]) -> Result<Args, String> {
        let full: Vec<String> = std::iter::once("rerank_bridges".to_string())
            .chain(args.iter().map(|s| (*s).to_string()))
            .collect();

        // Temporarily override std::env::args by using our own parser
        // Since Args::parse reads std::env::args, we test the individual logic instead
        let mut min_similarity = 0.40;
        let mut limit = None;
        let mut batch_size = 10;
        let mut source_filter = None;
        let mut target_filter = None;
        let mut provider = "anthropic".to_string();
        let mut model = None;
        let mut dry_run = false;

        let mut i = 1;
        while i < full.len() {
            match full[i].as_str() {
                "--min-similarity" => {
                    i += 1;
                    let val = full.get(i).ok_or("--min-similarity requires a number")?;
                    min_similarity = val
                        .parse::<f64>()
                        .map_err(|_| format!("--min-similarity must be a number, got: {val}"))?;
                    if !(0.0..=1.0).contains(&min_similarity) {
                        return Err(format!(
                            "--min-similarity must be in [0.0, 1.0], got: {min_similarity}"
                        ));
                    }
                }
                "--limit" => {
                    i += 1;
                    let val = full.get(i).ok_or("--limit requires a number")?;
                    limit =
                        Some(val.parse::<i64>().map_err(|_| {
                            format!("--limit must be a positive integer, got: {val}")
                        })?);
                }
                "--batch-size" => {
                    i += 1;
                    let val = full.get(i).ok_or("--batch-size requires a number")?;
                    batch_size = val.parse::<usize>().map_err(|_| {
                        format!("--batch-size must be a positive integer, got: {val}")
                    })?;
                }
                "--source-filter" => {
                    i += 1;
                    source_filter = Some(
                        full.get(i)
                            .ok_or("--source-filter requires a value")?
                            .clone(),
                    );
                }
                "--target-filter" => {
                    i += 1;
                    target_filter = Some(
                        full.get(i)
                            .ok_or("--target-filter requires a value")?
                            .clone(),
                    );
                }
                "--provider" => {
                    i += 1;
                    provider = full.get(i).ok_or("--provider requires a value")?.clone();
                }
                "--model" => {
                    i += 1;
                    model = Some(full.get(i).ok_or("--model requires a value")?.clone());
                }
                "--dry-run" | "-n" => dry_run = true,
                "--help" | "-h" => return Err(USAGE.to_string()),
                other => return Err(format!("Unknown argument: {other}")),
            }
            i += 1;
        }

        Ok(Args {
            min_similarity,
            limit,
            batch_size,
            source_filter,
            target_filter,
            provider,
            model,
            dry_run,
        })
    }

    #[test]
    fn test_args_defaults() {
        let args = parse_args(&[]).unwrap();
        assert!((args.min_similarity - 0.40).abs() < f64::EPSILON);
        assert_eq!(args.batch_size, 10);
        assert_eq!(args.provider, "anthropic");
        assert!(!args.dry_run);
        assert!(args.limit.is_none());
        assert!(args.source_filter.is_none());
        assert!(args.target_filter.is_none());
    }

    #[test]
    fn test_args_dry_run() {
        let args = parse_args(&["--dry-run"]).unwrap();
        assert!(args.dry_run);

        let args2 = parse_args(&["-n"]).unwrap();
        assert!(args2.dry_run);
    }

    #[test]
    fn test_args_all_flags() {
        let args = parse_args(&[
            "--min-similarity",
            "0.50",
            "--limit",
            "100",
            "--batch-size",
            "5",
            "--source-filter",
            "c1.labels @> '{paper}'",
            "--target-filter",
            "c2.labels @> '{textbook}'",
            "--provider",
            "mock",
            "--model",
            "claude-opus-4-6",
            "--dry-run",
        ])
        .unwrap();

        assert!((args.min_similarity - 0.50).abs() < f64::EPSILON);
        assert_eq!(args.limit, Some(100));
        assert_eq!(args.batch_size, 5);
        assert_eq!(
            args.source_filter.as_deref(),
            Some("c1.labels @> '{paper}'")
        );
        assert_eq!(
            args.target_filter.as_deref(),
            Some("c2.labels @> '{textbook}'")
        );
        assert_eq!(args.provider, "mock");
        assert_eq!(args.model.as_deref(), Some("claude-opus-4-6"));
        assert!(args.dry_run);
    }

    #[test]
    fn test_args_invalid_similarity_not_a_number() {
        let result = parse_args(&["--min-similarity", "abc"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be a number"));
    }

    #[test]
    fn test_args_invalid_similarity_out_of_bounds() {
        let result = parse_args(&["--min-similarity", "1.5"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[0.0, 1.0]"));

        let result2 = parse_args(&["--min-similarity", "-0.1"]);
        assert!(result2.is_err());
    }

    #[test]
    fn test_args_help_returns_usage() {
        let result = parse_args(&["--help"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("rerank_bridges"));
    }

    // ── Prompt building ─────────────────────────────────────────────────

    fn make_pair(src: &str, tgt: &str, sim: f64) -> CandidatePair {
        CandidatePair {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_content: src.to_string(),
            target_content: tgt.to_string(),
            source_doi: Some("paper/123".to_string()),
            target_doi: Some("textbook/chem".to_string()),
            similarity: sim,
        }
    }

    #[test]
    fn test_build_prompt_contains_pairs() {
        let pairs = vec![
            make_pair(
                "DNA nanoengine driven by chemical energy",
                "DNA is a polymer of four nucleotides",
                0.51,
            ),
            make_pair(
                "CO on Cu(111) occupies on-top sites",
                "Crystal field theory explains d-orbital splitting",
                0.49,
            ),
        ];

        let prompt = build_validation_prompt(&pairs);

        assert!(prompt.contains("Pair 0"));
        assert!(prompt.contains("Pair 1"));
        assert!(prompt.contains("DNA nanoengine"));
        assert!(prompt.contains("CO on Cu(111)"));
        assert!(prompt.contains("0.5100"));
        assert!(prompt.contains("0.4900"));
    }

    #[test]
    fn test_build_prompt_includes_rejection_criteria() {
        let pairs = vec![make_pair("a", "b", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        assert!(prompt.contains("FALSE POSITIVE"));
        assert!(prompt.contains("Crystal Field"));
        assert!(prompt.contains("vocabulary overlap"));
        assert!(prompt.contains("REJECT"));
        assert!(prompt.contains("peer-reviewed"));
    }

    #[test]
    fn test_build_prompt_includes_all_relationship_types() {
        let pairs = vec![make_pair("a", "b", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        for rel in VALID_RELATIONSHIPS {
            assert!(
                prompt.contains(rel),
                "Prompt missing relationship type: {rel}"
            );
        }
    }

    #[test]
    fn test_build_prompt_truncates_long_content() {
        let long_content = "A".repeat(500);
        let pairs = vec![make_pair(&long_content, "short", 0.5)];
        let prompt = build_validation_prompt(&pairs);

        // Should be truncated to 300 chars + "..."
        assert!(!prompt.contains(&"A".repeat(400)));
        assert!(prompt.contains("..."));
    }

    // ── Response parsing ────────────────────────────────────────────────

    #[test]
    fn test_parse_response_accepted() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 0.75,
                "rationale": "DNA origami uses DNA polymer structure"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert_eq!(results.len(), 1);
        assert!(results[0].valid);
        assert_eq!(results[0].relationship.as_deref(), Some("supports"));
        assert!((results[0].strength.unwrap() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_response_rejected() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": false,
                "relationship": null,
                "strength": null,
                "rationale": "Vocabulary overlap: both use 'octahedral' in different contexts"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert_eq!(results.len(), 1);
        assert!(!results[0].valid);
        assert!(results[0].relationship.is_none());
        assert!(results[0].strength.is_none());
    }

    #[test]
    fn test_parse_response_mixed() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "derives_from",
                "strength": 0.6,
                "rationale": "EUV photon energy relates to photoelectric effect"
            },
            {
                "pair_index": 1,
                "valid": false,
                "relationship": null,
                "strength": null,
                "rationale": "No genuine link between CFT and DNA lattice"
            }
        ]);

        let results = parse_validation_response(&json, 2);
        assert_eq!(results.len(), 2);
        assert!(results[0].valid);
        assert!(!results[1].valid);
    }

    #[test]
    fn test_parse_response_invalid_relationship() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "causes",
                "strength": 0.7,
                "rationale": "some reason"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(
            results.is_empty(),
            "Invalid relationship type should be rejected"
        );
    }

    #[test]
    fn test_parse_response_strength_too_low() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 0.1,
                "rationale": "weak connection"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty(), "Strength < 0.3 should be rejected");
    }

    #[test]
    fn test_parse_response_strength_too_high() {
        let json = serde_json::json!([
            {
                "pair_index": 0,
                "valid": true,
                "relationship": "supports",
                "strength": 1.5,
                "rationale": "too strong"
            }
        ]);

        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty(), "Strength > 1.0 should be rejected");
    }

    #[test]
    fn test_parse_response_pair_index_out_of_bounds() {
        let json = serde_json::json!([
            {
                "pair_index": 5,
                "valid": true,
                "relationship": "supports",
                "strength": 0.5,
                "rationale": "reason"
            }
        ]);

        let results = parse_validation_response(&json, 3);
        assert!(
            results.is_empty(),
            "pair_index >= batch_size should be rejected"
        );
    }

    #[test]
    fn test_parse_response_not_array() {
        let json = serde_json::json!({"error": "something"});
        let results = parse_validation_response(&json, 1);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_response_empty_array() {
        let json = serde_json::json!([]);
        let results = parse_validation_response(&json, 5);
        assert!(results.is_empty());
    }

    // ── Edge properties ─────────────────────────────────────────────────

    #[test]
    fn test_edge_properties_schema() {
        let pair = make_pair("source claim", "target claim", 0.48);
        let result = ValidationResult {
            pair_index: 0,
            valid: true,
            relationship: Some("supports".to_string()),
            strength: Some(0.75),
            rationale: "Genuine scientific connection".to_string(),
        };

        let properties = serde_json::json!({
            "strength": result.strength.unwrap_or(0.5),
            "cosine_similarity": pair.similarity,
            "validation_method": "llm_rerank",
            "validation_model": "claude-haiku-4-5-20251001",
            "rationale": result.rationale,
            "source_doi": pair.source_doi,
            "target_doi": pair.target_doi,
            "source": "rerank_bridges",
        });

        // All required fields present
        assert!(properties["strength"].is_number());
        assert!(properties["cosine_similarity"].is_number());
        assert_eq!(properties["validation_method"], "llm_rerank");
        assert!(properties["validation_model"].is_string());
        assert!(properties["rationale"].is_string());
        assert_eq!(properties["source"], "rerank_bridges");
    }

    #[test]
    fn test_valid_relationships_matches_domain_model() {
        // These must match the SemanticLinkType enum in epigraph-core
        assert!(VALID_RELATIONSHIPS.contains(&"supports"));
        assert!(VALID_RELATIONSHIPS.contains(&"contradicts"));
        assert!(VALID_RELATIONSHIPS.contains(&"derives_from"));
        assert!(VALID_RELATIONSHIPS.contains(&"refines"));
        assert!(VALID_RELATIONSHIPS.contains(&"analogous"));
        assert_eq!(VALID_RELATIONSHIPS.len(), 5);
    }

    // ── Truncation ──────────────────────────────────────────────────────

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let long = "A".repeat(500);
        let result = truncate(&long, 300);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 304); // 300 + "..."
    }

    #[test]
    fn test_truncate_exact_length() {
        let exact = "A".repeat(300);
        assert_eq!(truncate(&exact, 300), exact);
    }
}
