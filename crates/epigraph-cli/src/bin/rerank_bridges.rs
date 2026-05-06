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
//! Two operating modes:
//! - **Global join (default):** scan every claim pair above `--min-similarity`,
//!   optionally filtered by `--source-filter` / `--target-filter`.
//! - **Candidates table (`--candidates-table NAME`):** read pre-populated pairs
//!   from a `(source_id uuid, target_id uuid)` table — used by `bridge_component`
//!   and `bridge_sweep` to avoid the O(N²) global join.
//!
//! # Feature gate
//!
//! Requires the `genai` feature (implies `db`). Will not compile without it.
//! Requires `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` at runtime
//! unless `--provider mock`. Prefers OAuth when both are set.

use epigraph_cli::rerank::{
    rerank_candidates_table, rerank_global_join, RerankConfig, RerankSummary,
};

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
  --candidates-table <NAME>  Read pairs from a caller-supplied table with
                             (source_id, target_id) columns. Mutually exclusive
                             with --source-filter / --target-filter.
  --provider <NAME>          LLM provider [default: epigraph (auto-detect)]
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

  # Drive from a candidates table populated by bridge_component
  rerank_bridges --candidates-table cross_component_candidates --dry-run
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
    candidates_table: Option<String>,
    provider: String,
    model: Option<String>,
    dry_run: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();
        Self::parse_from(&args)
    }

    fn parse_from(args: &[String]) -> Result<Self, String> {
        let mut min_similarity = 0.40;
        let mut limit = None;
        let mut batch_size = 10;
        let mut source_filter = None;
        let mut target_filter = None;
        let mut candidates_table = None;
        let mut provider = "epigraph".to_string();
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
                "--candidates-table" => {
                    i += 1;
                    candidates_table = Some(
                        args.get(i)
                            .ok_or("--candidates-table requires a table name")?
                            .clone(),
                    );
                }
                "--provider" => {
                    i += 1;
                    provider = args
                        .get(i)
                        .ok_or("--provider requires a name (epigraph, anthropic, mock, or any registered extension)")?
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

        if candidates_table.is_some() && (source_filter.is_some() || target_filter.is_some()) {
            return Err(
                "--candidates-table is mutually exclusive with --source-filter / --target-filter"
                    .to_string(),
            );
        }

        Ok(Self {
            min_similarity,
            limit,
            batch_size,
            source_filter,
            target_filter,
            candidates_table,
            provider,
            model,
            dry_run,
        })
    }

    fn to_config(&self) -> RerankConfig {
        RerankConfig {
            min_similarity: self.min_similarity,
            batch_size: self.batch_size,
            provider: self.provider.clone(),
            model: self.model.clone(),
            dry_run: self.dry_run,
            limit: self.limit,
            verbose: true,
        }
    }
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

    // `--model` is propagated to the LLM client via `ENRICHMENT_MODEL` inside
    // the library (see rerank::core::rerank_inner).

    let auth_label = match args.provider.as_str() {
        "epigraph" => "auto-detect",
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
    if let Some(ref t) = args.candidates_table {
        println!("Candidates:     table {t}");
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

    let config = args.to_config();

    println!("\nFinding candidate pairs...");
    let summary_result = if let Some(table) = args.candidates_table.as_deref() {
        rerank_candidates_table(&pool, table, &config).await
    } else {
        rerank_global_join(
            &pool,
            args.source_filter.as_deref(),
            args.target_filter.as_deref(),
            &config,
        )
        .await
    };

    let summary = match summary_result {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: Rerank failed: {e}");
            std::process::exit(1);
        }
    };

    print_summary(&summary, args.dry_run);
}

// =============================================================================
// SUMMARY OUTPUT
// =============================================================================

fn print_summary(summary: &RerankSummary, dry_run: bool) {
    if summary.candidates_evaluated == 0 {
        println!("No candidate pairs found above threshold. Nothing to do.");
        return;
    }

    println!("\n=== Re-Ranking Complete ===");
    println!("Candidates evaluated: {}", summary.candidates_evaluated);
    println!("Accepted:             {}", summary.llm_accepted);
    println!("Rejected:             {}", summary.llm_rejected);
    if dry_run {
        println!("Dry run — no edges created");
    } else {
        println!("Edges created:        {}", summary.edges_created);
    }
    if summary.errors > 0 {
        println!("Errors:               {}", summary.errors);
    }
    println!("Duration:             {} ms", summary.duration_ms);

    if !summary.relationship_counts.is_empty() {
        println!("\nRelationship breakdown:");
        let mut entries: Vec<_> = summary.relationship_counts.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (rel, n) in entries {
            println!("  {rel:<14} {n}");
        }
    }

    if let Some(ref pair) = summary.sample_contradiction {
        println!("\nSample contradiction (first encountered):");
        println!(
            "  {} <-> {} (sim={:.3})",
            &pair.source_id.to_string()[..8],
            &pair.target_id.to_string()[..8],
            pair.similarity
        );
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Args, String> {
        let full: Vec<String> = std::iter::once("rerank_bridges".to_string())
            .chain(args.iter().map(|s| (*s).to_string()))
            .collect();
        Args::parse_from(&full)
    }

    #[test]
    fn test_args_defaults() {
        let args = parse_args(&[]).unwrap();
        assert!((args.min_similarity - 0.40).abs() < f64::EPSILON);
        assert_eq!(args.batch_size, 10);
        assert_eq!(args.provider, "epigraph");
        assert!(!args.dry_run);
        assert!(args.limit.is_none());
        assert!(args.source_filter.is_none());
        assert!(args.target_filter.is_none());
        assert!(args.candidates_table.is_none());
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

    #[test]
    fn test_args_candidates_table_accepted() {
        let args = parse_args(&["--candidates-table", "bridge_test_candidates"]).unwrap();
        assert_eq!(
            args.candidates_table.as_deref(),
            Some("bridge_test_candidates")
        );
        assert!(args.source_filter.is_none());
    }

    #[test]
    fn test_args_candidates_table_rejects_with_source_filter() {
        let result = parse_args(&[
            "--candidates-table",
            "t",
            "--source-filter",
            "c1.id IS NOT NULL",
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mutually exclusive"));
    }

    #[test]
    fn test_args_candidates_table_rejects_with_target_filter() {
        let result = parse_args(&[
            "--target-filter",
            "c2.id IS NOT NULL",
            "--candidates-table",
            "t",
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mutually exclusive"));
    }

    #[test]
    fn test_to_config_propagates_fields() {
        let args = parse_args(&[
            "--min-similarity",
            "0.55",
            "--batch-size",
            "7",
            "--limit",
            "42",
            "--provider",
            "mock",
            "--dry-run",
        ])
        .unwrap();
        let config = args.to_config();
        assert!((config.min_similarity - 0.55).abs() < f64::EPSILON);
        assert_eq!(config.batch_size, 7);
        assert_eq!(config.limit, Some(42));
        assert_eq!(config.provider, "mock");
        assert!(config.dry_run);
        assert!(config.verbose);
    }
}
