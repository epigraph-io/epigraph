//! Library API for the LLM bridge reranker.
//!
//! Two entry points:
//! - [`rerank_global_join`] — original behaviour: scan all pairs above similarity
//!   threshold (drives the `rerank_bridges` CLI default mode).
//! - [`rerank_candidates_table`] — read pairs from a caller-supplied temp table
//!   (drives `bridge_component` / `bridge_sweep`, issue #53).
//!
//! Both share the same batch loop, prompt, and edge-creation helpers.

use sqlx::PgPool;
use uuid::Uuid;

use crate::enrichment::llm_client::{create_llm_client, LlmClient, LlmError};
use crate::rerank::candidates::{CandidatePair, ValidationResult};
use crate::rerank::errors::RerankError;
use crate::rerank::prompt::{build_validation_prompt, parse_validation_response};

// =============================================================================
// CONFIG / SUMMARY
// =============================================================================

#[derive(Debug, Clone)]
pub struct RerankConfig {
    pub min_similarity: f64,
    pub batch_size: usize,
    pub provider: String,
    pub model: Option<String>,
    pub dry_run: bool,
    pub limit: Option<i64>,
    /// Print per-batch progress to stdout. Binary sets true; library callers
    /// that just want a summary should leave false.
    pub verbose: bool,
}

impl Default for RerankConfig {
    fn default() -> Self {
        Self {
            min_similarity: 0.40,
            batch_size: 10,
            provider: "anthropic".to_string(),
            model: None,
            dry_run: false,
            limit: None,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RerankSummary {
    /// Number of candidate pairs sent to the LLM (= input candidate count).
    pub candidates_evaluated: usize,
    /// Pairs the LLM marked `valid: true` (regardless of edge creation).
    pub llm_accepted: usize,
    /// Pairs the LLM marked `valid: false`.
    pub llm_rejected: usize,
    /// Edges actually inserted (zero if `dry_run` is set).
    pub edges_created: usize,
    /// Per-batch errors (LLM failures, edge insert failures, missing entries).
    pub errors: usize,
    /// Wall-clock duration of the rerank loop.
    pub duration_ms: u128,
    /// First accepted pair whose relationship is `contradicts`.
    pub sample_contradiction: Option<CandidatePair>,
    /// Counts per accepted relationship type.
    pub relationship_counts: std::collections::HashMap<String, usize>,
}

// =============================================================================
// PUBLIC ENTRY POINTS
// =============================================================================

/// Rerank the global candidate space — equivalent to the original
/// `rerank_bridges` invocation pattern. `source_filter` and `target_filter`
/// are optional WHERE fragments aliased as `c1` / `c2`.
pub async fn rerank_global_join(
    pool: &PgPool,
    source_filter: Option<&str>,
    target_filter: Option<&str>,
    config: &RerankConfig,
) -> Result<RerankSummary, RerankError> {
    let candidates = find_candidates_global(pool, source_filter, target_filter, config).await?;
    rerank_inner(pool, candidates, config).await
}

/// Rerank pairs from a caller-supplied temp table. The table must have
/// `(source_id uuid, target_id uuid)` columns; any extra columns are ignored.
/// Similarity is recomputed in SQL for consistency with the global path.
///
/// Introduced for issue #53 (cross-component bridge sweep). The caller —
/// e.g. `bridge_component` — populates the table via a per-source kNN insert
/// before calling this function.
///
/// Caveats for callers (Tasks 4/5):
/// - `config.min_similarity` is **ignored** in this path — selection is the
///   caller's responsibility.
/// - The caller should deduplicate pairs ordered consistently (e.g. always
///   `min(a,b), max(a,b)`); duplicate `(A,B)` and `(B,A)` rows would burn LLM
///   tokens twice before the post-hoc `edge_exists` check skips the second
///   insert.
pub async fn rerank_candidates_table(
    pool: &PgPool,
    candidates_table: &str,
    config: &RerankConfig,
) -> Result<RerankSummary, RerankError> {
    let candidates = find_candidates_from_table(pool, candidates_table, config).await?;
    rerank_inner(pool, candidates, config).await
}

// =============================================================================
// CANDIDATE DISCOVERY
// =============================================================================

async fn find_candidates_global(
    pool: &PgPool,
    source_filter: Option<&str>,
    target_filter: Option<&str>,
    config: &RerankConfig,
) -> Result<Vec<CandidatePair>, RerankError> {
    let source_clause = source_filter.map_or(String::new(), |f| format!("AND {f}"));
    let target_clause = target_filter.map_or(String::new(), |f| format!("AND {f}"));
    let limit_clause = config
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
    .bind(config.min_similarity)
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
            )| CandidatePair {
                source_id,
                target_id,
                source_content,
                target_content,
                source_doi,
                target_doi,
                similarity,
            },
        )
        .collect())
}

async fn find_candidates_from_table(
    pool: &PgPool,
    candidates_table: &str,
    config: &RerankConfig,
) -> Result<Vec<CandidatePair>, RerankError> {
    // SECURITY: candidates_table is interpolated into SQL — restrict to a
    // safe identifier shape to block injection. Caller is internal but the
    // table name comes from CLI args.
    if !is_safe_identifier(candidates_table) {
        return Err(RerankError::Config(format!(
            "candidates_table name must be [a-zA-Z0-9_]+: {candidates_table}"
        )));
    }

    let limit_clause = config.limit.map_or(String::new(), |n| format!("LIMIT {n}"));

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
        FROM {candidates_table} ct
        JOIN claims c1 ON c1.id = ct.source_id
        JOIN claims c2 ON c2.id = ct.target_id
        WHERE c1.embedding IS NOT NULL
          AND c2.embedding IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM edges e
              WHERE (e.source_id = c1.id AND e.target_id = c2.id)
                 OR (e.source_id = c2.id AND e.target_id = c1.id)
          )
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
            )| CandidatePair {
                source_id,
                target_id,
                source_content,
                target_content,
                source_doi,
                target_doi,
                similarity,
            },
        )
        .collect())
}

fn is_safe_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// =============================================================================
// CORE BATCH LOOP
// =============================================================================

async fn rerank_inner(
    pool: &PgPool,
    candidates: Vec<CandidatePair>,
    config: &RerankConfig,
) -> Result<RerankSummary, RerankError> {
    let started = std::time::Instant::now();
    let mut summary = RerankSummary {
        candidates_evaluated: candidates.len(),
        ..Default::default()
    };

    if candidates.is_empty() {
        summary.duration_ms = started.elapsed().as_millis();
        return Ok(summary);
    }

    // The LLM client factory reads `ENRICHMENT_MODEL` from env. If the caller
    // supplied an override via `config.model`, propagate it before constructing
    // the client. (Process-global mutation; library callers in async contexts
    // should be aware, but the rerank loop is single-shot per process today.)
    if let Some(ref model) = config.model {
        std::env::set_var("ENRICHMENT_MODEL", model);
    }

    let llm = create_llm_client(&config.provider).map_err(|e| RerankError::Llm(e.to_string()))?;
    let model_name = llm.model_name().to_string();

    let num_batches = candidates.len().div_ceil(config.batch_size);

    for (batch_idx, batch) in candidates.chunks(config.batch_size).enumerate() {
        if config.verbose {
            println!(
                "\n--- Batch {}/{} ({} pairs) ---",
                batch_idx + 1,
                num_batches,
                batch.len()
            );
        }

        let prompt = build_validation_prompt(batch);

        let json = match call_llm_with_retry(&*llm, &prompt).await {
            Ok(j) => j,
            Err(e) => {
                eprintln!("  ERROR calling LLM: {e}");
                summary.errors += batch.len();
                continue;
            }
        };

        let results = parse_validation_response(&json, batch.len());

        for result in &results {
            let pair = &batch[result.pair_index];

            if result.valid {
                summary.llm_accepted += 1;
                let rel = result.relationship.as_deref().unwrap_or("analogous");
                let str_val = result.strength.unwrap_or(0.5);

                *summary
                    .relationship_counts
                    .entry(rel.to_string())
                    .or_insert(0) += 1;

                if rel == "contradicts" && summary.sample_contradiction.is_none() {
                    summary.sample_contradiction = Some(pair.clone());
                }

                if config.verbose {
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
                }

                if !config.dry_run {
                    match edge_exists(pool, pair.source_id, pair.target_id).await {
                        Ok(true) => {
                            if config.verbose {
                                println!("    (edge already exists, skipping)");
                            }
                        }
                        Ok(false) => match create_edge(pool, pair, result, &model_name).await {
                            Ok(edge_id) => {
                                summary.edges_created += 1;
                                if config.verbose {
                                    println!("    Created edge {edge_id}");
                                }
                            }
                            Err(e) => {
                                summary.errors += 1;
                                eprintln!("    ERROR creating edge: {e}");
                            }
                        },
                        Err(e) => {
                            summary.errors += 1;
                            eprintln!("    ERROR checking edge existence: {e}");
                        }
                    }
                }
            } else {
                summary.llm_rejected += 1;
                if config.verbose {
                    let rationale_preview: String = result.rationale.chars().take(100).collect();
                    println!(
                        "  REJECT pair {} (sim={:.3}): {}",
                        result.pair_index, pair.similarity, rationale_preview
                    );
                }
            }
        }

        // Count pairs the LLM didn't return results for
        let responded_indices: std::collections::HashSet<usize> =
            results.iter().map(|r| r.pair_index).collect();
        for i in 0..batch.len() {
            if !responded_indices.contains(&i) {
                eprintln!("  WARNING: LLM did not return a result for pair {i}");
                summary.errors += 1;
            }
        }
    }

    summary.duration_ms = started.elapsed().as_millis();
    Ok(summary)
}

// =============================================================================
// EDGE HELPERS (private)
// =============================================================================

/// Check if an edge already exists between two claims (either direction).
pub(crate) async fn edge_exists(pool: &PgPool, a: Uuid, b: Uuid) -> Result<bool, sqlx::Error> {
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
pub(crate) async fn create_edge(
    pool: &PgPool,
    pair: &CandidatePair,
    result: &ValidationResult,
    model_name: &str,
) -> Result<Uuid, sqlx::Error> {
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

    sqlx::query_scalar::<_, Uuid>(
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
    .await
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

    #[test]
    fn test_is_safe_identifier_accepts_alphanumeric_underscore() {
        assert!(is_safe_identifier("foo"));
        assert!(is_safe_identifier("foo_bar"));
        assert!(is_safe_identifier("Foo123"));
        assert!(is_safe_identifier("_underscore"));
        assert!(is_safe_identifier("bridge_test_candidates"));
    }

    #[test]
    fn test_is_safe_identifier_rejects_injection() {
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier("foo; DROP TABLE"));
        assert!(!is_safe_identifier("foo bar"));
        assert!(!is_safe_identifier("foo-bar"));
        assert!(!is_safe_identifier("foo.bar"));
        assert!(!is_safe_identifier("foo'bar"));
        assert!(!is_safe_identifier("\"foo\""));
    }

    #[test]
    fn test_edge_properties_schema() {
        let pair = CandidatePair {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_content: "src".to_string(),
            target_content: "tgt".to_string(),
            source_doi: Some("paper/123".to_string()),
            target_doi: Some("textbook/chem".to_string()),
            similarity: 0.48,
        };
        let result = ValidationResult {
            pair_index: 0,
            valid: true,
            relationship: Some("supports".to_string()),
            strength: Some(0.75),
            rationale: "Genuine scientific connection".to_string(),
        };

        // Mirror the JSON shape that create_edge() builds — keep this in sync.
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

        assert!(properties["strength"].is_number());
        assert!(properties["cosine_similarity"].is_number());
        assert_eq!(properties["validation_method"], "llm_rerank");
        assert!(properties["validation_model"].is_string());
        assert!(properties["rationale"].is_string());
        assert_eq!(properties["source"], "rerank_bridges");
    }
}
