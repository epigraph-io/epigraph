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

use crate::enrichment::llm_client::{create_llm_client, LlmError, LlmProvider};
use crate::rerank::candidates::{CandidatePair, DiscardReason, ValidationResult};
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
            provider: "epigraph".to_string(),
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
    /// Per-pair LLM verdicts in input order. Lets library callers (e.g. the
    /// cross-source matcher's verifier wrapper) attribute verdicts back to
    /// their pairs without re-parsing. Populated regardless of `dry_run`.
    pub per_pair_verdicts: Vec<PerPairVerdict>,
    /// Pairs that were batched but got no usable verdict, each with the reason.
    /// Disjoint from `per_pair_verdicts`. A batched pair in neither list is one
    /// the model answered about and simply omitted — that distinction is the
    /// point of this field.
    ///
    /// `errors` counts these; this says *why*. Note the complement is not
    /// visible here: a pair the caller asked about that never survived
    /// `find_candidates_from_table` appears in neither list and in no counter,
    /// because the reranker never saw it.
    pub per_pair_discards: Vec<PerPairDiscard>,
}

impl RerankSummary {
    /// Counts of `per_pair_discards` by reason, keyed on the
    /// [`DiscardReason::as_str`] text.
    ///
    /// **The values are pair counts, not event counts.** A batch-scoped reason
    /// is recorded against every unexplained pair in its batch, so a single
    /// malformed entry in a batch of 50 silent pairs reports as `50`. Read an
    /// entry as "50 pairs got no verdict, and this is why", never as "50 things
    /// went wrong".
    ///
    /// This is the operational readout the old `errors` counter could not give:
    /// `errors: 300` is the same number whether one LLM call failed on a
    /// 300-pair run, the model answered and omitted 300 pairs, or 300 entries
    /// named relationships outside the vocabulary. Those call for completely
    /// different responses.
    ///
    /// Consumed today only by `rerank_inner`'s end-of-run `eprintln!`. It is
    /// deliberately not written anywhere persistent — see [`DiscardReason`].
    pub fn discard_breakdown(&self) -> std::collections::BTreeMap<&'static str, usize> {
        let mut out = std::collections::BTreeMap::new();
        for d in &self.per_pair_discards {
            *out.entry(d.reason.as_str()).or_insert(0) += 1;
        }
        out
    }
}

/// Per-pair verdict surfaced alongside aggregate counts. Mirrors the
/// `ValidationResult` shape but carries the candidate's UUIDs so callers can
/// align it with their own pair list.
#[derive(Debug, Clone)]
pub struct PerPairVerdict {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub valid: bool,
    pub relationship: Option<String>,
    pub strength: Option<f64>,
    pub rationale: String,
}

/// A pair that was assigned to a batch but got no usable verdict out of it,
/// keyed to the candidate's UUIDs so callers can align it without re-parsing.
#[derive(Debug, Clone)]
pub struct PerPairDiscard {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub reason: DiscardReason,
}

/// Everything one LLM batch yields, in one value.
///
/// Extracted from [`rerank_inner`] so the parse → attribute step is reachable
/// without a database or a live LLM. The tests at the bottom of this module
/// drive it directly, which is the point: they exercise the same code the batch
/// loop runs, rather than a re-implementation of it.
pub(crate) struct BatchInterpretation {
    /// Entries that survived parsing and validation, in response order.
    pub results: Vec<ValidationResult>,
    /// One per surviving entry, keyed to the batch's claim UUIDs.
    pub verdicts: Vec<PerPairVerdict>,
    /// Unanswered pairs whose silence is explained by a discard.
    pub discards: Vec<PerPairDiscard>,
    /// Batch indices with no surviving entry — the model was silent about
    /// them, or their entry was discarded. Counted as errors by the caller.
    pub unanswered: Vec<usize>,
}

/// No response ever came back for this batch: the LLM call itself failed
/// (after the one rate-limit retry), so nothing was parsed.
///
/// Every pair is unanswered and every one carries
/// [`DiscardReason::BatchCallFailed`]. Without this, a failed call left all
/// `batch_size` pairs looking exactly like pairs the model *answered about and
/// omitted* — the same conflation this module exists to remove, one layer up.
pub(crate) fn interpret_failed_batch(batch: &[CandidatePair]) -> BatchInterpretation {
    BatchInterpretation {
        results: Vec::new(),
        verdicts: Vec::new(),
        discards: batch
            .iter()
            .map(|pair| PerPairDiscard {
                source_id: pair.source_id,
                target_id: pair.target_id,
                reason: DiscardReason::BatchCallFailed,
            })
            .collect(),
        unanswered: (0..batch.len()).collect(),
    }
}

/// Parse one batch response and attribute every entry back to its pair.
///
/// Pure: no I/O. `batch` is the slice of candidates the prompt described, so
/// `batch.len()` is the bound `pair_index` is checked against.
///
/// Attribution rule, and the reason it is shaped this way: a reason is
/// recorded *against a pair*, so it has to be true of that pair. A discard
/// naming an in-range `pair_index` is pair-scoped and belongs to that pair.
/// Everything else — a non-array response, an entry too broken to read an
/// index from, an index outside the batch — is batch-scoped: it is reported
/// against every otherwise-unexplained unanswered pair, but worded as a
/// statement about the batch (see [`DiscardReason::as_str`]), never as a claim
/// that *this* pair's entry was the broken one. Batch-scoped damage therefore
/// suppresses the "the model was silent about this pair" reading without
/// fabricating attribution — an instrument that guesses is worse than one that
/// admits what it does not know.
pub(crate) fn interpret_batch_response(
    batch: &[CandidatePair],
    json: &serde_json::Value,
) -> BatchInterpretation {
    let parsed = parse_validation_response(json, batch.len());
    let results = parsed.results;

    let mut attributed: std::collections::HashMap<usize, DiscardReason> =
        std::collections::HashMap::new();
    let mut batch_wide: Option<DiscardReason> = None;
    for discard in &parsed.discards {
        match discard.pair_index {
            Some(i) if i < batch.len() && discard.reason.is_pair_scoped() => {
                attributed.entry(i).or_insert(discard.reason);
            }
            // Batch-scoped: keep the first one seen. Reporting several
            // batch-level faults per pair would not tell a reader anything the
            // first one doesn't, and would make the strings ungroupable.
            //
            // The classification is total on purpose: anything that lands here
            // is about to be smeared over every unexplained pair in the batch,
            // so a reason worded as a claim about one identified pair would
            // become false for all the others. `parse_validation_response`
            // already bounds-checks the index it recovers, which should make
            // this branch unreachable for a pair-scoped reason — the downgrade
            // makes the invariant structural rather than a promise about the
            // caller's care, so a future reason cannot reopen it.
            _ => {
                let reason = if discard.reason.is_pair_scoped() {
                    DiscardReason::UnattributableEntry
                } else {
                    discard.reason
                };
                batch_wide.get_or_insert(reason);
            }
        }
    }

    let verdicts: Vec<PerPairVerdict> = results
        .iter()
        .map(|result| {
            let pair = &batch[result.pair_index];
            PerPairVerdict {
                source_id: pair.source_id,
                target_id: pair.target_id,
                valid: result.valid,
                relationship: result.relationship.clone(),
                strength: result.strength,
                rationale: result.rationale.clone(),
            }
        })
        .collect();

    let responded: std::collections::HashSet<usize> =
        results.iter().map(|r| r.pair_index).collect();
    let unanswered: Vec<usize> = (0..batch.len())
        .filter(|i| !responded.contains(i))
        .collect();

    let discards: Vec<PerPairDiscard> = unanswered
        .iter()
        .filter_map(|&i| {
            let reason = attributed.get(&i).copied().or(batch_wide)?;
            Some(PerPairDiscard {
                source_id: batch[i].source_id,
                target_id: batch[i].target_id,
                reason,
            })
        })
        .collect();

    BatchInterpretation {
        results,
        verdicts,
        discards,
        unanswered,
    }
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
                // Record WHY these pairs have no verdict. Bumping `errors` and
                // moving on used to leave every pair in the batch
                // indistinguishable from one the model answered about and
                // omitted.
                summary
                    .per_pair_discards
                    .extend(interpret_failed_batch(batch).discards);
                continue;
            }
        };

        let BatchInterpretation {
            results,
            verdicts,
            discards,
            unanswered,
        } = interpret_batch_response(batch, &json);

        // Capture per-pair verdicts before mutating `summary` further. Output
        // preserves input order across batches.
        summary.per_pair_verdicts.extend(verdicts);
        summary.per_pair_discards.extend(discards);

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

        // Count pairs the LLM didn't return usable results for.
        for i in unanswered {
            eprintln!("  WARNING: LLM did not return a result for pair {i}");
            summary.errors += 1;
        }
    }

    // One line naming *what kind* of failure the `errors` count is made of.
    // Unconditional (not `verbose`-gated) because the library callers — the
    // cross-source sweep in particular — run with `verbose: false` and are
    // exactly the ones whose operators have no other trace.
    //
    // The header says "pairs" because that is what the numbers count: one
    // batch-scoped fault is reported against every unexplained pair in its
    // batch, so `50 × the LLM call for this batch failed` is fifty affected
    // pairs, not fifty failed calls. Leaving that ambiguous would make the
    // instrument's own output misreadable.
    let breakdown = summary.discard_breakdown();
    if !breakdown.is_empty() {
        let rendered: Vec<String> = breakdown
            .iter()
            .map(|(reason, n)| format!("{n} × {reason}"))
            .collect();
        eprintln!(
            "  no-verdict breakdown (pairs, by reason): {}",
            rendered.join("; ")
        );
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
    llm: &dyn LlmProvider,
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

    fn candidate() -> CandidatePair {
        CandidatePair {
            source_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            source_content: "src".to_string(),
            target_content: "tgt".to_string(),
            source_doi: None,
            target_doi: None,
            similarity: 0.5,
        }
    }

    /// `summary.errors` counts every batch index without a surviving result —
    /// discarded entries included. Extracting the loop into
    /// `interpret_batch_response` must not quietly change that count.
    #[test]
    fn interpret_counts_discarded_and_silent_pairs_alike_as_unanswered() {
        let batch = vec![candidate(), candidate(), candidate()];
        let json = serde_json::json!([
            // pair 0 omitted (silent); pair 1 discarded (bad relationship)
            {"pair_index": 1, "valid": true, "relationship": "causes",
             "strength": 0.7, "rationale": "r"},
            {"pair_index": 2, "valid": true, "relationship": "supports",
             "strength": 0.7, "rationale": "r"},
        ]);

        let interpretation = interpret_batch_response(&batch, &json);

        assert_eq!(interpretation.unanswered, vec![0, 1]);
        assert_eq!(interpretation.results.len(), 1);
        assert_eq!(interpretation.verdicts.len(), 1);
        // Only the discarded pair gets a reason; the silent one gets none, and
        // that absence is the signal.
        assert_eq!(interpretation.discards.len(), 1);
        assert_eq!(interpretation.discards[0].source_id, batch[1].source_id);
        assert_eq!(
            interpretation.discards[0].reason,
            DiscardReason::RelationshipOutOfVocabulary
        );
    }

    /// A `pair_index` outside the batch names no real pair, so it must be
    /// treated as batch damage — reported against every unanswered pair, never
    /// pinned to a pair we merely guessed at.
    #[test]
    fn out_of_bounds_index_is_batch_scoped_not_pinned_to_a_pair() {
        let batch = vec![candidate(), candidate()];
        let json = serde_json::json!([
            {"pair_index": 7, "valid": true, "relationship": "supports",
             "strength": 0.7, "rationale": "r"}
        ]);

        let interpretation = interpret_batch_response(&batch, &json);

        assert_eq!(interpretation.unanswered, vec![0, 1]);
        assert_eq!(interpretation.discards.len(), 2);
        for d in &interpretation.discards {
            assert_eq!(d.reason, DiscardReason::PairIndexOutOfBounds);
        }
    }

    /// A batch whose LLM call never returned yields no verdicts, every pair
    /// unanswered, and a `BatchCallFailed` reason for each — so downstream can
    /// say "we never got an answer" instead of "the model omitted this pair".
    #[test]
    fn failed_batch_marks_every_pair_as_call_failed() {
        let batch = vec![candidate(), candidate(), candidate()];

        let interpretation = interpret_failed_batch(&batch);

        assert!(interpretation.results.is_empty());
        assert!(interpretation.verdicts.is_empty());
        assert_eq!(interpretation.unanswered, vec![0, 1, 2]);
        assert_eq!(interpretation.discards.len(), 3);
        for (d, pair) in interpretation.discards.iter().zip(&batch) {
            assert_eq!(d.reason, DiscardReason::BatchCallFailed);
            assert_eq!(d.source_id, pair.source_id);
        }
    }

    /// Scope classification is what keeps the emitted strings true: only
    /// reasons carrying an in-range `pair_index` may be attributed to a pair.
    #[test]
    fn only_entry_level_reasons_are_pair_scoped() {
        for r in [
            DiscardReason::EntrySchemaMismatch,
            DiscardReason::RelationshipOutOfVocabulary,
            DiscardReason::StrengthOutOfRange,
        ] {
            assert!(r.is_pair_scoped(), "{r:?} should be pair-scoped");
        }
        for r in [
            DiscardReason::BatchCallFailed,
            DiscardReason::ResponseNotArray,
            DiscardReason::UnattributableEntry,
            DiscardReason::PairIndexOutOfBounds,
        ] {
            assert!(!r.is_pair_scoped(), "{r:?} should be batch-scoped");
            assert!(
                r.as_str().contains("batch"),
                "batch-scoped reason {r:?} must say so: {:?}",
                r.as_str()
            );
        }
    }

    /// The invariant behind every emitted string, asserted as a property rather
    /// than pinned by one fixture: nothing that ends up smeared across a whole
    /// batch may be worded as a claim about one identified pair.
    ///
    /// The entry below is malformed (`valid` is a plain `bool`, so `"yes"`
    /// fails deserialization) *and* names an index outside the batch. Before
    /// the bounds check in `parse_validation_response`, the index was recovered
    /// and the discard came back pair-scoped as `EntrySchemaMismatch`; the
    /// `i < batch.len()` guard in `interpret_batch_response` then rejected it,
    /// dropping a pair-scoped reason into the batch-wide slot, from where
    /// "this pair's entry did not match the verdict schema" was reported
    /// against pairs that never had an entry at all.
    #[test]
    fn a_batch_wide_reason_is_never_worded_as_a_claim_about_one_pair() {
        let batch = vec![candidate(), candidate()];
        let json = serde_json::json!([{"pair_index": 7, "valid": "yes"}]);

        let interpretation = interpret_batch_response(&batch, &json);

        assert_eq!(
            interpretation.discards.len(),
            2,
            "both silent pairs must be explained, or this test proves nothing"
        );
        for d in &interpretation.discards {
            assert!(
                !d.reason.is_pair_scoped(),
                "{:?} smeared batch-wide but is worded as a claim about one \
                 pair: {:?}",
                d.reason,
                d.reason.as_str()
            );
        }
    }

    /// Accumulate batches into a `RerankSummary` the way `rerank_inner` does,
    /// so the tests below read the same struct a production caller reads.
    fn summarize(batches: Vec<BatchInterpretation>) -> RerankSummary {
        let mut s = RerankSummary::default();
        for b in batches {
            s.errors += b.unanswered.len();
            s.per_pair_verdicts.extend(b.verdicts);
            s.per_pair_discards.extend(b.discards);
        }
        s
    }

    /// The headline defect, at the level where it is actually observable.
    ///
    /// A batch whose LLM call failed outright and a pair the model answered
    /// about and omitted are completely different events — one means the
    /// verifier never ran, the other means it ran and had nothing to say — and
    /// they call for opposite operator responses. Before this change both
    /// showed up as nothing but `+1 errors`, so a run reporting `errors: 300`
    /// could be one dead API key or three hundred genuinely-silent pairs and
    /// there was no way to tell.
    #[test]
    fn failed_llm_call_and_model_silence_are_distinguishable_in_the_summary() {
        let call_failed = candidate();
        let silent = candidate();

        let s = summarize(vec![
            interpret_failed_batch(std::slice::from_ref(&call_failed)),
            // Well-formed empty array: the model answered and named nobody.
            interpret_batch_response(std::slice::from_ref(&silent), &serde_json::json!([])),
        ]);

        assert_eq!(s.errors, 2, "both pairs are still counted as errors");
        assert_eq!(
            s.discard_breakdown(),
            [("the LLM call for this batch failed", 1)]
                .into_iter()
                .collect(),
            "a failed call must be named, and model silence must NOT be — the \
             absence of a reason is what marks genuine silence"
        );
    }

    /// The other bypass the reverted PR #381 got wrong. An out-of-vocabulary
    /// relationship is a real model answer we threw away; silence is not. Both
    /// used to be a bare `continue` plus `+1 errors`.
    #[test]
    fn discarded_entry_and_model_silence_are_distinguishable_in_the_summary() {
        let silent = candidate();
        let oov = candidate();
        let batch = vec![silent, oov.clone()];
        let json = serde_json::json!([
            {"pair_index": 1, "valid": true, "relationship": "causes",
             "strength": 0.7, "rationale": "A causes B"}
        ]);

        let s = summarize(vec![interpret_batch_response(&batch, &json)]);

        assert_eq!(s.errors, 2);
        assert_eq!(s.per_pair_discards.len(), 1, "only the discarded pair");
        assert_eq!(s.per_pair_discards[0].source_id, oov.source_id);
        assert_eq!(
            s.discard_breakdown(),
            [(
                "this pair's relationship was outside the accepted vocabulary",
                1
            )]
            .into_iter()
            .collect()
        );
    }

    /// `discard_breakdown`'s values count *pairs*, not faults. One damaged
    /// entry in a batch of three silent pairs reports as `3`, which is why the
    /// rendered line says "(pairs, by reason)" — a reader who takes the number
    /// as an event count would conclude three separate things went wrong.
    #[test]
    fn breakdown_values_count_affected_pairs_not_faults() {
        let batch = vec![candidate(), candidate(), candidate()];
        // A single out-of-range entry: one fault, three unexplained pairs.
        let json = serde_json::json!([
            {"pair_index": 9, "valid": true, "relationship": "supports",
             "strength": 0.7, "rationale": "r"}
        ]);

        let s = summarize(vec![interpret_batch_response(&batch, &json)]);

        assert_eq!(
            s.discard_breakdown(),
            [(
                "the batch response contained an entry naming a pair_index outside the batch",
                3
            )]
            .into_iter()
            .collect(),
            "one fault, three pairs — the count is of pairs"
        );
    }

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
