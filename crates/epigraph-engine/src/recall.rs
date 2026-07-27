//! Library-level `recall` function.
//!
//! Lifted from `epigraph-mcp/src/tools/memory.rs` so episcience and other
//! crates can call it with `(pool, embedder, query, limit, min_truth)` without
//! spawning MCP-over-stdio.
//!
//! The MCP handler in `tools/memory.rs` becomes a thin adapter that delegates
//! here and shapes the result into a `CallToolResult`.
//!
//! # Fallback behaviour
//!
//! If `embedder.generate_query` fails (e.g. no API key), the function falls
//! back to text search via `ClaimRepository::list`. This matches the existing
//! MCP behaviour.

use epigraph_core::ClaimId;
use epigraph_db::{ClaimRepository, PgPool};
use epigraph_embeddings::EmbeddingService;
use thiserror::Error;

/// Errors from the library-level `recall` function.
///
/// Embedding failures (e.g. no API key, mock mode) trigger silent fallback to
/// text search; they are not surfaced as a `RecallError`. The only failure
/// mode this function can return is a database error from the fallback path.
#[derive(Debug, Error)]
pub enum RecallError {
    /// Database access failed (either embedding-search or text-search fallback).
    #[error("database error: {0}")]
    Db(#[from] epigraph_db::DbError),
}

/// A single result from a recall query.
#[derive(Debug, Clone)]
pub struct RecallResult {
    /// The claim's UUID, serialised as a string for JSON compatibility.
    pub claim_id: String,
    /// The claim's text content.
    pub content: String,
    /// Bayesian truth value (0.0–1.0).
    pub truth_value: f64,
    /// Cosine similarity to the query embedding (0.0 if text-search fallback).
    pub similarity: f64,
    /// Number of `is_current` claims contesting this one via
    /// `contradicts`/`refutes` (backlog 34d3400d). `0` when uncontested.
    pub dispute_count: u32,
    /// `true` iff `dispute_count > 0`. Surfaced alongside `truth_value`, not
    /// instead of it — contested does not mean false, it means unsettled.
    pub is_contested: bool,
    /// The three strongest contesters (by their own `truth_value`).
    pub contesting_claim_ids: Vec<uuid::Uuid>,
}

/// Format a `Vec<f32>` as a pgvector string literal `[a,b,c,...]`.
///
/// Mirrors the same helper in `epigraph-mcp/src/embed.rs` — kept private here
/// to avoid a cross-crate dependency on the MCP crate.
fn format_pgvector(vec: &[f32]) -> String {
    let inner: Vec<String> = vec.iter().map(|v| format!("{v}")).collect();
    format!("[{}]", inner.join(","))
}

/// Semantic recall: embed the query, find similar claims, filter by truth.
///
/// Falls back to `ClaimRepository::list` text search when `embedder` returns
/// an error (e.g. embeddings disabled, no API key).
///
/// # Parameters
/// - `pool`      — live database connection pool
/// - `embedder`  — embedding service; only `generate_query` is called
/// - `query`     — natural-language query string
/// - `limit`     — maximum number of results to return (clamped 1–50 by callers)
/// - `min_truth` — minimum truth value threshold; results below are dropped
///
/// # Errors
/// Returns `RecallError::Db` if the fallback text search fails.
/// Embedding errors cause silent fallback, not a returned error.
pub async fn recall(
    pool: &PgPool,
    embedder: &dyn EmbeddingService,
    query: &str,
    limit: usize,
    min_truth: f64,
) -> Result<Vec<RecallResult>, RecallError> {
    let limit_i64 = limit as i64;

    // Try semantic search first.
    let results = if let Ok(embedding) = embedder.generate_query(query).await {
        let pgvec = format_pgvector(&embedding);
        // ANN over `claims.embedding` (is_current, all levels) — NOT
        // `evidence.embedding`, which is a permanently-empty column: searching
        // it made this semantic leg always return nothing and silently starved
        // downstream callers (episcience synthesis stage-1 seeding).
        match ClaimRepository::search_by_embedding_current(pool, &pgvec, limit_i64).await {
            Ok(hits) => {
                let mut results = Vec::new();
                for hit in hits {
                    if let Ok(Some(claim)) =
                        ClaimRepository::get_by_id(pool, ClaimId::from_uuid(hit.claim_id)).await
                    {
                        let tv = claim.truth_value.value();
                        if tv >= min_truth {
                            results.push(RecallResult {
                                claim_id: hit.claim_id.to_string(),
                                content: claim.content,
                                truth_value: tv,
                                similarity: hit.similarity,
                                // Annotated by the batched dispute post-pass
                                // below, keyed by claim_id.
                                dispute_count: 0,
                                is_contested: false,
                                contesting_claim_ids: Vec::new(),
                            });
                        }
                    }
                }
                results
            }
            Err(e) => {
                tracing::warn!("embedding search failed, falling back to text search: {e}");
                text_search_fallback(pool, query, limit_i64, min_truth).await?
            }
        }
    } else {
        // Embedding generation failed (no API key, mock mode, etc.) — fall back
        // to text search. This matches the existing MCP behaviour.
        text_search_fallback(pool, query, limit_i64, min_truth).await?
    };

    let mut results = results;
    annotate_disputes(pool, &mut results).await;
    Ok(results)
}

/// Batched dispute annotation (backlog 34d3400d), shared by the semantic and
/// text-fallback paths so the two cannot drift.
///
/// Best-effort by design: a dispute-lookup failure warns and serves the page
/// unannotated rather than failing a recall that already has its results. The
/// signal informs the caller; it never re-ranks and never gates retrieval.
async fn annotate_disputes(pool: &PgPool, results: &mut [RecallResult]) {
    let claim_ids: Vec<uuid::Uuid> = results
        .iter()
        .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
        .collect();
    match ClaimRepository::dispute_batch(pool, &claim_ids).await {
        Ok(mut by_claim) => {
            for r in results.iter_mut() {
                let Ok(cid) = uuid::Uuid::parse_str(&r.claim_id) else {
                    continue;
                };
                // Absent key == uncontested, per the repo contract.
                if let Some(d) = by_claim.remove(&cid) {
                    r.dispute_count = d.dispute_count.max(0) as u32;
                    r.is_contested = d.dispute_count > 0;
                    r.contesting_claim_ids = d.contesting_claim_ids;
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "dispute batch failed; serving recall page without dispute annotations"
            );
        }
    }
}

/// Text-search fallback via `ClaimRepository::list` with `ILIKE` filter.
async fn text_search_fallback(
    pool: &PgPool,
    query: &str,
    limit: i64,
    min_truth: f64,
) -> Result<Vec<RecallResult>, RecallError> {
    let claims = ClaimRepository::list(pool, limit, 0, Some(query)).await?;
    Ok(claims
        .into_iter()
        .filter(|c| c.truth_value.value() >= min_truth)
        .map(|c| RecallResult {
            claim_id: c.id.as_uuid().to_string(),
            content: c.content,
            truth_value: c.truth_value.value(),
            similarity: 0.0,
            // Annotated by `annotate_disputes` once the caller has the page —
            // the fallback path returns into `recall`, which runs the pass.
            dispute_count: 0,
            is_contested: false,
            contesting_claim_ids: Vec::new(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_embeddings::{config::EmbeddingConfig, providers::MockProvider};

    // NOTE on deferred behavioral tests:
    //
    // Plan Task 0.4 specified `#[sqlx::test]`-based behavioral assertions
    // (e.g. `recall_returns_results_above_min_truth`) seeded via a helper
    // `epigraph_test_helpers::ingest_claim_via_api`. That helper does not
    // exist yet — `feedback_no_raw_sql` rules out direct INSERTs, and the
    // public `POST /claims` route requires a running API server and a valid
    // service token, neither of which is in scope for Task 0.4.
    //
    // Phase 1 introduces episcience's API client (`EpigraphEdgesClient` and
    // friends) plus a test fixture that spins up the API server with seeded
    // service credentials. The full behavioral suite for `recall` lands in
    // `crates/epigraph-engine/tests/recall_test.rs` at that point.
    //
    // Until then, the tests below cover the trait-bound and wiring layer
    // only. They will not catch a regression where, e.g., the `min_truth`
    // filter is applied at the wrong place — that gap closes in Phase 1.

    /// Confirm `MockProvider` satisfies the `EmbeddingService` bound required by
    /// `recall`. This is a compile-time wiring test; it panics with a DB error
    /// rather than a trait error if the trait bound is wrong.
    #[test]
    fn mock_provider_satisfies_embedding_service_bound() {
        // Confirm the type implements the trait at compile time.
        fn assert_embedding_service<T: EmbeddingService>(_: &T) {}
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        assert_embedding_service(&provider);
    }

    /// Confirm that `format_pgvector` produces a pgvector-compatible string.
    #[test]
    fn format_pgvector_roundtrip() {
        let vec = vec![0.1f32, 0.2, 0.3];
        let s = format_pgvector(&vec);
        assert!(s.starts_with('['), "should start with [");
        assert!(s.ends_with(']'), "should end with ]");
        // Three floats → two commas
        assert_eq!(s.matches(',').count(), 2);
    }

    /// Confirm `recall` is callable with a `&dyn EmbeddingService` by checking
    /// that `MockProvider` can be coerced to the trait object type.
    ///
    /// Integration tests against a real DB are deferred until episcience adds
    /// API-based seeding helpers in Phase 1+.
    #[test]
    fn recall_accepts_dyn_embedding_service() {
        // Just confirm the coercion compiles; no async runtime needed.
        let config = EmbeddingConfig::local(64);
        let provider = MockProvider::new(config);
        let _: &dyn EmbeddingService = &provider;
        // If this compiles, recall(&pool, &provider, ...) will also compile.
    }
}
