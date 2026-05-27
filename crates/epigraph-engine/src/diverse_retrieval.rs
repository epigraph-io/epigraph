//! Shared diverse-retrieval pipeline for HTTP `/api/v1/search/semantic`
//! and MCP `recall_with_context`.
//!
//! Pipeline:
//! 1. Find the `max_themes` most-similar themes for the query vector at
//!    the chosen centroid dimension (1536 or 3072).
//! 2. Pull up to `candidate_pool` claims from those themes, ranked by
//!    embedding similarity to the query.
//! 3. Build a similarity-proximity kNN neighborhood over the candidates.
//! 4. Run submodular `diverse_select` (relevance + coverage tradeoff) to
//!    pick `budget` final claims.
//!
//! Returns selected `(claim_id, content, similarity)` tuples in selection
//! order. Callers decide what to do with them — REST returns full claim
//! objects with graph neighbors; MCP feeds the IDs through
//! `fetch_batched_context` for paragraph-context enrichment.
//!
//! If the corpus has no themes yet, returns `Ok(vec![])` so the caller can
//! fall back to flat ANN. Same response if themes exist but contain no
//! candidates — the helper does not distinguish the two cases (matches the
//! REST route's pre-existing behaviour).
//!
//! # Layering
//!
//! Per CLAUDE.md, this module owns NO SQL. Every database touch routes
//! through [`epigraph_db::ClaimThemeRepository`]. The dim-aware
//! `find_similar_themes_at_dim` / `claims_in_themes_at_dim` repo methods
//! own the centroid-column interpolation and the `1536|3072` injection
//! gate. The layering test
//! `epigraph-engine/tests/diverse_retrieval_layering.rs` asserts this
//! module text-contains no raw SQL primitives — re-introducing them here
//! will fail that test loudly.

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::repos::claim_theme::ClaimThemeRepository;

use crate::diverse_select::diverse_select;

/// Number of similarity-rank neighbours each candidate gets in the
/// proximity graph fed to `diverse_select`. The REST route used `k=5`;
/// kept here for parity.
pub const DEFAULT_SIMILARITY_K: usize = 5;

/// Default candidate pool size for diverse selection. The REST route
/// hard-coded `100` (see `search.rs` pre-refactor). Same value here so
/// the post-helper REST behaviour is byte-for-byte equivalent when the
/// caller does NOT specify `candidate_pool`.
pub const DEFAULT_CANDIDATE_POOL: i32 = 100;

/// Hard cap on the candidate-pool top-K. [`build_similarity_neighbors`]
/// is O(n²) in candidate count, so an unbounded request would let a
/// caller balloon the in-memory similarity matrix. 1000 keeps the matrix
/// at ≤1M entries — same order of magnitude as the previous fixed 100
/// for typical traffic, but lets operators tune up to a finer cluster
/// granularity when they want it. Callers should clamp request values
/// against this cap at the request boundary so the user sees the value
/// they will actually get.
pub const MAX_CANDIDATE_POOL: u32 = 1000;

/// Find the `max_themes` claim_themes whose centroid at `centroid_dim` is
/// most similar to `query_pgvec`.
///
/// Thin async wrapper over [`ClaimThemeRepository::find_similar_themes_at_dim`]
/// that flattens [`epigraph_db::DbError`] into [`sqlx::Error`] so existing
/// callers (REST `search.rs`, MCP `recall.rs`) keep their pre-refactor
/// error-mapping codepath.
pub async fn find_similar_themes_at_dim(
    pool: &PgPool,
    query_pgvec: &str,
    max_themes: i32,
    centroid_dim: u32,
) -> Result<Vec<(Uuid, String, f64)>, sqlx::Error> {
    ClaimThemeRepository::find_similar_themes_at_dim(pool, query_pgvec, max_themes, centroid_dim)
        .await
        .map_err(db_error_to_sqlx)
}

/// Pull up to `limit` candidate claims from the given themes, ranked by
/// embedding similarity at `centroid_dim`.
///
/// Thin async wrapper over [`ClaimThemeRepository::claims_in_themes_at_dim`].
/// See the repo method for column-interpolation safety notes.
pub async fn candidates_in_themes_at_dim(
    pool: &PgPool,
    theme_ids: &[Uuid],
    query_pgvec: &str,
    limit: i32,
    centroid_dim: u32,
    paragraph_only: bool,
) -> Result<Vec<(Uuid, String, f64)>, sqlx::Error> {
    ClaimThemeRepository::claims_in_themes_at_dim(
        pool,
        theme_ids,
        query_pgvec,
        limit,
        centroid_dim,
        paragraph_only,
    )
    .await
    .map_err(db_error_to_sqlx)
}

/// Flatten [`epigraph_db::DbError`] back to [`sqlx::Error`] at the
/// engine boundary so pre-refactor callers keep their error types.
///
/// `DbError::QueryFailed` / `DbError::ConnectionFailed` already wrap an
/// `sqlx::Error`; unwrap them. `DbError::InvalidData` (raised by the dim
/// gate for `centroid_dim ≠ 1536|3072`) has no `sqlx` provenance so we
/// surface it via `sqlx::Error::Protocol`, which is the same string-typed
/// variant the engine module used pre-refactor for the same validation
/// case (engine callers `format!`-stringify the error).
fn db_error_to_sqlx(err: epigraph_db::DbError) -> sqlx::Error {
    match err {
        epigraph_db::DbError::QueryFailed { source }
        | epigraph_db::DbError::ConnectionFailed { source }
        | epigraph_db::DbError::MigrationFailed { source } => source,
        other => sqlx::Error::Protocol(other.to_string()),
    }
}

/// Build a similarity-based kNN neighborhood graph over a ranked
/// candidate list.
///
/// For each candidate `i`, the `k` other candidates with the closest
/// similarity score (a proxy for embedding proximity) are recorded as
/// neighbours. `diverse_select` uses these to avoid picking redundant
/// near-duplicates.
#[must_use]
pub fn build_similarity_neighbors(candidates: &[(Uuid, String, f64)], k: usize) -> Vec<Vec<usize>> {
    let n = candidates.len();
    let mut neighbors = vec![Vec::new(); n];

    for i in 0..n {
        let sim_i = candidates[i].2;
        // Score proximity as -|sim_i - sim_j| so the closest similarity
        // ranks comes first. Smaller absolute gap = more similar.
        let mut scored: Vec<(usize, f64)> = (0..n)
            .filter(|&j| j != i)
            .map(|j| (j, -(sim_i - candidates[j].2).abs()))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        neighbors[i] = scored.into_iter().take(k).map(|(j, _)| j).collect();
    }

    neighbors
}

/// Configuration for [`run_diverse_pipeline`].
#[derive(Debug, Clone, Copy)]
pub struct DiverseRetrievalConfig {
    pub centroid_dim: u32,
    pub max_themes: i32,
    /// Hard cap on candidates pulled from themes before
    /// [`diverse_select`] runs. Bigger pool = better diversity coverage
    /// but more SQL work AND a quadratic in-memory similarity matrix
    /// inside [`build_similarity_neighbors`]. Callers should clamp
    /// request values against [`MAX_CANDIDATE_POOL`] at the request
    /// boundary; the default if unset is [`DEFAULT_CANDIDATE_POOL`].
    pub candidate_pool: i32,
    /// Final selection size (after `diverse_select`).
    pub budget: usize,
    /// Coverage vs relevance tradeoff for `diverse_select`
    /// (0.0 = pure relevance, 1.0 = pure coverage).
    pub alpha: f32,
    /// When true, restrict candidates to `level=2` paragraphs. Used by
    /// MCP `recall_with_context` (paragraph-primary). REST passes
    /// `false` (matches its pre-helper behaviour).
    pub paragraph_only: bool,
}

/// Run the diverse-retrieval pipeline against the corpus.
///
/// Returns the selected `(claim_id, content, similarity)` tuples in
/// `diverse_select` selection order. Returns `Ok(vec![])` when no themes
/// exist OR when themes exist but the candidate pool is empty — callers
/// should fall back to flat ANN in either case (the helper does not
/// distinguish them, matching the REST route's pre-helper behaviour).
///
/// # Errors
///
/// Returns `sqlx::Error` if the theme lookup or candidate retrieval
/// query fails.
pub async fn run_diverse_pipeline(
    pool: &PgPool,
    query_pgvec: &str,
    config: DiverseRetrievalConfig,
) -> Result<Vec<(Uuid, String, f64)>, sqlx::Error> {
    let themes =
        find_similar_themes_at_dim(pool, query_pgvec, config.max_themes, config.centroid_dim)
            .await?;

    if themes.is_empty() {
        return Ok(vec![]);
    }

    let theme_ids: Vec<Uuid> = themes.iter().map(|(id, _, _)| *id).collect();
    let candidates = candidates_in_themes_at_dim(
        pool,
        &theme_ids,
        query_pgvec,
        config.candidate_pool,
        config.centroid_dim,
        config.paragraph_only,
    )
    .await?;

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    let neighbors = build_similarity_neighbors(&candidates, DEFAULT_SIMILARITY_K);
    let similarities: Vec<f32> = candidates.iter().map(|(_, _, s)| *s as f32).collect();

    let selected = diverse_select(&neighbors, &similarities, config.budget, config.alpha);
    Ok(selected
        .into_iter()
        .map(|idx| candidates[idx].clone())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_similarity_neighbors_picks_k_closest_by_similarity_gap() {
        // 5 candidates with monotonically decreasing similarity. For
        // candidate at rank 2 (sim=0.7), the closest two by |Δsim| are
        // ranks 1 (0.8) and 3 (0.6), each with gap=0.1.
        let candidates: Vec<(Uuid, String, f64)> = vec![
            (Uuid::nil(), "a".into(), 0.9),
            (Uuid::nil(), "b".into(), 0.8),
            (Uuid::nil(), "c".into(), 0.7),
            (Uuid::nil(), "d".into(), 0.6),
            (Uuid::nil(), "e".into(), 0.5),
        ];
        let nbrs = build_similarity_neighbors(&candidates, 2);
        assert_eq!(nbrs.len(), 5);
        // candidate index 2 should be paired with indices 1 and 3.
        let mut got = nbrs[2].clone();
        got.sort_unstable();
        assert_eq!(got, vec![1, 3]);
    }

    #[test]
    fn build_similarity_neighbors_empty_input_no_panic() {
        let nbrs = build_similarity_neighbors(&[], 5);
        assert!(nbrs.is_empty());
    }

    #[test]
    fn build_similarity_neighbors_excludes_self() {
        let candidates: Vec<(Uuid, String, f64)> = vec![
            (Uuid::nil(), "a".into(), 0.9),
            (Uuid::nil(), "b".into(), 0.8),
            (Uuid::nil(), "c".into(), 0.7),
        ];
        let nbrs = build_similarity_neighbors(&candidates, 5); // k > n-1
        for (i, ns) in nbrs.iter().enumerate() {
            assert!(
                !ns.contains(&i),
                "self-index {i} must never appear in its own neighbor list"
            );
            assert_eq!(
                ns.len(),
                2,
                "with n=3 and k=5, each candidate should have exactly n-1=2 neighbours"
            );
        }
    }
}
