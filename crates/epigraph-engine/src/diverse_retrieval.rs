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
//! fall back to flat ANN. Same response if the theme shortlist does not cover
//! the query's nearest neighbourhood (the theme-coverage guard, see
//! [`MIN_THEME_COVERAGE_FRACTION`]) or if themes exist but contain no
//! candidates — the helper does not distinguish the cases.
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

use chrono::{DateTime, Utc};
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

/// How many of the query's nearest claims the theme-coverage guard inspects.
///
/// Matched to pgvector's default `hnsw.ef_search` (40): an HNSW index scan
/// returns at most `ef_search` rows without iterative scanning, so a larger
/// probe would be truncated to this size on an index plan and not on a
/// sequential one.
///
/// That keeps the probe the same size across plans only when NO filter
/// applies. The viewer predicate, the `since` window, and a level filter the
/// chosen index does not carry are applied after the index scan, so under an
/// index plan a filtered probe can return far fewer than K rows. The
/// coverage fraction is therefore computed over the rows actually returned
/// (see [`epigraph_db::NeighbourhoodThemeCoverage::probed`]), and there is
/// deliberately no minimum on that count: a floor cannot tell a truncated
/// scan from a viewer whose visible neighbourhood is genuinely small, and the
/// flat fallback runs the same kind of post-filtered index scan, so falling
/// back would not recover the rows the probe missed.
pub const THEME_COVERAGE_PROBE_K: i32 = 40;

/// Minimum fraction of the query's nearest neighbourhood that diverse mode
/// must be able to reach through its theme shortlist for diverse selection to
/// run. Below it, diverse mode falls back to flat retrieval.
///
/// Why one half: diverse mode can only return members of the `max_themes`
/// themes it shortlisted, so the share of the neighbourhood outside that
/// shortlist (unthemed claims AND members of themes that were not
/// shortlisted) is exactly what it cannot see. Once that share is the
/// majority, the relevance lost outweighs any diversity gained. A small stale
/// theme set sits near 0 for almost every query; a partition whose nearest
/// themes hold the query's neighbours sits near 1.0. The boundary is
/// inclusive (`>=`).
///
/// Tradeoff, accepted: on a healthy fine-grained partition, a small
/// `max_themes` shortlist can hold less than half of a broad query's
/// neighbourhood, and such a request now falls back. That is the same
/// judgement applied honestly: diverse selection over that shortlist would
/// hide most of the relevant claims.
pub const MIN_THEME_COVERAGE_FRACTION: f64 = 0.5;

/// Decide whether a measured neighbourhood is covered well enough by the
/// theme shortlist for diverse selection to run.
///
/// `false` when nothing was probed: with no visible neighbour there is no
/// evidence the themes cover the query, and the flat path answers the empty
/// case just as well.
#[must_use]
pub fn theme_coverage_sufficient(
    coverage: epigraph_db::NeighbourhoodThemeCoverage,
    min_fraction: f64,
) -> bool {
    if coverage.probed <= 0 {
        return false;
    }
    (coverage.reachable as f64) / (coverage.probed as f64) >= min_fraction
}

/// Find the `max_themes` claim_themes whose centroid at `centroid_dim` is
/// most similar to `query_pgvec`.
///
/// Thin async wrapper over [`ClaimThemeRepository::find_similar_themes_at_dim`]
/// that flattens [`epigraph_db::DbError`] into [`sqlx::Error`] so its callers
/// keep their pre-refactor error-mapping codepath.
///
/// REST `search.rs` is NO LONGER one of them. PR-29 moved
/// `/api/v1/search/semantic` onto a viewer-stamped connection, and this wrapper
/// takes a `&PgPool`; widening it here rather than calling the repo directly
/// would have authored a connection-taking form that neither connection-shape
/// lint in `epigraph-db/tests/visibility_lint.rs` can see, because their
/// `repos_dir()` is a non-recursive `read_dir` over `epigraph-db/src/repos`.
/// The remaining callers, enumerated rather than gestured at: [`run_diverse_pipeline`]
/// — which is how MCP `recall.rs` reaches this wrapper, transitively; it does
/// not call it directly — and `epigraph-engine/tests/diverse_retrieval_integration.rs`.
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
///
/// # Callers: NONE, as of PR-29
///
/// Stated because a `pub` function with no caller is invisible to `dead_code`
/// and the next reader would otherwise have to grep for it. Its one real caller
/// was the REST `/api/v1/search/semantic?diverse=true` route, which PR-29 moved
/// onto a viewer-stamped connection calling
/// `ClaimThemeRepository::claims_in_themes_at_dim_since` directly (see
/// [`find_similar_themes_at_dim`] for why the route bypasses these wrappers
/// rather than widening them). [`run_diverse_pipeline`] calls the `_since`
/// sibling, not this one; the only remaining mentions of this name in the
/// workspace are comments.
///
/// Retained rather than removed: deleting a `pub` engine API is a decision for
/// a shard that owns this crate's surface, not for a route conversion.
pub async fn candidates_in_themes_at_dim(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    theme_ids: &[Uuid],
    query_pgvec: &str,
    limit: i32,
    centroid_dim: u32,
    paragraph_only: bool,
) -> Result<Vec<(Uuid, String, f64)>, sqlx::Error> {
    candidates_in_themes_at_dim_since(
        pool,
        viewer,
        theme_ids,
        query_pgvec,
        limit,
        centroid_dim,
        paragraph_only,
        None,
    )
    .await
}

/// [`candidates_in_themes_at_dim`] plus an optional `created_at >= since`
/// candidate window.
///
/// Added as a sibling rather than a seventh parameter on the existing function
/// so that the callers of [`candidates_in_themes_at_dim`] kept the exact call
/// they had at the time.
///
/// The REST `/api/v1/search/semantic?diverse=true` route was the caller that
/// rationale was written for, and it is no longer one: PR-29 has it call
/// `ClaimThemeRepository::claims_in_themes_at_dim_since` directly on a
/// viewer-stamped connection. See [`find_similar_themes_at_dim`] for why the
/// route bypasses these wrappers rather than widening them.
#[allow(clippy::too_many_arguments)]
pub async fn candidates_in_themes_at_dim_since(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    theme_ids: &[Uuid],
    query_pgvec: &str,
    limit: i32,
    centroid_dim: u32,
    paragraph_only: bool,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<(Uuid, String, f64)>, sqlx::Error> {
    ClaimThemeRepository::claims_in_themes_at_dim_since(
        pool,
        viewer,
        theme_ids,
        query_pgvec,
        limit,
        centroid_dim,
        paragraph_only,
        since,
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
    /// Optional `claims.created_at >= since` window on the candidate pool.
    /// `None` (the default everywhere it is not explicitly requested) is
    /// today's behaviour exactly. Applied in SQL before the candidate
    /// `LIMIT`, so a pool saturated by older claims cannot hide a newer one
    /// *within the themes that were chosen*.
    ///
    /// **Known limitation — theme selection is NOT windowed.**
    /// [`run_diverse_pipeline`] picks its `max_themes` themes by centroid
    /// similarity alone, before `since` is consulted, so a theme whose claims
    /// are all pre-window still consumes one of the slots and the windowed
    /// page comes back SHORT. This is a shortfall, never a leak: no
    /// pre-window claim can reach the caller, because the window still binds
    /// on the within-theme query. Bounded by `max_themes`. Windowing theme
    /// selection would need a new `claim_themes` query keyed on member
    /// `created_at`; it is deliberately deferred rather than half-done.
    ///
    /// Compatibility note: an additive REQUIRED field on a public struct
    /// breaks exhaustive struct literals outside this workspace. Judged
    /// acceptable, and NOT patched with `#[derive(Default)]`, because a
    /// defaulted `centroid_dim: 0` is rejected at runtime by
    /// `centroid_columns_for_dim` — deriving `Default` here would trade a
    /// compile error for a runtime `InvalidData`, which is strictly worse.
    /// Recorded as a decision, not an oversight.
    pub since: Option<DateTime<Utc>>,
}

/// Run the diverse-retrieval pipeline against the corpus.
///
/// Returns the selected `(claim_id, content, similarity)` tuples in
/// `diverse_select` selection order. Returns `Ok(vec![])` when no themes
/// exist, when the theme shortlist does not cover the query's nearest
/// neighbourhood (see [`MIN_THEME_COVERAGE_FRACTION`]; logged under the
/// `diverse_retrieval.coverage_guard` target), OR when themes exist but the
/// candidate pool is empty — callers should fall back to flat ANN in every
/// case (the helper does not distinguish them).
///
/// # Errors
///
/// Returns `sqlx::Error` if the theme lookup or candidate retrieval
/// query fails.
pub async fn run_diverse_pipeline(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
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

    // Theme-coverage guard. The theme lookup above is nearest-first with no
    // relevance floor, so ANY non-empty theme set wins the shortlist — and a
    // small stale one then funnels every query through its few members. Only
    // run diverse selection when most of the query's own nearest neighbourhood
    // (same candidate space, before theme restriction) is reachable through
    // the shortlist. MCP's candidate space is one dimension throughout, so the
    // neighbourhood and reachability dimensions are both `centroid_dim`.
    let coverage = ClaimThemeRepository::nearest_theme_coverage_since(
        pool,
        viewer,
        query_pgvec,
        config.centroid_dim,
        &theme_ids,
        config.centroid_dim,
        THEME_COVERAGE_PROBE_K,
        config.paragraph_only,
        config.since,
    )
    .await
    .map_err(db_error_to_sqlx)?;
    if !theme_coverage_sufficient(coverage, MIN_THEME_COVERAGE_FRACTION) {
        tracing::info!(
            target: "diverse_retrieval.coverage_guard",
            probed = coverage.probed,
            reachable = coverage.reachable,
            min_fraction = MIN_THEME_COVERAGE_FRACTION,
            centroid_dim = config.centroid_dim,
            "the theme shortlist does not cover the query's nearest neighbourhood; \
             diverse mode falls back to flat retrieval"
        );
        return Ok(vec![]);
    }

    let candidates = candidates_in_themes_at_dim_since(
        pool,
        viewer,
        &theme_ids,
        query_pgvec,
        config.candidate_pool,
        config.centroid_dim,
        config.paragraph_only,
        config.since,
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

    fn cov(probed: i64, reachable: i64) -> epigraph_db::NeighbourhoodThemeCoverage {
        epigraph_db::NeighbourhoodThemeCoverage { probed, reachable }
    }

    /// The boundary is inclusive: exactly the threshold share passes, one
    /// fewer themed neighbour fails. Derived from the constants so the arm
    /// tracks a retuned threshold instead of silently testing the old one.
    #[test]
    fn theme_coverage_boundary_is_inclusive_at_the_threshold() {
        let k = i64::from(THEME_COVERAGE_PROBE_K);
        let at = (MIN_THEME_COVERAGE_FRACTION * k as f64).ceil() as i64;
        assert!(
            at > 0 && at <= k,
            "threshold must be reachable within the probe"
        );
        assert!(
            theme_coverage_sufficient(cov(k, at), MIN_THEME_COVERAGE_FRACTION),
            "{at}/{k} themed is at the threshold and must keep diverse mode"
        );
        assert!(
            !theme_coverage_sufficient(cov(k, at - 1), MIN_THEME_COVERAGE_FRACTION),
            "{}/{k} themed is below the threshold and must fall back",
            at - 1
        );
    }

    /// The fraction is over rows actually probed, not over the requested k: an
    /// HNSW scan or the viewer predicate can return fewer rows, and dividing by
    /// k would read a fully-themed small neighbourhood as uncovered.
    #[test]
    fn theme_coverage_fraction_is_over_probed_rows_not_k() {
        let k = i64::from(THEME_COVERAGE_PROBE_K);
        let probed = k / 4;
        assert!(probed > 0 && probed < k);
        assert!(
            theme_coverage_sufficient(cov(probed, probed), MIN_THEME_COVERAGE_FRACTION),
            "{probed}/{probed} themed is full coverage even though fewer than k rows came back"
        );
    }

    /// Nothing probed is not evidence of coverage.
    #[test]
    fn theme_coverage_with_nothing_probed_is_insufficient() {
        assert!(!theme_coverage_sufficient(cov(0, 0), 0.0));
        assert!(!theme_coverage_sufficient(
            cov(0, 0),
            MIN_THEME_COVERAGE_FRACTION
        ));
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
