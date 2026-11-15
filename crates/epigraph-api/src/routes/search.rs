//! Semantic Search Routes
//!
//! Implements the `/api/v1/search/semantic` endpoint for vector similarity
//! search against claim embeddings using pgvector.
//!
//! # Overview
//!
//! The semantic search endpoint allows clients to find claims that are
//! semantically similar to a natural language query. Results are ranked
//! by cosine similarity and can be filtered by various criteria.
//!
//! # Example
//!
//! ```json
//! POST /api/v1/search/semantic
//! {
//!   "query": "climate change effects on agriculture",
//!   "limit": 10,
//!   "min_similarity": 0.5,
//!   "claim_type": "factual"
//! }
//! ```
//!
//! # Theme pin, theme-core ranking and paging
//!
//! ```json
//! POST /api/v1/search/semantic
//! { "query": "gold electrode capacitance", "limit": 50,
//!   "theme_id": "3b2f6a0e-9c1d-4c8e-9a51-2f0c9b7d1e44", "cursor": "o:50" }
//!
//! POST /api/v1/search/semantic
//! { "theme_id": "3b2f6a0e-9c1d-4c8e-9a51-2f0c9b7d1e44", "rank_by": "theme_core",
//!   "limit": 100, "cursor": "o:100" }
//! ```
//!
//! * **`theme_id`** confines every hit to `claims.theme_id = <theme>`, in SQL,
//!   above each cut (the semantics MCP recall's theme pin has). A malformed id
//!   is a 400 on `theme_id`. An unknown theme and a theme in which the viewer
//!   can read no member are the same 404 (`NotFound`, entity `Theme`). The
//!   response echoes `theme_scope: {theme_id, member_count, rank_by}`, where
//!   `member_count` is the viewer's count. **No theme label is ever
//!   returned**: labels are generated from member content with no visibility
//!   filter. This 404 is not a confidentiality guarantee for theme existence;
//!   other routes list every theme row.
//! * **`rank_by`** is `"query"` (default) or `"theme_core"`. `theme_core`
//!   needs `theme_id`, takes no `query` and no `diverse`, makes no embedding
//!   call, and ranks the theme's members by cosine similarity to the theme
//!   core: the mean embedding of its PUBLIC members, else (a theme with no
//!   public embedded member) the mean of the members this viewer can read.
//!   It is computed in SQL per request and is never the stored
//!   `claim_themes.centroid`, which averages private members too.
//!   `similarity` then means similarity to that core, and an absent
//!   `min_similarity` is -1 so a walk enumerates every embedded visible member.
//! * **`cursor`** is opaque: pass back a previous `next_cursor` unchanged. It
//!   is a position (`o:<offset>`), never an id, inside a 1,000-row window.
//!   `next_cursor` is emitted only on the flat path and only when the request
//!   carried `theme_id` or `cursor`; send `"o:0"` to page an unpinned search.
//! * **Pinned diverse** (`theme_id` with `diverse=true`) skips the theme
//!   shortlist and the coverage guard, draws exact candidates from the pinned
//!   theme with `created_after` and `min_similarity` applied in SQL, refuses
//!   `created_before`, `claim_type`, `agent_id` and `cursor`, and falls
//!   through to the pinned flat path when the theme has no candidate at the
//!   chosen dimension.
//! * **Byte budget**: every response is cut to about 2 MB. A paged flat
//!   response resumes the cut at `next_cursor`; any other cut response says
//!   `truncated: true`.
//! * **Embedder down**: with no embedding service configured, the
//!   deterministic mock vector goes through the same pinned read, so the pin
//!   holds while the order is meaningless. A configured service that FAILS on
//!   a request that can carry a cursor (`theme_id` or `cursor`, not
//!   `diverse`) is 503 `ServiceUnavailable`: a mock-ranked page inside a walk
//!   of the real ranking would skip and repeat rows unseen. Unpaged requests
//!   keep the old mock fallback.
//!
//! # Caching
//!
//! Every response is viewer-scoped: the route sets `Cache-Control: private,
//! no-store` and `Vary: Authorization` (`routes/mod.rs`), and any cache in
//! front of it must key on viewer identity plus theme, rank mode, query and
//! cursor. `next_cursor` is bound to no viewer and grants nothing: replayed by
//! another viewer it pages that viewer's own filtered ranking.

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(feature = "db")]
use sqlx::Row;

// PR-29: the two theme statements now go STRAIGHT to
// `epigraph_db::ClaimThemeRepository` rather than through the
// `epigraph_engine::diverse_retrieval` wrappers this file used to call.
//
// The wrappers take `pool: &PgPool` and are not generic, so keeping them would
// have meant widening them — and `visibility_lint.rs::repos_dir()` is a
// NON-RECURSIVE `read_dir` over `epigraph-db/src/repos`, so a connection-taking
// form authored in `epigraph-engine` is invisible to BOTH connection-shape
// lints. Calling the repo directly keeps every widened form inside the scan
// root where a control can see it, and matches CLAUDE.md's "routes call the repo
// layer" rule.
//
// What the wrappers add is `db_error_to_sqlx`, so pre-refactor callers keep
// `sqlx::Error`. This route maps either error type through
// `format!("{e}")` into `ApiError::InternalError`, so the flattening is not
// observable here. The one variant the wrapper reshapes that this route could
// otherwise surface is `DbError::InvalidData { unsupported centroid_dim }`, and
// `centroid_dim` is validated against `1536 | 3072` at the request boundary
// below before either call runs, so it is unreachable.
//
// NEITHER WRAPPER IS DELETED, but they are no longer symmetrical and saying
// otherwise would be a false claim about what this diff leaves behind:
//
// - `find_similar_themes_at_dim` KEEPS callers — `run_diverse_pipeline` (which
//   is how MCP `recall_with_context` reaches it; MCP does not call the wrapper
//   directly) and `epigraph-engine/tests/diverse_retrieval_integration.rs`.
// - `candidates_in_themes_at_dim` is left with NO caller anywhere in the
//   workspace, tests included, by this change. `run_diverse_pipeline` calls the
//   `_since` sibling, and the only remaining mentions of the name are comments.
//   It is retained rather than removed because deleting a `pub` engine API is
//   not a conversion shard's call; recorded here so the next shard finds it
//   already measured instead of re-deriving it.
#[cfg(feature = "db")]
use epigraph_engine::diverse_retrieval::{DEFAULT_CANDIDATE_POOL, MAX_CANDIDATE_POOL};

use crate::middleware::bearer::ViewerExtractor;
use crate::{errors::ApiError, state::AppState};

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request body for semantic search
///
/// # Fields
///
/// - `query`: The natural language query to search for semantically similar claims
/// - `limit`: Maximum number of results to return (default: 10, max: 100)
/// - `min_similarity`: Minimum similarity threshold [0.0, 1.0] (default: 0.0)
/// - `claim_type`: Filter by claim type: "factual", "hypothesis", "opinion"
/// - `created_after`: Filter claims created after this timestamp
/// - `created_before`: Filter claims created before this timestamp
/// - `agent_id`: Filter by the agent who made the claim
/// - `theme_id`: Confine every hit to one theme (see the module docs)
/// - `rank_by`: `"query"` (default) or `"theme_core"`
/// - `cursor`: Opaque page position from a previous `next_cursor`
#[derive(Debug, Default, Deserialize)]
pub struct SemanticSearchRequest {
    /// The query string to search for semantically similar claims.
    ///
    /// Required (non-blank) when `rank_by` is `"query"`; must be absent or
    /// blank with `rank_by = "theme_core"`. A missing key deserializes to the
    /// empty string so both cases answer a 400 `ValidationError` on `query`
    /// rather than a JSON rejection.
    #[serde(default)]
    pub query: String,

    /// Maximum number of results to return (default: 10, max: 100)
    #[serde(default)]
    pub limit: Option<u32>,

    /// Minimum similarity threshold [0.0, 1.0] (default: 0.0)
    #[serde(default)]
    pub min_similarity: Option<f64>,

    /// Filter by claim type: "factual", "hypothesis", "opinion"
    #[serde(default)]
    pub claim_type: Option<String>,

    /// Filter claims created after this timestamp
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,

    /// Filter claims created before this timestamp
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,

    /// Filter by the agent who made the claim
    #[serde(default)]
    pub agent_id: Option<Uuid>,

    /// Enable diverse hierarchical retrieval (theme-based + coverage selection).
    ///
    /// Falls back to flat search (reported as `centroid_dim_used: null`) when
    /// no themes exist, or when fewer than half of the query's nearest claims
    /// belong to the `max_themes` themes diverse mode would draw from.
    #[serde(default)]
    pub diverse: Option<bool>,

    /// Maximum number of themes to consider in diverse mode (default: 5)
    #[serde(default)]
    pub max_themes: Option<u32>,

    /// Coverage vs relevance tradeoff for diverse mode (0.0 = pure relevance, 1.0 = pure coverage, default: 0.5)
    #[serde(default)]
    pub diversity_weight: Option<f32>,

    /// Centroid dimension to query against in diverse mode. `None` =
    /// auto-detect (picks 3072 when ≥50% of `claim_themes` rows have
    /// `centroid_3072` populated, else 1536). `Some(1536)` forces the
    /// legacy `claim_themes.centroid` + `claims.embedding` columns;
    /// `Some(3072)` forces `claim_themes.centroid_3072` +
    /// `claims.embedding_3072` (operator must have run
    /// `epigraph-cli reembed --target claims` and rebuilt themes
    /// with `centroid_dim=3072` first, otherwise this returns 400
    /// ValidationError). Ignored when `diverse=false`.
    #[serde(default)]
    pub centroid_dim: Option<u32>,

    /// Candidate-pool top-K — the second-stage cutoff after theme
    /// selection. The diverse pipeline first picks the `max_themes`
    /// most-similar themes, then pulls up to this many claims across
    /// them as the input to submodular `diverse_select`. Higher values
    /// = better diversity coverage but more SQL work and a quadratic
    /// in-memory similarity matrix inside `build_similarity_neighbors`.
    ///
    /// Default is
    /// [`DEFAULT_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::DEFAULT_CANDIDATE_POOL)
    /// (100, matching the historical hard-coded value). Clamped to
    /// [`MAX_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::MAX_CANDIDATE_POOL)
    /// (1000) to prevent runaway matrices. Ignored when
    /// `diverse=false`.
    #[serde(default)]
    pub candidate_pool: Option<u32>,

    /// UUID of a `claim_themes` row. Every hit is confined to
    /// `claims.theme_id = <theme>`, in SQL, above every cut. Blank counts as
    /// absent; a malformed value is a 400 on `theme_id`; an unknown theme, and
    /// a theme in which the viewer can read no member, are the same 404.
    /// Parsed by hand (a `String`, not a `Uuid`) so the malformed case is a
    /// `ValidationError` with a field rather than a JSON rejection.
    #[serde(default)]
    pub theme_id: Option<String>,

    /// `"query"` (default) or `"theme_core"`. `theme_core` needs `theme_id`,
    /// takes no `query` and no `diverse`, makes no embedding call, and ranks
    /// the theme's members by similarity to the theme core (the mean of its
    /// public members, else of the members the viewer can read).
    #[serde(default)]
    pub rank_by: Option<String>,

    /// Opaque page position: pass back a previous `next_cursor` unchanged.
    /// The format is `o:<offset>`, a position and never an id. Blank counts
    /// as absent. Send `"o:0"` on the first page to page an unpinned search.
    /// Not accepted with `diverse=true`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// CDST belief interval for a claim — more informative than a single truth value
#[derive(Debug, Clone, Serialize)]
pub struct EpistemicState {
    /// Dempster-Shafer belief (lower bound of the belief interval)
    pub belief: Option<f64>,
    /// Dempster-Shafer plausibility (upper bound of the belief interval)
    pub plausibility: Option<f64>,
    /// Epistemic ignorance: plausibility - belief (width of the interval)
    pub ignorance: Option<f64>,
    /// Legacy truth value (point estimate)
    pub truth_value: f64,
}

impl EpistemicState {
    fn from_row(truth_value: f64, belief: Option<f64>, plausibility: Option<f64>) -> Self {
        let ignorance = match (belief, plausibility) {
            (Some(b), Some(p)) => Some((p - b).max(0.0)),
            _ => None,
        };
        Self {
            belief,
            plausibility,
            ignorance,
            truth_value,
        }
    }
}

/// A single search result with similarity score
#[derive(Debug, Serialize)]
pub struct SemanticSearchResult {
    /// The unique identifier of the claim
    pub claim_id: Uuid,

    /// The claim statement text
    pub statement: String,

    /// Cosine similarity score [0.0, 1.0] between query and claim embedding
    pub similarity: f64,

    /// CDST epistemic state: belief interval [Bel, Pl] + ignorance + legacy truth
    pub epistemic: EpistemicState,

    /// The agent who made the claim
    pub agent_id: Uuid,

    /// The reasoning trace ID associated with this claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<Uuid>,

    /// The type of claim: factual, hypothesis, or opinion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_type: Option<String>,

    /// When the claim was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Graph neighbors providing epistemic context (only in diverse mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_neighbors: Option<Vec<GraphNeighbor>>,

    /// Theme this claim belongs to (its `claims.theme_id` in `claim_themes`,
    /// maintained by the UMAP theme pipeline); always emitted in diverse mode so callers can render or filter by
    /// theme. `None` if the claim hasn't been assigned. Flat-search results
    /// omit this field via `skip_serializing_if`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_id: Option<Uuid>,

    /// Graph community this claim belongs to in the latest cluster run
    /// (Louvain over edges, populated by the cluster_graph job). Same
    /// emission semantics as `theme_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<Uuid>,
}

/// A graph neighbor of a search result, providing epistemic context
#[derive(Debug, Serialize)]
pub struct GraphNeighbor {
    /// The neighbor claim ID
    pub claim_id: Uuid,
    /// The claim content
    pub statement: String,
    /// Cosine similarity to the query
    pub similarity: f64,
    /// CDST epistemic state
    pub epistemic: EpistemicState,
    /// The edge relationship type (e.g., "CORROBORATES", "supports", "contradicts")
    pub edge_type: String,
    /// Whether this is inbound or outbound from the picked claim
    pub direction: String,
}

/// Response from semantic search endpoint
#[derive(Debug, Serialize)]
pub struct SemanticSearchResponse {
    /// The search results, sorted by similarity descending
    pub results: Vec<SemanticSearchResult>,

    /// Total number of matching claims (before limit applied)
    pub total: u64,

    /// Time taken to execute the query in milliseconds
    pub query_time_ms: u64,

    /// Centroid dimension actually used in diverse mode (1536 or 3072).
    /// `None` for non-diverse / flat searches. Reflects either the
    /// caller's explicit `centroid_dim` hint or the auto-detect
    /// outcome, so callers can verify which embedding space was
    /// queried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub centroid_dim_used: Option<u32>,

    /// The resolved theme pin. Present exactly when the request carried a
    /// `theme_id`. Carries no label: theme labels are generated from member
    /// content with no visibility filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme_scope: Option<SearchThemeScope>,

    /// Opaque position of the next page (`o:<offset>`), flat path only, and
    /// only when the request carried `theme_id` or `cursor`. Absent at the end
    /// of the ranking and at the 1,000-row window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// `true` when the response byte budget dropped hits and no `next_cursor`
    /// carries them (any diverse response, or an unpaged flat one). Omitted
    /// when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The theme a pinned search was confined to, as this viewer sees it.
///
/// Deliberately has no `label`: `claim_themes.label` is written from the
/// content of the members nearest the stored centroid with no visibility
/// filter, so it can summarise text this viewer may not read.
#[derive(Debug, Clone, Serialize)]
pub struct SearchThemeScope {
    /// The `claim_themes` id the request pinned.
    pub theme_id: Uuid,
    /// The viewer's count of current members (viewer-filtered; never the
    /// stored `claim_count`). At least the number of hits a full walk returns.
    pub member_count: i64,
    /// `"query"` or `"theme_core"`.
    pub rank_by: &'static str,
}

// ============================================================================
// Constants
// ============================================================================

/// Default number of results to return
const DEFAULT_LIMIT: u32 = 10;

/// Maximum number of results that can be requested
const MAX_LIMIT: u32 = 100;

/// Valid claim types for filtering
const VALID_CLAIM_TYPES: &[&str] = &["factual", "hypothesis", "opinion"];

/// Embedding dimension for OpenAI text-embedding-3-small (legacy default)
#[cfg(feature = "db")]
const EMBEDDING_DIM: usize = 1536;

/// Embedding dimension for OpenAI text-embedding-3-large (Phase 5 3072d path)
#[cfg(feature = "db")]
const EMBEDDING_DIM_LARGE: usize = 3072;

/// Maximum query string length in bytes.
/// Prevents DoS attacks via excessively long queries that could consume
/// excessive memory in embedding generation or database operations.
/// 10KB is sufficient for complex semantic queries.
const MAX_QUERY_LENGTH: usize = 10_240;

/// Maximum claim_type filter length in bytes.
/// Prevents buffer overflow or injection attempts via oversized filter values.
const MAX_CLAIM_TYPE_LENGTH: usize = 64;

/// The flat ranking pages inside this many rows: a `cursor` offset must be
/// below it, and a page is cut so that `offset + limit` never passes it.
const MAX_SEARCH_WINDOW: i64 = 1000;

/// Upper bound on a response body. Claim content can reach 64 KiB, so 100
/// hits could otherwise approach 7 MB.
const MAX_RESPONSE_BYTES: usize = 2_000_000;

/// Bytes reserved for the response envelope (`total`, `query_time_ms`,
/// `centroid_dim_used`, `theme_scope`, `next_cursor`, `truncated`) out of
/// [`MAX_RESPONSE_BYTES`]; the hits share the rest.
const RESPONSE_ENVELOPE_BYTES: usize = 1_024;

/// Bound on the serialised bytes of one hit outside its strings: keys,
/// punctuation, five UUIDs, five floats and a timestamp come to about 560.
const HIT_OVERHEAD_BYTES: usize = 700;

/// The same bound for one graph neighbour outside its strings: keys,
/// punctuation, one UUID and five floats come to about 300.
const NEIGHBOR_OVERHEAD_BYTES: usize = 400;

/// The cursor prefix: a position, never an id (as `privatization.rs`'s
/// `CURSOR_PREFIX`).
const SEARCH_CURSOR_PREFIX: &str = "o:";

// ============================================================================
// Theme pin, ranking, cursor and byte budget
// ============================================================================

/// What the flat path ranks by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RankBy {
    /// Similarity to the embedded `query` (the default).
    Query,
    /// Similarity to the pinned theme's core.
    ThemeCore,
}

impl RankBy {
    #[cfg_attr(not(feature = "db"), allow(dead_code))]
    fn as_str(self) -> &'static str {
        match self {
            RankBy::Query => "query",
            RankBy::ThemeCore => "theme_core",
        }
    }
}

/// `theme_id`: trimmed; blank is absent; otherwise a UUID or a 400. Mirrors
/// MCP recall's selector, which rejects rather than drops a bad pin: a scope
/// filter that failed open would widen the result set while the caller
/// believes it is scoped.
fn parse_theme_filter(raw: Option<&str>) -> Result<Option<Uuid>, ApiError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    Uuid::parse_str(s)
        .map(Some)
        .map_err(|_| ApiError::ValidationError {
            field: "theme_id".to_string(),
            reason: "theme_id must be a UUID".to_string(),
        })
}

/// `rank_by`: absent or blank is `query`.
fn parse_rank_by(raw: Option<&str>) -> Result<RankBy, ApiError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("query") => Ok(RankBy::Query),
        Some("theme_core") => Ok(RankBy::ThemeCore),
        Some(_) => Err(ApiError::ValidationError {
            field: "rank_by".to_string(),
            reason: "rank_by must be \"query\" or \"theme_core\"".to_string(),
        }),
    }
}

/// `cursor`: `None` when absent or blank, so the handler can tell a supplied
/// cursor (a paged request) from none. Otherwise `o:` plus a non-negative
/// integer below [`MAX_SEARCH_WINDOW`].
fn parse_search_cursor(raw: Option<&str>) -> Result<Option<i64>, ApiError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let bad = |reason: &str| ApiError::ValidationError {
        field: "cursor".to_string(),
        reason: reason.to_string(),
    };
    let digits = s
        .strip_prefix(SEARCH_CURSOR_PREFIX)
        .ok_or_else(|| bad("cursor must be a next_cursor value from a previous page"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(
            "cursor must be a next_cursor value from a previous page",
        ));
    }
    let offset: i64 = digits
        .parse()
        .map_err(|_| bad("cursor is beyond the search window"))?;
    if offset >= MAX_SEARCH_WINDOW {
        return Err(bad("cursor is beyond the search window"));
    }
    Ok(Some(offset))
}

#[cfg_attr(not(feature = "db"), allow(dead_code))]
fn encode_search_cursor(offset: i64) -> String {
    format!("{SEARCH_CURSOR_PREFIX}{offset}")
}

/// The exact length of `s` as a serde_json string body (without the quotes):
/// `"` and `\` and the five short-form controls take 2 bytes, every other
/// control character 6 (`\u00XX`), everything else its UTF-8 length.
#[cfg_attr(not(feature = "db"), allow(dead_code))]
fn json_escaped_len(s: &str) -> usize {
    s.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// An upper bound on the serialised size of one hit, neighbours included.
#[cfg_attr(not(feature = "db"), allow(dead_code))]
fn hit_cost(hit: &SemanticSearchResult) -> usize {
    let own = HIT_OVERHEAD_BYTES
        + json_escaped_len(&hit.statement)
        + hit.claim_type.as_deref().map_or(0, json_escaped_len);
    let neighbours: usize = hit.graph_neighbors.as_ref().map_or(0, |ns| {
        ns.iter()
            .map(|n| {
                NEIGHBOR_OVERHEAD_BYTES
                    + json_escaped_len(&n.statement)
                    + json_escaped_len(&n.edge_type)
                    + json_escaped_len(&n.direction)
            })
            .sum()
    });
    own + neighbours
}

/// Keep hits, in order, while their summed [`hit_cost`] fits the budget;
/// always keep the first. Returns the kept hits and whether any were dropped.
#[cfg_attr(not(feature = "db"), allow(dead_code))]
fn apply_byte_budget(results: Vec<SemanticSearchResult>) -> (Vec<SemanticSearchResult>, bool) {
    let budget = MAX_RESPONSE_BYTES - RESPONSE_ENVELOPE_BYTES;
    let total = results.len();
    let mut used = 0usize;
    let mut kept = Vec::with_capacity(total);
    for hit in results {
        let cost = hit_cost(&hit);
        if !kept.is_empty() && used + cost > budget {
            break;
        }
        used += cost;
        kept.push(hit);
    }
    let cut = kept.len() < total;
    (kept, cut)
}

// ============================================================================
// Embedding Generation
// ============================================================================

/// Generate a mock embedding vector for the given text at the requested dimension.
///
/// This creates a deterministic embedding based on the input text for testing
/// purposes. Used as a fallback when no embedding service is configured, or
/// when the configured service's dimension doesn't match the centroid dim
/// the caller is querying against (e.g. diverse-mode 3072d path).
///
/// # Arguments
/// * `text` - The text to embed
/// * `dim` - Target embedding dimension (e.g. 1536 or 3072)
///
/// # Returns
/// A normalized `dim`-dimensional vector
#[cfg(feature = "db")]
fn generate_mock_embedding_with_dim(text: &str, dim: usize) -> Vec<f32> {
    let mut embedding = vec![0.0f32; dim];

    // Create a deterministic "embedding" based on text bytes
    // This is NOT a real embedding, just for testing similarity ranking
    let text_bytes = text.as_bytes();
    for (i, byte) in text_bytes.iter().enumerate() {
        let idx = i % dim;
        embedding[idx] += (*byte as f32) / 255.0;
    }

    // Normalize to unit vector (required for cosine similarity)
    let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for val in embedding.iter_mut() {
            *val /= magnitude;
        }
    }

    embedding
}

/// Generate embedding for query text using the embedding service if available,
/// falling back to mock embedding generation if the service is unavailable or fails.
///
/// # Arguments
/// * `state` - Application state containing the optional embedding service
/// * `text` - The text to embed
///
/// # Returns
/// A vector of floats representing the text embedding (1536d, legacy default).
///
/// # Behavior
/// - If embedding service is configured and succeeds: returns real embedding
/// - If embedding service fails: logs warning and falls back to mock
/// - If no embedding service configured: uses mock embedding
#[cfg(feature = "db")]
async fn generate_query_embedding(state: &AppState, text: &str) -> Vec<f32> {
    generate_query_embedding_with_dim(state, text, EMBEDDING_DIM).await
}

/// Generate query embedding at a target dimension.
///
/// Used by the diverse-search 3072d path: when the caller asks for
/// `centroid_dim=3072` the centroid lookup runs against `claim_themes.centroid_3072`,
/// so the query vector must also be 3072-dimensional. If the configured embedding
/// service produces a different dimension (e.g. it's pinned to
/// `text-embedding-3-small`/1536d while we need 3072d), we fall back to a
/// deterministic mock at the target dim — the caller will get degraded
/// similarity quality but the query won't fail. Operators running the 3072d
/// path in production are expected to configure a service whose
/// `dimension()` matches.
#[cfg(feature = "db")]
async fn generate_query_embedding_with_dim(
    state: &AppState,
    text: &str,
    target_dim: usize,
) -> Vec<f32> {
    // Try to use the real embedding service if available AND its dimension matches.
    if let Some(ref embedding_service) = state.embedding_service {
        if embedding_service.dimension() == target_dim {
            match embedding_service.generate_query(text).await {
                Ok(embedding) => {
                    tracing::debug!(
                        text_len = text.len(),
                        embedding_dim = embedding.len(),
                        "Generated real embedding for search query"
                    );
                    return embedding;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Embedding service failed, falling back to mock embedding"
                    );
                    // Fall through to mock embedding
                }
            }
        } else {
            tracing::warn!(
                service_dim = embedding_service.dimension(),
                target_dim = target_dim,
                "Configured embedding service dimension differs from requested centroid_dim; using mock at target dim"
            );
        }
    }

    // Fallback to mock embedding at the target dim.
    tracing::debug!(
        text_len = text.len(),
        target_dim = target_dim,
        "Using mock embedding for search query (no service configured, dim mismatch, or service failed)"
    );
    generate_mock_embedding_with_dim(text, target_dim)
}

/// The 1536-d query embedding for a flat request that can carry a cursor.
///
/// Same as [`generate_query_embedding`] except in one case: a configured
/// service whose dimension matches and whose call FAILS is a 503, not the mock
/// fallback. A cursor is an offset into the real ranking; serving one page of
/// a walk from the mock vector would rank that page by an unrelated order
/// while its `next_cursor` continued the real one, so the walk would skip and
/// repeat rows with nothing in the response to say so. The other mock cases
/// (no service configured, or a service at another dimension) are the same on
/// every page, so a walk over them stays consistent and they are unchanged.
#[cfg(feature = "db")]
async fn generate_walk_query_embedding(state: &AppState, text: &str) -> Result<Vec<f32>, ApiError> {
    if let Some(ref embedding_service) = state.embedding_service {
        if embedding_service.dimension() == EMBEDDING_DIM {
            return embedding_service.generate_query(text).await.map_err(|e| {
                tracing::warn!(
                    error = %e,
                    "Embedding service failed on a pageable search; refusing the mock fallback"
                );
                ApiError::ServiceUnavailable {
                    service: "embedding".to_string(),
                }
            });
        }
    }
    Ok(generate_query_embedding(state, text).await)
}

/// Format embedding vector as pgvector string literal
///
/// Converts a Vec<f32> to the format "[0.1,0.2,0.3,...]" expected by pgvector.
/// Run the diverse-mode theme-coverage probe on the request's viewer-stamped
/// `read` WITHOUT letting a probe failure poison it.
///
/// The guard fails open (see
/// `epigraph_engine::diverse_retrieval::theme_coverage_allows_diverse`): a
/// failed probe sends the request to the flat tail, which runs on this same
/// `read`. Under `SessionGucMode::Transaction` the read is ONE transaction, so
/// a failing statement (an error, or `statement_timeout`) would abort it and
/// the flat search after it would then fail with "current transaction is
/// aborted". The probe therefore runs inside a savepoint, rolled back to on
/// failure — which restores the transaction to its state before the probe,
/// including the transaction-local tenancy stamp. Under
/// `SessionGucMode::Session` each statement is its own implicit transaction,
/// so a failed probe poisons nothing and no bracket is needed.
///
/// No `statement_timeout` is set here: `SET LOCAL` would outlive the probe and
/// cap the flat search too. The probe is kept cheap instead, by always ordering
/// the neighbourhood by the ANN-indexed 1536-d column.
///
/// Outer `Err`: the savepoint bracket itself failed, so the transaction can no
/// longer be trusted — the caller propagates it. Inner `Err`: the probe
/// failed and the transaction is intact — the caller falls back to flat.
#[cfg(feature = "db")]
async fn probe_theme_coverage_isolated(
    read: &mut epigraph_db::ScopedRead<'_>,
    viewer: &epigraph_db::Viewer,
    query_vec_1536: &str,
    shortlist: &[Uuid],
    reachable_dim: u32,
) -> Result<Result<epigraph_db::NeighbourhoodThemeCoverage, epigraph_db::DbError>, ApiError> {
    use epigraph_engine::diverse_retrieval::THEME_COVERAGE_PROBE_K;

    let bracket_failed = |e: sqlx::Error| {
        tracing::error!(
            target: "diverse_retrieval.coverage_guard",
            error = %e,
            handler = "semantic_search",
            "theme-coverage probe savepoint bracket failed"
        );
        ApiError::InternalError {
            message: "Theme coverage probe could not be isolated".to_string(),
        }
    };

    let in_tx = read.mode() == epigraph_db::SessionGucMode::Transaction;
    if in_tx {
        sqlx::query("SAVEPOINT theme_coverage_probe")
            .execute(&mut **read)
            .await
            .map_err(bracket_failed)?;
    }
    let probe = epigraph_db::ClaimThemeRepository::nearest_theme_coverage_since(
        read,
        viewer,
        query_vec_1536,
        /*neighbourhood_dim=*/ 1536,
        shortlist,
        reachable_dim,
        THEME_COVERAGE_PROBE_K,
        /*paragraph_only=*/ false,
        /*since=*/ None,
    )
    .await;
    if in_tx {
        let end = if probe.is_ok() {
            "RELEASE SAVEPOINT theme_coverage_probe"
        } else {
            "ROLLBACK TO SAVEPOINT theme_coverage_probe"
        };
        sqlx::query(end)
            .execute(&mut **read)
            .await
            .map_err(bracket_failed)?;
    }
    Ok(probe)
}

#[cfg(feature = "db")]
fn format_embedding_for_pgvector(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

// `build_similarity_neighbors` and the diverse-pipeline helpers live in
// `epigraph_engine::diverse_retrieval` so the MCP `recall_with_context`
// tool can share the same retrieval logic. See the module docs for the
// pipeline shape.

// ============================================================================
// Handler
// ============================================================================

/// Semantic search handler
///
/// POST /api/v1/search/semantic
///
/// Searches for claims semantically similar to the query using pgvector.
/// Results are ranked by cosine similarity and filtered according to
/// the provided criteria.
///
/// # Validation
///
/// - Query cannot be empty or whitespace-only (with `rank_by=query`), and
///   must be absent or blank with `rank_by=theme_core`
/// - Limit must be > 0 (capped at 100, and at the 1,000-row window)
/// - min_similarity must be in [0.0, 1.0]
/// - claim_type must be one of: factual, hypothesis, opinion
/// - created_after must be <= created_before if both provided
/// - theme_id must be a UUID; rank_by must be `query` or `theme_core`;
///   `theme_core` needs theme_id and excludes diverse
/// - cursor must be `o:<n>` with `n < 1000`, and excludes diverse
/// - with theme_id and diverse, created_before / claim_type / agent_id are
///   refused (the diverse path does not apply them)
///
/// # Theme pin
///
/// Resolved on the viewer-stamped connection before any embedding call: an
/// unknown theme and one with no member the viewer can read are one 404. See
/// the module docs for the theme core, the cursor, the byte budget and the
/// caching contract.
///
/// # Security
///
/// - Query is parameterized to prevent SQL injection
/// - Special characters are safely handled by sqlx
pub async fn semantic_search(
    ViewerExtractor(viewer): crate::middleware::bearer::ViewerExtractor,
    #[allow(unused_variables)] State(state): State<AppState>,
    Json(request): Json<SemanticSearchRequest>,
) -> Result<Json<SemanticSearchResponse>, ApiError> {
    let start_time = std::time::Instant::now();

    // The theme pin, the ranking and the cursor are parsed before anything
    // else, and none of it touches the database: a 400 holds no connection.
    #[allow(unused_variables)]
    let theme_filter = parse_theme_filter(request.theme_id.as_deref())?;
    let rank_by = parse_rank_by(request.rank_by.as_deref())?;
    let cursor = parse_search_cursor(request.cursor.as_deref())?;
    let offset = cursor.unwrap_or(0);
    // `next_cursor` is emitted only to a caller that pinned a theme or sent a
    // cursor, so an unpinned, unpaged response keeps its old shape.
    #[allow(unused_variables)]
    let paged = theme_filter.is_some() || cursor.is_some();
    let diverse = request.diverse.unwrap_or(false);

    // Validate the query against the ranking: required for `query`, refused
    // for `theme_core` (which ranks a theme's members, not a query's
    // neighbours, and makes no embedding call).
    let query = request.query.trim();
    match rank_by {
        RankBy::ThemeCore => {
            if theme_filter.is_none() {
                return Err(ApiError::ValidationError {
                    field: "rank_by".to_string(),
                    reason: "theme_core ranks a theme's members; supply theme_id".to_string(),
                });
            }
            if diverse {
                return Err(ApiError::ValidationError {
                    field: "rank_by".to_string(),
                    reason: "theme_core is not available with diverse=true".to_string(),
                });
            }
            if !query.is_empty() {
                return Err(ApiError::ValidationError {
                    field: "query".to_string(),
                    reason: "query is not used with rank_by=theme_core; omit it".to_string(),
                });
            }
        }
        RankBy::Query => {
            if query.is_empty() {
                return Err(ApiError::ValidationError {
                    field: "query".to_string(),
                    reason: "Query cannot be empty".to_string(),
                });
            }
        }
    }

    // Diverse mode selects a set, not a ranking, so it has no pages.
    if diverse && cursor.is_some() {
        return Err(ApiError::ValidationError {
            field: "cursor".to_string(),
            reason: "cursor is not available with diverse=true".to_string(),
        });
    }

    // A pinned diverse request applies `created_after` and `min_similarity`
    // in SQL. The other three filters the diverse path has never applied are
    // refused rather than silently ignored under a pin.
    if diverse && theme_filter.is_some() {
        let unsupported = [
            ("created_before", request.created_before.is_some()),
            ("claim_type", request.claim_type.is_some()),
            ("agent_id", request.agent_id.is_some()),
        ];
        if let Some((field, _)) = unsupported.iter().find(|(_, set)| *set) {
            return Err(ApiError::ValidationError {
                field: (*field).to_string(),
                reason: format!("{field} is not applied by diverse=true with theme_id; omit it"),
            });
        }
    }

    // Validate query length (DoS prevention)
    if request.query.len() > MAX_QUERY_LENGTH {
        return Err(ApiError::ValidationError {
            field: "query".to_string(),
            reason: format!(
                "Query too long: {} bytes, maximum is {} bytes",
                request.query.len(),
                MAX_QUERY_LENGTH
            ),
        });
    }

    // Validate and apply limit
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 {
        return Err(ApiError::ValidationError {
            field: "limit".to_string(),
            reason: "Limit must be greater than 0".to_string(),
        });
    }
    // Capped at MAX_LIMIT, and cut so a page never passes the search window
    // (`offset < MAX_SEARCH_WINDOW`, so this is at least 1). `page_limit` is
    // the size before the window cut: the flat read asks SQL for that many
    // rows and drops the ones past the window in Rust, so the HNSW scan's
    // `ef_search` (derived from the SQL limit) stays the same on the last
    // page of a walk as on every page before it.
    #[allow(unused_variables)]
    let page_limit = limit.min(MAX_LIMIT) as usize;
    #[allow(unused_variables)]
    let limit = page_limit.min((MAX_SEARCH_WINDOW - offset) as usize);

    // Validate min_similarity. An explicit value must lie in [0, 1]. Absent,
    // it is 0.0, except under `theme_core`, where it is -1.0 (cosine's lower
    // bound, the floor `voids.rs` passes) so a full walk enumerates every
    // embedded member the viewer can read.
    if let Some(m) = request.min_similarity {
        if !(0.0..=1.0).contains(&m) {
            return Err(ApiError::ValidationError {
                field: "min_similarity".to_string(),
                reason: "min_similarity must be between 0.0 and 1.0".to_string(),
            });
        }
    }
    #[allow(unused_variables)]
    let min_similarity = match (rank_by, request.min_similarity) {
        (RankBy::ThemeCore, None) => -1.0,
        (_, v) => v.unwrap_or(0.0),
    };

    // Validate claim_type if provided
    if let Some(ref claim_type) = request.claim_type {
        // Validate claim_type length (DoS prevention)
        if claim_type.len() > MAX_CLAIM_TYPE_LENGTH {
            return Err(ApiError::ValidationError {
                field: "claim_type".to_string(),
                reason: format!(
                    "claim_type too long: {} bytes, maximum is {} bytes",
                    claim_type.len(),
                    MAX_CLAIM_TYPE_LENGTH
                ),
            });
        }
        if !VALID_CLAIM_TYPES.contains(&claim_type.as_str()) {
            return Err(ApiError::ValidationError {
                field: "claim_type".to_string(),
                reason: format!(
                    "Invalid claim_type '{}'. Must be one of: factual, hypothesis, opinion",
                    claim_type
                ),
            });
        }
    }

    // Validate date range
    if let (Some(after), Some(before)) = (request.created_after, request.created_before) {
        if after > before {
            return Err(ApiError::ValidationError {
                field: "created_after".to_string(),
                reason: "created_after cannot be after created_before".to_string(),
            });
        }
    }

    // Execute semantic search with pgvector
    #[cfg(feature = "db")]
    {
        // Validate centroid_dim hint up front (only meaningful when diverse=true,
        // but reject obvious garbage values regardless so callers get a clear error).
        //
        // This gate is also what makes the direct `ClaimThemeRepository` calls
        // below unable to surface `DbError::InvalidData` — see the import note
        // at the top of this file.
        if let Some(dim) = request.centroid_dim {
            if dim != 1536 && dim != 3072 {
                return Err(ApiError::ValidationError {
                    field: "centroid_dim".to_string(),
                    reason: format!("centroid_dim must be 1536 or 3072 (got {dim})"),
                });
            }
        }

        // ---- The one viewer-stamped connection every read below runs on ----
        //
        // PR-29, conversion shard 3 against
        // `D-PR17-request-path-never-stamps-session-gucs`. All seven of this
        // handler's reads run on this handle: the `frac_3072` auto-detect, the
        // theme lookup, the theme-coverage probe, the candidate pull, the
        // full-row fetch, the graph neighbours, and the flat search. (The
        // coverage probe was added after PR-29 and follows the same rule.)
        // `read_as` and not `acquire_as`: the
        // latter hard-refuses `EPIGRAPH_SESSION_GUC_MODE=transaction`, the
        // pooler fallback `bin/server.rs` advertises to operators.
        //
        // ACQUIRED HERE, AND THE PLACEMENT IS FORCED rather than chosen. This
        // handler has two success paths — the diverse `return Ok(...)` and the
        // flat tail — and the diverse path FALLS THROUGH to the flat one when
        // the corpus has no themes or the themes do not cover the query.
        // Acquiring separately per path would put the
        // fall-through shape on two connections and two transactions, which is
        // precisely the property the conversion exists to establish. One acquire
        // above the branch is the only shape that holds for all three request
        // shapes.
        //
        // THE COST, STATED, AND IT DIFFERS BY REQUEST SHAPE — the earlier
        // wording said `frac_3072` runs before the embedding call full stop,
        // which is true only of `diverse=true`:
        //
        // - `diverse=true`: the `frac_3072` auto-detect runs on this handle
        //   BEFORE the outbound embedding round trip and the remaining reads
        //   after it, so the hoist costs nothing that path would not pay anyway.
        // - `diverse=false`, THE DEFAULT AND MORE COMMON SHAPE: no statement at
        //   all runs before `generate_query_embedding` in the flat tail, so the
        //   handle is held idle across that network call. That is an
        //   unconditional cost accepted for the fall-through property above, not
        //   one forced by this path; `voids.rs::embedding_density` shows the
        //   acquire-after-embed alternative, which is not available here without
        //   splitting the acquire the fall-through requires be single.
        //
        // The pool it is held against is the API request pool, whose size is
        // `epigraph_db::ScopedPoolOptions::default()` — cited rather than
        // transcribed so a sizing change invalidates the citation instead of
        // silently invalidating this comment. (An earlier revision wrote "8",
        // which was the background JOB pool; since operator decision D9 that
        // pool lives in `bin/drain_jobs.rs`, not in this process.) Bounded regardless: at most seven reads on one handle (plus, under
        // `SessionGucMode::Transaction`, the two-statement savepoint bracket
        // around the coverage probe), no
        // per-node loop, no unbounded N. `detect_voids` in `routes/voids.rs` is
        // the shape in this shard that is NOT bounded; its own doc says so.
        // This shard does NOT discharge
        // `F-PR26-lineage-holds-one-connection-for-n-round-trips`.
        //
        // The validation returns above are deliberately NOT covered: they answer
        // without touching the database, and hoisting the acquire over them
        // would hold a pooled connection across every 400. Nothing in the gate
        // enforces that ordering — read it as an observation, not an invariant.
        //
        // THE ERROR SHAPE IS PART OF THE TEMPLATE (see `routes/claims_query.rs`).
        // `read_as`'s refusal reason is a paragraph of internal design prose
        // aimed at whoever mis-built the `AppState`; `errors.rs` serialises
        // `ApiError::InternalError { message }` verbatim into the response body,
        // so it is logged in full and answered with an opaque message.
        let mut read = state.read_as(&viewer).await.map_err(|e| {
            tracing::error!(
                target: "tenancy.scoped_read",
                error = %e,
                handler = "semantic_search",
                "could not acquire a viewer-stamped connection"
            );
            ApiError::InternalError {
                message: "Failed to acquire a scoped connection".to_string(),
            }
        })?;

        // ---- Theme pin: resolved first, before any embedding call ----
        //
        // `get_summary` counts only the members this viewer can read. An
        // unknown theme and a theme with no member the viewer can read get the
        // same 404, so "gone" and "not yours" look alike from this route.
        // `s.label` is never read: it is generated from member content with no
        // visibility filter. Returning drops `read`, which rolls back.
        let theme_scope: Option<SearchThemeScope> = match theme_filter {
            None => None,
            Some(id) => {
                let summary =
                    epigraph_db::ClaimThemeRepository::get_summary(&mut *read, &viewer, id)
                        .await
                        .map_err(|e| ApiError::InternalError {
                            message: format!("Theme lookup failed: {e}"),
                        })?;
                match summary {
                    Some(s) if s.member_count > 0 => Some(SearchThemeScope {
                        theme_id: s.id,
                        member_count: s.member_count,
                        rank_by: rank_by.as_str(),
                    }),
                    _ => {
                        return Err(ApiError::NotFound {
                            entity: "Theme".to_string(),
                            id: id.to_string(),
                        })
                    }
                }
            }
        };

        // Step 2a: Diverse hierarchical retrieval path (theme-based + coverage selection)
        // When `diverse=true`, navigate themes first, then apply submodular selection.
        // Falls through to flat search if no themes exist yet (clustering hasn't run)
        // or if the themes do not cover the query's nearest neighbourhood.
        // The 1536-d query vector the flat tail searches with, once some step
        // of the diverse branch has had to compute it (at 1536 the diverse
        // embedding IS this vector; at 3072 the coverage probe needs it).
        // Reused by the flat tail so a diverse request that falls back does
        // not embed the same text twice.
        let mut flat_query_vec: Option<String> = None;

        // `rank_by=theme_core` with `diverse=true` was refused above, so this
        // branch always ranks by the query.
        if diverse {
            let max_themes = request.max_themes.unwrap_or(5) as i32;
            let alpha = request.diversity_weight.unwrap_or(0.5);

            // Clamp the candidate-pool top-K at the request boundary so the
            // caller sees the value they will actually get (vs. silently
            // capping deep in `build_similarity_neighbors`). Default to the
            // pre-refactor `DEFAULT_CANDIDATE_POOL` (100) when unset.
            let candidate_pool = request
                .candidate_pool
                .map(|n| n.min(MAX_CANDIDATE_POOL))
                .map(|n| n as i32)
                .unwrap_or(DEFAULT_CANDIDATE_POOL);

            // Resolve which centroid dimension to query against. Explicit hint
            // wins; otherwise auto-detect via the population fraction of
            // `claim_themes.centroid_3072` (≥50% → 3072, else 1536). This lets
            // operators flip the corpus to 3072d theme-by-theme and have the
            // search path follow automatically once the majority is migrated.
            let frac_3072 = sqlx::query_scalar::<_, Option<f64>>(
                "SELECT \
                    COUNT(*) FILTER (WHERE centroid_3072 IS NOT NULL)::float8 \
                      / NULLIF(COUNT(*), 0)::float8 \
                  FROM claim_themes",
            )
            .fetch_one(&mut *read)
            .await
            .map_err(|e| ApiError::InternalError {
                message: format!("centroid_dim auto-detect failed: {e}"),
            })?
            .unwrap_or(0.0);

            let centroid_dim_used: u32 = match request.centroid_dim {
                Some(d) => d,
                None => {
                    if frac_3072 >= 0.5 {
                        3072
                    } else {
                        1536
                    }
                }
            };

            // Operator-misordering guard: caller asked for 3072d but no
            // themes have a centroid_3072 populated. Match PR #84's pattern
            // (BadRequest body) using ValidationError for the clearer
            // `field` surface — spec calls for 412 Precondition Failed but
            // ApiError has no PreconditionFailed variant yet.
            if centroid_dim_used == 3072 && frac_3072 == 0.0 {
                return Err(ApiError::ValidationError {
                    field: "centroid_dim".to_string(),
                    reason: "no 3072d centroids populated; run \
                             `epigraph-cli reembed --target claims` and rebuild \
                             themes with centroid_dim=3072 first"
                        .to_string(),
                });
            }

            // Step 1: generate the query embedding at the centroid's
            // dimension so the pgvector `<=>` operator can compare them.
            let target_dim = if centroid_dim_used == 3072 {
                EMBEDDING_DIM_LARGE
            } else {
                EMBEDDING_DIM
            };
            let query_embedding =
                generate_query_embedding_with_dim(&state, query, target_dim).await;
            let embedding_str = format_embedding_for_pgvector(&query_embedding);
            if target_dim == EMBEDDING_DIM {
                // `generate_query_embedding` is exactly this call at
                // `EMBEDDING_DIM`, so the flat tail can reuse the vector.
                flat_query_vec = Some(embedding_str.clone());
            }

            // The claim-embedding column name (still used by the post-
            // selection full-row + graph-neighbor queries below). Column
            // names are not user input (only `1536` or `3072` reach this
            // point), so `format!`-interpolating them is injection-safe.
            let claim_embedding_col = if centroid_dim_used == 3072 {
                "embedding_3072"
            } else {
                "embedding"
            };

            // A PINNED request skips the shortlist and the coverage guard: the
            // caller named the one theme to draw from, so there is no
            // shortlist that could be stale and nothing to cover.
            let (theme_ids, covered): (Vec<Uuid>, bool) = if let Some(pin) = theme_filter {
                (vec![pin], true)
            } else {
                // Pre-flight: cheap theme lookup ONLY to determine whether
                // the corpus has themes at all. If empty, fall through to
                // flat ANN (matching pre-helper behaviour); otherwise run
                // the shared pipeline.
                let themes = epigraph_db::ClaimThemeRepository::find_similar_themes_at_dim(
                    &mut *read,
                    &embedding_str,
                    max_themes,
                    centroid_dim_used,
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Theme search failed: {e}"),
                })?;

                // Theme-coverage guard (same rule and verdict function as
                // `epigraph_engine::diverse_retrieval::run_diverse_pipeline`, which
                // this route does not call — see the import note at the top of
                // this file). The theme lookup above is nearest-first with no
                // relevance floor, so any non-empty theme set wins the shortlist;
                // a small stale one would answer every query from its few members.
                // Enter diverse mode only when most of the query's own nearest
                // neighbourhood — REST's candidate space: all levels, no window —
                // is reachable through the shortlist.
                //
                // The neighbourhood is ordered by the 1536-d column at EVERY
                // `centroid_dim`: that column carries the ANN index (the 3072-d one
                // has none, so ordering by it would scan every row that has one),
                // and it is also what the flat tail this guard falls back to
                // searches. Reachability is still checked at `centroid_dim_used`.
                // A probe failure falls back to flat rather than failing the
                // request; see `probe_theme_coverage_isolated`.
                let theme_ids: Vec<Uuid> = themes.iter().map(|(id, _, _)| *id).collect();
                let covered = if themes.is_empty() {
                    false
                } else {
                    let probe_vec = match &flat_query_vec {
                        Some(v) => v.clone(),
                        None => {
                            let v = format_embedding_for_pgvector(
                                &generate_query_embedding(&state, query).await,
                            );
                            flat_query_vec = Some(v.clone());
                            v
                        }
                    };
                    let probe = probe_theme_coverage_isolated(
                        &mut read,
                        &viewer,
                        &probe_vec,
                        &theme_ids,
                        centroid_dim_used,
                    )
                    .await?;
                    epigraph_engine::diverse_retrieval::theme_coverage_allows_diverse(
                        probe,
                        "semantic_search",
                        centroid_dim_used,
                    )
                };
                (theme_ids, covered)
            };

            // Candidate claims, from one of two viewer-filtered sources.
            //
            // - PINNED: `claims_in_theme_exact_at_dim`, the theme's members
            //   ranked by exact distance (no HNSW under-fill for a large
            //   theme), with `created_after` and `min_similarity` applied in
            //   SQL above the pool cut.
            // - UNPINNED: `claims_in_themes_at_dim_since(.., since = None)`
            //   over the shortlist, unchanged. Same SQL shape as before, plus
            //   the level-filter knob for MCP; REST passes
            //   `paragraph_only=false` to preserve pre-helper behaviour. It is
            //   exactly what the `candidates_in_themes_at_dim` wrapper this file
            //   used to call delegates to.
            //
            // `None` when diverse mode does not apply: no themes, themes that
            // do not cover the query, or a pin with no candidate at this
            // dimension (for example 3072-d with no `embedding_3072` member).
            // The last falls through to the flat tail, which is pinned too, the
            // rule MCP recall applies to an empty pinned diverse pool.
            let candidates = if !covered {
                None
            } else if let Some(pin) = theme_filter {
                let pinned = epigraph_db::ClaimThemeRepository::claims_in_theme_exact_at_dim(
                    &mut *read,
                    &viewer,
                    pin,
                    &embedding_str,
                    candidate_pool,
                    centroid_dim_used,
                    request.created_after,
                    min_similarity,
                )
                .await
                .map_err(|e| ApiError::InternalError {
                    message: format!("Candidate retrieval failed: {e}"),
                })?;
                (!pinned.is_empty()).then_some(pinned)
            } else {
                Some(
                    epigraph_db::ClaimThemeRepository::claims_in_themes_at_dim_since(
                        &mut read,
                        &viewer,
                        &theme_ids,
                        &embedding_str,
                        candidate_pool,
                        centroid_dim_used,
                        /*paragraph_only=*/ false,
                        /*since=*/ None,
                    )
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("Candidate retrieval failed: {e}"),
                    })?,
                )
            };

            // Only enter diverse mode if themes exist AND cover this query
            // (or the request pinned a theme that has candidates).
            if let Some(candidates) = candidates {
                // Build proximity graph + run greedy submodular selection.
                // Helper centralises this (k=5, alpha=user-supplied) so MCP
                // and REST agree.
                let selected_rows = {
                    use epigraph_engine::diverse_retrieval::{
                        build_similarity_neighbors, DEFAULT_SIMILARITY_K,
                    };
                    use epigraph_engine::diverse_select::diverse_select;
                    let neighbors = build_similarity_neighbors(&candidates, DEFAULT_SIMILARITY_K);
                    let similarities: Vec<f32> =
                        candidates.iter().map(|(_, _, s)| *s as f32).collect();
                    let selected = diverse_select(&neighbors, &similarities, limit, alpha);
                    selected
                        .into_iter()
                        .map(|idx| candidates[idx].clone())
                        .collect::<Vec<_>>()
                };

                // Collect the selected claim IDs for enrichment queries
                let selected_claim_ids: Vec<Uuid> =
                    selected_rows.iter().map(|(id, _, _)| *id).collect();

                // NOTE (PR-07): this statement is deliberately NOT viewer-
                // spliced, and that is safe by derivation rather than by
                // oversight. It is bounded by `WHERE c.id = ANY($2)` over
                // `selected_claim_ids`, every element of which came out of ONE
                // of exactly two viewer-filtered sources:
                //
                // - `ClaimThemeRepository::claims_in_themes_at_dim_since`
                //   (unpinned), and
                // - `ClaimThemeRepository::claims_in_theme_exact_at_dim`
                //   (pinned, `theme_id`).
                //
                // Both splice `{VISIBILITY:c}` onto every `claims` alias they
                // read. (PR-29 re-pointed the first off the
                // `epigraph_engine::diverse_retrieval::candidates_in_themes_at_dim`
                // wrapper; the wrapper's whole body was that same call with
                // `since = None`.) A second predicate here would be redundant.
                // Do not "harden" it by adding a marker without also
                // re-checking that derivation: if a THIRD source of
                // `selected_claim_ids` is ever added, or either of these stops
                // filtering, this needs a real predicate, not a marker.
                //
                // Fetch full claim data for the selected IDs (including CDST
                // columns + theme_id and the latest cluster_id from
                // claim_cluster_membership). #49: surface the partition
                // labels so callers can render or filter by them.
                let full_sql = format!(
                    r#"
                    SELECT c.id, c.content, c.truth_value, c.belief, c.plausibility,
                           c.agent_id, c.trace_id,
                           c.labels[1] as claim_type, c.created_at,
                           c.theme_id,
                           (
                               SELECT m.cluster_id
                               FROM claim_cluster_membership m
                               JOIN graph_cluster_runs r ON r.run_id = m.run_id
                               WHERE m.claim_id = c.id
                               ORDER BY r.completed_at DESC
                               LIMIT 1
                           ) AS cluster_id,
                           1 - (c.{claim_embedding_col} <=> $1::vector) as similarity
                    FROM claims c
                    WHERE c.id = ANY($2)
                    ORDER BY c.{claim_embedding_col} <=> $1::vector
                    "#
                );
                let full_rows = sqlx::query(&full_sql)
                    .bind(&embedding_str)
                    .bind(&selected_claim_ids)
                    .fetch_all(&mut *read)
                    .await
                    .map_err(|e| ApiError::InternalError {
                        message: format!("Claim fetch failed: {e}"),
                    })?;

                // Fetch graph neighbors for all selected claims.
                //
                // PR-07: this ran unfiltered inline. The neighbour ids are the
                // FAR side of each edge — they are not in `selected_claim_ids`
                // and were never viewer-checked — so 200 characters of
                // arbitrary out-of-tenant claim content rode out attached to
                // every result. The repo now splices the predicate onto the
                // joined `claims`, dropping invisible neighbours entirely.
                let neighbor_rows = epigraph_db::ClaimRepository::semantic_graph_neighbors(
                    &mut *read,
                    &viewer,
                    claim_embedding_col,
                    &embedding_str,
                    &selected_claim_ids,
                )
                .await
                .unwrap_or_default();

                // Group neighbors by the selected claim they connect to
                let mut neighbor_map: HashMap<Uuid, Vec<GraphNeighbor>> = HashMap::new();
                for row in neighbor_rows {
                    // Determine which selected claim this neighbor connects to
                    let parent_id = if selected_claim_ids.contains(&row.source_id) {
                        row.source_id
                    } else {
                        row.target_id
                    };

                    let neighbor = GraphNeighbor {
                        claim_id: row.neighbor_id,
                        statement: row.content,
                        similarity: row.similarity,
                        epistemic: EpistemicState::from_row(
                            row.truth_value,
                            row.nb_belief,
                            row.nb_plausibility,
                        ),
                        edge_type: row.relationship,
                        direction: row.direction,
                    };

                    neighbor_map.entry(parent_id).or_default().push(neighbor);
                }

                // Build response DTOs with full claim data and neighbors
                let mut results: Vec<SemanticSearchResult> = full_rows
                    .iter()
                    .map(|row| {
                        let claim_id: Uuid = row.get("id");
                        let neighbors = neighbor_map.remove(&claim_id).filter(|n| !n.is_empty());
                        SemanticSearchResult {
                            claim_id,
                            statement: row.get("content"),
                            similarity: row.get("similarity"),
                            epistemic: EpistemicState::from_row(
                                row.get("truth_value"),
                                row.get("belief"),
                                row.get("plausibility"),
                            ),
                            agent_id: row.get("agent_id"),
                            trace_id: row.get("trace_id"),
                            claim_type: row.get("claim_type"),
                            created_at: row.get("created_at"),
                            graph_neighbors: neighbors,
                            theme_id: row.try_get::<Option<Uuid>, _>("theme_id").ok().flatten(),
                            cluster_id: row.try_get::<Option<Uuid>, _>("cluster_id").ok().flatten(),
                        }
                    })
                    .collect();

                // Restore original diverse_select ordering (full_rows is ordered by DB)
                // Re-sort to match selected order for deterministic output
                let id_order: HashMap<Uuid, usize> = selected_claim_ids
                    .iter()
                    .enumerate()
                    .map(|(i, &id)| (id, i))
                    .collect();
                results.sort_by_key(|r| id_order.get(&r.claim_id).copied().unwrap_or(usize::MAX));

                // Diverse mode has no pages, so anything the byte budget drops
                // is reported as `truncated` rather than carried by a cursor.
                let (results, truncated) = apply_byte_budget(results);

                let total = results.len() as u64;
                let query_time_ms = start_time.elapsed().as_millis() as u64;

                crate::routes::finish_scoped_read(read, "semantic_search").await?;

                return Ok(Json(SemanticSearchResponse {
                    results,
                    total,
                    query_time_ms,
                    centroid_dim_used: Some(centroid_dim_used),
                    theme_scope,
                    next_cursor: None,
                    truncated,
                }));
            }
            // No themes yet, or themes that do not cover this query — fall
            // through to flat search below, ON THE SAME `read`. This fall-through is why the acquire is above the branch:
            // the flat search this shape reaches must be the same stamped
            // session the theme lookup ran on.
        }

        // Flat-path uses the legacy 1536d `claims.embedding` column directly,
        // so it needs the query embedding at that dim. A diverse request that
        // fell through may already have computed it (see `flat_query_vec`);
        // otherwise generate it here.
        //
        // `rank_by=theme_core` embeds nothing: it ranks by the theme core,
        // which the repo computes in SQL, so no embedding call is made.
        //
        // A request that can carry a cursor (`paged && !diverse`) must not be
        // ranked by the mock when a configured service fails: its offset
        // belongs to the real ranking, so a mock-ranked page would silently
        // skip and repeat rows of the walk. It gets 503 instead (see
        // `generate_walk_query_embedding`).
        let embedding_str: Option<String> = match rank_by {
            RankBy::ThemeCore => None,
            RankBy::Query => Some(match flat_query_vec {
                Some(v) => v,
                None if paged && !diverse => format_embedding_for_pgvector(
                    &generate_walk_query_embedding(&state, query).await?,
                ),
                None => {
                    format_embedding_for_pgvector(&generate_query_embedding(&state, query).await)
                }
            }),
        };
        let ranking = match embedding_str.as_deref() {
            Some(v) => epigraph_db::FlatRanking::Query(v),
            // Validation guarantees a theme pin here.
            None => epigraph_db::FlatRanking::ThemeCore,
        };

        // Step 2b: Flat pgvector similarity search (DEFAULT path)
        //
        // PR-07: this is reached whenever `diverse` is absent — i.e. the
        // default request shape — and whenever `diverse=true` but the corpus
        // has no themes (or, since the theme-coverage guard, themes that do not
        // cover the query). It ran unfiltered and returned `claims.content`, with
        // no `check_content_access` pass behind it: an authenticated principal
        // could submit an arbitrary probe vector and get other tenants' claim
        // text back, ranked by relevance. The statement now lives in
        // `ClaimRepository::semantic_search_flat` with the predicate spliced in.
        //
        // With a theme pin the statement is the exact pinned form (the theme
        // predicate above every cut). With no embedding service this is the
        // deterministic mock vector through the same pinned read, so the pin
        // holds even when the ranking is meaningless.
        //
        // SQL is asked for `page_limit` rows, not the window-cut `limit`, so
        // the last page of a walk runs the same HNSW scan as the pages before
        // it; the rows past the window are dropped here.
        let mut rows = epigraph_db::ClaimRepository::semantic_search_flat(
            &mut *read,
            &viewer,
            ranking,
            min_similarity,
            request.claim_type.as_deref(),
            request.created_after,
            request.created_before,
            request.agent_id,
            page_limit as i64,
            theme_filter,
            offset,
        )
        .await
        .map_err(|e| ApiError::InternalError {
            message: format!("Database query failed: {e}"),
        })?;
        let full_page = rows.len() == page_limit;
        rows.truncate(limit);

        // Step 3: Convert rows to response DTOs. Every pinned hit is in the
        // pinned theme by construction, so it says so.
        let results: Vec<SemanticSearchResult> = rows
            .into_iter()
            .map(|row| SemanticSearchResult {
                claim_id: row.claim_id,
                statement: row.statement,
                similarity: row.similarity,
                epistemic: EpistemicState::from_row(row.truth_value, row.belief, row.plausibility),
                agent_id: row.agent_id,
                trace_id: row.trace_id,
                claim_type: row.claim_type,
                created_at: row.created_at,
                graph_neighbors: None,
                theme_id: theme_filter,
                cluster_id: None,
            })
            .collect();

        // The byte budget, then the cursor. A page the budget cut resumes at
        // the first dropped hit; a full SQL page may have more behind it. The
        // cursor stops at the window, and only a paged request gets one.
        let (results, cut) = apply_byte_budget(results);
        let kept = results.len() as i64;
        let next_cursor =
            (paged && !diverse && (cut || full_page) && offset + kept < MAX_SEARCH_WINDOW)
                .then(|| encode_search_cursor(offset + kept));
        let truncated = cut && next_cursor.is_none();

        let total = results.len() as u64;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        crate::routes::finish_scoped_read(read, "semantic_search").await?;

        Ok(Json(SemanticSearchResponse {
            results,
            total,
            query_time_ms,
            centroid_dim_used: None,
            theme_scope,
            next_cursor,
            truncated,
        }))
    }

    // Fallback when db feature is disabled
    #[cfg(not(feature = "db"))]
    {
        let results: Vec<SemanticSearchResult> = Vec::new();
        let total = 0u64;
        let query_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(SemanticSearchResponse {
            results,
            total,
            query_time_ms,
            centroid_dim_used: None,
            theme_scope: None,
            next_cursor: None,
            truncated: false,
        }))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests for request/response serialization and constants.
    /// Handler tests that require database access are in tests/routes/semantic_search_tests.rs

    #[test]
    fn test_default_limit_constant() {
        assert_eq!(DEFAULT_LIMIT, 10);
    }

    #[test]
    fn test_max_limit_constant() {
        assert_eq!(MAX_LIMIT, 100);
    }

    #[test]
    fn test_valid_claim_types_constant() {
        assert!(VALID_CLAIM_TYPES.contains(&"factual"));
        assert!(VALID_CLAIM_TYPES.contains(&"hypothesis"));
        assert!(VALID_CLAIM_TYPES.contains(&"opinion"));
        assert!(!VALID_CLAIM_TYPES.contains(&"invalid"));
    }

    #[test]
    fn test_semantic_search_request_deserialize() {
        let json = r#"{
            "query": "test query",
            "limit": 20,
            "min_similarity": 0.7,
            "claim_type": "factual"
        }"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "test query");
        assert_eq!(request.limit, Some(20));
        assert_eq!(request.min_similarity, Some(0.7));
        assert_eq!(request.claim_type, Some("factual".to_string()));
        assert!(request.created_after.is_none());
        assert!(request.created_before.is_none());
        assert!(request.agent_id.is_none());
    }

    #[test]
    fn test_semantic_search_request_minimal() {
        let json = r#"{"query": "test"}"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "test");
        assert!(request.limit.is_none());
        assert!(request.min_similarity.is_none());
        assert!(request.claim_type.is_none());
    }

    #[test]
    fn test_semantic_search_response_serialize() {
        let response = SemanticSearchResponse {
            results: vec![SemanticSearchResult {
                claim_id: Uuid::nil(),
                statement: "Test claim".to_string(),
                similarity: 0.85,
                epistemic: EpistemicState::from_row(0.75, Some(0.3), Some(0.9)),
                agent_id: Uuid::nil(),
                trace_id: None,
                claim_type: Some("factual".to_string()),
                created_at: None,
                graph_neighbors: None,
                theme_id: None,
                cluster_id: None,
            }],
            total: 1,
            query_time_ms: 15,
            centroid_dim_used: None,
            theme_scope: None,
            next_cursor: None,
            truncated: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":1"));
        assert!(json.contains("\"query_time_ms\":15"));
        assert!(json.contains("\"similarity\":0.85"));
        assert!(json.contains("\"truth_value\":0.75"));
        assert!(json.contains("\"belief\":0.3"));
        assert!(json.contains("\"plausibility\":0.9"));
        assert!(json.contains("\"ignorance\":"));
    }

    #[test]
    fn test_semantic_search_result_optional_fields_skipped() {
        let result = SemanticSearchResult {
            claim_id: Uuid::nil(),
            statement: "Test".to_string(),
            similarity: 0.5,
            epistemic: EpistemicState::from_row(0.5, None, None),
            agent_id: Uuid::nil(),
            trace_id: None,
            claim_type: None,
            created_at: None,
            graph_neighbors: None,
            theme_id: None,
            cluster_id: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        // Optional None fields should be skipped
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("claim_type"));
        assert!(!json.contains("created_at"));
        assert!(!json.contains("graph_neighbors"));
        assert!(!json.contains("theme_id"));
        assert!(!json.contains("cluster_id"));
    }

    #[test]
    fn test_semantic_search_result_with_all_fields() {
        let now = Utc::now();
        let claim_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let trace_id = Uuid::new_v4();

        let theme_id = Uuid::new_v4();
        let cluster_id = Uuid::new_v4();
        let result = SemanticSearchResult {
            claim_id,
            statement: "Full claim".to_string(),
            similarity: 0.95,
            epistemic: EpistemicState::from_row(0.88, Some(0.7), Some(0.95)),
            agent_id,
            trace_id: Some(trace_id),
            claim_type: Some("hypothesis".to_string()),
            created_at: Some(now),
            graph_neighbors: None,
            theme_id: Some(theme_id),
            cluster_id: Some(cluster_id),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"trace_id\":"));
        assert!(json.contains("\"claim_type\":\"hypothesis\""));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains(&format!("\"theme_id\":\"{theme_id}\"")));
        assert!(json.contains(&format!("\"cluster_id\":\"{cluster_id}\"")));
    }

    #[test]
    fn test_semantic_search_request_with_date_range() {
        let json = r#"{
            "query": "test",
            "created_after": "2024-01-01T00:00:00Z",
            "created_before": "2024-12-31T23:59:59Z"
        }"#;

        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert!(request.created_after.is_some());
        assert!(request.created_before.is_some());
    }

    #[test]
    fn test_semantic_search_request_with_agent_id() {
        let agent_id = Uuid::new_v4();
        let json = format!(r#"{{"query": "test", "agent_id": "{}"}}"#, agent_id);

        let request: SemanticSearchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request.agent_id, Some(agent_id));
    }

    #[test]
    fn test_semantic_search_request_centroid_dim_field() {
        // 3072d hint deserializes into the new field.
        let json = r#"{"query": "test", "diverse": true, "centroid_dim": 3072}"#;
        let request: SemanticSearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.centroid_dim, Some(3072));

        // Absent field defaults to None (auto-detect).
        let json2 = r#"{"query": "test", "diverse": true}"#;
        let request2: SemanticSearchRequest = serde_json::from_str(json2).unwrap();
        assert!(request2.centroid_dim.is_none());
    }

    #[test]
    fn test_semantic_search_response_serializes_centroid_dim_used() {
        // Some(3072) → field is present in JSON.
        let resp_with = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: Some(3072),
            theme_scope: None,
            next_cursor: None,
            truncated: false,
        };
        let json = serde_json::to_string(&resp_with).unwrap();
        assert!(json.contains("\"centroid_dim_used\":3072"));

        // None → field is skipped (flat-search responses stay backwards-compat).
        let resp_without = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: None,
            theme_scope: None,
            next_cursor: None,
            truncated: false,
        };
        let json2 = serde_json::to_string(&resp_without).unwrap();
        assert!(!json2.contains("centroid_dim_used"));
    }

    // ---- theme_id / rank_by / cursor (request and response shape) ----

    fn field_of(e: ApiError) -> String {
        match e {
            ApiError::ValidationError { field, .. } => field,
            other => panic!("expected a ValidationError, got {other:?}"),
        }
    }

    #[test]
    fn request_deserializes_theme_id_rank_by_and_cursor() {
        let theme = Uuid::new_v4();
        let json = format!(
            r#"{{"query": "q", "theme_id": "{theme}", "rank_by": "theme_core", "cursor": "o:50"}}"#
        );
        let r: SemanticSearchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r.theme_id.as_deref(), Some(theme.to_string().as_str()));
        assert_eq!(r.rank_by.as_deref(), Some("theme_core"));
        assert_eq!(r.cursor.as_deref(), Some("o:50"));

        // A malformed theme id still deserializes, so the handler can answer a
        // 400 on the field instead of a JSON rejection.
        let r: SemanticSearchRequest =
            serde_json::from_str(r#"{"query": "q", "theme_id": "not-a-uuid"}"#).unwrap();
        assert_eq!(r.theme_id.as_deref(), Some("not-a-uuid"));
    }

    #[test]
    fn request_without_query_deserializes_to_blank() {
        let theme = Uuid::new_v4();
        let json = format!(r#"{{"theme_id": "{theme}", "rank_by": "theme_core"}}"#);
        let r: SemanticSearchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r.query, "");
        let r: SemanticSearchRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(r.query, "");
        assert!(r.theme_id.is_none() && r.rank_by.is_none() && r.cursor.is_none());
    }

    #[test]
    fn parse_search_cursor_absent_and_blank_are_none() {
        assert_eq!(parse_search_cursor(None).unwrap(), None);
        assert_eq!(parse_search_cursor(Some("")).unwrap(), None);
        assert_eq!(parse_search_cursor(Some("   ")).unwrap(), None);
    }

    #[test]
    fn parse_search_cursor_round_trips() {
        for n in [0_i64, 1, 50, 999] {
            assert_eq!(
                parse_search_cursor(Some(&encode_search_cursor(n))).unwrap(),
                Some(n)
            );
        }
        assert_eq!(encode_search_cursor(100), "o:100");
    }

    #[test]
    fn parse_search_cursor_rejects_negative_prefixless_and_garbage() {
        for bad in ["o:-1", "x:1", "1", "o:", "o:abc", "o:1.5", "o:+3", "O:1"] {
            assert_eq!(
                field_of(parse_search_cursor(Some(bad)).unwrap_err()),
                "cursor",
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_search_cursor_rejects_beyond_the_window() {
        for bad in ["o:1000", "o:5000", "o:99999999999999999999999"] {
            assert_eq!(
                field_of(parse_search_cursor(Some(bad)).unwrap_err()),
                "cursor",
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_theme_filter_treats_blank_as_absent_and_rejects_garbage() {
        assert_eq!(parse_theme_filter(None).unwrap(), None);
        assert_eq!(parse_theme_filter(Some("")).unwrap(), None);
        assert_eq!(parse_theme_filter(Some("  ")).unwrap(), None);
        let id = Uuid::new_v4();
        assert_eq!(
            parse_theme_filter(Some(&format!(" {id} "))).unwrap(),
            Some(id)
        );
        assert_eq!(
            field_of(parse_theme_filter(Some("not-a-uuid")).unwrap_err()),
            "theme_id"
        );
    }

    #[test]
    fn parse_rank_by_defaults_to_query_and_rejects_unknown() {
        assert_eq!(parse_rank_by(None).unwrap(), RankBy::Query);
        assert_eq!(parse_rank_by(Some("")).unwrap(), RankBy::Query);
        assert_eq!(parse_rank_by(Some("query")).unwrap(), RankBy::Query);
        assert_eq!(
            parse_rank_by(Some("theme_core")).unwrap(),
            RankBy::ThemeCore
        );
        assert_eq!(
            field_of(parse_rank_by(Some("centroid")).unwrap_err()),
            "rank_by"
        );
        assert_eq!(RankBy::Query.as_str(), "query");
        assert_eq!(RankBy::ThemeCore.as_str(), "theme_core");
    }

    #[test]
    fn response_skips_theme_scope_next_cursor_and_truncated_when_unset() {
        let resp = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: None,
            theme_scope: None,
            next_cursor: None,
            truncated: false,
        };
        let v = serde_json::to_value(&resp).unwrap();
        let obj = v.as_object().unwrap();
        for key in ["theme_scope", "next_cursor", "truncated"] {
            assert!(!obj.contains_key(key), "{key} must be omitted when unset");
        }

        let resp = SemanticSearchResponse {
            results: vec![],
            total: 0,
            query_time_ms: 1,
            centroid_dim_used: None,
            theme_scope: None,
            next_cursor: Some("o:10".to_string()),
            truncated: true,
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["next_cursor"], "o:10");
        assert_eq!(v["truncated"], true);
    }

    #[test]
    fn theme_scope_serialises_without_a_label() {
        let theme = Uuid::new_v4();
        let scope = SearchThemeScope {
            theme_id: theme,
            member_count: 412,
            rank_by: "theme_core",
        };
        let v = serde_json::to_value(&scope).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["member_count", "rank_by", "theme_id"]);
        assert_eq!(v["theme_id"], theme.to_string());
        assert_eq!(v["member_count"], 412);
        assert_eq!(v["rank_by"], "theme_core");
    }

    /// The worst case the overhead constants must cover: every optional field
    /// set, floats with the longest shortest-round-trip spelling.
    fn heavy_hit(statement: String, neighbours: usize) -> SemanticSearchResult {
        let worst = -2.225_073_858_507_201_4e-308_f64;
        let ep = || EpistemicState {
            belief: Some(worst),
            plausibility: Some(worst),
            ignorance: Some(worst),
            truth_value: worst,
        };
        SemanticSearchResult {
            claim_id: Uuid::new_v4(),
            statement: statement.clone(),
            similarity: worst,
            epistemic: ep(),
            agent_id: Uuid::new_v4(),
            trace_id: Some(Uuid::new_v4()),
            claim_type: Some("hypothesis\u{1}\"".to_string()),
            created_at: Some(Utc::now()),
            graph_neighbors: Some(
                (0..neighbours)
                    .map(|_| GraphNeighbor {
                        claim_id: Uuid::new_v4(),
                        statement: statement.clone(),
                        similarity: worst,
                        epistemic: ep(),
                        edge_type: "CORROBORATES\u{2}".to_string(),
                        direction: "outbound\\".to_string(),
                    })
                    .collect(),
            ),
            theme_id: Some(Uuid::new_v4()),
            cluster_id: Some(Uuid::new_v4()),
        }
    }

    #[test]
    fn hit_cost_is_an_upper_bound_on_serialised_size() {
        let statements = [
            String::new(),
            "plain text".to_string(),
            // Control characters escape to six bytes each, quotes and
            // backslashes to two.
            "\u{1}\u{2}\u{1f}\"\\\n\t\r\u{8}\u{c}".repeat(200),
            "multi-byte: \u{e9}\u{4e2d}\u{1f600}".repeat(50),
            "x".repeat(65_536),
        ];
        for s in statements {
            for n in [0, 1, 5] {
                let hit = heavy_hit(s.clone(), n);
                let real = serde_json::to_vec(&hit).unwrap().len() + 1; // array comma
                assert!(
                    hit_cost(&hit) >= real,
                    "hit_cost {} must bound the serialised size {real} (statement len {}, {n} \
                     neighbours)",
                    hit_cost(&hit),
                    s.len()
                );
            }
        }
        assert_eq!(json_escaped_len("\u{1}"), 6);
        assert_eq!(json_escaped_len("\"\\\n"), 6);
        assert_eq!(json_escaped_len("\u{e9}"), 2);
    }

    #[test]
    fn byte_budget_keeps_the_first_hit_and_cuts_in_order() {
        let big = "y".repeat(60 * 1024);
        let hits: Vec<SemanticSearchResult> = (0..40).map(|_| heavy_hit(big.clone(), 0)).collect();
        let ids: Vec<Uuid> = hits.iter().map(|h| h.claim_id).collect();
        let (kept, cut) = apply_byte_budget(hits);
        assert!(cut, "40 hits of 60 KiB exceed the budget");
        assert!(!kept.is_empty() && kept.len() < 40);
        let kept_ids: Vec<Uuid> = kept.iter().map(|h| h.claim_id).collect();
        assert_eq!(
            kept_ids,
            ids[..kept.len()].to_vec(),
            "the budget keeps a prefix"
        );
        let resp = SemanticSearchResponse {
            results: kept,
            total: 0,
            query_time_ms: u64::MAX,
            centroid_dim_used: Some(3072),
            theme_scope: Some(SearchThemeScope {
                theme_id: Uuid::new_v4(),
                member_count: i64::MAX,
                rank_by: "theme_core",
            }),
            next_cursor: Some("o:999".to_string()),
            truncated: true,
        };
        assert!(serde_json::to_vec(&resp).unwrap().len() <= MAX_RESPONSE_BYTES);

        // One oversized hit is still served: the first is always kept.
        let huge = vec![heavy_hit("z".repeat(MAX_RESPONSE_BYTES), 0)];
        let (kept, cut) = apply_byte_budget(huge);
        assert_eq!(kept.len(), 1);
        assert!(!cut);
    }
}

// ============================================================================
// DB integration tests for the diverse-search centroid_dim path
// ============================================================================

#[cfg(all(test, feature = "db"))]
mod db_integration_tests {
    use super::*;
    use crate::state::{ApiConfig, AppState};

    /// Rebuild a connection URL for the database `pool` is connected to.
    ///
    /// `#[sqlx::test]` hands each arm a randomly-named private database but no
    /// URL, and [`call_diverse_search`] needs one to build its `ScopedPool`.
    /// Asking the database its own name and splicing that onto the ambient
    /// `DATABASE_URL`'s authority is the same move
    /// `tests/viewer_fixture.rs::database_url_for` makes; it is duplicated here
    /// because this is an in-crate `#[cfg(test)]` module and cannot reach the
    /// integration-test fixture.
    ///
    /// Without it the arms would seed the private database and the handler
    /// would read the SHARED one -- a silent vacuous pass, which is strictly
    /// worse than the flake being fixed.
    async fn database_url_for(pool: &sqlx::PgPool) -> String {
        let db: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(pool)
            .await
            .expect("current_database()");
        let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        // Strip the query string before touching the path, or `?sslmode=require`
        // would be mistaken for part of the database name.
        let (authority, query) = match base.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (base.as_str(), None),
        };
        let prefix = authority
            .trim_end_matches('/')
            .rsplit_once('/')
            .expect("DATABASE_URL must carry a database path")
            .0;
        match query {
            Some(q) => format!("{prefix}/{db}?{q}"),
            None => format!("{prefix}/{db}"),
        }
    }

    /// Insert a fresh agent for the test scope (returns its UUID).
    async fn seed_agent(pool: &sqlx::PgPool, label: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels) \
             VALUES (sha256(gen_random_uuid()::text::bytea), $1, 'system', ARRAY['test']) \
             RETURNING id",
        )
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("seed agent")
    }

    /// Build a deterministic pgvector literal at the given dim, biased toward
    /// `seed` so two calls with the same seed produce similar (but not equal)
    /// vectors after normalization.
    fn pgvec_at_dim(seed: f32, dim: usize) -> String {
        let mut v = vec![0.0f32; dim];
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = if i == 0 { seed + 0.5 } else { seed * 1e-3 };
        }
        let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    /// Insert N themes with `centroid_3072` populated. Returns the inserted ids.
    async fn seed_themes_with_3072_centroids(pool: &sqlx::PgPool, n: usize) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-3072-theme-{i}"))
            .bind("3072d test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM_LARGE);
            sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
                .bind(theme_id)
                .bind(&pgvec)
                .execute(pool)
                .await
                .expect("set 3072 centroid");
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N themes with ONLY the legacy 1536d `centroid` populated. Used
    /// to assert the rejection path when the caller asks for 3072d but the
    /// corpus hasn't been migrated.
    async fn seed_themes_with_only_1536_centroids(pool: &sqlx::PgPool, n: usize) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-1536-only-theme-{i}"))
            .bind("1536d-only test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM);
            sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
                .bind(theme_id)
                .bind(&pgvec)
                .execute(pool)
                .await
                .expect("set 1536 centroid");
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N themes; `n_3072_populated` of them get `centroid_3072` set,
    /// the rest get only the legacy `centroid` set. Used for the auto-detect
    /// majority test.
    async fn seed_themes_with_mixed_centroids(
        pool: &sqlx::PgPool,
        total: usize,
        n_3072_populated: usize,
    ) -> Vec<Uuid> {
        let mut ids = Vec::with_capacity(total);
        for i in 0..total {
            let theme_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claim_themes (label, description) VALUES ($1, $2) RETURNING id",
            )
            .bind(format!("test-mixed-theme-{i}"))
            .bind("mixed-dim test theme")
            .fetch_one(pool)
            .await
            .expect("create theme");

            if i < n_3072_populated {
                let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM_LARGE);
                sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
                    .bind(theme_id)
                    .bind(&pgvec)
                    .execute(pool)
                    .await
                    .expect("set 3072 centroid");
            } else {
                let pgvec = pgvec_at_dim(i as f32 * 0.1, EMBEDDING_DIM);
                sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
                    .bind(theme_id)
                    .bind(&pgvec)
                    .execute(pool)
                    .await
                    .expect("set 1536 centroid");
            }
            ids.push(theme_id);
        }
        ids
    }

    /// Insert N claims with `embedding_3072` AND the 1536-d `embedding`
    /// populated, assigned to the given themes (round-robin). Returns
    /// inserted claim ids.
    ///
    /// Both columns, because the diverse path's theme-coverage probe orders
    /// the query's neighbourhood by the (ANN-indexed) 1536-d column at every
    /// `centroid_dim` — as the flat fallback does. A claim with only a 3072-d
    /// embedding is outside that neighbourhood, and a corpus of such claims
    /// reads as uncovered and falls back. Real 3072-d claims are re-embeddings
    /// of claims that already carry the 1536-d vector.
    async fn seed_claims_with_3072_embeddings(
        pool: &sqlx::PgPool,
        n: usize,
        theme_ids: &[Uuid],
        agent_id: Uuid,
    ) -> Vec<Uuid> {
        assert!(
            !theme_ids.is_empty(),
            "need at least one theme to attach claims"
        );
        let mut ids = Vec::with_capacity(n);
        for i in 0..n {
            let theme_id = theme_ids[i % theme_ids.len()];
            let pgvec = pgvec_at_dim(i as f32 * 0.05, EMBEDDING_DIM_LARGE);
            let pgvec_1536 = pgvec_at_dim(i as f32 * 0.05, EMBEDDING_DIM);
            let content = format!("test-3072-claim-{}-{}", i, Uuid::new_v4());
            let claim_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding_3072, theme_id, embedding) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, $4, $5::vector) \
                 RETURNING id",
            )
            .bind(&content)
            .bind(agent_id)
            .bind(&pgvec)
            .bind(theme_id)
            .bind(&pgvec_1536)
            .fetch_one(pool)
            .await
            .expect("seed 3072 claim");
            ids.push(claim_id);
        }
        ids
    }

    /// Helper that invokes `semantic_search` with diverse mode on. Returns
    /// the parsed response or the raw `ApiError`.
    ///
    /// # Why this builds a `ScopedPool` and not `AppState::with_db`
    ///
    /// PR-29 moved `semantic_search`'s six reads onto `AppState::read_as`, and
    /// `read_as` HARD-REFUSES a state whose `scoped` is `None` — that refusal is
    /// the fail-closed behaviour the conversion exists to establish, not an
    /// inconvenience to work around. `AppState::with_db` sets `scoped: None`, so
    /// all three tests below would have failed against the converted handler,
    /// and `diverse_search_rejects_when_3072d_centroids_missing` would have
    /// failed QUIETLY: it asserts `ValidationError` and the `frac_3072` read
    /// that precedes that rejection would have returned `InternalError` instead.
    ///
    /// These tests are about centroid-dimension selection, not tenancy, so they
    /// want the cheapest state that satisfies `read_as`.
    /// `AppState::with_scoped_pool` sets `db_pool = scoped.inner().clone()`,
    /// which is the same connection posture they had before.
    ///
    /// The `DATABASE_URL` is read again rather than taken from `state.db_pool`
    /// on purpose: `no_unscoped_pool.rs`'s scanner does not cut `#[cfg(test)]`
    /// and its `SCAN_ROOT` is `crates/epigraph-api/src`, so a `state.db_pool` in
    /// this helper would count as an unconverted site and silently break the
    /// register this shard just lowered.
    async fn call_diverse_search(
        pool: sqlx::PgPool,
        centroid_dim: Option<u32>,
    ) -> Result<SemanticSearchResponse, ApiError> {
        call_diverse_search_with_query(pool, "test query for diverse search", centroid_dim).await
    }

    /// [`call_diverse_search`] with a caller-chosen query text. No embedding
    /// service is configured on the test state, so the handler embeds `query`
    /// with [`generate_mock_embedding_with_dim`] — which lets a test compute
    /// the exact query vector and seed claims at known similarities to it.
    async fn call_diverse_search_with_query(
        pool: sqlx::PgPool,
        query: &str,
        centroid_dim: Option<u32>,
    ) -> Result<SemanticSearchResponse, ApiError> {
        call_diverse_search_in_mode(
            pool,
            query,
            centroid_dim,
            epigraph_db::SessionGucMode::Session,
        )
        .await
    }

    /// [`call_diverse_search_with_query`] with the scoped pool's
    /// `SessionGucMode` chosen by the caller. Under `Transaction` the handler's
    /// `read` is one transaction, which is the shape a failed statement can
    /// poison for every read after it.
    async fn call_diverse_search_in_mode(
        pool: sqlx::PgPool,
        query: &str,
        centroid_dim: Option<u32>,
        mode: epigraph_db::SessionGucMode,
    ) -> Result<SemanticSearchResponse, ApiError> {
        let viewer = epigraph_db::Viewer::resolve(&pool, uuid::Uuid::nil())
            .await
            .expect("resolve viewer");
        let url = database_url_for(&pool).await;
        let scoped = epigraph_db::ScopedPool::connect(&url, mode)
            .await
            .expect("connect a scoped pool");
        let state = AppState::with_scoped_pool(scoped, ApiConfig::default());
        let request = SemanticSearchRequest {
            query: query.to_string(),
            limit: Some(5),
            min_similarity: None,
            claim_type: None,
            created_after: None,
            created_before: None,
            agent_id: None,
            diverse: Some(true),
            max_themes: Some(3),
            diversity_weight: Some(0.5),
            centroid_dim,
            candidate_pool: None,
            theme_id: None,
            rank_by: None,
            cursor: None,
        };
        let response = semantic_search(
            crate::middleware::bearer::ViewerExtractor(viewer),
            axum::extract::State(state),
            axum::Json(request),
        )
        .await?;
        Ok(response.0)
    }

    /// Test 1 — explicit 3072d hint queries the 3072d centroids and
    /// surfaces `centroid_dim_used: 3072`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_uses_3072d_centroids_when_hinted(pool: sqlx::PgPool) {
        let agent = seed_agent(&pool, "diverse-3072-test").await;
        let theme_ids = seed_themes_with_3072_centroids(&pool, 5).await;
        let _claims = seed_claims_with_3072_embeddings(&pool, 50, &theme_ids, agent).await;

        let resp = call_diverse_search(pool.clone(), Some(3072))
            .await
            .expect("3072d diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used,
            Some(3072),
            "response must surface centroid_dim_used=3072"
        );
        assert!(
            !resp.results.is_empty(),
            "should return at least one claim from the 3072d themes"
        );
    }

    /// Test 2 — explicit 3072d hint with NO 3072d centroids populated:
    /// must reject with ValidationError on field=centroid_dim.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_rejects_when_3072d_centroids_missing(pool: sqlx::PgPool) {
        let _ids = seed_themes_with_only_1536_centroids(&pool, 5).await;

        let result = call_diverse_search(pool.clone(), Some(3072)).await;

        match result {
            Err(ApiError::ValidationError { field, .. }) => {
                assert_eq!(field, "centroid_dim", "validation must blame centroid_dim");
            }
            other => panic!(
                "expected ValidationError on centroid_dim, got: {:?}",
                other.map(|r| format!("Ok(results={})", r.results.len()))
            ),
        }
    }

    /// Test 3 — auto-detect: when ≥50% of themes have `centroid_3072`
    /// populated and the caller does NOT hint, the search picks 3072d.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_auto_picks_3072d_when_majority_populated(pool: sqlx::PgPool) {
        // 3/5 themes have centroid_3072 (60% > 50% threshold)
        let theme_ids = seed_themes_with_mixed_centroids(&pool, 5, 3).await;
        let agent = seed_agent(&pool, "diverse-auto-test").await;
        // Attach claims to the 3072-populated themes only so the search has
        // candidates after theme selection. Exactly as many 3072-d themes as
        // the helper's `max_themes` (3), so the whole 3072-d theme set is the
        // shortlist and the query's neighbourhood is fully reachable through
        // it — the theme-coverage guard counts shortlist membership only, and
        // this arm is about dimension auto-detect, not the guard.
        let theme_ids_3072 = &theme_ids[..3];
        let _claims = seed_claims_with_3072_embeddings(&pool, 50, theme_ids_3072, agent).await;

        let resp = call_diverse_search(pool.clone(), None)
            .await
            .expect("auto-detected diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used,
            Some(3072),
            "auto-detect should pick 3072 when ≥50% of themes have centroid_3072 set"
        );
    }

    // ---- Theme-coverage guard -------------------------------------------
    //
    // Diverse mode draws candidates ONLY from themed claims, and the theme
    // shortlist is `ORDER BY distance LIMIT n` with no relevance floor. A small
    // stale theme set therefore captured every diverse query. These arms pin
    // that diverse mode falls back to flat search when the query's own
    // neighbourhood is not covered by themes, and keeps diverse selection when
    // it is.

    const COVERAGE_QUERY: &str = "theme coverage guard query";

    fn to_pgvec(v: &[f32]) -> String {
        let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        format!("[{}]", inner.join(","))
    }

    /// The exact vector the handler will embed [`COVERAGE_QUERY`] to (no
    /// embedding service is configured on the test state), with `drift` added
    /// on an axis the query does not use — so cosine similarity to the query
    /// is `1 / sqrt(1 + drift²)`, strictly decreasing in `drift`.
    fn query_neighbour(drift: f32) -> String {
        let mut v = generate_mock_embedding_with_dim(COVERAGE_QUERY, EMBEDDING_DIM);
        v[EMBEDDING_DIM - 2] = drift;
        to_pgvec(&v)
    }

    /// A vector orthogonal to the query (the query's mock embedding is zero on
    /// the last axis), nudged by `drift` on a second unused axis.
    fn off_topic(drift: f32) -> String {
        let mut v = vec![0.0f32; EMBEDDING_DIM];
        v[EMBEDDING_DIM - 1] = 1.0;
        v[EMBEDDING_DIM - 3] = drift;
        to_pgvec(&v)
    }

    async fn seed_theme_1536(pool: &sqlx::PgPool, label: &str, centroid: &str) -> Uuid {
        let theme_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claim_themes (label, description) VALUES ($1, 'coverage test') \
             RETURNING id",
        )
        .bind(label)
        .fetch_one(pool)
        .await
        .expect("create theme");
        sqlx::query("UPDATE claim_themes SET centroid = $2::vector WHERE id = $1")
            .bind(theme_id)
            .bind(centroid)
            .execute(pool)
            .await
            .expect("set centroid");
        theme_id
    }

    async fn seed_claim_1536(
        pool: &sqlx::PgPool,
        agent_id: Uuid,
        content: &str,
        embedding: &str,
        theme_id: Option<Uuid>,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, theme_id) \
             VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, $4) \
             RETURNING id",
        )
        .bind(content)
        .bind(agent_id)
        .bind(embedding)
        .bind(theme_id)
        .fetch_one(pool)
        .await
        .expect("seed 1536 claim")
    }

    /// [`seed_claim_1536`] plus an optional `embedding_3072` and an optional
    /// owning group (`visibility = 'group'`), all set in the INSERT.
    ///
    /// Everything goes into the INSERT on purpose: a later write to `claims`
    /// from this file counts against `viewer_route_table_lint`'s route-layer
    /// write ratchet, whose scanner does not skip `#[cfg(test)]` code.
    async fn seed_claim_with(
        pool: &sqlx::PgPool,
        agent_id: Uuid,
        content: &str,
        embedding: &str,
        embedding_3072: Option<&str>,
        theme_id: Option<Uuid>,
        owner_group: Option<Uuid>,
    ) -> Uuid {
        let q = match owner_group {
            None => sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, \
                                     embedding_3072, theme_id) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, $4::vector, $5) \
                 RETURNING id",
            ),
            Some(_) => sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, \
                                     embedding_3072, theme_id, visibility, owner_group_id) \
                 VALUES ($1, sha256($1::bytea), 0.5, $2, $3::vector, $4::vector, $5, 'group', $6) \
                 RETURNING id",
            ),
        };
        let q = q
            .bind(content)
            .bind(agent_id)
            .bind(embedding)
            .bind(embedding_3072)
            .bind(theme_id);
        let q = match owner_group {
            Some(g) => q.bind(g),
            None => q,
        };
        q.fetch_one(pool).await.expect("seed claim")
    }

    /// Give the planner statistics, as a live database has, so the covered arm
    /// runs the probe and candidate query under realistic plans.
    async fn analyze_claims(pool: &sqlx::PgPool) {
        sqlx::query("VACUUM ANALYZE claims")
            .execute(pool)
            .await
            .expect("analyze claims");
    }

    /// Make every vector read in this test's private database EXACT by
    /// dropping the approximate (HNSW) indexes on `claims` and `claim_themes`.
    ///
    /// The bug arm needs it: an approximate read on the way to the theme
    /// candidates can come back empty, and an empty theme lookup or candidate
    /// pull falls through to flat search BY ACCIDENT — letting unfixed code
    /// pass. Observed mechanism: with no table statistics the candidate query
    /// plans as an HNSW scan whose `theme_id = ANY(..)` post-filter finds none
    /// of the far-away themed rows. Exact reads remove every approximate step,
    /// so the arm is deterministic in both directions.
    async fn drop_ann_indexes(pool: &sqlx::PgPool) {
        sqlx::query(
            "DO $$ DECLARE r record; BEGIN \
               FOR r IN SELECT i.relname FROM pg_index x \
                          JOIN pg_class i ON i.oid = x.indexrelid \
                          JOIN pg_am a ON a.oid = i.relam \
                         WHERE x.indrelid IN ('claims'::regclass, 'claim_themes'::regclass) \
                       AND a.amname = 'hnsw' LOOP \
                 EXECUTE format('DROP INDEX %I', r.relname); \
               END LOOP; \
             END $$",
        )
        .execute(pool)
        .await
        .expect("drop claims and claim_themes ANN indexes");
    }

    /// The bug, on the REST surface: many relevant UNTHEMED claims plus a tiny
    /// off-topic theme set. Before the guard the handler entered diverse mode
    /// (themes were non-empty) and answered with the off-topic theme members
    /// only. It must instead fall back to flat search — observable as
    /// `centroid_dim_used == None` (the flat tail's value) and the flat top-5.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_falls_back_when_theme_set_does_not_cover_query(pool: sqlx::PgPool) {
        let agent = seed_agent(&pool, "coverage-bug").await;

        let theme = seed_theme_1536(&pool, "stale-probe-theme", &off_topic(0.0)).await;
        let mut off = std::collections::HashSet::new();
        for i in 0..3 {
            off.insert(
                seed_claim_1536(
                    &pool,
                    agent,
                    &format!("off-topic-{i}"),
                    &off_topic(i as f32 * 0.01),
                    Some(theme),
                )
                .await,
            );
        }
        let mut relevant = Vec::new();
        for i in 0..60 {
            relevant.push(
                seed_claim_1536(
                    &pool,
                    agent,
                    &format!("relevant-{i}"),
                    &query_neighbour(i as f32 * 0.01),
                    None,
                )
                .await,
            );
        }
        drop_ann_indexes(&pool).await;

        let resp = call_diverse_search_with_query(pool.clone(), COVERAGE_QUERY, Some(1536))
            .await
            .expect("diverse search must succeed");

        let returned: std::collections::HashSet<Uuid> =
            resp.results.iter().map(|r| r.claim_id).collect();
        let leaked: Vec<&Uuid> = returned.intersection(&off).collect();
        assert!(
            leaked.is_empty(),
            "diverse=true returned off-topic members of an uncovering theme set: {leaked:?}"
        );
        let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
        assert_eq!(
            returned, flat_top_5,
            "uncovered query must fall back to flat search and return the 5 most relevant claims"
        );
        assert_eq!(
            resp.centroid_dim_used, None,
            "the fallback answers from the flat tail, which reports no centroid_dim"
        );
    }

    /// Per-query, not corpus-wide: most of the corpus is an unthemed far
    /// cluster, but the query's neighbourhood is themed except for its single
    /// nearest claim. Diverse selection must still run: `centroid_dim_used` is
    /// `Some`, and the unthemed nearest claim (which flat search would rank
    /// first) is absent because diverse candidates are themed only.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_keeps_diverse_selection_when_query_is_covered(pool: sqlx::PgPool) {
        let agent = seed_agent(&pool, "coverage-ok").await;

        let theme = seed_theme_1536(&pool, "near-theme", &query_neighbour(0.0)).await;
        let unthemed_nearest = seed_claim_1536(
            &pool,
            agent,
            "unthemed-nearest",
            &query_neighbour(0.0),
            None,
        )
        .await;
        let mut themed = std::collections::HashSet::new();
        for i in 0..60 {
            themed.insert(
                seed_claim_1536(
                    &pool,
                    agent,
                    &format!("themed-{i}"),
                    &query_neighbour(0.05 + i as f32 * 0.01),
                    Some(theme),
                )
                .await,
            );
        }
        for i in 0..150 {
            seed_claim_1536(
                &pool,
                agent,
                &format!("far-{i}"),
                &off_topic(i as f32 * 0.01),
                None,
            )
            .await;
        }
        analyze_claims(&pool).await;

        let resp = call_diverse_search_with_query(pool.clone(), COVERAGE_QUERY, Some(1536))
            .await
            .expect("diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used,
            Some(1536),
            "a covered query must be answered by the diverse path"
        );
        let returned: std::collections::HashSet<Uuid> =
            resp.results.iter().map(|r| r.claim_id).collect();
        assert_eq!(returned.len(), 5, "limit=5 → 5 results");
        assert!(
            !returned.contains(&unthemed_nearest),
            "the unthemed nearest claim can only appear via the flat fallback"
        );
        assert!(
            returned.is_subset(&themed),
            "every diverse pick must come from the covering theme; got {returned:?}"
        );
    }

    /// The fallback at `centroid_dim = 3072`, reached by AUTO-DETECT, with the
    /// ANN indexes kept and planner statistics present (the realistic plan
    /// shape). A single stale theme carries a 3072-d centroid (so auto-detect
    /// resolves to 3072) and three off-topic members; the query's neighbourhood
    /// is sixty relevant unthemed claims. The guard must send the request to
    /// the flat tail: `centroid_dim_used == None` and the flat top-5.
    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_at_3072_falls_back_when_theme_set_does_not_cover_query(
        pool: sqlx::PgPool,
    ) {
        let agent = seed_agent(&pool, "coverage-3072").await;
        let off_3072 = pgvec_at_dim(0.0, EMBEDDING_DIM_LARGE);

        let theme = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claim_themes (label, description) VALUES ('stale-3072', 'coverage test') \
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .expect("create theme");
        sqlx::query("UPDATE claim_themes SET centroid_3072 = $2::vector WHERE id = $1")
            .bind(theme)
            .bind(&off_3072)
            .execute(&pool)
            .await
            .expect("set 3072 centroid");

        let mut off = std::collections::HashSet::new();
        for i in 0..3 {
            let c = seed_claim_with(
                &pool,
                agent,
                &format!("off-topic-3072-{i}"),
                &off_topic(i as f32 * 0.01),
                Some(&off_3072),
                Some(theme),
                None,
            )
            .await;
            off.insert(c);
        }
        let mut relevant = Vec::new();
        for i in 0..60 {
            relevant.push(
                seed_claim_1536(
                    &pool,
                    agent,
                    &format!("relevant-3072-{i}"),
                    &query_neighbour(i as f32 * 0.01),
                    None,
                )
                .await,
            );
        }
        analyze_claims(&pool).await;

        let resp = call_diverse_search_with_query(pool.clone(), COVERAGE_QUERY, None)
            .await
            .expect("diverse search must succeed");

        assert_eq!(
            resp.centroid_dim_used, None,
            "an uncovered query must be answered by the flat tail even when auto-detect \
             resolved to 3072"
        );
        let returned: std::collections::HashSet<Uuid> =
            resp.results.iter().map(|r| r.claim_id).collect();
        assert!(
            returned.is_disjoint(&off),
            "the stale 3072-d theme's off-topic members must not be returned"
        );
        let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
        assert_eq!(returned, flat_top_5, "the fallback returns the flat top-5");
    }

    /// A FAILING coverage probe falls back to flat instead of failing the
    /// request, in the given `SessionGucMode`.
    ///
    /// Layout: one theme holding sixty relevant claims (a covered query — the
    /// control run proves diverse mode runs), plus one group-private claim
    /// nearest of all that the public viewer must never see. The probe is then
    /// broken by renaming `claims.theme_id`, which only the probe and the
    /// diverse candidate query read (the auto-detect and theme lookup read
    /// `claim_themes`; the flat search reads neither).
    ///
    /// Under `Transaction` this is the savepoint's test: without it the failed
    /// probe aborts the request's transaction and the flat search on the same
    /// `read` fails with "current transaction is aborted".
    async fn assert_probe_failure_falls_back_to_flat(
        pool: sqlx::PgPool,
        mode: epigraph_db::SessionGucMode,
    ) {
        let agent = seed_agent(&pool, "coverage-probe-fails").await;
        let theme = seed_theme_1536(&pool, "covering", &query_neighbour(0.0)).await;
        let mut relevant = Vec::new();
        for i in 0..60 {
            relevant.push(
                seed_claim_1536(
                    &pool,
                    agent,
                    &format!("themed-relevant-{i}"),
                    &query_neighbour(0.01 + i as f32 * 0.01),
                    Some(theme),
                )
                .await,
            );
        }
        // A real personal group owned by the author (the shape
        // `AgentRepository::ensure_personal_group` mints); the nil test viewer
        // is not a member.
        let group: Uuid = sqlx::query_scalar(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id) \
             VALUES ('coverage-private', 'did:epigraph:personal:' || $1::text, ''::bytea, \
                     'personal', $1) \
             RETURNING id",
        )
        .bind(agent)
        .fetch_one(&pool)
        .await
        .expect("seed a private group");
        let private = seed_claim_with(
            &pool,
            agent,
            "group-private-nearest",
            &query_neighbour(0.0),
            None,
            Some(theme),
            Some(group),
        )
        .await;

        let control = call_diverse_search_in_mode(pool.clone(), COVERAGE_QUERY, Some(1536), mode)
            .await
            .expect("control diverse search must succeed");
        assert_eq!(
            control.centroid_dim_used,
            Some(1536),
            "control: the covered query runs diverse selection"
        );

        sqlx::query("ALTER TABLE claims RENAME COLUMN theme_id TO theme_id_unavailable")
            .execute(&pool)
            .await
            .expect("break the coverage probe");

        let resp = call_diverse_search_in_mode(pool.clone(), COVERAGE_QUERY, Some(1536), mode)
            .await
            .unwrap_or_else(|e| {
                panic!("a failed coverage probe must fall back to flat, not fail ({mode:?}): {e:?}")
            });
        assert_eq!(
            resp.centroid_dim_used, None,
            "the fallback answers from the flat tail ({mode:?})"
        );
        let returned: std::collections::HashSet<Uuid> =
            resp.results.iter().map(|r| r.claim_id).collect();
        assert!(
            !returned.contains(&private),
            "the flat fallback must stay viewer-scoped ({mode:?})"
        );
        let flat_top_5: std::collections::HashSet<Uuid> = relevant[..5].iter().copied().collect();
        assert_eq!(
            returned, flat_top_5,
            "the fallback returns the viewer's flat top-5 ({mode:?})"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_probe_failure_falls_back_in_session_mode(pool: sqlx::PgPool) {
        assert_probe_failure_falls_back_to_flat(pool, epigraph_db::SessionGucMode::Session).await;
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn diverse_search_probe_failure_falls_back_in_transaction_mode(pool: sqlx::PgPool) {
        assert_probe_failure_falls_back_to_flat(pool, epigraph_db::SessionGucMode::Transaction)
            .await;
    }
}
