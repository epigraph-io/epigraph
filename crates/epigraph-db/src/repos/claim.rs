//! Claim repository for database operations

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::{AgentId, Claim, ClaimId, TenancyDecl, TraceId, TruthValue};
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Claim operations
pub struct ClaimRepository;

/// `MAX_AGENT_CLAIMS` is bound as a `LIMIT` in `get_by_agent`; a zero or
/// negative value would turn that query into a silent "return nothing" (or a
/// Postgres error) rather than a cap. Enforced at compile time.
const _: () = assert!(ClaimRepository::MAX_AGENT_CLAIMS > 0);

/// **The belief score** a truth gate compares against, as one SQL expression
/// over an unaliased `claims` row: the Dempster-Shafer pignistic probability
/// when a DS write has populated the cache, else the independently authored
/// `truth_value`.
///
/// ONE spelling, shared by every reader that gates or projects on belief
/// (backlog 14b98adc, GitHub #395): [`ClaimRepository::effective_belief_batch`]
/// — which `recall`'s BetP-gated `min_truth`, `traverse` and the other
/// `min_truth` call sites use — and [`ClaimRepository::list_by_belief_range`],
/// which `query_claims` filters AND projects on. Two copies of this CASE are how
/// `query_claims(max_truth=0.4)` came to disagree with `recall(min_truth=…)`
/// about the same refuted claim.
///
/// The `(belief, plausibility)` both-present guard is deliberate; see
/// `effective_belief_batch`. `truth_value` is `NOT NULL`, so the value never is.
pub(crate) const EFFECTIVE_BELIEF_SCORE_SQL: &str =
    "(CASE WHEN belief IS NOT NULL AND plausibility IS NOT NULL \
     THEN COALESCE(pignistic_prob, belief) ELSE truth_value END)::float8";

/// **The embedded population**, as one SQL predicate over `claims`: the rows
/// CLAUDE.md's embedding invariant says should carry a vector.
///
/// Spliced by all three statements that decide whether a given claim is owed an
/// embedding — [`ClaimRepository::find_claims_needing_embeddings`] (the
/// maintenance enumerator), [`ClaimRepository::claim_text_for_embedding`] (the
/// by-id read the unseal restoration uses) and
/// [`ClaimRepository::claim_text_if_embedding_missing`] (the by-id read the MCP
/// write path's repair arm uses). One string rather than three copies because
/// the three answers must agree: a copy that omitted the telemetry clauses would
/// make a write path embed the very population the enumerator excludes
/// (host-provenance claims are `is_current = true` with `embedding IS NULL` BY
/// DESIGN and dominate the gap), and one that omitted the `claim_encryption`
/// clause would put a plaintext-derived vector on a sealed row, which CLAUDE.md
/// calls a confidentiality violation rather than an embedding gap.
///
/// Deliberately does NOT include `embedding IS NULL`: "is this claim in the
/// embedded population" and "is its vector missing right now" are different
/// questions, and `claim_text_for_embedding`'s caller already holds a row it
/// intends to (re)embed.
const EMBEDDABLE_POPULATION: &str = "COALESCE(is_current, true) = true \
     AND NOT ('telemetry' = ANY(labels)) \
     AND (properties->>'event') IS NULL \
     AND NOT EXISTS ( \
         SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id \
     )";

/// `hnsw.ef_search` for a hybrid dense leg of `candidate_pool` rows: the pool
/// itself, clamped to pgvector's default (40) below and its maximum (1000)
/// above. See [`ClaimRepository::search_hybrid_scoped_since_in_theme`].
fn hnsw_ef_search_for_pool(candidate_pool: i64) -> i64 {
    candidate_pool.clamp(40, 1000)
}

/// Cached Dempster–Shafer belief columns for a claim, as read by
/// [`ClaimRepository::get_belief_columns`].
///
/// Each field is `Option` because the column is NULL on claims that have never
/// had a BBA combined onto them (the edge-wiring recompute populates them).
#[derive(Debug, Clone, Copy, sqlx::FromRow, serde::Serialize)]
pub struct ClaimBeliefColumns {
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_on_empty: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Sort key for [`ClaimRepository::list_filtered`].
///
/// An enum, not a string: the column name is interpolated into the `ORDER BY`
/// clause, so it must never be reachable from request data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimSortField {
    /// `ORDER BY created_at` (the endpoint default).
    #[default]
    CreatedAt,
    /// `ORDER BY truth_value`.
    TruthValue,
}

/// Sort direction for [`ClaimRepository::list_filtered`]. Enum for the same
/// reason as [`ClaimSortField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimSortOrder {
    /// Highest / most-recent first (the endpoint default).
    #[default]
    Desc,
    /// Lowest / oldest first.
    Asc,
}

/// Predicate set shared by [`ClaimRepository::list_filtered`] and
/// [`ClaimRepository::count_filtered`].
///
/// Every field is `None` by default, meaning "do not constrain this column",
/// so `ClaimListFilter::default()` selects the whole table. The two methods
/// bind this struct through the **same** WHERE clause, which is the point of
/// the struct: a `total` produced by a different predicate set than the rows
/// it describes is the defect this type exists to prevent (backlog
/// `2265a67b`).
#[derive(Debug, Default, Clone)]
pub struct ClaimListFilter<'a> {
    /// Case-insensitive `content ILIKE '%search%'`.
    pub search: Option<&'a str>,
    /// Inclusive lower bound on `truth_value`.
    pub truth_min: Option<f64>,
    /// Inclusive upper bound on `truth_value`.
    pub truth_max: Option<f64>,
    /// Restrict to claims authored by this agent.
    pub agent_id: Option<Uuid>,
    /// Drop claims authored by this agent (composes with `agent_id`).
    pub exclude_agent_id: Option<Uuid>,
    /// Restrict to current (`true`) or superseded (`false`) claims.
    /// `None` returns both.
    pub is_current: Option<bool>,
    /// Inclusive lower bound on `created_at`.
    pub created_after: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `created_at`.
    pub created_before: Option<DateTime<Utc>>,
    /// Restrict to this id set (used for predicates resolved by a prior query,
    /// e.g. "has a reasoning trace with methodology X").
    ///
    /// **`Some(&[])` means "nothing matches", not "no filter"** — it becomes
    /// `id = ANY('{}')`, which is false for every row. A caller that resolved
    /// an id set and found it empty must pass the empty slice, not `None`, or
    /// the filter inverts into "return everything".
    pub ids: Option<&'a [Uuid]>,
    /// `ORDER BY` column (ignored by `count_filtered`).
    pub sort_by: ClaimSortField,
    /// `ORDER BY` direction (ignored by `count_filtered`).
    pub sort_order: ClaimSortOrder,
}

/// Filter arguments for [`ClaimRepository::list_by_labels`].
///
/// These six travelled as positional parameters until the tenancy work added a
/// `viewer` argument. Grouping them is not only about the argument count: the
/// tail was `(.., current_only, min_truth, limit, offset)`, four unnamed
/// literals whose types (`bool`, `f64`, `i64`, `i64`) let `limit` and `offset`
/// swap silently. As named fields that becomes a compile error.
///
/// [`Default`] gives the common "no exclusions, everything, first page" shape,
/// so a caller states only what it actually constrains.
#[derive(Debug, Clone, Copy)]
pub struct LabelQuery<'a> {
    /// Claims must contain ALL of these (PostgreSQL `@>` containment).
    pub labels: &'a [String],
    /// Drop any claim whose labels intersect these (`&&` overlap). Empty = no exclusion.
    pub exclude_labels: &'a [String],
    /// Restrict to `is_current = true`, dropping superseded rows.
    pub current_only: bool,
    /// Minimum `truth_value`.
    pub min_truth: f64,
    /// Max rows returned.
    pub limit: i64,
    /// Rows to skip, for paging `(created_at DESC, id DESC)`. Kept for
    /// compatibility; prefer [`Self::after`], which does not drift.
    pub offset: i64,
    /// Keyset position: return only rows strictly after this one in
    /// `(created_at DESC, id DESC)` order. `None` starts at the newest row.
    /// Unlike `offset`, a page boundary does not move when rows are inserted
    /// or retired between pages.
    pub after: Option<LabelCursor>,
}

impl Default for LabelQuery<'_> {
    fn default() -> Self {
        Self {
            labels: &[],
            exclude_labels: &[],
            current_only: false,
            min_truth: 0.0,
            limit: 100,
            offset: 0,
            after: None,
        }
    }
}

/// A keyset position in [`ClaimRepository::list_by_labels`]'s
/// `(created_at DESC, id DESC)` order: the last row of the previous page.
///
/// Callers see it only as the opaque token from [`Self::encode`], which the
/// REST `GET /api/v1/claims/by-labels` and MCP `query_claims_by_label`
/// surfaces hand out as the next-page cursor and accept back as `after`.
/// A token names a row the caller was already served, and a forged one
/// only moves the starting point of a read that stays viewer-filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelCursor {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub id: Uuid,
}

/// Version prefix of [`LabelCursor`]'s token, so a later format can be told
/// apart (and an old one refused) rather than half-parsed.
const LABEL_CURSOR_PREFIX: &str = "k1.";

/// Postgres `timestamptz`'s earliest value (4714-11-24 00:00 BC UTC) in Unix
/// microseconds. chrono reaches further back, so without this check a forged
/// token could decode and then fail at bind time ("timestamp out of range"),
/// which the surfaces would report as an internal error instead of a refused
/// cursor. chrono's latest value is inside Postgres's upper bound (294276 AD),
/// so only the lower edge needs checking.
const PG_TIMESTAMPTZ_MIN_MICROS: i64 = -210_866_803_200_000_000;

impl LabelCursor {
    /// The cursor of `claim`, the last row of a page.
    #[must_use]
    pub fn of(claim: &Claim) -> Self {
        Self {
            created_at: claim.created_at,
            id: claim.id.as_uuid(),
        }
    }

    /// The next-page cursor for a page `rows` read with `limit`: the last
    /// row's position when the page is full (more rows may follow), `None`
    /// when it is short (the set is exhausted). `limit` is clamped exactly as
    /// [`ClaimRepository::list_by_labels`] clamps it.
    #[must_use]
    pub fn next_page(rows: &[(Claim, Vec<String>)], limit: i64) -> Option<Self> {
        let limit = usize::try_from(limit.clamp(1, 1000)).unwrap_or(usize::MAX);
        if rows.len() < limit {
            return None;
        }
        rows.last().map(|(c, _)| Self::of(c))
    }

    /// The opaque token: `k1.<created_at micros>.<id hex>`. URL-safe.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{LABEL_CURSOR_PREFIX}{}.{}",
            self.created_at.timestamp_micros(),
            self.id.simple()
        )
    }

    /// Parse a token from [`Self::encode`]. `None` for anything else,
    /// including a position Postgres `timestamptz` cannot represent, so every
    /// decoded cursor binds.
    #[must_use]
    pub fn decode(token: &str) -> Option<Self> {
        let rest = token.strip_prefix(LABEL_CURSOR_PREFIX)?;
        let (micros, id) = rest.split_once('.')?;
        let micros: i64 = micros.parse().ok()?;
        if micros < PG_TIMESTAMPTZ_MIN_MICROS {
            return None;
        }
        let created_at = chrono::DateTime::from_timestamp_micros(micros)?;
        let id = Uuid::try_parse(id).ok()?;
        Some(Self { created_at, id })
    }
}

/// One row of [`ClaimRepository::list_all_by_labels_ordered_by_id`]: the
/// fields a label-family planner reads, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LabelFamilyRow {
    pub id: Uuid,
    pub content: String,
    pub labels: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One row of [`ClaimRepository::marked_duplicates_of`]: a claim marked a
/// duplicate (at any depth) of `canonical`, with the fields a label-family
/// planner reads.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct MarkedDuplicateRow {
    pub canonical: Uuid,
    pub id: Uuid,
    pub content: String,
    pub labels: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The duplicate's author.
    pub agent_id: Uuid,
    /// The canonical's author, so a caller can tell a duplicate of another
    /// owner from one of the canonical's own.
    pub canonical_agent_id: Uuid,
}

/// The deepest chain [`ClaimRepository::marked_duplicates_of`] follows.
pub const MAX_DUPLICATE_CHAIN_DEPTH: i32 = 16;

/// What [`ClaimRepository::marked_duplicates_of`] read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MarkedDuplicates {
    /// At most `cap + 1` rows, none deeper than [`MAX_DUPLICATE_CHAIN_DEPTH`].
    pub rows: Vec<MarkedDuplicateRow>,
    /// Whether some chain went on past [`MAX_DUPLICATE_CHAIN_DEPTH`]: the
    /// duplicates beyond it are not in `rows`, so the read is incomplete.
    pub chain_truncated: bool,
}

/// One row of the walk behind [`ClaimRepository::marked_duplicates_of`]: the
/// truncation flag, and a duplicate when there is one (the statement always
/// returns at least the flag row).
#[derive(sqlx::FromRow)]
struct MarkedDuplicateWalkRow {
    chain_truncated: bool,
    canonical: Option<Uuid>,
    id: Option<Uuid>,
    content: Option<String>,
    labels: Option<Vec<String>>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    agent_id: Option<Uuid>,
    canonical_agent_id: Option<Uuid>,
}

/// Result row for [`ClaimRepository::search_by_embedding`].
///
/// `similarity` is `1 - cosine_distance`, in `[0, 1]` for non-degenerate
/// vectors (and matching the convention used by callers in `epigraph-mcp`).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ClaimEmbeddingHit {
    pub claim_id: Uuid,
    pub similarity: f64,
}

/// Which claims [`ClaimRepository::search_by_embedding_since`] draws its kNN
/// candidates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingSeedScope {
    /// Level-2 (`(properties->>'level')::int = 2`) claims only: the paragraph
    /// layer of `ingest_document`'s hierarchy, plus anything else written at
    /// level 2 (workflow steps). The historical contract, kept by the
    /// [`ClaimRepository::search_by_embedding`] wrapper.
    Paragraphs,
    /// Every claim with a vector in the searched column, at any level or
    /// none: memorized and `submit_claim` claims, sections, atoms, workflow
    /// steps and paragraphs alike. MCP `recall_with_context` seeds here
    /// (drain U082, backlog a1d89aab): parentage is an enrichment attribute,
    /// not an eligibility filter.
    AllClaims,
}

/// One link in the supersession chain returned by
/// [`ClaimRepository::version_history`], ordered oldest-first by
/// `(depth, id)`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimVersionHit {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub is_current: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub depth: i32,
    /// The claim that supersedes this one, read from `claims.supersedes` — not
    /// inferred from the position of the next row.
    ///
    /// Positional inference is wrong on a forked chain, and forks are reachable
    /// in normal operation: `ClaimRepository::mark_duplicate` sets
    /// `supersedes = <canonical>` on every duplicate, so any canonical claim
    /// with two marked duplicates has two children. `None` here means "nothing
    /// visible to this viewer supersedes it", which is the honest answer; a
    /// successor in another tenant is correctly reported as absent rather than
    /// as a dangling id.
    pub superseded_by: Option<Uuid>,
}

/// Result row for [`ClaimRepository::semantic_search_flat`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SemanticFlatHit {
    pub claim_id: Uuid,
    pub statement: String,
    pub similarity: f64,
    pub truth_value: f64,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub agent_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub claim_type: Option<String>,
    /// `Option` to match the `SemanticSearchResult` DTO, which has always
    /// modelled this as nullable.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One `(properties->>'level', properties->>'source_type')` pair from
/// [`ClaimRepository::embedding_radius_breakdown`].
///
/// A named alias rather than the bare tuple only because
/// `clippy::type_complexity` rejects `Vec<(Option<String>, Option<String>)>` in
/// a return position; both fields are genuinely optional (the JSON keys are not
/// guaranteed present) and the caller histograms them.
pub type LevelAndSourceType = (Option<String>, Option<String>);

/// Result row for [`ClaimRepository::neighborhood_embeddings`].
///
/// A named struct rather than a `(Uuid, Vec<f32>, Option<f64>)` tuple: the
/// projection is a raw embedding, and an unlabelled `Vec<f32>` at a call site
/// is exactly the kind of value that gets forwarded somewhere it should not go.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NeighborhoodEmbeddingRow {
    pub id: Uuid,
    pub embedding: Vec<f32>,
    pub truth_value: Option<f64>,
}

/// Result row for [`ClaimRepository::semantic_graph_neighbors`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SemanticNeighborHit {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub neighbor_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub nb_belief: Option<f64>,
    pub nb_plausibility: Option<f64>,
    pub similarity: f64,
    pub direction: String,
}

/// Result row for [`ClaimRepository::list_by_belief_bounds`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BeliefBoundedClaimHit {
    pub id: Uuid,
    pub content: String,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub mass_on_empty: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Result row for [`ClaimRepository::frame_claims_sorted`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FrameClaimBeliefHit {
    pub claim_id: Uuid,
    pub content: String,
    pub hypothesis_index: Option<i32>,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// Sort key for [`ClaimRepository::frame_claims_sorted`].
///
/// An enum rather than a `&str` so the `ORDER BY` interpolation in that
/// function is unreachable from user input by construction, instead of being
/// safe only as long as every caller keeps validating with a match arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeliefSort {
    Belief,
    Plausibility,
    Ignorance,
}

impl BeliefSort {
    /// The SQL expression to sort on. Always a compile-time literal.
    #[must_use]
    pub const fn sql_expr(self) -> &'static str {
        match self {
            BeliefSort::Belief => "c.belief",
            BeliefSort::Plausibility => "c.plausibility",
            BeliefSort::Ignorance => "(c.plausibility - c.belief)",
        }
    }

    /// Parse the wire value. `None` for anything else — callers turn that into
    /// a 400 rather than silently defaulting.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "belief" => Some(BeliefSort::Belief),
            "plausibility" => Some(BeliefSort::Plausibility),
            "ignorance" => Some(BeliefSort::Ignorance),
            _ => None,
        }
    }
}

/// Sort direction for [`ClaimRepository::frame_claims_sorted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    /// Always a compile-time literal.
    #[must_use]
    pub const fn sql_keyword(self) -> &'static str {
        match self {
            SortDirection::Asc => "ASC",
            SortDirection::Desc => "DESC",
        }
    }

    /// Parse the wire value. `None` for anything else.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "asc" => Some(SortDirection::Asc),
            "desc" => Some(SortDirection::Desc),
            _ => None,
        }
    }
}

/// Result row for [`ClaimRepository::rag_hybrid_context`].
///
/// Mirrors the projection `GET /api/v1/query/rag` serialises. It lives here
/// rather than in `epigraph-api` because PR-07 moved the statement out of
/// `routes/rag.rs` — where it was inline SQL with no visibility predicate —
/// into the repo layer, which is the only place a `{VISIBILITY:...}` marker is
/// reviewed (CLAUDE.md: "All SQL stays in `crates/epigraph-db/src/repos/`").
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RagContextHit {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub similarity: f64,
    pub domain: Option<String>,
    pub trace_id: Option<Uuid>,
    pub agent_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub edge_count: i64,
    pub hybrid_score: f64,
}

/// Result row for [`ClaimRepository::nearest_by_embedding`].
///
/// `distance` is raw pgvector cosine distance (`<=>`), in `[0, 2]`, 0 =
/// identical direction. Unlike [`ClaimEmbeddingHit::similarity`] this is NOT
/// inverted, because the write-side novelty gate (backlog `1bcaed94`)
/// thresholds directly on distance (`dist < 0.05` / `dist < 0.15`).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct NearestClaimHit {
    pub claim_id: Uuid,
    pub distance: f64,
}

/// One fused hit from [`ClaimRepository::search_hybrid_scoped`] /
/// [`ClaimRepository::search_lexical_scoped`].
///
/// `rrf_score` is the Reciprocal Rank Fusion score (higher = better; sums
/// `1/(k+rank)` across the legs the claim appeared in). `dense_similarity` is
/// `Some(1 - cosine_distance)` when the claim was in the dense (embedding) leg,
/// `None` for lexical-only hits. `in_lexical` is true when it appeared in the
/// lexical (`content_tsv`) leg.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct HybridHit {
    pub claim_id: Uuid,
    pub rrf_score: f64,
    pub dense_similarity: Option<f64>,
    pub in_lexical: bool,
}

/// Result row for [`ClaimRepository::latest_in_lineage`].
///
/// Represents a head of a step lineage: a claim with `step_lineage_id = $1`
/// and no incoming `supersedes` edge. See spec §3.1 in
/// `docs/superpowers/specs/2026-05-05-step-level-versioning-design.md`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LineageHead {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// `COALESCE(claims.is_current, true)`. Headship (no incoming
    /// `supersedes` edge) and `is_current` are independent: a claim retired
    /// without a supersedes edge (a deprecated workflow's step reused by a
    /// later generation, a marked duplicate) is still a head, and
    /// `evolve_step_conn` refuses to supersede it. Flagged, not filtered: a
    /// sole lineage member would otherwise vanish from the lineage silently.
    pub is_current: bool,
}

/// Result of a successful [`ClaimRepository::evolve_step`] call.
#[derive(Debug)]
pub struct EvolveStepResult {
    pub new_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
    pub edge_id: Uuid,
}

/// What [`ClaimRepository::mark_duplicate_with_repair`] repaired in-transaction,
/// and what the caller still has to re-derive outside it.
///
/// The repo layer can fix *where* a derived record lives (delete BBAs whose
/// edge is gone, move BBAs whose edge moved) with pure SQL. It cannot
/// recompute belief: that needs the Dempster-Shafer combine pipeline, which
/// lives in `epigraph-engine`. So this struct is the hand-off.
#[derive(Debug, Clone, Default)]
pub struct DedupRepair {
    /// Claims whose cached DS scalars no longer match their surviving BBA set:
    /// both dedup endpoints, plus every third claim that lost a BBA to the
    /// collision pre-deletes.
    pub stale_claims: Vec<Uuid>,
    /// `(edge_id, target_id, relationship)` for claim→claim edges re-sourced
    /// from `dup` onto `canonical`. Their BBAs encode `dup`'s interval, frozen
    /// at wire time; the caller must invalidate and re-wire them from
    /// `canonical`.
    pub resourced_edges: Vec<(Uuid, Uuid, String)>,
    /// BBAs deleted because their edge was deleted (orphan repair).
    pub deleted_bbas: u64,
    /// BBAs moved from `dup` to `canonical` because their edge was re-pointed
    /// (stranding repair).
    pub moved_bbas: u64,
    /// Edges the collision guards retracted (their BBAs are in `deleted_bbas`).
    pub retracted_edges: Vec<Uuid>,
    /// Edges re-pointed from `dup` onto `canonical` as their TARGET.
    pub retargeted_edges: Vec<Uuid>,
    /// The duplicate's copies of a BBA the canonical already carried under the
    /// same (frame, source agent, edge) key: dropped, so the canonical keeps
    /// its own row (migration 115 section 4's rule, now the only rule).
    pub dropped_duplicate_copies: u64,
    /// `binary_truth` bindings at a non-zero index that were NOT copied onto a
    /// canonical owned by another group (review finding W2's rule, FA07).
    pub skipped_false_bindings: u64,
    /// The duplicate's non-edge BBAs (its creation row, assess rows, agent
    /// BBAs) moved onto the canonical so their evidence is pooled there.
    pub pooled_bbas: Vec<Uuid>,
    /// The duplicate's non-edge BBAs left on it: a key the canonical already
    /// holds (the same source counted once), an `attributed_v1` row, or every
    /// such row when the canonical is a compound.
    pub kept_on_duplicate: Vec<Uuid>,
    /// The canonical has an in-force `decomposes_to` out-edge, so nothing was
    /// pooled onto it.
    pub canonical_is_compound: bool,
    /// What the repair changed, with the before-state an un-mark needs. It
    /// names other writers' rows, so it is persisted only where a privileged
    /// session reads it (the administrative cascade's applied audit row),
    /// never returned to a caller.
    pub revert: DedupRevert,
}

/// A BBA the dedup repair moved onto the canonical, with its tenancy before
/// the move.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct MovedBba {
    /// The `mass_functions` row.
    pub id: Uuid,
    /// Its `owner_group_id` on the duplicate.
    pub owner_group_id: Option<Uuid>,
    /// Its `visibility` on the duplicate.
    pub visibility: String,
    /// Its `writer_owned` on the duplicate.
    pub writer_owned: bool,
}

/// An edge the dedup repair re-pointed, with its tenancy before the move (the
/// edge tenancy trigger re-derives it from the new endpoints).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct EdgeTenancy {
    /// The edge.
    pub id: Uuid,
    /// Its `owner_group_id` before the re-point.
    pub owner_group_id: Option<Uuid>,
    /// Its `visibility` before the re-point.
    pub visibility: String,
    /// Its `co_owner_group_id` before the re-point.
    pub co_owner_group_id: Option<Uuid>,
}

/// The revert record of one dedup repair: every row it changed, and enough of
/// the before-state to put each back. Keyed to the act's identity edge.
///
/// [`ClaimRepository::reverse_marked_duplicate_conn`] reads it. Rows are
/// restored only while they are still where the repair left them; anything
/// another write has touched since is left alone and reported.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DedupRevert {
    /// The `same_as` identity edge of the act this repair followed.
    pub identity_edge: Option<Uuid>,
    /// Edges the collision guards retracted (`valid_to` set).
    pub retracted_edges: Vec<Uuid>,
    /// The `valid_to` the repair stamped on them (its transaction's `now()`).
    /// An un-mark puts back only an edge still carrying exactly this stamp: a
    /// different `valid_to` is a later decision, not the repair's.
    #[serde(default)]
    pub retracted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Edges re-pointed from the duplicate onto the canonical as their TARGET.
    pub retargeted_edges: Vec<Uuid>,
    /// Edges re-pointed from the duplicate onto the canonical as their SOURCE.
    pub resourced_edges: Vec<Uuid>,
    /// The tenancy each re-pointed edge had before the re-point.
    #[serde(default)]
    pub edge_tenancy: Vec<EdgeTenancy>,
    /// BBAs moved from the duplicate onto the canonical (edge-keyed and pooled).
    pub moved_bbas: Vec<MovedBba>,
    /// BBAs the repair deleted (those of retracted edges, and the duplicate's
    /// copies the canonical already held), each as its whole row.
    pub deleted_bbas: Vec<serde_json::Value>,
    /// Frames the repair bound the canonical to.
    pub copied_frames: Vec<Uuid>,
    /// The canonical's own input BBAs on those frames when the repair bound
    /// it. An un-mark removes a binding only while the canonical has no input
    /// on that frame beyond these (a later writer's input needs it).
    #[serde(default)]
    pub canonical_frame_inputs: Vec<Uuid>,
}

/// What [`ClaimRepository::reverse_marked_duplicate_conn`] put back, and what
/// it had to leave.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct DedupReversal {
    /// `(edge_id, target_id, relationship)` of claim->claim edges re-sourced
    /// back onto the duplicate: their far-end BBAs were re-derived from the
    /// canonical's interval and must be re-derived from the duplicate's.
    pub resourced_back: Vec<(Uuid, Uuid, String)>,
    /// Edges re-pointed back onto the duplicate as their target.
    pub retargeted_back: Vec<Uuid>,
    /// Retracted edges back in force.
    pub unretracted_edges: Vec<Uuid>,
    /// Moved BBAs returned to the duplicate with their old tenancy.
    pub returned_bbas: Vec<Uuid>,
    /// Deleted BBAs re-inserted.
    pub restored_bbas: Vec<Uuid>,
    /// Frame bindings the repair added to the canonical, removed again.
    pub unbound_frames: Vec<Uuid>,
    /// The canonical's cached combination rows removed because a returning
    /// input needed their slot on the duplicate (re-derived by the cascade).
    pub cleared_cached_rows: u64,
    /// Rows the record names that a later write has moved, re-pointed or
    /// deleted; left as they are.
    pub drifted: Vec<Uuid>,
    /// Claims whose cached belief no longer matches their BBA set.
    pub stale_claims: Vec<Uuid>,
}

impl DedupReversal {
    /// The reversal as the belief cascade's input
    /// (`retraction_cascade::cascade_after_dedup` with the DUPLICATE as the
    /// claim whose own interval is refreshed first).
    #[must_use]
    pub fn as_repair(&self) -> DedupRepair {
        DedupRepair {
            stale_claims: self.stale_claims.clone(),
            resourced_edges: self.resourced_back.clone(),
            ..DedupRepair::default()
        }
    }
}

/// A marked duplicate an un-mark's act restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmarkedDuplicate {
    /// The canonical it had been marked a duplicate of.
    pub canonical: Uuid,
    /// That canonical, then each claim that replaced it in turn (supersession
    /// or consolidation), ending with the CURRENT canonical the duplicate is
    /// restored against (operator ruling R-11); `[canonical]` when the
    /// canonical is still current ([`ClaimRepository::unmark_chain_conn`]).
    pub chain: Vec<Uuid>,
    /// The identity edge the act retracted.
    pub identity_edge: Uuid,
    /// The identity edge is one the legacy backfill wrote
    /// ([`ClaimRepository::backfill_legacy_dedup_identity_edges_conn`]): a mark
    /// the raw-SQL `fuzzy_dedup_claims` made, which kept no repair record.
    /// Read from the edge's reserved `properties.dedup` (only the act and the
    /// backfill write it), never from the claim's patchable properties.
    pub legacy_backfill: bool,
}

impl UnmarkedDuplicate {
    /// The current canonical: the last claim of [`Self::chain`].
    #[must_use]
    pub fn current_canonical(&self) -> Uuid {
        self.chain.last().copied().unwrap_or(self.canonical)
    }
}

/// The relationship of the identity edge a dedup's act writes,
/// `duplicate -> canonical`.
pub const DUPLICATE_IDENTITY_RELATIONSHIP: &str = "same_as";

/// The key under which the identity edge's `properties` carry its
/// [`DuplicateProvenance`]. An in-force `same_as` edge out of a retired claim
/// with this key is a dedup's record; a `same_as` edge without it is somebody's
/// assertion and no dedup reads or retracts it.
pub const DUPLICATE_IDENTITY_PROPERTY: &str = "dedup";

/// Whether an application edge write's `properties` carry
/// [`DUPLICATE_IDENTITY_PROPERTY`]. That key marks a dedup act's identity edge,
/// which the un-mark and the revert-record lookup key on, so only the act
/// writes it: every application surface that writes edge `properties` (create
/// and patch, HTTP and MCP) refuses a body that carries it.
#[must_use]
pub fn carries_dedup_identity_key(properties: &serde_json::Value) -> bool {
    properties.get(DUPLICATE_IDENTITY_PROPERTY).is_some()
}

/// The refusal text for [`carries_dedup_identity_key`].
pub const DEDUP_IDENTITY_KEY_RESERVED: &str =
    "properties.dedup is reserved for the identity edge a dedup act writes \
     (mark_duplicate); nothing was written";

/// The tool the legacy raw-SQL marks name in `claims.properties.deduped_by`:
/// `scripts/fuzzy_dedup_claims.py` before it marked through the dedup endpoint.
pub const LEGACY_FUZZY_DEDUP_TOOL: &str = "fuzzy_dedup_claims";

/// The `run_tag` of an identity edge the legacy backfill wrote
/// ([`ClaimRepository::backfill_legacy_dedup_identity_edges_conn`]).
pub const LEGACY_IDENTITY_BACKFILL_RUN_TAG: &str = "legacy_identity_backfill";

/// The legacy backfill's selection of a claim `c` whose `deduped_by` names
/// [`LEGACY_FUZZY_DEDUP_TOOL`]: what the legacy mark wrote is all still there
/// (the `deduped` label, the claim retired, and its `supersedes` still the
/// `deduped_into` the mark named), so its identity edge can be reconstructed.
/// One fragment for the backfill and the un-mark's refusal
/// ([`legacy_mark_refusal`]), so the two cannot disagree on which marks the
/// backfill reaches.
const LEGACY_MARK_RECONSTRUCTABLE_SQL: &str = "\
    'deduped' = ANY(COALESCE(c.labels, ARRAY[]::text[])) \
    AND NOT COALESCE(c.is_current, true) \
    AND c.supersedes IS NOT NULL \
    AND c.supersedes::text = c.properties->>'deduped_into'";

/// One duplicate the legacy identity-edge backfill selected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LegacyDuplicate {
    /// The retired duplicate.
    pub duplicate: Uuid,
    /// The claim its `supersedes` (and its legacy `deduped_into`) names.
    pub canonical: Uuid,
    /// The identity edge written for it (`None` on a dry run).
    pub identity_edge: Option<Uuid>,
}

/// What [`ClaimRepository::backfill_legacy_dedup_identity_edges_conn`] found
/// and, with `apply`, wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct LegacyIdentityBackfill {
    /// Whether the edges were written (false: a dry run, nothing written).
    pub applied: bool,
    /// Every selected duplicate, in id order.
    pub duplicates: Vec<LegacyDuplicate>,
    /// Identity edges written.
    pub inserted: u64,
}

/// Who marked a duplicate, through which tool, and by which rule: the
/// `properties.dedup` of the `same_as` identity edge the act writes. The act
/// adds `marked_at` (the transaction's `now()`), and `marked_by` from the
/// session principal when the caller names none.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateProvenance {
    /// The surface that marked it (`mark_duplicate`, `http:mark_duplicate`,
    /// `sweep_semantic_duplicates`, `label_dedup`, ...).
    pub tool: String,
    /// Why the two claims are one: [`Self::RULE_CALLER_ASSERTED`],
    /// [`Self::RULE_EXACT_RESTATEMENT`], or a caller's own rule name.
    pub rule: String,
    /// What the rule matched on (a shared identifier, a score), when it has
    /// something to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_on: Option<serde_json::Value>,
    /// The run that marked it, when the caller is a batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_tag: Option<String>,
    /// The hash of the plan the mark came from, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
    /// The acting agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked_by: Option<Uuid>,
    /// The caller's free-text reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl DuplicateProvenance {
    /// A caller named the canonical itself (`mark_duplicate`).
    pub const RULE_CALLER_ASSERTED: &'static str = "caller_asserted";
    /// The two claims have the same content hash (the semantic sweep's only
    /// automatic collapse).
    pub const RULE_EXACT_RESTATEMENT: &'static str = "exact_restatement";

    /// Provenance with only the tool and rule set.
    #[must_use]
    pub fn new(tool: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            rule: rule.into(),
            matched_on: None,
            run_tag: None,
            plan_hash: None,
            marked_by: None,
            reason: None,
        }
    }

    /// What the repository's own wrappers record when their caller gave no
    /// provenance: the act through [`ClaimRepository::mark_duplicate`] and the
    /// other provenance-less entry points.
    #[must_use]
    pub fn unattributed() -> Self {
        Self::new("repository", Self::RULE_CALLER_ASSERTED)
    }

    /// Set the acting agent.
    #[must_use]
    pub fn marked_by(mut self, agent: Option<Uuid>) -> Self {
        self.marked_by = agent;
        self
    }

    /// Set what the rule matched on.
    #[must_use]
    pub fn matched_on(mut self, matched_on: serde_json::Value) -> Self {
        self.matched_on = Some(matched_on);
        self
    }

    /// Set the batch run tag.
    #[must_use]
    pub fn run_tag(mut self, tag: impl Into<String>) -> Self {
        self.run_tag = Some(tag.into());
        self
    }

    /// Set the plan hash.
    #[must_use]
    pub fn plan_hash(mut self, hash: impl Into<String>) -> Self {
        self.plan_hash = Some(hash.into());
        self
    }

    /// The longest reason, in characters, an identity edge keeps.
    pub const MAX_REASON_CHARS: usize = 1000;

    /// Set the caller's reason (an empty one is dropped; a longer one is cut
    /// at [`Self::MAX_REASON_CHARS`]).
    #[must_use]
    pub fn reason(mut self, reason: Option<&str>) -> Self {
        self.reason = reason
            .filter(|r| !r.is_empty())
            .map(|r| r.chars().take(Self::MAX_REASON_CHARS).collect());
        self
    }
}

/// Labels a supersession does NOT carry from the retired claim onto its
/// replacement ([`ClaimRepository::supersede_act_conn`] carries every other
/// one). `near-duplicate` is the novelty gate's flag on one submission (its
/// content was near another claim's); on the replacement, whose content is
/// new, it would read as pointing at its own predecessor.
pub const NON_CARRIED_LABELS: &[&str] = &["near-duplicate"];

/// What [`ClaimRepository::migrate_superseded_edges_conn`] re-pointed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupersedeEdgeMigration {
    /// Edges re-pointed from the retired claim onto the replacement as their
    /// TARGET (other writers' assertions about the superseded claim).
    pub retargeted: Vec<Uuid>,
    /// Edges re-pointed from the retired claim onto the replacement as their
    /// SOURCE.
    pub resourced: Vec<Uuid>,
}

/// Relationships a STEP-LINEAGE supersession (`evolve_step(supersedes)`) leaves
/// on the retired step, in either direction.
///
/// `executes` attaches a workflow to its FROZEN original step: the live head is
/// resolved through the lineage (`WorkflowRepository`'s `ResolvedStep`,
/// `ClaimRepository::latest_in_lineage`), so moving the edge would detach the
/// frozen step the workflow was defined with.
///
/// `step_follows` (between steps) and `phase_follows` (between phases) are the
/// workflow's chain, and they link those same FROZEN claims:
/// `workflow_steps::ordered_steps` takes its id set from the `executes`
/// targets and follows `step_follows` only inside it. Moved onto the head, the
/// chain would leave that set, the walk would stop at the evolved slot, and a
/// later `add_step` there would find no `prev -> next` row to replace and fork
/// the chain.
///
/// `revises` is lineage-internal history, like `supersedes` (which no
/// supersession moves): `R -revises-> S` records that R branched from S.
/// Carried onto S's successor it would say R branched from a version that did
/// not exist when R was written; carried onto R's successor it would say the
/// successor branched from S directly.
pub(crate) const STEP_LINEAGE_FROZEN_RELATIONSHIPS: &[&str] =
    &["executes", "step_follows", "phase_follows", "revises"];

/// Relationships every replacement of a NON-PUBLIC claim leaves on the retired
/// claim, in either direction: a supersession ([`migrate_superseded_edges`]),
/// a dedup ([`repair_marked_duplicate`]) and a merge
/// ([`migrate_consolidated_edges`]), whether or not the pair shares a step
/// lineage (OD-32).
///
/// `executes` names the steps of a FROZEN workflow generation, and a pinned
/// group-private generation is verified against exactly those edges (their
/// `plan_index`, and each target's id and content). A plain `supersede_claim`
/// writes no `step_lineage_id`, so [`STEP_LINEAGE_FROZEN_RELATIONSHIPS`] never
/// applies to it, and the dedup and merge paths have no lineage rule at all:
/// without this set, each of them re-points (a merge of two executed steps also
/// retracts) the edge and the generation no longer verifies. A non-public
/// step's content changes only through a new generation.
///
/// The rule is read from the retired claim's row (`visibility <> 'public'`, a
/// missing row counting as non-public), never from a caller flag, because the
/// deferred replay of each cascade runs the same function knowing nothing of
/// the original caller. A PUBLIC claim keeps the previous behaviour.
pub(crate) const NON_PUBLIC_FROZEN_RELATIONSHIPS: &[&str] = &["executes"];

/// [`NON_PUBLIC_FROZEN_RELATIONSHIPS`] when `claim` is not public (or has no
/// row), else nothing: the relationships a replacement of `claim` must leave
/// on it.
async fn non_public_frozen_relationships(
    conn: &mut sqlx::PgConnection,
    claim: Uuid,
) -> Result<Vec<String>, DbError> {
    let non_public: bool = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; this read classifies the retired claim for the edge migration that follows.
        SELECT NOT EXISTS (
            SELECT 1 FROM claims WHERE id = $1 AND visibility::text = 'public')"#,
    )
    .bind(claim)
    .fetch_one(&mut *conn)
    .await?;
    Ok(if non_public {
        NON_PUBLIC_FROZEN_RELATIONSHIPS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        Vec::new()
    })
}

/// Relationships an AGENT holds on a step that a step-lineage supersession
/// leaves on the retired step (incoming edges with `source_type = 'agent'`).
///
/// `evolve_step` writes its successor under the CALLER's `agent_id`, not the
/// retired step's (unlike the supersede act, which keeps the old author). An
/// agent's `asserts` / `AUTHORED` edge records that THAT agent stated THAT
/// content; carried onto the successor it would record the agent asserting
/// content it never saw. (Scope U047 sub-decision A, default "exclude"; the
/// opposite ruling is removing this constant's use.)
pub(crate) const STEP_LINEAGE_AGENT_AUTHORSHIP_RELATIONSHIPS: &[&str] = &["asserts", "AUTHORED"];

/// Refuse a non-privileged session, naming `what` needs the privilege.
///
/// "Privileged" is migration 114's `epigraph_session_is_privileged_writer()`: a
/// superuser or BYPASSRLS role, a maintenance login, or a body running as the
/// maintenance role. The functions that call this re-point or remove rows
/// other writers own; since migration 117 a non-privileged session's
/// statements would match only its own rows and leave the rest behind with no
/// error, so they refuse instead of doing part of the job.
async fn require_privileged_session(
    conn: &mut sqlx::PgConnection,
    what: &str,
) -> Result<(), DbError> {
    let privileged: bool =
        sqlx::query_scalar("SELECT public.epigraph_session_is_privileged_writer()")
            .fetch_one(&mut *conn)
            .await?;
    if privileged {
        return Ok(());
    }
    Err(DbError::InvalidData {
        reason: format!(
            "{what} runs only on a privileged (maintenance) connection: it re-points or removes \
             rows other writers own, which a non-privileged session cannot touch (migration 117). \
             Run the caller's act on its own stamped transaction and this on the maintenance \
             connection (epigraph_engine::admin_cascade)."
        ),
    })
}

/// The two edge-migration statements of a supersession, unchecked: the
/// callers ([`ClaimRepository::supersede_conn`],
/// [`ClaimRepository::migrate_superseded_edges_conn`]) establish the privilege
/// and the supersession first.
///
/// Both directions carry the STRENGTHENING relationships forward and leave the
/// WEAKENING ones (`crate::repos::edge::WEAKENING_RELATIONSHIPS` — `refutes`,
/// `contradicts`) attached to the claim they were filed against or by; see the
/// "Edge migration policy" section of [`ClaimRepository::supersede`]'s doc
/// comment for why (issue #398).
///
/// A STEP-LINEAGE supersession (old and new share a non-null
/// `step_lineage_id`: `evolve_step(supersedes)`) also leaves
/// [`STEP_LINEAGE_FROZEN_RELATIONSHIPS`] on the retired step, and its agents'
/// [`STEP_LINEAGE_AGENT_AUTHORSHIP_RELATIONSHIPS`] edges. The rule is
/// derived from the rows, not from a caller flag, because the deferred replay
/// runs this same function knowing nothing of the original caller.
///
/// A supersession of a NON-PUBLIC claim also leaves
/// [`NON_PUBLIC_FROZEN_RELATIONSHIPS`] (`executes`) on it, lineage or not, so a
/// frozen group-private workflow generation keeps its plan (OD-32).
///
/// Neither direction moves a dedup identity edge
/// ([`DUPLICATE_IDENTITY_RELATIONSHIP`] carrying
/// [`DUPLICATE_IDENTITY_PROPERTY`]), as [`repair_marked_duplicate`] does not:
/// it names the claim its duplicate's `supersedes` names, and the un-mark and
/// the index view read it by that pointer. A duplicate of a canonical that is
/// later superseded (or consolidated) therefore keeps its edge to the retired
/// canonical, and stays marked: its un-mark follows the supersession (or
/// merge) to the current canonical and restores the duplicate against that one
/// (operator ruling R-11, [`ClaimRepository::unmark_chain_conn`]).
async fn migrate_superseded_edges(
    conn: &mut sqlx::PgConnection,
    old_uuid: Uuid,
    new_uuid: Uuid,
) -> Result<SupersedeEdgeMigration, DbError> {
    let weakening: Vec<String> = crate::repos::edge::WEAKENING_RELATIONSHIPS
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // Is this a step-lineage supersession? Both rows must carry the SAME
    // lineage: a plain supersede of a step writes a successor with no
    // `step_lineage_id` (supersede_act_conn's INSERT omits it), so the lineage
    // rule does not apply to it; its `executes` still moves unless the old
    // claim is non-public (`NON_PUBLIC_FROZEN_RELATIONSHIPS`, below).
    let step_lineage: bool = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; this read classifies the supersession the mutation below carries out.
        SELECT EXISTS (
            SELECT 1 FROM claims o JOIN claims n ON n.id = $1
             WHERE o.id = $2
               AND o.step_lineage_id IS NOT NULL
               AND n.step_lineage_id = o.step_lineage_id)"#,
    )
    .bind(new_uuid)
    .bind(old_uuid)
    .fetch_one(&mut *conn)
    .await?;
    let step_lineage_set = |set: &[&str]| -> Vec<String> {
        if step_lineage {
            set.iter().map(|s| (*s).to_string()).collect()
        } else {
            Vec::new()
        }
    };
    let mut frozen = step_lineage_set(STEP_LINEAGE_FROZEN_RELATIONSHIPS);
    for rel in non_public_frozen_relationships(&mut *conn, old_uuid).await? {
        if !frozen.contains(&rel) {
            frozen.push(rel);
        }
    }
    let agent_authorship = step_lineage_set(STEP_LINEAGE_AGENT_AUTHORSHIP_RELATIONSHIPS);

    // Migrate incoming edges: redirect edges pointing TO old claim to point
    // to new claim. `NOT (source_type = 'claim' AND source_id = $1)` is
    // mark_duplicate's self-loop guard, carried over so the two replacement
    // paths share one rule; see the doc comment for the one shape that
    // reaches it here.
    let retargeted: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE edges SET target_id = $1 \
         WHERE target_id = $2 AND target_type = 'claim' \
           AND relationship != 'supersedes' \
           AND NOT (relationship = ANY($3)) \
           AND NOT (relationship = ANY($4)) \
           AND NOT (source_type = 'agent' AND relationship = ANY($5)) \
           AND NOT (source_type = 'claim' AND source_id = $1) \
           AND NOT (relationship = 'same_as' AND properties ? 'dedup') \
         RETURNING id",
    )
    .bind(new_uuid)
    .bind(old_uuid)
    .bind(&weakening)
    .bind(&frozen)
    .bind(&agent_authorship)
    .fetch_all(&mut *conn)
    .await?;

    // Migrate outgoing edges: redirect edges FROM old claim to come from new claim
    let resourced: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE edges SET source_id = $1 \
         WHERE source_id = $2 AND source_type = 'claim' \
           AND relationship != 'supersedes' \
           AND NOT (relationship = ANY($3)) \
           AND NOT (relationship = ANY($4)) \
           AND NOT (target_type = 'claim' AND target_id = $1) \
           AND NOT (relationship = 'same_as' AND properties ? 'dedup') \
         RETURNING id",
    )
    .bind(new_uuid)
    .bind(old_uuid)
    .bind(&weakening)
    .bind(&frozen)
    .fetch_all(&mut *conn)
    .await?;

    Ok(SupersedeEdgeMigration {
        retargeted,
        resourced,
    })
}

/// Input for [`ClaimRepository::patch_claim_atomic_conn`].
#[derive(Debug, Clone, Default)]
pub struct PatchClaimInput {
    pub trace_id: Option<Uuid>,
    pub properties: Option<serde_json::Value>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
}

/// Which audited admin write [`ClaimRepository::admin_patch_claim_conn`] records.
///
/// A closed set, because it is written into the `security_events` audit row
/// and migration 111's function refuses anything else (`ADM03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminClaimAction {
    /// MCP `update_labels` / HTTP `PATCH /api/v1/claims/:id/labels`.
    UpdateLabels,
    /// MCP `patch_claim`.
    PatchClaim,
    /// The original's `resolved` label in MCP `resolve_backlog_item`.
    ResolveBacklogItem,
}

impl AdminClaimAction {
    /// The `action` string migration 111 records and accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpdateLabels => "update_labels",
            Self::PatchClaim => "patch_claim",
            Self::ResolveBacklogItem => "resolve_backlog_item",
        }
    }
}

/// What [`ClaimRepository::admin_patch_claim_conn`] wrote: the row's labels,
/// properties and trace after the write, and before it.
#[derive(Debug, Clone)]
pub struct AdminClaimWrite {
    pub labels: Vec<String>,
    pub properties: serde_json::Value,
    pub trace_id: Option<Uuid>,
    pub before_labels: Vec<String>,
    pub before_properties: serde_json::Value,
    pub before_trace_id: Option<Uuid>,
}

/// The token facts the audited admin path re-checks and records: the token's
/// `sub` (an `oauth_clients.id`) and its `jti`.
#[derive(Debug, Clone, Copy)]
pub struct AdminToken {
    pub client_id: Uuid,
    pub jti: Uuid,
}

/// Diff produced by [`ClaimRepository::patch_claim_atomic_conn`].
#[derive(Debug)]
pub struct PatchClaimDiff {
    pub before_labels: Vec<String>,
    pub after_labels: Vec<String>,
    pub before_props: serde_json::Value,
    pub after_props: serde_json::Value,
    pub before_trace: Option<Uuid>,
    pub after_trace: Option<Uuid>,
}

/// Build a Claim from database row data.
///
/// # The crypto fields are PLACEHOLDERS, not data
///
/// `content_hash` is **recomputed from `content`**, `public_key` is
/// `[0u8; 32]`, and `signature` is `None` — regardless of what the row says.
/// The older comment here claimed these columns "may not exist in the database
/// yet ... until the database schema is migrated"; that was false. `claims`
/// has carried `content_hash bytea NOT NULL`, `signature bytea` and
/// `signer_id uuid` (FK to `agents`, with the
/// `claims_signature_requires_signer` CHECK) since `001_initial_schema.sql`,
/// and `agents.public_key bytea NOT NULL` alongside them. The placeholders are
/// a projection gap, and the false comment is why it went unnoticed long
/// enough for MCP `verify_claim` to ship as theatre (backlog `49c17386`):
/// recomputing the digest makes `computed == stored` a tautology, so a
/// tampered body verified clean.
///
/// Callers that expose or verify crypto state MUST extend their `SELECT` and
/// post-fix the returned `Claim` via [`post_fix_crypto_columns`]. Exactly two
/// do: [`ClaimRepository::get_by_id`] and
/// [`ClaimRepository::get_by_id_with_labels`];
/// [`ClaimRepository::get_by_id_conn`] delegates to the first.
///
/// # The residual set is NOT just the bulk readers
///
/// Every other call site still returns fabricated crypto, and that includes
/// single-claim paths, not only list/search:
///
/// * single-claim reads — `find_by_content_hash_and_agent`, `get_by_agent`
/// * create paths that return the row they wrote — `create`, `create_with_tx`,
///   `create_strict`, `batch_create`
/// * single-claim updates that return the updated row — `update_truth_value`,
///   `update_truth_value_conn`, `update_trace_id`, `update_trace_id_conn`
/// * the bulk list/search readers (`list`, `list_by_labels`, `search_*`, …)
///
/// The create paths are the sharpest case: `create` INSERTs the caller's
/// `claim.content_hash` — which on the ingest path is a seed-scoped compound
/// digest, deliberately not `blake3(content)` — and then hands back a `Claim`
/// whose `content_hash` is `claim_from_row`'s recomputed `blake3(content)`, so
/// the read-back disagrees with the row just written. No current caller reads
/// that field off a create/update return, which is the only reason this is
/// latent rather than a live bug; anything promoted to a crypto-reading path
/// must move to the post-fix pattern first.
///
/// The bulk readers are left alone on cost grounds (a per-row `agents` join to
/// hydrate a field no summary projection reads). The single-claim ones above are
/// left alone only because nothing reads them — a weaker justification, recorded
/// here rather than glossed.
///
/// Its signature stays fixed (~20 call sites) per `CLAUDE.md`.
fn claim_from_row(
    id: Uuid,
    content: String,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    truth_value: TruthValue,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Claim {
    // Compute content hash from the content
    let content_hash_vec = ContentHasher::hash(content.as_bytes());
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_vec);

    // Placeholder public key - will be populated when DB schema includes it
    let public_key = [0u8; 32];

    // No signature from legacy DB records
    let signature = None;

    Claim::with_id(
        ClaimId::from_uuid(id),
        content,
        AgentId::from_uuid(agent_id),
        public_key,
        content_hash,
        trace_id.map(TraceId::from_uuid),
        signature,
        truth_value,
        created_at,
        updated_at,
    )
}

/// The crypto columns a single-claim reader must project to make
/// `claim_from_row`'s placeholders real: `claims.content_hash`,
/// `claims.signature`, and the signer's `agents.public_key` resolved through
/// `claims.signer_id`.
///
/// `signer_public_key` is `Option` because the join that supplies it MUST be a
/// `LEFT JOIN` — `signer_id` is NULL on every claim written by the `create*`
/// methods other than [`ClaimRepository::create_strict_signed`] (batch H-b's
/// MCP submission path), so an inner join would turn every single-claim read of
/// an unsigned row into "not found".
struct RowCryptoColumns {
    content_hash: Vec<u8>,
    signature: Option<Vec<u8>>,
    signer_public_key: Option<Vec<u8>>,
}

/// Replace [`claim_from_row`]'s fabricated crypto fields with the row's stored
/// values.
///
/// - `content_hash` is the **stored** digest, so a hash check against a
///   freshly computed digest is falsifiable: if the body was mutated without
///   rewriting the column, they differ. Note that "they differ" is not the same
///   as "the body was mutated" — the ingest writer stores a seed-scoped digest
///   on document-scoped compound rows, so a reader must classify before it
///   accuses (see `epigraph_mcp::tools::claims::verify_claim`).
/// - `signature` is `None` unless the column holds exactly
///   [`SIGNATURE_SIZE`](epigraph_crypto::SIGNATURE_SIZE) bytes. A wrong-length
///   blob is a corrupt signature, and `None` ("unsigned") is the only safe
///   reading — decoding it as valid is impossible and panicking on a row is
///   worse than reporting it unverifiable.
/// - `public_key` is the **signer's** key, not the author's. It stays
///   `[0u8; 32]` when `signer_id` is NULL: there is no signing agent, and
///   substituting `agents.public_key` for `claims.agent_id` would re-introduce
///   a fabricated value (and verify a signature against the wrong key if one
///   were ever present without a signer).
///
/// Both length checks are DEFENSIVE ONLY and unreachable through Postgres:
/// `001_initial_schema.sql` carries `CONSTRAINT claims_content_hash_length CHECK
/// (octet_length(content_hash) = 32)` and `CONSTRAINT claims_signature_length
/// CHECK (signature IS NULL OR octet_length(signature) = 64)`. They exist so the
/// `Vec<u8>` → fixed-array conversion has a defined answer rather than a panic,
/// not because a wrong-length row is an anticipated state.
///
/// # Errors
/// [`DbError::InvalidData`] if `content_hash` is not 32 bytes. Unlike the
/// signature there is no safe fallback: the column is `NOT NULL` and a
/// wrong-length digest means the row cannot be integrity-checked at all.
fn post_fix_crypto_columns(claim: &mut Claim, cols: RowCryptoColumns) -> Result<(), DbError> {
    let len = cols.content_hash.len();
    claim.content_hash =
        <[u8; 32]>::try_from(cols.content_hash.as_slice()).map_err(|_| DbError::InvalidData {
            reason: format!(
                "claims.content_hash for {} is {len} bytes, expected 32",
                claim.id.as_uuid()
            ),
        })?;

    claim.signature = match cols.signature {
        Some(sig) => match <[u8; epigraph_crypto::SIGNATURE_SIZE]>::try_from(sig.as_slice()) {
            Ok(sig) => Some(sig),
            Err(_) => {
                tracing::warn!(
                    claim_id = %claim.id.as_uuid(),
                    len = sig.len(),
                    "claims.signature is not 64 bytes; treating claim as unsigned"
                );
                None
            }
        },
        None => None,
    };

    claim.public_key = match cols.signer_public_key {
        Some(key) => match <[u8; 32]>::try_from(key.as_slice()) {
            Ok(key) => key,
            Err(_) => {
                tracing::warn!(
                    claim_id = %claim.id.as_uuid(),
                    len = key.len(),
                    "signer agents.public_key is not 32 bytes; leaving key unset"
                );
                [0u8; 32]
            }
        },
        None => [0u8; 32],
    };

    Ok(())
}

/// One claim row as the single-claim readers project it: the seven
/// `claim_from_row` columns plus the retirement state and the crypto columns
/// both post-fixes read. Shared by [`ClaimRepository::get_by_id`] and
/// [`ClaimRepository::get_by_id_with_labels`] (and, through delegation,
/// [`ClaimRepository::get_by_id_conn`]) so the mapping exists once.
///
/// Decoded through `query_as` + `FromRow`, never `sqlx::Row::get`: `Row::get`
/// panics on a missing column or a type mismatch, where a `FromRow` decode
/// returns `Err` for the same row.
#[derive(sqlx::FromRow)]
struct SingleClaimRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    is_current: bool,
    supersedes: Option<Uuid>,
    content_hash: Vec<u8>,
    signature: Option<Vec<u8>>,
    signer_public_key: Option<Vec<u8>>,
}

impl SingleClaimRow {
    /// Build the `Claim` and post-fix it with the row's real retirement state
    /// (instead of `claim_from_row`'s `is_current = true, supersedes = None`)
    /// and its stored crypto columns (instead of the recomputed digest and
    /// blank signature).
    ///
    /// # Errors
    /// * [`DbError::CoreError`] if `truth_value` is outside `[0, 1]`.
    /// * [`DbError::InvalidData`] if the stored `content_hash` is not 32 bytes.
    fn into_claim(self) -> Result<Claim, DbError> {
        let truth_value = TruthValue::new(self.truth_value)?;
        let mut claim = claim_from_row(
            self.id,
            self.content,
            self.agent_id,
            self.trace_id,
            truth_value,
            self.created_at,
            self.updated_at,
        );
        claim.is_current = self.is_current;
        claim.supersedes = self.supersedes.map(ClaimId::from_uuid);
        post_fix_crypto_columns(
            &mut claim,
            RowCryptoColumns {
                content_hash: self.content_hash,
                signature: self.signature,
                signer_public_key: self.signer_public_key,
            },
        )?;
        Ok(claim)
    }
}

/// [`SingleClaimRow`] plus `claims.labels`, for
/// [`ClaimRepository::get_by_id_with_labels`].
#[derive(sqlx::FromRow)]
struct SingleClaimRowWithLabels {
    #[sqlx(flatten)]
    row: SingleClaimRow,
    labels: Vec<String>,
}

impl ClaimRepository {
    /// The declaration a write path uses when its caller expressed no
    /// preference: **`('public', <the author's personal group>)`**.
    ///
    /// This is D2's shape, applied forward. The one-shot backfill stamps every
    /// pre-existing row `('public', <author's personal group>)` — those rows
    /// were already world-readable, so declaring `public` is a no-op rather
    /// than a new disclosure — and a new claim from a surface that has not yet
    /// grown a "which group?" parameter must land in the same place, or the
    /// corpus splits into two populations with different owners for no reason a
    /// reader could see.
    ///
    /// **It is not a default.** The distinction matters and is the whole of
    /// D1: a `DEFAULT` in `pg_attrdef` applies to a write that said nothing,
    /// with no principal in scope and nobody to hold responsible. This resolves
    /// a *named* agent's *own* group, fails if it cannot, and is spelled at
    /// every call site. Grepping this symbol enumerates exactly the surfaces
    /// that still owe their callers a visibility parameter.
    ///
    /// `ensure_personal_group` is idempotent and is already called for every
    /// authenticated principal at token mint (PR-02), so on a live path this is
    /// a lookup, not a write (migration 105's live path writes nothing).
    ///
    /// # An OPERATED author writes into its operator's group (migration 107)
    ///
    /// When `agent_id` has an ACTING operator link
    /// ([`AgentRepository::operator_actor`](crate::repos::AgentRepository::operator_actor)),
    /// the declaration is `('public', <the OPERATOR's personal group>)`. The
    /// agent holds `writer` there, so the author-stamped transaction it writes
    /// in (`epigraph_mcp::claim_helper::begin_author_stamped_tx`) can write the
    /// claim and every claim-derived row, and the operator — and every other
    /// agent it operates — owns what it wrote. Model upgrades mint new agent
    /// identities (`keypair_from_llm_agent`), so this is what keeps a job's work
    /// in one place across them.
    ///
    /// The operator lookup runs FIRST and goes through a `SECURITY DEFINER`
    /// read, so it answers correctly on an unstamped `epigraph_app` session,
    /// where `groups_tenancy` hides every row and a read-first lookup here
    /// would be blind. An unlinked, revoked or RETIRED author falls through to
    /// [`Self::personal_group_of`]; once the database is armed (migration 122)
    /// an unbound author is refused before that (`OPL01`), and a live-linked
    /// agent whose membership was revoked is refused after it (`OPL02`: its own
    /// personal group is not a group its operator writes).
    ///
    /// It is the ACTOR read, never the author read
    /// ([`AgentRepository::operator_of_author`](crate::repos::AgentRepository::operator_of_author)):
    /// a retired identity has no membership in its operator's group, so if it
    /// ever ran again and this chose that group, RLS would refuse every claim
    /// it wrote (`operator_link.rs::a_retired_agent_gains_no_write_authority`).
    ///
    /// # An UNBOUND author is refused first (migration 122)
    ///
    /// Once the database is armed, an author that is neither a human operator
    /// nor the holder of a live operator link is refused here with
    /// [`DbError::OperatorLinkRequired`] (`OPL01`), before its personal group is
    /// resolved (and so before one could be provisioned for it). The
    /// `claims_require_operator_binding` trigger is the guarantee on every
    /// path; this is the same check, earlier.
    ///
    /// # Errors
    /// Returns `DbError::OperatorLinkRequired` for an unbound author once the
    /// database is armed, `DbError::MembershipRevoked` if the author holds only
    /// revoked rows in its personal group (and has no acting operator link),
    /// `DbError::ForeignKeyViolation` if `agent_id` names no agent, and
    /// `DbError::QueryFailed` for other database failures — including a
    /// database that has not applied migration 107, which fails CLOSED here
    /// rather than authoring as if the author had no operator.
    pub async fn default_decl_for_author(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<TenancyDecl, DbError> {
        if let Some(link) = crate::repos::AgentRepository::operator_actor(conn, agent_id).await? {
            // An acting link is a live (not retired) link. It binds (migration
            // 122) only while its operator is a registered human operator; if
            // not, the claims trigger refuses the write (OPL01), not this read.
            return Ok(TenancyDecl::public(link.operator_group_id));
        }
        // Refuse an unbound author BEFORE 105's definer can provision a
        // personal group for an agent that may not write at all.
        crate::repos::AgentRepository::require_bound_author(conn, agent_id).await?;
        let group = Self::personal_group_of(conn, agent_id).await?;
        // A live-linked agent that is not ACTING (its membership was revoked)
        // falls back to its own personal group, which its operator does not
        // write: refused here by name (OPL02, 122 section 1b) rather than by
        // the trigger after the caller built the whole write.
        //
        // For an allowlisted author (migration 149) this is quiet: the door
        // reads links only. Its as-itself write lands in its own personal
        // group, and the claims trigger's writer scope is the refusal (OPL02).
        // The allowlist does not re-home the agent's own authorship.
        crate::repos::AgentRepository::require_operator_scope(conn, agent_id, group).await?;
        Ok(TenancyDecl::public(group))
    }

    /// The `(id, visibility, owner_group_id)` of each of `ids` that `viewer`
    /// may read, in no particular order.
    ///
    /// Filtered twice: by `viewer`'s predicate in the SQL, and by row security
    /// on `conn`'s own stamp, which may be a different principal's. An id
    /// missing from the answer is a claim that does not exist or that one of
    /// the two may not read. It is the question a declared-tenancy workflow
    /// ingest asks about the claims it REUSED rather than created
    /// (`epigraph_ingest_executor`'s `reused_items`): on the system-agent
    /// stamped transaction, through the CALLER's viewer, so the answer never
    /// tells a caller the tenancy of a claim it cannot read.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn tenancy_of_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String, Uuid)>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "SELECT id, visibility::text, owner_group_id FROM claims \
              WHERE id = ANY($1) /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String, Uuid)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// The `(id, visibility, owner_group_id)` of each of `ids` that `conn`'s own
    /// session may read, in no particular order.
    ///
    /// Row security on `conn`'s stamp is the ONLY filter: there is no viewer
    /// predicate, so this answers "what can the principal this connection is
    /// stamped as see", never a caller's question. A declared-tenancy workflow
    /// ingest asks it on its system-agent stamped transaction about the claims
    /// it REUSED, before it writes an edge to any of them: an id missing from
    /// the answer is a claim that exists (the ingest's `ON CONFLICT` saw it)
    /// but that the stamp cannot read. Never return this answer to a caller; it
    /// is the stamp's view, not theirs ([`Self::tenancy_of_conn`] is the
    /// caller-filtered read).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn tenancy_on_session_conn(
        conn: &mut sqlx::PgConnection,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, String, Uuid)>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Ok(sqlx::query_as::<_, (Uuid, String, Uuid)>(
            "SELECT id, visibility::text, owner_group_id FROM claims WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// The id of `agent_id`'s personal group, resolved by the `SECURITY DEFINER`
    /// function alone: **no read on the caller's connection first.**
    ///
    /// # Why the read-first lookup was removed (batch F)
    ///
    /// This used to `SELECT id FROM groups WHERE did_key = …` on the caller's
    /// connection and call `ensure_personal_group` only on a miss, and the doc
    /// called that order a SECURITY property: migration 077's function revived a
    /// revoked membership as admin, and the lookup was what kept a write path
    /// from reaching it. The property held only where the lookup could see the
    /// row, and the callers were not all such places:
    ///
    /// * on an UNSTAMPED `epigraph_app` connection — `default_decl_for_author_pool`
    ///   from the API routes, `personal_group_of_pool` from the recall audit
    ///   (#493) — `groups_tenancy` hides every group, so the read was BLIND and
    ///   every call took the reviving mint;
    /// * on a BYPASSRLS connection (the operator CLI's maintenance pool, the
    ///   `Privileged` ingest arm) the read was not blind, and so it returned the
    ///   personal group of an agent whose membership was REVOKED — a claim
    ///   authored by a revoked agent was quietly owned by the group it had been
    ///   revoked from.
    ///
    /// Migration 105 moved the discrimination into the function, which reads
    /// every row in its definer frame: a live membership returns the group with
    /// no write, only-revoked rows raise [`DbError::MembershipRevoked`], and only
    /// an agent with no row at all is provisioned. Calling it directly gives the
    /// SAME answer on every connection role, which a read on the caller's
    /// connection cannot.
    ///
    /// The `did_key` is the deterministic `did:epigraph:personal:<agent_uuid>`,
    /// spelled once, in the function: nothing on `agents` records which group is
    /// the personal one.
    ///
    /// # Errors
    /// Returns [`DbError::MembershipRevoked`] if the agent holds only revoked
    /// rows in its personal group, `DbError::ForeignKeyViolation` if `agent_id`
    /// names no agent (the mint path FKs to `agents`), and
    /// `DbError::QueryFailed` otherwise.
    async fn personal_group_of(
        conn: &mut sqlx::PgConnection,
        agent_id: Uuid,
    ) -> Result<Uuid, DbError> {
        crate::repos::AgentRepository::ensure_personal_group(conn, agent_id).await
    }

    /// [`Self::default_decl_for_author`] for a caller holding a pool rather
    /// than a connection.
    ///
    /// # Errors
    /// As [`Self::default_decl_for_author`], plus `DbError::ConnectionFailed`
    /// if no connection can be acquired.
    pub async fn default_decl_for_author_pool(
        pool: &PgPool,
        agent_id: Uuid,
    ) -> Result<TenancyDecl, DbError> {
        let mut conn = pool.acquire().await?;
        Self::default_decl_for_author(&mut conn, agent_id).await
    }

    /// [`Self::personal_group_of`] for a caller holding a pool, and for a
    /// caller that wants the GROUP rather than the `public` declaration
    /// [`Self::default_decl_for_author_pool`] wraps it in.
    ///
    /// Exists because not every row an agent owns is a row anyone else should
    /// read. `default_decl_for_author_pool` is the right answer for a claim —
    /// the corpus is shared and the author's group is who a later privatization
    /// acts on — and the wrong one for a private audit row, which wants the
    /// same owner and `visibility = 'group'`. Returning the id keeps that
    /// choice at the call site instead of hiding it in a helper's name.
    ///
    /// Resolved by the definer function alone, never by a read on the pool's
    /// (unstamped) connection — see [`Self::personal_group_of`]. It has no
    /// production caller since the recall audit stopped using it (#493); the
    /// audit must never provision, and this can.
    ///
    /// # Errors
    /// As [`Self::personal_group_of`], plus `DbError::ConnectionFailed` if no
    /// connection can be acquired.
    pub async fn personal_group_of_pool(pool: &PgPool, agent_id: Uuid) -> Result<Uuid, DbError> {
        let mut conn = pool.acquire().await?;
        Self::personal_group_of(&mut conn, agent_id).await
    }

    /// The grounded embedding neighborhood of a query vector, read through a
    /// `Viewer`.
    ///
    /// "Grounded" is the caller's existing definition and is unchanged: a claim
    /// counts only if some `paper` / `evidence` / `analysis` row asserts,
    /// supports, concludes or provides evidence for it. Claim-to-claim
    /// propagation alone is not grounded evidence.
    ///
    /// # Why this exists rather than an inline route read
    ///
    /// `routes/hypothesis.rs::create_hypothesis` ran this statement inline
    /// against a pool, with no viewer, and returned aggregate statistics
    /// derived from it — so the aggregates were functions of rows the caller
    /// may not read. That is latent only while the corpus is entirely public,
    /// and `routes/privatization.rs` makes private claims producible today.
    /// `viewer_route_table_lint.rs::UNCOMPENSATED_INLINE_READS` carried it as
    /// `("hypothesis.rs", 1)`: the statement names `FROM claims` and projects
    /// `embedding`, which is the tier-A content column set the register
    /// matches, so it was counted debt rather than an unseen read. This moves
    /// it to the repo layer, where CLAUDE.md says the SQL belongs, and retires
    /// that register entry.
    ///
    /// # Both relations are marked
    ///
    /// `claims c` carries `/* {VISIBILITY:c} */` and the grounding subquery's
    /// `edges e` carries `/* {EDGE_VISIBILITY:e} */`. Marking only the outer
    /// relation would leave the *grounding decision* — and therefore
    /// `neighbor_count` — a function of edges the viewer cannot see. Both
    /// markers resolve to the SAME bind index, so the statement still binds
    /// [`Viewer::group_bind`](crate::visibility::Viewer::group_bind) exactly
    /// once. Migration 070 makes an edge inherit its endpoints' tenancy, so on
    /// a public claim the edge predicate is satisfied by the leading `public`
    /// disjunct and the result is unchanged; it becomes load-bearing exactly
    /// when the endpoints are private.
    ///
    /// **The edge marker is defense in depth and is NOT what the acceptance
    /// test proves**, which is stated rather than left for a reader to assume.
    /// Because 070 makes the edge inherit, a private claim's grounding edge is
    /// private too, and the edge predicate alone would exclude the neighbour
    /// whatever the `claims` predicate did — a test built that way passes with
    /// the `claims` filter removed. So
    /// `hypothesis_ownership_from_principal.rs::hypothesis_voi_neighborhood_excludes_claims_the_caller_cannot_read`
    /// forces the grounding edge public, leaving the `claims` predicate as the
    /// only thing that can exclude the row.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn grounded_neighborhood<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_vector: &str,
        exclude: Uuid,
        min_similarity: f64,
        limit: i64,
    ) -> Result<Vec<GroundedNeighbor>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.belief, c.plausibility,
                   1 - (c.embedding <=> $1::vector) AS similarity
            FROM claims c
            WHERE c.embedding IS NOT NULL
              AND c.id != $2
              AND 1 - (c.embedding <=> $1::vector) >= $3
              AND EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.target_id = c.id
                    AND e.target_type = 'claim'
                    AND e.source_type IN ('paper', 'evidence', 'analysis')
                    AND e.relationship IN ('asserts', 'SUPPORTS', 'supports', 'concludes', 'provides_evidence')
                    /* {EDGE_VISIBILITY:e} */
              )
              /* {VISIBILITY:c} */
            ORDER BY similarity DESC
            LIMIT $4
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, GroundedNeighbor>(&sql)
            .bind(query_vector)
            .bind(exclude)
            .bind(min_similarity)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Create a new claim in the database (LEGACY — implicit content-hash dedup)
    ///
    /// **Legacy behavior:** dedups on `content_hash` alone (NOT on
    /// `(content_hash, agent_id)`), so a request from agent B with the same
    /// content as an earlier claim from agent A returns agent A's row. This is
    /// a noun-claim invariant violation. New code should use
    /// `find_by_content_hash_and_agent` + `create_or_get` / `create_strict`
    /// (see `docs/architecture/noun-claims-and-verb-edges.md`). The ~44
    /// internal callers of this method are migrated as a separate
    /// out-of-band task.
    ///
    /// **Concurrency:** a first, unlocked find answers a dedup HIT on an
    /// already-committed row without taking any lock. On a miss, the find is
    /// re-run and the insert made under [`Self::lock_content_hash_agent`] for
    /// the `(content_hash, agent_id)` the INSERT writes, inside one scope (a
    /// real `BEGIN` on a bare connection, a SAVEPOINT in a caller's
    /// transaction). Two concurrent first creates of one pair therefore yield
    /// one row, and the lock is shared with `create_or_get`. Creates of the
    /// same content by DIFFERENT agents are not serialized against each other.
    ///
    /// `decl` declares the row's tenancy. Migration 074 drops the
    /// `visibility` / `owner_group_id` defaults, so a write that names neither
    /// and has no parent to inherit from raises `23502`. This method's INSERT
    /// binds no parent at all, so [`TenancyDecl::Inherited`] here reaches the
    /// seed escape hatch for a test-harness role and raises for an application
    /// role — which is the intended asymmetry, not an oversight. See
    /// `docs/tenancy.md#declaring-visibility-on-write`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, claim))]
    pub async fn create(pool: &PgPool, claim: &Claim, decl: TenancyDecl) -> Result<Claim, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_conn(&mut conn, claim, decl).await
    }

    /// [`Self::create`] on a connection the caller owns — the form a
    /// tenancy-stamped transaction can reach.
    ///
    /// The pool-taking wrapper above delegates here, so the dedup probe, the
    /// INSERT and the event are one implementation. `ingest_document`'s atoms
    /// (level 3, content-addressed) are written through it, and on an unstamped
    /// checkout migration 077's `claims_tenancy` `WITH CHECK` refuses the INSERT
    /// on a cleanly-migrated schema; handed `&mut *tx` from
    /// `ScopedPool::begin_as(author_viewer)` the atom rides the same transaction
    /// as the document's other rows.
    ///
    /// The `claim.created` event moved to `publish_or_log_conn`: it is a
    /// SWALLOWED failure, and inside a caller's transaction a swallowed failure is
    /// a deferred silent ROLLBACK at COMMIT unless it is SAVEPOINT-wrapped (hard
    /// constraint #6). On a bare pooled connection that SAVEPOINT is a real
    /// `BEGIN`/`COMMIT` around the one INSERT, which is what the pool path did.
    ///
    /// # Errors
    /// As [`Self::create`].
    pub async fn create_conn(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
        decl: TenancyDecl,
    ) -> Result<Claim, DbError> {
        use sqlx::Acquire;

        // A dedup HIT on an already-committed row is answered here, unlocked
        // and outside any scope, exactly as before the dedup lock existed. Only
        // a MISS goes on to take the lock: inside `ingest_document`'s document
        // transaction a lock taken on a hit would be held until the whole
        // document commits, so two same-author ingests sharing pre-existing
        // atoms would serialize (and could deadlock) on rows neither writes.
        // This find decides nothing on a miss; the one under the lock does.
        let content_hash = ContentHasher::hash(claim.content.as_bytes());
        if let Some(existing) =
            Self::find_by_content_hash_legacy_conn(&mut *conn, content_hash.as_slice()).await?
        {
            return Ok(existing);
        }

        // The serialization scope, exactly as in `create_or_get_signed`: a real
        // BEGIN on a bare connection (the `create(pool)` path, where an
        // advisory xact lock taken in autocommit would be released at the end
        // of its own statement), a SAVEPOINT inside the caller's transaction
        // (the lock then lives until the caller's transaction ends). Closed
        // explicitly on every path below.
        let mut scope = conn
            .begin()
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        match Self::create_conn_serialized(&mut scope, claim, decl).await {
            Ok(out) => {
                scope
                    .commit()
                    .await
                    .map_err(|source| DbError::QueryFailed { source })?;
                Ok(out)
            }
            Err(e) => {
                scope
                    .rollback()
                    .await
                    .map_err(|source| DbError::QueryFailed { source })?;
                Err(e)
            }
        }
    }

    /// The legacy content-hash dedup probe of [`Self::create_conn`]: any row
    /// with this `content_hash`, by any agent. Run twice by a create that
    /// misses: unlocked first (a hit returns without taking the dedup lock),
    /// then again under the lock, where its answer decides the insert.
    async fn find_by_content_hash_legacy_conn(
        conn: &mut sqlx::PgConnection,
        content_hash: &[u8],
    ) -> Result<Option<Claim>, DbError> {
        let existing = sqlx::query!(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
               SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
               FROM claims WHERE content_hash = $1 LIMIT 1"#,
            content_hash
        )
        .fetch_optional(&mut *conn)
        .await?;

        existing
            .map(|row| {
                let tv = TruthValue::new(row.truth_value)?;
                Ok(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    tv,
                    row.created_at,
                    row.updated_at,
                ))
            })
            .transpose()
    }

    /// The miss path of [`Self::create_conn`], run inside its serialization
    /// scope: the `(content_hash, agent_id)` dedup lock, the legacy
    /// content-hash find again (now deciding), then the insert.
    async fn create_conn_serialized(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
        decl: TenancyDecl,
    ) -> Result<Claim, DbError> {
        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;

        // Calculate content hash using BLAKE3
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        // Serialize against every other find-then-insert of this
        // `(content_hash, agent_id)` — `create_or_get`, POST /claims, a
        // consolidation, and another caller of this method — before the
        // deciding find (backlog 00f1a517). Without it two first creates both
        // miss the find (neither can see the other's uncommitted row) and both
        // insert. The find stays content-hash-only (the legacy contract); the
        // lock serializes the pair the INSERT writes.
        Self::lock_content_hash_agent(&mut *conn, content_hash.as_slice(), agent_id).await?;

        // Dedup, re-run under the lock: a new statement under READ COMMITTED,
        // so it sees a row a previous lock holder committed after
        // `create_conn`'s unlocked probe missed. If a claim with this content
        // now exists, return it instead of inserting a duplicate.
        if let Some(existing) =
            Self::find_by_content_hash_legacy_conn(&mut *conn, content_hash.as_slice()).await?
        {
            return Ok(existing);
        }

        let row = sqlx::query!(
            r#"
            INSERT INTO claims (
                id, content, content_hash, truth_value, agent_id, trace_id,
                created_at, updated_at, visibility, owner_group_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            id,
            claim.content,
            content_hash.as_slice(),
            truth_value,
            agent_id,
            trace_id,
            created_at,
            updated_at,
            decl.visibility_bind(),
            decl.owner_group_bind()
        )
        .fetch_one(&mut *conn)
        .await?;

        // Fire-and-forget claim.created event (closes #61). This is the
        // central emit for ALL writers that go through ClaimRepository::create
        // (MCP ingestion paths, API conventions, paper repo, tests). The
        // dedup early-return above does NOT emit, so resubmissions of an
        // existing content_hash do not pollute the audit log.
        let _ = crate::repos::EventRepository::publish_or_log_conn(
            &mut *conn,
            "claim.created",
            Some(row.agent_id),
            &serde_json::json!({
                "claim_id": row.id,
                "agent_id": row.agent_id,
                "truth_value": row.truth_value,
            }),
        )
        .await;

        let truth_value = TruthValue::new(row.truth_value)?;

        Ok(claim_from_row(
            row.id,
            row.content,
            row.agent_id,
            row.trace_id,
            truth_value,
            row.created_at,
            row.updated_at,
        ))
    }

    /// Set the `properties` JSONB column on an existing claim. Overwrites the
    /// existing value (does not merge). Used by ingest to attach hierarchy
    /// metadata (level, section, source_type, generality) at creation time.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn set_properties(
        pool: &PgPool,
        claim_id: ClaimId,
        properties: serde_json::Value,
    ) -> Result<(), DbError> {
        let mut conn = pool.acquire().await?;
        Self::set_properties_conn(&mut conn, claim_id, properties).await
    }

    /// [`Self::set_properties`] on a connection the caller owns, so an ingest's
    /// hierarchy metadata lands in the same stamped transaction as the claim it
    /// describes. `rows_affected() == 0` stays an ERROR here, and that matters
    /// more on a stamped connection than it did on the pool: an `UPDATE` that
    /// `claims_tenancy`'s USING hides matches zero rows WITHOUT raising, so this
    /// check is what keeps an invisible target from reading as success.
    ///
    /// # Errors
    /// As [`Self::set_properties`].
    pub async fn set_properties_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: ClaimId,
        properties: serde_json::Value,
    ) -> Result<(), DbError> {
        let id: Uuid = claim_id.into();
        let result = sqlx::query!(
            "UPDATE claims SET properties = $2, updated_at = NOW() WHERE id = $1",
            id,
            properties
        )
        .execute(&mut *conn)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id,
            });
        }
        Ok(())
    }

    /// Read a claim's whole `properties` JSONB.
    ///
    /// `Ok(None)` means there is no such claim; a claim with a NULL column reads
    /// back as `Ok(Some(json!({})))` so callers can treat "no properties" and
    /// "empty properties" alike.
    ///
    /// Exists for readers that must classify a row by its ingest provenance
    /// rather than act on one key — MCP `verify_claim` needs `level` and
    /// `source_type` together to tell a document-scoped compound digest (which
    /// is NOT `blake3(content)` by construction) from a body/digest
    /// disagreement. Deliberately the whole object and not a `->>` projection:
    /// the predicate lives next to the writer in
    /// `epigraph_ingest::document::stored_content_hash_is_seed_scoped`, so the
    /// repo layer must not re-encode which keys matter. (Its workflow subset is
    /// re-derived rather than left undecided: the seed is recovered through
    /// `WorkflowRepository::executing_canonical_names`.)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn get_properties(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: ClaimId,
    ) -> Result<Option<serde_json::Value>, DbError> {
        let id: Uuid = claim_id.into();
        // Runtime `query_scalar`, not the `query!` macro: adding a macro call
        // would require regenerating `.sqlx`.
        //
        // Viewer-scoped like every other claim read. This one took `&PgPool`
        // rather than `PgConnection`/`PgExecutor` and never called `splice`, so
        // it sat in the one gap none of the four ratchets cover:
        // `every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt` selects on
        // `PgConnection`, `every_executor_taking_repo_fn_...` on `PgExecutor`,
        // `every_spliced_statement_carries_the_canonical_marker_spelling` on
        // `.splice(`, and `no_unscoped_pool` scans handler call sites for
        // `state.db_pool` (this caller is MCP, on `server.pool`). A passing test
        // suite was no evidence either way: `splice` panics on a missing marker,
        // but only for statements that call it at all.
        let sql = viewer.splice(
            "SELECT COALESCE(properties, '{}'::jsonb) FROM claims \
             WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_scalar(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let props: Option<serde_json::Value> = q.fetch_optional(pool).await?;
        Ok(props)
    }

    /// Read a claim's workflow-promotion flag
    /// (`properties->'promotion'->>'promotable'`). `None` when the claim was
    /// never evaluated (or does not exist); `Some(bool)` otherwise. Used by
    /// `find_workflow` to surface whether a variant has been promoted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn promotion_flag<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: ClaimId,
    ) -> Result<Option<bool>, DbError> {
        let id: Uuid = claim_id.into();
        let sql = viewer.splice(
            "SELECT (properties->'promotion'->>'promotable')::bool FROM claims \
             WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Option<bool>>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let flag: Option<Option<bool>> = q.fetch_optional(executor).await?;
        Ok(flag.flatten())
    }

    /// Read a claim's cached Dempster–Shafer belief columns
    /// (`belief`, `plausibility`, `pignistic_prob`, `mass_on_empty`,
    /// `mass_on_missing`).
    ///
    /// These are the columns the edge-wiring recompute path
    /// (`MassFunctionRepository::update_claim_belief`) writes — distinct from
    /// `truth_value`, which the recompute leaves untouched. Callers that need
    /// the *post-wire* combined belief (e.g. the MCP `link_epistemic` readback)
    /// must read these columns, NOT `truth_value`; the unframed
    /// `belief_query::get_belief` path reads `truth_value` and so does not
    /// reflect a recompute. `mass_on_empty` and `mass_on_missing` round out the
    /// set needed to fully reconstruct a claim's cached DS interval
    /// (mass_on_conflict == mass_on_empty, mass_on_missing).
    ///
    /// Returns `Ok(None)` when the claim does not exist; the columns inside
    /// [`ClaimBeliefColumns`] are individually `Option` (NULL when the claim
    /// has never had a BBA combined onto it).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_belief_columns<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: ClaimId,
    ) -> Result<Option<ClaimBeliefColumns>, DbError> {
        let id: Uuid = claim_id.into();
        let sql = viewer.splice(
            "SELECT belief, plausibility, pignistic_prob, mass_on_empty, mass_on_missing \
             FROM claims WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimBeliefColumns>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<ClaimBeliefColumns> = q.fetch_optional(executor).await?;
        Ok(row)
    }

    /// The scalar an epistemic quality gate (`min_truth`) should compare
    /// against, for a whole page of claims in ONE round-trip.
    ///
    /// Backlog `14b98adc`. `claims.truth_value` is an **independently authored**
    /// scalar: `submit_claim` and `update_with_evidence` seed it from BetP, but
    /// `patch_claim`, `POST /api/v1/claims`, `routes/conventions.rs` and
    /// `tools/workflows.rs` all set it directly, and NO Dempster–Shafer write
    /// path ever refreshes it — `auto_wire_ds_for_edge` →
    /// `recompute_combined_belief` and `recompute_beliefs` both write
    /// `claims.{belief, plausibility, pignistic_prob, …}` and leave
    /// `truth_value` alone. So the two columns agree only until the first
    /// epistemic edge is wired, after which a thoroughly refuted claim still
    /// carries its pre-edge `truth_value` (production 2026-09-07: claim
    /// `8f192373` at `truth_value` 1.0000 against BetP 0.1797).
    ///
    /// Because `truth_value` has independent authorship, syncing it FROM the DS
    /// state is the wrong repair — a third party's `refutes` edge would silently
    /// overwrite an operator-set value. The repair is that the *gate* reads the
    /// DS state, which is what this method returns.
    ///
    /// The selection is the exact SQL twin of `belief_query::get_belief`'s
    /// unframed branch, deliberately including its both-of-`(belief,
    /// plausibility)` guard: a bare `COALESCE(pignistic_prob, belief,
    /// truth_value)` would report a half-written DS row as authoritative, which
    /// is precisely what that guard exists to prevent. `truth_value` is
    /// `NOT NULL` (migration 001), so the `ELSE` arm always yields a value and
    /// the returned `f64` is never null.
    ///
    /// Claims absent from the returned map are absent because the **viewer
    /// cannot see them** (or they were deleted mid-page). Callers must fall back
    /// to the `truth_value` they already hydrated rather than treating absence
    /// as pass-or-drop — see the four `min_truth` call sites
    /// (`epigraph-mcp` `tools::memory::recall_post_embed`,
    /// `tools::recall::recall_with_context_post_embed`, `tools::graph::traverse`,
    /// and `epigraph-engine` `recall::effective_beliefs`).
    ///
    /// One caller is not a gate: `recall_with_context_post_embed` adds its
    /// hits' context-atom ids to the same batch and reports each atom's value
    /// as that atom's `belief_score`. It relies on the same fall-back contract,
    /// so an atom absent from the map keeps its `truth_value`.
    ///
    /// `claim_ids` is kept out of the tracing span (only its length is
    /// recorded): that context-atom page can carry thousands of ids.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, claim_ids), fields(claim_count = claim_ids.len()))]
    pub async fn effective_belief_batch<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, f64>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // `concat`, not `format!`: the marker stays a plain literal, so the
        // marker scanners in `tests/visibility_lint.rs` read it as written.
        let sql = viewer.splice(
            &[
                "SELECT id, ",
                EFFECTIVE_BELIEF_SCORE_SQL,
                " AS score FROM claims WHERE id = ANY($1) /* {VISIBILITY:claims} */",
            ]
            .concat(),
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, f64)>(&sql).bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?.into_iter().collect())
    }

    /// Walk a claim's supersession chain and return every version the viewer
    /// may see, oldest first (`depth` 0 = root).
    ///
    /// Backs `GET /api/v1/claims/:id/history`. Returns an empty vector when
    /// `claim_id` does not exist **or the viewer cannot see it** — the caller
    /// renders both as 404, so the endpoint stops being an existence oracle.
    ///
    /// A chain whose *ancestors* are invisible is NOT empty: the walk is
    /// rooted at the deepest visible ancestor, so a viewer that can read a
    /// claim always gets that claim back even when an earlier revision is
    /// another tenant's. Versions the viewer cannot see are omitted from the
    /// chain rather than truncating it to nothing.
    ///
    /// # Forked chains
    ///
    /// A fork (two claims superseding the same claim) returns both branches,
    /// interleaved by depth. Two things make that well-defined rather than
    /// nondeterministic:
    ///
    /// * The final `ORDER BY chain.depth, chain.id` is a **total** order.
    ///   `ORDER BY depth` alone is not — two rows at the same depth could come
    ///   back in either order, and because the handler derives the version
    ///   number from row position, two identical requests could report
    ///   different version numbers for the same claim.
    /// * `superseded_by` is selected from `claims.supersedes` rather than
    ///   inferred by the handler as "the following row's id". Positional
    ///   inference is simply wrong at a fork point, and forks are reachable:
    ///   `mark_duplicate` points every duplicate at the same canonical claim.
    ///
    /// # Cycle safety
    ///
    /// `mark_duplicate` refuses only when the *duplicate* is already
    /// superseded, so `A.supersedes = B` followed by `B.supersedes = A` is
    /// accepted and forms a cycle; a self-supersede `A.supersedes = A` is the
    /// degenerate case. Two guards, for two different failures:
    ///
    /// * **`CYCLE id SET … USING …` on both recursive CTEs** makes each version
    ///   appear exactly once. Postgres still emits the row that revisits an id
    ///   (flagged `*_is_cycle`) but does not expand it, so the flag is filtered
    ///   in `root` and in the final SELECT. Without it a cycle is walked until
    ///   the depth cap: a self-loop came back as the same row 101 times and
    ///   X↔Y as 101 alternating rows, and from X the root was X itself rather
    ///   than Y, the deepest non-revisited ancestor. Requires PostgreSQL 14+.
    /// * **Both recursive terms stay capped at depth 100.** The cycle guard
    ///   does not bound a long ACYCLIC chain; the cap does. Without any bound a
    ///   cycle pins one backend at 100% CPU building an unbounded tuplestore
    ///   that spills to disk, and the request pool sets no `statement_timeout`
    ///   to stop it. 100 is far above any real supersession depth.
    ///
    /// # Why one statement and not a loop
    ///
    /// Before PR-07 the handler ran this as an N+1 walk of three inline
    /// statements (`SELECT supersedes …`, `SELECT id, content … `,
    /// `SELECT id … WHERE supersedes = $1`), none of them filtered. Beyond the
    /// round trips, a per-row loop is the wrong shape for a visibility
    /// predicate: filtering each step individually would let a chain be walked
    /// *through* a version the reader cannot see, disclosing the existence and
    /// position of hidden revisions even while withholding their content. A
    /// single recursive CTE with the predicate on every branch cannot do that
    /// — an invisible link terminates the walk.
    ///
    /// `is_current` is `COALESCE(is_current, true)`, matching the handler's
    /// prior semantics for rows predating the column.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn version_history<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<ClaimVersionHit>, DbError> {
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE up AS (
                SELECT c.id, c.supersedes, 0::int4 AS up_depth
                FROM claims c
                WHERE c.id = $1 /* {VISIBILITY:c} */
              UNION ALL
                SELECT p.id, p.supersedes, up.up_depth + 1
                FROM claims p
                JOIN up ON p.id = up.supersedes
                WHERE up.up_depth < 100 /* {VISIBILITY:p} */
            -- CYCLE, not merely the depth bound. `mark_duplicate` writes
            -- `dup.supersedes = canonical` with no cycle check, so X<->Y and
            -- X->X loops are writable through the repo (how many exist in prod
            -- data was never counted). `up_depth < 100` stops the walk
            -- running forever, but it does NOT stop it EMITTING: MEASURED on a
            -- database migrated 001->head, a self-supersedes loop came back as
            -- the same row 101 times and an X<->Y pair as 101 alternating rows,
            -- which `GET /claims/:id/history` served verbatim (~50x response
            -- amplification). `CYCLE ... SET ... USING ...` still EMITS the row
            -- that revisits an id, flagged, but stops expanding it; so the flag
            -- is filtered in BOTH consumers -- `root` below (or the revisited
            -- start claim would be picked as the deepest ancestor) and the
            -- final SELECT. The depth bound stays as a second guard. Both
            -- recursive terms keep their visibility splices, so this costs no
            -- tenancy filtering.
            ) CYCLE id SET up_is_cycle USING up_path,
            -- The DEEPEST VISIBLE ancestor, not the true root. `up` already
            -- stops at the first link the viewer cannot see, so requiring
            -- `supersedes IS NULL` here would return nothing whenever a
            -- visible claim has an invisible ancestor — a 404 on a read the
            -- caller is entitled to. When the whole chain is visible the
            -- deepest row IS the `supersedes IS NULL` root, so this is the
            -- same answer for the fully-visible case.
            root AS (
                SELECT id FROM up WHERE NOT up_is_cycle ORDER BY up_depth DESC LIMIT 1
            ),
            chain AS (
                SELECT r0.id,
                       r0.content,
                       r0.truth_value,
                       COALESCE(r0.is_current, true) AS is_current,
                       r0.created_at,
                       0::int4 AS depth
                FROM claims r0
                JOIN root ON root.id = r0.id
                WHERE true /* {VISIBILITY:r0} */
              UNION ALL
                SELECT n.id,
                       n.content,
                       n.truth_value,
                       COALESCE(n.is_current, true) AS is_current,
                       n.created_at,
                       chain.depth + 1
                FROM claims n
                JOIN chain ON n.supersedes = chain.id
                WHERE chain.depth < 100 /* {VISIBILITY:n} */
            ) CYCLE id SET chain_is_cycle USING chain_path
            SELECT chain.id,
                   chain.content,
                   chain.truth_value,
                   chain.is_current,
                   chain.created_at,
                   chain.depth,
                   (
                       SELECT n2.id
                       FROM claims n2
                       WHERE n2.supersedes = chain.id /* {VISIBILITY:n2} */
                       ORDER BY n2.created_at, n2.id
                       LIMIT 1
                   ) AS superseded_by
            FROM chain
            WHERE NOT chain_is_cycle
            ORDER BY chain.depth, chain.id
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimVersionHit>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Flat pgvector ANN search over `claims.embedding`.
    ///
    /// Backs the **default** path of `POST /api/v1/search/semantic` — the one
    /// taken whenever `diverse` is absent, and also whenever `diverse=true` but
    /// the corpus has no themes yet or the themes do not cover the query's
    /// nearest neighbourhood (the theme-coverage guard).
    ///
    /// # Why this moved out of `routes/search.rs`
    ///
    /// AS MEASURED AT PR-07: `semantic_search` destructured a `ViewerExtractor`
    /// and then spent it on exactly one of its four statements — the theme
    /// candidate pull, then reached through the engine wrapper
    /// `candidates_in_themes_at_dim` and since PR-29 called directly as
    /// `ClaimThemeRepository::claims_in_themes_at_dim_since`. (That handler now
    /// runs six statements, all viewer-stamped; the count and the callee name
    /// are both restated here rather than left to read as current.) This
    /// one — which returns `claims.content` for the whole corpus ranked against
    /// a caller-supplied probe vector — ran unfiltered, with no
    /// `check_content_access` pass behind it either.
    ///
    /// That is the same primitive [`Self::rag_hybrid_context`] describes as
    /// "the single highest-value exfiltration primitive in the API": an
    /// authenticated principal submits an arbitrary probe vector and gets other
    /// tenants' claim text back, verbatim, ranked by relevance. PR-07 closed it
    /// in `rag.rs` and left it standing in the more heavily used sibling
    /// endpoint, because the self-audit was scoped to files the PR touched and
    /// `search.rs` was not one of them.
    ///
    /// # The scan is served by the HNSW index
    ///
    /// The statement orders by the raw cosine distance, `c.embedding <=> q.vec`,
    /// because that is the only form pgvector's HNSW index can serve. It used to
    /// order by the derived `similarity` column (`1 - distance`), which the
    /// index cannot match, so every call computed the distance to every
    /// embedded claim and sorted them all: on prod (~348k embedded claims,
    /// 1536-d) that ran past 30 s and timed out every Explorer search, against
    /// 92 ms on the index. `1 - d` is strictly decreasing in `d`, so ascending
    /// distance is the same order as descending similarity.
    ///
    /// An HNSW index scan yields at most `hnsw.ef_search` rows (pgvector
    /// default 40), and the scope predicates (`claim_type`, the dates,
    /// `agent_id`, the visibility splice, `min_similarity`) are applied AFTER
    /// it. So the query runs in a short transaction that first sets, `is_local`:
    ///
    ///  - `hnsw.iterative_scan = strict_order`: keep scanning past `ef_search`
    ///    until `LIMIT $7` matching rows are found, in exact distance order.
    ///  - `hnsw.ef_search = clamp(limit, 40, 1000)`: the first batch already
    ///    covers an unscoped `limit`.
    ///
    /// The transaction is ROLLED BACK, not committed: on a caller's own
    /// transaction `begin()` opens a savepoint, and releasing it would carry the
    /// `SET LOCAL` values into the caller's later HNSW reads. This is the same
    /// arrangement as the hybrid recall dense leg. `hnsw.max_scan_tuples` stays
    /// at its default (20,000), so a scope rarer than about `limit / 20,000` of
    /// the embedded claims can still return fewer than `limit` rows.
    ///
    /// Requires pgvector >= 0.8.0 (`hnsw.iterative_scan`); prod runs 0.8.2.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn semantic_search_flat<'a, A>(
        executor: A,
        viewer: &crate::visibility::Viewer,
        embedding: &str,
        min_similarity: f64,
        claim_type: Option<&str>,
        created_after: Option<chrono::DateTime<chrono::Utc>>,
        created_before: Option<chrono::DateTime<chrono::Utc>>,
        agent_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<SemanticFlatHit>, DbError>
    where
        A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
    {
        let sql = viewer.splice(
            r#"
            WITH query_vec AS (
                SELECT $1::vector AS vec
            )
            SELECT
                c.id as claim_id,
                c.content as statement,
                1 - (c.embedding <=> q.vec) as similarity,
                c.truth_value,
                c.belief,
                c.plausibility,
                c.agent_id,
                c.trace_id,
                c.labels[1] as claim_type,
                c.created_at
            FROM claims c, query_vec q
            WHERE c.embedding IS NOT NULL
              AND 1 - (c.embedding <=> q.vec) >= $2
              AND ($3::text IS NULL OR $3 = ANY(c.labels))
              AND ($4::timestamptz IS NULL OR c.created_at >= $4)
              AND ($5::timestamptz IS NULL OR c.created_at <= $5)
              AND ($6::uuid IS NULL OR c.agent_id = $6)
              /* {VISIBILITY:c} */
            ORDER BY c.embedding <=> q.vec
            LIMIT $7
            "#,
            8,
        );
        let mut q = sqlx::query_as::<_, SemanticFlatHit>(&sql)
            .bind(embedding)
            .bind(min_similarity)
            .bind(claim_type)
            .bind(created_after)
            .bind(created_before)
            .bind(agent_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }

        // See "The scan is served by the HNSW index" above.
        let mut tx = executor.begin().await?;
        sqlx::query(
            "SELECT set_config('hnsw.iterative_scan', 'strict_order', true), \
                    set_config('hnsw.ef_search', $1, true)",
        )
        .bind(limit.clamp(40, 1000).to_string())
        .execute(&mut *tx)
        .await?;
        let rows = q.fetch_all(&mut *tx).await?;
        tx.rollback().await?;

        Ok(rows)
    }

    /// `claims.content` and `claims.properties` for one id, viewer-filtered.
    ///
    /// # Why this exists
    ///
    /// `routes/hypothesis.rs::hypothesis_status` destructured a
    /// `ViewerExtractor` and then ran `SELECT id, content, truth_value, belief,
    /// plausibility, labels, properties FROM claims WHERE id = $1` straight
    /// against the pool. Its viewer was spent only on
    /// `MassFunctionRepository::get_for_claim_frame` and
    /// `ExperimentRepository::count_completed_with_analysis`, both of which
    /// return scalars — so the handler satisfied acceptance criterion #1
    /// *syntactically* (a `ViewerExtractor` is present) while disclosing
    /// content, truth value, belief, plausibility, labels and properties for an
    /// arbitrary claim id to any bearer principal. That is the same
    /// Viewer-held-but-never-spent shape as `frame_claims_sorted`, which is the
    /// defect PR-07 exists to eliminate, and it had no `check_content_access`
    /// pass behind it (`hypothesis.rs` contains zero calls to it).
    ///
    /// [`Self::get_by_id`] is not reusable here: it returns a `Claim`, which
    /// carries no `properties`, and CLAUDE.md forbids widening
    /// `claim_from_row`'s signature to add one.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn content_and_properties<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<(String, serde_json::Value)>, DbError> {
        let sql = viewer.splice(
            "SELECT c.content, c.properties \
             FROM claims c \
             WHERE c.id = $1 \
               /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (String, serde_json::Value)>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }

    /// Corpus-wide embedding-neighbourhood cardinality and mean similarity.
    ///
    /// Backs `GET /api/v1/voids/density`, which ran this aggregate inline and
    /// unfiltered over the whole corpus against a caller-supplied probe vector.
    /// A bare `COUNT(*)` there is a cardinality oracle in the sense
    /// [`MassFunctionRepository::count_for_claim`] documents: it reports how
    /// much of the corpus sits near an arbitrary point in embedding space
    /// without disclosing any of it. Filtered, the count is the reader's count.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn embedding_density_stats<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        embedding: &str,
        radius: f64,
    ) -> Result<(i64, Option<f64>), DbError> {
        let sql = viewer.splice(
            "SELECT COUNT(*), AVG(1 - (c.embedding <=> $1::vector)) \
             FROM claims c \
             WHERE c.embedding IS NOT NULL \
               AND 1 - (c.embedding <=> $1::vector) >= $2 \
               /* {VISIBILITY:c} */",
            3,
        );
        let mut q = sqlx::query_as::<_, (i64, Option<f64>)>(&sql)
            .bind(embedding)
            .bind(radius);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(executor).await?)
    }

    /// Raw `claims.embedding` vectors for a probe neighbourhood, viewer-filtered.
    ///
    /// Backs the optional clustering branch of `POST /api/v1/experiments/hypothesize`.
    ///
    /// A raw embedding is not a weaker disclosure than the text it encodes —
    /// PR-07's own acceptance criteria treat embeddings as approximately
    /// invertible to content, which is why `/themes/:id/embeddings` returns
    /// none. This projection handed back full 1536-d vectors for the 200 claims
    /// nearest a caller-supplied probe, unfiltered.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn neighborhood_embeddings<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        embedding: &str,
        min_similarity: f64,
        limit: i64,
    ) -> Result<Vec<NeighborhoodEmbeddingRow>, DbError> {
        // `embedding::real[]` rather than `embedding::text::float4[]`: pgvector's
        // text form `[a,b,c]` is not a valid Postgres array literal.
        let sql = viewer.splice(
            "SELECT c.id, c.embedding::real[], c.truth_value \
             FROM claims c \
             WHERE c.embedding IS NOT NULL \
               AND c.is_current = true \
               AND 1 - (c.embedding <=> $1::vector) >= $2 \
               /* {VISIBILITY:c} */ \
             ORDER BY c.embedding <=> $1::vector \
             LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, NeighborhoodEmbeddingRow>(&sql)
            .bind(embedding)
            .bind(min_similarity)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Count / mean / median cosine similarity inside a distance radius of a
    /// probe vector, viewer-filtered.
    ///
    /// Backs MCP `embedding_neighborhood_density` (PR-09). That tool ran this
    /// aggregate inline in `epigraph-mcp/src/tools/embeddings.rs` with no
    /// `Viewer` parameter at all. It is the same cardinality-oracle shape as
    /// [`Self::embedding_density_stats`] — which already exists for the HTTP
    /// twin `GET /api/v1/voids/density` — but not the same query: this one
    /// gates on cosine *distance* `<= radius` rather than similarity
    /// `>= min_similarity`, and adds the median. Keeping them separate is
    /// deliberate: collapsing them would silently change one caller's
    /// threshold semantics.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn embedding_radius_density<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        embedding: &str,
        radius: f64,
    ) -> Result<(i64, Option<f64>, Option<f64>), DbError> {
        let sql = viewer.splice(
            "SELECT COUNT(*)::bigint, \
                    AVG(1 - (c.embedding <=> $1::vector))::float8, \
                    percentile_cont(0.5) WITHIN GROUP \
                        (ORDER BY 1 - (c.embedding <=> $1::vector))::float8 \
             FROM claims c \
             WHERE c.embedding IS NOT NULL \
               AND c.is_current = true \
               AND (c.embedding <=> $1::vector) <= $2 \
               /* {VISIBILITY:c} */",
            3,
        );
        let mut q = sqlx::query_as::<_, (i64, Option<f64>, Option<f64>)>(&sql)
            .bind(embedding)
            .bind(radius);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(executor).await?)
    }

    /// `properties->>'level'` / `properties->>'source_type'` for the nearest
    /// claims inside a distance radius, viewer-filtered.
    ///
    /// The MCP `embedding_neighborhood_density` breakdown. Unfiltered this was
    /// the sharper of that tool's two leaks: the level/source-type histogram of
    /// the nearest neighbours to a caller-chosen probe is a membership oracle
    /// over the whole corpus — it answers "is there private material near this
    /// topic, and what kind" without returning a single id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn embedding_radius_breakdown<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        embedding: &str,
        radius: f64,
        limit: i64,
    ) -> Result<Vec<LevelAndSourceType>, DbError> {
        let sql = viewer.splice(
            "SELECT c.properties->>'level', c.properties->>'source_type' \
             FROM claims c \
             WHERE c.embedding IS NOT NULL \
               AND c.is_current = true \
               AND (c.embedding <=> $1::vector) <= $2 \
               /* {VISIBILITY:c} */ \
             ORDER BY c.embedding <=> $1::vector \
             LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, LevelAndSourceType>(&sql)
            .bind(embedding)
            .bind(radius)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Graph neighbours of a selected claim set, for the diverse search path's
    /// `graph_neighbors` enrichment.
    ///
    /// `embedding_col` must be `"embedding"` or `"embedding_3072"`; anything
    /// else is rejected rather than interpolated, so the `format!` below cannot
    /// carry caller-controlled text even if a future caller forgets to validate.
    ///
    /// # Why this is filtered
    ///
    /// The neighbour ids come from traversing `edges` outward from the
    /// selected claims — they are NOT in the viewer-checked `selected_claim_ids`
    /// set. The previous inline version projected `left(c.content, 200)` for
    /// each one, so 200 characters of arbitrary out-of-tenant claim text rode
    /// out attached to every result. The predicate is spliced onto the joined
    /// `c`, so an invisible neighbour drops out of the row entirely rather than
    /// appearing with truncated content.
    ///
    /// # What is NOT filtered — the `edges` alias
    ///
    /// Only the joined `claims` alias `c` carries a predicate. The `edges`
    /// alias `e` carries none, and the projection includes `e.source_id`,
    /// `e.target_id` and `e.relationship` — so this is a member of
    /// `F-edges-unfiltered` (see `docs/tenancy/progress.json`), and a stronger
    /// one than `rag_hybrid_context`, whose residual is a scalar `edge_count`.
    /// PR-13 converted every `edges` read that ALREADY carried a visibility
    /// predicate; it did not ADD predicates to never-filtered statements,
    /// because each needs its own JOIN-vs-WHERE placement reasoning rather than
    /// a fragment swap. Adding `/* {{EDGE_VISIBILITY:e}} */` here is the fix,
    /// and it is bind-safe (both fragments render to the same `$3`) — it is
    /// deferred only so the whole class lands with one set of acceptance
    /// numbers. Bounded meanwhile: the returned rows are claims-filtered, so
    /// this discloses STRUCTURE, never content.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails, or
    /// `DbError::InvalidData` for an unrecognised `embedding_col`.
    #[instrument(skip(executor, viewer, embedding))]
    pub async fn semantic_graph_neighbors<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        embedding_col: &str,
        embedding: &str,
        claim_ids: &[Uuid],
    ) -> Result<Vec<SemanticNeighborHit>, DbError> {
        if embedding_col != "embedding" && embedding_col != "embedding_3072" {
            return Err(DbError::InvalidData {
                reason: format!("unsupported embedding column {embedding_col:?}"),
            });
        }
        let sql = viewer.splice(
            &format!(
                r#"
                SELECT
                    e.source_id, e.target_id, e.relationship,
                    c.id as neighbor_id, left(c.content, 200) as content,
                    c.truth_value, c.belief as nb_belief,
                    c.plausibility as nb_plausibility,
                    (1 - (c.{embedding_col} <=> $1::vector))::float8 as similarity,
                    CASE WHEN e.source_id = ANY($2) THEN 'outbound'
                         ELSE 'inbound' END as direction
                FROM edges e
                JOIN claims c
                  ON c.id = CASE WHEN e.source_id = ANY($2)
                                 THEN e.target_id ELSE e.source_id END
                WHERE (e.source_id = ANY($2) OR e.target_id = ANY($2))
                  AND e.source_type = 'claim' AND e.target_type = 'claim'
                  AND e.relationship IN ('CORROBORATES', 'corroborates', 'supports',
                                         'refines', 'continues_argument',
                                         'contradicts')
                  /* {{VISIBILITY:c}} */
                ORDER BY c.{embedding_col} <=> $1::vector
                LIMIT 50
                "#
            ),
            3,
        );
        let mut q = sqlx::query_as::<_, SemanticNeighborHit>(&sql)
            .bind(embedding)
            .bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Claims whose belief interval falls inside the given bounds, optionally
    /// restricted to one frame.
    ///
    /// Backs `GET /api/v1/claims/by-belief`.
    ///
    /// # Why this moved out of `routes/belief.rs`
    ///
    /// The handler ran this inline with **no `ViewerExtractor` at all** — only
    /// the fail-open `auth_ctx: Option<Extension<AuthContext>>` pattern — over
    /// an unbounded, caller-paginated corpus scan projecting `c.content`. It
    /// was the live counterexample to PR-07's own acceptance criterion ("no
    /// handler that returns claim content lacks a `ViewerExtractor`"). Its only
    /// control was the per-row `check_content_access`, whose backward-compat
    /// branch returns `ContentAccess::Full` for any claim with no `ownership`
    /// row — i.e. most of the corpus.
    ///
    /// Both `claims` and the `claim_frames` subquery are filtered: an unfiltered
    /// frame subquery would let a caller test membership of claims they cannot
    /// read by watching the result set change.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_by_belief_bounds<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        min_belief: f64,
        max_plausibility: f64,
        frame_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<BeliefBoundedClaimHit>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.belief, c.plausibility,
                   c.mass_on_empty, c.mass_on_missing
            FROM claims c
            WHERE c.belief >= $1 AND c.plausibility <= $2
              AND ($3::uuid IS NULL OR c.id IN (
                  SELECT cf.claim_id FROM claim_frames cf
                  WHERE cf.frame_id = $3 /* {VISIBILITY:cf} */
              ))
              /* {VISIBILITY:c} */
            ORDER BY c.belief DESC, c.id
            LIMIT $4 OFFSET $5
            "#,
            6,
        );
        let mut q = sqlx::query_as::<_, BeliefBoundedClaimHit>(&sql)
            .bind(min_belief)
            .bind(max_plausibility)
            .bind(frame_id)
            .bind(limit)
            .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Claims belonging to a frame, sorted by a belief metric.
    ///
    /// Backs `GET /api/v1/frames/:id/claims`.
    ///
    /// # Why this moved out of `routes/belief.rs`
    ///
    /// `frame_claims_sorted` took a `ViewerExtractor`, spent the viewer on
    /// `FrameRepository::get_by_id`, and then built this statement with
    /// `format!` + `sqlx::query_as` — no `{VISIBILITY:...}` marker, no
    /// `splice` call. That is exactly the fail-open [`Viewer::splice`]'s panic
    /// exists to catch, and it evaded the panic precisely *because* `splice`
    /// was never called. Both `claims` and `claim_frames` are filtered here;
    /// `claim_frames` is in migration 062's `tier_a` list and carries its own
    /// tenancy columns.
    ///
    /// `sort` and `direction` are enums, not strings. The previous code
    /// interpolated `&str`s that happened to come from handler match arms —
    /// safe, but only readable as safe by tracing back to the caller. Taking
    /// enums moves that guarantee into the type system, so the `format!` here
    /// cannot be made injectable by a future edit to the handler.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn frame_claims_sorted<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        frame_id: Uuid,
        sort: BeliefSort,
        direction: SortDirection,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FrameClaimBeliefHit>, DbError> {
        let order_col = sort.sql_expr();
        let order_dir = direction.sql_keyword();
        let sql = viewer.splice(
            &format!(
                r#"
                SELECT cf.claim_id, c.content, cf.hypothesis_index,
                       c.belief, c.plausibility, c.mass_on_missing
                FROM claim_frames cf
                JOIN claims c ON c.id = cf.claim_id
                WHERE cf.frame_id = $1
                  /* {{VISIBILITY:cf}} */
                  /* {{VISIBILITY:c}} */
                ORDER BY {order_col} {order_dir} NULLS LAST, cf.claim_id
                LIMIT $2 OFFSET $3
                "#
            ),
            4,
        );
        let mut q = sqlx::query_as::<_, FrameClaimBeliefHit>(&sql)
            .bind(frame_id)
            .bind(limit)
            .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Hybrid semantic + epistemic + connectivity retrieval for
    /// `GET /api/v1/query/rag`.
    ///
    /// `hybrid_score = similarity * 0.6 + truth_value * 0.2 +
    /// min(edge_count / 10, 1) * 0.2`. `min_truth` is the epistemic quality
    /// gate that distinguishes this from plain semantic search; `domain`, when
    /// `Some`, restricts to claims carrying that label.
    ///
    /// # Why this is here and not in `routes/rag.rs`
    ///
    /// Until PR-07 this statement was inline in the handler with no visibility
    /// predicate. That made `/api/v1/query/rag` a verbatim-corpus oracle: any
    /// authenticated principal could submit an arbitrary probe vector and get
    /// back other tenants' `claims.content` verbatim, ranked by relevance to
    /// the probe. Semantic search is the most efficient exfiltration primitive
    /// in the API precisely because it does not require knowing what to ask
    /// for. The predicate is spliced onto `c` below.
    ///
    /// `edge_count` is NOT visibility-filtered, and — correcting an earlier
    /// version of this comment — it **is** returned to the caller.
    /// `rag::rag_context` maps it to `RagContextResult::edge_count` as
    /// `Some(row.edge_count)`, which is always `Some`, so the
    /// `skip_serializing_if = "Option::is_none"` attribute never fires and the
    /// field is always emitted.
    ///
    /// What it discloses is therefore a *degree* over unfiltered `edges` for a
    /// claim the viewer can already see: a scalar count, never the ids or the
    /// adjacency. That is a real residual, not a non-issue, and it is the same
    /// unfiltered-`edges` gap recorded in `repos/graph_view.rs`. PR-13 shipped
    /// `Viewer::edge_predicate_fragment` and `edges.co_owner_group_id`, so the
    /// tool to close it now exists — but this statement never carried an `edges`
    /// marker at all, so it needs a predicate ADDED rather than swapped, and
    /// PR-13 converted only the reads that already had one. Still open as
    /// `F-edges-unfiltered` in `docs/tenancy/progress.json`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, query_embedding_pgvector))]
    pub async fn rag_hybrid_context<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        min_truth: f64,
        domain: Option<&str>,
        limit: i64,
    ) -> Result<Vec<RagContextHit>, DbError> {
        let sql = viewer.splice(
            r#"
            WITH query_vec AS (
                SELECT $1::vector AS vec
            ),
            base AS (
                SELECT
                    c.id as claim_id,
                    c.content,
                    c.truth_value,
                    1 - (c.embedding <=> q.vec) as similarity,
                    c.labels[1] as domain,
                    c.trace_id,
                    c.agent_id,
                    c.created_at,
                    COALESCE((
                        SELECT COUNT(*)
                        FROM edges e
                        WHERE e.source_id = c.id OR e.target_id = c.id
                    ), 0) as edge_count
                FROM claims c, query_vec q
                WHERE c.embedding IS NOT NULL
                  AND c.truth_value >= $2
                  AND 1 - (c.embedding <=> q.vec) >= 0.0
                  AND ($3::text IS NULL OR $3 = ANY(c.labels))
                  /* {VISIBILITY:c} */
            )
            SELECT *,
                similarity * 0.6
                    + truth_value * 0.2
                    + LEAST(edge_count::float / 10.0, 1.0) * 0.2
                as hybrid_score
            FROM base
            ORDER BY hybrid_score DESC
            LIMIT $4
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, RagContextHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(min_truth)
            .bind(domain)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Shallow-merge `patch` into the claim's `properties` JSONB (`||`),
    /// preserving keys not present in `patch` and overwriting those that are.
    /// Unlike [`set_properties`] (which replaces the whole object), this is for
    /// incrementally attaching/refreshing a sub-object — e.g. the workflow
    /// promotion verdict — without clobbering hierarchy metadata like `level`.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no claim has `claim_id`;
    /// `DbError::QueryFailed` on other database errors.
    #[instrument(skip(pool, patch))]
    pub async fn merge_properties(
        pool: &PgPool,
        claim_id: ClaimId,
        patch: &serde_json::Value,
    ) -> Result<(), DbError> {
        let id: Uuid = claim_id.into();
        let result = sqlx::query(
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $2, \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(patch)
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id,
            });
        }
        Ok(())
    }

    /// Create a new claim within an existing transaction (LEGACY — implicit content-hash dedup)
    ///
    /// Same as `create()` but accepts a `&mut PgConnection` for transactional use.
    /// Delegates to [`Self::create_conn`], which is the same contract.
    ///
    /// **Legacy behavior:** see the note on `create()` — this method shares
    /// the same cross-agent collapse bug. New transactional code should use
    /// `create_or_get` / `create_strict`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn create_with_tx(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
        decl: TenancyDecl,
    ) -> Result<Claim, DbError> {
        // One implementation of the legacy find-then-insert, so this entry point
        // takes the same `(content_hash, agent_id)` dedup lock (backlog
        // 00f1a517) and emits the same `claim.created` event.
        Self::create_conn(conn, claim, decl).await
    }

    /// The authoring agent of a claim, or `None` when no such claim exists.
    ///
    /// Narrow read for callers that need attribution without paying for a full
    /// [`Claim`] hydration — notably
    /// `epigraph_engine::retraction_cascade::invalidate_and_rewire`, which
    /// re-derives an edge-factor BBA and must attribute it the way the
    /// edge-write path does ("A's author asserts A SUPPORTS B"), i.e. to the
    /// **source** claim's author rather than to whoever triggered the
    /// retraction.
    ///
    /// Exists as a repo function rather than an inline query at the call site
    /// because `CLAUDE.md` keeps all SQL in `crates/epigraph-db/src/repos/`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_agent_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<Uuid>, DbError> {
        let sql = viewer.splice(
            "SELECT agent_id FROM claims WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let agent_id: Option<Uuid> = q.fetch_optional(executor).await?;
        Ok(agent_id)
    }

    /// Get a claim by ID
    ///
    /// # Returns
    /// A `Claim` post-fixed with the row's real retirement state
    /// (`is_current`, `supersedes`) **and** its real crypto state
    /// (`content_hash`, `signature`, signer `public_key`) — see
    /// [`post_fix_crypto_columns`]. This is the read MCP `verify_claim` runs
    /// on, and until backlog `49c17386` it inherited `claim_from_row`'s
    /// placeholders: `content_hash` recomputed from `content` (so
    /// `computed == stored` compared a value against itself and a tampered
    /// body verified clean) and `signature = None` (so the signature check
    /// could never pass).
    ///
    /// Uses a runtime `query_as` over [`SingleClaimRow`] rather than
    /// `sqlx::query!`, mirroring [`Self::list`]: the `LEFT JOIN agents` needed
    /// to resolve `signer_id → public_key` would otherwise require regenerating
    /// `.sqlx`, which is a serialized, separately owned step in this repo.
    /// [`Self::get_by_id_with_labels`] decodes the same row type, so the
    /// mapping and both post-fixes exist once.
    ///
    /// # Errors
    /// * [`DbError::QueryFailed`] if the database query fails or a column does
    ///   not decode.
    /// * [`DbError::InvalidData`] if the stored `content_hash` is not 32 bytes.
    /// * [`DbError::CoreError`] if the stored `truth_value` is outside `[0, 1]`.
    ///
    /// # Not a `sqlx::query!` macro site any more
    ///
    /// The tenancy series left this read on the macro's static three-bind
    /// spelling (`$2::bool OR visibility = 'public' OR owner_group_id =
    /// ANY($3)`). Backlog `49c17386` then needed three more columns and a
    /// `LEFT JOIN agents`, which the macro cannot express without regenerating
    /// `.sqlx` — a serialized, separately owned step in this repo. The runtime
    /// `query_as` + [`crate::visibility::Viewer::splice`] form is the
    /// alternative `visibility.rs` names, and it is STRICTER than what it
    /// replaces: an omitted marker panics, where an omitted macro disjunct
    /// merely compiles.
    ///
    /// The marker sits on `c` and on `c` only. `agents` is not in migration
    /// 062's `tier_a` set — it has `profile_visibility`, not `owner_group_id` —
    /// so there is nothing on `s` to filter, and the join reaches it only to
    /// resolve a public key for a claim the viewer has already been allowed to
    /// see.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: ClaimId,
    ) -> Result<Option<Claim>, DbError> {
        let uuid: Uuid = id.into();

        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at,
                   COALESCE(c.is_current, true) AS is_current, c.supersedes,
                   c.content_hash, c.signature,
                   s.public_key AS signer_public_key
            FROM claims c
            LEFT JOIN agents s ON s.id = c.signer_id
            WHERE c.id = $1
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, SingleClaimRow>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row = q.fetch_optional(executor).await?;

        row.map(SingleClaimRow::into_claim).transpose()
    }

    /// Fetch only the labels for a single claim.
    ///
    /// No production caller remains: MCP and REST `get_claim` read the claim
    /// and its labels in one statement through [`Self::get_by_id_with_labels`].
    /// Kept as a test oracle (it answers `[]` for a row the viewer cannot see,
    /// which several tests rely on).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_labels<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: ClaimId,
    ) -> Result<Vec<String>, DbError> {
        let sql = viewer.splice(
            "SELECT labels FROM claims WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Vec<String>,)>(&sql).bind(id.as_uuid());
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<(Vec<String>,)> = q.fetch_optional(executor).await?;
        Ok(row.map(|(l,)| l).unwrap_or_default())
    }

    /// Get a claim by ID together with its labels in a single SQL statement.
    ///
    /// `get_by_id` followed by `get_labels` is two independent round trips
    /// against the shared pool: a concurrent `update_labels` between them can
    /// return labels inconsistent with the already-read claim row (TOCTOU).
    /// A single-statement, single-row `SELECT` is inherently consistent under
    /// Postgres MVCC, so this is the atomic alternative for callers (e.g. MCP
    /// `get_claim`) that need both together.
    ///
    /// Decodes through [`SingleClaimRowWithLabels`] (`query_as` + `FromRow`),
    /// the same row type and post-fixes [`Self::get_by_id`] uses, so a
    /// drifted column is an `Err` rather than a `sqlx::Row::get` panic.
    ///
    /// # Errors
    /// * [`DbError::QueryFailed`] if the database query fails or a column does
    ///   not decode.
    /// * [`DbError::InvalidData`] if the stored `content_hash` is not 32 bytes.
    /// * [`DbError::CoreError`] if the stored `truth_value` is outside `[0, 1]`.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id_with_labels<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: ClaimId,
    ) -> Result<Option<(Claim, Vec<String>)>, DbError> {
        let uuid: Uuid = id.into();

        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at,
                   COALESCE(c.is_current, true) AS is_current, c.supersedes,
                   c.labels, c.content_hash, c.signature,
                   s.public_key AS signer_public_key
            FROM claims c
            LEFT JOIN agents s ON s.id = c.signer_id
            WHERE c.id = $1
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, SingleClaimRowWithLabels>(&sql).bind(uuid);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row = q.fetch_optional(executor).await?;

        // The crypto post-fix matters here as much as in `get_by_id`: MCP
        // `get_claim` renders this `content_hash` to the caller as hex as the
        // claim's stable identity, and serving a digest recomputed from the
        // body there is the same fabrication `verify_claim` was caught on.
        row.map(|r| Ok((r.row.into_claim()?, r.labels))).transpose()
    }

    /// kNN search over `claims.embedding` (1536d) or `claims.embedding_3072`,
    /// restricted to paragraph-level (level=2) claims, optionally filtered by
    /// the paper that asserts the claim. Results are ordered by cosine
    /// similarity descending (= cosine distance ascending), and rows whose
    /// chosen embedding column is NULL are excluded.
    ///
    /// `query_embedding_pgvector` is a pgvector text literal, e.g. `"[0.1,0.2,...]"`.
    /// `paper_doi_filter`, when set, restricts results to claims that have an
    /// incoming `'asserts'` edge from a `papers` row with the given DOI.
    ///
    /// The `dim=1536` path is index-aligned with the partial HNSW
    /// `idx_claims_paragraph_embedding` introduced in migration 029. The
    /// `dim=3072` path is intentionally seq-scan (paragraph counts ≤ 10⁴; see
    /// the `recall_with_context` design doc).
    ///
    /// # Errors
    /// * [`DbError::InvalidData`] if `dim` is neither 1536 nor 3072.
    /// * [`DbError::QueryFailed`] on database errors.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_by_embedding_since`]; `None` = no window = today's
    /// behaviour.
    #[instrument(skip(pool, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        dim: u32,
        limit: i64,
        paper_doi_filter: Option<&str>,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        Self::search_by_embedding_since(
            pool,
            viewer,
            query_embedding_pgvector,
            dim,
            limit,
            paper_doi_filter,
            None,
            EmbeddingSeedScope::Paragraphs,
        )
        .await
    }

    /// [`Self::search_by_embedding`] plus an optional `created_at >= since`
    /// window and a choice of candidate population ([`EmbeddingSeedScope`]).
    ///
    /// The predicate sits in the same WHERE clause as the level/NULL guards,
    /// i.e. before `ORDER BY … LIMIT`, so the window narrows the candidate
    /// pool rather than trimming an already-truncated top-K (see
    /// [`Self::search_hybrid_scoped_since`] for why that distinction decides
    /// correctness rather than performance).
    ///
    /// # Scope
    ///
    /// [`EmbeddingSeedScope::Paragraphs`] keeps the `level = 2` predicate (and
    /// so, at 1536d, the partial HNSW index from migration 029).
    /// [`EmbeddingSeedScope::AllClaims`] drops it, so the 1536d statement is
    /// served by `idx_claims_embedding_hnsw` (migration 001, `WHERE embedding
    /// IS NOT NULL`). No `is_current` predicate is needed in either scope:
    /// `chk_deprecated_no_embedding` guarantees a retired claim carries no
    /// vector in either column.
    ///
    /// # Iterative HNSW scan
    ///
    /// An HNSW index scan yields at most `hnsw.ef_search` rows (pgvector
    /// default 40), and the predicates the index does not encode (`since`, the
    /// DOI `EXISTS`, the visibility splice, and in the `AllClaims` scope every
    /// row the viewer cannot see out of the whole corpus) are applied AFTER
    /// it. So, exactly as in [`Self::semantic_search_flat`], the statement
    /// runs in a short transaction that first sets, `is_local`:
    ///
    ///  - `hnsw.iterative_scan = strict_order`: keep scanning past
    ///    `ef_search` until `LIMIT $2` matching rows are found, in exact
    ///    distance order;
    ///  - `hnsw.ef_search = clamp(limit, 40, 1000)`.
    ///
    /// The transaction is ROLLED BACK, not committed: on a caller's own
    /// transaction `begin()` opens a savepoint, and releasing it would carry
    /// the `SET LOCAL` values into the caller's later HNSW reads.
    /// `hnsw.max_scan_tuples` stays at its default (20,000). The 3072d column
    /// has no ANN index, so there the settings are inert and the statement is
    /// an exact scan.
    ///
    /// Requires pgvector >= 0.8.0 (`hnsw.iterative_scan`).
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(executor, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding_since<'a, A>(
        executor: A,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        dim: u32,
        limit: i64,
        paper_doi_filter: Option<&str>,
        since: Option<DateTime<Utc>>,
        scope: EmbeddingSeedScope,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError>
    where
        A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
    {
        let column = match dim {
            1536 => "embedding",
            3072 => "embedding_3072",
            _ => {
                return Err(DbError::InvalidData {
                    reason: format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"),
                });
            }
        };

        // Two query shapes — paper-filter vs no-filter — to keep both
        // index-friendly. In the `Paragraphs` scope the shared WHERE
        // predicate matches the partial HNSW index from migration 029 for the
        // 1536d path; in the `AllClaims` scope it matches migration 001's
        // `idx_claims_embedding_hnsw`.
        //
        // `level_clause` is one of two static literals, never caller input.
        let level_clause = match scope {
            EmbeddingSeedScope::Paragraphs => "(c.properties->>'level')::int = 2 AND",
            EmbeddingSeedScope::AllClaims => "",
        };
        //
        // `since` is bound at a FIXED $3 in BOTH shapes and the conditional
        // DOI moves to $4. Appending `since` after a conditionally-bound
        // parameter would leave the no-filter shape with a bind-count
        // mismatch — a runtime error, not a compile error.
        // The marker is written `{{VISIBILITY:c}}` in these two literals because
        // they are `format!` templates: `{` is a format placeholder, so the
        // braces are doubled and `format!` emits the single-brace marker
        // `Viewer::splice` looks for. `visibility_lint.rs` normalises `{{` to
        // `{` before matching, for the same reason.
        let sql = if paper_doi_filter.is_some() {
            format!(
                r#"
                SELECT c.id AS claim_id,
                       1 - (c.{column} <=> $1::vector) AS similarity
                FROM claims c
                WHERE {level_clause} c.{column} IS NOT NULL
                  AND ($3::timestamptz IS NULL OR c.created_at >= $3::timestamptz)
                  AND EXISTS (
                      SELECT 1 FROM edges e
                      JOIN papers p ON p.id = e.source_id
                      WHERE e.target_id = c.id
                        AND e.relationship = 'asserts'
                        AND p.doi = ANY($4::text[])
                  )
                  /* {{VISIBILITY:c}} */
                ORDER BY c.{column} <=> $1::vector
                LIMIT $2
                "#
            )
        } else {
            format!(
                r#"
                SELECT c.id AS claim_id,
                       1 - (c.{column} <=> $1::vector) AS similarity
                FROM claims c
                WHERE {level_clause} c.{column} IS NOT NULL
                  AND ($3::timestamptz IS NULL OR c.created_at >= $3::timestamptz)
                  /* {{VISIBILITY:c}} */
                ORDER BY c.{column} <=> $1::vector
                LIMIT $2
                "#
            )
        };

        // The DOI shape binds its filter at $4, so the group bind lands at $5
        // there and at $4 without it. Splicing per-shape is what keeps the two
        // literals from sharing a wrong index.
        let vis_bind = if paper_doi_filter.is_some() { 5 } else { 4 };
        let sql = viewer.splice(&sql, vis_bind);

        let mut q = sqlx::query_as::<_, ClaimEmbeddingHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit)
            .bind(since);
        if let Some(doi) = paper_doi_filter {
            // Every stored spelling of the document key (backlog 90756d26),
            // through the normalizer the paper writers use: a bare filter
            // finds a URL-keyed legacy paper and vice versa.
            q = q.bind(crate::repos::paper::document_key_spellings(doi));
        }
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }

        // See "Iterative HNSW scan" above.
        let mut tx = executor.begin().await?;
        sqlx::query(
            "SELECT set_config('hnsw.iterative_scan', 'strict_order', true), \
                    set_config('hnsw.ef_search', $1, true)",
        )
        .bind(limit.clamp(40, 1000).to_string())
        .execute(&mut *tx)
        .await?;
        let rows = q.fetch_all(&mut *tx).await?;
        tx.rollback().await?;

        Ok(rows)
    }

    /// Search **current** claims by embedding similarity across **all levels**.
    ///
    /// This is the search backing the simple `recall` MCP tool. Unlike
    /// [`search_by_embedding`] — which is paper-paragraph-primary and
    /// restricts to `(properties->>'level')::int = 2` — memorized claims have
    /// no `level` property and store their vector on the 1536d
    /// `claims.embedding` column. `recall` therefore needs a search with no
    /// level restriction, limited to `is_current` so superseded/retired claims
    /// are not resurfaced. (`recall` previously queried
    /// `EvidenceRepository::search_by_embedding`, i.e. `evidence.embedding`,
    /// which is unpopulated — so its semantic path returned nothing.)
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(pool, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding_current(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        Self::search_by_embedding_scoped(pool, viewer, query_embedding_pgvector, limit, None, None)
            .await
    }

    /// [`search_by_embedding_current`] with optional scope predicates pushed
    /// into the query: `tags` requires label containment (`c.labels @> $tags`,
    /// the claim must carry ALL given tags) and `agent_id` requires authorship.
    /// A `None`/empty filter does not restrict (the `$n IS NULL OR …` idiom),
    /// so the two compose with AND. Scoping at the DB keeps it correct and
    /// index-friendly rather than over-fetching and filtering in Rust.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(executor, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding_scoped<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        // Empty tag slice scopes to nothing meaningful (`@> '{}'` is all rows);
        // collapse it to None so the IS NULL branch short-circuits.
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let sql = viewer.splice(
            r#"
            SELECT c.id AS claim_id,
                   1 - (c.embedding <=> $1::vector) AS similarity
            FROM claims c
            WHERE c.embedding IS NOT NULL
              AND c.is_current
              AND ($3::text[] IS NULL OR c.labels @> $3::text[])
              AND ($4::uuid IS NULL OR c.agent_id = $4::uuid)
              /* {VISIBILITY:c} */
            ORDER BY c.embedding <=> $1::vector
            LIMIT $2
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, ClaimEmbeddingHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit)
            .bind(tags_owned)
            .bind(agent_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// ANN lookup backing the write-side semantic novelty gate (backlog
    /// `1bcaed94`, Task 6.4): the `limit` nearest `is_current` claims to
    /// `query_embedding_pgvector`, ordered closest-first by cosine distance
    /// (`<=>`, matching `idx_claims_embedding_hnsw`'s `vector_cosine_ops` and
    /// every other ANN query in this repo — the backlog plan's SQL sketch
    /// wrote `<->` (L2), but L2 is neither index-accelerated here nor
    /// calibrated for the 0.05/0.15 thresholds).
    ///
    /// Excludes `embedding IS NULL` (no defined distance) and
    /// `is_current = false` rows (superseded/retired claims must never
    /// suppress a new near-paraphrase insert).
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(executor, viewer, query_embedding_pgvector))]
    pub async fn nearest_by_embedding<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<NearestClaimHit>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT id AS claim_id,
                   (embedding <=> $1::vector)::float8 AS distance
            FROM claims
            WHERE embedding IS NOT NULL
              AND is_current
              /* {VISIBILITY:claims} */
            ORDER BY embedding <=> $1::vector
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, NearestClaimHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Hybrid retrieval over current claims: RRF-fuse a dense
    /// (`claims.embedding`, HNSW) leg and a lexical (`content_tsv`, GIN) leg in
    /// one round-trip. Both legs share the `is_current` / `labels @> tags` /
    /// `agent_id` predicates, so the only difference is the relevance signal.
    /// `candidate_pool` caps each leg before fusion; `k_rrf` is the RRF constant.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_hybrid_scoped_since`] so existing callers
    /// (`epigraph-mcp`'s `McpEmbedder::search_hybrid_scoped` novelty path)
    /// keep the call they already have. `None` = no creation-time window,
    /// which is the pre-existing behaviour exactly.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        Self::search_hybrid_scoped_since(
            pool,
            viewer,
            query_embedding_pgvector,
            query_text,
            candidate_pool,
            k_rrf,
            limit,
            tags,
            agent_id,
            None,
        )
        .await
    }

    /// [`Self::search_hybrid_scoped`] plus an optional creation-time window.
    ///
    /// `since` is pushed into the WHERE clause of **both** the `dense` and
    /// `lex` CTEs, i.e. ABOVE their `LIMIT $3`. This placement is the whole
    /// point: each leg caps its candidate pool before fusion, so a window
    /// applied to the fused output would first let `candidate_pool`
    /// pre-window rows consume the entire pool and then discard them,
    /// returning `[]` for a query that has a real answer. An empty result
    /// reads to the caller as "nothing changed" — the exact inverse of the
    /// truth — so this is a correctness requirement, not an optimisation.
    ///
    /// The predicate is `created_at`, never `updated_at`:
    /// [`Self::batch_update_truth_values`] bumps `updated_at` on every claim a
    /// belief recomputation touches without changing its content, so an
    /// `updated_at` window would report the whole recomputed corpus as new.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped_since<'a, A>(
        executor: A,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<HybridHit>, DbError>
    where
        A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
    {
        Self::search_hybrid_scoped_since_in_theme(
            executor,
            viewer,
            query_embedding_pgvector,
            query_text,
            candidate_pool,
            k_rrf,
            limit,
            0,
            tags,
            agent_id,
            since,
            None,
        )
        .await
    }

    /// [`Self::search_hybrid_scoped_since`] plus an optional `claims.theme_id`
    /// narrowing and an `offset` for paging the fused output.
    ///
    /// `theme_id` is pushed into **both** the `dense` and `lex` CTEs, above
    /// their `LIMIT $3`, for exactly the reason spelled out on
    /// `search_hybrid_scoped_since` for `since`: a theme predicate applied to
    /// the fused output would let `candidate_pool` off-theme rows consume the
    /// whole pool and then be discarded, returning `[]` for a theme that has a
    /// real answer. Off-theme rows must never enter the pool in the first
    /// place.
    ///
    /// `offset` pages the fused output so a caller can walk one theme to
    /// exhaustion (the stated requirement of backlog `c95a2509`). For that walk
    /// to be sound the final `ORDER BY` must be TOTAL, so it carries a
    /// `claim_id` tiebreaker: `rrf_score` is a sum of `1/(k+rank)` terms and
    /// ties are common (two claims appearing in the same pair of legs at
    /// mirrored ranks collide exactly), and under a non-total sort Postgres may
    /// return tied rows in a different order per page — showing the caller one
    /// claim twice and another never.
    ///
    /// ## The tiebreaker is on the FUSED output only, deliberately
    ///
    /// The two CTEs' own `ORDER BY`s are left alone. An earlier revision added
    /// `, c.id` to each CTE's `row_number()` window and `LIMIT` as well, on the
    /// theory that a deterministic candidate-pool cut is strictly better. It is
    /// not free: the dense and lexical legs then break their ties on
    /// *independent* keys, so a claim can be 2nd in one leg and 3rd in the
    /// other where previously the two arbitrary orders were correlated, and the
    /// RRF sum flips. That regressed
    /// `claim_search_hybrid::hybrid_fuses_both_legs_ranking_the_overlap_first`
    /// in 2 of 6 runs (6 of 6 green before, 6 of 6 green again after this was
    /// reverted). Making the pool cut deterministic is a real improvement but
    /// it is a RANKING change, not a paging one, and it belongs in its own
    /// commit with its own analysis of which tied row deserves the pool slot.
    ///
    /// ## Residual, recorded rather than fixed
    ///
    /// The fused `ORDER BY` is total WITHIN one execution. A walk spans several
    /// executions, and across them two things are still arbitrary:
    ///
    ///  - which rows of a tie group enter the pool when `candidate_pool`
    ///    truncates it (needs a tie group straddling the 50th candidate at
    ///    `HYBRID_CANDIDATE_POOL = 50`); and
    ///  - the `row_number()` ranks assigned inside a tie group, which feed
    ///    `rrf_score`, so two executions could in principle score a tied group
    ///    differently and reorder it.
    ///
    /// In practice the legs stay correlated — each sees the same physical scan
    /// order, so a fully tied group scores `2/(k+r)`, monotone in the same `r`
    /// — which is why the paging walk is stable. Both hazards predate this
    /// change; neither is introduced by it. Closing them properly means an
    /// explicit deterministic key inside each leg, which is the ranking change
    /// described above.
    ///
    /// ## The dense leg runs with pgvector's iterative HNSW scan (fdd8e494)
    ///
    /// The `dense` CTE is served by `idx_claims_embedding_hnsw`, and an HNSW
    /// index scan yields at most `hnsw.ef_search` rows (pgvector default 40)
    /// unless iterative scanning is on. Every scope predicate in the CTE —
    /// `labels @>`, `agent_id`, `since`, `theme_id` and the visibility splice —
    /// is applied AFTER that scan, so a scope rare among the ~40 nearest
    /// neighbours returned 0–2 dense rows (prod: `recall(tags=['backlog'])`
    /// matched one row via dense), and even unscoped recall could not fill a
    /// `candidate_pool` above 40. So the query runs in a short transaction that
    /// first sets, `is_local`:
    ///
    ///  - `hnsw.iterative_scan = strict_order` — keep scanning past
    ///    `ef_search` until `LIMIT $3` scope-matching rows are found.
    ///    `strict_order`, not `relaxed_order`: the scan's output stays exactly
    ///    distance-ordered, so the `LIMIT $3` cut and the `row_number()` ranks
    ///    behave as before and the paging argument above still holds.
    ///  - `hnsw.ef_search = clamp(candidate_pool, 40, 1000)` — the first
    ///    batch is already the whole pool for an unscoped query.
    ///
    /// The transaction is ROLLED BACK, not committed. On a caller's own
    /// transaction `begin()` opens a savepoint, and `RELEASE SAVEPOINT` would
    /// carry the `SET LOCAL` values up into the caller's transaction, where
    /// they would perturb any later HNSW read (e.g. the ef_search-tuned
    /// `THEME_COVERAGE_PROBE_K` probe). `ROLLBACK TO SAVEPOINT` reverts them;
    /// for a read-only statement the two are otherwise equivalent.
    ///
    /// Residual: the iterative scan still stops at `hnsw.max_scan_tuples`
    /// (default 20,000) or at its memory budget (`hnsw.scan_mem_multiplier` x
    /// `work_mem`), whichever comes first; neither is changed here. A scope
    /// whose share of embedded current claims is below about
    /// `candidate_pool / 20,000` (0.25% at a pool of 50) can still under-fill
    /// the dense leg.
    ///
    /// Requires pgvector >= 0.8.0, the release that added
    /// `hnsw.iterative_scan`; check the deployed extension version before
    /// shipping. On an older extension the call is unsupported, and how it
    /// misbehaves depends on the backend: where the `vector` library is
    /// already loaded, pgvector has reserved the `hnsw.` GUC prefix and the
    /// `set_config` is expected to fail the whole call; on a fresh pooled
    /// backend the unknown name may be accepted as a placeholder and then
    /// discarded (with a WARNING) when the library loads, so the query runs
    /// silently without iterative scan.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped_since_in_theme<'a, A>(
        executor: A,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        offset: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
        theme_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError>
    where
        A: sqlx::Acquire<'a, Database = sqlx::Postgres>,
    {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        // BOTH CTEs are marked. The recursive hazard's flat cousin: filtering
        // only `dense` would let `lex` re-admit a row the viewer cannot read,
        // and the FULL OUTER JOIN would surface it. `splice` asserts both
        // markers resolve to the same bind ($11).
        let sql = viewer.splice(
            r#"
            WITH dense AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY c.embedding <=> $1::vector) AS rank,
                       1 - (c.embedding <=> $1::vector) AS cos
                FROM claims c
                WHERE c.embedding IS NOT NULL AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                  AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
                  AND ($10::uuid IS NULL OR c.theme_id = $10::uuid)
                  /* {VISIBILITY:c} */
                ORDER BY c.embedding <=> $1::vector
                LIMIT $3
            ),
            lex AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY ts_rank_cd(c.content_tsv, q) DESC) AS rank
                FROM claims c, websearch_to_tsquery('english', $2) q
                WHERE c.content_tsv @@ q AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                  AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
                  AND ($10::uuid IS NULL OR c.theme_id = $10::uuid)
                  /* {VISIBILITY:c} */
                ORDER BY ts_rank_cd(c.content_tsv, q) DESC
                LIMIT $3
            )
            SELECT COALESCE(d.id, l.id) AS claim_id,
                   (COALESCE(1.0/($4 + d.rank), 0)
                    + COALESCE(1.0/($4 + l.rank), 0))::float8 AS rrf_score,
                   d.cos::float8 AS dense_similarity,
                   (l.rank IS NOT NULL) AS in_lexical
            FROM dense d
            FULL OUTER JOIN lex l ON d.id = l.id
            ORDER BY rrf_score DESC, claim_id
            LIMIT $5 OFFSET $9
            "#,
            11,
        );
        let mut q = sqlx::query_as::<_, HybridHit>(&sql)
            .bind(query_embedding_pgvector) // $1
            .bind(query_text) // $2
            .bind(candidate_pool) // $3
            .bind(k_rrf) // $4
            .bind(limit) // $5
            .bind(tags_owned) // $6
            .bind(agent_id) // $7
            .bind(since) // $8
            .bind(offset) // $9
            .bind(theme_id); // $10
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $11
        }

        // See "The dense leg runs with pgvector's iterative HNSW scan" above.
        let mut tx = executor.begin().await?;
        sqlx::query(
            "SELECT set_config('hnsw.iterative_scan', 'strict_order', true), \
                    set_config('hnsw.ef_search', $1, true)",
        )
        .bind(hnsw_ef_search_for_pool(candidate_pool).to_string())
        .execute(&mut *tx)
        .await?;
        let rows = q.fetch_all(&mut *tx).await?;
        tx.rollback().await?;

        Ok(rows)
    }

    /// Lexical-only retrieval over current claims (`content_tsv` / GIN), ranked
    /// by `ts_rank_cd`. Returns `HybridHit`s with `dense_similarity = None` and
    /// `in_lexical = true`; `rrf_score = 1/(k_rrf + rank)` keeps the score scale
    /// consistent with the hybrid path. Used as `recall`'s embedder-down
    /// fallback — unlike an ILIKE scan it honors the tag/agent scope in SQL.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_lexical_scoped_since`]; `None` = no window = today's
    /// behaviour.
    pub async fn search_lexical_scoped(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        Self::search_lexical_scoped_since(
            pool, viewer, query_text, k_rrf, limit, tags, agent_id, None,
        )
        .await
    }

    /// [`Self::search_lexical_scoped`] plus an optional `created_at >= since`
    /// window, applied in the WHERE clause above `LIMIT` for the same
    /// pool-saturation reason documented on
    /// [`Self::search_hybrid_scoped_since`]. This is the surface `recall`
    /// falls back to when the embedder is down; a window that held on the
    /// hybrid path but not here would silently widen on embedder failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_lexical_scoped_since<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<HybridHit>, DbError> {
        Self::search_lexical_scoped_since_in_theme(
            executor, viewer, query_text, k_rrf, limit, 0, tags, agent_id, since, None,
        )
        .await
    }

    /// [`Self::search_lexical_scoped_since`] plus the same optional
    /// `claims.theme_id` narrowing and `offset` paging as
    /// [`Self::search_hybrid_scoped_since_in_theme`].
    ///
    /// This is `recall`'s embedder-down fallback. The theme filter has to hold
    /// HERE as well as on the hybrid path, or the scope would silently widen to
    /// the whole corpus exactly when the embedder is unavailable — the same
    /// argument that put `since` on both surfaces.
    ///
    /// `row_number()` is evaluated over the whole filtered set before
    /// `LIMIT`/`OFFSET`, so the reported `rrf_score` stays on the global rank
    /// rather than restarting at 1 on each page. Its window and the outer
    /// `ORDER BY` share the `c.id` tiebreaker so the two agree and the walk is
    /// repeat-free.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_lexical_scoped_since_in_theme<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        offset: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
        theme_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let sql = viewer.splice(
            r#"
            SELECT c.id AS claim_id,
                   (1.0 / ($2 + row_number() OVER (
                       ORDER BY ts_rank_cd(c.content_tsv, q) DESC, c.id)))::float8 AS rrf_score,
                   NULL::float8 AS dense_similarity,
                   true AS in_lexical
            FROM claims c, websearch_to_tsquery('english', $1) q
            WHERE c.content_tsv @@ q AND c.is_current
              AND ($4::text[] IS NULL OR c.labels @> $4::text[])
              AND ($5::uuid IS NULL OR c.agent_id = $5::uuid)
              AND ($6::timestamptz IS NULL OR c.created_at >= $6::timestamptz)
              AND ($8::uuid IS NULL OR c.theme_id = $8::uuid)
              /* {VISIBILITY:c} */
            ORDER BY ts_rank_cd(c.content_tsv, q) DESC, c.id
            LIMIT $3 OFFSET $7
            "#,
            9,
        );
        let mut q = sqlx::query_as::<_, HybridHit>(&sql)
            .bind(query_text) // $1
            .bind(k_rrf) // $2
            .bind(limit) // $3
            .bind(tags_owned) // $4
            .bind(agent_id) // $5
            .bind(since) // $6
            .bind(offset) // $7
            .bind(theme_id); // $8
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $9
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Maximum number of claims returned by [`get_by_agent`](Self::get_by_agent) in a single
    /// call. Prevents loading an arbitrarily large `Vec<Claim>` into heap for agents with many
    /// claims. Callers that need pagination should use `list_by_belief_range` with explicit
    /// offset/limit.
    pub const MAX_AGENT_CLAIMS: i64 = 500;

    /// Get all claims by an agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_agent<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_id: AgentId,
    ) -> Result<Vec<Claim>, DbError> {
        let uuid: Uuid = agent_id.into();

        let sql = viewer.splice(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE agent_id = $1
              /* {VISIBILITY:claims} */
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, ClaimRow>(&sql)
            .bind(uuid)
            .bind(Self::MAX_AGENT_CLAIMS);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Update the truth value of a claim
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_truth_value(
        pool: &PgPool,
        id: ClaimId,
        truth: TruthValue,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let truth_value = truth.value();

        let row = sqlx::query!(
            r#"
            UPDATE claims
            SET truth_value = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            uuid,
            truth_value
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.truth_value)?;

                Ok(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the truth value of a claim using an existing connection (e.g. inside a transaction).
    pub async fn update_truth_value_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
        truth: TruthValue,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let truth_value = truth.value();

        use sqlx::Row;
        let row = sqlx::query(
            r#"UPDATE claims
               SET truth_value = $2, updated_at = NOW()
               WHERE id = $1
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(uuid)
        .bind(truth_value)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the trace_id of a claim
    ///
    /// Use this to associate a claim with a reasoning trace after both have been created.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_trace_id(
        pool: &PgPool,
        id: ClaimId,
        trace_id: TraceId,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let trace_uuid: Uuid = trace_id.into();

        let row = sqlx::query!(
            r#"
            UPDATE claims
            SET trace_id = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            uuid,
            trace_uuid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.truth_value)?;

                Ok(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the trace_id of a claim using an existing connection (e.g. inside a transaction).
    pub async fn update_trace_id_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
        trace_id: TraceId,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let trace_uuid: Uuid = trace_id.into();

        use sqlx::Row;
        let row = sqlx::query(
            r#"UPDATE claims
               SET trace_id = $2, updated_at = NOW()
               WHERE id = $1
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(uuid)
        .bind(trace_uuid)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Get claims with truth value above a threshold
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_high_truth<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        threshold: f64,
    ) -> Result<Vec<Claim>, DbError> {
        // MACRO SITE — static three-bind spelling; see `get_by_id`.
        let rows = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE truth_value >= $1
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            ORDER BY truth_value DESC, created_at DESC
            "#,
            threshold,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Get claims with truth value below a threshold
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_low_truth<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        threshold: f64,
    ) -> Result<Vec<Claim>, DbError> {
        // MACRO SITE — static three-bind spelling; see `get_by_id`.
        let rows = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE truth_value <= $1
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            ORDER BY truth_value ASC, created_at DESC
            "#,
            threshold,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Delete a claim by ID
    ///
    /// # Returns
    /// Returns `true` if the claim was deleted, `false` if this session cannot
    /// read it (it does not exist, or is invisible).
    ///
    /// # Errors
    /// `DbError::WriteRefused` when the claim is readable but migration 115's
    /// owner-scoped DELETE refused it (a refused DELETE matches no row and
    /// reports success, so the one statement compares what it saw with what it
    /// deleted); `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: ClaimId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let r = sqlx::query!(
            r#"
            WITH seen AS (SELECT 1 FROM claims WHERE id = $1),
                 done AS (DELETE FROM claims WHERE id = $1 RETURNING 1)
            SELECT (SELECT count(*) FROM seen) AS "seen!", (SELECT count(*) FROM done) AS "done!"
            "#,
            uuid
        )
        .fetch_one(pool)
        .await?;

        Ok(super::require_all_changed("claim", uuid, "delete", (r.seen, r.done))? > 0)
    }

    /// Get a claim by ID on a caller-supplied connection.
    ///
    /// The connection-taking twin of [`Self::get_by_id`], and — since PR-23 —
    /// the shape a request handler reaches through `AppState::read_as`.
    ///
    /// Delegates to the generic form, which accepts any executor — `&mut
    /// PgConnection` included — so the visibility predicate, the projection
    /// and the retirement / crypto post-fix exist in exactly one SQL text and
    /// one decode. The same shape as [`Self::list_conn`] and
    /// [`Self::count_conn`].
    ///
    /// # Why this is a delegator and not a copy
    ///
    /// It used to be a hand-written second copy of `get_by_id`'s SQL, and that
    /// copy drifted once already: it projected seven columns where its twin
    /// projected nine, so a superseded claim read back as current. No gate
    /// sees that class — `visibility_lint.rs` checks that each SQL text carries
    /// a marker, never that two texts agree — so the copy is gone rather than
    /// re-synchronised (backlog `fd47651c`). The reason it was once left as a
    /// copy (`get_by_id` being a `sqlx::query!` macro site with a fixed bind
    /// arity) stopped holding when `get_by_id` moved to a spliced runtime
    /// `query_as`. `tests/get_by_id_conn_delegates_to_get_by_id.rs` pins both
    /// the delegation and the field-for-field equivalence.
    ///
    /// # Errors
    /// As [`Self::get_by_id`].
    pub async fn get_by_id_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        id: ClaimId,
    ) -> Result<Option<Claim>, DbError> {
        Self::get_by_id(&mut *conn, viewer, id).await
    }

    /// List claims with pagination
    ///
    /// # Returns
    /// Claims post-fixed with the row's real `is_current` and `supersedes`, so
    /// superseded rows are distinguishable from live ones. Before backlog bug
    /// `f1992766` this SELECT omitted both columns and every row inherited
    /// `claim_from_row`'s defaults (`is_current = true`, `supersedes = None`) —
    /// `GET /api/v1/claims` asserted currency it had never read, and that
    /// endpoint's `?is_current=false` filter (an in-memory `retain` over this
    /// result) compared against a constant and could never match.
    ///
    /// `supersedes` has no reader on the `ClaimSummary` path today, but it is
    /// projected anyway: leaving a `Claim` field fabricated because nothing
    /// currently reads it is precisely how `is_current` rotted, and the two
    /// belong to the same retirement state. Every other retirement-aware
    /// reader ([`Self::get_by_id`], [`Self::get_by_id_with_labels`],
    /// [`Self::list_by_labels`]) post-fixes both.
    ///
    /// Uses a local `Row` rather than the shared [`ClaimRow`] because that
    /// struct backs five other SELECTs that don't project these columns, and
    /// `claim_from_row`'s signature stays untouched per `CLAUDE.md` — same
    /// shape as [`Self::list_by_labels`].
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> Result<Vec<Claim>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let search_pattern = search.map(|s| format!("%{}%", s));

        // Two shapes, two bind indices: the ILIKE shape consumes $3, so the
        // group bind lands at $4 there and at $3 without it.
        let (query_str, vis_bind) = if search_pattern.is_some() {
            (
                r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at,
                   COALESCE(is_current, true) AS is_current, supersedes
            FROM claims
            WHERE content ILIKE $3
              /* {VISIBILITY:claims} */
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
                4,
            )
        } else {
            (
                r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at,
                   COALESCE(is_current, true) AS is_current, supersedes
            FROM claims
            WHERE true /* {VISIBILITY:claims} */
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
                3,
            )
        };
        let sql = viewer.splice(query_str, vis_bind);

        let mut query = sqlx::query_as::<_, Row>(&sql).bind(limit).bind(offset);

        if let Some(s) = search_pattern {
            query = query.bind(s);
        }
        if let Some(g) = viewer.group_bind() {
            query = query.bind(g);
        }

        let rows = query.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            // Post-fix retirement state; `claim_from_row` defaults these to
            // (true, None) regardless of what the row actually says.
            claim.is_current = row.is_current;
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            claims.push(claim);
        }

        Ok(claims)
    }

    /// WHERE clause shared verbatim by [`Self::list_filtered`] and
    /// [`Self::count_filtered`].
    ///
    /// Every predicate is guarded by `$n IS NULL OR …` and every parameter is
    /// bound unconditionally in a fixed order (see [`Self::bind_filter`]), so
    /// the two queries cannot drift apart: there is one clause string and one
    /// bind order, used by both.
    ///
    /// # The visibility marker is NOT in here, and that was a deliberate reversal
    ///
    /// It was, briefly: appending `/* {VISIBILITY:claims} */` to this constant
    /// makes both methods inherit the tenancy predicate by construction, which
    /// is the same argument the constant itself rests on. It also makes both
    /// methods invisible to
    /// `crates/epigraph-db/tests/visibility_lint.rs::every_spliced_statement_carries_the_canonical_marker_spelling`,
    /// which scans the FUNCTION BODY — measured: it reported both as splicing
    /// marker-free SQL. Hiding the marker from the ratchet that checks for its
    /// ABSENCE buys a construction guarantee by disabling a control, which is
    /// the wrong trade.
    ///
    /// So each method writes the marker itself, and three things hold it in
    /// place:
    ///
    /// * [`crate::visibility::Viewer::splice`] PANICS on SQL carrying no
    ///   marker, so removing it from either body fails that method's first
    ///   execution rather than silently widening it. Both are executed by
    ///   `tests/claim_list_filtered.rs`.
    /// * `visibility_lint` fails the build if a `.splice(` body carries no
    ///   marker at all.
    /// * `claim_list_filtered.rs::the_viewer_filters_both_halves_of_the_pair`
    ///   asserts the two AGREE against a corpus containing rows the viewer
    ///   cannot read — the assertion neither of the controls above can make,
    ///   because each sees one statement at a time.
    ///
    /// That last one is the invariant that matters. A `total` computed over a
    /// different predicate set than the rows it describes is backlog
    /// `2265a67b`, and "the rows are viewer-filtered but the count is not" is
    /// that defect in its widest form — `total` reporting the whole corpus
    /// while the page shows one tenant's slice.
    ///
    /// The bind indices differ (`$10` for the count, `$12` after
    /// `LIMIT`/`OFFSET`), so the viewer half of these two statements could
    /// never have been literally shared anyway.
    const FILTER_WHERE: &'static str = r#"
            WHERE ($1::text IS NULL OR content ILIKE $1)
              AND ($2::float8 IS NULL OR truth_value >= $2)
              AND ($3::float8 IS NULL OR truth_value <= $3)
              AND ($4::uuid IS NULL OR agent_id = $4)
              AND ($5::uuid IS NULL OR agent_id <> $5)
              AND ($6::bool IS NULL OR COALESCE(is_current, true) = $6)
              AND ($7::timestamptz IS NULL OR created_at >= $7)
              AND ($8::timestamptz IS NULL OR created_at <= $8)
              AND ($9::uuid[] IS NULL OR id = ANY($9))
    "#;

    /// Bind `$1..$9` of [`Self::FILTER_WHERE`], in order.
    ///
    /// Generic over the query type so `query_as` (rows) and `query_scalar`
    /// (count) share one implementation — the binds cannot diverge between
    /// the two call sites because there is only one.
    fn bind_filter<'q, O>(
        query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
        search_pattern: Option<String>,
        filter: &ClaimListFilter<'_>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        query
            .bind(search_pattern)
            .bind(filter.truth_min)
            .bind(filter.truth_max)
            .bind(filter.agent_id)
            .bind(filter.exclude_agent_id)
            .bind(filter.is_current)
            .bind(filter.created_after)
            .bind(filter.created_before)
            .bind(filter.ids.map(|ids| ids.to_vec()))
    }

    /// `%`-wrap the substring search, or `None` when no search was requested.
    fn filter_search_pattern(filter: &ClaimListFilter<'_>) -> Option<String> {
        filter.search.map(|s| format!("%{}%", s))
    }

    /// Count the claims matching `filter` — a real `COUNT(*)` over the whole
    /// table, evaluated by PostgreSQL.
    ///
    /// Paired with [`Self::list_filtered`], which applies the identical
    /// predicates before `LIMIT`. Callers must use the pair: the previous
    /// approach (fetch a capped window, filter in memory, report the slice
    /// length as `total`) both understated the count and, because the window
    /// was always the most-recent rows, returned an empty set for filters that
    /// only match older claims — indistinguishable from a true zero
    /// (backlog `2265a67b`).
    ///
    /// Uses the runtime `query_scalar` form (no compile-time `.sqlx` cache
    /// entry) to keep `cargo sqlx prepare` out of this change's footprint —
    /// same rationale as [`Self::contents_by_ids`] and [`Self::labels_by_ids`].
    ///
    /// The tracing span skips `filter` and records only `id_count`: `filter`
    /// carries an unbounded `ids` slice (the `methodology` / `evidence_type`
    /// pre-resolution has no `LIMIT`) and the raw caller-supplied `search`
    /// string, and `#[instrument]` records fields eagerly at INFO — which the
    /// deployed `EnvFilter` admits. See [`Self::list_filtered`] for the same
    /// treatment.
    ///
    /// # The viewer is not optional, and neither is running it on the SAME
    /// executor as [`Self::list_filtered`]
    ///
    /// Two statements describe one population only if both saw the same corpus.
    /// Splicing the viewer into both but running one on a pooled connection and
    /// the other on the handler's viewer-stamped one restores `2265a67b` in a
    /// new form: under `SessionGucMode::Transaction` the stamped handle is also
    /// a transaction, so the unstamped statement is a different snapshot AND —
    /// once migration 079 FORCEs RLS — carries no `epigraph.group_ids` GUC for
    /// the policies to read. Hence `E: PgExecutor`, so a caller passes the one
    /// `&mut *read` to both.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] if the database query fails.
    #[instrument(skip(executor, viewer, filter), fields(id_count = filter.ids.map(|ids| ids.len())))]
    pub async fn count_filtered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        filter: &ClaimListFilter<'_>,
    ) -> Result<i64, DbError> {
        // `bind_filter` consumes `$1..$9` and this statement has no `LIMIT`, so
        // the group bind is `$10` here and `$12` in `list_filtered`. The
        // marker is written here rather than carried by `FILTER_WHERE` — see
        // that constant's doc for why, and for what holds the two in step.
        let sql = viewer.splice(
            &format!(
                "SELECT COUNT(*) FROM claims{where_clause}\n              /* {{VISIBILITY:claims}} */",
                where_clause = Self::FILTER_WHERE,
            ),
            10,
        );
        // `query_scalar` is `query_as` over a 1-tuple; going through the
        // tuple form lets `bind_filter` serve both methods.
        let mut q = Self::bind_filter(
            sqlx::query_as::<_, (i64,)>(&sql),
            Self::filter_search_pattern(filter),
            filter,
        );
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let (count,): (i64,) = q.fetch_one(executor).await?;
        Ok(count)
    }

    /// List the claims matching `filter`, sorted and paginated **in SQL**.
    ///
    /// All predicates run before `LIMIT`/`OFFSET`, so a matching claim is
    /// reachable regardless of how recently it was created — the property
    /// [`Self::list_by_belief_range`] established (then for `truth_value`, now for the belief score) and this
    /// method generalises to the rest of the `GET /api/v1/claims` filter set.
    ///
    /// The returned `Claim`s are post-fixed with the row's `is_current` and
    /// `supersedes`; `claim_from_row`'s signature stays untouched per
    /// `CLAUDE.md`, same shape as [`Self::list`] and [`Self::list_by_labels`].
    ///
    /// `ORDER BY` is built from the [`ClaimSortField`] / [`ClaimSortOrder`]
    /// enums, never from caller-supplied strings, and carries an `id`
    /// tiebreaker so `LIMIT`/`OFFSET` paging is stable across rows sharing a
    /// `created_at` or `truth_value`.
    ///
    /// The tracing span skips `filter` for the reason given on
    /// [`Self::count_filtered`]; `limit`/`offset` are still recorded, and
    /// `id_count` keeps the cardinality without the payload.
    ///
    /// The `Viewer` is threaded and spent for the reason given on
    /// [`Self::count_filtered`], which also explains why both take an executor
    /// rather than a pool.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] if the database query fails, or
    /// [`DbError`] from [`TruthValue::new`] on an out-of-range stored value.
    #[instrument(skip(executor, viewer, filter), fields(id_count = filter.ids.map(|ids| ids.len())))]
    pub async fn list_filtered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        filter: &ClaimListFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Claim>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let sort_column = match filter.sort_by {
            ClaimSortField::CreatedAt => "created_at",
            ClaimSortField::TruthValue => "truth_value",
        };
        let direction = match filter.sort_order {
            ClaimSortOrder::Desc => "DESC",
            ClaimSortOrder::Asc => "ASC",
        };

        // `bind_filter` consumes `$1..$9`, `LIMIT`/`OFFSET` take `$10`/`$11`,
        // so the group bind is `$12`. The marker is the same literal
        // `count_filtered` writes, and `the_viewer_filters_both_halves_of_the_pair`
        // is what asserts the two statements agree about it.
        let sql = viewer.splice(
            &format!(
                r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at,
                   COALESCE(is_current, true) AS is_current, supersedes
            FROM claims{where_clause}
              /* {{VISIBILITY:claims}} */
            ORDER BY {sort_column} {direction}, id {direction}
            LIMIT $10 OFFSET $11
            "#,
                where_clause = Self::FILTER_WHERE,
            ),
            12,
        );

        let mut q = Self::bind_filter(
            sqlx::query_as::<_, Row>(&sql),
            Self::filter_search_pattern(filter),
            filter,
        )
        .bind(limit)
        .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            // Post-fix retirement state; `claim_from_row` defaults these to
            // (true, None) regardless of what the row actually says.
            claim.is_current = row.is_current;
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            claims.push(claim);
        }

        Ok(claims)
    }

    /// List claims whose **belief score** falls within `[min_belief,
    /// max_belief]`, most-recent first, each paired with that score. The range
    /// filter is applied in SQL **before** `LIMIT`, so matching claims are
    /// reachable regardless of how recently they were created.
    ///
    /// # The score, not `truth_value` (GitHub #395, G10)
    ///
    /// This was `list_by_truth_range` and filtered `truth_value >= $1 AND
    /// truth_value <= $2`. No DS write path refreshes `truth_value`, so a claim
    /// refuted by epistemic edges (BetP 0.18) kept its stale authored value
    /// (0.78) and never entered a `query_claims(max_truth=0.4)` assessment
    /// queue, while `recall(min_truth=…)`, which gates on BetP, excluded it. It
    /// now filters AND returns [`EFFECTIVE_BELIEF_SCORE_SQL`], the one spelling
    /// `effective_belief_batch` uses, so the two tools cannot disagree about the
    /// same row again. It was renamed because a function named "truth range"
    /// that filters something else is the next caller's trap.
    ///
    /// # Deterministic paging
    ///
    /// `ORDER BY created_at DESC, id`. It was `created_at DESC` alone while the
    /// function exposes `offset`, so two claims sharing a `created_at` (a batch
    /// insert, one transaction's `now()`) could swap places between pages —
    /// repeating one and skipping the other.
    ///
    /// This exists because the obvious `list()` + post-query filter can only
    /// ever inspect the first `limit` most-recent rows — a matching claim
    /// outside that window is silently invisible (backlog bug `5a55a48e`:
    /// `query_claims(max_truth=0.75)` returned empty while matching claims
    /// existed).
    ///
    /// `is_current` filters retirement state in SQL for the same reason:
    /// `Some(true)` = current claims only, `Some(false)` = superseded only,
    /// `None` = both. The returned `Claim`s carry the row's real `is_current`
    /// and `supersedes` (post-fixed after `claim_from_row`, whose signature
    /// stays untouched per `CLAUDE.md`), so a caller can no longer assert
    /// currency it never read — the defect `ClaimRepository::list` had in
    /// backlog `f1992766` and this query still had in `a85ee585`.
    ///
    /// # `exclude_spine`
    ///
    /// When `true`, every claim whose `properties.level` is 0, 1 or 2 is
    /// dropped in SQL *before* `LIMIT`. The target is the verbatim document
    /// spine (thesis, section heading, paragraph), but the predicate reads
    /// `level` alone, so workflow thesis/phase/step nodes (the workflow
    /// builder, the ingest executor's steps, `evolve_step` rows, which carry
    /// no `source_type`) go too. Narrowing by `source_type` would leak the
    /// `evolve_step` rows, so the predicate deliberately does not.
    ///
    /// Backlog `31e7b727`: the `max_truth=0.4` assessment page is
    /// newest-first, and "Keywords:" lists, captions, headings and transcript
    /// turns, each carrying its paragraph's low extraction confidence, filled
    /// it (64% of the newest 50 low-truth rows on prod, 2026-10-14) before the
    /// agent could discard them; the same reason the range itself is filtered
    /// before `LIMIT` (`5a55a48e`). Atoms (level 3) and claims with no `level`
    /// at all (`submit_claim`, `memorize`) are kept. The comparison is on the
    /// text value, never a cast, so an absent or odd `level` cannot raise.
    /// `false` folds the predicate away and leaves the page unchanged.
    ///
    /// # Bind layout
    ///
    /// `is_current` occupies `$3` and `exclude_spine` `$6`, so the viewer's
    /// group bind is `$7`. The group bind is conditional (a `Bypass` or
    /// elevated viewer binds nothing), so it must stay LAST: were it `$6`, a
    /// bind-less viewer would leave the statement one value short of the
    /// `$7` it references.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_by_belief_range<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        min_belief: f64,
        max_belief: f64,
        is_current: Option<bool>,
        limit: i64,
        offset: i64,
        exclude_spine: bool,
    ) -> Result<Vec<(Claim, f64)>, DbError> {
        // Inline row type, NOT the shared `ClaimRow`: adding these columns to
        // `ClaimRow` would break every other `query_as::<_, ClaimRow>` whose
        // SELECT omits them, and at runtime rather than at compile time.
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            is_current: bool,
            supersedes: Option<Uuid>,
            belief_score: f64,
        }

        // The score is computed once in the inner SELECT and both filtered and
        // returned from there. `concat`, not `format!`, so the visibility marker
        // stays a plain literal for `tests/visibility_lint.rs`'s scanners.
        let sql = viewer.splice(
            &[
                r#"
            SELECT * FROM (
                SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at,
                       COALESCE(is_current, true) AS is_current, supersedes,
                       "#,
                EFFECTIVE_BELIEF_SCORE_SQL,
                r#" AS belief_score
                FROM claims
                WHERE ($3::bool IS NULL OR COALESCE(is_current, true) = $3)
                  AND (NOT $6::bool OR COALESCE(properties->>'level', '') NOT IN ('0', '1', '2'))
                  /* {VISIBILITY:claims} */
            ) scored
            WHERE belief_score >= $1 AND belief_score <= $2
            ORDER BY created_at DESC, id
            LIMIT $4 OFFSET $5
            "#,
            ]
            .concat(),
            7,
        );
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(min_belief)
            .bind(max_belief)
            .bind(is_current)
            .bind(limit)
            .bind(offset)
            .bind(exclude_spine);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            claim.is_current = row.is_current;
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            claims.push((claim, row.belief_score));
        }
        Ok(claims)
    }

    /// Returns `true` iff **every** id in `ids` exists AND has
    /// `is_current = true`.
    ///
    /// A missing id, a superseded claim (`is_current = false` via
    /// [`Self::supersede`]), or a duplicate (via [`Self::mark_duplicate`])
    /// all yield `false`. Used to guard structural-edge creation against
    /// stale/duplicate endpoints — e.g. a CORROBORATES edge must not point at
    /// a claim that has already been retired (backlog bug `5c7fc645`).
    pub async fn are_all_current<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<bool, DbError> {
        if ids.is_empty() {
            return Ok(true);
        }
        // Filtered, so an invisible endpoint reads as "not current" and the
        // structural-edge guard refuses rather than silently wiring a claim the
        // caller cannot see.
        let sql = viewer.splice(
            "SELECT COUNT(*) FROM claims \
             WHERE id = ANY($1) AND COALESCE(is_current, true) = true \
             /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let live: i64 = q.fetch_one(executor).await?;
        // Distinct ids must each be present-and-current. A missing or
        // non-current id lowers the count below the distinct cardinality.
        let distinct: std::collections::HashSet<&uuid::Uuid> = ids.iter().collect();
        Ok(live as usize == distinct.len())
    }

    /// Each of `ids` the viewer reads, with whether it is current, LOCKED
    /// `FOR NO KEY UPDATE` (in id order) until the caller's transaction ends.
    ///
    /// The locking twin of [`Self::are_all_current`], for a check that a later
    /// write in the same transaction relies on (a dedup mark onto a canonical
    /// that must stay current). Supersede, deprecate, consolidate and mark
    /// retire a claim with a plain `UPDATE` (itself a `FOR NO KEY UPDATE`
    /// lock), which this conflicts with: a retirement that has not committed
    /// when this runs is waited for and its result read; one that starts
    /// afterwards waits for the caller's commit. `FOR KEY SHARE` would not
    /// conflict with it at all. `FOR SHARE` would, but two callers would then
    /// both hold the row and deadlock when each goes on to `UPDATE` it (a
    /// label-dedup unit relabels its canonical after marking onto it), where
    /// `FOR NO KEY UPDATE` makes the second wait for the first and then read
    /// its result. It does not conflict with `FOR KEY SHARE`, so a foreign-key
    /// check against the row is not blocked.
    ///
    /// `is_current` is returned, not filtered on: under READ COMMITTED a row
    /// retired while this waited is re-read and comes back `false`, rather
    /// than vanishing. An id absent from the result is missing, invisible, or
    /// not lockable by the session (a locking read takes the UPDATE row
    /// policy, which admits only rows in the session's writable groups).
    ///
    /// # Errors
    /// `DbError::QueryFailed`.
    pub async fn current_state_locked<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<Vec<(uuid::Uuid, bool)>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "SELECT id, COALESCE(is_current, true) FROM claims \
             WHERE id = ANY($1) \
             /* {VISIBILITY:claims} */ \
             ORDER BY id FOR NO KEY UPDATE OF claims",
            2,
        );
        let mut q = sqlx::query_as::<_, (uuid::Uuid, bool)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Fetch `(id, content)` for a batch of claim ids, current rows only.
    ///
    /// Lightweight companion to the structural enrichment in
    /// `epigraph-mcp`'s `fetch_batched_context`: the rerank pipeline needs
    /// the candidate *text* to score query-relevance, but must NOT pay for
    /// siblings/corroborates/neighbor joins until AFTER it has truncated the
    /// widened pool down to the final `limit`. Returns a `HashMap` so the
    /// caller can look up content by id in any order (ANN result order is
    /// not preserved by `id = ANY(...)`). Missing/non-current ids are simply
    /// absent from the map.
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry)
    /// to keep `cargo sqlx prepare` out of this change's footprint.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn contents_by_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashMap<uuid::Uuid, String>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let sql = viewer.splice(
            "SELECT c.id, c.content FROM claims c \
             WHERE c.id = ANY($1) AND COALESCE(c.is_current, true) = true \
             /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (uuid::Uuid, String)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch `(id, content)` for a batch of claim ids **at any version**.
    ///
    /// Identical to [`Self::contents_by_ids`] except that it does not filter
    /// `is_current`. It exists because that filter is a *contract of the rerank
    /// pool*, not a property of "fetch some content" — and PR-09 nearly
    /// exported it as one.
    ///
    /// `epigraph-api`'s `routes/cross_source.rs::list_candidates` replaced an
    /// inline `SELECT id, content FROM claims WHERE id = ANY($1)` (no
    /// `is_current`) with a call to `contents_by_ids` (which has one).
    /// `match_candidates` rows are long-lived and routinely name claims that
    /// are later retired by `supersede_claim` / `mark_duplicate`, and nothing
    /// prunes the queue when that happens — so every such row would have
    /// rendered as the literal string `"(claim not found)"` for a claim that
    /// does exist. That is a silent narrowing of an endpoint whose own doc
    /// advertises "verbatim content excerpts of both claims in each pair", and
    /// it is unrelated to tenancy. A separate function rather than a
    /// `bool` parameter: a boolean at a security-relevant read is a flag that
    /// eventually gets passed wrong, and `contents_by_ids`'s current-only
    /// contract is pinned by name in
    /// `contents_by_ids_returns_current_only_and_skips_missing`.
    ///
    /// The visibility predicate is identical, so this is not a widening of read
    /// authority — only of version scope.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn contents_by_ids_any_version<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashMap<uuid::Uuid, String>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let sql = viewer.splice(
            "SELECT c.id, c.content FROM claims c \
             WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (uuid::Uuid, String)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;
        Ok(rows.into_iter().collect())
    }

    /// The subset of `ids` that name a `claims` row this viewer **cannot**
    /// read.
    ///
    /// The Rust-callable half of the rule
    /// [`crate::repos::EventRepository::list`] implements in SQL, for callers
    /// that hold rows the database cannot filter — specifically
    /// `epigraph-api`'s `list_events`, which merges an in-process ring buffer
    /// (`global_event_store()`) into the same response as the persisted table.
    /// Filtering only the SQL half would have left the merge as the trivial
    /// bypass for the filter, and the ring buffer is not a no-db artefact: the
    /// `db`-build handlers in `routes/edges.rs`, `routes/belief.rs` and
    /// `routes/community.rs` all push into it.
    ///
    /// "Cannot read" is deliberately narrower than "is absent from the
    /// result": an id that names **no** row at all is not returned, because
    /// there is no row to classify and no owner to protect. Only
    /// *existing-but-invisible* ids come back, so a caller that drops its
    /// records on a non-empty intersection matches the SQL exactly.
    ///
    /// # BOTH ARMS RUN INSIDE A DEFINER FRAME — THIS IS STILL NOT A CONVERSION SITE
    ///
    /// The set difference below asks two questions: *does this id name a row*
    /// (first arm) and *may this viewer read it* (second, spliced arm). It only
    /// answers anything while the two arms have **different authority**.
    ///
    /// Read against `claims` directly, they do not, once migration 079's FORCE
    /// posture is live on an application role: `claims_tenancy` (077) filters
    /// both, its `USING` predicate keys on `epigraph_session_groups()` — the
    /// session GUCs — and the difference collapses. That was
    /// `F-PR23-existence-probe-collapses-under-force`, and an empty result is
    /// read by both callers as "nothing is hidden", so the failure was
    /// uninformative rather than conservative. **It could not be repaired by
    /// stamping the connection**: `epigraph_bypass()` and
    /// `epigraph_definer_bypass()` are role-based (`session_user` /
    /// `current_user`) and unreachable from `ScopedPool::apply_session_gucs`.
    ///
    /// Migration **086** repairs it by moving *both* arms into a
    /// `SECURITY DEFINER` frame — `public.epigraph_claim_tenancy_by_ids(uuid[])`,
    /// which returns `(id, visibility, owner_group_id)` for caller-named ids and
    /// never content — and splicing the viewer predicate over that function's
    /// output instead of over `claims`. The only filter left on either arm is
    /// then the viewer's own predicate, which is the authority this signature
    /// promises.
    ///
    /// ## Why the existence arm alone was not enough
    ///
    /// Measured on the throwaway at head 91 with FORCE live. With only the
    /// existence arm in the frame, the spliced arm is *still* narrowed by the
    /// policy to `visibility = 'public'` whatever `$V` binds — so on an
    /// **unstamped** connection carrying a **member** viewer, a group-private
    /// claim the viewer is entitled to read comes back reported hidden, and
    /// both callers drop its delivery. That is the shape both call sites
    /// actually have: they take a raw `&PgPool` as a parameter and nothing
    /// stamps it (`D-PR17-request-path-never-stamps-session-gucs`). Splicing
    /// over the function's output is what makes the answer independent of
    /// whether the session is stamped, unstamped, or incoherently stamped.
    ///
    /// ## What did NOT change
    ///
    /// * A `Bypass` viewer still short-circuits through the existing mechanism:
    ///   `splice` renders it to a bare separator, the two arms coincide, and
    ///   the difference is empty. No hand-rolled branch.
    /// * The contract above — an id naming **no** row is not reported — is
    ///   unchanged and is what `locked_decisions.rs` pins for both callers.
    /// * The two callers (`epigraph-api`'s `routes/webhooks.rs` and
    ///   `routes/events.rs`) must **still not** be "converted" onto
    ///   `AppState::read_as`. Closing this probe does not by itself make them
    ///   safe to convert; that is a separate decision, and the do-not-convert
    ///   rule in `epigraph-db/tests/no_unscoped_pool.rs` is updated rather than
    ///   removed. Step 11d also remains blocked on
    ///   `D-PR17-request-path-never-stamps-session-gucs`; this discharged one
    ///   precondition, not the gate.
    ///
    /// The behaviour is pinned by
    /// `epigraph-db/tests/rls_enforcement.rs::hidden_claim_ids_still_classifies_on_the_app_role_under_force`,
    /// which runs on a real `epigraph_app` session and carries an
    /// owner-connection calibration arm — the unit test below runs on the
    /// superuser harness pool, where no policy applies, and therefore cannot
    /// distinguish a working probe from a broken one.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn hidden_claim_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashSet<uuid::Uuid>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        // EXCEPT rather than a negated predicate: `render_predicate` produces a
        // positive `AND (...)` fragment and there is no spelling of the marker
        // that inverts it. Set difference gets the same answer without asking
        // the splice mechanism to do something it was not built for.
        //
        // The CTE is not cosmetic: it calls the definer ONCE for both arms, so
        // the two cannot disagree about the row set, and it gives the spliced
        // arm an alias to hang `/* {VISIBILITY:c} */` on. `WHERE true` is the
        // established spelling for a marker with no other predicate to append
        // to (see `repos/frame.rs`, `repos/community.rs`).
        let sql = viewer.splice(
            "WITH t AS ( \
                 SELECT id, visibility, owner_group_id \
                   FROM public.epigraph_claim_tenancy_by_ids($1) \
             ) \
             SELECT id FROM t \
             EXCEPT \
             SELECT c.id FROM t c WHERE true /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, uuid::Uuid>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?.into_iter().collect())
    }

    /// The subset of `ids` that are claims `viewer` may read.
    ///
    /// The positive twin of [`Self::hidden_claim_ids`], over the same definer
    /// (`epigraph_claim_tenancy_by_ids`), so it answers the same on any
    /// connection: a caller's RLS-filtered session, or the privileged
    /// maintenance connection a request path's administrative cascade runs on.
    /// Every id that is not a claim the viewer can read -- a hidden claim, a
    /// missing one, an edge id -- is absent. That makes it the filter for what
    /// an administrative act may report back to the caller that triggered it
    /// (migration 117): an id outside this set is not the caller's to learn.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn visible_claim_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashSet<uuid::Uuid>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let sql = viewer.splice(
            "SELECT c.id FROM public.epigraph_claim_tenancy_by_ids($1) c \
              WHERE true /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, uuid::Uuid>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?.into_iter().collect())
    }

    /// Fetch `labels` for a batch of claim ids in one round-trip.
    ///
    /// Batch companion to [`Self::get_labels`], used by MCP `query_claims` to
    /// populate `ClaimResponse.labels` without an N+1 fan-out of per-claim
    /// `get_labels` calls (backlog bug `babd5904`: `query_claims` hardcoded
    /// `labels: Vec::new()`).
    ///
    /// Deliberately does **NOT** filter on `is_current`. Whether superseded
    /// rows reach this helper is the *caller's* decision — `query_claims`
    /// passes `is_current` through to [`Self::list_by_belief_range`] and may
    /// legitimately ask for superseded rows — and the single-claim label
    /// source this mirrors (`get_labels` → `SELECT labels FROM claims WHERE
    /// id = $1`) has no `is_current` clause either. Filtering here would
    /// silently drop labels for whichever superseded rows the caller
    /// deliberately selected — the same bug class, narrowed. A missing id is
    /// simply absent from the map (caller treats absence as "no labels").
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry)
    /// to keep `cargo sqlx prepare` out of this change's footprint.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn labels_by_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashMap<uuid::Uuid, Vec<String>>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let sql = viewer.splice(
            "SELECT id, COALESCE(labels, ARRAY[]::text[]) FROM claims \
             WHERE id = ANY($1) /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (uuid::Uuid, Vec<String>)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;
        Ok(rows.into_iter().collect())
    }

    /// List claims that contain ALL of the specified labels.
    ///
    /// Uses the GIN index on `claims.labels` for efficient `@>` containment queries.
    /// Results are ordered by `(created_at DESC, id DESC)`, a total order, and
    /// filtered by optional truth threshold.
    ///
    /// # Paging
    /// - `after` (keyset, preferred): rows strictly after a [`LabelCursor`]
    ///   taken from the previous page with [`LabelCursor::next_page`]. A
    ///   boundary does not drift when rows are inserted or retired between
    ///   pages, and the sort keeps `limit` rows rather than `limit + offset`.
    ///   It is not an index seek: there is no `(created_at, id)` index and
    ///   the predicate is optional (`$7 IS NULL OR ...`), so the planner may
    ///   still read every matching row (via the labels GIN index) and top-N
    ///   sort it. A composite index is a follow-up if a re-measure shows the
    ///   scan itself matters.
    /// - `offset` (compatibility): skip N rows. It still applies when `after`
    ///   is set, but the API surfaces refuse that combination.
    ///
    /// # Filters
    /// - `exclude_labels`: drop any claim whose label set intersects this
    ///   collection (PostgreSQL `&&` overlap operator). Empty slice = no
    ///   exclusion.
    /// - `current_only`: when true, restrict to `is_current = true` (drops
    ///   superseded rows).
    ///
    /// # Returns
    /// Pairs of `(Claim, labels)`. The returned `Claim` is post-fixed with the
    /// row's `is_current` and `supersedes` values so callers can distinguish
    /// live, resolved, and superseded claims without re-querying.
    ///
    /// The inline `Row` struct keeps the global [`ClaimRow`] (used by other
    /// queries that don't need these columns) untouched, and we don't widen
    /// `claim_from_row`'s signature — its other ~20 callers don't care about
    /// retirement state.
    #[instrument(skip(executor, viewer))]
    pub async fn list_by_labels<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query: LabelQuery<'_>,
    ) -> Result<Vec<(Claim, Vec<String>)>, DbError> {
        let LabelQuery {
            labels,
            exclude_labels,
            current_only,
            min_truth,
            limit,
            offset,
            after,
        } = query;
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            labels: Vec<String>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at, c.labels, c.is_current, c.supersedes
            FROM claims c
            WHERE c.labels @> $1
              AND c.truth_value >= $2
              AND ($3::text[] = '{}'::text[] OR NOT (c.labels && $3))
              AND ($4 = false OR COALESCE(c.is_current, true) = true)
              AND ($7::timestamptz IS NULL OR (c.created_at, c.id) < ($7::timestamptz, $8::uuid))
              /* {VISIBILITY:c} */
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT $5
            OFFSET $6
            "#,
            9,
        );
        let mut q = sqlx::query_as::<_, Row>(&sql)
            .bind(labels)
            .bind(min_truth)
            .bind(exclude_labels)
            .bind(current_only)
            .bind(limit)
            .bind(offset)
            .bind(after.map(|a| a.created_at))
            .bind(after.map(|a| a.id));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            claim.is_current = row.is_current;
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            out.push((claim, row.labels));
        }
        Ok(out)
    }

    /// Every claim carrying ALL of `include` and NONE of `exclude`, in id
    /// order, with no offset: a whole label family in one deterministic read.
    ///
    /// Returns at most `cap + 1` rows. A caller that receives more than `cap`
    /// knows the family is larger than its cap and must treat the read as
    /// truncated (the planner refuses to act on a prefix), which offset paging
    /// over `created_at` could never tell it: a page boundary drifts under
    /// concurrent writes.
    ///
    /// Viewer-scoped: rows the viewer cannot read are absent. Under forced
    /// row security a group-private row is visible only on a connection
    /// stamped from a viewer that reads its group, so call it on
    /// `ScopedPool::read_as`.
    ///
    /// # Errors
    /// `DbError::InvalidData` when `include` is empty (that would read every
    /// claim) or `cap` is negative; `DbError::QueryFailed` on a database
    /// failure.
    #[instrument(skip(executor, viewer))]
    pub async fn list_all_by_labels_ordered_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        include: &[String],
        exclude: &[String],
        current_only: bool,
        cap: i64,
    ) -> Result<Vec<LabelFamilyRow>, DbError> {
        if include.is_empty() {
            return Err(DbError::InvalidData {
                reason: "a label-family read needs at least one include label; an empty set \
                         would read every claim"
                    .to_string(),
            });
        }
        if cap < 0 {
            return Err(DbError::InvalidData {
                reason: format!("a label-family read needs a non-negative cap, got {cap}"),
            });
        }
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, COALESCE(c.labels, ARRAY[]::text[]) AS labels, c.created_at
            FROM claims c
            WHERE c.labels @> $1
              AND ($2::text[] = '{}'::text[] OR NOT (c.labels && $2))
              AND ($3 = false OR COALESCE(c.is_current, true) = true)
              /* {VISIBILITY:c} */
            ORDER BY c.id
            LIMIT $4
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, LabelFamilyRow>(&sql)
            .bind(include)
            .bind(exclude)
            .bind(current_only)
            .bind(cap.saturating_add(1));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The label-dedup `index_view`: for each of `canonicals`, every claim
    /// marked a duplicate of it, down a chain (a duplicate of a duplicate, to
    /// [`MAX_DUPLICATE_CHAIN_DEPTH`]), through IN-FORCE dedup identity edges
    /// only (`same_as` carrying `properties.dedup`; a plain `same_as`, or the
    /// retracted edge of an un-marked duplicate, is not followed). Only
    /// non-current claims are returned (a marked duplicate is retired).
    ///
    /// The walk looks one step past the bound: a duplicate found there is not
    /// returned, and [`MarkedDuplicates::chain_truncated`] says the chain went
    /// on, so a caller never takes a cut-off chain for a whole one.
    ///
    /// Filtered by `viewer` on every edge and claim it reads: a duplicate the
    /// viewer cannot read is not returned, so a caller that needs every
    /// duplicate must use a viewer that reads them all.
    ///
    /// Ordered by `(canonical, id)`; at most `cap + 1` rows, so a caller sees
    /// that more than `cap` exist.
    ///
    /// # Errors
    /// `DbError::InvalidData` for a negative cap; `DbError::QueryFailed`.
    pub async fn marked_duplicates_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        canonicals: &[Uuid],
        cap: i64,
    ) -> Result<MarkedDuplicates, DbError> {
        if cap < 0 {
            return Err(DbError::InvalidData {
                reason: format!("an index-view read needs a non-negative cap, got {cap}"),
            });
        }
        if canonicals.is_empty() {
            return Ok(MarkedDuplicates::default());
        }
        // `walk` goes to depth $4 + 1; `hits` keeps what the viewer reads and
        // marks the rows past the bound; `kept` is the capped answer. The
        // final LEFT JOIN returns the flag even when nothing is kept.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE walk(canonical, dup, depth) AS (
                SELECT e.target_id, e.source_id, 1
                  FROM edges e
                 WHERE e.target_id = ANY($1) AND e.target_type = 'claim'
                   AND e.source_type = 'claim' AND e.relationship = $2
                   AND e.valid_to IS NULL AND e.properties ? $3
                   /* {EDGE_VISIBILITY:e} */
                UNION
                SELECT w.canonical, e.source_id, w.depth + 1
                  FROM walk w
                  JOIN edges e ON e.target_id = w.dup
                 WHERE e.target_type = 'claim' AND e.source_type = 'claim'
                   AND e.relationship = $2 AND e.valid_to IS NULL AND e.properties ? $3
                   AND w.depth <= $4
                   /* {EDGE_VISIBILITY:e} */
            ),
            hits AS (
                SELECT w.canonical, c.id, c.content,
                       COALESCE(c.labels, ARRAY[]::text[]) AS labels, c.created_at,
                       c.agent_id, k.agent_id AS canonical_agent_id,
                       w.depth > $4 AS beyond
                  FROM walk w
                  JOIN claims c ON c.id = w.dup
                  JOIN claims k ON k.id = w.canonical
                 WHERE NOT COALESCE(c.is_current, true) AND c.id <> w.canonical
                   /* {VISIBILITY:c} */
                   /* {VISIBILITY:k} */
            ),
            kept AS (
                SELECT DISTINCT canonical, id, content, labels, created_at,
                       agent_id, canonical_agent_id
                  FROM hits
                 WHERE NOT beyond
                 ORDER BY canonical, id
                 LIMIT $5
            )
            SELECT EXISTS (SELECT 1 FROM hits WHERE beyond) AS chain_truncated,
                   kept.canonical, kept.id, kept.content, kept.labels, kept.created_at,
                   kept.agent_id, kept.canonical_agent_id
              FROM (SELECT 1) AS one
              LEFT JOIN kept ON true
             ORDER BY kept.canonical, kept.id
            "#,
            6,
        );
        let mut q = sqlx::query_as::<_, MarkedDuplicateWalkRow>(&sql)
            .bind(canonicals)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY)
            .bind(MAX_DUPLICATE_CHAIN_DEPTH)
            .bind(cap.saturating_add(1));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let walked = q.fetch_all(executor).await?;
        let chain_truncated = walked.first().is_some_and(|r| r.chain_truncated);
        let rows = walked
            .into_iter()
            .filter_map(|r| {
                Some(MarkedDuplicateRow {
                    canonical: r.canonical?,
                    id: r.id?,
                    content: r.content?,
                    labels: r.labels?,
                    created_at: r.created_at?,
                    agent_id: r.agent_id?,
                    canonical_agent_id: r.canonical_agent_id?,
                })
            })
            .collect();
        Ok(MarkedDuplicates {
            rows,
            chain_truncated,
        })
    }

    /// The in-force dedup identity edge out of `dup` (`same_as` carrying
    /// `properties.dedup`), with the claim it names, when the viewer can read
    /// it: which mark a claim currently carries, so a revert can tell the mark
    /// it made from a later one onto the same canonical.
    ///
    /// # Errors
    /// `DbError::QueryFailed`.
    pub async fn dedup_identity_edge_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        dup: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.id, e.target_id
              FROM edges e
             WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim'
               AND e.relationship = $2 AND e.valid_to IS NULL AND e.properties ? $3
               /* {EDGE_VISIBILITY:e} */
             ORDER BY e.created_at DESC, e.id
             LIMIT 1
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql)
            .bind(dup)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }

    /// List claims that have NEVER been touched by decomposition: claims that
    /// are neither the source (parent) nor the target (child) of any
    /// `decomposes_to` edge.
    ///
    /// `decomposes_to` is parent -> child (source = compound/parent, target =
    /// atom/child) — see `epigraph_ingest::common::edges::decomposes_edge`
    /// ("Build a decomposes_to edge between two claim nodes ... for parent ->
    /// child relationships"). A leaf atom therefore has only an *incoming*
    /// decomposes_to edge, so an outgoing-only predicate would wrongly
    /// re-select every atom for re-decomposition. We exclude BOTH directions —
    /// matching V2 `scripts/export_decomposition_input.py`'s
    /// `NOT EXISTS (... source_id = c.id ...) AND NOT EXISTS (... target_id =
    /// c.id ...)` predicate — so only standalone claims created via
    /// non-hierarchical paths (`memorize`, `submit_claim`, workflow outputs,
    /// legacy imports) are returned.
    ///
    /// Excludes host-telemetry claims (the `telemetry` label OR a
    /// `properties->>'event'` marker) per the repo embedding policy — these
    /// are container/task lifecycle noise with no decomposable propositional
    /// content, and replace V2's brittle `content LIKE 'Agent sent message%'`
    /// skip-patterns. Also drops trivially short content (`length > 10`), the
    /// one filter ported verbatim from V2.
    ///
    /// Ordered `created_at ASC` (oldest first) so offset paging is stable.
    /// Claims that `epigraph_core::atomicity::looks_atomic` accepts are
    /// terminal by policy (U073, backlog `5e1debbc`): `decompose_claims` skips
    /// them, so they never leave this population and its row count is not a
    /// progress measure.
    ///
    /// Every returned row is current by the `WHERE` clause, so `claim_from_row`'s
    /// `is_current = true` default is already true here; `supersedes` is NOT
    /// (a current claim that replaced another carries a non-null link), so it
    /// is projected and post-fixed — the `claim_from_row` rule in `CLAUDE.md`.
    pub async fn list_undecomposed<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Claim>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            supersedes: Option<Uuid>,
        }

        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        // The two `NOT EXISTS` probes over `edges` are deliberately NOT marked:
        // they are exclusion tests, so filtering them would make a
        // decomposes_to edge the viewer cannot see stop excluding its claim —
        // widening the result set, not narrowing it. The `claims` alias carries
        // the predicate.
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at, c.supersedes
            FROM claims c
            WHERE COALESCE(c.is_current, true) = true
              AND length(c.content) > 10
              AND NOT ('telemetry' = ANY(c.labels))
              AND (c.properties ->> 'event') IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.source_id = c.id AND e.relationship = 'decomposes_to'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.target_id = c.id AND e.relationship = 'decomposes_to'
              )
              /* {VISIBILITY:c} */
            ORDER BY c.created_at ASC
            LIMIT $1 OFFSET $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, Row>(&sql).bind(limit).bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            claims.push(claim);
        }
        Ok(claims)
    }

    /// Search workflow-tagged claims by content text match.
    ///
    /// Used by find_workflow MCP tool as a fallback when semantic search via
    /// evidence embeddings returns insufficient results. Workflow claims are
    /// the canonical storage; the legacy `workflows` table is mostly empty.
    ///
    /// Excludes superseded claims (`is_current = false`) so callers never
    /// receive a deprecated workflow definition while a newer version exists.
    /// `supersedes` itself is NOT used as an exclusion predicate — the new
    /// claim populates `supersedes = $old` to record lineage, so filtering on
    /// `supersedes IS NULL` would silently drop the replacement.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn search_by_label_and_text<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        labels: &[String],
        text: &str,
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<Claim>, DbError> {
        let limit = limit.clamp(1, 1000);
        // Use the GIN-indexed `content_tsv` column so the text filter can hit
        // the `idx_claims_content_tsv` index (migration 050) instead of forcing
        // a sequential scan with a leading-wildcard ILIKE. `websearch_to_tsquery`
        // accepts free-form query strings and handles quoting internally.
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at
            FROM claims c
            WHERE c.labels @> $1
              AND c.content_tsv @@ websearch_to_tsquery('english', $2)
              AND c.truth_value >= $3
              AND COALESCE(c.is_current, true) = true
              /* {VISIBILITY:c} */
            ORDER BY c.truth_value DESC, c.created_at DESC
            LIMIT $4
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, ClaimRow>(&sql)
            .bind(labels)
            .bind(text)
            .bind(min_truth)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }
        Ok(claims)
    }

    /// Count total number of claims
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        search: Option<&str>,
    ) -> Result<i64, DbError> {
        let search_pattern = search.map(|s| format!("%{}%", s));

        let (query_str, vis_bind) = if search_pattern.is_some() {
            (
                r#"
            SELECT COUNT(*) as count
            FROM claims
            WHERE content ILIKE $1 /* {VISIBILITY:claims} */
            "#,
                2,
            )
        } else {
            (
                r#"
            SELECT COUNT(*) as count
            FROM claims
            WHERE true /* {VISIBILITY:claims} */
            "#,
                1,
            )
        };
        let sql = viewer.splice(query_str, vis_bind);

        let mut query = sqlx::query_scalar::<_, i64>(&sql);

        if let Some(s) = search_pattern {
            query = query.bind(s);
        }
        if let Some(g) = viewer.group_bind() {
            query = query.bind(g);
        }

        let row_count = query.fetch_one(executor).await?;

        Ok(row_count)
    }

    /// List claims with pagination within an existing transaction.
    ///
    /// Delegates to the generic form above, which accepts any executor —
    /// `&mut PgConnection` included — so the visibility predicate exists in
    /// exactly one SQL text. The hand-written duplicate this replaced was the
    /// same drift class `count_conn` was collapsed for: two copies of one
    /// tenancy predicate, only one of which a future fix reaches, and no gate
    /// can see the divergence because each copy carries its own marker.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn list_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> Result<Vec<Claim>, DbError> {
        Self::list(&mut *conn, viewer, limit, offset, search).await
    }

    /// Count total number of claims within an existing transaction.
    ///
    /// Delegates to the generic form above, which accepts any executor. The
    /// hand-written duplicate this replaced was the drift class that a gate
    /// cannot see: two copies of one predicate, only one of which gets fixed.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn count_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        search: Option<&str>,
    ) -> Result<i64, DbError> {
        Self::count(&mut *conn, viewer, search).await
    }

    /// Batch create multiple claims in a single transaction
    ///
    /// Uses PostgreSQL multi-value INSERT for efficiency. All claims are inserted
    /// atomically - if any insert fails, the entire batch is rolled back.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claims` - Slice of claims to insert
    /// * `decl` - the tenancy declaration applied to EVERY claim in the batch.
    ///   One declaration for the whole batch, not one per claim: a batch is a
    ///   single caller's single decision, and a per-claim vector would make it
    ///   possible to mix two groups' rows into one statement, which is the
    ///   shape `consolidate`'s cross-group refusal exists to forbid.
    ///
    /// # Returns
    /// Vector of created claims with server-generated timestamps
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    /// Returns `DbError::DuplicateKey` if any claim ID already exists.
    ///
    /// # Performance
    /// - Batch size is limited internally to prevent memory issues
    /// - For very large batches (>1000), consider chunking externally
    #[instrument(skip(pool, claims), fields(batch_size = claims.len()))]
    pub async fn batch_create(
        pool: &PgPool,
        claims: &[Claim],
        decl: TenancyDecl,
    ) -> Result<Vec<Claim>, DbError> {
        if claims.is_empty() {
            return Ok(Vec::new());
        }

        // Limit batch size to prevent memory issues (Architect review requirement)
        const MAX_BATCH_SIZE: usize = 1000;
        if claims.len() > MAX_BATCH_SIZE {
            tracing::warn!(
                "Batch size {} exceeds recommended maximum {}. Consider chunking.",
                claims.len(),
                MAX_BATCH_SIZE
            );
        }

        // Use a transaction for atomicity
        let mut tx = pool.begin().await?;

        // Build multi-value INSERT query dynamically
        // PostgreSQL supports multi-row VALUES: INSERT INTO t VALUES (...), (...), (...)
        let mut query_builder = String::from(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at, visibility, owner_group_id)
               VALUES "#,
        );

        // Build parameter placeholders and collect values.
        //
        // TEN placeholders per row, not eight: the two tenancy columns are
        // bound per row rather than hoisted into a single shared pair of
        // parameters. Hoisting would be fewer binds, but it would put the
        // declaration outside the per-row loop below and the two would drift
        // the first time someone made `decl` per-claim. The stride and the
        // bind order are the same arithmetic; keeping them adjacent is what
        // makes an off-by-two visible.
        const PARAMS_PER_ROW: usize = 10;
        let mut param_idx = 1;
        for (i, _) in claims.iter().enumerate() {
            if i > 0 {
                query_builder.push_str(", ");
            }
            let placeholders: Vec<String> = (0..PARAMS_PER_ROW)
                .map(|k| format!("${}", param_idx + k))
                .collect();
            query_builder.push('(');
            query_builder.push_str(&placeholders.join(", "));
            query_builder.push(')');
            param_idx += PARAMS_PER_ROW;
        }

        query_builder.push_str(
            " RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at",
        );

        // Pre-compute all content hashes to avoid lifetime issues
        // (hashes must outlive the query)
        let content_hashes: Vec<Vec<u8>> = claims
            .iter()
            .map(|c| ContentHasher::hash(c.content.as_bytes()).to_vec())
            .collect();

        // Build the query with all parameters
        let mut query = sqlx::query_as::<_, ClaimRow>(&query_builder);

        for (i, claim) in claims.iter().enumerate() {
            let id: Uuid = claim.id.into();
            let agent_id: Uuid = claim.agent_id.into();
            let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);

            query = query
                .bind(id)
                .bind(&claim.content)
                .bind(&content_hashes[i])
                .bind(claim.truth_value.value())
                .bind(agent_id)
                .bind(trace_id)
                .bind(claim.created_at)
                .bind(claim.updated_at)
                .bind(decl.visibility_bind())
                .bind(decl.owner_group_bind());
        }

        let rows = query.fetch_all(&mut *tx).await?;

        tx.commit().await?;

        // Convert rows to Claims
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            result.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(result)
    }

    /// Batch update truth values for multiple claims in a single query
    ///
    /// One static `UPDATE … FROM unnest($1::uuid[], $2::float8[])` statement,
    /// so the SQL text and the bind count (two) do not depend on the batch
    /// size. Only updates claims that exist - non-existent IDs are silently
    /// skipped. An id listed more than once is updated once, with the value
    /// of its FIRST occurrence (the contract the previous `CASE id WHEN …`
    /// form had: its first matching arm won).
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `updates` - Slice of (ClaimId, TruthValue) pairs to update
    ///
    /// # Returns
    /// Number of rows actually updated
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database operation fails.
    ///
    /// # Example
    /// ```rust,no_run
    /// use epigraph_db::ClaimRepository;
    /// use epigraph_core::{ClaimId, TruthValue};
    ///
    /// # async fn example(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    /// let updates = vec![
    ///     (ClaimId::new(), TruthValue::new(0.8)?),
    ///     (ClaimId::new(), TruthValue::new(0.9)?),
    /// ];
    /// let affected = ClaimRepository::batch_update_truth_values(pool, &updates).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(pool, updates), fields(update_count = updates.len()))]
    pub async fn batch_update_truth_values(
        pool: &PgPool,
        updates: &[(ClaimId, TruthValue)],
    ) -> Result<usize, DbError> {
        if updates.is_empty() {
            return Ok(0);
        }

        // One static statement over two parallel arrays. The previous form
        // built `CASE id WHEN $1 THEN $2 …` plus `WHERE id IN ($1, $3, …)` with
        // two placeholders per item, so its text varied with the batch size
        // (one prepared statement per size) and a batch above 32767 items
        // exceeded the protocol's 65535-bind limit. `unnest` binds two arrays
        // whatever the size.
        //
        // Deduplicated here, first occurrence kept: `UPDATE … FROM` joining a
        // target row to several source rows applies an unspecified one of
        // them, so the old first-wins contract has to be made explicit.
        let mut seen = std::collections::HashSet::with_capacity(updates.len());
        let (ids, values): (Vec<Uuid>, Vec<f64>) = updates
            .iter()
            .map(|(claim_id, truth_value)| (Uuid::from(*claim_id), truth_value.value()))
            .filter(|(id, _)| seen.insert(*id))
            .unzip();

        let result = sqlx::query(
            "UPDATE claims c SET truth_value = u.tv, updated_at = NOW() \
             FROM unnest($1::uuid[], $2::float8[]) AS u(id, tv) \
             WHERE c.id = u.id",
        )
        .bind(&ids)
        .bind(&values)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Supersede a claim with a corrected version in a single transaction.
    ///
    /// Creates a new claim linked to the old one via `supersedes`, and marks
    /// the old claim `is_current = false`. Both operations are atomic.
    ///
    /// # Errors
    /// - `DbError::NotFound` if the old claim doesn't exist
    /// - `DbError::QueryFailed` if the old claim is already superseded or DB fails
    ///
    /// # Implementation Notes
    /// The UPDATE that marks the old claim `is_current = false` also sets
    /// `embedding = NULL` and `embedding_3072 = NULL` in the **same
    /// statement**.  This is required by the CHECK constraint
    /// `chk_deprecated_no_embedding` (migration 052), which fires
    /// per-statement rather than per-transaction: splitting the assignments
    /// across two UPDATE statements would violate the constraint between
    /// statements.  Any future caller — REST handlers, CLI tools, tests
    /// — must preserve this single-statement invariant.  See also
    /// [`ClaimRepository::mark_duplicate`] which is subject to the same
    /// constraint.
    ///
    /// # Edge migration policy (issue #398)
    ///
    /// Edges are re-pointed at the replacement in both directions, with one
    /// exception: the WEAKENING relationships
    /// ([`crate::repos::edge::WEAKENING_RELATIONSHIPS`] — `refutes`,
    /// `contradicts`) do NOT migrate, in either direction. They stay on
    /// `old_claim_id`.
    ///
    /// The rule follows from what an edge asserts. `A -refutes-> B` is a claim
    /// about a *specific pair of contents*. Supersession replaces one of those
    /// contents, so the relation has to be re-established, not assumed — and
    /// the same reasoning already stated fifty lines below for `properties`
    /// ("blanket copy would propagate the bug the supersede was meant to
    /// correct") applies with more force here, because a migrated weakening
    /// edge does not merely carry a stale value forward, it *suppresses the
    /// correction*: [`ClaimRepository::dispute_batch`] reads exactly these two
    /// relationships into `is_contested`, and `recall(exclude_contested: true)`
    /// drops contested rows.
    ///
    /// Both directions are excluded because both were observed corrupting
    /// production (issue #398):
    ///
    /// * **Incoming.** Refute the false claim, then correct it — the natural
    ///   correction workflow — and the refutation lands on the correction. The
    ///   fix arrives pre-refuted, by the very claim that motivated it.
    /// * **Outgoing.** A claim holding two `contradicts` edges was superseded
    ///   by a replacement that *retracted* those objections; the edges followed,
    ///   recording the retraction as contesting the claims it declared correct.
    ///   That instance was cleaned up by hand with `DELETE /api/v1/edges/:id`.
    ///
    /// Leaving an outgoing weakening edge on the superseded source is not a
    /// leak, because `dispute_batch` joins `claims src ON … AND src.is_current`:
    /// a retired contester stops counting automatically. The cost of the rule is
    /// therefore bounded and one-directional — a supersession that merely
    /// *sharpens* an existing refutation must re-file it via `link_epistemic`,
    /// exactly as it must re-set `properties`. The cost of the opposite default
    /// is unbounded and silent.
    ///
    /// Incoming STRENGTHENING edges still migrate, unchanged. They are the
    /// mirror-image judgement call, but their failure mode is the loss of a
    /// positive signal rather than the manufacture of a negative one, and
    /// changing them is not this function's decision to make.
    ///
    /// ## Step lineages (backlog 8d3b4527)
    ///
    /// `evolve_step(supersedes)` is a supersession too: it records
    /// `supersedes = parent`, and the request paths run the same administrative
    /// cascade. When the old and new claims share a non-null `step_lineage_id`,
    /// the migration also leaves `executes` (the workflow's FROZEN step; the
    /// head is resolved through the lineage), the workflow's chain edges
    /// `step_follows` / `phase_follows` in either direction (they link the
    /// frozen steps `executes` names, which is the id set
    /// `workflow_steps::ordered_steps` walks), `revises` in either direction
    /// (the lineage's branch history, like `supersedes`) and agents'
    /// `asserts` / `AUTHORED` (the successor is written by the evolve_step
    /// caller, not by the agents that asserted the old content) on the retired
    /// step. A supersession made here writes no `step_lineage_id`, so the
    /// lineage rule does not apply to it. The rule is read from the rows,
    /// because the deferred replay knows nothing of the original caller.
    ///
    /// ## Non-public steps keep their `executes` (OD-32)
    ///
    /// Whatever the lineage, a supersession of a claim whose `visibility` is
    /// not `public` leaves `executes`
    /// ([`NON_PUBLIC_FROZEN_RELATIONSHIPS`]) on the retired claim, in either
    /// direction. That edge is how a frozen workflow generation names its
    /// steps, and a pinned group-private generation is verified against it, so
    /// a plain supersede (which writes no lineage) must not re-point it. The
    /// dedup and merge cascades apply the same rule. The workflow keeps
    /// executing the retired step until a new generation is published; the
    /// chain edges `step_follows` / `phase_follows` still move as before
    /// outside a step lineage. A public step's `executes` moves as before. The
    /// rule is read from the old claim's row, so the deferred replay gives the
    /// same result.
    ///
    /// ## Self-loop guards — deliberately unreachable
    ///
    /// Both statements also carry [`ClaimRepository::mark_duplicate`]'s
    /// `source_id`/`target_id` self-loop guards, and unlike there they are
    /// **defence in depth, not a live defect fix**. Issue #398 reports the
    /// guards as missing; they are, but nothing can currently reach them:
    ///
    /// * `supersede` MINTS `new_uuid` in this transaction, so no pre-existing
    ///   edge can already name it (the only one that does is the `supersedes`
    ///   edge inserted above, excluded by `relationship != 'supersedes'`).
    ///   Contrast `mark_duplicate`, whose canonical claim pre-exists and
    ///   routinely already has edges — there the guards are load-bearing.
    /// * The remaining shape — a pre-existing `old -rel-> old` self-edge that
    ///   the two statements would compose into `new -rel-> new` — cannot be
    ///   stored at all: `edges_no_self_loop`
    ///   (`CHECK (source_id <> target_id OR source_type <> target_type)`,
    ///   migration 001) rejects claim→claim self-edges on insert.
    ///
    /// They are kept anyway because the schema CHECK's failure mode is worse
    /// than the guards': were a future migration to relax it, an ungarded
    /// UPDATE that produced a self-loop would abort the whole transaction and
    /// turn a bad edge into a failed supersession. The guard degrades that to
    /// "this one edge does not migrate". There is no test pinning them, because
    /// the precondition cannot be constructed through the schema.
    #[instrument(skip(pool))]
    pub async fn supersede(
        pool: &PgPool,
        old_claim_id: ClaimId,
        new_content: &str,
        new_truth: TruthValue,
        reason: &str,
    ) -> Result<(Uuid, Uuid), DbError> {
        let mut tx = pool.begin().await?;
        let ids =
            Self::supersede_conn(&mut tx, old_claim_id, new_content, new_truth, reason).await?;
        tx.commit().await?;
        Ok(ids)
    }

    /// [`Self::supersede`] on a connection the CALLER owns, so it can run inside
    /// a viewer-stamped transaction (`ScopedPool::begin_as`) and commit with
    /// whatever else that transaction writes.
    ///
    /// Every statement is an `UPDATE`/`INSERT` on `claims` or `edges`, so
    /// migration 077's `*_tenancy` `WITH CHECK` governs each one. On an
    /// unstamped session the writable set is `{}` and the first UPDATE is
    /// refused with `42501` on a schema without the orphan `*_privacy` policies.
    /// Stamped, the database admits exactly the supersessions the stamp's
    /// writable set covers. The caller must run this in a transaction: it issues
    /// several statements that must land together, and it does not begin one.
    ///
    /// # Migration 117: a PRIVILEGED session only
    ///
    /// The edge migration re-points edges whatever their owner: an incoming
    /// edge is its SOURCE's writer's assertion, not the superseder's. Since 117
    /// a non-privileged session's UPDATE of an edge it does not own matches no
    /// row, so on such a session this would retire the claim and silently
    /// leave other writers' edges on it. It therefore refuses a non-privileged
    /// session outright. A request path runs [`Self::supersede_act_conn`] on
    /// the caller's stamped transaction and [`Self::migrate_superseded_edges_conn`]
    /// on the maintenance connection (`epigraph_engine::admin_cascade`).
    ///
    /// # Errors
    /// As [`Self::supersede`]: `DbError::NotFound` for a missing (or, on a
    /// filtered session, invisible) claim, `DbError::QueryFailed` for an
    /// already-superseded one or any refused statement, `DbError::InvalidData`
    /// on a non-privileged session.
    pub async fn supersede_conn(
        conn: &mut sqlx::PgConnection,
        old_claim_id: ClaimId,
        new_content: &str,
        new_truth: TruthValue,
        reason: &str,
    ) -> Result<(Uuid, Uuid), DbError> {
        require_privileged_session(
            &mut *conn,
            "supersede_conn (its edge migration re-points other writers' edges)",
        )
        .await?;
        let (new_uuid, old_uuid) =
            Self::supersede_act_conn(&mut *conn, old_claim_id, new_content, new_truth, reason)
                .await?;
        migrate_superseded_edges(&mut *conn, old_uuid, new_uuid).await?;
        Ok((new_uuid, old_uuid))
    }

    /// The supersession's own act, and nothing else: retire `old_claim_id`,
    /// insert its replacement and the `supersedes` edge between them. Returns
    /// `(new_id, old_id)`.
    ///
    /// Every row it writes is a row the superseder authors (its own claim, the
    /// replacement, which inherits the old claim's tenancy, and the edge
    /// between the two), so it runs on the CALLER's stamped transaction and
    /// the database decides write authority exactly as before. It does NOT
    /// migrate the old claim's other edges: those belong to whoever asserted
    /// them, and moving them is the administrative cascade's job
    /// ([`Self::migrate_superseded_edges_conn`], migration 117). The caller
    /// must run this in a transaction.
    ///
    /// # Errors
    /// As [`Self::supersede_conn`], without its privilege requirement.
    pub async fn supersede_act_conn(
        conn: &mut sqlx::PgConnection,
        old_claim_id: ClaimId,
        new_content: &str,
        new_truth: TruthValue,
        reason: &str,
    ) -> Result<(Uuid, Uuid), DbError> {
        let old_uuid: Uuid = old_claim_id.into();
        let new_uuid = Uuid::new_v4();
        let content_hash = ContentHasher::hash(new_content.as_bytes());
        let new_truth_val = new_truth.value();

        // Retire the old claim and read what the replacement inherits in ONE
        // statement. `AND is_current` is what makes two concurrent
        // supersessions of one claim mutually exclusive: under READ COMMITTED
        // the second blocks on the first's row lock, re-evaluates the WHERE
        // once the first commits, and matches nothing. A separate unlocked
        // `SELECT is_current` followed by `UPDATE … WHERE id = $1` let both
        // pass and insert two current successors.
        //
        // Both embedding columns are nulled in this same statement: the CHECK
        // constraint `chk_deprecated_no_embedding` (migration 052) fires
        // per-statement, not per-transaction, so a two-step update would
        // violate it between statements.
        //
        // Labels are carried so that downstream consumers that filter by
        // labels (e.g. find_workflow's `labels @> ['workflow']` predicate) do
        // not silently lose the replacement. Properties are NOT carried
        // forward: if the supersession is fixing something that lived in
        // `properties` (e.g. a stale `confidence_source`), blanket copy would
        // propagate the bug the supersede was meant to correct. Callers that
        // want to preserve specific properties on the new claim should set
        // them via a follow-up `patch_claim`.
        let retired: Option<(Uuid, Vec<String>)> = sqlx::query_as(
            "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL, \
             updated_at = NOW() WHERE id = $1 AND is_current \
             RETURNING agent_id, COALESCE(labels, ARRAY[]::text[])",
        )
        .bind(old_uuid)
        .fetch_optional(&mut *conn)
        .await?;

        let (agent_id, mut old_labels) = match retired {
            Some(r) => r,
            None => {
                // Nothing retired: tell a missing claim from a retired one, the
                // two refusals this function has always distinguished.
                let is_current: Option<bool> = sqlx::query_scalar(
                    r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read classifies the refusal of the mutation it guards, not a disclosure to a caller.
                     SELECT COALESCE(is_current, true) FROM claims WHERE id = $1"#,
                )
                .bind(old_uuid)
                .fetch_optional(&mut *conn)
                .await?;
                return Err(match is_current {
                    None => DbError::NotFound {
                        entity: "Claim".to_string(),
                        id: old_uuid,
                    },
                    Some(false) => DbError::QueryFailed {
                        source: sqlx::Error::Protocol(format!(
                            "Claim {} has already been superseded",
                            old_uuid
                        )),
                    },
                    // Visible and current, yet the UPDATE matched no row: the
                    // session may read it but not retire it (an UPDATE policy
                    // whose USING hides the row, e.g. an elevated session's
                    // `claims_elevated_no_update`). Refuse rather than insert
                    // a successor next to a still-current claim; both
                    // transports map `WriteRefused` to a denial (HTTP 403,
                    // MCP INVALID_REQUEST).
                    Some(true) => DbError::WriteRefused {
                        entity: "Claim".to_string(),
                        id: old_uuid,
                        action: "supersede".to_string(),
                    },
                });
            }
        };
        // Per-submission review flags describe the OLD content, not the
        // replacement's, so they do not carry (see `NON_CARRIED_LABELS`).
        old_labels.retain(|l| !NON_CARRIED_LABELS.contains(&l.as_str()));

        // Insert new claim with supersedes link, carrying forward only labels
        // from the old row. Embeddings are intentionally NOT copied: the new
        // claim's content differs and any stale vector would mislead semantic
        // search. Properties are NOT copied either (see above) — callers must
        // re-set them explicitly if needed.
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                 supersedes, is_current, labels, \
                                 created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, true, $7, NOW(), NOW())",
        )
        .bind(new_uuid)
        .bind(new_content)
        .bind(content_hash.as_slice())
        .bind(new_truth_val)
        .bind(agent_id)
        .bind(old_uuid)
        .bind(&old_labels)
        .execute(&mut *conn)
        .await?;

        // Insert supersedes edge for graph traversal
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
             VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supersedes', jsonb_build_object('reason', $3), NOW())",
        )
        .bind(new_uuid)
        .bind(old_uuid)
        .bind(reason)
        .execute(&mut *conn)
        .await?;

        Ok((new_uuid, old_uuid))
    }

    /// The supersession's edge migration, as the administrative cascade runs it
    /// after the caller's [`Self::supersede_act_conn`] committed.
    ///
    /// Re-verifies the committed act first (`new_id` supersedes `old_id`, and
    /// `old_id` is retired), so it acts only on a supersession that happened,
    /// and it is idempotent: a second run finds no edge left on `old_id` to
    /// move. That makes it the replay of a deferred cascade too. Runs in its
    /// own transaction (a SAVEPOINT when the connection is already in one).
    ///
    /// # Errors
    /// `DbError::InvalidData` on a non-privileged session, or when the claims
    /// do not record `new_id` superseding a retired `old_id`;
    /// `DbError::QueryFailed` on any failed statement.
    pub async fn migrate_superseded_edges_conn(
        conn: &mut sqlx::PgConnection,
        old_id: Uuid,
        new_id: Uuid,
    ) -> Result<SupersedeEdgeMigration, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "migrate_superseded_edges_conn (it re-points other writers' edges)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let recorded: Option<(Option<Uuid>, bool)> = sqlx::query_as(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; this read verifies the act the mutation follows.
            SELECT n.supersedes, COALESCE(o.is_current, true)
              FROM claims n LEFT JOIN claims o ON o.id = $2
             WHERE n.id = $1"#,
        )
        .bind(new_id)
        .bind(old_id)
        .fetch_optional(&mut *tx)
        .await?;
        match recorded {
            Some((Some(sup), false)) if sup == old_id => {}
            _ => {
                return Err(DbError::InvalidData {
                    reason: format!(
                        "claim {new_id} does not supersede a retired claim {old_id}; \
                         refusing to migrate its edges"
                    ),
                })
            }
        }
        let migration = migrate_superseded_edges(&mut tx, old_id, new_id).await?;
        tx.commit().await?;
        Ok(migration)
    }

    // ============================================================
    // S1 noun-claims-and-verb-edges helpers
    // (see docs/architecture/noun-claims-and-verb-edges.md)
    // ============================================================

    /// Find an existing claim by `(content_hash, agent_id)`.
    ///
    /// Returns the matching row if any, else `None`. Unlike `create()` /
    /// `create_with_tx()` (which dedup on `content_hash` alone and return
    /// the first agent's row regardless of requester), this helper enforces
    /// the noun-claim invariant that `(content_hash, agent_id)` is the
    /// canonical key.
    ///
    /// Takes `&mut PgConnection` so the caller can compose the lookup with
    /// edge creation in the same transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn find_by_content_hash_and_agent(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        content_hash: &[u8],
        agent_id: Uuid,
    ) -> Result<Option<Claim>, DbError> {
        use sqlx::Row;

        let sql = viewer.splice(
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
               FROM claims
               WHERE content_hash = $1 AND agent_id = $2
                 /* {VISIBILITY:claims} */
               LIMIT 1"#,
            3,
        );
        let mut q = sqlx::query(&sql).bind(content_hash).bind(agent_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row = q.fetch_optional(&mut *conn).await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(Some(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    /// Serialize every find-then-insert of one `(content_hash, agent_id)` for
    /// the rest of the caller's CURRENT TRANSACTION.
    ///
    /// # Why the database does not do this
    ///
    /// Migration 013's `uq_claims_content_hash_agent` is absent on the
    /// long-lived database (migrations/README.md, "Known schema drift"), and
    /// migration 150 drops it everywhere else so CI matches it. Without it,
    /// "find, and insert on a miss" is a check-then-act race: the find runs on
    /// a snapshot that cannot see a concurrent caller's uncommitted insert, so
    /// two first creates of one pair both miss and both insert. This lock is
    /// the contract now; the `DuplicateKey` catch arms stay for a future
    /// partial unique index (`WHERE is_current`).
    ///
    /// # How a caller must use it
    ///
    /// Take it as its OWN statement, inside a transaction, BEFORE the find whose
    /// answer decides the insert, and keep that transaction open until the
    /// insert commits. An earlier unlocked find may answer a hit on its own (a
    /// committed row is a committed row); it must not decide a miss. A
    /// `pg_advisory_xact_lock` is released at the end of the transaction that
    /// took it — on an autocommit connection that is the end of this very
    /// statement, which serializes nothing. Under READ COMMITTED the find,
    /// issued after the lock is granted, reads a snapshot that includes the
    /// previous holder's committed row.
    ///
    /// The two-key form keeps this lock space disjoint from the single-key
    /// locks elsewhere; `'epigraph.claim_dedup'` keeps it disjoint from
    /// `policies.rs::create_challenge`'s `'epigraph.policy_challenge'`.
    ///
    /// A caller that creates many claims in one transaction holds one lock per
    /// distinct pair until it commits, in input order.
    ///
    /// # Who takes it
    ///
    /// Every writer that looks for an existing row of the pair (or of its
    /// content hash) and inserts on a miss: [`Self::create_or_get`] /
    /// [`Self::create_or_get_signed`], POST /claims' duplicate check
    /// (`if_not_exists=false`), the legacy content-hash creates
    /// ([`Self::create_conn`], and [`Self::create`] / [`Self::create_with_tx`],
    /// which delegate to it), [`Self::consolidate_act_conn`]'s "identical
    /// merged claim already exists" probe, and the `method_search` maintenance
    /// binary in `epigraph-cli`. Each takes it BEFORE the find that decides its
    /// insert, and before any row lock of its own. `create_conn` and
    /// `method_search` first run an unlocked find that answers only a hit.
    ///
    /// Writers that do not take it:
    ///
    /// - [`Self::create_strict`] and the other unconditional INSERTs
    ///   (supersede, `evolve_step`, `batch_create`, hypothesis creation) have
    ///   no find, so there is no check-then-act to race.
    /// - [`Self::create_with_id_if_absent`] and the ingest-executor's
    ///   workflow `add_step` dedup on a caller-derived deterministic id
    ///   (`ON CONFLICT (id)`), which the primary key already serializes among
    ///   their own callers; one id means one pair. They have NO pair dedup at
    ///   all, so they do not dedup against a random-id row of the same pair:
    ///   a [`Self::create_or_get`] of exact atom text by the same agent,
    ///   committed earlier or running concurrently, followed by a
    ///   deterministic-id create of that atom, leaves two rows of the pair.
    ///   Taking this lock without adding a pair find would close neither
    ///   case, so the gap stays open here and is tracked separately.
    /// - `policies.rs::create_challenge` finds on the pair PLUS the
    ///   `policy:challenge` label and serializes its own callers under
    ///   `'epigraph.policy_challenge'`. A non-challenge row of the same pair
    ///   does not satisfy its find, so the shared key would not change its
    ///   outcome.
    ///
    /// A concurrent writer of the same pair that does not take this lock can
    /// still add a row that a lock holder's find did not see.
    ///
    /// # Deadlocks and lock-table use
    ///
    /// The ingest atoms reach it through [`Self::create_conn`] inside one
    /// document transaction. `create_conn` answers a hit on an
    /// already-committed atom with an unlocked find and takes the lock only
    /// on a MISS, so an ingest holds one lock per NEWLY INSERTED atom until it
    /// commits; atoms that already existed cost no lock and add no wait.
    /// Ingest against ingest keeps the wait graph it had without the lock: a
    /// miss is an atom some concurrent ingest may be inserting, and since an
    /// atom's id is `atom_id(content_hash)` an overlapping same-author ingest
    /// already waited on the other's uncommitted primary-key entry (and then
    /// failed on that key instead of returning the first's row). New: a
    /// same-author ingest against a multi-pair [`Self::create_or_get`]
    /// transaction or a consolidation into the same content, meeting shared
    /// NEW pairs in opposite orders, can now deadlock (40P01, retryable) where
    /// it previously minted a duplicate.
    ///
    /// Every lock held until commit takes a slot in the shared lock table
    /// (`max_locks_per_transaction` x (`max_connections` +
    /// `max_prepared_transactions`)), which the primary-key waits did not. A
    /// document with very many new atoms, or several concurrent large ones,
    /// uses correspondingly many slots.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the lock statement fails.
    pub async fn lock_content_hash_agent(
        conn: &mut sqlx::PgConnection,
        content_hash: &[u8],
        agent_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtext('epigraph.claim_dedup'), \
                    hashtext(encode($1, 'hex') || $2::text))",
        )
        .bind(content_hash)
        .bind(agent_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Insert a claim row unconditionally (no implicit dedup).
    ///
    /// Use this when the caller has already determined that an insert is
    /// the correct action. A caller that must not mint a second row for one
    /// `(content_hash, agent_id)` takes [`Self::lock_content_hash_agent`] and
    /// runs [`Self::find_by_content_hash_and_agent`] first, in the same
    /// transaction (or uses [`Self::create_or_get`], which does both).
    ///
    /// **Without `uq_claims_content_hash_agent`** (the long-lived database,
    /// and every database from migration 150): inserts a duplicate row when
    /// `(content_hash, agent_id)` already exists.
    ///
    /// **With it** (a database that re-adds it, or a future partial unique
    /// index): duplicate insertions surface as `DbError::DuplicateKey`.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` on a `(content_hash, agent_id)`
    /// collision (only where a unique constraint on the pair exists). Returns
    /// `DbError::QueryFailed` for other database errors.
    pub async fn create_strict(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
        decl: TenancyDecl,
    ) -> Result<Claim, DbError> {
        Self::create_strict_signed(conn, claim, decl, None).await
    }

    /// [`Self::create_strict`], additionally persisting the claim's Ed25519
    /// signature with `signer_id` as its SIGNER (batch H-b, D1-sig).
    ///
    /// # Why the signer is recorded apart from the author
    ///
    /// `claims.agent_id` is the AUTHOR. Since D1 an authenticated MCP write
    /// authors as the caller, while the digest is still signed with the MCP
    /// server's key, so the two are different agents and often the author has no
    /// private key at all (an OAuth principal's `derived` agent). `verify_claim`
    /// already verifies against `claims.signer_id -> agents.public_key`, never
    /// against the author's key (`post_fix_crypto_columns`), so recording the
    /// signer is what lets a caller-authored claim verify, without weakening the
    /// check.
    ///
    /// # What is persisted, and when nothing is
    ///
    /// The signature and `signer_id` are written together or not at all (the
    /// `claims_signature_requires_signer` CHECK), and ONLY when the signature
    /// verifies under `claim.public_key` over the digest this INSERT stores
    /// (`blake3(content)`). A signature over a different digest (the ingest
    /// planner's seed-scoped compound hash) or one that does not verify is not
    /// stored: an unverifiable signature on a row would read as tampering. The
    /// caller vouches that `signer_id` is the agent whose registered key is
    /// `claim.public_key`; `verify_claim` re-checks that pairing on every read.
    ///
    /// `signer_id = None` is exactly [`Self::create_strict`]: every existing row
    /// keeps `signature = NULL` and reports `signed: false`, unchanged.
    ///
    /// # Errors
    /// As [`Self::create_strict`].
    pub async fn create_strict_signed(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
        decl: TenancyDecl,
        signer_id: Option<Uuid>,
    ) -> Result<Claim, DbError> {
        use sqlx::Row;

        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        let (signature, signer_id): (Option<Vec<u8>>, Option<Uuid>) =
            match (signer_id, claim.signature) {
                (Some(signer), Some(sig))
                    if epigraph_crypto::SignatureVerifier::verify(
                        &claim.public_key,
                        &content_hash,
                        &sig,
                    )
                    .unwrap_or(false) =>
                {
                    (Some(sig.to_vec()), Some(signer))
                }
                _ => (None, None),
            };

        let row = sqlx::query(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at, visibility, owner_group_id, signature, signer_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(id)
        .bind(&claim.content)
        .bind(content_hash.as_slice())
        .bind(truth_value)
        .bind(agent_id)
        .bind(trace_id)
        .bind(created_at)
        .bind(updated_at)
        .bind(decl.visibility_bind())
        .bind(decl.owner_group_bind())
        .bind(signature)
        .bind(signer_id)
        .fetch_one(&mut *conn)
        .await?;

        let row_id: Uuid = row.get("id");
        let row_agent_id: Uuid = row.get("agent_id");
        let row_truth_value: f64 = row.get("truth_value");

        // Fire-and-forget claim.created event (closes #61). Emitted from
        // create_strict (not create_or_get) so:
        //   (a) `claims.rs::create_strict(...)` direct callers also emit,
        //   (b) create_or_get's success branch is exactly when create_strict
        //       returned Ok — no duplicate emit needed there,
        //   (c) the DuplicateKey/race branch in create_or_get correctly
        //       does NOT emit (no row was actually inserted).
        // Uses publish_or_log_conn so the event INSERT participates in the
        // caller's transaction — if the caller rolls back, neither the claim
        // nor the event lands.
        let _ = crate::repos::EventRepository::publish_or_log_conn(
            &mut *conn,
            "claim.created",
            Some(row_agent_id),
            &serde_json::json!({
                "claim_id": row_id,
                "agent_id": row_agent_id,
                "truth_value": row_truth_value,
            }),
        )
        .await;

        let tv = TruthValue::new(row_truth_value)?;
        Ok(claim_from_row(
            row_id,
            row.get("content"),
            row_agent_id,
            row.get("trace_id"),
            tv,
            row.get("created_at"),
            row.get("updated_at"),
        ))
    }

    /// Find-or-insert a claim by `(content_hash, agent_id)`.
    ///
    /// Looks up an existing row first; if found, returns it with
    /// `was_created=false`. Otherwise inserts and returns the new row with
    /// `was_created=true`.
    ///
    /// **Race handling:** the find and the insert run inside one transaction
    /// (a real `BEGIN` on a bare connection, a SAVEPOINT inside the caller's)
    /// that first takes [`Self::lock_content_hash_agent`]. Two concurrent first
    /// creates of one pair therefore serialize: the second waits for the
    /// first's transaction to end, then its find sees the committed row and it
    /// returns `was_created=false`. This holds without any unique constraint,
    /// which is the shape of the long-lived database and, from migration 150,
    /// of every database (backlog 00f1a517). Inside a caller's transaction the
    /// lock is held until THAT transaction ends, which is what keeps the
    /// caller's still-uncommitted row from being missed.
    ///
    /// **Belt-and-braces catch:** a writer that inserts the pair WITHOUT the
    /// lock (see [`Self::lock_content_hash_agent`], "Who takes it") can still
    /// win between the find and the insert. Where a unique
    /// constraint on the pair exists, the INSERT then fails; this helper
    /// catches that error, re-runs the find, and returns the resulting row with
    /// `was_created=false`. Without such a constraint that writer's row is a
    /// duplicate this helper cannot see.
    ///
    /// **Constraint match assumption:** the catch path matches
    /// `DbError::DuplicateKey { .. }` only because
    /// `uq_claims_content_hash_agent` is the only unique constraint that can
    /// fire on a fresh-UUID `INSERT INTO claims`. If a future migration adds
    /// another unique constraint to `claims`, narrow this match to inspect
    /// the constraint name.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Why the insert attempt runs inside a SAVEPOINT
    ///
    /// The race-handling above is only expressible if the connection is still
    /// usable after the failed INSERT, and inside a transaction it is not:
    /// PostgreSQL aborts the whole transaction on the first failed statement, so
    /// the `find_by_content_hash_and_agent` re-read in the catch path could not
    /// run at all. MEASURED, by removing this savepoint and running
    /// `claim_repo_helpers.rs::the_dedup_race_is_absorbed_inside_a_caller_transaction`:
    /// the call fails with `25P02 current transaction is aborted, commands
    /// ignored until end of transaction block`. So a genuine
    /// `(content_hash, agent_id)` race — the only thing this method's dedup
    /// contract exists for — stopped de-duplicating and started failing the
    /// caller's whole unit of work the moment a writer wrapped it in a
    /// transaction. `epigraph-mcp`'s submission path is that writer.
    ///
    /// The savepoint restores the contract without changing it: the refused
    /// INSERT is rolled back alone, the re-find runs on a usable connection, and
    /// the caller gets `(existing, false)`. Same construction as
    /// `EventRepository::publish_or_log_conn` and
    /// `epigraph-mcp/src/claim_helper.rs::emit_verb_edge_best_effort`, for the
    /// same reason.
    ///
    /// On a connection that is NOT already in a transaction, the outer scope is
    /// a real `BEGIN`/`COMMIT` pair around the lock, the find and the insert,
    /// and the insert's own scope is a SAVEPOINT inside it — same durability,
    /// and the row is visible to the next lock holder the moment the lock is
    /// released.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-unique-violation database errors,
    /// and for a failure to take or release the savepoint (the caller's
    /// transaction is then already unusable and must not be handed back as if
    /// the write had succeeded).
    pub async fn create_or_get(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim: &Claim,
        decl: TenancyDecl,
    ) -> Result<(Claim, bool), DbError> {
        Self::create_or_get_signed(conn, viewer, claim, decl, None).await
    }

    /// [`Self::create_or_get`], persisting the claim's signature with
    /// `signer_id` as its signer on the INSERT branch; see
    /// [`Self::create_strict_signed`]. A found row is returned as it is: its
    /// signature (or its absence) is never rewritten.
    ///
    /// # Errors
    /// As [`Self::create_or_get`].
    pub async fn create_or_get_signed(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim: &Claim,
        decl: TenancyDecl,
        signer_id: Option<Uuid>,
    ) -> Result<(Claim, bool), DbError> {
        use sqlx::Acquire;

        // The serialization scope: a real BEGIN on a bare connection (an
        // advisory xact lock taken in autocommit is released at the end of its
        // own statement), a SAVEPOINT inside the caller's transaction (the lock
        // then lives until the caller's transaction ends). Closed explicitly on
        // every path below.
        let mut scope = conn
            .begin()
            .await
            .map_err(|source| DbError::QueryFailed { source })?;
        match Self::create_or_get_serialized(&mut scope, viewer, claim, decl, signer_id).await {
            Ok(out) => {
                scope
                    .commit()
                    .await
                    .map_err(|source| DbError::QueryFailed { source })?;
                Ok(out)
            }
            Err(e) => {
                scope
                    .rollback()
                    .await
                    .map_err(|source| DbError::QueryFailed { source })?;
                Err(e)
            }
        }
    }

    /// The body of [`Self::create_or_get_signed`], run inside its
    /// serialization scope: lock, find, then the savepointed insert.
    async fn create_or_get_serialized(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim: &Claim,
        decl: TenancyDecl,
        signer_id: Option<Uuid>,
    ) -> Result<(Claim, bool), DbError> {
        use sqlx::Acquire;

        let agent_id: Uuid = claim.agent_id.into();
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        Self::lock_content_hash_agent(&mut *conn, content_hash.as_slice(), agent_id).await?;

        if let Some(existing) = Self::find_by_content_hash_and_agent(
            &mut *conn,
            viewer,
            content_hash.as_slice(),
            agent_id,
        )
        .await?
        {
            return Ok((existing, false));
        }

        let attempt = {
            let mut sp = conn
                .begin()
                .await
                .map_err(|source| DbError::QueryFailed { source })?;
            match Self::create_strict_signed(&mut sp, claim, decl, signer_id).await {
                Ok(c) => {
                    sp.commit()
                        .await
                        .map_err(|source| DbError::QueryFailed { source })?;
                    Ok(c)
                }
                Err(e) => {
                    sp.rollback()
                        .await
                        .map_err(|source| DbError::QueryFailed { source })?;
                    Err(e)
                }
            }
        };

        match attempt {
            Ok(c) => Ok((c, true)),
            Err(DbError::DuplicateKey { .. }) => {
                // A writer that bypassed the lock won, and a unique constraint
                // on the pair caught it. Re-find and return.
                let existing = Self::find_by_content_hash_and_agent(
                    &mut *conn,
                    viewer,
                    content_hash.as_slice(),
                    agent_id,
                )
                .await?
                .ok_or_else(|| DbError::InvalidData {
                    reason: "DuplicateKey from create_strict but no row found on re-find"
                        .to_string(),
                })?;
                Ok((existing, false))
            }
            Err(e) => Err(e),
        }
    }

    /// Insert a claim with a caller-supplied id. Returns `true` if the row
    /// was newly inserted, `false` if the id already existed (silently
    /// skipped via `ON CONFLICT (id) DO NOTHING`). Used by ingest paths that
    /// generate deterministic UUIDs and rely on idempotent re-runs.
    ///
    /// # Why this takes an `Acquire` rather than a `&PgPool`
    ///
    /// Migration 077's `claims_tenancy` `WITH CHECK` asks
    /// `owner_group_id = ANY(epigraph_writable_groups())`, and on an unstamped
    /// pool checkout that set is `{}` — so on a cleanly-migrated schema this
    /// INSERT is **refused**, which is how `store_workflow` came to be entirely
    /// unavailable (`new row violates row-level security policy for table
    /// "claims"`, raised from `epigraph-ingest-executor`). MEASURED as
    /// `epigraph_app` (`rolbypassrls = false`) on a database migrated 001→head
    /// from empty: this statement is refused unstamped, refused when stamped
    /// from a *different* real group, and admitted when stamped from the group
    /// the row is owned by.
    ///
    /// A generic `Acquire` rather than `&mut PgConnection` because every
    /// existing caller passes `&pool` and `&PgPool` implements `Acquire`: the
    /// twelve unconverted call sites keep their current behaviour verbatim,
    /// while a converted caller passes `&mut *tx` from
    /// `ScopedPool::begin_as(author_viewer)` and both statements below ride
    /// that one stamped transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-conflict failures, or
    /// `DbError::InvalidData` if a label carries unexpanded shell syntax.
    // Eight parameters, one over clippy's default. Allowed rather than bundled
    // into a struct: the eighth is `decl`, and the whole point of PR-16 is that
    // the tenancy declaration is VISIBLE at every call site. A parameter object
    // would hide it inside a literal that a caller can construct without
    // thinking about the field — which is the shape a `Default` impl grows out
    // of, and D1 is the rule that says there must not be one.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_id_if_absent(
        pool: &PgPool,
        id: Uuid,
        content: &str,
        content_hash: &[u8; 32],
        agent_id: Uuid,
        truth: TruthValue,
        labels: &[String],
        decl: TenancyDecl,
    ) -> Result<bool, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_with_id_if_absent_conn(
            &mut conn,
            id,
            content,
            content_hash,
            agent_id,
            truth,
            labels,
            decl,
        )
        .await
    }

    /// [`Self::create_with_id_if_absent`] on a connection the caller owns — the
    /// form a stamped transaction can reach.
    ///
    /// The pool-taking wrapper above delegates here, so there is one statement
    /// pair and one tenancy argument. A concrete `&mut PgConnection` rather than
    /// a generic `Acquire`: the workflow-ingest path reaches this through
    /// `#[tool_router]`'s boxed `dyn Future + Send`, and an `Acquire<'a>` bound
    /// there fails to prove `for<'x> &'x mut PgConnection: Acquire<'x>`
    /// ("implementation of `sqlx::Acquire` is not general enough"). Measured, not
    /// anticipated.
    ///
    /// # Errors
    /// As [`Self::create_with_id_if_absent`].
    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_id_if_absent_conn(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        content: &str,
        content_hash: &[u8; 32],
        agent_id: Uuid,
        truth: TruthValue,
        labels: &[String],
        decl: TenancyDecl,
    ) -> Result<bool, DbError> {
        // Labels-at-creation is the second caller-supplied label surface (the
        // ingest paths); same predicate, refused before the INSERT so a bad
        // label never reaches a row.
        crate::label_validation::reject_unexpanded_labels(labels)?;

        let row: Option<(bool,)> = sqlx::query_as(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO NOTHING \
             RETURNING (xmax = 0) AS was_inserted",
        )
        .bind(id)
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(truth.value())
        .bind(labels)
        .bind(decl.visibility_bind())
        .bind(decl.owner_group_bind())
        .fetch_optional(&mut *conn)
        .await?;
        // RETURNING is empty when the conflict path is taken, so None == not new.
        let was_inserted = row.map(|(b,)| b).unwrap_or(false);

        // Fire-and-forget claim.created event (closes #61), gated on actual
        // insertion. ON CONFLICT (id) DO NOTHING swallows duplicate-id paths,
        // and we rely on `was_inserted` (xmax=0 only on freshly-inserted rows)
        // to skip emission for idempotent re-runs.
        //
        // `publish_or_log_conn`, NOT `publish_or_log`: this is a swallowed
        // failure, and once the caller can hand us a transaction a swallowed
        // failure stops being fire-and-forget and becomes a DEFERRED abort —
        // PostgreSQL answers the eventual `COMMIT` with `ROLLBACK` and no error,
        // so the tool reports success having written nothing. The `_conn`
        // variant wraps the INSERT in a SAVEPOINT, which keeps "the event is
        // best-effort" true inside a transaction instead of only outside one.
        if was_inserted {
            let truth_value = truth.value();
            let _ = crate::repos::EventRepository::publish_or_log_conn(
                &mut *conn,
                "claim.created",
                Some(agent_id),
                &serde_json::json!({
                    "claim_id": id,
                    "agent_id": agent_id,
                    "truth_value": truth_value,
                }),
            )
            .await;
        }

        Ok(was_inserted)
    }

    /// Walks `supersedes` edges on a step lineage. Returns one row per head:
    /// claims with `step_lineage_id = $1` and NO incoming `supersedes` edge.
    /// Multiple heads = unmerged concurrent branches (created via `revises`).
    /// Empty = no claims have this `step_lineage_id`.
    ///
    /// `revises` does NOT remove head status — only `supersedes` does. See
    /// `docs/superpowers/specs/2026-05-05-step-level-versioning-design.md` §3.1.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn latest_in_lineage<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        lineage_id: Uuid,
    ) -> Result<Vec<LineageHead>, DbError> {
        // The `NOT EXISTS` over `edges` is an EXCLUSION test and is left
        // unfiltered on purpose: filtering it would let a supersedes edge the
        // viewer cannot see stop suppressing a stale head, so the function
        // would return MORE, and wrong. Only `c` carries the predicate.
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.created_at,
                   COALESCE(c.is_current, true) AS is_current
            FROM claims c
            WHERE c.step_lineage_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.target_id = c.id
                    AND e.relationship = 'supersedes'
              )
              /* {VISIBILITY:c} */
            ORDER BY c.created_at DESC
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, LineageHead>(&sql).bind(lineage_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;
        Ok(rows)
    }
}

/// Result of a pairwise cosine distance query between two claims.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimPairDistance {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub distance: f64,
}

/// Row struct for batch query results
#[derive(sqlx::FromRow)]
struct ClaimRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ClaimRepository {
    /// Copy evidence links from old claim to new claim via derived_from edges.
    /// Returns the number of inherited evidence links.
    pub async fn inherit_evidence(
        pool: &PgPool,
        old_claim_id: Uuid,
        new_claim_id: Uuid,
    ) -> Result<usize, DbError> {
        // Create derived_from edges from new claim to old claim's evidence
        let result = sqlx::query(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
             INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
             SELECT $1, 'claim', e.id, 'evidence', 'derived_from', 
                    jsonb_build_object('inherited_from', $2::text) 
             FROM evidence e 
             WHERE e.claim_id = $2 
             ON CONFLICT DO NOTHING"#,
        )
        .bind(new_claim_id)
        .bind(old_claim_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Count all evidence for a claim, including inherited evidence (via derived_from edges).
    pub async fn count_all_evidence_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<i64, DbError> {
        // PARENTHESES: the WHERE is an OR, and AND binds tighter. The `edges`
        // marker sits in the LEFT JOIN's ON clause so it cannot null-filter the
        // outer side into an inner join.
        let sql = viewer.splice(
            "SELECT COUNT(DISTINCT e.id) \
             FROM evidence e \
             LEFT JOIN edges ed ON ed.target_id = e.id \
                AND ed.target_type = 'evidence' \
                AND ed.source_id = $1 \
                AND ed.source_type = 'claim' \
                AND ed.relationship = 'derived_from' \
                /* {EDGE_VISIBILITY:ed} */ \
             WHERE (e.claim_id = $1 OR ed.id IS NOT NULL) /* {VISIBILITY:e} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: (i64,) = q.fetch_one(executor).await?;

        Ok(row.0)
    }

    /// Check whether a claim has grounded evidence — i.e., at least one
    /// non-claim provenance chain (published paper, experimental evidence,
    /// or analysis with data). Claims supported only by other claims
    /// (claim-to-claim propagation) are NOT considered grounded.
    ///
    /// Grounded evidence means at least one of:
    /// - `paper  --asserts-->          claim`
    /// - `evidence --SUPPORTS-->       claim` (either spelling, `SUPPORTS` or `supports`)
    /// - `analysis --concludes-->      claim`
    /// - `analysis --provides_evidence--> claim`
    pub async fn has_grounded_evidence<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM edges
                WHERE target_id = $1
                  AND target_type = 'claim'
                  AND source_type IN ('paper', 'evidence', 'analysis')
                  AND relationship IN ('asserts', 'SUPPORTS', 'supports', 'concludes', 'provides_evidence')
                  /* {EDGE_VISIBILITY:edges} */
            )
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (bool,)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: (bool,) = q.fetch_one(executor).await?;

        Ok(row.0)
    }
}

impl ClaimRepository {
    /// Return claim IDs whose reasoning trace matches the given `reasoning_type`.
    ///
    /// Valid values mirror the DB CHECK constraint on reasoning_traces:
    /// deductive, inductive, abductive, analogical, statistical.
    pub async fn claim_ids_by_methodology<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        reasoning_type: &str,
    ) -> Result<Vec<Uuid>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT c.id
            FROM claims c
            INNER JOIN reasoning_traces rt ON c.trace_id = rt.id
            WHERE rt.reasoning_type = $1
              /* {VISIBILITY:c} */ /* {VISIBILITY:rt} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(reasoning_type);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid,)> = q.fetch_all(executor).await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Return claim IDs that have at least one evidence record of the given type.
    ///
    /// Valid values mirror the DB evidence_type column:
    /// document, observation, testimony, computation, reference, figure, conversational.
    pub async fn claim_ids_by_evidence_type<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        evidence_type: &str,
    ) -> Result<Vec<Uuid>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT e.claim_id
            FROM evidence e
            WHERE e.evidence_type = $1
              /* {VISIBILITY:e} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(evidence_type);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid,)> = q.fetch_all(executor).await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}

impl ClaimRepository {
    /// Find claims that have no embedding, returning (id, content) pairs.
    ///
    /// Excludes activity log claims (content starting with known activity prefixes).
    ///
    /// # The executor is generic, and that is the point
    ///
    /// This is a corpus-wide maintenance enumerator: it runs under a bypass
    /// `Viewer`, which emits no predicate, so once RLS is active the
    /// *connection* — not the viewer — decides what it sees. Taking `&PgPool`
    /// forced every caller onto whatever pool it happened to hold, which is how
    /// `epigraph-api`'s handler ended up minting a privileged lease and then
    /// spending it on the application pool: the privileged handle existed and
    /// the statement ran somewhere else. Accepting any `PgExecutor` lets a
    /// caller pass the maintenance connection it is already holding
    /// (`&mut *maint_conn`), so the bypass and the connection cannot drift
    /// apart. Callers that legitimately hold a maintenance pool still pass
    /// `&PgPool` unchanged.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn find_claims_needing_embeddings<'e, E>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, DbError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Postgres>,
    {
        debug_assert!(
            viewer.is_bypass(),
            "find_claims_needing_embeddings is a maintenance enumerator; a Scoped \
             viewer here would silently leave other tenants unembedded forever"
        );
        // Exclude host-provenance telemetry (epiclaw-host ProvenanceRecorder
        // signs every observable event as an immutable claim — container
        // lifecycle, task execution, agent output, messages). These are
        // intentionally NOT embedded (no semantic value, one OpenAI call each)
        // and dominate the is_current embedding gap; embedding them would
        // pollute semantic recall. They carry the `telemetry` label (added by
        // provenance.rs) and a `properties->>'event'` marker — filter on both
        // so pre-label-backfill rows and any label-PATCH-failure rows are still
        // excluded. Also restrict to current claims: per the embedding
        // invariant, `is_current = false` rows should have `embedding = NULL`
        // by design, so they never "need" an embedding. (backlog a4aaa487)
        let rows: Vec<(Uuid, String)> = sqlx::query_as(&format!(
            r#"
            -- VISIBILITY-EXEMPT: embedding backfill must see every unembedded
            -- row; a per-tenant view of the gap would leave every other
            -- tenant's claims unembedded forever and silently break semantic
            -- recall for them. Runs under SystemReason::EmbeddingBackfill on a
            -- maintenance connection (debug_assert above, and the generic
            -- executor so the caller can pass that very connection).
            --
            -- The population predicate is `EMBEDDABLE_POPULATION`, shared with
            -- the two by-id reads so the enumerator and the write paths cannot
            -- disagree about which rows are owed a vector. Encrypted claims are
            -- excluded there, keyed on `claim_encryption` and NEVER on
            -- `visibility`: a group-private claim is still plaintext in
            -- `claims.content` and must be embedded, whereas a sealed claim has
            -- no plaintext to embed and calling the embedder on its ciphertext
            -- would both fail and leak length.
            SELECT id, content FROM claims
            WHERE embedding IS NULL
              AND {EMBEDDABLE_POPULATION}
            ORDER BY created_at
            LIMIT $1
            "#
        ))
        .bind(limit)
        .fetch_all(executor)
        .await?;

        Ok(rows)
    }

    /// The text one claim should be embedded from, or `None` if it should not
    /// be embedded at all.
    ///
    /// The by-id counterpart to
    /// [`find_claims_needing_embeddings`](Self::find_claims_needing_embeddings),
    /// for the restoration a privatization unseal enqueues: that path knows the
    /// claim id and must not enumerate the corpus, but it has to apply the SAME
    /// population rules, or the two paths disagree about which rows carry a
    /// vector.
    ///
    /// # Why the encryption check is here and not at the caller
    ///
    /// **This is the load-bearing predicate.** A privatization seal nulls the
    /// vector columns and replaces `content` with a stub; the plaintext lives
    /// only in `claim_encryption`, which the server cannot read. Embedding a
    /// sealed row would therefore either fail on the stub or — worse, if a
    /// caller had plaintext in hand — write a plaintext-derived vector onto a
    /// row whose whole point is that no such derivative exists. CLAUDE.md's
    /// audit calls a sealed claim carrying a vector a confidentiality
    /// violation rather than an embedding gap, so the refusal belongs in the
    /// statement every caller shares, not in one caller's control flow. The
    /// same predicate is in all three statements that can put a vector on a
    /// claim — this read, [`store_embedding`](Self::store_embedding) and
    /// [`store_embedding_if_unsealed`](Self::store_embedding_if_unsealed) —
    /// rather than in the one path that happened to be written last.
    ///
    /// Keyed on `claim_encryption`, NEVER on `visibility`: a group-private
    /// claim is ordinary plaintext and must still be embedded.
    ///
    /// # The viewer IS spent
    ///
    /// The job runner holds a bypass, for which the predicate renders empty —
    /// but the parameter is real rather than decorative: any caller that is not
    /// a maintenance path is filtered, so this cannot become a by-id content
    /// read that ignores tenancy.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn claim_text_for_embedding<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT content FROM claims WHERE id = $1 AND {EMBEDDABLE_POPULATION} \
                 /* {{VISIBILITY:claims}} */"
            ),
            2,
        );
        let mut q = sqlx::query_as::<_, (String,)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<(String,)> = q.fetch_optional(executor).await?;
        Ok(row.map(|(content,)| content))
    }

    /// [`claim_text_for_embedding`](Self::claim_text_for_embedding) narrowed to
    /// claims that are **missing** their vector: the text to embed, or `None` if
    /// this claim either already carries one or does not belong to the embedded
    /// population at all.
    ///
    /// # Why a write path needs this and `was_created` is not enough
    ///
    /// The MCP submission path used to gate its post-commit embed on
    /// `was_created` alone, on the reasoning that a dedup hit means "the
    /// canonical row already has its embedding". That is false for exactly the
    /// row the orphan-repair arms were added for. A production orphan is a claim
    /// whose submission committed the claim and was then refused on
    /// `reasoning_traces` with `42501` — and the refusal arrived BEFORE the
    /// post-commit embed, so the row carries `is_current = true` AND
    /// `embedding IS NULL`, which is CLAUDE.md's `live_missing` invariant
    /// violation. Repairing its provenance and leaving that `NULL` in place
    /// leaves it permanently invisible to `recall()`, while the tool reports
    /// HTTP success.
    ///
    /// # The population rules are shared, not restated
    ///
    /// [`EMBEDDABLE_POPULATION`] is the single predicate this and
    /// `claim_text_for_embedding` splice, so the repair path cannot drift into
    /// embedding a row the enumerators exclude. That matters most for TELEMETRY:
    /// host-provenance claims are `is_current = true` with `embedding IS NULL`
    /// BY DESIGN (CLAUDE.md's telemetry exception — they dominate the gap), so a
    /// naive `embedding IS NULL` test would make every telemetry resubmit pay an
    /// embedding call and pollute semantic recall. Sealed claims are excluded for
    /// the reason `claim_text_for_embedding`'s doc gives.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn claim_text_if_embedding_missing<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            &format!(
                "SELECT content FROM claims WHERE id = $1 AND embedding IS NULL \
                 AND {EMBEDDABLE_POPULATION} /* {{VISIBILITY:claims}} */"
            ),
            2,
        );
        let mut q = sqlx::query_as::<_, (String,)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<(String,)> = q.fetch_optional(executor).await?;
        Ok(row.map(|(content,)| content))
    }

    /// Read a claim's cached CDST classification label (`supported` |
    /// `contradicted` | `not_enough_info`), or `None` if unclassified or the
    /// claim does not exist. Written by `recompute_combined_belief` via
    /// `MassFunctionRepository::update_claim_classification`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_classification<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            "SELECT classification FROM claims WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Option<String>,)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<(Option<String>,)> = q.fetch_optional(executor).await?;
        Ok(row.and_then(|(c,)| c))
    }

    /// Store an embedding vector on a claim that is not sealed.
    ///
    /// The embedding string must be a valid pgvector literal (e.g., "[0.1,0.2,...]").
    /// Follows the same pattern as `EvidenceRepository::store_embedding`.
    ///
    /// # Why the seal predicate is in THIS statement
    ///
    /// This is the shared write every embedding producer goes through — the MCP
    /// submit/memorize/ingest paths, the backfill tool, `embed_backfill`, and
    /// `PUT /api/v1/claims/:id`, whose caller supplies the vector itself. The
    /// enumerators those callers select from already exclude sealed rows, so
    /// the predicate is a no-op for every one of them; the by-id caller has no
    /// enumerator at all, and for it the predicate is the only thing standing
    /// between a caller who still holds plaintext and a plaintext-derived
    /// vector on a row whose whole point is that no such derivative survives.
    /// CLAUDE.md's audit calls that a confidentiality violation rather than an
    /// embedding gap, which is why the refusal is in the statement every caller
    /// shares rather than in one caller's control flow.
    ///
    /// Keyed on `claim_encryption`, NEVER on `visibility`: a group-private
    /// claim is ordinary plaintext and must still be embedded.
    ///
    /// # Returns
    ///
    /// `true` when a row was updated; `false` for both "no such claim" and "the
    /// claim is sealed", which this statement deliberately does not
    /// distinguish. Callers treat a `false` as "nothing to store".
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, embedding_pgvector))]
    pub async fn store_embedding(
        pool: &PgPool,
        id: Uuid,
        embedding_pgvector: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE claims SET embedding = $1::vector \
              WHERE id = $2 \
                AND NOT EXISTS ( \
                    SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id \
                )",
        )
        .bind(embedding_pgvector)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Store an embedding vector on a claim **only while that claim is not
    /// sealed**, and only on a row the viewer may write.
    ///
    /// The counterpart to
    /// [`claim_text_for_embedding`](Self::claim_text_for_embedding), and the
    /// reason the pair exists rather than a single read followed by
    /// [`store_embedding`](Self::store_embedding): the read and the write are
    /// separated by a network round trip to an embedding provider, and a claim
    /// can be sealed inside that window. Both halves of the pair therefore
    /// apply the same population rules — `claim_encryption`, `is_current`.
    ///
    /// The `NOT EXISTS` is on `claim_encryption`, not on `visibility` — a
    /// group-private claim is ordinary plaintext and must still be embedded.
    ///
    /// # Why the row is locked first, rather than trusting one statement's `WHERE`
    ///
    /// A single `UPDATE` whose `WHERE` re-checks `claim_encryption` is NOT
    /// enough, and an earlier revision of this comment claimed it was. Under
    /// `READ COMMITTED` an `UPDATE` that blocks on a row another transaction is
    /// updating re-evaluates its qualification after that transaction commits,
    /// but it does so against its ORIGINAL snapshot for every OTHER table — and
    /// `claim_encryption` is another table. A seal committing inside that wait
    /// would therefore go unseen and the vector would be written anyway.
    ///
    /// Taking the row lock in a SEPARATE statement first fixes that: the
    /// `UPDATE` then takes a fresh statement snapshot AFTER the lock is
    /// granted, and that snapshot does include the committed seal. It must be a
    /// separate statement — folding the lock into a CTE of the same statement
    /// changes nothing, because all parts of one statement share a snapshot.
    /// The reverse interleaving is safe without any of this: if this
    /// transaction takes the lock first, the seal's own `UPDATE` blocks behind
    /// it and nulls the vector when it proceeds.
    ///
    /// # Returns
    ///
    /// `true` when a row was updated. `false` covers four cases deliberately
    /// indistinguishable to the caller: no such claim, a claim sealed since the
    /// text was read, a claim superseded since the text was read, and a claim
    /// the viewer may not write. A caller that needs to tell "sealed" from
    /// "absent" would need a second read, and the answer it got would already
    /// be stale.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, viewer, embedding_pgvector))]
    pub async fn store_embedding_if_unsealed(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
        embedding_pgvector: &str,
    ) -> Result<bool, DbError> {
        let mut tx = sqlx::Connection::begin(&mut *conn).await?;

        // The lock, as its own statement. See the section above: this is what
        // makes the `NOT EXISTS` below read a snapshot that contains a seal
        // which committed while this job was calling the provider.
        sqlx::query("SELECT 1 FROM claims WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;

        let sql = viewer.splice_write(
            "UPDATE claims AS c SET embedding = $2::vector \
              WHERE c.id = $1 \
                AND COALESCE(c.is_current, true) = true \
                AND NOT EXISTS ( \
                    SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = c.id \
                ) \
                /* {WRITABLE:c} */",
            3,
        );
        let mut q = sqlx::query(&sql).bind(id).bind(embedding_pgvector);
        // Conditional, not `unwrap_or(&[])`: a `Bypass` viewer renders `" "`, so
        // the statement has no `$3` to fill and binding unconditionally would
        // over-supply the maintenance path by one parameter.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let result = q.execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

    /// Maximum number of claim IDs accepted by [`pairwise_cosine_distance`](Self::pairwise_cosine_distance).
    /// At N=1000 the O(N²) cross-join produces ~500 k pair comparisons in Postgres; beyond
    /// this threshold query time becomes unreasonable and the result set itself is huge.
    pub const MAX_PAIRWISE_IDS: usize = 1_000;

    /// Compute pairwise cosine distances between claims in the given set, over
    /// `claims.embedding` (1536d).
    ///
    /// Thin wrapper over [`Self::pairwise_cosine_distance_at_dim`] at
    /// `dim = 1536`, kept because 1536 is this repo's default vector space and
    /// most callers have no dim to thread.
    ///
    /// # Errors
    /// See [`Self::pairwise_cosine_distance_at_dim`].
    #[instrument(skip(executor))]
    pub async fn pairwise_cosine_distance<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
        max_distance: f64,
    ) -> Result<Vec<ClaimPairDistance>, DbError> {
        Self::pairwise_cosine_distance_at_dim(executor, viewer, claim_ids, max_distance, 1536).await
    }

    /// Compute pairwise cosine distances between claims in the given set, in
    /// the vector space named by `dim`.
    ///
    /// Returns all pairs where distance < `max_distance`, ordered ascending.
    /// Uses pgvector `<=>` operator, so distances are on `[0, 2]` and a
    /// SMALLER number means MORE similar. Note: this is a brute-force O(N²)
    /// scan — HNSW indexes do not accelerate distance filters.
    ///
    /// # `dim` must be the dim the retrieval being filtered actually searched
    ///
    /// `claims.embedding` (1536) and `claims.embedding_3072` are different
    /// spaces. Measuring a page retrieved at 3072 against the 1536 column
    /// compares vectors that were never comparable, and on a corpus embedded
    /// only at 3072 it silently returns NO pairs at all — which every caller
    /// that reads "no pair" as "far apart" would report as a perfectly diverse
    /// result set. `recall_with_context` chooses its dim at runtime
    /// (`detect_centroid_dim`), which is why this parameter exists rather than
    /// the column being hardcoded as it was when this function had no callers.
    ///
    /// # An unmeasurable pair is ABSENT from the result, never distance 0
    ///
    /// A pair is absent when either side has a NULL vector in the selected
    /// column (the embedder-down lexical leg produces such hits; so does a
    /// corpus half-migrated between the two columns), when either id is not a
    /// `claims` row at all, or when the viewer predicate excludes it. Callers
    /// must read absence as "not known to be near": treating it as distance 0
    /// would mark every unembedded row a duplicate of everything.
    ///
    /// # Errors
    /// - `DbError::InvalidData` for a `dim` other than 1536 or 3072
    /// - `DbError::QueryFailed` if `claim_ids.len() > MAX_PAIRWISE_IDS`
    /// - `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn pairwise_cosine_distance_at_dim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
        max_distance: f64,
        dim: u32,
    ) -> Result<Vec<ClaimPairDistance>, DbError> {
        // A closed match, never caller-supplied text: `column` is interpolated
        // into the statement, so only these two spellings can reach it.
        let column = match dim {
            1536 => "embedding",
            3072 => "embedding_3072",
            _ => {
                return Err(DbError::InvalidData {
                    reason: format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"),
                });
            }
        };
        if claim_ids.len() < 2 {
            return Ok(vec![]);
        }
        if claim_ids.len() > Self::MAX_PAIRWISE_IDS {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "pairwise_cosine_distance: {} ids exceeds MAX_PAIRWISE_IDS={}; \
                     split the input into smaller batches",
                    claim_ids.len(),
                    Self::MAX_PAIRWISE_IDS,
                )),
            });
        }

        // `{{VISIBILITY:…}}` is doubled because this is now a `format!`
        // template; see `search_by_embedding_since` for the same doubling and
        // why `visibility_lint.rs` normalises it before matching. Both aliases
        // stay marked — they resolve to the SAME bind index, so two markers
        // still cost one bind, and marking only `c1` would measure a pair
        // against a `c2` the reader cannot see.
        let sql = viewer.splice(
            &format!(
                r#"
            SELECT
                c1.id AS claim_a,
                c2.id AS claim_b,
                (c1.{column} <=> c2.{column})::float8 AS distance
            FROM claims c1
            JOIN claims c2 ON c1.id < c2.id
            WHERE c1.id = ANY($1)
              AND c2.id = ANY($1)
              AND c1.{column} IS NOT NULL
              AND c2.{column} IS NOT NULL
              AND (c1.{column} <=> c2.{column}) < $2
              /* {{VISIBILITY:c1}} */ /* {{VISIBILITY:c2}} */
            ORDER BY (c1.{column} <=> c2.{column})
            "#
            ),
            3,
        );
        let mut q = sqlx::query_as::<_, ClaimPairDistance>(&sql)
            .bind(claim_ids)
            .bind(max_distance);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<ClaimPairDistance> = q.fetch_all(executor).await?;

        Ok(rows)
    }
}

// ── Step Evolution ──

impl ClaimRepository {
    /// Atomically create a new step claim that supersedes or revises a parent.
    ///
    /// `edge_type` must be `"supersedes"` (linear; flips parent.is_current=false)
    /// or `"revises"` (parallel branch; both heads stay current).
    ///
    /// The new claim inherits the parent's `step_lineage_id`. If the parent has
    /// no lineage id yet, one is generated and back-filled onto the parent first.
    /// `level` defaults to 2 (step). The `properties` JSONB on the new claim
    /// includes `level` and `step_lineage_id` so existing find_workflow_hierarchical
    /// queries (which filter on `properties->>'level' = '2'`) still work.
    ///
    /// With `supersedes`, the new claim also records `supersedes = parent`, so
    /// the Supersede admin cascade (and its deferred replay) migrates the
    /// parent's edges onto it; see [`Self::migrate_superseded_edges_conn`] and
    /// the step-lineage paragraph of [`Self::supersede`]'s edge migration
    /// policy. This function performs only the act: the request paths run the
    /// cascade after it commits.
    #[instrument(skip(pool))]
    pub async fn evolve_step(
        pool: &PgPool,
        parent: ClaimId,
        new_content: &str,
        edge_type: &str,
        reason: Option<&str>,
        level: u32,
        agent_id: Uuid,
    ) -> Result<EvolveStepResult, DbError> {
        let mut tx = pool.begin().await?;
        let result = Self::evolve_step_conn(
            &mut tx,
            parent,
            new_content,
            edge_type,
            reason,
            level,
            agent_id,
        )
        .await?;
        tx.commit().await?;
        Ok(result)
    }

    /// [`Self::evolve_step`] on the caller's connection, inside the caller's
    /// transaction (which the caller commits). The request paths use this on
    /// a transaction stamped with the caller's viewer, so that migration 122's
    /// claims trigger sees the writing principal: once the database is armed
    /// it refuses a claim written by an application session with no
    /// principal.
    ///
    /// # Errors
    /// Every refusal below writes nothing.
    /// - `DbError::InvalidData` for an `edge_type` other than `supersedes` /
    ///   `revises`, or a parent whose stored visibility is outside the
    ///   vocabulary.
    /// - `DbError::NotFound` for a parent that does not exist or that the
    ///   parent's locked read does not return (row security hides it).
    /// - `DbError::Conflict` for `supersedes` on a parent that is no longer
    ///   current.
    /// - `DbError::WriteRefused` for `supersedes` when the retire of a parent
    ///   the locked read returned changed no row (for example a trigger
    ///   skipped it). Defensive: the claims tenancy policy refuses a readable
    ///   parent the session may not write by raising at its WITH CHECK
    ///   (`QueryFailed`, SQLSTATE 42501, the transaction aborted), not by
    ///   matching zero rows.
    #[instrument(skip(conn))]
    pub async fn evolve_step_conn(
        conn: &mut sqlx::PgConnection,
        parent: ClaimId,
        new_content: &str,
        edge_type: &str,
        reason: Option<&str>,
        level: u32,
        agent_id: Uuid,
    ) -> Result<EvolveStepResult, DbError> {
        // The two refusals below are the CALLER's to fix (backlog 769989ae):
        // `InvalidData` (HTTP 400, MCP INVALID_PARAMS) for a request outside
        // the vocabulary and `Conflict` (HTTP 409) for a parent that is no
        // longer current. A `QueryFailed` here read as a server fault on both
        // transports.
        if !matches!(edge_type, "supersedes" | "revises") {
            return Err(DbError::InvalidData {
                reason: format!(
                    "evolve_step: edge_type must be 'supersedes' or 'revises', got {edge_type}"
                ),
            });
        }
        let parent_uuid: Uuid = parent.into();
        let tx = conn;

        // The parent's tenancy is read HERE, under the same FOR UPDATE that
        // guards the lineage id, and bound explicitly on the INSERT below.
        //
        // Migration 074 arm 2 would derive it from `step_lineage_id` anyway, so
        // this is belt and braces -- but the plan says "prefer explicit" and the
        // reason is concrete: arm 2 picks the lineage's most recent row by
        // `created_at DESC`, which is not necessarily THIS parent. On a
        // `revises` branch the lineage has two live heads, and inheriting from
        // whichever was written last is a different answer from inheriting from
        // the step being revised. Binding the parent's own values makes the two
        // agree by construction instead of by timing.
        let row: Option<(Option<Uuid>, bool, Uuid, String)> =
            sqlx::query_as(
                r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
                SELECT step_lineage_id, COALESCE(is_current, true),
                       owner_group_id, visibility
                FROM claims
                WHERE id = $1 FOR UPDATE"#,
            )
                .bind(parent_uuid)
                .fetch_optional(&mut *tx)
                .await?;
        let (existing_lineage, parent_current, parent_group, parent_visibility) =
            row.ok_or(DbError::NotFound {
                entity: "Claim".into(),
                id: parent_uuid,
            })?;
        let decl = match epigraph_core::Visibility::from_db_str(&parent_visibility) {
            Some(v) => TenancyDecl::Declared {
                visibility: v,
                owner_group_id: parent_group,
            },
            // An unparseable stored visibility is not a value to guess at. The
            // column is NOT NULL with a CHECK, so reaching this means the
            // constraint was dropped out of band -- fail the write rather than
            // pick a side.
            None => {
                return Err(DbError::InvalidData {
                    reason: format!(
                        "evolve_step: parent claim {parent_uuid} has visibility \
                         {parent_visibility:?}, which is outside the vocabulary"
                    ),
                })
            }
        };
        if edge_type == "supersedes" && !parent_current {
            return Err(DbError::Conflict {
                reason: format!("evolve_step: cannot supersede a non-current step {parent_uuid}"),
            });
        }
        if edge_type == "supersedes" {
            // Retire the predecessor BEFORE any other write (the lineage
            // back-fill, the successor, its edge), and refuse when the retire
            // changed nothing (backlog d34f5096). An UPDATE that changes no
            // row does not raise: it reports success. The locked read above
            // already returned the parent current, so a zero-row retire means
            // something skipped it (a trigger, say; the claims tenancy policy
            // refuses an unwritable row by raising at WITH CHECK instead), and
            // inserting the successor after it would leave the lineage with
            // two current heads. Retiring first means a refusal has written
            // nothing, as in `supersede_act_conn`.
            //
            // Also null both embedding columns so the retired step drops out
            // of semantic search. Mirrors the invariant enforced by
            // supersede() and mark_duplicate(): is_current=false → embedding
            // (and embedding_3072) = NULL.
            let retired = sqlx::query(
                "UPDATE claims SET is_current = false, embedding = NULL, embedding_3072 = NULL, \
                 updated_at = NOW() WHERE id = $1",
            )
            .bind(parent_uuid)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if retired != 1 {
                return Err(DbError::WriteRefused {
                    entity: "Claim".to_string(),
                    id: parent_uuid,
                    action: "supersede".to_string(),
                });
            }
        }

        let lineage_id = match existing_lineage {
            Some(l) => l,
            None => {
                let new_lineage = Uuid::new_v4();
                sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
                    .bind(new_lineage)
                    .bind(parent_uuid)
                    .execute(&mut *tx)
                    .await?;
                new_lineage
            }
        };

        let new_uuid = Uuid::new_v4();
        let hash = ContentHasher::hash(new_content.as_bytes());
        let properties = serde_json::json!({
            "level": level,
            "step_lineage_id": lineage_id.to_string(),
        });
        // A `supersedes` step also records the supersession in the column, as
        // the supersede act does: that is what `migrate_superseded_edges_conn`
        // (the Supersede admin cascade, and its deferred replay) and migration
        // 120's deferral check verify before carrying the retired step's edges
        // to this one. A `revises` branch supersedes nothing (both heads stay
        // current), so it records none.
        let supersedes: Option<Uuid> = (edge_type == "supersedes").then_some(parent_uuid);
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties, step_lineage_id, \
                                 visibility, owner_group_id, supersedes) \
             VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], $5, $6, $7, $8, $9)",
        )
        .bind(new_uuid)
        .bind(new_content)
        .bind(hash.as_slice())
        .bind(agent_id)
        .bind(&properties)
        .bind(lineage_id)
        .bind(decl.visibility_bind())
        .bind(decl.owner_group_bind())
        .bind(supersedes)
        .execute(&mut *tx)
        .await?;

        let edge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, $2, 'claim', $3, 'claim', $4, jsonb_build_object('reason', $5))",
        )
        .bind(edge_id)
        .bind(new_uuid)
        .bind(parent_uuid)
        .bind(edge_type)
        .bind(reason.unwrap_or(""))
        .execute(&mut *tx)
        .await?;

        Ok(EvolveStepResult {
            new_claim_id: new_uuid,
            step_lineage_id: lineage_id,
            edge_type: edge_type.to_string(),
            edge_id,
        })
    }

    /// Mark `dup` as a duplicate of `canonical` without creating a new claim.
    /// Sets `supersedes = canonical, is_current = false` on `dup` only.
    /// Refuses if `dup.supersedes` is already set.
    ///
    /// Thin wrapper over [`ClaimRepository::mark_duplicate_with_repair`],
    /// discarding the repair report. Existing callers that do not need to run
    /// a downstream belief cascade keep the exact pre-cascade signature and
    /// behaviour.
    ///
    /// # Implementation Notes
    /// The UPDATE that sets `is_current = false` on the duplicate also sets
    /// `embedding = NULL` and `embedding_3072 = NULL` in the **same
    /// statement**, satisfying the CHECK constraint
    /// `chk_deprecated_no_embedding` (migration 052).  This constraint fires
    /// per-statement, so any split across two UPDATE statements would violate
    /// it between them.  Any future caller must preserve this single-statement
    /// invariant.  See also [`ClaimRepository::supersede`] which has the same
    /// requirement.
    #[instrument(skip(pool))]
    pub async fn mark_duplicate(
        pool: &PgPool,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<(), DbError> {
        Self::mark_duplicate_with_repair(pool, dup, canonical)
            .await
            .map(|_| ())
    }

    /// [`ClaimRepository::mark_duplicate`] plus in-transaction repair of the
    /// **derived-record layer**, returning what the caller must re-derive.
    ///
    /// # Why the edge migration alone corrupts belief
    /// Edge-factor BBAs are stored on the edge's **target** claim keyed
    /// `perspective_id = edge_id` (`auto_wire_ds_for_edge` →
    /// `store_with_perspective(pool, target_id, ...)`). Before this function
    /// existed, dedup touched only `edges` and `claims`, which left two
    /// distinct classes of wreckage — both instances of the MemTX I2
    /// violation "retracting a belief leaves an orphaned derived record":
    ///
    /// * **Orphaned.** The three collision pre-deletes below remove edges
    ///   whose BBA rows survive: `mass_functions_perspective_id_fkey`
    ///   references `perspectives(id)`, and `perspectives` rows minted by
    ///   `ensure_edge_perspective` have no FK back to `edges`, so nothing
    ///   cascades. The phantom supporter keeps being combined forever.
    /// * **Stranded.** `UPDATE edges SET target_id = canonical` re-points an
    ///   edge while its BBA stays on `dup`, so `canonical` **under-counts**
    ///   that supporter permanently — and it can never self-heal, because
    ///   `MassFunctionRepository::exists_for_perspective` is keyed on
    ///   `perspective_id` alone and ignores `claim_id`, so
    ///   `auto_wire_edge_if_epistemic` short-circuits on it forever.
    ///
    /// Both repairs run inside the same transaction as the edge mutation, so
    /// there is no window in which the graph is observably inconsistent.
    ///
    /// The returned [`DedupRepair`] carries the claims whose cached scalars
    /// are now stale and the edges whose BBAs must be re-derived from
    /// `canonical`'s interval instead of `dup`'s. Recombining those existing
    /// BBA rows would be a numeric no-op — their `masses` were frozen at wire
    /// time — so the caller-side cascade
    /// (`epigraph_engine::retraction_cascade`) invalidates and re-wires them.
    ///
    /// # Errors
    /// Same as [`ClaimRepository::mark_duplicate`].
    #[instrument(skip(pool))]
    pub async fn mark_duplicate_with_repair(
        pool: &PgPool,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<DedupRepair, DbError> {
        let mut conn = pool.acquire().await?;
        Self::mark_duplicate_with_repair_conn(&mut conn, dup, canonical).await
    }

    /// [`Self::mark_duplicate_with_repair`] on a connection the caller owns: the
    /// dedup's act ([`Self::mark_duplicate_act_conn`]) and its repair
    /// ([`Self::repair_marked_duplicate_conn`]) in ONE transaction.
    ///
    /// The pool-taking wrapper above delegates here, so there is one
    /// implementation. `begin()` below opens a real transaction when this
    /// connection is not already in one and a **SAVEPOINT** when it is, so the
    /// repair stays atomic in both shapes.
    ///
    /// A concrete `&mut PgConnection` rather than a generic `Acquire` for the
    /// reason recorded on [`Self::create_with_id_if_absent_conn`].
    ///
    /// # Migration 117: a PRIVILEGED session only
    ///
    /// The repair retracts and re-points edges and moves BBAs whoever owns
    /// them. Since 117 a non-privileged session's UPDATE of an edge it does not
    /// own matches no row, so on such a session this would retire the
    /// duplicate and silently leave most of the repair undone. It therefore
    /// refuses one outright. The semantic-duplicate sweep runs it on the
    /// maintenance connection; a request path runs the act on the caller's
    /// stamped transaction and the repair on the maintenance connection
    /// (`epigraph_engine::admin_cascade`).
    ///
    /// # Errors
    /// As [`Self::mark_duplicate_with_repair`], and `DbError::InvalidData` on a
    /// non-privileged session.
    pub async fn mark_duplicate_with_repair_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<DedupRepair, DbError> {
        Self::mark_duplicate_with_repair_attributed_conn(
            conn,
            dup,
            canonical,
            &DuplicateProvenance::unattributed(),
        )
        .await
    }

    /// [`Self::mark_duplicate_with_repair_conn`] with the caller's
    /// [`DuplicateProvenance`] on the identity edge the act writes.
    ///
    /// # Errors
    /// As [`Self::mark_duplicate_with_repair_conn`].
    pub async fn mark_duplicate_with_repair_attributed_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
        provenance: &DuplicateProvenance,
    ) -> Result<DedupRepair, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "mark_duplicate_with_repair_conn (its repair re-points other writers' edges)",
        )
        .await?;
        let dup_uuid: Uuid = dup.into();
        let canon_uuid: Uuid = canonical.into();
        let mut tx = conn.begin().await?;
        mark_duplicate_act(&mut tx, dup_uuid, canon_uuid, provenance).await?;
        let repair = repair_marked_duplicate(&mut tx, dup_uuid, canon_uuid).await?;
        tx.commit().await?;
        Ok(repair)
    }

    /// The dedup's own act, and nothing else: mark `dup` a duplicate of
    /// `canonical` (`supersedes = canonical`, `is_current = false`, embeddings
    /// NULL, in one statement).
    ///
    /// The one row it writes is the duplicate, which the caller must be able to
    /// write, so it runs on the CALLER's stamped transaction and the database
    /// decides write authority. Everything the old single transaction also did
    /// -- retracting colliding edges, re-pointing other writers' edges onto the
    /// canonical, moving their BBAs -- is the administrative cascade's
    /// ([`Self::repair_marked_duplicate_conn`], migration 117).
    ///
    /// It keeps one refusal of that repair, because the repair runs with
    /// administrative authority and must not carry a content decision the
    /// caller could not make itself: a duplicate bound to `binary_truth` at a
    /// non-zero index (FALSE) does not hand that binding to a canonical the
    /// caller cannot write and that has none (FA07, review finding W2). The
    /// repair also skips such a copy; refusing here keeps the act and the
    /// repair from diverging when the caller can see the edge or the BBA (the
    /// repair pools the duplicate's own BBAs too) that would carry it.
    ///
    /// And it keeps 114's attach rule for the canonical (FA04: a non-owner may
    /// attach only to a PUBLIC claim). The repair moves the duplicate's
    /// edge-keyed BBAs and copies its frame bindings onto the canonical with
    /// administrative authority, and on a non-public canonical those rows take
    /// the canonical's owner: a session that may only READ that canonical would
    /// be writing into its group through the repair. So a non-privileged
    /// session may dedup onto a non-public canonical only when it writes that
    /// canonical. The refusal is unconditional (it does not ask whether there
    /// is anything to move), because the caller cannot see every edge the
    /// repair will move.
    ///
    /// # Errors
    /// `DbError::NotFound` for a missing canonical or duplicate,
    /// `DbError::QueryFailed` for a duplicate already superseded, for
    /// `dup == canonical`, for the FA04 and FA07 refusals and for any refused
    /// statement.
    pub async fn mark_duplicate_act_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<(), DbError> {
        Self::mark_duplicate_act_attributed_conn(
            conn,
            dup,
            canonical,
            &DuplicateProvenance::unattributed(),
        )
        .await
        .map(|_| ())
    }

    /// [`Self::mark_duplicate_act_conn`] with the caller's
    /// [`DuplicateProvenance`]. Returns the id of the `same_as` identity edge
    /// the act wrote.
    ///
    /// # Errors
    /// As [`Self::mark_duplicate_act_conn`].
    pub async fn mark_duplicate_act_attributed_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
        provenance: &DuplicateProvenance,
    ) -> Result<Uuid, DbError> {
        use sqlx::Acquire;
        let dup_uuid: Uuid = dup.into();
        let canon_uuid: Uuid = canonical.into();
        let mut tx = conn.begin().await?;
        let identity_edge = mark_duplicate_act(&mut tx, dup_uuid, canon_uuid, provenance).await?;
        let foreign_private_canonical: bool = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
            SELECT NOT public.epigraph_session_is_privileged_writer()
               AND c.visibility::text <> 'public'
               AND NOT public.epigraph_session_writes_node(c.id, 'claim')
              FROM claims c WHERE c.id = $1"#,
        )
        .bind(canon_uuid)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);
        if foreign_private_canonical {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "FA04: canonical {canon_uuid} is not public and this session cannot write \
                     it; a dedup would move the duplicate's derived rows into its owner's \
                     group, and a non-owner may attach only to a PUBLIC claim; nothing was \
                     written"
                )),
            });
        }
        let false_binding: bool = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
            SELECT NOT public.epigraph_session_is_privileged_writer()
               AND NOT public.epigraph_session_writes_node($2, 'claim')
               AND EXISTS (
                   SELECT 1 FROM claim_frames cf
                     JOIN frames f ON f.id = cf.frame_id AND f.name = 'binary_truth'
                    WHERE cf.claim_id = $1
                      AND cf.hypothesis_index IS DISTINCT FROM 0
                      AND NOT EXISTS (SELECT 1 FROM claim_frames c2
                                       WHERE c2.claim_id = $2 AND c2.frame_id = cf.frame_id))
               AND (EXISTS (
                   SELECT 1 FROM edges e
                    WHERE e.target_id = $1 AND e.target_type = 'claim'
                      AND e.relationship != 'supersedes' AND e.valid_to IS NULL
                      AND NOT (e.source_type = 'claim' AND e.source_id = $2))
                 -- The repair's pooling (part 3) copies the frame bindings too.
                 OR EXISTS (SELECT 1 FROM mass_functions m WHERE m.claim_id = $1))"#,
        )
        .bind(dup_uuid)
        .bind(canon_uuid)
        .fetch_one(&mut *tx)
        .await?;
        if false_binding {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "FA07: duplicate {dup_uuid} is bound to binary_truth at a non-zero index, and \
                     canonical {canon_uuid} (which this session cannot write) has no binding: a \
                     dedup may not hand it one; nothing was written"
                )),
            });
        }
        tx.commit().await?;
        Ok(identity_edge)
    }

    /// The dedup's repair, as the administrative cascade runs it after the
    /// caller's [`Self::mark_duplicate_act_conn`] committed: retract the
    /// duplicate's colliding edges and drop their BBAs, re-point every other
    /// edge onto the canonical, and move (or, on a key collision, drop) the
    /// BBAs of the edges that now target it. Returns what the belief cascade
    /// must re-derive.
    ///
    /// Re-verifies the committed act first (`dup` supersedes `canonical` and
    /// is retired), so it acts only on a dedup that happened, and it is
    /// idempotent: a second run finds nothing left on `dup` to move. That makes
    /// it the replay of a deferred cascade too.
    ///
    /// # Errors
    /// `DbError::InvalidData` on a non-privileged session, or when `dup` is
    /// not a retired duplicate of `canonical`; `DbError::QueryFailed` on any
    /// failed statement.
    pub async fn repair_marked_duplicate_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<DedupRepair, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "repair_marked_duplicate_conn (it re-points other writers' edges)",
        )
        .await?;
        let dup_uuid: Uuid = dup.into();
        let canon_uuid: Uuid = canonical.into();
        let mut tx = conn.begin().await?;
        let recorded: Option<(Option<Uuid>, bool)> = sqlx::query_as(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; this read verifies the act the mutation follows.
            SELECT supersedes, COALESCE(is_current, true) FROM claims WHERE id = $1 FOR UPDATE"#,
        )
        .bind(dup_uuid)
        .fetch_optional(&mut *tx)
        .await?;
        match recorded {
            Some((Some(sup), false)) if sup == canon_uuid => {}
            _ => {
                return Err(DbError::InvalidData {
                    reason: format!(
                        "claim {dup_uuid} is not a retired duplicate of {canon_uuid}; refusing to \
                         repair its edges"
                    ),
                })
            }
        }
        let repair = repair_marked_duplicate(&mut tx, dup_uuid, canon_uuid).await?;
        tx.commit().await?;
        Ok(repair)
    }

    /// Backfill the `same_as` identity edge of every duplicate the legacy
    /// raw-SQL `fuzzy_dedup_claims` marked (backlog d5781a48). Dry run unless
    /// `apply`; an operator runs it (`epigraph-cli backfill_dedup_identity_edges`).
    ///
    /// Before 2026-10 that script retired a duplicate with its own
    /// `UPDATE claims` and wrote no identity edge, so no reader of the dedup
    /// identity (the index view [`Self::marked_duplicates_of`], the un-mark)
    /// sees the mark. Selected, and nothing else: a claim carrying the
    /// `deduped` label with `properties.deduped_by =`
    /// [`LEGACY_FUZZY_DEDUP_TOOL`], retired (`is_current = false`), whose
    /// `supersedes` is still the `properties.deduped_into` the mark wrote, and
    /// that has no in-force identity edge to it. A consolidation source or a
    /// supersession (no marker), a soft-marked duplicate still current, a mark
    /// whose claim was since re-pointed elsewhere, and a dedup act's mark (it
    /// has its edge) are all left alone, and a second run finds nothing.
    ///
    /// The edge carries [`DuplicateProvenance`] under
    /// [`DUPLICATE_IDENTITY_PROPERTY`] with the legacy tool, the
    /// [`LEGACY_IDENTITY_BACKFILL_RUN_TAG`], the mark's own `deduped_at` as
    /// `marked_at` and a `backfilled_at`; no `marked_by`, which the legacy mark
    /// never recorded. The legacy `deduped_at` is Postgres timestamp text
    /// (`now()::text`); `marked_at` is re-encoded as the act writes it
    /// (`to_jsonb` of the `timestamptz`), and left out when the text is not
    /// timestamp-shaped, so a stray non-timestamp value does not abort the
    /// run's single transaction. Like the act's edge it is written after the
    /// retirement, so `edges_auto_factor` mints no factor for it.
    ///
    /// Once its edge is written the mark is an ordinary dedup record
    /// (operator ruling R-7): the administrative un-mark makes the duplicate
    /// current again and retracts the edge. The legacy script kept no repair
    /// record, so that un-mark has nothing to put back (it reports
    /// `legacy_mark`); a legacy mark this selection does not reach is refused
    /// with the reason ([`ClaimRepository::unmark_duplicate_act_conn`]).
    ///
    /// # Errors
    /// `DbError::InvalidData` on a non-privileged session (the selection is
    /// corpus-wide, and row security would hide most of it);
    /// `DbError::QueryFailed` on a failed statement.
    pub async fn backfill_legacy_dedup_identity_edges_conn(
        conn: &mut sqlx::PgConnection,
        apply: bool,
    ) -> Result<LegacyIdentityBackfill, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "backfill_legacy_dedup_identity_edges_conn (it selects and writes across every owner)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let select_sql = format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; the selection is a corpus-wide maintenance backfill.
             SELECT c.id, c.supersedes FROM claims c
              WHERE c.properties->>'deduped_by' = $1
                AND {LEGACY_MARK_RECONSTRUCTABLE_SQL}
                AND NOT EXISTS (
                    SELECT 1 FROM edges e
                     WHERE e.source_id = c.id AND e.source_type = 'claim'
                       AND e.target_id = c.supersedes AND e.target_type = 'claim'
                       AND e.relationship = $2 AND e.valid_to IS NULL
                       AND e.properties ? $3)
              ORDER BY c.id
              FOR UPDATE OF c"#
        );
        let selected: Vec<(Uuid, Uuid)> = sqlx::query_as(&select_sql)
            .bind(LEGACY_FUZZY_DEDUP_TOOL)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY)
            .fetch_all(&mut *tx)
            .await?;
        let mut out = LegacyIdentityBackfill {
            applied: apply,
            duplicates: selected
                .iter()
                .map(|(duplicate, canonical)| LegacyDuplicate {
                    duplicate: *duplicate,
                    canonical: *canonical,
                    identity_edge: None,
                })
                .collect(),
            inserted: 0,
        };
        if !apply || selected.is_empty() {
            tx.rollback().await?;
            return Ok(out);
        }
        let provenance = DuplicateProvenance::new(LEGACY_FUZZY_DEDUP_TOOL, "legacy_fuzzy_dedup")
            .run_tag(LEGACY_IDENTITY_BACKFILL_RUN_TAG)
            .reason(Some(
                "identity edge backfilled for a duplicate fuzzy_dedup_claims retired by raw SQL \
                 before identity edges were recorded; no repair record exists for this mark",
            ));
        let provenance_json =
            serde_json::to_value(&provenance).map_err(|e| DbError::InvalidData {
                reason: format!("legacy identity backfill: provenance does not serialize: {e}"),
            })?;
        let duplicate_ids: Vec<Uuid> = selected.iter().map(|(d, _)| *d).collect();
        let written: Vec<(Uuid, Uuid)> = sqlx::query_as(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
             SELECT c.id, 'claim', c.supersedes, 'claim', $2,
                    jsonb_build_object($3::text,
                        $4::jsonb
                        || jsonb_strip_nulls(jsonb_build_object(
                               'marked_at', CASE WHEN c.properties->>'deduped_at'
                                   ~ '^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?\s*(Z|[+-]\d{2}(:?\d{2})?)?\s*$'
                                   THEN to_jsonb((c.properties->>'deduped_at')::timestamptz)
                                   END,
                               'backfilled_at', now())))
               FROM claims c WHERE c.id = ANY($1)
             RETURNING source_id, id"#,
        )
        .bind(&duplicate_ids)
        .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
        .bind(DUPLICATE_IDENTITY_PROPERTY)
        .bind(&provenance_json)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        for d in &mut out.duplicates {
            d.identity_edge = written
                .iter()
                .find(|(dup, _)| *dup == d.duplicate)
                .map(|(_, edge)| *edge);
        }
        out.inserted = written.len() as u64;
        Ok(out)
    }

    /// The un-mark's own act, on the CALLER's stamped transaction: `dup` is
    /// current again (`is_current = true`, `supersedes = NULL`) and the act's
    /// `same_as` identity edge is retracted. The database decides write
    /// authority over both rows.
    ///
    /// Only a duplicate a dedup act marked can be un-marked: one with an
    /// in-force identity edge to the claim its `supersedes` names (a legacy
    /// `fuzzy_dedup_claims` mark has one once the backfill wrote it, and is
    /// then an ordinary record, `legacy_backfill`). A claim retired some other
    /// way (a consolidation source, a supersession) is refused, because there
    /// is no record of which rows a reversal would have to put back; so is a
    /// legacy mark without its edge, saying whether the backfill can still
    /// reconstruct it or why it cannot.
    ///
    /// A canonical superseded or consolidated since the mark is followed to
    /// its current replacement ([`Self::unmark_chain_conn`]), and the
    /// reversal restores the duplicate against that one; a canonical that
    /// was itself marked a duplicate is refused (un-mark it first).
    ///
    /// The embeddings stay NULL: the caller re-embeds after commit
    /// (best-effort, as every write path does), or a backfill does.
    ///
    /// # Errors
    /// `DbError::NotFound` for a missing claim; `DbError::QueryFailed` for a
    /// claim that is not a marked duplicate or a refused statement.
    pub async fn unmark_duplicate_act_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        dup: ClaimId,
    ) -> Result<UnmarkedDuplicate, DbError> {
        Self::unmark_duplicate_act_authorized_conn(conn, viewer, dup, None).await
    }

    /// [`Self::unmark_duplicate_act_conn`] for a request path that checked the
    /// caller's authority over every claim of the canonical's chain, read
    /// through the CALLER ([`Self::unmark_chain_conn`]): `authorized_chain` is
    /// that chain. An act whose own read (under `viewer`, on the request paths
    /// the maintenance connection's bypass viewer) resolves any other chain,
    /// or none, is refused with nothing written: the canonical was replaced
    /// again since the caller was checked. That refusal names no claim of the
    /// chain the act read, which the caller may not be able to read.
    ///
    /// # Errors
    /// As [`Self::unmark_duplicate_act_conn`].
    pub async fn unmark_duplicate_act_authorized_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        dup: ClaimId,
        authorized_chain: Option<&[Uuid]>,
    ) -> Result<UnmarkedDuplicate, DbError> {
        use sqlx::Acquire;
        let dup_uuid: Uuid = dup.into();
        let mut tx = conn.begin().await?;
        // Every read below is filtered by the viewer, like the writes: a claim
        // or edge it cannot read is "not marked", never an existence oracle.
        let sql = viewer.splice(
            "SELECT c.supersedes, COALESCE(c.is_current, true) FROM claims c \
              WHERE c.id = $1 /* {VISIBILITY:c} */ FOR UPDATE",
            2,
        );
        let mut q = sqlx::query_as::<_, (Option<Uuid>, bool)>(&sql).bind(dup_uuid);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row = q.fetch_optional(&mut *tx).await?;
        let Some((supersedes, current)) = row else {
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: dup_uuid,
            });
        };
        let not_marked = |why: &str| DbError::QueryFailed {
            source: sqlx::Error::Protocol(format!(
                "unmark_duplicate: claim {dup_uuid} {why}; nothing was written"
            )),
        };
        let canonical = match (supersedes, current) {
            (Some(c), false) => c,
            _ => return Err(not_marked("is not a retired duplicate")),
        };
        let sql = viewer.splice(
            "SELECT e.id, \
                    COALESCE(e.properties->$4->>'tool' = $5 \
                             AND e.properties->$4->>'run_tag' = $6, false) \
               FROM edges e \
              WHERE e.source_id = $1 AND e.source_type = 'claim' \
                AND e.target_id = $2 AND e.target_type = 'claim' \
                AND e.relationship = $3 AND e.valid_to IS NULL AND e.properties ? $4 \
                /* {EDGE_VISIBILITY:e} */ \
              ORDER BY e.created_at DESC, e.id DESC LIMIT 1 FOR UPDATE",
            7,
        );
        let mut q = sqlx::query_as::<_, (Uuid, bool)>(&sql)
            .bind(dup_uuid)
            .bind(canonical)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY)
            .bind(LEGACY_FUZZY_DEDUP_TOOL)
            .bind(LEGACY_IDENTITY_BACKFILL_RUN_TAG);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let identity_edge = q.fetch_optional(&mut *tx).await?;
        // No identity edge is refused FIRST, with its reason (a legacy mark
        // says whether the backfill can still write it, operator ruling R-7),
        // before anything about the canonical: the missing edge is what blocks
        // this un-mark whatever became of the canonical since.
        let Some((identity_edge, legacy_backfill)) = identity_edge else {
            return Err(not_marked(
                &no_identity_edge_refusal(&mut tx, viewer, dup_uuid).await?,
            ));
        };
        // A canonical superseded or consolidated since is followed to its
        // current replacement (operator ruling R-11); one that was itself
        // marked a duplicate is refused (un-mark it first).
        let chain = match (
            canonical_chain(&mut tx, viewer, canonical, ChainLock::ForShare).await?,
            authorized_chain,
        ) {
            (Ok(chain), None) => chain,
            (Err(why), None) => return Err(not_marked(&why)),
            (Ok(chain), Some(authorized)) if chain.as_slice() == authorized => chain,
            // Said without the claims this read found: under the maintenance
            // viewer they may include a replacement the caller cannot read.
            (_, Some(_)) => {
                return Err(not_marked(
                    "has a canonical that was replaced again since the caller's authority was \
                     checked (the chain the un-mark would follow is no longer the one checked); \
                     retry the un-mark",
                ))
            }
        };
        // Both writes carry the write predicate: on an application session the
        // viewer's writable groups, on the maintenance session (a bypass
        // viewer) nothing, as row security decides there too.
        let claim_sql = viewer.splice_write(
            "UPDATE claims AS c SET supersedes = NULL, is_current = true, updated_at = NOW() \
              WHERE c.id = $1 /* {WRITABLE:c} */",
            2,
        );
        let mut q = sqlx::query(&claim_sql).bind(dup_uuid);
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let restored = q.execute(&mut *tx).await?.rows_affected();
        let edge_sql = viewer.splice_write(
            "UPDATE edges AS e SET valid_to = now() WHERE e.id = $1 /* {WRITABLE:e} */",
            2,
        );
        let mut q = sqlx::query(&edge_sql).bind(identity_edge);
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let retracted = q.execute(&mut *tx).await?.rows_affected();
        if restored != 1 || retracted != 1 {
            return Err(not_marked(
                "or its identity edge is not writable by this session",
            ));
        }
        tx.commit().await?;
        Ok(UnmarkedDuplicate {
            canonical,
            chain,
            identity_edge,
            legacy_backfill,
        })
    }

    /// What an un-mark of `dup`, marked a duplicate of `canonical`, restores
    /// it against, read through `viewer`, with the act's refusals in the
    /// act's order: `Err` with the reason when `dup` has no in-force dedup
    /// identity edge to `canonical` (a legacy `fuzzy_dedup_claims` mark says
    /// whether the backfill can still write it, operator ruling R-7), then
    /// the canonical chain's verdict: `Ok` with `canonical`, then each claim
    /// that replaced it in turn (supersession or consolidation), ending with
    /// the current one (`[canonical]` when it is current), or `Err` with the
    /// reason there is none (a claim of the chain was itself marked a
    /// duplicate, was deprecated, or has two replacements; operator ruling
    /// R-11). The request paths resolve it before the act, to check the
    /// caller's authority over every claim the reversal acts on, so they
    /// refuse with the act's own reason.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on a failed query.
    pub async fn unmark_chain_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        dup: Uuid,
        canonical: Uuid,
    ) -> Result<Result<Vec<Uuid>, String>, DbError> {
        let sql = viewer.splice(
            "SELECT e.id FROM edges e \
              WHERE e.source_id = $1 AND e.source_type = 'claim' \
                AND e.target_id = $2 AND e.target_type = 'claim' \
                AND e.relationship = $3 AND e.valid_to IS NULL AND e.properties ? $4 \
                /* {EDGE_VISIBILITY:e} */ \
              LIMIT 1",
            5,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(dup)
            .bind(canonical)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        if q.fetch_optional(&mut *conn).await?.is_none() {
            return Ok(Err(no_identity_edge_refusal(conn, viewer, dup).await?));
        }
        canonical_chain(conn, viewer, canonical, ChainLock::None).await
    }

    /// Whether THIS session may un-mark `dup` from `canonical`: a privileged
    /// writer may; otherwise it writes the duplicate, and it writes the
    /// canonical or the canonical is public (the dedup act's FA04 attach rule,
    /// mirrored: the reversal moves rows off the canonical with administrative
    /// authority). The same predicates the act's own row security and FA04
    /// check apply.
    ///
    /// The request paths ask this on the caller's stamped transaction instead
    /// of rehearsing [`Self::unmark_duplicate_act_conn`] there: once operator
    /// binding is armed, migration 153 refuses any application session that
    /// clears a `supersedes`, whatever its authority, and the act that commits
    /// runs on the maintenance connection anyway.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on a failed query.
    pub async fn session_may_unmark_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<bool, DbError> {
        let dup_uuid: Uuid = dup.into();
        let canon_uuid: Uuid = canonical.into();
        Ok(sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
            SELECT public.epigraph_session_is_privileged_writer()
                OR (public.epigraph_session_writes_node($1, 'claim')
                    AND (public.epigraph_session_writes_node($2, 'claim')
                         OR EXISTS (SELECT 1 FROM claims k
                                     WHERE k.id = $2 AND k.visibility::text = 'public')))"#,
        )
        .bind(dup_uuid)
        .bind(canon_uuid)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// Whether THIS session's [`Self::mark_duplicate_act_attributed_conn`]
    /// would pass the act's authority checks for `dup` onto `canonical`: the
    /// same predicate as [`Self::session_may_unmark_conn`] (row security on
    /// the duplicate, and FA04's attach rule for the canonical). A prediction
    /// that writes nothing, for a planner showing which marks will apply;
    /// FA07 and a concurrent change are left to the act.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on a failed query.
    pub async fn session_may_mark_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<bool, DbError> {
        Self::session_may_unmark_conn(conn, dup, canonical).await
    }

    /// Put back what a dedup repair did, from its [`DedupRevert`] record, along
    /// `canonical_chain` (the recorded canonical first, the current one last:
    /// [`UnmarkedDuplicate::chain`]; a supersession or merge since the mark
    /// carried some of the repaired rows on to a replacement and left others):
    /// re-source and re-target its edges onto `dup`, return its moved BBAs
    /// with their old tenancy, re-insert the BBAs it deleted, put its
    /// retracted edges back in force, and remove the frame bindings it added
    /// to the canonical. Returns what the belief cascade must re-derive.
    ///
    /// Each step acts only on rows still where the repair left them (an edge
    /// still pointing at the canonical, a BBA still on it); a row a later
    /// write has changed is left alone and reported in
    /// [`DedupReversal::drifted`].
    ///
    /// Runs on a PRIVILEGED session (it re-points other writers' edges and
    /// moves their BBAs), as the repair does.
    ///
    /// # Errors
    /// `DbError::InvalidData` on a non-privileged session; `DbError::QueryFailed`
    /// on a failed statement (nothing is changed).
    pub async fn reverse_marked_duplicate_conn(
        conn: &mut sqlx::PgConnection,
        dup: ClaimId,
        canonical_chain: &[Uuid],
        record: &DedupRevert,
    ) -> Result<DedupReversal, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "reverse_marked_duplicate_conn (it re-points other writers' edges)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let out = reverse_marked_duplicate(&mut tx, dup.into(), canonical_chain, record).await?;
        tx.commit().await?;
        Ok(out)
    }

    /// The un-mark's act and its reversal in ONE transaction on a privileged
    /// connection (the shape the semantic sweep and the tests use; a request
    /// path runs the act on the caller's stamped transaction instead).
    ///
    /// # Errors
    /// As [`Self::unmark_duplicate_act_conn`] and
    /// [`Self::reverse_marked_duplicate_conn`].
    pub async fn unmark_duplicate_with_reversal_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        dup: ClaimId,
        record: &DedupRevert,
    ) -> Result<(UnmarkedDuplicate, DedupReversal), DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "unmark_duplicate_with_reversal_conn (its reversal re-points other writers' edges)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let unmarked = Self::unmark_duplicate_act_conn(&mut tx, viewer, dup).await?;
        if record.identity_edge != Some(unmarked.identity_edge) {
            return Err(DbError::InvalidData {
                reason: format!(
                    "the revert record names identity edge {:?}, but the duplicate's in-force \
                     identity edge is {}; refusing to reverse another mark's repair",
                    record.identity_edge, unmarked.identity_edge
                ),
            });
        }
        let reversal =
            reverse_marked_duplicate(&mut tx, dup.into(), &unmarked.chain, record).await?;
        tx.commit().await?;
        Ok((unmarked, reversal))
    }

    /// Apply a patch atomically on the supplied connection. Returns a diff so
    /// callers can build provenance or HTTP responses. No provenance writing here.
    ///
    /// # Why this takes a connection, not a `Transaction`
    ///
    /// It used to take `&mut sqlx::Transaction`. That shape made it unreachable
    /// from a STAMPED transaction: `ScopedPool::begin_as` yields a `ScopedTx`,
    /// which derefs to `PgConnection` and is not a `sqlx::Transaction`. So the MCP
    /// `patch_claim` tool could only reach it through an unstamped
    /// `server.pool.begin()`, and on a cleanly-migrated schema `claims_tenancy`'s
    /// `WITH CHECK` refused the UPDATE. That session's writable set is `{}`.
    ///
    /// The function stays atomic on its own. The body opens `conn.begin()`, which
    /// is a real transaction on a bare connection and a SAVEPOINT inside a caller's
    /// transaction. The FOR UPDATE read and the (at most two) UPDATEs therefore land
    /// together in both shapes. A `&mut Transaction` caller still compiles
    /// unchanged through deref coercion.
    pub async fn patch_claim_atomic_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
        patch: &PatchClaimInput,
    ) -> Result<PatchClaimDiff, DbError> {
        use sqlx::Acquire as _;
        use sqlx::Row as _;
        let mut tx = conn.begin().await?;
        let id_uuid: Uuid = id.into();
        let row = sqlx::query(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
             SELECT trace_id, COALESCE(labels, ARRAY[]::text[]) AS labels,
                    COALESCE(properties, '{}'::jsonb) AS properties
             FROM claims WHERE id = $1 FOR UPDATE"#,
        )
        .bind(id_uuid).fetch_optional(&mut *tx).await?
        .ok_or(DbError::NotFound { entity: "Claim".into(), id: id_uuid })?;
        let before_labels: Vec<String> = row.get("labels");
        let before_props: serde_json::Value = row.get("properties");
        let before_trace: Option<Uuid> = row.get("trace_id");

        // trace_id and properties land in ONE statement, issued only when the
        // patch sets either. `PatchClaimInput::trace_id` is `Option<Uuid>` and
        // `None` means "leave it", never "clear it", so `COALESCE($2, trace_id)`
        // is exactly the old `if let Some(t)` write; the CASE keeps the column
        // untouched when no properties were supplied and otherwise applies the
        // same shallow `||` merge as before.
        let after_trace = patch.trace_id.or(before_trace);
        let mut after_props = before_props.clone();
        if patch.trace_id.is_some() || patch.properties.is_some() {
            sqlx::query(
                "UPDATE claims SET trace_id = COALESCE($2::uuid, trace_id), \
                 properties = CASE WHEN $3::jsonb IS NULL THEN properties \
                                   ELSE COALESCE(properties, '{}'::jsonb) || $3::jsonb END \
                 WHERE id = $1",
            )
            .bind(id_uuid)
            .bind(patch.trace_id)
            .bind(patch.properties.as_ref())
            .execute(&mut *tx)
            .await?;
        }
        if let Some(p) = &patch.properties {
            if let (Some(merged), Some(po)) = (after_props.as_object_mut(), p.as_object()) {
                for (k, v) in po {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }

        let mut after_labels = before_labels.clone();
        if !patch.add_labels.is_empty() || !patch.remove_labels.is_empty() {
            after_labels =
                Self::update_labels_conn(&mut tx, id_uuid, &patch.add_labels, &patch.remove_labels)
                    .await?;
        }

        tx.commit().await?;

        Ok(PatchClaimDiff {
            before_labels,
            after_labels,
            before_props,
            after_props,
            before_trace,
            after_trace,
        })
    }
}

// ── Graph-expanded recall (Task 6.1 / claim 29e789fd) ──

/// Epistemic relationship types followed by [`ClaimRepository::graph_expand_seeds`].
///
/// Matches the traversal set named in claim 29e789fd's design sketch
/// (supports/corroborates/elaborates) — the "argument-chain" subset of
/// `link_epistemic`'s full `EPISTEMIC_RELATIONSHIPS` allowlist. `contradicts`/
/// `refutes`/`generalizes`/`specializes` are intentionally excluded: expansion
/// is meant to pull in claims that reinforce a seed's argument, not claims
/// that merely relate to it in some other epistemic sense.
pub const EXPANSION_RELATIONSHIPS: &[&str] = &["supports", "corroborates", "elaborates"];

/// One claim reached by [`ClaimRepository::graph_expand_seeds`], with the hop
/// count at which it was first discovered (BFS order, so this is the shortest
/// path length from any seed).
#[derive(Debug, Clone, Copy, sqlx::FromRow)]
pub struct GraphExpansionHit {
    pub claim_id: Uuid,
    pub hops: i32,
}

impl ClaimRepository {
    /// Hard cap on the number of distinct claims [`Self::graph_expand_seeds`]
    /// will discover, mirroring the `traverse` MCP tool's `node_limit`
    /// (`.clamp(1, 100)`, default 50). Depth-clamping alone does NOT bound
    /// the work: supports/corroborates/elaborates fan-out over up to 4 hops
    /// on a dense graph can reach thousands of claims, each costing one
    /// sequential `EdgeRepository::get_by_source` round-trip inside a
    /// synchronous `recall_with_context` call. The caller's final
    /// `raw_hits.truncate(want)` bounds the OUTPUT size, not the work done
    /// to produce it — this cap bounds the work itself.
    const MAX_EXPANSION_NODES: usize = 200;

    /// Hard cap on the number of distinct claims [`Self::graph_expand_seeds`]
    /// will *visit* when a `since` window is in force — as opposed to
    /// [`Self::MAX_EXPANSION_NODES`], which caps how many it *emits*.
    ///
    /// Two budgets are needed because out-of-window claims are legitimate
    /// BRIDGES: with one shared budget, 200 pre-window neighbours exhaust the
    /// cap before the walk ever reaches the in-window claim behind them, and
    /// the call returns `[]`. Unwindowed, emitted == visited, so
    /// `MAX_EXPANSION_NODES` binds first and behaviour is bit-identical to
    /// before this budget existed. Windowed, the walk may cost up to
    /// `MAX_EXPANSION_VISITS` sequential `get_by_source` round-trips — 5× the
    /// old worst case, paid only on the path where the old bound produced
    /// wrong answers rather than slow ones.
    const MAX_EXPANSION_VISITS: usize = 1_000;

    /// Bounded multi-hop BFS from a set of seed claims, following outgoing
    /// edges whose relationship is in [`EXPANSION_RELATIONSHIPS`].
    ///
    /// Mirrors what the `traverse` MCP tool does internally (BFS over
    /// `EdgeRepository::get_by_source`, filtering relationship in Rust) rather
    /// than round-tripping through the MCP tool layer — `traverse` only
    /// supports a single relationship string and returns a serialized
    /// `CallToolResult`, neither of which fit a per-seed multi-relationship
    /// expansion called from inside `recall_with_context`.
    ///
    /// Seed IDs themselves are never included in the result (callers already
    /// have them as ANN hits); a claim reachable from more than one seed, or
    /// at more than one hop count, is returned once at its shortest hop
    /// count. `max_depth` is clamped to `[1, 4]` to match `traverse`'s depth
    /// bound; the number of DISTINCT claims EMITTED is separately capped at
    /// [`Self::MAX_EXPANSION_NODES`] (mirroring `traverse`'s `node_limit`) so
    /// a dense graph can't turn one `recall_with_context` call into an
    /// unbounded sequential BFS. When the cap is hit mid-frontier the BFS
    /// stops immediately — same tradeoff `traverse` makes.
    ///
    /// Retained at its original three-argument arity as a delegating wrapper
    /// over [`Self::graph_expand_seeds_since`]; `None` = no window = today's
    /// behaviour, so out-of-workspace callers keep the call they have.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any underlying edge query fails.
    #[instrument(skip(pool, seed_ids))]
    pub async fn graph_expand_seeds(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        seed_ids: &[Uuid],
        max_depth: u32,
    ) -> Result<Vec<GraphExpansionHit>, DbError> {
        Self::graph_expand_seeds_since(pool, viewer, seed_ids, max_depth, None).await
    }

    /// [`Self::graph_expand_seeds`] plus an optional `created_at >= since`
    /// window on the EMITTED destinations.
    ///
    /// The reached claims are folded into `recall_with_context`'s top-level
    /// `results`, so they must satisfy the caller's window like any other
    /// hit. Two things follow, and they pull in opposite directions:
    ///
    /// 1. **The walk is not pruned.** A claim created in 2024 is a perfectly
    ///    legitimate BRIDGE to a claim created yesterday; stopping at it would
    ///    sever reachability the unwindowed call would have found. So the BFS
    ///    traverses through out-of-window nodes and filters only what it
    ///    emits.
    /// 2. **Out-of-window nodes therefore must not consume the emission
    ///    budget.** Membership is resolved per BFS level, in one batched
    ///    set-membership query, and only in-window destinations count toward
    ///    [`Self::MAX_EXPANSION_NODES`]; the walk itself is bounded separately
    ///    by [`Self::MAX_EXPANSION_VISITS`]. A single shared budget would let
    ///    200 pre-window neighbours exhaust it before the walk reached the one
    ///    in-window claim behind them, and the caller would read the resulting
    ///    `[]` as "nothing changed since T" — the same silent inversion that
    ///    post-filtering a saturated candidate pool produces on the ANN legs.
    ///
    /// Truncation is still possible (a windowed walk can exceed
    /// `MAX_EXPANSION_VISITS` before filling the emission budget), so an empty
    /// return is "nothing in-window within the traversed neighbourhood", not a
    /// proof that nothing in-window is reachable. What it is no longer is an
    /// artefact of out-of-window rows crowding the budget.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any underlying edge query fails.
    #[instrument(skip(pool, viewer, seed_ids))]
    pub async fn graph_expand_seeds_since(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        seed_ids: &[Uuid],
        max_depth: u32,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<GraphExpansionHit>, DbError> {
        let max_depth = max_depth.clamp(1, 4) as i32;
        let seeds: std::collections::HashSet<Uuid> = seed_ids.iter().copied().collect();

        // Unwindowed, every visited node is emitted, so the emission cap is
        // the only bound that can bind and the walk is byte-identical to the
        // pre-window implementation. Windowed, the larger visit budget buys
        // the walk room to get past an out-of-window neighbourhood.
        let visit_budget = if since.is_some() {
            Self::MAX_EXPANSION_VISITS
        } else {
            Self::MAX_EXPANSION_NODES
        };

        let mut visited: std::collections::HashSet<Uuid> = seeds.clone();
        let mut discovered_at: std::collections::HashMap<Uuid, i32> =
            std::collections::HashMap::new();
        let mut frontier: Vec<Uuid> = seed_ids.to_vec();
        let mut depth = 0;
        let mut stop = false;

        while depth < max_depth && !frontier.is_empty() && !stop {
            depth += 1;
            let mut next_frontier = Vec::new();
            let mut level_new: Vec<Uuid> = Vec::new();
            'level: for &node in &frontier {
                let outgoing =
                    crate::repos::edge::EdgeRepository::get_by_source(pool, viewer, node, "claim")
                        .await?;
                for e in outgoing {
                    if !EXPANSION_RELATIONSHIPS.contains(&e.relationship.as_str()) {
                        continue;
                    }
                    if visited.insert(e.target_id) {
                        level_new.push(e.target_id);
                        next_frontier.push(e.target_id);
                        if visited.len() - seeds.len() >= visit_budget {
                            stop = true;
                            break 'level;
                        }
                    }
                }
            }

            // One batched membership round-trip per level (≤ 4 total), not one
            // per node and not a Rust-side filter over an already-truncated
            // page. Iterating `level_new` rather than the SQL row order keeps
            // emission deterministic when the budget truncates mid-level.
            let admitted: Vec<Uuid> = match since {
                None => level_new,
                Some(_) if level_new.is_empty() => level_new,
                Some(since) => {
                    let win_sql = viewer.splice(
                        "SELECT id FROM claims WHERE id = ANY($1) AND created_at >= $2 \
                         /* {VISIBILITY:claims} */",
                        3,
                    );
                    let mut wq = sqlx::query_scalar::<_, Uuid>(&win_sql)
                        .bind(&level_new)
                        .bind(since);
                    if let Some(g) = viewer.group_bind() {
                        wq = wq.bind(g);
                    }
                    let in_window: std::collections::HashSet<Uuid> =
                        wq.fetch_all(pool).await?.into_iter().collect();
                    level_new
                        .into_iter()
                        .filter(|id| in_window.contains(id))
                        .collect()
                }
            };

            for id in admitted {
                discovered_at.entry(id).or_insert(depth);
                if discovered_at.len() >= Self::MAX_EXPANSION_NODES {
                    stop = true;
                    break;
                }
            }

            frontier = next_frontier;
        }

        Ok(discovered_at
            .into_iter()
            .map(|(claim_id, hops)| GraphExpansionHit { claim_id, hops })
            .collect())
    }

    /// In-degree of epistemic-relationship edges (the full `link_epistemic`
    /// allowlist: supports/corroborates/elaborates/generalizes/specializes/
    /// contradicts/refutes) targeting each of `claim_ids`, batched in one
    /// round-trip. Claims with no such incoming edges are simply absent from
    /// the returned map (degree 0) rather than present with a zero — callers
    /// should treat a missing key as 0.
    ///
    /// One `GROUP BY` query for the whole batch, not one query per claim: the
    /// N+1 shape would be the naive approach given `recall_with_context`
    /// calls this once per page over its (already small, ≤200) candidate
    /// pool, not once per claim.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer, claim_ids))]
    pub async fn in_epistemic_degree_batch<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, i64>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let relationships: Vec<String> = crate::repos::edge::EPISTEMIC_RELATIONSHIPS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rows = sqlx::query!(
            r#"
            SELECT target_id, COUNT(*) AS "degree!"
            FROM edges
            WHERE target_id = ANY($1)
              AND source_type = 'claim' AND target_type = 'claim'
              AND relationship = ANY($2)
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            GROUP BY target_id
            "#,
            claim_ids,
            &relationships[..],
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows.into_iter().map(|r| (r.target_id, r.degree)).collect())
    }

    /// Live-dispute signal for each of `claim_ids`, batched in one round-trip
    /// (backlog 34d3400d).
    ///
    /// Deliberately narrower than [`Self::in_epistemic_degree_batch`], which
    /// counts the whole `EPISTEMIC_RELATIONSHIPS` allowlist: only
    /// `contradicts`/`refutes` constitute dispute, and only from a contester
    /// that is still `is_current`. A superseded challenger is not live
    /// counter-evidence — without that filter a retracted contester would mark
    /// its target contested permanently.
    ///
    /// Claims with no live dispute are ABSENT from the returned map rather
    /// than present with a zero (same contract as
    /// [`Self::in_epistemic_degree_batch`]); callers treat a missing key as
    /// uncontested.
    ///
    /// `contesting_claim_ids` is capped at the three strongest contesters
    /// (by contesting `truth_value` DESC) so a heavily-disputed claim cannot
    /// bloat a recall page; `dispute_count` is the UNCAPPED total, so callers
    /// can tell "3 contesters" from "30".
    ///
    /// This is a post-fix batch query over ids already returned by retrieval —
    /// deliberately NOT a join inside the ANN/RRF SQL, which would put the
    /// HNSW plan at risk for a signal that does not affect ranking.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer, claim_ids))]
    pub async fn dispute_batch<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, ClaimDispute>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query!(
            r#"
            SELECT e.target_id,
                   COUNT(*) AS "dispute_count!",
                   (array_agg(e.source_id ORDER BY src.truth_value DESC, src.id))[1:3]
                       AS "contesting_claim_ids!"
            FROM edges e
            JOIN claims src ON src.id = e.source_id AND src.is_current
            WHERE e.target_id = ANY($1)
              AND e.source_type = 'claim' AND e.target_type = 'claim'
              AND e.relationship IN ('contradicts', 'refutes')
              AND ($2::bool OR e.visibility = 'public'
                   OR (e.owner_group_id = ANY($3::uuid[])
                       AND (e.co_owner_group_id IS NULL
                            OR e.co_owner_group_id = ANY($3::uuid[]))))
              AND ($2::bool OR src.visibility = 'public' OR src.owner_group_id = ANY($3::uuid[]))
            GROUP BY e.target_id
            "#,
            claim_ids,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.target_id,
                    ClaimDispute {
                        dispute_count: r.dispute_count,
                        contesting_claim_ids: r.contesting_claim_ids,
                    },
                )
            })
            .collect())
    }
}

/// Live-dispute signal for a single claim, as returned by
/// [`ClaimRepository::dispute_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDispute {
    /// Total number of `is_current` claims contesting this one via
    /// `contradicts`/`refutes`. Uncapped.
    pub dispute_count: i64,
    /// The three strongest contesters (by their own `truth_value` DESC).
    pub contesting_claim_ids: Vec<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_claim_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/claim_tests.rs
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_find_claims_needing_embeddings(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-embed-regen', 'system', ARRAY['test'])
             RETURNING id"
        ).fetch_one(&pool).await.unwrap();

        let content = format!("test-embed-regen-{}", Uuid::new_v4());
        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL)
             RETURNING id",
        )
        .bind(&content)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Host-provenance telemetry must be EXCLUDED: one via the `telemetry`
        // label, one via the `properties->>'event'` marker (covers rows whose
        // label back-fill / post-submit PATCH never landed). (backlog a4aaa487)
        let tele_labeled = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, labels)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL, ARRAY['telemetry','epiclaw'])
             RETURNING id",
        )
        .bind(format!(
            "Container epiclaw-x exited code 0 after 5ms {}",
            Uuid::new_v4()
        ))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let tele_event_prop = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, properties)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL, '{\"event\":\"task_executed\"}'::jsonb)
             RETURNING id",
        )
        .bind(format!("Task t-{} executed, status: completed", Uuid::new_v4()))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let missing = ClaimRepository::find_claims_needing_embeddings(
            &pool,
            &crate::visibility::Viewer::test_bypass(
                crate::visibility::SystemReason::EmbeddingBackfill,
            ),
            1000,
        )
        .await
        .unwrap();
        assert!(
            missing.iter().any(|(id, _)| *id == claim_id),
            "substantive claim must be returned"
        );
        assert!(
            !missing.iter().any(|(id, _)| *id == tele_labeled),
            "telemetry-labeled claim must be excluded"
        );
        assert!(
            !missing.iter().any(|(id, _)| *id == tele_event_prop),
            "event-property telemetry claim must be excluded"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn contents_by_ids_returns_current_only_and_skips_missing(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-contents-by-ids', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let current_text = format!("current-claim-{}", Uuid::new_v4());
        let current_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, true)
             RETURNING id",
        )
        .bind(&current_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // A superseded (is_current = false) row must NOT be returned — the
        // rerank pool must never score retired claim text.
        let stale_text = format!("stale-claim-{}", Uuid::new_v4());
        let stale_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, false)
             RETURNING id",
        )
        .bind(&stale_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let absent_id = Uuid::new_v4();
        let map = ClaimRepository::contents_by_ids(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            &[current_id, stale_id, absent_id],
        )
        .await
        .unwrap();

        assert_eq!(
            map.get(&current_id).map(String::as_str),
            Some(current_text.as_str()),
            "current claim content must be returned verbatim"
        );
        assert!(
            !map.contains_key(&stale_id),
            "non-current (superseded) claim must be absent from the map"
        );
        assert!(
            !map.contains_key(&absent_id),
            "id with no matching row must be absent from the map"
        );
        assert_eq!(
            map.len(),
            1,
            "only the single current claim should be present"
        );

        // Empty input short-circuits to an empty map without touching the DB.
        let empty = ClaimRepository::contents_by_ids(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            &[],
        )
        .await
        .unwrap();
        assert!(empty.is_empty());
    }

    /// The sibling that does NOT filter `is_current`, and the reason it exists.
    ///
    /// `routes/cross_source.rs::list_candidates` renders excerpts for a queue
    /// of `match_candidates` rows that outlive the claims they name — nothing
    /// prunes the queue when `supersede_claim` / `mark_duplicate` flips
    /// `is_current`. Calling `contents_by_ids` there returns `None` for every
    /// such pair, and `excerpt(None)` renders the literal
    /// `"(claim not found)"` for a claim that exists. This test is the
    /// discriminator between the two functions: swap the call under test to
    /// `contents_by_ids` and the `stale_id` assertion fails.
    #[sqlx::test(migrations = "../../migrations")]
    async fn contents_by_ids_any_version_returns_superseded_rows_too(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-any-version', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let current_text = format!("current-claim-{}", Uuid::new_v4());
        let current_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, true)
             RETURNING id",
        )
        .bind(&current_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let stale_text = format!("superseded-claim-{}", Uuid::new_v4());
        let stale_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, false)
             RETURNING id",
        )
        .bind(&stale_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let absent_id = Uuid::new_v4();
        let viewer = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]);
        let map = ClaimRepository::contents_by_ids_any_version(
            &pool,
            &viewer,
            &[current_id, stale_id, absent_id],
        )
        .await
        .unwrap();

        assert_eq!(
            map.get(&stale_id).map(String::as_str),
            Some(stale_text.as_str()),
            "a superseded claim's content MUST come back — this is the whole difference from `contents_by_ids`, and the reason `list_candidates` calls this one"
        );
        assert_eq!(
            map.get(&current_id).map(String::as_str),
            Some(current_text.as_str()),
            "current rows are unaffected"
        );
        assert!(
            !map.contains_key(&absent_id),
            "an id naming no row is still absent"
        );
        assert_eq!(map.len(), 2);

        // The visibility predicate is NOT relaxed alongside the version scope.
        // A stranger's viewer (empty group set) must still be refused a
        // group-private superseded row.
        // A REAL group, not the world group: `claims_group_needs_real_group`
        // (migration 062) refuses `visibility = 'group'` paired with the
        // all-zero world group id, which is exactly what makes an unbackfilled
        // row unable to masquerade as private.
        let group_id: Uuid = sqlx::query_scalar(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
             VALUES ('t', 'did:epigraph:test:' || gen_random_uuid()::text, ''::bytea,
                     'personal', $1)
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let private_text = format!("private-superseded-{}", Uuid::new_v4());
        let private_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current,
                                 visibility, owner_group_id)
             VALUES ($1, sha256($1::bytea), 0.5, $2, false, 'group', $3)
             RETURNING id",
        )
        .bind(&private_text)
        .bind(agent_id)
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let stranger_map =
            ClaimRepository::contents_by_ids_any_version(&pool, &viewer, &[private_id])
                .await
                .unwrap();
        assert!(
            stranger_map.is_empty(),
            "dropping the `is_current` filter must not drop the visibility predicate with it"
        );

        let member = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![group_id]);
        let member_map =
            ClaimRepository::contents_by_ids_any_version(&pool, &member, &[private_id])
                .await
                .unwrap();
        assert_eq!(
            member_map.get(&private_id).map(String::as_str),
            Some(private_text.as_str()),
            "a member of the owning group must still read it — otherwise the assertion above is satisfied by a function that returns nothing"
        );
    }

    /// `hidden_claim_ids` is the Rust half of `EventRepository::list`'s rule,
    /// used to filter the in-process event ring buffer in
    /// `epigraph-api`'s `list_events`. Its contract is narrower than "absent
    /// from the visible set": an id naming NO row must not be reported, or the
    /// caller would drop events for hard-deleted claims and agent ids.
    ///
    /// **This is the OWNER-SIDE calibration and is NOT the acceptance test for
    /// migration 086.** `#[sqlx::test]` hands out a pool connected as the
    /// owning superuser, for whom RLS does not apply and `FORCE` is irrelevant,
    /// so it returned exactly these answers before 086 and returns them after —
    /// it cannot distinguish a working probe from a collapsed one. Its value is
    /// the other direction: it proves the fixture can detect a hidden id at all.
    /// The discriminating test is
    /// `crates/epigraph-db/tests/rls_enforcement.rs::hidden_claim_ids_still_classifies_on_the_app_role_under_force`,
    /// which runs under `SET SESSION AUTHORIZATION epigraph_app`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn hidden_claim_ids_reports_existing_but_invisible_ids_only(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-hidden-ids', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // A REAL group, not the world group: `claims_group_needs_real_group`
        // (migration 062) refuses `visibility = 'group'` paired with the
        // all-zero world group id, which is exactly what makes an unbackfilled
        // row unable to masquerade as private.
        let group_id: Uuid = sqlx::query_scalar(
            "INSERT INTO groups (display_name, did_key, public_key, kind, created_by_agent_id)
             VALUES ('t', 'did:epigraph:test:' || gen_random_uuid()::text, ''::bytea,
                     'personal', $1)
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let public_text = format!("public-{}", Uuid::new_v4());
        let public_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id)
             VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        )
        .bind(&public_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let private_text = format!("private-{}", Uuid::new_v4());
        let private_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id,
                                 visibility, owner_group_id)
             VALUES ($1, sha256($1::bytea), 0.5, $2, 'group', $3) RETURNING id",
        )
        .bind(&private_text)
        .bind(agent_id)
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let absent_id = Uuid::new_v4();
        let stranger = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]);
        let hidden = ClaimRepository::hidden_claim_ids(
            &pool,
            &stranger,
            &[public_id, private_id, absent_id],
        )
        .await
        .unwrap();

        assert!(
            hidden.contains(&private_id),
            "an existing row the viewer cannot read IS hidden"
        );
        assert!(!hidden.contains(&public_id), "a public row is not hidden");
        assert!(
            !hidden.contains(&absent_id),
            "an id naming no row has no owner to protect and must NOT be reported — reporting it would make the caller drop every event carrying an agent_id or a hard-deleted claim id"
        );
        assert_eq!(hidden.len(), 1);

        let member = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![group_id]);
        let for_member =
            ClaimRepository::hidden_claim_ids(&pool, &member, &[public_id, private_id])
                .await
                .unwrap();
        assert!(
            for_member.is_empty(),
            "nothing is hidden from a member of the owning group — without this, a function that reports EVERY id passes the assertions above"
        );
    }

    /// `get_by_id_conn` must report retirement state, not `claim_from_row`'s
    /// defaults.
    ///
    /// PR-23 makes the `*_conn` sibling the shape a conversion shard writes
    /// when it moves a handler onto `AppState::read_as`, and this one used to
    /// project seven columns where its pool-taking twin projects nine — so a
    /// superseded claim came back reporting `is_current = true, supersedes =
    /// None`. No gate could catch it: the dropped fields default to *plausible*
    /// values instead of erroring, so the only failure is a widened answer.
    ///
    /// Asserted against `get_by_id` on the same row rather than against
    /// literals, so the two cannot drift apart again for either value of the
    /// field. The CALIBRATION half is the retired row: without it, two
    /// functions that both returned the defaults would agree and pass.
    #[sqlx::test(migrations = "../../migrations")]
    async fn get_by_id_conn_reports_the_same_retirement_state_as_get_by_id(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'conn-parity', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let live_text = format!("live-{}", Uuid::new_v4());
        let live_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id)
             VALUES ($1, sha256($1::bytea), 0.5, $2) RETURNING id",
        )
        .bind(&live_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // The retired row: is_current = false AND supersedes set, so both
        // dropped columns carry a value that differs from the default.
        let retired_text = format!("retired-{}", Uuid::new_v4());
        let retired_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id,
                                 is_current, supersedes)
             VALUES ($1, sha256($1::bytea), 0.5, $2, false, $3) RETURNING id",
        )
        .bind(&retired_text)
        .bind(agent_id)
        .bind(live_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let viewer = crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]);
        let mut conn = pool.acquire().await.unwrap();

        for id in [live_id, retired_id] {
            let via_pool = ClaimRepository::get_by_id(&pool, &viewer, ClaimId::from_uuid(id))
                .await
                .unwrap()
                .expect("public claim is readable");
            let via_conn =
                ClaimRepository::get_by_id_conn(&mut conn, &viewer, ClaimId::from_uuid(id))
                    .await
                    .unwrap()
                    .expect("public claim is readable on a connection too");

            assert_eq!(
                via_conn.is_current, via_pool.is_current,
                "get_by_id_conn must report the same is_current as get_by_id for {id}; a \
                 *_conn sibling that drops the column reports every claim as live"
            );
            let conn_sup: Option<Uuid> = via_conn.supersedes.map(Into::into);
            let pool_sup: Option<Uuid> = via_pool.supersedes.map(Into::into);
            assert_eq!(
                conn_sup, pool_sup,
                "get_by_id_conn must report the same supersedes as get_by_id for {id}"
            );
        }

        // CALIBRATION: the retired row really does differ from the defaults, or
        // the parity above is satisfied by two functions returning the same
        // wrong answer.
        let retired =
            ClaimRepository::get_by_id_conn(&mut conn, &viewer, ClaimId::from_uuid(retired_id))
                .await
                .unwrap()
                .unwrap();
        assert!(
            !retired.is_current,
            "CALIBRATION: the retired fixture must not be current"
        );
        let retired_sup: Option<Uuid> = retired.supersedes.map(Into::into);
        assert_eq!(
            retired_sup,
            Some(live_id),
            "CALIBRATION: the retired fixture must name what it supersedes"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn set_properties_writes_jsonb_column(pool: sqlx::PgPool) {
        // Seed agent inline (no epigraph_test_support helper available),
        // following the existing pattern in this test module.
        let (agent_id, agent_pk): (Uuid, Vec<u8>) = sqlx::query_as(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'set-props-test', 'system', ARRAY['test'])
             RETURNING id, public_key",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&agent_pk);

        let claim = Claim::new(
            "Test claim for properties".to_string(),
            AgentId::from_uuid(agent_id),
            public_key,
            TruthValue::clamped(0.5),
        );
        let persisted =
            ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
                .await
                .unwrap();
        let props = serde_json::json!({"level": 3, "section": "Body", "source_type": "Wiki"});

        ClaimRepository::set_properties(&pool, persisted.id, props.clone())
            .await
            .unwrap();

        let row: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, props);
    }

    /// `merge_properties` shallow-merges a patch into `properties`, preserving
    /// untouched keys and OVERWRITING the patched key on a repeat call. This is
    /// what makes the workflow-promotion flag bidirectional: re-running the
    /// pass with promotable=false replaces a prior promotable=true rather than
    /// leaving a stale mark, while sibling keys (e.g. `level`) survive.
    #[sqlx::test(migrations = "../../migrations")]
    async fn merge_properties_preserves_siblings_and_overwrites_target(pool: sqlx::PgPool) {
        let (agent_id, agent_pk): (Uuid, Vec<u8>) = sqlx::query_as(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'merge-props-test', 'system', ARRAY['test'])
             RETURNING id, public_key",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&agent_pk);
        let claim = Claim::new(
            "Test claim for merge".to_string(),
            AgentId::from_uuid(agent_id),
            public_key,
            TruthValue::clamped(0.5),
        );
        let persisted =
            ClaimRepository::create(&pool, &claim, epigraph_core::TenancyDecl::Inherited)
                .await
                .unwrap();
        ClaimRepository::set_properties(&pool, persisted.id, serde_json::json!({"level": 2}))
            .await
            .unwrap();

        // Merge a promotion verdict — `level` must survive.
        ClaimRepository::merge_properties(
            &pool,
            persisted.id,
            &serde_json::json!({"promotion": {"promotable": true, "lower_bound": 0.72}}),
        )
        .await
        .unwrap();
        let row: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0["level"], 2, "sibling key preserved");
        assert_eq!(row.0["promotion"]["promotable"], true);

        // Re-merge with promotable=false (a demotion) — overwrites the promotion
        // sub-object, `level` still preserved.
        ClaimRepository::merge_properties(
            &pool,
            persisted.id,
            &serde_json::json!({"promotion": {"promotable": false}}),
        )
        .await
        .unwrap();
        let row2: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row2.0["level"], 2,
            "sibling key still preserved after re-merge"
        );
        assert_eq!(
            row2.0["promotion"]["promotable"], false,
            "promotion sub-object overwritten — bidirectional, no stale mark"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_pairwise_cosine_distance(pool: sqlx::PgPool) {
        // Find two claims that both have embeddings — a fresh test DB has none,
        // so we skip gracefully rather than fail.
        let pairs: Vec<(Uuid, Uuid, f64)> = sqlx::query_as(
            r"SELECT c1.id, c2.id, (c1.embedding <=> c2.embedding)::float8
              FROM claims c1, claims c2
              WHERE c1.embedding IS NOT NULL AND c2.embedding IS NOT NULL
                AND c1.id < c2.id
              LIMIT 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        if pairs.is_empty() {
            // No embeddings in fresh test DB; the function is exercised elsewhere.
            return;
        }

        let (id1, id2, expected_distance) = &pairs[0];
        let results = ClaimRepository::pairwise_cosine_distance(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            &[*id1, *id2],
            1.0,
        )
        .await
        .unwrap();

        assert!(!results.is_empty());
        let first = &results[0];
        assert!((first.distance - expected_distance).abs() < 1e-6);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_id_if_absent_is_idempotent(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-create-idempotent', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let id = uuid::Uuid::new_v4();
        let hash = blake3::hash(b"x");
        let was_new1 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent_id,
            TruthValue::clamped(0.5),
            &["test".to_string()],
            epigraph_core::TenancyDecl::Inherited,
        )
        .await
        .unwrap();
        let was_new2 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent_id,
            TruthValue::clamped(0.5),
            &["test".to_string()],
            epigraph_core::TenancyDecl::Inherited,
        )
        .await
        .unwrap();
        assert!(was_new1);
        assert!(!was_new2);
    }
}

// ── Label Mutation ──

impl ClaimRepository {
    /// Deprecate a single claim: drop its truth to the 0.05 sentinel, flip
    /// `is_current = false`, and NULL its `embedding` and `embedding_3072` in
    /// one statement.
    ///
    /// This is the canonical deprecation primitive for workflow claims. It is
    /// the THIRD `is_current = false` cleanup path (alongside `supersede` and
    /// `mark_duplicate`); per CLAUDE.md "Embedding policy → Cleanup paths",
    /// any path flipping `is_current = false` MUST null both embedding
    /// columns in the same statement so the row drops out of semantic recall
    /// and does not inflate the `stale_present` audit count.
    ///
    /// Returns the number of rows affected (0 when `id` does not exist).
    /// Idempotent: re-running on an already-deprecated claim is a no-op flip
    /// plus a no-op NULL — safe to call twice (used as the post-deploy
    /// remediation path for claims deprecated by the pre-fix binary).
    ///
    /// Uses the runtime `sqlx::query` (string) form — NOT the compile-time
    /// `query!` macro — to match the existing deprecation call-sites and to
    /// avoid touching `.sqlx/` (no `cargo sqlx prepare` required).
    ///
    /// # Errors
    /// Returns `DbError` if the database query fails.
    /// # The executor is generic, and that is what makes this table writable
    ///
    /// This is an `UPDATE claims`, so migration 077's `claims_tenancy`
    /// `WITH CHECK (owner_group_id = ANY(epigraph_writable_groups()))` governs
    /// it, and an unstamped application session's writable set is `{}` — the
    /// UPDATE is refused with `42501`. Only a `ScopedPool::begin_as` connection
    /// can satisfy it, and that is a transaction rather than a pool. `&PgPool`
    /// and `&mut PgConnection` both satisfy [`sqlx::PgExecutor`], so existing
    /// pool-taking callers compile unchanged.
    pub async fn deprecate_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: ClaimId,
    ) -> Result<u64, DbError> {
        let uuid: Uuid = id.into();
        let result = sqlx::query(
            "UPDATE claims \
             SET truth_value = 0.05, is_current = false, embedding = NULL, \
                 embedding_3072 = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(uuid)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// [`Self::deprecate_claim`] (same `SET` list, so both ANN columns are
    /// nulled in the same statement, CLAUDE.md "Cleanup paths"), restricted to
    /// a row that is still current, so `rows_affected` means "this call retired
    /// it". `deprecate_workflow` reports only claims whose state changed
    /// (U017; backlog fe874d2a): a re-run must report nothing.
    ///
    /// # Errors
    /// Returns `DbError` if the statement fails, including a `42501` refusal
    /// by `claims_tenancy`'s `WITH CHECK` on a session that may not write it.
    pub async fn deprecate_claim_if_current<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: ClaimId,
    ) -> Result<u64, DbError> {
        let uuid: Uuid = id.into();
        let result = sqlx::query(
            "UPDATE claims \
             SET truth_value = 0.05, is_current = false, embedding = NULL, \
                 embedding_3072 = NULL, updated_at = NOW() \
             WHERE id = $1 AND is_current",
        )
        .bind(uuid)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// Update labels on a claim by adding and/or removing labels atomically.
    ///
    /// Uses PostgreSQL array functions. Idempotent: adding a duplicate is a no-op,
    /// removing a nonexistent label is a no-op. Returns the updated labels array.
    ///
    /// This is the chokepoint for caller-supplied labels: the HTTP
    /// `PATCH /api/v1/claims/:id/labels` handler and the MCP `submit_claim`,
    /// `update_labels` and `resolve_backlog_item` tools all route their label
    /// writes through here, so the `add`-side validation below covers every one.
    /// `remove` is deliberately NOT validated — it is the remediation path for
    /// labels already corrupted in the graph.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist, or
    /// `DbError::InvalidData` if an added label carries unexpanded shell syntax.
    #[instrument(skip(pool))]
    pub async fn update_labels(
        pool: &PgPool,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        crate::label_validation::reject_unexpanded_labels(add)?;

        let row: Option<(Vec<String>,)> = sqlx::query_as(
            r#"
            -- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
            WITH current AS (
                SELECT id, labels FROM claims WHERE id = $1
            ),
            updated AS (
                SELECT COALESCE(
                    array_agg(DISTINCT lbl ORDER BY lbl),
                    ARRAY[]::text[]
                ) AS new_labels
                FROM (
                    SELECT unnest(c.labels) AS lbl FROM current c
                    UNION
                    SELECT unnest($2::text[])
                ) all_labels
                WHERE lbl != ALL($3::text[])
            )
            UPDATE claims SET labels = (SELECT new_labels FROM updated)
            WHERE id = $1
            RETURNING labels
            "#,
        )
        .bind(claim_id)
        .bind(add)
        .bind(remove)
        .fetch_optional(pool)
        .await?;

        match row {
            Some((labels,)) => Ok(labels),
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id,
            }),
        }
    }

    /// Update labels using an existing connection (e.g. inside a transaction).
    ///
    /// Same `add`-only validation contract as [`Self::update_labels`]; this is
    /// the variant `patch_claim_atomic_conn` (HTTP `PATCH /api/v1/claims/:id`
    /// and MCP `patch_claim`) calls, so the rejection reaches those too.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist, or
    /// `DbError::InvalidData` if an added label carries unexpanded shell syntax.
    pub async fn update_labels_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        crate::label_validation::reject_unexpanded_labels(add)?;

        use sqlx::Row;
        let row: Option<sqlx::postgres::PgRow> = sqlx::query(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
               WITH current AS (
                   SELECT id, labels FROM claims WHERE id = $1
               ),
               updated AS (
                   SELECT COALESCE(
                       array_agg(DISTINCT lbl ORDER BY lbl),
                       ARRAY[]::text[]
                   ) AS new_labels
                   FROM (
                       SELECT unnest(c.labels) AS lbl FROM current c
                       UNION
                       SELECT unnest($2::text[])
                   ) all_labels
                   WHERE lbl != ALL($3::text[])
               )
               UPDATE claims SET labels = (SELECT new_labels FROM updated)
               WHERE id = $1
               RETURNING labels"#,
        )
        .bind(claim_id)
        .bind(add)
        .bind(remove)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => Ok(row.get::<Vec<String>, _>("labels")),
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id,
            }),
        }
    }

    /// The AUDITED admin path for a `claims:admin` write into a claim whose
    /// owning group the admin cannot write (batch H-b, D2; migration 111).
    ///
    /// Calls `public.epigraph_admin_patch_claim`, a SECURITY DEFINER owned by
    /// `epigraph_maintenance`, which in one step re-checks the token's client
    /// record (`oauth_clients`: active, `claims:admin` granted, bound to the
    /// session principal), applies the label add/remove, the shallow properties
    /// merge and the trace relink with exactly the semantics of
    /// [`Self::update_labels_conn`] and [`Self::patch_claim_atomic_conn`], and
    /// writes a `security_events` row (`claims.admin_write`) naming the admin,
    /// the token, the action, the target and the before/after state. The write
    /// and its audit row commit with the caller's transaction or not at all.
    ///
    /// The ADMIN is read from the session's `epigraph.principal_id`, so `conn`
    /// must be a transaction stamped from the admin's OWN viewer (never the
    /// claim author's). A NULL principal is refused.
    ///
    /// # Errors
    /// * `DbError::InvalidData` if an added label carries unexpanded shell
    ///   syntax (checked before the call, as the ordinary path checks it).
    /// * `DbError::QueryFailed` with SQLSTATE `42501` when the function refuses
    ///   the admin (`ADM01` no principal, `ADM02` no live `claims:admin` grant),
    ///   `P0002` when the claim does not exist (`ADM04`).
    #[allow(clippy::too_many_arguments)]
    pub async fn admin_patch_claim_conn(
        conn: &mut sqlx::PgConnection,
        token: AdminToken,
        claim_id: Uuid,
        action: AdminClaimAction,
        add_labels: &[String],
        remove_labels: &[String],
        properties: Option<&serde_json::Value>,
        trace_id: Option<Uuid>,
    ) -> Result<AdminClaimWrite, DbError> {
        crate::label_validation::reject_unexpanded_labels(add_labels)?;
        let out: serde_json::Value = sqlx::query_scalar(
            "SELECT public.epigraph_admin_patch_claim($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(token.client_id)
        .bind(token.jti)
        .bind(claim_id)
        .bind(action.as_str())
        .bind(add_labels)
        .bind(remove_labels)
        .bind(properties)
        .bind(trace_id)
        .fetch_one(&mut *conn)
        .await?;
        let labels = |key: &str| -> Vec<String> {
            out.get(key)
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let trace = |key: &str| -> Option<Uuid> {
            out.get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
        };
        Ok(AdminClaimWrite {
            labels: labels("labels"),
            properties: out.get("properties").cloned().unwrap_or_default(),
            trace_id: trace("trace_id"),
            before_labels: labels("before_labels"),
            before_properties: out.get("before_properties").cloned().unwrap_or_default(),
            before_trace_id: trace("before_trace_id"),
        })
    }

    /// The two facts a write gate decides on for one claim, read through
    /// `viewer`: its author (`claims.agent_id`) and its owning group
    /// (`claims.owner_group_id`).
    ///
    /// `None` when the claim does not exist OR the viewer cannot read it. The
    /// two are deliberately indistinguishable, so a caller that answers `None`
    /// with 404 leaks nothing about claims it cannot see.
    ///
    /// # Why the owning group is returned, not only the author
    ///
    /// Migration 077's `claims_tenancy` `WITH CHECK` admits an UPDATE only when
    /// `owner_group_id = ANY(epigraph_writable_groups())`, so a write path has
    /// to stamp its transaction from a viewer whose writable set holds THIS
    /// group. The author and the owning group are not interchangeable:
    /// `POST /api/v1/claims` owns a row by the authenticated principal's
    /// personal group while taking `agent_id` from the request body. A gate
    /// that chose its stamp from the author alone would refuse every such row.
    ///
    /// Read-only, and it mints nothing.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on a database failure.
    pub async fn write_target_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.agent_id, c.owner_group_id
            FROM claims c
            WHERE c.id = $1
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    /// Helper: create a test claim and return (pool, claim_id, agent_id) for cleanup.
    async fn setup_test_claim() -> (sqlx::PgPool, Uuid, Uuid) {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();

        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'label-test', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id)
             VALUES ('label test claim', sha256('label-test'::bytea), 0.5, $1)
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        (pool, claim_id, agent_id)
    }

    async fn cleanup(pool: &sqlx::PgPool, claim_id: Uuid, agent_id: Uuid) {
        let _ = sqlx::query("DELETE FROM claims WHERE id = $1")
            .bind(claim_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_add() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        let labels =
            ClaimRepository::update_labels(&pool, claim_id, &["foo".into(), "bar".into()], &[])
                .await
                .unwrap();
        assert!(labels.contains(&"foo".to_string()));
        assert!(labels.contains(&"bar".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["a".into(), "b".into(), "c".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &[], &["b".into()])
            .await
            .unwrap();
        assert!(labels.contains(&"a".to_string()));
        assert!(!labels.contains(&"b".to_string()));
        assert!(labels.contains(&"c".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_atomic_add_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["x".into(), "y".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &["z".into()], &["x".into()])
            .await
            .unwrap();
        assert!(!labels.contains(&"x".to_string()));
        assert!(labels.contains(&"y".to_string()));
        assert!(labels.contains(&"z".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_idempotent_add() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["dup".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &["dup".into()], &[])
            .await
            .unwrap();
        assert_eq!(labels.iter().filter(|l| l.as_str() == "dup").count(), 1);
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_idempotent_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        // Remove a label that was never added — should not error
        let labels = ClaimRepository::update_labels(&pool, claim_id, &[], &["nonexistent".into()])
            .await
            .unwrap();
        assert!(labels.is_empty() || !labels.contains(&"nonexistent".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    // ── list_by_labels tests ──

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_happy_path() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["backlog".into(), "pending".into()], &[])
            .await
            .unwrap();

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["backlog".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "should find claim by single label"
        );

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["backlog".into(), "pending".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "should find claim by ALL labels"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_no_match() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["backlog".into()], &[])
            .await
            .unwrap();

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["nonexistent-label".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            !results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "should not match unrelated label"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_min_truth_filter() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        // Default truth_value from setup is 0.5
        ClaimRepository::update_labels(&pool, claim_id, &["truth-test".into()], &[])
            .await
            .unwrap();

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["truth-test".into()],
                min_truth: 0.4,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "0.5 >= 0.4 should match"
        );

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["truth-test".into()],
                min_truth: 0.9,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            !results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "0.5 < 0.9 should not match"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_respects_limit() {
        let (pool, _, agent_id) = setup_test_claim().await;
        // Create a second claim with the same label
        let claim_id_2 = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, labels)
             VALUES ('limit test 2', sha256('limit-test-2'::bytea), 0.5, $1, ARRAY['limit-test'])
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id_1 = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, labels)
             VALUES ('limit test 1', sha256('limit-test-1'::bytea), 0.5, $1, ARRAY['limit-test'])
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let results = ClaimRepository::list_by_labels(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            crate::repos::claim::LabelQuery {
                labels: &["limit-test".into()],
                limit: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 1, "limit=1 should return exactly 1 result");

        // cleanup
        let _ = sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
            .bind([claim_id_1, claim_id_2])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE id = $1")
            .bind(agent_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_not_found() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let fake_id = Uuid::new_v4();
        let result = ClaimRepository::update_labels(&pool, fake_id, &["x".into()], &[]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::NotFound { entity, id } => {
                assert_eq!(entity, "Claim");
                assert_eq!(id, fake_id);
            }
            other => panic!("Expected NotFound, got: {other:?}"),
        }
    }

    // The two unexpanded-shell-variable regression tests that used to live here
    // moved to `crates/epigraph-db/tests/label_shell_variable_repo.rs`. Reason:
    // every test in this module is `#[ignore]` (live-DB convention), so
    // `cargo test -p epigraph-db` skipped the headline regression test for
    // backlog f6310444. The new file uses `#[sqlx::test]` and runs in the gate.

    /// Verify `pairwise_cosine_distance` enforces the `MAX_PAIRWISE_IDS` cap.
    /// No DB required: the size guard fires before the query is issued.
    #[tokio::test]
    async fn pairwise_cosine_distance_rejects_oversized_input() {
        use sqlx::postgres::PgPoolOptions;
        // We need a (dummy) pool even though the guard fires before any query.
        // Use a non-existent URL — `connect_lazy` does not dial at construction time.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://invalid-host/nodb")
            .unwrap();
        let too_many: Vec<Uuid> = (0..=ClaimRepository::MAX_PAIRWISE_IDS)
            .map(|_| Uuid::new_v4())
            .collect();
        let result = ClaimRepository::pairwise_cosine_distance(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            &too_many,
            0.5,
        )
        .await;
        assert!(
            result.is_err(),
            "should return Err when claim_ids exceeds MAX_PAIRWISE_IDS"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("MAX_PAIRWISE_IDS"),
            "error message should mention MAX_PAIRWISE_IDS; got: {err_msg}"
        );
    }
}

/// How a consolidation restates its sources. Recorded in
/// `properties.merge.mode`; the server does not interpret it — the caller
/// supplies the synthesized content either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsolidateMode {
    /// Combined restatement of all sources.
    Merge,
    /// Higher-level generalisation over the sources.
    Abstract,
    /// Refined restatement (typically N=2, near-identical inputs).
    Rewrite,
}

impl ConsolidateMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Abstract => "abstract",
            Self::Rewrite => "rewrite",
        }
    }

    /// Parse a wire-format mode string.
    ///
    /// # Errors
    /// Returns the offending string when it is not a known mode.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "merge" => Ok(Self::Merge),
            "abstract" => Ok(Self::Abstract),
            "rewrite" => Ok(Self::Rewrite),
            other => Err(other.to_string()),
        }
    }
}

/// Outcome of [`ClaimRepository::consolidate`].
#[derive(Debug, Clone)]
pub struct ConsolidateResult {
    pub merged_id: Uuid,
    pub superseded: Vec<Uuid>,
    pub edges_migrated: u64,
    pub edges_deduped: u64,
    /// `true` when an identical merged claim by this agent already existed and
    /// was returned instead of inserting a second one.
    pub already_existed: bool,
}

/// Minimum / maximum sources accepted by one consolidation.
pub const CONSOLIDATE_MIN_SOURCES: usize = 2;
pub const CONSOLIDATE_MAX_SOURCES: usize = 20;

impl ClaimRepository {
    /// Merge 2..=20 `is_current` claims into one new claim (backlog 44b19521).
    ///
    /// The CALLER supplies `merged_content`: synthesis is an agent-side
    /// concern, storage is the server's — the same division of labour as
    /// `epigraph-ingest-executor`.
    ///
    /// # Why the mark_duplicate convention, not supersede's
    ///
    /// `claims.supersedes` is a single UUID and an N→1 merge has N parents, so
    /// the supersede convention (new row points at the one row it replaced)
    /// cannot express this. Each retired source instead gets
    /// `supersedes = merged_id` as a forwarding pointer — the `mark_duplicate`
    /// convention — which additionally makes `mark_duplicate`'s existing
    /// "already superseded; refusing to overwrite" guard protect merged
    /// sources for free. The reverse fan-out is carried by N `supersedes`
    /// EDGES (merged → source) plus `properties.merge`.
    ///
    /// # Edge collision classes
    ///
    /// Unlike `mark_duplicate`'s canonical, the merged claim is brand new and
    /// therefore has no pre-existing edges — so the "diamond" class cannot
    /// arise here. What can, and is new to N→1, is the CROSS-SOURCE class:
    /// `T→[REL]→s1` and `T→[REL]→s2` both migrate onto `T→[REL]→merged`.
    ///
    /// That matters for two distinct reasons, confirmed by
    /// `docs/architecture/audit-edge-collision-mark-duplicate.md`:
    /// - `alternative_of` carries a symmetric partial unique index
    ///   (`edges_alternative_of_symmetric_uniq`, migration 042), so a collision
    ///   is a HARD error that rolls the whole merge back. Because the index is
    ///   keyed on `(LEAST, GREATEST)` it is direction-agnostic, so those edges
    ///   are deduped ignoring direction.
    /// - Every other relationship collides SILENTLY (migration 018 dropped the
    ///   triple-uniqueness constraint and nothing re-added it), producing
    ///   duplicate rows that feed the same Dempster-Shafer mass twice through
    ///   `auto_create_factor_from_edge`. Belief corruption, not an error.
    ///
    /// `AUTHORED` is excluded from deduplication (migration 017 explicitly
    /// allows it to accumulate) and `supersedes` from migration entirely.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` on a bad source set (wrong count,
    /// duplicates, non-current, already-superseded) and `DbError::NotFound`
    /// when a source id does not exist.
    #[instrument(skip(pool, merged_content), fields(n_sources = source_ids.len()))]
    pub async fn consolidate(
        pool: &PgPool,
        source_ids: &[Uuid],
        merged_content: &str,
        merged_truth: f64,
        mode: ConsolidateMode,
        reason: &str,
        acting_agent_id: Uuid,
    ) -> Result<ConsolidateResult, DbError> {
        let mut conn = pool.acquire().await?;
        Self::consolidate_conn(
            &mut conn,
            source_ids,
            merged_content,
            merged_truth,
            mode,
            reason,
            acting_agent_id,
        )
        .await
    }

    /// [`Self::consolidate`] on a connection the caller owns — the form a
    /// tenancy-stamped transaction can reach.
    ///
    /// The pool-taking wrapper above delegates here, so there is one
    /// implementation. `begin()` below issues a real `BEGIN` on a bare pooled
    /// connection — exactly what `pool.begin()` did — and a `SAVEPOINT` inside a
    /// caller's transaction, so the merge is one unit in both shapes.
    ///
    /// # Why a stamped caller needs this
    ///
    /// On an unstamped pool checkout, migration 077's `claims_tenancy` `WITH
    /// CHECK` has an empty writable set, so the merged-claim INSERT is refused
    /// for every caller on a cleanly-migrated schema — `consolidate_claims` was
    /// unavailable there. And the all-public branch's `personal_group_of` read
    /// was BLIND on that connection (`groups_tenancy` has no true arm), so it
    /// took the mint path on every merge: migration 077's reviving `ON
    /// CONFLICT` inside an unrelated write — hard constraint #3's hazard. Since
    /// batch F `personal_group_of` asks the definer function directly, which
    /// (migration 105) returns a live group without writing and refuses a
    /// revoked one, so the answer no longer depends on the stamp.
    ///
    /// # Migration 117: a PRIVILEGED session only
    ///
    /// The edge migration re-points and retracts edges whatever their owner (an
    /// edge into a source is its SOURCE's writer's assertion). Since 117 a
    /// non-privileged session's UPDATE of an edge it does not own matches no
    /// row, so on such a session this would merge and silently leave other
    /// writers' edges on the retired sources. It therefore refuses a
    /// non-privileged session outright. A request path runs
    /// [`Self::consolidate_act_conn`] on the caller's stamped transaction and
    /// [`Self::migrate_consolidated_edges_conn`] on the maintenance connection
    /// (`epigraph_engine::admin_cascade`).
    ///
    /// # Errors
    /// As [`Self::consolidate`], plus `DbError::InvalidData` on a
    /// non-privileged session.
    pub async fn consolidate_conn(
        conn: &mut sqlx::PgConnection,
        source_ids: &[Uuid],
        merged_content: &str,
        merged_truth: f64,
        mode: ConsolidateMode,
        reason: &str,
        acting_agent_id: Uuid,
    ) -> Result<ConsolidateResult, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "consolidate_conn (its edge migration re-points other writers' edges)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let mut result = Self::consolidate_act_conn(
            &mut tx,
            source_ids,
            merged_content,
            merged_truth,
            mode,
            reason,
            acting_agent_id,
        )
        .await?;
        if !result.already_existed {
            let m = migrate_consolidated_edges(&mut tx, result.merged_id, source_ids).await?;
            result.edges_migrated = m.migrated.len() as u64;
            result.edges_deduped = m.retracted.len() as u64;
        }
        tx.commit().await?;
        Ok(result)
    }

    /// The consolidation's own act, and nothing else: validate and lock the
    /// sources, insert the merged claim, retire every source (`supersedes =
    /// merged`) and insert the `supersedes` edges merged → source.
    ///
    /// Every row it writes is one the consolidating caller authors or must be
    /// able to write (the merged claim, its own sources, the edges between
    /// them), so it runs on the CALLER's stamped transaction and the database
    /// decides write authority. It does NOT migrate the sources' other edges:
    /// those belong to whoever asserted them, and moving them is the
    /// administrative cascade's job
    /// ([`Self::migrate_consolidated_edges_conn`], migration 117). The
    /// returned counts of migrated and deduped edges are therefore zero.
    ///
    /// # Errors
    /// As [`Self::consolidate`].
    #[allow(clippy::too_many_lines)]
    pub async fn consolidate_act_conn(
        conn: &mut sqlx::PgConnection,
        source_ids: &[Uuid],
        merged_content: &str,
        merged_truth: f64,
        mode: ConsolidateMode,
        reason: &str,
        acting_agent_id: Uuid,
    ) -> Result<ConsolidateResult, DbError> {
        use sqlx::Acquire;
        let protocol = |m: String| DbError::QueryFailed {
            source: sqlx::Error::Protocol(m),
        };

        if source_ids.len() < CONSOLIDATE_MIN_SOURCES || source_ids.len() > CONSOLIDATE_MAX_SOURCES
        {
            return Err(protocol(format!(
                "consolidate: need {CONSOLIDATE_MIN_SOURCES}..={CONSOLIDATE_MAX_SOURCES} sources, got {}",
                source_ids.len()
            )));
        }
        let unique: std::collections::HashSet<Uuid> = source_ids.iter().copied().collect();
        if unique.len() != source_ids.len() {
            return Err(protocol("consolidate: duplicate source ids".into()));
        }
        if merged_content.trim().is_empty() {
            return Err(protocol("consolidate: merged_content is empty".into()));
        }

        let mut tx = conn.begin().await?;

        let content_hash = epigraph_crypto::ContentHasher::hash(merged_content.as_bytes()).to_vec();

        // Serialize every find-then-insert of the merged claim's
        // `(content_hash, acting agent)` — another consolidation into the same
        // content, `create_or_get`, POST /claims, the legacy creates — before
        // the "already exists" probe below (backlog 00f1a517). Without it two
        // concurrent merges into identical content both miss the probe and
        // both insert. Taken FIRST, before the sources' row locks: a merge
        // then never holds a source row lock while it waits on the pair, which
        // is the order every other holder of this lock uses (pair lock, then
        // its own row writes).
        Self::lock_content_hash_agent(&mut tx, content_hash.as_slice(), acting_agent_id).await?;

        // Lock every source up front so a concurrent merge/supersede cannot
        // interleave between validation and retirement.
        let locked = sqlx::query!(
            r#"
            -- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
            SELECT id, is_current, supersedes, labels, visibility, owner_group_id
            FROM claims WHERE id = ANY($1) FOR UPDATE
            "#,
            source_ids,
        )
        .fetch_all(&mut *tx)
        .await?;

        if locked.len() != source_ids.len() {
            let found: std::collections::HashSet<Uuid> = locked.iter().map(|r| r.id).collect();
            let missing = source_ids.iter().find(|id| !found.contains(id));
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: missing.copied().unwrap_or_default(),
            });
        }
        for r in &locked {
            if !r.is_current {
                return Err(protocol(format!(
                    "consolidate: source {} is not current",
                    r.id
                )));
            }
            if r.supersedes.is_some() {
                return Err(protocol(format!(
                    "consolidate: source {} is already superseded; refusing to re-merge",
                    r.id
                )));
            }
        }

        // Labels union across sources (same carry rationale as supersede).
        // Properties are deliberately NOT carried — a blanket copy propagates
        // whatever bug the merge may be fixing.
        let mut labels: Vec<String> = locked
            .iter()
            .flat_map(|r| r.labels.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        labels.sort();

        let merge_props = serde_json::json!({
            "merge": {
                "mode": mode.as_str(),
                "merged_from": source_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "merged_at": chrono::Utc::now().to_rfc3339(),
                "reason": reason,
            }
        });
        // ── The merged row's tenancy (plan §4.6) ──
        //
        // `consolidate` binds NEITHER `supersedes` NOR `step_lineage_id` --
        // the sources are retired separately, AFTER this insert -- so none of
        // migration 074's inheritance arms can reach it. Left undeclared it
        // would raise 23502 for the app role. Left on the old default it was
        // worse than that: a WIDENING primitive, merging a private claim into a
        // world-owned public row.
        //
        // The rule itself is a pure function in epigraph-core so it can be
        // tested without a database (§8.1); this is the only place it is
        // applied. `owner_group_id` on a source is read under the FOR UPDATE
        // taken above, so it cannot change between the decision and the insert.
        let source_tenancy: Vec<epigraph_core::SourceTenancy> = locked
            .iter()
            .map(|r| {
                epigraph_core::Visibility::from_db_str(&r.visibility)
                    .map(|v| (r.owner_group_id, v))
                    .ok_or_else(|| DbError::InvalidData {
                        reason: format!(
                            "consolidate: source {} has visibility {:?}, which is outside \
                             the vocabulary",
                            r.id, r.visibility
                        ),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // THE REFUSAL IS DECIDED FIRST, and it costs nothing: `consolidate_owner`
        // is a pure function over the tenancies just read under FOR UPDATE. A
        // cross-group merge therefore refuses before this transaction has
        // written anything at all, and refuses identically whether or not a
        // retry has already inserted the row.
        //
        // `Ok(None)` means every source is public, and the owner is the acting
        // agent's own group -- resolved BELOW, after the idempotent-return
        // branch, because that resolution can WRITE.
        let merged_owner = epigraph_core::consolidate_owner(&source_tenancy).map_err(|e| {
            // The PAIR is logged, never rendered into the 409: see
            // `ConsolidateTenancyError`'s `Display` impl for why. An
            // operator reads the owners here; the caller reads only that
            // the sources span more than one group.
            // A `match` rather than `if let`: `ConsolidateTenancyError` has
            // one variant today, so `if let` is irrefutable and lints — and
            // a `match` is what forces this arm to be revisited if a second
            // refusal reason is ever added.
            match &e {
                epigraph_core::ConsolidateTenancyError::CrossGroup { groups: (a, b) } => {
                    tracing::warn!(
                        owner_a = %a,
                        owner_b = %b,
                        acting_agent_id = %acting_agent_id,
                        "consolidate refused: sources span two owner groups"
                    );
                }
            }
            DbError::Conflict {
                reason: e.to_string(),
            }
        })?;

        // ── The actor must be IN the group it is writing into (PR-16) ──
        //
        // `consolidate` takes no `Viewer`. Before migration 074 that was a
        // DISCLOSURE hole and nothing more: a cross-tenant merge landed on the
        // world default, so it produced a public row. The meet rule above is
        // the right rule, but it changes the shape of the hole — the merged row
        // now lands INSIDE the owning group, so an unrelated caller could write
        // its own content into a foreign group's private corpus while retiring
        // that group's claims through the `supersedes` forwarding below. That
        // is an integrity and availability defect against a group the caller
        // has no relationship with.
        //
        // The full write-side gate (`viewer.writable_bind()`'s SQL half, the
        // fail-open scope sites, the MCP write tools) is 16b's territory and is
        // NOT delivered here. This is the narrow refusal that keeps 16a's own
        // tenancy rule from creating a primitive 16b would have to close: every
        // group-visible source's owner must be a live group of the acting
        // agent. It costs one query, and only on merges that actually touch a
        // private claim — an all-public merge (`merged_owner == None`) skips it
        // entirely.
        //
        // Membership, not write-role: role-granularity is `writable_bind`'s
        // job and arrives with 16b. Refusing a non-member is strictly stronger
        // than the nothing that stood here before.
        let private_owners: Vec<Uuid> = source_tenancy
            .iter()
            .filter(|(_, v)| *v == epigraph_core::Visibility::Group)
            .map(|(g, _)| *g)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if !private_owners.is_empty() {
            let member_of: Vec<Uuid> = sqlx::query_scalar(
                "SELECT group_id FROM group_memberships \
                  WHERE agent_id = $1 AND group_id = ANY($2) AND revoked_at IS NULL",
            )
            .bind(acting_agent_id)
            .bind(&private_owners)
            .fetch_all(&mut *tx)
            .await?;
            let member_of: std::collections::HashSet<Uuid> = member_of.into_iter().collect();
            if let Some(foreign) = private_owners.iter().find(|g| !member_of.contains(g)) {
                // Same disclosure discipline as the cross-group refusal: the
                // group id goes to the log, not to the caller.
                tracing::warn!(
                    owner_group_id = %foreign,
                    acting_agent_id = %acting_agent_id,
                    "consolidate refused: actor is not a live member of a source's owner group"
                );
                return Err(DbError::Conflict {
                    reason: "consolidate: at least one source is private to a group you are \
                             not a member of. Merging would write into that group's corpus \
                             and retire its claims."
                        .to_string(),
                });
            }
        }

        // An identical merged claim by this agent is returned rather than
        // inserted again (novelty-gate style), so a retried merge is idempotent
        // instead of minting a second row. Runs under the pair lock taken above,
        // so a concurrent merge's committed row is visible here.
        if let Some(existing) = sqlx::query!(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
             SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2"#,
            content_hash.as_slice(),
            acting_agent_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.rollback().await?;
            return Ok(ConsolidateResult {
                merged_id: existing.id,
                superseded: vec![],
                edges_migrated: 0,
                edges_deduped: 0,
                already_existed: true,
            });
        }

        // ── The actor's authoring default, for the all-public case ──
        //
        // AFTER the idempotent-return branch above, deliberately: that branch
        // ends in `tx.rollback()`, and resolving the group before it would make
        // a no-op retry perform a `groups` upsert and a `group_memberships`
        // upsert only to discard them.
        //
        // `default_decl_for_author`, not `personal_group_of`: an actor with an
        // ACTING operator link (migration 107) authors into its OPERATOR's
        // personal group, exactly as every other authoring path does, so a
        // merge by a model-bumped job does not split its work across groups
        // again (review finding: the merged claim landed in the agent's own
        // group while every source sat in the operator's). An unlinked,
        // revoked or retired actor falls through to `personal_group_of`, which
        // resolves through the definer function: it (migration 105) returns a
        // live group without writing and refuses a revoked membership rather
        // than reviving it as a side effect of a merge. See its doc.
        let decl = match merged_owner {
            Some(g) => TenancyDecl::group(g),
            None => Self::default_decl_for_author(&mut tx, acting_agent_id).await?,
        };

        let merged_id = sqlx::query_scalar!(
            r#"
            INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current,
                                labels, properties, visibility, owner_group_id)
            VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8)
            RETURNING id
            "#,
            merged_content,
            content_hash.as_slice(),
            merged_truth.clamp(0.0, 1.0),
            acting_agent_id,
            &labels[..],
            merge_props,
            decl.visibility_bind(),
            decl.owner_group_bind(),
        )
        .fetch_one(&mut *tx)
        .await?;

        // Retire sources. One statement: chk_deprecated_no_embedding (migration
        // 052) is a per-statement CHECK, so is_current=false and both
        // embedding=NULL / embedding_3072=NULL must land together.
        sqlx::query!(
            r#"
            UPDATE claims
            SET supersedes = $1, is_current = false, embedding = NULL, embedding_3072 = NULL, updated_at = NOW()
            WHERE id = ANY($2)
            "#,
            merged_id,
            source_ids,
        )
        .execute(&mut *tx)
        .await?;

        // Reverse fan-out: merged → each source, mirroring supersede()'s edge.
        for src in source_ids {
            sqlx::query!(
                r#"
                INSERT INTO edges (source_id, source_type, target_id, target_type,
                                   relationship, properties)
                VALUES ($1, 'claim', $2, 'claim', 'supersedes', $3)
                "#,
                merged_id,
                src,
                serde_json::json!({
                    "reason": reason,
                    "mode": mode.as_str(),
                    "merged_at": chrono::Utc::now().to_rfc3339(),
                }),
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(ConsolidateResult {
            merged_id,
            superseded: source_ids.to_vec(),
            edges_migrated: 0,
            edges_deduped: 0,
            already_existed: false,
        })
    }

    /// The consolidation's edge migration, as the administrative cascade runs it
    /// after the caller's [`Self::consolidate_act_conn`] committed (migration
    /// 117): re-point every live edge on a retired source onto the merged
    /// claim, and retract the redundant copies the merge creates.
    ///
    /// Re-verifies the committed act first (every source is retired with
    /// `supersedes = merged_id`), so it acts only on a merge that happened, and
    /// it is idempotent: it considers LIVE edges only (`valid_to IS NULL`), and
    /// a second run finds none left on the sources. That makes it the replay
    /// of a deferred cascade too. Runs in its own transaction (a SAVEPOINT when
    /// the connection is already in one).
    ///
    /// # Errors
    /// `DbError::InvalidData` on a non-privileged session, or when the claims
    /// do not record `merged_id` replacing every retired source;
    /// `DbError::QueryFailed` on any failed statement.
    pub async fn migrate_consolidated_edges_conn(
        conn: &mut sqlx::PgConnection,
        merged_id: Uuid,
        source_ids: &[Uuid],
    ) -> Result<ConsolidateEdgeMigration, DbError> {
        use sqlx::Acquire;
        require_privileged_session(
            &mut *conn,
            "migrate_consolidated_edges_conn (it re-points other writers' edges)",
        )
        .await?;
        let mut tx = conn.begin().await?;
        let merged: Vec<(Uuid, Option<Uuid>, bool)> = sqlx::query_as(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection; this read verifies the act the mutation follows.
            SELECT id, supersedes, COALESCE(is_current, true)
              FROM claims WHERE id = ANY($1) FOR UPDATE"#,
        )
        .bind(source_ids)
        .fetch_all(&mut *tx)
        .await?;
        let unique: std::collections::HashSet<Uuid> = source_ids.iter().copied().collect();
        let verified = !source_ids.is_empty()
            && unique.len() == source_ids.len()
            && merged.len() == source_ids.len()
            && merged
                .iter()
                .all(|(_, sup, current)| *sup == Some(merged_id) && !*current);
        if !verified {
            return Err(DbError::InvalidData {
                reason: format!(
                    "claim {merged_id} does not replace every retired source of this \
                     consolidation; refusing to migrate their edges"
                ),
            });
        }
        let migration = migrate_consolidated_edges(&mut tx, merged_id, source_ids).await?;
        tx.commit().await?;
        Ok(migration)
    }
}

/// What [`ClaimRepository::migrate_consolidated_edges_conn`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsolidateEdgeMigration {
    /// Live edges re-pointed from a retired source onto the merged claim.
    pub migrated: Vec<Uuid>,
    /// Live edges retracted: interior to the merge (both endpoints were
    /// sources) or a redundant later copy of a surviving edge.
    pub retracted: Vec<Uuid>,
}

/// The consolidation's edge migration, unchecked: the callers
/// ([`ClaimRepository::consolidate_conn`],
/// [`ClaimRepository::migrate_consolidated_edges_conn`]) establish the
/// privilege and the committed act first.
async fn migrate_consolidated_edges(
    tx: &mut sqlx::PgConnection,
    merged_id: Uuid,
    source_ids: &[Uuid],
) -> Result<ConsolidateEdgeMigration, DbError> {
    let unique: std::collections::HashSet<Uuid> = source_ids.iter().copied().collect();
    // Collect every LIVE non-supersedes edge touching a source, dropping those
    // interior to the merge (both endpoints inside the source set) — those
    // would collapse to merged→merged self-loops. A retracted edge stays where
    // it is: it is history, and leaving it makes a second run a no-op.
    //
    // A NON-PUBLIC source keeps its `executes` edges
    // (`NON_PUBLIC_FROZEN_RELATIONSHIPS`, OD-32): they name the steps of a
    // frozen workflow generation, so they are neither moved nor retracted as
    // a redundant copy. The test is on the source endpoint's own row (a
    // missing row counting as non-public), so the deferred replay gives the
    // same result.
    //
    // A dedup identity edge (`same_as` carrying `properties.dedup`) is not a
    // candidate either: it names the claim its duplicate supersedes, so it is
    // neither moved nor retracted (see `migrate_superseded_edges`).
    let frozen: Vec<String> = NON_PUBLIC_FROZEN_RELATIONSHIPS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let candidates: Vec<(Uuid, Uuid, Uuid, String, String, String)> = sqlx::query_as(
        r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
        SELECT e.id, e.source_id, e.target_id, e.source_type, e.target_type, e.relationship
        FROM edges e
        WHERE e.relationship != 'supersedes'
          AND e.valid_to IS NULL
          AND ( (e.source_id = ANY($1) AND e.source_type = 'claim')
             OR (e.target_id = ANY($1) AND e.target_type = 'claim') )
          AND NOT (e.relationship = 'same_as' AND e.properties ? 'dedup')
          AND NOT ( e.relationship = ANY($2) AND (
                  (e.source_id = ANY($1) AND e.source_type = 'claim'
                   AND NOT EXISTS (SELECT 1 FROM claims c
                                    WHERE c.id = e.source_id AND c.visibility::text = 'public'))
               OR (e.target_id = ANY($1) AND e.target_type = 'claim'
                   AND NOT EXISTS (SELECT 1 FROM claims c
                                    WHERE c.id = e.target_id AND c.visibility::text = 'public')) ) )
        ORDER BY e.created_at, e.id"#,
    )
    .bind(source_ids)
    .bind(&frozen)
    .fetch_all(&mut *tx)
    .await?;

    let mut to_delete: Vec<Uuid> = Vec::new();
    let mut survivors: Vec<Uuid> = Vec::new();
    let mut seen: std::collections::HashSet<(Uuid, String, String, i8)> =
        std::collections::HashSet::new();

    for (id, source_id, target_id, source_type, target_type, relationship) in &candidates {
        let src_in = source_type == "claim" && unique.contains(source_id);
        let tgt_in = target_type == "claim" && unique.contains(target_id);

        if src_in && tgt_in {
            // Interior to the merge: would become merged→merged.
            to_delete.push(*id);
            continue;
        }
        // AUTHORED is allowed to accumulate (migration 017) — migrate, never dedupe.
        if relationship == "AUTHORED" {
            survivors.push(*id);
            continue;
        }

        let (other, other_type) = if src_in {
            (*target_id, target_type.clone())
        } else {
            (*source_id, source_type.clone())
        };
        // alternative_of's unique index is keyed on (LEAST, GREATEST) and
        // is therefore direction-agnostic; every other relationship
        // duplicates per-direction.
        let direction = if relationship == "alternative_of" {
            0
        } else if src_in {
            1
        } else {
            -1
        };
        let key = (other, other_type, relationship.clone(), direction);
        if seen.insert(key) {
            survivors.push(*id);
        } else {
            // Earliest edge already claimed this slot (ORDER BY created_at, id).
            to_delete.push(*id);
        }
    }

    let mut out = ConsolidateEdgeMigration::default();
    if !to_delete.is_empty() {
        // `survivors` keeps the earliest edge per slot and `to_delete` holds only
        // the redundant later copies, so retracting them leaves the assertion in
        // force on the survivor. Retraction rather than deletion keeps the
        // duplicates auditable — you can still see that the graph once carried
        // two copies and when the redundancy was resolved.
        out.retracted = sqlx::query_scalar(
            "UPDATE edges SET valid_to = now() WHERE id = ANY($1) AND valid_to IS NULL \
             RETURNING id",
        )
        .bind(&to_delete[..])
        .fetch_all(&mut *tx)
        .await?;
    }

    if !survivors.is_empty() {
        let resourced: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE edges SET source_id = $1 \
             WHERE id = ANY($2) AND source_type = 'claim' AND source_id = ANY($3) \
             RETURNING id",
        )
        .bind(merged_id)
        .bind(&survivors[..])
        .bind(source_ids)
        .fetch_all(&mut *tx)
        .await?;
        let retargeted: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE edges SET target_id = $1 \
             WHERE id = ANY($2) AND target_type = 'claim' AND target_id = ANY($3) \
             RETURNING id",
        )
        .bind(merged_id)
        .bind(&survivors[..])
        .bind(source_ids)
        .fetch_all(&mut *tx)
        .await?;
        out.migrated = resourced;
        out.migrated.extend(retargeted);
    }
    Ok(out)
}

/// One grounded neighbour of a query vector, as
/// [`ClaimRepository::grounded_neighborhood`] returns it.
///
/// `belief`, `plausibility` and `similarity` are `Option` because the columns
/// are nullable and the caller supplies its own defaults — the shape the route
/// layer already had, preserved so the move changes no arithmetic.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroundedNeighbor {
    /// `claims.id`.
    pub id: Uuid,
    /// `claims.belief`.
    pub belief: Option<f64>,
    /// `claims.plausibility`.
    pub plausibility: Option<f64>,
    /// `1 - cosine_distance(embedding, query_vector)`.
    pub similarity: Option<f64>,
}

/// One near-duplicate neighbour of a seed claim.
#[derive(Debug, Clone)]
pub struct ClaimNeighbor {
    pub claim_id: Uuid,
    pub distance: f64,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A claim eligible for the dedup sweep.
#[derive(Debug, Clone)]
pub struct SweepCandidate {
    pub id: Uuid,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ClaimRepository {
    /// Page through `is_current` claims that carry an embedding and are
    /// eligible for semantic deduplication (backlog e3732d16).
    ///
    /// Exclusions are policy, not optimisation:
    /// - `telemetry`-labelled claims are never embedded by design (CLAUDE.md),
    ///   so they cannot participate in an ANN sweep at all.
    /// - claims carrying `properties->>'level'` are document-structure rows
    ///   (spine/paragraph/atom). Near-identical paragraphs across two papers
    ///   are a legitimate corpus fact, not a duplicate to collapse.
    /// - claims whose `supersedes` is already set have been merged or
    ///   deduplicated once; re-processing them would rewrite settled lineage.
    ///
    /// Ordered by `created_at, id` so `offset` paging is stable across calls —
    /// the sweep is resumable by design, since the corpus is far larger than
    /// one invocation should touch.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn enumerate_current_embedded<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_scope: Option<&[Uuid]>,
        labels_scope: Option<&[String]>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<SweepCandidate>, DbError> {
        // MACRO SITE — static three-bind spelling; see `get_by_id`.
        let rows = sqlx::query!(
            r#"
            SELECT id, truth_value, created_at
            FROM claims
            WHERE is_current
              AND embedding IS NOT NULL
              AND supersedes IS NULL
              AND NOT (labels @> ARRAY['telemetry']::text[])
              AND properties->>'level' IS NULL
              AND ($1::uuid[] IS NULL OR agent_id = ANY($1))
              AND ($2::text[] IS NULL OR labels @> $2)
              AND ($5::bool OR visibility = 'public' OR owner_group_id = ANY($6::uuid[]))
            ORDER BY created_at, id
            LIMIT $3 OFFSET $4
            "#,
            agent_scope,
            labels_scope,
            limit.clamp(1, 2000),
            offset.max(0),
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| SweepCandidate {
                id: r.id,
                truth_value: r.truth_value,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Nearest `is_current` neighbours of a STORED claim, by cosine distance.
    ///
    /// Mirrors [`Self::nearest_by_embedding`] but seeds from a row already in
    /// the table rather than a caller-supplied vector, which is what a sweep
    /// over existing claims needs.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn nearest_neighbors_of_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        k: i64,
    ) -> Result<Vec<ClaimNeighbor>, DbError> {
        // MACRO SITE — static three-bind spelling; see `get_by_id`.
        //
        // THREE predicates, not one. `c2` is the neighbour set, but the seed
        // vector is read by TWO correlated subqueries (projection and ORDER BY)
        // over `claims` on `$1`. Left unfiltered they make this function an
        // existence-and-neighbourhood oracle: a scoped caller passes a claim id
        // it cannot read and gets back a cosine ranking seeded from its content.
        // An unreadable seed now yields a NULL embedding, so `distance` is NULL
        // and the row is dropped by the `<=>` comparison being NULL — the query
        // returns nothing rather than a ranking.
        let rows = sqlx::query!(
            r#"
            SELECT c2.id, c2.truth_value, c2.created_at,
                   (c2.embedding <=> (
                       SELECT cs.embedding FROM claims cs
                       WHERE cs.id = $1
                         AND ($3::bool OR cs.visibility = 'public'
                              OR cs.owner_group_id = ANY($4::uuid[]))
                   )) AS "distance!"
            FROM claims c2
            WHERE c2.is_current
              AND c2.embedding IS NOT NULL
              AND c2.supersedes IS NULL
              AND c2.id != $1
              AND NOT (c2.labels @> ARRAY['telemetry']::text[])
              AND c2.properties->>'level' IS NULL
              AND ($3::bool OR c2.visibility = 'public'
                   OR c2.owner_group_id = ANY($4::uuid[]))
            ORDER BY c2.embedding <=> (
                SELECT cs.embedding FROM claims cs
                WHERE cs.id = $1
                  AND ($3::bool OR cs.visibility = 'public'
                       OR cs.owner_group_id = ANY($4::uuid[]))
            )
            LIMIT $2
            "#,
            claim_id,
            k.clamp(1, 50),
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ClaimNeighbor {
                claim_id: r.id,
                distance: r.distance,
                truth_value: r.truth_value,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Content hashes for a set of claims, so a sweep can tell an exact
    /// restatement (safe to `mark_duplicate`) from a merely-similar pair
    /// (needs synthesis via `consolidate`).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(executor, viewer, ids))]
    pub async fn content_hashes_for<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<u8>>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // MACRO SITE — static three-bind spelling; see `get_by_id`. A content
        // hash is a content oracle: equality against a known plaintext confirms
        // a claim's exact text without ever returning it.
        let rows = sqlx::query!(
            "SELECT id, content_hash FROM claims \
             WHERE id = ANY($1) \
               AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))",
            ids,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.content_hash)).collect())
    }
}

/// Whether [`canonical_chain`] locks the claims it walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainLock {
    /// A plain read (the request paths, on the caller's read transaction).
    None,
    /// `FOR SHARE OF c` on each claim of the chain (the un-mark's act).
    ForShare,
}

/// The most replacements [`canonical_chain`] follows from one canonical: far
/// above any real supersession depth, as the version-chain walk's cap.
const CANONICAL_CHAIN_MAX: usize = 100;

/// `canonical`, then each claim that replaced it in turn, ending with the
/// current one; or why there is no current canonical to restore a duplicate
/// against. Read through `viewer` (an unreadable `canonical` is taken as it
/// is, as the act always has).
///
/// The replacement of a retired claim `C` is the source `N` of an in-force
/// claim-to-claim `supersedes` edge targeting `C` whose rows agree: a
/// supersession (`N.supersedes = C`, [`ClaimRepository::supersede_act_conn`])
/// or a consolidation (`C.supersedes = N`,
/// [`ClaimRepository::consolidate_act_conn`]); both write that edge, `N -> C`,
/// and no dedup does. Refused: a claim of the chain that is itself a marked
/// duplicate (it carries a dedup identity edge; un-mark it first), one retired
/// with no replacement (a deprecation), one with two, a cycle, and a chain
/// longer than [`CANONICAL_CHAIN_MAX`].
///
/// [`ChainLock::ForShare`] (the un-mark's act, on the maintenance connection)
/// holds every claim of the chain `FOR SHARE` until the act's transaction
/// ends, so none can be retired while the reversal re-mints factors on the
/// head; the request paths read it without locks.
async fn canonical_chain(
    conn: &mut sqlx::PgConnection,
    viewer: &crate::visibility::Viewer,
    canonical: Uuid,
    lock: ChainLock,
) -> Result<Result<Vec<Uuid>, String>, DbError> {
    let mut chain = vec![canonical];
    loop {
        let at = *chain.last().unwrap_or(&canonical);
        let which = if at == canonical {
            "which".to_string()
        } else {
            format!("whose replacement {at}")
        };
        let mut sql = viewer.splice(
            "SELECT COALESCE(c.is_current, true) FROM claims c \
              WHERE c.id = $1 /* {VISIBILITY:c} */",
            2,
        );
        if lock == ChainLock::ForShare {
            sql.push_str(" FOR SHARE OF c");
        }
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(at);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        if q.fetch_optional(&mut *conn).await? != Some(false) {
            return Ok(Ok(chain));
        }
        if chain.len() > CANONICAL_CHAIN_MAX {
            return Ok(Err(format!(
                "supersedes {canonical}, which was replaced more than {CANONICAL_CHAIN_MAX} \
                 times; refusing to follow the chain further"
            )));
        }
        let sql = viewer.splice(
            "SELECT e.target_id FROM edges e JOIN claims c ON c.id = e.source_id \
              WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim' \
                AND e.relationship = $2 AND e.valid_to IS NULL AND e.properties ? $3 \
                AND e.target_id = c.supersedes \
                /* {EDGE_VISIBILITY:e} */ \
              LIMIT 1",
            4,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(at)
            .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
            .bind(DUPLICATE_IDENTITY_PROPERTY);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        if let Some(of) = q.fetch_optional(&mut *conn).await? {
            return Ok(Err(format!(
                "supersedes {canonical}, {which} is itself retired (a marked duplicate of \
                 {of}); un-mark {at} first"
            )));
        }
        let sql = viewer.splice(
            "SELECT e.source_id FROM edges e \
               JOIN claims n ON n.id = e.source_id \
               JOIN claims o ON o.id = e.target_id \
              WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim' \
                AND e.relationship = 'supersedes' AND e.valid_to IS NULL \
                AND e.source_id <> e.target_id \
                AND (n.supersedes = o.id OR o.supersedes = n.id) \
                /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:n} */ \
              ORDER BY e.source_id",
            2,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(at);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut next: Vec<Uuid> = q.fetch_all(&mut *conn).await?;
        next.dedup();
        match next.as_slice() {
            [] => {
                return Ok(Err(format!(
                    "supersedes {canonical}, {which} is retired with no replacement (it was \
                     deprecated, or retired by another act); there is no current canonical to \
                     restore it against"
                )))
            }
            [n] if chain.contains(n) => {
                return Ok(Err(format!(
                    "supersedes {canonical}, whose replacements form a cycle at {n}; refusing \
                     to follow it"
                )))
            }
            [n] => chain.push(*n),
            many => {
                return Ok(Err(format!(
                    "supersedes {canonical}, {which} has {} replacements ({}); refusing to pick \
                     one",
                    many.len(),
                    many.iter()
                        .map(Uuid::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )))
            }
        }
    }
}

/// Why the un-mark refuses `dup`, retired with no in-force dedup identity edge
/// to the claim it supersedes: [`legacy_mark_refusal`]'s reason for a legacy
/// `fuzzy_dedup_claims` mark, otherwise that it was retired by another act.
async fn no_identity_edge_refusal(
    conn: &mut sqlx::PgConnection,
    viewer: &crate::visibility::Viewer,
    dup: Uuid,
) -> Result<String, DbError> {
    if let Some(why) = legacy_mark_refusal(conn, viewer, dup).await? {
        return Ok(why);
    }
    Ok(
        "has no dedup identity edge to the claim it supersedes (it was retired by another \
        act, or marked before identity edges were recorded)"
            .to_string(),
    )
}

/// Why the un-mark refuses `dup`, retired with no dedup identity edge, when it
/// is a legacy `fuzzy_dedup_claims` mark (its `deduped_by` names
/// [`LEGACY_FUZZY_DEDUP_TOOL`]); `None` for any other claim. Says whether the
/// backfill can still reconstruct the edge (by its own selection,
/// [`LEGACY_MARK_RECONSTRUCTABLE_SQL`]) and, if not, why not. Read through the
/// un-mark's viewer, like every read of the act.
async fn legacy_mark_refusal(
    conn: &mut sqlx::PgConnection,
    viewer: &crate::visibility::Viewer,
    dup: Uuid,
) -> Result<Option<String>, DbError> {
    let sql = viewer.splice(
        &format!(
            "SELECT COALESCE(({LEGACY_MARK_RECONSTRUCTABLE_SQL}), false), \
                    'deduped' = ANY(COALESCE(c.labels, ARRAY[]::text[])), \
                    c.properties->>'deduped_into', c.supersedes \
               FROM claims c \
              WHERE c.id = $1 AND c.properties->>'deduped_by' = $2 /* {{VISIBILITY:c}} */"
        ),
        3,
    );
    let mut q = sqlx::query_as::<_, (bool, bool, Option<String>, Option<Uuid>)>(&sql)
        .bind(dup)
        .bind(LEGACY_FUZZY_DEDUP_TOOL);
    if let Some(g) = viewer.group_bind() {
        q = q.bind(g);
    }
    let Some((reconstructable, labelled, deduped_into, supersedes)) =
        q.fetch_optional(&mut *conn).await?
    else {
        return Ok(None);
    };
    let head = format!(
        "is a legacy {LEGACY_FUZZY_DEDUP_TOOL} mark (made by raw SQL, without an identity edge)"
    );
    if reconstructable {
        return Ok(Some(format!(
            "{head} whose same_as identity edge has not been reconstructed yet; an operator's \
             `backfill_dedup_identity_edges --apply` writes it, after which the mark can be \
             un-marked"
        )));
    }
    let why = if !labelled {
        "it no longer carries the `deduped` label the mark wrote".to_string()
    } else {
        match (deduped_into, supersedes) {
            (None, _) => "it records no deduped_into".to_string(),
            (Some(into), Some(sup)) if into != sup.to_string() => {
                format!("its supersedes {sup} is no longer the claim the mark named (deduped_into {into})")
            }
            (Some(into), _) => {
                format!("it no longer supersedes the claim the mark named (deduped_into {into})")
            }
        }
    };
    Ok(Some(format!(
        "{head} that backfill_dedup_identity_edges cannot reconstruct: {why}; it cannot be \
         un-marked"
    )))
}

/// The checks, the one `claims` UPDATE and the identity edge of a dedup's act.
/// The callers ([`ClaimRepository::mark_duplicate_act_attributed_conn`],
/// [`ClaimRepository::mark_duplicate_with_repair_attributed_conn`]) own the
/// transaction. Returns the identity edge's id.
async fn mark_duplicate_act(
    conn: &mut sqlx::PgConnection,
    dup_uuid: Uuid,
    canon_uuid: Uuid,
    provenance: &DuplicateProvenance,
) -> Result<Uuid, DbError> {
    if dup_uuid == canon_uuid {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol("mark_duplicate: dup == canonical".into()),
        });
    }
    // The canonical must exist and be CURRENT: a mark onto a retired claim
    // names a canonical the caller never saw as one, which the un-mark then
    // has to follow or refuse. A plain read, not FOR SHARE
    // (that would take the UPDATE policy on the caller's stamped session); a
    // concurrent retirement after it makes an ordinary chain, which the
    // un-mark already orders.
    let canon_current: Option<bool> = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
        SELECT COALESCE(is_current, true) FROM claims WHERE id = $1"#,
    )
    .bind(canon_uuid)
    .fetch_optional(&mut *conn)
    .await?;
    match canon_current {
        None => {
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: canon_uuid,
            })
        }
        Some(false) => {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "mark_duplicate: canonical {canon_uuid} is not current; refusing to build a \
                     dedup chain onto a retired claim"
                )),
            })
        }
        Some(true) => {}
    }
    let row: Option<(Option<Uuid>,)> = sqlx::query_as(
        r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
        SELECT supersedes FROM claims WHERE id = $1 FOR UPDATE"#,
    )
    .bind(dup_uuid)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((existing,)) = row else {
        return Err(DbError::NotFound {
            entity: "Claim".into(),
            id: dup_uuid,
        });
    };
    if existing.is_some() {
        return Err(DbError::QueryFailed {
            source: sqlx::Error::Protocol(format!(
                "Claim {dup_uuid} already superseded; refusing to overwrite"
            )),
        });
    }
    // Null both embedding columns in the same statement as is_current=false
    // so the CHECK constraint chk_deprecated_no_embedding (migration 052)
    // is not violated mid-transaction. Dropping it from semantic search is
    // the same invariant as supersede() and deprecate_claim().
    sqlx::query(
        "UPDATE claims \
         SET supersedes = $1, is_current = false, embedding = NULL, \
             embedding_3072 = NULL, updated_at = NOW() \
         WHERE id = $2",
    )
    .bind(canon_uuid)
    .bind(dup_uuid)
    .execute(&mut *conn)
    .await?;
    // The identity, as a traversable and attributed graph fact: one `same_as`
    // edge duplicate -> canonical carrying who marked it, how and when.
    // `supersedes` stays the pointer readers already follow; the edge is what
    // an audit or an un-mark reads.
    //
    // Written AFTER the UPDATE above on purpose: `auto_create_factor_from_edge`
    // skips an edge with a non-current endpoint, so the identity edge never
    // becomes a belief factor between the pair. `same_as` is in no DS auto-wire
    // list either, so no BBA is keyed to it.
    //
    // It is the caller's own row (its tenancy is derived from the two
    // endpoints), so it lands on the caller's stamped transaction with the act.
    // The repair's resource and collision clauses all exclude edges whose
    // other end is the canonical, so the edge stays on the duplicate.
    let provenance_json = serde_json::to_value(provenance).map_err(|e| DbError::InvalidData {
        reason: format!("mark_duplicate: provenance does not serialize: {e}"),
    })?;
    let identity_edge: Uuid = sqlx::query_scalar(
        r#"INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
           VALUES ($1, 'claim', $2, 'claim', $3,
                   jsonb_build_object($4::text,
                       jsonb_strip_nulls(jsonb_build_object(
                           'marked_by', public.epigraph_principal_id()))
                       || $5::jsonb
                       || jsonb_build_object('marked_at', now())))
           RETURNING id"#,
    )
    .bind(dup_uuid)
    .bind(canon_uuid)
    .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
    .bind(DUPLICATE_IDENTITY_PROPERTY)
    .bind(&provenance_json)
    .fetch_one(&mut *conn)
    .await?;
    Ok(identity_edge)
}

/// The dedup's repair of the edge and derived-record layers, unchecked: the
/// callers establish the privilege and the committed (or same-transaction)
/// act first, and own the transaction.
///
/// # Why the edge migration alone corrupts belief
/// See [`ClaimRepository::mark_duplicate_with_repair`]: without the two
/// derived-record repairs below, the collision guards ORPHAN BBAs and the
/// retarget STRANDS them.
async fn repair_marked_duplicate(
    conn: &mut sqlx::PgConnection,
    dup_uuid: Uuid,
    canon_uuid: Uuid,
) -> Result<DedupRepair, DbError> {
    // Migrate edges off the now-non-current duplicate onto the canonical
    // claim, mirroring supersede()'s edge migration — otherwise edges to/from
    // third claims dangle at a claim that no longer surfaces. Unlike supersede
    // (which targets a freshly-minted claim with no pre-existing edges), the
    // canonical here already exists, so we must guard against two collision
    // classes before running the UPDATEs:
    //
    //   1. Self-loops: `dup→canonical` or `canonical→dup` edges that would
    //      become `canonical→canonical` after migration (handled by the
    //      `AND NOT (... = $1)` filters in the UPDATE clauses below).
    //
    //   2. Diamond duplicates: a third claim T that has edges to *both* dup
    //      and canonical with the same relationship — e.g.
    //      `T→[CORROBORATES]→dup` AND `T→[CORROBORATES]→canonical`.
    //      Migrating the dup edge to point at canonical would produce a
    //      second `T→[CORROBORATES]→canonical` triple, tripping the partial
    //      unique index `idx_edges_unique_triple_non_authored`
    //      (migration 017, covers all relationship types except AUTHORED)
    //      and rolling back the whole transaction before `is_current` is
    //      flipped.  Pre-delete the redundant dup edges so the UPDATE only
    //      touches survivors.  AUTHORED edges are excluded because the
    //      partial index does not cover them, and they are meant to
    //      accumulate (migration 017 explicitly allows multiple AUTHORED
    //      edges per triple).
    //
    // The 'supersedes' edges (dedup/lineage trail) are preserved throughout.
    //
    // A NON-PUBLIC duplicate also keeps its `executes` edges
    // (`NON_PUBLIC_FROZEN_RELATIONSHIPS`, OD-32): they name the steps of a
    // frozen workflow generation, so neither the collision guards nor the
    // migration below touch them. Read from the duplicate's row, so the
    // deferred replay gives the same result. Every shipped `executes` writer
    // is workflow-sourced, so only the incoming retarget below meets one
    // today; the outgoing clauses and the claim-sourced incoming collision
    // guard cover a claim-sourced `executes`, which the edges table accepts.
    let frozen = non_public_frozen_relationships(&mut *conn, dup_uuid).await?;

    // The act's identity edge, which keys this repair's revert record (a
    // mark made before identity edges existed has none).
    let identity_edge: Option<Uuid> = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         SELECT id FROM edges
          WHERE source_id = $1 AND source_type = 'claim'
            AND target_id = $2 AND target_type = 'claim'
            AND relationship = $3 AND valid_to IS NULL AND properties ? $4
          ORDER BY created_at DESC, id DESC LIMIT 1"#,
    )
    .bind(dup_uuid)
    .bind(canon_uuid)
    .bind(DUPLICATE_IDENTITY_RELATIONSHIP)
    .bind(DUPLICATE_IDENTITY_PROPERTY)
    .fetch_optional(&mut *conn)
    .await?;

    // Drop incoming dup-edges whose migrated triple already exists on canonical.
    // Alias the outer table as `e` so the correlated subquery references
    // `e.source_id`, `e.source_type`, `e.relationship` unambiguously.
    // Without the alias, unqualified column names inside the EXISTS bind to
    // `edges e2` (innermost scope in PostgreSQL), making the predicate
    // tautological and causing false-positive deletions of edges that should
    // be migrated.
    // `RETURNING id, target_id` (here and on the two pre-deletes below) is
    // the only addition to these statements: the edge rows are about to be
    // gone, and their `perspective_id = id` BBAs — which live on
    // `target_id` — have to be deleted with them, so the ids must be
    // captured before the DELETE commits.
    let mut deleted_edges: Vec<(Uuid, Uuid)> = sqlx::query_as(
        r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
         UPDATE edges AS e SET valid_to = now()
         WHERE e.target_id = $2 AND e.target_type = 'claim'
         AND e.relationship != 'supersedes' AND e.relationship != 'AUTHORED'
         AND NOT (e.relationship = ANY($3))
         AND NOT (e.relationship = 'same_as' AND e.properties ? 'dedup')
         AND e.source_type = 'claim' AND e.source_id != $1
         AND e.valid_to IS NULL
         AND EXISTS (
         SELECT 1 FROM edges e2
         WHERE e2.source_id = e.source_id
         AND e2.source_type = e.source_type
         AND e2.target_id = $1
         AND e2.target_type = 'claim'
         AND e2.relationship = e.relationship
         AND (e2.valid_to IS NULL OR e2.valid_to > now())
         )
         RETURNING e.id, e.target_id"#,
    )
    .bind(canon_uuid)
    .bind(dup_uuid)
    .bind(&frozen)
    .fetch_all(&mut *conn)
    .await?;

    // Drop outgoing dup-edges whose migrated triple already exists on canonical.
    // Same aliasing discipline: `e.target_id`, `e.target_type`, `e.relationship`
    // must refer to the outer (being-deleted) row, not the subquery table.
    deleted_edges.extend(
        sqlx::query_as::<_, (Uuid, Uuid)>(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
             UPDATE edges AS e SET valid_to = now()
             WHERE e.source_id = $2 AND e.source_type = 'claim'
             AND e.relationship != 'supersedes' AND e.relationship != 'AUTHORED'
             AND NOT (e.relationship = ANY($3))
             AND NOT (e.relationship = 'same_as' AND e.properties ? 'dedup')
             AND e.target_type = 'claim' AND e.target_id != $1
             AND e.valid_to IS NULL
             AND EXISTS (
             SELECT 1 FROM edges e2
             WHERE e2.source_id = $1
             AND e2.source_type = 'claim'
             AND e2.target_id = e.target_id
             AND e2.target_type = e.target_type
             AND e2.relationship = e.relationship
             AND (e2.valid_to IS NULL OR e2.valid_to > now())
             )
             RETURNING e.id, e.target_id"#,
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .bind(&frozen)
        .fetch_all(&mut *conn)
        .await?,
    );

    // Symmetric-collision guard for `alternative_of` (migration 042).
    //
    // That relationship is governed by `edges_alternative_of_symmetric_uniq`,
    // a UNIQUE index on `(LEAST(source_id,target_id), GREATEST(source_id,target_id))`
    // — so the pair {A,B} is unique *regardless of direction*.  The two
    // directional pre-deletes above only recognise same-`(source,target,
    // relationship)` triples, so they miss the case where `dup` and
    // `canonical` are joined to a common third claim T by `alternative_of`
    // edges of *opposite* orientation (e.g. `dup→T` and `T→canonical`).
    // Migrating `dup→canonical` would then rewrite `dup→T` into `canonical→T`,
    // whose symmetric key {canonical,T} collides with the existing `T→canonical`
    // edge, tripping the unique index and rolling the whole transaction back
    // before `is_current` is flipped (backlog 2905150e / issue #286).
    //
    // Pre-delete the redundant dup-side `alternative_of` edge whenever
    // `canonical` already shares a symmetric `alternative_of` edge with the
    // same third claim.  Edges where `canonical` is itself an endpoint are
    // left for the self-loop guards in the migration UPDATEs below.
    deleted_edges.extend(
        sqlx::query_as::<_, (Uuid, Uuid)>(
            r#"-- VISIBILITY-EXEMPT: WRITE path. PR-16 owns the write-side predicate; this read is part of the mutation it guards, not a disclosure to a caller.
             UPDATE edges AS e SET valid_to = now()
             WHERE e.relationship = 'alternative_of'
             AND e.valid_to IS NULL
             AND e.source_type = 'claim' AND e.target_type = 'claim'
             AND (e.source_id = $2 OR e.target_id = $2)
             AND e.source_id != $1 AND e.target_id != $1
             AND EXISTS (
             SELECT 1 FROM edges e2
             WHERE e2.relationship = 'alternative_of'
             AND e2.source_type = 'claim' AND e2.target_type = 'claim'
             AND e2.id <> e.id
             AND (e2.valid_to IS NULL OR e2.valid_to > now())
             AND LEAST(e2.source_id, e2.target_id) =
             LEAST($1, CASE WHEN e.source_id = $2 THEN e.target_id ELSE e.source_id END)
             AND GREATEST(e2.source_id, e2.target_id) =
             GREATEST($1, CASE WHEN e.source_id = $2 THEN e.target_id ELSE e.source_id END)
             )
             RETURNING e.id, e.target_id"#,
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *conn)
        .await?,
    );

    // ── Derived-record repair, part 1: no ORPHANS ────────────────────────
    // Every edge the three guards just retracted takes its edge-factor BBA
    // with it. Without this, the BBA outlives its edge (nothing cascades from
    // `edges` to `mass_functions`) and keeps being combined into the target's
    // belief forever. These BBAs are routinely other writers' rows; this runs
    // on a privileged session (the caller's precondition), so it is the plain
    // statement (migration 117).
    let deleted_edge_ids: Vec<Uuid> = deleted_edges.iter().map(|(id, _)| *id).collect();
    // The rows are about to be deleted, so the revert record keeps them whole.
    let mut deleted_rows: Vec<serde_json::Value> = if deleted_edge_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             SELECT to_jsonb(mf) FROM mass_functions mf
              WHERE mf.perspective_id = ANY($1) ORDER BY mf.id"#,
        )
        .bind(&deleted_edge_ids)
        .fetch_all(&mut *conn)
        .await?
    };
    let deleted_bbas = crate::repos::mass_function::delete_edge_bbas(
        &mut *conn,
        &deleted_edge_ids,
        crate::repos::mass_function::EdgeBbaCascade::DedupRetractedEdge,
    )
    .await?;

    // The tenancy of every in-force edge on the duplicate, before the
    // re-points below make the edge tenancy trigger re-derive it; the revert
    // record keeps the re-pointed ones.
    let edge_tenancy_before: Vec<EdgeTenancy> = sqlx::query_as(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         SELECT id, owner_group_id, visibility::text AS visibility, co_owner_group_id
           FROM edges
          WHERE valid_to IS NULL
            AND ((target_id = $1 AND target_type = 'claim')
                 OR (source_id = $1 AND source_type = 'claim'))"#,
    )
    .bind(dup_uuid)
    .fetch_all(&mut *conn)
    .await?;

    let retargeted: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE edges SET target_id = $1 \
         WHERE target_id = $2 AND target_type = 'claim' AND relationship != 'supersedes' \
           AND valid_to IS NULL \
           -- Retracted edges do NOT migrate. A withdrawn assertion was made
           -- ABOUT the duplicate; re-pointing it at the canonical claim would
           -- rewrite history, and it would also leave two rows for the same
           -- pair (one live, one retracted) where callers expect one.
           AND NOT (source_type = 'claim' AND source_id = $1) \
           AND NOT (relationship = ANY($3)) \
           -- A dedup identity edge names the claim its duplicate SUPERSEDES;
           -- it stays with it when that claim is itself marked a duplicate.
           AND NOT (relationship = 'same_as' AND properties ? 'dedup') \
         RETURNING id",
    )
    .bind(canon_uuid)
    .bind(dup_uuid)
    .bind(&frozen)
    .fetch_all(&mut *conn)
    .await?;

    // ── Derived-record repair, part 2: no STRANDINGS ─────────────────────
    // Those edges now point at `canonical`, but their BBAs still sit on
    // `dup`. Move them, so `canonical` counts the supporters its edges say it
    // has.
    let retargeted_ids: Vec<Uuid> = retargeted.into_iter().map(|(id,)| id).collect();
    let mut moved_bbas = 0_u64;
    let mut dropped_duplicate_copies = 0_u64;
    let mut skipped_false_bindings = 0_u64;
    let mut copied_frames: Vec<Uuid> = Vec::new();
    let mut canonical_frame_inputs: Vec<Uuid> = Vec::new();
    let mut moved_rows: Vec<MovedBba> = Vec::new();

    // Part 3 (below) pools the duplicate's own belief inputs on the canonical,
    // unless the canonical is a COMPOUND (an in-force `decomposes_to`
    // out-edge): under atom-level belief a compound is a query over its atoms
    // and takes no BBA of its own, so nothing is moved onto one.
    let canonical_is_compound: bool = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         SELECT EXISTS (SELECT 1 FROM edges e
                         WHERE e.source_id = $1 AND e.source_type = 'claim'
                           AND e.relationship = 'decomposes_to' AND e.valid_to IS NULL)"#,
    )
    .bind(canon_uuid)
    .fetch_one(&mut *conn)
    .await?;
    let poolable_sql = poolable_bba_sql();
    let poolable: Vec<Uuid> = if canonical_is_compound {
        Vec::new()
    } else {
        sqlx::query_scalar(&format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             SELECT mf.id FROM mass_functions mf
              WHERE mf.claim_id = $2 AND {poolable_sql}
                AND NOT EXISTS ({CANONICAL_HOLDS_KEY_SQL})
              ORDER BY mf.id"#
        ))
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *conn)
        .await?
    };

    if !retargeted_ids.is_empty() || !poolable.is_empty() {
        // `canonical` must be assigned to every frame whose BBAs it is about
        // to inherit, or the frame-scoped read paths
        // (`claim_frames.hypothesis_index`) would not see them. The copy is
        // the claim's own row (a privileged insert inherits the claim's
        // tenancy), and it never overwrites an existing assignment.
        //
        // One exception, which the administrative authority this runs with
        // must not erase: a `binary_truth` binding at a non-zero index (FALSE)
        // is not copied onto a canonical owned by a different group than the
        // duplicate. That index is what every reader takes as the claim's own
        // truth, and a dedup by the duplicate's writer is no licence to set it
        // on somebody else's claim (FA07, review finding W2; the caller's act
        // refuses the case it can see).
        skipped_false_bindings = sqlx::query_scalar::<_, i64>(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             SELECT count(*) FROM claim_frames cf
               JOIN frames f ON f.id = cf.frame_id
               JOIN claims d ON d.id = $2
               JOIN claims c ON c.id = $1
              WHERE cf.claim_id = $2
                AND f.name = 'binary_truth' AND cf.hypothesis_index IS DISTINCT FROM 0
                AND c.owner_group_id IS DISTINCT FROM d.owner_group_id
                AND NOT EXISTS (SELECT 1 FROM claim_frames c2
                                 WHERE c2.claim_id = $1 AND c2.frame_id = cf.frame_id)"#,
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_one(&mut *conn)
        .await
        .map(|n| u64::try_from(n).unwrap_or(0))?;
        copied_frames = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
             SELECT $1, cf.frame_id, cf.hypothesis_index FROM claim_frames cf
               JOIN frames f ON f.id = cf.frame_id
               JOIN claims d ON d.id = $2
               JOIN claims c ON c.id = $1
              WHERE cf.claim_id = $2
                AND NOT (f.name = 'binary_truth' AND cf.hypothesis_index IS DISTINCT FROM 0
                         AND c.owner_group_id IS DISTINCT FROM d.owner_group_id)
             ON CONFLICT (claim_id, frame_id) DO NOTHING
             RETURNING frame_id"#,
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *conn)
        .await?;
        if !copied_frames.is_empty() {
            canonical_frame_inputs = sqlx::query_scalar(&format!(
                r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
                 SELECT mf.id FROM mass_functions mf
                  WHERE mf.claim_id = $1 AND mf.frame_id = ANY($2) AND NOT {}
                  ORDER BY mf.id"#,
                crate::repos::mass_function::cached_combination_predicate("mf.")
            ))
            .bind(canon_uuid)
            .bind(&copied_frames)
            .fetch_all(&mut *conn)
            .await?;
        }

        // Guard `mass_functions_unique_per_perspective` (claim_id, frame_id,
        // source_agent_id, perspective_id, NULLS NOT DISTINCT -- migration
        // 034): when `canonical` already holds a row for an incoming
        // perspective, the DUPLICATE's copy is dropped and the canonical keeps
        // its own. Both carry the same edge, frame and source agent; only the
        // moment their masses were frozen differs, and the canonical's row may
        // be another writer's contribution, which a dedup does not destroy
        // (migration 115 section 4's rule, now the only one).
        let dropped: Vec<serde_json::Value> = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             DELETE FROM mass_functions d
              WHERE d.claim_id = $2 AND d.perspective_id = ANY($3)
                AND EXISTS (
                    SELECT 1 FROM mass_functions c
                     WHERE c.claim_id = $1
                       AND c.perspective_id = d.perspective_id
                       AND c.frame_id = d.frame_id
                       AND c.source_agent_id IS NOT DISTINCT FROM d.source_agent_id)
             RETURNING to_jsonb(d)"#,
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .bind(&retargeted_ids)
        .fetch_all(&mut *conn)
        .await?;
        dropped_duplicate_copies = dropped.len() as u64;
        deleted_rows.extend(dropped);

        // The move keeps "a writer's contribution is the writer's" (migration
        // 114). Onto a PUBLIC canonical, a row keeps its owner and comes out
        // writer-owned whenever that owner is not the canonical's (so a later
        // insert on the canonical does not re-stamp it to the canonical's
        // owner); onto a group-private canonical it becomes the claim's own
        // row, as every derived row of a private claim is.
        let moved: Vec<MovedBba> = sqlx::query_as(&format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             WITH before AS (
                 SELECT b.id, b.owner_group_id, b.visibility::text AS visibility, b.writer_owned
                   FROM mass_functions b
                  WHERE b.claim_id = $2 AND b.perspective_id = ANY($3))
             {MOVE_BBAS_ONTO_CANONICAL_SQL}"#
        ))
        .bind(canon_uuid)
        .bind(dup_uuid)
        .bind(&retargeted_ids)
        .fetch_all(&mut *conn)
        .await?;
        moved_bbas = moved.len() as u64;
        moved_rows.extend(moved);
    }

    // ── Derived-record repair, part 3: POOL the duplicate's own inputs ────
    // Parts 1 and 2 move only EDGE-keyed BBAs, with their edges. The
    // duplicate's other BBAs -- its auto-wired creation row, assess rows,
    // agent BBAs (`perspective_id` NULL or naming no edge) -- would otherwise
    // stay on a claim no reader folds (V-1), so the canonical would not count
    // evidence the duplicate had. They move under part 2's ownership rule
    // (migration 114). Three kinds stay on the duplicate, and are reported:
    //
    // * a row whose (frame, source agent, perspective) key the canonical
    //   already holds: the same source's view of the same proposition, which
    //   pooling would count twice; the canonical keeps its own and the
    //   duplicate's copy is KEPT (not dropped, unlike part 2's edge rule), so
    //   nothing is destroyed and an un-mark has nothing to restore;
    // * an `attributed_v1` row: under atom-level belief those are re-derived
    //   by the attributor for the canonical, never moved;
    // * every row, when the canonical is a compound (above).
    //
    // The duplicate's `evidence` rows never move: they are its provenance, a
    // moved BBA keeps citing its row through `evidence_id`, and the canonical
    // reaches them through the identity edge.
    let mut pooled_bbas: Vec<Uuid> = Vec::new();
    if !poolable.is_empty() {
        let pooled: Vec<MovedBba> = sqlx::query_as(&format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             WITH before AS (
                 SELECT b.id, b.owner_group_id, b.visibility::text AS visibility, b.writer_owned
                   FROM mass_functions b
                  WHERE b.claim_id = $2 AND b.id = ANY($3))
             {MOVE_BBAS_ONTO_CANONICAL_SQL}"#
        ))
        .bind(canon_uuid)
        .bind(dup_uuid)
        .bind(&poolable)
        .fetch_all(&mut *conn)
        .await?;
        pooled_bbas = pooled.iter().map(|m| m.id).collect();
        pooled_bbas.sort_unstable();
        moved_rows.extend(pooled);
    }
    let kept_on_duplicate: Vec<Uuid> = sqlx::query_scalar(&format!(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         SELECT mf.id FROM mass_functions mf
          WHERE mf.claim_id = $2
            AND (mf.perspective_id IS NULL
                 OR NOT EXISTS (SELECT 1 FROM edges e WHERE e.id = mf.perspective_id))
            AND ($3 OR NOT {poolable_sql} OR EXISTS ({CANONICAL_HOLDS_KEY_SQL}))
          ORDER BY mf.id"#
    ))
    .bind(canon_uuid)
    .bind(dup_uuid)
    .bind(canonical_is_compound)
    .fetch_all(&mut *conn)
    .await?;

    // Outgoing edges are re-sourced at `canonical`. Their BBAs live on the
    // far end and are unmoved, but their *content* was frozen from `dup`'s
    // interval at wire time, so they now misattribute. They cannot be fixed
    // by recombination -- the caller re-derives them (see
    // `DedupRepair::resourced_edges`).
    let resourced_rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "UPDATE edges SET source_id = $1 \
         WHERE source_id = $2 AND source_type = 'claim' AND relationship != 'supersedes' \
           AND valid_to IS NULL \
           -- Retracted edges do NOT migrate. A withdrawn assertion was made
           -- ABOUT the duplicate; re-pointing it at the canonical claim would
           -- rewrite history, and it would also leave two rows for the same
           -- pair (one live, one retracted) where callers expect one.
           AND NOT (target_type = 'claim' AND target_id = $1) \
           AND NOT (relationship = ANY($3)) \
           AND NOT (relationship = 'same_as' AND properties ? 'dedup') \
         RETURNING id, target_id, relationship, target_type",
    )
    .bind(canon_uuid)
    .bind(dup_uuid)
    .bind(&frozen)
    .fetch_all(&mut *conn)
    .await?;
    let resourced_rows_ids: Vec<Uuid> = resourced_rows.iter().map(|r| r.0).collect();

    // The BP factor graph (backlog ddb231b7). The act's retirement of the
    // duplicate deleted every factor naming it (`claims_deactivate_factors`),
    // and the two re-points above are UPDATEs, which `edges_auto_factor`
    // (INSERT only) never sees: without this, belief propagation never sees
    // an edge the canonical inherited. Mint each moved edge's factor as the
    // trigger would now, and only those (an existing `(type, pair)` slot on
    // the canonical is kept, as the trigger's ON CONFLICT keeps it). The
    // un-mark's stale-factor DELETE removes these again by `source_edge_id`.
    let moved_edges: Vec<Uuid> = retargeted_ids
        .iter()
        .chain(resourced_rows_ids.iter())
        .copied()
        .collect();
    if !moved_edges.is_empty() {
        sqlx::query(REGENERATE_EDGE_FACTORS_SQL)
            .bind(canon_uuid)
            .bind(canon_uuid)
            .bind(Vec::<String>::new())
            .bind(Some(&moved_edges))
            .execute(&mut *conn)
            .await?;
    }
    let resourced_edges: Vec<(Uuid, Uuid, String)> = resourced_rows
        .into_iter()
        .filter(|(_, _, _, target_type)| target_type == "claim")
        .map(|(id, target_id, relationship, _)| (id, target_id, relationship))
        .collect();

    let deleted_edge_ids_for_revert = deleted_edge_ids.clone();
    // The collision guards stamped `valid_to = now()`, the transaction's time.
    let retracted_at: Option<chrono::DateTime<chrono::Utc>> = if deleted_edge_ids.is_empty() {
        None
    } else {
        Some(
            sqlx::query_scalar("SELECT now()")
                .fetch_one(&mut *conn)
                .await?,
        )
    };
    let retargeted_for_revert = retargeted_ids.clone();
    let resourced_for_revert: Vec<Uuid> = resourced_rows_ids;
    let edge_tenancy: Vec<EdgeTenancy> = edge_tenancy_before
        .into_iter()
        .filter(|t| retargeted_for_revert.contains(&t.id) || resourced_for_revert.contains(&t.id))
        .collect();

    // Claims whose cached scalars no longer match their BBA set: the two
    // dedup endpoints, plus every third claim that lost a BBA above.
    let mut stale_claims = vec![canon_uuid, dup_uuid];
    for (_, target) in &deleted_edges {
        if !stale_claims.contains(target) {
            stale_claims.push(*target);
        }
    }

    Ok(DedupRepair {
        stale_claims,
        resourced_edges,
        deleted_bbas,
        moved_bbas,
        retracted_edges: deleted_edge_ids,
        retargeted_edges: retargeted_ids,
        dropped_duplicate_copies,
        skipped_false_bindings,
        pooled_bbas,
        kept_on_duplicate,
        canonical_is_compound,
        revert: DedupRevert {
            identity_edge,
            retracted_edges: deleted_edge_ids_for_revert,
            retracted_at,
            retargeted_edges: retargeted_for_revert,
            resourced_edges: resourced_for_revert,
            edge_tenancy,
            moved_bbas: moved_rows,
            deleted_bbas: deleted_rows,
            copied_frames,
            canonical_frame_inputs,
        },
    })
}

/// The tail of both BBA moves onto the canonical (`$1`) in the dedup repair:
/// the UPDATE over a `before` CTE of the rows to move (`id`, and their
/// tenancy before the move), returning that before-state for the revert
/// record. The move keeps migration 114's "a writer's contribution is the
/// writer's" rule.
const MOVE_BBAS_ONTO_CANONICAL_SQL: &str = "\
     UPDATE mass_functions mf
        SET claim_id       = c.id,
            owner_group_id = CASE WHEN c.visibility = 'public' THEN mf.owner_group_id
                                  ELSE c.owner_group_id END,
            visibility     = c.visibility,
            writer_owned   = CASE
                               WHEN c.visibility IS DISTINCT FROM 'public' THEN false
                               WHEN mf.owner_group_id IS DISTINCT FROM c.owner_group_id
                                    THEN true
                               ELSE mf.writer_owned END
       FROM claims c, before b
      WHERE c.id = $1 AND mf.id = b.id
     RETURNING b.id, b.owner_group_id, b.visibility, b.writer_owned";

/// The reversal of a dedup repair, unchecked: the callers establish the
/// privilege and own the transaction. See
/// [`ClaimRepository::reverse_marked_duplicate_conn`].
async fn reverse_marked_duplicate(
    conn: &mut sqlx::PgConnection,
    dup_uuid: Uuid,
    canonical_chain: &[Uuid],
    record: &DedupRevert,
) -> Result<DedupReversal, DbError> {
    // The recorded canonical (where the repair bound frames) and the current
    // one (whose BP factor slots the un-mark frees); a repaired row is taken
    // back from wherever along the chain it now is.
    let (Some(&canon_uuid), Some(&head_uuid)) = (canonical_chain.first(), canonical_chain.last())
    else {
        return Err(DbError::InvalidData {
            reason: "reverse_marked_duplicate: an empty canonical chain".into(),
        });
    };
    let chain: Vec<Uuid> = canonical_chain.to_vec();
    let mut out = DedupReversal::default();
    let mut drifted: Vec<Uuid> = Vec::new();
    let note_drift = |asked: &[Uuid], done: &[Uuid], drifted: &mut Vec<Uuid>| {
        drifted.extend(asked.iter().filter(|id| !done.contains(id)).copied());
    };

    // Edges first, so the BBAs below go back beside the edges they are keyed
    // to. Only an edge still in force and still on the canonical moves.
    let resourced: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         UPDATE edges SET source_id = $2
          WHERE id = ANY($3) AND source_id = ANY($1) AND source_type = 'claim' AND valid_to IS NULL
         RETURNING id, target_id, relationship, target_type"#,
    )
    .bind(&chain)
    .bind(dup_uuid)
    .bind(&record.resourced_edges)
    .fetch_all(&mut *conn)
    .await?;
    let done: Vec<Uuid> = resourced.iter().map(|r| r.0).collect();
    note_drift(&record.resourced_edges, &done, &mut drifted);
    out.resourced_back = resourced
        .into_iter()
        .filter(|(_, _, _, tt)| tt == "claim")
        .map(|(id, target, rel, _)| (id, target, rel))
        .collect();

    out.retargeted_back = sqlx::query_scalar(
        r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         UPDATE edges SET target_id = $2
          WHERE id = ANY($3) AND target_id = ANY($1) AND target_type = 'claim' AND valid_to IS NULL
         RETURNING id"#,
    )
    .bind(&chain)
    .bind(dup_uuid)
    .bind(&record.retargeted_edges)
    .fetch_all(&mut *conn)
    .await?;
    let done = out.retargeted_back.clone();
    note_drift(&record.retargeted_edges, &done, &mut drifted);

    // The re-pointed edges take back the tenancy they had where the trigger
    // cannot derive it: re-pointed onto a private canonical it re-stamped them
    // private, and re-pointed back onto two PUBLIC endpoints its no-widening
    // arm keeps them so. Only that case is restored. With either endpoint
    // non-public the re-point has already given the edge its endpoints' meet
    // as they are NOW, and a recorded tenancy could only be wider.
    let repointed: Vec<Uuid> = out
        .retargeted_back
        .iter()
        .copied()
        .chain(out.resourced_back.iter().map(|(id, _, _)| *id))
        .collect();
    if !repointed.is_empty() && !record.edge_tenancy.is_empty() {
        let tenancy =
            serde_json::to_value(&record.edge_tenancy).map_err(|e| DbError::InvalidData {
                reason: format!("revert record: {e}"),
            })?;
        sqlx::query(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             UPDATE edges e
                SET owner_group_id = r.owner_group_id,
                    visibility = r.visibility,
                    co_owner_group_id = r.co_owner_group_id
               FROM jsonb_to_recordset($1)
                    AS r(id uuid, owner_group_id uuid, visibility text, co_owner_group_id uuid)
              WHERE e.id = r.id AND e.id = ANY($2)
                AND e.source_type = 'claim' AND e.target_type = 'claim'
                AND EXISTS (SELECT 1 FROM claims s
                             WHERE s.id = e.source_id AND s.visibility::text = 'public')
                AND EXISTS (SELECT 1 FROM claims t
                             WHERE t.id = e.target_id AND t.visibility::text = 'public')
                AND (e.owner_group_id, e.visibility::text, e.co_owner_group_id)
                    IS DISTINCT FROM (r.owner_group_id, r.visibility, r.co_owner_group_id)"#,
        )
        .bind(&tenancy)
        .bind(&repointed)
        .execute(&mut *conn)
        .await?;
    }

    // Only an edge still retracted BY THE REPAIR (its exact stamp) and still
    // touching the duplicate comes back; any other retraction is a later
    // decision this un-mark has no record of.
    out.unretracted_edges = match record.retracted_at {
        Some(at) => {
            sqlx::query_scalar(
                r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
                 UPDATE edges SET valid_to = NULL
                  WHERE id = ANY($1) AND valid_to = $2
                    AND (source_id = $3 OR target_id = $3)
                 RETURNING id"#,
            )
            .bind(&record.retracted_edges)
            .bind(at)
            .bind(dup_uuid)
            .fetch_all(&mut *conn)
            .await?
        }
        None => Vec::new(),
    };
    let done = out.unretracted_edges.clone();
    note_drift(&record.retracted_edges, &done, &mut drifted);

    // The BP factor graph. Retiring the duplicate deleted every factor naming
    // it (`claims_deactivate_factors`), and the edges came back above by
    // UPDATE, which `edges_auto_factor` (INSERT only) never sees. A factor
    // keyed to an edge just moved back off the canonical names the canonical
    // (one an earlier un-mark in a chain minted there) and is stale; it goes
    // first, and the `(type, pair)` slots it held on the canonical are kept.
    // Then the duplicate's edges are re-minted, and on the canonical only
    // those freed slots: the un-mark leaves every other canonical factor as
    // it found it. Two statements, not one data-modifying CTE: in one
    // statement the INSERT's ON CONFLICT would still see the rows being
    // deleted and leave the freed slot empty.
    let moved_back: Vec<String> = out
        .retargeted_back
        .iter()
        .copied()
        .chain(out.resourced_back.iter().map(|(id, _, _)| *id))
        .map(|id| id.to_string())
        .collect();
    let freed_slots: Vec<String> = if moved_back.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             DELETE FROM factors f
              WHERE f.variable_ids @> ARRAY[$1]::uuid[]
                AND f.properties->>'source_edge_id' = ANY($2)
             RETURNING f.factor_type || ':' || array_to_string(f.variable_ids, ',')"#,
        )
        .bind(head_uuid)
        .bind(&moved_back)
        .fetch_all(&mut *conn)
        .await?
    };
    sqlx::query(REGENERATE_EDGE_FACTORS_SQL)
        .bind(dup_uuid)
        .bind(head_uuid)
        .bind(&freed_slots)
        .bind(None::<Vec<Uuid>>)
        .execute(&mut *conn)
        .await?;

    // BBAs moved onto the canonical go back with their old tenancy while the
    // duplicate is still public (its audience then is what it was); on a
    // duplicate that has since gone non-public a row becomes the claim's own,
    // as every derived row of a private claim is, and is never left public. A
    // returning input's slot on the duplicate may since hold the duplicate's
    // re-derived CACHED combination (the cascade recomputed it); that row is
    // derived and is cleared so the input can return. Any other occupant of
    // the slot is a later write: the row stays where it is (drifted).
    let moved_ids: Vec<Uuid> = record.moved_bbas.iter().map(|m| m.id).collect();
    let moved_json =
        serde_json::to_value(&record.moved_bbas).map_err(|e| DbError::InvalidData {
            reason: format!("revert record: {e}"),
        })?;
    if !moved_ids.is_empty() {
        out.cleared_cached_rows = sqlx::query(&format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             DELETE FROM mass_functions k
              USING mass_functions m
              WHERE k.claim_id = $2 AND {}
                AND m.id = ANY($3) AND m.claim_id = ANY($1)
                AND m.frame_id = k.frame_id
                AND m.source_agent_id IS NOT DISTINCT FROM k.source_agent_id
                AND m.perspective_id IS NOT DISTINCT FROM k.perspective_id"#,
            crate::repos::mass_function::cached_combination_predicate("k.")
        ))
        .bind(&chain)
        .bind(dup_uuid)
        .bind(&moved_ids)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        out.returned_bbas = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             UPDATE mass_functions mf
                SET claim_id = $2,
                    owner_group_id = CASE WHEN d.visibility::text = 'public'
                                          THEN r.owner_group_id ELSE d.owner_group_id END,
                    visibility = CASE WHEN d.visibility::text = 'public'
                                      THEN r.visibility ELSE d.visibility END,
                    writer_owned = CASE WHEN d.visibility::text = 'public'
                                        THEN r.writer_owned ELSE false END
               FROM jsonb_to_recordset($3)
                    AS r(id uuid, owner_group_id uuid, visibility text, writer_owned boolean),
                    claims d
              WHERE d.id = $2 AND mf.id = r.id AND mf.claim_id = ANY($1)
                AND NOT EXISTS (SELECT 1 FROM mass_functions k
                                 WHERE k.claim_id = $2 AND k.frame_id = mf.frame_id
                                   AND k.source_agent_id IS NOT DISTINCT FROM mf.source_agent_id
                                   AND k.perspective_id IS NOT DISTINCT FROM mf.perspective_id)
             RETURNING mf.id"#,
        )
        .bind(&chain)
        .bind(dup_uuid)
        .bind(&moved_json)
        .fetch_all(&mut *conn)
        .await?;
        let done = out.returned_bbas.clone();
        note_drift(&moved_ids, &done, &mut drifted);
    }

    // BBAs the repair deleted come back whole (same id, same tenancy), but
    // only beside an edge that is in force again: every one of them is keyed
    // to an edge, and a BBA on a retracted edge is exactly the orphan the
    // repair exists to prevent. One whose id or key is taken again is a later
    // write's and is skipped.
    if !record.deleted_bbas.is_empty() {
        let deleted = serde_json::Value::Array(record.deleted_bbas.clone());
        let asked: Vec<Uuid> = record
            .deleted_bbas
            .iter()
            .filter_map(|r| {
                r.get("id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .collect();
        out.restored_bbas = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             INSERT INTO mass_functions
             SELECT r.* FROM jsonb_populate_recordset(NULL::mass_functions, $1) r
              WHERE EXISTS (SELECT 1 FROM edges e
                             WHERE e.id = r.perspective_id AND e.valid_to IS NULL)
                -- Every row the record names must still be insertable: its
                -- claim, frame, perspective, agent and evidence still exist.
                -- One that is not is reported drifted, never fatal.
                AND EXISTS (SELECT 1 FROM claims c WHERE c.id = r.claim_id)
                AND EXISTS (SELECT 1 FROM frames f WHERE f.id = r.frame_id)
                AND EXISTS (SELECT 1 FROM perspectives p WHERE p.id = r.perspective_id)
                AND (r.source_agent_id IS NULL
                     OR EXISTS (SELECT 1 FROM agents a WHERE a.id = r.source_agent_id))
                AND (r.evidence_id IS NULL
                     OR EXISTS (SELECT 1 FROM evidence ev WHERE ev.id = r.evidence_id))
             ON CONFLICT DO NOTHING
             RETURNING id"#,
        )
        .bind(&deleted)
        .fetch_all(&mut *conn)
        .await?;
        // An INSERT re-derives tenancy from the claim (migrations 070, 114);
        // the restored row takes back what it had while its claim is still
        // public, and otherwise keeps the claim's own (never a public row on a
        // claim that went private since).
        sqlx::query(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             UPDATE mass_functions mf
                SET owner_group_id = r.owner_group_id,
                    visibility = r.visibility,
                    writer_owned = r.writer_owned
               FROM jsonb_populate_recordset(NULL::mass_functions, $1) r, claims c
              WHERE mf.id = r.id AND mf.id = ANY($2)
                AND c.id = mf.claim_id AND c.visibility::text = 'public'
                AND (mf.owner_group_id, mf.visibility, mf.writer_owned)
                    IS DISTINCT FROM (r.owner_group_id, r.visibility, r.writer_owned)"#,
        )
        .bind(&deleted)
        .bind(&out.restored_bbas)
        .execute(&mut *conn)
        .await?;
        let done = out.restored_bbas.clone();
        note_drift(&asked, &done, &mut drifted);
    }

    // The frame bindings the repair added go, unless the canonical has since
    // gained an input on that frame (one it did not hold when it was bound and
    // that is not on its way back to the duplicate above).
    if !record.copied_frames.is_empty() {
        out.unbound_frames = sqlx::query_scalar(&format!(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             DELETE FROM claim_frames cf
              WHERE cf.claim_id = $1 AND cf.frame_id = ANY($2)
                AND NOT EXISTS (SELECT 1 FROM mass_functions mf
                                 WHERE mf.claim_id = $1 AND mf.frame_id = cf.frame_id
                                   AND NOT {}
                                   AND NOT (mf.id = ANY($3)))
             RETURNING cf.frame_id"#,
            crate::repos::mass_function::cached_combination_predicate("mf.")
        ))
        .bind(canon_uuid)
        .bind(&record.copied_frames)
        .bind(&record.canonical_frame_inputs)
        .fetch_all(&mut *conn)
        .await?;
        let done = out.unbound_frames.clone();
        note_drift(&record.copied_frames, &done, &mut drifted);
    }

    // Claims whose BBA set changed: the duplicate, every claim of the chain,
    // and every far-end claim a restored BBA landed on.
    let mut stale = vec![dup_uuid];
    for c in &chain {
        if !stale.contains(c) {
            stale.push(*c);
        }
    }
    if !out.restored_bbas.is_empty() {
        let targets: Vec<Uuid> = sqlx::query_scalar(
            r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
             SELECT DISTINCT claim_id FROM mass_functions WHERE id = ANY($1)"#,
        )
        .bind(&out.restored_bbas)
        .fetch_all(&mut *conn)
        .await?;
        for t in targets {
            if !stale.contains(&t) {
                stale.push(t);
            }
        }
    }
    out.stale_claims = stale;
    drifted.sort_unstable();
    drifted.dedup();
    out.drifted = drifted;
    Ok(out)
}

/// The INSERT minting the BP factors `edges_auto_factor` would mint, as if
/// each edge were inserted now, for every in-force claim-claim edge whose
/// endpoints are both current and that either touches the claim `$1` or
/// touches the claim `$2` in a `(factor_type, pair)` slot listed in `$3`
/// (as `type:lo,hi`), and, when `$4` (`uuid[]`) is not NULL, is one of the
/// edges it lists. Both dedup directions move edges by UPDATE, which that
/// INSERT trigger never sees:
///
/// * the un-mark puts edges back onto a claim made current again: `$1` is the
///   duplicate, `$2` its canonical, `$3` the slots the stale-factor DELETE
///   freed there, `$4` NULL;
/// * the mark's repair ([`repair_marked_duplicate`]) re-points the retired
///   duplicate's edges onto the canonical, whose factors the retirement
///   deleted (`claims_deactivate_factors`): `$1` and `$2` are the canonical,
///   `$3` empty and `$4` the edges it moved, so only those are minted and a
///   canonical edge whose factor something else removed stays without one.
///
/// It is the body of migration 038's `auto_create_factor_from_edge`, over a
/// set, and must stay that: a migration that changes the trigger's mapping,
/// potentials, description or properties changes this too (the
/// `unmark_duplicate` tests compare the re-minted rows with the trigger's).
/// Like the trigger it mints `decomposes_to` factors, on the duplicate's
/// edges. A dedup identity edge is skipped (the act writes it after retiring
/// the duplicate, so it never had one). One factor per `(factor_type, pair)`,
/// from the earliest edge, and an existing one is kept
/// (`idx_factors_type_vars_frame`), as the trigger's `ON CONFLICT DO NOTHING`.
const REGENERATE_EDGE_FACTORS_SQL: &str = r#"-- VISIBILITY-EXEMPT: WRITE path, on the privileged maintenance connection.
         INSERT INTO factors (factor_type, variable_ids, potential, description, properties)
         SELECT DISTINCT ON (x.ft, x.var_ids) x.ft, x.var_ids, x.pot, x.descr, x.props
           FROM (
             SELECT e.id, e.created_at, m.ft, (e.source_id = $1 OR e.target_id = $1) AS on_dup,
                    CASE WHEN e.source_id < e.target_id
                         THEN ARRAY[e.source_id, e.target_id]
                         ELSE ARRAY[e.target_id, e.source_id] END AS var_ids,
                    CASE WHEN m.ft = 'mutual_exclusion' THEN '{}'::jsonb
                         WHEN m.ft = 'directional_support' THEN jsonb_build_object(
                              'forward_strength', m.fwd, 'reverse_strength', m.rev,
                              'source_var', e.source_id::text)
                         ELSE jsonb_build_object('strength', m.fwd) END AS pot,
                    format('Auto-generated from %s edge %s', e.relationship, e.id) AS descr,
                    jsonb_build_object('source_edge_id', e.id, 'relationship', e.relationship,
                                       'edge_source_id', e.source_id,
                                       'edge_target_id', e.target_id) AS props
               FROM edges e
               JOIN claims s ON s.id = e.source_id
               JOIN claims t ON t.id = e.target_id
               CROSS JOIN LATERAL edge_to_factor_type(e.relationship) ft
               -- 038's override: a cross-source matcher's evidential_support
               -- edge carries its own strength in properties.score, clamped
               -- to [0, 1]. The trigger casts it at INSERT; properties can be
               -- patched since, so a score that is not a decimal number falls
               -- back to the constant (as a missing one does) instead of
               -- failing the whole un-mark. The exponent is bounded to three
               -- digits so the numeric cast itself cannot overflow (numeric_in
               -- raises on e.g. "1e999999"); clamped as numeric, then cast, so
               -- a large in-range exponent cannot overflow the double either.
               CROSS JOIN LATERAL (
                 SELECT ft.factor_type AS ft,
                        COALESCE(ms.score, ft.forward_strength) AS fwd,
                        COALESCE(ms.score, ft.reverse_strength) AS rev
                   FROM (SELECT CASE WHEN ft.factor_type = 'evidential_support'
                                      AND e.properties ? 'source'
                                      AND e.properties->>'source' = 'cross_source_matcher'
                                      AND e.properties ? 'score'
                                      AND e.properties->>'score'
                                          ~ '^\s*[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]{1,3})?\s*$'
                                     THEN GREATEST(0.0, LEAST(1.0,
                                              (e.properties->>'score')::numeric))::double precision
                                END AS score) ms
               ) m
              WHERE e.source_type = 'claim' AND e.target_type = 'claim'
                -- `EDGE_IN_FORCE` (`repos::edge`), inlined into a const.
                AND (e.valid_to IS NULL OR e.valid_to > now())
                AND (e.source_id IN ($1, $2) OR e.target_id IN ($1, $2))
                AND ($4::uuid[] IS NULL OR e.id = ANY($4::uuid[]))
                AND NOT (e.relationship = 'same_as' AND e.properties ? 'dedup')
                AND COALESCE(s.is_current, true) AND COALESCE(t.is_current, true)
                AND m.ft IS NOT NULL
           ) x
          WHERE x.on_dup
             OR (x.ft || ':' || array_to_string(x.var_ids, ',')) = ANY($3)
          ORDER BY x.ft, x.var_ids, x.created_at, x.id
         ON CONFLICT DO NOTHING"#;

/// A BBA on the duplicate (`mf`) that part 3 of the dedup repair pools: not
/// keyed to any edge (those follow their edge, or stay with it), not an
/// `attributed_v1` row, and not a cached combination (the duplicate's own fold
/// of its inputs; folded again on the canonical it would count them twice),
/// and not wider-reaching on the canonical (`$1`) than it is now: a public row
/// pools anywhere, a group's row only onto a non-public canonical of the same
/// group. Otherwise the move would disclose the group's assessment and fold it
/// into a belief a wider audience reads (migration 114's move rule makes a row
/// on a public canonical public). Fully parenthesized: it is spliced after a
/// `NOT`.
fn poolable_bba_sql() -> String {
    format!(
        "((mf.perspective_id IS NULL \
           OR NOT EXISTS (SELECT 1 FROM edges e WHERE e.id = mf.perspective_id)) \
          AND mf.combination_method IS DISTINCT FROM 'attributed_v1' \
          AND NOT {} \
          AND (mf.visibility::text = 'public' \
               OR EXISTS (SELECT 1 FROM claims k \
                           WHERE k.id = $1 AND k.visibility::text <> 'public' \
                             AND k.owner_group_id = mf.owner_group_id)))",
        crate::repos::mass_function::cached_combination_predicate("mf.")
    )
}

/// The canonical (`$1`) already holds a row under the duplicate row `mf`'s
/// `mass_functions_unique_per_perspective` key (migration 034).
const CANONICAL_HOLDS_KEY_SQL: &str = "SELECT 1 FROM mass_functions k \
      WHERE k.claim_id = $1 AND k.frame_id = mf.frame_id \
        AND k.source_agent_id IS NOT DISTINCT FROM mf.source_agent_id \
        AND k.perspective_id IS NOT DISTINCT FROM mf.perspective_id";
