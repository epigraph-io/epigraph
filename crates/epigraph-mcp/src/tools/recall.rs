//! `recall_with_context` MCP tool — paragraph-primary semantic search with
//! batched structural context. See docs/superpowers/specs/2026-05-05-recall-with-context-design.md.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Fraction of level-2 paragraphs carrying a 3072-d embedding, viewer-scoped.
///
/// PR-09: took a bare pool. The ratio itself is not the disclosure — the
/// denominator is: `COUNT(*) FROM claims WHERE level = 2` told any caller the
/// exact paragraph population of the whole corpus, and the result is surfaced
/// through `recall_with_context`'s `corpus_scope`. Scoped, both counts are the
/// reader's own, and the auto-detect decision is made on the corpus the reader
/// will actually search — which is also the more correct answer.
pub async fn paragraph_3072_population(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<f64, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE c.embedding_3072 IS NOT NULL)::float8
              / NULLIF(COUNT(*), 0)::float8 AS frac_3072
        FROM claims c
        WHERE (c.properties->>'level')::int = 2
          AND ($1::bool OR c.visibility = 'public'
               OR c.owner_group_id = ANY($2::uuid[]))
        "#,
        viewer.bypass_bind(),
        viewer.group_bind().unwrap_or(&[])
    )
    .fetch_one(pool)
    .await?;
    Ok(row.frac_3072.unwrap_or(0.0))
}

async fn detect_centroid_dim(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<u32, sqlx::Error> {
    let frac = paragraph_3072_population(pool, viewer).await?;
    Ok(if frac >= 0.5 { 3072 } else { 1536 })
}

/// Corpus cardinality reported alongside every `recall_with_context` response.
///
/// PR-09: three of the four counts are viewer-scoped. `papers` and
/// `claim_themes` are NOT in migration 062's `tier_a` array and have no
/// `owner_group_id`, so there is nothing to filter on; `claim_themes` is the
/// table plan §2.4 registers as `tenancy_exempt` with theme clustering as its
/// control. Both are annotated in the SQL rather than left silent.
async fn compute_corpus_scope(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
) -> Result<CorpusScope, sqlx::Error> {
    // Per spec §3.1 / Locked-in 5.5: corpus_scope always populated on success.
    // One round-trip with subselects to avoid four separate COUNT queries.
    let row = sqlx::query!(
        r#"
        SELECT
          (SELECT COUNT(*) FROM claims c
             WHERE ($1::bool OR c.visibility = 'public'
                    OR c.owner_group_id = ANY($2::uuid[]))) AS claims_total,
          (SELECT COUNT(*) FROM claims c2
             WHERE (c2.properties->>'level')::int = 2
               AND ($1::bool OR c2.visibility = 'public'
                    OR c2.owner_group_id = ANY($2::uuid[]))) AS paragraph_total,
          -- VISIBILITY-EXEMPT: `papers` is not in migration 062's tier_a array
          -- and carries no owner_group_id. A bibliographic-record count, not
          -- claim content.
          (SELECT COUNT(*) FROM papers) AS paper_total,
          -- VISIBILITY-EXEMPT: `claim_themes` is the table plan §2.4 registers
          -- as tenancy_exempt; it has no owner_group_id either, so no predicate
          -- can be written here.
          --
          -- §2.4's stated control for that residual is viewer-scoped
          -- clustering, and PR-09 DID NOT SHIP IT. `theme_cluster` still calls
          -- `epigraph_engine::theme_kmeans::run_theme_kmeans`, which takes no
          -- Viewer. An earlier revision of this comment asserted the control as
          -- if it existed; an exemption whose written reason is false is worse
          -- than an unannotated one, because `visibility_lint.rs` trains
          -- reviewers to read exactly these lines.
          --
          -- Owner of the residual: the PR that threads a Viewer through
          -- `theme_kmeans::run_theme_kmeans` must land BOTH callers together —
          -- this tool and `epigraph-api/src/routes/crud.rs::build_themes_from_corpus`
          -- — or MCP hardens while HTTP stays corpus-wide. Ledgered as
          -- D-PR16-theme-cluster-viewer-scope in docs/tenancy/progress.json.
          (SELECT COUNT(*) FROM claim_themes) AS themes_total
        "#,
        viewer.bypass_bind(),
        viewer.group_bind().unwrap_or(&[])
    )
    .fetch_one(pool)
    .await?;
    Ok(CorpusScope {
        claims_total: row.claims_total.unwrap_or(0).max(0) as usize,
        paragraph_total: row.paragraph_total.unwrap_or(0).max(0) as usize,
        paper_total: row.paper_total.unwrap_or(0).max(0) as usize,
        themes_total: row.themes_total.unwrap_or(0).max(0) as usize,
    })
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RecallWithContextParams {
    pub query: String,
    pub limit: Option<u32>,
    pub min_truth: Option<f64>,
    pub centroid_dim: Option<u32>,
    pub paper_doi_filter: Option<String>,
    pub siblings_limit: Option<u32>,
    pub corroborates_limit: Option<u32>,
    /// Max epistemic-edge neighbours returned **per relationship** per hit
    /// (supports / refutes / contradicts / specializes / elaborates / cites).
    /// Default 4. Per-relationship rather than per-hit so a claim with many
    /// `supports` edges cannot crowd out its single `refutes`.
    pub epistemic_limit: Option<u32>,
    pub neighbor_paragraphs_limit: Option<u32>,
    /// When `true`, run the diverse retrieval pipeline before structural
    /// enrichment: pull candidates from the most-similar themes and use
    /// submodular [`diverse_select`] to spread the selection across the
    /// theme graph. Mirrors `POST /api/v1/search/semantic?diverse=true`.
    /// Default `false` (existing flat ANN behaviour).
    ///
    /// Falls back to flat ANN if the corpus has no themes yet.
    ///
    /// [`diverse_select`]: epigraph_engine::diverse_select::diverse_select
    pub diverse: Option<bool>,
    /// Max number of themes to consider in diverse mode. Default 5.
    /// Ignored when `diverse=false`.
    pub max_themes: Option<u32>,
    /// Coverage vs relevance tradeoff for diverse mode. `0.0` = pure
    /// relevance, `1.0` = pure coverage. Default `0.4`. Ignored when
    /// `diverse=false`.
    pub diversity_weight: Option<f32>,
    /// Candidate-pool top-K — the second-stage cutoff after theme
    /// selection. The diverse pipeline first picks the `max_themes`
    /// most-similar themes, then pulls up to this many paragraphs from
    /// them as input to submodular `diverse_select`. Bigger pool =
    /// finer cluster granularity reaches retrieval, at the cost of more
    /// SQL work and a quadratic in-memory similarity matrix.
    ///
    /// Default is
    /// [`DEFAULT_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::DEFAULT_CANDIDATE_POOL)
    /// (100). Clamped to
    /// [`MAX_CANDIDATE_POOL`](epigraph_engine::diverse_retrieval::MAX_CANDIDATE_POOL)
    /// (1000) to keep the matrix bounded. Ignored when `diverse=false`.
    pub candidate_pool: Option<u32>,
    /// When `true`, widen the flat-ANN candidate pool and re-rank it with a
    /// cross-encoder before structural enrichment. Degrades to plain flat ANN
    /// (a warn, not an error) when no `RERANK_API_KEY` is configured. Default
    /// `false`. Independent of `diverse`; if both set, rerank runs on the
    /// diverse selection's output.
    pub rerank: Option<bool>,
    /// Pool-widening multiplier for `rerank`. Final pool = `limit *
    /// rerank_pool_factor`, clamped to `[limit, 200]`. Default 5. Ignored when
    /// `rerank=false`.
    pub rerank_pool_factor: Option<u32>,
    /// When `true` (and `rerank=true`), run the MiniCheck-style groundedness
    /// gate and DROP passages judged ungrounded. Requires a registered
    /// `LlmProvider`; degrades to annotate-only when none is active. Default
    /// `false`.
    pub groundedness_gate: Option<bool>,
    /// Optional lens frame UUID (from `list_frames`). Must be paired with
    /// `perspective_id`. When both are set, each returned hit carries an
    /// additive `lensed_belief` computed under that `(frame, perspective)` lens;
    /// retrieval, rerank, and `min_truth` stay on the global `truth_value`.
    pub frame_id: Option<String>,
    /// Optional lens perspective UUID (from `list_perspectives`). Must be paired
    /// with `frame_id`. The perspective's source/locality reliability re-weights
    /// each hit's BBAs on-read.
    pub perspective_id: Option<String>,
    /// When set, after the normal ANN seed retrieval, follow outgoing
    /// supports/corroborates/elaborates edges up to this many hops from each
    /// ANN seed and fold the reached claims into the candidate pool (deduped
    /// against the seeds), reranked by
    /// `similarity * (1 + 0.1 * in_epistemic_degree)` before the usual
    /// `min_truth`/context-enrichment pipeline runs. `None` (the default)
    /// preserves today's flat-ANN-only behaviour byte-for-byte. Clamped to
    /// `[1, 4]` to match the `traverse` MCP tool's depth bound. Composes with
    /// `diverse`/`rerank` — expansion runs on whichever seed pool those
    /// stages already produced.
    pub graph_expansion_depth: Option<u32>,
    /// When `true`, drop hits that are actively contested (any `is_current`
    /// claim `contradicts`/`refutes` them). Applied AFTER ranking and context
    /// enrichment, so a page may come back short rather than back-filling with
    /// worse-ranked material. Default `false`: contested hits are returned,
    /// annotated with `dispute_count` / `is_contested` / `contesting_claim_ids`.
    #[serde(default)]
    pub exclude_contested: bool,
    /// Optional RFC3339 creation-time window. When set, the candidate pool on
    /// EVERY retrieval surface — flat ANN, the diverse/theme pipeline, and
    /// graph expansion — is narrowed to claims with
    /// `created_at >= since`, in SQL, before each surface's `LIMIT`, so no
    /// hit older than `since` can reach the caller on any path.
    ///
    /// **Completeness caveat on `diverse=true`.** The theme *shortlist* is
    /// chosen by centroid similarity before the window is applied, so a theme
    /// holding only pre-window claims still consumes one of `max_themes`
    /// slots and the page can come back SHORT of `limit`. Nothing pre-window
    /// leaks; the result may just be less complete than an unwindowed diverse
    /// call would suggest. Set `diverse=false` for a windowed query that must
    /// be exhaustive.
    ///
    /// **Boundary: the window constrains top-level HITS, not their CONTEXT.**
    /// `atoms`, `siblings`, `corroborates`, `neighbor_paragraphs`, `section`
    /// and `paper` are deliberately NOT filtered. A two-year-old supporting
    /// paragraph is legitimate evidence for a claim created yesterday;
    /// dropping it would remove the caller's ability to see *why* a recent
    /// hit is believed, which is the opposite of what this parameter is for.
    /// "What changed since T" is a question about hits; the reasons a hit is
    /// believed are older than the change by construction.
    ///
    /// Filters on creation time, never `updated_at` — belief recomputation
    /// rewrites `updated_at` without changing content. Default: no window,
    /// and no window is ever applied implicitly.
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    /// When `true`, REPLACE the flat `results` array with an
    /// `epistemic_partition` object grouping the same hits into `confirmed`
    /// (`truth_value >= 0.75` and not contested), `open_question`
    /// (`is_contested` — any live `contradicts`/`refutes`), and `uncertain`
    /// (everything else). Contest is checked FIRST, so a high-truth paragraph
    /// carrying a live refutation is reported as an open question rather than
    /// as confirmed.
    ///
    /// Ranking is UNCHANGED: each bucket keeps the order the flat list would
    /// have had, and the union of the three buckets is exactly the flat list.
    /// This regroups the page; it does not filter or re-rank it, and it runs
    /// after every other post-filter (`min_truth`, `exclude_contested`), so
    /// the returned SET is identical with and without it.
    ///
    /// `results` is OMITTED when this is true. Default `false`: output is
    /// byte-identical to `recall_with_context` without this parameter.
    #[serde(default)]
    pub epistemic_partition: bool,
    /// Optional intra-result diversity constraint, as a COSINE DISTANCE in
    /// `(0.0, 2.0]`. When set, a greedy MMR pass walks the ranked page
    /// top-down and DROPS any hit sitting closer than this to a hit already
    /// kept above it, so a query cannot come back as ten paraphrases of one
    /// paragraph. `0.15` is a reasonable starting value.
    ///
    /// Measured in the SAME vector space the retrieval used — whichever of
    /// `claims.embedding` / `claims.embedding_3072` `centroid_dim_used` names.
    /// Comparing a 3072-retrieved page against the 1536 column would measure
    /// vectors that were never comparable.
    ///
    /// SHRINKS the page rather than back-filling: with `rerank=false` the
    /// candidate pool is exactly `limit`, so there is nothing below to promote.
    /// Same contract as `min_truth` / `exclude_contested`.
    ///
    /// Hits whose distance cannot be MEASURED are always KEPT — a paragraph
    /// with no vector in the searched column is not known to be near anything.
    ///
    /// Runs LAST, after `min_truth`, `exclude_contested` and the
    /// missing-paper-attribution drop, so only a hit that is ITSELF being
    /// returned can suppress another. Ordering it earlier would let a paragraph
    /// those filters are about to discard evict its surviving near-duplicate on
    /// the way out — which makes switching on a de-duplication filter DELETE a
    /// hit rather than merely de-duplicate.
    ///
    /// A value outside the range is REJECTED, not clamped. Default: no
    /// diversity filtering.
    #[serde(default)]
    pub diversity_radius: Option<f64>,
}

/// Why a recall audit row has no owner — and therefore must not be written.
///
/// **Every variant is a DROP, and that is the whole point of the type.** It has
/// no shape meaning "write it instance-wide", so the widening is unreachable
/// from a caller that handles the failure sloppily. The earlier spelling —
/// `Result<Option<Uuid>, DbError>` — did have such a shape: `Ok(None)` selected
/// `TenancyDecl::instance_wide()`, and a caller that reached it through an
/// `.ok()` on a fallible identity lookup turned a transient failure into a
/// world-readable row carrying the querying agent's raw query text. The `Err`
/// arm failed closed and the `None` arm failed open; only the type can keep
/// those from drifting apart again.
///
/// A retrieval that is not audited is recoverable from the request log; a
/// disclosure is not.
///
/// Shared by both MCP recall surfaces so the rule has one spelling.
#[derive(Debug)]
pub(crate) enum AuditOwnerUnresolved {
    /// The surface produced no principal at all. On the MCP transports this is
    /// a bypass viewer, which `request_viewer` never returns — so it is a
    /// defensive arm, and it drops rather than widening for the same reason the
    /// lookup failure does.
    NoPrincipal,
    /// There IS a principal and its personal group could not be resolved.
    Lookup(epigraph_db::DbError),
}

impl std::fmt::Display for AuditOwnerUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPrincipal => f.write_str("the call carried no principal"),
            Self::Lookup(e) => write!(f, "the principal's personal group could not be read: {e}"),
        }
    }
}

/// The group that will own a recall audit row: **the request principal's**
/// personal group.
///
/// `principal` is [`Viewer::principal`](epigraph_db::Viewer::principal), not
/// `EpiGraphMcpFull::agent_id`, and the distinction is the security property.
/// `agent_id` resolves the agent for the *signer's public key* — one agent per
/// process — while `get_recall_events` filters with the viewer built from the
/// *per-request* `AuthContext`. On stdio the two are the same value. On the
/// HTTP transport they are not, and owning the row from the process identity
/// would both misattribute it and suppress it from the agent that authored it.
///
/// # Errors
/// [`AuditOwnerUnresolved`] — see that type: every variant means drop the row.
pub(crate) async fn recall_audit_owner_group(
    pool: &sqlx::PgPool,
    principal: Option<Uuid>,
) -> Result<Uuid, AuditOwnerUnresolved> {
    let principal = principal.ok_or(AuditOwnerUnresolved::NoPrincipal)?;
    epigraph_db::ClaimRepository::personal_group_of_pool(pool, principal)
        .await
        .map_err(AuditOwnerUnresolved::Lookup)
}

/// Spawn the fire-and-forget recall audit write (backlog 8cbffa0e).
///
/// Shared by the empty-result early return and the main path so the two
/// cannot drift. A zero-result recall is deliberately logged too: "this query
/// returned nothing at that time" is exactly the kind of claim an audit needs
/// to be able to settle.
///
/// The id is minted by the caller rather than read back from the insert,
/// because the write is not awaited.
fn spawn_recall_audit(
    server: &EpiGraphMcpFull,
    event_id: Uuid,
    principal: Option<Uuid>,
    query: &str,
    pgvec: &str,
    params_json: serde_json::Value,
    returned_claim_ids: Vec<Uuid>,
) {
    let query = query.to_string();
    let pgvec = pgvec.to_string();
    let pool = server.pool.clone();
    tokio::spawn(async move {
        // Resolved inside the spawn: everything this needs is an owned `Uuid`,
        // so nothing here borrows the request, and the group lookup — a pool
        // acquire, a SELECT, and on an agent's first recall a personal-group
        // mint — stays off the response path. `058_recall_events.sql`'s own
        // table comment is the contract: "never blocks a recall".
        let owner_group_id = match recall_audit_owner_group(&pool, principal).await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    reason = %e,
                    "recall_with_context audit skipped rather than widened"
                );
                return;
            }
        };
        let event = epigraph_db::NewRecallEvent {
            id: event_id,
            // The REQUEST principal, not the process identity. See
            // `recall_audit_owner_group`.
            agent_id: principal,
            tool: "recall_with_context".to_string(),
            query_text: query,
            query_pgvector: Some(pgvec),
            params: params_json,
            returned_claim_ids,
            owner_group_id: Some(owner_group_id),
        };
        if let Err(e) = epigraph_db::RecallEventRepository::log(&pool, event).await {
            tracing::warn!(error = %e, "recall_with_context audit log failed; recall unaffected");
        }
    });
}

#[derive(Debug, Clone, Serialize)]
pub struct RecallWithContextResponse {
    /// The flat ranked page. `None` — and therefore absent from the JSON —
    /// exactly when `epistemic_partition=true` replaced it with the bucketed
    /// shape below. `Some(vec![])` still serializes as `"results": []`, so a
    /// zero-hit recall is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<RecallHit>>,
    /// The same page regrouped by epistemic status (backlog e7736ff6).
    /// Present only when the caller asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epistemic_partition: Option<crate::types::EpistemicPartition<RecallHit>>,
    pub corpus_scope: CorpusScope,
    pub centroid_dim_used: u32,
    /// Id of the audit row logged for this retrieval (backlog 8cbffa0e), so a
    /// caller can cite which recall fed a downstream decision. Omitted when
    /// the audit write was not attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recall_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecallHit {
    pub paragraph_id: Uuid,
    pub paragraph_content: String,
    pub similarity: f64,
    /// Cross-encoder relevance score; `None` when rerank was off/skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rerank_score: Option<f64>,
    /// Groundedness verdict (`"grounded"`/`"ungrounded"`); `None` when the gate
    /// was off/skipped. Surfaced alongside, NOT instead of, belief/truth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<epigraph_engine::rerank::Groundedness>,
    /// Per-hit belief under the requested `(frame, perspective)` lens. Present
    /// only when a lens was supplied; omitted (not null) otherwise so a
    /// lens-free recall is byte-identical to today. Surfaced ALONGSIDE the
    /// global `truth_value`, not instead of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lensed_belief: Option<crate::types::LensedBelief>,
    pub truth_value: f64,
    pub paper: PaperMeta,
    pub section: Option<SectionMeta>,
    pub atoms: Vec<AtomChild>,
    pub atoms_total: usize,
    pub atoms_truncated: bool,
    pub siblings: Vec<SiblingParagraph>,
    pub siblings_total: usize,
    pub siblings_truncated: bool,
    pub corroborates: Vec<CorroboratesEdge>,
    pub corroborates_total: usize,
    pub corroborates_truncated: bool,
    pub neighbor_paragraphs: Vec<NeighborParagraph>,
    pub neighbor_paragraphs_total: usize,
    pub neighbor_paragraphs_truncated: bool,
    /// Number of `is_current` claims contesting this paragraph via
    /// `contradicts`/`refutes` (backlog 34d3400d). `0` when uncontested.
    /// Uncapped, unlike `contesting_claim_ids`.
    #[serde(skip_serializing_if = "crate::types::is_zero_u32")]
    pub dispute_count: u32,
    /// `true` iff `dispute_count > 0`. Surfaced ALONGSIDE `truth_value`, not
    /// instead of it — contested means unsettled, not false.
    #[serde(skip_serializing_if = "crate::types::is_false")]
    pub is_contested: bool,
    /// The three strongest contesters (by their own `truth_value`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contesting_claim_ids: Vec<Uuid>,
    /// `claims.created_at` for this paragraph — its creation instant, not
    /// `updated_at` and not the request time. `Option` +
    /// `skip_serializing_if` so an unresolvable row omits the key instead of
    /// reporting a fabricated timestamp.
    ///
    /// Surfaced on every hit whether or not `since` was supplied: the caller
    /// needs the signal to arbitrate between a stale and a current memory
    /// even when it did not ask for a window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaperMeta {
    pub paper_id: Uuid,
    pub doi: Option<String>,
    pub title: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionMeta {
    pub section_id: Uuid,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AtomChild {
    pub atom_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub bridge_to_paragraphs: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiblingParagraph {
    pub paragraph_id: Uuid,
    pub content: String,
    pub truth_value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorroboratesEdge {
    pub claim_id: Uuid,
    pub content: String,
    pub similarity: f64,
    pub paper_doi: Option<String>,
}

/// Epistemic relationship types carried through structural context assembly
/// (in addition to the corroborates edges handled separately above).
///
/// Deliberately excludes `decomposes_to` and `continues_argument`: those are
/// document-skeleton structure, already carried by their own context fields,
/// and counting them here would double-report the skeleton as argument.
const EPISTEMIC_EDGE_RELATIONSHIPS: &[&str] = &[
    "supports",
    "refutes",
    "contradicts",
    "specializes",
    "elaborates",
    "cites",
];

/// Whether a returned epistemic-edge hit is the source or the target of the
/// edge. This matters because e.g. "refutes" read backwards means "is
/// refuted by".
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Serialize)]
pub struct EpistemicEdgeNeighbor {
    pub claim_id: Uuid,
    pub content: String,
    pub relationship: String,
    pub direction: EdgeDirection,
    pub truth_value: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeighborParagraph {
    pub paragraph_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub paper: PaperMeta,
    pub via: Vec<NeighborPath>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NeighborPath {
    ContinuesArgument,
    AtomBridge {
        atom_id: Uuid,
    },
    AtomAtomBridge {
        atom_a: Uuid,
        atom_b: Uuid,
        relationship: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusScope {
    pub claims_total: usize,
    pub paragraph_total: usize,
    pub paper_total: usize,
    pub themes_total: usize,
}

pub async fn recall_with_context(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: RecallWithContextParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let siblings_limit = params.siblings_limit.unwrap_or(8);
    let corroborates_limit = params.corroborates_limit.unwrap_or(4);
    let epistemic_limit = params.epistemic_limit.unwrap_or(4);
    let neighbor_paragraphs_limit = params.neighbor_paragraphs_limit.unwrap_or(16);

    // Stage 1: pick centroid_dim (request hint OR auto-detect via population threshold).
    let centroid_dim = match params.centroid_dim {
        Some(d) if d == 1536 || d == 3072 => d,
        Some(d) => {
            return Err(invalid_params(format!(
                "centroid_dim must be 1536 or 3072 (got {d})"
            )));
        }
        None => detect_centroid_dim(&server.pool, viewer)
            .await
            .map_err(|e| internal_error(format!("auto-detect centroid_dim: {e}")))?,
    };

    // Spec §3.4: explicit 3072 against an unpopulated column must error
    // (otherwise the empty kNN result is indistinguishable from "no relevant paragraphs").
    if matches!(params.centroid_dim, Some(3072)) {
        let frac = paragraph_3072_population(&server.pool, viewer)
            .await
            .map_err(|e| internal_error(format!("3072 population check: {e}")))?;
        if frac == 0.0 {
            return Err(invalid_params(
                "centroid_dim=3072 requested but embedding_3072 has no populated rows on level=2 paragraphs; re-run with centroid_dim=1536 or omit to auto-detect"
                    .to_string(),
            ));
        }
    }

    // Stage 2: embed query at the right model (1536 -> -small, 3072 -> -large).
    let query_embedding = server
        .embedder
        .generate_at_dim(&params.query, centroid_dim)
        .await
        .map_err(|e| internal_error(format!("embed query: {e}")))?;
    let pgvec = crate::embed::format_pgvector(&query_embedding);

    // Resolve + existence-check the optional (frame, perspective) lens ONCE,
    // before the page loop, so a bad lens fails fast and the bounded post-pass
    // never round-trips the repo per claim for existence.
    let lens = crate::tools::lens::resolve_lens(
        params.frame_id.as_deref(),
        params.perspective_id.as_deref(),
    )?;
    if let Some((frame_id, perspective_id)) = lens {
        crate::tools::lens::validate_lens_exists(&server.pool, viewer, frame_id, perspective_id)
            .await?;
    }

    recall_with_context_post_embed(
        server,
        viewer,
        &params,
        centroid_dim,
        &pgvec,
        limit,
        min_truth,
        siblings_limit,
        corroborates_limit,
        epistemic_limit,
        neighbor_paragraphs_limit,
        lens,
    )
    .await
}

/// Weight applied to `in_epistemic_degree` in the graph-expansion rerank
/// formula: `similarity * (1 + GRAPH_EXPANSION_DEGREE_WEIGHT * in_degree)`.
/// Matches the coefficient named in claim 29e789fd's design sketch.
const GRAPH_EXPANSION_DEGREE_WEIGHT: f64 = 0.1;

/// Stage 4 of [`recall_with_context_post_embed`]: fold graph-reachable
/// claims into the ANN seed pool and rerank the combined set.
///
/// 1. BFS up to `depth` hops (clamped `[1,4]`) from every seed in `seeds`,
///    following outgoing supports/corroborates/elaborates edges
///    ([`epigraph_db::EXPANSION_RELATIONSHIPS`]) — the same edge-walk
///    `traverse` does internally, reproduced directly against
///    `ClaimRepository`/`EdgeRepository` rather than round-tripping the MCP
///    tool layer (which only takes a single relationship string and returns
///    a serialized `CallToolResult`).
/// 2. Dedup: a claim already in `seeds` is never added a second time as an
///    expansion hit, even if graph-reachable from another seed.
/// 3. Assign each expanded claim a base "similarity" derived from the
///    HIGHEST-similarity seed in the whole seed set, decayed by the hop
///    count at which BFS first reached the claim
///    (`best_seed_similarity * 0.7^hops`) — expanded claims have no ANN
///    score of their own, and this keeps them rankable alongside direct
///    hits while ranking closer expansions above farther ones. This is a
///    conservative approximation, not a true per-path "closest reaching
///    seed" score: `graph_expand_seeds`' BFS reports hop count from the
///    frontier as a whole, not which specific seed a given path originated
///    from, so the single highest seed similarity is used as an upper bound
///    for every expanded claim rather than tracking per-seed provenance.
/// 4. Rerank the combined (seed ∪ expansion) set by
///    `similarity * (1 + 0.1 * in_epistemic_degree)`, where
///    `in_epistemic_degree` is the claim's in-degree over the full
///    `link_epistemic` allowlist ([`epigraph_db::EPISTEMIC_RELATIONSHIPS`] —
///    all 7 types, not just the 3 traversal types: a claim's authority is a
///    function of everyone who has weighed in on it, including
///    `contradicts`/`refutes`, not only the reinforcing subset), computed in
///    one batched `GROUP BY` query
///    ([`epigraph_db::ClaimRepository::in_epistemic_degree_batch`]) — not
///    one query per claim.
async fn apply_graph_expansion(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    seeds: Vec<epigraph_db::ClaimEmbeddingHit>,
    depth: u32,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<epigraph_db::ClaimEmbeddingHit>, McpError> {
    let seed_ids: Vec<Uuid> = seeds.iter().map(|h| h.claim_id).collect();
    let seed_similarity: std::collections::HashMap<Uuid, f64> =
        seeds.iter().map(|h| (h.claim_id, h.similarity)).collect();

    // Expansion output is folded into `raw_hits`, i.e. into the TOP-LEVEL
    // results — so it is a candidate-producing surface, not a context
    // surface, and every row it contributes must satisfy the window. The
    // walk itself is not pruned (an old claim may bridge to a new one); only
    // the emitted destinations are, and only in-window destinations consume
    // the expansion budget.
    let expansion = epigraph_db::ClaimRepository::graph_expand_seeds_since(
        pool, viewer, &seed_ids, depth, since,
    )
    .await
    .map_err(|e| internal_error(format!("graph expansion traverse: {e}")))?;

    // Best (highest) decayed score per expanded claim, in case it's
    // reachable from more than one seed at different hop counts / seed
    // similarities. graph_expand_seeds already dedupes to each claim's
    // SHORTEST hop count overall, but that shortest path may not originate
    // from the highest-similarity seed, so we still need a max-fold here
    // rather than trusting hop count alone as the tiebreak.
    const HOP_DECAY: f64 = 0.7;
    let mut expanded_similarity: std::collections::HashMap<Uuid, f64> =
        std::collections::HashMap::new();
    for hit in &expansion {
        // graph_expand_seeds reports hops from the frontier as a whole, not
        // per-originating-seed, so approximate the base with the highest
        // seed similarity available — a conservative upper bound that still
        // makes expanded claims rank below their strongest supporting seed
        // once hop decay is applied.
        let best_seed_similarity = seed_similarity.values().cloned().fold(0.0_f64, f64::max);
        let score = best_seed_similarity * HOP_DECAY.powi(hit.hops);
        expanded_similarity
            .entry(hit.claim_id)
            .and_modify(|s| *s = s.max(score))
            .or_insert(score);
    }

    let mut combined = seeds;
    for (claim_id, similarity) in expanded_similarity {
        combined.push(epigraph_db::ClaimEmbeddingHit {
            claim_id,
            similarity,
        });
    }

    if combined.is_empty() {
        return Ok(combined);
    }

    let all_ids: Vec<Uuid> = combined.iter().map(|h| h.claim_id).collect();
    let degree = epigraph_db::ClaimRepository::in_epistemic_degree_batch(pool, viewer, &all_ids)
        .await
        .map_err(|e| internal_error(format!("in_epistemic_degree_batch: {e}")))?;

    combined.sort_by(|a, b| {
        let score = |h: &epigraph_db::ClaimEmbeddingHit| {
            let d = degree.get(&h.claim_id).copied().unwrap_or(0) as f64;
            h.similarity * (1.0 + GRAPH_EXPANSION_DEGREE_WEIGHT * d)
        };
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(combined)
}

/// Post-embedding pipeline: shared by `recall_with_context` and the
/// `__test_only::recall_with_context_with_pgvec` entry point that lets
/// integration tests skip the OpenAI embedder (no API key available in
/// the test environment).
///
/// Consumes a pre-computed pgvector literal and a resolved `centroid_dim`.
#[allow(clippy::too_many_arguments)]
async fn recall_with_context_post_embed(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: &RecallWithContextParams,
    centroid_dim: u32,
    pgvec: &str,
    limit: u32,
    min_truth: f64,
    siblings_limit: u32,
    corroborates_limit: u32,
    epistemic_limit: u32,
    neighbor_paragraphs_limit: u32,
    lens: Option<(Uuid, Uuid)>,
) -> Result<CallToolResult, McpError> {
    // Validated before any retrieval runs, so a mistyped radius is reported
    // instead of being paid for and then discarded. Checked here rather than in
    // the wrapper because `__test_only::recall_with_context_with_pgvec` enters
    // at this function, and a validation the test path skips is a validation
    // the tests cannot pin.
    let diversity_radius = params
        .diversity_radius
        .map(crate::types::validate_diversity_radius)
        .transpose()
        .map_err(invalid_params)?;

    // Stage 3: candidate retrieval. Two paths:
    //
    //  - `diverse=true`: run the shared diverse-retrieval pipeline
    //    (theme lookup → candidate pool → similarity-neighbour graph →
    //    `diverse_select`). Falls back to flat ANN when the corpus has
    //    no themes yet OR when no candidates were found in the selected
    //    themes (matches REST `/api/v1/search/semantic?diverse=true`
    //    behaviour).
    //
    //  - `diverse=false` (default): flat paragraph-primary ANN over
    //    `claims.embedding[_3072]`. Unchanged from pre-diverse behaviour.
    //
    // The `paper_doi_filter` does NOT apply to the diverse path —
    // candidates_in_themes_at_dim has no DOI predicate. If the caller
    // provides BOTH `diverse=true` AND `paper_doi_filter`, the filter is
    // currently ignored on the diverse path. TODO(diverse-recall): wire
    // paper_doi_filter into candidates_in_themes_at_dim or reject the
    // combination at param-parse time.
    let diverse = params.diverse.unwrap_or(false);
    // Stage 3 sizing. When rerank is on, OVER-FETCH the flat candidate pool
    // (`want * pool_factor`, clamped to [want, 200]) so the cross-encoder has a
    // surplus to re-rank before truncation; otherwise fetch exactly `want`.
    // This is the seed's root-cause fix: flat recall previously fetched only
    // `limit`, leaving nothing to re-rank.
    let want = limit as usize;
    let pool = if params.rerank.unwrap_or(false) {
        let factor = params.rerank_pool_factor.unwrap_or(5).max(1) as usize;
        (want.saturating_mul(factor)).clamp(want, 200)
    } else {
        want
    };
    let flat_limit = pool as i64;
    let mut raw_hits = if diverse {
        let max_themes = params.max_themes.unwrap_or(5).clamp(1, 50) as i32;
        let alpha = params.diversity_weight.unwrap_or(0.4);
        // Clamp candidate_pool at the request boundary so the caller sees
        // the value they'll actually get. `build_similarity_neighbors` is
        // O(n²) in candidate count, so MAX_CANDIDATE_POOL keeps the matrix
        // bounded (≤1M entries at 1000) — the user explicitly asked for
        // this lever so finer cluster granularity can reach retrieval.
        let candidate_pool = params
            .candidate_pool
            .map(|n| n.min(epigraph_engine::diverse_retrieval::MAX_CANDIDATE_POOL))
            .map(|n| n as i32)
            .unwrap_or(epigraph_engine::diverse_retrieval::DEFAULT_CANDIDATE_POOL);
        let config = epigraph_engine::diverse_retrieval::DiverseRetrievalConfig {
            centroid_dim,
            max_themes,
            candidate_pool,
            budget: limit as usize,
            alpha,
            // recall_with_context is paragraph-primary; restrict candidates
            // to level=2 so the downstream batched-context fetch (which
            // assumes paragraphs) has nothing to drop.
            paragraph_only: true,
            // The diverse pipeline bypasses `search_by_embedding` entirely,
            // so the window has to reach it here or `diverse=true` would
            // silently ignore `since`.
            since: params.since,
        };
        let selected = epigraph_engine::diverse_retrieval::run_diverse_pipeline(
            &server.pool,
            viewer,
            pgvec,
            config,
        )
        .await
        .map_err(|e| internal_error(format!("diverse retrieval: {e}")))?;

        if selected.is_empty() {
            // No themes (or no candidates in themes) — fall back to flat ANN
            // so callers still get results in a freshly-clustered or
            // unclustered corpus. Matches the REST diverse-mode fallback.
            epigraph_db::ClaimRepository::search_by_embedding_since(
                &server.pool,
                viewer,
                pgvec,
                centroid_dim,
                flat_limit,
                params.paper_doi_filter.as_deref(),
                params.since,
            )
            .await
            .map_err(|e| internal_error(format!("kNN fallback: {e}")))?
        } else {
            selected
                .into_iter()
                .map(
                    |(id, _content, similarity)| epigraph_db::ClaimEmbeddingHit {
                        claim_id: id,
                        similarity,
                    },
                )
                .collect()
        }
    } else {
        // Flat paragraph-primary kNN (level=2 only, optional paper_doi pre-filter).
        epigraph_db::ClaimRepository::search_by_embedding_since(
            &server.pool,
            viewer,
            pgvec,
            centroid_dim,
            flat_limit,
            params.paper_doi_filter.as_deref(),
            params.since,
        )
        .await
        .map_err(|e| internal_error(format!("kNN: {e}")))?
    };

    if raw_hits.is_empty() {
        // Empty result still returns corpus_scope (#52 Finding 2).
        let corpus_scope = compute_corpus_scope(&server.pool, viewer)
            .await
            .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;
        let event_id = Uuid::new_v4();
        spawn_recall_audit(
            server,
            event_id,
            viewer.principal(),
            &params.query,
            pgvec,
            // `since` is recorded on the EMPTY path too: "this window
            // returned nothing at that time" is exactly the claim an audit
            // has to be able to settle, and it is unsettleable without the
            // window that produced it.
            serde_json::json!({
                "limit": limit,
                "min_truth": min_truth,
                "empty": true,
                "since": params.since,
            }),
            vec![],
        );
        // The empty page honours `epistemic_partition` too: a caller that
        // asked for the bucketed shape must get three empty buckets, not a
        // silently different shape on the zero-hit path. Getting `results: []`
        // back from a partitioned request would look like the flag was ignored.
        let (results, epistemic_partition) = crate::types::split_epistemic(
            Vec::new(),
            params.epistemic_partition,
            |_: &RecallHit| (0.0, false),
        );
        return success_json(&RecallWithContextResponse {
            results,
            epistemic_partition,
            corpus_scope,
            centroid_dim_used: centroid_dim,
            recall_event_id: Some(event_id.to_string()),
        });
    }

    // Stage 4: graph expansion (Task 6.1 / claim 29e789fd). Default-off —
    // `None` reproduces today's flat-ANN-only `raw_hits` exactly. When set,
    // follow outgoing supports/corroborates/elaborates edges up to
    // `graph_expansion_depth` hops from each ANN seed, fold the reached
    // claims into the pool (deduped against the seeds — a claim that's both
    // an ANN seed and graph-reachable is not double-counted), and rerank the
    // combined set by `similarity * (1 + 0.1 * in_epistemic_degree)`.
    //
    // Runs BEFORE the optional cross-encoder rerank stage so `rerank=true`
    // (when both are set) re-ranks the graph-expanded pool, not just the raw
    // ANN seeds — matching "expand seeds, then rank" rather than "rank seeds,
    // then expand the winners".
    if let Some(depth) = params.graph_expansion_depth {
        raw_hits =
            apply_graph_expansion(&server.pool, viewer, raw_hits, depth, params.since).await?;
    }

    // Stage 4.5: cross-encoder rerank + optional groundedness gate over the
    // widened pool. Reorders by RELEVANCE and truncates to `want` BEFORE the
    // expensive fetch_batched_context. Belief/truth fields are untouched here:
    // rerank_score/verdict are surfaced as SEPARATE metadata.
    let mut rerank_meta: std::collections::HashMap<
        Uuid,
        (Option<f64>, Option<epigraph_engine::rerank::Groundedness>),
    > = std::collections::HashMap::new();
    if params.rerank.unwrap_or(false) {
        let ids: Vec<Uuid> = raw_hits.iter().map(|h| h.claim_id).collect();
        let contents = epigraph_db::ClaimRepository::contents_by_ids(&server.pool, viewer, &ids)
            .await
            .map_err(|e| internal_error(format!("rerank content fetch: {e}")))?;
        let cands: Vec<epigraph_engine::rerank::RerankCandidate> = raw_hits
            .iter()
            .filter_map(|h| {
                contents
                    .get(&h.claim_id)
                    .map(|c| epigraph_engine::rerank::RerankCandidate {
                        id: h.claim_id,
                        content: c.clone(),
                    })
            })
            .collect();
        match epigraph_engine::rerank::build_rerank_client_from_env() {
            Some(Ok(client)) => {
                use epigraph_engine::rerank::RerankClient;
                match client.rerank(&params.query, &cands).await {
                    Ok(scores) => {
                        // No BetP belief is carried on this flat path yet, so
                        // belief stays `None`; the merge preserves it untouched.
                        let inputs: Vec<(Uuid, f64, Option<f64>)> = raw_hits
                            .iter()
                            .map(|h| (h.claim_id, h.similarity, None))
                            .collect();
                        let mut merged =
                            epigraph_engine::rerank::merge_rerank_scores(&inputs, &scores);
                        // Optional groundedness gate over the survivors (top `want`).
                        if params.groundedness_gate.unwrap_or(false) {
                            let llm = epigraph_interfaces::default_llm_provider();
                            if llm.is_active() {
                                let top: Vec<epigraph_engine::rerank::RerankCandidate> = merged
                                    .iter()
                                    .take(want)
                                    .filter_map(|h| {
                                        contents.get(&h.id).map(|c| {
                                            epigraph_engine::rerank::RerankCandidate {
                                                id: h.id,
                                                content: c.clone(),
                                            }
                                        })
                                    })
                                    .collect();
                                let gate = epigraph_engine::rerank::GroundednessGate::new(&*llm);
                                if let Ok(verdicts) = gate.judge(&params.query, &top).await {
                                    let vmap: std::collections::HashMap<
                                        Uuid,
                                        epigraph_engine::rerank::Groundedness,
                                    > = top.iter().map(|c| c.id).zip(verdicts).collect();
                                    merged = epigraph_engine::rerank::apply_groundedness(
                                        merged, &vmap, true,
                                    );
                                }
                            } else {
                                // KNOWN LIMITATION: the deployed epigraph-mcp binary
                                // registers no LlmProvider (epigraph-cli's AnthropicClient
                                // cannot be reused — cli depends on mcp), so the gate is
                                // inert here and annotates nothing. Follow-up: register a
                                // provider directly in mcp `main`.
                                tracing::warn!(
                                    "groundedness_gate requested but no active LlmProvider; annotating only"
                                );
                            }
                        }
                        merged.truncate(want);
                        for h in &merged {
                            rerank_meta.insert(h.id, (h.rerank_score, h.verdict));
                        }
                        let order: Vec<Uuid> = merged.iter().map(|h| h.id).collect();
                        let by_id: std::collections::HashMap<Uuid, epigraph_db::ClaimEmbeddingHit> =
                            raw_hits.into_iter().map(|h| (h.claim_id, h)).collect();
                        raw_hits = order
                            .into_iter()
                            .filter_map(|id| by_id.get(&id).cloned())
                            .collect();
                    }
                    Err(e) => tracing::warn!("rerank failed, using flat order: {e}"),
                }
            }
            _ => tracing::warn!("rerank requested but RERANK_API_KEY absent/disabled; flat order"),
        }
    }
    // Cap to `want` even when rerank is off (or skipped), since the flat pool
    // may have been widened above.
    raw_hits.truncate(want);

    // Stage 5: batch context fetches.
    let paragraph_ids: Vec<Uuid> = raw_hits.iter().map(|h| h.claim_id).collect();
    let ctx = fetch_batched_context(
        &server.pool,
        viewer,
        &paragraph_ids,
        siblings_limit,
        corroborates_limit,
        epistemic_limit,
    )
    .await
    .map_err(|e| internal_error(format!("batch fetch: {e}")))?;

    // Stage 4 + 6: filter min_truth, drop paragraphs missing core or paper, assemble.
    let mut results = Vec::with_capacity(raw_hits.len());
    for hit in raw_hits {
        let paragraph_id = hit.claim_id;
        let (rerank_score, verdict) = rerank_meta
            .get(&paragraph_id)
            .copied()
            .unwrap_or((None, None));
        let core = match ctx.paragraph_meta.get(&paragraph_id) {
            Some(c) => c,
            None => continue, // paragraph deleted between kNN and batch fetch
        };
        if core.truth_value < min_truth {
            continue;
        }
        let paper = match ctx.paper_meta.get(&paragraph_id) {
            Some(p) => p.clone(),
            None => continue, // paragraph with no paper attribution — drop
        };

        let atoms = ctx
            .atoms_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let atoms_total = ctx
            .atoms_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(atoms.len());
        let atoms_truncated = atoms_total > atoms.len();

        let siblings = ctx
            .siblings_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let siblings_total = ctx
            .siblings_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(siblings.len());
        let siblings_truncated = siblings_total > siblings.len();

        let corroborates = ctx
            .corroborates_by_paragraph
            .get(&paragraph_id)
            .cloned()
            .unwrap_or_default();
        let corroborates_total = ctx
            .corroborates_total_by_paragraph
            .get(&paragraph_id)
            .copied()
            .unwrap_or(corroborates.len());
        let corroborates_truncated = corroborates_total > corroborates.len();

        let (neighbor_paragraphs, neighbor_paragraphs_total, neighbor_paragraphs_truncated) =
            assemble_neighbor_paragraphs(
                paragraph_id,
                &atoms,
                &siblings,
                &ctx,
                neighbor_paragraphs_limit,
            );

        results.push(RecallHit {
            paragraph_id,
            paragraph_content: core.content.clone(),
            similarity: hit.similarity,
            rerank_score,
            verdict,
            // Populated by the bounded lens post-pass below (after the loop),
            // once per page, keyed by paragraph_id. None until then.
            lensed_belief: None,
            truth_value: core.truth_value,
            paper,
            section: ctx.section_meta.get(&paragraph_id).cloned(),
            atoms,
            atoms_total,
            atoms_truncated,
            siblings,
            siblings_total,
            siblings_truncated,
            corroborates,
            corroborates_total,
            corroborates_truncated,
            neighbor_paragraphs,
            neighbor_paragraphs_total,
            neighbor_paragraphs_truncated,
            // Populated by the bounded dispute post-pass below (after the
            // loop), once per page, keyed by paragraph_id.
            dispute_count: 0,
            is_contested: false,
            contesting_claim_ids: Vec::new(),
            created_at: Some(core.created_at),
        });
    }

    // Bounded lens post-pass: when a lens is active, annotate each already-built
    // hit with its lensed belief, keyed by paragraph_id. This does NOT touch
    // retrieval, rerank, diverse selection, or min_truth (all on the global
    // value). Per-claim degrade-not-fail: a compute error for ONE hit yields
    // null + a warn, never an aborted page (spec §8).
    if let Some((frame_id, perspective_id)) = lens {
        // Batch the lens post-pass so the perspective row + per-frame overrides
        // are resolved ONCE for the whole page, not once per hit (the N+1 fixed
        // in backlog 9e33ddf7). Per-hit degrade-not-fail is preserved: each
        // claim carries its own `Result`, so one malformed claim warns + serves
        // a null lens without aborting the page.
        let claim_ids: Vec<Uuid> = results.iter().map(|h| h.paragraph_id).collect();
        match epigraph_engine::belief_query::get_perspective_belief_batch(
            &server.pool,
            viewer,
            &claim_ids,
            frame_id,
            perspective_id,
        )
        .await
        {
            Ok(intervals) => {
                let mut by_claim: std::collections::HashMap<Uuid, _> =
                    intervals.into_iter().collect();
                for hit in &mut results {
                    match by_claim.remove(&hit.paragraph_id) {
                        Some(Ok(interval)) => {
                            hit.lensed_belief = Some(crate::types::LensedBelief::from_interval(
                                frame_id,
                                perspective_id,
                                &interval,
                            ));
                        }
                        Some(Err(e)) => {
                            tracing::warn!(
                                claim_id = %hit.paragraph_id,
                                error = %e,
                                "lensed belief compute failed; serving null lens for this claim"
                            );
                        }
                        None => {}
                    }
                }
            }
            Err(e) => {
                // Page-level failure (e.g. frame vanished): degrade the whole
                // lens to null rather than abort the recall, matching the
                // per-hit degrade-not-fail contract.
                tracing::warn!(
                    error = %e,
                    "lensed belief batch failed; serving null lens for this page"
                );
            }
        }
    }

    // Bounded dispute post-pass (backlog 34d3400d), the same batched shape as
    // `tools::memory::recall`'s — one follow-up query over the ids this page
    // already returned, never a join inside the ANN/RRF SQL.
    //
    // Keyed on `paragraph_id`: paragraphs ARE claims (level-2 rows in the same
    // table), so `dispute_batch` takes them directly, exactly as the lens
    // post-pass above does.
    //
    // Scope: TOP-LEVEL hits only. The `atoms`/`siblings`/`corroborates`/
    // `neighbor_paragraphs` children are context for a hit, not results the
    // caller is being asked to act on, and annotating them would multiply the
    // id set by the fan-out of every hit. A caller that needs a child's
    // dispute status can recall it as a hit in its own right.
    {
        let paragraph_ids: Vec<Uuid> = results.iter().map(|h| h.paragraph_id).collect();
        match epigraph_db::ClaimRepository::dispute_batch(&server.pool, viewer, &paragraph_ids)
            .await
        {
            Ok(mut by_claim) => {
                for hit in &mut results {
                    // Absent key == uncontested, per the repo contract.
                    if let Some(d) = by_claim.remove(&hit.paragraph_id) {
                        hit.dispute_count = d.dispute_count.max(0) as u32;
                        hit.is_contested = d.dispute_count > 0;
                        hit.contesting_claim_ids = d.contesting_claim_ids;
                    }
                }
            }
            Err(e) => {
                // Degrade-not-fail, matching the lens contract above: serve the
                // page unannotated rather than lose results already retrieved.
                tracing::warn!(
                    error = %e,
                    "dispute batch failed; serving page without dispute annotations"
                );
            }
        }

        // Post-filter after ranking/enrichment — a page may come back short
        // rather than back-fill with worse-ranked material (same precedent as
        // `min_truth`).
        if params.exclude_contested {
            results.retain(|h| !h.is_contested);
        }
    }

    // Diversity post-filter (backlog a9397e8a): greedy MMR over the ranked
    // page, dropping any hit within `diversity_radius` cosine distance of a hit
    // already kept above it.
    //
    // # Why this runs LAST, not on the seed set
    //
    // An earlier revision ran it right after `raw_hits.truncate(want)`, which
    // is cheaper — a dropped paragraph never pays for its siblings, atoms,
    // corroborates and neighbour fan-out in `fetch_batched_context`. It is also
    // WRONG, and the test
    // `a_hit_another_filter_will_drop_cannot_suppress_a_surviving_one` pins the
    // exact failure: on this surface `min_truth` is applied AFTER context
    // assembly, so a low-truth paragraph ranked first could evict its
    // high-truth near-duplicate and then be dropped itself by `min_truth`. The
    // measured result was a page that returned the 0.9 paragraph WITHOUT the
    // radius and nothing at all WITH it — switching on a de-duplication filter
    // deleted the good hit. `exclude_contested` and the missing-paper drop have
    // the same shape.
    //
    // Running last makes the rule "a hit may only be suppressed by a hit that
    // is itself being returned", and makes this surface agree with
    // `tools::memory::recall`, where `min_truth` and `exclude_contested`
    // already ran first. The lost saving is bounded and buys correctness.
    //
    // Still ahead of `spawn_recall_audit` below, which derives
    // `returned_claim_ids` from `results`: an audit row naming paragraphs the
    // caller never received would be a false disclosure record.
    //
    // `centroid_dim` — NOT a hardcoded 1536. This tool auto-detects its vector
    // space, and measuring a 3072-retrieved page against `claims.embedding`
    // would compare vectors that were never comparable, or find no pairs at all
    // on a corpus embedded only at 3072 and silently report a perfectly diverse
    // page.
    if let Some(radius) = diversity_radius {
        let ids: Vec<Uuid> = results.iter().map(|h| h.paragraph_id).collect();
        match epigraph_db::ClaimRepository::pairwise_cosine_distance_at_dim(
            &server.pool,
            viewer,
            &ids,
            radius,
            centroid_dim,
        )
        .await
        {
            Ok(pairs) => {
                // The repo applied the `< radius` cut in SQL, so every returned
                // pair IS a too-similar pair. A pair that is ABSENT is kept —
                // see `greedy_diversity_keep`; a paragraph with no vector in
                // the searched column is not known to be near anything.
                let too_similar: std::collections::HashSet<(Uuid, Uuid)> = pairs
                    .iter()
                    .map(|p| crate::types::unordered_pair(p.claim_a, p.claim_b))
                    .collect();
                let keep: std::collections::HashSet<Uuid> =
                    crate::types::greedy_diversity_keep(&ids, &too_similar)
                        .into_iter()
                        .collect();
                results.retain(|h| keep.contains(&h.paragraph_id));
            }
            Err(e) => {
                // Degrade-not-fail, matching the lens and dispute post-passes:
                // serve the undiversified page rather than lose hits already
                // retrieved, and say so in the log so an unfiltered page is
                // distinguishable from one with nothing to filter.
                tracing::warn!(
                    error = %e,
                    "diversity filter failed; serving the page without it"
                );
            }
        }
    }

    let corpus_scope = compute_corpus_scope(&server.pool, viewer)
        .await
        .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;

    // Recall audit log (backlog 8cbffa0e) — same fire-and-forget contract as
    // `tools::memory::recall`: spawned after the response is assembled so an
    // audit failure can never fail or delay a retrieval that already
    // succeeded. Id is minted here rather than read back from the insert.
    let event_id = Uuid::new_v4();
    spawn_recall_audit(
        server,
        event_id,
        viewer.principal(),
        &params.query,
        pgvec,
        serde_json::json!({
            "limit": limit,
            "min_truth": min_truth,
            "centroid_dim": centroid_dim,
            "diverse": params.diverse,
            "rerank": params.rerank,
            "graph_expansion_depth": params.graph_expansion_depth,
            "exclude_contested": params.exclude_contested,
            // See the empty-path literal above: the window is part of the
            // question, so it has to survive into the audit row.
            "since": params.since,
            // Same argument: the radius changes WHICH paragraphs came back, so
            // a retrieval whose diversity cut cannot be reconstructed from its
            // audit row is an unauditable retrieval. `epistemic_partition` is
            // deliberately absent — it regroups the response without changing
            // the set.
            "diversity_radius": params.diversity_radius,
        }),
        results.iter().map(|h| h.paragraph_id).collect(),
    );

    // Epistemic partitioning (backlog e7736ff6), in the same position as
    // `tools::memory::recall`'s: after the dispute post-pass (nothing is
    // `is_contested` before it, so bucketing earlier would leave
    // `open_question` permanently empty), after `exclude_contested`'s retain,
    // and after the audit spawn, which derives `returned_claim_ids` from
    // `results` and must name exactly the hits that were served.
    //
    // The score is the SAME `truth_value` `min_truth` gates on, read back off
    // the built hit rather than recomputed, so the bucket threshold and the
    // gate cannot drift apart.
    let (results, epistemic_partition) =
        crate::types::split_epistemic(results, params.epistemic_partition, |h: &RecallHit| {
            (h.truth_value, h.is_contested)
        });

    success_json(&RecallWithContextResponse {
        results,
        epistemic_partition,
        corpus_scope,
        centroid_dim_used: centroid_dim,
        recall_event_id: Some(event_id.to_string()),
    })
}

pub struct ParagraphCore {
    pub content: String,
    pub truth_value: f64,
    /// `claims.created_at`, carried through the batched context fetch so the
    /// hit can report a real creation instant without a second round-trip.
    /// Context enrichment does NOT window on it — see `RecallHit::created_at`.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct BatchedContext {
    pub paragraph_meta: std::collections::HashMap<Uuid, ParagraphCore>,
    pub paper_meta: std::collections::HashMap<Uuid, PaperMeta>,
    pub paragraph_to_section: std::collections::HashMap<Uuid, Uuid>,
    pub section_meta: std::collections::HashMap<Uuid, SectionMeta>,
    pub atoms_by_paragraph: std::collections::HashMap<Uuid, Vec<AtomChild>>,
    pub atoms_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    pub siblings_by_paragraph: std::collections::HashMap<Uuid, Vec<SiblingParagraph>>,
    pub siblings_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    pub corroborates_by_paragraph: std::collections::HashMap<Uuid, Vec<CorroboratesEdge>>,
    pub corroborates_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    pub epistemic_edges_by_paragraph: std::collections::HashMap<Uuid, Vec<EpistemicEdgeNeighbor>>,
    pub epistemic_edges_total_by_paragraph: std::collections::HashMap<Uuid, usize>,
    /// continues_argument neighbors of each input paragraph (bidirectional).
    pub continues_argument_by_paragraph: std::collections::HashMap<Uuid, Vec<Uuid>>,
    /// atom_a -> [(atom_b, relationship)] where atom_a is one of "our" atoms
    /// (a level=3 child of an input paragraph) and atom_b is on the OTHER end
    /// of any non-decomposes_to edge between two level=3 atoms.
    pub atom_atom_links_by_atom: std::collections::HashMap<Uuid, Vec<(Uuid, String)>>,
    /// atom_b -> [parent paragraph IDs] (full parent list for atoms reached via
    /// atom-atom-bridge). Used to resolve which paragraphs contain atom_b.
    pub paragraphs_by_atom: std::collections::HashMap<Uuid, Vec<Uuid>>,
}

/// Batched structural context for a set of paragraph hits.
///
/// # Tenancy (PR-09)
///
/// This function is the single largest fail-open the MCP surface had. It took a
/// bare `&sqlx::PgPool` and no `Viewer`, and it is called from
/// `recall_with_context_post_embed` — which *does* hold a `&Viewer` and passes
/// it to seven other calls. So a viewer-scoped seed set was enriched with
/// unscoped neighbours: the tenancy filter applied to the hits and was then
/// bypassed for the section text, sibling paragraphs, atom children,
/// CORROBORATES neighbours and paper attribution returned alongside them. Four
/// of the ten statements selected `c.content` directly.
///
/// Every one of the ten now carries the static three-bind visibility form
/// (`$N::bool OR <alias>.visibility = 'public' OR <alias>.owner_group_id =
/// ANY($M::uuid[])`) rather than `Viewer::splice`, because `sqlx::query!` needs
/// a compile-time literal of fixed arity and cannot take a spliced string —
/// the same reason `repos/claim.rs`'s four macro read sites use that spelling.
/// `visibility.rs`'s module doc names it as the accepted equivalent.
///
/// Three of the ten (`bridge_to_paragraphs`, `continues_argument`,
/// `atom_b -> parent paragraphs`) previously touched only `edges` and returned
/// bare claim ids. They gained a `JOIN claims` purely so there is something to
/// filter on: an id is a disclosure, and the neighbour ids feed
/// `all_paragraph_ids`, which the last two statements then hydrate into content.
///
/// # A deliberate deviation, recorded
///
/// The SQL stays in `crates/epigraph-mcp/src/tools/` rather than moving to
/// `crates/epigraph-db/src/repos/` as CLAUDE.md requires. Ten `sqlx::query!`
/// macros, six anonymous row shapes and the `BatchedContext` type would have to
/// move together, and `recall.rs` is the one caller. The security property —
/// the filter — is delivered here; the relocation is recorded as outstanding in
/// `crates/epigraph-mcp/tests/no_inline_sql_in_tools.rs`'s expected set, which
/// is an exact-set ratchet, so it cannot quietly grow.
pub async fn fetch_batched_context(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    paragraph_ids: &[Uuid],
    siblings_limit: u32,
    corroborates_limit: u32,
    epistemic_limit: u32,
) -> Result<BatchedContext, sqlx::Error> {
    let v_bypass = viewer.bypass_bind();
    let v_groups: &[Uuid] = viewer.group_bind().unwrap_or(&[]);
    let mut paragraph_meta: std::collections::HashMap<Uuid, ParagraphCore> = Default::default();
    let mut paper_meta: std::collections::HashMap<Uuid, PaperMeta> = Default::default();
    let mut paragraph_to_section: std::collections::HashMap<Uuid, Uuid> = Default::default();
    let mut section_meta: std::collections::HashMap<Uuid, SectionMeta> = Default::default();
    let mut atoms_by_paragraph: std::collections::HashMap<Uuid, Vec<AtomChild>> =
        Default::default();
    let mut atoms_total_by_paragraph: std::collections::HashMap<Uuid, usize> = Default::default();
    let mut siblings_by_paragraph: std::collections::HashMap<Uuid, Vec<SiblingParagraph>> =
        Default::default();
    let mut siblings_total_by_paragraph: std::collections::HashMap<Uuid, usize> =
        Default::default();
    let mut corroborates_by_paragraph: std::collections::HashMap<Uuid, Vec<CorroboratesEdge>> =
        Default::default();
    let mut corroborates_total_by_paragraph: std::collections::HashMap<Uuid, usize> =
        Default::default();
    let mut epistemic_edges_by_paragraph: std::collections::HashMap<
        Uuid,
        Vec<EpistemicEdgeNeighbor>,
    > = Default::default();
    let mut epistemic_edges_total_by_paragraph: std::collections::HashMap<Uuid, usize> =
        Default::default();
    let mut continues_argument_by_paragraph: std::collections::HashMap<Uuid, Vec<Uuid>> =
        Default::default();
    let mut atom_atom_links_by_atom: std::collections::HashMap<Uuid, Vec<(Uuid, String)>> =
        Default::default();
    let mut paragraphs_by_atom: std::collections::HashMap<Uuid, Vec<Uuid>> = Default::default();

    if paragraph_ids.is_empty() {
        return Ok(BatchedContext {
            paragraph_meta,
            paper_meta,
            paragraph_to_section,
            section_meta,
            atoms_by_paragraph,
            atoms_total_by_paragraph,
            siblings_by_paragraph,
            siblings_total_by_paragraph,
            corroborates_by_paragraph,
            corroborates_total_by_paragraph,
            epistemic_edges_by_paragraph,
            epistemic_edges_total_by_paragraph,
            continues_argument_by_paragraph,
            atom_atom_links_by_atom,
            paragraphs_by_atom,
        });
    }

    // 3. Section parents (level=1 via decomposes_to incoming).
    {
        let rows = sqlx::query!(
            r#"
            SELECT e.target_id AS paragraph_id, c.id AS section_id, c.content
            FROM edges e
            JOIN claims c ON c.id = e.source_id
            WHERE e.target_id = ANY($1)
              AND e.relationship = 'decomposes_to'
              AND (c.properties->>'level')::int = 1
              AND ($2::bool OR c.visibility = 'public'
                   OR c.owner_group_id = ANY($3::uuid[]))
            "#,
            paragraph_ids,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paragraph_to_section.insert(r.paragraph_id, r.section_id);
            section_meta.insert(
                r.paragraph_id,
                SectionMeta {
                    section_id: r.section_id,
                    content: r.content,
                },
            );
        }
    }

    // 4. Atoms (level=3) — windowed by paragraph; cap at 50 atoms per paragraph.
    let atoms_per_paragraph_cap: i64 = 50;
    {
        let rows = sqlx::query!(
            r#"
            WITH ranked AS (
                SELECT
                    e.source_id AS paragraph_id,
                    c.id AS atom_id,
                    c.content,
                    c.truth_value,
                    ROW_NUMBER() OVER (PARTITION BY e.source_id ORDER BY c.created_at) AS rn,
                    COUNT(*) OVER (PARTITION BY e.source_id) AS total
                FROM edges e
                JOIN claims c ON c.id = e.target_id
                WHERE e.source_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND (c.properties->>'level')::int = 3
                  AND ($3::bool OR c.visibility = 'public'
                       OR c.owner_group_id = ANY($4::uuid[]))
            )
            SELECT
                paragraph_id AS "paragraph_id!",
                atom_id AS "atom_id!",
                content AS "content!",
                truth_value AS "truth_value!",
                total AS "total!"
            FROM ranked
            WHERE rn <= $2
            "#,
            paragraph_ids,
            atoms_per_paragraph_cap,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            atoms_total_by_paragraph
                .entry(r.paragraph_id)
                .or_insert_with(|| r.total.max(0) as usize);
            atoms_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(AtomChild {
                    atom_id: r.atom_id,
                    content: r.content,
                    truth_value: r.truth_value,
                    bridge_to_paragraphs: vec![],
                });
        }
    }

    // 5. bridge_to_paragraphs: for each atom in atoms_by_paragraph, find OTHER parents.
    {
        let atom_ids: Vec<Uuid> = atoms_by_paragraph
            .values()
            .flat_map(|v| v.iter().map(|a| a.atom_id))
            .collect();
        if !atom_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                SELECT e.target_id AS "atom_id!", e.source_id AS "parent_paragraph_id!"
                FROM edges e
                JOIN claims cp ON cp.id = e.source_id
                WHERE e.target_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND ($2::bool OR cp.visibility = 'public'
                       OR cp.owner_group_id = ANY($3::uuid[]))
                "#,
                &atom_ids,
                v_bypass,
                v_groups
            )
            .fetch_all(pool)
            .await?;
            let mut all_parents: std::collections::HashMap<Uuid, Vec<Uuid>> = Default::default();
            for r in rows {
                all_parents
                    .entry(r.atom_id)
                    .or_default()
                    .push(r.parent_paragraph_id);
            }
            for (paragraph_id, atoms) in atoms_by_paragraph.iter_mut() {
                for atom in atoms.iter_mut() {
                    if let Some(parents) = all_parents.get(&atom.atom_id) {
                        atom.bridge_to_paragraphs = parents
                            .iter()
                            .filter(|p| **p != *paragraph_id)
                            .copied()
                            .collect();
                    }
                }
            }
        }
    }

    // 6. Sibling paragraphs (level=2 sharing the same section).
    {
        let section_ids: Vec<Uuid> = paragraph_to_section.values().copied().collect();
        if !section_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                SELECT
                    e.source_id AS section_id,
                    e.target_id AS paragraph_id,
                    c.content,
                    c.truth_value
                FROM edges e
                JOIN claims c ON c.id = e.target_id
                WHERE e.source_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND (c.properties->>'level')::int = 2
                  AND ($2::bool OR c.visibility = 'public'
                       OR c.owner_group_id = ANY($3::uuid[]))
                "#,
                &section_ids,
                v_bypass,
                v_groups
            )
            .fetch_all(pool)
            .await?;

            // Group by section_id.
            let mut by_section: std::collections::HashMap<Uuid, Vec<(Uuid, String, f64)>> =
                Default::default();
            for r in rows {
                by_section.entry(r.section_id).or_default().push((
                    r.paragraph_id,
                    r.content,
                    r.truth_value,
                ));
            }

            for (paragraph_id, section_id) in &paragraph_to_section {
                if let Some(group) = by_section.get(section_id) {
                    let other_siblings: Vec<&(Uuid, String, f64)> = group
                        .iter()
                        .filter(|(pid, _, _)| pid != paragraph_id)
                        .collect();
                    siblings_total_by_paragraph.insert(*paragraph_id, other_siblings.len());
                    let truncated: Vec<SiblingParagraph> = other_siblings
                        .iter()
                        .take(siblings_limit as usize)
                        .map(|(pid, content, tv)| SiblingParagraph {
                            paragraph_id: *pid,
                            content: content.clone(),
                            truth_value: *tv,
                        })
                        .collect();
                    siblings_by_paragraph.insert(*paragraph_id, truncated);
                }
            }
        }
    }

    // 7. CORROBORATES: paragraph → ANY direction. Sort by edge strength desc, tie-break truth_value desc.
    {
        let rows = sqlx::query!(
            r#"
            WITH neighbors AS (
                SELECT e.source_id AS paragraph_id, e.target_id AS neighbor_id,
                       COALESCE((e.properties->>'strength')::float8, 0.0) AS strength
                FROM edges e
                WHERE e.source_id = ANY($1) AND e.relationship = 'CORROBORATES'
                UNION ALL
                SELECT e.target_id AS paragraph_id, e.source_id AS neighbor_id,
                       COALESCE((e.properties->>'strength')::float8, 0.0) AS strength
                FROM edges e
                WHERE e.target_id = ANY($1) AND e.relationship = 'CORROBORATES'
            ),
            joined AS (
                SELECT
                    n.paragraph_id, n.neighbor_id, n.strength,
                    c.content, c.truth_value,
                    p.doi AS paper_doi
                FROM neighbors n
                JOIN claims c
                  ON c.id = n.neighbor_id
                 AND ($3::bool OR c.visibility = 'public'
                      OR c.owner_group_id = ANY($4::uuid[]))
                LEFT JOIN edges asserts_e
                  ON asserts_e.target_id = c.id
                  AND asserts_e.relationship = 'asserts'
                  AND asserts_e.source_type = 'paper'
                LEFT JOIN papers p ON p.id = asserts_e.source_id
            ),
            ranked AS (
                SELECT *,
                    ROW_NUMBER() OVER (PARTITION BY paragraph_id ORDER BY strength DESC, truth_value DESC) AS rn,
                    COUNT(*) OVER (PARTITION BY paragraph_id) AS total
                FROM joined
            )
            SELECT
                paragraph_id AS "paragraph_id!",
                neighbor_id AS "neighbor_id!",
                content AS "content!",
                strength AS "strength!",
                truth_value AS "truth_value!",
                paper_doi AS "paper_doi?",
                total AS "total!"
            FROM ranked
            WHERE rn <= $2
            "#,
            paragraph_ids,
            i64::from(corroborates_limit),
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            corroborates_total_by_paragraph
                .entry(r.paragraph_id)
                .or_insert_with(|| r.total.max(0) as usize);
            corroborates_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(CorroboratesEdge {
                    claim_id: r.neighbor_id,
                    content: r.content,
                    similarity: r.strength,
                    paper_doi: r.paper_doi,
                });
        }
    }

    // 7b. Epistemic-edge neighbours — bidirectional, per-relationship capped.
    //
    // Carries the same static three-bind visibility form as the other ten queries in
    // this function. It was authored on a branch where `Viewer` did not exist, so it
    // arrived here without one — and because both branches merely ADDED a parameter to
    // this function, git conflicted only on the test call sites. Resolving those the
    // obvious way produces a tree that compiles, passes, and returns epistemic-edge
    // neighbours across tenancy boundaries. See ops note
    // 2026-09-18-tenancy-epistemic-edge-viewer-gap.md and claim 76df5e6e.
    //
    // Direction is part of the payload because it carries the meaning: an
    // incoming `refutes` means "is refuted by", which is the opposite claim
    // about credibility from an outgoing one.
    {
        let relationships: Vec<String> = EPISTEMIC_EDGE_RELATIONSHIPS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let rows = sqlx::query!(
            r#"
            WITH neighbors AS (
                SELECT e.source_id AS paragraph_id, e.target_id AS neighbor_id,
                       e.relationship, 'outgoing' AS direction
                FROM edges e
                WHERE e.source_id = ANY($1) AND e.relationship = ANY($3)
                UNION ALL
                SELECT e.target_id AS paragraph_id, e.source_id AS neighbor_id,
                       e.relationship, 'incoming' AS direction
                FROM edges e
                WHERE e.target_id = ANY($1) AND e.relationship = ANY($3)
            ),
            joined AS (
                SELECT n.paragraph_id, n.neighbor_id, n.relationship, n.direction,
                       c.content, c.truth_value
                FROM neighbors n
                JOIN claims c ON c.id = n.neighbor_id
                  AND ($4::bool OR c.visibility = 'public'
                       OR c.owner_group_id = ANY($5::uuid[]))
            ),
            ranked AS (
                SELECT *,
                    ROW_NUMBER() OVER (
                        PARTITION BY paragraph_id, relationship
                        ORDER BY truth_value DESC, neighbor_id
                    ) AS rn,
                    COUNT(*) OVER (PARTITION BY paragraph_id) AS total
                FROM joined
            )
            SELECT
                paragraph_id AS "paragraph_id!",
                neighbor_id AS "neighbor_id!",
                content AS "content!",
                relationship AS "relationship!",
                direction AS "direction!",
                truth_value AS "truth_value!",
                total AS "total!"
            FROM ranked
            WHERE rn <= $2
            "#,
            paragraph_ids,
            i64::from(epistemic_limit),
            &relationships,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            epistemic_edges_total_by_paragraph
                .entry(r.paragraph_id)
                .or_insert_with(|| r.total.max(0) as usize);
            epistemic_edges_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(EpistemicEdgeNeighbor {
                    claim_id: r.neighbor_id,
                    content: r.content,
                    relationship: r.relationship,
                    direction: if r.direction == "incoming" {
                        EdgeDirection::Incoming
                    } else {
                        EdgeDirection::Outgoing
                    },
                    truth_value: r.truth_value,
                });
        }
    }

    // 8. continues_argument neighbors (Query A) — bidirectional.
    {
        let rows = sqlx::query!(
            r#"
            SELECT e.source_id AS "paragraph_id!", e.target_id AS "neighbor_id!"
            FROM edges e
            JOIN claims cn ON cn.id = e.target_id
            WHERE e.source_id = ANY($1) AND e.relationship = 'continues_argument'
              AND ($2::bool OR cn.visibility = 'public'
                   OR cn.owner_group_id = ANY($3::uuid[]))
            UNION ALL
            SELECT e.target_id AS "paragraph_id!", e.source_id AS "neighbor_id!"
            FROM edges e
            JOIN claims cn ON cn.id = e.source_id
            WHERE e.target_id = ANY($1) AND e.relationship = 'continues_argument'
              AND ($2::bool OR cn.visibility = 'public'
                   OR cn.owner_group_id = ANY($3::uuid[]))
            "#,
            paragraph_ids,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            continues_argument_by_paragraph
                .entry(r.paragraph_id)
                .or_default()
                .push(r.neighbor_id);
        }
    }

    // 9. Atom-atom edges (Query C) — both directions. Restricted to non-decomposes_to
    //    edges between two level=3 atoms. atom_a is "ours" (a level=3 child of an
    //    input paragraph); atom_b is on the other end.
    {
        let our_atom_ids: Vec<Uuid> = atoms_by_paragraph
            .values()
            .flat_map(|v| v.iter().map(|a| a.atom_id))
            .collect();
        if !our_atom_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                WITH forward AS (
                    SELECT e.source_id AS atom_a, e.target_id AS atom_b, e.relationship
                    FROM edges e
                    JOIN claims ca ON ca.id = e.source_id
                    JOIN claims cb ON cb.id = e.target_id
                    WHERE e.source_id = ANY($1)
                      AND e.relationship != 'decomposes_to'
                      AND (ca.properties->>'level')::int = 3
                      AND (cb.properties->>'level')::int = 3
                      AND ($2::bool OR cb.visibility = 'public'
                           OR cb.owner_group_id = ANY($3::uuid[]))
                ),
                backward AS (
                    SELECT e.target_id AS atom_a, e.source_id AS atom_b, e.relationship
                    FROM edges e
                    JOIN claims ca ON ca.id = e.target_id
                    JOIN claims cb ON cb.id = e.source_id
                    WHERE e.target_id = ANY($1)
                      AND e.relationship != 'decomposes_to'
                      AND (ca.properties->>'level')::int = 3
                      AND (cb.properties->>'level')::int = 3
                      AND ($2::bool OR cb.visibility = 'public'
                           OR cb.owner_group_id = ANY($3::uuid[]))
                )
                SELECT atom_a AS "atom_a!", atom_b AS "atom_b!", relationship AS "relationship!"
                FROM forward
                UNION ALL
                SELECT atom_a AS "atom_a!", atom_b AS "atom_b!", relationship AS "relationship!"
                FROM backward
                "#,
                &our_atom_ids,
                v_bypass,
                v_groups
            )
            .fetch_all(pool)
            .await?;
            for r in rows {
                atom_atom_links_by_atom
                    .entry(r.atom_a)
                    .or_default()
                    .push((r.atom_b, r.relationship));
            }
        }
    }

    // 10. atom_b -> parent paragraphs (Query D). atom_b is the "outside" atom in
    //     atom-atom-bridge; we need to know which paragraph(s) decompose to it.
    {
        let atom_b_ids: Vec<Uuid> = atom_atom_links_by_atom
            .values()
            .flat_map(|v| v.iter().map(|(b, _)| *b))
            .collect();
        if !atom_b_ids.is_empty() {
            let rows = sqlx::query!(
                r#"
                SELECT e.source_id AS "paragraph_id!", e.target_id AS "atom_id!"
                FROM edges e
                JOIN claims c ON c.id = e.source_id
                WHERE e.target_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                  AND (c.properties->>'level')::int = 2
                  AND ($2::bool OR c.visibility = 'public'
                       OR c.owner_group_id = ANY($3::uuid[]))
                "#,
                &atom_b_ids,
                v_bypass,
                v_groups
            )
            .fetch_all(pool)
            .await?;
            for r in rows {
                paragraphs_by_atom
                    .entry(r.atom_id)
                    .or_default()
                    .push(r.paragraph_id);
            }
        }
    }

    // 11. Build the union of all paragraph IDs that paragraph_meta + paper_meta
    //     must cover: input paragraphs ∪ continues_argument neighbors ∪
    //     atom-bridge parents ∪ atom-atom-bridge parents.
    let mut all_paragraph_ids: Vec<Uuid> = paragraph_ids.to_vec();
    for v in continues_argument_by_paragraph.values() {
        all_paragraph_ids.extend(v.iter().copied());
    }
    for atoms in atoms_by_paragraph.values() {
        for atom in atoms {
            all_paragraph_ids.extend(atom.bridge_to_paragraphs.iter().copied());
        }
    }
    for v in paragraphs_by_atom.values() {
        all_paragraph_ids.extend(v.iter().copied());
    }
    all_paragraph_ids.sort();
    all_paragraph_ids.dedup();

    // 1. Paragraphs themselves (content + truth_value + created_at) — extended
    //    to cover neighbor IDs.
    //
    //    Note what is NOT here: a `since` predicate. This fetch populates both
    //    the hits' own metadata AND their context (siblings, neighbours,
    //    atom parents), and the window is deliberately a hits-only concept —
    //    windowing here would blank the context of a legitimately-returned
    //    recent hit. The filtering happens on the candidate surfaces upstream.
    {
        let rows = sqlx::query!(
            "SELECT c.id, c.content, c.truth_value, c.created_at FROM claims c \
             WHERE c.id = ANY($1) \
               AND ($2::bool OR c.visibility = 'public' \
                    OR c.owner_group_id = ANY($3::uuid[]))",
            &all_paragraph_ids,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paragraph_meta.insert(
                r.id,
                ParagraphCore {
                    content: r.content,
                    truth_value: r.truth_value,
                    created_at: r.created_at,
                },
            );
        }
    }

    // 2. Papers via paper-attribution asserts edge — extended to cover neighbor IDs.
    {
        let rows = sqlx::query!(
            r#"
            SELECT
                e.target_id AS paragraph_id,
                p.id AS paper_id,
                p.doi,
                COALESCE(p.title, '') AS "title!"
            FROM edges e
            JOIN papers p ON p.id = e.source_id
            JOIN claims c ON c.id = e.target_id
            WHERE e.target_id = ANY($1)
              AND e.relationship = 'asserts'
              AND e.source_type = 'paper'
              AND ($2::bool OR c.visibility = 'public'
                   OR c.owner_group_id = ANY($3::uuid[]))
            "#,
            &all_paragraph_ids,
            v_bypass,
            v_groups
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paper_meta.insert(
                r.paragraph_id,
                PaperMeta {
                    paper_id: r.paper_id,
                    doi: Some(r.doi),
                    title: r.title,
                },
            );
        }
    }

    Ok(BatchedContext {
        paragraph_meta,
        paper_meta,
        paragraph_to_section,
        section_meta,
        atoms_by_paragraph,
        atoms_total_by_paragraph,
        siblings_by_paragraph,
        siblings_total_by_paragraph,
        corroborates_by_paragraph,
        corroborates_total_by_paragraph,
        epistemic_edges_by_paragraph,
        epistemic_edges_total_by_paragraph,
        continues_argument_by_paragraph,
        atom_atom_links_by_atom,
        paragraphs_by_atom,
    })
}

#[derive(Default)]
struct NeighborParagraphAccumulator {
    via: Vec<NeighborPath>,
}

fn neighbor_path_priority(p: &NeighborPath) -> u8 {
    match p {
        NeighborPath::ContinuesArgument => 0,
        NeighborPath::AtomBridge { .. } => 1,
        NeighborPath::AtomAtomBridge { .. } => 2,
    }
}

/// Build the per-hit `neighbor_paragraphs` list.
///
/// Aggregates three reachability paths (continues_argument, atom-bridge,
/// atom-atom-bridge) across `ctx`, dedupes by paragraph_id, drops siblings
/// plus the result paragraph itself plus paragraphs missing paper attribution,
/// sorts by (min path priority asc, truth_value desc), and caps at
/// `neighbor_paragraphs_limit`.
///
/// Returns `(materialized, total_pre_truncation, truncated_flag)`.
pub fn assemble_neighbor_paragraphs(
    paragraph_id: Uuid,
    atoms: &[AtomChild],
    siblings: &[SiblingParagraph],
    ctx: &BatchedContext,
    neighbor_paragraphs_limit: u32,
) -> (Vec<NeighborParagraph>, usize, bool) {
    let mut by_id: std::collections::HashMap<Uuid, NeighborParagraphAccumulator> =
        Default::default();

    // (1) continues_argument
    if let Some(neighbors) = ctx.continues_argument_by_paragraph.get(&paragraph_id) {
        for nbr in neighbors {
            if *nbr == paragraph_id {
                continue;
            }
            by_id
                .entry(*nbr)
                .or_default()
                .via
                .push(NeighborPath::ContinuesArgument);
        }
    }

    // (2) atom-bridge
    for atom in atoms.iter() {
        for parent in &atom.bridge_to_paragraphs {
            if *parent == paragraph_id {
                continue;
            }
            by_id
                .entry(*parent)
                .or_default()
                .via
                .push(NeighborPath::AtomBridge {
                    atom_id: atom.atom_id,
                });
        }
    }

    // (3) atom-atom-bridge
    let atom_ids_under_p: std::collections::HashSet<Uuid> =
        atoms.iter().map(|a| a.atom_id).collect();
    for atom_a in atom_ids_under_p.iter() {
        if let Some(links) = ctx.atom_atom_links_by_atom.get(atom_a) {
            for (atom_b, relationship) in links {
                if let Some(parent_paragraphs) = ctx.paragraphs_by_atom.get(atom_b) {
                    for parent in parent_paragraphs {
                        if *parent == paragraph_id {
                            continue;
                        }
                        by_id
                            .entry(*parent)
                            .or_default()
                            .via
                            .push(NeighborPath::AtomAtomBridge {
                                atom_a: *atom_a,
                                atom_b: *atom_b,
                                relationship: relationship.clone(),
                            });
                    }
                }
            }
        }
    }

    // Drop siblings (avoid duplicate reporting per spec §3.8).
    let sibling_ids: std::collections::HashSet<Uuid> =
        siblings.iter().map(|s| s.paragraph_id).collect();
    by_id.retain(|pid, _| !sibling_ids.contains(pid));

    // Drop paragraphs with no paper meta.
    by_id.retain(|pid, _| ctx.paper_meta.contains_key(pid));

    let neighbor_paragraphs_total = by_id.len();

    // Materialize.
    let mut materialized: Vec<NeighborParagraph> = by_id
        .into_iter()
        .filter_map(|(pid, acc)| {
            let core = ctx.paragraph_meta.get(&pid)?;
            let paper = ctx.paper_meta.get(&pid)?.clone();
            Some(NeighborParagraph {
                paragraph_id: pid,
                content: core.content.clone(),
                truth_value: core.truth_value,
                paper,
                via: acc.via,
            })
        })
        .collect();

    materialized.sort_by(|a, b| {
        let a_p = a
            .via
            .iter()
            .map(neighbor_path_priority)
            .min()
            .unwrap_or(255);
        let b_p = b
            .via
            .iter()
            .map(neighbor_path_priority)
            .min()
            .unwrap_or(255);
        a_p.cmp(&b_p).then(
            b.truth_value
                .partial_cmp(&a.truth_value)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    let limit = neighbor_paragraphs_limit as usize;
    let neighbor_paragraphs_truncated = materialized.len() > limit;
    materialized.truncate(limit);

    (
        materialized,
        neighbor_paragraphs_total,
        neighbor_paragraphs_truncated,
    )
}

#[doc(hidden)]
pub mod __test_only {
    pub use super::{
        assemble_neighbor_paragraphs, fetch_batched_context, paragraph_3072_population,
        BatchedContext, ParagraphCore,
    };
    use super::{
        recall_with_context_post_embed, EpiGraphMcpFull, McpError, RecallWithContextParams,
    };
    use rmcp::model::CallToolResult;

    /// Integration-test entry point that skips the OpenAI embedder.
    ///
    /// Tests cannot call the real embedder (no API key in CI / sandbox),
    /// so they pre-format a known pgvector literal and dispatch directly
    /// into the post-embed pipeline. This is the same code that
    /// `recall_with_context` runs after `embedder.generate_at_dim`.
    pub async fn recall_with_context_with_pgvec(
        server: &EpiGraphMcpFull,
        viewer: &epigraph_db::visibility::Viewer,
        params: RecallWithContextParams,
        centroid_dim: u32,
        pgvec: &str,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).clamp(1, 50);
        let min_truth = params.min_truth.unwrap_or(0.3);
        let siblings_limit = params.siblings_limit.unwrap_or(8);
        let corroborates_limit = params.corroborates_limit.unwrap_or(4);
        let epistemic_limit = params.epistemic_limit.unwrap_or(4);
        let neighbor_paragraphs_limit = params.neighbor_paragraphs_limit.unwrap_or(16);
        // Mirror the real entry: resolve + existence-check the lens up front so
        // integration tests exercise the same validation path.
        let lens = crate::tools::lens::resolve_lens(
            params.frame_id.as_deref(),
            params.perspective_id.as_deref(),
        )?;
        if let Some((frame_id, perspective_id)) = lens {
            crate::tools::lens::validate_lens_exists(
                &server.pool,
                viewer,
                frame_id,
                perspective_id,
            )
            .await?;
        }
        recall_with_context_post_embed(
            server,
            viewer,
            &params,
            centroid_dim,
            pgvec,
            limit,
            min_truth,
            siblings_limit,
            corroborates_limit,
            epistemic_limit,
            neighbor_paragraphs_limit,
            lens,
        )
        .await
    }
}

/// Unit tests for the recall audit owner helper.
///
/// **The module MUST be named `tests`.** `no_inline_sql_in_tools.rs`'s
/// `the_cfg_test_boundary_is_the_last_item_in_every_file_that_has_one` splits
/// production from test sites on the first test-cfg attribute in a file and
/// refuses any other module name, because a differently-named module would make
/// that split wrong for every site below it. That lint finds the boundary with
/// a plain substring search, so this comment deliberately does NOT spell the
/// attribute out — a mention inside a doc comment IS the first match.
#[cfg(test)]
mod tests {
    use super::{recall_audit_owner_group, AuditOwnerUnresolved};
    use sqlx::PgPool;
    use uuid::Uuid;

    /// The DROP arms, asserted directly rather than through a handler.
    ///
    /// A handler-level version of this — "poll for a second and assert no row
    /// appeared" — would pass whenever the spawned write is merely slow, which
    /// is the false-green shape this suite rejects elsewhere. At the helper the
    /// answer is a value, not a race.
    ///
    /// Both arms exist because they used to be one: the earlier
    /// `Result<Option<Uuid>, DbError>` spelling made "no principal" a
    /// SUCCESS that selected the instance-wide declaration, so the two failure
    /// modes disagreed about whether to publish the row.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unresolvable_principal_is_an_error_not_a_widening(pool: PgPool) {
        assert!(
            matches!(
                recall_audit_owner_group(&pool, None).await,
                Err(AuditOwnerUnresolved::NoPrincipal)
            ),
            "no principal must be an error the caller has to handle, never an \
             owner-less row"
        );

        // A uuid that is not an `agents` row: the group cannot be resolved and
        // cannot be minted either.
        assert!(
            matches!(
                recall_audit_owner_group(&pool, Some(Uuid::new_v4())).await,
                Err(AuditOwnerUnresolved::Lookup(_))
            ),
            "a principal whose group cannot be resolved must take the same drop \
             path as no principal at all"
        );
    }

    /// The positive direction, on the same plant: a real agent resolves, and
    /// resolves to the SAME group on the second call — `personal_group_of` is
    /// mint-if-absent, and a helper that minted a fresh group per recall would
    /// scatter one agent's history across groups instead of scoping it.
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_real_principal_resolves_to_one_stable_group(pool: PgPool) {
        // Seeded through the repo layer, not an inline INSERT: `recall.rs` is
        // registered in `no_inline_sql_in_tools.rs` at zero cfg(test) SQL
        // sites, and a fixture is not a reason to move that number.
        let pk: [u8; 32] = *Uuid::new_v4().as_bytes().repeat(2).first_chunk().unwrap();
        let agent = epigraph_db::AgentRepository::create(
            &pool,
            &epigraph_core::Agent::new(pk, Some("audit-owner-fixture".to_string())),
        )
        .await
        .expect("seed agent")
        .id
        .as_uuid();

        let first = recall_audit_owner_group(&pool, Some(agent))
            .await
            .expect("a real principal resolves");
        let second = recall_audit_owner_group(&pool, Some(agent))
            .await
            .expect("and resolves again");
        assert_eq!(first, second, "one agent, one personal group, every call");
    }
}
