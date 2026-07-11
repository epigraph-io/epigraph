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

pub async fn paragraph_3072_population(pool: &sqlx::PgPool) -> Result<f64, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE embedding_3072 IS NOT NULL)::float8
              / NULLIF(COUNT(*), 0)::float8 AS frac_3072
        FROM claims
        WHERE (properties->>'level')::int = 2
        "#
    )
    .fetch_one(pool)
    .await?;
    Ok(row.frac_3072.unwrap_or(0.0))
}

async fn detect_centroid_dim(pool: &sqlx::PgPool) -> Result<u32, sqlx::Error> {
    let frac = paragraph_3072_population(pool).await?;
    Ok(if frac >= 0.5 { 3072 } else { 1536 })
}

async fn compute_corpus_scope(pool: &sqlx::PgPool) -> Result<CorpusScope, sqlx::Error> {
    // Per spec §3.1 / Locked-in 5.5: corpus_scope always populated on success.
    // One round-trip with subselects to avoid four separate COUNT queries.
    let row = sqlx::query!(
        r#"
        SELECT
          (SELECT COUNT(*) FROM claims) AS claims_total,
          (SELECT COUNT(*) FROM claims WHERE (properties->>'level')::int = 2) AS paragraph_total,
          (SELECT COUNT(*) FROM papers) AS paper_total,
          (SELECT COUNT(*) FROM claim_themes) AS themes_total
        "#
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
}

#[derive(Debug, Clone, Serialize)]
pub struct RecallWithContextResponse {
    pub results: Vec<RecallHit>,
    pub corpus_scope: CorpusScope,
    pub centroid_dim_used: u32,
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
    params: RecallWithContextParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let siblings_limit = params.siblings_limit.unwrap_or(8);
    let corroborates_limit = params.corroborates_limit.unwrap_or(4);
    let neighbor_paragraphs_limit = params.neighbor_paragraphs_limit.unwrap_or(16);

    // Stage 1: pick centroid_dim (request hint OR auto-detect via population threshold).
    let centroid_dim = match params.centroid_dim {
        Some(d) if d == 1536 || d == 3072 => d,
        Some(d) => {
            return Err(invalid_params(format!(
                "centroid_dim must be 1536 or 3072 (got {d})"
            )));
        }
        None => detect_centroid_dim(&server.pool)
            .await
            .map_err(|e| internal_error(format!("auto-detect centroid_dim: {e}")))?,
    };

    // Spec §3.4: explicit 3072 against an unpopulated column must error
    // (otherwise the empty kNN result is indistinguishable from "no relevant paragraphs").
    if matches!(params.centroid_dim, Some(3072)) {
        let frac = paragraph_3072_population(&server.pool)
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
        crate::tools::lens::validate_lens_exists(&server.pool, frame_id, perspective_id).await?;
    }

    recall_with_context_post_embed(
        server,
        &params,
        centroid_dim,
        &pgvec,
        limit,
        min_truth,
        siblings_limit,
        corroborates_limit,
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
    seeds: Vec<epigraph_db::ClaimEmbeddingHit>,
    depth: u32,
) -> Result<Vec<epigraph_db::ClaimEmbeddingHit>, McpError> {
    let seed_ids: Vec<Uuid> = seeds.iter().map(|h| h.claim_id).collect();
    let seed_similarity: std::collections::HashMap<Uuid, f64> =
        seeds.iter().map(|h| (h.claim_id, h.similarity)).collect();

    let expansion = epigraph_db::ClaimRepository::graph_expand_seeds(pool, &seed_ids, depth)
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
    let degree = epigraph_db::ClaimRepository::in_epistemic_degree_batch(pool, &all_ids)
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
    params: &RecallWithContextParams,
    centroid_dim: u32,
    pgvec: &str,
    limit: u32,
    min_truth: f64,
    siblings_limit: u32,
    corroborates_limit: u32,
    neighbor_paragraphs_limit: u32,
    lens: Option<(Uuid, Uuid)>,
) -> Result<CallToolResult, McpError> {
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
        };
        let selected =
            epigraph_engine::diverse_retrieval::run_diverse_pipeline(&server.pool, pgvec, config)
                .await
                .map_err(|e| internal_error(format!("diverse retrieval: {e}")))?;

        if selected.is_empty() {
            // No themes (or no candidates in themes) — fall back to flat ANN
            // so callers still get results in a freshly-clustered or
            // unclustered corpus. Matches the REST diverse-mode fallback.
            epigraph_db::ClaimRepository::search_by_embedding(
                &server.pool,
                pgvec,
                centroid_dim,
                flat_limit,
                params.paper_doi_filter.as_deref(),
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
        epigraph_db::ClaimRepository::search_by_embedding(
            &server.pool,
            pgvec,
            centroid_dim,
            flat_limit,
            params.paper_doi_filter.as_deref(),
        )
        .await
        .map_err(|e| internal_error(format!("kNN: {e}")))?
    };

    if raw_hits.is_empty() {
        // Empty result still returns corpus_scope (#52 Finding 2).
        let corpus_scope = compute_corpus_scope(&server.pool)
            .await
            .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;
        return success_json(&RecallWithContextResponse {
            results: vec![],
            corpus_scope,
            centroid_dim_used: centroid_dim,
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
        raw_hits = apply_graph_expansion(&server.pool, raw_hits, depth).await?;
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
        let contents = epigraph_db::ClaimRepository::contents_by_ids(&server.pool, &ids)
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
        &paragraph_ids,
        siblings_limit,
        corroborates_limit,
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

    let corpus_scope = compute_corpus_scope(&server.pool)
        .await
        .map_err(|e| internal_error(format!("corpus_scope: {e}")))?;

    success_json(&RecallWithContextResponse {
        results,
        corpus_scope,
        centroid_dim_used: centroid_dim,
    })
}

pub struct ParagraphCore {
    pub content: String,
    pub truth_value: f64,
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

pub async fn fetch_batched_context(
    pool: &sqlx::PgPool,
    paragraph_ids: &[Uuid],
    siblings_limit: u32,
    corroborates_limit: u32,
) -> Result<BatchedContext, sqlx::Error> {
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
            "#,
            paragraph_ids
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
            atoms_per_paragraph_cap
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
                SELECT e.target_id AS atom_id, e.source_id AS parent_paragraph_id
                FROM edges e
                WHERE e.target_id = ANY($1)
                  AND e.relationship = 'decomposes_to'
                "#,
                &atom_ids
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
                "#,
                &section_ids
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
                JOIN claims c ON c.id = n.neighbor_id
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
            i64::from(corroborates_limit)
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

    // 8. continues_argument neighbors (Query A) — bidirectional.
    {
        let rows = sqlx::query!(
            r#"
            SELECT e.source_id AS "paragraph_id!", e.target_id AS "neighbor_id!"
            FROM edges e
            WHERE e.source_id = ANY($1) AND e.relationship = 'continues_argument'
            UNION ALL
            SELECT e.target_id AS "paragraph_id!", e.source_id AS "neighbor_id!"
            FROM edges e
            WHERE e.target_id = ANY($1) AND e.relationship = 'continues_argument'
            "#,
            paragraph_ids
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
                )
                SELECT atom_a AS "atom_a!", atom_b AS "atom_b!", relationship AS "relationship!"
                FROM forward
                UNION ALL
                SELECT atom_a AS "atom_a!", atom_b AS "atom_b!", relationship AS "relationship!"
                FROM backward
                "#,
                &our_atom_ids
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
                "#,
                &atom_b_ids
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

    // 1. Paragraphs themselves (content + truth_value) — extended to cover neighbor IDs.
    {
        let rows = sqlx::query!(
            "SELECT id, content, truth_value FROM claims WHERE id = ANY($1)",
            &all_paragraph_ids
        )
        .fetch_all(pool)
        .await?;
        for r in rows {
            paragraph_meta.insert(
                r.id,
                ParagraphCore {
                    content: r.content,
                    truth_value: r.truth_value,
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
            WHERE e.target_id = ANY($1)
              AND e.relationship = 'asserts'
              AND e.source_type = 'paper'
            "#,
            &all_paragraph_ids
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
        params: RecallWithContextParams,
        centroid_dim: u32,
        pgvec: &str,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).clamp(1, 50);
        let min_truth = params.min_truth.unwrap_or(0.3);
        let siblings_limit = params.siblings_limit.unwrap_or(8);
        let corroborates_limit = params.corroborates_limit.unwrap_or(4);
        let neighbor_paragraphs_limit = params.neighbor_paragraphs_limit.unwrap_or(16);
        // Mirror the real entry: resolve + existence-check the lens up front so
        // integration tests exercise the same validation path.
        let lens = crate::tools::lens::resolve_lens(
            params.frame_id.as_deref(),
            params.perspective_id.as_deref(),
        )?;
        if let Some((frame_id, perspective_id)) = lens {
            crate::tools::lens::validate_lens_exists(&server.pool, frame_id, perspective_id)
                .await?;
        }
        recall_with_context_post_embed(
            server,
            &params,
            centroid_dim,
            pgvec,
            limit,
            min_truth,
            siblings_limit,
            corroborates_limit,
            neighbor_paragraphs_limit,
            lens,
        )
        .await
    }
}
