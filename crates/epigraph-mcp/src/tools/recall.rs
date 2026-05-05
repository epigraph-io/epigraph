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

async fn detect_centroid_dim(pool: &sqlx::PgPool) -> Result<u32, sqlx::Error> {
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

    Ok(if row.frac_3072.unwrap_or(0.0) >= 0.5 {
        3072
    } else {
        1536
    })
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
    // Underscore-prefixed: accepted now but consumed in Task 4.
    let _min_truth = params.min_truth.unwrap_or(0.3);
    let _siblings_limit = params.siblings_limit.unwrap_or(8);
    let _corroborates_limit = params.corroborates_limit.unwrap_or(4);

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

    // Stage 2: embed query at the right model (1536 -> -small, 3072 -> -large).
    let query_embedding = server
        .embedder
        .generate_at_dim(&params.query, centroid_dim)
        .await
        .map_err(|e| internal_error(format!("embed query: {e}")))?;
    let pgvec = crate::embed::format_pgvector(&query_embedding);

    // Stage 3: paragraph-primary kNN (level=2 only, optional paper_doi pre-filter).
    let raw_hits = epigraph_db::ClaimRepository::search_by_embedding(
        &server.pool,
        &pgvec,
        centroid_dim,
        i64::from(limit),
        params.paper_doi_filter.as_deref(),
    )
    .await
    .map_err(|e| internal_error(format!("kNN: {e}")))?;

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

    // Stages 4-5: filter by min_truth and assemble structural context.
    // Implemented in Task 4.
    Err(internal_error(
        "Stage 5 batch fetches not yet implemented".to_string(),
    ))
}
