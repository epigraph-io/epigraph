//! `recall_with_context` MCP tool — paragraph-primary semantic search with
//! batched structural context. See docs/superpowers/specs/2026-05-05-recall-with-context-design.md.

use rmcp::model::CallToolResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;

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
    _server: &EpiGraphMcpFull,
    _params: RecallWithContextParams,
) -> Result<CallToolResult, McpError> {
    // Filled in by later tasks. Stub keeps the file compilable.
    Err(internal_error("recall_with_context not yet implemented"))
}
