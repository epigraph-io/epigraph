#![allow(clippy::doc_markdown)]

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

// Defensive deserializer for `Option<Vec<String>>` parameters.
//
// Some MCP clients double-encode array arguments when they appear
// alongside required string fields, so `tags: ["a","b"]` arrives at
// the server as the JSON-encoded string `"[\"a\",\"b\"]"`. The default
// `Vec` deserializer rejects this with `expected a sequence` and the
// tool call fails before any work happens. Accept both shapes so a
// client bug doesn't silently break every call.
fn deserialize_opt_string_array<'de, D>(d: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Vec(Vec<String>),
        Str(String),
    }

    match Option::<Either>::deserialize(d)? {
        None => Ok(None),
        Some(Either::Vec(v)) => Ok(Some(v)),
        Some(Either::Str(s)) if s.is_empty() => Ok(None),
        Some(Either::Str(s)) => serde_json::from_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

// ── Claims ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubmitClaimParams {
    #[schemars(
        description = "The epistemic claim content (e.g. 'Water boils at 100C at standard pressure')"
    )]
    pub content: String,

    #[schemars(
        description = "Methodology: bayesian_inference, deductive_logic, inductive_generalization, expert_elicitation, statistical_analysis, meta_analysis"
    )]
    pub methodology: String,

    #[schemars(
        description = "The supporting evidence text. Stored permanently for human audit — not just hashed."
    )]
    pub evidence_data: String,

    #[schemars(
        description = "Evidence type: empirical, statistical, logical, testimonial, circumstantial"
    )]
    pub evidence_type: String,

    #[schemars(description = "Confidence level 0.0-1.0")]
    pub confidence: f64,

    #[schemars(
        description = "Source URL, DOI, or reference for the evidence. Optional but strongly recommended."
    )]
    pub source_url: Option<String>,

    #[schemars(
        description = "Why does the evidence support this claim? Explicit reasoning produces richer provenance."
    )]
    pub reasoning: Option<String>,

    #[schemars(
        description = "Optional labels to attach to the new claim (e.g. ['backlog','bug'])"
    )]
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsParams {
    #[schemars(description = "Minimum balanced truth value (0.0-1.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum balanced truth value (0.0-1.0)")]
    pub max_truth: Option<f64>,

    #[schemars(description = "Maximum number of results (default 20)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryUndecomposedClaimsParams {
    #[schemars(
        description = "Maximum number of undecomposed claims to return (default 50, max 1000). Claims are ordered created_at ASC (oldest first) so scheduled runs make monotonic progress."
    )]
    pub limit: Option<i64>,

    #[schemars(
        description = "Skip the first N matching claims (default 0). Combine with limit to page through the backlog."
    )]
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetClaimParams {
    #[schemars(description = "The UUID of the claim to retrieve")]
    pub claim_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyClaimParams {
    #[schemars(description = "The UUID of the claim to verify")]
    pub claim_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateWithEvidenceParams {
    #[schemars(description = "The UUID of the claim to update")]
    pub claim_id: String,

    #[schemars(
        description = "The new evidence text. Stored permanently for human audit — not just hashed."
    )]
    pub evidence_data: String,

    #[schemars(
        description = "Evidence type: empirical, statistical, logical, testimonial, circumstantial"
    )]
    pub evidence_type: String,

    #[schemars(description = "true if evidence supports the claim, false if it refutes it")]
    pub supports: bool,

    #[schemars(description = "Evidence strength 0.0-1.0")]
    pub strength: f64,

    #[schemars(description = "Source URL or DOI for this evidence (optional)")]
    pub source_url: Option<String>,
}

// ── Provenance ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetProvenanceParams {
    #[schemars(description = "The UUID of the claim to get provenance for")]
    pub claim_id: String,
}

// ── Memory ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemorizeParams {
    #[schemars(description = "The fact, observation, or decision to remember")]
    pub content: String,

    #[schemars(description = "How confident you are in this memory (0.0-1.0, default 0.7)")]
    pub confidence: Option<f64>,

    #[schemars(
        description = "Tags for categorization, e.g. ['code', 'rust'] or ['decision', 'architecture']. \
                       Persisted as claim labels — discoverable via `query_claims_by_label`. \
                       Labels accumulate non-destructively when memorize is called more than once on the same content."
    )]
    #[serde(default, deserialize_with = "deserialize_opt_string_array")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecallParams {
    #[schemars(description = "What you want to remember — describe the topic or question")]
    pub query: String,

    #[schemars(description = "Minimum truth value for returned memories (0.0-1.0, default 0.3)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum number of memories to return (default 10)")]
    pub limit: Option<i64>,

    #[schemars(
        description = "Restrict recall to claims carrying ALL these labels/tags (array containment). Default: no tag filter."
    )]
    #[serde(default)]
    pub tags: Vec<String>,

    #[schemars(
        description = "Restrict recall to claims authored by this agent UUID. Default: any agent. An invalid UUID is rejected, not silently ignored."
    )]
    #[serde(default)]
    pub agent_id: Option<String>,
}

// ── Ingestion ──

// ── Paper Queries ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryPaperParams {
    #[schemars(description = "DOI of the paper (e.g. '10.48550/arXiv.2508.16798')")]
    pub doi: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsByEvidenceParams {
    #[schemars(
        description = "Evidence type: observation, computation, reference, testimony, document"
    )]
    pub evidence_type: String,

    #[schemars(description = "Minimum evidence strength (0.0-1.0, default 0.0)")]
    pub min_strength: Option<f64>,

    #[schemars(description = "Minimum truth value (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsByMethodologyParams {
    #[schemars(
        description = "Methodology: statistical, deductive, inductive, abductive, analogical"
    )]
    pub methodology: String,

    #[schemars(description = "Minimum truth value (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
}

// ── Label Queries ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsByLabelParams {
    #[schemars(
        description = "Labels to filter by — returns claims containing ALL specified labels (e.g. [\"backlog\", \"pending\"]). Uses PostgreSQL array containment (@>) with GIN index."
    )]
    pub labels: Vec<String>,

    #[schemars(
        description = "Labels to exclude — drops claims containing ANY of these labels (e.g. [\"resolved\"]). Default: no exclusion."
    )]
    #[serde(default)]
    pub exclude_labels: Vec<String>,

    #[schemars(
        description = "When true, returns only claims with is_current = true (drops superseded/retired claims). Default: false."
    )]
    #[serde(default)]
    pub current_only: bool,

    #[schemars(description = "Minimum truth value (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,

    #[schemars(
        description = "Skip the first N matching claims (default 0). Combine with `limit` to page through large result sets — results are ordered by `created_at DESC`."
    )]
    #[serde(default)]
    pub offset: Option<i64>,
}

// ── Workflows ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StoreWorkflowParams {
    #[schemars(
        description = "What this workflow accomplishes (e.g. 'Deploy Rust binary to Windows server')"
    )]
    pub goal: String,

    #[schemars(
        description = "Ordered list of steps (e.g. ['cargo build --release', 'scp binary to server'])"
    )]
    pub steps: Vec<String>,

    #[schemars(
        description = "Conditions that must hold before starting (e.g. ['Rust toolchain installed'])"
    )]
    #[serde(default, deserialize_with = "deserialize_opt_string_array")]
    pub prerequisites: Option<Vec<String>>,

    #[schemars(description = "Expected outcome when the workflow succeeds")]
    pub expected_outcome: Option<String>,

    #[schemars(description = "Confidence in this workflow (0.0-1.0, default 0.5 — unproven)")]
    pub confidence: Option<f64>,

    #[schemars(description = "Tags for categorization (e.g. ['deployment', 'rust', 'windows'])")]
    #[serde(default, deserialize_with = "deserialize_opt_string_array")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindWorkflowParams {
    #[schemars(description = "What you want to accomplish — describes the workflow goal")]
    pub goal: String,

    #[schemars(description = "Minimum truth value for returned workflows (0.0-1.0, default 0.3)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum number of workflows to return (default 5)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetWorkflowExecutionsParams {
    #[schemars(
        description = "Workflow UUID (a `workflows` row id / lineage member) whose recent executions to fetch"
    )]
    pub workflow_id: String,

    #[schemars(description = "Max executions to return, newest first (default 20, max 100)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EvaluateWorkflowPromotionParams {
    #[schemars(
        description = "Workflow variant UUID to evaluate for promotion over its variant_of parent"
    )]
    pub workflow_id: String,

    #[schemars(
        description = "Execution window compared on each side, newest first (default 50, max 500)"
    )]
    pub window: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StepExecution {
    #[schemars(description = "Zero-based index of the step in the workflow")]
    pub step_index: usize,

    #[schemars(description = "What the workflow plan said to do for this step")]
    pub planned: String,

    #[schemars(description = "What you actually did")]
    pub actual: String,

    #[schemars(description = "true if the actual execution differed from the plan")]
    pub deviated: bool,

    #[schemars(description = "Reason for deviation (if deviated is true)")]
    pub deviation_reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportWorkflowOutcomeParams {
    #[schemars(description = "UUID of the workflow claim to report on")]
    pub workflow_id: String,

    #[schemars(description = "true if the workflow succeeded, false if it failed")]
    pub success: bool,

    #[schemars(description = "Step-by-step execution log: planned vs actual")]
    pub execution_log: Vec<StepExecution>,

    #[schemars(
        description = "Summary of what happened (e.g. 'Completed in 45s, all checks passed')"
    )]
    pub outcome_details: String,

    #[schemars(
        description = "Execution quality 0.0-1.0 (default: 1.0 if success, 0.0 if failure)"
    )]
    pub quality: Option<f64>,

    #[schemars(
        description = "Your specific goal for this run. Falls back to the workflow's goal if omitted. More specific goal text improves future affinity matching."
    )]
    pub goal_text: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeprecateWorkflowParams {
    #[schemars(description = "UUID of the workflow to deprecate")]
    pub workflow_id: String,

    #[schemars(
        description = "Reason for deprecation (e.g. 'New API broke step 2, entire approach is obsolete')"
    )]
    pub reason: String,

    #[schemars(
        description = "Also deprecate all descendant variants of this workflow (default false)"
    )]
    pub cascade: Option<bool>,
}

// ── Hierarchical Workflows ──
//
// The flat `StoreWorkflowParams` above models steps as plain strings on a
// single root claim. The hierarchical primitive (issue #34) lands every
// step as its own claim node connected to a `workflows` row via `executes`
// edges, so each step accrues evidence and Darwinian variants independently.

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestWorkflowParams {
    #[schemars(
        description = "Hierarchical workflow extraction: source (canonical_name, goal, generation, authors, tags, metadata), thesis, thesis_derivation, phases (each with title/summary/steps where each step has compound, rationale, operations, generality, confidence), and relationships."
    )]
    pub extraction: epigraph_ingest::workflow::WorkflowExtraction,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImproveWorkflowHierarchyParams {
    #[schemars(
        description = "Canonical name of the existing workflow lineage to variant. The tool resolves the current max generation under this name and creates the new variant at generation = max + 1."
    )]
    pub parent_canonical_name: String,

    #[schemars(
        description = "Hierarchical extraction for the new variant. The tool overwrites `extraction.source.canonical_name`, `generation`, and `parent_canonical_name`: canonical_name and parent_canonical_name are both set to the tool's `parent_canonical_name` param (same-lineage improvement only — cross-lineage variants are not supported by this tool), and generation is set to the parent's current max + 1. Caller-supplied values for those three fields are ignored."
    )]
    pub extraction: epigraph_ingest::workflow::WorkflowExtraction,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindWorkflowHierarchicalParams {
    #[schemars(
        description = "Free-text search over hierarchical workflow goal and canonical_name (ILIKE). The canonical_name slug is hyphen-normalized to spaces before matching so a goal-text query still matches the slug across generations whose goals have diverged from the lineage's canonical phrase."
    )]
    pub query: String,

    #[schemars(description = "Maximum number of workflows to return (default 10, max 50).")]
    pub limit: Option<i64>,

    #[schemars(
        description = "When true, walk each step's step_lineage_id to the head version(s) and surface them as `resolved_steps`, and order results by (canonical_name ASC, generation DESC) so the newest variant per lineage is first. Defaults to false (frozen step references, newest-created-at first)."
    )]
    pub resolve_to_latest: Option<bool>,

    #[schemars(
        description = "Minimum truth value to surface; defaults to 0.3 so deprecated rows (truth=0.05 via deprecate_workflow) are hidden. Pass 0.0 to include deprecated workflows."
    )]
    pub min_truth: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HierarchicalStepExecution {
    #[schemars(
        description = "Zero-based index of the step in the workflow's plan order (matches `executes`-edge ordering at level=2)."
    )]
    pub step_index: usize,

    #[schemars(description = "What the workflow plan said to do for this step.")]
    pub planned: String,

    #[schemars(description = "What you actually did.")]
    pub actual: String,

    #[schemars(description = "true if the actual execution differed from the plan.")]
    pub deviated: bool,

    #[schemars(description = "Reason for deviation (if deviated is true).")]
    pub deviation_reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportHierarchicalOutcomeParams {
    #[schemars(
        description = "UUID of the hierarchical workflow root (a row in the `workflows` table, not a flat workflow claim)."
    )]
    pub workflow_id: String,

    #[schemars(description = "true if the workflow succeeded, false if it failed.")]
    pub success: bool,

    #[schemars(
        description = "Per-step execution log. Each step_index is resolved to the step's claim node via `executes` edges so per-step evidence accrues."
    )]
    pub step_executions: Vec<HierarchicalStepExecution>,

    #[schemars(
        description = "Summary of what happened (e.g. 'Completed in 45s, all checks passed')."
    )]
    pub outcome_details: String,

    #[schemars(
        description = "Execution quality 0.0-1.0 (default: 1.0 if success, 0.0 if failure)."
    )]
    pub quality: Option<f64>,

    #[schemars(
        description = "Your specific goal for this run. More specific goal text improves future affinity matching."
    )]
    pub goal_text: Option<String>,
}

// ── Graph ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetNeighborhoodParams {
    #[schemars(description = "The UUID of the node to get neighbors for")]
    pub node_id: String,

    #[schemars(
        description = "Filter by relationship type (e.g. 'asserts', 'authored', 'variant_of', 'produced')"
    )]
    pub relationship: Option<String>,

    #[schemars(
        description = "Edge direction: 'outgoing', 'incoming', or 'both' (default: 'both')"
    )]
    pub direction: Option<String>,

    #[schemars(description = "Maximum number of edges to return (default 50)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraverseParams {
    #[schemars(description = "UUID of the starting node for traversal")]
    pub start_id: String,

    #[schemars(description = "Maximum number of hops from start node (default 2, max 4)")]
    pub max_depth: Option<i64>,

    #[schemars(
        description = "Only follow edges with this relationship type (e.g. 'asserts', 'variant_of')"
    )]
    pub relationship: Option<String>,

    #[schemars(description = "Minimum truth value for claim nodes (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum number of nodes to return (default 50, max 100)")]
    pub limit: Option<i64>,
}

// ── DS/Belief ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFrameParams {
    #[schemars(
        description = "Unique name for the frame (e.g. 'climate_attribution' or 'treatment_efficacy')"
    )]
    pub name: String,

    #[schemars(description = "Description of what this frame represents")]
    pub description: Option<String>,

    #[schemars(
        description = "Ordered list of mutually exclusive hypotheses (e.g. ['anthropogenic', 'natural', 'mixed'])"
    )]
    pub hypotheses: Vec<String>,

    #[schemars(description = "Whether this frame can be refined into sub-frames (default true)")]
    pub is_refinable: Option<bool>,

    #[schemars(description = "Optional parent frame UUID if this is a refinement")]
    pub parent_frame_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SubmitDsEvidenceParams {
    #[schemars(description = "UUID of the claim to submit DS evidence for")]
    pub claim_id: String,

    #[schemars(description = "UUID of the frame of discernment")]
    pub frame_id: String,

    #[schemars(description = "0-based index of the hypothesis this claim represents in the frame")]
    pub hypothesis_index: i32,

    #[schemars(
        description = "Mass assignments: {'0': 0.6, '0,1': 0.3, '~0,1': 0.1}. Keys: comma-separated indices (positive) or ~-prefixed (negative/complement). '' = conflict, '~' = open-world ignorance."
    )]
    pub masses: serde_json::Value,

    #[schemars(
        description = "Source reliability: 1.0 = fully reliable, 0.0 = ignore. Default 1.0"
    )]
    pub reliability: Option<f64>,

    #[schemars(
        description = "Combination method: Dempster (default), Conjunctive, YagerOpen, YagerClosed, DuboisPrade, Inagaki"
    )]
    pub combination_method: Option<String>,

    #[schemars(
        description = "Inagaki gamma parameter (only used with Inagaki method, default 0.5)"
    )]
    pub gamma: Option<f64>,

    #[schemars(description = "Perspective UUID for scoped combination (optional)")]
    pub perspective_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetBeliefParams {
    #[schemars(description = "UUID of the claim to query belief for")]
    pub claim_id: String,

    #[schemars(
        description = "Optional frame UUID. If provided, recomputes Bel/Pl/BetP from stored BBAs. If omitted, returns cached DS columns."
    )]
    pub frame_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFramesParams {
    #[schemars(description = "Maximum number of frames to return (default 20)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareMethodsParams {
    #[schemars(description = "UUID of the claim")]
    pub claim_id: String,

    #[schemars(description = "UUID of the frame of discernment")]
    pub frame_id: String,

    #[schemars(description = "0-based hypothesis index for Bel/Pl/BetP")]
    pub hypothesis_index: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScopedBeliefParams {
    #[schemars(description = "UUID of the claim")]
    pub claim_id: String,

    #[schemars(description = "Scope type: 'perspective' or 'community'")]
    pub scope_type: String,

    #[schemars(description = "UUID of the perspective or community")]
    pub scope_id: String,

    #[schemars(
        description = "Optional frame UUID. When set with scope_type='perspective', the \
                       belief is computed live from the claim's BBAs, each discounted by \
                       this perspective's source-reliability map (the frame function), so \
                       it reflects current evidence regardless of ingest path. When \
                       omitted, returns the cached scoped belief if one exists."
    )]
    #[serde(default)]
    pub frame_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetDivergenceParams {
    #[schemars(description = "UUID of the claim to query DS-vs-Bayesian divergence for")]
    pub claim_id: String,
}

// ── Response types ──

#[derive(Debug, Serialize)]
pub struct EpistemicSummary {
    pub truth_value: f64,
    pub evidence_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ClaimResponse {
    pub id: String,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: String,
    pub content_hash: String,
    pub created_at: String,
    pub labels: Vec<String>,
    pub is_current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitClaimResponse {
    pub claim_id: String,
    pub truth_value: f64,
    pub content_hash: String,
    pub embedded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub claim_id: String,
    pub signature_valid: bool,
    pub hash_matches: bool,
    pub truth_value: f64,
}

#[derive(Debug, Serialize)]
pub struct UpdateResponse {
    pub claim_id: String,
    pub truth_before: f64,
    pub truth_after: f64,
    pub evidence_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MemorizeResponse {
    pub claim_id: String,
    pub truth_value: f64,
    pub embedded: bool,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct RecallResult {
    pub claim_id: String,
    pub content: String,
    pub truth_value: f64,
    /// Dense cosine similarity in `[0,1]`; `0.0` for a lexical-only hit.
    pub similarity: f64,
    /// Reciprocal Rank Fusion score (primary ordering).
    pub rrf_score: f64,
    /// Which legs matched: subset of `["dense","lexical"]`.
    pub matched_via: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorResponse {
    pub agent_id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestDocumentParams {
    #[schemars(
        description = "Absolute or working-directory-relative path to a JSON file containing a hierarchical DocumentExtraction (thesis -> sections -> paragraphs -> atoms)."
    )]
    pub file_path: String,
}

/// Parameters for the `link_hierarchical` MCP tool.
///
/// Wires two existing claims with one of the structural relationships emitted
/// by the hierarchical ingest pipeline (`decomposes_to`, `section_follows`,
/// `continues_argument`). Mirrors the contract of
/// `POST /api/v1/edges/hierarchical` but bypasses HTTP and goes directly
/// through the repo layer, which keeps per-chapter chapter-to-book wiring
/// working when the HTTP API binary is unavailable.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkHierarchicalParams {
    #[schemars(description = "UUID of the source claim")]
    pub source_claim_id: String,

    #[schemars(description = "UUID of the target claim")]
    pub target_claim_id: String,

    #[schemars(
        description = "Structural relationship type. One of: decomposes_to, section_follows, continues_argument."
    )]
    pub relationship: String,

    #[schemars(description = "Optional arbitrary JSON object attached to the edge.")]
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

/// Response for the `link_hierarchical` MCP tool.
///
/// `created=true` means a new edge row was inserted; `created=false` means an
/// edge with the same `(source, target, relationship)` triple already
/// existed and the existing edge_id is returned (idempotent re-runs).
#[derive(Debug, Serialize)]
pub struct LinkHierarchicalResponse {
    pub edge_id: String,
    pub created: bool,
}

#[derive(Debug, Serialize)]
pub struct IngestDocumentResponse {
    pub paper_id: String,
    pub paper_title: String,
    pub doi: String,
    pub authors: Vec<AuthorResponse>,
    pub claims_ingested: usize,
    pub claims_embedded: usize,
    pub claims_skipped_dedup: usize,
    pub relationships_created: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_ds_wired: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_frame_id: Option<String>,
    pub already_ingested: bool,
}

#[derive(Debug, Serialize)]
pub struct PaperResponse {
    pub doi: String,
    pub title: String,
    pub authors: Vec<AuthorResponse>,
    pub claim_count: i64,
    pub claims: Vec<ClaimResponse>,
}

#[derive(Debug, Serialize)]
pub struct StoreWorkflowResponse {
    /// `workflows.id` (deterministic from canonical_name + generation).
    pub workflow_id: String,
    pub canonical_name: String,
    pub goal: String,
    pub generation: i32,
    pub step_count: usize,
    pub claims_ingested: usize,
    /// `true` if a workflow with this `(canonical_name, generation)` was
    /// already present and the call short-circuited.
    pub already_ingested: bool,
}

#[derive(Debug, Serialize)]
pub struct FindWorkflowResult {
    pub workflow_id: String,
    pub goal: String,
    pub steps: Vec<String>,
    pub truth_value: f64,
    pub similarity: f64,
    pub use_count: i64,
    pub success_count: i64,
    pub generation: i64,
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_affinity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_success_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_execution_count: Option<i64>,
    /// Set by the workflow-promotion maintenance pass (`refresh_workflow_promotion`)
    /// from the variant's `properties.promotion.promotable`. `Some(true)` means
    /// the gate found this variant statistically better than its parent; absent
    /// when never evaluated. Advisory — callers may prefer promoted variants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotable: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ReportWorkflowOutcomeResponse {
    pub workflow_id: String,
    pub evidence_id: String,
    pub truth_before: f64,
    pub truth_after: f64,
    pub total_uses: i64,
    pub success_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct DeprecateWorkflowResponse {
    pub deprecated_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct NeighborhoodEdge {
    pub edge_id: String,
    pub source_id: String,
    pub source_type: String,
    pub target_id: String,
    pub target_type: String,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct NeighborhoodResponse {
    pub node_id: String,
    pub edge_count: usize,
    pub edges: Vec<NeighborhoodEdge>,
}

#[derive(Debug, Serialize)]
pub struct TraverseNode {
    pub id: String,
    pub node_type: String,
    pub label: Option<String>,
    pub truth_value: Option<f64>,
    pub depth: i32,
}

#[derive(Debug, Serialize)]
pub struct TraverseEdge {
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
}

#[derive(Debug, Serialize)]
pub struct TraverseResponse {
    pub start_id: String,
    pub nodes: Vec<TraverseNode>,
    pub edges: Vec<TraverseEdge>,
    pub depth_reached: i32,
}

// ── DS Response types ──

#[derive(Debug, Serialize)]
pub struct CreateFrameResponse {
    pub frame_id: String,
    pub name: String,
    pub hypotheses: Vec<String>,
    pub version: i32,
}

#[derive(Debug, Serialize)]
pub struct DsEvidenceResponse {
    pub mass_function_id: String,
    pub claim_id: String,
    pub frame_id: String,
    pub belief: f64,
    pub plausibility: f64,
    pub ignorance: f64,
    pub pignistic_prob: f64,
    pub mass_on_conflict: f64,
    pub mass_on_missing: f64,
    pub bba_count: i64,
    pub method_used: String,
}

#[derive(Debug, Serialize)]
pub struct BeliefResponse {
    pub claim_id: String,
    pub belief: f64,
    pub plausibility: f64,
    pub ignorance: f64,
    pub pignistic_prob: f64,
    pub mass_on_conflict: f64,
    pub mass_on_missing: f64,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct FrameEntry {
    pub frame_id: String,
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
    pub version: i32,
    pub parent_frame_id: Option<String>,
    pub is_refinable: bool,
}

#[derive(Debug, Serialize)]
pub struct CompareMethodResult {
    pub method: String,
    pub belief: f64,
    pub plausibility: f64,
    pub pignistic_prob: f64,
    pub mass_on_conflict: f64,
    pub mass_on_missing: f64,
}

#[derive(Debug, Serialize)]
pub struct CompareMethodsResponse {
    pub claim_id: String,
    pub frame_id: String,
    pub hypothesis_index: i32,
    pub results: Vec<CompareMethodResult>,
}

#[derive(Debug, Serialize)]
pub struct ScopedBeliefResponse {
    pub claim_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub belief: f64,
    pub plausibility: f64,
    pub mass_on_conflict: f64,
    pub mass_on_missing: f64,
    pub pignistic_prob: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct DivergenceResponse {
    pub claim_id: String,
    pub pignistic_prob: f64,
    pub bayesian_posterior: f64,
    pub kl_divergence: f64,
    pub computed_at: String,
}

// ── Claim mutation ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MarkDuplicateParams {
    #[schemars(description = "UUID of the duplicate claim")]
    pub claim_id: String,
    #[schemars(description = "UUID of the canonical claim")]
    pub canonical_id: String,
    #[schemars(description = "Reason for marking duplicate")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SupersedeClaimParams {
    #[schemars(description = "UUID of the claim being superseded")]
    pub claim_id: String,
    #[schemars(description = "Content of the new superseding claim")]
    pub content: String,
    #[schemars(description = "Truth value of the new claim (0.0–1.0)")]
    pub truth_value: f64,
    #[schemars(description = "Why the previous claim is being superseded")]
    pub reason: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveBacklogItemParams {
    #[schemars(description = "UUID of the backlog claim being retired")]
    pub original_id: String,

    #[schemars(
        description = "Narrative explaining how the issue was resolved. Will be prefixed with 'Resolves <original_id>: '."
    )]
    pub resolution_content: String,

    #[schemars(
        description = "Methodology for the resolution claim (default: 'expert_elicitation'). Use 'inductive_generalization' if the resolution generalizes from an observed pattern."
    )]
    pub methodology: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateLabelsParams {
    #[schemars(description = "UUID of the claim to label")]
    pub claim_id: String,
    #[schemars(description = "Labels to add (idempotent)")]
    #[serde(default)]
    pub add: Vec<String>,
    #[schemars(description = "Labels to remove (idempotent)")]
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchClaimParams {
    #[schemars(description = "UUID of the claim to patch")]
    pub claim_id: String,
    #[schemars(description = "New trace_id (must reference an existing reasoning_traces row)")]
    pub trace_id: Option<String>,
    #[schemars(description = "JSONB to merge into properties")]
    pub properties: Option<serde_json::Value>,
    #[schemars(description = "Labels to add")]
    #[serde(default)]
    pub add_labels: Vec<String>,
    #[schemars(description = "Labels to remove")]
    #[serde(default)]
    pub remove_labels: Vec<String>,
}

// ── Challenges ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChallengeclaimParams {
    #[schemars(description = "UUID of the claim to challenge")]
    pub claim_id: String,

    #[schemars(
        description = "Challenge type: insufficient_evidence, outdated_evidence, flawed_methodology, contradicting_evidence, factual_error"
    )]
    pub challenge_type: String,

    #[schemars(description = "Detailed explanation of why this claim is being challenged")]
    pub explanation: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListChallengesParams {
    #[schemars(description = "UUID of the claim to list challenges for")]
    pub claim_id: String,
}

// ── Events ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListEventsParams {
    #[schemars(description = "Filter by event type (e.g. 'claim.created', 'claim.challenged')")]
    pub event_type: Option<String>,

    #[schemars(description = "Filter by actor UUID")]
    pub actor_id: Option<String>,

    #[schemars(description = "Maximum number of events to return (default 50)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PublishEventParams {
    #[schemars(description = "Event type (e.g. 'claim.created', 'analysis.completed')")]
    pub event_type: String,

    #[schemars(description = "UUID of the actor (agent) triggering this event")]
    pub actor_id: Option<String>,

    #[schemars(description = "JSON payload with event details")]
    pub payload: serde_json::Value,
}

// ── Batch / Staging / Stats ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchSubmitClaimsParams {
    #[schemars(description = "Array of claim objects to submit (max 100)")]
    pub claims: Vec<BatchClaimEntry>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchClaimEntry {
    #[schemars(description = "The claim content")]
    pub content: String,

    #[schemars(description = "Evidence text")]
    pub evidence_data: String,

    #[schemars(description = "Evidence type: empirical, statistical, logical, testimonial")]
    pub evidence_type: String,

    #[schemars(description = "Confidence 0.0-1.0")]
    pub confidence: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StageClaimsParams {
    #[schemars(description = "Array of claim content strings to validate without persisting")]
    pub claims: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SystemStatsParams {
    #[schemars(description = "Include detailed breakdowns by type (default false)")]
    pub detailed: Option<bool>,
}

// ── Sheaf ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckSheafConsistencyParams {
    #[schemars(
        description = "Minimum consistency radius to include in results (0.0-1.0, default 0.1). Higher values return only the most inconsistent nodes."
    )]
    pub min_radius: Option<f64>,

    #[schemars(
        description = "Maximum number of sections to return, sorted by inconsistency (default 50, max 200)"
    )]
    pub limit: Option<i64>,

    #[schemars(
        description = "Restriction profile for edge belief transmission: 'scientific' (default) or 'regulatory'. Scientific uses looser factors; regulatory uses stricter transmission."
    )]
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SheafCohomologyParams {
    #[schemars(
        description = "Minimum edge inconsistency to count as an obstruction (default 0.05). Lower values surface more subtle inconsistencies."
    )]
    pub threshold: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReconcileSheafParams {
    #[schemars(
        description = "Minimum obstruction inconsistency to process in reconciliation (default 0.15). Only obstructions above this threshold trigger belief-propagation repair."
    )]
    pub min_inconsistency: Option<f64>,

    #[schemars(
        description = "Maximum outer reconciliation iterations (default 3). Each pass re-checks which obstructions remain after the previous BP run."
    )]
    pub max_depth: Option<usize>,

    #[schemars(
        description = "Restriction profile: 'scientific' (default) or 'regulatory'. Determines edge transmission factors used during reconciliation."
    )]
    pub profile: Option<String>,
}

// ── Sheaf Response types ──

#[derive(Debug, Serialize)]
pub struct SheafSectionEntry {
    pub node_id: String,
    pub local_betp: f64,
    pub expected_betp: f64,
    pub consistency_radius: f64,
    pub neighbor_count: usize,
    pub local_belief: f64,
    pub local_plausibility: f64,
    pub open_world_local: f64,
    pub open_world_expected: f64,
    pub interval_inconsistency: f64,
    pub ignorance_inconsistency: f64,
}

#[derive(Debug, Serialize)]
pub struct CheckSheafConsistencyResponse {
    pub sections: Vec<SheafSectionEntry>,
    pub min_radius_threshold: f64,
    pub max_radius: f64,
}

#[derive(Debug, Serialize)]
pub struct CdstObstructionEntry {
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub source_betp: f64,
    pub target_betp: f64,
    pub expected_target_betp: f64,
    pub edge_inconsistency: f64,
    pub obstruction_kind: String,
    pub conflict_component: f64,
    pub ignorance_component: f64,
    pub open_world_component: f64,
}

#[derive(Debug, Serialize)]
pub struct SheafCohomologyResponse {
    pub h0: usize,
    pub h1: f64,
    pub h1_normalized: f64,
    pub edge_count: usize,
    pub consistency_threshold: f64,
    pub conflict_h1: f64,
    pub ignorance_h1: f64,
    pub open_world_h1: f64,
    pub belief_conflict_count: usize,
    pub open_world_spread_count: usize,
    pub frame_closure_count: usize,
    pub ignorance_drift_count: usize,
    pub obstructions: Vec<CdstObstructionEntry>,
    pub obstruction_count: usize,
}

#[derive(Debug, Serialize)]
pub struct UpdatedIntervalEntry {
    pub node_id: String,
    pub bel: f64,
    pub pl: f64,
    pub betp: f64,
    pub open_world: f64,
}

#[derive(Debug, Serialize)]
pub struct FrameEvidenceProposalEntry {
    pub target_claim_id: String,
    pub evidence_source_id: String,
    pub proposed_reduction: f64,
    pub confidence: f64,
    pub scope_description: String,
}

#[derive(Debug, Serialize)]
pub struct OversizedClusterEntry {
    pub node_count: usize,
    pub obstruction_count: usize,
    pub max_inconsistency: f64,
}

#[derive(Debug, Serialize)]
pub struct ReconcileSheafResponse {
    pub clusters_processed: usize,
    pub converged: bool,
    pub total_iterations: usize,
    pub updated_count: usize,
    pub updated_intervals: Vec<UpdatedIntervalEntry>,
    pub frame_evidence_proposals: Vec<FrameEvidenceProposalEntry>,
    pub oversized_clusters: Vec<OversizedClusterEntry>,
    pub min_inconsistency: f64,
    pub max_depth: usize,
}

// ── Perspectives ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreatePerspectiveParams {
    #[schemars(
        description = "Name for the perspective (e.g. 'climate_skeptic' or 'bayesian_analyst')"
    )]
    pub name: String,

    #[schemars(description = "Description of what this perspective represents")]
    pub description: Option<String>,

    #[schemars(
        description = "UUID of the agent who owns this perspective (defaults to current agent)"
    )]
    pub owner_agent_id: Option<String>,

    #[schemars(
        description = "Perspective type: analytical, ideological, disciplinary, cultural (default: analytical)"
    )]
    pub perspective_type: Option<String>,

    #[schemars(description = "Frame UUIDs this perspective is associated with")]
    #[serde(default, deserialize_with = "deserialize_opt_string_array")]
    pub frame_ids: Option<Vec<String>>,

    #[schemars(
        description = "How the perspective was extracted: ai_generated, manual, survey (default: ai_generated)"
    )]
    pub extraction_method: Option<String>,

    #[schemars(description = "Confidence calibration 0.0-1.0 (default 0.5)")]
    pub confidence_calibration: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetSourceReliabilityParams {
    #[schemars(description = "UUID of the perspective whose source-reliability lens to set")]
    pub perspective_id: String,

    #[schemars(
        description = "Map of evidence-type tag -> reliability alpha in [0,1] (e.g. {\"western_clinical\":0.95,\"ayurvedic_classical\":0.15}). This is the frame-function lens read by scoped_belief. An empty map clears the override."
    )]
    pub source_reliability: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListPerspectivesParams {
    #[schemars(description = "Maximum number of perspectives to return (default 20)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetPerspectiveParams {
    #[schemars(description = "UUID of the perspective to retrieve")]
    pub perspective_id: String,
}

// ── Ownership ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AssignOwnershipParams {
    #[schemars(description = "UUID of the node to assign ownership for")]
    pub node_id: String,

    #[schemars(
        description = "Type of node: claim, agent, evidence, perspective, community, context, frame (default: claim)"
    )]
    pub node_type: Option<String>,

    #[schemars(description = "Partition type: public, community, private (default: public)")]
    pub partition_type: Option<String>,

    #[schemars(description = "UUID of the agent who owns this node (defaults to current agent)")]
    pub owner_id: Option<String>,

    #[schemars(description = "For community partitions: community UUID that gates read access")]
    pub community_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetOwnershipParams {
    #[schemars(description = "UUID of the node to get ownership info for")]
    pub node_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdatePartitionParams {
    #[schemars(description = "UUID of the node to update")]
    pub node_id: String,

    #[schemars(description = "New partition type: public, community, private")]
    pub partition_type: String,
}

// ── RDF Triple Layer ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryTriplesParams {
    #[schemars(description = "Subject entity name (optional — omit to wildcard)")]
    pub subject: Option<String>,
    #[schemars(description = "Subject entity type: Material, Molecule, Method, etc. (optional)")]
    pub subject_type: Option<String>,
    #[schemars(description = "Predicate pattern — matches via trigram similarity (optional)")]
    pub predicate: Option<String>,
    #[schemars(description = "Object entity name (optional)")]
    pub object: Option<String>,
    #[schemars(description = "Object entity type (optional)")]
    pub object_type: Option<String>,
    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EntityNeighborhoodParams {
    #[schemars(description = "Entity name or UUID — returns all triples involving this entity")]
    pub entity: String,
    #[schemars(description = "Entity type hint for name resolution (optional, default Material)")]
    pub entity_type: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchTriplesParams {
    #[schemars(
        description = "Natural language query — searches triples via entity matching + embedding fallback"
    )]
    pub query: String,
    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memorize_tags_accepts_array() {
        let p: MemorizeParams =
            serde_json::from_str(r#"{"content":"x","tags":["a","b"]}"#).unwrap();
        assert_eq!(p.tags.as_deref(), Some(["a".into(), "b".into()].as_slice()));
    }

    #[test]
    fn memorize_tags_accepts_double_encoded_string() {
        // Some MCP clients double-encode array params alongside string params.
        let p: MemorizeParams =
            serde_json::from_str(r#"{"content":"x","tags":"[\"a\",\"b\"]"}"#).unwrap();
        assert_eq!(p.tags.as_deref(), Some(["a".into(), "b".into()].as_slice()));
    }

    #[test]
    fn memorize_tags_accepts_null() {
        let p: MemorizeParams = serde_json::from_str(r#"{"content":"x","tags":null}"#).unwrap();
        assert!(p.tags.is_none());
    }

    #[test]
    fn memorize_tags_accepts_missing() {
        let p: MemorizeParams = serde_json::from_str(r#"{"content":"x"}"#).unwrap();
        assert!(p.tags.is_none());
    }

    #[test]
    fn memorize_tags_empty_string_is_none() {
        let p: MemorizeParams = serde_json::from_str(r#"{"content":"x","tags":""}"#).unwrap();
        assert!(p.tags.is_none());
    }

    #[test]
    fn memorize_tags_invalid_string_errors() {
        let r: Result<MemorizeParams, _> =
            serde_json::from_str(r#"{"content":"x","tags":"not-json"}"#);
        assert!(r.is_err());
    }
}

// ── Cross-source matching (T19) ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindCrossSourceMatchesParams {
    #[schemars(description = "Claim UUID to look up existing cross-source matches for")]
    pub claim_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListMatchCandidatesParams {
    #[schemars(description = "Optional status filter: pending | promoted | rejected | stale")]
    pub status: Option<String>,
    #[schemars(description = "Maximum candidates to return (default 50, max 500)")]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecideMatchCandidateParams {
    #[schemars(description = "Match-candidate UUID to decide on")]
    pub candidate_id: String,
    #[schemars(description = "Decision: 'promote' (writes CORROBORATES edge) or 'reject'")]
    pub verdict: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecomputeBeliefsParams {
    #[schemars(
        description = "Explicit claim UUIDs to recompute. Highest-priority target selector — when present and non-empty, `labels` and the bulk enumeration are ignored."
    )]
    #[serde(default)]
    pub claim_ids: Option<Vec<String>>,

    #[schemars(
        description = "Recompute every current claim carrying ALL of these labels (e.g. a paper's claim set). Used only when `claim_ids` is absent/empty."
    )]
    #[serde(default)]
    pub labels: Option<Vec<String>>,

    #[schemars(
        description = "Cap on the number of claims processed (default 500, max 2000). For the bulk path (no claim_ids/labels) this bounds the DISTINCT-claim enumeration and the response reports `truncated=true` when more remain — page with repeated calls or use the `epigraph-recompute-belief` CLI for full-DB rebuilds."
    )]
    pub limit: Option<i64>,

    #[schemars(
        description = "Offset into the bulk DISTINCT-claim enumeration for pagination (default 0). Ignored when `claim_ids` or `labels` is given."
    )]
    #[serde(default)]
    pub offset: Option<i64>,
}
