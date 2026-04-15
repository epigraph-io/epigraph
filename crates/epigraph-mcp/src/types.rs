#![allow(clippy::doc_markdown)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
        description = "Tags for categorization, e.g. ['code', 'rust'] or ['decision', 'architecture']"
    )]
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
}

// ── Ingestion ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestPaperParams {
    #[schemars(
        description = "Absolute file path to the claims JSON (e.g. '/data/extractions/paper_claims.json')"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestPaperUrlParams {
    #[schemars(
        description = "Paper source: arXiv ID like '2508.16798', DOI like '10.48550/arXiv.2508.16798', or absolute path to a local PDF"
    )]
    pub source: String,

    #[schemars(
        description = "Directory for intermediate extraction files (default: /tmp/epigraph-extractions)"
    )]
    pub output_dir: Option<String>,
}

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

    #[schemars(description = "Minimum truth value (0.0-1.0, default 0.0)")]
    pub min_truth: Option<f64>,

    #[schemars(description = "Maximum results (default 20)")]
    pub limit: Option<i64>,
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
    pub prerequisites: Option<Vec<String>>,

    #[schemars(description = "Expected outcome when the workflow succeeds")]
    pub expected_outcome: Option<String>,

    #[schemars(description = "Confidence in this workflow (0.0-1.0, default 0.5 — unproven)")]
    pub confidence: Option<f64>,

    #[schemars(description = "Tags for categorization (e.g. ['deployment', 'rust', 'windows'])")]
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
pub struct ImproveWorkflowParams {
    #[schemars(description = "UUID of the parent workflow to improve")]
    pub parent_workflow_id: String,

    #[schemars(description = "Updated goal (omit to inherit from parent)")]
    pub goal: Option<String>,

    #[schemars(description = "Updated steps (omit to inherit from parent)")]
    pub steps: Option<Vec<String>>,

    #[schemars(description = "Updated prerequisites (omit to inherit from parent)")]
    pub prerequisites: Option<Vec<String>>,

    #[schemars(description = "Updated expected outcome (omit to inherit from parent)")]
    pub expected_outcome: Option<String>,

    #[schemars(
        description = "Why this variant was created (e.g. 'Step 3 consistently fails, switching to rsync')"
    )]
    pub change_rationale: String,

    #[schemars(description = "Tags for categorization (inherits from parent + adds these)")]
    pub tags: Option<Vec<String>>,
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
    pub similarity: f64,
}

#[derive(Debug, Serialize)]
pub struct IngestPaperResponse {
    pub paper_title: String,
    pub doi: String,
    pub claims_ingested: usize,
    pub claims_embedded: usize,
    pub relationships_created: usize,
    pub claim_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_ds_wired: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_frame_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorResponse {
    pub agent_id: String,
    pub name: String,
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
    pub workflow_id: String,
    pub goal: String,
    pub step_count: usize,
    pub truth_value: f64,
    pub embedded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
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
pub struct ImproveWorkflowResponse {
    pub variant_id: String,
    pub parent_id: String,
    pub goal: String,
    pub step_count: usize,
    pub generation: i64,
    pub truth_value: f64,
    pub embedded: bool,
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

// ── Literature JSON types (matching EpiGraph ingest_literature format) ──

#[derive(Debug, Deserialize)]
pub struct LiteratureExtraction {
    pub source: LiteratureSource,
    pub claims: Vec<LiteratureClaim>,
    #[serde(default)]
    pub relationships: Vec<ClaimRelationship>,
}

#[derive(Debug, Deserialize)]
pub struct LiteratureSource {
    pub doi: String,
    pub title: String,
    pub authors: Vec<serde_json::Value>,
    #[serde(default)]
    pub journal: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LiteratureClaim {
    pub statement: String,
    pub page: Option<u32>,
    pub section: Option<String>,
    pub confidence: f64,
    pub supporting_text: String,
    #[serde(default)]
    pub methodology: Option<String>,
    #[serde(default)]
    pub evidence_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClaimRelationship {
    pub source_index: usize,
    pub target_index: usize,
    pub relationship: String,
    #[serde(default)]
    pub strength: Option<f64>,
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
    pub frame_ids: Option<Vec<String>>,

    #[schemars(
        description = "How the perspective was extracted: ai_generated, manual, survey (default: ai_generated)"
    )]
    pub extraction_method: Option<String>,

    #[schemars(description = "Confidence calibration 0.0-1.0 (default 0.5)")]
    pub confidence_calibration: Option<f64>,
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
