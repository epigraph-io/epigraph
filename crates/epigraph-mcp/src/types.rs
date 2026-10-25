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

// Defensive deserializer for object-typed parameters like `DocumentSource`.
//
// Some MCP clients stringify object-valued arguments (sending the JSON object
// as a JSON-encoded string) when the schema field isn't explicitly typed as
// `"type": "object"`. Accept both shapes so a client bug doesn't make the
// tool uncallable.
fn deserialize_document_source<'de, D>(
    d: D,
) -> Result<epigraph_ingest::schema::DocumentSource, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Object(epigraph_ingest::schema::DocumentSource),
        Str(String),
    }

    match Either::deserialize(d)? {
        Either::Object(src) => Ok(src),
        Either::Str(s) => serde_json::from_str(&s).map_err(serde::de::Error::custom),
    }
}

fn deserialize_document_extraction<'de, D>(
    d: D,
) -> Result<epigraph_ingest::schema::DocumentExtraction, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Object(Box<epigraph_ingest::schema::DocumentExtraction>),
        Str(String),
    }

    match Either::deserialize(d)? {
        Either::Object(e) => Ok(*e),
        Either::Str(s) => serde_json::from_str(&s).map_err(serde::de::Error::custom),
    }
}

fn deserialize_workflow_extraction<'de, D>(
    d: D,
) -> Result<epigraph_ingest::workflow::WorkflowExtraction, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Object(Box<epigraph_ingest::workflow::WorkflowExtraction>),
        Str(String),
    }

    match Either::deserialize(d)? {
        Either::Object(e) => Ok(*e),
        Either::Str(s) => serde_json::from_str(&s).map_err(serde::de::Error::custom),
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
        description = "How the claim was derived. Use direct_observation (aliases: observation, observational) when you saw it yourself — a run, a test failure, a measured defect; this is the usual answer for an engineering finding. Other accepted values: instrumental, statistical_analysis, computational, negative_result, bayesian_inference, deductive_logic, theoretical_derivation, formal_proof, inductive_generalization, meta_analysis, abductive, visual_inspection, extraction, legal_document_review, textbook_assertion, expert_elicitation."
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

    #[schemars(
        description = "Semantic novelty gate threshold on ANN cosine distance to the nearest existing (is_current) claim, checked only on genuinely new content (after content-hash dedup). Default 0.05: a nearer match returns the EXISTING claim id instead of inserting, writes nothing from this call, and marks the response deduplicated.by='novelty_gate'. A match in [threshold, 0.15) still inserts but is labeled 'near-duplicate'. Set to 0.0 to always insert (escape hatch) — the 0.15 near-duplicate label still applies."
    )]
    #[serde(default)]
    pub novelty_threshold: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryClaimsParams {
    #[schemars(
        description = "Minimum belief score (0.0-1.0, default 0.0). The score is the claim's \
                       Dempster-Shafer pignistic probability when it has DS state, else its \
                       truth_value — the same score recall's min_truth gates on — and each result \
                       reports it as belief_score."
    )]
    pub min_truth: Option<f64>,

    #[schemars(
        description = "Maximum belief score (0.0-1.0, default 1.0), on the same score as \
                       min_truth. A claim refuted by epistemic evidence has a low belief score even \
                       when its authored truth_value is still high, so max_truth=0.4 finds it."
    )]
    pub max_truth: Option<f64>,

    #[schemars(description = "Maximum number of results (default 20)")]
    pub limit: Option<i64>,

    #[schemars(
        description = "Retirement-state filter. DEFAULTS TO true: superseded/refuted claims are \
                       excluded unless you pass false explicitly, which returns ONLY superseded \
                       rows. Omitting this is not 'no filter' — it is 'current claims only', so a \
                       queue built on this tool does not keep re-surfacing claims that have \
                       already been resolved. THERE IS NO VALUE THAT RETURNS BOTH POPULATIONS: \
                       true and false are the only two states and each excludes the other \
                       (this tool did return both when the parameter was omitted; it no longer \
                       does). To see both, call twice — once with true, once with false — and \
                       merge the results."
    )]
    pub is_current: Option<bool>,

    #[schemars(
        description = "When true, drop EVERY claim whose properties.level is 0, 1 or 2, in SQL \
                       before LIMIT: document thesis/section/paragraph nodes (headings, keyword \
                       lists, captions, transcript turns) AND workflow thesis/phase/step nodes \
                       (including evolve_step rows). Atoms (level 3) and unleveled claims are \
                       kept. Default false (no level filter)."
    )]
    pub exclude_spine: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryUndecomposedClaimsParams {
    #[schemars(
        description = "Maximum number of undecomposed claims to return (default 50, max 1000). Claims are ordered created_at ASC (oldest first), so paging with offset is stable. Atomic rows (looks_atomic=true) never leave this list, so the row count is not a progress measure."
    )]
    pub limit: Option<i64>,

    #[schemars(
        description = "Skip the first N matching claims (default 0). Combine with limit to page through the backlog."
    )]
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetWorkflowPlanParams {
    #[schemars(
        description = "The hierarchical workflow's id: the `workflows`-table id that ingest_workflow returns (deterministic from canonical_name and generation)."
    )]
    pub workflow_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetClaimParams {
    #[schemars(description = "The UUID of the claim to retrieve")]
    pub claim_id: String,

    #[schemars(
        description = "Optional lens frame UUID (from list_frames). Must be paired with perspective_id. \
                       When both are set, the response carries an additive lensed_belief computed under that (frame, perspective) lens; the global truth_value is unchanged."
    )]
    #[serde(default)]
    pub frame_id: Option<String>,

    #[schemars(
        description = "Optional lens perspective UUID (from list_perspectives). Must be paired with frame_id. \
                       The perspective's source/locality reliability re-weights the claim's BBAs on-read."
    )]
    #[serde(default)]
    pub perspective_id: Option<String>,
}

/// Additive per-claim belief computed under a `(frame, perspective)` lens.
///
/// Attached as an `Option<LensedBelief>` on the four context-delivery read
/// tools (`recall`, `recall_with_context`, `get_claim`, `get_belief`) ONLY when
/// a valid lens is supplied. Serialize-only with
/// `#[serde(skip_serializing_if = "Option::is_none")]` on the field so a
/// lens-free call is byte-identical to today (the key is omitted, never `null`).
///
/// Source: `epigraph_engine::belief_query::get_perspective_belief` —
/// recomputes the claim's belief on-read, re-discounting every stored BBA by
/// the perspective's reliability maps. Order claims by `pignistic_prob` (BetP).
#[derive(Debug, Clone, Serialize)]
pub struct LensedBelief {
    /// Echoes the lens frame UUID.
    pub frame_id: String,
    /// Echoes the lens perspective UUID.
    pub perspective_id: String,
    /// Dempster-Shafer belief (lower probability bound) under the lens.
    pub belief: f64,
    /// Dempster-Shafer plausibility (upper probability bound) under the lens.
    pub plausibility: f64,
    /// Pignistic probability (BetP) under the lens — use for ordering.
    pub pignistic_prob: f64,
}

impl LensedBelief {
    /// Build from a computed `BeliefInterval`, carrying only the three lens
    /// fields (spec §5 names exactly frame_id, perspective_id, belief,
    /// plausibility, pignistic_prob — not mass/source/framed).
    #[must_use]
    pub fn from_interval(
        frame_id: uuid::Uuid,
        perspective_id: uuid::Uuid,
        interval: &epigraph_engine::BeliefInterval,
    ) -> Self {
        Self {
            frame_id: frame_id.to_string(),
            perspective_id: perspective_id.to_string(),
            belief: interval.belief,
            plausibility: interval.plausibility,
            pignistic_prob: interval.pignistic_prob,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyClaimParams {
    #[schemars(description = "The UUID of the claim to verify")]
    pub claim_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateWithEvidenceParams {
    #[schemars(
        description = "The UUID of the claim to update (id-mode). Provide this, OR both canonical_name and step_index to address a workflow step by name."
    )]
    #[serde(default)]
    pub claim_id: String,

    #[schemars(
        description = "(name-mode) Canonical workflow name; with step_index, resolves to the current head of that step's lineage — the same executes-edge walk report_hierarchical_outcome uses. Alternative to claim_id."
    )]
    #[serde(default)]
    pub canonical_name: Option<String>,

    #[schemars(
        description = "(name-mode) Zero-based step index within the workflow (used with canonical_name)."
    )]
    #[serde(default)]
    pub step_index: Option<usize>,

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

    #[schemars(
        description = "Optional labels to add to the claim (e.g. current-cycle run tags like \
                        'norcal-rfp-2026-07-05'). Additive: merged into the claim's existing \
                        label array via ClaimRepository::update_labels, never overwrites \
                        pre-existing labels — matches submit_claim/memorize's dedup-hit behavior."
    )]
    #[serde(default)]
    pub labels: Vec<String>,
}

// ── Provenance ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetProvenanceParams {
    #[schemars(description = "The UUID of the claim to get provenance for")]
    pub claim_id: String,

    #[schemars(
        description = "Maximum ancestor depth to walk. Default 5, clamped to 1..=20. \
                       The bundle reports `truncated: true` when the walk stopped early."
    )]
    pub max_depth: Option<i32>,

    #[schemars(
        description = "Maximum number of claim nodes kept in the bundle. Default 50, \
                       clamped to 1..=500. The target claim plus its nearest ancestors \
                       are kept; `truncated: true` when the cap bit."
    )]
    pub max_nodes: Option<usize>,

    #[schemars(
        description = "Per-claim content character budget. Default 500, clamped to \
                       50..=20000. Entities whose content was cut carry \
                       `content_truncated: true` and the original `content_chars`."
    )]
    pub max_content_chars: Option<usize>,

    #[schemars(
        description = "Budget for the whole response, in characters of compact JSON. \
                       Default 40000, clamped to 10000..=500000. Claims are admitted \
                       nearest-first with their evidence (at most 10 per claim) and \
                       traces until the next would overrun it; the bundle then reports \
                       `budget_exhausted: true` and `truncated: true`."
    )]
    pub max_output_chars: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SweepSemanticDuplicatesParams {
    #[schemars(
        description = "Cosine DISTANCE below which two claims are near-duplicates \
                       (0.0 = identical). Default 0.10."
    )]
    #[serde(default)]
    pub similarity_threshold: Option<f64>,

    #[schemars(
        description = "Restrict the sweep to these agent UUIDs. Default: cross-agent — the \
                       duplicate corpus spans 20+ agents, so scoping to one usually misses \
                       the duplicates."
    )]
    #[serde(default)]
    pub agent_scope: Option<Vec<String>>,

    #[schemars(description = "Restrict the sweep to claims carrying ALL these labels.")]
    #[serde(default)]
    pub labels_scope: Option<Vec<String>>,

    #[schemars(
        description = "When true (the DEFAULT), report clusters without mutating anything. \
                       Set false to actually collapse exact-restatement clusters."
    )]
    #[serde(default)]
    pub dry_run: Option<bool>,

    #[schemars(description = "Claims scanned this call (default 500, capped 2000).")]
    #[serde(default)]
    pub limit: Option<i64>,

    #[schemars(description = "Resume offset for paging through the corpus (default 0).")]
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ConsolidateClaimsParams {
    #[schemars(
        description = "UUIDs of the 2..=20 is_current claims to merge. Each is retired with a \
                       forwarding pointer to the merged claim."
    )]
    pub source_claim_ids: Vec<String>,

    #[schemars(
        description = "The synthesized replacement text. The CALLER synthesizes this — the \
                       server never invokes an LLM."
    )]
    pub merged_content: String,

    #[schemars(description = "One of: merge | abstract | rewrite.")]
    pub mode: String,

    #[schemars(description = "Why these claims were consolidated; recorded on the lineage edges.")]
    pub reason: String,

    #[schemars(
        description = "Confidence for the merged claim. Defaults to the highest source \
                       truth_value * 0.95, so a merge never claims more certainty than its \
                       best input."
    )]
    #[serde(default)]
    pub confidence: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRecallEventsParams {
    #[schemars(description = "Only events logged by this agent UUID.")]
    #[serde(default)]
    pub agent_id: Option<String>,

    #[schemars(
        description = "Only events whose result set CONTAINED this claim UUID — \
                       'which queries ever surfaced this claim?'"
    )]
    #[serde(default)]
    pub claim_id: Option<String>,

    #[schemars(description = "Only events at or after this RFC3339 timestamp.")]
    #[serde(default)]
    pub since: Option<String>,

    #[schemars(description = "Only events at or before this RFC3339 timestamp.")]
    #[serde(default)]
    pub until: Option<String>,

    #[schemars(description = "Max events to return (default 50, capped at 500).")]
    #[serde(default)]
    pub limit: Option<i64>,

    #[schemars(description = "Skip this many events (default 0).")]
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetProvenanceChainParams {
    #[schemars(description = "The UUID of the conclusion claim to trace backwards from")]
    pub claim_id: String,

    #[schemars(description = "How many derivation hops to walk. Clamped to 1..=8. Default 4.")]
    #[serde(default)]
    pub max_depth: Option<u8>,

    #[schemars(
        description = "Restrict the traversal to these relationships. Default: \
                       supports, corroborates, elaborates, decomposes_to, supersedes. \
                       Traversal DIRECTION per relationship is fixed by the schema \
                       (supersedes is followed outgoing, the rest incoming) and is not \
                       caller-selectable."
    )]
    #[serde(default)]
    pub relationships: Option<Vec<String>>,
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

    #[schemars(
        description = "Semantic novelty gate threshold on ANN cosine distance to the nearest existing (is_current) claim, checked only on genuinely new content (after content-hash dedup). Default 0.05: a nearer match returns the EXISTING claim id instead of inserting, writes nothing from this call, and marks the response deduplicated.by='novelty_gate'. A match in [threshold, 0.15) still inserts but is labeled 'near-duplicate'. Set to 0.0 to always insert (escape hatch) — the 0.15 near-duplicate label still applies."
    )]
    #[serde(default)]
    pub novelty_threshold: Option<f64>,
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

    #[schemars(
        description = "Optional lens frame UUID (from list_frames). Must be paired with perspective_id. \
                       When both are set, each returned claim carries an additive lensed_belief computed under that (frame, perspective) lens. Ranking stays on the global truth_value; min_truth gates on the UNFRAMED DS pignistic probability (falling back to truth_value for a claim with no DS cache), so it is not the lensed value and not the authored scalar."
    )]
    #[serde(default)]
    pub frame_id: Option<String>,

    #[schemars(
        description = "Optional lens perspective UUID (from list_perspectives). Must be paired with frame_id. \
                       The perspective's source/locality reliability re-weights each claim's BBAs on-read."
    )]
    #[serde(default)]
    pub perspective_id: Option<String>,

    #[schemars(
        description = "When true, also search workflows.goal_embedding and RRF-merge workflow hits \
                       into the results (tagged result_type=\"workflow\"). Default false: recall \
                       searches claims only, byte-identical to pre-existing behavior."
    )]
    #[serde(default)]
    pub include_workflows: bool,

    #[schemars(
        description = "When true, drop claims that are actively contested (any is_current claim \
                       contradicts/refutes them) from the results. Applied AFTER ranking, so a \
                       page may come back short rather than back-filling with worse-ranked hits. \
                       Default false: contested claims are returned, annotated with dispute_count \
                       / is_contested / contesting_claim_ids."
    )]
    #[serde(default)]
    pub exclude_contested: bool,

    #[schemars(
        description = "Optional RFC3339 timestamp. When set, the CANDIDATE POOL is narrowed to \
                       claims (and, with include_workflows, workflows) whose created_at is at or \
                       after this instant — enabling \"what changed since T?\" semantic queries. \
                       Filters on creation time, NOT last-update time: a belief recomputation \
                       bumps updated_at without changing content, so an updated_at window would \
                       report the whole recomputed corpus as new. Default: no window, byte-\
                       identical to omitting the parameter. No default window is ever applied — \
                       every hit carries created_at, so a caller who wants a different temporal \
                       policy can apply it themselves."
    )]
    #[serde(default)]
    pub since: Option<chrono::DateTime<chrono::Utc>>,

    #[schemars(
        description = "Optional theme UUID (from list_themes / get_theme). When set, the CANDIDATE \
                       POOL of every claims retrieval surface — the hybrid dense leg, the hybrid \
                       lexical leg, and the embedder-down lexical fallback — is narrowed in SQL to \
                       that theme's members BEFORE each leg's LIMIT, so no off-theme claim can \
                       reach the caller and no off-theme claim consumes pool budget. Distinct from \
                       recall_with_context's diverse=true, which picks themes internally by \
                       centroid similarity and lets you pin none of them. Mutually exclusive with \
                       theme_label. A malformed UUID or an unknown theme is REJECTED, never \
                       silently ignored — a dropped scope filter would widen recall to the whole \
                       corpus while you believe it is scoped."
    )]
    #[serde(default)]
    pub theme_id: Option<String>,

    #[schemars(
        description = "Optional exact theme label, resolved to a theme UUID. Mutually exclusive \
                       with theme_id. Rejected when it matches zero themes, and rejected (listing \
                       the candidates) when it matches more than one — claim_themes has no \
                       UNIQUE(label) constraint, so 'the first match' could be any of several \
                       distinct themes."
    )]
    #[serde(default)]
    pub theme_label: Option<String>,

    #[schemars(
        description = "Skip the first N ranked claims (default 0). Combine with limit to walk a \
                       theme to exhaustion; the response carries next_offset and more_available. \
                       Applied in SQL on the fused ranking, whose ORDER BY carries a claim_id \
                       tiebreaker so a page boundary cannot show one claim twice and another \
                       never. CAVEAT: min_truth and exclude_contested are applied in Rust AFTER \
                       the SQL page, so a page can come back SHORTER than limit while more pages \
                       remain — use more_available, not an empty page, as the stop condition. \
                       Rejected together with include_workflows=true: workflows are a separate \
                       id-space with no ranking continuity across claim pages, so paging them \
                       alongside claims would re-serve the same workflows on every page."
    )]
    #[serde(default)]
    pub offset: Option<i64>,

    #[schemars(
        description = "When true, REPLACE the flat `results` array with an `epistemic_partition` \
                       object grouping the same hits into `confirmed` (belief_score at or above the \
                       served belief profile's gates.confirmed_score, default 0.75, and \
                       not contested), `open_question` (is_contested — any live \
                       contradicts/refutes), and `uncertain` (everything else). The score is \
                       each hit's `belief_score`, the same value `min_truth` gates on, not its \
                       authored `truth_value`. Contest is \
                       checked FIRST, so a high-scoring claim carrying a live refutation is \
                       reported as an open question rather than as confirmed. Ranking is \
                       UNCHANGED: each bucket keeps the RRF order the flat list would have had, \
                       and the union of the three buckets is exactly the flat list — this \
                       regroups the page, it does not filter or re-rank it. `results` is OMITTED \
                       when this is true, so a caller opts into the new shape explicitly. \
                       Default false: output is byte-identical to recall without this parameter."
    )]
    #[serde(default)]
    pub epistemic_partition: bool,

    #[schemars(
        description = "Optional intra-result diversity constraint, as a COSINE DISTANCE in \
                       (0.0, 2.0] over claims.embedding. When set, a greedy MMR pass walks the \
                       ranked page top-down and DROPS any hit sitting closer than this to a hit \
                       already kept above it, so a query cannot come back as ten paraphrases of \
                       one fact. 0.15 is a reasonable starting value; larger = more aggressive \
                       de-duplication. SHRINKS the page rather than back-filling — the SQL page \
                       is already truncated to limit, so there is nothing below to promote, and \
                       this matches how min_truth and exclude_contested already behave. Use \
                       paging.more_available, not a short page, as the stop condition. Hits \
                       whose distance cannot be MEASURED are always KEPT, never dropped: that \
                       covers workflow hits (include_workflows=true — they are not claims rows) \
                       and any claim with no embedding, as on the embedder-down lexical \
                       fallback, where this parameter therefore does nothing. A value outside \
                       the range is REJECTED, not clamped. Default: no diversity filtering."
    )]
    #[serde(default)]
    pub diversity_radius: Option<f64>,
}

// ── Ingestion ──

// ── Paper Queries ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct QueryPaperParams {
    #[schemars(description = "DOI of the paper (e.g. '10.48550/arXiv.2508.16798')")]
    pub doi: String,

    #[schemars(
        description = "Maximum asserted claims to return in this page. Default 25, \
                       clamped to 1..=200. `claim_count` remains the full total, so \
                       `claim_count > offset + returned` means there are more pages."
    )]
    pub limit: Option<i64>,

    #[schemars(description = "Asserted claims to skip (paging). Default 0.")]
    pub offset: Option<i64>,
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

    #[schemars(
        description = "Opt-in (default false). When true, each returned claim carries `source_urls`: the URLs of the evidence attached to it (the evidence `source_url`; for older rows a document URL, an http(s) testimony source, or a DOI as https://doi.org/<doi>), oldest evidence first, deduplicated. Costs one extra batched query for the page. When false the response is unchanged and no `source_urls` key is present."
    )]
    #[serde(default)]
    pub include_source_urls: bool,
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

    #[schemars(
        description = "Confidence in this workflow's steps (default 0.8; clamped to 0.0-1.0)"
    )]
    pub confidence: Option<f64>,

    #[schemars(
        description = "Tags for categorization (e.g. ['deployment', 'rust', 'windows']). Stored on the workflows row as metadata.tags (trimmed, empties dropped, de-duplicated) on the FIRST store only: a re-store of the same goal is a no-op that keeps the original tags. Not added as claim labels."
    )]
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
    #[schemars(
        description = "Zero-based index of the step in the workflow's plan order; a step add_step left without a plan_index comes after every indexed step."
    )]
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
    #[schemars(
        description = "UUID of the workflow: a workflows-table id (from store_workflow / ingest_workflow / find_workflow), or a legacy flat workflow claim id."
    )]
    pub workflow_id: String,

    #[schemars(
        description = "true only if the workflow's goal or expected outcome was achieved: every gate and check passed. A run that ran every step but a gate or check failed is success=false; record what the steps did in the execution log instead."
    )]
    pub success: bool,

    #[schemars(description = "Step-by-step execution log: planned vs actual")]
    pub execution_log: Vec<StepExecution>,

    #[schemars(
        description = "Summary of what happened (e.g. 'Completed in 45s, all checks passed'). Recorded in the evidence row for a legacy flat workflow claim; not stored for a workflows-table id."
    )]
    pub outcome_details: String,

    #[schemars(
        description = "Execution quality 0.0-1.0 (default: 1.0 if success, 0.0 if failure)"
    )]
    pub quality: Option<f64>,

    #[schemars(
        description = "Your specific goal for this run. If omitted it falls back to the workflow's goal for a legacy flat workflow claim, and to the literal 'hierarchical' for a workflows-table id. More specific goal text improves future affinity matching on both paths; for a workflows-table id an omitted goal is not embedded."
    )]
    pub goal_text: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeprecateWorkflowParams {
    #[schemars(
        description = "UUID of the workflow to deprecate: a flat workflow claim id, or a hierarchical workflows-table id (what store_workflow, ingest_workflow, find_workflow and find_workflow_hierarchical return). A hierarchical id retires the workflow with the thesis, phase and step claims no other live workflow executes (see the tool description). An id that is neither is an error."
    )]
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
    #[serde(deserialize_with = "deserialize_workflow_extraction")]
    pub extraction: epigraph_ingest::workflow::WorkflowExtraction,

    #[schemars(
        description = "Optional declared tenancy for the claims this ingest creates: {\"visibility\": \"group\", \"owner_group_id\": <uuid>} (\"group\" is the only accepted visibility). The calling agent ITSELF must hold a live writer or admin membership of the group (its operator's membership does not count), and so must the workflow-ingest system agent; otherwise the call is refused and nothing is written. New claims and their executes edges are then readable only by members of the group. Claims the plan reuses (an unchanged step of an earlier generation, a shared operation atom, a whole re-ingest) keep their tenancy and are listed in the response's reused_items; a reused claim private to a group the calling agent does not write refuses the ingest. The workflows row (canonical_name, goal, metadata, and the goal embedding unless embed is false) stays instance-readable, so keep those neutral. Omit for the default: public."
    )]
    #[serde(default)]
    pub tenancy: Option<epigraph_ingest::workflow::WorkflowTenancy>,

    #[schemars(
        description = "Whether to embed the created claims and the workflow goal (default true). false sends no text to the embedding provider and stores no vector, so the claims stay out of semantic recall and semantic dedup."
    )]
    #[serde(default)]
    pub embed: Option<bool>,
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
    #[serde(deserialize_with = "deserialize_workflow_extraction")]
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
        description = "When true, walk each step's step_lineage_id to the head version(s) and surface them as `resolved_steps`, and guarantee the true lineage head is present for every matched canonical_name: its highest generation (the one improve_workflow_hierarchy builds on) is added even when its goal does not match the query, it has no goal embedding, or its truth is below min_truth. Each entry then carries `is_lineage_head`, `lineage_head_generation` and `lineage_head_deprecated` (the head's truth is below min_truth), and the head leads its lineage group; the result can exceed `limit` by one head per matched lineage. Defaults to false (frozen step references, matched rows only, newest-created-at first)."
    )]
    pub resolve_to_latest: Option<bool>,

    #[schemars(
        description = "Minimum truth value to surface; defaults to 0.3 so deprecated rows (truth=0.05 via deprecate_workflow) are hidden. Pass 0.0 to include deprecated workflows. Exception: with resolve_to_latest=true the lineage head of each matched canonical_name is always returned, flagged `lineage_head_deprecated` when its truth is below min_truth."
    )]
    pub min_truth: Option<f64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct HierarchicalStepExecution {
    #[schemars(
        description = "Zero-based index of the step in the workflow's plan order (matches `executes`-edge ordering at level=2); a step add_step left without a plan_index comes after every indexed step. An out-of-range index is stored with a null step_claim_id."
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

    #[schemars(
        description = "true only if the workflow's goal or expected outcome was achieved: every gate and check passed. A run that ran every step but a gate or check failed is success=false; record what the steps did in the execution log instead."
    )]
    pub success: bool,

    #[schemars(
        description = "Per-step execution log. Each step_index is resolved to the step's claim node via `executes` edges and recorded as one behavioral_executions row (no evidence row, no belief change)."
    )]
    pub step_executions: Vec<HierarchicalStepExecution>,

    #[schemars(
        description = "Summary of what happened (e.g. 'Completed in 45s, all checks passed'). Currently accepted but not stored."
    )]
    pub outcome_details: String,

    #[schemars(
        description = "Execution quality 0.0-1.0 (default: 1.0 if success, 0.0 if failure)."
    )]
    pub quality: Option<f64>,

    #[schemars(
        description = "Optional run/variant label for parameter-sweep executions (e.g. 'joint-63bp', 'V2'). Persisted on the behavioral_executions row and surfaced by get_workflow_executions so sweep variants are machine-distinguishable rather than tellable apart only by prose."
    )]
    #[serde(default)]
    pub run_label: Option<String>,

    #[schemars(
        description = "Your specific goal for this run, stored on each behavioral_executions row (default 'hierarchical'). A non-blank goal is embedded onto every step row (best-effort), so the run feeds find_workflow's behavioral affinity for this workflow; the 'hierarchical' default is not embedded."
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

    #[schemars(
        description = "0-based index of the hypothesis this claim represents in the frame. It is \
                       stored on the claim's frame assignment and decides which hypothesis the \
                       returned belief (and every later framed or cached belief read) is about. \
                       An index outside the frame's hypotheses is stored as given, but every \
                       reader treats it as 0, and the response's warnings say so."
    )]
    pub hypothesis_index: i32,

    // `with` pins the advertised schema to `{"type":"object",
    // "additionalProperties":{"type":"number"}}`. A bare `serde_json::Value`
    // renders as schemars' permissive schema with no `type`, and clients that
    // build arguments from the schema then stringify the object and the call
    // is rejected. The map type mirrors what the handler actually parses —
    // `MassFunction::from_json_masses` deserializes into `BTreeMap<String, f64>`.
    //
    // `serde_json::Number`, not `f64`: `f64` would additionally emit
    // `"format":"double"`, and a certain mass of 1.0 reaches us as the JSON
    // integer `1` (`JSON.stringify(1.0) === "1"`), which serde happily coerces
    // but a client-side validator treating `format` as an assertion could
    // reject. Advertising a bare `"type":"number"` keeps the schema exactly as
    // permissive as the handler.
    #[schemars(
        with = "std::collections::BTreeMap<String, serde_json::Number>",
        description = "Mass assignments: {'0': 0.6, '0,1': 0.3, '~0,1': 0.1}. Keys: comma-separated indices (positive) or ~-prefixed (negative/complement). '' = conflict, '~' = open-world ignorance."
    )]
    pub masses: serde_json::Value,

    #[schemars(
        description = "Source reliability: 1.0 = fully reliable, 0.0 = ignore. Default 1.0"
    )]
    pub reliability: Option<f64>,

    // DEPRECATED in the description, deliberately NOT `#[deprecated]`: the
    // attribute would fire on ds.rs's own reads and fail `-D warnings`, and an
    // agent reads the description, not the attribute. Backlog 82dcff9d (G5):
    // honouring a per-call method would re-introduce the second, divergent
    // combine that backlog 2bffdfdc removed, which needs a design decision.
    #[schemars(
        description = "DEPRECATED: accepted and stored, no effect on belief. Combination method \
                       label: Dempster (default), Conjunctive, YagerOpen, YagerClosed, DuboisPrade, \
                       Inagaki. It is validated (an unknown name is refused), stored on the BBA and \
                       echoed as method_used, but the claim's belief is always recomputed by the \
                       shared Dempster fold that recompute_beliefs uses, whatever this says. Any \
                       value other than Dempster adds an entry to the response's warnings."
    )]
    pub combination_method: Option<String>,

    #[schemars(
        description = "DEPRECATED: accepted, NOT stored, no effect on belief. Inagaki gamma \
                       parameter; the belief recompute never reads it. Sending any value adds an \
                       entry to the response's warnings."
    )]
    pub gamma: Option<f64>,

    #[schemars(
        description = "Optional perspective UUID stored on the BBA. It is part of the BBA's \
                       replacement key: a resubmission by this agent for the same claim, frame and \
                       perspective_id replaces the earlier BBA, while a different perspective_id adds \
                       a separate one. It does not scope the combination: the returned belief \
                       combines every BBA on the claim and frame regardless of perspective."
    )]
    pub perspective_id: Option<String>,

    #[schemars(
        description = "Evidence classification tag (e.g. 'empirical', 'testimonial', 'statistical') \
                       used to key the calibrated per-source-class reliability prior \
                       (epigraph_engine::edge_factor::effective_source_strength / calibration.toml \
                       [evidence_type_weights]) instead of the caller-supplied `reliability` float. \
                       When omitted (default), behavior is unchanged: the raw `reliability` float is \
                       applied and the BBA is stored with evidence_type=NULL, matching every \
                       pre-existing caller byte-for-byte. A tag outside the calibration vocabulary \
                       (and not in the frame's evidence_type_weights override) is still stored, but \
                       is combined at the 0.5 unknown-type reliability and returned in the \
                       response's unknown_keys and warnings."
    )]
    #[serde(default)]
    pub evidence_type: Option<String>,

    #[schemars(
        description = "Locality classification of this evidence vs. the claim's asserting paper: \
                       'intra' (self-cite / methodological overlap) applies the calibrated intra-locality \
                       discount on top of the evidence_type weight; 'cross' or 'unknown' apply no locality \
                       discount. Only consulted when `evidence_type` is also supplied — otherwise ignored \
                       and the BBA is stored with locality_tag='unknown' as before. Default: 'unknown'."
    )]
    #[serde(default)]
    pub locality_tag: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetBeliefParams {
    #[schemars(description = "UUID of the claim to query belief for")]
    pub claim_id: String,

    #[schemars(
        description = "Optional frame UUID. If provided, recomputes Bel/Pl/BetP from stored BBAs. If omitted, returns cached DS columns."
    )]
    pub frame_id: Option<String>,

    #[schemars(
        description = "Optional lens perspective UUID (from list_perspectives). Requires frame_id. \
                       When set, the response also carries an additive lensed_belief computed under that (frame, perspective) lens; the existing global belief is unchanged."
    )]
    #[serde(default)]
    pub perspective_id: Option<String>,
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
    /// The scalar a truth range was compared against (GitHub #395): the
    /// Dempster-Shafer pignistic probability when the claim carries a DS cache,
    /// else `truth_value` — the same score `recall`'s `min_truth` gates on.
    /// Set by `query_claims`, whose `min_truth`/`max_truth` filter on it;
    /// omitted by tools that apply no truth range. `belief_score !=
    /// truth_value` means epistemic evidence has moved the claim away from its
    /// authored value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief_score: Option<f64>,
}

/// A [`ClaimResponse`] with the claim's evidence URLs, for tools that surface
/// them (`query_claims_by_label`'s `include_source_urls`).
///
/// A flattened wrapper rather than a `ClaimResponse` field so the other tools'
/// claim literals are untouched, and so the serialized claim is byte-identical
/// to a bare `ClaimResponse` when `source_urls` is `None`.
#[derive(Debug, Serialize)]
pub struct ClaimWithSources {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    /// URLs of the evidence attached to the claim, oldest first, deduplicated
    /// (`EvidenceRepository::source_urls_by_claim_ids`). `None` = not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_urls: Option<Vec<String>>,
}

/// A [`ClaimResponse`] row of `query_undecomposed_claims`, with whether the
/// claim is atomic and so terminal.
///
/// A flattened wrapper, like [`ClaimWithSources`], so the other tools' claim
/// literals are untouched and the claim fields serialize as before.
#[derive(Debug, Serialize)]
pub struct UndecomposedClaimResponse {
    #[serde(flatten)]
    pub claim: ClaimResponse,
    /// `epigraph_core::atomicity::looks_atomic(content)`: one sentence and at
    /// most 160 chars. `decompose_claims` skips these by default, and the
    /// operator ruled them terminal by policy (backlog `5e1debbc`): not a
    /// backlog and not a defect.
    pub looks_atomic: bool,
}

#[derive(Debug, Clone, Serialize)]
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
    /// Present ONLY when this call created nothing new because the claim
    /// already existed. Absent on a fresh insert. See [`Deduplicated`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<Deduplicated>,
}

/// Which dedup path answered a write with an EXISTING claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupBy {
    /// Byte-identical content already stored by this server's agent
    /// (`UNIQUE (content_hash, agent_id)`).
    ContentHash,
    /// The write-side semantic novelty gate found an existing current claim
    /// within `novelty_threshold` cosine distance. That claim may belong to
    /// ANOTHER agent, and nothing from this call was written.
    NoveltyGate,
}

/// The `deduplicated` block on a `submit_claim` / `memorize` /
/// `batch_submit_claims` response (backlog a3e63a12).
///
/// Before this block a dedup hit was byte-for-byte indistinguishable from a
/// fresh insert, so a caller could not tell what had become of its inputs. The
/// two lists are MEASURED per path from the code that runs on it, not assumed:
/// `tools::claims::dedup_block` and `tools::memory::memorize_dedup_block` decide
/// them. Only inputs the caller actually supplied are listed (an absent
/// `source_url`, `reasoning` or `novelty_threshold`, or empty `labels`/`tags`,
/// appear in neither list). On `batch_submit_claims`, an entry's omitted
/// `methodology` or `confidence` is filled from the batch defaults and is
/// likewise in neither list (`tools::batch::SuppliedByEntry`), although the
/// content-hash path still records the default on the trace it writes.
///
/// On EVERY dedup hit the existing claim's belief and truth_value are left
/// unchanged: this call's confidence and evidence are never combined into the
/// existing claim's belief, whichever list names them.
#[derive(Debug, Clone, Serialize)]
pub struct Deduplicated {
    pub by: DedupBy,
    /// The claim this call was answered with (always equal to `claim_id`).
    pub existing_claim_id: String,
    /// Inputs of this call that WERE recorded against the existing claim, e.g.
    /// labels merged in, or a new evidence row and reasoning trace linked to it.
    pub inputs_applied: Vec<&'static str>,
    /// Inputs of this call that were written nowhere.
    pub inputs_discarded: Vec<&'static str>,
}

/// Outcome of the content-integrity half of MCP `verify_claim`.
///
/// Three states, not two, because `claims.content_hash` is NOT `blake3(content)`
/// for every row. The canonical Tier-1 document pipeline deliberately binds
/// `compound_content_hash(blake3(text), artifact_seed)` on every level-0/1/2
/// (thesis / section / paragraph) node —
/// `epigraph_ingest::common::plan::PlannedClaim::content_hash` states the
/// contract, and migration 013's `UNIQUE (content_hash, agent_id)` is why it
/// exists. Collapsing that class into a boolean forces a wrong answer whichever
/// way the boolean falls: `true` is the always-passing theatre backlog
/// `49c17386` was filed about, `false` is a confident tampering accusation
/// against every untampered structural row in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashCheck {
    /// BLAKE3 over the body reproduces the stored digest. The body is intact
    /// *with respect to the digest* — who vouched for the digest is
    /// [`VerifyResponse::signature_valid`]'s question, not this one.
    Match,
    /// BLAKE3 over the body does NOT reproduce the stored digest, and this row's
    /// digest is supposed to be `blake3(content)`. **This is the tampering
    /// signal** — the body was mutated without rewriting the hash.
    Mismatch,
    /// The stored digest is not a function of the body alone, so comparing them
    /// decides nothing. Reported for document-scoped compound rows (detected
    /// via `epigraph_ingest::document::stored_content_hash_is_seed_scoped`),
    /// and for a canonical_name-scoped WORKFLOW row only when no executing
    /// workflow is visible to recover its seed from — a workflow row whose
    /// seed is recovered is re-derived and reported [`Self::Match`] or
    /// [`Self::Mismatch`].
    ///
    /// **Undecided, not clean.** Content-hash verification cannot rule tampering
    /// in *or* out here: the artifact seed that went into the stored digest is
    /// not carried on the claim, so the digest cannot be recomputed, and a
    /// guessed seed would manufacture false confidence. Treat this as "no
    /// integrity evidence available", and use the signature half plus the
    /// document's own provenance instead.
    NotApplicable,
}

/// Result of MCP `verify_claim`.
///
/// # A claim is attested only when `signed && signature_valid && hash_check == match`
///
/// The two checks are INDEPENDENT and neither implies the other. The signature
/// attests the digest; the digest attests the body. An attacker who mutates
/// `claims.content` while leaving `content_hash` and `signature` untouched
/// yields `{signed: true, signature_valid: true, hash_check: "mismatch"}` — the
/// signature is genuinely valid over a digest the body no longer matches, so a
/// caller reading `signature_valid` alone is still fooled. Conversely a
/// consistent body/digest pair says nothing about who wrote it.
///
/// `hash_check: "not_applicable"` is a third outcome and is NOT a failure
/// report: it means this row's digest is not derivable from its body by
/// construction (see [`HashCheck::NotApplicable`]), so the body-attests step is
/// simply unavailable. `{signed: true, signature_valid: true, hash_check:
/// "not_applicable"}` says a known key vouched for the stored digest and says
/// nothing at all about whether the body still matches it. Do not read that
/// combination as attestation of the content.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub claim_id: String,
    /// Whether the stored Ed25519 signature verifies over the **stored**
    /// `content_hash`, under the signer's `agents.public_key` or under an
    /// attested `agent_keys` key (`signing`, `identity-legacy`) of the claim's
    /// signer or author. See [`Self::key_bound`] for whether that key vouches
    /// for the author.
    ///
    /// `false` covers two very different states — read it together with
    /// [`Self::signed`]: `signed = false` means the claim carries no signature
    /// at all (nothing to verify), `signed = true` with
    /// `signature_valid = false` means a signature is present and REJECTED.
    pub signature_valid: bool,
    /// Whether the claim was signed at all (`claims.signature IS NOT NULL`).
    ///
    /// Added with backlog `49c17386`: `signature_valid` alone conflated
    /// "unsigned" with "bad signature", and while `claim_from_row` hardcoded
    /// `signature = None` every claim looked like the latter.
    ///
    /// The signature belongs to the claim's SIGNER (`claims.signer_id`), which
    /// is not necessarily its author (`claims.agent_id`). Since batch H-b an MCP
    /// `submit_claim` / `memorize` / `batch_submit_claims` / resolution claim is
    /// authored by the calling agent and signed by the MCP server's key, and the
    /// server's agent is recorded as the signer, so such a claim reports
    /// `signed = true, signature_valid = true`. Claims written before that, and
    /// by paths that store no signature, report `signed = false`.
    pub signed: bool,
    /// Whether the key that verifies the signature is BOUND to the claim's
    /// AUTHOR (agent identity lineage design D2): an attested `agent_keys` key
    /// of `claims.agent_id` (`signing`, or migration 161's `identity-legacy`)
    /// whose window holds the claim's `created_at` (`[valid_from - 60 s,
    /// valid_until)`, the 60 s absorbing clock skew; active, or rotated /
    /// expired with a recorded `valid_until`; never revoked or pending).
    ///
    /// `false` with `signature_valid = true` is a real signature by a key that
    /// does not vouch for the author: a key no attested row carries, a key of
    /// the SIGNER that is not the author's (an HTTP claim authored by its
    /// caller and signed by the server), a revoked key, or a claim dated
    /// outside the key's window.
    ///
    /// What `true` does NOT prove:
    /// * that the author asserted THIS claim. The signature covers
    ///   `blake3(content)` only: no author, no `created_at`, and no claim /
    ///   evidence distinction (evidence rows are signed the same way). Someone
    ///   who can write the database directly can copy the author's signature
    ///   from any claim or evidence row with the same bytes onto a row naming
    ///   that author, and it reports bound.
    /// * the date. `created_at` is set by the writer and is not signed, so the
    ///   window test trusts it: a backdated row passes it.
    /// * anything, under an `identity-legacy` key: its private half is
    ///   computable from public inputs, so such a signature, bound or not, is
    ///   never evidence of authorship.
    pub key_bound: bool,
    /// Which kind of key verified the signature: `"signing"` (a registered
    /// random signing key), `"identity-legacy"` (an agent's pre-existing
    /// identity key; under the unkeyed scheme its private half is computable
    /// from public inputs, so such a signature is forgeable), or
    /// `"unattested"` (only the signer's `agents.public_key` verifies it, and
    /// no attested row carries that key). `null` when no key verifies.
    pub key_kind: Option<&'static str>,
    /// The authoritative integrity verdict. See [`HashCheck`] — in particular,
    /// only [`HashCheck::Mismatch`] is evidence of tampering.
    pub hash_check: HashCheck,
    /// [`Self::hash_check`] as a boolean for callers that only branch two ways:
    /// `Some(true)` for `match`, `Some(false)` for `mismatch`, and `None` (JSON
    /// `null`) for `not_applicable`.
    ///
    /// Never `false` for the not-applicable class. That is the whole point: a
    /// `false` here is a positive claim that the body and its digest disagree,
    /// and emitting it for a row whose digest was never `blake3(content)` would
    /// libel every thesis/section/paragraph written by `ingest_document`. A
    /// consumer that treats `null` as untrustworthy fails safe; one that treats
    /// it as a mismatch is reading a verdict that was not given.
    pub hash_matches: Option<bool>,
    pub truth_value: f64,
}

#[derive(Debug, Serialize)]
pub struct UpdateResponse {
    pub claim_id: String,
    pub truth_before: f64,
    /// The claim's `truth_value` after this call. Equal to `truth_before` when
    /// [`Self::truth_written`] is `false`.
    pub truth_after: f64,
    /// Whether this call wrote the claim's `truth_value`. `false` when the
    /// caller attached to a PUBLIC claim it does not own (migration 114): the
    /// evidence and its BBA are the caller's own rows (owned by the caller's
    /// group, public), the claim's DS belief cache (`belief` / `plausibility`
    /// / `pignistic_prob` below) is recombined over every writer's mass
    /// functions, and the claim ROW's `truth_value` stays the owner's.
    pub truth_written: bool,
    /// `"claim_owner"` when the caller could write the claim (the evidence
    /// inherits the claim's owner, as before), `"writer"` when it attached to a
    /// public claim it does not own and the evidence and BBA are owned by the
    /// caller's own group (migration 114).
    pub evidence_owner: &'static str,
    pub evidence_id: String,
    /// Whether the Dempster-Shafer wiring for this submission landed. Always
    /// `true` in a response.
    ///
    /// Introduced by #497, when the DS wiring ran on a sibling pool connection
    /// after the evidence row had already self-committed, so a wire failure was
    /// reported as a SUCCESS with `belief_wired: false` rather than as an error
    /// for work the database had kept. D2 (Unit E) put evidence -> BBA ->
    /// `truth_value` -> labels in ONE author-stamped transaction, so a wire
    /// failure now rolls every one of those writes back and the tool returns an
    /// ERROR naming the failing step (`assign_claim: …`, `store BBA: …`,
    /// `update_claim_belief: …`). There is no longer a partially-successful
    /// outcome for this flag to disclose, and nothing is left behind: an
    /// identical re-submit of the same `evidence_data` is admitted once the
    /// cause is fixed (pinned in
    /// `tests/update_with_evidence_ds_wiring_failure_is_atomic.rs`).
    ///
    /// The field is RETAINED, constant `true`, because clients of #497 may
    /// already read it; `true` means what it always meant — a fresh BBA was
    /// materialized and `truth_after` / `belief` / `plausibility` /
    /// `pignistic_prob` describe the new epistemic state. Compare
    /// [`LinkEpistemicResponse::belief_wired`], which is still a live
    /// best-effort disclosure.
    pub belief_wired: bool,
    /// Whether THIS submission's BBA is persisted in `mass_functions`. Always
    /// `true` in a response.
    ///
    /// #497 defined it as always `true` when `belief_wired` is `true`, and used
    /// `false` to separate a first-step from a late-step wire drop on the old
    /// best-effort path. Under D2 both drops are a rolled-back ERROR — a BBA
    /// written before a late-step failure is rolled back with everything else —
    /// so no response can carry `false`. Retained for client compatibility.
    pub bba_stored: bool,
    /// Whether the claim's cached Dempster-Shafer columns now hold the
    /// `belief` / `plausibility` / `pignistic_prob` below. Always `true` for a
    /// caller that can write the claim. `false` when a non-owner of a public
    /// claim may not write its cache on this frame (migration 114: the cache
    /// is refreshed only on the frame it already carries, and seeded only on
    /// `binary_truth` when the claim has none): the evidence and its BBA are
    /// stored, the values below are this call's combination, and `warning`
    /// says so.
    pub cache_written: bool,
    /// Always absent from a response since D2.#497 reported the DS wiring's
    /// step-prefixed error here on its best-effort path; that text is now the
    /// tool's -32603 error MESSAGE instead, because the failure rolls the whole
    /// submission back. Kept (skipped when `None`) for client compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_wire_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plausibility: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pignistic_prob: Option<f64>,
    /// Populated when supporting evidence *lowered* the pignistic probability
    /// (the claim's prior sits above the plausibility its stored BBAs allow, so
    /// the monotonicity clamp yields to that bound; this is mathematically
    /// correct Dempster-Shafer combination, and the warning exists so callers
    /// don't mistake it for a bug), and when
    /// [`Self::cache_written`] is `false`. Several notes are joined by a space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
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
    /// Present ONLY when this call created nothing new because the memory
    /// already existed. Absent on a fresh insert. See [`Deduplicated`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deduplicated: Option<Deduplicated>,
}

#[derive(Debug, Serialize)]
pub struct RecallResult {
    pub claim_id: String,
    pub content: String,
    /// The claim's independently authored `claims.truth_value`, reported
    /// unchanged. NOT what `min_truth` gates on — see `belief_score`.
    pub truth_value: f64,
    /// The scalar `min_truth` was actually compared against (backlog
    /// `14b98adc`): the Dempster–Shafer pignistic probability when the claim
    /// carries a DS cache, and `truth_value` when it does not.
    ///
    /// `belief_score == truth_value` means the claim has no DS state and the
    /// gate fell back; a divergence means epistemic edges have moved the claim
    /// away from its authored value, which no DS write path copies back into
    /// `truth_value`.
    ///
    /// Workflow-origin hits (`result_type == "workflow"`) are not claims and
    /// carry no DS cache, so their `belief_score` always equals their
    /// `truth_value`.
    pub belief_score: f64,
    /// Dense cosine similarity in `[0,1]`; `0.0` for a lexical-only hit.
    pub similarity: f64,
    /// Reciprocal Rank Fusion score (primary ordering).
    pub rrf_score: f64,
    /// Which legs matched: subset of `["dense","lexical"]`.
    pub matched_via: Vec<String>,
    /// Per-claim belief under the requested `(frame, perspective)` lens.
    /// Present only when a lens was supplied; omitted (not null) otherwise, so
    /// a lens-free recall is byte-identical to today.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lensed_belief: Option<LensedBelief>,

    /// `Some("workflow")` for a hit sourced from `workflows.goal_embedding`
    /// (only possible when `include_workflows=true`); omitted (not `null`)
    /// for ordinary claim hits, so `include_workflows`-unset recall stays
    /// byte-identical to pre-existing output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_type: Option<String>,

    /// Number of `is_current` claims contesting this one via
    /// `contradicts`/`refutes` (backlog 34d3400d). `0` when uncontested.
    /// Uncapped, unlike `contesting_claim_ids` — `30` and `3` are
    /// distinguishable.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dispute_count: u32,

    /// `true` iff `dispute_count > 0`. Surfaced alongside `truth_value`, never
    /// instead of it: a contested claim is not necessarily false, it is
    /// claim the caller should not treat as settled.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_contested: bool,

    /// The three strongest contesters (by their own `truth_value`), so a
    /// caller can surface the counter-evidence without a second round-trip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contesting_claim_ids: Vec<uuid::Uuid>,

    /// When this result was created — `claims.created_at` for a claim hit,
    /// `workflows.created_at` for a workflow hit. Never `updated_at`, never
    /// the request time.
    ///
    /// `Option` + `skip_serializing_if` (the same pattern as `result_type` /
    /// `lensed_belief` above) so a row whose creation time is genuinely
    /// unknown OMITS the key rather than reporting a fabricated one. A
    /// caller can then tell "unknown" from a value; `Utc::now()` or the Unix
    /// epoch would be indistinguishable from a real timestamp while being a
    /// lie about provenance.
    ///
    /// Surfaced on every hit, windowed or not: temporal arbitration between
    /// a stale and a current memory is the caller's decision, and this is the
    /// signal it needs to make it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `skip_serializing_if` helper: keeps an uncontested hit byte-identical to
/// pre-F3 recall output (the field is omitted, not emitted as `0`).
///
/// Shared with `tools::recall`'s `RecallHit` so both dispute-annotated
/// surfaces omit-on-default identically.
pub(crate) fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// `skip_serializing_if` helper — see [`is_zero_u32`].
pub(crate) fn is_false(v: &bool) -> bool {
    !*v
}

/// Score at or above which a NON-contested result is reported as `confirmed`
/// by [`EpistemicPartition`] (backlog e7736ff6).
///
/// One parameter, shared by `recall` and `recall_with_context`, so "confirmed"
/// cannot come to mean two different things on the two recall surfaces. It is
/// the served belief profile's `gates.confirmed_score` (built-in default 0.75,
/// overridable in `calibration.toml`'s `[belief_profiles.<name>]`).
pub(crate) fn confirmed_score() -> f64 {
    epigraph_engine::belief_profile::BeliefProfile::served()
        .gates
        .confirmed_score
}

/// A post-RRF recall page grouped by the epistemic status of each hit, rather
/// than returned as one flat ranked list (backlog e7736ff6).
///
/// The three buckets are exhaustive and mutually exclusive, and the rule is
/// deliberately contest-first:
///
/// * `open_question` — `is_contested` (any live `contradicts`/`refutes`).
///   Checked FIRST, so a high-scoring claim that is actively disputed is
///   reported as unsettled rather than as `confirmed`. Score and dispute are
///   independent signals; a corpus can hold a 0.9 claim and a live refutation
///   of it at the same time, and that pair is precisely what the caller must
///   not be told is settled.
/// * `confirmed` — not contested AND gated score `>= `[`confirmed_score`].
/// * `uncertain` — everything else.
///
/// The score is the GATED score: the value `min_truth` compared against
/// (`RecallGatedSignals::gated_score`), never the authored `truth_value`.
/// The two differ whenever evidence has moved a claim's DS cache away from
/// what its author asserted, and a partition that read the authored value
/// would call a claim `confirmed` that the gate rates 0.4, or `uncertain` a
/// claim the gate admitted at 0.9.
///
/// Within each bucket the caller's ranking order is PRESERVED (items are
/// pushed in the order they were given), so bucketing re-groups the page
/// without re-ranking it.
///
/// # The partition never changes which hits are returned
///
/// It is a regrouping of a list already fully filtered by `min_truth`,
/// `exclude_contested` and every other post-filter. That is why `recall`'s
/// audit row does not record the flag: the returned SET is identical with and
/// without it, and only the JSON shape differs.
#[derive(Debug, Clone, Serialize)]
pub struct EpistemicPartition<T> {
    /// Uncontested, with a gated score at or above [`confirmed_score`].
    pub confirmed: Vec<T>,
    /// Neither confirmed nor contested — believed, but not settled.
    pub uncertain: Vec<T>,
    /// Actively contested: `dispute_count >= 1`.
    pub open_question: Vec<T>,
}

/// The two signals [`EpistemicPartition`] buckets a recall hit by.
///
/// A trait rather than a caller-supplied closure: the
/// closure let each call site choose which number to partition on, and both
/// sites chose the authored `truth_value` while their `min_truth` gate read
/// `belief_score`. Implementing this on the hit type puts the choice in ONE
/// place per type, next to the field the gate writes.
pub(crate) trait RecallGatedSignals {
    /// The score `min_truth` was compared against for this hit: the DS
    /// pignistic probability when the claim carries a DS cache, else the
    /// authored `truth_value` (a hit with no DS state falls back exactly as
    /// the gate does).
    fn gated_score(&self) -> f64;
    /// Whether the dispute post-pass found a live `contradicts`/`refutes`.
    fn is_contested(&self) -> bool;
}

impl RecallGatedSignals for RecallResult {
    fn gated_score(&self) -> f64 {
        self.belief_score
    }
    fn is_contested(&self) -> bool {
        self.is_contested
    }
}

impl<T> EpistemicPartition<T> {
    /// Bucket `items` by their gated score and contest flag.
    pub(crate) fn from_ranked<I>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: RecallGatedSignals,
    {
        let mut out = Self {
            confirmed: Vec::new(),
            uncertain: Vec::new(),
            open_question: Vec::new(),
        };
        let confirmed = confirmed_score();
        for item in items {
            let (score, is_contested) = (item.gated_score(), item.is_contested());
            if is_contested {
                out.open_question.push(item);
            } else if score >= confirmed {
                out.confirmed.push(item);
            } else {
                out.uncertain.push(item);
            }
        }
        out
    }
}

/// Widest cosine distance `diversity_radius` will accept.
///
/// pgvector's `<=>` is cosine distance on `[0, 2]`, so 2.0 is "drop everything
/// not diametrically opposed to an already-selected hit" — already absurd, and
/// the ceiling past which the value cannot mean anything at all.
pub(crate) const MAX_DIVERSITY_RADIUS: f64 = 2.0;

/// Validate a caller-supplied `diversity_radius`.
///
/// REJECTS rather than clamps. A silently clamped radius produces a page that
/// looks filtered and is not, and this parameter's whole job is to change which
/// hits come back — the one class of mistake a caller most needs told. `0.0` is
/// rejected too: nothing is ever strictly nearer than zero, so it is a no-op
/// spelled like a setting, and `None` is the way to say "off".
///
/// # Errors
/// Returns the caller-facing message when the value is not finite, or is
/// outside `(0.0, 2.0]`.
pub(crate) fn validate_diversity_radius(radius: f64) -> Result<f64, String> {
    if !radius.is_finite() || radius <= 0.0 || radius > MAX_DIVERSITY_RADIUS {
        return Err(format!(
            "diversity_radius must be a finite value in (0.0, {MAX_DIVERSITY_RADIUS}] — \
             cosine distance is bounded on [0, 2], and 0.0 would drop nothing. \
             Got {radius}. Omit the parameter to disable diversity filtering."
        ));
    }
    Ok(radius)
}

/// Greedy maximal-marginal-relevance pass over a ranked page (backlog
/// a9397e8a): walk the page in rank order and drop any hit that sits within
/// `diversity_radius` cosine distance of a hit ALREADY selected above it.
///
/// `too_similar` is the set of unordered id pairs the DB measured as closer
/// than the radius — i.e. `ClaimRepository::pairwise_cosine_distance_at_dim`'s
/// output, which already applies the `< max_distance` cut in SQL.
///
/// Returns the ids to KEEP, in the input order.
///
/// # A pair that is not in `too_similar` is KEPT
///
/// This is the load-bearing default, and it is the opposite of the one that
/// looks natural. A pair is missing from the measured set for two very
/// different reasons — it is genuinely far apart, OR it could not be measured
/// at all (an unembedded hit from the embedder-down lexical leg, a workflow hit
/// whose id is not in `claims`, a row the viewer cannot see). Defaulting an
/// unmeasurable pair to "distance 0" would make every such hit a duplicate of
/// everything and silently empty the page down to one row. Keeping is the
/// honest reading: not known to be near.
///
/// # Shrink-only, never back-fill
///
/// The candidate list this runs on has already been truncated to `limit` by
/// SQL, so dropping a redundant hit returns a SHORTER page rather than pulling
/// a more diverse hit up from below. That matches `min_truth` and
/// `exclude_contested`, which are documented on both recall surfaces as
/// returning a short page rather than back-filling with worse-ranked material,
/// and it leaves `paging.more_available` — derived from the SQL page size, not
/// from `results.len()` — correct without modification.
pub(crate) fn greedy_diversity_keep(
    ranked_ids: &[uuid::Uuid],
    too_similar: &std::collections::HashSet<(uuid::Uuid, uuid::Uuid)>,
) -> Vec<uuid::Uuid> {
    let mut kept: Vec<uuid::Uuid> = Vec::with_capacity(ranked_ids.len());
    for &candidate in ranked_ids {
        let redundant = kept
            .iter()
            .any(|&selected| too_similar.contains(&unordered_pair(selected, candidate)));
        if !redundant {
            kept.push(candidate);
        }
    }
    kept
}

/// Normalise an unordered id pair so lookups cannot miss by argument order.
pub(crate) fn unordered_pair(a: uuid::Uuid, b: uuid::Uuid) -> (uuid::Uuid, uuid::Uuid) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Split a ranked page into the two mutually-exclusive response shapes the
/// `epistemic_partition` flag selects between.
///
/// Returns `(flat, partitioned)` where exactly one side is `Some`. Both
/// envelope fields carry `skip_serializing_if = "Option::is_none"`, so with
/// the flag off the response is byte-identical to what it was before this
/// parameter existed — `Some(vec![])` still serializes as `"results": []`,
/// which an empty-page caller relies on.
pub(crate) fn split_epistemic<T: RecallGatedSignals>(
    items: Vec<T>,
    partition: bool,
) -> (Option<Vec<T>>, Option<EpistemicPartition<T>>) {
    if partition {
        (None, Some(EpistemicPartition::from_ranked(items)))
    } else {
        (Some(items), None)
    }
}

#[derive(Debug, Serialize)]
pub struct AuthorResponse {
    pub agent_id: String,
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestDocumentParams {
    #[schemars(
        description = "Absolute or working-directory-relative path to a JSON file containing a hierarchical DocumentExtraction (thesis -> sections -> paragraphs -> atoms). The JSON may carry an optional top-level `labels` array of caller labels (e.g. a stage tag), applied to every claim the ingest writes in addition to the writer's own `doi:<document key>` label; a claim another agent authored that the ingest converges onto gets the doi: label only."
    )]
    pub file_path: String,
    /// Opt-in synchronous mode. `None`/`false` keeps the queued contract.
    #[schemars(
        description = "Optional, default false. When true the call WAITS for the all-or-nothing walk and returns its result (claims_ingested, claims_skipped_dedup, relationships_created, ...) or its error, instead of {status: 'queued'} over a background task whose failure reaches only the server log. Prefer true for a single document: a failed walk is then reported to you, and nothing was written but (possibly) the empty papers row, so retrying is safe."
    )]
    #[serde(default)]
    pub wait: Option<bool>,
}

/// Inline counterpart to `IngestDocumentParams`. Where `ingest_document`
/// takes a `file_path` to an opaque JSON file, this carries the typed
/// `DocumentExtraction` directly, so the full hierarchical shape is
/// self-documenting in the tool schema — the fix for MCP-only agents that
/// cannot write a file first and otherwise have to guess the JSON shape.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestDocumentInlineParams {
    #[schemars(
        description = "Hierarchical document extraction passed inline (no file): source (title, doi/uri, source_type, authors, journal, year, metadata), thesis, thesis_derivation, sections (each with a title + optional heading_span {start,end} and paragraphs, where each paragraph has text (verbatim source), optional span {start,end}, atoms, generality, confidence, methodology, evidence_type), relationships, an optional top-level source_text, and an optional top-level `labels` array of caller labels (e.g. a stage tag) applied to every claim the ingest writes or resolves to, in addition to the writer's own `doi:<document key>` label (a claim another agent authored that the ingest converges onto gets the doi: label only). When source_text is present the writer re-runs the verbatim guard, re-verifying each paragraph's text against its span; when it is absent — the case for AUTHORED records (an ELN entry, run summary, or anything with no external source to quote) — the guard is skipped and each paragraph's text is trusted as-is, so this is a supported SINGLE-CALL path with no `structure_source` / `ingest_document_spine` prerequisite. Lands the same graph as `ingest_document` — paper node, claims at every level down to atoms, decomposes_to / section_follows / supports edges, evidence, traces, embeddings, and CDST mass functions for atoms. Idempotent per document: structural nodes (thesis/section/paragraph) are keyed on (document title, structural path, text) and atoms on content hash, so re-ingesting an abstract then the full paper is safe — existing nodes are reused and only new content is written. Structural nodes are NOT shared between documents; atoms still converge across documents by design."
    )]
    #[serde(deserialize_with = "deserialize_document_extraction")]
    pub extraction: epigraph_ingest::schema::DocumentExtraction,
    /// Opt-in synchronous mode. `None`/`false` keeps the queued contract.
    #[schemars(
        description = "Optional, default false. When true the call WAITS for the all-or-nothing walk and returns its result (claims_ingested, claims_skipped_dedup, relationships_created, ...) or its error, instead of {status: 'queued'} over a background task whose failure reaches only the server log. Prefer true for a single document: a failed walk is then reported to you, and nothing was written but (possibly) the empty papers row, so retrying is safe."
    )]
    #[serde(default)]
    pub wait: Option<bool>,
}

/// Parameters for the `ingest_document_spine` MCP tool. Phase 1 of the
/// two-phase ingest flow: writes thesis + sections + paragraphs (levels 0–2)
/// and returns which paragraph paths are NEW so the caller can atomize only
/// those before calling `ingest_document_inline` with atoms.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestDocumentSpineParams {
    #[schemars(
        description = "DocumentExtraction whose `atoms` fields are EMPTY (e.g. the output of `structure_source`). Writes thesis + sections + paragraphs into the graph (structural nodes are scoped to this document, not shared with other papers that share a heading); atom fields are ignored. Returns `new_paragraph_paths` — the subset of paragraph paths that are NEW to this ingest. Atomize only those paragraphs, fill their atoms, then call `ingest_document_inline` with the full extraction. Two-phase ingest: spine first → atomize new paragraphs only → inline with atoms. An optional top-level `labels` array of caller labels (e.g. a stage tag) is applied to every node this call writes, in addition to the writer's own `doi:<document key>` label; a node another agent authored gets the doi: label only."
    )]
    #[serde(deserialize_with = "deserialize_document_extraction")]
    pub extraction: epigraph_ingest::schema::DocumentExtraction,
}

#[derive(Debug, Serialize)]
pub struct IngestDocumentSpineResponse {
    pub paper_id: String,
    pub paper_title: String,
    pub doi: String,
    /// `true` when `doi` is a `urn:epigraph:doc:*` key synthesized because the
    /// document carries no DOI — it is this document's identity, not a real DOI
    /// (issue #356). Poll and label with it exactly as returned.
    pub synthesized_key: bool,
    pub authors: Vec<AuthorResponse>,
    pub paragraphs_new: usize,
    pub paragraphs_deduped: usize,
    pub paragraphs_embedded: usize,
    /// Paragraph paths (e.g. `"sections[0].paragraphs[1]"`) that were written
    /// as new in this ingest. Atomize exactly these paragraphs, then call
    /// `ingest_document_inline` with atoms filled for those paths only.
    pub new_paragraph_paths: Vec<String>,
    /// Spine nodes this ingest resolved to that belong to a group the ingesting
    /// agent cannot write, so the document's labels (`doi:` and any caller
    /// `labels`) were not added to them.
    /// See `IngestDocumentResponse::converged_claims_unlabelled`.
    pub converged_claims_unlabelled: usize,
    /// Spine nodes this ingest resolved to that ANOTHER agent authored: they got
    /// the document's `doi:` label but not the caller's `labels`.
    /// See `IngestDocumentResponse::converged_claims_caller_labels_withheld`.
    pub converged_claims_caller_labels_withheld: usize,
    /// `true` when every paragraph in the extraction already existed; nothing new was written.
    pub already_ingested: bool,
}

/// Parameters for the `structure_source` MCP tool. Deterministically slices raw
/// markdown/plaintext (or an agent-supplied messy-input `segmentation`) into a
/// verbatim `DocumentExtraction` — sections + paragraphs as byte-exact source
/// slices, with `atoms` left EMPTY for the agent to fill and resubmit via
/// `ingest_document_inline`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructureSourceParams {
    #[schemars(
        description = "Raw source text to structure into a verbatim section/paragraph tree."
    )]
    pub text: String,
    #[schemars(
        description = "Document source metadata (title, doi/uri, source_type, authors, year, …) — same shape as DocumentExtraction.source."
    )]
    #[serde(deserialize_with = "deserialize_document_source")]
    pub source: epigraph_ingest::schema::DocumentSource,
    #[schemars(
        description = "Format of `text`: \"markdown\" or \"plaintext\". Determines the deterministic parser."
    )]
    pub format: String,
    #[schemars(
        description = "Optional messy-input boundary segmentation: per-section heading + verbatim paragraph block strings, located in order. When present, overrides deterministic parsing."
    )]
    #[serde(default)]
    pub segmentation: Option<epigraph_ingest::document::structure::SegmentationWire>,
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
    #[schemars(
        description = "UUID of the source claim. Written with YOUR agent's authority (your own OAuth agent over HTTP, where a caller with no authenticated principal cannot write; this server's own agent on stdio): a group-private claim of your own group works; a group-private claim you cannot read reports not found, and one owned by a group your agent cannot write is refused. Either refusal writes nothing."
    )]
    pub source_claim_id: String,

    #[schemars(
        description = "UUID of the target claim. Same authority rule as source_claim_id: own-group private claims work, another group's private claim is not found or refused, and nothing is written."
    )]
    pub target_claim_id: String,

    #[schemars(
        description = "Structural relationship type. One of: decomposes_to, section_follows, continues_argument."
    )]
    pub relationship: String,

    #[schemars(
        with = "Option<std::collections::BTreeMap<String, serde_json::Value>>",
        description = "Optional arbitrary JSON object attached to the edge."
    )]
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
    /// Whether this server's writing session owns the returned edge (its owner
    /// or co-owner is in the session's writable set), and so may patch,
    /// retract or delete it. `false` on a re-assertion of another writer's edge
    /// (operator decision D8: an edge between two public claims is its
    /// writer's).
    pub owned_by_caller: bool,
}

/// Parameters for the `patch_edge` MCP tool.
///
/// Mirrors the body of `PATCH /api/v1/edges/:id`: at least one of `valid_to`
/// or `properties` must be supplied. `properties` shallow-merges into the
/// existing JSONB object and must itself be an object.
///
/// `valid_to` is a string rather than a timestamp type because of the one
/// deliberate divergence from the HTTP contract: the literal `"now"` resolves
/// server-side to the current instant, since an LLM-driven MCP client has no
/// wall clock and would otherwise have to guess it.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchEdgeParams {
    #[schemars(
        description = "UUID of the edge to patch. Must be an edge YOU can read and your agent can write (your own OAuth agent over HTTP; this server's own agent on stdio). An edge you cannot read (for example one touching another group's private claim) reports not found; one you can read but your agent may not update (another writer's edge, or a world-owned edge between two public claims, which is administrative) is refused as such. Either way nothing is written."
    )]
    pub edge_id: String,

    #[schemars(
        description = "Close the edge's lifecycle window (retire it without losing audit history). Either an RFC3339 timestamp or the literal \"now\"."
    )]
    #[serde(default)]
    pub valid_to: Option<String>,

    #[schemars(
        with = "Option<std::collections::BTreeMap<String, serde_json::Value>>",
        description = "JSON object shallow-merged into the edge's existing properties: overlapping keys are overwritten, absent keys are preserved. Must be an object."
    )]
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

/// Response for the `patch_edge` MCP tool — the edge row as it stands after
/// the merge, plus `retired` (true when this call set `valid_to`).
#[derive(Debug, Serialize)]
pub struct PatchEdgeResponse {
    pub edge_id: String,
    pub source_id: String,
    pub source_type: String,
    pub target_id: String,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub retired: bool,
    /// When this patch took the edge out of force (`valid_to <= now()`), the
    /// edge-keyed BBA cleanup that ran in the same transaction (migration 120):
    /// the caller's own BBAs deleted, and the deferral that hands every other
    /// writer's to the maintenance replay. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bba_cleanup: Option<epigraph_db::BbaCleanup>,
}

/// Parameters for the `delete_edge` MCP tool — mirrors
/// `DELETE /api/v1/edges/:id`. Both RETRACT the row (`valid_to = now()` via
/// `EdgeRepository::retract_by_id`). Neither hard-deletes it.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteEdgeParams {
    #[schemars(
        description = "UUID of the edge to take out of force (retracted: valid_to is set, the row survives). Must be an edge YOU can read and your agent can write (your own OAuth agent over HTTP; this server's own agent on stdio). An edge you cannot read reports not found; one you can read but your agent may not retract (another writer's edge, or a world-owned edge between two public claims, which is administrative) is refused as such. Either way nothing is written."
    )]
    pub edge_id: String,
}

/// Response for the `delete_edge` MCP tool. `deleted` is always `true` on
/// success — a missing edge is an error, not `deleted=false`, mirroring the
/// route's 404.
#[derive(Debug, Serialize)]
pub struct DeleteEdgeResponse {
    pub edge_id: String,
    pub deleted: bool,
    /// The edge-keyed BBA cleanup that ran in the retraction's transaction
    /// (migration 120): `deleted` counts the caller's own BBAs removed;
    /// `deferral_event_id` is the `edge_retract` deferral handing every other
    /// writer's BBAs to the maintenance replay (absent when no BBA can be keyed
    /// on the edge).
    pub bba_cleanup: epigraph_db::BbaCleanup,
}

/// Parameters for the `link_alternative` MCP tool.
///
/// Promotes two existing claims into a mutually-exclusive alternative pair by
/// writing the **symmetric** `alternative_of` edge that `suggest_alternative_sets`
/// documents but no other tool can create (`link_epistemic` rejects the
/// relationship; `link_hierarchical` only takes structural types). The edge is
/// direction-agnostic — `{claim_a, claim_b}` is one edge regardless of order
/// (migration 042's `edges_alternative_of_symmetric_uniq`) — and deliberately
/// inert at write time: its belief effect flows later through CDST BP's
/// max-plausibility combine over the `alternative_set` view, not a Dempster
/// re-wire here. Idempotent on the unordered pair: a re-hit returns the existing
/// `edge_id` with `created=false`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkAlternativeParams {
    #[schemars(
        description = "UUID of the first competing claim. Written with YOUR agent's authority (your own OAuth agent over HTTP, where a caller with no authenticated principal cannot write; this server's own agent on stdio): a group-private claim of your own group works; a group-private claim you cannot read reports not found, and one owned by a group your agent cannot write is refused, with nothing written."
    )]
    pub claim_a: String,

    #[schemars(
        description = "UUID of the second competing claim. Same authority rule as claim_a."
    )]
    pub claim_b: String,

    #[schemars(
        description = "Optional UUID of the shared target the two claims are rival supporters of. Validated and stored on the edge for provenance. A claim you cannot read reports not found and nothing is written."
    )]
    #[serde(default)]
    pub target_claim_id: Option<String>,

    #[schemars(
        description = "Optional human rationale for why these two claims are alternatives. Stored on the edge."
    )]
    #[serde(default)]
    pub rationale: Option<String>,
}

/// Response for the `link_alternative` MCP tool.
///
/// `created=true` means the symmetric `alternative_of` edge was newly inserted;
/// `created=false` means an edge already linked the pair (in either direction)
/// and its existing `edge_id` is returned (idempotent re-runs).
#[derive(Debug, Serialize)]
pub struct LinkAlternativeResponse {
    pub edge_id: String,
    pub created: bool,
}

/// Parameters for the `link_epistemic` MCP tool.
///
/// Wires two existing claims with a **belief-affecting** epistemic relationship
/// (`supports`, `corroborates`, `elaborates`, `generalizes`, `specializes`,
/// `contradicts`, `refutes`) and triggers Dempster–Shafer recomputation on the
/// **target** claim. Direction is `source -> target` ("source `relationship`
/// target"). Unlike `link_hierarchical` (which is deliberately inert), this
/// tool mirrors `POST /api/v1/edges`'s create→wire path: on first creation it
/// builds a BBA from the source claim's belief interval and recomputes the
/// target's combined belief. Idempotent on `(source, target, relationship)`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LinkEpistemicParams {
    #[schemars(
        description = "UUID of the source claim (the evidence / asserting side). Written with YOUR agent's authority (your own OAuth agent over HTTP, where a caller with no authenticated principal cannot write; this server's own agent on stdio): a group-private claim of your own group works; a group-private claim you cannot read reports not found, and one owned by a group your agent cannot write is refused, with nothing written."
    )]
    pub source_claim_id: String,

    #[schemars(
        description = "UUID of the target claim (the side whose belief is recomputed). Same authority rule as source_claim_id for the edge itself. A PUBLIC target owned by a group your agent cannot write still gets the edge, but its belief is not moved: the response reports belief_wired=false."
    )]
    pub target_claim_id: String,

    #[schemars(
        description = "Epistemic relationship type. One of: supports, corroborates, elaborates, generalizes, specializes, contradicts, refutes; or the structural relations that move no belief: cites, and qualifies (a scope caveat: the source bounds the conditions under which the target applies; moves no belief). Use qualifies, not contradicts, for a caveat that limits where the target holds without saying it is false. (supersedes is intentionally NOT accepted — use supersede_claim.)"
    )]
    pub relationship: String,

    #[schemars(
        with = "Option<std::collections::BTreeMap<String, serde_json::Value>>",
        description = "Optional arbitrary JSON object attached to the edge."
    )]
    #[serde(default)]
    pub properties: Option<serde_json::Value>,
}

/// Belief interval echoed back in [`LinkEpistemicResponse`] so the caller can
/// observe the target claim's combined belief after the wire.
#[derive(Debug, Serialize)]
pub struct LinkEpistemicBelief {
    pub belief: f64,
    pub plausibility: f64,
    pub pignistic_prob: f64,
}

/// Response for the `link_epistemic` MCP tool.
///
/// `was_created=true` means a new edge row was inserted; `false` means an edge
/// with the same `(source, target, relationship)` — or, for a symmetric
/// relationship, the same unordered pair — already existed (idempotent re-hit).
/// Belief wiring is attempted on EVERY call, re-hits included. `belief_wired` is
/// `true` only when THIS call materialized the edge's BBA and recomputed the
/// target (engine outcome `Wired`), which a re-hit can do when the edge had no
/// BBA yet and its source has since gained belief. It is `false` when no belief
/// moved: the edge was already wired, the source has no belief interval, the
/// transfer was vacuous, the relationship is structural, or the wire was
/// refused or failed (e.g. a target owned by a group the calling agent cannot
/// write) — the edge row stays either way. `target_belief` is a best-effort read of the
/// target's cached DS columns after the recompute (`None` if the target carries
/// no belief yet or the read failed).
#[derive(Debug, Serialize)]
pub struct LinkEpistemicResponse {
    pub edge_id: String,
    pub was_created: bool,
    /// Whether this server's writing session owns the returned edge (see
    /// `LinkHierarchicalResponse::owned_by_caller`).
    pub owned_by_caller: bool,
    pub relationship: String,
    pub belief_wired: bool,
    /// Why `belief_wired` is false (backlog 0a996437); omitted when it is
    /// true. One of `source_has_no_belief`, `structural_relationship`,
    /// `vacuous_source_mass`, `already_wired` or `refused_or_failed` (the
    /// wiring was refused, e.g. a target this caller cannot write, or failed);
    /// `edge_retracted` and `source_author_unresolved` are defensive values
    /// seen only under a concurrent retraction or removal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief_wired_reason: Option<&'static str>,
    /// The claim `target_belief` describes, and the one the belief wire
    /// recomputed.
    ///
    /// Normally equals the request's `target_claim_id`. It is the request's
    /// `source_claim_id` in exactly one case: a SYMMETRIC relationship
    /// (`contradicts` / `corroborates`) that deduped against an edge already
    /// stored in the opposite direction. Those two orderings are one fact, so
    /// only one row exists, and both the wire and this readback follow the
    /// row's recorded orientation rather than the caller's argument order.
    /// Always echoed so a caller never has to infer which claim the interval
    /// belongs to.
    pub belief_target_claim_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_belief: Option<LinkEpistemicBelief>,
}

#[derive(Debug, Serialize)]
pub struct IngestDocumentResponse {
    pub paper_id: String,
    pub paper_title: String,
    pub doi: String,
    /// `true` when `doi` is a `urn:epigraph:doc:*` key synthesized because the
    /// document carries no DOI — it is this document's identity, not a real DOI
    /// (issue #356). Poll and label with it exactly as returned.
    pub synthesized_key: bool,
    pub authors: Vec<AuthorResponse>,
    pub claims_ingested: usize,
    pub claims_embedded: usize,
    pub claims_skipped_dedup: usize,
    pub relationships_created: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_ds_wired: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ds_frame_id: Option<String>,
    /// Claims this ingest RESOLVED TO (content-addressed convergence onto a row
    /// that already existed) but could not tag with the document's labels (its
    /// `doi:` label and any caller `labels`), because they belong to a group the
    /// ingesting agent cannot write. The paper still `asserts` each of them; only
    /// the labels are missing. Disclosed rather
    /// than swallowed, so a caller counting a paper's claim set by label can
    /// see the gap.
    ///
    /// **Who actually sees it.** This response reaches a caller only from the
    /// operator `ingest-document` CLI, which calls `do_ingest_document`
    /// synchronously (`ingest_document_spine` returns its own response type
    /// with the same field). The two DETACHED MCP tools, `ingest_document` and
    /// `ingest_document_inline`, answer `queued` and run `do_ingest_document`
    /// in a spawned task whose response is dropped — for them the count reaches
    /// only the server log (one WARN per unlabelled claim, target
    /// `tenancy.scoped_write`). A caller
    /// of those tools that needs the gap must compare the paper's `asserts`
    /// edges against its `doi:` label set itself. Stated because an earlier
    /// summary described this field as the disclosure for every ingest path.
    pub converged_claims_unlabelled: usize,
    /// Claims this ingest RESOLVED TO that another agent authored, which got the
    /// document's `doi:` label but NOT the caller's `labels`: caller vocabulary
    /// (a `resolved`, a `policy:` tag) is never written onto someone else's
    /// claim by an ingest, even one the ingesting agent's group membership lets
    /// it write. Disjoint from `converged_claims_unlabelled` (which counts rows
    /// that got no label at all) and always 0 when the extraction carries no
    /// `labels`. Reaches callers exactly as `converged_claims_unlabelled` does;
    /// the detached tools log one WARN per claim (target `tenancy.scoped_write`).
    pub converged_claims_caller_labels_withheld: usize,
    pub already_ingested: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckAlreadyIngestedParams {
    #[schemars(
        description = "Document identity key to check: a real DOI, or the `document_key` \
                       an ingest call returned for a document with no DOI (a \
                       `urn:epigraph:doc:*` key). Placeholders like \"unknown\" are \
                       rejected — they are not an identity."
    )]
    pub doi: String,
    #[schemars(
        description = "Pipeline version stamp, matched EXACTLY when given (e.g. \
                       'hierarchical_extraction_v2:ch3' to check one chapter of a chunked ingest; \
                       each chunk writes its own stamp). Omit to match the current hierarchical \
                       extraction pipeline's whole family: the whole-document stamp \
                       'hierarchical_extraction_v2' AND every per-chapter \
                       'hierarchical_extraction_v2:ch{n}' stamp. A default-mode \
                       already_ingested=true means AT LEAST ONE stamp in the family exists, not \
                       that every chapter landed; matched_pipeline_versions lists which were \
                       found."
    )]
    pub pipeline_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckAlreadyIngestedResponse {
    pub already_ingested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paper_id: Option<String>,
    pub doi: String,
    /// The stamp requested, or the base stamp when the caller omitted it.
    pub pipeline_version: String,
    /// The `processed_by` stamps actually found: the one exact stamp for an
    /// explicit `pipeline_version`, or every stamp in the base family
    /// (`base` and `base:ch{n}`, sorted) when it was omitted. Empty when not
    /// ingested (backlog 02653c4a). Each chunk of a chunked ingest writes its
    /// own stamp, so in default mode this is the list of chunks that landed,
    /// and `already_ingested` is `true` as soon as it holds ONE entry. A
    /// document chunk-ingested by an older server may list only its first
    /// chunk.
    pub matched_pipeline_versions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PaperResponse {
    pub doi: String,
    pub title: String,
    pub authors: Vec<AuthorResponse>,
    /// Total asserted claims for the paper, independent of paging. Compare
    /// against `offset + returned` to decide whether another page exists.
    pub claim_count: i64,
    /// `claims.len()` — the size of THIS page, not the total.
    pub returned: usize,
    /// Echo of the applied `offset` (after clamping).
    pub offset: i64,
    /// Echo of the applied `limit` (after clamping).
    pub limit: i64,
    /// `true` when `offset + returned < claim_count`, i.e. another page exists.
    pub has_more: bool,
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
    /// Hierarchical results only (absent for flat workflow claims). `steps` is
    /// the FROZEN plan text: the claims the workflow's `executes` edges named
    /// at ingest. `Some(true)` when at least one of those steps has since been
    /// evolved (`evolve_step`), so its lineage head differs from the frozen
    /// claim; the heads are in [`Self::evolved_steps`]. Absent when the
    /// lineage lookup failed (best-effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_evolved_steps: Option<bool>,
    /// The steps whose lineage head is not the frozen claim, indexed the way
    /// `evolve_step` / `report_hierarchical_outcome` index steps. Absent when
    /// nothing evolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evolved_steps: Option<Vec<EvolvedStep>>,
    /// Hierarchical results only: the highest `generation` that exists for
    /// this workflow's `canonical_name`. Greater than `generation` when a newer
    /// generation of the same lineage exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_generation: Option<i64>,
}

/// One frozen step of a hierarchical [`FindWorkflowResult`] whose lineage head
/// has moved on: listed when the lineage has more than one head, or its single
/// head is not the frozen claim. A step whose sole head is the frozen claim is
/// not listed, even when that claim is retired (it never evolved).
#[derive(Debug, Serialize)]
pub struct EvolvedStep {
    /// The index `evolve_step` / `report_hierarchical_outcome` take. It counts
    /// the `executes` edges the caller can see, so it is not guaranteed to be
    /// the position of the same step in [`FindWorkflowResult::steps`]; match on
    /// `frozen_claim_id` when that matters.
    pub step_index: usize,
    pub frozen_claim_id: String,
    /// The newest head with `is_current=true`, which is the claim name-mode
    /// `evolve_step` and `update_with_evidence` act on. When no head of the
    /// lineage is current, the newest head, with [`Self::is_current`] false.
    pub head_claim_id: String,
    pub head_content: String,
    /// `false` when every head of the lineage is retired (`is_current=false`
    /// with no `supersedes` edge): the step cannot be evolved or take
    /// evidence by name until it is revived or re-ingested.
    pub is_current: bool,
    /// The lineage has more than one head (concurrent `revises`); the head
    /// shown is the newest, and the caller must reconcile before relying on it.
    pub pending_resolution: bool,
}

#[derive(Debug, Serialize)]
pub struct ReportWorkflowOutcomeResponse {
    pub workflow_id: String,
    pub evidence_id: String,
    pub truth_before: f64,
    /// The workflow claim's `truth_value` after this call. Equal to
    /// `truth_before` when [`Self::truth_written`] is `false`.
    pub truth_after: f64,
    /// Whether this call wrote the workflow claim's `truth_value`. `false` when
    /// the caller reported on a PUBLIC workflow claim it does not own
    /// (migration 114): the outcome evidence and its BBA are the caller's own
    /// rows (owned by the caller's group, public), and the claim ROW stays its
    /// owner's.
    pub truth_written: bool,
    /// Whether the workflow claim's cached Dempster-Shafer columns were written
    /// by this call. See [`UpdateResponse::cache_written`].
    pub cache_written: bool,
    pub total_uses: i64,
    pub success_rate: f64,
    /// Present when [`Self::cache_written`] is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeprecateWorkflowResponse {
    /// Workflow ids (a flat workflow claim or a hierarchical `workflows` row)
    /// whose state this call changed. An id already deprecated is not listed.
    pub deprecated_ids: Vec<String>,
    /// Thesis, phase and step claims of a hierarchical workflow that this call
    /// retired (`is_current = false`, embeddings nulled).
    pub retired_claim_ids: Vec<String>,
    /// Claims of a deprecated hierarchical workflow that were KEPT because
    /// another live workflow still executes them.
    pub kept_shared_claim_ids: Vec<String>,
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
    /// The node's entity type(s) as recorded on the edges this caller can see
    /// ('claim', 'paper', 'workflow', 'agent', ...). Normally one; empty when
    /// the node has no visible edges.
    pub node_types: Vec<String>,
    pub edge_count: usize,
    pub edges: Vec<NeighborhoodEdge>,
}

#[derive(Debug, Serialize)]
pub struct TraverseNode {
    pub id: String,
    pub node_type: String,
    pub label: Option<String>,
    /// The node's independently authored `claims.truth_value`, reported
    /// unchanged. `None` for a non-claim node. NOT what `min_truth` gates on.
    pub truth_value: Option<f64>,
    /// The scalar `min_truth` was compared against (backlog `14b98adc`): the
    /// Dempster–Shafer pignistic probability when the node carries a DS cache,
    /// else `truth_value`. `None` for a non-claim node.
    ///
    /// On the default `min_truth = 0.0` path the DS lookup is skipped — no
    /// value of it could change which nodes are kept — so this equals
    /// `truth_value` there.
    pub belief_score: Option<f64>,
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
    /// Only edges whose source AND target are in `nodes`.
    pub edges: Vec<TraverseEdge>,
    /// Edges the walk followed (relationship filter already applied) that are
    /// not in `edges` because an endpoint was not returned: the node `limit`
    /// was reached, or `min_truth` dropped it. Always present, 0 when nothing
    /// was left out (backlog cdd8d097).
    pub edges_omitted: usize,
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
    /// What this call did to the caller's BBA for this (claim, frame,
    /// perspective_id): `inserted` (none existed), `unchanged` (an identical
    /// BBA was already stored, so nothing new was combined) or `replaced` (an
    /// earlier, different BBA was overwritten in place, same id). Backlog
    /// bcbe34b2.
    pub write_outcome: String,
    /// True iff `write_outcome` is `unchanged`: an identical resubmission is
    /// stored once, not combined again.
    pub deduplicated: bool,
    /// Human-readable notes about inputs that were ACCEPTED but do not do what
    /// their name suggests (e.g. a non-default `combination_method` or any
    /// `gamma`, neither of which changes the returned belief). Omitted when
    /// empty. Never a refusal: the evidence was stored.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// The supplied `evidence_type`, when the belief recompute cannot resolve
    /// it to a calibrated weight (not a calibration key or alias, and not in
    /// the frame's own override), so the BBA was combined at the 0.5
    /// unknown-type reliability. A WARNING, not a refusal: the BBA was stored.
    /// A matching sentence is in `warnings`. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_keys: Vec<String>,
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
    /// Belief under the requested `(frame, perspective)` lens. Present only when
    /// a perspective_id was supplied (frame_id required); omitted (not null)
    /// otherwise so a lens-free get_belief is byte-identical to today. The
    /// top-level belief/plausibility/etc remain the global (unlensed) values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lensed_belief: Option<LensedBelief>,
    /// The claim's belief under the atom-level model, beside the served value
    /// (`EPIGRAPH_COMPOUND_BELIEF=shadow` only; omitted, not null, otherwise,
    /// so a get_belief in the default mode is byte-identical to today). A
    /// compound carries `basis: "derived"`: computed from its visible atoms,
    /// not evidence about the claim. The top-level fields stay the served
    /// values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow: Option<epigraph_engine::belief_view::BeliefView>,
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
pub struct UnmarkDuplicateParams {
    #[schemars(description = "UUID of the claim to un-mark (a claim mark_duplicate retired)")]
    pub claim_id: String,
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

    /// The CLOSURE BASIS: the claims whose content justified closing the item.
    ///
    /// Without it a closure records no basis at all, so nothing can even
    /// identify a reopen candidate when later evidence contradicts whatever the
    /// resolution rested on. Each id becomes a
    /// `basis -justifies-> resolution` edge.
    ///
    /// WHAT THIS DOES AND DOES NOT BUY, measured rather than assumed — the
    /// backlog item that requested this asserted the stronger claim, and it is
    /// false on two independent counts today:
    ///   * `sheaf::restriction_kind_with_profile` does not name `"justifies"`,
    ///     so it takes the `_ => RestrictionKind::Neutral` arm;
    ///     `auto_wire_edge_if_epistemic` short-circuits on Neutral, so the edge
    ///     carries no BBA. `invalidate_and_rewire`'s own doc says "Only edges
    ///     that actually carried a BBA become targets", so `retraction_cascade`
    ///     skips it.
    ///   * `semantic_graph_neighbors` hard-codes its relationship set and does
    ///     not include `justifies`, so no existing traversal consumes it.
    ///
    /// What it DOES buy: the basis is recorded durably and is reverse-queryable
    /// — given a retracted basis, a query on `edges.source_id` finds every
    /// closure that rested on it. Making the cascade act on that automatically
    /// is a separate change (it requires giving `justifies` a non-Neutral
    /// restriction kind, which is a belief-semantics decision).
    ///
    /// Optional and defaulted so every existing caller stays wire-compatible.
    #[schemars(
        description = "UUIDs of the claims that justified this resolution (the closure basis). Each becomes a `basis -justifies-> resolution` edge, recording WHY the item was closed so that a later retraction of a basis can be reverse-queried to find the closures resting on it. It does NOT by itself reopen anything: `justifies` carries no belief mass today, so retraction_cascade and recompute_beliefs do not act on it. Must be visible to the caller."
    )]
    #[serde(default)]
    pub basis_claim_ids: Vec<String>,
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
    #[schemars(
        description = "UUID of the claim to patch. Must be a claim you can read (otherwise: not found) and one owned by a group your agent can write (otherwise: refused, nothing written). When you are authenticated (HTTP) you must also own it or hold claims:admin."
    )]
    pub claim_id: String,
    #[schemars(description = "New trace_id (must reference an existing reasoning_traces row)")]
    pub trace_id: Option<String>,
    #[schemars(
        with = "Option<std::collections::BTreeMap<String, serde_json::Value>>",
        description = "JSONB to merge into properties"
    )]
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

    #[schemars(
        description = "UUID of the actor (agent) triggering this event. Over an authenticated (HTTP) connection it must be your own agent id (omitted, it defaults to you); another agent's id is refused. On stdio it is recorded as given."
    )]
    pub actor_id: Option<String>,

    #[schemars(
        with = "std::collections::BTreeMap<String, serde_json::Value>",
        description = "JSON payload with event details"
    )]
    pub payload: serde_json::Value,
}

// ── Batch / Staging / Stats ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchSubmitClaimsParams {
    #[schemars(description = "Array of claim objects to submit (max 100)")]
    pub claims: Vec<BatchClaimEntry>,
}

/// One entry of `batch_submit_claims`: every field `submit_claim` accepts
/// (backlog 73657204).
///
/// This used to carry five of `SubmitClaimParams`'s nine fields, and the batch
/// tool hard-coded the other four — `methodology: "inductive_generalization"`
/// (which sets the trust modifier), `source_url: None`, `reasoning: None`,
/// `novelty_threshold: None` — so a batch submission could not say how a claim
/// was derived or where its evidence came from.
///
/// # Why the two structs cannot drift again
///
/// They are kept separate only because two fields are REQUIRED on
/// `submit_claim` and optional here (`methodology`, `confidence`), which a
/// flattened shared struct cannot express. Drift is closed in both directions
/// at compile time by `From<BatchClaimEntry> for SubmitClaimParams`: it
/// destructures this struct exhaustively with no `..` (a field added here is a
/// hard error, E0027, until the pattern binds it, and a bound field that is not
/// passed through is an unused variable, which `-D warnings` refuses) and builds
/// `SubmitClaimParams` with a full struct literal (a field added there and
/// missing here is a missing-field error). The schema-level ratchet
/// `tests/batch_submit_claims_parity.rs` additionally pins that this entry's
/// advertised properties are a superset of `submit_claim`'s.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchClaimEntry {
    #[schemars(description = "The claim content")]
    pub content: String,

    #[schemars(
        description = "How the claim was derived; the same vocabulary as submit_claim's \
                       methodology (direct_observation, instrumental, statistical_analysis, \
                       deductive_logic, inductive_generalization, ...). Optional: when omitted \
                       the entry is submitted as inductive_generalization, which is what every \
                       batch entry used before this field existed. An unknown value refuses \
                       THIS entry only (reported in results/error_details) and writes nothing \
                       for it; the other entries still land."
    )]
    #[serde(default)]
    pub methodology: Option<String>,

    #[schemars(description = "Evidence text. Stored permanently for human audit.")]
    pub evidence_data: String,

    #[schemars(
        description = "Evidence type: empirical, statistical, logical, testimonial, circumstantial"
    )]
    pub evidence_type: String,

    #[schemars(description = "Confidence 0.0-1.0 (default 0.5)")]
    pub confidence: Option<f64>,

    #[schemars(
        description = "Source URL, DOI, or reference for the evidence, as in submit_claim. \
                       Optional but strongly recommended."
    )]
    #[serde(default)]
    pub source_url: Option<String>,

    #[schemars(
        description = "Why the evidence supports this claim, as in submit_claim. Stored on the \
                       entry's reasoning trace."
    )]
    #[serde(default)]
    pub reasoning: Option<String>,

    #[schemars(
        description = "Optional labels to attach to the new claim (e.g. ['backlog','bug'])"
    )]
    #[serde(default)]
    pub labels: Vec<String>,

    #[schemars(
        description = "Semantic novelty gate threshold for this entry, exactly as submit_claim's \
                       novelty_threshold (default 0.05; 0.0 always inserts)."
    )]
    #[serde(default)]
    pub novelty_threshold: Option<f64>,
}

/// The methodology a batch entry gets when it names none — the value every
/// batch entry was hard-coded to before [`BatchClaimEntry::methodology`]
/// existed, so an existing caller's submissions are unchanged.
pub const BATCH_DEFAULT_METHODOLOGY: &str = "inductive_generalization";

/// The confidence a batch entry gets when it names none (unchanged).
pub const BATCH_DEFAULT_CONFIDENCE: f64 = 0.5;

impl From<BatchClaimEntry> for SubmitClaimParams {
    fn from(entry: BatchClaimEntry) -> Self {
        // EXHAUSTIVE on both sides, deliberately: no `..` in the pattern and
        // none in the literal. See `BatchClaimEntry`'s doc for why that is the
        // drift guard.
        let BatchClaimEntry {
            content,
            methodology,
            evidence_data,
            evidence_type,
            confidence,
            source_url,
            reasoning,
            labels,
            novelty_threshold,
        } = entry;
        Self {
            content,
            methodology: methodology.unwrap_or_else(|| BATCH_DEFAULT_METHODOLOGY.to_string()),
            evidence_data,
            evidence_type,
            confidence: confidence.unwrap_or(BATCH_DEFAULT_CONFIDENCE),
            source_url,
            reasoning,
            labels,
            novelty_threshold,
        }
    }
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
    /// BetP of the all-neighbour average restricted interval. Display only:
    /// `consistency_radius` is not `|local_betp - expected_betp|` once a
    /// Positive neighbour is present.
    pub expected_betp: f64,
    /// Max of the Positive-group Bel-floor shortfall (the node's Bel below
    /// the strongest supporter's restricted Bel; over-support scores 0) and
    /// `|local_betp - expected|` over the Negative/FrameEvidence group.
    pub consistency_radius: f64,
    /// Neighbour rows that constrain this node. The source side of a
    /// directional positive edge (supports, elaborates, specializes,
    /// generalizes) is not counted, so a pure supporter reports 0.
    pub neighbor_count: usize,
    pub local_belief: f64,
    pub local_plausibility: f64,
    pub open_world_local: f64,
    pub open_world_expected: f64,
    /// Interval twin of `consistency_radius`: the max of the Bel-floor
    /// shortfall and the Hausdorff distance to the Negative/FrameEvidence
    /// group's expected interval.
    pub interval_inconsistency: f64,
    /// `|width_local - width_expected|` against the all-neighbour average.
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
        description = "UUID of the agent who owns this perspective (defaults to the calling agent: your own OAuth agent over HTTP, where a caller with no authenticated principal cannot write; this server's own agent on stdio). Over HTTP it must be your own agent id; another agent's id is refused."
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
        description = "Map of evidence-type tag -> reliability alpha in [0,1] (e.g. {\"empirical\":0.95,\"testimonial\":0.3}). This is the frame-function lens read by scoped_belief. It is looked up with each BBA's evidence_type LOWERCASED and strict-key, so keys must be lowercase evidence-type vocabulary (calibration.toml [evidence_type_weights] keys or [evidence_type_aliases]). Any other key is still stored but is reported back in unknown_keys and warnings, because it matches no BBA the ingest and edge paths write. An empty map clears the override."
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
    #[schemars(
        description = "Subject entity name (optional; omit to match any subject). Requires subject_type. A name that matches no entity returns no triples and is listed in `unresolved`."
    )]
    pub subject: Option<String>,
    #[schemars(
        description = "Subject entity type_top: Material, Molecule, Method, etc. Required when subject is given; there is no default."
    )]
    pub subject_type: Option<String>,
    #[schemars(description = "Predicate pattern — matches via trigram similarity (optional)")]
    pub predicate: Option<String>,
    #[schemars(
        description = "Object entity name (optional; omit to match any object). Requires object_type. A name that matches no entity returns no triples and is listed in `unresolved`."
    )]
    pub object: Option<String>,
    #[schemars(
        description = "Object entity type_top. Required when object is given; there is no default."
    )]
    pub object_type: Option<String>,
    #[schemars(
        description = "Minimum triple confidence threshold, 0.0–1.0 (default 0.0 — no filtering)"
    )]
    pub min_confidence: Option<f64>,
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

    #[test]
    fn structure_source_params_accepts_stringified_source() {
        // Simulate a client that double-encodes the `source` object as a JSON string.
        let raw = serde_json::json!({
            "text": "hello world",
            "format": "plaintext",
            "source": "{\"title\":\"On the Stability of DNA Origami\",\"doi\":\"10.1002/anie.201802890\",\"source_type\":\"Paper\",\"authors\":[{\"name\":\"Kielar, C.\"}],\"journal\":\"Angew. Chem.\",\"year\":2018,\"metadata\":{\"pmid\":\"29799663\"}}"
        });
        let params: StructureSourceParams =
            serde_json::from_value(raw).expect("should deserialize");
        assert_eq!(params.source.title, "On the Stability of DNA Origami");
        assert_eq!(params.source.doi.as_deref(), Some("10.1002/anie.201802890"));
    }

    #[test]
    fn structure_source_params_accepts_object_source() {
        // Normal path: `source` arrives as a proper JSON object.
        let raw = serde_json::json!({
            "text": "hello world",
            "format": "plaintext",
            "source": {
                "title": "On the Stability of DNA Origami",
                "doi": "10.1002/anie.201802890"
            }
        });
        let params: StructureSourceParams =
            serde_json::from_value(raw).expect("should deserialize");
        assert_eq!(params.source.title, "On the Stability of DNA Origami");
    }

    #[test]
    fn ingest_document_inline_accepts_stringified_extraction() {
        let inner = serde_json::json!({
            "source": {"title": "Kielar 2018", "doi": "10.1002/anie.201802890"},
            "sections": []
        });
        let raw = serde_json::json!({ "extraction": inner.to_string() });
        let params: IngestDocumentInlineParams =
            serde_json::from_value(raw).expect("should deserialize");
        assert_eq!(params.extraction.source.title, "Kielar 2018");
    }

    #[test]
    fn ingest_document_inline_accepts_object_extraction() {
        let raw = serde_json::json!({
            "extraction": {
                "source": {"title": "Kielar 2018", "doi": "10.1002/anie.201802890"},
                "sections": []
            }
        });
        let params: IngestDocumentInlineParams =
            serde_json::from_value(raw).expect("should deserialize");
        assert_eq!(params.extraction.source.title, "Kielar 2018");
    }

    #[test]
    fn ingest_workflow_accepts_stringified_extraction() {
        let inner = serde_json::json!({
            "source": {"canonical_name": "test-workflow", "goal": "do stuff"},
            "phases": []
        });
        let raw = serde_json::json!({ "extraction": inner.to_string() });
        let params: IngestWorkflowParams = serde_json::from_value(raw).expect("should deserialize");
        assert_eq!(params.extraction.source.canonical_name, "test-workflow");
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
    #[schemars(
        description = "Decision: 'promote' (records the edge the row's verifier_verdict calls for — CORROBORATES for same/paraphrase/overlapping, contradicts for contradicts; refused for distinct) or 'reject'. To undo a promotion use the separate `retire_match_candidate` tool — it requires claims:admin because it withdraws another principal's assertion."
    )]
    pub verdict: String,
}

/// Params for `retire_match_candidate`.
///
/// Deliberately a SEPARATE tool from `decide_match_candidate` rather than a third
/// verdict on it. `SCOPE_MAP` is one scope per tool, and retirement is a different
/// class of act from promote/reject: those are additive (`claims:write`, the scope
/// that files a challenge), whereas retirement withdraws an assertion another
/// principal (the matcher) made, never the caller's own, which is administrative
/// (`claims:admin`). Supersession is no longer the analogy: since batch OA1 it is
/// the caller's act on a claim it writes, at `claims:write`. Folding it back into
/// `decide_match_candidate` would force one of the two to hold the wrong scope.
/// `sudo` (elevation plan EL-11): why the caller asks to elevate. Shown on
/// the ceremony page and kept on the ticket, the session and their audit
/// rows.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SudoParams {
    #[schemars(
        description = "Why you need to elevate (shown on the confirmation page and kept in the audit trail; at most 500 characters)"
    )]
    pub reason: String,
}

/// `propose_admin_act` (elevation plan EL-12b): an administrative act an
/// ELEVATED caller asks its own passkey to confirm.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProposeAdminActParams {
    #[schemars(
        description = "The act: role.grant, role.end, claim.custodial_supersede or passkey.register"
    )]
    pub kind: String,
    #[schemars(
        description = "The act's arguments, exactly the kind's keys. role.grant: role, holder (uuid), valid_from (time or null: from the execution), valid_to (time or null: open-ended), reason. role.end: assignment (uuid), reason. claim.custodial_supersede: claim (uuid), content_sha256 (64 hex), truth (decimal string, six places), reason, allow_owned (bool). passkey.register: person (your own uuid), label (or null), reason"
    )]
    pub args: serde_json::Map<String, serde_json::Value>,
    #[schemars(
        description = "Why you propose it (shown on the confirmation page and kept in the audit trail; at most 500 characters)"
    )]
    pub reason: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RetireMatchCandidateParams {
    #[schemars(description = "Match-candidate UUID to retire")]
    pub candidate_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecomputeBeliefsParams {
    #[schemars(
        description = "Explicit claim UUIDs to recompute. Highest-priority target selector — when present and non-empty, `labels` and the bulk enumeration are ignored."
    )]
    #[serde(default)]
    pub claim_ids: Option<Vec<String>>,

    #[schemars(
        description = "Recompute every current claim carrying ALL of these labels (e.g. a paper's claim set — ingest_document/ingest_document_inline tag every claim they write with `doi:<doi>`, so pass that to recompute just one paper). Used only when `claim_ids` is absent/empty."
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

// ── Label-family dedup (plan / apply / probe) ──

/// One would-be claim a writer asks `probe_label_dedup` about.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct LabelDedupCandidateParam {
    #[schemars(description = "Caller-chosen key, echoed back with the verdict")]
    pub key: String,
    #[schemars(description = "The content the writer is about to file")]
    pub content: String,
    #[schemars(description = "The labels the writer is about to file it with")]
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PlanLabelDedupParams {
    #[schemars(
        description = "STDIO ONLY. Path of the dedup profile file: absolute under, or relative to, the profile root this server was started with (EPIGRAPH_MCP_PROFILE_ROOT). Refused over HTTP, when no root is set, outside the root, through a symlink, or when it is not a regular file. Exactly one of profile_path / profile_json."
    )]
    pub profile_path: Option<String>,
    #[schemars(
        description = "HTTP ONLY. The dedup profile as inline JSON text (schema label-dedup-profile/v1). Refused on stdio. Exactly one of profile_path / profile_json."
    )]
    pub profile_json: Option<String>,
    #[schemars(
        description = "Reserved: reading the profile from a stored claim is not available yet; a call that sets it is refused (PROFILE_CLAIM_DEFERRED)."
    )]
    pub profile_claim_id: Option<String>,
    #[schemars(
        description = "REQUIRED. BLAKE3 (hex) of the exact profile bytes; a profile that hashes differently is refused (PROFILE_HASH_MISMATCH). On stdio it must also equal the pin this server was started with (EPIGRAPH_MCP_PROFILE_PIN) when one is set."
    )]
    pub profile_hash: String,
    #[schemars(description = "Run tag substituted into {run_tag}; must be a valid label")]
    pub run_tag: String,
    #[schemars(
        description = "YYYY-MM-DD. Required by the closeout and lifecycle sections; never defaulted to today"
    )]
    pub as_of: Option<String>,
    #[schemars(
        description = "Sections to plan: any of hygiene, dedup, closeout, lifecycle, signal_dedup. Default [hygiene, dedup]"
    )]
    #[serde(default)]
    pub sections: Vec<String>,
    #[schemars(
        description = "Most claims read per family (default and server cap 5000; a larger value is clamped and the clamp reported). A family larger than this is reported truncated, and apply refuses a truncated plan."
    )]
    pub max_claims: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApplyLabelDedupParams {
    #[schemars(description = "As plan_label_dedup (stdio only)")]
    pub profile_path: Option<String>,
    #[schemars(description = "As plan_label_dedup (HTTP only)")]
    pub profile_json: Option<String>,
    #[schemars(description = "Reserved; refused (PROFILE_CLAIM_DEFERRED)")]
    pub profile_claim_id: Option<String>,
    #[schemars(description = "As plan_label_dedup")]
    pub profile_hash: String,
    #[schemars(description = "As plan_label_dedup")]
    pub run_tag: String,
    #[schemars(description = "As plan_label_dedup")]
    pub as_of: Option<String>,
    #[schemars(description = "As plan_label_dedup")]
    #[serde(default)]
    pub sections: Vec<String>,
    #[schemars(description = "As plan_label_dedup")]
    pub max_claims: Option<i64>,
    #[schemars(
        description = "REQUIRED. The plan_hash of the plan you reviewed. Apply re-plans from live state with the same arguments and refuses with PLAN_DRIFT, writing nothing, when the hash differs."
    )]
    pub plan_hash: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ProbeLabelDedupParams {
    #[schemars(description = "As plan_label_dedup (stdio only)")]
    pub profile_path: Option<String>,
    #[schemars(description = "As plan_label_dedup (HTTP only)")]
    pub profile_json: Option<String>,
    #[schemars(description = "Reserved; refused (PROFILE_CLAIM_DEFERRED)")]
    pub profile_claim_id: Option<String>,
    #[schemars(description = "As plan_label_dedup")]
    pub profile_hash: String,
    #[schemars(description = "At most 100 would-be claims to classify")]
    pub candidates: Vec<LabelDedupCandidateParam>,
    #[schemars(
        description = "Also match against closed lifecycle signals (verdict match_only). Default false"
    )]
    #[serde(default)]
    pub include_closed_signals: bool,
    #[schemars(description = "As plan_label_dedup")]
    pub max_claims: Option<i64>,
}

/// One label change an apply committed, as `apply_label_dedup` returned it.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AppliedLabelChangeParam {
    pub unit: String,
    pub claim_id: String,
    #[serde(default)]
    pub labels_added: Vec<String>,
    #[serde(default)]
    pub labels_removed: Vec<String>,
}

/// One duplicate an apply marked, as `apply_label_dedup` returned it.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AppliedMarkParam {
    pub unit: String,
    #[schemars(description = "The marked duplicate")]
    pub dup: String,
    #[schemars(description = "The claim it was marked a duplicate of")]
    pub canonical: String,
    #[schemars(description = "The matching tier, as the apply returned it")]
    pub rule: String,
    #[serde(default)]
    pub matched_on: String,
    #[schemars(
        description = "The identity edge the mark wrote; when given, a claim marked again since (a new edge) is not un-marked"
    )]
    #[serde(default)]
    pub identity_edge: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RevertLabelDedupParams {
    #[schemars(description = "applied_units from the apply_label_dedup response, verbatim")]
    #[serde(default)]
    pub applied_units: Vec<AppliedLabelChangeParam>,
    #[schemars(description = "applied_marks from the apply_label_dedup response, verbatim")]
    #[serde(default)]
    pub applied_marks: Vec<AppliedMarkParam>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct LabelDedupIndexViewParams {
    #[schemars(description = "Canonical claim ids (at most 100)")]
    pub claim_ids: Vec<String>,
    #[schemars(
        description = "Cap on the duplicates read across all canonicals (default and server cap 5000); a read that hits it is reported truncated"
    )]
    pub max_claims: Option<i64>,
    #[schemars(
        description = "Leave out a duplicate whose author has another owner than the canonical's, as the plan does (default true); each one left out is listed in foreign_duplicates_ignored. false returns every duplicate"
    )]
    pub same_owner_only: Option<bool>,
}
