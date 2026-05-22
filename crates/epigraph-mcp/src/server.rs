#![allow(clippy::doc_markdown)]
#![allow(clippy::wildcard_imports)]

use std::sync::Arc;

use http::request::Parts;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_router, ServerHandler};
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::embed::McpEmbedder;
use crate::errors::{internal_error, McpError};
use crate::tools;
use crate::types::*;

use epigraph_crypto::AgentSigner;

#[derive(Clone)]
pub struct EpiGraphMcpFull {
    pub(crate) tool_router: ToolRouter<Self>,
    pub(crate) pool: PgPool,
    pub(crate) signer: Arc<AgentSigner>,
    pub(crate) agent_db_id: Arc<Mutex<Option<uuid::Uuid>>>,
    pub(crate) embedder: Arc<McpEmbedder>,
    pub(crate) read_only: bool,
}

impl EpiGraphMcpFull {
    /// Ensure agent exists in DB, return cached ID.
    pub(crate) async fn agent_id(&self) -> Result<uuid::Uuid, McpError> {
        let mut cached = self.agent_db_id.lock().await;
        if let Some(id) = *cached {
            return Ok(id);
        }
        let pub_key = self.signer.public_key();
        let agent = if let Some(a) =
            epigraph_db::AgentRepository::get_by_public_key(&self.pool, &pub_key)
                .await
                .map_err(internal_error)?
        {
            a
        } else {
            let agent = epigraph_core::Agent::new(pub_key, Some("mcp-agent".to_string()));
            epigraph_db::AgentRepository::create(&self.pool, &agent)
                .await
                .map_err(internal_error)?
        };
        let id = agent.id.as_uuid();
        *cached = Some(id);
        drop(cached);
        Ok(id)
    }

    /// Emit a durable `tool.invoked` event for an MCP dispatch.
    ///
    /// Called from `ServerHandler::call_tool` for every tool invocation
    /// (closes #61's tool.invoked requirement). Public so integration
    /// tests can exercise the same wiring without having to synthesize a
    /// full `rmcp::service::RequestContext`. Always best-effort: failure
    /// to publish must not break dispatch.
    pub async fn emit_tool_invoked(&self, tool_name: &str) {
        let actor_id = match self.agent_id().await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::warn!(
                    tool = tool_name,
                    error = ?e,
                    "tool.invoked: could not resolve MCP agent_id; recording event with NULL actor"
                );
                None
            }
        };

        let _ = epigraph_db::EventRepository::publish_or_log(
            &self.pool,
            "tool.invoked",
            actor_id,
            &serde_json::json!({
                "tool": tool_name,
                "read_only": self.read_only,
            }),
        )
        .await;
    }

    /// Return a JSON array of all registered MCP tools (name, description, schema).
    ///
    /// This is a static operation — no database access required. Used by the REST
    /// discovery endpoint so agents can introspect available tools at runtime.
    #[must_use]
    pub fn all_tools_json() -> serde_json::Value {
        let tools = Self::tool_router().list_all();
        serde_json::to_value(tools).unwrap_or(serde_json::Value::Array(vec![]))
    }

    /// Look up the required scope for `tool_name` and verify the
    /// caller has it. Returns `Err` with a JSON-RPC-style error if:
    /// - no `AuthContext` is attached (token validation never ran or
    ///   middleware was bypassed), or
    /// - the tool is not in `scope_map::SCOPE_MAP` (deny by default), or
    /// - the caller's token is missing the required scope.
    pub fn enforce_tool_scope(
        auth: Option<&epigraph_auth::AuthContext>,
        tool_name: &str,
    ) -> Result<(), McpError> {
        let Some(auth) = auth else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Unauthorized: no auth context (Bearer token required)",
                ),
                data: None,
            });
        };
        let Some(required) = crate::scope_map::required_scope(tool_name) else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' is not authorized (no scope mapping)"
                )),
                data: None,
            });
        };
        if !auth.has_scope(required) {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: tool '{tool_name}' requires scope '{required}'"
                )),
                data: None,
            });
        }
        Ok(())
    }

    /// Return an error if the server is in read-only mode.
    pub(crate) fn reject_if_read_only(&self) -> Result<(), McpError> {
        if self.read_only {
            Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Server is in read-only mode. Write operations are disabled.",
                ),
                data: None,
            })
        } else {
            Ok(())
        }
    }
}

#[tool_router]
impl EpiGraphMcpFull {
    #[must_use]
    pub fn new(pool: PgPool, signer: AgentSigner, embedder: McpEmbedder, read_only: bool) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            signer: Arc::new(signer),
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder: Arc::new(embedder),
            read_only,
        }
    }

    /// Create from pre-wrapped `Arc` values (for HTTP transport factory closure).
    #[must_use]
    pub fn new_shared(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        embedder: Arc<McpEmbedder>,
        read_only: bool,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            signer,
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder,
            read_only,
        }
    }

    // ── Claims (5 tools) ──

    #[tool(
        description = "Submit an epistemic claim with evidence. The full evidence text is preserved for human audit. Supports all evidence types (empirical 1.0x, statistical 0.9x, logical 0.85x, testimonial 0.6x). Prefer this over memorize when you have a source or data to cite."
    )]
    async fn submit_claim(
        &self,
        Parameters(params): Parameters<SubmitClaimParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::claims::submit_claim(self, params).await
    }

    #[tool(
        description = "Query epistemic claims by truth value threshold. Returns claims with their truth values and epistemic status."
    )]
    async fn query_claims(
        &self,
        Parameters(params): Parameters<QueryClaimsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::claims::query_claims(self, params).await
    }

    #[tool(
        description = "Retrieve a single epistemic claim by its UUID, including full epistemic state."
    )]
    async fn get_claim(
        &self,
        Parameters(params): Parameters<GetClaimParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::claims::get_claim(self, params).await
    }

    #[tool(
        description = "Verify a claim's Ed25519 signature and BLAKE3 content hash. Reports whether the claim has been tampered with."
    )]
    async fn verify_claim(
        &self,
        Parameters(params): Parameters<VerifyClaimParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::claims::verify_claim(self, params).await
    }

    #[tool(
        description = "Add new evidence to an existing claim and run a Bayesian belief update. Returns the before/after truth values."
    )]
    async fn update_with_evidence(
        &self,
        Parameters(params): Parameters<UpdateWithEvidenceParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::claims::update_with_evidence(self, params).await
    }

    #[tool(
        description = "Create a new claim that supersedes an existing one (semantic versioning). Old claim's is_current flips to false; new claim's supersedes column points at the old. NEW CLAIM INHERITS THE OLD CLAIM'S agent_id. Use mark_duplicate to mark a duplicate WITHOUT creating a new claim."
    )]
    async fn supersede_claim(
        &self,
        Parameters(params): Parameters<crate::types::SupersedeClaimParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::supersede::supersede_claim(self, params).await
    }

    #[tool(
        description = "Mark a claim as a duplicate of a canonical claim WITHOUT creating a new claim. Sets supersedes+is_current=false on the duplicate; canonical untouched. Use REST endpoint POST /api/v1/claims/:id/dedup for audit-trail provenance."
    )]
    async fn mark_duplicate(
        &self,
        Parameters(params): Parameters<crate::types::MarkDuplicateParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::supersede::mark_duplicate(self, params).await
    }

    #[tool(description = "Atomically add and/or remove labels on an existing claim. Idempotent.")]
    async fn update_labels(
        &self,
        Parameters(params): Parameters<crate::types::UpdateLabelsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::claims::update_labels(self, params).await
    }

    #[tool(
        description = "Retire a backlog claim in one call: submits a resolution claim via the canonical submit_claim pipeline (idempotent create + Evidence + Trace + DERIVED_FROM/HAS_TRACE/AUTHORED edges + DS auto-wire + embedding), prefixed with 'Resolves <original_id>: ' and labeled ['resolved'], then patches the original claim's labels with add=['resolved'] (keeping 'backlog'). Label-side retirement — original stays is_current=true / supersedes=None. Returns {resolution_claim_id, original_id, original_labels}."
    )]
    async fn resolve_backlog_item(
        &self,
        Parameters(params): Parameters<crate::types::ResolveBacklogItemParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::claims::resolve_backlog_item(self, params).await
    }

    #[tool(
        description = "Patch a claim atomically (trace_id, properties JSONB merge, label add/remove). FAST PATH — does NOT emit provenance. Use REST PATCH /api/v1/claims/:id if audit trail required."
    )]
    async fn patch_claim(
        &self,
        Parameters(params): Parameters<crate::types::PatchClaimParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::claims::patch_claim(self, params).await
    }

    // ── Provenance (1 tool) ──

    #[tool(
        description = "Get the provenance lineage for a claim — all ancestor claims, evidence, and reasoning traces in topological order."
    )]
    async fn get_provenance(
        &self,
        Parameters(params): Parameters<GetProvenanceParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::provenance::get_provenance(self, params).await
    }

    // ── Memory (2 tools) ──

    #[tool(
        description = "Quick-store a memory as a testimonial claim (0.6x evidence weight). For facts you want to recall later."
    )]
    async fn memorize(
        &self,
        Parameters(params): Parameters<MemorizeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::memory::memorize(self, params).await
    }

    #[tool(
        description = "Recall relevant memories using semantic search with epistemic quality scoring."
    )]
    async fn recall(
        &self,
        Parameters(params): Parameters<RecallParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::memory::recall(self, params).await
    }

    #[tool(
        description = "Paragraph-primary semantic search over the claim graph with batched structural context: parent paper, parent section, child atoms (with cross-paragraph bridges), sibling paragraphs, neighbor paragraphs reachable via continues_argument / atom-bridge / atom-atom-bridge, and CORROBORATES neighbors. Auto-detects centroid_dim (1536 vs 3072) by default."
    )]
    async fn recall_with_context(
        &self,
        Parameters(params): Parameters<crate::tools::recall::RecallWithContextParams>,
    ) -> Result<CallToolResult, McpError> {
        crate::tools::recall::recall_with_context(self, params).await
    }

    #[tool(
        description = "Evolve a versioned step or operation by atomically creating a new claim that supersedes or revises an existing one. Use 'supersedes' for linear refinement; 'revises' for a concurrent branch from a common ancestor. The new claim shares the same step_lineage_id as the parent."
    )]
    async fn evolve_step(
        &self,
        Parameters(params): Parameters<crate::tools::evolve_step::EvolveStepParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::evolve_step::evolve_step(self, params).await
    }

    // ── Ingestion ──

    #[tool(
        description = "Ingest a hierarchical DocumentExtraction JSON file (thesis -> sections -> paragraphs -> atoms). Creates a paper node, claims at each level, decomposes_to / section_follows / supports / contradicts / refines edges, evidence, traces, embeddings, and CDST mass functions for atoms. Idempotent for re-runs at the same pipeline version."
    )]
    async fn ingest_document(
        &self,
        Parameters(params): Parameters<IngestDocumentParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document(self, params).await
    }

    #[tool(
        description = "Create a cross-tier structural edge between two existing claims (decomposes_to, section_follows, or continues_argument). Purpose-built for per-chapter ingest wire-ups (chapter thesis -> book thesis, chapter[N] -> chapter[N+1]). Idempotent on (source, target, relationship): re-runs return the existing edge_id with created=false. Bypasses HTTP and goes straight through the repo layer."
    )]
    async fn link_hierarchical(
        &self,
        Parameters(params): Parameters<LinkHierarchicalParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::link_hierarchical::link_hierarchical(self, params).await
    }

    // ── Paper Queries (3 tools) ──

    #[tool(description = "Look up a paper by its DOI, returning title, authors, and claims.")]
    async fn query_paper(
        &self,
        Parameters(params): Parameters<QueryPaperParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::paper_queries::query_paper(self, params).await
    }

    #[tool(
        description = "Find claims backed by a specific type of evidence (observation, computation, reference, testimony, document)."
    )]
    async fn query_claims_by_evidence(
        &self,
        Parameters(params): Parameters<QueryClaimsByEvidenceParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::paper_queries::query_claims_by_evidence(self, params).await
    }

    #[tool(
        description = "Find claims derived from a specific reasoning methodology (statistical, deductive, inductive, abductive, analogical)."
    )]
    async fn query_claims_by_methodology(
        &self,
        Parameters(params): Parameters<QueryClaimsByMethodologyParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::paper_queries::query_claims_by_methodology(self, params).await
    }

    #[tool(
        description = "Find claims by label using PostgreSQL array containment (GIN-indexed). Returns claims containing ALL specified labels. Useful for querying backlog items (e.g. [\"backlog\", \"pending\"]), workflows, or any labeled claim set."
    )]
    async fn query_claims_by_label(
        &self,
        Parameters(params): Parameters<QueryClaimsByLabelParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::paper_queries::query_claims_by_label(self, params).await
    }

    // ── Workflows (5 tools) ──

    #[tool(
        description = "Store a new workflow as an epistemic hypothesis with ordered steps and prerequisites."
    )]
    async fn store_workflow(
        &self,
        Parameters(params): Parameters<StoreWorkflowParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflows::store_workflow(self, params).await
    }

    #[tool(description = "Search for existing workflows by goal using semantic search.")]
    async fn find_workflow(
        &self,
        Parameters(params): Parameters<FindWorkflowParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::workflows::find_workflow(self, params).await
    }

    #[tool(
        description = "Record what actually happened when you used a workflow — step-by-step lab notebook with deviations."
    )]
    async fn report_workflow_outcome(
        &self,
        Parameters(params): Parameters<ReportWorkflowOutcomeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflows::report_workflow_outcome(self, params).await
    }

    #[tool(
        description = "Deprecate a workflow (and optionally its entire lineage). Sets truth to 0.05."
    )]
    async fn deprecate_workflow(
        &self,
        Parameters(params): Parameters<DeprecateWorkflowParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflows::deprecate_workflow(self, params).await
    }

    // ── Hierarchical Workflows (4 tools) ──
    //
    // Counterparts to the flat `store_workflow` family above. These operate
    // on the `workflows` table where every step is a claim node connected
    // via `executes` edges, so each step accrues evidence and Darwinian
    // variants independently of its workflow root.

    #[tool(
        description = "Ingest a hierarchical WorkflowExtraction: persists thesis → phases → steps → operation atoms as claim nodes, writes `executes` edges from the workflow root to every planned claim, and resolves author identities. Idempotent: re-ingesting the same canonical_name+generation is a no-op."
    )]
    async fn ingest_workflow(
        &self,
        Parameters(params): Parameters<IngestWorkflowParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflow_ingest::ingest_workflow(self, params).await
    }

    #[tool(
        description = "Create a generation-incremented hierarchical variant of an existing workflow. Looks up parent by canonical_name, finds its latest generation, and ingests the new extraction with generation = parent + 1 and parent_canonical_name linked. Same-lineage improvement only: the new variant's canonical_name and parent_canonical_name are both set to the tool's `parent_canonical_name` param; cross-lineage variants are not supported. Each call produces a new generation."
    )]
    async fn improve_workflow_hierarchy(
        &self,
        Parameters(params): Parameters<ImproveWorkflowHierarchyParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflow_ingest::improve_workflow_hierarchy(self, params).await
    }

    #[tool(
        description = "Search hierarchical workflows by free-text over goal and canonical_name (ILIKE). Returns rows from the `workflows` table — distinct from `find_workflow` which searches flat workflow claims."
    )]
    async fn find_workflow_hierarchical(
        &self,
        Parameters(params): Parameters<FindWorkflowHierarchicalParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::workflow_hierarchical::find_workflow_hierarchical(self, params).await
    }

    #[tool(
        description = "Record an outcome for a hierarchical workflow run. Updates rolling counters in workflows.metadata (use_count, success_count, failure_count, avg_variance) and writes one behavioral_executions row per step_execution with step_claim_id resolved from the workflow's `executes` edges in plan order. Use `report_workflow_outcome` instead for flat workflow claims."
    )]
    async fn report_hierarchical_outcome(
        &self,
        Parameters(params): Parameters<ReportHierarchicalOutcomeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflow_hierarchical::report_hierarchical_outcome(self, params).await
    }

    #[tool(
        description = "Append or middle-insert a step into an existing hierarchical workflow. `position=None` appends; `position=Some(i)` inserts at the 0-indexed slot i. Idempotent on `(canonical_name, step_text)` via deterministic claim ID. Re-wires the `step_follows` chain."
    )]
    async fn add_step(
        &self,
        Parameters(params): Parameters<crate::tools::step_ops::AddStepParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::step_ops::add_step(self, params).await
    }

    #[tool(
        description = "Soft-delete a workflow step by step_lineage_id. Sets the head claim's truth_value to 0.05; default min_truth filters hide it from active queries while preserving history. Does not rewire the step_follows chain."
    )]
    async fn delete_step(
        &self,
        Parameters(params): Parameters<crate::tools::step_ops::DeleteStepParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::step_ops::delete_step(self, params).await
    }

    // ── Graph (2 tools) ──

    #[tool(
        description = "Get the immediate graph neighborhood of any node — all connected edges with optional relationship and direction filters."
    )]
    async fn get_neighborhood(
        &self,
        Parameters(params): Parameters<GetNeighborhoodParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::graph::get_neighborhood(self, params).await
    }

    #[tool(
        description = "Multi-hop graph walk from a starting node. BFS traversal with optional relationship filter and truth threshold."
    )]
    async fn traverse(
        &self,
        Parameters(params): Parameters<TraverseParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::graph::traverse(self, params).await
    }

    // ── Challenges (2 tools) ──

    #[tool(
        description = "Submit a typed challenge against a claim. Types: insufficient_evidence, outdated_evidence, flawed_methodology, contradicting_evidence, factual_error."
    )]
    async fn challenge_claim(
        &self,
        Parameters(params): Parameters<ChallengeclaimParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::challenges::challenge_claim(self, params).await
    }

    #[tool(description = "List all challenges filed against a specific claim.")]
    async fn list_challenges(
        &self,
        Parameters(params): Parameters<ListChallengesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::challenges::list_challenges(self, params).await
    }

    // ── Events (2 tools) ──

    #[tool(
        description = "Query the event log with optional type and actor filters. Returns recent graph events."
    )]
    async fn list_events(
        &self,
        Parameters(params): Parameters<ListEventsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::events::list_events(self, params).await
    }

    #[tool(
        description = "Manually publish an event to the graph event log for audit and traceability."
    )]
    async fn publish_event(
        &self,
        Parameters(params): Parameters<PublishEventParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::events::publish_event(self, params).await
    }

    // ── Batch / Staging / Stats (3 tools) ──

    #[tool(
        description = "Submit multiple claims in a single batch (max 100). Each entry needs content, evidence_data, evidence_type, and optional confidence."
    )]
    async fn batch_submit_claims(
        &self,
        Parameters(params): Parameters<BatchSubmitClaimsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::batch::batch_submit_claims(self, params).await
    }

    #[tool(
        description = "Validate claims without persisting them. Returns validity checks and warnings for each claim."
    )]
    async fn stage_claims(
        &self,
        Parameters(params): Parameters<StageClaimsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::batch::stage_claims(self, params).await
    }

    #[tool(
        description = "Get aggregate system statistics — claim, evidence, edge, agent, and frame counts. Set detailed=true for breakdowns."
    )]
    async fn system_stats(
        &self,
        Parameters(params): Parameters<SystemStatsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::batch::system_stats(self, params).await
    }

    // ── Perspectives & Ownership (6 tools) ──

    #[tool(
        description = "Create a new perspective (viewpoint) for scoped belief reasoning. Perspectives can be associated with frames and agents."
    )]
    async fn create_perspective(
        &self,
        Parameters(params): Parameters<CreatePerspectiveParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::create_perspective(self, params).await
    }

    #[tool(description = "List all perspectives with optional limit.")]
    async fn list_perspectives(
        &self,
        Parameters(params): Parameters<ListPerspectivesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::perspectives::list_perspectives(self, params).await
    }

    #[tool(description = "Get a single perspective by UUID.")]
    async fn get_perspective(
        &self,
        Parameters(params): Parameters<GetPerspectiveParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::perspectives::get_perspective(self, params).await
    }

    #[tool(
        description = "Assign ownership of a graph node (claim, evidence, perspective, etc.) to an agent with a partition type (public/community/private)."
    )]
    async fn assign_ownership(
        &self,
        Parameters(params): Parameters<AssignOwnershipParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::assign_ownership(self, params).await
    }

    #[tool(description = "Get ownership info (partition, owner) for a graph node by UUID.")]
    async fn get_ownership(
        &self,
        Parameters(params): Parameters<GetOwnershipParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::perspectives::get_ownership(self, params).await
    }

    #[tool(
        description = "Update the partition type of a node (public → private, etc.). Only changes visibility, not ownership."
    )]
    async fn update_partition(
        &self,
        Parameters(params): Parameters<UpdatePartitionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::update_partition(self, params).await
    }

    // ── DS/Belief (7 tools — 4 enhanced + 3 new) ──

    #[tool(
        description = "Create a frame of discernment (set of mutually exclusive hypotheses) for Dempster-Shafer belief reasoning. Supports refinement hierarchies."
    )]
    async fn create_frame(
        &self,
        Parameters(params): Parameters<CreateFrameParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ds::create_frame(self, params).await
    }

    #[tool(
        description = "Submit Dempster-Shafer evidence (mass function / BBA) for a claim within a frame. Supports all 6 combination methods (Dempster, Conjunctive, YagerOpen, YagerClosed, DuboisPrade, Inagaki) and perspective-scoped combination."
    )]
    async fn submit_ds_evidence(
        &self,
        Parameters(params): Parameters<SubmitDsEvidenceParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ds::submit_ds_evidence(self, params).await
    }

    #[tool(
        description = "Query the Dempster-Shafer belief interval for a claim. Returns Bel, Pl, ignorance, BetP, and CDST conflict/missing separation."
    )]
    async fn get_belief(
        &self,
        Parameters(params): Parameters<GetBeliefParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ds::get_belief(self, params).await
    }

    #[tool(
        description = "List all frames of discernment with their hypotheses, version, and refinement info."
    )]
    async fn list_frames(
        &self,
        Parameters(params): Parameters<ListFramesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ds::list_frames(self, params).await
    }

    #[tool(
        description = "Run all 6 CDST combination methods on stored BBAs for a claim, returning side-by-side Bel/Pl/BetP and conflict metrics for comparison."
    )]
    async fn compare_methods(
        &self,
        Parameters(params): Parameters<CompareMethodsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ds::compare_methods(self, params).await
    }

    #[tool(
        description = "Get belief scoped to a specific perspective or community, showing how different viewpoints assess a claim."
    )]
    async fn scoped_belief(
        &self,
        Parameters(params): Parameters<ScopedBeliefParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ds::scoped_belief(self, params).await
    }

    #[tool(
        description = "Get the DS-vs-Bayesian KL divergence for a claim, measuring how much the Dempster-Shafer and Bayesian assessments disagree."
    )]
    async fn get_divergence(
        &self,
        Parameters(params): Parameters<GetDivergenceParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ds::get_divergence(self, params).await
    }

    // ── Sheaf (3 tools) ──

    #[tool(
        description = "Check CDST sheaf consistency across all claims. Computes per-node consistency radii using restriction maps — identifies claims whose local belief diverges from what their epistemic neighbors would predict. Returns sections sorted by inconsistency (worst first). Use this to find belief staleness, local contradictions, and open-world spread in the knowledge graph."
    )]
    async fn check_sheaf_consistency(
        &self,
        Parameters(params): Parameters<CheckSheafConsistencyParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::sheaf::check_sheaf_consistency(self, params).await
    }

    #[tool(
        description = "Compute CDST sheaf cohomology — the global inconsistency measure for the knowledge graph. Returns decomposed H¹ with three channels: conflict_h1 (genuine belief contradictions), ignorance_h1 (epistemic staleness), and open_world_h1 (frame incompleteness spread). Use this to assess overall knowledge-graph health and triage which type of inconsistency dominates."
    )]
    async fn sheaf_cohomology(
        &self,
        Parameters(params): Parameters<SheafCohomologyParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::sheaf::sheaf_cohomology(self, params).await
    }

    #[tool(
        description = "Run Phase 2 sheaf reconciliation: clusters obstruction subgraphs and runs interval belief propagation within each cluster to propose updated belief intervals. Returns updated_intervals (suggested BetP/Bel/Pl corrections), frame_evidence_proposals (claims where new frame evidence would reduce open-world mass), and convergence status. Does NOT write to the database — results are proposals for human or automated review."
    )]
    async fn reconcile_sheaf(
        &self,
        Parameters(params): Parameters<ReconcileSheafParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::sheaf::reconcile_sheaf(self, params).await
    }

    // ── Themes (1 tool) ──

    #[tool(
        description = "Trigger server-side theme clustering via k-means over the claim corpus. Mirrors POST /api/v1/themes/build-from-corpus. Defaults: k_min=4, k_max=16, min_claims_per_theme=5, limit=500 (hard-capped at 500 here for OOM safety), label_prefix=\"auto\", centroid_dim=1536. Default `wipe_first=true` ensures clean rebuilds on each call. Pass `false` only for additive runs with a unique `label_prefix` (otherwise duplicate themes accumulate — see backlog: missing UNIQUE constraint on claim_themes.label)."
    )]
    async fn theme_cluster(
        &self,
        Parameters(params): Parameters<crate::tools::themes::ThemeClusterParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::themes::theme_cluster(self, params).await
    }

    // ── RDF Triple Layer (3 tools) ──

    #[tool(
        description = "Query RDF-style triples extracted from claims. Filter by subject entity, predicate pattern, and/or object entity. All filters optional (omit to wildcard). Returns triples with source claim references."
    )]
    async fn query_triples(
        &self,
        Parameters(params): Parameters<QueryTriplesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::rdf::query_triples(self, params).await
    }

    #[tool(
        description = "Get everything known about an entity — all triples where it appears as subject or object, grouped by predicate. Pass entity name (e.g. 'DNA origami') or UUID."
    )]
    async fn entity_neighborhood(
        &self,
        Parameters(params): Parameters<EntityNeighborhoodParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::rdf::entity_neighborhood(self, params).await
    }

    #[tool(
        description = "Search triples via natural language. Uses embedding similarity to find relevant claims, then returns their structured triples. Complements query_triples (structured) with fuzzy discovery."
    )]
    async fn search_triples(
        &self,
        Parameters(params): Parameters<SearchTriplesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::rdf::search_triples(self, params).await
    }

    // ── Cross-source matching (3 tools) ──

    #[tool(
        description = "Look up existing cross-source matches for a claim. Returns match_candidates rows (any status) plus any CORROBORATES edges already written. Read-only — to *run* the matcher across new claims, use the `cross_source_sweep` CLI."
    )]
    async fn find_cross_source_matches(
        &self,
        Parameters(params): Parameters<FindCrossSourceMatchesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::matching::find_cross_source_matches(self, params).await
    }

    #[tool(
        description = "List match_candidates rows, sorted by score desc. Filter by status (pending|promoted|rejected|stale) or get all. Use this to triage what the matcher has surfaced."
    )]
    async fn list_match_candidates(
        &self,
        Parameters(params): Parameters<ListMatchCandidatesParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::matching::list_match_candidates(self, params).await
    }

    #[tool(
        description = "Decide a pending match candidate: 'promote' writes a CORROBORATES edge and marks the row promoted; 'reject' marks it rejected. Honours read-only mode."
    )]
    async fn decide_match_candidate(
        &self,
        Parameters(params): Parameters<DecideMatchCandidateParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::matching::decide_match_candidate(self, params).await
    }

    // ── Meta (1 tool) ──

    #[tool(
        description = "List all MCP tools available on this server. Returns the name, description, and JSON Schema for every registered tool. Use this for runtime tool discovery — the list reflects the live server state, including newly deployed tools not yet stored in the knowledge graph."
    )]
    async fn list_mcp_tools(&self) -> Result<CallToolResult, McpError> {
        let tools = self.tool_router.list_all();
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&tools).map_err(crate::errors::internal_error)?,
        )]))
    }
}

// Manual `ServerHandler` impl (in lieu of `#[tool_handler]`) so `call_tool`
// can be wrapped with durable event emission. Mirrors the macro's expansion
// for `list_tools` and `get_tool` verbatim — see
// `rmcp-macros-0.15.0/src/tool_handler.rs` for the canonical body.
//
// `call_tool` is the single chokepoint for every MCP tool invocation. We
// emit one `tool.invoked` event per call (closes #61's tool.invoked
// requirement) and forward to the macro-built dispatcher unchanged. Event
// emission is fire-and-forget; a failed event publish must not break tool
// dispatch.
impl ServerHandler for EpiGraphMcpFull {
    fn get_info(&self) -> ServerInfo {
        let mode = if self.read_only { "read-only" } else { "full" };
        let tool_count = if self.read_only { 33 } else { 60 };
        ServerInfo {
            instructions: Some(format!(
                "EpiGraph {mode} MCP server with {tool_count} epistemic tools."
            )),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        // For HTTP requests, the Bearer middleware (`auth::bearer_auth_middleware`)
        // inserts an `AuthContext` into request.extensions; rmcp's
        // `StreamableHttpService` forwards those into `context.extensions` via
        // `http::request::Parts` (see rmcp/src/transport/streamable_http_server/
        // tower.rs:326/384/463). For stdio transport there is no `Parts` attached —
        // the stdio process boundary is the trust gate and no auth check applies.
        let http_parts = context.extensions.get::<Parts>();
        let auth = http_parts.and_then(|p| p.extensions.get::<epigraph_auth::AuthContext>());

        if http_parts.is_some() {
            if let Err(err) = Self::enforce_tool_scope(auth, &request.name) {
                // Emit a denial audit event so 403s show up alongside successes.
                self.emit_tool_invoked(&format!("denied:{}", request.name))
                    .await;
                return Err(err);
            }
        }

        // Single chokepoint for every MCP tool invocation: emit a durable
        // tool.invoked event before dispatch, then forward to the
        // macro-built dispatcher.
        //
        // **DO NOT remove this line without updating
        // `tests/event_log_wiring_tests.rs::tool_dispatch_emits_tool_invoked_event`.**
        self.emit_tool_invoked(&request.name).await;

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListToolsResult {
            tools: self.tool_router.list_all(),
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        self.tool_router.get(name).cloned()
    }
}

#[cfg(test)]
mod scope_guard_tests {
    use super::*;
    use epigraph_auth::{AuthContext, ClientType};
    use uuid::Uuid;

    fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
        AuthContext {
            client_id: Uuid::new_v4(),
            agent_id: None,
            owner_id: None,
            client_type: ClientType::Service,
            scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
            jti: Uuid::new_v4(),
        }
    }

    #[test]
    fn scope_guard_allows_matching_scope() {
        let auth = auth_with_scopes(&["claims:admin"]);
        assert!(EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate").is_ok());
    }

    #[test]
    fn scope_guard_rejects_missing_scope() {
        let auth = auth_with_scopes(&["claims:read"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "mark_duplicate")
            .expect_err("read-only token must NOT be allowed to mark_duplicate");
        // Error message should mention the required scope name so callers can
        // debug a 403 without reading the source.
        assert!(
            err.message.contains("claims:admin"),
            "error should cite the required scope; got: {}",
            err.message
        );
    }

    #[test]
    fn scope_guard_rejects_missing_auth_context() {
        let err = EpiGraphMcpFull::enforce_tool_scope(None, "query_claims")
            .expect_err("no AuthContext must yield 401-style rejection");
        assert!(
            err.message.to_lowercase().contains("auth"),
            "error should mention auth; got: {}",
            err.message
        );
    }

    #[test]
    fn scope_guard_rejects_unmapped_tool_by_default() {
        let auth = auth_with_scopes(&["claims:admin"]);
        let err = EpiGraphMcpFull::enforce_tool_scope(Some(&auth), "tool_that_does_not_exist")
            .expect_err("unmapped tool must fail closed");
        assert!(
            err.message.to_lowercase().contains("not authorized")
                || err.message.to_lowercase().contains("no scope mapping"),
            "error should indicate the tool isn't authorized; got: {}",
            err.message
        );
    }
}
