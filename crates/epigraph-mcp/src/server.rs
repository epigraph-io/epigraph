#![allow(clippy::doc_markdown)]
#![allow(clippy::wildcard_imports)]

use std::sync::Arc;

use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{tool, tool_handler, tool_router, ServerHandler};
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

    // ── Ingestion (2 tools) ──

    #[tool(
        description = "Ingest a research paper from a claims JSON file (EpiGraph pipeline format). Creates claims, evidence, authors, and relationship edges."
    )]
    async fn ingest_paper(
        &self,
        Parameters(params): Parameters<IngestPaperParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_paper(self, params).await
    }

    #[tool(
        description = "Extract and ingest a paper from an arXiv ID, DOI, or local PDF path. Runs the extraction pipeline, then ingests."
    )]
    async fn ingest_paper_url(
        &self,
        Parameters(params): Parameters<IngestPaperUrlParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_paper_url(self, params).await
    }

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
        description = "Create a mutated variant of an existing workflow, linking it as a child in the lineage."
    )]
    async fn improve_workflow(
        &self,
        Parameters(params): Parameters<ImproveWorkflowParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflows::improve_workflow(self, params).await
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
}

#[tool_handler]
impl ServerHandler for EpiGraphMcpFull {
    fn get_info(&self) -> ServerInfo {
        let mode = if self.read_only { "read-only" } else { "full" };
        let tool_count = if self.read_only { 23 } else { 43 };
        ServerInfo {
            instructions: Some(format!(
                "EpiGraph {mode} MCP server with {tool_count} epistemic tools."
            )),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}
