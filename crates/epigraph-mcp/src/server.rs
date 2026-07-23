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
    /// The federation gateway's routing table over downstream extension MCPs.
    /// Built once in `main` (from `EPIGRAPH_MCP_EXTENSIONS`) and injected into
    /// both transport paths. When no extensions are configured this is an empty
    /// registry ([`crate::federation::FederationRegistry::empty`]) and the server
    /// behaves exactly as it did pre-federation. The plain `new`/`new_shared`
    /// constructors default to empty (mirroring the `claim_from_row` house rule
    /// of not widening a ~30-caller signature); `main` and any caller that has a
    /// registry use `new_with_federation`/`new_shared_with_federation`.
    pub(crate) federation: Arc<crate::federation::FederationRegistry>,
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

    /// Scope gate for FEDERATED tools, kept deliberately separate from
    /// [`enforce_tool_scope`](Self::enforce_tool_scope).
    ///
    /// Federated tools are NOT in the static `SCOPE_MAP` (its coverage is a
    /// compile-time invariant over kernel tools only), so the static gate would
    /// fail them closed with "no scope mapping". Instead the required scope comes
    /// from the extension's `EPIGRAPH_MCP_EXTENSIONS` config (`scope=…`), passed
    /// here as `required`. Same fail-closed shape as the static gate: no
    /// `AuthContext` (stdio, or middleware bypassed) is a hard reject, and a
    /// caller lacking the extension's scope is forbidden.
    pub fn enforce_federated_scope(
        auth: Option<&epigraph_auth::AuthContext>,
        tool_name: &str,
        required: &str,
    ) -> Result<(), McpError> {
        let Some(auth) = auth else {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Borrowed(
                    "Unauthorized: federated tools require a Bearer token (no auth context; \
                     not available over stdio)",
                ),
                data: None,
            });
        };
        if !auth.has_scope(required) {
            return Err(McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: std::borrow::Cow::Owned(format!(
                    "Forbidden: federated tool '{tool_name}' requires scope '{required}'"
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
        Self::new_with_federation(
            pool,
            signer,
            embedder,
            read_only,
            Arc::new(crate::federation::FederationRegistry::empty()),
        )
    }

    /// Like [`new`](Self::new) but with a caller-supplied federation registry.
    /// `main` uses this for the stdio path so stdio's `list_tools` surfaces the
    /// same federated tools as the HTTP path (the registry is populated at build
    /// time with the discovery service token, independent of transport).
    #[must_use]
    pub fn new_with_federation(
        pool: PgPool,
        signer: AgentSigner,
        embedder: McpEmbedder,
        read_only: bool,
        federation: Arc<crate::federation::FederationRegistry>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            signer: Arc::new(signer),
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder: Arc::new(embedder),
            read_only,
            federation,
        }
    }

    /// Create from pre-wrapped `Arc` values (for HTTP transport factory closure).
    /// Federation defaults to empty; the HTTP factory in `main` uses
    /// [`new_shared_with_federation`](Self::new_shared_with_federation) to inject
    /// the live registry per session.
    #[must_use]
    pub fn new_shared(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        embedder: Arc<McpEmbedder>,
        read_only: bool,
    ) -> Self {
        Self::new_shared_with_federation(
            pool,
            signer,
            embedder,
            read_only,
            Arc::new(crate::federation::FederationRegistry::empty()),
        )
    }

    /// Like [`new_shared`](Self::new_shared) but with a caller-supplied
    /// federation registry. The HTTP transport factory closure in `main` clones
    /// the one `Arc<FederationRegistry>` built at boot into every per-session
    /// server via this constructor.
    #[must_use]
    pub fn new_shared_with_federation(
        pool: PgPool,
        signer: Arc<AgentSigner>,
        embedder: Arc<McpEmbedder>,
        read_only: bool,
        federation: Arc<crate::federation::FederationRegistry>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            pool,
            signer,
            agent_db_id: Arc::new(Mutex::new(None)),
            embedder,
            read_only,
            federation,
        }
    }

    // ── Claims (11 tools) ──

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
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::claims::query_claims(self, params, requester).await
    }

    #[tool(
        description = "List claims that have NEVER been decomposed — claims that are neither parent (source) nor child (target) of any decomposes_to edge. These are standalone claims from non-hierarchical paths (memorize, submit_claim, legacy imports). Excludes host-telemetry claims and content <=10 chars. Ordered oldest-first. Step 1 of the 'Process undecomposed claims through decomposition pipeline' workflow; feed the returned claim_ids to the decompose_claims CLI."
    )]
    async fn query_undecomposed_claims(
        &self,
        Parameters(params): Parameters<crate::types::QueryUndecomposedClaimsParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::claims::query_undecomposed_claims(self, params, requester).await
    }

    #[tool(
        description = "Retrieve a single epistemic claim by its UUID, including full epistemic state."
    )]
    async fn get_claim(
        &self,
        Parameters(params): Parameters<GetClaimParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::claims::get_claim(self, params, requester).await
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
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        crate::tools::supersede::supersede_claim(self, params, auth).await
    }

    #[tool(
        description = "Mark a claim as a duplicate of a canonical claim WITHOUT creating a new claim. Sets supersedes+is_current=false on the duplicate; canonical untouched. Use REST endpoint POST /api/v1/claims/:id/dedup for audit-trail provenance."
    )]
    async fn mark_duplicate(
        &self,
        Parameters(params): Parameters<crate::types::MarkDuplicateParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        crate::tools::supersede::mark_duplicate(self, params, auth).await
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
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        // For HTTP callers `call_tool` copies the AuthContext into
        // `context.extensions` so admin-scope holders can bypass the
        // agent-equality ownership check. For stdio (no auth context)
        // we pass `None` and the handler falls back to agent-equality
        // against the server's own signer agent.
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        crate::tools::claims::resolve_backlog_item(self, params, auth).await
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

    // ── Alternative-set candidate finder (1 tool) ──

    #[tool(
        description = "Suggest candidate alternative_of pairs: supporters of a shared target connected by a contradicts edge that are not already linked by alternative_of. Pure suggestion — operator promotes by submitting an explicit alternative_of edge. Returns ordered candidates with score = min(BetP_A, BetP_B)."
    )]
    async fn suggest_alternative_sets(
        &self,
        Parameters(params): Parameters<
            crate::tools::alternative_sets::SuggestAlternativeSetsParams,
        >,
    ) -> Result<CallToolResult, McpError> {
        crate::tools::alternative_sets::suggest_alternative_sets(self, params).await
    }

    // ── Memory (2 tools) ──

    #[tool(
        description = "Quick-store a memory as a testimonial claim (0.6x evidence weight). For facts you want to recall later. Tags are persisted as claim labels — queryable via `query_claims_by_label`."
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
        description = "Paragraph-primary semantic search over the claim graph with batched structural context: parent paper, parent section, child atoms (with cross-paragraph bridges), sibling paragraphs, neighbor paragraphs reachable via continues_argument / atom-bridge / atom-atom-bridge, and CORROBORATES neighbors. Auto-detects centroid_dim (1536 vs 3072) by default. Set diverse=true (optional max_themes, diversity_weight) to spread results across multiple themes via submodular selection — falls back to flat ANN when the corpus has no themes yet."
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
        description = "Check whether a paper has been ingested (has a processed_by edge). Returns {already_ingested, paper_id?, doi, pipeline_version}. Useful as a quick pre-flight read before calling ingest_document_spine. Note: with node-level dedup, already_ingested=true means the spine was previously run — it does NOT mean all atoms are present. Use ingest_document_spine to discover which paragraphs are new. Read-only."
    )]
    async fn check_already_ingested(
        &self,
        Parameters(params): Parameters<CheckAlreadyIngestedParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ingestion::check_already_ingested(self, params).await
    }

    #[tool(
        description = "Phase 1 of the two-phase ingest flow. Ingests a DocumentExtraction with EMPTY atoms (e.g. output of structure_source): writes thesis + sections + paragraphs into the graph with content-hash dedup, ignores atom fields. Returns new_paragraph_paths — the paths (e.g. 'sections[0].paragraphs[1]') of paragraphs that are NEW to this ingest. Atomize only those paragraphs (LLM cost saved on already-ingested paragraphs), then call ingest_document_inline with atoms for those paths. Idempotent on paragraph content hash: re-running spine on a paper whose abstract was already ingested returns the abstract paragraphs in paragraphs_deduped and the new body paragraphs in new_paragraph_paths."
    )]
    async fn ingest_document_spine(
        &self,
        Parameters(params): Parameters<IngestDocumentSpineParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document_spine(self, params).await
    }

    #[tool(
        description = "Ingest a hierarchical DocumentExtraction passed INLINE (thesis -> sections -> paragraphs -> atoms) — same writer as `ingest_document` but the typed `extraction` is in the call, not a file path, so the full shape is self-documenting and no file write is needed (use this from MCP-only clients). Creates a paper node, claims at each level down to atoms, decomposes_to / section_follows / supports / contradicts / refines edges, evidence, traces, embeddings, and CDST mass functions for atoms. Idempotent on paragraph and atom content hashes (node-level): re-ingesting a full paper after its abstract was ingested is safe — existing nodes dedup and only new content is written. For AUTHORED records (an ELN entry, run summary, or other content with no external source to quote) omit the top-level source_text: the verbatim guard is then skipped and this is a supported SINGLE-CALL path — structure_source / ingest_document_spine are NOT required and exist only to re-verify EXTRACTED text byte-for-byte. For the two-phase flow that saves LLM atomization cost on extracted papers, use ingest_document_spine first."
    )]
    async fn ingest_document_inline(
        &self,
        Parameters(params): Parameters<IngestDocumentInlineParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::ingestion::ingest_document_inline(self, params).await
    }

    #[tool(
        description = "Deterministically structure raw markdown/plaintext into a verbatim DocumentExtraction (sections + paragraphs as byte-exact source slices, source_text + spans populated, atoms EMPTY). This is for EXTRACTED source text that must be re-verified byte-for-byte; AUTHORED records (ELN entries, run summaries) need no structuring step and can call ingest_document_inline directly with source_text omitted. Fill atoms per paragraph and resubmit via ingest_document_inline. Read-only / no DB writes."
    )]
    async fn structure_source(
        &self,
        Parameters(params): Parameters<StructureSourceParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::ingestion::structure_source(self, params).await
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

    #[tool(
        description = "Promote two existing claims into a mutually-exclusive alternative_of pair — the symmetric edge suggest_alternative_sets tells you to submit but link_epistemic/link_hierarchical cannot create. Direction-agnostic and idempotent on the unordered {claim_a, claim_b} pair (migration 042's symmetric index): re-runs return the existing edge_id with created=false. Optional target_claim_id (the shared target the two claims are rival supporters of) and rationale are validated and stored on the edge. Deliberately inert at write time — the belief effect of an alternative set flows later through CDST max-plausibility combine over the alternative_set view, not a Dempster re-wire here."
    )]
    async fn link_alternative(
        &self,
        Parameters(params): Parameters<crate::types::LinkAlternativeParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::link_alternative::link_alternative(self, params).await
    }

    #[tool(
        description = "Create a BELIEF-AFFECTING epistemic edge between two existing claims and wire it into Dempster-Shafer belief propagation. Direction is source -> target ('source RELATIONSHIP target'). Valid relationships: supports, corroborates, elaborates, generalizes, specializes (these STRENGTHEN the target's belief), contradicts, refutes (these WEAKEN it). On first creation, builds a mass function from the source claim's belief interval and recomputes the target claim's combined belief, then emits an edge.added event; the response reports was_created, belief_wired, and the target's resulting {belief, plausibility, pignistic_prob}. Idempotent on (source, target, relationship): a re-hit returns the existing edge with was_created=false and belief_wired=false (no re-wire). For supersedes use supersede_claim instead."
    )]
    async fn link_epistemic(
        &self,
        Parameters(params): Parameters<LinkEpistemicParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::link_epistemic::link_epistemic(self, params).await
    }

    // ── Paper Queries (3 tools) ──

    #[tool(description = "Look up a paper by its DOI, returning title, authors, and claims.")]
    async fn query_paper(
        &self,
        Parameters(params): Parameters<QueryPaperParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::paper_queries::query_paper(self, params, requester).await
    }

    #[tool(
        description = "Find claims backed by a specific type of evidence (observation, computation, reference, testimony, document)."
    )]
    async fn query_claims_by_evidence(
        &self,
        Parameters(params): Parameters<QueryClaimsByEvidenceParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::paper_queries::query_claims_by_evidence(self, params, requester).await
    }

    #[tool(
        description = "Find claims derived from a specific reasoning methodology (statistical, deductive, inductive, abductive, analogical)."
    )]
    async fn query_claims_by_methodology(
        &self,
        Parameters(params): Parameters<QueryClaimsByMethodologyParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::paper_queries::query_claims_by_methodology(self, params, requester).await
    }

    #[tool(
        description = "Find claims by label using PostgreSQL array containment (GIN-indexed). Returns claims containing ALL specified labels. Useful for querying backlog items (e.g. [\"backlog\", \"pending\"]), workflows, or any labeled claim set."
    )]
    async fn query_claims_by_label(
        &self,
        Parameters(params): Parameters<QueryClaimsByLabelParams>,
        extensions: rmcp::model::Extensions,
    ) -> Result<CallToolResult, McpError> {
        let auth = extensions.get::<epigraph_auth::AuthContext>();
        let server_agent = self.agent_id().await?;
        let requester = crate::tools::redaction::mcp_requester(auth, server_agent);
        tools::paper_queries::query_claims_by_label(self, params, requester).await
    }

    #[tool(
        description = "Recompute cached claim beliefs (Bel/Pl/BetP/conflict) from current mass_functions state, per-frame, in deterministic frame-name order. The in-server sibling of the epigraph-recompute-belief CLI. Target by `claim_ids` (explicit), `labels` (e.g. a paper's claim set), or neither (bulk over all claims with BBAs, bounded by `limit`). Use after ingest or after editing calibration.toml / per-frame overrides so the cached scalars catch up to the combine path."
    )]
    async fn recompute_beliefs(
        &self,
        Parameters(params): Parameters<RecomputeBeliefsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::cdst_maintenance::recompute_beliefs(self, params).await
    }

    // ── Workflows (8 tools) ──

    #[tool(
        description = "Store a new workflow with ordered steps and prerequisites. Returns a workflow_id from the hierarchical `workflows` table; use `report_workflow_outcome` with that returned id to record execution results."
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
        description = "List a workflow's most recent behavioral executions, newest first: per-run success, quality, tool_pattern, deviation_count and step_beliefs (per-step deviation_reason), plus a window success-rate. Read-only telemetry for analysing or evolving a workflow."
    )]
    async fn get_workflow_executions(
        &self,
        Parameters(params): Parameters<GetWorkflowExecutionsParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::workflows::get_workflow_executions(self, params).await
    }

    #[tool(
        description = "Evaluate whether a workflow variant is statistically ready to be promoted over its immediate (variant_of) parent: the Wilson lower bound of the variant's behavioral success rate vs the parent's rate, over the same window, gated on a minimum sample. Read-only — returns a verdict, does not promote."
    )]
    async fn evaluate_workflow_promotion(
        &self,
        Parameters(params): Parameters<EvaluateWorkflowPromotionParams>,
    ) -> Result<CallToolResult, McpError> {
        tools::workflows::evaluate_workflow_promotion(self, params).await
    }

    #[tool(
        description = "Re-evaluate a workflow variant's promotion verdict and write it to the variant's properties.promotion, overwriting any prior value (so a regressed variant is demoted, not left stale). The apply layer of the workflow-evolution gate; the maintenance pass calls this per candidate variant. Write."
    )]
    async fn refresh_workflow_promotion(
        &self,
        Parameters(params): Parameters<EvaluateWorkflowPromotionParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::workflows::refresh_workflow_promotion(self, params).await
    }

    #[tool(
        description = "Record what actually happened when you used a workflow. Accepts workflow_id values returned by `store_workflow` (rows in `workflows`) and delegates to the hierarchical outcome path; legacy flat workflow claim IDs are still supported for backward compatibility."
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
        description = "Record an outcome for a hierarchical workflow run by workflows-table id. Updates rolling counters in workflows.metadata (use_count, success_count, failure_count, avg_variance) and writes one behavioral_executions row per step_execution with step_claim_id resolved from the workflow's `executes` edges in plan order. `report_workflow_outcome` is the compatibility entry point for callers that may have either store_workflow ids or legacy flat workflow claim ids."
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

    #[tool(
        description = "Set a perspective's source-reliability map (evidence-type tag -> alpha in [0,1]) — the frame-function lens read by scoped_belief / get_perspective_belief, so two observers weight the same evidence differently. An empty map clears the override."
    )]
    async fn set_source_reliability(
        &self,
        Parameters(params): Parameters<SetSourceReliabilityParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        tools::perspectives::set_source_reliability(self, params).await
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

    // ── Embeddings (2 tools) ──

    #[tool(
        description = "Aggregate claim count + similarity stats for the embedding ball around a free-text query. Mirrors POST /api/v1/embeddings/neighborhood-density. Returns n_claims, mean/median cosine similarity, a squashed sparsity score, and breakdowns by level + source_type. Defaults: radius=0.30 (cosine distance), max_sample=500 (clamped to [1, 5000]). Use this to detect dense regions that warrant theme sub-splitting and to drive the nightly theme-maintenance workflow."
    )]
    async fn embedding_neighborhood_density(
        &self,
        Parameters(params): Parameters<
            crate::tools::embeddings::EmbeddingNeighborhoodDensityParams,
        >,
    ) -> Result<CallToolResult, McpError> {
        crate::tools::embeddings::embedding_neighborhood_density(self, params).await
    }

    #[tool(
        description = "Generate and store the missing claims.embedding vector for current, non-telemetry claims that lack one (the is_current AND embedding IS NULL gap the CLAUDE.md embedding-policy invariant tracks). Server-side, MCP-executable counterpart to the embed_backfill CLI: the embed stage of the decomposition-cycle's decompose→embed→cross-source-match pipeline. Selection is oldest-first so repeated runs drain the backlog monotonically. Params: limit (default 200, clamped 1..=2000), dry_run (default false — count candidates without writing; safe with no OpenAI key). Returns {candidates, embedded, failed, dry_run}. Errors if the server has no OPENAI_API_KEY and dry_run is false. Requires claims:write."
    )]
    async fn backfill_embeddings(
        &self,
        Parameters(params): Parameters<crate::tools::embeddings::BackfillEmbeddingsParams>,
    ) -> Result<CallToolResult, McpError> {
        self.reject_if_read_only()?;
        crate::tools::embeddings::backfill_embeddings(self, params).await
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
        description = "Query RDF-style triples extracted from claims. Filter by subject entity, predicate pattern, and/or object entity. All filters optional (omit to wildcard). Optional min_confidence threshold (default 0.0, no filtering). Returns triples with source claim references."
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
        description = "List all MCP tools available on this server. Returns the name, description, and full JSON Schema for every registered tool — including tools your client may have DEFERRED (name visible but schema not loaded). Use this for runtime tool discovery and to load the schema of any tool your client could not call directly. The list reflects the live server state, including newly deployed tools not yet stored in the knowledge graph."
    )]
    async fn list_mcp_tools(&self) -> Result<CallToolResult, McpError> {
        // Kernel tools + every federated tool the gateway advertises, matching
        // `ServerHandler::list_tools`. `server_instructions` directs clients here
        // to enumerate every tool with its schema, so the federated tools must be
        // present or a deferred-schema client following that guidance would never
        // discover them.
        let mut tools = self.tool_router.list_all();
        tools.extend(self.federation.list_federated_tools());
        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&tools).map_err(crate::errors::internal_error)?,
        )]))
    }
}

impl EpiGraphMcpFull {
    /// Build the `instructions` string surfaced in the MCP `initialize`
    /// payload (`ServerInfo.instructions`).
    ///
    /// This is the ALWAYS-shown, never-deferred handshake text — clients
    /// (including the claude.ai web connector) render it verbatim before
    /// any `tools/list` page-in. We therefore use it to advertise the
    /// deferred-tool / tool-search gate: many clients list a tool's *name*
    /// but defer its *schema*, so a direct call fails with "not loaded
    /// yet / call tool-search first". That is client-side deferral, NOT a
    /// missing server tool — `tools/list` returns every registered tool.
    ///
    /// `tool_count` is derived from the live tool router (`all_tools_json`),
    /// so it can never drift from the registered tool set the way a
    /// hardcoded constant would.
    #[must_use]
    pub fn server_instructions(read_only: bool) -> String {
        let mode = if read_only { "read-only" } else { "full" };
        let tool_count = Self::all_tools_json().as_array().map_or(0, Vec::len);
        format!(
            "EpiGraph {mode} MCP server with {tool_count} epistemic tools. \
             Many EpiGraph tools are DEFERRED by your client — their names may appear but \
             their schemas are not loaded, so a direct call can fail with \
             \"not loaded yet / call tool-search first\". This is NOT a missing tool. \
             Use your client's tool-search mechanism (e.g. tool_search / ToolSearch) to load \
             a tool's schema by name before calling it (the edge-writers submit_claim, \
             link_hierarchical, supersede_claim and the graph reads get_neighborhood, traverse, \
             query_claims are all available this way), or call list_mcp_tools to enumerate every \
             tool with its full schema."
        )
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
        ServerInfo {
            instructions: Some(Self::server_instructions(self.read_only)),
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
        let is_http_call;
        let auth_owned: Option<epigraph_auth::AuthContext>;
        // The verbatim caller bearer, present only on the HTTP path (stashed by
        // `auth::bearer_auth_middleware`). Needed to forward to a downstream
        // extension MCP on a federated call.
        let raw_token: Option<String>;
        {
            let http_parts = context.extensions.get::<Parts>();
            is_http_call = http_parts.is_some();
            // Clone the AuthContext out of the borrow so we can both
            // (a) run scope enforcement and (b) reassign `context`
            // below to insert it into rmcp's extensions map.
            auth_owned = http_parts
                .and_then(|p| p.extensions.get::<epigraph_auth::AuthContext>())
                .cloned();
            raw_token = http_parts
                .and_then(|p| p.extensions.get::<crate::auth::RawBearerToken>())
                .map(|t| t.0.clone());
        }

        // FEDERATION BRANCH — only for names the static tool router does NOT own.
        // Must intercept BEFORE the static scope gate below: that gate fails
        // closed for any name absent from `SCOPE_MAP`, and federated tools are
        // deliberately not in `SCOPE_MAP`. Kept outside the `is_http_call` guard
        // so a stdio federated call reaches `enforce_federated_scope` and fails
        // closed there (no `AuthContext`) rather than falling through to a bare
        // "unknown tool" from the router. A genuinely-unknown name (neither
        // static nor federated) still falls through to the static path and its
        // fail-closed gate, exactly as before.
        if self.tool_router.get(&request.name).is_none() {
            if let Some(ext) = self.federation.route(&request.name) {
                let ext_name = ext.name.clone();
                let ext_scope = ext.scope.clone();
                // (a) enforce the extension's configured scope against the caller.
                if let Err(err) =
                    Self::enforce_federated_scope(auth_owned.as_ref(), &request.name, &ext_scope)
                {
                    self.emit_tool_invoked(&format!("denied:{}:{}", ext_name, request.name))
                        .await;
                    return Err(err);
                }
                // (b) require the caller's raw bearer to forward downstream.
                let Some(token) = raw_token else {
                    return Err(McpError {
                        code: rmcp::model::ErrorCode::INVALID_REQUEST,
                        message: std::borrow::Cow::Borrowed(
                            "Unauthorized: no Bearer token to forward to the downstream \
                             extension (federated tools are unavailable over stdio)",
                        ),
                        data: None,
                    });
                };
                // (c) durable audit event, namespaced by the owning extension.
                self.emit_tool_invoked(&format!("{}:{}", ext_name, request.name))
                    .await;
                // (d) proxy to the downstream on a fresh caller-token session.
                // `McpError` IS `rmcp::ErrorData`, so `internal_error` yields the
                // handler's error type directly (no further conversion).
                return self
                    .federation
                    .invoke(&request.name, &token, request.arguments)
                    .await
                    .map_err(crate::errors::internal_error);
            }
        }

        if is_http_call {
            if let Err(err) = Self::enforce_tool_scope(auth_owned.as_ref(), &request.name) {
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

        // Propagate the HTTP-side `AuthContext` (set by
        // `auth::bearer_auth_middleware` and forwarded by
        // `StreamableHttpService` through `http::request::Parts`) into
        // rmcp's `RequestContext::extensions` so per-tool handlers can
        // pull it out via the `rmcp::model::Extensions` extractor and
        // run per-row ownership checks (e.g. `resolve_backlog_item`'s
        // owner-or-`claims:admin` gate). For stdio transport there is
        // no `Parts` and no auth to copy; handlers see an empty
        // extensions map and fall back to coarse, signer-agent-based
        // checks.
        let mut context = context;
        if let Some(auth) = auth_owned {
            context.extensions.insert(auth);
        }

        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        // Kernel tools first, then every federated tool the gateway currently
        // advertises. Static-first mirrors `call_tool`'s resolution order: a
        // kernel tool always wins a name clash (the operator resolves clashes
        // between an extension and the kernel with a `prefix=`).
        let mut tools = self.tool_router.list_all();
        tools.extend(self.federation.list_federated_tools());
        Ok(rmcp::model::ListToolsResult {
            tools,
            meta: None,
            next_cursor: None,
        })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        // Static router first (kernel tools win name clashes, as in call_tool),
        // then fall back to a federated tool from the routing map.
        self.tool_router.get(name).cloned().or_else(|| {
            self.federation
                .list_federated_tools()
                .into_iter()
                .find(|t| t.name.as_ref() == name)
        })
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

#[cfg(test)]
mod instructions_tests {
    use super::*;

    /// The `initialize` instructions are the only EpiGraph text a client (incl.
    /// the claude.ai web connector) is GUARANTEED to render before any tool
    /// schema is paged in. This guards that the deferred-tool / tool-search
    /// gate guidance is present there, so an agent that sees a tool name but no
    /// schema knows how to load it (rather than reporting the tool "missing").
    ///
    /// No DB: `server_instructions` is a pure function of `read_only` + the
    /// static tool router, so it exercises the real production code path.
    #[test]
    fn instructions_advertise_the_tool_search_gate() {
        let s = EpiGraphMcpFull::server_instructions(false);

        // The gate must name a tool-search mechanism the client can act on.
        assert!(
            s.contains("tool_search") || s.contains("tool-search"),
            "instructions must point at the tool-search gate; got: {s}"
        );
        // ...and the always-available enumerate-every-schema escape hatch.
        assert!(
            s.contains("list_mcp_tools"),
            "instructions must mention list_mcp_tools as the schema-enumeration fallback; got: {s}"
        );
        // It must frame deferral as client-side, NOT a missing server tool —
        // that framing is the whole point (an agent reported tools "absent").
        assert!(
            s.contains("DEFERRED"),
            "instructions must explain tools are DEFERRED (not missing); got: {s}"
        );
    }

    /// The tool count in the instructions must equal the LIVE registered tool
    /// count, computed dynamically here (never a hardcoded literal) — that is
    /// exactly what stops it going stale. If a tool is added/removed and this
    /// substring stops matching, the production string is wrong.
    #[test]
    fn instructions_tool_count_matches_live_router() {
        let n = EpiGraphMcpFull::tool_router().list_all().len();
        let s = EpiGraphMcpFull::server_instructions(false);
        assert!(
            s.contains(&format!("{n} epistemic tools")),
            "instructions must report the live tool count ({n}); got: {s}"
        );
    }

    /// `read_only` only changes the human-readable mode label, not the
    /// registered tool set (read-only is enforced at call time, not
    /// registration), so the count is identical across modes.
    #[test]
    fn instructions_reflect_mode_label() {
        assert!(EpiGraphMcpFull::server_instructions(true).contains("read-only"));
        assert!(EpiGraphMcpFull::server_instructions(false).contains("full"));
    }
}
