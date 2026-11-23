//! OpenAPI specification for the EpiGraph API
//!
//! Generates an OpenAPI 3.1 document for the EpiGraph REST API, served at
//! `GET /api/v1/openapi.json`.
//!
//! **The document is PARTIAL.** It describes the 20 operations listed in
//! `ApiDoc`'s `paths(...)` below (health, packet submit, RAG query, admin
//! stats, challenges, supersede / dedup / undedup, claim get / patch / labels,
//! agent search, five workflow routes, the hierarchical edge create and the
//! authorship countersign), with
//! their schemas and the bearer security scheme. The router in
//! `routes/mod.rs` registers well over two hundred routes; the rest are not
//! described here, and no test ties this list to the route table. Each entry
//! is a stub function in this file carrying `#[utoipa::path]`, so a described
//! operation is not checked against its real handler either.

// Path stub functions are consumed by #[utoipa::path] for spec generation only
#![allow(dead_code)]

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::{self};
use utoipa::{Modify, OpenApi};

use crate::routes::admin::{
    CacheStats, ChallengeStats, ConfigSummary, EventBusStats, PropagationStats, SecurityStats,
    SystemStats, WebhookStats,
};
use crate::routes::challenge::{ChallengeResponse, SubmitChallengeRequest};
use crate::routes::claims::{
    AuthorRefView, AuthoredByView, ClaimResponse, FilerView, IngesterView, PaperAuthorView,
    PaperAuthorshipView, PaperRefView, PatchClaimRequest, PromptSnapshotView, UpdateLabelsRequest,
    UpdateLabelsResponse,
};
use crate::routes::countersign::{
    CountersignAuthorshipRequest, CountersignAuthorshipResponse, CountersignedRowView,
};
use crate::routes::edges::{LinkHierarchicalRequest, LinkHierarchicalResponse};
use crate::routes::health::HealthResponse;
use crate::routes::rag::{RagContextResponse, RagContextResult, RagQueryParams};
use crate::routes::submit::{
    ClaimSubmission, EpistemicPacket, EvidenceSubmission, EvidenceTypeSubmission,
    MethodologySubmission, ReasoningTraceSubmission, SubmitPacketResponse, TraceInputSubmission,
};
use crate::routes::versioning::{
    DedupRequest, DedupResponse, SupersedeRequest, SupersessionResponse, UndedupResponse,
};
#[cfg(feature = "db")]
use crate::routes::workflows::{
    EvolveStepRequest, EvolveStepResponse, HierarchicalSearchResponse, HierarchicalWorkflowResult,
    LineageHeadResult, ReportOutcomeRequest, ResolvedStepResult, StepExecution,
};
// Without `db` the `routes::workflows` module is compiled out, but the
// `#[derive(OpenApi)]` schema list below cannot itself carry a cfg. Empty
// stand-ins keep the derive resolvable; the db build never sees them.
#[cfg(not(feature = "db"))]
mod workflow_schema_stubs {
    #[derive(utoipa::ToSchema)]
    pub struct EvolveStepRequest {}
    #[derive(utoipa::ToSchema)]
    pub struct EvolveStepResponse {}
    #[derive(utoipa::ToSchema)]
    pub struct HierarchicalSearchResponse {}
    #[derive(utoipa::ToSchema)]
    pub struct HierarchicalWorkflowResult {}
    #[derive(utoipa::ToSchema)]
    pub struct LineageHeadResult {}
    #[derive(utoipa::ToSchema)]
    pub struct ReportOutcomeRequest {}
    #[derive(utoipa::ToSchema)]
    pub struct ResolvedStepResult {}
    #[derive(utoipa::ToSchema)]
    pub struct StepExecution {}
}
use epigraph_ingest::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowExtraction, WorkflowSource};
#[cfg(not(feature = "db"))]
use workflow_schema_stubs::{
    EvolveStepRequest, EvolveStepResponse, HierarchicalSearchResponse, HierarchicalWorkflowResult,
    LineageHeadResult, ReportOutcomeRequest, ResolvedStepResult, StepExecution,
};

/// EpiGraph API OpenAPI specification
///
/// Defines the documented subset of endpoints (see the module doc: the list
/// is partial), their schemas, and the security requirements of the epistemic
/// knowledge graph REST API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "EpiGraph API",
        version = "0.1.0",
        description = "Epistemic Knowledge Graph API - A cryptographically verifiable, \
            reasoning-centric knowledge graph where truth is probabilistic and agent \
            reputation is derived solely from evidentiary accuracy.",
        license(name = "MIT", url = "https://opensource.org/licenses/MIT"),
        contact(name = "EpiGraph", url = "https://github.com/tylorsama/EpiGraphV2")
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development"),
    ),
    paths(
        health_check,
        submit_packet,
        rag_context,
        system_stats,
        submit_challenge,
        list_challenges,
        supersede_claim_doc,
        mark_duplicate_doc,
        unmark_duplicate_doc,
        get_claim_doc,
        patch_claim_doc,
        update_labels_doc,
        evolve_step_doc,
        find_workflow_hierarchical_doc,
        report_hierarchical_outcome_doc,
        deprecate_workflow_doc,
        ingest_workflow_doc,
        create_hierarchical_edge_doc,
        search_agents_doc,
        countersign_authorship_doc,
    ),
    components(
        schemas(
            HealthResponse,
            EpistemicPacket,
            SubmitPacketResponse,
            ClaimSubmission,
            EvidenceSubmission,
            EvidenceTypeSubmission,
            ReasoningTraceSubmission,
            MethodologySubmission,
            TraceInputSubmission,
            RagQueryParams,
            RagContextResponse,
            RagContextResult,
            SubmitChallengeRequest,
            ChallengeResponse,
            SystemStats,
            EventBusStats,
            PropagationStats,
            CacheStats,
            ChallengeStats,
            SecurityStats,
            WebhookStats,
            ConfigSummary,
            ErrorResponse,
            SupersedeRequest,
            SupersessionResponse,
            DedupRequest,
            DedupResponse,
            UndedupResponse,
            PatchClaimRequest,
            ClaimResponse,
            AuthoredByView,
            AuthorRefView,
            PromptSnapshotView,
            FilerView,
            IngesterView,
            PaperAuthorshipView,
            PaperRefView,
            PaperAuthorView,
            UpdateLabelsRequest,
            UpdateLabelsResponse,
            EvolveStepRequest,
            EvolveStepResponse,
            ReportOutcomeRequest,
            StepExecution,
            WorkflowExtraction,
            WorkflowSource,
            Phase,
            Step,
            AuthorEntry,
            ClaimRelationship,
            ThesisDerivation,
            HierarchicalSearchResponse,
            HierarchicalWorkflowResult,
            ResolvedStepResult,
            LineageHeadResult,
            LinkHierarchicalRequest,
            LinkHierarchicalResponse,
            CountersignAuthorshipRequest,
            CountersignAuthorshipResponse,
            CountersignedRowView,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "submit", description = "Claim and evidence submission"),
        (name = "query", description = "Query and search endpoints"),
        (name = "challenge", description = "Claim challenge endpoints"),
        (name = "admin", description = "Administrative endpoints"),
        (name = "claims", description = "Claim management endpoints"),
        (name = "workflows", description = "Workflow management endpoints"),
        (name = "edges", description = "Edge creation and management"),
        (name = "papers", description = "Papers and their authorship"),
    )
)]
pub struct ApiDoc;

/// Security scheme modifier for Ed25519 signature authentication.
///
/// Also sets the document's DEFAULT security requirement to that scheme: the
/// router serves every documented operation behind its bearer layer except
/// the anonymous ones, which say so with an explicit `security(())` (an empty
/// requirement). An operation with no `security(...)` of its own therefore
/// inherits "authentication required" rather than advertising "none".
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        openapi.security = Some(vec![SecurityRequirement::new(
            "ed25519_signature",
            Vec::<String>::new(),
        )]);
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "ed25519_signature",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("Ed25519-Signature")
                        .description(Some(
                            "Ed25519 digital signature over the request body. \
                             Protected endpoints require a valid signature from a \
                             registered agent's private key."
                                .to_string(),
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// Standard error response returned by all endpoints on failure
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    /// Error type identifier (e.g., "BadRequest", "NotFound", "Unauthorized")
    pub error: String,
    /// Human-readable error description
    pub message: String,
    /// Optional structured error details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ============================================================================
// Path definitions (manually specified since handlers are feature-gated)
// ============================================================================

/// Health check
///
/// Returns service status, version, current timestamp and `belief_modes`, the
/// belief-mode flags this process read at startup.
/// Used for monitoring and load balancer health checks.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
    ),
    // Anonymous (the public router): an explicit empty requirement, so the
    // document's default does not claim a signature here.
    security(())
)]
async fn health_check() {}

/// Submit epistemic packet
///
/// Accepts a complete epistemic packet containing a claim, supporting evidence,
/// and reasoning trace. The system calculates initial truth from evidence alone
/// (agent reputation is never a factor).
///
/// Requires Ed25519 signature authentication.
#[utoipa::path(
    post,
    path = "/api/v1/submit/packet",
    tag = "submit",
    request_body = EpistemicPacket,
    responses(
        (status = 200, description = "Packet accepted and claim created", body = SubmitPacketResponse),
        (status = 400, description = "Invalid packet (validation failed)", body = ErrorResponse),
        (status = 401, description = "Invalid or missing signature", body = ErrorResponse),
        (status = 409, description = "Duplicate submission (idempotency key match)", body = SubmitPacketResponse),
    ),
    security(
        ("ed25519_signature" = [])
    )
)]
async fn submit_packet() {}

/// RAG context retrieval
///
/// Returns high-truth claims suitable for LLM context retrieval.
/// Applies an epistemic quality gate (min_truth >= 0.7 by default)
/// to ensure only verified claims are returned.
#[utoipa::path(
    get,
    path = "/api/v1/query/rag",
    tag = "query",
    params(
        ("query" = String, Query, description = "Natural language query to find relevant claims"),
        ("limit" = Option<u32>, Query, description = "Maximum results (default: 5, max: 20)"),
        ("min_truth" = Option<f64>, Query, description = "Minimum truth value threshold (default: 0.7)"),
        ("domain" = Option<String>, Query, description = "Filter by domain: factual, hypothesis, opinion"),
    ),
    responses(
        (status = 200, description = "High-truth claims matching the query", body = RagContextResponse),
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 401, description = "Missing or invalid Bearer token"),
    ),
    security(("ed25519_signature" = []))
)]
async fn rag_context() {}

/// System statistics
///
/// Returns comprehensive system health and operational metrics
/// from all major subsystems. Requires the `claims:admin` scope.
///
/// Without the 401/403 arms below a generated client is told 200 is the only
/// outcome of a route that refuses every non-admin token, which is a false
/// contract rather than an incomplete one. Its `security(...)` names the
/// signature scheme like every authenticated operation in this document (the
/// test `every_documented_operation_declares_its_authentication` holds them to
/// the router).
#[utoipa::path(
    get,
    path = "/api/v1/admin/stats",
    tag = "admin",
    responses(
        (status = 200, description = "System statistics snapshot", body = SystemStats),
        (status = 401, description = "Missing or invalid Bearer token"),
        (status = 403, description = "Token does not carry the `claims:admin` scope"),
    ),
    security(("ed25519_signature" = []))
)]
async fn system_stats() {}

/// Submit a challenge against a claim
///
/// Allows agents to dispute existing claims with counter-evidence.
/// Challenges are a core epistemic mechanism: truth must be contestable
/// to be trustworthy.
///
/// Requires Ed25519 signature authentication.
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/challenge",
    tag = "challenge",
    params(
        ("id" = uuid::Uuid, Path, description = "The claim ID to challenge"),
    ),
    request_body = SubmitChallengeRequest,
    responses(
        (status = 201, description = "Challenge submitted successfully", body = ChallengeResponse),
        (status = 400, description = "Invalid challenge request", body = ErrorResponse),
        (status = 401, description = "Invalid or missing signature", body = ErrorResponse),
        (status = 404, description = "Claim not found", body = ErrorResponse),
    ),
    security(
        ("ed25519_signature" = [])
    )
)]
async fn submit_challenge() {}

/// List challenges for a claim
///
/// Returns all challenges submitted against a specific claim,
/// ordered by submission time (newest first).
#[utoipa::path(
    get,
    path = "/api/v1/claims/{id}/challenges",
    tag = "challenge",
    params(
        ("id" = uuid::Uuid, Path, description = "The claim ID"),
    ),
    responses(
        (status = 200, description = "List of challenges", body = Vec<ChallengeResponse>),
        (status = 401, description = "Missing or invalid Bearer token"),
        (status = 404, description = "Claim not found", body = ErrorResponse),
    ),
    security(("ed25519_signature" = []))
)]
async fn list_challenges() {}

/// Supersede an existing claim (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/supersede",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the claim to supersede")),
    request_body = SupersedeRequest,
    responses(
        (status = 201, body = SupersessionResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
    ),
    security(("ed25519_signature" = []))
)]
async fn supersede_claim_doc() {}

/// Mark a claim as a duplicate (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/dedup",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the duplicate claim")),
    request_body = DedupRequest,
    responses(
        (status = 200, body = DedupResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
    ),
    security(("ed25519_signature" = []))
)]
async fn mark_duplicate_doc() {}

/// Un-mark a duplicate (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/claims/{id}/undedup",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the marked duplicate")),
    responses(
        (status = 200, body = UndedupResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
    ),
    security(("ed25519_signature" = []))
)]
async fn unmark_duplicate_doc() {}

/// Read one claim (doc stub)
///
/// A claim the caller may not read is 404, exactly as an id with no claim.
/// The response carries `authored_by`, tagged by `source`. `agent` (no
/// readable creation record names a document): `agent` (the filer, the
/// author), `human` (the human the agent was bound to when it filed the
/// claim, read from the binding record, never from an `OPERATED_BY` edge)
/// for every reader, and `prompt_snapshot` only for the agent's linked human
/// and admins (the prompt-history gate). `literature` (the document ingest
/// recorded at creation that a document's ingest created the claim):
/// `paper` (that document and its authors: the claim's primary authors are
/// the ones its creating ingest recorded at creation, each on that ingest's
/// own authorship of the document; authors an ingester named without their
/// countersignature are listed apart under `pending_authors`, and authors a
/// later ingest of the same document that also recorded the claim added
/// under `added_authors` with `added_by`, neither ever primary; only the
/// ingests that recorded the claim contribute authors) and `ingested_by` (the
/// filer, with the same three parts). Both carry `corroborated_by` (every
/// other readable document whose ingest recorded the claim) and `ingesters`
/// (every readable ingest, each with the human its agent was bound to then).
/// A bare `asserts` edge no ingest recorded is not read. A part the caller
/// may not see is `null`, exactly as a part that does not exist.
#[utoipa::path(
    get,
    path = "/api/v1/claims/{id}",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the claim")),
    responses(
        (status = 200, body = ClaimResponse),
        (status = 401),
        (status = 403),
        (status = 404),
    ),
    security(("ed25519_signature" = []))
)]
async fn get_claim_doc() {}

/// Find agents by name (doc stub)
///
/// Case-insensitive, accent-folded name match (plus exact ORCID / ROR id where
/// the caller may see the profile), ranked `orcid`/`ror` > `exact` > `prefix` >
/// `trigram`. The body is `{results: [...], candidates_truncated}`; each result
/// is an agent card (`id`, `display_name`, `kind`, `kind_evidence`, `roles`,
/// `role_attachments`, `orcid`, `ror_id`, `operator_human`, `created_at`,
/// `counts`) plus `tier`
/// and `score`. `operator_human` (the human the agent is currently bound
/// to: its live operator link, else its unrevoked client allowance; null
/// once the link is retired) is shown to every reader; every other field is
/// computed under the caller's viewer. `counts` holds `authored_papers`
/// (papers it has an authorship of that is not awaiting its countersignature;
/// a name-derived author is never countersigned and never pending),
/// `pending_authored_papers` (papers an ingester named it on, awaiting its
/// countersignature, where it has no other authorship) and `asserted_claims`,
/// each paper and claim once. They count only in-force edges that carry the
/// document ingest's ingest-written marker, which no other writer can set (an
/// edge written over `POST /api/v1/edges` never counts, whatever its shape),
/// and an attribution only when the same principal's ingest wrote the
/// agent's counted authorship of a paper and that paper's assertion of the
/// claim: each ingest that names the agent credits it with that ingest's
/// claims, and no other ingest does.
/// Same code as MCP `find_agent`. Scope `claims:read`.
#[utoipa::path(
    get,
    path = "/api/v1/agents/search",
    tag = "agents",
    params(
        ("name" = String, Query, description = "Name, ORCID or ROR id (2-200 characters)"),
        ("kind" = Option<String>, Query, description = "human | llm_agent | system | role | ingest_author | unknown"),
        ("role" = Option<String>, Query, description = "Keep agents holding this role (role:<key> or <key>)"),
        ("limit" = Option<i64>, Query, description = "1-25, default 10"),
    ),
    responses(
        (status = 200, description = "Ranked agent cards"),
        (status = 400),
        (status = 401),
        (status = 403),
    ),
    security(("ed25519_signature" = []))
)]
async fn search_agents_doc() {}

/// Partial update of a claim (doc stub)
#[utoipa::path(
    patch,
    path = "/api/v1/claims/{id}",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the claim to patch")),
    request_body = PatchClaimRequest,
    responses(
        (status = 200, body = ClaimResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
    ),
    security(("ed25519_signature" = []))
)]
async fn patch_claim_doc() {}

/// Update labels on a claim (doc stub)
#[utoipa::path(
    patch,
    path = "/api/v1/claims/{id}/labels",
    tag = "claims",
    params(("id" = uuid::Uuid, Path, description = "UUID of the claim")),
    request_body = UpdateLabelsRequest,
    responses(
        (status = 200, body = UpdateLabelsResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
    ),
    security(("ed25519_signature" = []))
)]
async fn update_labels_doc() {}

/// Evolve a workflow step (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/workflows/steps/{id}/evolve",
    tag = "workflows",
    params(("id" = uuid::Uuid, Path, description = "UUID of the parent step claim")),
    request_body = EvolveStepRequest,
    responses(
        (status = 200, body = EvolveStepResponse),
        (status = 400),
        (status = 401),
        (status = 403),
        (status = 404),
        (status = 409),
    ),
    security(("ed25519_signature" = []))
)]
async fn evolve_step_doc() {}

/// Search hierarchical workflows (doc stub)
#[utoipa::path(
    get,
    path = "/api/v1/workflows/hierarchical/search",
    tag = "workflows",
    params(
        ("q" = String, Query, description = "Search query"),
        ("limit" = Option<i64>, Query, description = "Maximum results (default: 10, max: 50)"),
        ("resolve_to_latest" = Option<bool>, Query, description = "Whether to resolve steps to latest versions. When true, the lineage head (highest generation) of every matched canonical_name is always returned, and each entry carries is_lineage_head, lineage_head_generation and lineage_head_deprecated (the head's truth is below min_truth); a live head leads its lineage group, while a deprecated head (truth below min_truth) sorts after the live rows of its group. The result can exceed limit by one head per matched lineage."),
        ("min_truth" = Option<f64>, Query, description = "Minimum truth_value to surface (default: 0.3, so rows deprecated via deprecate_workflow at 0.05 drop out). With resolve_to_latest it also decides which lineage heads are flagged deprecated and sorted after their group's live rows."),
    ),
    responses(
        (status = 200, body = HierarchicalSearchResponse),
        (status = 500),
    ),
    security(("ed25519_signature" = []))
)]
async fn find_workflow_hierarchical_doc() {}

/// Report hierarchical workflow outcome (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/workflows/hierarchical/{id}/outcome",
    tag = "workflows",
    params(("id" = uuid::Uuid, Path, description = "UUID of the hierarchical workflow")),
    request_body = ReportOutcomeRequest,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 404),
        (status = 500),
    ),
    security(("ed25519_signature" = []))
)]
async fn report_hierarchical_outcome_doc() {}

/// Deprecate a workflow (doc stub)
#[utoipa::path(
    delete,
    path = "/api/v1/workflows/{id}",
    tag = "workflows",
    params(
        ("id" = uuid::Uuid, Path, description = "UUID of the workflow to deprecate"),
        ("reason" = String, Query, description = "Reason for deprecation"),
        ("cascade" = Option<bool>, Query, description = "Whether to cascade deprecation to descendants"),
    ),
    responses(
        (status = 200, body = serde_json::Value),
        (status = 404),
        (status = 500),
    ),
    security(("ed25519_signature" = []))
)]
async fn deprecate_workflow_doc() {}

/// Ingest a workflow extraction (doc stub)
#[utoipa::path(
    post,
    path = "/api/v1/workflows/ingest",
    tag = "workflows",
    request_body = WorkflowExtraction,
    responses(
        (status = 200, body = serde_json::Value),
        (status = 500),
    ),
    security(("ed25519_signature" = []))
)]
async fn ingest_workflow_doc() {}

/// Create a cross-tier hierarchical structural edge between two claims (doc stub).
///
/// Tight-contract sibling of the generic POST /api/v1/edges: locked to the
/// three structural relationships (`decomposes_to`, `section_follows`,
/// `continues_argument`), both endpoints must be existing claims, and
/// `(source, target, relationship)` is idempotent so per-chapter wire-ups
/// can retry safely.
#[utoipa::path(
    post,
    path = "/api/v1/edges/hierarchical",
    tag = "edges",
    request_body = LinkHierarchicalRequest,
    responses(
        (status = 200, description = "Edge created or already present", body = LinkHierarchicalResponse),
        (status = 400, description = "Invalid relationship or self-loop", body = ErrorResponse),
        (status = 401, description = "Missing or invalid token", body = ErrorResponse),
        (status = 403, description = "Token missing edges:write scope", body = ErrorResponse),
        (status = 404, description = "Source or target claim does not exist", body = ErrorResponse),
    ),
    security(("ed25519_signature" = []))
)]
async fn create_hierarchical_edge_doc() {}

/// Confirm or decline a pending authorship of a paper (doc stub)
///
/// The named person (or that agent's live operator, passing `agent_id`)
/// confirms or declines an ingester's naming of them as an author of the
/// paper. 200 with the rows changed, or with `changed: []` and a `message`
/// when nothing is pending (a repeat included; nothing written). 403 with a
/// coded reason when the definer refuses the caller (`CSG01`: no
/// authenticated principal; `CSG02`: not the named agent nor its live
/// operator), or without `claims:write`. The REST twin of MCP
/// `countersign_authorship`.
#[utoipa::path(
    post,
    path = "/api/v1/papers/{id}/authors/countersign",
    tag = "papers",
    params(("id" = uuid::Uuid, Path, description = "UUID of the paper the caller was named on")),
    request_body = CountersignAuthorshipRequest,
    responses(
        (status = 200, body = CountersignAuthorshipResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 403, body = ErrorResponse),
    ),
    security(("ed25519_signature" = []))
)]
async fn countersign_authorship_doc() {}

/// Generate the OpenAPI JSON specification.
///
/// The `version` field is overridden at runtime with `CARGO_PKG_VERSION` so it
/// always matches the crate version regardless of what string is written in the
/// `#[openapi(info(version = "..."))]` attribute (proc-macros only accept string
/// literals, not `env!()` expressions).
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    let mut spec = ApiDoc::openapi();
    spec.info.version = env!("CARGO_PKG_VERSION").to_string();
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_spec_generates_valid_json() {
        let spec = openapi_spec();
        let json = serde_json::to_string_pretty(&spec).unwrap();
        assert!(json.contains("EpiGraph API"));
        assert!(json.contains("/health"));
        assert!(json.contains("/api/v1/submit/packet"));
        assert!(json.contains("/api/v1/query/rag"));
    }

    #[test]
    fn openapi_spec_has_security_scheme() {
        let spec = openapi_spec();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("ed25519_signature"));
    }

    /// The path literals `routes/mod.rs` registers on its anonymous `public`
    /// router chains (both `create_router` variants), read from the source as
    /// `tests/public_router_allowlist.rs` reads it: axum spelling (`:id`).
    fn anonymous_router_paths() -> std::collections::BTreeSet<String> {
        let src = include_str!("routes/mod.rs");
        let mut out = std::collections::BTreeSet::new();
        let mut rest = src;
        while let Some(i) = rest.find("let public = Router::new()") {
            let chunk = &rest[i..];
            let end = chunk.find(";\n").expect("the public chain ends");
            let mut body = &chunk[..end];
            while let Some(j) = body.find(".route(") {
                body = &body[j + ".route(".len()..];
                if let Some(lit) = body.trim_start().strip_prefix('"') {
                    let k = lit.find('"').expect("closing quote");
                    out.insert(lit[..k].to_string());
                }
            }
            rest = &chunk[end..];
        }
        out
    }

    /// `/api/v1/claims/{id}` -> `/api/v1/claims/:id`.
    fn axum_path(openapi_path: &str) -> String {
        openapi_path
            .split('/')
            .map(
                |seg| match seg.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
                    Some(name) => format!(":{name}"),
                    None => seg.to_string(),
                },
            )
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Backlog d1e573ae (2): every documented operation states its
    /// authentication. One the router serves anonymously declares it (an
    /// empty requirement, `{}`); every other one requires `ed25519_signature`,
    /// on the operation or through the document's default, and admits no
    /// anonymous alternative. Before the fix four read operations carried no
    /// `security` and the document no default, so the schema advertised them
    /// as needing nothing while the router answered them 401.
    #[test]
    fn every_documented_operation_declares_its_authentication() {
        let anonymous = anonymous_router_paths();
        assert!(
            anonymous.contains("/health") && anonymous.contains("/api/v1/openapi.json"),
            "the source parse of the public router found {anonymous:?}"
        );
        let doc = serde_json::to_value(openapi_spec()).unwrap();
        let default = doc.get("security").cloned();
        let paths = doc["paths"].as_object().expect("paths");
        let mut checked = 0;
        for (path, item) in paths {
            for (method, op) in item.as_object().expect("path item") {
                if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                    continue;
                }
                checked += 1;
                let effective = op.get("security").cloned().or_else(|| default.clone());
                let reqs: Vec<serde_json::Value> = effective
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                let allows_anonymous = reqs
                    .iter()
                    .any(|r| r.as_object().is_some_and(serde_json::Map::is_empty));
                let names_scheme = reqs.iter().any(|r| r.get("ed25519_signature").is_some());
                if anonymous.contains(&axum_path(path)) {
                    assert!(
                        allows_anonymous,
                        "{method} {path} is on the anonymous router but its security \
                         {reqs:?} does not say so"
                    );
                } else {
                    assert!(
                        names_scheme && !allows_anonymous,
                        "{method} {path} requires authentication on the router but its \
                         security is {reqs:?}"
                    );
                }
            }
        }
        assert!(checked >= 19, "only {checked} operations checked");
    }

    /// Backlog 04c02296: the countersign route is described, as a POST with
    /// its typed body and the bearer scheme.
    #[test]
    fn openapi_spec_documents_the_countersign_route() {
        let doc = serde_json::to_value(openapi_spec()).unwrap();
        let op = &doc["paths"]["/api/v1/papers/{id}/authors/countersign"]["post"];
        assert!(op.is_object(), "countersign route not described");
        let body_ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap_or_default();
        assert!(
            body_ref.ends_with("/CountersignAuthorshipRequest"),
            "request body: {body_ref:?}"
        );
        let ok_ref = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap_or_default();
        assert!(
            ok_ref.ends_with("/CountersignAuthorshipResponse"),
            "200 body: {ok_ref:?}"
        );
        assert!(op["responses"]["403"].is_object());
        let schemes: Vec<&str> = op["security"]
            .as_array()
            .expect("security")
            .iter()
            .flat_map(|o| o.as_object().unwrap().keys().map(String::as_str))
            .collect();
        assert!(schemes.contains(&"ed25519_signature"), "{schemes:?}");
    }

    #[test]
    fn openapi_spec_version_matches_crate() {
        let spec = openapi_spec();
        assert_eq!(spec.info.version, env!("CARGO_PKG_VERSION"));
    }
}
