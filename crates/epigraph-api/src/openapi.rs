//! OpenAPI specification for the EpiGraph API
//!
//! Generates a complete OpenAPI 3.1 specification for the EpiGraph REST API.
//! The spec is available at `GET /api/v1/openapi.json` and describes all
//! endpoints, request/response schemas, and security requirements.

// Path stub functions are consumed by #[utoipa::path] for spec generation only
#![allow(dead_code)]

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{self};
use utoipa::{Modify, OpenApi};

use crate::routes::admin::{
    CacheStats, ChallengeStats, ConfigSummary, EventBusStats, PropagationStats, SecurityStats,
    SystemStats, WebhookStats,
};
use crate::routes::challenge::{ChallengeResponse, SubmitChallengeRequest};
use crate::routes::claims::{
    ClaimResponse, PatchClaimRequest, UpdateLabelsRequest, UpdateLabelsResponse,
};
use crate::routes::edges::{LinkHierarchicalRequest, LinkHierarchicalResponse};
use crate::routes::health::HealthResponse;
use crate::routes::rag::{RagContextResponse, RagContextResult, RagQueryParams};
use crate::routes::submit::{
    ClaimSubmission, EpistemicPacket, EvidenceSubmission, EvidenceTypeSubmission,
    MethodologySubmission, ReasoningTraceSubmission, SubmitPacketResponse, TraceInputSubmission,
};
use crate::routes::versioning::{
    DedupRequest, DedupResponse, SupersedeRequest, SupersessionResponse,
};
use crate::routes::workflows::{
    EvolveStepRequest, EvolveStepResponse, HierarchicalSearchResponse, HierarchicalWorkflowResult,
    LineageHeadResult, ReportOutcomeRequest, ResolvedStepResult, StepExecution,
};
use epigraph_ingest::common::schema::{AuthorEntry, ClaimRelationship, ThesisDerivation};
use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowExtraction, WorkflowSource};

/// EpiGraph API OpenAPI specification
///
/// Defines all endpoints, schemas, and security requirements for the
/// epistemic knowledge graph REST API.
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
        patch_claim_doc,
        update_labels_doc,
        evolve_step_doc,
        find_workflow_hierarchical_doc,
        report_hierarchical_outcome_doc,
        deprecate_workflow_doc,
        ingest_workflow_doc,
        create_hierarchical_edge_doc,
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
            PatchClaimRequest,
            ClaimResponse,
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
    )
)]
pub struct ApiDoc;

/// Security scheme modifier for Ed25519 signature authentication
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
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
/// Returns service status, version, and current timestamp.
/// Used for monitoring and load balancer health checks.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
    )
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
    )
)]
async fn rag_context() {}

/// System statistics
///
/// Returns comprehensive system health and operational metrics
/// from all major subsystems.
#[utoipa::path(
    get,
    path = "/api/v1/admin/stats",
    tag = "admin",
    responses(
        (status = 200, description = "System statistics snapshot", body = SystemStats),
    )
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
        (status = 404, description = "Claim not found", body = ErrorResponse),
    )
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
        (status = 404),
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
        ("resolve_to_latest" = Option<bool>, Query, description = "Whether to resolve steps to latest versions"),
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

    #[test]
    fn openapi_spec_version_matches_crate() {
        let spec = openapi_spec();
        assert_eq!(spec.info.version, env!("CARGO_PKG_VERSION"));
    }
}
