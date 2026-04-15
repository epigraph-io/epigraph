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
use crate::routes::health::HealthResponse;
use crate::routes::rag::{RagContextResponse, RagContextResult, RagQueryParams};
use crate::routes::submit::{
    ClaimSubmission, EpistemicPacket, EvidenceSubmission, EvidenceTypeSubmission,
    MethodologySubmission, ReasoningTraceSubmission, SubmitPacketResponse, TraceInputSubmission,
};

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
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "submit", description = "Claim and evidence submission"),
        (name = "query", description = "Query and search endpoints"),
        (name = "challenge", description = "Claim challenge endpoints"),
        (name = "admin", description = "Administrative endpoints"),
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
