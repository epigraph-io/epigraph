//! HTTP twins of MCP read tools that had no `/api/v1` route (backlog
//! fff61b9e; the Explorer spec, 2026-09-15, section 8.2):
//!
//! | route | MCP tool |
//! |---|---|
//! | `POST /api/v1/ingest/structure-source` | `structure_source` |
//! | `GET /api/v1/ingest/already-ingested?doi=&pipeline_version=` | `check_already_ingested` |
//! | `GET /api/v1/claims/undecomposed?limit=&offset=` | `query_undecomposed_claims` |
//! | `GET /api/v1/claims/:id/verify` | `verify_claim` |
//! | `GET /api/v1/alternative-sets/suggestions?target_claim_id=&min_pair_strength=&exclude_settled=&surface_reconsiderations=` | `suggest_alternative_sets` |
//!
//! # One implementation, two surfaces
//!
//! Each handler calls the SAME function its tool calls (`epigraph_mcp`'s
//! `structure_source_extraction`, `check_already_ingested_on`,
//! `undecomposed_claims_page`, `verify_claim_report`,
//! `suggest_alternative_sets_on`), deserializes the request into the tool's
//! own parameter type and serializes the tool's own response type. A field
//! added on one side is therefore on the other, and the answer cannot drift
//! the way `recall` and `/search/semantic` did (spec section 8.3).
//!
//! Each read runs on ONE connection stamped with the caller's viewer
//! (`routes::open_scoped_read`), as the tool's runs on
//! `EpiGraphMcpFull::read_as`, and each handler requires the scope the tool's
//! `epigraph_mcp::scope_map` entry names (`claims:read` for all five, pinned by
//! a unit test below), checked before anything is read.
//!
//! # Errors
//!
//! A tool error maps by its JSON-RPC code (`epigraph_mcp::errors::http_class`):
//! `invalid_params` is a 400 carrying the tool's message verbatim,
//! `invalid_request` (a denial) a 403, anything else a 500 whose detail stays
//! in the server log. One deliberate difference: `verify_claim` reports a
//! claim the caller cannot read (or that does not exist) as `invalid_params`
//! "not found"; the route answers 404, the same for both cases.
//!
//! The module is `#[cfg(feature = "db")]` as a whole and registered only in
//! the db router, so it needs no `cfg(not(db))` stub.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};

use crate::errors::ApiError;
use crate::middleware::bearer::{AuthContext, ViewerExtractor};
use crate::state::AppState;
use epigraph_ingest::document::schema::DocumentExtraction;
use epigraph_mcp::errors::{http_class, HttpClass, McpError};
use epigraph_mcp::tools::alternative_sets::{
    SuggestAlternativeSetsParams, SuggestAlternativeSetsResponse,
};
use epigraph_mcp::types::{
    CheckAlreadyIngestedParams, CheckAlreadyIngestedResponse, QueryUndecomposedClaimsParams,
    StructureSourceParams, UndecomposedClaimResponse, VerifyResponse,
};

/// Every twin here: its route, and the MCP tool it answers for. Each tool's
/// `scope_map` entry must be `claims:read`, the scope
/// [`require_claims_read`] checks (unit test
/// `every_twin_requires_its_tools_scope`).
pub const TWINS: &[(&str, &str)] = &[
    ("POST /api/v1/ingest/structure-source", "structure_source"),
    (
        "GET /api/v1/ingest/already-ingested",
        "check_already_ingested",
    ),
    (
        "GET /api/v1/claims/undecomposed",
        "query_undecomposed_claims",
    ),
    ("GET /api/v1/claims/:id/verify", "verify_claim"),
    (
        "GET /api/v1/alternative-sets/suggestions",
        "suggest_alternative_sets",
    ),
];

/// The scope every twin requires: its tool's (`epigraph_mcp::scope_map`).
fn require_claims_read(
    auth_ctx: Option<Extension<AuthContext>>,
    handler: &str,
) -> Result<(), ApiError> {
    let auth = auth_ctx
        .ok_or_else(|| ApiError::Unauthorized {
            reason: format!("{handler} requires authentication"),
        })?
        .0;
    crate::middleware::scopes::check_scopes(&auth, &["claims:read"])
}

/// A tool error, answered over HTTP by its JSON-RPC code.
fn from_tool(e: McpError) -> ApiError {
    let class = http_class(&e);
    let message = e.message.into_owned();
    match class {
        HttpClass::BadRequest => ApiError::BadRequest { message },
        HttpClass::Forbidden => ApiError::Forbidden { reason: message },
        // Logged by `ApiError`'s responder; the body is a fixed literal.
        HttpClass::Internal => ApiError::InternalError { message },
    }
}

/// `POST /api/v1/ingest/structure-source`: MCP `structure_source`. Pure
/// computation over the body; nothing is read or written.
pub async fn structure_source(
    auth_ctx: Option<Extension<AuthContext>>,
    Json(params): Json<StructureSourceParams>,
) -> Result<Json<DocumentExtraction>, ApiError> {
    require_claims_read(auth_ctx, "structure_source")?;
    epigraph_mcp::tools::ingestion::structure_source_extraction(params)
        .map(Json)
        .map_err(from_tool)
}

/// `GET /api/v1/ingest/already-ingested`: MCP `check_already_ingested`.
pub async fn check_already_ingested(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    Query(params): Query<CheckAlreadyIngestedParams>,
) -> Result<Json<CheckAlreadyIngestedResponse>, ApiError> {
    require_claims_read(auth_ctx, "check_already_ingested")?;
    // Refused before a connection is taken, as the tool refuses it.
    epigraph_mcp::tools::ingestion::refuse_placeholder_document_key(&params.doi)
        .map_err(from_tool)?;
    let mut read = super::open_scoped_read(&state, &viewer, "check_already_ingested").await?;
    let answer =
        epigraph_mcp::tools::ingestion::check_already_ingested_on(&mut read, &viewer, params)
            .await
            .map_err(from_tool)?;
    super::finish_scoped_read(read, "check_already_ingested").await?;
    Ok(Json(answer))
}

/// `GET /api/v1/claims/undecomposed`: MCP `query_undecomposed_claims`.
pub async fn query_undecomposed_claims(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    Query(params): Query<QueryUndecomposedClaimsParams>,
) -> Result<Json<Vec<UndecomposedClaimResponse>>, ApiError> {
    require_claims_read(auth_ctx, "query_undecomposed_claims")?;
    let mut read = super::open_scoped_read(&state, &viewer, "query_undecomposed_claims").await?;
    let page = epigraph_mcp::tools::claims::undecomposed_claims_page(&mut read, &viewer, params)
        .await
        .map_err(from_tool)?;
    super::finish_scoped_read(read, "query_undecomposed_claims").await?;
    Ok(Json(page))
}

/// `GET /api/v1/claims/:id/verify`: MCP `verify_claim`.
///
/// The id is taken as text and parsed the way the tool parses it, so a
/// malformed one is the tool's `invalid UUID` 400 rather than axum's
/// plain-text rejection. A claim the caller may not read is a 404, exactly as
/// one that does not exist.
pub async fn verify_claim(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    Path(claim_id): Path<String>,
) -> Result<Json<VerifyResponse>, ApiError> {
    require_claims_read(auth_ctx, "verify_claim")?;
    let id = epigraph_mcp::errors::parse_uuid(&claim_id).map_err(from_tool)?;
    let mut read = super::open_scoped_read(&state, &viewer, "verify_claim").await?;
    let report = epigraph_mcp::tools::claims::verify_claim_report(&mut read, &viewer, id)
        .await
        .map_err(from_tool)?;
    super::finish_scoped_read(read, "verify_claim").await?;
    report.map(Json).ok_or_else(|| ApiError::NotFound {
        entity: "Claim".to_string(),
        id: id.to_string(),
    })
}

/// `GET /api/v1/alternative-sets/suggestions`: MCP `suggest_alternative_sets`.
pub async fn suggest_alternative_sets(
    ViewerExtractor(viewer): ViewerExtractor,
    State(state): State<AppState>,
    auth_ctx: Option<Extension<AuthContext>>,
    Query(params): Query<SuggestAlternativeSetsParams>,
) -> Result<Json<SuggestAlternativeSetsResponse>, ApiError> {
    require_claims_read(auth_ctx, "suggest_alternative_sets")?;
    let mut read = super::open_scoped_read(&state, &viewer, "suggest_alternative_sets").await?;
    let answer = epigraph_mcp::tools::alternative_sets::suggest_alternative_sets_on(
        &mut read, &viewer, &params,
    )
    .await
    .map_err(from_tool)?;
    super::finish_scoped_read(read, "suggest_alternative_sets").await?;
    Ok(Json(answer))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A twin requires exactly its tool's scope. `require_claims_read` checks
    /// `claims:read`; a tool whose `scope_map` entry moves fails here rather
    /// than leaving its HTTP twin weaker or stronger than it.
    #[test]
    fn every_twin_requires_its_tools_scope() {
        for (route, tool) in TWINS {
            assert_eq!(
                epigraph_mcp::scope_map::required_scope(tool),
                Some("claims:read"),
                "{route} answers for `{tool}` and checks claims:read"
            );
        }
    }

    /// A tool's refusal keeps its class and its text over HTTP.
    #[test]
    fn a_tool_error_maps_by_its_code() {
        match from_tool(epigraph_mcp::errors::invalid_params("bad key")) {
            ApiError::BadRequest { message } => assert_eq!(message, "bad key"),
            other => panic!("invalid_params must be a 400, got {other:?}"),
        }
        match from_tool(epigraph_mcp::errors::claim_not_writer(
            uuid::Uuid::nil(),
            "supersede",
        )) {
            ApiError::Forbidden { .. } => {}
            other => panic!("a denial must be a 403, got {other:?}"),
        }
        match from_tool(epigraph_mcp::errors::internal_error_text("boom")) {
            ApiError::InternalError { .. } => {}
            other => panic!("a fault must be a 500, got {other:?}"),
        }
    }
}
