//! supersede_claim — wraps ClaimRepository::supersede.
//! NOTE: the new claim INHERITS the OLD claim's agent_id (per
//! ClaimRepository::supersede semantics). For caller-attributed
//! supersession use the REST endpoint with explicit auth.

use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::SupersedeClaimParams;
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    params: SupersedeClaimParams,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let truth = TruthValue::clamped(params.truth_value);
    let (new_id, old_id) = ClaimRepository::supersede(
        &server.pool,
        ClaimId::from_uuid(old),
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
        }))
        .map_err(internal_error)?,
    )]))
}
