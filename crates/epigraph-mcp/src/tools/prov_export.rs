//! MCP `export_provenance_prov_o`: the PROV-O JSON-LD export of one claim's
//! provenance (backlog `4ba388eb`), the agent-callable twin of the
//! `export_provenance` operator CLI.
//!
//! Both call `epigraph_engine::export::prov::export_provenance_prov_o`; this
//! one runs it on the CALLER's viewer-stamped read, so the export holds the
//! claims this caller may read and nothing else: a member's own group-private
//! ancestors are in it, a stranger's are absent (not redacted, and their ids
//! are printed nowhere in the document).

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::ExportProvenanceProvOParams;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;

/// Default ancestor depth: `get_provenance`'s, so the two provenance reads
/// walk the same distance unless asked otherwise.
const DEFAULT_MAX_DEPTH: i32 = 5;
/// Ceiling on `max_depth`, as `get_provenance`'s: the export carries every
/// ancestor's full content, so an unbounded walk is an unbounded response.
const MAX_MAX_DEPTH: i32 = 20;

/// `max_depth` defaulted and clamped to `1..=MAX_MAX_DEPTH`.
fn effective_depth(requested: Option<i32>) -> i32 {
    requested
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(1, MAX_MAX_DEPTH)
}

pub async fn export_provenance_prov_o(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ExportProvenanceProvOParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let depth = effective_depth(params.max_depth);

    let mut read = server.read_as(viewer, "export_provenance_prov_o").await?;
    // The root first, with `get_claim`'s refusal: a claim this caller cannot
    // read and a uuid that names nothing give the same error, and no export
    // (not even an empty one naming the id) is produced for either.
    if ClaimRepository::get_by_id(&mut *read, viewer, ClaimId::from_uuid(id))
        .await
        .map_err(internal_error)?
        .is_none()
    {
        return Err(invalid_params(format!("claim {id} not found")));
    }
    let document =
        epigraph_engine::export::prov::export_provenance_prov_o(&mut read, viewer, id, Some(depth))
            .await
            .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&document).map_err(internal_error)?,
    )]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_defaults_to_five_and_is_clamped() {
        assert_eq!(effective_depth(None), 5);
        assert_eq!(effective_depth(Some(0)), 1);
        assert_eq!(effective_depth(Some(-3)), 1);
        assert_eq!(effective_depth(Some(7)), 7);
        assert_eq!(effective_depth(Some(10_000)), 20);
    }
}
