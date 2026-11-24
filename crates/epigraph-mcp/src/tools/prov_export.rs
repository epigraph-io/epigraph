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
use epigraph_engine::export::prov::ProvExportLimits;

/// Default ancestor depth: `get_provenance`'s, so the two provenance reads
/// walk the same distance unless asked otherwise.
const DEFAULT_MAX_DEPTH: i32 = 5;
/// Ceiling on `max_depth`, as `get_provenance`'s.
const MAX_MAX_DEPTH: i32 = 20;
/// Default node cap: `get_provenance`'s. Depth alone bounds nothing on a hub
/// claim (the ancestor walk has no row cap), so the node cap is what bounds
/// the statements one call issues (about `2 * max_nodes + 2`) and, with the
/// content clip, the size of the response.
const DEFAULT_MAX_NODES: usize = 50;
/// Ceiling on `max_nodes`: about 400 statements in one read transaction.
const MAX_MAX_NODES: usize = 200;
/// Default per-claim content budget: `get_provenance`'s.
const DEFAULT_MAX_CONTENT_CHARS: usize = 500;
const MIN_MAX_CONTENT_CHARS: usize = 50;
/// Ceiling on `max_content_chars`. With [`MAX_MAX_NODES`] this bounds the
/// claim text of one response at 800k characters.
const MAX_MAX_CONTENT_CHARS: usize = 4_000;

/// `max_depth` defaulted and clamped to `1..=MAX_MAX_DEPTH`.
fn effective_depth(requested: Option<i32>) -> i32 {
    requested
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .clamp(1, MAX_MAX_DEPTH)
}

/// The node cap and content clip, defaulted and clamped. Never unbounded:
/// [`ProvExportLimits::default`] is the operator CLI's `--unbounded` opt-in,
/// never a request's.
fn effective_limits(params: &ExportProvenanceProvOParams) -> ProvExportLimits {
    ProvExportLimits {
        max_nodes: Some(
            params
                .max_nodes
                .unwrap_or(DEFAULT_MAX_NODES)
                .clamp(1, MAX_MAX_NODES),
        ),
        max_content_chars: Some(
            params
                .max_content_chars
                .unwrap_or(DEFAULT_MAX_CONTENT_CHARS)
                .clamp(MIN_MAX_CONTENT_CHARS, MAX_MAX_CONTENT_CHARS),
        ),
    }
}

pub async fn export_provenance_prov_o(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ExportProvenanceProvOParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.claim_id)?;
    let depth = effective_depth(params.max_depth);
    let limits = effective_limits(&params);

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
    let mut document = epigraph_engine::export::prov::export_provenance_prov_o(
        &mut read,
        viewer,
        id,
        Some(depth),
        limits,
    )
    .await
    .map_err(internal_error)?;
    read.commit().await.map_err(internal_error)?;
    // Echo the applied limits, so a caller can tell a cut export from a
    // complete one and ask again with a larger budget.
    document["limits"] = serde_json::json!({
        "max_depth": depth,
        "max_nodes": limits.max_nodes,
        "max_content_chars": limits.max_content_chars,
    });

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

    fn params(
        max_nodes: Option<usize>,
        max_content_chars: Option<usize>,
    ) -> ExportProvenanceProvOParams {
        ExportProvenanceProvOParams {
            claim_id: String::new(),
            max_depth: None,
            max_nodes,
            max_content_chars,
        }
    }

    #[test]
    fn limits_default_to_get_provenance_and_are_never_unbounded() {
        let l = effective_limits(&params(None, None));
        assert_eq!((l.max_nodes, l.max_content_chars), (Some(50), Some(500)));
        let l = effective_limits(&params(Some(0), Some(1)));
        assert_eq!((l.max_nodes, l.max_content_chars), (Some(1), Some(50)));
        let l = effective_limits(&params(Some(usize::MAX), Some(usize::MAX)));
        assert_eq!((l.max_nodes, l.max_content_chars), (Some(200), Some(4_000)));
    }
}
