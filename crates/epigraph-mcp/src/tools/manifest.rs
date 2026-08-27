//! `export_subgraph_manifest` / `verify_manifest` — the MCP surface for signed
//! Merkle commitments over a set of graph rows (backlog 6e2364b8).
//!
//! Both delegate to `epigraph_engine::export::manifest`, which in turn issues
//! every statement through `ManifestRepository`. No SQL lives here.
//!
//! The signing identity is `EpiGraphMcpFull`'s own — `self.signer` plus the
//! `agents` row resolved by `agent_id()` — so there is no new key plumbing and
//! no way for a caller to name a signer it does not control.
//!
//! # What an exported manifest does and does not prove
//!
//! It proves that THIS set of claims and edges, and no other, is what the
//! export contained: dropping, adding, or substituting any row changes the
//! root, and the recipient can detect that from the bundle alone with no access
//! to this instance. It does NOT prove the shape of the subgraph — an edge leaf
//! binds `(id, relationship, created_at)` and deliberately not its endpoints,
//! because dedup re-sourcing legitimately rewrites them.

use rmcp::model::{CallToolResult, Content};
use uuid::Uuid;

use epigraph_crypto::ManifestRowKind;
use epigraph_engine::export::manifest::{verify_manifest as engine_verify, ManifestError};
use epigraph_engine::export::prov::export_provenance_prov_o;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{ExportSubgraphManifestParams, VerifyManifestParams};

/// A caller naming a row that does not exist is the caller's mistake, not an
/// internal fault; everything else is opaque to the caller.
fn map_manifest_error(e: ManifestError) -> McpError {
    match e {
        ManifestError::UnknownRow { .. }
        | ManifestError::Empty
        | ManifestError::NotFound(_)
        | ManifestError::Invalid { .. } => invalid_params(e.to_string()),
        other => internal_error(other),
    }
}

/// Export a claim's provenance subgraph as PROV-O JSON-LD, anchored by a signed
/// Merkle manifest over exactly the rows the document contains.
pub async fn export_subgraph_manifest(
    server: &EpiGraphMcpFull,
    params: ExportSubgraphManifestParams,
) -> Result<CallToolResult, McpError> {
    // Guarded here as well as in the `#[tool_router]` method, matching
    // `tools::blobs::attach_blob`: this path writes, so it must be closed no
    // matter which entry point reaches it.
    server.reject_if_read_only()?;

    let root_claim_id = parse_uuid(params.root_claim_id.trim())?;
    let signer_agent_id = server.agent_id().await?;

    let export = export_provenance_prov_o(
        &server.pool,
        root_claim_id,
        params.max_depth,
        &server.signer,
        signer_agent_id,
    )
    .await
    .map_err(map_manifest_error)?;

    // The full self-verifying bundle (every leaf's material, the signed header,
    // the signature) is inside `document.manifest`; the top-level `manifest`
    // here is a summary so a caller does not have to dig through the document
    // just to record what was anchored.
    let manifest_block = &export.document["manifest"];
    let body = serde_json::json!({
        "document": export.document,
        "manifest": {
            "manifest_id": manifest_block["manifest_id"],
            "root": manifest_block["root"],
            "entry_count": manifest_block["entry_count"],
            "created_at": manifest_block["created_at"],
            "signer_did": manifest_block["signer_did"],
            "subject": manifest_block["subject"],
        },
        "claim_ids": export.claim_ids,
        "edge_ids": export.edge_ids,
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

/// Re-verify a stored manifest against the live graph, optionally returning an
/// inclusion proof for one committed row.
pub async fn verify_manifest(
    server: &EpiGraphMcpFull,
    params: VerifyManifestParams,
) -> Result<CallToolResult, McpError> {
    let manifest_id = parse_uuid(params.manifest_id.trim())?;

    let prove_claim = params
        .prove_claim_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_uuid)
        .transpose()?;
    let prove_edge = params
        .prove_edge_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_uuid)
        .transpose()?;

    if prove_claim.is_some() && prove_edge.is_some() {
        return Err(invalid_params(
            "pass at most one of prove_claim_id / prove_edge_id — a proof covers one leaf",
        ));
    }

    let prove_row: Option<(ManifestRowKind, Uuid)> = prove_claim
        .map(|id| (ManifestRowKind::Claim, id))
        .or_else(|| prove_edge.map(|id| (ManifestRowKind::Edge, id)));

    let report = engine_verify(&server.pool, manifest_id, prove_row)
        .await
        .map_err(map_manifest_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&report).map_err(internal_error)?,
    )]))
}
