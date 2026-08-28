//! `anchor_manifest` / `verify_anchor` — the MCP surface for external
//! anchoring (backlog 94e62824).
//!
//! Both delegate to `epigraph_db::anchor::AnchorService`, which issues every
//! statement through `AnchorRepository`. No SQL lives here.
//!
//! # Neither tool is how anchoring normally happens
//!
//! Every sealed manifest is anchored automatically by the post-commit hook in
//! `epigraph_engine::export::manifest::anchor_manifest`. `anchor_manifest`
//! here is the RETRY path — for a root whose first attempt hit an unconfigured
//! or unreachable backend — and it is idempotent, so calling it on an already
//! anchored root returns the existing anchor and publishes nothing.
//!
//! # A NAME COLLISION, stated so nobody trips on it
//!
//! The manifest track (backlog 6e2364b8) uses "anchor" for *creating* a
//! manifest: `epigraph_engine::export::manifest::anchor_manifest` writes the
//! `manifests` row. This tool uses it in the external sense — publishing an
//! existing manifest's root to a ledger. Same word, two layers.
//!
//! # What a green verdict does and does not mean
//!
//! `trust_basis` is on every report and is load-bearing. `"operator-held"`
//! (the mock backend, which is the default) means the mechanism checks out but
//! the ledger is in the operator's own Postgres — that is NOT third-party
//! proof of existence-at-a-time, and must not be quoted as an audit result.
//! `"third-party"` is what a configured real backend reports.

use rmcp::model::{CallToolResult, Content};

use epigraph_db::anchor::{trust_basis_for_backend, AnchorService, AnchorServiceError};
use epigraph_db::ROOT_TYPE_MANIFEST;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{AnchorManifestParams, VerifyAnchorParams};

/// A caller naming an unknown root or root type is the caller's mistake;
/// everything else is opaque to the caller.
fn map_anchor_error(e: AnchorServiceError) -> McpError {
    match e {
        AnchorServiceError::UnknownRootType { .. }
        | AnchorServiceError::RootNotFound { .. }
        | AnchorServiceError::UnknownBackend(_) => invalid_params(e.to_string()),
        other => internal_error(other),
    }
}

/// Publish a manifest's Merkle root as an external commitment.
pub async fn anchor_manifest(
    server: &EpiGraphMcpFull,
    params: AnchorManifestParams,
) -> Result<CallToolResult, McpError> {
    // Guarded here as well as in the `#[tool_router]` method, matching
    // `tools::manifest::export_subgraph_manifest`: this path writes, so it must
    // be closed no matter which entry point reaches it.
    server.reject_if_read_only()?;

    let manifest_id = parse_uuid(params.manifest_id.trim())?;
    let service = AnchorService::from_env(&server.pool).map_err(map_anchor_error)?;

    let row = service
        .anchor(&server.pool, ROOT_TYPE_MANIFEST, manifest_id)
        .await
        .map_err(map_anchor_error)?;

    let body = serde_json::json!({
        "anchor_id": row.id,
        "root_type": row.root_type,
        "root_id": row.root_id,
        "root": hex_of(&row.root_hash),
        "backend": row.backend,
        "network": row.network,
        "status": row.status,
        "tx_id": row.tx_id,
        "block_height": row.block_height,
        "block_time": row.block_time,
        "sealed_at": row.sealed_at,
        "failure_reason": row.failure_reason,
        "commitment_bytes_len": row.commitment_bytes.len(),
        // Derived from the ROW, not from `service`, so the label names the ledger
        // this anchor actually lives on. The two agree here today only because
        // `insert_pending` keys ON CONFLICT by (root_type, root_id, backend,
        // network) and so can only hand back a row for this process's backend;
        // deriving it from the row makes that structural instead of incidental,
        // and matches `verify_row`.
        "trust_basis": trust_basis_for_backend(&row.backend),
    });

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&body).map_err(internal_error)?,
    )]))
}

/// Re-verify an anchored root against the ledger and the live graph.
pub async fn verify_anchor(
    server: &EpiGraphMcpFull,
    params: VerifyAnchorParams,
) -> Result<CallToolResult, McpError> {
    let root_id = parse_uuid(params.root_id.trim())?;
    let root_type = params
        .root_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(ROOT_TYPE_MANIFEST);

    let service = AnchorService::from_env(&server.pool).map_err(map_anchor_error)?;
    let report = service
        .verify(&server.pool, root_type, root_id)
        .await
        .map_err(map_anchor_error)?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&report).map_err(internal_error)?,
    )]))
}

/// Lowercase hex, matching every other digest this server prints.
fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
