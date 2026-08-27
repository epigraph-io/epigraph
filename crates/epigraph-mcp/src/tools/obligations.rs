//! Obligation tools (backlog 4b48ffb5).
//!
//! One tool: re-count an obligation's anchors against the live graph and
//! persist the fresh verdict. All SQL lives in
//! `epigraph_db::ObligationRepository`; nothing here issues a statement.
//!
//! Why this is a WRITE tool despite reading like a query: `recheck` stores the
//! recomputed verdict and bumps `checked_at`, so the row it returns is the row
//! it just wrote.

use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::CheckObligationParams;

/// Re-count an obligation and return its fresh verdict.
///
/// Coverage DECAYS: `supersede` and `mark_duplicate` both flip
/// `is_current = false`, so a contract satisfied at write time can be a breach
/// later. That is what makes rechecking meaningful rather than a replay of a
/// stored number.
pub async fn check_obligation(
    server: &EpiGraphMcpFull,
    params: CheckObligationParams,
) -> Result<CallToolResult, McpError> {
    let id = parse_uuid(&params.obligation_id)?;

    let row = epigraph_db::ObligationRepository::recheck(&server.pool, id)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| invalid_params(format!("obligation {id} not found")))?;

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "obligation_id": row.id.to_string(),
            "agent_id": row.agent_id.map(|a| a.to_string()),
            "coverage_standard": row.standard,
            "coverage_unit": row.unit,
            "declared": row.declared_total,
            "observed_total": row.observed_total,
            "coverage_verdict": row.verdict,
            "verdict_reason": row.verdict_reason,
            "missing_contract_fields": row.missing_contract_fields,
            "anchor_kind": row.anchor_kind,
            "anchors": row.anchors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "source_tool": row.source_tool,
            "created_at": row.created_at.to_rfc3339(),
            "checked_at": row.checked_at.to_rfc3339(),
        })
        .to_string(),
    )]))
}
