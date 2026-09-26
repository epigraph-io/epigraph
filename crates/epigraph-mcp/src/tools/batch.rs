#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

/// Batch submit multiple claims (max 100).
///
/// Each entry is converted with `From<BatchClaimEntry> for SubmitClaimParams`
/// (every `submit_claim` field passes through; see that impl for the drift
/// guard) and submitted through the SAME pipeline as `submit_claim`, one entry
/// at a time, each on its own transaction. A refused entry — an unknown
/// methodology or evidence_type, a bad label, a refused write — is refused
/// before or inside its own transaction, so it writes nothing and the other
/// entries still land.
///
/// # Response (additive only)
///
/// `submitted`, `errors` and `error_details` are unchanged. `results` is new:
/// one object per entry, in input order, `{index, status: "ok", ...the full
/// submit_claim response}` or `{index, status: "error", error}`.
pub async fn batch_submit_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: BatchSubmitClaimsParams,
) -> Result<CallToolResult, McpError> {
    if params.claims.is_empty() {
        return Err(invalid_params("claims array cannot be empty"));
    }
    if params.claims.len() > 100 {
        return Err(invalid_params("Maximum 100 claims per batch"));
    }

    let _agent_id = server.agent_id().await?;
    let mut submitted = 0_usize;
    let mut errors = Vec::new();
    let mut results = Vec::with_capacity(params.claims.len());

    for (i, entry) in params.claims.into_iter().enumerate() {
        let claim_params = SubmitClaimParams::from(entry);

        match crate::tools::claims::submit_claim_response(server, viewer, claim_params).await {
            Ok(response) => {
                submitted += 1;
                let mut row = serde_json::to_value(&response).map_err(internal_error)?;
                if let Some(obj) = row.as_object_mut() {
                    obj.insert("index".into(), serde_json::json!(i));
                    obj.insert("status".into(), serde_json::json!("ok"));
                }
                results.push(row);
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "index": i,
                    "status": "error",
                    "error": e.message,
                }));
                errors.push(serde_json::json!({
                    "index": i,
                    "error": format!("{e:?}"),
                }));
            }
        }
    }

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "submitted": submitted,
            "errors": errors.len(),
            "error_details": errors,
            "results": results,
        })
        .to_string(),
    )]))
}

/// Stage claims for validation without persisting.
pub async fn stage_claims(
    _server: &EpiGraphMcpFull,
    params: StageClaimsParams,
) -> Result<CallToolResult, McpError> {
    if params.claims.is_empty() {
        return Err(invalid_params("claims array cannot be empty"));
    }

    let mut results = Vec::new();

    for (i, content) in params.claims.iter().enumerate() {
        let trimmed = content.trim();
        let valid = !trimmed.is_empty() && trimmed.len() >= 10;
        let warnings: Vec<String> = if trimmed.len() < 20 {
            vec!["Claim is very short — consider adding more detail".into()]
        } else {
            vec![]
        };

        results.push(serde_json::json!({
            "index": i,
            "valid": valid,
            "content_length": trimmed.len(),
            "warnings": warnings,
        }));
    }

    let valid_count = results
        .iter()
        .filter(|r| r["valid"].as_bool().unwrap_or(false))
        .count();

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "total": params.claims.len(),
            "valid": valid_count,
            "invalid": params.claims.len() - valid_count,
            "results": results,
        })
        .to_string(),
    )]))
}

/// Get system statistics.
///
/// # Tenancy (PR-09)
///
/// Every cardinality except `agents` is now **viewer-scoped**: the numbers are
/// "rows this viewer can read", not "rows that exist". Before PR-09 this
/// function took a `&Viewer` and spent it on exactly one call
/// (`TripleRepository::index_counts`) while issuing eight raw `SELECT COUNT(*)`
/// statements of its own, so any principal — including the nil principal of an
/// unauthenticated HTTP call — learned the exact global corpus size. That is a
/// membership oracle, and it was invisible to a lint keyed on the presence of
/// the parameter.
///
/// `agents` and the triple/entity index counts stay corpus-wide and are
/// annotated `VISIBILITY-EXEMPT:` at their repo functions
/// (`corpus_stats.rs::agent_count`, `triple.rs::index_counts`): neither table
/// carries migration 062's tenancy columns, and both numbers exist to tell
/// "the index is empty" apart from "your query matched nothing".
pub async fn system_stats(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SystemStatsParams,
) -> Result<CallToolResult, McpError> {
    let detailed = params.detailed.unwrap_or(false);

    let counts = epigraph_db::CorpusStatsRepository::tenant_counts(&server.pool, viewer, detailed)
        .await
        .map_err(internal_error)?;
    let agent_count = epigraph_db::CorpusStatsRepository::agent_count(&server.pool, viewer)
        .await
        .map_err(internal_error)?;

    let mut stats = serde_json::json!({
        "claims": counts.claims,
        "evidence": counts.evidence,
        "edges": counts.edges,
        "agents": agent_count,
        "frames": counts.frames,
    });

    if detailed {
        // Structured triple/entity index health. Surfaced here so an empty /
        // unpopulated RDF layer is observable, rather than silently reported as
        // count=0 / entity-not-found by query_triples/search_triples/
        // entity_neighborhood (backlog ae2784a9).
        let index = epigraph_db::TripleRepository::index_counts(&server.pool, viewer)
            .await
            .map_err(internal_error)?;

        stats["workflows"] = serde_json::json!(counts.workflow_claims.unwrap_or(0));
        stats["challenges"] = serde_json::json!(counts.challenges.unwrap_or(0));
        stats["embeddings"] = serde_json::json!(counts.embedded_claims.unwrap_or(0));
        stats["triples"] = serde_json::json!(index.triples);
        stats["entities"] = serde_json::json!(index.entities);
        stats["entity_mentions"] = serde_json::json!(index.entity_mentions);
    }

    Ok(CallToolResult::success(vec![Content::text(
        stats.to_string(),
    )]))
}
