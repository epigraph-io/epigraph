#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

/// Batch submit multiple claims (max 100).
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
    let mut submitted = Vec::new();
    let mut errors = Vec::new();

    for (i, entry) in params.claims.iter().enumerate() {
        let claim_params = SubmitClaimParams {
            content: entry.content.clone(),
            methodology: "inductive_generalization".to_string(),
            evidence_data: entry.evidence_data.clone(),
            evidence_type: entry.evidence_type.clone(),
            confidence: entry.confidence.unwrap_or(0.5),
            source_url: None,
            reasoning: None,
            labels: entry.labels.clone(),
            novelty_threshold: None,
        };

        match crate::tools::claims::submit_claim(server, viewer, claim_params).await {
            Ok(result) => {
                // Extract claim_id from the JSON text content returned by submit_claim
                let claim_id = result
                    .content
                    .first()
                    .and_then(|c| c.as_text())
                    .and_then(|t| serde_json::from_str::<serde_json::Value>(&t.text).ok())
                    .and_then(|v| {
                        v.get("claim_id")
                            .and_then(|id| id.as_str())
                            .map(String::from)
                    })
                    .unwrap_or_default();
                submitted.push(serde_json::json!({
                    "index": i,
                    "status": "ok",
                    "claim_id": claim_id,
                }));
            }
            Err(e) => {
                errors.push(serde_json::json!({
                    "index": i,
                    "error": format!("{e:?}"),
                }));
            }
        }
    }

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            "submitted": submitted.len(),
            "errors": errors.len(),
            "error_details": errors,
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
