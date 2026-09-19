#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

/// Batch submit multiple claims (max 100).
pub async fn batch_submit_claims(
    server: &EpiGraphMcpFull,
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

        match crate::tools::claims::submit_claim(server, claim_params).await {
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
pub async fn system_stats(
    server: &EpiGraphMcpFull,
    params: SystemStatsParams,
) -> Result<CallToolResult, McpError> {
    let detailed = params.detailed.unwrap_or(false);

    // The counts live in `epigraph_db::StatsRepository` so that this tool and
    // `GET /api/v1/stats` report the same corpus. Same definitions, same
    // output keys and values as when the SQL was inline here.
    let counts = epigraph_db::StatsRepository::corpus_counts(&server.pool)
        .await
        .map_err(internal_error)?;

    let mut stats = serde_json::json!({
        "claims": counts.claims,
        "evidence": counts.evidence,
        "edges": counts.edges,
        "agents": counts.agents,
        "frames": counts.frames,
    });

    if detailed {
        let detail = epigraph_db::StatsRepository::detailed_counts(&server.pool)
            .await
            .map_err(internal_error)?;

        // Structured triple/entity index health. Surfaced here so an empty /
        // unpopulated RDF layer is observable, rather than silently reported as
        // count=0 / entity-not-found by query_triples/search_triples/
        // entity_neighborhood (backlog ae2784a9).
        let index = epigraph_db::TripleRepository::index_counts(&server.pool)
            .await
            .map_err(internal_error)?;

        stats["workflows"] = serde_json::json!(detail.workflows);
        stats["challenges"] = serde_json::json!(detail.challenges);
        stats["embeddings"] = serde_json::json!(detail.embeddings);
        stats["triples"] = serde_json::json!(index.triples);
        stats["entities"] = serde_json::json!(index.entities);
        stats["entity_mentions"] = serde_json::json!(index.entity_mentions);
    }

    Ok(CallToolResult::success(vec![Content::text(
        stats.to_string(),
    )]))
}
