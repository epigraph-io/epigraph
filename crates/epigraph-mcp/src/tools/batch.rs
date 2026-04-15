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
            methodology: "batch_submission".to_string(),
            evidence_data: entry.evidence_data.clone(),
            evidence_type: entry.evidence_type.clone(),
            confidence: entry.confidence.unwrap_or(0.5),
            source_url: None,
            reasoning: None,
        };

        match crate::tools::claims::submit_claim(server, claim_params).await {
            Ok(result) => {
                // Extract claim_id from the JSON text content returned by submit_claim
                let claim_id = result
                    .content
                    .first()
                    .and_then(|c| c.as_text())
                    .and_then(|t| serde_json::from_str::<serde_json::Value>(&t.text).ok())
                    .and_then(|v| v.get("claim_id").and_then(|id| id.as_str()).map(String::from))
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

    let claim_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM claims")
        .fetch_one(&server.pool)
        .await
        .map_err(internal_error)?;

    let evidence_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM evidence")
        .fetch_one(&server.pool)
        .await
        .map_err(internal_error)?;

    let edge_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM edges")
        .fetch_one(&server.pool)
        .await
        .map_err(internal_error)?;

    let agent_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM agents")
        .fetch_one(&server.pool)
        .await
        .map_err(internal_error)?;

    let frame_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM frames")
        .fetch_one(&server.pool)
        .await
        .map_err(internal_error)?;

    let mut stats = serde_json::json!({
        "claims": claim_count.0,
        "evidence": evidence_count.0,
        "edges": edge_count.0,
        "agents": agent_count.0,
        "frames": frame_count.0,
    });

    if detailed {
        let workflow_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM claims WHERE 'workflow' = ANY(labels)")
                .fetch_one(&server.pool)
                .await
                .map_err(internal_error)?;

        let challenge_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM challenges")
            .fetch_one(&server.pool)
            .await
            .map_err(internal_error)?;

        let embedding_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM claims WHERE embedding IS NOT NULL")
                .fetch_one(&server.pool)
                .await
                .map_err(internal_error)?;

        stats["workflows"] = serde_json::json!(workflow_count.0);
        stats["challenges"] = serde_json::json!(challenge_count.0);
        stats["embeddings"] = serde_json::json!(embedding_count.0);
    }

    Ok(CallToolResult::success(vec![Content::text(
        stats.to_string(),
    )]))
}
