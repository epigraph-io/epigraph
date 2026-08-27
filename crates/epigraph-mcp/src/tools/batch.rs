#![allow(clippy::wildcard_imports)]

use std::collections::BTreeSet;

use epigraph_core::obligation::{evaluate, CoverageContract, CoverageStandard};
use epigraph_db::{NewObligation, ObligationRepository, ANCHOR_KIND_CLAIM};
use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

/// `obligations.source_tool` for the batch path.
const SOURCE_TOOL: &str = "batch_submit_claims";

/// Batch submit multiple claims (max 100).
///
/// # The implicit coverage contract
///
/// Every call carries one, derived from the payload itself: `declared_total`
/// is `params.claims.len()`, the unit is `claim`, and the standard defaults to
/// `exhaustive`. There is no config key, no env var and no feature gate — the
/// ON path is the only path, and the optional `coverage` param can only weaken
/// or relabel the contract, never disable the counting.
///
/// This tool is the one kernel tool that already published a completeness
/// number capable of being FALSE. It reports `"submitted": submitted.len()`,
/// but `submit_claim` returns `Ok` with a PRE-EXISTING claim id on both the
/// content-hash dedup path (`create_claim_idempotent`) and the novelty-gate
/// path (`GateDecision::ReturnExisting`). A batch of 40 could therefore report
/// `submitted: 40` while producing 12 distinct claims. The verdict replaces
/// that trust with a count.
///
/// Verdicts are ADVISORY: a `breach` does not fail the call, roll anything
/// back, or alter a claim that was written. `submitted`, `errors` and
/// `error_details` keep their exact prior meaning; every coverage field is
/// additive. Converting a shortfall into a hard error would reject every
/// legitimate resubmit. A blocking strict mode is elaboration work, not built.
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

    // Parse the contract BEFORE anything is written: an unrecognised standard
    // is a caller error, and letting it through would silently produce a batch
    // that owes nothing.
    let contract = coverage_contract(params.coverage.as_ref(), params.claims.len())?;

    let agent_id = server.agent_id().await?;
    let mut submitted = Vec::new();
    let mut errors = Vec::new();
    // Distinct anchors, not per-entry successes. Two byte-identical entries
    // collapse to one claim id here — which is the finding: the agent believed
    // it was asserting two distinct things and asserted one.
    let mut anchors: BTreeSet<uuid::Uuid> = BTreeSet::new();

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
                // A successful submit that yields no parseable claim id is an
                // anchor we cannot count. Failing loudly beats silently
                // dropping it and under-reporting coverage as a breach the
                // caller cannot act on.
                let parsed = claim_id.parse::<uuid::Uuid>().map_err(|e| {
                    internal_error(format!(
                        "batch entry {i} submitted but returned an unparseable claim_id \
                         {claim_id:?}: {e}"
                    ))
                })?;
                anchors.insert(parsed);
                submitted.push(serde_json::json!({
                    "index": i,
                    "status": "ok",
                    "claim_id": claim_id,
                }));
            }
            Err(e) => {
                // An errored entry anchored nothing, so it contributes to the
                // denominator and not to the numerator.
                errors.push(serde_json::json!({
                    "index": i,
                    "error": format!("{e:?}"),
                }));
            }
        }
    }

    let observed = u32::try_from(anchors.len()).unwrap_or(u32::MAX);
    let assessment = evaluate(&contract, observed);

    // Best-effort persistence, mirroring the post-commit embedding contract:
    // the claims are already written, and an obligations INSERT failure must
    // not fail a batch that succeeded. The verdict is still returned.
    let obligation_id = match ObligationRepository::record(
        &server.pool,
        NewObligation {
            agent_id: Some(agent_id),
            standard: contract.standard,
            unit: contract.unit.clone(),
            declared_total: i32::try_from(contract.declared_total).unwrap_or(i32::MAX),
            anchors: anchors.iter().copied().collect(),
            anchor_kind: ANCHOR_KIND_CLAIM.to_string(),
            observed_total: i32::try_from(assessment.observed_total).unwrap_or(i32::MAX),
            verdict: assessment.verdict.as_str().to_string(),
            verdict_reason: Some(assessment.reason.clone()),
            missing_contract_fields: assessment.missing_contract_fields.clone(),
            source_tool: SOURCE_TOOL.to_string(),
        },
    )
    .await
    {
        Ok(id) => Some(id.to_string()),
        Err(e) => {
            tracing::warn!(error = %e, "failed to record batch coverage obligation");
            None
        }
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::json!({
            // Unchanged fields — same meaning as before the obligation layer.
            "submitted": submitted.len(),
            "errors": errors.len(),
            "error_details": errors,
            // Additive: the counted verdict, not a self-report.
            "declared": contract.declared_total,
            "distinct_claims": anchors.len(),
            "deduplicated": submitted.len().saturating_sub(anchors.len()),
            "coverage_standard": contract.standard.as_str(),
            "coverage_unit": contract.unit,
            "coverage_verdict": assessment.verdict.as_str(),
            "verdict_reason": assessment.reason,
            "missing_contract_fields": assessment.missing_contract_fields,
            "obligation_id": obligation_id,
        })
        .to_string(),
    )]))
}

/// Build the coverage contract for one batch.
///
/// The default is the whole design: `exhaustive` over `entry_count` claims,
/// with no opt-in. `coverage` may relabel the unit, weaken the standard, or
/// substitute an external denominator; it cannot turn the checking off.
fn coverage_contract(
    coverage: Option<&CoverageParams>,
    entry_count: usize,
) -> Result<CoverageContract, McpError> {
    let standard = match coverage.and_then(|c| c.standard.as_deref()) {
        // An unknown standard is REJECTED, never silently defaulted — a quiet
        // fallback to `summary` would make a typo owe nothing.
        Some(raw) => raw.parse::<CoverageStandard>().map_err(|e| {
            invalid_params(format!(
                "{e}. Omit `coverage.standard` to accept the default `exhaustive`."
            ))
        })?,
        None => CoverageStandard::Exhaustive,
    };

    let unit = coverage
        .and_then(|c| c.unit.as_deref())
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or("claim")
        .to_string();

    let declared_total = coverage
        .and_then(|c| c.declared_total)
        .unwrap_or_else(|| u32::try_from(entry_count).unwrap_or(u32::MAX));

    Ok(CoverageContract {
        standard,
        unit,
        declared_total,
    })
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

        // Structured triple/entity index health. Surfaced here so an empty /
        // unpopulated RDF layer is observable, rather than silently reported as
        // count=0 / entity-not-found by query_triples/search_triples/
        // entity_neighborhood (backlog ae2784a9).
        let index = epigraph_db::TripleRepository::index_counts(&server.pool)
            .await
            .map_err(internal_error)?;

        stats["workflows"] = serde_json::json!(workflow_count.0);
        stats["challenges"] = serde_json::json!(challenge_count.0);
        stats["embeddings"] = serde_json::json!(embedding_count.0);
        stats["triples"] = serde_json::json!(index.triples);
        stats["entities"] = serde_json::json!(index.entities);
        stats["entity_mentions"] = serde_json::json!(index.entity_mentions);
    }

    Ok(CallToolResult::success(vec![Content::text(
        stats.to_string(),
    )]))
}
