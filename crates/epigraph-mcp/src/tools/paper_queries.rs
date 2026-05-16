#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_core::Claim;
use epigraph_crypto::ContentHasher;
use epigraph_db::{ClaimRepository, EvidenceRepository, PaperRepository, ReasoningTraceRepository};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

/// Look up a paper by DOI and return its title, authors, claim count, and up
/// to 100 asserted-claim summaries.
///
/// The earlier implementation searched claim *content* for the DOI substring
/// via `ClaimRepository::list(.., Some(doi))` — that almost never matched, so
/// every paper looked like a "bare shell with claim_count=0", which then made
/// EpiClaw's nightly monitor mis-diagnose `ingest_document`'s (correct)
/// `already_ingested=true` idempotency response as a bug.
///
/// The real shape: papers are first-class nodes joined to claims by
/// `paper -asserts-> claim` edges and to authors by
/// `agent -authored-> paper` edges.
///
/// Returns a zero-shaped response (claim_count=0, empty title/authors) when
/// the DOI isn't in the graph. Callers (the monitor) use this as a dedup
/// probe and expect a structured response, not a 404.
pub async fn query_paper(
    server: &EpiGraphMcpFull,
    params: QueryPaperParams,
) -> Result<CallToolResult, McpError> {
    let paper = PaperRepository::find_by_doi(&server.pool, &params.doi)
        .await
        .map_err(internal_error)?;

    let Some(paper) = paper else {
        return success_json(&PaperResponse {
            doi: params.doi,
            title: String::new(),
            authors: vec![],
            claim_count: 0,
            claims: vec![],
        });
    };

    let claim_count = PaperRepository::count_asserted_claims(&server.pool, paper.id)
        .await
        .map_err(internal_error)?;

    let authors = PaperRepository::list_authors(&server.pool, paper.id)
        .await
        .map_err(internal_error)?
        .into_iter()
        .map(|(agent_id, display_name)| AuthorResponse {
            agent_id: agent_id.to_string(),
            name: display_name.unwrap_or_default(),
        })
        .collect();

    let claim_rows = PaperRepository::list_asserted_claims(&server.pool, paper.id, 100)
        .await
        .map_err(internal_error)?;

    let claims = claim_rows
        .into_iter()
        .map(|c| ClaimResponse {
            id: c.id.to_string(),
            content: c.content,
            truth_value: c.truth_value,
            agent_id: c.agent_id.to_string(),
            content_hash: ContentHasher::to_hex(&c.content_hash),
            created_at: c.created_at.to_rfc3339(),
        })
        .collect();

    success_json(&PaperResponse {
        doi: paper.doi,
        title: paper.title.unwrap_or_default(),
        authors,
        claim_count,
        claims,
    })
}

pub async fn query_claims_by_evidence(
    server: &EpiGraphMcpFull,
    params: QueryClaimsByEvidenceParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    // Search claims and filter by evidence type
    let claims = ClaimRepository::list(&server.pool, limit * 2, 0, None)
        .await
        .map_err(internal_error)?;

    let evidence_type_lower = params.evidence_type.to_lowercase();
    let mut results = Vec::new();

    for claim in claims {
        if claim.truth_value.value() < min_truth {
            continue;
        }

        let evidence_list = EvidenceRepository::get_by_claim(&server.pool, claim.id)
            .await
            .unwrap_or_default();

        let matches = evidence_list.iter().any(|e| {
            let type_name = match &e.evidence_type {
                epigraph_core::EvidenceType::Observation { .. } => "observation",
                epigraph_core::EvidenceType::Document { .. } => "document",
                epigraph_core::EvidenceType::Testimony { .. } => "testimony",
                epigraph_core::EvidenceType::Literature { .. } => "reference",
                epigraph_core::EvidenceType::Consensus { .. } => "consensus",
                epigraph_core::EvidenceType::Figure { .. } => "figure",
            };
            type_name == evidence_type_lower
                || (evidence_type_lower == "computation" && type_name == "document")
        });

        if matches {
            results.push(ClaimResponse {
                id: claim.id.as_uuid().to_string(),
                content: claim.content.clone(),
                truth_value: claim.truth_value.value(),
                agent_id: claim.agent_id.as_uuid().to_string(),
                content_hash: ContentHasher::to_hex(&claim.content_hash),
                created_at: claim.created_at.to_rfc3339(),
            });
        }

        if results.len() >= limit as usize {
            break;
        }
    }

    success_json(&results)
}

pub async fn query_claims_by_methodology(
    server: &EpiGraphMcpFull,
    params: QueryClaimsByMethodologyParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    let claims = ClaimRepository::list(&server.pool, limit * 2, 0, None)
        .await
        .map_err(internal_error)?;

    let methodology_lower = params.methodology.to_lowercase();
    let mut results = Vec::new();

    for claim in claims {
        if claim.truth_value.value() < min_truth {
            continue;
        }

        // Check reasoning traces for methodology
        if let Some(trace_id) = claim.trace_id {
            if let Ok(Some(trace)) =
                ReasoningTraceRepository::get_by_id(&server.pool, trace_id).await
            {
                let method_name = trace.methodology.description().to_lowercase();
                if method_name.contains(&methodology_lower) {
                    results.push(ClaimResponse {
                        id: claim.id.as_uuid().to_string(),
                        content: claim.content.clone(),
                        truth_value: claim.truth_value.value(),
                        agent_id: claim.agent_id.as_uuid().to_string(),
                        content_hash: ContentHasher::to_hex(&claim.content_hash),
                        created_at: claim.created_at.to_rfc3339(),
                    });
                }
            }
        }

        if results.len() >= limit as usize {
            break;
        }
    }

    success_json(&results)
}

pub async fn query_claims_by_label(
    server: &EpiGraphMcpFull,
    params: QueryClaimsByLabelParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);

    if params.labels.is_empty() {
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: std::borrow::Cow::Borrowed("labels must contain at least one label"),
            data: None,
        });
    }

    // Pass default `exclude_labels=[]` and `current_only=false` for now; Task 3
    // of the backlog-retirement plan rewires this caller to surface the new
    // fields and accept the filters from MCP params.
    let claim_pairs =
        ClaimRepository::list_by_labels(&server.pool, &params.labels, &[], false, min_truth, limit)
            .await
            .map_err(internal_error)?;
    let claims: Vec<Claim> = claim_pairs.into_iter().map(|(c, _)| c).collect();

    let results: Vec<ClaimResponse> = claims
        .iter()
        .map(|c| ClaimResponse {
            id: c.id.as_uuid().to_string(),
            content: c.content.clone(),
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid().to_string(),
            content_hash: ContentHasher::to_hex(&c.content_hash),
            created_at: c.created_at.to_rfc3339(),
        })
        .collect();

    success_json(&results)
}
