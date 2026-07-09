#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::*;

use epigraph_db::access_control::check_content_access;
use epigraph_db::{ClaimRepository, EvidenceRepository, PaperRepository, ReasoningTraceRepository};
use uuid::Uuid;

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
///
/// `claim_count` is `max(asserted_count, labeled_count)`: the `asserts`-edge
/// count alone under-reports a partially-ingested paper, because ingestion
/// labels a claim `doi:<doi>` before it links the `asserts` edge (see
/// `PaperRepository::count_claims_by_doi_label`). Without the label-based
/// floor, a crash between those two writes leaves a claim in the graph that
/// this probe would report as `claim_count=0`, letting the nightly monitor
/// re-extract an already (partially) ingested paper.
///
/// This closes the write-order race going forward; it does not retroactively
/// recover claims ingested before the `doi:<doi>` label existed (they carry
/// neither the label nor, in the failure case, the edge — no DOI-keyed query
/// can find them). Investigating backlog 7c6ce1b3-b372-4727-a510-43e63001bf18
/// (arXiv 2504.18085) found exactly that: its orphaned claims predate the
/// label and are unlabeled in the live DB, so this fix prevents the same
/// class of gap from recurring rather than repairing that specific paper
/// (which was already made whole by a subsequent full re-ingestion).
pub async fn query_paper(
    server: &EpiGraphMcpFull,
    params: QueryPaperParams,
    requester: Option<Uuid>,
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

    let asserted_count = PaperRepository::count_asserted_claims(&server.pool, paper.id)
        .await
        .map_err(internal_error)?;
    // Node-existence probe, independent of the `asserts` edge: catches claims
    // a partial/crashed ingestion already labelled `doi:<doi>` but never got
    // to link, which `asserted_count` alone would silently report as zero.
    let labeled_count = PaperRepository::count_claims_by_doi_label(&server.pool, &paper.doi)
        .await
        .map_err(internal_error)?;
    let claim_count = asserted_count.max(labeled_count);

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

    let mut claims = Vec::with_capacity(claim_rows.len());
    for c in claim_rows {
        let access = check_content_access(&server.pool, c.id, requester).await;
        let (content, content_hash) =
            crate::tools::redaction::redact_content(access, &c.content, &c.content_hash);
        claims.push(ClaimResponse {
            id: c.id.to_string(),
            content,
            truth_value: c.truth_value,
            agent_id: c.agent_id.to_string(),
            content_hash,
            created_at: c.created_at.to_rfc3339(),
            labels: Vec::new(),
            is_current: true,
            supersedes: None,
        });
    }

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
    requester: Option<Uuid>,
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
            let access = check_content_access(&server.pool, claim.id.as_uuid(), requester).await;
            let (content, content_hash) = crate::tools::redaction::redact_content(
                access,
                &claim.content,
                &claim.content_hash,
            );
            results.push(ClaimResponse {
                id: claim.id.as_uuid().to_string(),
                content,
                truth_value: claim.truth_value.value(),
                agent_id: claim.agent_id.as_uuid().to_string(),
                content_hash,
                created_at: claim.created_at.to_rfc3339(),
                labels: Vec::new(),
                is_current: true,
                supersedes: None,
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
    requester: Option<Uuid>,
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
                    let access =
                        check_content_access(&server.pool, claim.id.as_uuid(), requester).await;
                    let (content, content_hash) = crate::tools::redaction::redact_content(
                        access,
                        &claim.content,
                        &claim.content_hash,
                    );
                    results.push(ClaimResponse {
                        id: claim.id.as_uuid().to_string(),
                        content,
                        truth_value: claim.truth_value.value(),
                        agent_id: claim.agent_id.as_uuid().to_string(),
                        content_hash,
                        created_at: claim.created_at.to_rfc3339(),
                        labels: Vec::new(),
                        is_current: true,
                        supersedes: None,
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
    requester: Option<Uuid>,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let min_truth = params.min_truth.unwrap_or(0.0);
    let offset = params.offset.unwrap_or(0).max(0);

    if params.labels.is_empty() {
        return Err(McpError {
            code: rmcp::model::ErrorCode::INVALID_PARAMS,
            message: std::borrow::Cow::Borrowed("labels must contain at least one label"),
            data: None,
        });
    }

    let rows = ClaimRepository::list_by_labels(
        &server.pool,
        &params.labels,
        &params.exclude_labels,
        params.current_only,
        min_truth,
        limit,
        offset,
    )
    .await
    .map_err(internal_error)?;

    let mut results: Vec<ClaimResponse> = Vec::with_capacity(rows.len());
    for (c, labels) in rows {
        let access = check_content_access(&server.pool, c.id.as_uuid(), requester).await;
        let (content, content_hash) =
            crate::tools::redaction::redact_content(access, &c.content, &c.content_hash);
        results.push(ClaimResponse {
            id: c.id.as_uuid().to_string(),
            content,
            truth_value: c.truth_value.value(),
            agent_id: c.agent_id.as_uuid().to_string(),
            content_hash,
            created_at: c.created_at.to_rfc3339(),
            labels,
            is_current: c.is_current,
            supersedes: c.supersedes.map(|s| s.as_uuid().to_string()),
        });
    }

    success_json(&results)
}
