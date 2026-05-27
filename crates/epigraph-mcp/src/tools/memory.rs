#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    ClaimRepository, EvidenceRepository, ReasoningTraceRepository, WorkflowRepository,
};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn memorize(
    server: &EpiGraphMcpFull,
    params: MemorizeParams,
) -> Result<CallToolResult, McpError> {
    let agent_id = server.agent_id().await?;
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let pub_key = server.signer.public_key();
    let confidence = params.confidence.unwrap_or(0.7).clamp(0.0, 1.0);
    let tags = params.tags.unwrap_or_default();

    let raw_truth = (confidence * 0.6).clamp(0.01, 0.99);
    let truth_value = TruthValue::clamped(raw_truth);

    let mut claim = Claim::new(params.content.clone(), agent_id_typed, pub_key, truth_value);
    claim.content_hash = ContentHasher::hash(params.content.as_bytes());
    claim.signature = Some(server.signer.sign(&claim.content_hash));

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&server.pool, &claim, "memorize").await?;
    let claim_uuid = claim.id.as_uuid();

    let (final_truth, ds, embedded) = if was_created {
        let evidence_text = if tags.is_empty() {
            "Memory stored via MCP memorize tool".to_string()
        } else {
            format!("Memory [{}] stored via MCP memorize tool", tags.join(", "))
        };
        let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
        let mut evidence = Evidence::new(
            agent_id_typed,
            pub_key,
            evidence_hash,
            EvidenceType::Testimony {
                source: "mcp-memorize".to_string(),
                testified_at: chrono::Utc::now(),
                verification: None,
            },
            Some(evidence_text),
            claim.id,
        );
        evidence.signature = Some(server.signer.sign(&evidence_hash));

        let trace = ReasoningTrace::new(
            agent_id_typed,
            pub_key,
            Methodology::Heuristic,
            vec![TraceInput::Evidence { id: evidence.id }],
            confidence,
            format!("Memory stored via memorize tool. Tags: {}", tags.join(", ")),
        );

        ReasoningTraceRepository::create(&server.pool, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&server.pool, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id(&server.pool, claim.id, trace.id)
            .await
            .map_err(internal_error)?;

        let ds = match ds_auto::auto_wire_ds_for_claim(
            &server.pool,
            claim_uuid,
            agent_id,
            confidence,
            0.6,
            true,
            None,
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(claim_id = %claim_uuid, "ds auto-wire memorize failed: {e}");
                None
            }
        };

        let embedded = server
            .embedder
            .embed_and_store(claim_uuid, &params.content)
            .await;

        (raw_truth, ds, embedded)
    } else {
        // Option A: skip Evidence + Trace + update_trace_id + DS + embed.
        // AUTHORED already fired in the helper. Report canonical truth.
        (claim.truth_value.value(), None, false)
    };

    success_json(&MemorizeResponse {
        claim_id: claim_uuid.to_string(),
        truth_value: final_truth,
        embedded,
        tags,
        belief: ds.as_ref().map(|d| d.belief),
        plausibility: ds.as_ref().map(|d| d.plausibility),
        pignistic_prob: ds.as_ref().map(|d| d.pignistic_prob),
    })
}

pub async fn recall(
    server: &EpiGraphMcpFull,
    params: RecallParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);

    // Try semantic search first
    let results = match server.embedder.search(&params.query, limit).await {
        Ok(hits) => {
            let mut results = Vec::new();
            for (claim_id, similarity) in hits {
                if let Ok(Some(claim)) =
                    ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(claim_id)).await
                {
                    let tv = claim.truth_value.value();
                    if tv >= min_truth {
                        results.push(RecallResult {
                            claim_id: claim_id.to_string(),
                            content: claim.content,
                            truth_value: tv,
                            similarity,
                        });
                    }
                }
            }

            // Second pass: hierarchical workflow theses live on
            // `claims.embedding` (not an evidence row), so the evidence-only
            // search above misses them. Narrowly augment with workflow
            // thesis claims — does NOT change recall's semantics for
            // non-workflow memories. Resolves bug 6d3fc460.
            if let Ok(pgvec) = server
                .embedder
                .generate(&params.query)
                .await
                .map(|v| crate::embed::format_pgvector(&v))
            {
                if let Ok(thesis_hits) =
                    WorkflowRepository::search_thesis_by_embedding(&server.pool, &pgvec, limit)
                        .await
                {
                    let already: std::collections::HashSet<String> =
                        results.iter().map(|r| r.claim_id.clone()).collect();
                    for (claim_id, similarity) in thesis_hits {
                        if already.contains(&claim_id.to_string()) {
                            continue;
                        }
                        if let Ok(Some(claim)) =
                            ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(claim_id))
                                .await
                        {
                            let tv = claim.truth_value.value();
                            if tv >= min_truth {
                                results.push(RecallResult {
                                    claim_id: claim_id.to_string(),
                                    content: claim.content,
                                    truth_value: tv,
                                    similarity,
                                });
                            }
                        }
                    }
                    // Re-sort by similarity (desc) and truncate to the caller's limit.
                    results.sort_by(|a, b| {
                        b.similarity
                            .partial_cmp(&a.similarity)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                    results.truncate(limit as usize);
                }
            }

            results
        }
        Err(_) => {
            // Fallback to text search
            let claims = ClaimRepository::list(&server.pool, limit, 0, Some(&params.query))
                .await
                .map_err(internal_error)?;
            claims
                .into_iter()
                .filter(|c| c.truth_value.value() >= min_truth)
                .map(|c| RecallResult {
                    claim_id: c.id.as_uuid().to_string(),
                    content: c.content,
                    truth_value: c.truth_value.value(),
                    similarity: 0.0,
                })
                .collect()
        }
    };

    success_json(&results)
}
