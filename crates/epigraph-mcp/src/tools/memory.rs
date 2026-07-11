#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{ClaimRepository, EvidenceRepository, HybridHit, ReasoningTraceRepository};

use crate::embed::HYBRID_RRF_K;

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

    // Persist tags as claim labels so `query_claims_by_label` can surface them.
    // Apply on dedup-hit too — labels accumulate non-destructively via the repo's
    // SELECT DISTINCT, so re-memorizing existing content with new tags is additive.
    if !tags.is_empty() {
        if let Err(e) = ClaimRepository::update_labels(&server.pool, claim_uuid, &tags, &[]).await {
            tracing::warn!(claim_id = %claim_uuid, "memorize: update_labels failed: {e}");
        }
    }

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

/// Parse the optional `agent_id` recall scope filter. A present-but-invalid
/// UUID is an ERROR, never a silently dropped filter — silently ignoring it
/// would widen recall to every agent (a scope bypass) while the caller
/// believes the results are scoped. Blank/whitespace is treated as absent.
fn parse_agent_filter(raw: Option<&str>) -> Result<Option<uuid::Uuid>, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => uuid::Uuid::parse_str(s)
            .map(Some)
            .map_err(|e| format!("invalid agent_id {s:?}: {e}")),
    }
}

pub async fn recall(
    server: &EpiGraphMcpFull,
    params: RecallParams,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let agent_filter = parse_agent_filter(params.agent_id.as_deref()).map_err(invalid_params)?;
    let tags = params.tags;
    let tags_opt: Option<&[String]> = if tags.is_empty() { None } else { Some(&tags) };

    // Resolve the optional (frame, perspective) lens up front (both-or-neither,
    // parse, existence) so the bulk retrieval / ranking / min_truth path — all
    // unchanged on the global truth_value — is never entered with a bad lens,
    // and the existence round-trips run ONCE, not per claim.
    let lens = crate::tools::lens::resolve_lens(
        params.frame_id.as_deref(),
        params.perspective_id.as_deref(),
    )?;
    if let Some((frame_id, perspective_id)) = lens {
        crate::tools::lens::validate_lens_exists(&server.pool, frame_id, perspective_id).await?;
    }

    // Hybrid retrieval: dense (claims.embedding) + lexical (content_tsv), RRF-fused.
    // On embedder failure, degrade to lexical-only — which, unlike the old ILIKE
    // fallback, still honors tag/agent scope because it filters in SQL.
    let hits: Vec<HybridHit> = match server
        .embedder
        .search_hybrid_scoped(&params.query, limit, tags_opt, agent_filter)
        .await
    {
        Ok(hits) => hits,
        Err(e) => {
            tracing::warn!(
                error = %e,
                query = %params.query,
                "recall: hybrid embed leg failed; serving scope-honoring lexical-only"
            );
            ClaimRepository::search_lexical_scoped(
                &server.pool,
                &params.query,
                HYBRID_RRF_K,
                limit,
                tags_opt,
                agent_filter,
            )
            .await
            .map_err(internal_error)?
        }
    };

    let mut results = Vec::new();
    for hit in hits {
        if let Ok(Some(claim)) =
            ClaimRepository::get_by_id(&server.pool, ClaimId::from_uuid(hit.claim_id)).await
        {
            let tv = claim.truth_value.value();
            if tv >= min_truth {
                let mut matched_via = Vec::new();
                if hit.dense_similarity.is_some() {
                    matched_via.push("dense".to_string());
                }
                if hit.in_lexical {
                    matched_via.push("lexical".to_string());
                }

                results.push(RecallResult {
                    claim_id: hit.claim_id.to_string(),
                    content: claim.content,
                    truth_value: tv,
                    similarity: hit.dense_similarity.unwrap_or(0.0),
                    rrf_score: hit.rrf_score,
                    matched_via,
                    // Populated by the bounded lens post-pass below (once per
                    // page), keyed by claim_id. None until then.
                    lensed_belief: None,
                });
            }
        }
    }

    // Bounded lens post-pass: when a lens is active, resolve the perspective row
    // + per-frame overrides ONCE for the whole page (the N+1 fix, backlog
    // 9e33ddf7) instead of once per claim, then annotate each already-built
    // result keyed by claim_id. Per-claim degrade-not-fail is preserved: each
    // claim carries its own `Result`, so one malformed claim warns + serves a
    // null lens without aborting the page (spec §8). min_truth/ranking stayed
    // on the global `tv` above and are untouched here.
    if let Some((frame_id, perspective_id)) = lens {
        let claim_ids: Vec<uuid::Uuid> = results
            .iter()
            .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
            .collect();
        match epigraph_engine::belief_query::get_perspective_belief_batch(
            &server.pool,
            &claim_ids,
            frame_id,
            perspective_id,
        )
        .await
        {
            Ok(intervals) => {
                let mut by_claim: std::collections::HashMap<uuid::Uuid, _> =
                    intervals.into_iter().collect();
                for r in &mut results {
                    let Ok(cid) = uuid::Uuid::parse_str(&r.claim_id) else {
                        continue;
                    };
                    match by_claim.remove(&cid) {
                        Some(Ok(interval)) => {
                            r.lensed_belief = Some(LensedBelief::from_interval(
                                frame_id,
                                perspective_id,
                                &interval,
                            ));
                        }
                        Some(Err(e)) => {
                            tracing::warn!(
                                claim_id = %cid,
                                error = %e,
                                "lensed belief compute failed; serving null lens for this claim"
                            );
                        }
                        None => {}
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "lensed belief batch failed; serving null lens for this page"
                );
            }
        }
    }

    success_json(&results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_agent_filter_none_or_blank_is_unscoped() {
        assert_eq!(parse_agent_filter(None).unwrap(), None);
        assert_eq!(parse_agent_filter(Some("")).unwrap(), None);
        assert_eq!(parse_agent_filter(Some("   ")).unwrap(), None);
    }

    #[test]
    fn parse_agent_filter_accepts_valid_uuid() {
        let u = uuid::Uuid::new_v4();
        assert_eq!(parse_agent_filter(Some(&u.to_string())).unwrap(), Some(u));
    }

    #[test]
    fn parse_agent_filter_rejects_bad_uuid_instead_of_silently_dropping() {
        // A present-but-invalid agent_id MUST error. Silently returning None
        // would widen recall to every agent while the caller believes the
        // results are scoped — a scope bypass.
        assert!(parse_agent_filter(Some("not-a-uuid")).is_err());
    }
}
