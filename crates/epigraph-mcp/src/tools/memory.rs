#![allow(clippy::wildcard_imports)]

use rmcp::model::*;

use crate::errors::{db_caller_error, internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::*;

use epigraph_core::{
    AgentId, Claim, ClaimId, Evidence, EvidenceType, Methodology, ReasoningTrace, TraceInput,
    TruthValue,
};
use epigraph_crypto::ContentHasher;
use epigraph_db::{
    ClaimRepository, EvidenceRepository, HybridHit, ReasoningTraceRepository, WorkflowRepository,
};

use crate::embed::{format_pgvector, HYBRID_CANDIDATE_POOL, HYBRID_RRF_K};

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

pub async fn memorize(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: MemorizeParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    // Author = the request's principal (batch H-b, D1); signer = this server.
    let author = server.write_identity(auth, viewer).await?;
    let agent_id = author.agent_id();
    let agent_id_typed = AgentId::from_uuid(agent_id);
    let signer_typed = AgentId::from_uuid(server.signer_agent_id().await?);
    let pub_key = server.signer.public_key();
    let confidence = params.confidence.unwrap_or(0.7).clamp(0.0, 1.0);
    let mut tags = params.tags.unwrap_or_default();

    // Validate the caller's tags BEFORE anything is written (backlog
    // f6310444). `tags` become `claims.labels` via `update_labels` further
    // down, which refuses unexpanded shell syntax at the repo layer — but that
    // call sits after `create_claim_idempotent` and its failure used to be
    // swallowed into a `tracing::warn!`, so `memorize(tags =
    // ["claude-memory", "group:$EPICLAW_GROUP_ID"])` returned SUCCESS with the
    // claim stored and ALL tags dropped. That is strictly worse than the
    // corruption the guard exists to stop: a mislabelled claim is findable by
    // sweeping for `$`, whereas a silently untagged one is indistinguishable
    // from a claim never meant to be grouped — the second consequence the
    // backlog report names. Refusing the call outright makes the failure
    // visible to the caller that can still fix it.
    epigraph_db::reject_unexpanded_labels(&tags).map_err(db_caller_error)?;

    let raw_truth = (confidence * 0.6).clamp(0.01, 0.99);
    let truth_value = TruthValue::clamped(raw_truth);

    let mut claim = Claim::new(params.content.clone(), agent_id_typed, pub_key, truth_value);
    let content_hash = ContentHasher::hash(params.content.as_bytes());
    claim.content_hash = content_hash;
    claim.signature = Some(server.signer.sign(&claim.content_hash));

    // Write-side semantic novelty gate (backlog 1bcaed94, Task 6.4) — same
    // shape as `submit_claim`'s wiring, see `crate::tools::novelty_gate`
    // module docs for the full rationale (content-hash check first so an
    // exact resubmit is unaffected; gate only runs on genuinely new content).
    let is_exact_resubmit = {
        let mut conn = server.pool.acquire().await.map_err(internal_error)?;
        ClaimRepository::find_by_content_hash_and_agent(&mut conn, viewer, &content_hash, agent_id)
            .await
            .map_err(internal_error)?
            .is_some()
    };
    let mut pending_embedding: Option<String> = None;
    if !is_exact_resubmit {
        let novelty_threshold = params
            .novelty_threshold
            .unwrap_or(crate::tools::novelty_gate::DEFAULT_NOVELTY_THRESHOLD);
        if let Some((decision, pgvec)) = crate::tools::novelty_gate::decide(
            &server.pool,
            viewer,
            server.embedder.as_ref(),
            &params.content,
            novelty_threshold,
        )
        .await
        {
            if let crate::tools::novelty_gate::GateDecision::ReturnExisting(existing_id) = decision
            {
                // See submit_claim's identical branch (claims.rs) for the
                // full rationale on both deliberate differences from
                // content-hash dedup: corpus-wide (cross-agent) suppression
                // — with the same epistemic-corroboration-loss consequence
                // for memorize's caller — and this submission's `tags`
                // being dropped since nothing is inserted.
                let existing = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    ClaimId::from_uuid(existing_id),
                )
                .await
                .map_err(internal_error)?
                .ok_or_else(|| {
                    internal_error(format!(
                        "novelty gate: nearest claim {existing_id} vanished before read-back"
                    ))
                })?;
                return success_json(&MemorizeResponse {
                    claim_id: existing_id.to_string(),
                    truth_value: existing.truth_value.value(),
                    embedded: false,
                    tags,
                    belief: None,
                    plausibility: None,
                    pignistic_prob: None,
                });
            }
            pending_embedding = Some(pgvec);
            if matches!(
                decision,
                crate::tools::novelty_gate::GateDecision::InsertFlagged
            ) && !tags.iter().any(|t| t == "near-duplicate")
            {
                tags.push("near-duplicate".to_string());
            }
        }
    }

    // ── THE ONE TRANSACTION THIS SUBMISSION RUNS IN ─────────────────────
    // Identical construction, identical reasoning and the same two defects as
    // `tools::claims::submit_claim` — see the long comment at that call site for
    // why claim + labels + Trace + Evidence + `update_trace_id` + the DS auto-wire
    // must share one author-stamped transaction, and why only the embedding stays
    // outside it.
    let mut tx = crate::claim_helper::begin_author_stamped_tx(server, author, "memorize").await?;

    // Idempotent canonical claim create + AUTHORED verb-edge.
    let (claim, was_created) =
        crate::claim_helper::create_claim_idempotent(&mut tx, viewer, &claim, "memorize").await?;
    let claim_uuid = claim.id.as_uuid();

    // Persist tags as claim labels so `query_claims_by_label` can surface them.
    // Apply on dedup-hit too — labels accumulate non-destructively via the repo's
    // SELECT DISTINCT, so re-memorizing existing content with new tags is additive.
    //
    // The failure is PROPAGATED, not warned-and-dropped. A memory whose tags
    // silently vanished is unfindable by the `query_claims_by_label` call the
    // caller stored it for, so reporting success would be a lie; and because
    // `create_claim_idempotent` dedupes on (content_hash, agent_id) and
    // `update_labels_conn` unions labels, a caller that retries on this error
    // lands on the same claim and gets its tags applied rather than a duplicate.
    // In the transaction now, so a rejected tag set also rolls the claim back
    // rather than leaving an untagged one behind.
    if !tags.is_empty() {
        ClaimRepository::update_labels_conn(&mut tx, claim_uuid, &tags, &[])
            .await
            .map_err(db_caller_error)?;
    }

    // `was_created` alone used to gate the whole provenance block, which is why
    // `memory.rs`'s own doc recorded that a dedup hit "skips Evidence + Trace +
    // update_trace_id + DS + embed". For a claim that is a PRE-EXISTING ORPHAN
    // — committed by a submission whose trace was refused with 42501 — that made
    // every retry return `{"embedded": false}` and HTTP success for a row with
    // no provenance at all, so the retry a caller performs to repair the row
    // could not repair it. The provenance half is now gated on
    // `was_created || claim.trace_id.is_none()`, and the embed below on
    // `was_created || <the canonical row has no vector>` — an orphan lost its
    // embedding to the same refusal, and repairing provenance while leaving
    // `embedding IS NULL` leaves the claim unrecallable. Only DS auto-wire stays
    // gated on `was_created` alone, because re-running it on an existing claim
    // would combine the same mass twice.
    let needs_provenance = was_created || claim.trace_id.is_none();
    if needs_provenance {
        let evidence_text = if tags.is_empty() {
            "Memory stored via MCP memorize tool".to_string()
        } else {
            format!("Memory [{}] stored via MCP memorize tool", tags.join(", "))
        };
        let evidence_hash = ContentHasher::hash(evidence_text.as_bytes());
        // `Evidence::agent_id` is `evidence.signer_id`: the SIGNER of the
        // signature below, which is this server, not the author.
        let mut evidence = Evidence::new(
            signer_typed,
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

        ReasoningTraceRepository::create(&mut *tx, &trace, claim.id)
            .await
            .map_err(internal_error)?;
        EvidenceRepository::create(&mut *tx, &evidence)
            .await
            .map_err(internal_error)?;
        ClaimRepository::update_trace_id_conn(&mut tx, claim.id, trace.id)
            .await
            .map_err(internal_error)?;
    }

    // DS auto-wire: FIRST-CREATE ONLY (re-running would combine the same mass
    // twice). The embed below is deliberately NOT gated the same way — see the
    // comment there and `tools::claims::submit_claim`, which carries the long
    // form of both halves.
    //
    // IN THIS TRANSACTION, BEFORE COMMIT, and a failure fails the call: the
    // claim and its `claim_frames` / `mass_functions` / cached-belief
    // `UPDATE claims` land together or not at all. It used to run post-commit and
    // warn-only, which returned success with `belief: null` over a committed claim
    // with no BBA. `memorize` passes `persist_truth_from_pignistic = false` —
    // unlike `submit_claim` it does not derive a `truth_value` from the BBA, so
    // there is no second write to keep consistent with it.
    let ds = if was_created {
        Some(
            crate::claim_helper::wire_ds_for_new_claim_in_tx(
                &mut tx,
                viewer,
                agent_id,
                claim_uuid,
                ds_auto::DsAutoInput {
                    confidence,
                    weight: 0.6,
                    supports: true,
                    evidence_type: None,
                },
                /* persist_truth_from_pignistic */ false,
                "memorize",
            )
            .await?,
        )
    } else {
        // Option A: a dedup hit. AUTHORED already fired in the helper, and Trace
        // + Evidence + `update_trace_id` ran above IF and only if the canonical
        // claim had no trace. No DS: it would double-count.
        None
    };

    // COMMIT. Everything below this line is post-commit and best-effort.
    tx.commit().await.map_err(internal_error)?;

    // EMBEDDING. `was_created` OR "the canonical row is missing its vector" —
    // the repaired orphan is exactly the row for which those differ, and
    // `submit_claim` carries the full argument. Telemetry and sealed rows are
    // excluded inside `claim_text_if_embedding_missing`; an unreadable answer is
    // treated as "do not embed" and left to the maintenance backfill.
    let embed_text: Option<String> = if was_created {
        Some(params.content.clone())
    } else {
        match ClaimRepository::claim_text_if_embedding_missing(&server.pool, viewer, claim_uuid)
            .await
        {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(
                    claim_id = %claim_uuid,
                    "could not read whether the canonical claim still needs an embedding; \
                     skipping the repair embed: {e}"
                );
                None
            }
        }
    };

    // On an AUTHOR-STAMPED connection, reusing the novelty gate's vector when
    // there is one. Identical construction and identical reasoning to
    // `tools::claims::submit_claim`; `claim_helper::embed_claim_author_stamped`
    // carries the long form — in short, the `UPDATE claims SET embedding` is
    // refused on the unstamped pool and the refusal is silent because the embed
    // is best-effort.
    let embedded = match embed_text {
        None => false,
        Some(text) => {
            crate::claim_helper::embed_claim_author_stamped(
                server,
                agent_id,
                claim_uuid,
                &text,
                pending_embedding.take(),
                "memorize",
            )
            .await
        }
    };

    // A dedup hit reports the CANONICAL truth, not this call's raw value.
    let final_truth = if was_created {
        raw_truth
    } else {
        claim.truth_value.value()
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
    viewer: &epigraph_db::visibility::Viewer,
    params: RecallParams,
) -> Result<CallToolResult, McpError> {
    // Generate the query embedding ONCE up front. Reused for both the claims
    // dense leg and (when requested) the workflows ANN leg — recall must not
    // re-embed the same query text twice (see `recall_post_embed`/workflows
    // leg below). `None` on embedder failure degrades both legs: claims fall
    // back to lexical-only (existing behavior) and the workflows leg is
    // skipped entirely (there is no lexical fallback for goal_embedding).
    let pgvec_opt = match server.embedder.generate(&params.query).await {
        Ok(v) => Some(format_pgvector(&v)),
        Err(e) => {
            tracing::warn!(
                error = %e,
                query = %params.query,
                "recall: embedder failed; degrading to lexical-only claims leg, no workflows leg"
            );
            None
        }
    };

    recall_post_embed(server, viewer, params, pgvec_opt).await
}

/// Post-embedding pipeline: shared by `recall` and the
/// `__test_only::recall_with_pgvec` entry point that lets integration tests
/// skip the OpenAI embedder (no API key available in CI / sandbox), mirroring
/// `workflows.rs`'s `find_workflow`/`find_workflow_post_embed` split.
///
/// Recomputes `limit`/`min_truth` from `params` internally so the two
/// extraction sites cannot drift.
async fn recall_post_embed(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: RecallParams,
    pgvec_opt: Option<String>,
) -> Result<CallToolResult, McpError> {
    let limit = params.limit.unwrap_or(10).clamp(1, 50);
    let min_truth = params.min_truth.unwrap_or(0.3);
    let agent_filter = parse_agent_filter(params.agent_id.as_deref()).map_err(invalid_params)?;
    let offset = params.offset.unwrap_or(0).max(0);
    let tags = params.tags;
    let tags_opt: Option<&[String]> = if tags.is_empty() { None } else { Some(&tags) };

    // Theme scope (backlog c95a2509). Resolved up front, and fails closed on
    // every ambiguity — see `themes::resolve_theme_selector`. Sharing that
    // resolver with `get_theme` is what makes `theme_label` mean the same thing
    // on both tools.
    let theme = crate::tools::themes::resolve_theme_selector(
        &server.pool,
        viewer,
        params.theme_id.as_deref(),
        params.theme_label.as_deref(),
    )
    .await?;
    let theme_filter = theme.as_ref().map(|t| t.id);

    // The workflows leg is the fourth candidate-producing surface on this tool,
    // and it is the one a theme filter CANNOT be pushed into: `workflows` rows
    // carry no `theme_id`, so a theme-scoped recall that still ran that leg
    // would hand back unthemed workflow hits inside a result the caller asked
    // to be confined to one theme. Rejecting is chosen over silently skipping
    // the leg because a caller who passed `include_workflows=true` asked for
    // something this combination cannot deliver, and a quietly-dropped option
    // is the failure mode the `since`-window work already had to stamp out on
    // this surface.
    if theme_filter.is_some() && params.include_workflows {
        return Err(invalid_params(
            "theme_id/theme_label cannot be combined with include_workflows=true: workflows carry \
             no theme_id, so the workflow hits could not be confined to the theme. Drop one.",
        ));
    }

    // Paging and the workflows leg are likewise incompatible. The two hit lists
    // are disjoint id-spaces RRF-merged in Rust after the SQL page; an offset
    // applied to the claims leg alone would re-serve the same top workflows on
    // every page, and there is no ranking continuity to offset them by.
    if offset > 0 && params.include_workflows {
        return Err(invalid_params(
            "offset cannot be combined with include_workflows=true: offset pages the claims \
             ranking, and the workflows leg has no page-consistent counterpart, so the same \
             workflows would reappear on every page.",
        ));
    }

    // Resolve the optional (frame, perspective) lens up front (both-or-neither,
    // parse, existence) so the bulk retrieval / ranking / min_truth path — all
    // unchanged by the lens (retrieval and ranking stay on similarity/RRF, and
    // min_truth stays on the UNLENSED belief; backlog 14b98adc moved it from
    // `truth_value` to the global DS cache, not to a per-perspective value) —
    // is never entered with a bad lens,
    // and the existence round-trips run ONCE, not per claim.
    // Same up-front-validation rule as the lens below: a malformed
    // `diversity_radius` is rejected BEFORE any retrieval runs, so a caller who
    // mistyped it gets told instead of paying for a page and then losing it.
    let diversity_radius = params
        .diversity_radius
        .map(crate::types::validate_diversity_radius)
        .transpose()
        .map_err(invalid_params)?;

    let lens = crate::tools::lens::resolve_lens(
        params.frame_id.as_deref(),
        params.perspective_id.as_deref(),
    )?;
    if let Some((frame_id, perspective_id)) = lens {
        crate::tools::lens::validate_lens_exists(&server.pool, viewer, frame_id, perspective_id)
            .await?;
    }

    // Hybrid retrieval: dense (claims.embedding) + lexical (content_tsv), RRF-fused.
    // On embedder failure (pgvec_opt is None), degrade to lexical-only — which,
    // unlike the old ILIKE fallback, still honors tag/agent scope because it
    // filters in SQL.
    //
    // `params.since` is threaded into BOTH branches: the window must not
    // silently widen just because the embedder happened to be down.
    //
    // `theme_filter` and `offset` are threaded into BOTH branches for the same
    // reason: a scope that held on the hybrid path but not on the degrade path
    // would widen to the whole corpus precisely when the embedder is down.
    let hits: Vec<HybridHit> = match pgvec_opt.as_deref() {
        Some(pgvec) => ClaimRepository::search_hybrid_scoped_since_in_theme(
            &server.pool,
            viewer,
            pgvec,
            &params.query,
            HYBRID_CANDIDATE_POOL,
            HYBRID_RRF_K,
            limit,
            offset,
            tags_opt,
            agent_filter,
            params.since,
            theme_filter,
        )
        .await
        .map_err(internal_error)?,
        None => ClaimRepository::search_lexical_scoped_since_in_theme(
            &server.pool,
            viewer,
            &params.query,
            HYBRID_RRF_K,
            limit,
            offset,
            tags_opt,
            agent_filter,
            params.since,
            theme_filter,
        )
        .await
        .map_err(internal_error)?,
    };

    // Captured BEFORE the min_truth / exclude_contested post-filters shrink the
    // page. `hits.len()` is what SQL could supply for this window, so
    // `== limit` is the exact "another page may exist" signal; the post-filtered
    // `results.len()` is not (a page filtered down to zero is not the end of the
    // walk).
    let sql_page_len = hits.len() as i64;

    // Workflows ANN leg (opt-in, backlog 88a09fd2 / Task 6.3). Only runs when
    // BOTH include_workflows=true AND the query embedding succeeded — there is
    // no lexical fallback for workflows.goal_embedding, so on embedder failure
    // this leg is silently absent rather than serving stale/irrelevant rows.
    // Ranked by cosine distance (best first), independent of the claims dense+
    // lexical fusion above; RRF-merged with the claims ranking below using the
    // SAME k constant/formula `search_hybrid_scoped` already uses in SQL for
    // its dense+lexical fusion (`crate::embed::HYBRID_RRF_K`), just applied in
    // Rust across two disjoint (claim vs workflow) ranked lists instead of two
    // legs of one list.
    let workflow_hits: Vec<epigraph_db::WorkflowGoalEmbeddingHit> = if params.include_workflows {
        match pgvec_opt.as_deref() {
            Some(pgvec) => WorkflowRepository::search_by_goal_embedding_since(
                &server.pool,
                pgvec,
                HYBRID_CANDIDATE_POOL,
                params.since,
            )
            .await
            .map_err(internal_error)?,
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };

    // RRF-merge: claims already carry a fused `rrf_score` from the SQL dense+
    // lexical fusion — that score is used ONLY to establish the claims'
    // relative rank order here (rank 1 = best), then discarded. Each item's
    // merged score is a single `1/(k + rank)` term against its own list;
    // claims and workflows are disjoint id-spaces so nothing sums across
    // lists (unlike the dense+lexical fusion, where the SAME claim can appear
    // in both legs and its two terms sum).
    #[derive(Clone)]
    enum MergedHit {
        Claim(HybridHit),
        Workflow(epigraph_db::WorkflowGoalEmbeddingHit),
    }
    let mut merged: Vec<(f64, MergedHit)> = Vec::with_capacity(hits.len() + workflow_hits.len());
    for (idx, hit) in hits.iter().enumerate() {
        let rank = idx as f64 + 1.0;
        merged.push((
            1.0 / (HYBRID_RRF_K as f64 + rank),
            MergedHit::Claim(hit.clone()),
        ));
    }
    for (idx, hit) in workflow_hits.iter().enumerate() {
        let rank = idx as f64 + 1.0;
        merged.push((
            1.0 / (HYBRID_RRF_K as f64 + rank),
            MergedHit::Workflow(hit.clone()),
        ));
    }
    merged.sort_by(|a, b| b.0.total_cmp(&a.0));
    merged.truncate(limit as usize);

    // Backlog 14b98adc: `min_truth` gates on the DS pignistic probability, not
    // on `claims.truth_value` — which no DS write path refreshes, so a claim
    // refuted by epistemic edges kept passing a gate set against its pre-edge
    // authored value. Resolved in ONE round-trip for the page, BEFORE the loop;
    // a per-hit read would add an N+1 on top of the `get_by_id` below. Only
    // claim hits are looked up: workflows are a different id-space with no DS
    // cache. Degrade-not-fail — a failed lookup yields an empty map, and every
    // hit then falls back to the `truth_value` already in hand.
    let belief_by_claim = {
        let ids: Vec<uuid::Uuid> = merged
            .iter()
            .filter_map(|(_, h)| match h {
                MergedHit::Claim(c) => Some(c.claim_id),
                MergedHit::Workflow(_) => None,
            })
            .collect();
        match ClaimRepository::effective_belief_batch(&server.pool, viewer, &ids).await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "DS belief batch failed; min_truth falls back to claims.truth_value for this page"
                );
                std::collections::HashMap::new()
            }
        }
    };

    let mut results = Vec::new();
    for (merged_rrf_score, merged_hit) in merged {
        match merged_hit {
            MergedHit::Claim(hit) => {
                if let Ok(Some(claim)) = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    ClaimId::from_uuid(hit.claim_id),
                )
                .await
                {
                    let tv = claim.truth_value.value();
                    // Absent key == invisible to this viewer / deleted between
                    // the ANN page and this read. Falling back to the `tv`
                    // already in hand keeps a claim with no DS state
                    // byte-identical to pre-fix behaviour.
                    let score = belief_by_claim.get(&hit.claim_id).copied().unwrap_or(tv);
                    if score >= min_truth {
                        let mut matched_via = Vec::new();
                        if hit.dense_similarity.is_some() {
                            matched_via.push("dense".to_string());
                        }
                        if hit.in_lexical {
                            matched_via.push("lexical".to_string());
                        }

                        // Without a workflows leg (include_workflows=false, the
                        // default), `merged_rrf_score` is 1/(k+rank) where rank is
                        // the claim's position in `hits` — the SAME ordering
                        // `hit.rrf_score` already produced (hits is sorted by
                        // rrf_score DESC in SQL). Reporting hit.rrf_score (not
                        // merged_rrf_score) here keeps the field byte-identical to
                        // pre-Task-6.3 output for claims-only recall.
                        let _ = merged_rrf_score;
                        results.push(RecallResult {
                            claim_id: hit.claim_id.to_string(),
                            content: claim.content,
                            truth_value: tv,
                            belief_score: score,
                            similarity: hit.dense_similarity.unwrap_or(0.0),
                            rrf_score: hit.rrf_score,
                            matched_via,
                            // Populated by the bounded lens post-pass below (once
                            // per page, backlog 9e33ddf7's N+1 fix), keyed by
                            // claim_id. None until then.
                            lensed_belief: None,
                            result_type: None,
                            // Populated by the bounded dispute post-pass below
                            // (backlog 34d3400d), keyed by claim_id.
                            dispute_count: 0,
                            is_contested: false,
                            contesting_claim_ids: Vec::new(),
                            // The claim's real creation instant, straight off
                            // the row `get_by_id` already fetched — no extra
                            // round-trip, and specifically NOT `updated_at`,
                            // which a belief recompute rewrites corpus-wide.
                            created_at: Some(claim.created_at),
                        });
                    }
                }
            }
            MergedHit::Workflow(hit) => {
                if hit.truth_value >= min_truth {
                    results.push(RecallResult {
                        claim_id: hit.workflow_id.to_string(),
                        content: hit.content,
                        truth_value: hit.truth_value,
                        // A workflow row is not a claim: it has no DS cache to
                        // read, so the gate value IS its truth_value. Reported
                        // rather than omitted so the field means the same thing
                        // ("what min_truth compared against") on every row.
                        belief_score: hit.truth_value,
                        similarity: hit.similarity,
                        rrf_score: merged_rrf_score,
                        // Workflows aren't claims, so the batch lens post-pass's
                        // claim_id-keyed lookup below never matches a workflow_id
                        // — lensed_belief stays None for workflow-origin results,
                        // which is correct (lensing is a claim-belief concept).
                        matched_via: vec!["dense".to_string()],
                        lensed_belief: None,
                        result_type: Some("workflow".to_string()),
                        // Dispute is a claim-belief concept; workflows are not
                        // claims, so the post-pass below skips them and these
                        // stay at their uncontested defaults.
                        dispute_count: 0,
                        is_contested: false,
                        contesting_claim_ids: Vec::new(),
                        // The workflow's OWN `workflows.created_at`, selected
                        // by the ANN leg. Not `Utc::now()`: a workflow row is
                        // not a claim, and inventing a timestamp to satisfy
                        // the type would make every workflow the newest thing
                        // in the corpus and sort it first under any recency
                        // preference — self-consistent, invisible on
                        // inspection, and false.
                        created_at: Some(hit.created_at),
                    });
                }
            }
        }
    }

    // Bounded lens post-pass: when a lens is active, resolve the perspective row
    // + per-frame overrides ONCE for the whole page (the N+1 fix, backlog
    // 9e33ddf7) instead of once per claim, then annotate each already-built
    // result keyed by claim_id. Per-claim degrade-not-fail is preserved: each
    // claim carries its own `Result`, so one malformed claim warns + serves a
    // null lens without aborting the page (spec §8). min_truth/ranking stayed
    // on the UNLENSED `score` above (the global DS cache, backlog 14b98adc) and
    // are untouched here: a lens annotates, it does not gate.
    if let Some((frame_id, perspective_id)) = lens {
        let claim_ids: Vec<uuid::Uuid> = results
            .iter()
            .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
            .collect();
        match epigraph_engine::belief_query::get_perspective_belief_batch(
            &server.pool,
            viewer,
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

    // Bounded dispute post-pass (backlog 34d3400d): one batched follow-up query
    // over the ids this page already returned, NOT a join inside the ANN/RRF
    // SQL — the signal must not put the HNSW plan at risk. Same shape as the
    // lens post-pass above: once per page, keyed by claim_id, degrade-not-fail
    // (a failed dispute lookup serves an unannotated page rather than failing
    // the recall).
    //
    // Ranking is deliberately untouched: per MemSyco-Bench the failure mode is
    // MISSING signal, not mis-ordering, so dispute informs the caller without
    // re-ranking behind their back.
    {
        let claim_ids: Vec<uuid::Uuid> = results
            .iter()
            .filter(|r| r.result_type.is_none()) // workflows aren't claims
            .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
            .collect();
        match ClaimRepository::dispute_batch(&server.pool, viewer, &claim_ids).await {
            Ok(mut by_claim) => {
                for r in &mut results {
                    let Ok(cid) = uuid::Uuid::parse_str(&r.claim_id) else {
                        continue;
                    };
                    // Absent key == uncontested (repo contract), so the
                    // default 0/false/[] below is the correct reading.
                    if let Some(d) = by_claim.remove(&cid) {
                        r.dispute_count = d.dispute_count.max(0) as u32;
                        r.is_contested = d.dispute_count > 0;
                        r.contesting_claim_ids = d.contesting_claim_ids;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "dispute batch failed; serving page without dispute annotations"
                );
            }
        }

        // Post-filter, applied AFTER ranking and truncation — so a page whose
        // hits are contested comes back short rather than back-filling with
        // worse-ranked material. This matches how `min_truth` already behaves
        // (merged.truncate(limit) runs before the min_truth drop above).
        if params.exclude_contested {
            results.retain(|r| !r.is_contested);
        }
    }

    // Diversity post-filter (backlog a9397e8a): greedy MMR over the ranked
    // page, dropping any hit within `diversity_radius` cosine distance of a
    // hit already kept above it.
    //
    // Runs BEFORE the audit block below, which derives `returned_claim_ids`
    // from `results`. An audit row naming claims the caller never received
    // would be a false disclosure record, and this is the only post-filter on
    // this surface that runs late enough to create one.
    //
    // Claim ids only. A workflow hit (`result_type = Some("workflow")`) carries
    // a `workflows.id` in `claim_id` and has no row in `claims`, so it can
    // neither be measured nor suppress anything — `greedy_diversity_keep`'s
    // keep-on-unmeasurable rule covers it, and the filter below re-admits it
    // explicitly rather than relying on a uuid from a foreign id-space failing
    // to collide.
    if let Some(radius) = diversity_radius {
        let claim_ids: Vec<uuid::Uuid> = results
            .iter()
            .filter(|r| r.result_type.is_none())
            .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
            .collect();
        // `recall`'s claims legs search `claims.embedding`, the 1536d column,
        // on both the hybrid and the lexical-fallback path — there is no
        // runtime dim choice here, unlike `recall_with_context`.
        match ClaimRepository::pairwise_cosine_distance_at_dim(
            &server.pool,
            viewer,
            &claim_ids,
            radius,
            1536,
        )
        .await
        {
            Ok(pairs) => {
                // The repo already applied the `< radius` cut in SQL, so every
                // returned pair IS a too-similar pair.
                let too_similar: std::collections::HashSet<(uuid::Uuid, uuid::Uuid)> = pairs
                    .iter()
                    .map(|p| crate::types::unordered_pair(p.claim_a, p.claim_b))
                    .collect();
                let keep: std::collections::HashSet<uuid::Uuid> =
                    crate::types::greedy_diversity_keep(&claim_ids, &too_similar)
                        .into_iter()
                        .collect();
                results.retain(|r| {
                    // Workflow hits, and any row whose id will not parse, are
                    // outside the measured id-space entirely.
                    if r.result_type.is_some() {
                        return true;
                    }
                    match uuid::Uuid::parse_str(&r.claim_id) {
                        Ok(id) => keep.contains(&id),
                        Err(_) => true,
                    }
                });
            }
            Err(e) => {
                // Degrade-not-fail, matching the lens and dispute post-passes
                // above: serve the undiversified page rather than lose results
                // already retrieved. Deliberately NOT a silent success — a
                // caller reading the log can tell a page that was not filtered
                // from one that had nothing to filter.
                tracing::warn!(
                    error = %e,
                    "diversity filter failed; serving the page without it"
                );
            }
        }
    }

    // Id is minted HERE, not read back from the insert: the write is spawned,
    // so the response must be able to cite the event without awaiting it.
    let event_id = uuid::Uuid::new_v4();

    // Recall audit log (backlog 8cbffa0e). Fire-and-forget AFTER the response
    // is fully built: an audit-write failure must never fail, delay, or alter
    // a recall that already has its results — same best-effort contract as
    // post-commit embedding. Spawned, so the caller does not wait on it.
    {
        let returned_claim_ids: Vec<uuid::Uuid> = results
            .iter()
            .filter(|r| r.result_type.is_none()) // claims only; workflows are a different id-space
            .filter_map(|r| uuid::Uuid::parse_str(&r.claim_id).ok())
            .collect();
        // THE AUDIT ROW'S IDENTITY IS THE REQUEST PRINCIPAL, NOT THE PROCESS.
        // This was `server.agent_id()`, which resolves the agent for the
        // SIGNER'S PUBLIC KEY — one agent per process — while
        // `get_recall_events` filters with the viewer built from the
        // per-request `AuthContext`. On stdio the two are the same value and
        // nothing moves. On the HTTP transport they are not, and owning the row
        // from the process identity would misattribute it AND suppress it from
        // the agent that authored it.
        //
        // Nothing here borrows the request, so everything the write needs is
        // assembled as owned values and the group lookup happens INSIDE the
        // spawn — `058_recall_events.sql`'s table comment is the contract
        // ("never blocks a recall"), and resolving a personal group is a pool
        // acquire plus a SELECT plus, on an agent's first recall, a mint.
        let principal = viewer.principal();
        let query_text = params.query.clone();
        let query_pgvector = pgvec_opt.clone();
        let params_json = serde_json::json!({
            "limit": limit,
            "min_truth": min_truth,
            "tags": tags,
            "agent_filter": agent_filter,
            "include_workflows": params.include_workflows,
            "exclude_contested": params.exclude_contested,
            // A retrieval whose temporal window cannot be reconstructed from
            // its audit row is an unauditable retrieval: the same query with
            // and without a window returns different sets, so the window is
            // part of what was asked.
            "since": params.since,
            // Same argument for the theme scope and the page offset: the same
            // query pinned to a theme, or taken at offset 20, returns a
            // different set, so both are part of what was asked and a
            // retrieval whose scope cannot be reconstructed from its audit row
            // is an unauditable retrieval. The RESOLVED theme id is logged, not
            // the raw selector, so a `theme_label` lookup stays reconstructible
            // after the label is renamed.
            "theme_id": theme_filter,
            "offset": offset,
            // Recorded for the same reason as `since` and `theme_id`: it
            // changes WHICH claims came back, so a retrieval whose diversity
            // cut cannot be reconstructed from its audit row is an unauditable
            // retrieval. `epistemic_partition` is deliberately NOT recorded —
            // it regroups the response without changing the set.
            "diversity_radius": params.diversity_radius,
        });
        let scoped = server.scoped.clone();
        tokio::spawn(async move {
            // Unresolvable ⇒ DROP, never widen, and never mint (#493). The row
            // is written on the principal-stamped transaction that resolved its
            // owner; see `recall::write_recall_audit`.
            let written =
                super::recall::write_recall_audit(scoped.as_ref(), principal, |owner_group_id| {
                    epigraph_db::NewRecallEvent {
                        id: event_id,
                        agent_id: principal,
                        tool: "recall".to_string(),
                        query_text,
                        query_pgvector,
                        params: params_json,
                        returned_claim_ids,
                        owner_group_id: Some(owner_group_id),
                    }
                })
                .await;
            match written {
                Ok(_) => {}
                Err(super::recall::RecallAuditNotWritten::Unresolved(e)) => {
                    tracing::warn!(reason = %e, "recall audit skipped rather than widened");
                }
                Err(super::recall::RecallAuditNotWritten::Write(e)) => tracing::warn!(
                    error = %e,
                    "recall audit log failed; recall itself unaffected"
                ),
            }
        });
    }

    // Epistemic partitioning (backlog e7736ff6). Runs LAST, on the page every
    // other stage has already settled:
    //
    //  * AFTER the dispute post-pass — `is_contested` is `false` on every
    //    result until that pass runs, so bucketing any earlier would leave
    //    `open_question` permanently empty while every happy-path test still
    //    passed.
    //  * AFTER `exclude_contested`'s retain — partitioning rows that are about
    //    to be dropped would be both wasted and misleading.
    //  * AFTER the audit block — that block derives `returned_claim_ids` from
    //    `results`, and this consumes `results` by value.
    //
    // The score is the SAME `truth_value` `min_truth` gates on above, read out
    // of the already-built result rather than recomputed, so the threshold and
    // the gate cannot come to disagree about what a claim's belief is.
    let (results, epistemic_partition) =
        crate::types::split_epistemic(results, params.epistemic_partition, |r| {
            (r.truth_value, r.is_contested)
        });

    success_json(&RecallEnvelope {
        results,
        epistemic_partition,
        recall_event_id: Some(event_id.to_string()),
        // Echoed only when a theme scope or a page offset was actually
        // requested, so an unscoped recall's response stays byte-identical to
        // what it produced before this feature existed.
        theme_scope: theme.as_ref().map(|t| ThemeScopeOut {
            theme_id: t.id.to_string(),
            label: t.label.clone(),
            member_count: t.member_count,
        }),
        paging: (offset > 0 || theme_filter.is_some()).then(|| RecallPaging {
            offset,
            limit,
            sql_page_len,
            next_offset: offset + sql_page_len,
            more_available: sql_page_len == limit,
        }),
    })
}

/// The theme a recall was confined to, echoed back so a theme-scoped retrieval
/// is self-describing rather than opaque: the caller can see WHICH theme the
/// label resolved to, and `member_count` bounds how far a walk can go.
#[derive(serde::Serialize)]
struct ThemeScopeOut {
    theme_id: String,
    label: String,
    /// Live count of `is_current` claims in the theme — the ceiling on what a
    /// limit/offset walk can enumerate, before `min_truth` and the lexical /
    /// dense predicates cut it further.
    member_count: i64,
}

/// Paging state for a theme-scoped or offset recall.
///
/// `more_available` is derived from `sql_page_len`, the size of the page SQL
/// produced, NOT from `results.len()`. `min_truth` and `exclude_contested` run
/// in Rust after the SQL page, so a fully-filtered page has `results == []`
/// while more pages remain. Treating an empty `results` as the end of the walk
/// would silently truncate it.
#[derive(serde::Serialize)]
struct RecallPaging {
    offset: i64,
    limit: i64,
    sql_page_len: i64,
    next_offset: i64,
    more_available: bool,
}

/// Response envelope carrying the audit-event id alongside the hits, so an
/// agent can cite which retrieval fed a downstream decision (composes with the
/// PROV-O layer from PR #334).
#[derive(serde::Serialize)]
struct RecallEnvelope {
    /// The flat RRF-ranked page. `None` — and therefore absent from the JSON —
    /// exactly when `epistemic_partition=true` replaced it with the bucketed
    /// shape below. `Some(vec![])` still serializes as `"results": []`, so a
    /// zero-hit recall is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<RecallResult>>,
    /// The same page regrouped by epistemic status (backlog e7736ff6).
    /// Present only when the caller asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    epistemic_partition: Option<crate::types::EpistemicPartition<RecallResult>>,
    /// Same contract as `RecallWithContextResponse::recall_event_id`: the id the
    /// audit row is written under, minted before an asynchronous best-effort
    /// write, so it does not prove a row exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    recall_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    theme_scope: Option<ThemeScopeOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paging: Option<RecallPaging>,
}

#[doc(hidden)]
pub mod __test_only {
    use super::{recall_post_embed, EpiGraphMcpFull, McpError, RecallParams};
    use rmcp::model::CallToolResult;

    /// Integration-test entry point that skips the OpenAI embedder.
    ///
    /// Tests cannot call the real embedder (no API key in CI / sandbox), so
    /// they pre-format a known pgvector literal and dispatch directly into
    /// the post-embed pipeline. This is the same code `recall` runs after
    /// `embedder.generate`. Mirrors `workflows.rs`'s
    /// `__test_only::find_workflow_with_pgvec`.
    pub async fn recall_with_pgvec(
        server: &EpiGraphMcpFull,
        viewer: &epigraph_db::visibility::Viewer,
        params: RecallParams,
        pgvec: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        recall_post_embed(server, viewer, params, pgvec).await
    }
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
