//! `consolidate_claims` MCP tool (backlog 44b19521 / design F1).
//!
//! N→1 memory consolidation. The caller supplies the synthesized content —
//! the server never invokes an LLM, matching `epigraph-ingest-executor`'s
//! division of labour (agent-side synthesis, server-side storage).

use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::ConsolidateClaimsParams;

use epigraph_db::{ClaimRepository, ConsolidateMode};

#[derive(Debug, Serialize)]
struct ConsolidateResponse {
    merged_claim_id: String,
    superseded_ids: Vec<String>,
    edges_migrated: u64,
    edges_deduped: u64,
    embedded: bool,
    /// `true` when an identical merged claim by this agent already existed and
    /// was returned rather than inserted twice.
    already_existed: bool,
    /// The administrative cascade that moved the sources' edges (migration
    /// 117): applied, deferred or failed, with its `security_events` row. Absent
    /// on the idempotent return, which wrote nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    cascade: Option<epigraph_engine::admin_cascade::CascadeStatus>,
}

pub async fn consolidate_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ConsolidateClaimsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let acting = server.write_identity(auth, viewer).await?;
    let acting_agent_id = acting.agent_id();

    let source_ids = params
        .source_claim_ids
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<Result<Vec<_>, _>>()?;

    let mode = ConsolidateMode::parse(&params.mode).map_err(|bad| {
        invalid_params(format!("unknown mode {bad:?}; want merge|abstract|rewrite"))
    })?;

    // Default confidence: the strongest source discounted slightly, so a merge
    // never claims more certainty than its best input.
    let merged_truth = match params.confidence {
        Some(c) => c.clamp(0.0, 1.0),
        None => {
            let mut best: f64 = 0.0;
            for id in &source_ids {
                if let Ok(Some(c)) = ClaimRepository::get_by_id(
                    &server.pool,
                    viewer,
                    epigraph_core::ClaimId::from_uuid(*id),
                )
                .await
                {
                    best = best.max(c.truth_value.value());
                }
            }
            (best * 0.95).clamp(0.0, 1.0)
        }
    };

    // ONE transaction stamped from the ACTING agent — the author of the merged
    // row, and the identity whose writable set migration 077's `WITH CHECK` asks
    // about for the merged INSERT and for the sources' retirement UPDATE.
    //
    // On the unstamped pool this was refused for every caller on a cleanly
    // migrated schema (`new row violates row-level security policy for table
    // "claims"` at the merged INSERT) — loud and atomic, but unavailable for its
    // whole population. It is safe to stamp because it is safe to retry: the
    // merge is one transaction, and a retried merge hits the `(content_hash,
    // agent_id)` idempotent return rather than inserting a second row.
    //
    // Who it still refuses, by construction and loudly: a source owned by a
    // group the acting agent cannot write. A PRIVATE foreign source is invisible
    // under `claims_tenancy`'s USING, so the `FOR UPDATE` lock finds fewer rows
    // than it was given and the merge refuses with NotFound before writing; a
    // PUBLIC foreign source is visible but its retirement UPDATE fails `WITH
    // CHECK`, which aborts the whole transaction — the merged row included.
    let mut tx =
        crate::claim_helper::begin_author_stamped_tx(server, acting, "consolidate_claims").await?;
    //
    // Migration 117: this is the consolidation's ACT only (the merged claim,
    // the retired sources, the `supersedes` edges). The sources' other edges
    // belong to whoever asserted them; moving them is the administrative
    // cascade below.
    let result = ClaimRepository::consolidate_act_conn(
        &mut tx,
        &source_ids,
        &params.merged_content,
        merged_truth,
        mode,
        &params.reason,
        acting_agent_id,
    )
    .await
    .map_err(|e| match e {
        // The cross-group refusal (PR-16, plan §4.6) is a CLIENT error: the
        // caller asked for a merge whose sources span two owner groups, and
        // the answer is "pick sources within one group", not "the server
        // failed". `internal_error` would render it as INTERNAL_ERROR and an
        // agent would retry it forever. The HTTP twin is 409
        // (`DbError::Conflict` -> `ApiError::Conflict`); INVALID_PARAMS is the
        // nearest JSON-RPC code that carries the message to the caller.
        epigraph_db::DbError::Conflict { ref reason } => invalid_params(reason.clone()),
        // Migration 105's refusal from the all-public branch's owner lookup
        // (the acting agent's personal membership is revoked, or its did_key
        // squatted): a denial, INVALID_REQUEST, as on every other write tool.
        other if other.is_personal_group_refusal() => crate::errors::db_caller_error(other),
        other => internal_error(other),
    })?;
    // The cascade's trigger, and its administrative session acquired BEFORE
    // the act commits (or the deferral recorded in the act's own transaction).
    // The idempotent return wrote nothing, so it has no cascade.
    let trigger = epigraph_engine::admin_cascade::CascadeTrigger {
        sources: source_ids.clone(),
        ..epigraph_engine::admin_cascade::CascadeTrigger::new(
            epigraph_engine::admin_cascade::CascadeCause::Consolidate,
            Some(acting_agent_id),
            crate::tools::supersede::oauth_principal(auth),
            result.merged_id,
            None,
        )
    };
    let (mut session, deferred) = if result.already_existed {
        (None, None)
    } else {
        let (session, status) =
            crate::tools::supersede::admin_session_or_deferral(server, &mut tx, &trigger).await?;
        (session, Some(status))
    };
    // The idempotent-return branch rolled its SAVEPOINT back and wrote nothing;
    // committing the (then empty) outer transaction is harmless and uniform.
    tx.commit()
        .await
        .map_err(|e| internal_error(format!("consolidate_claims: could not commit: {e}")))?;

    // THE CASCADE (migration 117), with administrative authority on the
    // maintenance connection: re-point the sources' live edges onto the merged
    // claim and retract the redundant copies, audited atomically. Best-effort:
    // the merge has committed.
    let cascade = match (session.as_mut(), deferred) {
        (Some(session), _) => Some(
            epigraph_engine::admin_cascade::apply_after_consolidate(session.conn(), &trigger).await,
        ),
        (None, status) => status,
    };
    let touched_count = |key: &str| -> u64 {
        cascade
            .as_ref()
            .and_then(|c| c.touched.as_ref())
            .and_then(|t| t.get(key))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };

    // Post-commit embedding, best-effort: warn but never fail the merge (the
    // CLAUDE.md write-path invariant). Skipped on the idempotent return, where
    // nothing new was written.
    let embedded = if result.already_existed {
        false
    } else {
        match server
            .embedder
            .embed_and_store(result.merged_id, &params.merged_content)
            .await
        {
            true => true,
            false => {
                tracing::warn!(
                    claim_id = %result.merged_id,
                    "consolidate: merged claim embedding failed; claim is stored but not semantically recallable yet"
                );
                false
            }
        }
    };

    let response = ConsolidateResponse {
        merged_claim_id: result.merged_id.to_string(),
        superseded_ids: result.superseded.iter().map(ToString::to_string).collect(),
        edges_migrated: touched_count("edges_migrated"),
        edges_deduped: touched_count("edges_retracted"),
        embedded,
        already_existed: result.already_existed,
        cascade,
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}
