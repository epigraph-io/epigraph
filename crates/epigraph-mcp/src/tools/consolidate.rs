//! `consolidate_claims` MCP tool (backlog 44b19521 / design F1).
//!
//! N→1 memory consolidation, in one of three explicit modes (backlog
//! 22602dd8, [`ConsolidateMode`]):
//!
//! - `identity`: the sources restate one of them, the caller-named survivor.
//!   Each other source goes through the dedup act onto it, exactly as
//!   `mark_duplicate` would, so it can be un-marked. No new claim.
//! - `merge` (alias `rewrite`): a new merged claim; the sources are retired
//!   into it and their edges move to it.
//! - `abstract`: a new generalisation linked to each source by a
//!   `generalizes` edge; no source is retired and no edge moves.
//!
//! For `merge` and `abstract` the caller supplies the synthesized content —
//! the server never invokes an LLM, matching `epigraph-ingest-executor`'s
//! division of labour (agent-side synthesis, server-side storage).

use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;

use crate::errors::{internal_error, internal_error_logged, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::ConsolidateClaimsParams;

use epigraph_db::repos::claim::{CONSOLIDATE_MAX_SOURCES, CONSOLIDATE_MIN_SOURCES};
use epigraph_db::{ClaimRepository, ConsolidateMode};

#[derive(Debug, Serialize)]
struct ConsolidateResponse {
    /// `merge` or `abstract` (an `identity` call answers with
    /// [`IdentityResponse`]).
    mode: &'static str,
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
    /// on the idempotent return, which wrote nothing, and on an abstraction,
    /// which moves no edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    cascade: Option<epigraph_engine::admin_cascade::CascadeStatus>,
}

/// What `consolidate_claims(mode='identity')` did: one `mark_duplicate`
/// answer per non-survivor source, in the order given.
#[derive(Debug, Serialize)]
struct IdentityResponse {
    mode: &'static str,
    survivor_claim_id: String,
    marked: Vec<serde_json::Value>,
}

pub async fn consolidate_claims(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ConsolidateClaimsParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let mode = ConsolidateMode::parse(&params.mode).map_err(|bad| {
        invalid_params(format!(
            "unknown mode {bad:?}; want identity|merge|abstract (rewrite is accepted as merge)"
        ))
    })?;
    let source_ids = params
        .source_claim_ids
        .iter()
        .map(|s| parse_uuid(s))
        .collect::<Result<Vec<_>, _>>()?;

    if mode == ConsolidateMode::Identity {
        return consolidate_identity(server, viewer, params, auth, &source_ids).await;
    }
    if params.survivor_claim_id.is_some() {
        return Err(invalid_params(format!(
            "survivor_claim_id applies to mode 'identity' only; mode '{}' writes a new claim \
             and has no survivor",
            mode.as_str()
        )));
    }

    // merge and abstract write a new claim, so they need its text. Refused
    // here as a parameter error: the field is optional on the wire (identity
    // takes none), and the act's own empty-content refusal would surface as
    // an internal error an agent retries.
    if params.merged_content.trim().is_empty() {
        return Err(invalid_params(format!(
            "mode '{}' writes a new claim and needs merged_content",
            mode.as_str()
        )));
    }

    // The merged claim is a claim like any other: the same content cap as
    // `submit_claim` and its HTTP twins, checked before anything is resolved,
    // embedded or written (backlog b76e284b).
    crate::tools::claims::check_claim_content_length(&params.merged_content)?;
    let acting = server.write_identity(auth, viewer).await?;
    let acting_agent_id = acting.agent_id();

    // Default confidence: the strongest source discounted slightly, so a merge
    // never claims more certainty than its best input.
    //
    // The sources are read on the CALLER's stamped read, not the plain pool. On
    // the application role an unstamped connection admits public rows only, so
    // a member's own group-private sources read as missing, `best` stayed 0 and
    // the merged claim was written with truth_value 0, with no error. The read
    // is released before the write transaction below is taken, so the tool
    // never holds two pooled connections.
    //
    // A failed read REFUSES the merge rather than skipping the source. Under
    // `EPIGRAPH_SESSION_GUC_MODE=transaction` the stamped read is one
    // transaction, so one SQL error aborts it and every later source read in
    // this loop fails too; skipping them wrote the merged claim at a default
    // drawn from whatever was read before the error (0 when the first source
    // failed), with no warning. A source the caller cannot see (`Ok(None)`)
    // is still skipped here: the write transaction's `FOR UPDATE` lock below
    // refuses it.
    let merged_truth = match params.confidence {
        Some(c) => c.clamp(0.0, 1.0),
        None => {
            let mut read = server.read_as(viewer, "consolidate_claims").await?;
            let mut best: f64 = 0.0;
            for id in &source_ids {
                let source = ClaimRepository::get_by_id(
                    &mut *read,
                    viewer,
                    epigraph_core::ClaimId::from_uuid(*id),
                )
                .await
                .map_err(|e| {
                    internal_error_logged(
                        format!(
                            "consolidate_claims: could not read source claim {id} to derive the \
                             default confidence; nothing was written. Retry, or pass \
                             `confidence` explicitly."
                        ),
                        e,
                    )
                })?;
                if let Some(c) = source {
                    best = best.max(c.truth_value.value());
                }
            }
            drop(read);
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
        other if other.is_write_authority_refusal() => crate::errors::db_caller_error(other),
        other => internal_error(other),
    })?;
    // The cascade's trigger, and its administrative session acquired BEFORE
    // the act commits (or the deferral recorded in the act's own transaction).
    // The idempotent return wrote nothing, so it has no cascade; nor has an
    // abstraction, which retires no source and so has no edge to move (the
    // consolidate cascade and its deferral both verify retired sources, and
    // would refuse one).
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
    let (mut session, deferred) = if result.already_existed || !mode.retires_sources() {
        (None, None)
    } else {
        let (session, status) =
            crate::tools::supersede::admin_session_or_deferral(server, &mut tx, &trigger).await?;
        (session, Some(status))
    };
    // The idempotent-return branch rolled its SAVEPOINT back and wrote nothing;
    // committing the (then empty) outer transaction is harmless and uniform.
    tx.commit().await.map_err(|e| {
        crate::errors::internal_error_logged("consolidate_claims: could not commit", e)
    })?;

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
    //
    // Stored as the ACTING agent, the merged row's author, on a connection
    // stamped from it (`claim_helper::embed_claim_author_stamped`), not through
    // `McpEmbedder::embed_and_store`: that path resolves the author by reading
    // the claim as PUBLIC, and a merge of team or private sources is neither,
    // so it stored nothing there (backlog 46902f71). The merge's transaction
    // carries no team-write grant, so none is needed here either.
    let embedded = if result.already_existed {
        false
    } else {
        crate::claim_helper::embed_claim_author_stamped(
            server,
            acting_agent_id,
            result.merged_id,
            &params.merged_content,
            None,
            "consolidate_claims",
        )
        .await
    };

    let response = ConsolidateResponse {
        mode: mode.as_str(),
        merged_claim_id: result.merged_id.to_string(),
        superseded_ids: result.superseded.iter().map(ToString::to_string).collect(),
        edges_migrated: touched_count("edges_migrated"),
        edges_deduped: touched_count("edges_retracted"),
        embedded,
        already_existed: result.already_existed,
        cascade,
    };

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}

/// `consolidate_claims(mode='identity')`: every non-survivor source is marked
/// a duplicate of the survivor through the dedup act, as `mark_duplicate`
/// does, so each gets the identity edge, its belief inputs pool onto the
/// survivor, and each can be un-marked (`unmark_duplicate`). No claim is
/// written.
///
/// All-or-nothing up to the first act: every source's state and the caller's
/// authority over every pair are checked before any source is marked. A
/// source that changes between that check and its own act (a concurrent
/// writer) is refused by the act, and the sources marked before it stay
/// marked; each can be un-marked.
async fn consolidate_identity(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ConsolidateClaimsParams,
    auth: Option<&epigraph_auth::AuthContext>,
    source_ids: &[uuid::Uuid],
) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "consolidate_claims";
    if !params.merged_content.trim().is_empty() {
        return Err(invalid_params(
            "mode 'identity' writes no new claim, so it takes no merged_content: the \
             survivor's text stands. Omit merged_content, or use mode 'merge'.",
        ));
    }
    if params.confidence.is_some() {
        return Err(invalid_params(
            "mode 'identity' writes no new claim, so it takes no confidence",
        ));
    }
    let survivor = match params.survivor_claim_id.as_deref() {
        Some(s) => parse_uuid(s)?,
        None => {
            return Err(invalid_params(
                "mode 'identity' needs survivor_claim_id: the source every other source is \
                 marked a duplicate of",
            ))
        }
    };
    if source_ids.len() < CONSOLIDATE_MIN_SOURCES || source_ids.len() > CONSOLIDATE_MAX_SOURCES {
        return Err(invalid_params(format!(
            "consolidate: need {CONSOLIDATE_MIN_SOURCES}..={CONSOLIDATE_MAX_SOURCES} sources, got {}",
            source_ids.len()
        )));
    }
    let unique: std::collections::HashSet<uuid::Uuid> = source_ids.iter().copied().collect();
    if unique.len() != source_ids.len() {
        return Err(invalid_params("consolidate: duplicate source ids"));
    }
    if !unique.contains(&survivor) {
        return Err(invalid_params(format!(
            "survivor_claim_id {survivor} is not one of source_claim_ids"
        )));
    }
    let duplicates: Vec<uuid::Uuid> = source_ids
        .iter()
        .copied()
        .filter(|id| *id != survivor)
        .collect();

    // Every source's state, read through the CALLER: one it cannot read is
    // not found, exactly as `mark_duplicate` reports it. The survivor must be
    // current; every other source current and not already a successor or a
    // marked duplicate (the dedup act's own refusals, asked first so that one
    // bad source refuses the call before any source is marked).
    {
        let mut read = server.read_as(viewer, TOOL).await?;
        for id in source_ids {
            let claim = ClaimRepository::get_by_id(
                &mut *read,
                viewer,
                epigraph_core::ClaimId::from_uuid(*id),
            )
            .await
            .map_err(|e| {
                internal_error_logged(
                    format!(
                        "consolidate_claims: could not read source claim {id}; nothing was written"
                    ),
                    e,
                )
            })?
            .ok_or_else(|| invalid_params(format!("claim {id} not found")))?;
            if !claim.is_current {
                return Err(invalid_params(format!(
                    "consolidate: source {id} is not current; nothing was written"
                )));
            }
            if *id != survivor && claim.supersedes.is_some() {
                return Err(invalid_params(format!(
                    "consolidate: source {id} already supersedes a claim; marking it a \
                     duplicate would overwrite that pointer. Nothing was written."
                )));
            }
        }
    }
    for dup in &duplicates {
        crate::tools::supersede::mark_duplicate_preflight(
            server, viewer, auth, *dup, survivor, TOOL,
        )
        .await?;
    }

    let mut marked = Vec::with_capacity(duplicates.len());
    for dup in duplicates {
        marked.push(
            crate::tools::supersede::mark_duplicate_pair(
                server,
                viewer,
                auth,
                dup,
                survivor,
                Some(params.reason.as_str()),
                TOOL,
            )
            .await?,
        );
    }

    let response = IdentityResponse {
        mode: ConsolidateMode::Identity.as_str(),
        survivor_claim_id: survivor.to_string(),
        marked,
    };
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&response).map_err(internal_error)?,
    )]))
}
