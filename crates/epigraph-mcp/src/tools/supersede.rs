use rmcp::model::{CallToolResult, Content};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::ClaimRepository;
use epigraph_engine::admin_cascade::{
    self, CascadeCause, CascadeStatus, CascadeTrigger, OauthPrincipal,
};
use epigraph_engine::retraction_cascade::CascadeReport;

/// The OAuth principal behind an authenticated call, for the cascade's audit row.
pub(crate) fn oauth_principal(auth: Option<&epigraph_auth::AuthContext>) -> Option<OauthPrincipal> {
    auth.map(|a| OauthPrincipal {
        client_id: Some(a.client_id),
        owner_id: a.owner_id,
        agent_id: a.agent_id,
    })
}

pub async fn supersede_claim(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: SupersedeClaimParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let old = parse_uuid(&params.claim_id)?;
    let old_claim_id = ClaimId::from_uuid(old);

    // The gate read, the authority decision and the stamped transaction the
    // act runs on (batch OA1): see [`begin_claim_act`]. `actor` is the
    // principal that transaction is stamped as, which the cascade's audit row
    // names.
    let (mut tx, actor) = begin_claim_act(
        server,
        viewer,
        auth,
        old,
        None,
        "supersede_claim",
        "supersede",
    )
    .await?;

    // THE ACT (migration 117): retire the claim, insert the replacement and the
    // `supersedes` edge. It does NOT migrate the old claim's other edges: an
    // incoming edge is its source writer's assertion, and re-pointing another
    // writer's edge is the administrative cascade's job below.
    let truth = TruthValue::clamped(params.truth_value);
    let (new_id, old_id) = ClaimRepository::supersede_act_conn(
        &mut tx,
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
    )
    .await
    .map_err(internal_error)?;

    let trigger = CascadeTrigger::new(
        CascadeCause::Supersede,
        Some(actor),
        oauth_principal(auth),
        old_id,
        Some(new_id),
    );
    // The administrative connection is acquired BEFORE the act commits. With
    // none (not configured, or unusable), the deferral is recorded in the act's
    // own transaction, attributed to the principal it is stamped with, so the
    // act and its audit row commit together (or neither does).
    let (mut session, deferred) = admin_session_or_deferral(server, &mut tx, &trigger).await?;
    tx.commit().await.map_err(internal_error)?;

    // THE CASCADE (backlog 20e9ed83; migration 117): migrate the retired
    // claim's edges onto the replacement, then invalidate the BBAs its
    // supporters froze from ITS interval and re-derive them. It runs with
    // ADMINISTRATIVE authority, on the server's maintenance connection and its
    // bypass viewer, because the edges and BBAs it rewrites belong to other
    // writers; the repair and its `security_events` row naming this caller
    // commit together. What comes back is filtered to the CALLER's viewer.
    // Best-effort by construction: the act has committed, and failing the call
    // here would hand the caller an error for a write that succeeded (the retry
    // then hits "already been superseded").
    let (cascade, belief_cascade) = match (session.as_mut(), deferred) {
        (Some(session), _) => {
            let (conn, v) = session.split();
            admin_cascade::apply_after_supersede(conn, v, viewer, &trigger, old_id, new_id).await
        }
        (None, status) => (status, CascadeReport::default()),
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
            "cascade": cascade,
            "belief_cascade": belief_cascade,
        }))
        .map_err(internal_error)?,
    )]))
}

/// Acquire the administrative (maintenance) session BEFORE the caller's act
/// commits. When there is none -- not configured, or not usable -- record the
/// deferral inside the act's own transaction `tx`, so the act and its audit row
/// commit together, and return that status.
///
/// # Errors
/// The deferral INSERT's error: the caller propagates it and nothing commits.
pub(crate) async fn admin_session_or_deferral<'s>(
    server: &'s EpiGraphMcpFull,
    tx: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
) -> Result<(Option<epigraph_db::MaintenanceSession<'s>>, CascadeStatus), McpError> {
    match crate::maintenance::admin_cascade_session(server).await {
        Ok(session) => Ok((Some(session), CascadeStatus::default())),
        Err(reason) => {
            let status = admin_cascade::record_deferral(&mut *tx, trigger, &reason)
                .await
                .map_err(internal_error)?;
            Ok((None, status))
        }
    }
}

/// The gate read, the authority decision and the stamped transaction a claim
/// act (`supersede_claim`, `mark_duplicate`) runs on. Returns that transaction
/// and the principal it is stamped as.
///
/// # Authenticated callers (batch OA1, operator decision D1)
///
/// The scope is `claims:write` (`scope_map`); this is the per-claim rule.
///
/// 1. `claim` (and `also_readable`, the dedup's canonical) are read through the
///    CALLER's viewer on a transaction stamped with that viewer. A claim it
///    cannot read is `claim <id> not found`, the same text a missing id gets,
///    so nothing here is an existence oracle.
/// 2. [`epigraph_auth::claim_act::claim_act_arm`] (shared with HTTP): a
///    `claims:admin` holder, or a caller whose viewer WRITES the claim's owning
///    group (its author or not). Authorship alone admits nothing, and no
///    transport-specific arm is added here. Otherwise the named refusal
///    [`crate::errors::claim_not_writer`].
/// 3. THE STAMP. Every non-admin act runs on the caller's own stamped
///    transaction, the one step 1 read on (D1: "the act keeps the CALLER's
///    authority"), so the authority read and the write see the same state,
///    and the cascade deferral is attributed to the caller. A `claims:admin`
///    caller that writes the owning group does the same. Only a `claims:admin`
///    caller on a claim it does NOT write acts on a transaction stamped from
///    this server's own agent: that is how the tool worked before batch OA1,
///    when `claims:admin` was its scope. No other admission may borrow the
///    server agent's stamp, because that would hand a `claims:write` caller
///    the server agent's write authority over the group. Either way the
///    database decides the write: a stamp that cannot write the row is
///    refused and nothing commits.
///
/// # stdio (no `AuthContext`)
///
/// Unchanged: the server agent's stamp, the read through `viewer`, and
/// `require_owner_or_admin`'s stdio arms.
async fn begin_claim_act<'p>(
    server: &'p EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    claim: uuid::Uuid,
    also_readable: Option<uuid::Uuid>,
    tool: &'static str,
    action: &str,
) -> Result<(epigraph_db::ScopedTx<'p>, uuid::Uuid), McpError> {
    let not_found = |id: uuid::Uuid| invalid_params(format!("claim {id} not found"));

    let Some(auth) = auth else {
        let author = server.agent_id().await?;
        let mut tx = crate::claim_helper::begin_author_stamped_tx(server, author, tool).await?;
        let (claim_author, _) = ClaimRepository::write_target_of(&mut *tx, viewer, claim)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| not_found(claim))?;
        crate::tools::claims::require_owner_or_admin(server, None, claim_author).await?;
        return Ok((tx, author));
    };

    let scoped = server.scoped.as_ref().ok_or_else(|| {
        internal_error(format!(
            "{tool}: this MCP server was not built from a ScopedPool, so the caller's read \
             cannot be stamped. Nothing was written. Construct the server with \
             EpiGraphMcpFull::with_scoped_pool."
        ))
    })?;
    let mut caller_tx = scoped.begin_as(viewer).await.map_err(|e| {
        internal_error(format!(
            "{tool}: could not begin a transaction stamped with the caller's viewer: {e}"
        ))
    })?;
    let (author, owner_group) = ClaimRepository::write_target_of(&mut *caller_tx, viewer, claim)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found(claim))?;
    if let Some(other) = also_readable {
        ClaimRepository::write_target_of(&mut *caller_tx, viewer, other)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| not_found(other))?;
    }

    let target = epigraph_auth::claim_act::ClaimActTarget {
        author,
        owner_group,
    };
    let Some(arm) = epigraph_auth::claim_act::claim_act_arm(
        auth,
        viewer.principal(),
        viewer.writable_groups(),
        target,
    ) else {
        return Err(crate::errors::claim_not_writer(claim, action));
    };
    tracing::info!(tool, claim = %claim, arm = arm.as_str(), "claim act admitted");

    if viewer.writable_groups().contains(&owner_group) {
        if let Some(caller) = viewer.principal() {
            return Ok((caller_tx, caller));
        }
    }
    if arm != epigraph_auth::claim_act::ClaimActArm::Admin {
        // Not reachable through `claim_act_arm` (a non-admin arm requires the
        // owning group in a Scoped viewer's writable set, and a Scoped viewer
        // has a principal). Refused rather than falling through to the server
        // agent's stamp below, which only `claims:admin` may borrow.
        return Err(crate::errors::claim_not_writer(claim, action));
    }
    // Rolled back: it read, and wrote nothing.
    drop(caller_tx);
    let server_agent = server.agent_id().await?;
    let tx = crate::claim_helper::begin_author_stamped_tx(server, server_agent, tool).await?;
    Ok((tx, server_agent))
}

pub async fn mark_duplicate(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: MarkDuplicateParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let canon = parse_uuid(&params.canonical_id)?;
    let dup_claim_id = ClaimId::from_uuid(dup);

    // THE ACT's gate and stamp (batch OA1), as `supersede_claim` above: the
    // duplicate is the claim the caller must be able to retire; the canonical
    // must only be READABLE by the caller (the act writes the duplicate's row
    // alone, and its FA04 refusal still demands write authority over a
    // non-public canonical). Either one the caller cannot read is reported as
    // not found, exactly like a missing claim.
    let (mut tx, actor) = begin_claim_act(
        server,
        viewer,
        auth,
        dup,
        Some(canon),
        "mark_duplicate",
        "mark as a duplicate",
    )
    .await?;

    ClaimRepository::mark_duplicate_act_conn(&mut tx, dup_claim_id, ClaimId::from_uuid(canon))
        .await
        .map_err(internal_error)?;

    let trigger = CascadeTrigger::new(
        CascadeCause::Dedup,
        Some(actor),
        oauth_principal(auth),
        dup,
        Some(canon),
    );
    let (mut session, deferred) = admin_session_or_deferral(server, &mut tx, &trigger).await?;
    tx.commit().await.map_err(internal_error)?;

    // THE CASCADE (migration 117), with administrative authority on the
    // maintenance connection: retract the duplicate's colliding edges and drop
    // their BBAs, re-point every other edge onto the canonical, move the BBAs
    // that follow them, and re-derive what changed. Same contract as
    // supersede: audited atomically, filtered to the caller, best-effort (the
    // act's own failure is an error, the cascade's is reported).
    let (cascade, belief_cascade) = match (session.as_mut(), deferred) {
        (Some(session), _) => {
            let (conn, v) = session.split();
            admin_cascade::apply_after_dedup(conn, v, viewer, &trigger, dup, canon).await
        }
        (None, status) => (status, CascadeReport::default()),
    };

    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "duplicate_id": dup,
            "canonical_id": canon,
            "mode": "mark_duplicate",
            "cascade": cascade,
            "belief_cascade": belief_cascade,
        }))
        .map_err(internal_error)?,
    )]))
}
