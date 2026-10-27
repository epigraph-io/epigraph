use rmcp::model::{CallToolResult, ContentBlock};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams, UnmarkDuplicateParams};
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, DuplicateProvenance};
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
    // The replacement's size cap, before the act's transaction opens: a refusal
    // leaves the old claim current.
    crate::tools::claims::check_claim_content_length(&params.content)?;
    let old_claim_id = ClaimId::from_uuid(old);

    // The gate read, the authority decision and the stamped transaction the
    // act runs on (batch OA1): see [`begin_claim_act`]. `actor` is the
    // principal that transaction is stamped as, which the cascade's audit row
    // names; `caller` is the agent that called (the same agent unless a
    // `claims:admin` caller borrowed this server's stamp).
    let (mut tx, actor, caller) = begin_claim_act(
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
    //
    // The replacement keeps the retired claim's author; the CALLER is recorded
    // as its `AUTHORED` edge (backlog 73085534, ruling R-23), the #600
    // convention for a claim authored by someone other than the agent that
    // called. Not the borrowed server stamp: crediting the server agent would
    // misattribute the act exactly as the inherited author did.
    let (new_id, old_id) = ClaimRepository::supersede_act_conn(
        &mut tx,
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
        epigraph_db::SupersedeActor::new(caller, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .map_err(|e| match e {
        // Readable as current but not retirable by this session: a denial of
        // authority (INVALID_REQUEST), with nothing written.
        e @ epigraph_db::DbError::WriteRefused { .. } => crate::errors::db_caller_error(e),
        other => internal_error(other),
    })?;

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

    Ok(CallToolResult::success(vec![ContentBlock::text(
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
/// act (`supersede_claim`, `mark_duplicate`) runs on. Returns that transaction,
/// the principal it is stamped as, and the CALLER's write identity (the agent
/// that called; it differs from the stamp only on the `claims:admin` borrow of
/// this server's agent, step 3 below).
///
/// # Authenticated callers (batch OA1, operator decision D1)
///
/// The scope is `claims:write` (`scope_map`); this is the per-claim rule.
///
/// 1. `claim` (and `canonical`, the dedup's target) are read through the
///    CALLER's viewer on a transaction stamped with that viewer. A claim it
///    cannot read is `claim <id> not found`, the same text a missing id gets,
///    so nothing here is an existence oracle. Both are read before either is
///    judged, so a refusal never concerns a claim the caller cannot see.
/// 2. [`epigraph_auth::claim_act::claim_act_arm`] (shared with HTTP): a
///    `claims:admin` holder, or a caller whose viewer WRITES the claim's owning
///    group (its author or not). Authorship alone admits nothing, and no
///    transport-specific arm is added here. Otherwise the named refusal
///    [`crate::errors::claim_not_writer`]. The same rule is then applied to
///    `canonical`: brief (a) asks write authority over the target claim(s),
///    and the cascade that follows re-points OTHER writers' edges and BBAs
///    onto the canonical with administrative authority, so a `claims:write`
///    caller may only choose a canonical it could write itself.
/// 3. THE STAMP. Every non-admin act runs on the caller's own stamped
///    transaction, the one step 1 read on (D1: "the act keeps the CALLER's
///    authority"), so the authority read and the write see the same state,
///    and the cascade deferral is attributed to the caller. A `claims:admin`
///    caller that writes the owning group does the same. Only a `claims:admin`
///    caller on a claim it does NOT write acts on a transaction stamped from
///    this server's own agent: that is how the tool worked before batch OA1,
///    when `claims:admin` was its scope. No other admission may borrow the
///    server agent's stamp, because that would hand a `claims:write` caller
///    the server agent's write authority over the group; the borrow is
///    granted only by `EpiGraphMcpFull::admin_borrowed_server_identity`, which
///    re-checks `claims:admin` on the token AND a live `claims:admin` grant on
///    the token's client record (migration 111's `ADM02` predicate). Either way the database decides the write: a
///    stamp that cannot write the row is refused and nothing commits.
///
/// The caller's own stamp is its WRITE IDENTITY (batch H-b, D1):
/// `EpiGraphMcpFull::write_identity(auth, viewer)`, which also refuses a
/// principal-less caller the listener did not opt in to writes (batch HTTP-id)
/// and a viewer whose principal is not the token's.
///
/// # stdio (no `AuthContext`)
///
/// The write identity's stdio answer (the server agent), the read through
/// `viewer`, and `require_owner_or_admin`'s stdio arms.
async fn begin_claim_act<'p>(
    server: &'p EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    claim: uuid::Uuid,
    canonical: Option<uuid::Uuid>,
    tool: &'static str,
    action: &str,
) -> Result<(epigraph_db::ScopedTx<'p>, uuid::Uuid, uuid::Uuid), McpError> {
    let not_found = |id: uuid::Uuid| invalid_params(format!("claim {id} not found"));

    // The write identity (batch H-b, D1): the caller's own agent over HTTP,
    // refused for a principal-less caller without write scopes; the server's
    // own agent on stdio.
    let caller = server.write_identity(auth, viewer).await?;

    let Some(token) = auth else {
        let mut tx = crate::claim_helper::begin_author_stamped_tx(server, caller, tool).await?;
        let (claim_author, _) = ClaimRepository::write_target_of(&mut *tx, viewer, claim)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| not_found(claim))?;
        crate::tools::claims::require_owner_or_admin(server, auth, caller, claim_author).await?;
        return Ok((tx, caller.agent_id(), caller.agent_id()));
    };

    let mut caller_tx = crate::claim_helper::begin_author_stamped_tx(server, caller, tool).await?;
    let (author, owner_group) = ClaimRepository::write_target_of(&mut *caller_tx, viewer, claim)
        .await
        .map_err(internal_error)?
        .ok_or_else(|| not_found(claim))?;
    let canonical_target = match canonical {
        Some(other) => Some((
            other,
            ClaimRepository::write_target_of(&mut *caller_tx, viewer, other)
                .await
                .map_err(internal_error)?
                .ok_or_else(|| not_found(other))?,
        )),
        None => None,
    };

    let target = epigraph_auth::claim_act::ClaimActTarget {
        author,
        owner_group,
    };
    let Some(arm) = epigraph_auth::claim_act::claim_act_arm(
        token,
        viewer.principal(),
        viewer.writable_groups(),
        target,
    ) else {
        return Err(crate::errors::claim_not_writer(claim, action));
    };
    if let Some((other, (other_author, other_group))) = canonical_target {
        let other_target = epigraph_auth::claim_act::ClaimActTarget {
            author: other_author,
            owner_group: other_group,
        };
        if epigraph_auth::claim_act::claim_act_arm(
            token,
            viewer.principal(),
            viewer.writable_groups(),
            other_target,
        )
        .is_none()
        {
            return Err(crate::errors::claim_not_writer(
                other,
                "mark a duplicate onto",
            ));
        }
    }
    tracing::info!(tool, claim = %claim, arm = arm.as_str(), "claim act admitted");

    if viewer.writable_groups().contains(&owner_group) {
        return Ok((caller_tx, caller.agent_id(), caller.agent_id()));
    }
    if arm != epigraph_auth::claim_act::ClaimActArm::Admin {
        // Not reachable through `claim_act_arm` (a non-admin arm requires the
        // owning group in a Scoped viewer's writable set). Refused rather than falling through to the server
        // agent's stamp below, which only `claims:admin` may borrow.
        return Err(crate::errors::claim_not_writer(claim, action));
    }
    // The borrow re-checks the token's client record (111's ADM02 predicate)
    // on the caller's own transaction, then that transaction is rolled back:
    // it read, and wrote nothing.
    let server_agent = server
        .admin_borrowed_server_identity(token, &mut caller_tx)
        .await?;
    drop(caller_tx);
    let tx = crate::claim_helper::begin_author_stamped_tx(server, server_agent, tool).await?;
    Ok((tx, server_agent.agent_id(), caller.agent_id()))
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
    // caller must be able to write BOTH the duplicate and the canonical (or
    // hold claims:admin). The act writes the duplicate's row alone, but the
    // cascade re-points other writers' edges and BBAs onto the canonical, so
    // the canonical is the caller's choice to make only where it could write
    // itself. Either one the caller cannot read is reported as not found,
    // exactly like a missing claim.
    let (mut tx, actor, _) = begin_claim_act(
        server,
        viewer,
        auth,
        dup,
        Some(canon),
        "mark_duplicate",
        "mark as a duplicate",
    )
    .await?;

    let provenance =
        DuplicateProvenance::new("mark_duplicate", DuplicateProvenance::RULE_CALLER_ASSERTED)
            .marked_by(Some(actor))
            .reason(params.reason.as_deref());
    ClaimRepository::mark_duplicate_act_attributed_conn(
        &mut tx,
        dup_claim_id,
        ClaimId::from_uuid(canon),
        &provenance,
    )
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

    Ok(CallToolResult::success(vec![ContentBlock::text(
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

/// The refusal an un-mark gets on a server without the administrative
/// connection: unlike a mark, an un-mark has no deferred form (migration 117's
/// deferral definer accepts no such cause), so nothing is written.
pub const UNMARK_NEEDS_ADMIN_CONNECTION: &str =
    "unmark_duplicate needs this server's administrative (maintenance) connection: an \
     un-mark is the dedup's act and its reversal together and cannot be deferred to the \
     replay; nothing was written";

pub async fn unmark_duplicate(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: UnmarkDuplicateParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let out =
        unmark_duplicate_expecting(server, viewer, auth, dup, UnmarkExpectation::default()).await?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&out).map_err(internal_error)?,
    )]))
}

/// Which mark a caller means to undo (`revert_label_dedup`): the canonical it
/// was marked onto and, when known, the identity edge that mark wrote. A claim
/// marked since onto another claim, or marked again (a new identity edge),
/// is refused with nothing written.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UnmarkExpectation {
    pub canonical: Option<uuid::Uuid>,
    pub identity_edge: Option<uuid::Uuid>,
}

/// What [`unmark_gate`] proved: the claim's canonical, its author and text,
/// and the principal the un-mark acts as.
pub(crate) struct UnmarkGate {
    pub canonical: uuid::Uuid,
    /// The canonical, then each claim that replaced it since, ending with the
    /// current one the duplicate is restored against (operator ruling R-11);
    /// the caller's authority was checked over every one of them. `Err` with
    /// the reason when the duplicate has no dedup identity edge (reported
    /// first, as the act does: R-7), or there is no current canonical (one of
    /// the chain is itself a marked duplicate, or was deprecated): the un-mark
    /// refuses then, and a batch that un-marks that claim first may still
    /// proceed.
    pub chain: Result<Vec<uuid::Uuid>, String>,
    author: uuid::Uuid,
    content: String,
    actor: uuid::Uuid,
}

/// Every check `unmark_duplicate` makes before it writes, and nothing else:
/// the claim and its canonical read through the CALLER (a claim it cannot
/// read is "not found", like a missing one), the expectation, then the same
/// gate as mark_duplicate and the database's own write predicate on the
/// caller's stamped transaction, rolled back. Not a rehearsal of the act:
/// once operator binding is armed, an application session may not clear a
/// `supersedes` at all (migration 153), and the act that commits runs with
/// the reversal on the administrative connection. Read-only, so a caller can
/// prove a batch of un-marks admissible before writing any of it.
pub(crate) async fn unmark_gate(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    dup: uuid::Uuid,
    expected: UnmarkExpectation,
) -> Result<UnmarkGate, McpError> {
    let (canonical, chain, author, content) = {
        let mut tx = crate::claim_helper::begin_author_stamped_tx(
            server,
            server.write_identity(auth, viewer).await?,
            "unmark_duplicate",
        )
        .await?;
        let claim = ClaimRepository::get_by_id(&mut *tx, viewer, ClaimId::from_uuid(dup))
            .await
            .map_err(internal_error)?
            .ok_or_else(|| invalid_params(format!("claim {dup} not found")))?;
        let canonical: uuid::Uuid = claim
            .supersedes
            .ok_or_else(|| invalid_params(format!("claim {dup} is not a marked duplicate")))?
            .into();
        if let Some(edge) = expected.identity_edge {
            let live = ClaimRepository::dedup_identity_edge_of(&mut *tx, viewer, dup)
                .await
                .map_err(internal_error)?;
            if live.map(|(id, _)| id) != Some(edge) {
                return Err(invalid_params(format!(
                    "claim {dup} no longer carries the mark with identity edge {edge} (it was \
                     un-marked or marked again since); nothing was written"
                )));
            }
        }
        // A canonical superseded or consolidated since is followed to its
        // current replacement, and the reversal acts on every claim of that
        // chain, so the caller's authority is checked over each below.
        let chain = ClaimRepository::unmark_chain_conn(&mut tx, viewer, dup, canonical)
            .await
            .map_err(internal_error)?;
        (
            canonical,
            chain,
            claim.agent_id.into(),
            claim.content.clone(),
        )
    };
    if let Some(expected) = expected.canonical.filter(|e| *e != canonical) {
        return Err(invalid_params(format!(
            "claim {dup} is now a duplicate of {canonical}, not of {expected}; nothing was \
             written"
        )));
    }
    let (mut tx, actor, _) = begin_claim_act(
        server,
        viewer,
        auth,
        dup,
        Some(canonical),
        "unmark_duplicate",
        "un-mark as a duplicate",
    )
    .await?;
    let may = ClaimRepository::session_may_unmark_conn(
        &mut tx,
        ClaimId::from_uuid(dup),
        ClaimId::from_uuid(canonical),
    )
    .await
    .map_err(internal_error)?;
    tx.rollback().await.map_err(internal_error)?;
    if !may {
        return Err(crate::errors::claim_not_writer(
            dup,
            "un-mark as a duplicate",
        ));
    }
    // The same gate over each claim that replaced the canonical: the reversal
    // moves the duplicate's rows off it as off the canonical.
    for replacement in chain.iter().flat_map(|c| c.iter().skip(1)) {
        let (mut tx, _, _) = begin_claim_act(
            server,
            viewer,
            auth,
            dup,
            Some(*replacement),
            "unmark_duplicate",
            "un-mark as a duplicate",
        )
        .await?;
        let may = ClaimRepository::session_may_unmark_conn(
            &mut tx,
            ClaimId::from_uuid(dup),
            ClaimId::from_uuid(*replacement),
        )
        .await
        .map_err(internal_error)?;
        tx.rollback().await.map_err(internal_error)?;
        if !may {
            return Err(crate::errors::claim_not_writer(
                *replacement,
                "un-mark a duplicate onto",
            ));
        }
    }
    Ok(UnmarkGate {
        canonical,
        chain,
        author,
        content,
        actor,
    })
}

/// [`unmark_duplicate`]'s body, for a caller that knows which dedup it means
/// to undo (`revert_label_dedup`, see [`UnmarkExpectation`]). Returns the
/// tool's response object.
pub(crate) async fn unmark_duplicate_expecting(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    dup: uuid::Uuid,
    expected: UnmarkExpectation,
) -> Result<serde_json::Value, McpError> {
    let UnmarkGate {
        canonical,
        chain,
        author,
        content,
        actor,
    } = unmark_gate(server, viewer, auth, dup, expected).await?;
    let chain =
        chain.map_err(|why| invalid_params(format!("claim {dup} {why}; nothing was written")))?;

    // No administrative connection: refuse before anything is written.
    let mut session = crate::maintenance::admin_cascade_session(server)
        .await
        .map_err(|reason| McpError {
            code: rmcp::model::ErrorCode::INVALID_REQUEST,
            message: format!("{UNMARK_NEEDS_ADMIN_CONNECTION} ({reason})").into(),
            data: None,
        })?;

    let trigger = CascadeTrigger::new(
        CascadeCause::Undedup,
        Some(actor),
        oauth_principal(auth),
        dup,
        Some(canonical),
    );
    let (conn, admin_viewer) = session.split();
    let (outcome, belief_cascade) = admin_cascade::apply_unmark_authorized(
        conn,
        admin_viewer,
        viewer,
        &trigger,
        dup,
        canonical,
        Some(&chain),
    )
    .await
    .map_err(|e| match e {
        admin_cascade::UnmarkRefusal::Failed(_) => internal_error(e),
        other => invalid_params(other.to_string()),
    })?;

    // Current again: embed post-commit, best-effort (CLAUDE.md's write-path
    // rule), through the claim's author like every other write path.
    let embedded = crate::claim_helper::embed_claim_author_stamped(
        server,
        author,
        dup,
        &content,
        None,
        "unmark_duplicate",
    )
    .await;

    Ok(serde_json::json!({
        "duplicate_id": dup,
        "canonical_id": outcome.canonical_id,
        "current_canonical_id": outcome.current_canonical_id,
        "mode": "unmark_duplicate",
        "embedded": embedded,
        "cascade": outcome.cascade,
        "belief_cascade": belief_cascade,
    }))
}
