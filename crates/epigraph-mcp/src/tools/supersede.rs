use rmcp::model::{CallToolResult, ContentBlock};

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::types::{MarkDuplicateParams, SupersedeClaimParams, UnmarkDuplicateParams};
use epigraph_auth::claim_act::ClaimActRefusal;
use epigraph_core::{ClaimId, TruthValue};
use epigraph_db::{ClaimRepository, DuplicateProvenance};
use epigraph_engine::admin_cascade::{
    self, CascadeCause, CascadeStatus, CascadeTrigger, OauthPrincipal,
};
use epigraph_engine::retraction_cascade::CascadeReport;

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
    // The act's edges are attested at INSERT with the server's key (backlog
    // `dae795f8`), resolved before the act's transaction opens.
    let edge_key = server.edge_signing_key().await?;
    let (mut tx, actor, caller, _) = begin_claim_act(
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
        Some(edge_key),
        old_claim_id,
        &params.content,
        truth,
        &params.reason,
        epigraph_db::SupersedeActor::new(caller, epigraph_db::SupersedeTool::SupersedeClaim),
    )
    .await
    .map_err(|e| supersede_refusal(old, e))?;

    let trigger = CascadeTrigger::new(
        CascadeCause::Supersede,
        Some(actor),
        auth.map(OauthPrincipal::from),
        old_id,
        Some(new_id),
    );
    // The administrative connection is acquired BEFORE the act commits. With
    // none (not configured, or unusable), the deferral is recorded in the act's
    // own transaction, attributed to the principal it is stamped with, so the
    // act and its audit row commit together (or neither does).
    let (mut session, deferred) = supersede_session_or_deferral(server, &mut tx, &trigger).await?;
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
    // The maintenance connection goes back to its pool BEFORE the provider
    // round trip below: an embedding call must not hold a pooled connection.
    drop(session);

    // The replacement is a new CURRENT claim, so it is embedded post-commit,
    // best-effort (CLAUDE.md's write-path rule; backlog 7628ab2c): without a
    // vector it is invisible to recall. Stored on a connection stamped as
    // `actor`, the principal whose transaction just INSERTed the row (and so
    // provably writes its owner group), not the inherited author, who may no
    // longer write the group the claim lives in.
    let embedded = crate::claim_helper::embed_claim_author_stamped(
        server,
        actor,
        new_id,
        &params.content,
        None,
        "supersede_claim",
    )
    .await;

    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "new_claim_id": new_id,
            "superseded_claim_id": old_id,
            "reason": params.reason,
            "embedded": embedded,
            "cascade": cascade,
            "belief_cascade": belief_cascade,
        }))
        .map_err(internal_error)?,
    )]))
}

/// The answer `supersede_claim` gives when the database refuses its act on
/// `claim` (`supersede_act_conn`) (supersede SPEC K5). The refusal's KIND is
/// decided once, for both transports, by
/// [`epigraph_engine::admin_cascade::supersede_act_refusal`]
/// ([`ClaimActRefusal::of_act`]); this only answers each kind as an
/// `McpError` ([`claim_act_refusal`]). Every denial is `INVALID_REQUEST` with
/// its code in the text, and nothing was written (the act and its deferral
/// share one transaction):
///
/// 1. [`ClaimActRefusal::Cx03`]: the session does not write the claim's group
///    ([`epigraph_auth::claim_act::supersede_not_recorded_message`]), the same
///    text as a refused deferral's CX03 ([`supersede_deferral_refusal`]);
/// 2. [`ClaimActRefusal::NotWriter`], row security's uncoded `42501`
///    (`claims_tenancy`'s WITH CHECK: the stamp, the caller's own or the
///    borrowed server agent's, does not write the claim's owner group), with
///    the HTTP route's words ([`SUPERSEDE_GROUP_WRITE_REFUSED`]);
/// 3. [`ClaimActRefusal::CodedDenial`] and [`ClaimActRefusal::Other`] through
///    [`crate::errors::db_caller_error`], which keeps a coded refusal's code,
///    names OPL01 / OPL02 / ROL01 and `WriteRefused` as denials, and keeps a
///    fault a fault.
pub fn supersede_refusal(claim: uuid::Uuid, e: epigraph_db::DbError) -> McpError {
    let kind = admin_cascade::supersede_act_refusal(&e);
    claim_act_refusal(kind, claim, e)
}

/// The answer to a failed supersede DEFERRAL
/// ([`admin_cascade::cascade_deferral_refusal`]): CX03 is the caller's denial
/// ([`supersede_refusal`]'s first arm, the same text); anything else is a
/// [`ClaimActRefusal::DeployFault`], answered as [`admin_session_or_deferral`]
/// answers it for the other claim acts. An uncoded `42501` here is a missing
/// EXECUTE grant on the definer, not row security refusing the caller, so it
/// must not read as the group-write denial.
pub fn supersede_deferral_refusal(claim: uuid::Uuid, e: epigraph_db::DbError) -> McpError {
    let kind = admin_cascade::cascade_deferral_refusal(&e);
    claim_act_refusal(kind, claim, e)
}

/// A claim act's refusal of kind `kind` (classified by `epigraph-auth`, once
/// for both transports) as this transport's error. The HTTP twin maps the
/// same kinds onto `ApiError`.
fn claim_act_refusal(
    kind: ClaimActRefusal,
    claim: uuid::Uuid,
    e: epigraph_db::DbError,
) -> McpError {
    match kind {
        ClaimActRefusal::Cx03 => {
            tracing::warn!(
                target: "tenancy.scoped_write",
                tool = "supersede_claim",
                claim = %claim,
                error = %e,
                "the cascade deferral refused the supersession"
            );
            caller_denial(epigraph_auth::claim_act::supersede_not_recorded_message(
                claim,
            ))
        }
        ClaimActRefusal::NotWriter => {
            tracing::warn!(
                target: "tenancy.scoped_write",
                tool = "supersede_claim",
                claim = %claim,
                error = %e,
                "the database refused the supersession"
            );
            caller_denial(SUPERSEDE_GROUP_WRITE_REFUSED.to_string())
        }
        ClaimActRefusal::CodedDenial | ClaimActRefusal::Other => crate::errors::db_caller_error(e),
        ClaimActRefusal::DeployFault => internal_error(e),
    }
}

/// Row security's refusal of a supersession, in the words the HTTP route
/// answers it with (`epigraph_api::errors::write_refused("claim")`).
pub const SUPERSEDE_GROUP_WRITE_REFUSED: &str =
    "no write authority over the group that owns this claim; nothing was written";

/// A denial of authority: `INVALID_REQUEST` with designed text.
fn caller_denial(message: String) -> McpError {
    McpError {
        code: rmcp::model::ErrorCode::INVALID_REQUEST,
        message: std::borrow::Cow::from(message),
        data: None,
    }
}

/// [`admin_session_or_deferral`] for `supersede_claim`: the deferral's own
/// refusal is answered by [`supersede_deferral_refusal`] for the trigger's
/// subject (the retired claim): CX03 as the caller's denial, anything else as
/// a fault. The other claim acts keep [`admin_session_or_deferral`].
///
/// # Errors
/// The deferral INSERT's error, mapped: the caller propagates it and nothing
/// commits.
pub async fn supersede_session_or_deferral<'s>(
    server: &'s EpiGraphMcpFull,
    tx: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
) -> Result<(Option<epigraph_db::MaintenanceSession<'s>>, CascadeStatus), McpError> {
    let claim = trigger.subject_id;
    admin_cascade::session_or_record_deferral(
        crate::maintenance::admin_cascade_session(server).await,
        tx,
        trigger,
    )
    .await
    .map_err(|e| supersede_deferral_refusal(claim, e))
}

/// Acquire the administrative (maintenance) session BEFORE the caller's act
/// commits. When there is none -- not configured, or not usable -- record the
/// deferral inside the act's own transaction `tx`, so the act and its audit row
/// commit together, and return that status. The core is
/// [`admin_cascade::session_or_record_deferral`], shared with the HTTP routes;
/// this answers its error as a [`ClaimActRefusal::DeployFault`].
///
/// # Errors
/// The deferral INSERT's error: the caller propagates it and nothing commits.
pub(crate) async fn admin_session_or_deferral<'s>(
    server: &'s EpiGraphMcpFull,
    tx: &mut sqlx::PgConnection,
    trigger: &CascadeTrigger,
) -> Result<(Option<epigraph_db::MaintenanceSession<'s>>, CascadeStatus), McpError> {
    let claim = trigger.subject_id;
    admin_cascade::session_or_record_deferral(
        crate::maintenance::admin_cascade_session(server).await,
        tx,
        trigger,
    )
    .await
    .map_err(|e| claim_act_refusal(ClaimActRefusal::DeployFault, claim, e))
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
) -> Result<
    (
        epigraph_db::ScopedTx<'p>,
        uuid::Uuid,
        uuid::Uuid,
        Option<LinkAdmission>,
    ),
    McpError,
> {
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
        let grant = crate::tools::claims::require_owner_or_admin(
            server,
            &mut tx,
            auth,
            caller,
            claim_author,
        )
        .await?;
        let link = grant.is_link().then_some(LinkAdmission {
            caller,
            author: claim_author,
        });
        return Ok((tx, caller.agent_id(), caller.agent_id(), link));
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
        return Ok((caller_tx, caller.agent_id(), caller.agent_id(), None));
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
    Ok((tx, server_agent.agent_id(), caller.agent_id(), None))
}

/// A claim act admitted through an operator link (`OwnershipGrant::is_link`):
/// the caller and the claim author it was admitted over. Returned by
/// [`begin_claim_act`] so an act that commits on ANOTHER transaction than the
/// gate's (the un-mark, on the administrative connection) can decide the
/// admission again there, under the link lock ([`LinkRecheck`]). An act that
/// commits on the transaction `begin_claim_act` returns needs nothing more:
/// the gate already read the link on it, under the lock.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LinkAdmission {
    caller: crate::write_identity::WriteIdentity,
    author: uuid::Uuid,
}

/// [`LinkAdmission`] decided again on the un-mark's own (administrative)
/// transaction, before its act: `require_owner_or_admin` on that transaction,
/// whose link arms take the link lock (backlog 9a5bc055). The un-mark's gate
/// ran on the caller's transaction and rolled it back, which released the lock;
/// without this a link retire committed between that gate and the un-mark's
/// commit did not stop the un-mark.
struct LinkRecheck<'a> {
    server: &'a EpiGraphMcpFull,
    auth: Option<&'a epigraph_auth::AuthContext>,
    link: LinkAdmission,
}

#[async_trait::async_trait]
impl admin_cascade::UnmarkPrecondition for LinkRecheck<'_> {
    async fn check(&self, tx: &mut sqlx::PgConnection) -> Result<(), String> {
        crate::tools::claims::require_owner_or_admin(
            self.server,
            tx,
            self.auth,
            self.link.caller,
            self.link.author,
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("{}; nothing was changed", e.message))
    }
}

pub async fn mark_duplicate(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: MarkDuplicateParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let dup = parse_uuid(&params.claim_id)?;
    let canon = parse_uuid(&params.canonical_id)?;
    let out = mark_duplicate_pair(
        server,
        viewer,
        auth,
        dup,
        canon,
        params.reason.as_deref(),
        "mark_duplicate",
    )
    .await?;
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&out).map_err(internal_error)?,
    )]))
}

/// The gate `mark_duplicate` applies before it writes `dup` onto `canon`,
/// and nothing else: the caller's authority over both claims, read through
/// the caller ([`begin_claim_act`]). The transaction it opens is rolled back.
/// Returns the principal the act would be stamped as (the caller, or this
/// server's agent on a `claims:admin` borrow) and, for a grant through an
/// operator link, the [`LinkAdmission`] to decide again on the transaction
/// that commits. [`mark_duplicates_onto`] asks it for every duplicate before
/// it opens its one transaction.
async fn mark_duplicate_preflight(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    dup: uuid::Uuid,
    canon: uuid::Uuid,
    tool: &'static str,
) -> Result<(uuid::Uuid, Option<LinkAdmission>), McpError> {
    let (tx, actor, _, link) = begin_claim_act(
        server,
        viewer,
        auth,
        dup,
        Some(canon),
        tool,
        "mark as a duplicate",
    )
    .await?;
    drop(tx);
    Ok((actor, link))
}

/// Several dedup acts onto ONE canonical, all or nothing
/// (`consolidate_claims(mode='identity')`, backlog 635dbfae). Each duplicate
/// gets exactly what [`mark_duplicate_pair`] gives one: the act with its
/// identity edge, then the cascade. Returns one `mark_duplicate` answer per
/// duplicate, in the order given.
///
/// 1. Every pair's gate ([`mark_duplicate_preflight`]) first, each on its own
///    rolled-back transaction, so one pair the caller may not mark refuses
///    the call before anything is written.
/// 2. ONE transaction, stamped as those gates decided, holds every act. All
///    the pairs must share that stamp: a `claims:admin` caller that writes
///    some duplicates' owning groups and not others' would need two stamps,
///    and is refused with nothing written (split the call).
/// 3. Inside it, every duplicate, and the canonical where the stamp can lock
///    it, is locked in id order and re-checked
///    ([`ClaimRepository::lock_dedup_sources_conn`]): a duplicate another
///    writer marked, revised or retired after the gates, or a canonical
///    another writer retired, refuses the whole batch. Any refusal before the
///    commit rolls back every mark; the answer says no source was marked.
/// 4. The administrative session is asked for once, before the commit; with
///    none, each duplicate's cascade deferral is recorded inside the same
///    transaction. After the commit the cascades run one by one on that
///    session, best-effort, as for a single mark.
///
/// A canonical the stamp cannot write (a `claims:admin` caller marking onto
/// a claim it may only read) cannot be locked, since a lock takes the UPDATE
/// policy. Each act still refuses a canonical that is not current when it
/// runs, which rolls the batch back too; only a retirement between the last
/// act and the commit is then not seen, as for a single `mark_duplicate`.
///
/// `dups` must be distinct and must not contain `canon`; the caller checks.
pub(crate) async fn mark_duplicates_onto(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    dups: &[uuid::Uuid],
    canon: uuid::Uuid,
    reason: Option<&str>,
    tool: &'static str,
) -> Result<Vec<serde_json::Value>, McpError> {
    let Some(&first) = dups.first() else {
        return Ok(Vec::new());
    };

    // 1. Every gate, before anything is written; each names its stamp.
    let mut stamp: Option<uuid::Uuid> = None;
    let mut links: Vec<LinkAdmission> = Vec::new();
    for dup in dups {
        let (actor, link) =
            mark_duplicate_preflight(server, viewer, auth, *dup, canon, tool).await?;
        links.extend(link);
        match stamp {
            None => stamp = Some(actor),
            Some(s) if s == actor => {}
            Some(_) => {
                return Err(invalid_params(format!(
                    "{tool}: claims {first} and {dup} would be marked under different write \
                     identities (your own for a claim whose owning group you write, this \
                     server's agent through the claims:admin borrow for one you do not), and \
                     the marks are one transaction, which carries one; nothing was written. \
                     Split the call by owning group."
                )))
            }
        }
    }

    // 2. The one transaction. The identity edges are attested at INSERT with
    // the server's key (backlog `dae795f8`), resolved before it opens.
    let edge_key = server.edge_signing_key().await?;
    let (mut tx, actor, _, _) = begin_claim_act(
        server,
        viewer,
        auth,
        first,
        Some(canon),
        tool,
        "mark as a duplicate",
    )
    .await?;
    if stamp != Some(actor) {
        return Err(invalid_params(format!(
            "{tool}: the write identity for claim {first} changed while the call ran (a \
             membership change); nothing was written. Retry."
        )));
    }
    // Every grant the gates made through an operator link is decided again
    // HERE, on the transaction that commits the marks, whose link arms take
    // the link lock (backlog 9a5bc055): each gate ran on its own transaction
    // and rolled it back, which released the lock, so a link retired since
    // then must still refuse the batch before anything is written.
    for link in &links {
        crate::tools::claims::require_owner_or_admin(
            server,
            &mut tx,
            auth,
            link.caller,
            link.author,
        )
        .await?;
    }
    let n = dups.len();
    let rolled_back = |e: epigraph_db::DbError| -> McpError {
        let mut err = match e {
            // A source another writer changed (or removed) since the gates,
            // or a malformed pair: the caller's to re-read, not a fault to
            // retry blindly.
            epigraph_db::DbError::Refused {
                kind: epigraph_db::RefusalKind::State | epigraph_db::RefusalKind::Input,
                message,
            } => invalid_params(message),
            e @ epigraph_db::DbError::NotFound { .. } => invalid_params(e.to_string()),
            // A denial of the caller's authority the gates do not predict
            // (the act's FA04 / FA07 refusals, a row-security refusal): the
            // denial class, as `db_caller_error` answers it on every write
            // tool, not a server fault an agent would retry.
            epigraph_db::DbError::Refused {
                kind: epigraph_db::RefusalKind::Authority,
                message,
            } => McpError {
                code: rmcp::model::ErrorCode::INVALID_REQUEST,
                message: message.into(),
                data: None,
            },
            other
                if matches!(other, epigraph_db::DbError::WriteRefused { .. })
                    || other.is_write_authority_refusal() =>
            {
                crate::errors::db_caller_error(other)
            }
            other => internal_error(other),
        };
        err.message = format!(
            "{} (no source was marked: the {n} marks are one transaction, and this refusal \
             rolled it back)",
            err.message
        )
        .into();
        err
    };

    // 3. Lock and re-check every duplicate, then every act.
    ClaimRepository::lock_dedup_sources_conn(&mut tx, dups, canon)
        .await
        .map_err(rolled_back)?;
    let provenance = DuplicateProvenance::new(tool, DuplicateProvenance::RULE_CALLER_ASSERTED)
        .marked_by(Some(actor))
        .reason(reason);
    for dup in dups {
        ClaimRepository::mark_duplicate_act_attributed_conn(
            &mut tx,
            Some(edge_key),
            ClaimId::from_uuid(*dup),
            ClaimId::from_uuid(canon),
            &provenance,
        )
        .await
        .map_err(rolled_back)?;
    }

    // 4. One administrative session for every cascade, or every deferral
    // recorded with the acts.
    let triggers: Vec<CascadeTrigger> = dups
        .iter()
        .map(|dup| {
            CascadeTrigger::new(
                CascadeCause::Dedup,
                Some(actor),
                auth.map(OauthPrincipal::from),
                *dup,
                Some(canon),
            )
        })
        .collect();
    let (mut session, deferred) = match crate::maintenance::admin_cascade_session(server).await {
        Ok(session) => (Some(session), Vec::new()),
        Err(why) => {
            let mut deferred = Vec::with_capacity(n);
            for trigger in &triggers {
                deferred.push(
                    admin_cascade::record_deferral(&mut *tx, trigger, &why)
                        .await
                        .map_err(rolled_back)?,
                );
            }
            (None, deferred)
        }
    };
    // A failed COMMIT is not a known rollback: the server may have committed
    // before the connection failed, so the answer must not say nothing was
    // marked.
    tx.commit().await.map_err(|e| {
        crate::errors::internal_error_logged(
            format!(
                "{tool}: the commit of the {n} marks failed, and whether they stand is unknown; \
                 re-read the sources before retrying"
            ),
            e,
        )
    })?;

    let mut deferred = deferred.into_iter();
    let mut out = Vec::with_capacity(n);
    for (dup, trigger) in dups.iter().zip(&triggers) {
        let (cascade, belief_cascade) = match session.as_mut() {
            Some(session) => {
                let (conn, v) = session.split();
                admin_cascade::apply_after_dedup(conn, v, viewer, trigger, *dup, canon).await
            }
            None => (
                deferred.next().unwrap_or_default(),
                CascadeReport::default(),
            ),
        };
        out.push(serde_json::json!({
            "duplicate_id": dup,
            "canonical_id": canon,
            "mode": "mark_duplicate",
            "cascade": cascade,
            "belief_cascade": belief_cascade,
        }));
    }
    Ok(out)
}

/// One dedup act, `dup` onto `canon`, and its cascade: the whole of
/// `mark_duplicate`. `tool` is recorded in the identity edge's provenance.
/// Several duplicates onto one canonical go through [`mark_duplicates_onto`]
/// instead, which holds every act in one transaction.
pub(crate) async fn mark_duplicate_pair(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    auth: Option<&epigraph_auth::AuthContext>,
    dup: uuid::Uuid,
    canon: uuid::Uuid,
    reason: Option<&str>,
    tool: &'static str,
) -> Result<serde_json::Value, McpError> {
    let dup_claim_id = ClaimId::from_uuid(dup);

    // THE ACT's gate and stamp (batch OA1), as `supersede_claim` above: the
    // caller must be able to write BOTH the duplicate and the canonical (or
    // hold claims:admin). The act writes the duplicate's row alone, but the
    // cascade re-points other writers' edges and BBAs onto the canonical, so
    // the canonical is the caller's choice to make only where it could write
    // itself. Either one the caller cannot read is reported as not found,
    // exactly like a missing claim.
    // The identity edge is attested at INSERT with the server's key (backlog
    // `dae795f8`), resolved before the act's transaction opens.
    let edge_key = server.edge_signing_key().await?;
    let (mut tx, actor, _, _) = begin_claim_act(
        server,
        viewer,
        auth,
        dup,
        Some(canon),
        tool,
        "mark as a duplicate",
    )
    .await?;

    let provenance = DuplicateProvenance::new(tool, DuplicateProvenance::RULE_CALLER_ASSERTED)
        .marked_by(Some(actor))
        .reason(reason);
    ClaimRepository::mark_duplicate_act_attributed_conn(
        &mut tx,
        Some(edge_key),
        dup_claim_id,
        ClaimId::from_uuid(canon),
        &provenance,
    )
    .await
    .map_err(internal_error)?;

    let trigger = CascadeTrigger::new(
        CascadeCause::Dedup,
        Some(actor),
        auth.map(OauthPrincipal::from),
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

    Ok(serde_json::json!({
        "duplicate_id": dup,
        "canonical_id": canon,
        "mode": "mark_duplicate",
        "cascade": cascade,
        "belief_cascade": belief_cascade,
    }))
}

/// The refusal an un-mark gets on a server without the administrative
/// connection: unlike a mark, an un-mark has no deferred form (migration 117's
/// deferral definer accepts no such cause), so nothing is written. It names
/// the operator CLI that runs the un-mark instead (backlog e8113079).
pub const UNMARK_NEEDS_ADMIN_CONNECTION: &str =
    "unmark_duplicate needs this server's administrative (maintenance) connection: an \
     un-mark is the dedup's act and its reversal together and cannot be deferred to the \
     replay; nothing was written. An operator runs it as the `unmark_duplicate` CLI on the \
     maintenance DSN";

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
    /// Set when the gate admitted the caller through an operator link: the
    /// un-mark decides it again on its own transaction ([`LinkRecheck`]).
    link: Option<LinkAdmission>,
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
    let (mut tx, actor, _, link) = begin_claim_act(
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
        let (mut tx, _, _, _) = begin_claim_act(
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
        link,
    })
}

/// The answer the un-mark tools give when the administrative un-mark changed
/// nothing ([`admin_cascade::UnmarkRefusal`]): an act refusal of authority is
/// a denial (`INVALID_REQUEST`), as on every other write tool; any other act
/// refusal, and a mark with no record to reverse, is the caller's to correct
/// (`INVALID_PARAMS`), with its text; a failure is a redacted internal error.
pub(crate) fn unmark_refusal(e: admin_cascade::UnmarkRefusal) -> McpError {
    match e {
        admin_cascade::UnmarkRefusal::Act {
            kind: epigraph_db::RefusalKind::Authority,
            message,
        } => caller_denial(message),
        e @ (admin_cascade::UnmarkRefusal::Act { .. } | admin_cascade::UnmarkRefusal::NoRecord) => {
            invalid_params(e.to_string())
        }
        e @ admin_cascade::UnmarkRefusal::Failed(_) => internal_error(e),
    }
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
        link,
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
        auth.map(OauthPrincipal::from),
        dup,
        Some(canonical),
    );
    let recheck = link.map(|link| LinkRecheck { server, auth, link });
    let (conn, admin_viewer) = session.split();
    let (outcome, belief_cascade) = admin_cascade::apply_unmark_checked(
        conn,
        admin_viewer,
        viewer,
        &trigger,
        dup,
        canonical,
        Some(&chain),
        recheck
            .as_ref()
            .map(|r| r as &dyn admin_cascade::UnmarkPrecondition),
    )
    .await
    .map_err(unmark_refusal)?;

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

/// The supersede refusal mappers, pinned byte for byte by refusal kind
/// (`epigraph_auth::claim_act::ClaimActRefusal`): each row is a database
/// error as the driver raises it and the exact `McpError` the caller gets.
#[cfg(test)]
mod refusal_table {
    use super::{supersede_deferral_refusal, supersede_refusal};
    use rmcp::model::ErrorCode;
    use std::borrow::Cow;

    #[derive(Debug)]
    struct FakeDbError {
        code: &'static str,
        message: String,
    }
    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }
    impl std::error::Error for FakeDbError {}
    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            &self.message
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn db(code: &'static str, message: &str) -> epigraph_db::DbError {
        epigraph_db::DbError::QueryFailed {
            source: sqlx::Error::Database(Box::new(FakeDbError {
                code,
                message: message.to_string(),
            })),
        }
    }

    const RLS: &str = "new row violates row-level security policy for table \"claims\"";
    const NO_EXECUTE: &str = "permission denied for function epigraph_record_cascade_deferral";
    const GROUP_WRITE: &str =
        "no write authority over the group that owns this claim; nothing was written";

    fn not_recorded(claim: uuid::Uuid) -> String {
        format!(
            "CX03: the supersession of claim {claim} cannot be recorded: the session acting on \
             it does not write the group that owns the claim; nothing was written"
        )
    }

    /// The redacted `INTERNAL_ERROR` text a fault gets: whatever it is, it is
    /// not the driver's message.
    fn assert_redacted_fault(got: &crate::errors::McpError, secret: &str, row: &str) {
        assert_eq!(got.code, ErrorCode::INTERNAL_ERROR, "{row}: {got:?}");
        assert!(!got.message.contains(secret), "{row}: {got:?}");
        assert!(!got.message.contains(GROUP_WRITE), "{row}: {got:?}");
    }

    /// The ACT: CX03, row security's uncoded 42501 (not writer), a coded
    /// 42501 (unlisted, then a reviewed supersede code), CX03's text on
    /// another SQLSTATE, an uncoded fault, and two repo refusals.
    #[test]
    fn every_act_refusal_kind_maps_to_its_exact_answer() {
        let c = uuid::Uuid::new_v4();
        let rows: [(&str, epigraph_db::DbError, ErrorCode, String); 7] = [
            (
                "cx03",
                db("42501", "CX03: not recorded as one this session made"),
                ErrorCode::INVALID_REQUEST,
                not_recorded(c),
            ),
            (
                "not writer: row security",
                db("42501", RLS),
                ErrorCode::INVALID_REQUEST,
                GROUP_WRITE.to_string(),
            ),
            (
                "not writer: uncoded engine 42501",
                db("42501", "permission denied for table claims"),
                ErrorCode::INVALID_REQUEST,
                GROUP_WRITE.to_string(),
            ),
            (
                "coded denial, unlisted: keeps its code as INTERNAL_ERROR",
                db("42501", "ZZ99: a probe refusal"),
                ErrorCode::INTERNAL_ERROR,
                "ZZ99: a probe refusal".to_string(),
            ),
            (
                "coded denial, a reviewed supersede code",
                db("42501", "SR09: a reviewed refusal"),
                ErrorCode::INVALID_REQUEST,
                "SR09: a reviewed refusal".to_string(),
            ),
            (
                "other: CX03's text on another SQLSTATE is not the CX03 denial",
                db("P0001", "CX03: raised elsewhere"),
                ErrorCode::INTERNAL_ERROR,
                "CX03: raised elsewhere".to_string(),
            ),
            (
                "other: a write row security hid",
                epigraph_db::DbError::WriteRefused {
                    entity: "claim".into(),
                    id: c,
                    action: "supersede".into(),
                },
                ErrorCode::INVALID_REQUEST,
                format!(
                    "supersede of claim {c} was refused: this session may read it but not \
                     supersede it; nothing was changed"
                ),
            ),
        ];
        for (row, e, code, message) in rows {
            let got = supersede_refusal(c, e);
            assert_eq!(got.code, code, "{row}: {got:?}");
            assert_eq!(got.message, message, "{row}");
            assert_eq!(got.data, None, "{row}");
        }

        // An uncoded fault on another SQLSTATE stays a redacted fault.
        let fault = supersede_refusal(c, db("XX000", "internal driver detail"));
        assert_redacted_fault(&fault, "internal driver detail", "other: uncoded fault");
    }

    /// The DEFERRAL: CX03 is the act's own denial, byte for byte; any other
    /// refusal (the missing EXECUTE grant's uncoded 42501 included) is a
    /// fault, never the group-write denial.
    #[test]
    fn every_deferral_refusal_kind_maps_to_its_exact_answer() {
        let c = uuid::Uuid::new_v4();
        let cx03 = supersede_deferral_refusal(c, db("42501", "CX03: not recorded"));
        assert_eq!(cx03.code, ErrorCode::INVALID_REQUEST, "{cx03:?}");
        assert_eq!(cx03.message, not_recorded(c));
        assert_eq!(
            cx03.message,
            supersede_refusal(c, db("42501", "CX03: from the act")).message,
            "CX03 reads the same whichever statement raised it"
        );

        let grant = supersede_deferral_refusal(c, db("42501", NO_EXECUTE));
        assert_redacted_fault(&grant, NO_EXECUTE, "deploy fault: missing EXECUTE");

        let coded = supersede_deferral_refusal(c, db("42501", "ZZ99: a probe refusal"));
        assert_eq!(coded.code, ErrorCode::INTERNAL_ERROR, "{coded:?}");
        assert_eq!(coded.message, "ZZ99: a probe refusal");

        let other = supersede_deferral_refusal(c, db("XX000", "internal driver detail"));
        assert_redacted_fault(&other, "internal driver detail", "deploy fault: uncoded");
    }
}

#[cfg(test)]
mod tests {
    use super::unmark_refusal;
    use epigraph_db::RefusalKind;
    use epigraph_engine::admin_cascade::UnmarkRefusal;
    use rmcp::model::ErrorCode;

    /// An un-mark's act refusal of AUTHORITY is a denial (`INVALID_REQUEST`),
    /// as on every other write tool; its other refusals stay the caller's to
    /// correct (`INVALID_PARAMS`) with their text; a failure is redacted
    /// (backlog dca9ed56: the act's driver errors used to be stringified into
    /// the refusal and sent).
    #[test]
    fn an_unmark_refusal_is_answered_by_its_kind() {
        let act = |kind| UnmarkRefusal::Act {
            kind,
            message: "unmark_duplicate: refused".into(),
        };
        let denial = unmark_refusal(act(RefusalKind::Authority));
        assert_eq!(denial.code, ErrorCode::INVALID_REQUEST, "{denial:?}");
        assert_eq!(denial.message, "unmark_duplicate: refused");
        for kind in [RefusalKind::Input, RefusalKind::State] {
            let e = unmark_refusal(act(kind));
            assert_eq!(e.code, ErrorCode::INVALID_PARAMS, "{kind:?}: {e:?}");
            assert_eq!(e.message, "unmark_duplicate: refused");
        }
        let none = unmark_refusal(UnmarkRefusal::NoRecord);
        assert_eq!(none.code, ErrorCode::INVALID_PARAMS, "{none:?}");
        let failed = unmark_refusal(UnmarkRefusal::Failed(
            "Query failed: canceling statement due to lock timeout".into(),
        ));
        assert_eq!(failed.code, ErrorCode::INTERNAL_ERROR, "{failed:?}");
        assert!(!failed.message.contains("lock timeout"), "{failed:?}");
    }
}
