//! Caller authority over a hierarchical workflow (batch H-b, H3; backlog
//! 84b2a98d).
//!
//! # The measurement that bounds this module
//!
//! Every write a workflow mutation makes used to be authored by, and stamped
//! from, the registered workflow-ingest system agent, and before batch H-b
//! nothing on that path asked whether the CALLER had any authority over the
//! workflow it named (since workflow writes moved to the caller, the rows are
//! authored by and stamped from the caller itself,
//! `claim_helper::begin_caller_workflow_tx`; this gate is unchanged): any `claims:write` caller could
//! `add_step` / `delete_step` on any workflow (the e2e `delete_step` arm drove a
//! step's truth to 0.05 with no relation between caller and workflow).
//!
//! Measured on `origin/main` before choosing a rule: the `workflows` table has
//! no owner column, its claims are all the system agent's, and the executor
//! records no submitter anywhere. "Owner" is therefore UNDEFINED for every
//! workflow written before this change, and inventing one (the system agent,
//! the first `executes` edge's author, ...) would be a guess dressed as a rule.
//!
//! # The rule, forward-only
//!
//! * A workflow row CREATED through an ingest entry point records its submitter
//!   — the request's write identity — once, under
//!   `WorkflowRepository::SUBMITTER_KEY` in `metadata`. A re-ingest never
//!   overwrites it, and the key is stripped from caller-supplied metadata so it
//!   cannot be forged.
//! * A NEW GENERATION of a canonical name that already has rows is a generation
//!   of THAT lineage, whether or not the caller names a parent. It requires
//!   authority over the lineage's current head and INHERITS the head's
//!   submitter (an unrecorded head passes on no record). Batch H-b review,
//!   measured on the real binary: the first revision checked authority only
//!   when `parent_canonical_name` was set, so any `claims:write` caller could
//!   ingest `generation + 1` of another agent's lineage with no parent, be
//!   recorded as its submitter, and then pass every head-keyed check
//!   (`add_step`, `delete_step`, `improve_workflow_hierarchy`) while the real
//!   submitter was refused on its own lineage.
//! * Every new generation that links a parent — a variant ingest
//!   (`parent_canonical_name` set), or since U032 an unnamed generation > 0
//!   linked to its lineage predecessor — also requires authority over EXACTLY
//!   the row the executor links as `parent_id`
//!   (`WorkflowRepository::ingest_anchors`, via
//!   `WorkflowRepository::resolve_ingest_parent`), not the latest generation of
//!   the parent's name, and inherits that row's submitter when the name is new.
//! * `add_step`, `delete_step`, `deprecate_workflow`, `evolve_step` and every
//!   new generation require, over the AUTHENTICATED transport and when a
//!   submitter is recorded, in this order: the submitter; its operator (#503,
//!   the operator itself as on every HTTP gate); a WRITER OF THE WORKFLOW'S
//!   OWNER GROUP; or the AUDITED admin arm. Agents bound to the submitter's
//!   human are not admitted as such over HTTP (operator ruling, 2026-10-13: the
//!   shared host credential must not gain edit rights over a human's
//!   workflows); their authority traces to the human through `OPERATED_BY` /
//!   the author binding, and their authorship through the `AUTHORED` edges
//!   below.
//! * THE OWNER-GROUP WRITER ARM. A team's workflows are the team's: a caller
//!   that holds a live writer or admin membership of the row's owner group
//!   (direct or through a role binding, checked live on the write's own
//!   transaction by `epigraph_ingest_executor::caller_writes_group_now`, which
//!   also asks the session stamp) may edit it and publish its next generation,
//!   whoever submitted it, and on a row with no recorded submitter too. An
//!   operator link or an author binding confers no membership, so an agent
//!   bound to a human is admitted over the human's workflows only where it
//!   holds a membership row of their owner group itself. Recorded as
//!   `"arm": "owner_group_writer"` with the `owner_group`.
//! * STDIO (backlog 222289f3, reversing the batch H-b bar that left stdio
//!   unchecked). The writes run on the system agent's stamp, which writes
//!   every group the system agent is a writer of, so an unchecked stdio caller
//!   could add a step to, soft-delete the steps of, mint the next generation
//!   of, or deprecate a GROUP-PRIVATE lineage it could not even read, while the
//!   REST twins refused the same outsider. The stdio caller (this server's own
//!   agent, the write identity) is now checked against the TARGET row
//!   ([`stdio_workflow_authority`]): it must READ the row on its OWN stamp
//!   (a row it cannot read is refused without naming it) and, for a group row,
//!   WRITE the row's owner group; then a recorded submitter admits the
//!   submitter, its operator (the operator itself, as over HTTP), or a live
//!   writer of the row's owner group (there is no admin arm without a token). Two stdio-only arms remain, both recorded:
//!   a LEGACY row (no recorded submitter) that passes the read (and group
//!   write) check is admitted (stdio has no audited admin path to send it to; an operator
//!   ruling may close this), and a server with NO declared signer identity
//!   (`--agent-key` / `--agent-model` absent, a random per-process agent) is
//!   admitted on a submitted row that passes the same check, with a WARN, because
//!   ownership is undecidable for it, exactly as
//!   `tools::claims::require_owner_or_admin`'s stdio arm decides for claims.
//!   The submitter is still INHERITED by a new generation: only the submitter
//!   or its operator can add one now, so the inheritance names the truth.
//! * PROVENANCE. Every write admitted over the authenticated transport is
//!   recorded on its own transaction ([`record_workflow_write`]): the admin
//!   arm's `workflows.admin_write` row, and for the submitter and operator arms
//!   one `workflows.caller_write` `security_events` row
//!   ([`record_caller_workflow_write`]) naming the `arm`, the `acting_agent`,
//!   the human it acted for (`operator`, on the operator arm), the
//!   `submitter`, the tool (`action`), the `workflow_id`, the token
//!   (`client_id`, `token_jti`) and the tool's own facts (`write`). The row is
//!   attributed to the session principal (077's `security_events_append`
//!   admits no other attribution), which is now the caller itself; the actor
//!   is `acting_agent`. A new generation records one row per anchor it
//!   was checked against, naming the anchor and the row it created. A stdio
//!   write records the same `workflows.caller_write` row with
//!   `"transport": "stdio"` and no token (`client_id` / `token_jti` null).
//! * AUTHORSHIP, on EVERY transport (stdio included). Every claim a workflow
//!   mutation CREATES gets an `AUTHORED` edge (agent -> claim) from the ACTING
//!   agent (the caller over HTTP, this server's pinned agent on stdio), on the
//!   write's own transaction
//!   (`epigraph_ingest_executor::record_caller_authorship`). The claims are
//!   authored by that same acting agent (`claims.agent_id`) since workflow
//!   writes moved to the caller; the edge is the graph form of it. Only claims the
//!   call CREATED get one: a reused claim (a step already present, an
//!   operation atom shared with another workflow or a document, a re-ingest)
//!   keeps the edge of the agent that created it. The edge is idempotent, its
//!   tenancy is the edges trigger's, and `delete_step` / `deprecate_workflow`
//!   create no claims and write none (the provenance row records who acted).
//! * THE ADMIN ARM IS NOT THE TOKEN'S SCOPE. It was: the first revision reused
//!   [`crate::tools::claims::require_owner_or_admin`], which admits on
//!   `claims:admin` in the token alone, and the write then ran on the system
//!   stamp, where RLS is no backstop because the rows are system-owned. So a
//!   token whose client record grants nothing kept cross-owner workflow
//!   mutation (measured) while the same token was refused `ADM02` on
//!   `update_labels`. Now the client record is re-checked with migration 111's
//!   predicate (active, `claims:admin` granted, bound to the principal), and
//!   the write records a `workflows.admin_write` `security_events` row on its
//!   own transaction, naming the admin, the token, the workflow, its submitter
//!   and what was written (D2's semantics for a write that needs no definer).
//! * A workflow with NO record (every workflow written before batch H-b) is
//!   PLATFORM CORPUS (U005, default decision A, following the D1 ruling that
//!   the legacy corpus stays platform-owned). Over the authenticated transport
//!   it is mutable ONLY through the audited admin arm, whose audit row records
//!   `"submitter": null`; everyone else, the agent that happened to ingest it
//!   included, is refused with "no recorded submitter". It used to keep the
//!   pre-H-b behaviour with a WARN, which left any `claims:write` token able to
//!   `delete_step` on the whole legacy corpus. A new generation of a legacy
//!   lineage inherits no record, so platform lineage stays platform. No
//!   submitter is backfilled: there is no provenance to backfill from. On
//!   stdio a legacy row is admitted only to a caller that reads it and, for a
//!   group row, writes its owner group (see STDIO above). When the custodian role
//!   (#529) lands, its check replaces `claims:admin` in `admin_arm`.
//! * A refusal names the WORKFLOW and its submitter. It used to reuse the claim
//!   gate's text ("claim is owned by agent X ... cannot retire it"), which named
//!   the wrong object and the wrong verb. It names them only to a caller that
//!   can READ the row (backlog c831df4a, ruling R-100): the act's transaction is
//!   often the ingest system agent's, which reads groups the caller does not,
//!   so a REFUSAL to a caller that cannot read the row is the call site's
//!   not-found answer, with no id, no submitter and no arm. Only the answer
//!   changes: the arms admit exactly whom they admitted before.
//!
//! Writing as the caller adds the database's own check on top of these arms
//! for the rows a write CREATES: they land in a group the caller writes
//! (`epigraph_ingest_executor::owner`) and row security refuses a new claim or
//! edge in one it does not. It is not a check on the existing `workflows` row
//! itself: migration 183's `workflows_update` policy admits an UPDATE of any
//! public row, so an entry point must never update an existing row on a path
//! these arms did not admit (a re-ingest stores no goal embedding).

use crate::errors::{internal_error_logged, internal_error_text, McpError};
use crate::server::EpiGraphMcpFull;
use crate::write_identity::WriteIdentity;

/// Which arm of [`require_workflow_authority`] admitted the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkflowArm {
    /// The caller is the recorded submitter.
    Submitter,
    /// The caller is the operator of the submitter (#503).
    Operator,
    /// The caller writes the workflow's owner group `group`, live.
    OwnerGroupWriter { group: uuid::Uuid },
    /// The AUDITED admin arm.
    Admin,
    /// stdio only: a row with no recorded submitter (platform corpus) that
    /// the caller reads (and, for a group row, whose owner group it writes).
    StdioLegacy,
    /// stdio only: this server has no declared signer identity, so ownership
    /// of a submitted row is undecidable; admitted on a row that passes the
    /// read (and group write) check, with a WARN.
    StdioUndeclaredSigner,
}

/// What [`require_workflow_authority`] admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkflowGrant {
    /// The workflow's recorded submitter, if any.
    pub owner: Option<uuid::Uuid>,
    /// The arm that admitted the caller. Every write it admits records it on
    /// the same transaction through [`record_workflow_write`].
    pub arm: WorkflowArm,
}

impl WorkflowGrant {
    /// Admitted ONLY through the audited admin arm.
    pub(crate) fn is_admin(&self) -> bool {
        matches!(self.arm, WorkflowArm::Admin)
    }
}

/// Refuse the caller unless it has authority over workflow `workflow_id`; see
/// the module doc for the rule and the order of its arms.
///
/// `not_found` is the CALL SITE's answer for a workflow that does not exist
/// (a step tool's unknown name, `evolve_step`'s unknown parent, ...). Over the
/// authenticated transport every REFUSAL to a caller that cannot READ the row
/// is exactly that answer, never text naming the row or its submitter
/// (backlog c831df4a, ruling R-100: ids stay deterministic, so the answer
/// must not confirm one). The act's transaction may be stamped with the
/// ingest system agent, which reads groups the caller does not; the caller's
/// own view decides what it is told. It does not decide who is admitted: the
/// ruling masks answers and changes no authority, so the submitter, operator
/// and admin arms run exactly as before, whether or not the caller reads the
/// row.
///
/// # Errors
/// A workflow-specific refusal naming the submitter (never the claim gate's
/// "cannot retire it" wording, which named the wrong object and verb), the
/// call site's not-found answer for a row the caller cannot read, or an
/// internal error if the caller's view, the submitter, the operator link or
/// the admin grant cannot be read.
pub(crate) async fn require_workflow_authority(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    workflow_id: uuid::Uuid,
    tool_name: &'static str,
    not_found: &(dyn Fn() -> McpError + Send + Sync),
) -> Result<WorkflowGrant, McpError> {
    let owner = epigraph_db::WorkflowRepository::submitter_of(&mut *conn, workflow_id)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!("{tool_name}: could not read the workflow's submitter"),
                e,
            )
        })?;
    let grant = |arm| WorkflowGrant { owner, arm };
    // stdio (backlog 222289f3): no token, so the caller is this server's own
    // agent, checked against the target row on its own stamp.
    let Some(auth) = auth else {
        let arm =
            stdio_workflow_authority(server, conn, caller, workflow_id, owner, tool_name).await?;
        return Ok(grant(arm));
    };
    let caller_agent = caller.agent_id();
    // The CALLER's view of the row (backlog c831df4a). It words refusals only:
    // a refusal to a caller that cannot read the row is answered as the call
    // site answers an unknown one, and names nothing. Admission is unchanged.
    let view = caller_view_of(server, conn, caller_agent, workflow_id, tool_name).await?;
    let readable = view.is_some();
    let refuse = |text: String| {
        if readable {
            crate::errors::invalid_params(text)
        } else {
            not_found()
        }
    };
    // A workflow with NO recorded submitter (written before batch H-b) has no
    // submitter to match and no operator to derive: a writer of its owner
    // group, or the audited admin arm. When the custodian role lands (#529),
    // its check replaces `claims:admin` here. A GROUP row with no record (a
    // plan migration 183 backfilled into its group) is the group's, not the
    // platform's, and is not called one.
    let Some(owner) = owner else {
        if let Some(group) = owner_group_arm(conn, caller_agent, view.as_ref(), tool_name).await? {
            return Ok(grant(WorkflowArm::OwnerGroupWriter { group }));
        }
        let group_row = matches!(view.as_ref(), Some((visibility, _)) if visibility == "group");
        let (subject, kind) = if group_row {
            (
                format!(
                    "workflow {workflow_id} has no recorded submitter (a group workflow written \
                     before batch H-b)"
                ),
                "a workflow with no recorded submitter",
            )
        } else {
            (
                format!(
                    "workflow {workflow_id} has no recorded submitter (legacy platform \
                     workflow, written before batch H-b)"
                ),
                "a legacy platform workflow",
            )
        };
        let needs = "a writer of the workflow's owner group, or a live claims:admin grant (the \
                     audited claims:admin path)";
        return match admin_arm(
            conn,
            auth,
            caller_agent,
            &subject,
            needs,
            tool_name,
            &refuse,
        )
        .await?
        {
            Some(()) => Ok(grant(WorkflowArm::Admin)),
            None => Err(refuse(format!(
                "{subject}; caller agent {caller_agent} does not write the workflow's owner \
                 group and holds no claims:admin. {tool_name} on {kind} requires a writer of its \
                 owner group or the audited claims:admin path. Nothing was written."
            ))),
        };
    };
    // 1. The submitter.
    if caller_agent == owner {
        return Ok(grant(WorkflowArm::Submitter));
    }
    // 2. The submitter's operator (#503; HTTP admits the operator itself, never
    //    the actor arm, exactly as `require_owner_or_admin` does).
    if crate::tools::claims::operator_arm_allows(server, caller_agent, owner, false).await? {
        return Ok(grant(WorkflowArm::Operator));
    }
    // 3. A writer of the workflow's owner group.
    if let Some(group) = owner_group_arm(conn, caller_agent, view.as_ref(), tool_name).await? {
        return Ok(grant(WorkflowArm::OwnerGroupWriter { group }));
    }
    // 4. The AUDITED admin arm.
    let subject = format!("workflow {workflow_id} was submitted by agent {owner}");
    let needs = "the workflow's submitter, the submitter's operator, a writer of its owner \
                 group, or a live claims:admin grant";
    if admin_arm(
        conn,
        auth,
        caller_agent,
        &subject,
        needs,
        tool_name,
        &refuse,
    )
    .await?
    .is_some()
    {
        return Ok(grant(WorkflowArm::Admin));
    }
    Err(refuse(format!(
        "workflow {workflow_id} was submitted by agent {owner}; caller agent {caller_agent} is \
         neither that submitter nor its operator, does not write the workflow's owner group, and \
         holds no claims:admin. {tool_name} requires the workflow's submitter, the submitter's \
         operator, a writer of its owner group, or the audited claims:admin path. Nothing was \
         written."
    )))
}

/// The owner-group writer arm: `Some(group)` when the caller can READ the row
/// (`view`, its own view of it) and holds a live writer or admin membership
/// of the row's owner group NOW, on `conn` (the write's own transaction,
/// stamped from the caller): the live-membership definer and the session
/// stamp both (`epigraph_ingest_executor::caller_writes_group_now`). An
/// operator link or an author binding is not a membership, so it admits no
/// agent bound to a human through them alone.
async fn owner_group_arm(
    conn: &mut sqlx::PgConnection,
    caller_agent: uuid::Uuid,
    view: Option<&(String, uuid::Uuid)>,
    tool_name: &'static str,
) -> Result<Option<uuid::Uuid>, McpError> {
    let Some((_, group)) = view else {
        return Ok(None);
    };
    let writes = epigraph_ingest_executor::caller_writes_group_now(conn, caller_agent, *group)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!("{tool_name}: could not check the caller's owner-group membership"),
                e,
            )
        })?;
    Ok(writes.then_some(*group))
}

/// The stdio arms of [`require_workflow_authority`] (backlog 222289f3; see the
/// module doc's STDIO bullet). `caller` is the write identity, this server's
/// own agent; the `viewer` a tool was handed is NOT consulted, so the check is
/// on the principal that writes.
///
/// 1. The caller must READ the row on its OWN stamp (the system-ingest stamp
///    the write runs on reads every group the system agent writes). A row it
///    cannot read is refused without its id or submitter. That text is NOT a
///    tool's own not-found text (an unknown `canonical_name` reaches the
///    executor's "workflow not found"), so a stdio caller can still tell that
///    a hidden name exists: the reveal residual ruling R-100 accepted, as the
///    HTTP twins' 403 does.
/// 2. A GROUP row: the caller must hold a live writer/admin membership of the
///    row's owner group, the group the write lands in.
/// 3. A recorded submitter: the submitter, its operator (the operator
///    itself, as over HTTP), or a live writer of the row's owner group; a
///    server with no declared signer identity is admitted with a WARN
///    (undecidable, as for claims). No submitter: the legacy stdio arm.
///
/// # Errors
/// A refusal (nothing was written), or an internal error if the caller's view
/// or the operator link cannot be read.
async fn stdio_workflow_authority(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    caller: WriteIdentity,
    workflow_id: uuid::Uuid,
    owner: Option<uuid::Uuid>,
    tool_name: &'static str,
) -> Result<WorkflowArm, McpError> {
    let caller_agent = caller.agent_id();
    let viewer = epigraph_db::visibility::Viewer::resolve(&server.pool, caller_agent)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!("{tool_name}: could not resolve the stdio caller's viewer"),
                e,
            )
        })?;
    let tenancy = match server.scoped.as_ref() {
        Some(scoped) => {
            let mut read = scoped.read_as(&viewer).await.map_err(|e| {
                internal_error_logged(
                    format!("{tool_name}: could not read the workflow as the stdio caller"),
                    e,
                )
            })?;
            let t =
                epigraph_db::WorkflowRepository::tenancy_as_viewer(&mut read, &viewer, workflow_id)
                    .await
                    .map_err(|e| {
                        internal_error_logged(
                            format!("{tool_name}: could not read the workflow as the stdio caller"),
                            e,
                        )
                    })?;
            read.commit().await.map_err(|e| {
                internal_error_logged(
                    format!("{tool_name}: could not read the workflow as the stdio caller"),
                    e,
                )
            })?;
            t
        }
        // No tenancy-aware pool (a development superuser): the in-query
        // predicate alone, on the act's own (unstamped) connection, as every
        // reader on that configuration.
        None => epigraph_db::WorkflowRepository::tenancy_as_viewer(conn, &viewer, workflow_id)
            .await
            .map_err(|e| {
                internal_error_logged(
                    format!("{tool_name}: could not read the workflow as the stdio caller"),
                    e,
                )
            })?,
    };
    let Some((visibility, owner_group)) = tenancy else {
        return Err(crate::errors::invalid_params(format!(
            "{tool_name}: no workflow this caller (agent {caller_agent}) can read matches the \
             request. Nothing was written."
        )));
    };
    if visibility == "group" && !viewer.writable_groups().contains(&owner_group) {
        return Err(crate::errors::invalid_params(format!(
            "{tool_name}: the workflow belongs to a group caller agent {caller_agent} does not \
             write (it holds no live writer or admin membership of the workflow's owner group). \
             Nothing was written."
        )));
    }
    let Some(owner) = owner else {
        return Ok(WorkflowArm::StdioLegacy);
    };
    if caller_agent == owner {
        return Ok(WorkflowArm::Submitter);
    }
    if crate::tools::claims::operator_arm_allows(server, caller_agent, owner, false).await? {
        return Ok(WorkflowArm::Operator);
    }
    let view = (visibility, owner_group);
    if let Some(group) = owner_group_arm(conn, caller_agent, Some(&view), tool_name).await? {
        return Ok(WorkflowArm::OwnerGroupWriter { group });
    }
    if !server.signer_identity_declared {
        tracing::warn!(
            workflow_id = %workflow_id,
            submitter = %owner,
            caller_agent = %caller_agent,
            tool = tool_name,
            "workflow mutation allowed on stdio over another agent's workflow: this server has \
             no declared signer identity (--agent-key / --agent-model absent), so ownership is \
             undecidable. Pass --agent-key to enforce the submitter rule."
        );
        return Ok(WorkflowArm::StdioUndeclaredSigner);
    }
    Err(crate::errors::invalid_params(format!(
        "workflow {workflow_id} was submitted by agent {owner}; stdio caller agent \
         {caller_agent} is neither that submitter nor its operator and does not write the \
         workflow's owner group. {tool_name} over stdio requires the workflow's submitter, the \
         submitter's operator, or a writer of its owner group (the audited claims:admin path \
         needs an authenticated transport). Nothing was written."
    )))
}

/// `(visibility, owner_group_id)` of workflow `workflow_id` as the caller
/// `caller_agent` reads it, on the act's own connection (so the answer is
/// what both that connection's stamp and the caller read), or `None` when the
/// caller cannot read it (backlog c831df4a).
async fn caller_view_of(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    caller_agent: uuid::Uuid,
    workflow_id: uuid::Uuid,
    tool_name: &'static str,
) -> Result<Option<(String, uuid::Uuid)>, McpError> {
    let viewer = epigraph_db::visibility::Viewer::resolve(&server.pool, caller_agent)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!("{tool_name}: could not resolve the caller's view"),
                e,
            )
        })?;
    epigraph_db::WorkflowRepository::tenancy_as_viewer(conn, &viewer, workflow_id)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!("{tool_name}: could not read the workflow as the caller"),
                e,
            )
        })
}

/// The AUDITED admin arm, shared by a submitted workflow (after its submitter
/// and operator arms) and a legacy one (its only arm). The token's scope is
/// necessary, not sufficient: its client record must still grant
/// `claims:admin` to this principal (migration 111's ADM02 predicate), and the
/// write that follows records a `workflows.admin_write` audit row on the same
/// transaction.
///
/// `Ok(Some(()))`: admitted. `Ok(None)`: the token holds no `claims:admin`, so
/// the caller words its own refusal. `Err`: the token holds `claims:admin` but
/// its client record grants none (ADM02), refused through `refuse` with
/// `subject` naming the workflow and `needs` naming the arms that would admit
/// (`refuse` masks the text for a caller that cannot read the row).
async fn admin_arm(
    conn: &mut sqlx::PgConnection,
    auth: &epigraph_auth::AuthContext,
    caller_agent: uuid::Uuid,
    subject: &str,
    needs: &str,
    tool_name: &'static str,
    refuse: &(dyn Fn(String) -> McpError + Send + Sync),
) -> Result<Option<()>, McpError> {
    if !auth.has_scope("claims:admin") {
        return Ok(None);
    }
    let live = epigraph_db::SecurityEventRepository::admin_grant_is_live(
        &mut *conn,
        auth.client_id,
        caller_agent,
        auth.admin_scopes == epigraph_auth::AdminScopePosture::Armed,
    )
    .await
    .map_err(|e| {
        internal_error_logged(
            format!("{tool_name}: could not re-check the admin grant"),
            e,
        )
    })?;
    if live {
        return Ok(Some(()));
    }
    Err(refuse(format!(
        "{subject}; caller agent {caller_agent} holds claims:admin in its token, but the token's \
         client record ({}) grants it no live claims:admin, so the audited admin path refused it \
         (ADM02). {tool_name} requires {needs}. Nothing was written.",
        auth.client_id
    )))
}

/// Record a cross-owner workflow write made through the audited admin arm
/// (`workflows.admin_write`), on the SAME transaction as the write, so the two
/// commit together or not at all. `details` carries the tool's own before /
/// after facts; this adds the admin, the token and the target.
///
/// # Errors
/// An internal error if the audit row cannot be written; the caller's write
/// then rolls back with it.
pub(crate) async fn audit_admin_workflow_write(
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    tool_name: &'static str,
    workflow_id: uuid::Uuid,
    submitter: Option<uuid::Uuid>,
    details: serde_json::Value,
) -> Result<(), McpError> {
    let Some(token) = auth else {
        return Err(internal_error_text(format!(
            "{tool_name}: an admin workflow write with no token to audit. Nothing was written."
        )));
    };
    let record = serde_json::json!({
        "action": tool_name,
        "workflow_id": workflow_id,
        "submitter": submitter,
        "write": details,
    });
    // Migration 112's definer, not an INSERT: the audit row is written with
    // the definer's own guarantees (the token's live grant re-checked) on
    // whatever stamp the write runs on; it used to be the system agent's, where
    // `security_events_append` refused an INSERT attributed to the caller.
    epigraph_db::SecurityEventRepository::admin_audit_write(
        &mut *conn,
        token.client_id,
        token.jti,
        caller.agent_id(),
        "workflows.admin_write",
        &record,
    )
    .await
    .map_err(|e| {
        internal_error_logged(
            format!("{tool_name}: could not write the admin audit row. Nothing was written."),
            e,
        )
    })
}

/// Record the write a [`WorkflowGrant`] admitted, on the SAME transaction as
/// the write: the admin arm's `workflows.admin_write` row
/// ([`audit_admin_workflow_write`]); for the submitter and operator arms,
/// [`record_caller_workflow_write`], on either transport. `details` carries
/// the tool's own facts.
///
/// # Errors
/// An internal error if the row cannot be written; the caller's write then
/// rolls back with it.
pub(crate) async fn record_workflow_write(
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    tool_name: &'static str,
    workflow_id: uuid::Uuid,
    grant: WorkflowGrant,
    details: serde_json::Value,
) -> Result<(), McpError> {
    if grant.is_admin() {
        return audit_admin_workflow_write(
            conn,
            auth,
            caller,
            tool_name,
            workflow_id,
            grant.owner,
            details,
        )
        .await;
    }
    record_caller_workflow_write(conn, auth, caller, tool_name, workflow_id, grant, details).await
}

/// The PROVENANCE of a write admitted through any non-admin arm, on either
/// transport: one `workflows.caller_write`
/// `security_events` row on the write's own transaction
/// (`SecurityEventRepository::workflow_caller_write`), recording the arm, the
/// acting agent, the human it acted for (`operator`: the caller itself on the
/// operator arm, null on the submitter arm), the submitter, the tool, the
/// workflow and the token. The rows the write makes are authored and stamped
/// by the caller; this row records under which arm it acted, and the
/// `AUTHORED` edges which claims it created. `transport` says which transport carried
/// the call; a stdio row has no token (`client_id` / `token_jti` null). A
/// no-op for an admin grant (the admin arm has its own row).
///
/// # Errors
/// An internal error if the row cannot be written; the caller's write then
/// rolls back with it.
pub(crate) async fn record_caller_workflow_write(
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    tool_name: &'static str,
    workflow_id: uuid::Uuid,
    grant: WorkflowGrant,
    details: serde_json::Value,
) -> Result<(), McpError> {
    let acting = caller.agent_id();
    let (arm, operator, owner_group) = match grant.arm {
        WorkflowArm::Admin => return Ok(()),
        WorkflowArm::Submitter => ("submitter", None, None),
        WorkflowArm::Operator => ("operator", Some(acting), None),
        WorkflowArm::OwnerGroupWriter { group } => ("owner_group_writer", None, Some(group)),
        WorkflowArm::StdioLegacy => ("legacy", None, None),
        WorkflowArm::StdioUndeclaredSigner => ("undeclared_signer", None, None),
    };
    let (transport, client_id, token_jti) = match auth {
        Some(token) => ("http", Some(token.client_id), Some(token.jti)),
        None => ("stdio", None, None),
    };
    if auth.is_some()
        && matches!(
            grant.arm,
            WorkflowArm::StdioLegacy | WorkflowArm::StdioUndeclaredSigner
        )
    {
        return Err(internal_error_text(format!(
            "{tool_name}: a stdio-only {arm} grant on an authenticated call. Nothing was written."
        )));
    }
    let record = serde_json::json!({
        "action": tool_name,
        "workflow_id": workflow_id,
        "submitter": grant.owner,
        "arm": arm,
        "acting_agent": acting,
        "operator": operator,
        "owner_group": owner_group,
        "transport": transport,
        "client_id": client_id,
        "token_jti": token_jti,
        "write": details,
    });
    epigraph_db::SecurityEventRepository::workflow_caller_write(&mut *conn, &record)
        .await
        .map_err(|e| {
            internal_error_logged(
                format!(
                    "{tool_name}: could not record the write's provenance. Nothing was written."
                ),
                e,
            )
        })
}

/// Remove the submitter key from caller-supplied workflow metadata, so only the
/// ingest entry point can write it.
pub(crate) fn strip_submitter(metadata: &mut serde_json::Value) {
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove(epigraph_db::WorkflowRepository::SUBMITTER_KEY);
    }
}
