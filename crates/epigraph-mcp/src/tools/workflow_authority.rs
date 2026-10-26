//! Caller authority over a hierarchical workflow (batch H-b, H3; backlog
//! 84b2a98d).
//!
//! # The measurement that bounds this module
//!
//! Every write a workflow mutation makes is authored by, and stamped from,
//! the registered workflow-ingest system agent
//! (`claim_helper::begin_system_ingest_stamped_tx`),
//! and before batch H-b nothing on that path asked whether the CALLER had any
//! authority over the workflow it named: any `claims:write` caller could
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
//! * `add_step`, `delete_step`, `deprecate_workflow` and every new generation
//!   require, over the AUTHENTICATED transport and when a submitter is
//!   recorded, in this order: the submitter; its operator (#503, the operator
//!   itself as on every HTTP gate); or the AUDITED admin arm. stdio is
//!   unchanged (the batch H-b bar: stdio changes only for #374), as
//!   `patch_claim`'s whole-patch check is HTTP-only. Agents bound to the
//!   submitter's human are NOT admitted over HTTP (operator ruling,
//!   2026-10-13: the shared host credential must not gain edit rights over a
//!   human's workflows); their authority traces to the human through
//!   `OPERATED_BY` / the author binding, and their authorship through the
//!   `AUTHORED` edges below.
//! * PROVENANCE. Every write admitted over the authenticated transport is
//!   recorded on its own transaction ([`record_workflow_write`]): the admin
//!   arm's `workflows.admin_write` row, and for the submitter and operator arms
//!   one `workflows.caller_write` `security_events` row
//!   ([`record_caller_workflow_write`]) naming the `arm`, the `acting_agent`,
//!   the human it acted for (`operator`, on the operator arm), the
//!   `submitter`, the tool (`action`), the `workflow_id`, the token
//!   (`client_id`, `token_jti`) and the tool's own facts (`write`). The row is
//!   attributed to the session principal, the system agent, because 077's
//!   `security_events_append` admits no other attribution on that stamp; the
//!   actor is `acting_agent`. A new generation records one row per anchor it
//!   was checked against, naming the anchor and the row it created.
//! * AUTHORSHIP, on EVERY transport (stdio included). Every claim a workflow
//!   mutation CREATES gets an `AUTHORED` edge (agent -> claim) from the ACTING
//!   agent (the caller over HTTP, this server's pinned agent on stdio), on the
//!   write's own transaction
//!   (`epigraph_ingest_executor::record_caller_authorship`). The claims stay
//!   authored and stamped by the system ingest agent (`claims.agent_id`); the
//!   edge is what connects the agent that wrote them to them. Only claims the
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
//!   submitter is backfilled: there is no provenance to backfill from. stdio is
//!   unchanged here as everywhere in this module. When the custodian role
//!   (#529) lands, its check replaces `claims:admin` in `admin_arm`.
//! * A refusal names the WORKFLOW and its submitter. It used to reuse the claim
//!   gate's text ("claim is owned by agent X ... cannot retire it"), which named
//!   the wrong object and the wrong verb.
//!
//! The system-agent stamp is unchanged for the rows these writes make: the
//! caller is recorded in the provenance row, not by re-authoring the rows,
//! which would move them out of the system agent's group.

use crate::errors::{internal_error_logged, internal_error_text, McpError};
use crate::server::EpiGraphMcpFull;
use crate::write_identity::WriteIdentity;

/// Which arm of [`require_workflow_authority`] admitted the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkflowArm {
    /// stdio: the gate does not run (the batch H-b bar), and nothing is
    /// recorded about the caller.
    Unchecked,
    /// The caller is the recorded submitter.
    Submitter,
    /// The caller is the operator of the submitter (#503).
    Operator,
    /// The AUDITED admin arm.
    Admin,
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
/// # Errors
/// A workflow-specific refusal naming the submitter (never the claim gate's
/// "cannot retire it" wording, which named the wrong object and verb), or an
/// internal error if the submitter, the operator link or the admin grant
/// cannot be read.
pub(crate) async fn require_workflow_authority(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    workflow_id: uuid::Uuid,
    tool_name: &'static str,
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
    // AUTHENTICATED TRANSPORT ONLY. The batch H-b bar keeps stdio unchanged
    // except for #374's retirement label, and stdio is not a trust boundary
    // here: the process that spawned the server handed it the DSN, the same
    // argument that keeps `patch_claim`'s whole-patch ownership check
    // HTTP-only. The submitter is still RECORDED for a stdio ingest, so an
    // HTTP caller cannot take over a workflow a stdio agent created.
    let Some(auth) = auth else {
        return Ok(grant(WorkflowArm::Unchecked));
    };
    let caller_agent = caller.agent_id();
    // A workflow with NO recorded submitter (written before batch H-b) is
    // platform corpus (U005, default decision A; the D1 ruling keeps the
    // legacy corpus platform-owned). There is no submitter to match and no
    // operator to derive, so the only arm is the audited admin arm. When the
    // custodian role lands (#529), its check replaces `claims:admin` here.
    let Some(owner) = owner else {
        let subject = format!(
            "workflow {workflow_id} has no recorded submitter (legacy platform workflow, \
             written before batch H-b)"
        );
        let needs = "a live claims:admin grant (the audited claims:admin path)";
        return match admin_arm(conn, auth, caller_agent, &subject, needs, tool_name).await? {
            Some(()) => Ok(grant(WorkflowArm::Admin)),
            None => Err(crate::errors::invalid_params(format!(
                "{subject}; caller agent {caller_agent} holds no claims:admin. {tool_name} on a \
                 legacy platform workflow requires the audited claims:admin path. Nothing was \
                 written."
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
    // 3. The AUDITED admin arm.
    let subject = format!("workflow {workflow_id} was submitted by agent {owner}");
    let needs = "the workflow's submitter, the submitter's operator, or a live claims:admin grant";
    if admin_arm(conn, auth, caller_agent, &subject, needs, tool_name)
        .await?
        .is_some()
    {
        return Ok(grant(WorkflowArm::Admin));
    }
    Err(crate::errors::invalid_params(format!(
        "workflow {workflow_id} was submitted by agent {owner}; caller agent {caller_agent} is \
         neither that submitter nor its operator and holds no claims:admin. {tool_name} requires \
         the workflow's submitter, the submitter's operator, or the audited claims:admin path. \
         Nothing was written."
    )))
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
/// its client record grants none (ADM02), refused with `subject` naming the
/// workflow and `needs` naming the arms that would admit.
async fn admin_arm(
    conn: &mut sqlx::PgConnection,
    auth: &epigraph_auth::AuthContext,
    caller_agent: uuid::Uuid,
    subject: &str,
    needs: &str,
    tool_name: &'static str,
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
    Err(crate::errors::invalid_params(format!(
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
    // Migration 112's definer, not an INSERT: this transaction is stamped from
    // the system agent, and `security_events_append` admits an attributed row
    // only for the session principal (measured: the INSERT was refused).
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
/// [`record_caller_workflow_write`]; nothing for an
/// unchecked (stdio) grant. `details` carries the tool's own facts.
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

/// The PROVENANCE of a write admitted over the authenticated transport through
/// the submitter or operator arm: one `workflows.caller_write`
/// `security_events` row on the write's own transaction
/// (`SecurityEventRepository::workflow_caller_write`), recording the arm, the
/// acting agent, the human it acted for (`operator`: the caller itself on the
/// operator arm, null on the submitter arm), the submitter, the tool, the
/// workflow and the token. The rows the write makes stay authored and stamped
/// by the system agent; this row records who acted, and the `AUTHORED` edges
/// who wrote the claims it created. A no-op for an unchecked
/// (stdio) or admin grant (the admin arm has its own row).
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
    let (arm, operator) = match grant.arm {
        WorkflowArm::Unchecked | WorkflowArm::Admin => return Ok(()),
        WorkflowArm::Submitter => ("submitter", None),
        WorkflowArm::Operator => ("operator", Some(acting)),
    };
    let Some(token) = auth else {
        return Err(internal_error_text(format!(
            "{tool_name}: a {arm} workflow write with no token to record. Nothing was written."
        )));
    };
    let record = serde_json::json!({
        "action": tool_name,
        "workflow_id": workflow_id,
        "submitter": grant.owner,
        "arm": arm,
        "acting_agent": acting,
        "operator": operator,
        "client_id": token.client_id,
        "token_jti": token.jti,
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
