//! Caller authority over a hierarchical workflow (batch H-b, H3; backlog
//! 84b2a98d).
//!
//! # The measurement that bounds this module
//!
//! Every write a workflow mutation makes is authored by, and stamped from,
//! `workflow-ingest-system` (`claim_helper::begin_system_ingest_stamped_tx`),
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
//! * A variant ingest (`parent_canonical_name` set) also requires authority over
//!   EXACTLY the row the executor links as `parent_id`
//!   (`WorkflowRepository::ingest_anchors`), not the latest generation of the
//!   parent's name, and inherits that row's submitter when the name is new.
//! * `add_step`, `delete_step` and every new generation require, over the
//!   AUTHENTICATED transport and when a submitter is recorded, in this order:
//!   the submitter; its operator (#503, the operator itself as on every HTTP
//!   gate); or the AUDITED admin arm. stdio is unchanged (the batch H-b bar:
//!   stdio changes only for #374), as `patch_claim`'s whole-patch check is
//!   HTTP-only.
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
//! * A workflow with NO record keeps today's behaviour, with a WARN naming it,
//!   so the legacy population is neither tightened by accident nor handed to
//!   whoever touches it first. Which authority legacy workflows carry is an
//!   operator decision this module does not make.
//! * A refusal names the WORKFLOW and its submitter. It used to reuse the claim
//!   gate's text ("claim is owned by agent X ... cannot retire it"), which named
//!   the wrong object and the wrong verb.
//!
//! The system-agent stamp is unchanged for the rows these writes make.

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::write_identity::WriteIdentity;

/// What [`require_workflow_authority`] admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkflowGrant {
    /// The workflow's recorded submitter, if any.
    pub owner: Option<uuid::Uuid>,
    /// Admitted ONLY through the audited admin arm: the caller must then write
    /// [`audit_admin_workflow_write`] on the same transaction as its write.
    pub admin: bool,
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
            internal_error(format!(
                "{tool_name}: could not read the workflow's submitter: {e}"
            ))
        })?;
    let grant = |admin| WorkflowGrant { owner, admin };
    // AUTHENTICATED TRANSPORT ONLY. The batch H-b bar keeps stdio unchanged
    // except for #374's retirement label, and stdio is not a trust boundary
    // here: the process that spawned the server handed it the DSN, the same
    // argument that keeps `patch_claim`'s whole-patch ownership check
    // HTTP-only. The submitter is still RECORDED for a stdio ingest, so an
    // HTTP caller cannot take over a workflow a stdio agent created.
    let Some(auth) = auth else {
        return Ok(grant(false));
    };
    let Some(owner) = owner else {
        tracing::warn!(
            tool = tool_name,
            workflow_id = %workflow_id,
            caller = %caller.agent_id(),
            "workflow mutation on a workflow with no recorded submitter (written before batch \
             H-b): allowed, as before; which authority legacy workflows carry is an operator \
             decision"
        );
        return Ok(grant(false));
    };
    let caller_agent = caller.agent_id();
    // 1. The submitter.
    if caller_agent == owner {
        return Ok(grant(false));
    }
    // 2. The submitter's operator (#503; HTTP admits the operator itself, never
    //    the actor arm, exactly as `require_owner_or_admin` does).
    if crate::tools::claims::operator_arm_allows(server, caller_agent, owner, false).await? {
        return Ok(grant(false));
    }
    // 3. The AUDITED admin arm. The token's scope is necessary, not sufficient:
    //    its client record must still grant `claims:admin` to this principal
    //    (migration 111's ADM02 predicate), and the write that follows records
    //    a `workflows.admin_write` audit row on the same transaction.
    if auth.has_scope("claims:admin") {
        let live = epigraph_db::SecurityEventRepository::admin_grant_is_live(
            &mut *conn,
            auth.client_id,
            caller_agent,
        )
        .await
        .map_err(|e| {
            internal_error(format!(
                "{tool_name}: could not re-check the admin grant: {e}"
            ))
        })?;
        if live {
            return Ok(grant(true));
        }
        return Err(crate::errors::invalid_params(format!(
            "workflow {workflow_id} was submitted by agent {owner}; caller agent {caller_agent} \
             holds claims:admin in its token, but the token's client record ({}) grants it no \
             live claims:admin, so the audited admin path refused it (ADM02). {tool_name} \
             requires the workflow's submitter, the submitter's operator, or a live \
             claims:admin grant. Nothing was written.",
            auth.client_id
        )));
    }
    Err(crate::errors::invalid_params(format!(
        "workflow {workflow_id} was submitted by agent {owner}; caller agent {caller_agent} is \
         neither that submitter nor its operator and holds no claims:admin. {tool_name} requires \
         the workflow's submitter, the submitter's operator, or the audited claims:admin path. \
         Nothing was written."
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
    let (client_id, jti) = auth.map_or((None, None), |a| (Some(a.client_id), Some(a.jti)));
    let record = serde_json::json!({
        "action": tool_name,
        "admin_agent_id": caller.agent_id(),
        "client_id": client_id,
        "token_jti": jti,
        "workflow_id": workflow_id,
        "submitter": submitter,
        "write": details,
    });
    epigraph_db::SecurityEventRepository::log_conn(
        &mut *conn,
        &epigraph_db::SecurityEventRow {
            id: uuid::Uuid::new_v4(),
            event_type: "workflows.admin_write".to_string(),
            agent_id: Some(caller.agent_id()),
            success: Some(true),
            details: record,
            ip_address: None,
            user_agent: None,
            correlation_id: jti.map(|j| j.to_string()),
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(|e| {
        internal_error(format!(
            "{tool_name}: could not write the admin audit row: {e}. Nothing was written."
        ))
    })
}

/// Remove the submitter key from caller-supplied workflow metadata, so only the
/// ingest entry point can write it.
pub(crate) fn strip_submitter(metadata: &mut serde_json::Value) {
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove(epigraph_db::WorkflowRepository::SUBMITTER_KEY);
    }
}
