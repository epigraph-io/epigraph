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
//! * A new generation (`improve_workflow_hierarchy`, a variant ingest) INHERITS
//!   its parent's submitter and requires authority over the parent; a variant of
//!   a workflow with no record inherits no record.
//! * `add_step`, `delete_step` and a variant ingest require, over the
//!   AUTHENTICATED transport and when a submitter is recorded: the submitter,
//!   its operator, or `claims:admin` — exactly
//!   [`crate::tools::claims::require_owner_or_admin`] with the submitter as the
//!   target author. stdio is unchanged (the batch H-b bar: stdio changes only
//!   for #374), as `patch_claim`'s whole-patch check is HTTP-only.
//! * A workflow with NO record keeps today's behaviour, with a WARN naming it,
//!   so the legacy population is neither tightened by accident nor handed to
//!   whoever touches it first. Which authority legacy workflows carry is an
//!   operator decision this module does not make.
//!
//! The system-agent stamp is unchanged for the rows these writes make.

use crate::errors::{internal_error, McpError};
use crate::server::EpiGraphMcpFull;
use crate::write_identity::WriteIdentity;

/// Refuse the caller unless it has authority over workflow `workflow_id`; see
/// the module doc. `Ok(owner)` returns the recorded submitter, if any.
///
/// # Errors
/// The ownership refusal of [`crate::tools::claims::require_owner_or_admin`], or
/// an internal error if the submitter cannot be read.
pub(crate) async fn require_workflow_authority(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    workflow_id: uuid::Uuid,
    tool_name: &'static str,
) -> Result<Option<uuid::Uuid>, McpError> {
    let owner = epigraph_db::WorkflowRepository::submitter_of(&mut *conn, workflow_id)
        .await
        .map_err(|e| {
            internal_error(format!(
                "{tool_name}: could not read the workflow's submitter: {e}"
            ))
        })?;
    // AUTHENTICATED TRANSPORT ONLY. The batch H-b bar keeps stdio unchanged
    // except for #374's retirement label, and stdio is not a trust boundary
    // here: the process that spawned the server handed it the DSN, the same
    // argument that keeps `patch_claim`'s whole-patch ownership check
    // HTTP-only. The submitter is still RECORDED for a stdio ingest, so an
    // HTTP caller cannot take over a workflow a stdio agent created.
    if auth.is_none() {
        return Ok(owner);
    }
    match owner {
        Some(owner) => {
            crate::tools::claims::require_owner_or_admin(server, auth, caller, owner).await?;
        }
        None => tracing::warn!(
            tool = tool_name,
            workflow_id = %workflow_id,
            caller = %caller.agent_id(),
            "workflow mutation on a workflow with no recorded submitter (written before batch \
             H-b): allowed, as before; which authority legacy workflows carry is an operator \
             decision"
        ),
    }
    Ok(owner)
}

/// Remove the submitter key from caller-supplied workflow metadata, so only the
/// ingest entry point can write it.
pub(crate) fn strip_submitter(metadata: &mut serde_json::Value) {
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove(epigraph_db::WorkflowRepository::SUBMITTER_KEY);
    }
}
