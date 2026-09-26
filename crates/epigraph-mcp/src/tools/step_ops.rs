//! MCP wrappers for `add_step` and `delete_step`. Persistence lives in
//! [`epigraph_ingest_executor::workflow_steps`]; this module is a thin
//! parameter/response shim for the MCP tool surface.

use rmcp::model::{CallToolResult, Content};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddStepParams {
    /// Workflow's canonical_name (slug).
    pub canonical_name: String,
    /// Step text to append/insert.
    pub step_text: String,
    /// 0-indexed insertion slot in the `step_follows` chain. `None` (or
    /// out-of-range) appends. It does not change plan order: find_workflow,
    /// find_workflow_hierarchical and the outcome tools list an added step after
    /// all originally planned steps.
    #[serde(default)]
    pub position: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AddStepResponse {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_index: u32,
    pub step_lineage_id: Uuid,
    pub already_present: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteStepParams {
    pub canonical_name: String,
    /// Lineage UUID of the step to soft-delete.
    pub step_lineage_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteStepResponse {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub truth_value: f64,
}

fn success_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

fn map_step_err(e: epigraph_ingest_executor::StepOpError) -> McpError {
    use epigraph_ingest_executor::StepOpError as E;
    match e {
        E::Invalid(msg) | E::WorkflowNotFound(msg) => invalid_params(msg),
        E::StepNotFound { .. } | E::PhaseMissing => invalid_params(e.to_string()),
        // Migration 105's personal-group refusal (the step claim's owner
        // declaration): a denial, as on every other write tool.
        E::Repo(db) if db.is_personal_group_refusal() => crate::errors::db_caller_error(db),
        E::Executor(x) => crate::errors::executor_caller_error("executor error", x),
        E::Db(_) | E::Repo(_) => internal_error(e.to_string()),
    }
}

/// The caller's authority over the head of `canonical_name` (batch H-b, H3;
/// see `tools::workflow_authority`). An unknown name is left to the executor,
/// which reports it as not found. Returns the head and the grant, so an admin
/// write can be audited on the same transaction once it has been made.
async fn require_authority_over(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: crate::write_identity::WriteIdentity,
    canonical_name: &str,
    tool_name: &'static str,
) -> Result<Option<(uuid::Uuid, crate::tools::workflow_authority::WorkflowGrant)>, McpError> {
    let Some(head) = epigraph_db::WorkflowRepository::head_by_canonical(&mut *conn, canonical_name)
        .await
        .map_err(|e| internal_error(format!("{tool_name}: could not resolve the workflow: {e}")))?
    else {
        return Ok(None);
    };
    let grant = crate::tools::workflow_authority::require_workflow_authority(
        server, conn, auth, caller, head, tool_name,
    )
    .await?;
    Ok(Some((head, grant)))
}

/// Append or middle-insert a step under an existing workflow.
///
/// # One stamped transaction, not five pool checkouts
///
/// The step claim is authored by `workflow-ingest-system` and owned by that
/// agent's personal group, so on the unstamped pool its INSERT is refused on a
/// cleanly-migrated schema. The stamp is therefore the system agent's — see
/// [`crate::claim_helper::begin_system_ingest_stamped_tx`] — not
/// `server.agent_id()`.
///
/// Holding one transaction across the whole call also makes the chain rewire
/// atomic. `add_step` writes the claim, an `executes` edge, a `decomposes_to`
/// edge and up to three `step_follows` rewires including a `DELETE`; on separate
/// checkouts a refusal at the last of those left a step spliced into a broken
/// chain, which `ordered_steps` then reports by appending the orphan in
/// `created_at` order — a silent reordering rather than an error. Retrying is
/// safe because the claim id is `compound_claim_id(step_hash, canonical_name)`
/// and the INSERT carries `ON CONFLICT (id) DO NOTHING`.
pub async fn add_step(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: AddStepParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let caller = server.write_identity(auth, viewer).await?;
    let (_system_agent_id, mut tx) =
        crate::claim_helper::begin_system_ingest_stamped_tx(server, "add_step").await?;
    // H3 (batch H-b): the CALLER's authority over the workflow, before the
    // system-stamped write. The stamp stays the system agent's.
    let authority = require_authority_over(
        server,
        &mut tx,
        auth,
        caller,
        &params.canonical_name,
        "add_step",
    )
    .await?;
    let r = epigraph_ingest_executor::add_step(
        &mut tx,
        &params.canonical_name,
        &params.step_text,
        params.position,
    )
    .await
    .map_err(map_step_err)?;
    if let Some((head, grant)) = authority.filter(|(_, g)| g.admin) {
        crate::tools::workflow_authority::audit_admin_workflow_write(
            &mut tx,
            auth,
            caller,
            "add_step",
            head,
            grant.owner,
            serde_json::json!({
                "canonical_name": params.canonical_name,
                "step_claim_id": r.step_claim_id,
                "step_lineage_id": r.step_lineage_id,
                "step_index": r.step_index,
                "already_present": r.already_present,
            }),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|e| internal_error(format!("add_step: could not commit: {e}")))?;

    // Post-commit and best-effort, deliberately outside the transaction: the
    // embed holds a network round trip to OpenAI, and CLAUDE.md's embedding
    // policy forbids a failed embed from unwinding a committed claim.
    // `embed_and_store` reads the author off the row, so it stamps from the
    // system agent without being told to.
    if let Some(ref content) = r.inserted_content {
        let _ = server
            .embedder
            .embed_and_store(r.step_claim_id, content)
            .await;
    }

    success_json(&AddStepResponse {
        workflow_id: r.workflow_id,
        step_claim_id: r.step_claim_id,
        step_index: r.step_index,
        step_lineage_id: r.step_lineage_id,
        already_present: r.already_present,
    })
}

/// Soft-delete a step lineage by setting its head claim's `truth_value` to 0.05.
///
/// Same stamp and same reason as [`add_step`]: the row being updated is owned by
/// the system agent's personal group, and `claims_tenancy`'s `WITH CHECK`
/// governs an UPDATE as well as an INSERT. On the unstamped pool this was
/// admitted in production only by the orphan `claims_privacy` policy and refused
/// on a clean migrate.
pub async fn delete_step(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: DeleteStepParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let lineage = parse_uuid(&params.step_lineage_id)?;
    let caller = server.write_identity(auth, viewer).await?;
    let (_system_agent_id, mut tx) =
        crate::claim_helper::begin_system_ingest_stamped_tx(server, "delete_step").await?;
    // H3 (batch H-b); see `add_step`.
    let authority = require_authority_over(
        server,
        &mut tx,
        auth,
        caller,
        &params.canonical_name,
        "delete_step",
    )
    .await?;
    let r = epigraph_ingest_executor::delete_step(&mut tx, &params.canonical_name, lineage)
        .await
        .map_err(map_step_err)?;
    if let Some((head, grant)) = authority.filter(|(_, g)| g.admin) {
        crate::tools::workflow_authority::audit_admin_workflow_write(
            &mut tx,
            auth,
            caller,
            "delete_step",
            head,
            grant.owner,
            serde_json::json!({
                "canonical_name": params.canonical_name,
                "step_claim_id": r.step_claim_id,
                "step_lineage_id": r.step_lineage_id,
                "truth_value_after": r.truth_value,
            }),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|e| internal_error(format!("delete_step: could not commit: {e}")))?;
    success_json(&DeleteStepResponse {
        workflow_id: r.workflow_id,
        step_claim_id: r.step_claim_id,
        step_lineage_id: r.step_lineage_id,
        truth_value: r.truth_value,
    })
}
