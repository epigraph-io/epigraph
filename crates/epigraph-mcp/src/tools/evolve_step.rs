//! `evolve_step` — atomic creation of a versioned claim + supersedes/revises edge.
//!
//! See docs/superpowers/specs/2026-05-05-step-level-versioning-design.md §5, §9.9.
//!
//! Use `supersedes` for linear refinement (new claim takes over from parent);
//! use `revises` for a concurrent branch sharing a common ancestor. The new
//! claim shares the same `step_lineage_id` as the parent.

use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{internal_error, invalid_params, parse_uuid, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::workflow_authority::{
    record_workflow_write, require_workflow_authority, WorkflowGrant,
};
use crate::write_identity::WriteIdentity;
use epigraph_engine::admin_cascade::{self, CascadeCause, CascadeStatus, CascadeTrigger};
use epigraph_engine::retraction_cascade::CascadeReport;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EvolveStepParams {
    /// (id-mode) Claim being superseded or branched from. Provide this, OR both
    /// `canonical_name` and `step_index` to address the step by name.
    #[serde(default)]
    pub parent_id: String,
    /// (name-mode) Canonical workflow name; with `step_index`, resolves the
    /// parent to the current head of that step's lineage — the same
    /// `executes`-edge walk `report_hierarchical_outcome` uses. Alternative to
    /// `parent_id`.
    #[serde(default)]
    pub canonical_name: Option<String>,
    /// (name-mode) Zero-based step index within the workflow (used with
    /// `canonical_name`).
    #[serde(default)]
    pub step_index: Option<usize>,
    /// Deprecated / ignored: the lineage is derived from the parent claim, so
    /// this is retained only for backward compatibility with older callers.
    #[serde(default)]
    pub step_lineage_id: String,
    /// New step content.
    pub content: String,
    /// "supersedes" (linear refinement) or "revises" (concurrent branch).
    pub edge_type: String,
    /// Optional human-readable rationale.
    pub rationale: Option<String>,
    /// 2 (step) or 3 (operation). Default 2.
    pub level: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct EvolveStepResponse {
    pub claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_id: Uuid,
    /// `supersedes` only: the Supersede admin cascade that carried the retired
    /// step's edges onto this one (applied, or deferred for the replay), as
    /// `supersede_claim` reports it. Absent for `revises`, which supersedes
    /// nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cascade: Option<CascadeStatus>,
    /// `supersedes` only: the belief re-derivation that cascade ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub belief_cascade: Option<CascadeReport>,
}

pub async fn evolve_step(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: EvolveStepParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let level = params.level.unwrap_or(2);
    if level != 2 && level != 3 {
        return Err(invalid_params(format!(
            "level must be 2 or 3 (got {level})"
        )));
    }
    if params.content.trim().is_empty() {
        return Err(invalid_params("content must not be empty".to_string()));
    }

    // Two addressing modes, exactly one required: id-mode (`parent_id`) or
    // name-mode (`canonical_name` + `step_index`), the latter resolved through
    // the same `executes`-edge walk `report_hierarchical_outcome` uses (#352).
    let parent_uuid = if !params.parent_id.trim().is_empty() {
        if params.canonical_name.is_some() || params.step_index.is_some() {
            return Err(invalid_params(
                "provide EITHER parent_id OR (canonical_name + step_index), not both",
            ));
        }
        parse_uuid(params.parent_id.trim())?
    } else if let (Some(name), Some(idx)) = (params.canonical_name.as_deref(), params.step_index) {
        epigraph_db::WorkflowRepository::resolve_step_claim(&server.pool, viewer, name, idx, true)
            .await
            // `InvalidData` (every head of the step's lineage is retired) is
            // the caller's to fix, not an internal error.
            .map_err(crate::errors::db_caller_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "no step at index {idx} of workflow '{name}' (unknown workflow or index out of range)"
                ))
            })?
    } else {
        return Err(invalid_params(
            "provide a parent step: either `parent_id`, or both `canonical_name` and `step_index`",
        ));
    };
    let identity = server.write_identity(auth, viewer).await?;
    let agent_id = identity.agent_id();
    let parent = epigraph_core::ClaimId::from_uuid(parent_uuid);
    let write_details = |r: &epigraph_db::EvolveStepResult| {
        serde_json::json!({
            "parent_claim_id": parent_uuid,
            "claim_id": r.new_claim_id,
            "step_lineage_id": r.step_lineage_id,
            "edge_type": r.edge_type,
            "level": level,
        })
    };

    // The step claim is written on a transaction STAMPED with its author's
    // viewer, so migration 122's claims trigger sees the writing principal:
    // once the database is armed it refuses a claim written by an application
    // session with no principal, which is what the raw pool is. The raw-pool
    // form remains only for a server built without a ScopedPool (test
    // fixtures); on such a process's application role the database refuses the
    // write once armed, so it cannot fail open.
    let (result, cascade, belief_cascade) = if server.scoped.is_some() {
        let mut tx =
            crate::claim_helper::begin_author_stamped_tx(server, identity, "evolve_step").await?;
        let grants =
            require_lineage_authority(server, &mut tx, auth, identity, parent_uuid).await?;
        let r = epigraph_db::ClaimRepository::evolve_step_conn(
            &mut tx,
            parent,
            &params.content,
            &params.edge_type,
            params.rationale.as_deref(),
            level,
            agent_id,
        )
        .await
        .map_err(crate::errors::db_caller_error)?;
        record_lineage_writes(&mut tx, auth, identity, &grants, write_details(&r)).await?;
        if params.edge_type != "supersedes" {
            tx.commit().await.map_err(internal_error)?;
            (r, None, None)
        } else {
            // A `supersedes` step is a supersession (`claims.supersedes` names
            // the parent), so it runs `supersede_claim`'s cascade: the act
            // above moved no edge, and the retired step's decomposition,
            // argument and support edges belong to other writers, which only
            // the administrative cascade re-points (backlog 8d3b4527). The
            // step-lineage rule in `migrate_superseded_edges` leaves the
            // workflow's `executes` and its `step_follows` / `phase_follows`
            // chain, the lineage's `revises` history and agents' authorship
            // edges on the retired step. The maintenance session is acquired
            // before the act commits; without one the deferral commits with
            // the act, attributed to the principal this transaction is
            // stamped with.
            let trigger = CascadeTrigger::new(
                CascadeCause::Supersede,
                Some(agent_id),
                crate::tools::supersede::oauth_principal(auth),
                parent_uuid,
                Some(r.new_claim_id),
            );
            let (mut session, deferred) =
                crate::tools::supersede::admin_session_or_deferral(server, &mut tx, &trigger)
                    .await?;
            tx.commit().await.map_err(internal_error)?;
            // Best-effort, as in `supersede_claim`: the act has committed.
            let (cascade, belief) = match (session.as_mut(), deferred) {
                (Some(session), _) => {
                    let (conn, v) = session.split();
                    admin_cascade::apply_after_supersede(
                        conn,
                        v,
                        viewer,
                        &trigger,
                        parent_uuid,
                        r.new_claim_id,
                    )
                    .await
                }
                (None, status) => (status, CascadeReport::default()),
            };
            (r, Some(cascade), Some(belief))
        }
    } else {
        // No ScopedPool (test fixtures): the act only, as before; there is no
        // maintenance session to run the cascade on. The authority gate runs
        // here too, on the act's own transaction, so a server built without a
        // ScopedPool is not a way around it.
        let mut tx = server.pool.begin().await.map_err(internal_error)?;
        let grants =
            require_lineage_authority(server, &mut tx, auth, identity, parent_uuid).await?;
        let r = epigraph_db::ClaimRepository::evolve_step_conn(
            &mut tx,
            parent,
            &params.content,
            &params.edge_type,
            params.rationale.as_deref(),
            level,
            agent_id,
        )
        .await
        .map_err(crate::errors::db_caller_error)?;
        record_lineage_writes(&mut tx, auth, identity, &grants, write_details(&r)).await?;
        tx.commit().await.map_err(internal_error)?;
        (r, None, None)
    };

    success_json(&EvolveStepResponse {
        claim_id: result.new_claim_id,
        step_lineage_id: result.step_lineage_id,
        edge_id: result.edge_id,
        cascade,
        belief_cascade,
    })
}

/// Lineage-wide authority: refuse the caller unless it has workflow authority
/// ([`require_workflow_authority`]: the submitter, its operator, or the
/// audited admin arm) over EVERY workflow that executes the parent's step
/// lineage (`WorkflowRepository::workflows_executing_step_lineage`: the
/// parent and every claim sharing its `step_lineage_id`, retracted `executes`
/// edges included). Evolving a step changes the heads of a lineage those
/// workflows run, so it needs what `add_step` and `delete_step` need, over
/// each of them: a step two workflows execute needs authority over both.
///
/// Runs on the act's own transaction, BEFORE the act, so a refusal writes
/// nothing. Returns each workflow with the grant that admitted the caller, for
/// [`record_lineage_writes`]. A lineage no workflow executes returns none and
/// is unaffected.
///
/// stdio (no token) is unchanged, as for every workflow tool (the batch H-b
/// bar; see `workflow_authority.rs`): the lineage is not even read.
async fn require_lineage_authority(
    server: &EpiGraphMcpFull,
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    parent: Uuid,
) -> Result<Vec<(Uuid, WorkflowGrant)>, McpError> {
    if auth.is_none() {
        return Ok(Vec::new());
    }
    let workflows =
        epigraph_db::WorkflowRepository::workflows_executing_step_lineage(&mut *conn, parent)
            .await
            .map_err(|e| {
                crate::errors::internal_error_logged(
                    "evolve_step: could not read the workflows executing the step's lineage",
                    e,
                )
            })?;
    let mut grants = Vec::with_capacity(workflows.len());
    for workflow in workflows {
        let grant =
            require_workflow_authority(server, &mut *conn, auth, caller, workflow, "evolve_step")
                .await?;
        grants.push((workflow, grant));
    }
    Ok(grants)
}

/// Record the write once per workflow [`require_lineage_authority`] admitted
/// the caller over, on the act's own transaction: `workflows.caller_write` for
/// the submitter and operator arms, `workflows.admin_write` for the audited
/// admin arm (`record_workflow_write`). The rows are attributed to the
/// session principal, which here is the caller itself: the step claim is the
/// caller's, written on its own stamp.
async fn record_lineage_writes(
    conn: &mut sqlx::PgConnection,
    auth: Option<&epigraph_auth::AuthContext>,
    caller: WriteIdentity,
    grants: &[(Uuid, WorkflowGrant)],
    details: serde_json::Value,
) -> Result<(), McpError> {
    for (workflow, grant) in grants {
        record_workflow_write(
            &mut *conn,
            auth,
            caller,
            "evolve_step",
            *workflow,
            *grant,
            details.clone(),
        )
        .await?;
    }
    Ok(())
}

fn success_json<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}
