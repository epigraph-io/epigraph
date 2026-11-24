//! Matching a reworded goal to an existing hierarchical workflow, shared by
//! both store transports (backlog 51d599a9): MCP `store_workflow`
//! (`epigraph-mcp/src/tools/workflows.rs`) and REST `POST /api/v1/workflows`
//! (`epigraph-api/src/routes/workflows.rs::store_workflow`).
//!
//! The rule was written for MCP `store_workflow` (backlog 5e54282f): a goal
//! whose embedding is at or above [`STORE_WORKFLOW_MATCH_THRESHOLD`] cosine
//! similar to a live workflow's goal, under ANOTHER canonical name and in
//! exactly the tenancy the store would use, stores nothing and returns that
//! workflow's lineage head. Both transports now ask [`matching_workflow_conn`],
//! so the same input gets the same answer on either.

use epigraph_core::TenancyDecl;
use epigraph_db::visibility::Viewer;
use epigraph_db::{DbError, WorkflowRepository};
use uuid::Uuid;

/// Cosine similarity at or above which a store treats a new goal as a
/// rewording of an existing hierarchical workflow's goal (backlog 5e54282f).
/// Well above `find_workflow_hierarchical`'s 0.5 search floor: that one finds
/// candidates, this one refuses to mint a lineage.
pub const STORE_WORKFLOW_MATCH_THRESHOLD: f64 = 0.90;

/// A lineage head [`matching_workflow_conn`] found for a reworded goal.
#[derive(Debug, Clone)]
pub struct WorkflowGoalMatch {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub similarity: f64,
    pub visibility: String,
    pub owner_group_id: Uuid,
}

impl WorkflowGoalMatch {
    /// What the caller should do instead, the same text on both transports.
    /// `force_new` names the request field that mints anyway.
    #[must_use]
    pub fn hint(&self, store: &str) -> String {
        format!(
            "A workflow in the tenancy this store would use (visibility '{}', owner group {}) \
             already has a near-identical goal ({:.3} similar): '{}' (canonical_name '{}', \
             generation {}, the lineage head). Nothing was stored. To change its steps, call \
             improve_workflow_hierarchy with parent_canonical_name='{}'; to mint a separate \
             lineage anyway, call {store} again with force_new=true.",
            self.visibility,
            self.owner_group_id,
            self.similarity,
            self.goal,
            self.canonical_name,
            self.generation,
            self.canonical_name
        )
    }
}

/// The live (`truth_value >= 0.3`) hierarchical workflow LINEAGE HEAD whose
/// goal (or the goal of an earlier generation of its lineage) is the most
/// similar to `qvec`, when that clears [`STORE_WORKFLOW_MATCH_THRESHOLD`]
/// under a canonical_name other than `canonical_name`, AND the head has
/// exactly the tenancy this store would give a new lineage.
///
/// Runs on `conn`, a transaction STAMPED from the caller (the principal the
/// store writes as), with `caller_viewer` that principal's viewer; it writes
/// nothing, and the caller rolls the transaction back.
///
/// # The tenancy rule
///
/// A match redirects every later outcome report (goal text, per-step
/// deviation reasons, `outcome_details`) onto the matched plan. Matching
/// anything the caller merely READS would let a store meant to stay private
/// (the undeclared default, or a declared group) land on another team's
/// public plan, or on a plan of another group the caller is also in. So the
/// target tenancy is decided first, exactly as the ingest would: `declared`,
/// else [`crate::owner::resolve_caller_owner`] for a new lineage (the caller's
/// one team, else its own default). Only a head with the same
/// `(visibility, owner_group_id)` is a match. When the target cannot be
/// resolved (an unbound author), nothing is matched and the ingest reports
/// its own refusal.
///
/// # Heads, not generations
///
/// The search covers every generation, and each hit is resolved to the head
/// of its `canonical_name`, so a match never names a superseded generation.
/// A lineage with rows the caller cannot read is skipped: its readable
/// "head" may not be the real one.
///
/// # An identical goal is not a match
///
/// `None` whenever a row named `canonical_name` itself exists, readable or
/// not, embedded or not, live or deprecated: an identical goal stays the
/// ingest's own business (its idempotent `already_ingested` no-op, or its
/// refusal of a name with rows the caller cannot read), never a match to
/// another lineage. That check does not go through the goal embedding, which
/// rows stored before goals were embedded (and `embed: false` ingests) do not
/// have.
///
/// # Errors
/// A database error from any read.
pub async fn matching_workflow_conn(
    conn: &mut sqlx::PgConnection,
    caller_viewer: &Viewer,
    caller: Uuid,
    declared: Option<TenancyDecl>,
    canonical_name: &str,
    qvec: &[f32],
) -> Result<Option<WorkflowGoalMatch>, DbError> {
    let target = match declared {
        Some(d) => d,
        None => match crate::owner::resolve_caller_owner(&mut *conn, caller, None).await {
            Ok(owner) => owner.decl,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "store_workflow: no target tenancy for matching; not matching"
                );
                return Ok(None);
            }
        },
    };
    let (Some(target_visibility), Some(target_owner)) =
        (target.visibility_bind(), target.owner_group_bind())
    else {
        return Ok(None);
    };

    let name_taken = WorkflowRepository::head_by_canonical(&mut *conn, canonical_name)
        .await?
        .is_some()
        || WorkflowRepository::name_has_hidden_rows_conn(&mut *conn, canonical_name).await?;
    if name_taken {
        return Ok(None);
    }
    let hits = WorkflowRepository::search_hierarchical_by_embedding_scored(
        &mut *conn,
        caller_viewer,
        &epigraph_db::pgvector_literal(qvec),
        0.3,
        10,
    )
    .await?;

    let mut seen: Vec<String> = Vec::new();
    for hit in hits
        .into_iter()
        .filter(|h| h.similarity >= STORE_WORKFLOW_MATCH_THRESHOLD)
    {
        if seen.contains(&hit.canonical_name) {
            continue;
        }
        seen.push(hit.canonical_name.clone());
        if WorkflowRepository::name_has_hidden_rows_conn(&mut *conn, &hit.canonical_name).await? {
            continue;
        }
        let Some(head_id) =
            WorkflowRepository::head_by_canonical(&mut *conn, &hit.canonical_name).await?
        else {
            continue;
        };
        let Some(head) =
            WorkflowRepository::row_as_viewer(&mut *conn, caller_viewer, head_id).await?
        else {
            continue;
        };
        if head.truth_value < 0.3 {
            continue;
        }
        let Some((visibility, owner_group_id)) =
            WorkflowRepository::tenancy_as_viewer(&mut *conn, caller_viewer, head_id).await?
        else {
            continue;
        };
        if visibility != target_visibility || owner_group_id != target_owner {
            continue;
        }
        return Ok(Some(WorkflowGoalMatch {
            id: head.id,
            canonical_name: head.canonical_name,
            generation: head.generation,
            goal: head.goal,
            similarity: hit.similarity,
            visibility,
            owner_group_id,
        }));
    }
    Ok(None)
}
