//! Step manipulation primitives for hierarchical workflows.
//!
//! - [`add_step`] appends or middle-inserts a step claim under an existing
//!   workflow. Idempotent on `(canonical_name, step_text)`.
//! - [`delete_step`] soft-deletes a step lineage by setting the head claim's
//!   `truth_value` to 0.05.
//!
//! These are called from both the HTTP route (`epigraph-api`) and the MCP
//! tool (`epigraph-mcp`); they live here so neither has to depend on the
//! other.
//!
//! # Every entry point takes a CONNECTION the caller has stamped
//!
//! The step claim [`add_step`] inserts is owned by the `workflow-ingest-system`
//! agent's personal group — not by whoever called the tool — so on the unstamped
//! pool migration 077's `claims_tenancy` `WITH CHECK` refuses it on a cleanly
//! migrated schema. See
//! [`crate::system_agent::system_agent_write_authority`] for the measurement of
//! which identity the stamp must be, and why the answer is not the caller's.
//!
//! Taking a connection is also what makes these operations ATOMIC. `add_step`
//! writes a claim, two `executes`/`decomposes_to` edges and up to three
//! `step_follows` rewires; on a pool each of those was a separate checkout, so a
//! refusal at the rewire left a step claim linked into a broken chain. Handed
//! `&mut *tx` the whole rewire is one unit.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use epigraph_ingest::common::ids::{compound_claim_id, compound_content_hash, content_hash};
use epigraph_ingest::workflow::builder::{
    CONTENT_HASH_SCOPE_CANONICAL_NAME, CONTENT_HASH_SCOPE_KEY,
};

use crate::error::IngestExecutorError;
use crate::system_agent::get_or_create_system_agent;

#[derive(Debug, Clone)]
pub struct AddStepResult {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_index: u32,
    /// The `plan_index` on the step's `executes` edge, or `None` when it has
    /// none. A new step is indexed where the chain puts it (see
    /// [`add_step`]'s "plan_index" section); `None` means the plan could not
    /// be renumbered under this session, so the edge was written unindexed
    /// and the frozen plan read reports the plan as mutated in place.
    pub plan_index: Option<u32>,
    pub step_lineage_id: Uuid,
    /// `true` if the step already existed under this workflow (idempotent
    /// re-add); the existing position/lineage_id are returned and the chain
    /// is not rewired.
    pub already_present: bool,
    /// Content of the step claim if this call inserted a new row;
    /// `None` if the step was already present (idempotent re-add). The
    /// caller embeds when `Some(_)`; see CLAUDE.md "Embedding policy".
    pub inserted_content: Option<String>,
    /// `true` only when THIS call's INSERT created the step claim row. `false`
    /// for an idempotent re-add, and also when the step was spliced into the
    /// chain but its claim id (content-addressed per workflow) already existed,
    /// e.g. a step a deprecation retired. The caller records authorship
    /// (`AUTHORED`) only for a claim it created.
    pub claim_created: bool,
}

#[derive(Debug, Clone)]
pub struct DeleteStepResult {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub truth_value: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum StepOpError {
    #[error("workflow not found: canonical_name={0:?}")]
    WorkflowNotFound(String),
    #[error("workflow has no level-1 phase claim")]
    PhaseMissing,
    #[error("step not found: canonical_name={canonical_name:?} step_lineage_id={lineage}")]
    StepNotFound {
        canonical_name: String,
        lineage: Uuid,
    },
    #[error("invalid input: {0}")]
    Invalid(String),
    /// A mid-chain insert whose `prev -> next` `step_follows` edge this session
    /// may not delete. Under row security the DELETE would match nothing and
    /// report success, and the two INSERTs that follow would leave `prev` with
    /// two successors: a forked chain. Nothing is written.
    #[error(
        "cannot insert a step between {prev} and {next}: this session may not remove the \
         step_follows edge between them (row security matched {removable} of {existing}), so \
         the insert would fork the chain; nothing was written. Append the step instead \
         (omit position), or have the workflow's owner or an operator rewire it"
    )]
    ChainRewireRefused {
        prev: Uuid,
        next: Uuid,
        existing: i64,
        removable: u64,
    },
    /// `delete_step`'s soft delete changed no row: the session may not write
    /// the step's head claim.
    #[error(
        "step {step_claim_id} (lineage {lineage}) was not changed: this session cannot write \
         its claim, so it was not soft-deleted"
    )]
    StepNotWritable { step_claim_id: Uuid, lineage: Uuid },
    #[error("db error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("repo error: {0}")]
    Repo(#[from] epigraph_db::DbError),
    #[error("executor error: {0}")]
    Executor(#[from] IngestExecutorError),
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Find the latest-generation workflow row for a `canonical_name`.
pub async fn find_workflow_head(
    conn: &mut sqlx::PgConnection,
    canonical_name: &str,
) -> Result<(Uuid, i32), StepOpError> {
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, generation FROM workflows WHERE canonical_name = $1 \
         ORDER BY generation DESC LIMIT 1",
    )
    .bind(canonical_name)
    .fetch_optional(&mut *conn)
    .await?;
    row.ok_or_else(|| StepOpError::WorkflowNotFound(canonical_name.to_string()))
}

/// SQL `ORDER BY` key for a workflow's `executes` edges in PLAN order.
///
/// The `plan_index` ordinal `execute_workflow_ingest_plan` records on each edge,
/// then `(c.created_at, c.id)` for edges that carry none (written before the
/// ordinal existed, or by an [`add_step`] that could not renumber the plan). `c.created_at` cannot lead: the
/// executor writes a whole plan in ONE transaction, so every claim and every
/// edge of it shares one `NOW()`, and the order would fall through to `c.id` — a
/// content-derived UUID. See the comment on the `executes` loop in
/// `workflow.rs`.
const PLAN_ORDER: &str = "CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                               THEN (e.properties->>'plan_index')::int \
                               ELSE 2147483647 END, \
                          c.created_at ASC, c.id ASC";

/// First level-1 phase claim under a workflow, in PLAN order (migrate
/// convention: one phase; for a multi-phase workflow, the plan's first).
///
/// Ordered by [`PLAN_ORDER`], not `c.created_at` alone. A multi-phase
/// workflow's phases are written in one transaction and tie on `created_at`, so
/// `ORDER BY c.created_at LIMIT 1` picked whichever phase had the smaller UUID
/// and `add_step` attached the new step under it.
pub async fn find_phase(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
) -> Result<Uuid, StepOpError> {
    let sql = format!(
        "SELECT c.id FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 \
           AND (c.properties->>'level')::int = 1 \
         ORDER BY {PLAN_ORDER} LIMIT 1"
    );
    let row: Option<Uuid> = sqlx::query_scalar(&sql)
        .bind(workflow_id)
        .fetch_optional(&mut *conn)
        .await?;
    row.ok_or(StepOpError::PhaseMissing)
}

/// Level-2 step claims under a workflow, ordered by walking `step_follows`
/// from the head. Unreachable orphans (broken chain or no edges) are
/// appended in plan order ([`PLAN_ORDER`]), and when several steps could be
/// the head the earliest in plan order wins.
///
/// Both of those used to be `c.created_at`, which ties for every step of a plan
/// written in one transaction.
pub async fn ordered_steps(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
) -> Result<Vec<Uuid>, StepOpError> {
    let sql = format!(
        "SELECT c.id FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 \
           AND (c.properties->>'level')::int = 2 \
         ORDER BY {PLAN_ORDER}"
    );
    let all: Vec<Uuid> = sqlx::query_scalar(&sql)
        .bind(workflow_id)
        .fetch_all(&mut *conn)
        .await?;
    if all.is_empty() {
        return Ok(vec![]);
    }
    let id_set: Vec<Uuid> = all.clone();

    let head_candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT ws.id FROM unnest($1::uuid[]) AS ws(id) \
         WHERE NOT EXISTS ( \
           SELECT 1 FROM edges sf \
           WHERE sf.target_id = ws.id AND sf.relationship = 'step_follows' \
             AND sf.source_id = ANY($1::uuid[]) \
         )",
    )
    .bind(&id_set)
    .fetch_all(&mut *conn)
    .await?;

    // Pick the head that comes earliest in plan order among the candidates.
    let head = all.iter().copied().find(|id| head_candidates.contains(id));

    let mut chain: Vec<Uuid> = Vec::with_capacity(all.len());
    let mut visited: HashSet<Uuid> = HashSet::new();
    if let Some(h) = head {
        let mut cur = h;
        loop {
            chain.push(cur);
            visited.insert(cur);
            let next: Option<Uuid> = sqlx::query_scalar(
                "SELECT target_id FROM edges \
                 WHERE source_id = $1 AND relationship = 'step_follows' \
                   AND target_id = ANY($2::uuid[]) \
                 LIMIT 1",
            )
            .bind(cur)
            .bind(&id_set)
            .fetch_optional(&mut *conn)
            .await?;
            match next {
                Some(n) if !visited.contains(&n) => cur = n,
                _ => break,
            }
        }
    }
    for id in &all {
        if !visited.contains(id) {
            chain.push(*id);
        }
    }
    Ok(chain)
}

// ── plan_index for an added step ────────────────────────────────────────────

/// Where an added step's `executes` edge goes in plan order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// At this index, which no edge holds yet: an append.
    At(u32),
    /// At this index, after every edge at or past it moves up by one: the
    /// index of the step the new one now precedes.
    Before(u32),
    /// No index can be derived (the step it precedes, or every edge of the
    /// plan, carries none): written unindexed.
    Unindexed,
}

/// The `executes` edges of one workflow this session can see, as read for
/// [`add_step`]'s placement.
struct PlanEdges {
    /// Each target's integer `plan_index` (`None` for an edge without one).
    /// When a target has more than one edge, an indexed one wins.
    by_target: HashMap<Uuid, Option<u32>>,
    /// Every indexed edge, as `(edge id, plan_index)`.
    indexed: Vec<(Uuid, u32)>,
}

async fn plan_edges(
    conn: &mut sqlx::PgConnection,
    workflow_id: Uuid,
) -> Result<PlanEdges, StepOpError> {
    let mut by_target: HashMap<Uuid, Option<u32>> = HashMap::new();
    let mut indexed = Vec::new();
    for (edge, target, index) in
        epigraph_db::WorkflowRepository::executes_plan_indices(&mut *conn, workflow_id).await?
    {
        let index = index.and_then(|i| u32::try_from(i).ok());
        if let Some(i) = index {
            indexed.push((edge, i));
        }
        let slot = by_target.entry(target).or_insert(None);
        if slot.is_none() {
            *slot = index;
        }
    }
    Ok(PlanEdges { by_target, indexed })
}

/// The new step goes immediately before `chain[position]` in plan order, so
/// it takes that step's index; an append goes one past the plan's largest
/// index (atoms and later phases included, so nothing moves). Either way the
/// level-2 `plan_index` order stays the `step_follows` order `ordered_steps`
/// walks, which is what the plan-order readers (`find_workflow*`, the outcome
/// reports, the frozen plan read) and the chain must agree on.
fn plan_placement(chain: &[Uuid], position: usize, plan: &PlanEdges) -> Placement {
    if let Some(next) = chain.get(position) {
        return match plan.by_target.get(next).copied().flatten() {
            Some(k) => Placement::Before(k),
            None => Placement::Unindexed,
        };
    }
    match plan.indexed.iter().map(|(_, i)| *i).max() {
        Some(max) => max
            .checked_add(1)
            .map_or(Placement::Unindexed, Placement::At),
        None => Placement::Unindexed,
    }
}

/// Make room at `k` by moving every indexed `executes` edge at or past `k` up
/// by one, all or nothing, inside a SAVEPOINT. `Some(k)` when every one of them
/// moved; `None` (and nothing moved) when this session may not update one.
///
/// Each move goes through [`epigraph_db::EdgeRepository::update_valid_to_and_properties`],
/// the gated edge write `patch_edge` uses, which reports an edge the session
/// can read but row security will not let it update as `WriteRefused` (and a
/// `WITH CHECK` refusal surfaces as 42501).
///
/// That refusal is the expected case on the production shape, not an error: a
/// public plan's `executes` edges are world-owned (migration 120) and
/// migration 117's RESTRICTIVE `edges_update_owner` lets no application session
/// update them, and a step `add_step` added is a public claim whose edge is
/// world-owned in any plan. Writing `k` anyway would give two items one index;
/// refusing the insert would turn every middle insert into a public workflow
/// into an error. The edge is written unindexed instead, which the frozen plan
/// read reports as an in-place mutation, and `AddStepResult::plan_index` says
/// so.
async fn shift_from(
    conn: &mut sqlx::PgConnection,
    plan: &PlanEdges,
    k: u32,
) -> Result<Option<u32>, StepOpError> {
    // Highest index first. The order changes no outcome (the savepoint makes
    // the shift all or nothing), but it makes a lost rollback observable: the
    // edge most likely to be refused is a step `add_step` added, which sits at
    // the LOW end of the range when the insert goes right before it, so
    // ascending order would hit the refusal before anything had moved and a
    // kept partial shift would leave no trace for a test to see.
    let mut moving: Vec<(Uuid, u32)> = plan
        .indexed
        .iter()
        .copied()
        .filter(|(_, i)| *i >= k)
        .collect();
    moving.sort_unstable_by_key(|&(_, i)| std::cmp::Reverse(i));
    let mut savepoint = sqlx::Connection::begin(&mut *conn).await?;
    for (edge, index) in moving {
        let moved = epigraph_db::EdgeRepository::update_valid_to_and_properties(
            &mut *savepoint,
            edge,
            None,
            Some(serde_json::json!({ "plan_index": index + 1 })),
        )
        .await;
        match moved {
            Ok(_) => {}
            Err(e) if is_row_security_refusal(&e) => {
                savepoint.rollback().await?;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        }
    }
    savepoint.commit().await?;
    Ok(Some(k))
}

/// Row security refused an edge update: the USING half (`WriteRefused`, the
/// row stayed readable) or the `WITH CHECK` half (42501).
fn is_row_security_refusal(e: &epigraph_db::DbError) -> bool {
    match e {
        epigraph_db::DbError::WriteRefused { .. } => true,
        epigraph_db::DbError::QueryFailed { source } => {
            source.as_database_error().and_then(|d| d.code()).as_deref() == Some("42501")
        }
        _ => false,
    }
}

// ── add_step ────────────────────────────────────────────────────────────────

/// Append (`position` `None` or past the end) or insert a step at slot
/// `position` of the `step_follows` chain [`ordered_steps`] walks.
///
/// # plan_index
///
/// The new `executes` edge carries `{"level": 2, "plan_index": k}`, so the
/// plan-order readers and the chain agree on where the step is:
///
/// * an append takes one past the plan's largest index, and no edge moves;
/// * an insert takes the index of the step it now precedes, after every
///   `executes` edge at or past that index (atoms and later phases included)
///   moves up by one, all or nothing.
///
/// When this session may not move every one of those edges (a public plan's
/// edges are world-owned, and no application session may update them), or the
/// step it precedes has no index, the edge is written WITHOUT `plan_index` and
/// [`AddStepResult::plan_index`] is `None`: the chain is still rewired, no
/// index changes, and the frozen plan read counts the edge in
/// `unindexed_edges`, as it did for every `add_step` before this.
///
/// The `workflows` row is locked first, so two concurrent calls on one
/// workflow cannot both take the same index.
pub async fn add_step(
    conn: &mut sqlx::PgConnection,
    canonical_name: &str,
    step_text: &str,
    position: Option<u32>,
) -> Result<AddStepResult, StepOpError> {
    if step_text.trim().is_empty() {
        return Err(StepOpError::Invalid("step_text must not be empty".into()));
    }
    let (workflow_id, _generation) = find_workflow_head(&mut *conn, canonical_name).await?;
    // Before the plan is read: a concurrent add_step on this workflow waits
    // here, so the two cannot both take the same next `plan_index`.
    epigraph_db::WorkflowRepository::lock_for_plan_edit(&mut *conn, workflow_id).await?;
    let phase_id = find_phase(&mut *conn, workflow_id).await?;
    let chain = ordered_steps(&mut *conn, workflow_id).await?;
    let plan = plan_edges(&mut *conn, workflow_id).await?;

    let step_hash = content_hash(step_text);
    let step_claim_id = compound_claim_id(&step_hash, canonical_name);

    if let Some(idx) = chain.iter().position(|id| *id == step_claim_id) {
        let existing_lineage: Option<Uuid> =
            sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
                .bind(step_claim_id)
                .fetch_optional(&mut *conn)
                .await?
                .flatten();
        return Ok(AddStepResult {
            workflow_id,
            step_claim_id,
            step_index: idx as u32,
            plan_index: plan.by_target.get(&step_claim_id).copied().flatten(),
            step_lineage_id: existing_lineage.unwrap_or_else(Uuid::nil),
            already_present: true,
            inserted_content: None,
            claim_created: false,
        });
    }

    let position = match position {
        Some(p) if (p as usize) <= chain.len() => p as usize,
        _ => chain.len(),
    };
    let placement = plan_placement(&chain, position, &plan);

    // A mid-chain insert first removes `prev -> next`, and REFUSES before
    // writing anything if it could not: under row security (115's owner-scoped
    // DELETE) a DELETE the session may not make matches zero rows and reports
    // success, and inserting `prev -> step` beside the surviving `prev -> next`
    // forks the chain. The count is of the edges the session can SEE (it walked
    // the chain through them); a chain inferred from orphan order has none, and
    // then nothing needs removing.
    let rewire = if !chain.is_empty() && position > 0 && position < chain.len() {
        let (prev, next) = (chain[position - 1], chain[position]);
        // Every prev -> next row the session can see, RETRACTED ones included:
        // `ordered_steps` follows a retracted `step_follows` too (`LIMIT 1`, no
        // `valid_to` filter), so a surviving retracted row would still fork the
        // order.
        let existing_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM edges \
             WHERE source_id = $1 AND target_id = $2 AND relationship = 'step_follows'",
        )
        .bind(prev)
        .bind(next)
        .fetch_all(&mut *conn)
        .await?;
        let existing = i64::try_from(existing_ids.len()).unwrap_or(i64::MAX);
        // Migration 120: the rewire DELETEs these rows, so it withdraws them.
        // Their edge-keyed BBA cleanup (the session's own now, any other
        // writer's deferred to the maintenance replay) is recorded BEFORE the
        // DELETE, while the rows still exist. A row the session does not own is
        // left to the refusal below, which rolls the whole act back.
        for id in &existing_ids {
            epigraph_db::EdgeRepository::withdraw_edge_bbas_conn(
                &mut *conn,
                *id,
                epigraph_db::EdgeWithdrawal::BeingDeleted,
                None,
                epigraph_db::EDGE_RETRACT_DEFERRAL_REASON,
            )
            .await?;
        }
        let removable = sqlx::query(
            "DELETE FROM edges \
             WHERE source_id = $1 AND target_id = $2 \
               AND relationship = 'step_follows'",
        )
        .bind(prev)
        .bind(next)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if i64::try_from(removable).unwrap_or(i64::MAX) < existing {
            return Err(StepOpError::ChainRewireRefused {
                prev,
                next,
                existing,
                removable,
            });
        }
        Some((prev, next))
    } else {
        None
    };

    let agent_id = get_or_create_system_agent(&mut *conn).await?;
    let step_lineage = Uuid::new_v4();

    // ── Tenancy declaration (PR-16) ──
    //
    // This statement binds a FRESH `step_lineage_id`, so migration 074's arm 2
    // finds no sibling to inherit from and the row would fall through to the
    // seed arm (test roles) or raise 23502 (the app role). It has to declare.
    //
    // CORRECTION TO THE PLAN. §4.6 says `add_step` "takes a `TenancyDecl` from
    // its caller". Its two callers -- `epigraph-mcp/src/tools/step_ops.rs` and
    // `epigraph-api/src/routes/workflows.rs` -- have no group to give: a
    // workflow step is instance-wide content authored by the SYSTEM agent
    // (`get_or_create_system_agent` above, already resolved for `agent_id`),
    // and `find_workflow` / `find_workflow_hierarchical` read it for every
    // principal. Owning a step with the calling principal's group would make
    // every workflow private to whoever last edited it. A parameter here would
    // therefore only widen the ways to get it wrong, so the declaration is
    // derived from the author the row already names.
    let decl = epigraph_db::ClaimRepository::default_decl_for_author(&mut *conn, agent_id).await?;

    let claim_created = sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels, properties, step_lineage_id, \
                             visibility, owner_group_id) \
         VALUES ($1, $2, $3, $4, 0.99, ARRAY['claim','workflow_step'], $5, $6, $7, $8) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(step_claim_id)
    .bind(step_text)
    // Scoped to the workflow like the builder's step nodes: the row is
    // authored by the shared system agent, so a plain `blake3(step_text)`
    // collides on the (content_hash, agent_id) dedup key with any other
    // workflow's step of the same text (backlog 6178a205; 013's
    // `uq_claims_content_hash_agent` through migration 149, the app-layer
    // lock from 150).
    .bind(compound_content_hash(&step_hash, canonical_name).as_slice())
    .bind(agent_id)
    .bind(serde_json::json!({
        "level": 2,
        "source_type": "workflow",
        "kind": "workflow_step",
        // Marks the digest above as canonical_name-scoped, so `verify_claim`
        // tells this row from a pre-6178a205 plain-hash step (same stamp).
        CONTENT_HASH_SCOPE_KEY: CONTENT_HASH_SCOPE_CANONICAL_NAME,
        "step_lineage_id": step_lineage.to_string(),
    }))
    .bind(step_lineage)
    .bind(decl.visibility_bind())
    .bind(decl.owner_group_bind())
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;

    let plan_index = match placement {
        Placement::At(k) => Some(k),
        Placement::Unindexed => None,
        Placement::Before(k) => shift_from(&mut *conn, &plan, k).await?,
    };
    let executes_properties = match plan_index {
        Some(k) => serde_json::json!({"level": 2, "plan_index": k}),
        None => serde_json::json!({"level": 2}),
    };
    epigraph_db::EdgeRepository::create_if_not_exists_conn(
        &mut *conn,
        workflow_id,
        "workflow",
        step_claim_id,
        "claim",
        "executes",
        Some(executes_properties),
        None,
        None,
    )
    .await?;
    epigraph_db::EdgeRepository::create_if_not_exists_conn(
        &mut *conn,
        phase_id,
        "claim",
        step_claim_id,
        "claim",
        "decomposes_to",
        Some(serde_json::json!({})),
        None,
        None,
    )
    .await?;

    if !chain.is_empty() {
        if position == 0 {
            epigraph_db::EdgeRepository::create_if_not_exists_conn(
                &mut *conn,
                step_claim_id,
                "claim",
                chain[0],
                "claim",
                "step_follows",
                Some(serde_json::json!({})),
                None,
                None,
            )
            .await?;
        } else if position == chain.len() {
            epigraph_db::EdgeRepository::create_if_not_exists_conn(
                &mut *conn,
                chain[chain.len() - 1],
                "claim",
                step_claim_id,
                "claim",
                "step_follows",
                Some(serde_json::json!({})),
                None,
                None,
            )
            .await?;
        } else if let Some((prev, next)) = rewire {
            // `prev -> next` was removed (and verified) above.
            epigraph_db::EdgeRepository::create_if_not_exists_conn(
                &mut *conn,
                prev,
                "claim",
                step_claim_id,
                "claim",
                "step_follows",
                Some(serde_json::json!({})),
                None,
                None,
            )
            .await?;
            epigraph_db::EdgeRepository::create_if_not_exists_conn(
                &mut *conn,
                step_claim_id,
                "claim",
                next,
                "claim",
                "step_follows",
                Some(serde_json::json!({})),
                None,
                None,
            )
            .await?;
        }
    }

    Ok(AddStepResult {
        workflow_id,
        step_claim_id,
        step_index: position as u32,
        plan_index,
        step_lineage_id: step_lineage,
        already_present: false,
        inserted_content: Some(step_text.to_string()),
        claim_created,
    })
}

// ── delete_step ─────────────────────────────────────────────────────────────

pub async fn delete_step(
    conn: &mut sqlx::PgConnection,
    canonical_name: &str,
    step_lineage_id: Uuid,
) -> Result<DeleteStepResult, StepOpError> {
    let (workflow_id, _generation) = find_workflow_head(&mut *conn, canonical_name).await?;

    let claim_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 AND c.step_lineage_id = $2 \
         ORDER BY c.created_at DESC LIMIT 1",
    )
    .bind(workflow_id)
    .bind(step_lineage_id)
    .fetch_optional(&mut *conn)
    .await?;

    let claim_id = claim_id.ok_or_else(|| StepOpError::StepNotFound {
        canonical_name: canonical_name.to_string(),
        lineage: step_lineage_id,
    })?;

    // Checked: a soft delete that changed no row must not report the new
    // truth value. A step claim the session may read but not write is refused
    // by `claims_tenancy`'s WITH CHECK (42501); a row its USING filtered would
    // change nothing. Both are the same named refusal.
    let new_truth: f64 = 0.05;
    let not_writable = || StepOpError::StepNotWritable {
        step_claim_id: claim_id,
        lineage: step_lineage_id,
    };
    let changed = sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
        .bind(new_truth)
        .bind(claim_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| match e.as_database_error().and_then(|d| d.code()) {
            Some(code) if code == "42501" => not_writable(),
            _ => StepOpError::Db(e),
        })?
        .rows_affected();
    if changed != 1 {
        return Err(not_writable());
    }

    Ok(DeleteStepResult {
        workflow_id,
        step_claim_id: claim_id,
        step_lineage_id,
        truth_value: new_truth,
    })
}
