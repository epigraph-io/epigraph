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

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_ingest::common::ids::{compound_claim_id, content_hash};

use crate::error::IngestExecutorError;
use crate::system_agent::get_or_create_system_agent;

#[derive(Debug, Clone)]
pub struct AddStepResult {
    pub workflow_id: Uuid,
    pub step_claim_id: Uuid,
    pub step_index: u32,
    pub step_lineage_id: Uuid,
    /// `true` if the step already existed under this workflow (idempotent
    /// re-add); the existing position/lineage_id are returned and the chain
    /// is not rewired.
    pub already_present: bool,
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
    pool: &PgPool,
    canonical_name: &str,
) -> Result<(Uuid, i32), StepOpError> {
    let row: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, generation FROM workflows WHERE canonical_name = $1 \
         ORDER BY generation DESC LIMIT 1",
    )
    .bind(canonical_name)
    .fetch_optional(pool)
    .await?;
    row.ok_or_else(|| StepOpError::WorkflowNotFound(canonical_name.to_string()))
}

/// First level-1 phase claim under a workflow (migrate convention: one phase).
pub async fn find_phase(pool: &PgPool, workflow_id: Uuid) -> Result<Uuid, StepOpError> {
    let row: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 \
           AND (c.properties->>'level')::int = 1 \
         ORDER BY c.created_at ASC LIMIT 1",
    )
    .bind(workflow_id)
    .fetch_optional(pool)
    .await?;
    row.ok_or(StepOpError::PhaseMissing)
}

/// Level-2 step claims under a workflow, ordered by walking `step_follows`
/// from the head. Unreachable orphans (broken chain or no edges) are
/// appended in `created_at` order.
pub async fn ordered_steps(pool: &PgPool, workflow_id: Uuid) -> Result<Vec<Uuid>, StepOpError> {
    let all: Vec<(Uuid, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT c.id, c.created_at FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 \
           AND (c.properties->>'level')::int = 2 \
         ORDER BY c.created_at ASC",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await?;
    if all.is_empty() {
        return Ok(vec![]);
    }
    let id_set: Vec<Uuid> = all.iter().map(|(id, _)| *id).collect();

    let head_candidates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT ws.id FROM unnest($1::uuid[]) AS ws(id) \
         WHERE NOT EXISTS ( \
           SELECT 1 FROM edges sf \
           WHERE sf.target_id = ws.id AND sf.relationship = 'step_follows' \
             AND sf.source_id = ANY($1::uuid[]) \
         )",
    )
    .bind(&id_set)
    .fetch_all(pool)
    .await?;

    // Pick the head with the earliest created_at among candidates.
    let head = head_candidates
        .into_iter()
        .min_by_key(|id| all.iter().find(|(i, _)| i == id).map(|(_, t)| *t));

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
            .fetch_optional(pool)
            .await?;
            match next {
                Some(n) if !visited.contains(&n) => cur = n,
                _ => break,
            }
        }
    }
    for (id, _) in &all {
        if !visited.contains(id) {
            chain.push(*id);
        }
    }
    Ok(chain)
}

// ── add_step ────────────────────────────────────────────────────────────────

pub async fn add_step(
    pool: &PgPool,
    canonical_name: &str,
    step_text: &str,
    position: Option<u32>,
) -> Result<AddStepResult, StepOpError> {
    if step_text.trim().is_empty() {
        return Err(StepOpError::Invalid("step_text must not be empty".into()));
    }
    let (workflow_id, _generation) = find_workflow_head(pool, canonical_name).await?;
    let phase_id = find_phase(pool, workflow_id).await?;
    let chain = ordered_steps(pool, workflow_id).await?;

    let step_hash = content_hash(step_text);
    let step_claim_id = compound_claim_id(&step_hash, canonical_name);

    if let Some(idx) = chain.iter().position(|id| *id == step_claim_id) {
        let existing_lineage: Option<Uuid> =
            sqlx::query_scalar("SELECT step_lineage_id FROM claims WHERE id = $1")
                .bind(step_claim_id)
                .fetch_optional(pool)
                .await?
                .flatten();
        return Ok(AddStepResult {
            workflow_id,
            step_claim_id,
            step_index: idx as u32,
            step_lineage_id: existing_lineage.unwrap_or_else(Uuid::nil),
            already_present: true,
        });
    }

    let position = match position {
        Some(p) if (p as usize) <= chain.len() => p as usize,
        _ => chain.len(),
    };

    let agent_id = get_or_create_system_agent(pool).await?;
    let step_lineage = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels, properties, step_lineage_id) \
         VALUES ($1, $2, $3, $4, 0.99, ARRAY['claim','workflow_step'], $5, $6) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(step_claim_id)
    .bind(step_text)
    .bind(step_hash.as_slice())
    .bind(agent_id)
    .bind(serde_json::json!({
        "level": 2,
        "source_type": "workflow",
        "kind": "workflow_step",
        "step_lineage_id": step_lineage.to_string(),
    }))
    .bind(step_lineage)
    .execute(pool)
    .await?;

    epigraph_db::EdgeRepository::create_if_not_exists(
        pool,
        workflow_id,
        "workflow",
        step_claim_id,
        "claim",
        "executes",
        Some(serde_json::json!({"level": 2})),
        None,
        None,
    )
    .await?;
    epigraph_db::EdgeRepository::create_if_not_exists(
        pool,
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
            epigraph_db::EdgeRepository::create_if_not_exists(
                pool,
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
            epigraph_db::EdgeRepository::create_if_not_exists(
                pool,
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
        } else {
            let prev = chain[position - 1];
            let next = chain[position];
            sqlx::query(
                "DELETE FROM edges \
                 WHERE source_id = $1 AND target_id = $2 \
                   AND relationship = 'step_follows'",
            )
            .bind(prev)
            .bind(next)
            .execute(pool)
            .await?;
            epigraph_db::EdgeRepository::create_if_not_exists(
                pool,
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
            epigraph_db::EdgeRepository::create_if_not_exists(
                pool,
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
        step_lineage_id: step_lineage,
        already_present: false,
    })
}

// ── delete_step ─────────────────────────────────────────────────────────────

pub async fn delete_step(
    pool: &PgPool,
    canonical_name: &str,
    step_lineage_id: Uuid,
) -> Result<DeleteStepResult, StepOpError> {
    let (workflow_id, _generation) = find_workflow_head(pool, canonical_name).await?;

    let claim_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT c.id FROM claims c \
         JOIN edges e ON e.target_id = c.id AND e.source_type = 'workflow' \
                      AND e.relationship = 'executes' \
         WHERE e.source_id = $1 AND c.step_lineage_id = $2 \
         ORDER BY c.created_at DESC LIMIT 1",
    )
    .bind(workflow_id)
    .bind(step_lineage_id)
    .fetch_optional(pool)
    .await?;

    let claim_id = claim_id.ok_or_else(|| StepOpError::StepNotFound {
        canonical_name: canonical_name.to_string(),
        lineage: step_lineage_id,
    })?;

    let new_truth: f64 = 0.05;
    sqlx::query("UPDATE claims SET truth_value = $1 WHERE id = $2")
        .bind(new_truth)
        .bind(claim_id)
        .execute(pool)
        .await?;

    Ok(DeleteStepResult {
        workflow_id,
        step_claim_id: claim_id,
        step_lineage_id,
        truth_value: new_truth,
    })
}
