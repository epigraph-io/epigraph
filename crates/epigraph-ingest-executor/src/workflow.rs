//! Workflow ingest executor — applies an [`epigraph_ingest::common::plan::IngestPlan`]
//! built from a [`epigraph_ingest::workflow::WorkflowExtraction`] to the database.
//!
//! This module consolidates logic previously duplicated between
//! `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow_via_pool` and
//! `epigraph-api::routes::workflows::ingest_workflow`.

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_core::TruthValue;
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, WorkflowRepository};
use epigraph_ingest::common::plan::IngestPlan;
use epigraph_ingest::workflow::builder::root_workflow_id;
use epigraph_ingest::workflow::WorkflowExtraction;

use crate::error::IngestExecutorError;
use crate::system_agent::get_or_create_system_agent;

/// Summary of what the executor wrote (or skipped) for a single plan.
#[derive(Debug, Clone)]
pub struct WorkflowIngestExecutionResult {
    pub workflow_id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    pub executes_edges_created: usize,
    /// `true` when this ingest inserted (or upserted) a `workflow → variant_of
    /// → workflow` edge, i.e. when the extraction had `parent_canonical_name`
    /// set. Idempotent re-ingests that hit the gate at step 1 return `false`
    /// (no insertion attempted) even when the edge already exists in the DB.
    pub variant_of_edge_created: bool,
    pub relationship_edges_created: usize,
    /// `true` when the idempotency gate short-circuited (workflow already
    /// has `executes` edges). The other counters are zero in that case.
    pub already_ingested: bool,
}

/// Execute a workflow ingest plan against the database.
///
/// Idempotent. If the canonical workflow already has `executes` edges, this
/// returns early with `already_ingested: true` and no DB writes. Otherwise it
/// inserts the workflow row, ensures author and system agents, persists each
/// planned claim with dedup, writes `workflow —executes→ claim` edges, and
/// emits the intra-claim plan edges.
pub async fn execute_workflow_ingest_plan(
    pool: &sqlx::PgPool,
    plan: &IngestPlan,
    extraction: &WorkflowExtraction,
) -> Result<WorkflowIngestExecutionResult, IngestExecutorError> {
    let canonical_name = &extraction.source.canonical_name;
    let generation = extraction.source.generation as i32;
    let goal = &extraction.source.goal;

    let workflow_id = root_workflow_id(extraction);

    // ── 1. Idempotency gate: skip if workflow row already processed ──────
    if let Some(existing_id) =
        WorkflowRepository::find_root_by_canonical(pool, canonical_name, generation).await?
    {
        let edge_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(existing_id)
        .fetch_one(pool)
        .await?;

        if edge_count > 0 {
            return Ok(WorkflowIngestExecutionResult {
                workflow_id: existing_id,
                canonical_name: canonical_name.clone(),
                generation,
                claims_ingested: 0,
                claims_skipped_dedup: 0,
                executes_edges_created: edge_count as usize,
                variant_of_edge_created: false,
                relationship_edges_created: 0,
                already_ingested: true,
            });
        }
    }

    // ── 2. Ensure system agent ───────────────────────────────────────────
    let system_agent_id = get_or_create_system_agent(pool).await?;

    // ── 3. Insert workflow row (idempotent) ──────────────────────────────
    let parent_id = if let Some(ref pcn) = extraction.source.parent_canonical_name {
        WorkflowRepository::find_root_by_canonical(pool, pcn, generation.saturating_sub(1)).await?
    } else {
        None
    };

    WorkflowRepository::insert_root(
        pool,
        workflow_id,
        canonical_name,
        generation,
        goal,
        parent_id,
        extraction.source.metadata.clone(),
    )
    .await
    .map_err(|e| IngestExecutorError::WorkflowInsert(e.to_string()))?;

    // ── 3a. variant_of edge for hierarchical workflows (issue #51) ──────
    // When a workflow is ingested with parent_canonical_name (generation > 0
    // and the parent already exists), insert workflow → variant_of → parent
    // so graph-traversal queries that don't know about workflows.parent_id
    // can still see the lineage. Idempotent on re-ingest via
    // create_if_not_exists.
    let variant_of_edge_created = if let Some(parent_id_uuid) = parent_id {
        EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            parent_id_uuid,
            "workflow",
            "variant_of",
            Some(serde_json::json!({"generation": generation})),
            None,
            None,
        )
        .await?;
        true
    } else {
        false
    };

    // ── 4. Ensure author agents ──────────────────────────────────────────
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid: Uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes)
                .await
                .map_err(|e| IngestExecutorError::AgentCreation(format!("author lookup: {e}")))?
        {
            existing.id.into()
        } else {
            let author_agent = epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &author_agent)
                .await
                .map_err(|e| IngestExecutorError::AgentCreation(format!("author create: {e}")))?;
            created.id.into()
        };
        author_agent_map.insert(idx, agent_uuid);
    }

    // ── 5. Walk planned claims: dedup-by-id ─────────────────────────────
    let mut claims_ingested = 0_usize;
    let mut claims_skipped_dedup = 0_usize;
    let mut id_map: HashMap<Uuid, Uuid> = HashMap::new();

    for planned in &plan.claims {
        let confidence = planned.confidence.clamp(0.0, 1.0);
        let raw_truth = confidence.clamp(0.01, 0.99);
        let truth = TruthValue::clamped(raw_truth);

        // Derive labels from kind property.
        let kind = planned
            .properties
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("workflow_claim");
        let labels = vec!["claim".to_string(), kind.to_string()];

        let was_new = ClaimRepository::create_with_id_if_absent(
            pool,
            planned.id,
            &planned.content,
            &planned.content_hash,
            system_agent_id,
            truth,
            &labels,
        )
        .await?;

        if was_new {
            // Set properties via raw SQL (no set_properties method on ClaimRepository).
            sqlx::query("UPDATE claims SET properties = $1 WHERE id = $2")
                .bind(&planned.properties)
                .bind(planned.id)
                .execute(pool)
                .await?;
            claims_ingested += 1;
        } else {
            claims_skipped_dedup += 1;
        }

        id_map.insert(planned.id, planned.id);
    }

    // ── 6. workflow —executes→ claim edges ──────────────────────────────
    let mut executes_edges = 0_usize;
    for planned in &plan.claims {
        let (_row, _was_created) = EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            planned.id,
            "claim",
            "executes",
            Some(serde_json::json!({"level": planned.level})),
            None,
            None,
        )
        .await?;
        executes_edges += 1;
    }

    // ── 7. Intra-claim plan edges (decomposes_to / step_follows / phase_follows / cross-refs) ──
    let mut relationships_created = 0_usize;
    for edge in &plan.edges {
        let (src, src_type) = if edge.source_type == "author_placeholder" {
            let idx = edge.properties["author_index"].as_u64().unwrap_or(0) as usize;
            let Some(&agent_uuid) = author_agent_map.get(&idx) else {
                continue;
            };
            (agent_uuid, "agent".to_string())
        } else {
            let mapped = id_map
                .get(&edge.source_id)
                .copied()
                .unwrap_or(edge.source_id);
            (mapped, edge.source_type.clone())
        };
        let tgt = id_map
            .get(&edge.target_id)
            .copied()
            .unwrap_or(edge.target_id);

        let (_row, _was_created) = EdgeRepository::create_if_not_exists(
            pool,
            src,
            &src_type,
            tgt,
            &edge.target_type,
            &edge.relationship,
            Some(edge.properties.clone()),
            None,
            None,
        )
        .await?;
        relationships_created += 1;
    }

    Ok(WorkflowIngestExecutionResult {
        workflow_id,
        canonical_name: canonical_name.clone(),
        generation,
        claims_ingested,
        claims_skipped_dedup,
        executes_edges_created: executes_edges,
        variant_of_edge_created,
        relationship_edges_created: relationships_created,
        already_ingested: false,
    })
}
