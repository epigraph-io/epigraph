//! Workflow ingest plan application.
//!
//! Walks the plan produced by `epigraph_ingest::workflow::builder::
//! build_ingest_plan` and persists every claim, every `workflow→claim`
//! `executes` edge, every intra-claim hierarchy edge, the optional
//! `workflow→workflow` `variant_of` edge, and resolves author placeholders.
//!
//! The flow is idempotent on `(canonical_name, generation)`: re-ingest of
//! the same workflow short-circuits after the first call.

use std::collections::HashMap;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_core::TruthValue;
use epigraph_db::{AgentRepository, ClaimRepository, EdgeRepository, WorkflowRepository};
use epigraph_ingest::workflow::builder::root_workflow_id;
use epigraph_ingest::workflow::WorkflowExtraction;

use crate::error::IngestError;

/// Summary returned to callers describing what the ingest did.
#[derive(Debug, serde::Serialize)]
pub struct IngestWorkflowResponse {
    pub workflow_id: String,
    pub canonical_name: String,
    pub generation: i32,
    pub claims_ingested: usize,
    pub claims_skipped_dedup: usize,
    pub executes_edges: usize,
    pub relationships_created: usize,
    pub already_ingested: bool,
}

/// Persist a `WorkflowExtraction` to the kernel DB. Idempotent: subsequent
/// calls with the same `(canonical_name, generation)` return
/// `already_ingested: true` after a single edge-count check.
///
/// Both the MCP `ingest_workflow` tool and the HTTP `POST /api/v1/workflows/
/// ingest` endpoint delegate here so they cannot drift.
pub async fn ingest_workflow(
    pool: &PgPool,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResponse, IngestError> {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);

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
            return Ok(IngestWorkflowResponse {
                workflow_id: existing_id.to_string(),
                canonical_name: canonical_name.clone(),
                generation,
                claims_ingested: 0,
                claims_skipped_dedup: 0,
                executes_edges: edge_count as usize,
                relationships_created: 0,
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
    .await?;

    // ── 3a. variant_of edge: new generation —variant_of→ parent ──────────
    // Mirrors `claims.derived_from` + `derived_from` edge redundancy: the
    // FK column carries lineage; the edge row makes lineage visible to
    // graph-traversal queries that don't know about the workflows table.
    if let Some(parent_workflow_id) = parent_id {
        EdgeRepository::create_if_not_exists(
            pool,
            workflow_id,
            "workflow",
            parent_workflow_id,
            "workflow",
            "variant_of",
            Some(serde_json::json!({
                "generation_from": generation - 1,
                "generation_to": generation,
            })),
            None,
            None,
        )
        .await?;
    }

    // ── 4. Ensure author agents ──────────────────────────────────────────
    let mut author_agent_map: HashMap<usize, Uuid> = HashMap::new();
    for (idx, author) in extraction.source.authors.iter().enumerate() {
        if author.name.is_empty() {
            continue;
        }
        let (_did, pub_key_bytes) =
            epigraph_crypto::did_key::did_key_for_author(None, &author.name);
        let agent_uuid: Uuid = if let Some(existing) =
            AgentRepository::get_by_public_key(pool, &pub_key_bytes).await?
        {
            existing.id.into()
        } else {
            let author_agent =
                epigraph_core::Agent::new(pub_key_bytes, Some(author.name.clone()));
            let created = AgentRepository::create(pool, &author_agent).await?;
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
        EdgeRepository::create_if_not_exists(
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

    // ── 7. Intra-claim plan edges (decomposes_to / step_follows /
    //         phase_follows / cross-refs / author_asserts) ─────────────────
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

        EdgeRepository::create_if_not_exists(
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

    Ok(IngestWorkflowResponse {
        workflow_id: workflow_id.to_string(),
        canonical_name: canonical_name.clone(),
        generation,
        claims_ingested,
        claims_skipped_dedup,
        executes_edges,
        relationships_created,
        already_ingested: false,
    })
}

/// Look up (or create) the synthetic agent used as the author for ingest-
/// generated claims. Same DID derivation as the legacy MCP/API call sites
/// so existing rows are reused, not duplicated.
pub async fn get_or_create_system_agent(pool: &PgPool) -> Result<Uuid, IngestError> {
    let (_did, pub_key_bytes) =
        epigraph_crypto::did_key::did_key_for_author(None, "workflow-ingest-system");
    if let Some(existing) = AgentRepository::get_by_public_key(pool, &pub_key_bytes).await? {
        Ok(existing.id.into())
    } else {
        let agent = epigraph_core::Agent::new(
            pub_key_bytes,
            Some("workflow-ingest-system".to_string()),
        );
        let created = AgentRepository::create(pool, &agent).await?;
        Ok(created.id.into())
    }
}
