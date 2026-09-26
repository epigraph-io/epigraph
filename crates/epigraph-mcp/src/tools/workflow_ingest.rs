//! Hierarchical workflow ingest tool.
//!
//! `do_ingest_workflow` walks a `WorkflowExtraction` JSON payload, persists
//! the claim hierarchy (thesis → phases → steps → operation atoms), writes
//! `workflow —executes→ claim` edges for every planned claim, resolves author
//! placeholder edges, and returns a summary. Mirrors `do_ingest_document` in
//! `ingestion.rs`.
//!
//! The persistence body lives in [`epigraph_ingest_executor::execute_workflow_ingest_plan`];
//! this module is now a thin wrapper that builds an ingest plan, invokes the
//! executor, and maps the result into the MCP response shape.

use rmcp::model::*;

use crate::errors::{internal_error, invalid_params, McpError};
use crate::server::EpiGraphMcpFull;
use crate::tools::ds_auto;
use crate::types::{ImproveWorkflowHierarchyParams, IngestWorkflowParams};

use epigraph_ingest::workflow::WorkflowExtraction;

fn success_json(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(value).map_err(internal_error)?,
    )]))
}

// ── Response type ──────────────────────────────────────────────────────────

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

// ── Pool-only inner ────────────────────────────────────────────────────────

/// Inner helper: runs the executor and builds the response, but also returns
/// the executor's `inserted` vec so MCP entry points can embed those claims
/// inline. `pub(crate)` so sibling MCP tool modules (e.g.
/// `workflows::store_workflow`) can drive the same embed loop without
/// duplicating the executor wiring.
///
/// It does NOT hand back the system agent id, and does not need to: the embed
/// goes through `McpEmbedder::embed_and_store`, whose `StorePath::AuthorStamped`
/// arm reads the author off the ROW rather than taking it from a caller —
/// precisely so `store_workflow` cannot pass `server.agent_id()` here and get a
/// session stamped with the wrong writable group.
///
/// # The plan walk is one stamped transaction
///
/// `epigraph_ingest_executor::execute_workflow_ingest_plan` used to run on
/// `server.pool`, where migration 077's `claims_tenancy` `WITH CHECK` refuses
/// its first claim INSERT on a cleanly-migrated schema — that refusal is why
/// `store_workflow` was entirely unavailable there, and it is the release-gate
/// blocker this conversion clears. The stamp must be the
/// `workflow-ingest-system` agent's; see
/// [`crate::claim_helper::begin_system_ingest_stamped_tx`] for the measurement
/// that rules out `server.agent_id()`.
///
/// Wrapping the walk in a transaction also makes the failure ATOMIC. Before, a
/// refusal partway through left the `workflows` row, the claims inserted so far
/// and their `executes` edges behind. Now the ingest either lands whole or
/// leaves nothing — and re-running it converges, because every write in the walk
/// is keyed on a deterministic id with an `ON CONFLICT` clause.
pub(crate) async fn execute_workflow_ingest_with_inserted(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &WorkflowExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<(IngestWorkflowResponse, Vec<(uuid::Uuid, String)>), McpError> {
    // H3 (batch H-b): the submitter is recorded by THIS entry point, never
    // taken from the caller's metadata; see `tools::workflow_authority`.
    let caller = server.write_identity(auth, viewer).await?;
    let mut extraction = extraction.clone();
    crate::tools::workflow_authority::strip_submitter(&mut extraction.source.metadata);
    let extraction = &extraction;
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);

    let (_system_agent_id, mut tx) =
        crate::claim_helper::begin_system_ingest_stamped_tx(server, "workflow_ingest").await?;

    // WHICH EXISTING ROWS THIS INGEST TOUCHES (batch H-b, H3 review): the exact
    // row (a re-ingest, which the executor short-circuits), the head of the
    // lineage `canonical_name` already names (a new generation of it, parent
    // or no parent), and exactly the row the executor links as `parent_id`.
    let anchors = epigraph_db::WorkflowRepository::ingest_anchors(
        &mut tx,
        &extraction.source.canonical_name,
        extraction.source.generation as i32,
        extraction.source.parent_canonical_name.as_deref(),
    )
    .await
    .map_err(internal_error)?;
    let creating = anchors.existing.is_none();
    // `inherited`: `Some(x)` = the new row inherits submitter `x` (possibly no
    // record); `None` = a brand-new lineage, whose submitter is the caller.
    let mut inherited: Option<Option<uuid::Uuid>> = None;
    let mut admin_write = false;
    if creating {
        let mut checked: Vec<uuid::Uuid> = Vec::with_capacity(2);
        for anchor in [anchors.lineage_head, anchors.linked_parent]
            .into_iter()
            .flatten()
        {
            if checked.contains(&anchor) {
                continue;
            }
            checked.push(anchor);
            let grant = crate::tools::workflow_authority::require_workflow_authority(
                server,
                &mut tx,
                auth,
                caller,
                anchor,
                "workflow_ingest",
            )
            .await?;
            admin_write |= grant.admin;
            // The lineage head is checked first, so a new generation of an
            // existing name inherits ITS submitter; a new name forked from a
            // parent inherits the parent's.
            inherited.get_or_insert(grant.owner);
        }
    }

    let result = epigraph_ingest_executor::execute_workflow_ingest_plan(&mut tx, &plan, extraction)
        .await
        .map_err(|e| crate::errors::executor_caller_error("workflow ingest", e))?;
    // Recorded only when THIS call created the row: a re-ingest of an existing
    // (possibly pre-H-b, unrecorded) workflow must not make its caller the owner.
    let submitter = inherited.unwrap_or(Some(caller.agent_id()));
    if creating {
        if let Some(submitter) = submitter {
            epigraph_db::WorkflowRepository::record_submitter(
                &mut *tx,
                result.workflow_id,
                submitter,
            )
            .await
            .map_err(internal_error)?;
        }
    }
    if admin_write {
        crate::tools::workflow_authority::audit_admin_workflow_write(
            &mut tx,
            auth,
            caller,
            "workflow_ingest",
            result.workflow_id,
            submitter,
            serde_json::json!({
                "canonical_name": extraction.source.canonical_name,
                "generation": extraction.source.generation,
                "parent_canonical_name": extraction.source.parent_canonical_name,
                "lineage_head_before": anchors.lineage_head,
                "linked_parent": anchors.linked_parent,
                "claims_ingested": result.claims_ingested,
            }),
        )
        .await?;
    }
    tx.commit()
        .await
        .map_err(|e| internal_error(format!("workflow ingest: could not commit: {e}")))?;

    // The DS wiring runs in its OWN system-agent-stamped transaction, after the
    // ingest commit. `claim_frames` / `mass_functions` / the cached-belief
    // `UPDATE claims` are all owned by the same group as the claims they hang off
    // — the `workflow-ingest-system` agent's — so this needs the same stamp the
    // plan walk needed, and on the unstamped pool it was refused on BOTH
    // configurations (`claim_frames` carries no orphan `*_privacy` policy).
    //
    // A SECOND transaction rather than the ingest's own, because this half is
    // best-effort: a DS failure must not roll back a workflow that landed. Inside
    // it the per-entry work is SAVEPOINT-wrapped by `auto_wire_ds_batch` and
    // `auto_wire_edge_if_epistemic`, so one bad entry does not abort the rest.
    match crate::claim_helper::begin_system_ingest_stamped_tx(server, "workflow_ingest_ds").await {
        Ok((_agent, mut ds_tx)) => {
            wire_ds_after_ingest(&mut ds_tx, viewer, &plan, &result).await;
            if let Err(e) = ds_tx.commit().await {
                tracing::warn!(
                    workflow_id = %result.workflow_id,
                    "workflow ds wiring could not commit: {e}. The ingest is stored; its claims \
                     carry no BBA until a recompute reaches them"
                );
            }
        }
        Err(e) => tracing::warn!(
            workflow_id = %result.workflow_id,
            "workflow ds wiring skipped: {}. The ingest is stored and intact",
            e.message
        ),
    }

    let inserted = result.inserted.clone();
    let response = IngestWorkflowResponse {
        workflow_id: result.workflow_id.to_string(),
        canonical_name: result.canonical_name,
        generation: result.generation,
        claims_ingested: result.claims_ingested,
        claims_skipped_dedup: result.claims_skipped_dedup,
        executes_edges: result.executes_edges_created,
        relationships_created: result.relationship_edges_created,
        already_ingested: result.already_ingested,
    };
    Ok((response, inserted))
}

/// Post-commit DS wiring for a completed workflow ingest: an edge-factor BBA for
/// every newly-inserted epistemic plan edge, plus a per-claim BBA for every
/// newly-inserted level-3 operation atom.
///
/// # Post-commit and best-effort, deliberately outside the ingest transaction
///
/// The ingest is committed by the time this runs, and every failure below is
/// warned rather than returned. Pulling it inside the stamped transaction would
/// make a DS failure roll the whole ingest back — turning a WARN into a total
/// `store_workflow` outage, which is the fail-closed-regression-as-data-loss
/// shape `claim_helper::emit_verb_edge_best_effort`'s doc says this programme is
/// trying not to create.
///
/// Factored out of [`execute_workflow_ingest_with_inserted`] when that function
/// took the server instead of a pool: `do_ingest_workflow_via_pool` is the
/// `#[sqlx::test]` fixture and it must keep firing the same wiring, or a test
/// asserting on `mass_functions` measures the refactor instead of the tool.
/// MEASURED — the first revision of this change did lose it, and
/// `ingest_workflow_tags_atom_bbas_with_normalized_evidence_type` failed with
/// "expected exactly 2 operation-atom BBAs tagged 'empirical', found 0".
async fn wire_ds_after_ingest(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    plan: &epigraph_ingest::common::plan::IngestPlan,
    result: &epigraph_ingest_executor::WorkflowIngestExecutionResult,
) {
    // Auto-wire DS factors for newly-inserted epistemic edges. The executor
    // returns the edges so the caller can fire this without pulling
    // `epigraph-engine` into the executor's dep graph (matches the embedding
    // pattern documented in CLAUDE.md "Embedding policy").
    let Some(agent_id) = result.system_agent_id else {
        return;
    };
    for e in &result.inserted_edges {
        ds_auto::auto_wire_edge_if_epistemic(
            &mut *conn,
            viewer,
            true, // executor only emits an InsertedPlanEdge when was_created=true
            e.edge_id,
            e.source_id,
            &e.source_type,
            e.target_id,
            &e.target_type,
            &e.relationship,
            agent_id,
        )
        .await;
    }

    // Per-claim CDST batch wire (operation atoms only) — parity with
    // `do_ingest_document`, which wires a per-atom BBA carrying the
    // normalised `evidence_type` so the tag reaches `mass_functions` and
    // participates in `effective_source_strength` / the per-perspective
    // frame function. The workflow hierarchy edges (decomposes / *_follows /
    // executes / asserts) all map to `RestrictionKind::Neutral`, so edge
    // auto-wire writes no BBA — without this loop the operation atoms would
    // have no BBA at all. Only newly-inserted level-3 atoms get an entry:
    // thesis/phase/step claims are structural (matching the document path,
    // where only level-3 atoms are wired). `weight` mirrors the document
    // default for an untagged-methodology claim (`Methodology::Extraction`).
    let inserted_ids: std::collections::HashSet<uuid::Uuid> =
        result.inserted.iter().map(|(id, _)| *id).collect();
    let ds_entries: Vec<ds_auto::BatchDsEntry> = plan
        .claims
        .iter()
        .filter(|c| c.level == 3 && inserted_ids.contains(&c.id))
        .map(|c| ds_auto::BatchDsEntry {
            claim_id: c.id,
            confidence: c.confidence.clamp(0.0, 1.0),
            weight: epigraph_core::Methodology::Extraction.weight_modifier(),
            evidence_type: c.evidence_type.clone(),
            // Workflow steps carry no axis declaration; the workflow builder
            // always plans `axis: None`, so this is the binary frame (#222).
            axis: c.axis.clone(),
        })
        .collect();
    if !ds_entries.is_empty() {
        if let Err(e) = ds_auto::auto_wire_ds_batch(&mut *conn, viewer, &ds_entries, agent_id).await
        {
            tracing::warn!("workflow ds auto-wire batch failed: {e}");
        }
    }
}

/// Pool-only ingest logic, for test fixtures that hold a `sqlx::test`-managed
/// pool and no server.
///
/// **This is the UNSTAMPED path and it is deliberately not the production one.**
/// `#[sqlx::test]` connects as `epigraph` — superuser, `BYPASSRLS`, owner of
/// every protected table — so the tenancy stamp is inert there and an extra
/// connection is all a stamp would buy. Production goes through
/// [`execute_workflow_ingest_with_inserted`], which takes the server so it can
/// reach the `ScopedPool`. A caller that reaches for this function with a real
/// least-privilege pool gets the refusal the conversion exists to remove, which
/// is the correct outcome: it means the call site needs a server, not a pool.
///
/// Thin wrapper over [`epigraph_ingest_executor::execute_workflow_ingest_plan`];
/// see that function for the canonical persistence semantics. Does NOT embed
/// — embedding happens in the MCP entry point [`do_ingest_workflow`], which
/// has access to `server.embedder`.
///
/// **The walk runs in ONE transaction, as production's does.** Unstamped is a
/// deliberate difference from production; autocommit was not. On a bare pooled
/// checkout every statement got its own `NOW()`, so the fixture's plan got
/// strictly increasing `created_at` values that production's never has — and a
/// reader ordering a workflow's steps by `created_at` passed every test built on
/// this fixture while it returned steps in UUID order on the server. A fixture
/// that differs from production on the very property under test cannot see it.
pub async fn do_ingest_workflow_via_pool(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &WorkflowExtraction,
) -> Result<IngestWorkflowResponse, McpError> {
    let plan = epigraph_ingest::workflow::builder::build_ingest_plan(extraction);
    let result = {
        // Named `unstamped_tx`, not `tx`: `residual_unstamped_writes.rs`'s
        // executor-call register counts calls spelled `&mut tx` as STAMPED, and
        // this one is not.
        let mut unstamped_tx = pool
            .begin()
            .await
            .map_err(|e| internal_error(format!("workflow ingest: could not begin: {e}")))?;
        let result = epigraph_ingest_executor::execute_workflow_ingest_plan(
            &mut unstamped_tx,
            &plan,
            extraction,
        )
        .await
        .map_err(|e| crate::errors::executor_caller_error("workflow ingest", e))?;
        unstamped_tx
            .commit()
            .await
            .map_err(|e| internal_error(format!("workflow ingest: could not commit: {e}")))?;
        result
    };
    {
        let mut ds_conn = pool
            .acquire()
            .await
            .map_err(|e| internal_error(format!("workflow ingest: could not acquire: {e}")))?;
        wire_ds_after_ingest(&mut ds_conn, viewer, &plan, &result).await;
    }
    Ok(IngestWorkflowResponse {
        workflow_id: result.workflow_id.to_string(),
        canonical_name: result.canonical_name.clone(),
        generation: result.generation,
        claims_ingested: result.claims_ingested,
        claims_skipped_dedup: result.claims_skipped_dedup,
        executes_edges: result.executes_edges_created,
        relationships_created: result.relationship_edges_created,
        already_ingested: result.already_ingested,
    })
}

// ── MCP entry point ────────────────────────────────────────────────────────

/// MCP tool: ingest a `WorkflowExtraction` JSON.
pub async fn do_ingest_workflow(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    extraction: &WorkflowExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    let (response, inserted) =
        execute_workflow_ingest_with_inserted(server, viewer, extraction, auth).await?;

    // Embed inline, best-effort. Satisfies the is_current=true → has-embedding
    // invariant (CLAUDE.md "Embedding policy"). Failures warn and continue —
    // embedding is recoverable via backfill; the workflow ingest is not.
    // `embed_and_store` logs tracing::warn on failure internally; no outer handling needed.
    for (claim_id, content) in &inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }

    // Also embed the workflows-table goal for semantic find_workflow_hierarchical.
    // Best-effort: workflow is still findable via ILIKE fallback if this errors.
    if let Ok(wf_id) = uuid::Uuid::parse_str(&response.workflow_id) {
        match server.embedder.generate(&extraction.source.goal).await {
            Ok(qvec) => {
                if let Err(e) =
                    epigraph_db::WorkflowRepository::set_goal_embedding(&server.pool, wf_id, &qvec)
                        .await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed");
            }
        }
    }

    success_json(&response)
}

/// Param-driven MCP tool entry point. Thin wrapper over `do_ingest_workflow`.
pub async fn ingest_workflow(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: IngestWorkflowParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    do_ingest_workflow(server, viewer, &params.extraction, auth).await
}

// ── improve_workflow_hierarchy ─────────────────────────────────────────────
//
// Creates a generation-incremented variant of an existing hierarchical
// workflow lineage. Idempotent on `(canonical_name, generation)` via the
// underlying executor's gate: a fully-formed variant at the resolved
// generation is detected and reported as `already_ingested`. Note that the
// resolved generation is always `max(generation) + 1` for the canonical
// lineage, so back-to-back calls each produce a fresh generation rather
// than no-oping the second call.
//
// We do NOT add the `'workflow'` label to the thesis claim. That label is
// reserved for FLAT workflow claims (the `store_workflow` / `improve_workflow`
// lineage). Hierarchical workflows live in the `workflows` table and use
// `kind: workflow_thesis` on the root claim, matching `do_ingest_workflow`'s
// behavior.

#[derive(Debug, serde::Serialize)]
pub struct ImproveWorkflowHierarchyResponse {
    pub parent_canonical_name: String,
    pub parent_generation: i32,
    pub new_generation: i32,
    pub workflow_id: String,
    pub claims_ingested: usize,
    pub already_ingested: bool,
}

/// Inner helper: same as [`improve_workflow_hierarchy_via_pool`] but also
/// returns the executor's `inserted` vec so MCP entry points can embed.
/// Called by `improve_workflow_hierarchy` (this module) — kept private since
/// no other module needs the inserted vec for this path.
async fn improve_workflow_hierarchy_with_inserted(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    parent_canonical_name: &str,
    mut extraction: WorkflowExtraction,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<(ImproveWorkflowHierarchyResponse, Vec<(uuid::Uuid, String)>), McpError> {
    let parent_max = epigraph_db::WorkflowRepository::max_generation_by_canonical(
        &server.pool,
        parent_canonical_name,
    )
    .await
    .map_err(internal_error)?
    .ok_or_else(|| {
        invalid_params(format!(
            "no workflow with canonical_name={parent_canonical_name}"
        ))
    })?;

    let new_generation = parent_max + 1;

    extraction.source.canonical_name = parent_canonical_name.to_string();
    extraction.source.generation = u32::try_from(new_generation)
        .map_err(|e| internal_error(format!("new_generation does not fit in u32: {e}")))?;
    extraction.source.parent_canonical_name = Some(parent_canonical_name.to_string());

    let (response, inserted) =
        execute_workflow_ingest_with_inserted(server, viewer, &extraction, auth).await?;

    let improve_response = ImproveWorkflowHierarchyResponse {
        parent_canonical_name: parent_canonical_name.to_string(),
        parent_generation: parent_max,
        new_generation,
        workflow_id: response.workflow_id,
        claims_ingested: response.claims_ingested,
        already_ingested: response.already_ingested,
    };
    Ok((improve_response, inserted))
}

/// Pool-only logic for `improve_workflow_hierarchy`. Resolves the max
/// generation for `parent_canonical_name`, overwrites the caller-supplied
/// extraction source fields with the resolved variant identity, then calls
/// the shared inner helper to perform the actual hierarchical ingest.
///
/// Caller-supplied values for `extraction.source.canonical_name`,
/// `extraction.source.generation`, and `extraction.source.parent_canonical_name`
/// are intentionally OVERWRITTEN so that the variant's identity is dictated
/// by the resolver, not the caller. Does NOT embed — embedding happens in
/// the MCP entry point [`improve_workflow_hierarchy`].
///
/// **Unstamped, like [`do_ingest_workflow_via_pool`], and for the same reason:**
/// it is a fixture entry point for `#[sqlx::test]`, which connects as a
/// `BYPASSRLS` superuser. The production path is
/// [`improve_workflow_hierarchy`], which holds a server and can reach the
/// `ScopedPool`.
pub async fn improve_workflow_hierarchy_via_pool(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    parent_canonical_name: &str,
    mut extraction: WorkflowExtraction,
) -> Result<ImproveWorkflowHierarchyResponse, McpError> {
    let parent_max =
        epigraph_db::WorkflowRepository::max_generation_by_canonical(pool, parent_canonical_name)
            .await
            .map_err(internal_error)?
            .ok_or_else(|| {
                invalid_params(format!(
                    "no workflow with canonical_name={parent_canonical_name}"
                ))
            })?;
    let new_generation = parent_max + 1;
    extraction.source.canonical_name = parent_canonical_name.to_string();
    extraction.source.generation = u32::try_from(new_generation)
        .map_err(|e| internal_error(format!("new_generation does not fit in u32: {e}")))?;
    extraction.source.parent_canonical_name = Some(parent_canonical_name.to_string());

    let response = do_ingest_workflow_via_pool(pool, viewer, &extraction).await?;
    Ok(ImproveWorkflowHierarchyResponse {
        parent_canonical_name: parent_canonical_name.to_string(),
        parent_generation: parent_max,
        new_generation,
        workflow_id: response.workflow_id,
        claims_ingested: response.claims_ingested,
        already_ingested: response.already_ingested,
    })
}

/// MCP tool entry point for `improve_workflow_hierarchy`.
pub async fn improve_workflow_hierarchy(
    server: &EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: ImproveWorkflowHierarchyParams,
    auth: Option<&epigraph_auth::AuthContext>,
) -> Result<CallToolResult, McpError> {
    // Save goal before params.extraction is consumed by improve_workflow_hierarchy_with_inserted.
    let goal = params.extraction.source.goal.clone();
    let (response, inserted) = improve_workflow_hierarchy_with_inserted(
        server,
        viewer,
        &params.parent_canonical_name,
        params.extraction,
        auth,
    )
    .await?;

    // Embed inline, best-effort (see `do_ingest_workflow` for rationale).
    // `embed_and_store` logs tracing::warn on failure internally; no outer handling needed.
    for (claim_id, content) in &inserted {
        let _ = server.embedder.embed_and_store(*claim_id, content).await;
    }

    // Also embed into workflows.goal_embedding for find_workflow_hierarchical.
    // Without this, the new higher-generation row has NULL goal_embedding and is
    // invisible to find_hierarchical_by_embedding's WHERE goal_embedding IS NOT NULL
    // filter — the embedding search silently surfaces the last-embedded generation
    // instead of the latest one. Mirrors the identical block in do_ingest_workflow.
    if let Ok(wf_id) = uuid::Uuid::parse_str(&response.workflow_id) {
        match server.embedder.generate(&goal).await {
            Ok(qvec) => {
                if let Err(e) =
                    epigraph_db::WorkflowRepository::set_goal_embedding(&server.pool, wf_id, &qvec)
                        .await
                {
                    tracing::warn!(workflow_id=%wf_id, error=?e, "set_goal_embedding failed");
                }
            }
            Err(e) => {
                tracing::warn!(workflow_id=%wf_id, error=?e, "goal embedding generation failed");
            }
        }
    }

    success_json(&response)
}

// ── Integration tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ingest::workflow::schema::{Phase, Step, WorkflowSource};
    use uuid::Uuid;

    fn minimal_extraction() -> WorkflowExtraction {
        WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: "test-workflow-ingest".to_string(),
                goal: "Run integration tests for ingest".to_string(),
                generation: 0,
                parent_canonical_name: None,
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("This workflow validates ingest idempotency".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Phase 1".to_string(),
                summary: "Execute the first and only phase".to_string(),
                steps: vec![Step {
                    compound: "Run the integration test suite".to_string(),
                    rationale: "CI must pass".to_string(),
                    operations: vec!["cargo test".to_string(), "check exit code".to_string()],
                    generality: vec![2, 1],
                    confidence: 0.9,
                    evidence_type: None,
                }],
            }],
            relationships: vec![],
        }
    }

    /// Smoke test: a fresh extraction ingests without error and returns
    /// `already_ingested: false` with at least one claim inserted.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_smoke(pool: sqlx::PgPool) {
        let extraction = minimal_extraction();
        let result = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &extraction,
        )
        .await
        .expect("ingest must succeed");

        assert!(
            !result.already_ingested,
            "first ingest should not be skipped"
        );
        assert!(
            result.claims_ingested > 0,
            "expected at least one new claim"
        );
        assert!(result.executes_edges > 0, "expected executes edges");
    }

    /// Idempotency test: ingesting the same extraction twice returns
    /// `already_ingested: true` on the second call.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_idempotent(pool: sqlx::PgPool) {
        let mut extraction = minimal_extraction();
        // Use a unique canonical_name so this test doesn't collide with smoke.
        extraction.source.canonical_name = "test-workflow-idempotent".to_string();

        let r1 = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &extraction,
        )
        .await
        .expect("first ingest");
        assert!(!r1.already_ingested);

        let r2 = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &extraction,
        )
        .await
        .expect("second ingest");
        assert!(r2.already_ingested, "second ingest should be a no-op");

        // After re-ingest, edge count should be unchanged.
        let exec_edges_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges WHERE source_id = $1 AND relationship = 'executes'",
        )
        .bind(Uuid::parse_str(&r1.workflow_id).expect("valid uuid"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            exec_edges_after, r1.executes_edges as i64,
            "re-ingest must not duplicate executes edges"
        );

        let claim_count_after: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM claims WHERE id IN \
             (SELECT target_id FROM edges WHERE source_id = $1 AND relationship = 'executes')",
        )
        .bind(Uuid::parse_str(&r1.workflow_id).expect("valid uuid"))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            claim_count_after, r1.executes_edges as i64,
            "re-ingest must not duplicate claims"
        );
    }

    /// Cross-source convergence: same atom text in a document and a workflow → same claim id.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_atom_converges_with_document_atom(pool: sqlx::PgPool) {
        // Build the document's plan deterministically and manually persist its atom claim.
        let doc_extraction: epigraph_ingest::document::DocumentExtraction = serde_json::from_str(
            r#"{
                "source": {"title": "Test Paper", "source_type": "Paper", "authors": []},
                "thesis": "Doc thesis",
                "sections": [{
                    "title": "Body",
                    "paragraphs": [{
                        "text": "P1",
                        "atoms": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }],
                "relationships": []
            }"#,
        )
        .unwrap();

        let doc_plan = epigraph_ingest::document::build_ingest_plan(&doc_extraction);
        let atom_text = "text-embedding-3-large produces 3072-dimensional vectors.";
        let hash = blake3::hash(atom_text.as_bytes());
        let expected_atom_id = Uuid::new_v5(
            &epigraph_ingest::common::ids::ATOM_NAMESPACE,
            hash.as_bytes(),
        );

        // Manually insert the document atom (mirrors what do_ingest_document would do).
        let sys_agent_id = epigraph_ingest_executor::get_or_create_system_agent(
            &mut pool.acquire().await.expect("acquire"),
        )
        .await
        .unwrap();
        let doc_atom = doc_plan.claims.iter().find(|c| c.level == 3).unwrap();
        assert_eq!(doc_atom.id, expected_atom_id);
        epigraph_db::ClaimRepository::create_with_id_if_absent(
            &pool,
            doc_atom.id,
            &doc_atom.content,
            &doc_atom.content_hash,
            sys_agent_id,
            epigraph_core::TruthValue::clamped(0.5),
            &["paper_atom".to_string()],
            epigraph_db::ClaimRepository::default_decl_for_author_pool(&pool, sys_agent_id)
                .await
                .unwrap(),
        )
        .await
        .unwrap();

        // Now ingest a workflow that uses the same atom text as one of its operations.
        let wf_extraction: epigraph_ingest::workflow::WorkflowExtraction = serde_json::from_str(
            r#"{
                "source": {"canonical_name": "embed-pipeline-convergence-test", "goal": "G", "generation": 0, "authors": []},
                "thesis": "Workflow thesis",
                "phases": [{
                    "title": "Embed", "summary": "Embed step",
                    "steps": [{
                        "compound": "Run embedding",
                        "operations": ["text-embedding-3-large produces 3072-dimensional vectors."],
                        "generality": [1], "confidence": 0.9
                    }]
                }]
            }"#,
        )
        .unwrap();
        let wf_result = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &wf_extraction,
        )
        .await
        .unwrap();

        // Exactly one row in claims with this id (no duplicate from ingest).
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM claims WHERE id = $1")
            .bind(expected_atom_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "atom must converge to one claim node, not two");

        // The workflow has an `executes` edge to the same atom.
        let wf_id = Uuid::parse_str(&wf_result.workflow_id).expect("valid uuid");
        let wf_edge: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM edges \
             WHERE source_id = $1 AND target_id = $2 AND relationship = 'executes'",
        )
        .bind(wf_id)
        .bind(expected_atom_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(wf_edge, 1);
    }

    /// executes-edges test: the workflow row is linked to every planned claim.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_executes_edges_created(pool: sqlx::PgPool) {
        let mut extraction = minimal_extraction();
        extraction.source.canonical_name = "test-workflow-executes".to_string();

        let result = do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &extraction,
        )
        .await
        .expect("ingest must succeed");

        // Count executes edges in DB.
        let wf_id = Uuid::parse_str(&result.workflow_id).expect("valid uuid");
        let db_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges \
             WHERE source_id = $1 AND source_type = 'workflow' AND relationship = 'executes'",
        )
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("count query");

        assert_eq!(
            db_count, result.executes_edges as i64,
            "DB edge count must match reported executes_edges"
        );
        assert!(db_count > 0, "must have at least one executes edge");
    }

    /// End-to-end parity with #208 (document side): a workflow step tagged
    /// (mixed-case) "Empirical" must produce operation-atom BBAs whose
    /// `mass_functions.evidence_type` is the normalized canonical 'empirical'.
    /// Asserts on the DB-stored value, not the in-memory plan. Also covers the
    /// unknown-tag → None path and confirms structural claims (thesis/phase/
    /// step compound) get no per-claim BBA.
    #[sqlx::test(migrations = "../../migrations")]
    async fn ingest_workflow_tags_atom_bbas_with_normalized_evidence_type(pool: sqlx::PgPool) {
        let extraction = WorkflowExtraction {
            source: WorkflowSource {
                canonical_name: "test-workflow-evidence-type".to_string(),
                goal: "Validate evidence_type wiring".to_string(),
                generation: 0,
                parent_canonical_name: None,
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("Workflow evidence-type tags reach the BBA".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Phase 1".to_string(),
                summary: "Tagged phase".to_string(),
                steps: vec![
                    Step {
                        compound: "Empirical step compound".to_string(),
                        rationale: "measured directly".to_string(),
                        operations: vec![
                            "Empirical operation one under standard conditions".to_string(),
                            "Empirical operation two replicating operation one".to_string(),
                        ],
                        generality: vec![1, 1],
                        confidence: 0.9,
                        evidence_type: Some("Empirical".to_string()), // mixed case
                    },
                    Step {
                        compound: "Untagged step compound".to_string(),
                        rationale: "no evidence type".to_string(),
                        operations: vec!["Operation with a bogus tag source".to_string()],
                        generality: vec![1],
                        confidence: 0.9,
                        evidence_type: Some("made_up_type".to_string()), // unknown → None
                    },
                ],
            }],
            relationships: vec![],
        };

        do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &extraction,
        )
        .await
        .expect("ingest must succeed");

        // The two operation atoms under the "Empirical" step carry the
        // normalized canonical tag on their BBA.
        let empirical_bbas: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mass_functions WHERE evidence_type = 'empirical'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            empirical_bbas, 2,
            "expected exactly 2 operation-atom BBAs tagged 'empirical', found {empirical_bbas}"
        );

        // The raw (un-normalized) mixed-case value never reaches the column.
        let raw_case: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mass_functions WHERE evidence_type = 'Empirical'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            raw_case, 0,
            "raw 'Empirical' must be normalized to lowercase"
        );

        // The unknown tag is dropped: its atom BBA exists but is untagged.
        let bogus: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mass_functions WHERE evidence_type = 'made_up_type'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(bogus, 0, "unknown tag must not reach mass_functions");

        // Exactly 3 operation atoms total → 3 per-claim BBAs; no BBA for the
        // structural thesis/phase/step claims (only level-3 atoms are wired).
        let total_bbas: i64 = sqlx::query_scalar("SELECT count(*) FROM mass_functions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            total_bbas, 3,
            "one BBA per operation atom; structural claims get none, found {total_bbas}"
        );
    }

    /// Regression test for k1-trace-bug: `improve_workflow_hierarchy` must not
    /// produce a `claims_content_not_empty` constraint violation when a Phase
    /// has an empty (or omitted) `summary`.
    ///
    /// `Phase.summary` is `#[serde(default)]` so it defaults to `""` when
    /// absent from JSON. Before the fix, `build_ingest_plan` used
    /// `phase.summary.clone()` as the level-1 claim content without guarding
    /// against an empty value, causing PostgreSQL to reject the INSERT with
    /// `ERROR: new row violates check constraint "claims_content_not_empty"`.
    ///
    /// The fix falls back to `phase.title` in `builder.rs` when summary is blank.
    /// This test validates the full end-to-end path through
    /// `improve_workflow_hierarchy_via_pool`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn improve_workflow_hierarchy_empty_phase_summary_succeeds(pool: sqlx::PgPool) {
        // 1. Seed the base workflow (generation 0).
        let mut base = minimal_extraction();
        base.source.canonical_name = "weekly-capability-audit".to_string();
        do_ingest_workflow_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            &base,
        )
        .await
        .expect("base workflow ingest must succeed");

        // 2. Build an improved extraction where summary is explicitly empty —
        //    this is the triggering condition from the bug report.
        let improved = WorkflowExtraction {
            source: epigraph_ingest::workflow::schema::WorkflowSource {
                canonical_name: "will-be-overwritten".to_string(),
                goal: "Improved audit capabilities".to_string(),
                generation: 99, // overwritten by improve_workflow_hierarchy_via_pool
                parent_canonical_name: None, // overwritten
                authors: vec![],
                expected_outcome: None,
                tags: vec![],
                metadata: serde_json::json!({}),
            },
            thesis: Some("Improved thesis".to_string()),
            thesis_derivation: epigraph_ingest::common::schema::ThesisDerivation::TopDown,
            phases: vec![Phase {
                title: "Capability Review Phase".to_string(),
                summary: "".to_string(), // empty — the serde default; was the bug trigger
                steps: vec![Step {
                    compound: "Review all system capabilities".to_string(),
                    rationale: "Ensure completeness".to_string(),
                    operations: vec!["audit step".to_string()],
                    generality: vec![1],
                    confidence: 0.85,
                    evidence_type: None,
                }],
            }],
            relationships: vec![],
        };

        // 3. Must succeed without a constraint violation.
        let result = improve_workflow_hierarchy_via_pool(
            &pool,
            &epigraph_db::visibility::Viewer::resolve(&pool, uuid::Uuid::nil())
                .await
                .expect("resolve viewer"),
            "weekly-capability-audit",
            improved,
        )
        .await
        .expect("improve must not violate claims_content_not_empty constraint");

        assert!(!result.already_ingested, "should be a fresh generation");
        assert!(
            result.claims_ingested > 0,
            "expected at least one new claim"
        );
        assert_eq!(result.parent_generation, 0);
        assert_eq!(result.new_generation, 1);

        // 4. Verify the phase claim actually has the title as content (not empty).
        let phase_content: String = sqlx::query_scalar(
            "SELECT content FROM claims \
             WHERE properties->>'kind' = 'workflow_step' \
               AND properties->>'level' = '1' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("phase claim must exist");

        assert_eq!(
            phase_content, "Capability Review Phase",
            "phase claim content must fall back to title when summary is empty"
        );
    }
}
