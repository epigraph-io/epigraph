//! Repository for workflow claim operations.
//!
//! Workflows are claims labeled with 'workflow' that represent
//! reusable research procedures with variant lineages.

use std::collections::HashMap;

use futures::future::try_join_all;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::claim::{ClaimRepository, LineageHead};

/// Workflow recall result (semantic or text search).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowRecallResult {
    pub claim_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub similarity: f64,
    pub hybrid_score: f64,
    pub edge_count: i64,
    pub properties: serde_json::Value,
    pub parent_id: Option<String>,
}

#[derive(sqlx::FromRow)]
struct WorkflowRecallRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    similarity: f64,
    hybrid_score: f64,
    edge_count: i64,
    properties: serde_json::Value,
    parent_id: Option<String>,
}

/// Row type for list_workflows query.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct WorkflowListRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub labels: Vec<String>,
    pub properties: serde_json::Value,
}

/// Row type returned by `WorkflowRepository::search_hierarchical_by_text`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HierarchicalWorkflowRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Deprecation signal. Live rows are 1.0; `deprecate_workflow`
    /// cascades a write to 0.05 so callers can filter via `min_truth`.
    pub truth_value: f64,
}

/// Per-step resolution result for `find_workflow_hierarchical(resolve_to_latest=true)`.
///
/// `frozen_claim_id` is the original step claim attached to the workflow via
/// the `executes` edge. `heads` lists the current head(s) of the step's
/// lineage (claims with `step_lineage_id = $lineage` and no incoming
/// `supersedes` edge); empty when the step has no `step_lineage_id` (legacy)
/// or when the lineage has been pruned. `pending_resolution` is true when
/// the lineage has more than one head — caller must reconcile before reuse.
#[derive(Debug, serde::Serialize)]
pub struct ResolvedStep {
    pub step_index: usize,
    pub frozen_claim_id: Uuid,
    pub step_lineage_id: Option<Uuid>,
    pub heads: Vec<LineageHead>,
    pub pending_resolution: bool,
}

pub struct WorkflowRepository;

impl WorkflowRepository {
    /// Insert a row into the new `workflows` table (added in migration 020).
    /// Used by `epigraph-mcp::tools::workflow_ingest::do_ingest_workflow`.
    /// Idempotent on `(canonical_name, generation)` UNIQUE — repeated inserts
    /// of the same identity are silently ignored.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails for reasons other
    /// than a duplicate-key conflict on the UNIQUE constraint.
    pub async fn insert_root(
        pool: &PgPool,
        id: Uuid,
        canonical_name: &str,
        generation: i32,
        goal: &str,
        parent_id: Option<Uuid>,
        metadata: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO workflows (id, canonical_name, generation, goal, parent_id, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (canonical_name, generation) DO NOTHING",
        )
        .bind(id)
        .bind(canonical_name)
        .bind(generation)
        .bind(goal)
        .bind(parent_id)
        .bind(metadata)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Look up a workflow root by `(canonical_name, generation)`.
    pub async fn find_root_by_canonical(
        pool: &PgPool,
        canonical_name: &str,
        generation: i32,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2",
        )
        .bind(canonical_name)
        .bind(generation)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Return the highest existing `generation` for the given `canonical_name`,
    /// or `None` if no rows exist. Used by `improve_workflow_hierarchy` to
    /// pick the next generation for a variant.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the underlying query fails.
    pub async fn max_generation_by_canonical(
        pool: &PgPool,
        canonical_name: &str,
    ) -> Result<Option<i32>, sqlx::Error> {
        // `SELECT MAX(...)` always returns exactly one row in PostgreSQL —
        // `NULL` when no source rows match. `fetch_one` matches that contract;
        // the inner `Option<i32>` carries the "no matching rows" signal.
        let (max_gen,): (Option<i32>,) =
            sqlx::query_as("SELECT MAX(generation) FROM workflows WHERE canonical_name = $1")
                .bind(canonical_name)
                .fetch_one(pool)
                .await?;
        Ok(max_gen)
    }

    /// Semantic search for workflows by embedding with hybrid scoring.
    pub async fn find_by_embedding(
        pool: &PgPool,
        query_embedding: &[f32],
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<WorkflowRecallResult>, sqlx::Error> {
        let vec_str = format!(
            "[{}]",
            query_embedding
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );

        let rows: Vec<WorkflowRecallRow> = sqlx::query_as(
            "WITH query_vec AS (SELECT $1::vector AS vec), \
             base AS ( \
                 SELECT c.id, c.content, c.truth_value, c.properties, \
                        1 - (c.embedding <=> q.vec) AS similarity, \
                        COALESCE(( \
                            SELECT COUNT(*) FROM edges e \
                            WHERE e.source_id = c.id OR e.target_id = c.id \
                        ), 0) AS edge_count \
                 FROM claims c, query_vec q \
                 WHERE c.embedding IS NOT NULL AND vector_norm(c.embedding) > 0 \
                   AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   AND 'workflow' = ANY(c.labels) \
             ) \
             SELECT b.id, b.content, b.truth_value, b.similarity, b.edge_count, b.properties, \
                    b.similarity * 0.6 + b.truth_value * 0.2 + LEAST(b.edge_count::float / 10.0, 1.0) * 0.2 AS hybrid_score, \
                    (SELECT e2.source_id::text FROM edges e2 \
                     WHERE e2.target_id = b.id AND e2.relationship IN ('variant_of', 'supersedes') LIMIT 1) AS parent_id \
             FROM base b \
             ORDER BY hybrid_score DESC \
             LIMIT $3",
        )
        .bind(&vec_str)
        .bind(min_truth)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowRecallResult {
                claim_id: r.id,
                content: r.content,
                truth_value: r.truth_value,
                similarity: r.similarity,
                hybrid_score: r.hybrid_score,
                edge_count: r.edge_count,
                properties: r.properties,
                parent_id: r.parent_id,
            })
            .collect())
    }

    /// Text-based workflow search (fallback when embeddings unavailable).
    pub async fn find_by_text(
        pool: &PgPool,
        query: &str,
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<WorkflowRecallResult>, sqlx::Error> {
        let pattern = format!("%{query}%");

        let rows: Vec<WorkflowRecallRow> = sqlx::query_as(
            "WITH base AS ( \
                 SELECT c.id, c.content, c.truth_value, c.properties, \
                        0.0::float8 AS similarity, \
                        COALESCE(( \
                            SELECT COUNT(*) FROM edges e \
                            WHERE e.source_id = c.id OR e.target_id = c.id \
                        ), 0) AS edge_count \
                 FROM claims c \
                 WHERE c.content ILIKE $1 AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   AND 'workflow' = ANY(c.labels) \
             ) \
             SELECT b.id, b.content, b.truth_value, b.similarity, b.edge_count, b.properties, \
                    b.truth_value * 0.5 + LEAST(b.edge_count::float / 10.0, 1.0) * 0.5 AS hybrid_score, \
                    (SELECT e2.source_id::text FROM edges e2 \
                     WHERE e2.target_id = b.id AND e2.relationship IN ('variant_of', 'supersedes') LIMIT 1) AS parent_id \
             FROM base b \
             ORDER BY hybrid_score DESC \
             LIMIT $3",
        )
        .bind(&pattern)
        .bind(min_truth)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| WorkflowRecallResult {
                claim_id: r.id,
                content: r.content,
                truth_value: r.truth_value,
                similarity: r.similarity,
                hybrid_score: r.hybrid_score,
                edge_count: r.edge_count,
                properties: r.properties,
                parent_id: r.parent_id,
            })
            .collect())
    }

    /// List workflow claims filtered by truth threshold and optional category label.
    pub async fn list(
        pool: &PgPool,
        min_truth: f64,
        category: Option<&str>,
        limit: i64,
    ) -> Result<Vec<WorkflowListRow>, sqlx::Error> {
        if let Some(cat) = category {
            sqlx::query_as::<_, WorkflowListRow>(
                "SELECT c.id, c.content, c.truth_value, c.labels, c.properties \
                 FROM claims c \
                 WHERE 'workflow' = ANY(c.labels) \
                   AND $1 = ANY(c.labels) \
                   AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                 ORDER BY c.truth_value DESC \
                 LIMIT $3",
            )
            .bind(cat)
            .bind(min_truth)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as::<_, WorkflowListRow>(
                "SELECT c.id, c.content, c.truth_value, c.labels, c.properties \
                 FROM claims c \
                 WHERE 'workflow' = ANY(c.labels) \
                   AND c.truth_value >= $1 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                 ORDER BY c.truth_value DESC \
                 LIMIT $2",
            )
            .bind(min_truth)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }

    /// Find all descendants of a workflow via `variant_of` or `supersedes` edges
    /// (for cascade deprecation).
    pub async fn find_descendants(
        pool: &PgPool,
        workflow_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "WITH RECURSIVE descendants AS ( \
                 SELECT source_id AS id FROM edges \
                 WHERE target_id = $1 AND relationship IN ('variant_of', 'supersedes') \
                 UNION ALL \
                 SELECT e.source_id FROM edges e \
                 JOIN descendants d ON e.target_id = d.id \
                 WHERE e.relationship IN ('variant_of', 'supersedes') \
             ) \
             SELECT id FROM descendants",
        )
        .bind(workflow_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Walk up `variant_of` or `supersedes` edges to find the lineage root ancestor.
    ///
    /// Returns `workflow_id` itself if it has no parent (is already a root).
    /// The root is the ancestor with no outgoing `variant_of` or `supersedes` edge.
    pub async fn find_lineage_root(pool: &PgPool, workflow_id: Uuid) -> Result<Uuid, sqlx::Error> {
        let root: Option<(Uuid,)> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT $1::uuid AS id
                UNION ALL
                SELECT e.target_id AS id
                FROM ancestors a
                JOIN edges e ON e.source_id = a.id
                    AND e.relationship IN ('variant_of', 'supersedes')
                    AND e.source_type = 'claim' AND e.target_type = 'claim'
            )
            SELECT a.id FROM ancestors a
            WHERE NOT EXISTS (
                SELECT 1 FROM edges e
                WHERE e.source_id = a.id
                  AND e.relationship IN ('variant_of', 'supersedes')
                  AND e.source_type = 'claim' AND e.target_type = 'claim'
            )
            LIMIT 1
            "#,
        )
        .bind(workflow_id)
        .fetch_optional(pool)
        .await?;

        Ok(root.map(|(id,)| id).unwrap_or(workflow_id))
    }

    /// For each `executes`-edge from the workflow root, walk supersedes/revises
    /// edges to the latest head claim. Mirrors the resolution logic that
    /// previously lived in `epigraph-mcp::tools::workflow_hierarchical::build_resolved_steps`.
    ///
    /// # Errors
    /// Returns `DbError` if the database query fails.
    pub async fn resolve_steps_to_heads(
        pool: &PgPool,
        workflow_id: Uuid,
    ) -> Result<Vec<ResolvedStep>, DbError> {
        // Pull all level=2 step claims under this workflow with their
        // step_lineage_id, ordered by edge created_at + claim id (matches
        // do_report_hierarchical_outcome_via_pool).
        let step_rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
            "SELECT c.id, c.step_lineage_id \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = $1 AND e.relationship = 'executes' AND (c.properties->>'level')::int = 2 \
             ORDER BY e.created_at ASC, c.id ASC",
        )
        .bind(workflow_id)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let head_futures = step_rows.iter().map(|(_, step_lineage_id)| async move {
            if let Some(lineage_id) = *step_lineage_id {
                ClaimRepository::latest_in_lineage(pool, lineage_id).await
            } else {
                Ok(Vec::new())
            }
        });
        let heads_per_step: Vec<Vec<LineageHead>> = try_join_all(head_futures).await?;

        let resolved = step_rows
            .into_iter()
            .enumerate()
            .zip(heads_per_step)
            .map(
                |((step_index, (frozen_claim_id, step_lineage_id)), heads)| {
                    let pending_resolution = heads.len() > 1;
                    ResolvedStep {
                        step_index,
                        frozen_claim_id,
                        step_lineage_id,
                        heads,
                        pending_resolution,
                    }
                },
            )
            .collect();
        Ok(resolved)
    }

    /// Batched variant of [`resolve_steps_to_heads`] — resolves all workflows
    /// in a single pair of round-trips (one seed query + one head query)
    /// instead of O(N × M) calls.
    ///
    /// Returns a `HashMap` keyed by workflow_id. Each value is the same
    /// `Vec<ResolvedStep>` that `resolve_steps_to_heads` would return for
    /// that workflow. Workflows with no steps map to an empty Vec; workflows
    /// not in the input do not appear in the result.
    ///
    /// # Errors
    /// Returns `DbError` if either database query fails.
    pub async fn resolve_steps_to_heads_batched(
        pool: &PgPool,
        workflow_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<ResolvedStep>>, DbError> {
        // Short-circuit: nothing to do.
        if workflow_ids.is_empty() {
            return Ok(HashMap::new());
        }

        // ── Round-trip 1: fetch all step seeds (level=2) for all workflow IDs. ──
        // Order matches the single-workflow function: (e.created_at ASC, c.id ASC).
        #[derive(sqlx::FromRow)]
        struct StepSeedRow {
            workflow_id: Uuid,
            frozen_claim_id: Uuid,
            step_lineage_id: Option<Uuid>,
        }

        let seed_rows: Vec<StepSeedRow> = sqlx::query_as(
            "SELECT \
               e.source_id AS workflow_id, \
               c.id        AS frozen_claim_id, \
               c.step_lineage_id \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = ANY($1) \
               AND e.relationship = 'executes' \
               AND (c.properties->>'level')::int = 2 \
             ORDER BY e.source_id, e.created_at ASC, c.id ASC",
        )
        .bind(workflow_ids)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        // Initialise the result map with an empty Vec for every requested workflow
        // so callers get a deterministic entry even for step-less workflows.
        let mut result: HashMap<Uuid, Vec<ResolvedStep>> =
            workflow_ids.iter().map(|id| (*id, Vec::new())).collect();

        if seed_rows.is_empty() {
            return Ok(result);
        }

        // Build per-workflow step lists and collect the set of lineage_ids to query.
        // Preserve ordering: seeds are already in (workflow_id, e.created_at, c.id) order.
        // We need per-workflow sequential step_index, so we track a counter per workflow.
        let mut step_index_counter: HashMap<Uuid, usize> = HashMap::new();

        // Intermediate structure before heads are filled in.
        struct PartialStep {
            step_index: usize,
            frozen_claim_id: Uuid,
            step_lineage_id: Option<Uuid>,
        }

        let mut partial_by_workflow: HashMap<Uuid, Vec<PartialStep>> = HashMap::new();
        let mut all_lineage_ids: Vec<Uuid> = Vec::new();

        for row in seed_rows {
            let idx = step_index_counter.entry(row.workflow_id).or_insert(0);
            let step_index = *idx;
            *idx += 1;

            if let Some(lid) = row.step_lineage_id {
                all_lineage_ids.push(lid);
            }

            partial_by_workflow
                .entry(row.workflow_id)
                .or_default()
                .push(PartialStep {
                    step_index,
                    frozen_claim_id: row.frozen_claim_id,
                    step_lineage_id: row.step_lineage_id,
                });
        }

        // ── Round-trip 2: fetch all heads for all non-null lineage_ids at once. ──
        // Mirrors `latest_in_lineage`: claims with step_lineage_id in the set
        // and no incoming `supersedes` edge.  ORDER BY c.created_at DESC (same
        // as the single-lineage function).
        let mut heads_by_lineage: HashMap<Uuid, Vec<LineageHead>> = HashMap::new();

        if !all_lineage_ids.is_empty() {
            #[derive(sqlx::FromRow)]
            struct HeadRow {
                lineage_id: Uuid,
                id: Uuid,
                content: String,
                truth_value: f64,
                created_at: chrono::DateTime<chrono::Utc>,
            }

            let head_rows: Vec<HeadRow> = sqlx::query_as(
                "SELECT c.step_lineage_id AS lineage_id, c.id, c.content, c.truth_value, c.created_at \
                 FROM claims c \
                 WHERE c.step_lineage_id = ANY($1) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM edges e \
                       WHERE e.target_id = c.id \
                         AND e.relationship = 'supersedes' \
                   ) \
                 ORDER BY c.step_lineage_id, c.created_at DESC",
            )
            .bind(&all_lineage_ids)
            .fetch_all(pool)
            .await
            .map_err(DbError::from)?;

            for row in head_rows {
                heads_by_lineage
                    .entry(row.lineage_id)
                    .or_default()
                    .push(LineageHead {
                        id: row.id,
                        content: row.content,
                        truth_value: row.truth_value,
                        created_at: row.created_at,
                    });
            }
        }

        // ── Regroup into the final HashMap. ──
        for (workflow_id, partials) in partial_by_workflow {
            let steps: Vec<ResolvedStep> = partials
                .into_iter()
                .map(|p| {
                    let heads: Vec<LineageHead> = p
                        .step_lineage_id
                        .and_then(|lid| heads_by_lineage.get(&lid).cloned())
                        .unwrap_or_default();
                    let pending_resolution = heads.len() > 1;
                    ResolvedStep {
                        step_index: p.step_index,
                        frozen_claim_id: p.frozen_claim_id,
                        step_lineage_id: p.step_lineage_id,
                        heads,
                        pending_resolution,
                    }
                })
                .collect();
            result.insert(workflow_id, steps);
        }

        Ok(result)
    }

    /// Search hierarchical workflows by free-text query against `goal` and
    /// `canonical_name`. ILIKE pattern; canonical_name hyphens are normalized
    /// to spaces before matching so queries like "scan norcal rfps" still
    /// match the slug `scan-norcal-rfps` when a generation's `goal` text has
    /// diverged from the lineage's canonical phrase.
    ///
    /// Filters out rows with `truth_value < min_truth` so `deprecate_workflow`
    /// (truth=0.05) hides rows from active queries.
    ///
    /// When `resolve_to_latest` is true, callers want the newest generation
    /// per `canonical_name`; ordering becomes `(canonical_name ASC,
    /// generation DESC, created_at DESC)` so callers can dedup by walking
    /// the head of each canonical group without a sort.
    ///
    /// Used by `GET /api/v1/workflows/hierarchical/search` and the MCP
    /// `find_workflow_hierarchical` tool.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn search_hierarchical_by_text(
        pool: &PgPool,
        query: &str,
        limit: i64,
        min_truth: f64,
        resolve_to_latest: bool,
    ) -> Result<Vec<HierarchicalWorkflowRow>, sqlx::Error> {
        // Normalize hyphens to spaces on BOTH sides so `deploy-canary`
        // (slug form) and `deploy canary` (goal-text form) match each
        // other. Without this, callers that send a goal-shaped query
        // string (spaces) miss generations whose goals have diverged from
        // the lineage's canonical phrase — only the slug carries the
        // shared lineage signal. Likewise, a caller that sends the slug
        // verbatim should still match a goal that wrote out the words.
        let pattern = format!("%{}%", query.trim().replace('-', " "));
        let order_clause = if resolve_to_latest {
            "ORDER BY canonical_name ASC, generation DESC, created_at DESC, id ASC"
        } else {
            "ORDER BY created_at DESC, id ASC"
        };
        let sql = format!(
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value \
             FROM workflows \
             WHERE (replace(canonical_name, '-', ' ') || ' ' || replace(goal, '-', ' ')) ILIKE $1 \
               AND truth_value >= $2 \
             {order_clause} \
             LIMIT $3"
        );
        sqlx::query_as::<_, HierarchicalWorkflowRow>(&sql)
            .bind(&pattern)
            .bind(min_truth)
            .bind(limit)
            .fetch_all(pool)
            .await
    }

    /// Cosine-similarity search over `workflows.goal_embedding`.
    ///
    /// Mirrors `find_by_embedding` (flat) but reads the hierarchical
    /// `workflows` table. Rows without an embedding are skipped — caller
    /// should fall back to `search_hierarchical_by_text` for those.
    ///
    /// `similarity_threshold` filters by `(1 - cosine_distance) >=
    /// threshold`. `min_truth` filters out deprecated rows
    /// (`deprecate_workflow` writes 0.05). When `resolve_to_latest` is
    /// true, ordering is `(canonical_name ASC, generation DESC,
    /// distance ASC)` so heads-of-lineage surface first; otherwise
    /// `distance ASC, created_at DESC`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn find_hierarchical_by_embedding(
        pool: &PgPool,
        query_embedding: &[f32],
        similarity_threshold: f64,
        min_truth: f64,
        limit: i64,
        resolve_to_latest: bool,
    ) -> Result<Vec<HierarchicalWorkflowRow>, sqlx::Error> {
        let vec_str = format!(
            "[{}]",
            query_embedding
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        // For embedding-based search, semantic distance is the primary signal —
        // sorting by canonical_name first (as the ILIKE path does for heads-walk
        // dedup) would defeat that. Always sort by distance first; when
        // resolve_to_latest is requested, prefer higher generation as a
        // tiebreaker so newer variants of an equally-close lineage surface
        // first.
        let order_clause = if resolve_to_latest {
            "ORDER BY distance ASC, generation DESC, created_at DESC"
        } else {
            "ORDER BY distance ASC, created_at DESC, id ASC"
        };
        let sql = format!(
            "WITH q AS (SELECT $1::vector AS v) \
             SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value, \
                    (w.goal_embedding <=> q.v) AS distance \
             FROM workflows w, q \
             WHERE w.goal_embedding IS NOT NULL \
               AND w.truth_value >= $3 \
               AND (1 - (w.goal_embedding <=> q.v)) >= $2 \
             {order_clause} \
             LIMIT $4"
        );
        // The SELECT adds a `distance` column for ordering but it's not part of
        // HierarchicalWorkflowRow — wrap in an outer SELECT that drops it.
        let outer_sql = format!(
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value \
             FROM ({sql}) inner_q"
        );
        sqlx::query_as::<_, HierarchicalWorkflowRow>(&outer_sql)
            .bind(&vec_str)
            .bind(similarity_threshold)
            .bind(min_truth)
            .bind(limit)
            .fetch_all(pool)
            .await
    }

    /// Write the embedding vector for a hierarchical workflow's goal text.
    /// Idempotent: caller is expected to skip rows where `goal_embedding`
    /// is already set unless explicitly re-embedding.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn set_goal_embedding(
        pool: &PgPool,
        workflow_id: Uuid,
        embedding: &[f32],
    ) -> Result<u64, sqlx::Error> {
        let vec_str = format!(
            "[{}]",
            embedding
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let r = sqlx::query("UPDATE workflows SET goal_embedding = $1::vector WHERE id = $2")
            .bind(&vec_str)
            .bind(workflow_id)
            .execute(pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// Set `workflows.truth_value` for the given workflow id. Used by
    /// `deprecate_workflow` to cascade truth=0.05 from the flat-claim row
    /// onto the hierarchical-table row so `find_workflow_hierarchical`
    /// respects the deprecation signal.
    ///
    /// Returns the number of rows affected (0 if `workflow_id` is a
    /// flat-only workflow with no `workflows` row).
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn set_truth_value(
        pool: &PgPool,
        workflow_id: Uuid,
        truth_value: f64,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("UPDATE workflows SET truth_value = $1 WHERE id = $2")
            .bind(truth_value)
            .bind(workflow_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn insert_root_creates_workflows_row(pool: sqlx::PgPool) {
        let id = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            id,
            "deploy-canary",
            0,
            "Deploy a canary release safely.",
            None,
            serde_json::json!({"tags": ["deploy"]}),
        )
        .await
        .unwrap();

        let row: (String, i32, String, serde_json::Value) = sqlx::query_as(
            "SELECT canonical_name, generation, goal, metadata FROM workflows WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "deploy-canary");
        assert_eq!(row.1, 0);
        assert_eq!(row.2, "Deploy a canary release safely.");
        assert_eq!(row.3["tags"][0], "deploy");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn insert_root_is_idempotent_on_canonical_generation(pool: sqlx::PgPool) {
        let id1 = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            id1,
            "idempo-test",
            0,
            "first goal",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        // Second insert with a different id but same (canonical_name, generation) is a no-op.
        let id2 = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            id2,
            "idempo-test",
            0,
            "different goal text",
            None,
            serde_json::json!({"foo": "bar"}),
        )
        .await
        .unwrap();

        // Original row preserved; the second insert was silently dropped.
        let found = WorkflowRepository::find_root_by_canonical(&pool, "idempo-test", 0)
            .await
            .unwrap();
        assert_eq!(found, Some(id1));

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workflows WHERE canonical_name = 'idempo-test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn max_generation_by_canonical_returns_highest(pool: sqlx::PgPool) {
        // Insert two generations of the same canonical_name.
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "max-gen-test",
            1,
            "first",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "max-gen-test",
            3,
            "third",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let max = WorkflowRepository::max_generation_by_canonical(&pool, "max-gen-test")
            .await
            .unwrap();
        assert_eq!(max, Some(3));

        // Missing canonical_name returns None.
        let missing =
            WorkflowRepository::max_generation_by_canonical(&pool, "does-not-exist-at-all")
                .await
                .unwrap();
        assert_eq!(missing, None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn search_hierarchical_by_text_returns_matches(pool: sqlx::PgPool) {
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "data-pipeline-v1",
            0,
            "Process incoming sensor data and write to warehouse.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        WorkflowRepository::insert_root(
            &pool,
            uuid::Uuid::new_v4(),
            "deploy-canary",
            0,
            "Deploy a canary release safely.",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "sensor", 10, 0.0, false)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canonical_name, "data-pipeline-v1");

        // canonical_name match also works
        let hits =
            WorkflowRepository::search_hierarchical_by_text(&pool, "deploy-canary", 10, 0.0, false)
                .await
                .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canonical_name, "deploy-canary");

        // limit respected
        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "%", 1, 0.0, false)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
    }
}
