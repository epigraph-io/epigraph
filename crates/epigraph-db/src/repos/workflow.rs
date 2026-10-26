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

/// One hit from [`WorkflowRepository::search_by_goal_embedding`] — the ANN
/// leg `recall()` RRF-merges with its claims dense+lexical leg.
///
/// `similarity` is `1 - cosine_distance` in `[0, 1]`, matching the convention
/// used by `ClaimEmbeddingHit`/`HybridHit.dense_similarity`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct WorkflowGoalEmbeddingHit {
    pub workflow_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub similarity: f64,
    /// The workflow's own `workflows.created_at`. Carried so `recall`'s
    /// merged results array can report a REAL creation time for a
    /// workflow-origin hit instead of inventing one: a workflow is not a
    /// claim, so it has no `claims.created_at`, and filling the gap with
    /// `Utc::now()` would make every workflow the newest thing in the corpus
    /// — fabricated provenance in a graph whose purpose is provenance.
    ///
    /// Compatibility note: this is an additive REQUIRED field on a public
    /// struct, which breaks any exhaustive struct literal or pattern match
    /// outside this workspace. Judged acceptable because the struct is a
    /// query RESULT row (`sqlx::FromRow`), never constructed by hand —
    /// `grep -rn "WorkflowGoalEmbeddingHit {"` finds only this definition —
    /// and there is no wrapper form for a field the way there is for a
    /// function arity. Recorded as a decision, not an oversight.
    pub created_at: chrono::DateTime<chrono::Utc>,
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

/// A [`HierarchicalWorkflowRow`] carrying the cosine similarity that retrieved
/// it, so a caller can rank hierarchical hits against hits from another store
/// on one comparable scale.
///
/// Exists because the two existing embedding searches over
/// `workflows.goal_embedding` each drop half of what a cross-store ranker
/// needs: `find_hierarchical_by_embedding` returns the full row but discards
/// the distance column, and `search_by_goal_embedding` returns a similarity but
/// only `(id, goal, truth_value)`. Merging flat workflow CLAIMS with
/// hierarchical workflow ROWS in `find_workflow` needs both at once.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScoredHierarchicalWorkflowRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub truth_value: f64,
    /// `1 - cosine_distance` against the query embedding.
    pub similarity: f64,
}

/// What [`WorkflowRepository::ingest_anchors`] found; see its doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IngestAnchors {
    /// The exact `(canonical_name, generation)` row, if it already exists.
    pub existing: Option<Uuid>,
    /// The latest generation already stored under `canonical_name`.
    pub lineage_head: Option<Uuid>,
    /// The row the executor will link as `parent_id`, if any.
    pub linked_parent: Option<Uuid>,
}

/// An `executes` edge's `plan_index` as a `bigint`, or NULL unless it is a
/// JSON integer of at most nine digits. A `CASE`, not a `WHERE` guard plus a
/// cast: PostgreSQL does not promise to evaluate a guard before the cast.
const PLAN_INDEX_INT: &str = "(CASE WHEN jsonb_typeof(properties->'plan_index') = 'number' \
                                    AND properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                               THEN (properties->>'plan_index')::bigint END)";

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
    /// `workflows` is MEASURED `relrowsecurity = false` with no policy at
    /// migration head 101, so this write needs no stamp to be admitted. It takes
    /// an executor anyway so the workflow-ingest plan walk can run it on the SAME
    /// connection as the tier-A `claims` and `edges` writes it is atomic with —
    /// an `insert_root` on a sibling pool checkout would leave a `workflows` row
    /// behind when the claim walk rolled back, which is the zombie-row shape the
    /// executor's own pre-flight content guard exists to avoid.
    pub async fn insert_root<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        .execute(executor)
        .await?;
        Ok(())
    }

    /// The `metadata` key a `workflows` row records its SUBMITTER under (batch
    /// H-b, H3): the agent whose write created the row. Namespaced so it cannot
    /// collide with a caller's own metadata, and stripped from caller-supplied
    /// metadata by every ingest entry point, so it can only be written by
    /// [`Self::record_submitter`].
    pub const SUBMITTER_KEY: &'static str = "epigraph_submitted_by";

    /// The recorded submitter of workflow `id`, if any.
    ///
    /// `None` for a row written before batch H-b (nothing recorded who created
    /// it) and for a variant of such a row, which inherits "no owner" rather
    /// than having one invented for it. `workflows` has no row security
    /// (`relrowsecurity = false`), so this read needs no stamp.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn submitter_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata->>$2 END \
                   FROM workflows WHERE id = $1",
        )
        .bind(id)
        .bind(Self::SUBMITTER_KEY)
        .fetch_optional(executor)
        .await?;
        Ok(row
            .and_then(|(v,)| v)
            .and_then(|v| Uuid::parse_str(&v).ok()))
    }

    /// Record `agent` as the submitter of workflow `id`, ONCE: a row that
    /// already records one keeps it (a re-ingest by another caller must never
    /// take a workflow over). Returns whether it wrote.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the statement fails.
    pub async fn record_submitter<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
        agent: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let done = sqlx::query(
            // `metadata` may hold a JSON `null` (an extraction with no
            // metadata serializes that way), which `jsonb_set` refuses as a
            // scalar: normalise anything that is not an object to `{}`.
            "UPDATE workflows \
                SET metadata = jsonb_set( \
                        CASE WHEN jsonb_typeof(metadata) = 'object' THEN metadata \
                             ELSE '{}'::jsonb END, \
                        ARRAY[$2], to_jsonb($3::text)) \
              WHERE id = $1 \
                AND NOT (jsonb_typeof(metadata) = 'object' AND metadata ? $2)",
        )
        .bind(id)
        .bind(Self::SUBMITTER_KEY)
        .bind(agent.to_string())
        .execute(executor)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The latest-generation workflow row for `canonical_name`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn head_by_canonical<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        canonical_name: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows WHERE canonical_name = $1 ORDER BY generation DESC LIMIT 1",
        )
        .bind(canonical_name)
        .fetch_optional(executor)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// Lock one `workflows` row (`FOR UPDATE`) for the rest of the caller's
    /// transaction. `Ok(false)` when no row has this id.
    ///
    /// `add_step` takes it before it reads the plan it is about to extend, so
    /// two concurrent `add_step`s on one workflow cannot both compute the same
    /// next `plan_index`. `workflows` has no row security, so this needs no
    /// viewer.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn lock_for_plan_edit<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        workflow_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM workflows WHERE id = $1 FOR UPDATE")
                .bind(workflow_id)
                .fetch_optional(executor)
                .await?;
        Ok(row.is_some())
    }

    /// Every LIVE (`valid_to IS NULL`) `executes` edge of `workflow_id` this
    /// session can see, as `(target claim, plan_index, is public)`. The index
    /// is `None` unless the edge's `plan_index` is a JSON integer of at most
    /// nine digits (the bound every plan-order reader's `^[0-9]{1,9}$` uses),
    /// so a string `"3"` or a fraction is unindexed here as it is in the frozen
    /// plan read. A retracted edge is not a plan item for any reader, so it
    /// takes no part in where a new item goes.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn executes_plan_indices<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        workflow_id: Uuid,
    ) -> Result<Vec<(Uuid, Option<i64>, bool)>, sqlx::Error> {
        let sql = format!(
            "SELECT target_id, {PLAN_INDEX_INT}, COALESCE(visibility::text = 'public', false) FROM edges \
              WHERE source_id = $1 AND source_type = 'workflow' \
                AND relationship = 'executes' AND valid_to IS NULL"
        );
        sqlx::query_as(&sql)
            .bind(workflow_id)
            .fetch_all(executor)
            .await
    }

    /// The existing rows an ingest of `(canonical_name, generation)` with
    /// `parent_canonical_name` would touch or link (batch H-b, H3 review):
    ///
    /// * `existing` — the exact `(canonical_name, generation)` row. When it is
    ///   present the ingest is a re-ingest: since the plan walk became one
    ///   transaction a recorded row always has its `executes` edges, so the
    ///   executor short-circuits and writes nothing.
    /// * `lineage_head` — the latest generation already stored under
    ///   `canonical_name`. A NEW generation of a name that already has rows is a
    ///   generation of THAT lineage, whether or not the caller names a parent;
    ///   without this, a caller could ingest `generation + 1` with no parent,
    ///   record itself as submitter and then pass every head-keyed authority
    ///   check (the takeover the review measured).
    /// * `linked_parent` — exactly the row the executor links as `parent_id`
    ///   ([`Self::resolve_ingest_parent`], the SAME function the executor
    ///   calls), so authority is checked against the row actually linked, not a
    ///   different generation of the parent's name.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if a query fails.
    pub async fn ingest_anchors(
        conn: &mut sqlx::PgConnection,
        canonical_name: &str,
        generation: i32,
        parent_canonical_name: Option<&str>,
    ) -> Result<IngestAnchors, sqlx::Error> {
        let existing = Self::find_root_by_canonical(&mut *conn, canonical_name, generation).await?;
        let lineage_head = Self::head_by_canonical(&mut *conn, canonical_name).await?;
        let linked_parent = Self::resolve_ingest_parent(
            &mut *conn,
            canonical_name,
            generation,
            parent_canonical_name,
        )
        .await?;
        Ok(IngestAnchors {
            existing,
            lineage_head,
            linked_parent,
        })
    }

    /// The row an ingest of `(canonical_name, generation)` links as its
    /// `parent_id` (and `variant_of` target). The executor and
    /// [`Self::ingest_anchors`] both call this, so the row whose authority is
    /// checked is exactly the row that gets linked.
    ///
    /// 1. `parent_canonical_name = Some(p)`: `(p, generation - 1)` with the
    ///    same saturating arithmetic as before (issue #51 semantics, forks
    ///    included).
    /// 2. Otherwise — or when (1) finds nothing and `p` names this same
    ///    lineage — the PREDECESSOR: the highest generation of
    ///    `canonical_name` strictly BELOW `generation`. Not the lineage head:
    ///    for a gap-filling ingest (gen 2 while gen 5 exists) the head is above
    ///    the new row and must never become its parent (U032).
    /// 3. `None` when there is no predecessor (a lineage may legitimately
    ///    start above generation 0), or when a DIFFERENT lineage named in `p`
    ///    has no row at `generation - 1`: the named parent links nothing,
    ///    exactly as before, and there is no fallback to `canonical_name`'s own
    ///    predecessor. If `canonical_name` has no rows that ingest starts a new
    ///    lineage; if it already has lower generations, the row is stored
    ///    parentless even though [`Self::ingest_anchors`] treats it as a
    ///    generation of that lineage (authority over `lineage_head`, submitter
    ///    inherited). That residual is the current default pending operator
    ///    question Q2 (U032 scope §6), pinned by
    ///    `workflow_ingest::a_cross_lineage_parent_at_a_missing_generation_links_nothing_pending_q2`.
    ///
    /// `workflows` has no row security, as [`Self::find_root_by_canonical`]
    /// records, so this read needs no viewer.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if a query fails.
    pub async fn resolve_ingest_parent(
        conn: &mut sqlx::PgConnection,
        canonical_name: &str,
        generation: i32,
        parent_canonical_name: Option<&str>,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        if let Some(pcn) = parent_canonical_name {
            let named =
                Self::find_root_by_canonical(&mut *conn, pcn, generation.saturating_sub(1)).await?;
            if named.is_some() || pcn != canonical_name {
                return Ok(named);
            }
        }
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows WHERE canonical_name = $1 AND generation < $2 \
             ORDER BY generation DESC LIMIT 1",
        )
        .bind(canonical_name)
        .bind(generation)
        .fetch_optional(&mut *conn)
        .await?;
        Ok(row.map(|(id,)| id))
    }

    /// The distinct `canonical_name`s of the workflows that EXECUTE `claim_id`
    /// (a visible `workflow —executes→ claim` edge).
    ///
    /// Exists for MCP `verify_claim`: a workflow level-0..2 row marked
    /// `content_hash_scope = "canonical_name"` stores
    /// `compound_content_hash(blake3(content), canonical_name)`, and its seed is
    /// the name of the workflow that wrote it, which links the row by this edge
    /// in the same transaction (the executor's `executes` loop, and
    /// `workflow_steps::add_step`). Returning every executing workflow rather
    /// than one keeps the caller's rule simple — a match against ANY of them is
    /// sound — and an empty result (no edge, or none visible to `viewer`) means
    /// the seed is unrecoverable, which the caller reports as undecided.
    ///
    /// Viewer-scoped on the edge like `resolve_steps_to_heads`; the `workflows`
    /// table carries no visibility columns.
    ///
    /// RETRACTED edges are included ON PURPOSE — there is deliberately no
    /// `e.valid_to IS NULL` filter here, unlike the house-style edge read. The
    /// seed is a fact about who WROTE the row, and a soft retraction
    /// (`EdgeRepository::retract`, MCP `delete_edge`) does not change that.
    /// Filtering retracted edges would let anyone who can retract the
    /// `executes` edge downgrade a tampered row from `mismatch` to
    /// `not_applicable`. Including them is sound, because a match still needs a
    /// blake3 preimage of the stored digest. Pinned by
    /// `store_workflow_hash_scope::retracting_the_executes_edge_does_not_mask_tampering`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn executing_canonical_names(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<String>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT w.canonical_name \
             FROM edges e \
             JOIN workflows w ON w.id = e.source_id \
             WHERE e.target_id = $1 AND e.relationship = 'executes' \
               AND e.source_type = 'workflow' AND e.target_type = 'claim' \
               /* {EDGE_VISIBILITY:e} */ \
             ORDER BY w.canonical_name",
            2,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(pool).await.map_err(DbError::from)
    }

    /// The ids of every workflow that EXECUTES the step lineage of `claim_id`:
    /// a `workflow —executes→ claim` edge into `claim_id` itself or into any
    /// claim sharing its non-null `step_lineage_id`. Ascending by id.
    ///
    /// Exists for the `evolve_step` authority gate (MCP
    /// `tools/evolve_step.rs`, REST `routes/workflows.rs::evolve_step`), which
    /// requires workflow authority over EVERY workflow returned. The lineage is
    /// read, not just the parent's own edges, because `executes` stays on the
    /// frozen step when it is evolved (`migrate_superseded_edges`' step-lineage
    /// rule): the new head is executed by nothing directly, and a gate keyed on
    /// the parent's edges would admit anyone to the second evolve. A parent
    /// with no lineage yet (`evolve_step` mints one for it) is its own lineage.
    ///
    /// RETRACTED edges are included ON PURPOSE, as in
    /// [`Self::executing_canonical_names`]. Any principal that writes the
    /// owning group of a group-private `executes` edge can retract it
    /// (`EdgeRepository::retract_by_id`), so filtering on `valid_to` would let
    /// that writer lift the gate it is held to. Edge `properties` (e.g.
    /// `plan_index`, which the same writers can rewrite) play no part.
    ///
    /// NOT viewer-spliced, deliberately: this is an authority read, and an
    /// in-query viewer predicate could only remove workflows from the set the
    /// caller must hold authority over. It runs on the caller's own write
    /// transaction, so the one filter left is the row security that session is
    /// held to. Residual, stated: a lineage member or `executes` edge that
    /// row security hides from the caller is not counted. Every claim of a
    /// lineage takes its parent's tenancy at `evolve_step`, and an `executes`
    /// edge takes its step's, so a caller who can lock the parent can normally
    /// see them all; a lineage whose members were later split across tenancies
    /// out of band is the case this does not cover.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn workflows_executing_step_lineage(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT DISTINCT w.id \
             FROM edges e \
             JOIN workflows w ON w.id = e.source_id \
             WHERE e.relationship = 'executes' \
               AND e.source_type = 'workflow' AND e.target_type = 'claim' \
               AND (e.target_id = $1 \
                    OR e.target_id IN ( \
                        SELECT m.id FROM claims m \
                        JOIN claims p ON p.step_lineage_id = m.step_lineage_id \
                        WHERE p.id = $1)) \
             ORDER BY w.id",
        )
        .bind(claim_id)
        .fetch_all(&mut *conn)
        .await
    }

    /// Look up a workflow root by `(canonical_name, generation)`.
    pub async fn find_root_by_canonical<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        canonical_name: &str,
        generation: i32,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM workflows WHERE canonical_name = $1 AND generation = $2",
        )
        .bind(canonical_name)
        .bind(generation)
        .fetch_optional(executor)
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
    pub async fn find_by_embedding<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
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

        // `find_workflow`'s semantic path lands here. Workflow steps ARE
        // claims, so an unfiltered read returns another tenant's playbook text
        // verbatim. Four aliases across the CTE and the two correlated
        // subqueries; `e2` is a projection subquery, so its marker keeps a
        // parent id from leaking through an edge the viewer cannot read.
        let sql = viewer.splice(
            "WITH query_vec AS (SELECT $1::vector AS vec), \
             base AS ( \
                 SELECT c.id, c.content, c.truth_value, c.properties, \
                        1 - (c.embedding <=> q.vec) AS similarity, \
                        COALESCE(( \
                            SELECT COUNT(*) FROM edges e \
                            WHERE (e.source_id = c.id OR e.target_id = c.id) \
                              /* {EDGE_VISIBILITY:e} */ \
                        ), 0) AS edge_count \
                 FROM claims c, query_vec q \
                 WHERE c.embedding IS NOT NULL AND vector_norm(c.embedding) > 0 \
                   AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   AND 'workflow' = ANY(c.labels) \
                   /* {VISIBILITY:c} */ \
             ) \
             SELECT b.id, b.content, b.truth_value, b.similarity, b.edge_count, b.properties, \
                    b.similarity * 0.6 + b.truth_value * 0.2 + LEAST(b.edge_count::float / 10.0, 1.0) * 0.2 AS hybrid_score, \
                    (SELECT e2.source_id::text FROM edges e2 \
                     WHERE e2.target_id = b.id AND e2.relationship IN ('variant_of', 'supersedes') \
                       /* {EDGE_VISIBILITY:e2} */ LIMIT 1) AS parent_id \
             FROM base b \
             ORDER BY hybrid_score DESC \
             LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, WorkflowRecallRow>(&sql)
            .bind(&vec_str)
            .bind(min_truth)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<WorkflowRecallRow> = q.fetch_all(executor).await?;

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
    pub async fn find_by_text<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        query: &str,
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<WorkflowRecallResult>, sqlx::Error> {
        let pattern = format!("%{query}%");

        let sql = viewer.splice(
            "WITH base AS ( \
                 SELECT c.id, c.content, c.truth_value, c.properties, \
                        0.0::float8 AS similarity, \
                        COALESCE(( \
                            SELECT COUNT(*) FROM edges e \
                            WHERE (e.source_id = c.id OR e.target_id = c.id) \
                              /* {EDGE_VISIBILITY:e} */ \
                        ), 0) AS edge_count \
                 FROM claims c \
                 WHERE c.content ILIKE $1 AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   AND 'workflow' = ANY(c.labels) \
                   /* {VISIBILITY:c} */ \
             ) \
             SELECT b.id, b.content, b.truth_value, b.similarity, b.edge_count, b.properties, \
                    b.truth_value * 0.5 + LEAST(b.edge_count::float / 10.0, 1.0) * 0.5 AS hybrid_score, \
                    (SELECT e2.source_id::text FROM edges e2 \
                     WHERE e2.target_id = b.id AND e2.relationship IN ('variant_of', 'supersedes') \
                       /* {EDGE_VISIBILITY:e2} */ LIMIT 1) AS parent_id \
             FROM base b \
             ORDER BY hybrid_score DESC \
             LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, WorkflowRecallRow>(&sql)
            .bind(&pattern)
            .bind(min_truth)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<WorkflowRecallRow> = q.fetch_all(executor).await?;

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
    ///
    /// Generic over the executor so `routes/workflows.rs::list_workflows` and
    /// `routes/conventions.rs::list_skills` can each run it on the stamped
    /// connection [`crate::ScopedPool::read_as`] hands their handler. The two
    /// `fetch_all` calls below sit in MUTUALLY EXCLUSIVE branches, so a
    /// by-value `E` is consumed at most once and the bound does not have to be
    /// `&mut PgConnection`. The statement, its binds and its row shape are
    /// unchanged by the widening; it already took a `&Viewer` and already
    /// carried `/* {VISIBILITY:c} */`.
    pub async fn list<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        min_truth: f64,
        category: Option<&str>,
        limit: i64,
    ) -> Result<Vec<WorkflowListRow>, sqlx::Error> {
        if let Some(cat) = category {
            let sql = viewer.splice(
                "SELECT c.id, c.content, c.truth_value, c.labels, c.properties \
                 FROM claims c \
                 WHERE 'workflow' = ANY(c.labels) \
                   AND $1 = ANY(c.labels) \
                   AND c.truth_value >= $2 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   /* {VISIBILITY:c} */ \
                 ORDER BY c.truth_value DESC \
                 LIMIT $3",
                4,
            );
            let mut q = sqlx::query_as::<_, WorkflowListRow>(&sql)
                .bind(cat)
                .bind(min_truth)
                .bind(limit);
            if let Some(g) = viewer.group_bind() {
                q = q.bind(g);
            }
            q.fetch_all(executor).await
        } else {
            let sql = viewer.splice(
                "SELECT c.id, c.content, c.truth_value, c.labels, c.properties \
                 FROM claims c \
                 WHERE 'workflow' = ANY(c.labels) \
                   AND c.truth_value >= $1 \
                   AND (c.is_current IS NULL OR c.is_current = true) \
                   /* {VISIBILITY:c} */ \
                 ORDER BY c.truth_value DESC \
                 LIMIT $2",
                3,
            );
            let mut q = sqlx::query_as::<_, WorkflowListRow>(&sql)
                .bind(min_truth)
                .bind(limit);
            if let Some(g) = viewer.group_bind() {
                q = q.bind(g);
            }
            q.fetch_all(executor).await
        }
    }

    /// Find all descendants of a workflow via `variant_of` or `supersedes` edges
    /// (for cascade deprecation).
    pub async fn find_descendants<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        // RECURSIVE: anchor AND recursive term both filtered.
        let sql = viewer.splice(
            "WITH RECURSIVE descendants AS ( \
                 SELECT source_id AS id FROM edges \
                 WHERE target_id = $1 AND relationship IN ('variant_of', 'supersedes') \
                   /* {EDGE_VISIBILITY:edges} */ \
                 UNION ALL \
                 SELECT e.source_id FROM edges e \
                 JOIN descendants d ON e.target_id = d.id \
                 WHERE e.relationship IN ('variant_of', 'supersedes') \
                   /* {EDGE_VISIBILITY:e} */ \
             ) \
             SELECT id FROM descendants",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid,)> = q.fetch_all(executor).await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Walk up `variant_of` or `supersedes` edges to find the lineage root ancestor.
    ///
    /// Returns `workflow_id` itself if it has no parent (is already a root).
    /// The root is the ancestor with no outgoing `variant_of` or `supersedes` edge.
    pub async fn find_lineage_root<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Uuid, sqlx::Error> {
        // Only the RECURSIVE term is marked. The `NOT EXISTS` is an EXCLUSION
        // test: filtering it would let an invisible parent edge stop excluding
        // its child, so a non-root would be reported as the root.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT $1::uuid AS id
                UNION ALL
                SELECT e.target_id AS id
                FROM ancestors a
                JOIN edges e ON e.source_id = a.id
                    AND e.relationship IN ('variant_of', 'supersedes')
                    AND e.source_type = 'claim' AND e.target_type = 'claim'
                WHERE true /* {EDGE_VISIBILITY:e} */
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
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let root: Option<(Uuid,)> = q.fetch_optional(executor).await?;

        Ok(root.map(|(id,)| id).unwrap_or(workflow_id))
    }

    /// The immediate parent of a workflow variant: the `target` of its outgoing
    /// `variant_of`/`supersedes` edge (the workflow this one was derived from).
    /// Returns `None` for a lineage root (no such outgoing edge). One hop only —
    /// unlike [`find_lineage_root`], which walks to the ancestral root. Matches
    /// that method's relationship set and claim→claim typing.
    ///
    /// The promotion gate compares a variant against its immediate parent; this
    /// resolves which workflow that is.
    pub async fn immediate_variant_parent<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let sql = viewer.splice(
            r#"
            SELECT e.target_id
            FROM edges e
            WHERE e.source_id = $1
              AND e.relationship IN ('variant_of', 'supersedes')
              AND e.source_type = 'claim' AND e.target_type = 'claim'
              /* {EDGE_VISIBILITY:e} */
            LIMIT 1
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let parent: Option<(Uuid,)> = q.fetch_optional(executor).await?;

        Ok(parent.map(|(id,)| id))
    }

    /// For each `executes`-edge from the workflow root, walk supersedes/revises
    /// edges to the latest head claim. Mirrors the resolution logic that
    /// previously lived in `epigraph-mcp::tools::workflow_hierarchical::build_resolved_steps`.
    ///
    /// # Errors
    /// Returns `DbError` if the database query fails.
    pub async fn resolve_steps_to_heads(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Vec<ResolvedStep>, DbError> {
        // Pull all level=2 step claims under this workflow with their
        // step_lineage_id, in PLAN ORDER.
        //
        // The order key is the `plan_index` ordinal that
        // `epigraph_ingest_executor::execute_workflow_ingest_plan` records on the
        // `executes` edge, NOT `e.created_at`. Those edges are now written inside
        // ONE transaction, and `NOW()` is transaction-start time in PostgreSQL, so
        // they all share a `created_at` and the old `created_at, c.id` key returned
        // an arbitrary order. See that loop's comment for the measurement.
        // `created_at` remains the fallback so edges written before the ordinal
        // existed are ordered exactly as they were.
        let sql = viewer.splice(
            "SELECT c.id, c.step_lineage_id \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = $1 AND e.relationship = 'executes' AND (c.properties->>'level')::int = 2 \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */ \
             ORDER BY CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                           THEN (e.properties->>'plan_index')::int \
                           ELSE 2147483647 END, \
                      e.created_at ASC, c.id ASC",
            2,
        );
        let mut sq = sqlx::query_as::<_, (Uuid, Option<Uuid>)>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            sq = sq.bind(g);
        }
        let step_rows: Vec<(Uuid, Option<Uuid>)> =
            sq.fetch_all(pool).await.map_err(DbError::from)?;

        let head_futures = step_rows.iter().map(|(_, step_lineage_id)| async move {
            if let Some(lineage_id) = *step_lineage_id {
                ClaimRepository::latest_in_lineage(pool, viewer, lineage_id).await
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

    /// The workflow's level-2 step claims whose PLAN POSITION `viewer` can
    /// establish, in plan order: the lookup an outcome report maps each
    /// `step_index` through, shared by the MCP tool and the HTTP route so step
    /// N is one step on both transports. Element N is step N; a step whose
    /// position the viewer cannot establish is not listed, and neither is any
    /// step after it.
    ///
    /// Same order key as [`Self::resolve_steps_to_heads`] (`plan_index` first,
    /// `created_at` only for edges that carry none), and the same two
    /// predicates, on the edge and on the claim.
    ///
    /// # Run it on the caller's STAMPED transaction
    ///
    /// `conn` must be stamped with `viewer`. On an unstamped application
    /// session row security admits only public rows, so a group's own member
    /// would get none of its group-private steps back, without an error.
    ///
    /// # Only a provable prefix is returned
    ///
    /// A step the viewer cannot read is absent from what it reads, so counting
    /// the visible steps would shift every visible step after a hidden one
    /// onto the hidden one's index, and an outcome row would be attributed to
    /// the WRONG step with no signal. That is reachable: `add_step` declares
    /// its step public (`ClaimRepository::default_decl_for_author` of the
    /// system agent) and its `executes` edge carries no `plan_index`, so a
    /// group-private plan can end in a public step that a non-member sees
    /// alone. So the list stops where the viewer can no longer prove a step's
    /// position (`provable_plan_steps`):
    ///
    /// * The ingest executor numbers EVERY plan claim's `executes` edge
    ///   `0..n` (`plan_index`, phases included, so `plan_index` is not the step
    ///   index). A gap in the ordinals the viewer reads means an edge it
    ///   cannot see; nothing from the gap on is listed.
    /// * Edges with no ordinal (written by `add_step`, or before the ordinal
    ///   existed) sort after every ordinal one. They are listed only when the
    ///   viewer reads the plan they follow: at least one ordinal edge, or (a
    ///   plan written before the ordinal) a level-1 phase edge.
    ///
    /// A step that is not listed is reported by the callers like an
    /// out-of-range index (NULL `step_claim_id`, disclosed as unresolved). The
    /// two are deliberately indistinguishable: the difference is the existence
    /// of a step the caller cannot see. Residual, not detectable without a
    /// privileged read: hidden ordinal edges AFTER every visible one, followed
    /// by visible unordered steps. One ingest writes a plan's ordinal edges
    /// under one owner, so it needs a later re-ownership of part of a plan.
    ///
    /// # Errors
    /// Returns `DbError` if the query fails.
    pub async fn plan_step_claim_ids(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Vec<Uuid>, DbError> {
        // Every level, not only steps: the phases' ordinals are part of the
        // sequence a gap is detected in.
        let sql = viewer.splice(
            "SELECT c.id, c.properties->>'level', \
                    CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                         THEN (e.properties->>'plan_index')::int END \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = $1 AND e.relationship = 'executes' \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */ \
             ORDER BY CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                           THEN (e.properties->>'plan_index')::int \
                           ELSE 2147483647 END, \
                      e.created_at ASC, c.id ASC",
            2,
        );
        let mut q =
            sqlx::query_as::<_, (Uuid, Option<String>, Option<i32>)>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid, Option<String>, Option<i32>)> = q.fetch_all(&mut *conn).await?;
        Ok(provable_plan_steps(&rows))
    }

    /// Whether `viewer` reads at least one of `workflow_id`'s `executes`
    /// edges (any level: thesis, phase, step or operation), through the same
    /// edge and claim predicates as [`Self::plan_step_claim_ids`].
    ///
    /// This is the outcome reports' authority predicate. `workflows` has no
    /// row security, so a report's counter write cannot be scoped by the
    /// database; the plan's claims and edges can. The ingest executor gives
    /// every plan claim an `executes` edge, so a caller that reads none of
    /// them cannot read the workflow at all, and the reports answer it as
    /// for an id that does not exist. It deliberately does NOT require a
    /// resolvable step prefix: a member whose first ordinal edge was
    /// re-owned still reads the rest of the plan and may report.
    ///
    /// Run it on the caller's STAMPED transaction, as
    /// [`Self::plan_step_claim_ids`] must be.
    ///
    /// # Errors
    /// Returns `DbError` if the query fails.
    pub async fn viewer_reads_any_executes_edge(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice(
            "SELECT EXISTS ( \
               SELECT 1 FROM edges e \
               JOIN claims c ON c.id = e.target_id \
               WHERE e.source_id = $1 AND e.relationship = 'executes' \
                 /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */ \
             )",
            2,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(&mut *conn).await?)
    }

    /// Resolve `(canonical_name, step_index)` to a single step claim UUID for the
    /// name+index addressing mode of `evolve_step` / `update_with_evidence`
    /// (issue #352). Targets the **latest generation** of the named workflow and
    /// the same `executes`-edge ordering as [`resolve_steps_to_heads`], so the
    /// three step-facing tools address steps identically to
    /// `report_hierarchical_outcome`.
    ///
    /// With `prefer_head = true` returns the current head of the step's lineage
    /// (what `evolve_step` should branch from and where fresh evidence should
    /// land), falling back to the frozen original when the lineage is empty or
    /// legacy; with `prefer_head = false` returns the frozen original step claim.
    /// Returns `Ok(None)` when the workflow name is unknown or `step_index` is
    /// out of range.
    ///
    /// "Current head" means a head with `is_current` (newest first): a head
    /// is structural (no incoming `supersedes` edge), so a claim retired
    /// without one is still listed as a head, and superseding it is refused
    /// by `evolve_step_conn` with an opaque guard error (bridge 00132b1d).
    /// When the lineage has heads and NONE is current, this refuses with
    /// [`DbError::InvalidData`] naming the retired head, rather than handing
    /// back a claim the caller cannot evolve or should not attach evidence to.
    ///
    /// # Errors
    /// Returns `DbError` if a database query fails, and
    /// `DbError::InvalidData` when every head of the step's lineage is retired.
    pub async fn resolve_step_claim(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        canonical_name: &str,
        step_index: usize,
        prefer_head: bool,
    ) -> Result<Option<Uuid>, DbError> {
        let Some(max_gen) = Self::max_generation_by_canonical(pool, canonical_name)
            .await
            .map_err(DbError::from)?
        else {
            return Ok(None);
        };
        let Some(workflow_id) = Self::find_root_by_canonical(pool, canonical_name, max_gen)
            .await
            .map_err(DbError::from)?
        else {
            return Ok(None);
        };
        let steps = Self::resolve_steps_to_heads(pool, viewer, workflow_id).await?;
        let Some(step) = steps.into_iter().nth(step_index) else {
            return Ok(None);
        };
        let target = if prefer_head {
            let current = step.heads.iter().find(|h| h.is_current);
            if let (None, Some(retired)) = (current, step.heads.first()) {
                let reason = format!(
                    "step {step_index} of workflow '{canonical_name}': its lineage head {} is \
                     retired (is_current=false, with no supersedes edge), so it cannot be \
                     evolved or take evidence; revive or re-ingest the step first",
                    retired.id
                );
                return Err(DbError::InvalidData { reason });
            }
            current.map_or(step.frozen_claim_id, |h| h.id)
        } else {
            step.frozen_claim_id
        };
        Ok(Some(target))
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
    ///
    /// # Why `&mut PgConnection` and not `E: PgExecutor`
    ///
    /// The two round-trips below are SEQUENTIAL, not exclusive branches: the
    /// second is built from the first's rows. A by-value `E: PgExecutor<'e>` is
    /// consumed by the first `fetch_all`, so that bound does not compile here —
    /// and reborrowing a connection is what lets both statements run under the
    /// ONE tenancy stamp `routes/workflows.rs::find_workflow_hierarchical`
    /// acquires. It already took a `&Viewer` and already spliced it into both
    /// statements; the SQL, the binds and the row shapes are unchanged.
    pub async fn resolve_steps_to_heads_batched(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        workflow_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<ResolvedStep>>, DbError> {
        // Short-circuit: nothing to do.
        if workflow_ids.is_empty() {
            return Ok(HashMap::new());
        }

        // ── Round-trip 1: fetch all step seeds (level=2) for all workflow IDs. ──
        // Order matches the single-workflow function: the `plan_index` ordinal
        // first, `(e.created_at ASC, c.id ASC)` only as the fallback for edges
        // that predate it. This batched twin was left on the bare `created_at`
        // key when `resolve_steps_to_heads` was moved to `plan_index`, so once a
        // plan's edges were written in one transaction (one shared `NOW()`), the
        // `step_index` it assigns below followed `c.id` — a content-derived UUID
        // — while its single-workflow sibling followed the plan.
        #[derive(sqlx::FromRow)]
        struct StepSeedRow {
            workflow_id: Uuid,
            frozen_claim_id: Uuid,
            step_lineage_id: Option<Uuid>,
        }

        let seed_sql = viewer.splice(
            "SELECT \
               e.source_id AS workflow_id, \
               c.id        AS frozen_claim_id, \
               c.step_lineage_id \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = ANY($1) \
               AND e.relationship = 'executes' \
               AND (c.properties->>'level')::int = 2 \
               /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */ \
             ORDER BY e.source_id, \
                      CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                           THEN (e.properties->>'plan_index')::int \
                           ELSE 2147483647 END, \
                      e.created_at ASC, c.id ASC",
            2,
        );
        let mut sq = sqlx::query_as::<_, StepSeedRow>(&seed_sql).bind(workflow_ids);
        if let Some(g) = viewer.group_bind() {
            sq = sq.bind(g);
        }
        let seed_rows: Vec<StepSeedRow> = sq.fetch_all(&mut *conn).await.map_err(DbError::from)?;

        // Initialise the result map with an empty Vec for every requested workflow
        // so callers get a deterministic entry even for step-less workflows.
        let mut result: HashMap<Uuid, Vec<ResolvedStep>> =
            workflow_ids.iter().map(|id| (*id, Vec::new())).collect();

        if seed_rows.is_empty() {
            return Ok(result);
        }

        // Build per-workflow step lists and collect the set of lineage_ids to query.
        // Preserve ordering: seeds are already in (workflow_id, plan order) order.
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
                is_current: bool,
            }

            // The `NOT EXISTS` over `edges` is an exclusion test, left
            // unfiltered for the same reason as `latest_in_lineage`'s.
            let head_sql = viewer.splice(
                "SELECT c.step_lineage_id AS lineage_id, c.id, c.content, c.truth_value, c.created_at, \
                        COALESCE(c.is_current, true) AS is_current \
                 FROM claims c \
                 WHERE c.step_lineage_id = ANY($1) \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM edges e \
                       WHERE e.target_id = c.id \
                         AND e.relationship = 'supersedes' \
                   ) \
                   /* {VISIBILITY:c} */ \
                 ORDER BY c.step_lineage_id, c.created_at DESC",
                2,
            );
            let mut hq = sqlx::query_as::<_, HeadRow>(&head_sql).bind(&all_lineage_ids);
            if let Some(g) = viewer.group_bind() {
                hq = hq.bind(g);
            }
            let head_rows: Vec<HeadRow> = hq.fetch_all(&mut *conn).await.map_err(DbError::from)?;

            for row in head_rows {
                heads_by_lineage
                    .entry(row.lineage_id)
                    .or_default()
                    .push(LineageHead {
                        id: row.id,
                        content: row.content,
                        truth_value: row.truth_value,
                        created_at: row.created_at,
                        is_current: row.is_current,
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
    /// deprecated LAST, generation DESC, created_at DESC)`, where "deprecated"
    /// is `truth_value < min_truth`. A live head therefore leads its canonical
    /// group, and a deprecated head (only the added head can be below
    /// `min_truth`) sorts after the live rows of its group: still returned,
    /// never the first row a caller walking the group picks.
    ///
    /// **`resolve_to_latest` also guarantees the lineage head is present.** The
    /// ILIKE predicate matches each row's OWN goal text, and sibling
    /// generations carry different goals, so the head of a matched lineage
    /// could be filtered out before ordering ran (bridge 37d65fe0, backlog
    /// ed6a953e). So for every `canonical_name` among the matched rows, its
    /// highest-generation row (the head `max_generation_by_canonical` and
    /// `improve_workflow_hierarchy` use) is added when it was not matched,
    /// regardless of its goal or `truth_value`: a deprecated head is still the
    /// head, and the caller sees its truth. The result can therefore hold up
    /// to `limit` matched rows plus one head per matched lineage, and the
    /// highest generation of each canonical group in it IS the lineage head
    /// ([`lineage_heads_in`]).
    ///
    /// Used by `GET /api/v1/workflows/hierarchical/search` and the MCP
    /// `find_workflow_hierarchical` tool.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    ///
    /// Generic over the executor so `find_workflow_hierarchical` can run it on
    /// the stamped connection it acquires. It takes NO `&Viewer`; the reason is
    /// recorded in `visibility_lint.rs::EXECUTOR_WITHOUT_VIEWER`.
    pub async fn search_hierarchical_by_text<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        let sql = if resolve_to_latest {
            // `matched` is the old statement, LIMIT included; `heads` adds the
            // highest generation of each matched canonical_name with no goal
            // or truth filter. Both read `workflows` alone. The union is
            // wrapped so the ORDER BY may sort on an expression: a head below
            // `min_truth` ($2) trails the live rows of its group.
            "WITH matched AS ( \
                 SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value \
                 FROM workflows \
                 WHERE (replace(canonical_name, '-', ' ') || ' ' || replace(goal, '-', ' ')) ILIKE $1 \
                   AND truth_value >= $2 \
                 ORDER BY canonical_name ASC, generation DESC, created_at DESC, id ASC \
                 LIMIT $3 \
             ), heads AS ( \
                 SELECT DISTINCT ON (w.canonical_name) \
                        w.id, w.canonical_name, w.generation, w.goal, w.parent_id, w.metadata, \
                        w.created_at, w.truth_value \
                 FROM workflows w \
                 WHERE w.canonical_name IN (SELECT canonical_name FROM matched) \
                 ORDER BY w.canonical_name, w.generation DESC \
             ) \
             SELECT * FROM ( \
                 SELECT * FROM matched \
                 UNION ALL \
                 SELECT * FROM heads h WHERE h.id NOT IN (SELECT id FROM matched) \
             ) u \
             ORDER BY canonical_name ASC, (truth_value < $2) ASC, generation DESC, created_at DESC, id ASC"
                .to_string()
        } else {
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value \
             FROM workflows \
             WHERE (replace(canonical_name, '-', ' ') || ' ' || replace(goal, '-', ' ')) ILIKE $1 \
               AND truth_value >= $2 \
             ORDER BY created_at DESC, id ASC \
             LIMIT $3"
                .to_string()
        };
        sqlx::query_as::<_, HierarchicalWorkflowRow>(&sql)
            .bind(&pattern)
            .bind(min_truth)
            .bind(limit)
            .fetch_all(executor)
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
    /// (`deprecate_workflow` writes 0.05). Ordering is by distance; when
    /// `resolve_to_latest` is true a higher generation breaks ties, and
    /// otherwise `created_at DESC` does.
    ///
    /// With `resolve_to_latest`, as in [`Self::search_hierarchical_by_text`],
    /// the lineage head of every matched `canonical_name` is guaranteed
    /// present: a head with no `goal_embedding`, below the similarity floor,
    /// below `min_truth` or past the LIMIT is added. An added LIVE head sorts at
    /// its group's best match distance, ahead of that match; an added
    /// DEPRECATED head (`truth_value < min_truth`) sorts at its group's worst
    /// match distance, after that match, so it trails every live row of its
    /// group. Either way the matched rows keep their relative order.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    ///
    /// Generic over the executor for the same reason as
    /// [`Self::search_hierarchical_by_text`], and viewer-less for the same
    /// reason, recorded in the same register.
    pub async fn find_hierarchical_by_embedding<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        if resolve_to_latest {
            // `matched` is the old statement, LIMIT included; `heads` adds the
            // highest generation of each matched canonical_name with no
            // embedding, similarity or truth filter. All three CTEs read
            // `workflows` alone. The final ORDER BY sits on the outermost
            // SELECT: an injected live head (no distance) takes its group's
            // best distance and sorts ahead of that row; an injected
            // deprecated head takes the group's worst distance and sorts after
            // it. Only an injected head can be below `min_truth` ($3).
            let sql = "WITH q AS (SELECT $1::vector AS v), \
                 matched AS ( \
                     SELECT w.id, w.canonical_name, w.generation, w.goal, w.parent_id, w.metadata, \
                            w.created_at, w.truth_value, (w.goal_embedding <=> q.v) AS distance \
                     FROM workflows w, q \
                     WHERE w.goal_embedding IS NOT NULL \
                       AND w.truth_value >= $3 \
                       AND (1 - (w.goal_embedding <=> q.v)) >= $2 \
                     ORDER BY distance ASC, generation DESC, created_at DESC \
                     LIMIT $4 \
                 ), heads AS ( \
                     SELECT DISTINCT ON (w.canonical_name) \
                            w.id, w.canonical_name, w.generation, w.goal, w.parent_id, w.metadata, \
                            w.created_at, w.truth_value, NULL::float8 AS distance \
                     FROM workflows w \
                     WHERE w.canonical_name IN (SELECT canonical_name FROM matched) \
                     ORDER BY w.canonical_name, w.generation DESC \
                 ), combined AS ( \
                     SELECT m.*, false AS injected FROM matched m \
                     UNION ALL \
                     SELECT h.*, true AS injected FROM heads h \
                     WHERE h.id NOT IN (SELECT id FROM matched) \
                 ), ranked AS ( \
                     SELECT c.*, (c.truth_value < $3) AS deprecated, \
                            CASE WHEN c.truth_value < $3 \
                                 THEN MAX(c.distance) OVER (PARTITION BY c.canonical_name) \
                                 ELSE COALESCE(c.distance, \
                                      MIN(c.distance) OVER (PARTITION BY c.canonical_name)) \
                            END AS sort_distance \
                     FROM combined c \
                 ) \
                 SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, truth_value \
                 FROM ranked \
                 ORDER BY sort_distance ASC, deprecated ASC, injected DESC, generation DESC, created_at DESC, id ASC";
            return sqlx::query_as::<_, HierarchicalWorkflowRow>(sql)
                .bind(&vec_str)
                .bind(similarity_threshold)
                .bind(min_truth)
                .bind(limit)
                .fetch_all(executor)
                .await;
        }
        let order_clause = "ORDER BY distance ASC, created_at DESC, id ASC";
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
            .fetch_all(executor)
            .await
    }

    /// ANN search over `workflows.goal_embedding` shaped for `recall()`'s
    /// workflows leg: takes a pre-formatted pgvector literal (like
    /// `ClaimRepository::search_hybrid_scoped`/`search_by_embedding_scoped`,
    /// so callers reuse ONE query embedding across claims + workflows), and
    /// returns `similarity = 1 - cosine_distance` per row so `recall` can
    /// populate `RecallResult.similarity` the same way it does for claim
    /// hits.
    ///
    /// Distinct from `find_hierarchical_by_embedding`: that helper takes
    /// `&[f32]`, drops the distance/similarity column from its outer SELECT
    /// (only used for existence/ordering, not surfaced), and carries
    /// `resolve_to_latest`/threshold semantics recall doesn't need. This is
    /// a lighter sibling: no truth-value floor here (recall applies its own
    /// `min_truth` uniformly across claims + workflows after the merge, same
    /// as it already does for claim hits).
    ///
    /// Retained at its original three-argument arity as a delegating wrapper
    /// over [`Self::search_by_goal_embedding_since`]; `None` = no window =
    /// today's behaviour.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn search_by_goal_embedding(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<WorkflowGoalEmbeddingHit>, sqlx::Error> {
        Self::search_by_goal_embedding_since(pool, query_embedding_pgvector, limit, None).await
    }

    /// [`Self::search_by_goal_embedding`] plus an optional
    /// `created_at >= since` window.
    ///
    /// The predicate is in the WHERE clause, above the `LIMIT`, so a pool
    /// filled with older workflows cannot crowd out a newer one.
    /// `workflows.created_at` is a real column, so this leg honours the
    /// window for real rather than taking the "omit the field and exclude the
    /// row" fallback.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn search_by_goal_embedding_since(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<WorkflowGoalEmbeddingHit>, sqlx::Error> {
        sqlx::query_as::<_, WorkflowGoalEmbeddingHit>(
            "SELECT id AS workflow_id, goal AS content, truth_value, \
                    (1 - (goal_embedding <=> $1::vector))::float8 AS similarity, \
                    created_at \
             FROM workflows \
             WHERE goal_embedding IS NOT NULL \
               AND ($3::timestamptz IS NULL OR created_at >= $3::timestamptz) \
             ORDER BY goal_embedding <=> $1::vector \
             LIMIT $2",
        )
        .bind(query_embedding_pgvector)
        .bind(limit)
        .bind(since)
        .fetch_all(pool)
        .await
    }

    /// Cosine-similarity search over `workflows.goal_embedding` that keeps BOTH
    /// the full row and its similarity score — see
    /// [`ScoredHierarchicalWorkflowRow`] for why neither existing sibling does.
    ///
    /// Takes a pre-formatted pgvector literal (like
    /// `ClaimRepository::search_by_embedding_scoped`) so a caller can reuse ONE
    /// query embedding across the claims and workflows stores. `min_truth`
    /// filters out deprecated rows (`deprecate_workflow` writes 0.05). No
    /// similarity floor: the caller ranks and truncates, so imposing one here
    /// would silently drop rows it may still want to consider.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    ///
    /// Takes NO `&Viewer`, and no lint sees it either — it takes a `&PgPool`,
    /// which is neither of the two spellings `visibility_lint.rs` scans. The
    /// reason is recorded here so the next reader does not have to re-derive
    /// it: the statement's `FROM` is `workflows` alone and it joins no other
    /// relation, and `workflows` carries neither a `visibility` nor an
    /// `owner_group_id` column, so there is no predicate to write. This is the
    /// scored sibling of `find_hierarchical_by_embedding`, whose identical
    /// posture is registered in `visibility_lint.rs::EXECUTOR_WITHOUT_VIEWER`.
    /// Contrast `step_texts_for_hierarchical` below, which joins `claims` and
    /// therefore DOES take a viewer.
    pub async fn search_hierarchical_by_embedding_scored(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<ScoredHierarchicalWorkflowRow>, sqlx::Error> {
        sqlx::query_as::<_, ScoredHierarchicalWorkflowRow>(
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at, \
                    truth_value, \
                    (1 - (goal_embedding <=> $1::vector))::float8 AS similarity \
             FROM workflows \
             WHERE goal_embedding IS NOT NULL \
               AND truth_value >= $2 \
             ORDER BY goal_embedding <=> $1::vector \
             LIMIT $3",
        )
        .bind(query_embedding_pgvector)
        .bind(min_truth)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Step texts for hierarchical workflows, in plan order, keyed by workflow.
    ///
    /// A `workflows` row carries no inline steps — its steps are level-2 claims
    /// reached through `executes` edges. A caller that renders a hierarchical
    /// workflow into a steps-bearing shape MUST resolve them: handing back an
    /// empty `steps` array is the failure mode that caused the 2026-08-18
    /// incident, where an agent told to "follow the best-matching workflow
    /// steps" received `[]`, fell back to a bare `theme_cluster` with
    /// `wipe_first=true`, and destroyed 76 themes.
    ///
    /// Ordering is the `executes` edge's `plan_index` ordinal, falling back to
    /// `(edge created_at ASC, claim id ASC)` for edges that predate it — the
    /// same plan order [`Self::resolve_steps_to_heads`],
    /// [`Self::resolve_steps_to_heads_batched`] and both
    /// `report_hierarchical_outcome` handlers (MCP and HTTP) use, so step N
    /// means the same step in all of them.
    ///
    /// Returns the FROZEN step claims attached to the workflow, not lineage
    /// heads. `find_workflow` advertises the workflow as stored; callers that
    /// need head resolution have `find_workflow_hierarchical(resolve_to_latest)`.
    /// Workflows with no steps are simply absent from the map.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn step_texts_for_hierarchical(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        workflow_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<String>>, sqlx::Error> {
        if workflow_ids.is_empty() {
            return Ok(HashMap::new());
        }
        // This projects `c.content` — claim TEXT, not a scalar — so it is a
        // first-class claim read and carries the viewer predicate on `c`.
        // `$1` is the id array, so the viewer bind is `$2`.
        //
        // No `/* {EDGE_VISIBILITY:e} */`: the `edges` leg here has never
        // carried a predicate, and PR-13 deliberately converted only the reads
        // that already had one. Adding an edge filter needs its own
        // JOIN-vs-WHERE reasoning and belongs to the tracked open finding
        // `F-edges-unfiltered`, not to this merge.
        let sql = viewer.splice(
            "SELECT e.source_id, c.content \
             FROM edges e \
             JOIN claims c ON c.id = e.target_id \
             WHERE e.source_id = ANY($1) \
               AND e.relationship = 'executes' \
               AND (c.properties->>'level')::int = 2 /* {VISIBILITY:c} */ \
             ORDER BY e.source_id, \
                      CASE WHEN e.properties->>'plan_index' ~ '^[0-9]{1,9}$' \
                           THEN (e.properties->>'plan_index')::int \
                           ELSE 2147483647 END, \
                      e.created_at ASC, c.id ASC",
            2,
        );
        let mut q = sqlx::query_as(&sql).bind(workflow_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid, String)> = q.fetch_all(pool).await?;

        let mut out: HashMap<Uuid, Vec<String>> = HashMap::new();
        for (workflow_id, content) in rows {
            out.entry(workflow_id).or_default().push(content);
        }
        Ok(out)
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

    /// `(id, goal)` of hierarchical workflows whose `goal_embedding` is NULL,
    /// oldest first, at most `limit` rows. The recovery half of
    /// [`Self::set_goal_embedding`].
    ///
    /// Every write path embeds the goal best-effort and continues on an
    /// embedder failure, and the three embedding searches here
    /// (`find_hierarchical_by_embedding`, `search_by_goal_embedding_since`,
    /// `search_hierarchical_by_embedding_scored`) filter
    /// `goal_embedding IS NOT NULL`, so such a row stays invisible to them
    /// until the `embed_backfill` CLI embeds it from this list.
    ///
    /// A blank goal has nothing to embed and is excluded, or it would be
    /// reported (and fail) on every run.
    ///
    /// No viewer: `workflows` has `relrowsecurity = false` and no policy (see
    /// `set_truth_value`), so the read is the same on any connection.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn find_needing_goal_embedding(
        pool: &PgPool,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
        sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, goal FROM workflows \
             WHERE goal_embedding IS NULL AND btrim(goal) <> '' \
             ORDER BY created_at ASC, id ASC \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
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
    /// # The executor is generic for COHESION, not because `workflows` is protected
    ///
    /// MEASURED on a database migrated 001->101: `workflows` has
    /// `relrowsecurity = false`, no policy, and no entry in migration 062's
    /// tier-A array — so unlike the `claims` UPDATE this call cascades from, it
    /// is NOT refused on an unstamped session. It is generic so that the two
    /// halves of one deprecation can share a transaction: a `claims` row flipped
    /// to `is_current = false` while its hierarchical `workflows` row keeps its
    /// truth value is exactly the split `deprecate_workflow`'s cascade exists to
    /// prevent, and `find_workflow_hierarchical` reads the half that was missed.
    pub async fn set_truth_value<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        workflow_id: Uuid,
        truth_value: f64,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("UPDATE workflows SET truth_value = $1 WHERE id = $2")
            .bind(truth_value)
            .bind(workflow_id)
            .execute(executor)
            .await?;
        Ok(result.rows_affected())
    }

    /// [`Self::set_truth_value`], but `rows_affected` means "the state
    /// CHANGED": a row already at `truth_value` matches nothing, so a re-run of
    /// a deprecation reports nothing (U017; backlog fe874d2a). `truth_value` is
    /// `DOUBLE PRECISION NOT NULL` (migration 033), and an `f64` bind round-trips
    /// exactly, so `IS DISTINCT FROM` compares the same value it wrote.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the statement fails.
    pub async fn set_truth_value_if_changed<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        workflow_id: Uuid,
        truth_value: f64,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE workflows SET truth_value = $1 \
              WHERE id = $2 AND truth_value IS DISTINCT FROM $1",
        )
        .bind(truth_value)
        .bind(workflow_id)
        .execute(executor)
        .await?;
        Ok(result.rows_affected())
    }

    /// Whether a hierarchical `workflows` row with this id exists. `workflows`
    /// has no row security and no policy, so the answer is the same on every
    /// connection.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn exists<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
            .bind(id)
            .fetch_one(executor)
            .await
    }

    /// Every `workflows` row descended from `id` through `workflows.parent_id`
    /// (later generations and variants), transitively, in walk order and
    /// without `id` itself.
    ///
    /// `parent_id` and the `workflow -variant_of-> workflow` edge are written
    /// by the ingest executor under the SAME condition (a linked parent), so
    /// this is the lineage the variant edges describe. It is read from
    /// `workflows` rather than from `edges` because `workflows` has no row
    /// security, so the walk cannot be silently truncated by an edge the
    /// session's tenancy context does not reach. Cycle-guarded: a hand-edited
    /// `parent_id` loop terminates.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn lineage_descendants<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "WITH RECURSIVE d(id, depth) AS ( \
                 SELECT w.id, 1 FROM workflows w WHERE w.parent_id = $1 AND w.id <> $1 \
                 UNION ALL \
                 SELECT w.id, d.depth + 1 FROM workflows w JOIN d ON w.parent_id = d.id \
                  WHERE w.id <> $1 \
             ) CYCLE id SET is_cycle USING path \
             SELECT id FROM d WHERE NOT is_cycle \
              GROUP BY id ORDER BY min(depth), id",
        )
        .bind(id)
        .fetch_all(executor)
        .await
    }

    /// Lock, `FOR UPDATE` and in id order, every `workflows` row that shares a
    /// `canonical_name` with any of `ids` (U017; backlog fe874d2a).
    ///
    /// # Why
    ///
    /// [`Self::executed_structural_claims`] decides a claim is `shared` by
    /// reading OTHER workflows' `truth_value`. Under READ COMMITTED two
    /// concurrent deprecations of one lineage (say gen0 and gen1) would each
    /// read the other as live, because the other's `truth_value = 0.05` is not
    /// yet committed, and each would keep the step they share. Both commit, and
    /// the step stays current with no live workflow executing it: the stranded
    /// state the deprecation exists to prevent (write skew).
    ///
    /// Every possible sharer of a level 0-2 claim carries the same
    /// `canonical_name`, because that claim's id is
    /// `compound_claim_id(hash(text), canonical_name)` in both the ingest
    /// builder and `add_step`. So locking the rows of those canonical names
    /// serializes every pair of deprecations that could share a claim. A
    /// second deprecation waits for the first to commit, and its next
    /// statement takes a fresh snapshot that sees the first one's 0.05. Taking
    /// the locks in id order means two such calls cannot deadlock each other.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn lock_lineages_for_deprecation<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT w.id FROM workflows w \
              WHERE w.canonical_name IN ( \
                    SELECT t.canonical_name FROM workflows t WHERE t.id = ANY($1::uuid[])) \
              ORDER BY w.id \
                FOR UPDATE",
        )
        .bind(ids)
        .fetch_all(executor)
        .await?;
        Ok(())
    }

    /// The thesis, phase and step claims (levels 0-2) that hierarchical
    /// workflow `workflow_id` executes and that are still current, each with
    /// whether ANOTHER live workflow also executes it (U017; backlog
    /// fe874d2a).
    ///
    /// # Why "shared" exists
    ///
    /// A level 0-2 claim id is `compound_claim_id(hash(text), canonical_name)`:
    /// the generation is not in the seed, so every generation of a lineage
    /// that keeps a text executes the SAME claim row. Retiring it because one
    /// generation was deprecated would retire a step a live sibling still runs.
    /// A claim is `shared` when a workflow that is NOT in `deprecating` (the
    /// whole set being deprecated in this call) and is still live
    /// (`truth_value > 0.05`; `NOT NULL` since migration 033) executes it.
    ///
    /// Level-3 operation atoms are excluded outright: their ids are content-only
    /// and global, so a document may share one.
    ///
    /// The read rides the deprecation's own system-stamped transaction and is
    /// not filtered by a caller viewer on purpose: workflow claims belong to
    /// the ingest system agent, and the authority decision is the workflow
    /// authority rule over the `workflows` row, not read visibility.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the query fails.
    pub async fn executed_structural_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        workflow_id: Uuid,
        deprecating: &[Uuid],
    ) -> Result<Vec<ExecutedClaim>, sqlx::Error> {
        let rows: Vec<(Uuid, bool)> = sqlx::query_as(
            "-- VISIBILITY-EXEMPT: WRITE path. The deprecation this read plans is gated by the workflow authority rule over the workflows row; the claims are the ingest system agent's and the read rides that agent's stamped transaction.
             SELECT DISTINCT c.id, \
                    EXISTS (SELECT 1 FROM edges e2 JOIN workflows w2 ON w2.id = e2.source_id \
                             WHERE e2.target_id = c.id AND e2.relationship = 'executes' \
                               AND e2.source_type = 'workflow' \
                               AND NOT (w2.id = ANY($2::uuid[])) \
                               AND w2.truth_value > 0.05) AS shared \
               FROM edges e JOIN claims c ON c.id = e.target_id \
              WHERE e.source_id = $1 AND e.source_type = 'workflow' \
                AND e.relationship = 'executes' \
                AND c.properties->>'level' IN ('0', '1', '2') \
                AND c.is_current \
              ORDER BY c.id",
        )
        .bind(workflow_id)
        .bind(deprecating)
        .fetch_all(executor)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, shared)| ExecutedClaim { id, shared })
            .collect())
    }

    /// The `workflows` row and every `executes` edge of `workflow_id` that
    /// `viewer` may see, each joined to its target claim when `viewer` may read
    /// it. The raw input of the frozen-plan read
    /// (`epigraph_ingest_executor::workflow_plan::frozen_plan`), which derives
    /// the order, the integrity counts and the digest echo from these rows.
    ///
    /// `Ok(None)` when no `workflows` row has this id.
    ///
    /// # What is and is not filtered
    ///
    /// * The edges carry `{EDGE_VISIBILITY:e}` and the target claim
    ///   `{VISIBILITY:c}`, so a target the viewer cannot read comes back as an
    ///   edge with `readable = false` and no claim column: the caller counts it
    ///   and never sees its id or content past this function. An edge the viewer
    ///   cannot see does not come back at all. That is most hidden items: an
    ///   `executes` edge takes its target's tenancy (migration 072's meet).
    /// * RETRACTED edges (`valid_to` set) are returned, flagged, not dropped:
    ///   a retraction changes the plan and the caller must be able to say so.
    /// * `workflows` has no row security, so the row read needs no predicate.
    /// * `heads_diverged` asks whether the target's step lineage has a head
    ///   other than the target that the viewer may read (`{VISIBILITY:h}`). The
    ///   `supersedes` exclusion inside it carries no viewer predicate, as in
    ///   [`ClaimRepository::latest_in_lineage`], but on an RLS-bound
    ///   connection the policy still hides a `supersedes` edge in a group the
    ///   viewer is not in, so a head that edge retired can still count and
    ///   the flag can read `true` spuriously. It is informational (a resolver
    ///   warns on it and never refuses), so the over-report is accepted.
    ///
    /// Takes the ONE viewer-stamped connection of the request, so the in-query
    /// predicate and the session's tenancy GUCs agree under forced RLS.
    ///
    /// # Errors
    /// Returns `DbError` if a query fails.
    pub async fn frozen_plan(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        workflow_id: Uuid,
    ) -> Result<Option<FrozenPlanRead>, DbError> {
        let row: Option<FrozenPlanRow> = sqlx::query_as(
            "SELECT id, canonical_name, generation, goal, parent_id, truth_value, metadata \
               FROM workflows WHERE id = $1",
        )
        .bind(workflow_id)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };

        let sql = viewer.splice(
            r#"
            SELECT e.properties AS edge_properties,
                   (e.valid_to IS NOT NULL) AS retracted,
                   e.target_id,
                   (t.id IS NOT NULL) AS readable,
                   t.content, t.content_hash, t.properties AS claim_properties,
                   t.visibility, t.owner_group_id, t.truth_value, t.is_current,
                   t.heads_diverged
              FROM edges e
              LEFT JOIN LATERAL (
                  SELECT c.id, c.content, c.content_hash, c.properties,
                         c.visibility::text AS visibility, c.owner_group_id,
                         c.truth_value, c.is_current,
                         (c.step_lineage_id IS NOT NULL AND EXISTS (
                              SELECT 1 FROM claims h
                               WHERE h.step_lineage_id = c.step_lineage_id
                                 AND h.id <> c.id
                                 AND NOT EXISTS (
                                     SELECT 1 FROM edges s
                                      WHERE s.target_id = h.id
                                        AND s.relationship = 'supersedes')
                                 /* {VISIBILITY:h} */
                         )) AS heads_diverged
                    FROM claims c
                   WHERE c.id = e.target_id AND e.target_type = 'claim'
                     /* {VISIBILITY:c} */
              ) t ON true
             WHERE e.source_id = $1 AND e.relationship = 'executes'
               /* {EDGE_VISIBILITY:e} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, FrozenPlanEdgeRow>(&sql).bind(workflow_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let edges = q.fetch_all(&mut *conn).await?;
        Ok(Some(FrozenPlanRead { row, edges }))
    }
}

/// The lineage head of each `canonical_name` in `rows`: its highest
/// generation, as `(id, generation, truth_value)`.
///
/// Exact for the result of [`WorkflowRepository::search_hierarchical_by_text`]
/// or [`WorkflowRepository::find_hierarchical_by_embedding`] with
/// `resolve_to_latest = true`, which add each matched lineage's head, and
/// `UNIQUE (canonical_name, generation)` makes the highest generation a single
/// row. On any other row set it is only the highest generation PRESENT.
#[must_use]
pub fn lineage_heads_in(rows: &[HierarchicalWorkflowRow]) -> HashMap<String, (Uuid, i32, f64)> {
    let mut heads: HashMap<String, (Uuid, i32, f64)> = HashMap::new();
    for r in rows {
        let entry =
            heads
                .entry(r.canonical_name.clone())
                .or_insert((r.id, r.generation, r.truth_value));
        if r.generation > entry.1 {
            *entry = (r.id, r.generation, r.truth_value);
        }
    }
    heads
}

/// The `workflows` row of [`WorkflowRepository::frozen_plan`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FrozenPlanRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub generation: i32,
    pub goal: String,
    pub parent_id: Option<Uuid>,
    pub truth_value: f64,
    pub metadata: serde_json::Value,
}

/// One visible `executes` edge of [`WorkflowRepository::frozen_plan`]. Every
/// claim column is `None` when `readable` is false.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FrozenPlanEdgeRow {
    pub edge_properties: Option<serde_json::Value>,
    pub retracted: bool,
    pub target_id: Uuid,
    pub readable: bool,
    pub content: Option<String>,
    pub content_hash: Option<Vec<u8>>,
    pub claim_properties: Option<serde_json::Value>,
    pub visibility: Option<String>,
    pub owner_group_id: Option<Uuid>,
    pub truth_value: Option<f64>,
    pub is_current: Option<bool>,
    pub heads_diverged: Option<bool>,
}

/// What [`WorkflowRepository::frozen_plan`] read.
#[derive(Debug, Clone)]
pub struct FrozenPlanRead {
    pub row: FrozenPlanRow,
    pub edges: Vec<FrozenPlanEdgeRow>,
}

/// One row of [`WorkflowRepository::executed_structural_claims`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutedClaim {
    /// The thesis, phase or step claim.
    pub id: Uuid,
    /// Another live workflow, outside the set being deprecated, executes it.
    pub shared: bool,
}

/// The level-2 steps of one plan whose position is provable from the
/// `executes` edges a viewer reads: `rows` are `(claim id, claim level text,
/// edge plan_index)` in plan order (ordinal edges first, ascending). See
/// [`WorkflowRepository::plan_step_claim_ids`] for the rule; element N of the
/// result is step N.
#[must_use]
fn provable_plan_steps(rows: &[(Uuid, Option<String>, Option<i32>)]) -> Vec<Uuid> {
    let level = |l: &Option<String>| l.as_deref().and_then(|v| v.trim().parse::<i64>().ok());
    let mut steps = Vec::new();
    let mut next_ordinal: i32 = 0;
    let mut unordered = Vec::new();
    for (id, lvl, plan_index) in rows {
        match plan_index {
            Some(pi) => {
                // A gap (or a repeat) means an ordinal edge this viewer cannot
                // read, or a plan it cannot number: no later position holds.
                if *pi != next_ordinal {
                    return steps;
                }
                next_ordinal += 1;
                if level(lvl) == Some(2) {
                    steps.push(*id);
                }
            }
            None => unordered.push((*id, level(lvl))),
        }
    }
    let anchored = next_ordinal > 0 || unordered.iter().any(|(_, l)| *l == Some(1));
    if anchored {
        steps.extend(
            unordered
                .into_iter()
                .filter(|(_, l)| *l == Some(2))
                .map(|(id, _)| id),
        );
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(level: &str, plan_index: Option<i32>) -> (Uuid, Option<String>, Option<i32>) {
        (Uuid::new_v4(), Some(level.to_string()), plan_index)
    }

    /// A fully visible current-format plan (phase 0, steps 1..=2, phase 3,
    /// step 4) plus an appended unordered step: every step is listed, in
    /// order, and the phases' ordinals do not count as steps.
    #[test]
    fn a_complete_plan_lists_every_step_in_plan_order() {
        let rows = vec![
            row("1", Some(0)),
            row("2", Some(1)),
            row("2", Some(2)),
            row("1", Some(3)),
            row("2", Some(4)),
            row("2", None),
        ];
        let want: Vec<Uuid> = [1, 2, 4, 5].iter().map(|i| rows[*i].0).collect();
        assert_eq!(provable_plan_steps(&rows), want);
    }

    /// A hidden ordinal edge (here plan_index 2) stops the list: the step at
    /// plan_index 3 would otherwise be reported as step 1, and the appended
    /// step after it as step 2.
    #[test]
    fn a_gap_in_the_ordinals_stops_the_list() {
        let rows = vec![
            row("1", Some(0)),
            row("2", Some(1)),
            row("2", Some(3)),
            row("2", None),
        ];
        assert_eq!(provable_plan_steps(&rows), vec![rows[1].0]);

        // A plan whose first ordinal is hidden yields nothing at all.
        let rows = vec![row("2", Some(1)), row("2", Some(2))];
        assert!(provable_plan_steps(&rows).is_empty());
    }

    /// Unordered steps alone, with no ordinal edge and no phase visible, are
    /// the appended tail of a plan the viewer cannot read: their position is
    /// unknown, so none is listed. With a phase visible (a plan written before
    /// the ordinal existed) they are listed positionally, as before.
    #[test]
    fn unordered_steps_need_a_visible_plan_to_follow() {
        let appended = vec![row("2", None)];
        assert!(provable_plan_steps(&appended).is_empty());

        let legacy = vec![row("1", None), row("2", None), row("2", None)];
        assert_eq!(provable_plan_steps(&legacy), vec![legacy[1].0, legacy[2].0]);
    }

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
    async fn immediate_variant_parent_returns_one_hop(pool: sqlx::PgPool) {
        let agent: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO agents (public_key, display_name) VALUES ($1, 'ivp') RETURNING id",
        )
        .bind(blake3::hash(b"ivp-agent").as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        let mk_claim = |content: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, uuid::Uuid>(
                    "INSERT INTO claims (content, content_hash, agent_id, truth_value) \
                     VALUES ($1, sha256($1::bytea), $2, 0.5) RETURNING id",
                )
                .bind(content)
                .bind(agent)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let parent = mk_claim("ivp-parent").await;
        let variant = mk_claim("ivp-variant").await;
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) \
             VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'variant_of')",
        )
        .bind(variant)
        .bind(parent)
        .execute(&pool)
        .await
        .unwrap();

        // The variant's one-hop parent is the variant_of target.
        assert_eq!(
            WorkflowRepository::immediate_variant_parent(
                &pool,
                &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
                variant
            )
            .await
            .unwrap(),
            Some(parent)
        );
        // A lineage root has no outgoing variant_of/supersedes edge → None.
        assert_eq!(
            WorkflowRepository::immediate_variant_parent(
                &pool,
                &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
                parent
            )
            .await
            .unwrap(),
            None
        );
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

    /// Regression test for the improve_workflow_hierarchy embedding gap:
    ///
    /// When a new generation is inserted but `set_goal_embedding` is not called,
    /// the row has NULL goal_embedding and is invisible to
    /// `find_hierarchical_by_embedding` (filtered by WHERE goal_embedding IS NOT
    /// NULL). Only after `set_goal_embedding` is called does the row become
    /// searchable via the embedding path.
    ///
    /// This test exercises the DB-level invariant; the code fix lives in
    /// `improve_workflow_hierarchy` (workflow_ingest.rs) which now calls
    /// `set_goal_embedding` for every new generation it creates.
    #[sqlx::test(migrations = "../../migrations")]
    async fn find_hierarchical_by_embedding_skips_null_goal_embedding(pool: sqlx::PgPool) {
        let gen0_id = uuid::Uuid::new_v4();
        let gen1_id = uuid::Uuid::new_v4();

        WorkflowRepository::insert_root(
            &pool,
            gen0_id,
            "embed-gap-test",
            0,
            "Send daily digest email",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        WorkflowRepository::insert_root(
            &pool,
            gen1_id,
            "embed-gap-test",
            1,
            "Send daily digest email with retry",
            Some(gen0_id),
            serde_json::json!({}),
        )
        .await
        .unwrap();

        // Unit vector in 1536-d (matches workflows.goal_embedding vector(1536)).
        let mut qvec = vec![0.0f32; 1536];
        qvec[0] = 1.0;

        // Set embedding only on gen 0 — simulates the pre-fix state where
        // improve_workflow_hierarchy did not call set_goal_embedding.
        WorkflowRepository::set_goal_embedding(&pool, gen0_id, &qvec)
            .await
            .unwrap();

        // With only gen 0 embedded, the embedding search must return exactly one
        // row (gen 0). Gen 1 is invisible because its goal_embedding IS NULL.
        // Default mode: with `resolve_to_latest` the unembedded head is ADDED
        // as its lineage's head (see
        // `find_hierarchical_by_embedding_resolve_to_latest_includes_unembedded_head`),
        // so the ANN predicate itself is observed with it off.
        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.0, 0.0, 10, false)
                .await
                .unwrap();
        assert_eq!(
            hits.len(),
            1,
            "gen 1 must be invisible without goal_embedding"
        );
        assert_eq!(hits[0].generation, 0);

        // Now set embedding on gen 1 — what the fixed improve_workflow_hierarchy does.
        WorkflowRepository::set_goal_embedding(&pool, gen1_id, &qvec)
            .await
            .unwrap();

        // Both generations must now be visible, and with resolve_to_latest=true
        // (distance ASC then generation DESC) gen 1 surfaces first.
        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.0, 0.0, 10, true)
                .await
                .unwrap();
        assert_eq!(hits.len(), 2, "both gens visible after set_goal_embedding");
        assert_eq!(
            hits[0].generation, 1,
            "higher generation surfaces first with resolve_to_latest ordering"
        );
    }

    /// Bridge 37d65fe0 / backlog ed6a953e, embedding path: the ANN predicate
    /// (`goal_embedding IS NOT NULL`, similarity floor) runs BEFORE ordering,
    /// so a lineage head with no embedding, or one whose goal moved away from
    /// the query, never reached `generation DESC`. With `resolve_to_latest`
    /// the head of every matched `canonical_name` must be present and lead its
    /// group. Here the head (gen 2) has no embedding at all, and an unrelated
    /// lineage with a CLOSER match keeps its rank ahead of it.
    #[sqlx::test(migrations = "../../migrations")]
    async fn find_hierarchical_by_embedding_resolve_to_latest_includes_unembedded_head(
        pool: sqlx::PgPool,
    ) {
        let canonical = "embed-head-test";
        let mut ids = Vec::new();
        for g in 0..3 {
            let id = uuid::Uuid::new_v4();
            WorkflowRepository::insert_root(
                &pool,
                id,
                canonical,
                g,
                "Send daily digest email",
                None,
                serde_json::json!({}),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let other = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            other,
            "other-lineage",
            0,
            "Unrelated but closer",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();

        let mut qvec = vec![0.0f32; 1536];
        qvec[0] = 1.0;
        let mut near = vec![0.0f32; 1536];
        near[0] = 0.8;
        near[1] = 0.6;
        // gens 0 and 1 embedded (similarity 0.8); gen 2 (the head) has none.
        for id in &ids[..2] {
            WorkflowRepository::set_goal_embedding(&pool, *id, &near)
                .await
                .unwrap();
        }
        WorkflowRepository::set_goal_embedding(&pool, other, &qvec)
            .await
            .unwrap();

        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.5, 0.0, 10, true)
                .await
                .unwrap();
        let order: Vec<(String, i32)> = hits
            .iter()
            .map(|h| (h.canonical_name.clone(), h.generation))
            .collect();
        assert_eq!(
            order,
            vec![
                ("other-lineage".to_string(), 0),
                (canonical.to_string(), 2),
                (canonical.to_string(), 1),
                (canonical.to_string(), 0),
            ],
            "the unembedded head must be injected ahead of its matched siblings, \
             and the closer lineage keeps its rank"
        );

        // Default mode is unchanged: the unembedded head stays invisible.
        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.5, 0.0, 10, false)
                .await
                .unwrap();
        assert!(hits.iter().all(|h| h.id != ids[2]));
    }

    /// Embedding path, the LIMIT drop: the head is embedded and above the
    /// similarity floor but farther than a sibling, so with `limit = 1` only
    /// the sibling survives the matched LIMIT. `resolve_to_latest` must still
    /// return the head, ahead of that sibling; default mode returns the
    /// sibling alone.
    #[sqlx::test(migrations = "../../migrations")]
    async fn find_hierarchical_by_embedding_resolve_to_latest_includes_head_past_the_limit(
        pool: sqlx::PgPool,
    ) {
        let canonical = "limit-head-test";
        let mut ids = Vec::new();
        for g in 0..2 {
            let id = uuid::Uuid::new_v4();
            WorkflowRepository::insert_root(
                &pool,
                id,
                canonical,
                g,
                "Rotate the signing keys",
                None,
                serde_json::json!({}),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let mut qvec = vec![0.0f32; 1536];
        qvec[0] = 1.0;
        let mut near = vec![0.0f32; 1536];
        near[0] = 0.8;
        near[1] = 0.6;
        // gen 0 is the exact match; the head (gen 1) is above the 0.5 floor
        // (similarity 0.8) but farther.
        WorkflowRepository::set_goal_embedding(&pool, ids[0], &qvec)
            .await
            .unwrap();
        WorkflowRepository::set_goal_embedding(&pool, ids[1], &near)
            .await
            .unwrap();

        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.5, 0.0, 1, true)
                .await
                .unwrap();
        let order: Vec<uuid::Uuid> = hits.iter().map(|h| h.id).collect();
        assert_eq!(
            order,
            vec![ids[1], ids[0]],
            "the head cut by the LIMIT must be added, leading its group"
        );

        let hits =
            WorkflowRepository::find_hierarchical_by_embedding(&pool, &qvec, 0.5, 0.0, 1, false)
                .await
                .unwrap();
        let order: Vec<uuid::Uuid> = hits.iter().map(|h| h.id).collect();
        assert_eq!(order, vec![ids[0]], "default mode keeps the plain LIMIT");
    }

    /// Text path: the head of a matched `canonical_name` is returned even when
    /// its goal does not match and its truth is below `min_truth`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn search_hierarchical_by_text_resolve_to_latest_includes_head(pool: sqlx::PgPool) {
        let canonical = "text-head-test";
        for g in 0..2 {
            WorkflowRepository::insert_root(
                &pool,
                uuid::Uuid::new_v4(),
                canonical,
                g,
                "consider all available tools",
                None,
                serde_json::json!({}),
            )
            .await
            .unwrap();
        }
        let head = uuid::Uuid::new_v4();
        WorkflowRepository::insert_root(
            &pool,
            head,
            canonical,
            2,
            "rewrite the plan",
            None,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        WorkflowRepository::set_truth_value(&pool, head, 0.05)
            .await
            .unwrap();

        let hits = WorkflowRepository::search_hierarchical_by_text(
            &pool,
            "available tools",
            10,
            0.3,
            true,
        )
        .await
        .unwrap();
        let gens: Vec<i32> = hits.iter().map(|h| h.generation).collect();
        assert_eq!(
            gens,
            vec![1, 0, 2],
            "the head (truth 0.05, below min_truth) is injected but, being \
             deprecated, trails the live rows of its group"
        );
        assert_eq!(hits[2].id, head);

        let hits = WorkflowRepository::search_hierarchical_by_text(
            &pool,
            "available tools",
            10,
            0.3,
            false,
        )
        .await
        .unwrap();
        assert_eq!(hits.len(), 2, "default mode unchanged");
    }

    /// Seeds `canonical` gens 0..=1 (live, truth 1.0 and 0.6, goal
    /// "consider all available tools") and a head at gen 2 with
    /// `head_truth` and a goal the text query misses. Gen 0 sits at cosine
    /// similarity 0.8 to the axis-0 query vector, gen 1 at 1.0, and the head
    /// has no embedding, so on both search paths the head is ADDED. Returns
    /// `(ids by generation, query vector)`.
    async fn seed_threshold_lineage(
        pool: &sqlx::PgPool,
        canonical: &str,
        head_truth: f64,
    ) -> (Vec<uuid::Uuid>, Vec<f32>) {
        let mut qvec = vec![0.0f32; 1536];
        qvec[0] = 1.0;
        let mut near = vec![0.0f32; 1536];
        near[0] = 0.8;
        near[1] = 0.6;
        let mut ids = Vec::new();
        for (g, goal, truth, emb) in [
            (0, "consider all available tools", 1.0, Some(&near)),
            (1, "consider all available tools", 0.6, Some(&qvec)),
            (2, "rewrite the plan", head_truth, None),
        ] {
            let id = uuid::Uuid::new_v4();
            WorkflowRepository::insert_root(
                pool,
                id,
                canonical,
                g,
                goal,
                None,
                serde_json::json!({}),
            )
            .await
            .unwrap();
            WorkflowRepository::set_truth_value(pool, id, truth)
                .await
                .unwrap();
            if let Some(v) = emb {
                WorkflowRepository::set_goal_embedding(pool, id, v)
                    .await
                    .unwrap();
            }
            ids.push(id);
        }
        (ids, qvec)
    }

    /// Text path: "deprecated" is `truth_value < min_truth` for the CALLER's
    /// `min_truth`, not a constant. A 0.4 head leads at 0.3 and trails at
    /// 0.5; a 0.05 head leads at 0.0. Each case fails a hardcoded threshold
    /// (`< 0.3` fails 0.5, `<= 0.05` fails 0.5, any constant above 0.05
    /// fails 0.0).
    #[sqlx::test(migrations = "../../migrations")]
    async fn search_hierarchical_by_text_deprecation_follows_min_truth(pool: sqlx::PgPool) {
        let (ids, _) = seed_threshold_lineage(&pool, "text-threshold-test", 0.4).await;
        let order = |hits: Vec<HierarchicalWorkflowRow>| -> Vec<uuid::Uuid> {
            hits.iter().map(|h| h.id).collect()
        };
        let leads = vec![ids[2], ids[1], ids[0]];
        let trails = vec![ids[1], ids[0], ids[2]];

        let p = &pool;
        let at = move |min_truth: f64| {
            WorkflowRepository::search_hierarchical_by_text(
                p,
                "available tools",
                10,
                min_truth,
                true,
            )
        };
        assert_eq!(
            order(at(0.3).await.unwrap()),
            leads,
            "0.4 head at min_truth 0.3 is live"
        );
        assert_eq!(
            order(at(0.5).await.unwrap()),
            trails,
            "0.4 head at min_truth 0.5 is deprecated"
        );

        WorkflowRepository::set_truth_value(&pool, ids[2], 0.05)
            .await
            .unwrap();
        assert_eq!(
            order(at(0.0).await.unwrap()),
            leads,
            "0.05 head at min_truth 0.0 is live"
        );
        assert_eq!(
            order(at(0.3).await.unwrap()),
            trails,
            "0.05 head at min_truth 0.3 is deprecated"
        );
    }

    /// Embedding path, the same thresholds. A deprecated head takes its
    /// group's WORST distance, which here is gen 0's: the tie is decided by
    /// the `deprecated` tiebreak alone (`injected DESC` would put the head
    /// first). A live head takes the BEST distance, gen 1's. The statement
    /// spells the predicate twice (tiebreak column, distance CASE); with
    /// either copy on a constant `< 0.3`, the 0.5 case comes out by
    /// generation `[1, 2, 0]` instead of `[1, 0, 2]`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn find_hierarchical_by_embedding_deprecation_follows_min_truth(pool: sqlx::PgPool) {
        let (ids, qvec) = seed_threshold_lineage(&pool, "embed-threshold-test", 0.4).await;
        let order = |hits: Vec<HierarchicalWorkflowRow>| -> Vec<uuid::Uuid> {
            hits.iter().map(|h| h.id).collect()
        };
        let leads = vec![ids[2], ids[1], ids[0]];
        let trails = vec![ids[1], ids[0], ids[2]];

        let (p, q) = (&pool, &qvec[..]);
        let at = move |min_truth: f64| {
            WorkflowRepository::find_hierarchical_by_embedding(p, q, 0.5, min_truth, 10, true)
        };
        assert_eq!(
            order(at(0.3).await.unwrap()),
            leads,
            "0.4 head at min_truth 0.3 is live"
        );
        assert_eq!(
            order(at(0.5).await.unwrap()),
            trails,
            "0.4 head at min_truth 0.5 is deprecated"
        );

        WorkflowRepository::set_truth_value(&pool, ids[2], 0.05)
            .await
            .unwrap();
        assert_eq!(
            order(at(0.0).await.unwrap()),
            leads,
            "0.05 head at min_truth 0.0 is live"
        );
        assert_eq!(
            order(at(0.3).await.unwrap()),
            trails,
            "0.05 head at min_truth 0.3 is deprecated"
        );
    }
}
