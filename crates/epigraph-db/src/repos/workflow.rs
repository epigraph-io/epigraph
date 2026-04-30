//! Repository for workflow claim operations.
//!
//! Workflows are claims labeled with 'workflow' that represent
//! reusable research procedures with variant lineages.

use sqlx::PgPool;
use uuid::Uuid;

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
                     WHERE e2.target_id = b.id AND e2.relationship = 'variant_of' LIMIT 1) AS parent_id \
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
                     WHERE e2.target_id = b.id AND e2.relationship = 'variant_of' LIMIT 1) AS parent_id \
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

    /// Find all descendants of a workflow via `variant_of` edges (for cascade deprecation).
    pub async fn find_descendants(
        pool: &PgPool,
        workflow_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "WITH RECURSIVE descendants AS ( \
                 SELECT source_id AS id FROM edges \
                 WHERE target_id = $1 AND relationship = 'variant_of' \
                 UNION ALL \
                 SELECT e.source_id FROM edges e \
                 JOIN descendants d ON e.target_id = d.id \
                 WHERE e.relationship = 'variant_of' \
             ) \
             SELECT id FROM descendants",
        )
        .bind(workflow_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Walk up `variant_of` edges to find the lineage root ancestor.
    ///
    /// Returns `workflow_id` itself if it has no parent (is already a root).
    /// The root is the ancestor with no outgoing `variant_of` edge.
    pub async fn find_lineage_root(pool: &PgPool, workflow_id: Uuid) -> Result<Uuid, sqlx::Error> {
        let root: Option<(Uuid,)> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT $1::uuid AS id
                UNION ALL
                SELECT e.target_id AS id
                FROM ancestors a
                JOIN edges e ON e.source_id = a.id
                    AND e.relationship = 'variant_of'
                    AND e.source_type = 'claim' AND e.target_type = 'claim'
            )
            SELECT a.id FROM ancestors a
            WHERE NOT EXISTS (
                SELECT 1 FROM edges e
                WHERE e.source_id = a.id
                  AND e.relationship = 'variant_of'
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

    /// Search hierarchical workflows by free-text query against `goal` and
    /// `canonical_name`. ILIKE pattern; ranks newest first by `created_at`.
    ///
    /// Used by `GET /api/v1/workflows/hierarchical/search`.
    ///
    /// # Errors
    /// Returns `sqlx::Error` if the database query fails.
    pub async fn search_hierarchical_by_text(
        pool: &PgPool,
        query: &str,
        limit: i64,
    ) -> Result<Vec<HierarchicalWorkflowRow>, sqlx::Error> {
        let pattern = format!("%{}%", query.trim());
        sqlx::query_as::<_, HierarchicalWorkflowRow>(
            "SELECT id, canonical_name, generation, goal, parent_id, metadata, created_at \
             FROM workflows \
             WHERE goal ILIKE $1 OR canonical_name ILIKE $1 \
             ORDER BY created_at DESC, id ASC \
             LIMIT $2",
        )
        .bind(&pattern)
        .bind(limit)
        .fetch_all(pool)
        .await
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

        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "sensor", 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canonical_name, "data-pipeline-v1");

        // canonical_name match also works
        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "deploy-canary", 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].canonical_name, "deploy-canary");

        // limit respected
        let hits = WorkflowRepository::search_hierarchical_by_text(&pool, "%", 1)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
    }
}
