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

pub struct WorkflowRepository;

impl WorkflowRepository {
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
}
