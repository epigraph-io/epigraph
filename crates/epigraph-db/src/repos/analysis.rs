//! Repository for analysis record operations.
//!
//! Analyses represent interpretive reasoning over evidence,
//! linked to claims via `concludes` edges and to evidence via `interpreted_by` edges.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Public analysis record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisRecord {
    pub id: Uuid,
    pub analysis_type: String,
    pub method_description: String,
    pub inference_path: String,
    pub constraints: Option<String>,
    pub coverage_context: serde_json::Value,
    pub input_evidence_ids: Vec<Uuid>,
    pub agent_id: Uuid,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AnalysisRow {
    id: Uuid,
    analysis_type: String,
    method_description: String,
    inference_path: String,
    constraints: Option<String>,
    coverage_context: serde_json::Value,
    input_evidence_ids: Vec<Uuid>,
    agent_id: Uuid,
    properties: serde_json::Value,
    created_at: DateTime<Utc>,
}

/// Lightweight claim summary for analysis results.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClaimSummary {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ClaimSummaryRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    created_at: DateTime<Utc>,
}

fn from_row(row: AnalysisRow) -> AnalysisRecord {
    AnalysisRecord {
        id: row.id,
        analysis_type: row.analysis_type,
        method_description: row.method_description,
        inference_path: row.inference_path,
        constraints: row.constraints,
        coverage_context: row.coverage_context,
        input_evidence_ids: row.input_evidence_ids,
        agent_id: row.agent_id,
        properties: row.properties,
        created_at: row.created_at,
    }
}

pub struct AnalysisRepository;

impl AnalysisRepository {
    /// Insert a single analysis record.
    pub async fn insert(pool: &PgPool, analysis: &AnalysisRecord) -> Result<Uuid, sqlx::Error> {
        sqlx::query(
            "INSERT INTO analyses (id, analysis_type, method_description, inference_path, \
             constraints, coverage_context, input_evidence_ids, agent_id, properties, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(analysis.id)
        .bind(&analysis.analysis_type)
        .bind(&analysis.method_description)
        .bind(&analysis.inference_path)
        .bind(analysis.constraints.as_deref())
        .bind(&analysis.coverage_context)
        .bind(&analysis.input_evidence_ids)
        .bind(analysis.agent_id)
        .bind(&analysis.properties)
        .bind(analysis.created_at)
        .execute(pool)
        .await?;
        Ok(analysis.id)
    }

    /// Retrieve an analysis by ID.
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<AnalysisRecord>, sqlx::Error> {
        let row: Option<AnalysisRow> = sqlx::query_as(
            "SELECT id, analysis_type, method_description, inference_path, \
             constraints, coverage_context, input_evidence_ids, agent_id, \
             properties, created_at \
             FROM analyses WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(from_row))
    }

    /// Find all analyses that produced a given claim (via `concludes` edges).
    pub async fn get_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<AnalysisRecord>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT a.id, a.analysis_type, a.method_description, a.inference_path, \
             a.constraints, a.coverage_context, a.input_evidence_ids, a.agent_id, \
             a.properties, a.created_at \
             FROM analyses a \
             JOIN edges e ON e.source_id = a.id \
             WHERE e.target_id = $1 \
               AND e.relationship = 'concludes' \
               AND e.source_type = 'analysis' \
               AND e.target_type = 'claim' \
               /* {EDGE_VISIBILITY:e} */ \
             ORDER BY a.created_at DESC",
            2,
        );
        let mut q = sqlx::query_as::<_, AnalysisRow>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<AnalysisRow> = q.fetch_all(executor).await?;
        Ok(rows.into_iter().map(from_row).collect())
    }

    /// Find all claims produced by an analysis (via `concludes` edges).
    pub async fn get_claims_for_analysis<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        analysis_id: Uuid,
    ) -> Result<Vec<ClaimSummary>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT c.id, c.content, c.truth_value, c.created_at \
             FROM claims c \
             JOIN edges e ON e.target_id = c.id \
             WHERE e.source_id = $1 \
               AND e.relationship = 'concludes' \
               AND e.source_type = 'analysis' \
               AND e.target_type = 'claim' \
               /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */ \
             ORDER BY c.truth_value DESC",
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimSummaryRow>(&sql).bind(analysis_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<ClaimSummaryRow> = q.fetch_all(executor).await?;
        Ok(rows
            .into_iter()
            .map(|r| ClaimSummary {
                id: r.id,
                content: r.content,
                truth_value: r.truth_value,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Whether a `provides_evidence` edge that `viewer` may see links an
    /// analysis with non-empty `properties.scope_limitations` to `claim_id`.
    ///
    /// Backs `has_explicit_scope` in `GET /api/v1/hypothesis/:id/status`
    /// (`routes/hypothesis.rs::hypothesis_status`). That flag feeds
    /// `evaluate_promotion`, so it decides `promotion.ready` and whether
    /// `NoExplicitScope` appears in `promotion.failures`. The handler used to
    /// run this EXISTS inline with no viewer (`F-SHARD6-A1`), so the verdict was
    /// computed from links the viewer may not see.
    ///
    /// # Where the tenancy comes from
    ///
    /// `analyses` has no tenancy of its own. Measured at migration head 100: it
    /// has no `visibility` or `owner_group_id` column, row-level security is
    /// off, and `pg_policies` has no rows for it. So no predicate can be written
    /// on `a`. The predicates go on the two relations that do carry tenancy:
    ///
    /// * `{EDGE_VISIBILITY:e}` on the link, which is where a group-private
    ///   `provides_evidence` edge is withheld;
    /// * `{VISIBILITY:c}` on the target claim, so the function answers `false`
    ///   for a claim the viewer may not read, rather than leaking one bit about
    ///   it. The route already 404s on such a claim before calling this; the
    ///   marker makes the function safe on its own.
    ///
    /// Both markers resolve to the one bind `$2`. The SQL body is otherwise the
    /// handler's, unchanged. Like the sibling
    /// `ExperimentRepository::count_completed_with_analysis`, it does not filter
    /// on `edges.valid_to`, so a retracted link still counts. This function
    /// changes tenancy only.
    pub async fn has_scope_limited_evidence_for<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT EXISTS ( \
               SELECT 1 FROM analyses a \
               JOIN edges e ON e.source_id = a.id \
                           AND e.source_type = 'analysis' \
                           AND e.target_id = $1 \
                           AND e.target_type = 'claim' \
                           AND e.relationship = 'provides_evidence' \
               JOIN claims c ON c.id = e.target_id \
               WHERE a.properties->>'scope_limitations' IS NOT NULL \
                 AND a.properties->'scope_limitations' != '[]'::jsonb \
                 /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */ \
             )",
            2,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_one(executor).await
    }

    /// Create an `interpreted_by` edge from evidence to analysis.
    pub async fn link_evidence(
        pool: &PgPool,
        evidence_id: Uuid,
        analysis_id: Uuid,
    ) -> Result<Uuid, sqlx::Error> {
        let edge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, $2, 'evidence', $3, 'analysis', 'interpreted_by', '{}'::jsonb) \
             ON CONFLICT DO NOTHING",
        )
        .bind(edge_id)
        .bind(evidence_id)
        .bind(analysis_id)
        .execute(pool)
        .await?;
        Ok(edge_id)
    }

    /// Create a `concludes` edge from analysis to claim.
    pub async fn link_claim(
        pool: &PgPool,
        analysis_id: Uuid,
        claim_id: Uuid,
    ) -> Result<Uuid, sqlx::Error> {
        let edge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, $2, 'analysis', $3, 'claim', 'concludes', '{}'::jsonb) \
             ON CONFLICT DO NOTHING",
        )
        .bind(edge_id)
        .bind(analysis_id)
        .bind(claim_id)
        .execute(pool)
        .await?;
        Ok(edge_id)
    }

    /// Atomic: insert analysis + create all `concludes` and `interpreted_by` edges.
    pub async fn persist_bundle(
        pool: &PgPool,
        analysis: &AnalysisRecord,
        claim_ids: &[Uuid],
        evidence_ids: &[Uuid],
    ) -> Result<Uuid, sqlx::Error> {
        let mut tx = pool.begin().await?;

        sqlx::query(
            "INSERT INTO analyses (id, analysis_type, method_description, inference_path, \
             constraints, coverage_context, input_evidence_ids, agent_id, properties, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(analysis.id)
        .bind(&analysis.analysis_type)
        .bind(&analysis.method_description)
        .bind(&analysis.inference_path)
        .bind(analysis.constraints.as_deref())
        .bind(&analysis.coverage_context)
        .bind(&analysis.input_evidence_ids)
        .bind(analysis.agent_id)
        .bind(&analysis.properties)
        .bind(analysis.created_at)
        .execute(&mut *tx)
        .await?;

        for &claim_id in claim_ids {
            let edge_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
                 VALUES ($1, $2, 'analysis', $3, 'claim', 'concludes', '{}'::jsonb) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(edge_id)
            .bind(analysis.id)
            .bind(claim_id)
            .execute(&mut *tx)
            .await?;
        }

        for &evidence_id in evidence_ids {
            let edge_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
                 VALUES ($1, $2, 'evidence', $3, 'analysis', 'interpreted_by', '{}'::jsonb) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(edge_id)
            .bind(evidence_id)
            .bind(analysis.id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(analysis.id)
    }
}
