//! Repository for analysis record operations.
//!
//! Analyses represent interpretive reasoning over evidence,
//! linked to claims via `concludes` edges and to evidence via `interpreted_by` edges.

use crate::errors::DbError;
use crate::repos::edge::EdgeRepository;
use crate::repos::edge_signature::EdgeSigningKey;
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

    /// Atomic: insert analysis + create all `concludes` and `interpreted_by` edges.
    ///
    /// Every edge is attested at INSERT by `key` (backlog `dae795f8`, ruling
    /// R-50): the request transport's own key (the API's), never the
    /// analysis' agent; unsigned with `key = None`. No unique index of `edges`
    /// covers these two relationships (migrations 091, 175), so the old
    /// `ON CONFLICT DO NOTHING` could not fire and is not carried over.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if a statement fails (nothing is written);
    /// `DbError::InvalidData` if a stored edge cannot be attested.
    pub async fn persist_bundle(
        pool: &PgPool,
        key: Option<EdgeSigningKey<'_>>,
        analysis: &AnalysisRecord,
        claim_ids: &[Uuid],
        evidence_ids: &[Uuid],
    ) -> Result<Uuid, DbError> {
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
            EdgeRepository::create_signed_conn(
                &mut tx,
                key,
                analysis.id,
                "analysis",
                claim_id,
                "claim",
                "concludes",
                None,
                None,
                None,
            )
            .await?;
        }

        for &evidence_id in evidence_ids {
            EdgeRepository::create_signed_conn(
                &mut tx,
                key,
                evidence_id,
                "evidence",
                analysis.id,
                "analysis",
                "interpreted_by",
                None,
                None,
                None,
            )
            .await?;
        }

        tx.commit().await?;
        Ok(analysis.id)
    }
}
