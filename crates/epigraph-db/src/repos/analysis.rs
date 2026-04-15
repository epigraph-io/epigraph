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
    pub async fn get_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<AnalysisRecord>, sqlx::Error> {
        let rows: Vec<AnalysisRow> = sqlx::query_as(
            "SELECT a.id, a.analysis_type, a.method_description, a.inference_path, \
             a.constraints, a.coverage_context, a.input_evidence_ids, a.agent_id, \
             a.properties, a.created_at \
             FROM analyses a \
             JOIN edges e ON e.source_id = a.id \
             WHERE e.target_id = $1 \
               AND e.relationship = 'concludes' \
               AND e.source_type = 'analysis' \
               AND e.target_type = 'claim' \
             ORDER BY a.created_at DESC",
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(from_row).collect())
    }

    /// Find all claims produced by an analysis (via `concludes` edges).
    pub async fn get_claims_for_analysis(
        pool: &PgPool,
        analysis_id: Uuid,
    ) -> Result<Vec<ClaimSummary>, sqlx::Error> {
        let rows: Vec<ClaimSummaryRow> = sqlx::query_as(
            "SELECT c.id, c.content, c.truth_value, c.created_at \
             FROM claims c \
             JOIN edges e ON e.target_id = c.id \
             WHERE e.source_id = $1 \
               AND e.relationship = 'concludes' \
               AND e.source_type = 'analysis' \
               AND e.target_type = 'claim' \
             ORDER BY c.truth_value DESC",
        )
        .bind(analysis_id)
        .fetch_all(pool)
        .await?;
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
