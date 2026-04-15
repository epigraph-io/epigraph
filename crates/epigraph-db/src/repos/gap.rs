//! Repository for epistemic gap analysis operations.
//!
//! Gaps represent missing knowledge identified by comparing
//! graph-constrained and unconstrained analyses.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// A single gap identified between graph-constrained and unconstrained analyses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GapRecord {
    pub gap_type: String,
    pub severity: f64,
    pub unconstrained_claim: String,
    pub nearest_graph_claim: Option<String>,
    pub nearest_similarity: f64,
    pub graph_inference_path: Option<String>,
    pub recommendation: String,
}

/// Stored gap analysis result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GapAnalysisResult {
    pub id: Uuid,
    pub question: String,
    pub analysis_a_id: Option<Uuid>,
    pub analysis_b_id: Option<Uuid>,
    pub graph_claims_count: i32,
    pub unconstrained_claims_count: i32,
    pub matched_count: i32,
    pub gap_count: i32,
    pub proprietary_count: i32,
    pub confidence_boundary: Option<String>,
    pub gaps: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct GapAnalysisRow {
    id: Uuid,
    question: String,
    analysis_a_id: Option<Uuid>,
    analysis_b_id: Option<Uuid>,
    graph_claims_count: i32,
    unconstrained_claims_count: i32,
    matched_count: i32,
    gap_count: i32,
    proprietary_count: i32,
    confidence_boundary: Option<String>,
    gaps: serde_json::Value,
    created_at: DateTime<Utc>,
}

pub struct GapRepository;

impl GapRepository {
    /// Store a gap analysis result.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_gap_analysis(
        pool: &PgPool,
        question: &str,
        analysis_a_id: Option<Uuid>,
        analysis_b_id: Option<Uuid>,
        graph_claims_count: i32,
        unconstrained_claims_count: i32,
        matched_count: i32,
        gaps: &[GapRecord],
        proprietary_count: i32,
        confidence_boundary: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        #[allow(clippy::cast_possible_wrap)]
        let gap_count = gaps.len() as i32;
        let gaps_json = serde_json::to_value(gaps).unwrap_or(serde_json::json!([]));

        sqlx::query(
            "INSERT INTO gap_analyses (id, question, analysis_a_id, analysis_b_id, \
             graph_claims_count, unconstrained_claims_count, matched_count, gap_count, \
             proprietary_count, confidence_boundary, gaps, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())",
        )
        .bind(id)
        .bind(question)
        .bind(analysis_a_id)
        .bind(analysis_b_id)
        .bind(graph_claims_count)
        .bind(unconstrained_claims_count)
        .bind(matched_count)
        .bind(gap_count)
        .bind(proprietary_count)
        .bind(confidence_boundary)
        .bind(&gaps_json)
        .execute(pool)
        .await?;

        Ok(id)
    }

    /// Query past gap analyses with optional question text filter.
    pub async fn get_gap_analyses(
        pool: &PgPool,
        question_pattern: Option<&str>,
        limit: i64,
    ) -> Result<Vec<GapAnalysisResult>, sqlx::Error> {
        let rows: Vec<GapAnalysisRow> = if let Some(pattern) = question_pattern {
            let like = format!("%{pattern}%");
            sqlx::query_as(
                "SELECT id, question, analysis_a_id, analysis_b_id, graph_claims_count, \
                 unconstrained_claims_count, matched_count, gap_count, proprietary_count, \
                 confidence_boundary, gaps, created_at \
                 FROM gap_analyses WHERE question ILIKE $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(like)
            .bind(limit)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, question, analysis_a_id, analysis_b_id, graph_claims_count, \
                 unconstrained_claims_count, matched_count, gap_count, proprietary_count, \
                 confidence_boundary, gaps, created_at \
                 FROM gap_analyses ORDER BY created_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| GapAnalysisResult {
                id: r.id,
                question: r.question,
                analysis_a_id: r.analysis_a_id,
                analysis_b_id: r.analysis_b_id,
                graph_claims_count: r.graph_claims_count,
                unconstrained_claims_count: r.unconstrained_claims_count,
                matched_count: r.matched_count,
                gap_count: r.gap_count,
                proprietary_count: r.proprietary_count,
                confidence_boundary: r.confidence_boundary,
                gaps: r.gaps,
                created_at: r.created_at,
            })
            .collect())
    }
}
