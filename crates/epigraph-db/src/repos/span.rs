//! Repository for agent span operations (OTel-compatible tracing).

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A row from the agent_spans table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct SpanRow {
    pub id: Uuid,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub span_name: String,
    pub span_kind: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<f64>,
    pub status: String,
    pub status_message: Option<String>,
    pub agent_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub attributes: serde_json::Value,
    pub generated_ids: Vec<Uuid>,
    pub consumed_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

pub struct SpanRepository;

impl SpanRepository {
    /// Open a new span. Returns the row with server-generated id and started_at.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, attributes))]
    pub async fn insert(
        pool: &PgPool,
        trace_id: &str,
        span_id: &str,
        parent_span_id: Option<&str>,
        span_name: &str,
        span_kind: &str,
        agent_id: Option<Uuid>,
        user_id: Option<Uuid>,
        session_id: Option<Uuid>,
        attributes: &serde_json::Value,
    ) -> Result<SpanRow, sqlx::Error> {
        sqlx::query_as::<_, SpanRow>(
            r#"
            INSERT INTO agent_spans (
                trace_id, span_id, parent_span_id,
                span_name, span_kind,
                agent_id, user_id, session_id,
                attributes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(trace_id)
        .bind(span_id)
        .bind(parent_span_id)
        .bind(span_name)
        .bind(span_kind)
        .bind(agent_id)
        .bind(user_id)
        .bind(session_id)
        .bind(attributes)
        .fetch_one(pool)
        .await
    }

    /// Close a span: set ended_at, duration_ms, status, merge attributes,
    /// and set generated/consumed IDs.
    #[instrument(skip(pool, attributes))]
    pub async fn close(
        pool: &PgPool,
        id: Uuid,
        status: &str,
        status_message: Option<&str>,
        attributes: Option<&serde_json::Value>,
        generated_ids: &[Uuid],
        consumed_ids: &[Uuid],
    ) -> Result<SpanRow, sqlx::Error> {
        sqlx::query_as::<_, SpanRow>(
            r#"
            UPDATE agent_spans
            SET ended_at = NOW(),
                duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000,
                status = $2,
                status_message = $3,
                attributes = CASE
                    WHEN $4::jsonb IS NOT NULL THEN attributes || $4::jsonb
                    ELSE attributes
                END,
                generated_ids = $5,
                consumed_ids = $6
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(status_message)
        .bind(attributes)
        .bind(generated_ids)
        .bind(consumed_ids)
        .fetch_one(pool)
        .await
    }

    /// List all spans for a trace, ordered by started_at (waterfall view).
    #[instrument(skip(pool))]
    pub async fn list_by_trace(pool: &PgPool, trace_id: &str) -> Result<Vec<SpanRow>, sqlx::Error> {
        sqlx::query_as::<_, SpanRow>(
            r#"
            SELECT * FROM agent_spans
            WHERE trace_id = $1
            ORDER BY started_at ASC
            "#,
        )
        .bind(trace_id)
        .fetch_all(pool)
        .await
    }

    /// Get a single span by ID.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<SpanRow>, sqlx::Error> {
        sqlx::query_as::<_, SpanRow>("SELECT * FROM agent_spans WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }
}
