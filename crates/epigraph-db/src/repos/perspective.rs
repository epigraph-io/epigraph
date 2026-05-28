//! Perspective repository
//!
//! CRUD operations for agent perspectives (viewpoints that contextualize evidence).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

/// A row from the perspectives table
#[derive(Debug, Clone, FromRow)]
pub struct PerspectiveRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_agent_id: Option<Uuid>,
    pub perspective_type: Option<String>,
    pub frame_ids: Option<Vec<Uuid>>,
    pub extraction_method: Option<String>,
    pub confidence_calibration: Option<f64>,
    /// Free-form jsonb. The frame-function feature reads
    /// `properties->'source_reliability'` — a map of evidence-type tag →
    /// reliability α ∈ [0,1] — to discount a shared evidence corpus from this
    /// perspective's viewpoint. See [`PerspectiveRow::source_reliability`].
    pub properties: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl PerspectiveRow {
    /// Per-perspective source-reliability map: evidence-type tag → α ∈ [0,1],
    /// read from `properties->'source_reliability'`.
    ///
    /// This is the "frame function": it lets one observer down-weight, say,
    /// `practitioner_interview` evidence to 0.4 while another trusts it at 1.0,
    /// yielding different beliefs over the *same* evidence. Returns `None` when
    /// the key is absent (the perspective falls back to legacy own-BBA scoping)
    /// and silently skips any entry whose value is not a finite number in
    /// `[0, 1]`.
    #[must_use]
    pub fn source_reliability(&self) -> Option<std::collections::HashMap<String, f64>> {
        let obj = self
            .properties
            .as_ref()?
            .get("source_reliability")?
            .as_object()?;
        let map: std::collections::HashMap<String, f64> = obj
            .iter()
            .filter_map(|(k, v)| {
                let a = v.as_f64()?;
                (a.is_finite() && (0.0..=1.0).contains(&a)).then(|| (k.clone(), a))
            })
            .collect();
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }
}

/// Repository for Perspective operations
pub struct PerspectiveRepository;

impl PerspectiveRepository {
    /// Create a new perspective
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        owner_agent_id: Option<Uuid>,
        perspective_type: Option<&str>,
        frame_ids: &[Uuid],
        extraction_method: Option<&str>,
        confidence_calibration: Option<f64>,
    ) -> Result<PerspectiveRow, DbError> {
        let row: PerspectiveRow = sqlx::query_as(
            r#"
            INSERT INTO perspectives
                (name, description, owner_agent_id, perspective_type, frame_ids,
                 extraction_method, confidence_calibration)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, name, description, owner_agent_id, perspective_type,
                      frame_ids, extraction_method, confidence_calibration, properties, created_at
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(owner_agent_id)
        .bind(perspective_type)
        .bind(frame_ids)
        .bind(extraction_method)
        .bind(confidence_calibration)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Set this perspective's source-reliability map (the frame function),
    /// merging it into `properties` under the `source_reliability` key without
    /// disturbing other `properties` entries.
    ///
    /// `reliability` maps an evidence-type tag (matching `mass_functions.
    /// evidence_type`) to α ∈ [0,1]. Pass an empty map to clear the override
    /// (the perspective then falls back to legacy own-BBA scoping).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, reliability))]
    pub async fn set_source_reliability(
        pool: &PgPool,
        id: Uuid,
        reliability: &std::collections::HashMap<String, f64>,
    ) -> Result<(), DbError> {
        let value = serde_json::to_value(reliability).unwrap_or(serde_json::Value::Null);
        sqlx::query(
            r#"
            UPDATE perspectives
            SET properties = jsonb_set(
                COALESCE(properties, '{}'::jsonb),
                '{source_reliability}',
                $2::jsonb,
                true
            )
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(value)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Ensure a synthetic "evidence_grounded" perspective row exists with the
    /// given id. Used by `auto_wire_ds_update` to satisfy the
    /// `mass_functions.perspective_id` FK while keeping each evidence submission
    /// distinguishable on the unique index `(claim, frame, agent, perspective)`.
    ///
    /// Idempotent — `ON CONFLICT DO NOTHING` so concurrent inserts are safe.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn ensure_evidence_perspective(
        pool: &PgPool,
        id: Uuid,
        owner_agent_id: Option<Uuid>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO perspectives (id, name, owner_agent_id, perspective_type)
            VALUES ($1, 'evidence_grounded', $2, 'evidence')
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(owner_agent_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Ensure a synthetic "edge_factor" perspective row exists with the given
    /// id (= edge UUID). Used by `auto_wire_ds_for_edge` to satisfy the
    /// `mass_functions.perspective_id` FK so each epistemic edge produces its
    /// own BBA row keyed by `(claim, frame, agent, edge_id)`.
    ///
    /// Idempotent — `ON CONFLICT DO NOTHING`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn ensure_edge_perspective(
        pool: &PgPool,
        id: Uuid,
        owner_agent_id: Option<Uuid>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO perspectives (id, name, owner_agent_id, perspective_type)
            VALUES ($1, 'edge_factor', $2, 'edge')
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(owner_agent_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Get a perspective by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<PerspectiveRow>, DbError> {
        let row: Option<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, properties, created_at
            FROM perspectives
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List perspectives by agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_agent(
        pool: &PgPool,
        agent_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let rows: Vec<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, properties, created_at
            FROM perspectives
            WHERE owner_agent_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(agent_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// List all perspectives with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PerspectiveRow>, DbError> {
        let rows: Vec<PerspectiveRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, owner_agent_id, perspective_type,
                   frame_ids, extraction_method, confidence_calibration, properties, created_at
            FROM perspectives
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perspective_row_has_expected_fields() {
        let _row = PerspectiveRow {
            id: Uuid::new_v4(),
            name: "skeptical_analysis".to_string(),
            description: Some("Critical evaluation perspective".to_string()),
            owner_agent_id: Some(Uuid::new_v4()),
            perspective_type: Some("analytical".to_string()),
            frame_ids: Some(vec![Uuid::new_v4()]),
            extraction_method: Some("ai_generated".to_string()),
            confidence_calibration: Some(0.8),
            properties: Some(serde_json::json!({})),
            created_at: Utc::now(),
        };
    }

    #[test]
    fn perspective_row_allows_none_optionals() {
        let _row = PerspectiveRow {
            id: Uuid::new_v4(),
            name: "minimal".to_string(),
            description: None,
            owner_agent_id: None,
            perspective_type: None,
            frame_ids: None,
            extraction_method: None,
            confidence_calibration: None,
            properties: None,
            created_at: Utc::now(),
        };
    }

    #[test]
    fn source_reliability_parses_valid_map() {
        let row = make_row(Some(serde_json::json!({
            "source_reliability": {
                "western_clinical": 0.95,
                "practitioner_interview": 0.4
            }
        })));
        let map = row.source_reliability().expect("map present");
        assert!((map["western_clinical"] - 0.95).abs() < f64::EPSILON);
        assert!((map["practitioner_interview"] - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn source_reliability_none_when_key_absent() {
        let row = make_row(Some(serde_json::json!({"other": 1})));
        assert!(row.source_reliability().is_none());
        let row_null = make_row(None);
        assert!(row_null.source_reliability().is_none());
    }

    #[test]
    fn source_reliability_skips_out_of_range_and_nonnumeric() {
        // 1.5 (>1), -0.2 (<0), and "high" (non-numeric) must be dropped;
        // only the valid 0.6 entry survives.
        let row = make_row(Some(serde_json::json!({
            "source_reliability": {
                "too_big": 1.5,
                "negative": -0.2,
                "stringy": "high",
                "ok": 0.6
            }
        })));
        let map = row.source_reliability().expect("one valid entry");
        assert_eq!(map.len(), 1);
        assert!((map["ok"] - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn source_reliability_none_when_all_entries_invalid() {
        // An object that parses but yields zero valid entries is None, not
        // Some(empty) — so the caller cleanly falls back to legacy scoping.
        let row = make_row(Some(serde_json::json!({
            "source_reliability": { "bad": 2.0 }
        })));
        assert!(row.source_reliability().is_none());
    }

    fn make_row(properties: Option<serde_json::Value>) -> PerspectiveRow {
        PerspectiveRow {
            id: Uuid::new_v4(),
            name: "observer".to_string(),
            description: None,
            owner_agent_id: None,
            perspective_type: Some("analytical".to_string()),
            frame_ids: None,
            extraction_method: None,
            confidence_calibration: None,
            properties,
            created_at: Utc::now(),
        }
    }
}
