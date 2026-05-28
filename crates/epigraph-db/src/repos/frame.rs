//! Frame of discernment repository
//!
//! CRUD operations for DS frames and claim-frame assignments.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use tracing::{instrument, warn};
use uuid::Uuid;

/// A row from the frames table.
///
/// `properties` is a JSONB bag for per-frame epistemic overrides — see
/// `migrations/044_frames_properties.sql`. Conventional keys:
///   * `intra_evidence_locality_factor` (float) — locality-discount
///     multiplier for this frame; overrides `calibration.toml`'s global
///     default when set.
///   * `evidence_type_weights` (object) — per-frame override map for
///     evidence-type weights (Phase 4 of issue #197). Keys are
///     evidence-type strings (lowercased on read), values are floats
///     in `[0.0, 1.0]`. Patches the global `calibration.toml`
///     `[evidence_type_weights]` table at combine time for this frame
///     only. See `get_per_frame_evidence_type_weights` /
///     `set_evidence_type_weight`.
#[derive(Debug, Clone, FromRow)]
pub struct FrameRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub hypotheses: Vec<String>,
    pub parent_frame_id: Option<Uuid>,
    pub is_refinable: bool,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub properties: serde_json::Value,
}

/// A row from the claim_frames junction table
#[derive(Debug, Clone, FromRow)]
pub struct ClaimFrameRow {
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    pub hypothesis_index: Option<i32>,
}

/// Repository for Frame operations
pub struct FrameRepository;

impl FrameRepository {
    /// Create a new frame of discernment
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if a frame with the same name exists.
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, hypotheses))]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        description: Option<&str>,
        hypotheses: &[String],
    ) -> Result<FrameRow, DbError> {
        let row: FrameRow = sqlx::query_as(
            r#"
            INSERT INTO frames (name, description, hypotheses)
            VALUES ($1, $2, $3)
            RETURNING id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(hypotheses)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// Get a frame by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<FrameRow>, DbError> {
        let row: Option<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            FROM frames
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Get a frame by name
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_name(pool: &PgPool, name: &str) -> Result<Option<FrameRow>, DbError> {
        let row: Option<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            FROM frames
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// List frames with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            FROM frames
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

    /// Get all claims assigned to a frame
    ///
    /// Returns claim IDs and their optional hypothesis index within the frame.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_claims_in_frame(
        pool: &PgPool,
        frame_id: Uuid,
    ) -> Result<Vec<ClaimFrameRow>, DbError> {
        let rows: Vec<ClaimFrameRow> = sqlx::query_as(
            r#"
            SELECT claim_id, frame_id, hypothesis_index
            FROM claim_frames
            WHERE frame_id = $1
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Assign a claim to a frame with an optional hypothesis index
    ///
    /// Uses ON CONFLICT to update the hypothesis_index if the assignment exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn assign_claim(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
        hypothesis_index: Option<i32>,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index)
            VALUES ($1, $2, $3)
            ON CONFLICT (claim_id, frame_id) DO UPDATE
            SET hypothesis_index = EXCLUDED.hypothesis_index
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .bind(hypothesis_index)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Create a refinement of an existing frame
    ///
    /// The parent frame must have `is_refinable = true`. The new frame's
    /// `parent_frame_id` points back to the parent.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, hypotheses))]
    pub async fn create_refinement(
        pool: &PgPool,
        parent_frame_id: Uuid,
        name: &str,
        description: Option<&str>,
        hypotheses: &[String],
    ) -> Result<FrameRow, DbError> {
        let row: FrameRow = sqlx::query_as(
            r#"
            INSERT INTO frames (name, description, hypotheses, parent_frame_id)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            "#,
        )
        .bind(name)
        .bind(description)
        .bind(hypotheses)
        .bind(parent_frame_id)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// List child frames (direct refinements) of a frame
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_children(pool: &PgPool, frame_id: Uuid) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            FROM frames
            WHERE parent_frame_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Walk up the parent chain from a frame to the root
    ///
    /// Returns frames from the given frame up to (and including) the root.
    /// Uses a recursive CTE to traverse the hierarchy.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_ancestry(pool: &PgPool, frame_id: Uuid) -> Result<Vec<FrameRow>, DbError> {
        let rows: Vec<FrameRow> = sqlx::query_as(
            r#"
            WITH RECURSIVE ancestry AS (
                SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
                FROM frames
                WHERE id = $1
                UNION ALL
                SELECT f.id, f.name, f.description, f.hypotheses, f.parent_frame_id, f.is_refinable, f.version, f.created_at, f.properties
                FROM frames f
                JOIN ancestry a ON f.id = a.parent_frame_id
            )
            SELECT id, name, description, hypotheses, parent_frame_id, is_refinable, version, created_at, properties
            FROM ancestry
            "#,
        )
        .bind(frame_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get the hypothesis_index for a claim within a frame
    ///
    /// Returns the claim-frame assignment row if the claim is assigned to the frame.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_claim_assignment(
        pool: &PgPool,
        claim_id: Uuid,
        frame_id: Uuid,
    ) -> Result<Option<ClaimFrameRow>, DbError> {
        let row: Option<ClaimFrameRow> = sqlx::query_as(
            r#"
            SELECT claim_id, frame_id, hypothesis_index
            FROM claim_frames
            WHERE claim_id = $1 AND frame_id = $2
            "#,
        )
        .bind(claim_id)
        .bind(frame_id)
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Count total frames
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count(pool: &PgPool) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM frames")
            .fetch_one(pool)
            .await?;

        Ok(row.0)
    }

    /// Read the per-frame `intra_evidence_locality_factor` override, if any.
    ///
    /// Returns `Ok(None)` when:
    ///   * the frame row doesn't exist,
    ///   * `properties` does not contain the `intra_evidence_locality_factor`
    ///     key,
    ///   * the key's value isn't a number (i.e. the operator wrote
    ///     garbage — we treat that as "no override" rather than panic).
    ///
    /// Callers should fall back to the global default from
    /// `calibration.toml::evidence_locality.intra_evidence_locality_factor`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` only on actual DB failure. Missing
    /// rows / missing keys return `Ok(None)`, not an error — the consumer
    /// is expected to use a calibration default in that case.
    #[instrument(skip(pool))]
    pub async fn get_intra_evidence_locality_factor(
        pool: &PgPool,
        frame_id: Uuid,
    ) -> Result<Option<f64>, DbError> {
        // `properties->>'intra_evidence_locality_factor'` returns TEXT.
        // Casting to FLOAT8 inside the SQL would panic on malformed
        // values; safer to fetch the TEXT and parse in Rust so the worst
        // case is a benign None.
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT properties->>'intra_evidence_locality_factor' FROM frames WHERE id = $1",
        )
        .bind(frame_id)
        .fetch_optional(pool)
        .await?;
        let Some((Some(raw),)) = row else {
            return Ok(None);
        };
        Ok(raw.parse::<f64>().ok())
    }

    /// Set a single key on `frames.properties`. Operator/admin use; the
    /// main intent is per-frame `intra_evidence_locality_factor` overrides.
    ///
    /// Uses `||` (JSONB merge) so existing keys are preserved.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, value))]
    pub async fn set_property(
        pool: &PgPool,
        frame_id: Uuid,
        key: &str,
        value: &serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE frames
               SET properties = properties || jsonb_build_object($2::text, $3::jsonb)
             WHERE id = $1
            "#,
        )
        .bind(frame_id)
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Read the per-frame `evidence_type_weights` override map, if any.
    /// Phase 4 of issue #197.
    ///
    /// Returns `Ok(None)` when:
    ///   * the frame row doesn't exist,
    ///   * `properties` does not contain the `evidence_type_weights` key,
    ///   * the key's value is not a JSON object (operator wrote garbage),
    ///   * the JSON object is empty after parsing (no usable entries).
    ///
    /// Object entries are parsed:
    ///   * key normalised to lowercase (matches
    ///     `CalibrationConfig::get_evidence_type_weight`),
    ///   * value coerced via `as_f64()`; non-numeric values are dropped
    ///     with a `warn!` log (operator misspelled the weight),
    ///   * values outside `[0.0, 1.0]` are dropped with a `warn!` log.
    ///     The `[0.0, 1.0]` clamp matches Shafer's reliability semantics
    ///     (a discount, not an amplification). This is the Phase 4 Q10
    ///     locked decision — operators wanting `reference > 1.0` for
    ///     textbook frames are out of scope; widen later if needed.
    ///
    /// Callers fall back to `CalibrationConfig::get_evidence_type_weight`
    /// when this returns `None` or when the returned map does not contain
    /// the BBA's evidence-type key.
    ///
    /// **Vocabulary warning**: this accessor does NOT warn on unknown
    /// keys (keys not in `calibration.evidence_type_weights` ∪ aliases ∪
    /// relationship-vocab). That warning happens at the call-site in
    /// `recompute_combined_belief`, which has the `CalibrationConfig`
    /// loaded — keeping the repo layer dependency-free of engine types.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` only on actual DB failure. Missing
    /// rows / missing keys / malformed JSON return `Ok(None)`, not an
    /// error — the consumer is expected to fall back to the global
    /// calibration in that case.
    #[instrument(skip(pool))]
    pub async fn get_per_frame_evidence_type_weights(
        pool: &PgPool,
        frame_id: Uuid,
    ) -> Result<Option<HashMap<String, f64>>, DbError> {
        let row: Option<(Option<serde_json::Value>,)> =
            sqlx::query_as("SELECT properties->'evidence_type_weights' FROM frames WHERE id = $1")
                .bind(frame_id)
                .fetch_optional(pool)
                .await?;
        let Some((Some(value),)) = row else {
            return Ok(None);
        };
        let serde_json::Value::Object(obj) = value else {
            warn!(
                %frame_id,
                "per-frame evidence_type_weights override is not a JSON object; ignoring"
            );
            return Ok(None);
        };
        let mut map: HashMap<String, f64> = HashMap::with_capacity(obj.len());
        for (raw_key, raw_val) in obj {
            let Some(w) = raw_val.as_f64() else {
                warn!(
                    %frame_id,
                    key = %raw_key,
                    "per-frame evidence_type_weights value is not numeric; dropping entry"
                );
                continue;
            };
            if !(0.0..=1.0).contains(&w) || !w.is_finite() {
                warn!(
                    %frame_id,
                    key = %raw_key,
                    value = %w,
                    "per-frame evidence_type_weights value out of [0.0, 1.0]; dropping entry"
                );
                continue;
            }
            map.insert(raw_key.to_lowercase(), w);
        }
        if map.is_empty() {
            return Ok(None);
        }
        Ok(Some(map))
    }

    /// Set a single per-frame evidence-type weight. Convenience wrapper
    /// over `set_property` for the common single-key write path.
    /// Phase 4 of issue #197.
    ///
    /// Reads the existing `evidence_type_weights` object (if any), merges
    /// the new key, writes back. The key is NOT normalised on write —
    /// readers normalise on read, so `"observation"` and `"OBSERVATION"`
    /// in the JSONB resolve to the same effective entry but the JSONB
    /// stores what the operator typed (an audit-trail consideration).
    ///
    /// Does NOT validate the evidence_type key against calibration;
    /// operators may pre-register weights for evidence types not yet in
    /// `calibration.toml`. Validation happens at read time via a warn-log
    /// at the helper call-site (Q8 locked: loose validation).
    ///
    /// Does NOT validate the weight against `[0.0, 1.0]`; range-check
    /// happens at read time in `get_per_frame_evidence_type_weights`,
    /// dropping out-of-range entries with a warn-log (Q10 locked).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` on actual DB failure.
    #[instrument(skip(pool))]
    pub async fn set_evidence_type_weight(
        pool: &PgPool,
        frame_id: Uuid,
        evidence_type: &str,
        weight: f64,
    ) -> Result<(), DbError> {
        // Read existing map (raw, NOT through the validating accessor — we
        // want to preserve any operator-written entries verbatim during
        // the merge, even ones the validator would drop on read).
        let row: Option<(Option<serde_json::Value>,)> =
            sqlx::query_as("SELECT properties->'evidence_type_weights' FROM frames WHERE id = $1")
                .bind(frame_id)
                .fetch_optional(pool)
                .await?;
        let mut obj = match row {
            Some((Some(serde_json::Value::Object(map)),)) => map,
            _ => serde_json::Map::new(),
        };
        obj.insert(evidence_type.to_string(), serde_json::Value::from(weight));
        let merged = serde_json::Value::Object(obj);
        Self::set_property(pool, frame_id, "evidence_type_weights", &merged).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_row_has_expected_fields() {
        let _row = FrameRow {
            id: Uuid::new_v4(),
            name: "test_frame".to_string(),
            description: Some("A test frame".to_string()),
            hypotheses: vec!["h1".to_string(), "h2".to_string()],
            parent_frame_id: None,
            is_refinable: true,
            version: 1,
            created_at: Utc::now(),
            properties: serde_json::json!({}),
        };
    }

    #[test]
    fn claim_frame_row_has_expected_fields() {
        let _row = ClaimFrameRow {
            claim_id: Uuid::new_v4(),
            frame_id: Uuid::new_v4(),
            hypothesis_index: Some(0),
        };
    }
}
