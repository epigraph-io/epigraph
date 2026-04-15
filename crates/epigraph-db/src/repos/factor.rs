//! Factor graph persistence: factors and belief propagation messages.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

/// A factor row from the database.
#[derive(Debug, Clone)]
pub struct FactorRow {
    pub id: Uuid,
    pub factor_type: String,
    pub variable_ids: Vec<Uuid>,
    pub potential: JsonValue,
    pub description: Option<String>,
    pub frame_id: Option<Uuid>,
    pub properties: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A BP message row from the database.
#[derive(Debug, Clone)]
pub struct BpMessageRow {
    pub id: Uuid,
    pub direction: String,
    pub factor_id: Uuid,
    pub variable_id: Uuid,
    pub message: JsonValue,
    pub iteration: i32,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub struct FactorRepository;

impl FactorRepository {
    /// Insert a new factor.
    pub async fn insert(
        pool: &PgPool,
        factor_type: &str,
        variable_ids: &[Uuid],
        potential: &JsonValue,
        description: Option<&str>,
        frame_id: Option<Uuid>,
    ) -> Result<Uuid, crate::DbError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO factors (factor_type, variable_ids, potential, description, frame_id) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(factor_type)
        .bind(variable_ids)
        .bind(potential)
        .bind(description)
        .bind(frame_id)
        .fetch_one(pool)
        .await
        .map_err(crate::DbError::from)?;
        Ok(row.0)
    }

    /// Get a factor by ID.
    pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<FactorRow>, crate::DbError> {
        let row = sqlx::query_as::<_, (Uuid, String, Vec<Uuid>, JsonValue, Option<String>, Option<Uuid>, JsonValue, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, factor_type, variable_ids, potential, description, frame_id, properties, created_at \
             FROM factors WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(row.map(
            |(
                id,
                factor_type,
                variable_ids,
                potential,
                description,
                frame_id,
                properties,
                created_at,
            )| {
                FactorRow {
                    id,
                    factor_type,
                    variable_ids,
                    potential,
                    description,
                    frame_id,
                    properties,
                    created_at,
                }
            },
        ))
    }

    /// Get all factors that reference a given claim (variable).
    pub async fn get_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<FactorRow>, crate::DbError> {
        let rows = sqlx::query_as::<_, (Uuid, String, Vec<Uuid>, JsonValue, Option<String>, Option<Uuid>, JsonValue, chrono::DateTime<chrono::Utc>)>(
            "SELECT id, factor_type, variable_ids, potential, description, frame_id, properties, created_at \
             FROM factors WHERE $1 = ANY(variable_ids)",
        )
        .bind(claim_id)
        .fetch_all(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    factor_type,
                    variable_ids,
                    potential,
                    description,
                    frame_id,
                    properties,
                    created_at,
                )| {
                    FactorRow {
                        id,
                        factor_type,
                        variable_ids,
                        potential,
                        description,
                        frame_id,
                        properties,
                        created_at,
                    }
                },
            )
            .collect())
    }

    /// Get all factors, optionally filtered by frame.
    pub async fn get_all(
        pool: &PgPool,
        frame_id: Option<Uuid>,
    ) -> Result<Vec<FactorRow>, crate::DbError> {
        let rows = if let Some(fid) = frame_id {
            sqlx::query_as::<_, (Uuid, String, Vec<Uuid>, JsonValue, Option<String>, Option<Uuid>, JsonValue, chrono::DateTime<chrono::Utc>)>(
                "SELECT id, factor_type, variable_ids, potential, description, frame_id, properties, created_at \
                 FROM factors WHERE frame_id = $1 ORDER BY created_at",
            )
            .bind(fid)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as::<_, (Uuid, String, Vec<Uuid>, JsonValue, Option<String>, Option<Uuid>, JsonValue, chrono::DateTime<chrono::Utc>)>(
                "SELECT id, factor_type, variable_ids, potential, description, frame_id, properties, created_at \
                 FROM factors ORDER BY created_at",
            )
            .fetch_all(pool)
            .await
        }.map_err(crate::DbError::from)?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    factor_type,
                    variable_ids,
                    potential,
                    description,
                    frame_id,
                    properties,
                    created_at,
                )| {
                    FactorRow {
                        id,
                        factor_type,
                        variable_ids,
                        potential,
                        description,
                        frame_id,
                        properties,
                        created_at,
                    }
                },
            )
            .collect())
    }

    /// Upsert a BP message (factor↔variable, one direction).
    pub async fn upsert_bp_message(
        pool: &PgPool,
        factor_id: Uuid,
        variable_id: Uuid,
        direction: &str,
        message: &JsonValue,
        iteration: i32,
    ) -> Result<(), crate::DbError> {
        sqlx::query(
            "INSERT INTO bp_messages (factor_id, variable_id, direction, message, iteration) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (factor_id, variable_id, direction) \
             DO UPDATE SET message = $4, iteration = $5, updated_at = NOW()",
        )
        .bind(factor_id)
        .bind(variable_id)
        .bind(direction)
        .bind(message)
        .bind(iteration)
        .execute(pool)
        .await
        .map_err(crate::DbError::from)?;
        Ok(())
    }

    /// Get all BP messages for a given factor.
    pub async fn get_bp_messages_for_factor(
        pool: &PgPool,
        factor_id: Uuid,
    ) -> Result<Vec<BpMessageRow>, crate::DbError> {
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Uuid,
                Uuid,
                JsonValue,
                i32,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            "SELECT id, direction, factor_id, variable_id, message, iteration, updated_at \
             FROM bp_messages WHERE factor_id = $1",
        )
        .bind(factor_id)
        .fetch_all(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(rows
            .into_iter()
            .map(
                |(id, direction, factor_id, variable_id, message, iteration, updated_at)| {
                    BpMessageRow {
                        id,
                        direction,
                        factor_id,
                        variable_id,
                        message,
                        iteration,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    /// Get all BP messages targeting a given variable.
    pub async fn get_bp_messages_for_variable(
        pool: &PgPool,
        variable_id: Uuid,
    ) -> Result<Vec<BpMessageRow>, crate::DbError> {
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Uuid,
                Uuid,
                JsonValue,
                i32,
                chrono::DateTime<chrono::Utc>,
            ),
        >(
            "SELECT id, direction, factor_id, variable_id, message, iteration, updated_at \
             FROM bp_messages WHERE variable_id = $1",
        )
        .bind(variable_id)
        .fetch_all(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(rows
            .into_iter()
            .map(
                |(id, direction, factor_id, variable_id, message, iteration, updated_at)| {
                    BpMessageRow {
                        id,
                        direction,
                        factor_id,
                        variable_id,
                        message,
                        iteration,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    /// Clear all BP messages (reset before new propagation run).
    pub async fn clear_bp_messages(pool: &PgPool) -> Result<u64, crate::DbError> {
        let result = sqlx::query("DELETE FROM bp_messages")
            .execute(pool)
            .await
            .map_err(crate::DbError::from)?;
        Ok(result.rows_affected())
    }
}
