//! Experiment and ExperimentResult repository.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct ExperimentRow {
    pub id: Uuid,
    pub hypothesis_id: Uuid,
    pub created_by: Uuid,
    pub method_ids: Option<Vec<Uuid>>,
    pub protocol: Option<String>,
    pub protocol_source: Option<serde_json::Value>,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ExperimentResultRow {
    pub id: Uuid,
    pub experiment_id: Uuid,
    pub data_source: String,
    pub raw_measurements: serde_json::Value,
    pub measurement_count: i32,
    pub effective_random_error: Option<serde_json::Value>,
    pub processed_data: Option<serde_json::Value>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub struct ExperimentRepository;

impl ExperimentRepository {
    #[instrument(skip(pool))]
    pub async fn create(
        pool: &PgPool,
        hypothesis_id: Uuid,
        created_by: Uuid,
        method_ids: Option<&[Uuid]>,
        protocol: Option<&str>,
        protocol_source: Option<&serde_json::Value>,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO experiments (hypothesis_id, created_by, method_ids, protocol, protocol_source)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(hypothesis_id)
        .bind(created_by)
        .bind(method_ids)
        .bind(protocol)
        .bind(protocol_source)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ExperimentRow>, DbError> {
        let row = sqlx::query_as::<_, ExperimentRow>("SELECT * FROM experiments WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn get_for_hypothesis(
        pool: &PgPool,
        hypothesis_id: Uuid,
    ) -> Result<Vec<ExperimentRow>, DbError> {
        let rows = sqlx::query_as::<_, ExperimentRow>(
            "SELECT * FROM experiments WHERE hypothesis_id = $1 ORDER BY created_at DESC",
        )
        .bind(hypothesis_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    #[instrument(skip(pool))]
    pub async fn update_status(pool: &PgPool, id: Uuid, status: &str) -> Result<(), DbError> {
        let now = if status == "running" {
            Some(Utc::now())
        } else {
            None
        };
        let completed = if status == "complete" || status == "failed" {
            Some(Utc::now())
        } else {
            None
        };

        sqlx::query(
            r#"
            UPDATE experiments
            SET status = $2,
                started_at = COALESCE($3, started_at),
                completed_at = COALESCE($4, completed_at)
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(now)
        .bind(completed)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Count completed experiments for a hypothesis that have analysis nodes.
    #[instrument(skip(pool))]
    pub async fn count_completed_with_analysis(
        pool: &PgPool,
        hypothesis_id: Uuid,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(DISTINCT e.id)
            FROM experiments e
            JOIN experiment_results er ON er.experiment_id = e.id
            JOIN edges ed ON ed.source_type = 'analysis'
                         AND ed.target_type = 'experiment_result'
                         AND ed.target_id = er.id
                         AND ed.relationship = 'analyzes'
            WHERE e.hypothesis_id = $1
              AND e.status = 'complete'
            "#,
        )
        .bind(hypothesis_id)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }
}

pub struct ExperimentResultRepository;

impl ExperimentResultRepository {
    #[instrument(skip(pool, raw_measurements))]
    pub async fn create(
        pool: &PgPool,
        experiment_id: Uuid,
        data_source: &str,
        raw_measurements: &serde_json::Value,
        measurement_count: i32,
    ) -> Result<Uuid, DbError> {
        let row: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO experiment_results (experiment_id, data_source, raw_measurements, measurement_count)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(experiment_id)
        .bind(data_source)
        .bind(raw_measurements)
        .bind(measurement_count)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<ExperimentResultRow>, DbError> {
        let row = sqlx::query_as::<_, ExperimentResultRow>(
            "SELECT * FROM experiment_results WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    #[instrument(skip(pool))]
    pub async fn get_for_experiment(
        pool: &PgPool,
        experiment_id: Uuid,
    ) -> Result<Vec<ExperimentResultRow>, DbError> {
        let rows = sqlx::query_as::<_, ExperimentResultRow>(
            "SELECT * FROM experiment_results WHERE experiment_id = $1 ORDER BY created_at DESC",
        )
        .bind(experiment_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Add measurements to an existing result, recomputing effective_random_error.
    #[instrument(skip(pool, new_measurements))]
    pub async fn add_measurements(
        pool: &PgPool,
        id: Uuid,
        new_measurements: &serde_json::Value,
        new_count: i32,
        effective_random_error: &serde_json::Value,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            UPDATE experiment_results
            SET raw_measurements = raw_measurements || $2,
                measurement_count = measurement_count + $3,
                effective_random_error = $4
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(new_measurements)
        .bind(new_count)
        .bind(effective_random_error)
        .execute(pool)
        .await?;
        Ok(())
    }

    #[instrument(skip(pool))]
    pub async fn update_status(pool: &PgPool, id: Uuid, status: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE experiment_results SET status = $2 WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await?;
        Ok(())
    }
}
