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

    /// Every experiment recorded against a hypothesis, newest first.
    ///
    /// # Executor, and why this one takes no `Viewer`
    ///
    /// Generic over [`sqlx::PgExecutor`] so `routes/hypothesis.rs::hypothesis_status`
    /// can run it on the SAME viewer-stamped connection as the four tenancy-carrying
    /// reads that surround it, instead of checking a second connection out of the
    /// pool mid-handler. Conversion shard 6 widened the executor ONLY: the SQL, its
    /// single bind and the projected row shape are byte-identical and were not
    /// re-derived.
    ///
    /// It takes no `Viewer` because there is nothing on `experiments` for one to
    /// filter — see this function's row in
    /// `epigraph-db/tests/visibility_lint.rs::EXECUTOR_WITHOUT_VIEWER` for the
    /// measurement. Every pre-existing caller passes `&PgPool`, which satisfies
    /// `E: PgExecutor<'e>`, so none was edited.
    #[instrument(skip(executor))]
    pub async fn get_for_hypothesis<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        hypothesis_id: Uuid,
    ) -> Result<Vec<ExperimentRow>, DbError> {
        let rows = sqlx::query_as::<_, ExperimentRow>(
            "SELECT * FROM experiments WHERE hypothesis_id = $1 ORDER BY created_at DESC",
        )
        .bind(hypothesis_id)
        .fetch_all(executor)
        .await?;
        Ok(rows)
    }

    /// The hypothesis an experiment tests, read through `viewer`: its id and
    /// the group that owns it (`claims.owner_group_id`), the two facts the
    /// experiment routes' hypothesis gate decides on (operator ruling R-51).
    ///
    /// `experiments` and `experiment_results` carry no tenancy columns; what
    /// an experiment belongs to is its hypothesis claim, so the claim is the
    /// row the viewer's predicate filters. With `result_id`, the result must
    /// also belong to this experiment.
    ///
    /// `None` when the experiment does not exist, when its hypothesis is not
    /// readable by the viewer, or when `result_id` names no result of this
    /// experiment. The three are deliberately indistinguishable, so a caller
    /// that answers `None` with one 404 leaks nothing about experiments on
    /// hypotheses it cannot read. Whether the caller may WRITE is the caller's
    /// decision, from the returned owning group.
    ///
    /// # Errors
    /// `DbError::QueryFailed` on a database failure.
    #[instrument(skip(executor, viewer))]
    pub async fn hypothesis_target_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        experiment_id: Uuid,
        result_id: Option<Uuid>,
    ) -> Result<Option<(Uuid, Uuid)>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.hypothesis_id, c.owner_group_id
            FROM experiments e
            JOIN claims c ON c.id = e.hypothesis_id
            WHERE e.id = $1
              AND ($2::uuid IS NULL OR EXISTS (
                    SELECT 1 FROM experiment_results r
                     WHERE r.id = $2 AND r.experiment_id = e.id))
              /* {VISIBILITY:c} */
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql)
            .bind(experiment_id)
            .bind(result_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
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
    #[instrument(skip(executor, viewer))]
    pub async fn count_completed_with_analysis<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        hypothesis_id: Uuid,
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
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
              /* {EDGE_VISIBILITY:ed} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql).bind(hypothesis_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: (i64,) = q.fetch_one(executor).await?;
        Ok(row.0)
    }

    /// Retire the `hypothesis_assessment` BBA a promotion has just copied onto
    /// `research_validity`, so the promotion MOVES the evidence rather than
    /// duplicating it (backlog 846b808e).
    ///
    /// Both frames are 2-hypothesis frames, so a copy left beside its source
    /// was read twice by `MassFunctionRepository::get_for_claim_binary_frames`
    /// and, when the row carries no `evidence_id` (the `error_derived` BBA),
    /// folded twice as independent evidence.
    ///
    /// The row is named by id AND by the claim and frame it must sit on, so a
    /// stray id cannot delete a row anywhere else, and the statement carries
    /// the caller's write predicate: a scoped viewer retires only a row in its
    /// writable set; a maintenance viewer renders no predicate. Returns whether
    /// the row went. Callers run it in the promotion's transaction and treat
    /// `false` as a refusal of the whole promotion, so a promotion never leaves
    /// two copies.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the statement fails.
    #[instrument(skip(executor, viewer))]
    pub async fn retire_promoted_hypothesis_bba<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        mass_function_id: Uuid,
        hypothesis_id: Uuid,
        hypothesis_frame_id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice_write(
            "DELETE FROM mass_functions AS mf \
              WHERE mf.id = $1 AND mf.claim_id = $2 AND mf.frame_id = $3 \
                /* {WRITABLE:mf} */",
            4,
        );
        let mut q = sqlx::query(&sql)
            .bind(mass_function_id)
            .bind(hypothesis_id)
            .bind(hypothesis_frame_id);
        // Conditional: a maintenance viewer renders no predicate, so the
        // statement has no `$4` to fill.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        Ok(q.execute(executor).await?.rows_affected() == 1)
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
