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

    /// The factors in frame `frame_id` (every frame when `None`) whose EVERY
    /// variable is a claim the viewer may READ, oldest first.
    ///
    /// The factor load of `POST /api/v1/bp/propagate`
    /// (`routes/computation.rs::propagate_beliefs`, `F-SHARD4-A2`). The route
    /// ran `SELECT … FROM factors WHERE ($1::uuid IS NULL OR frame_id = $1)`
    /// inline on the raw pool, so a propagation run took in every factor in
    /// the corpus. Its response names every variable of every factor it ran
    /// over, each with a propagated BetP, so the unfiltered load disclosed the
    /// ids, and a belief-shaped summary, of claims the caller cannot read.
    ///
    /// # Why the whole factor is dropped, not only its hidden variables
    ///
    /// A factor is a potential over ALL of its variables. Removing a hidden
    /// variable would change the potential the factor encodes. Keeping the
    /// factor whole would carry the hidden claim's belief into the messages
    /// its visible neighbours receive, so hidden evidence would still move
    /// visible beliefs. Dropping it means the propagation the caller sees is
    /// computed only from what the caller can read.
    ///
    /// # No database backstop, stated
    ///
    /// `factors` has no tenancy columns and row-level security is off (measured
    /// at migration head 100: `relrowsecurity` false), so the `{VISIBILITY:c}`
    /// predicate on the `claims` subquery is the only gate this read has. A
    /// variable id that names no claim at all fails the predicate too. That is
    /// deliberate: under migration 077's policies a claim the session cannot
    /// see and a claim that does not exist are the same empty subquery, so
    /// treating them alike keeps this read's answer the same before and after
    /// the request path connects as an application role.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn list_readable<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        frame_id: Option<Uuid>,
    ) -> Result<Vec<FactorRow>, crate::DbError> {
        let sql = viewer.splice(
            "SELECT f.id, f.factor_type, f.variable_ids, f.potential, f.description, \
                    f.frame_id, f.properties, f.created_at \
               FROM factors f \
              WHERE ($1::uuid IS NULL OR f.frame_id = $1) \
                AND NOT EXISTS ( \
                    SELECT 1 FROM unnest(f.variable_ids) AS v(id) \
                     WHERE NOT EXISTS ( \
                         SELECT 1 FROM claims c \
                          WHERE c.id = v.id \
                            /* {VISIBILITY:c} */ \
                     ) \
                ) \
              ORDER BY f.created_at",
            2,
        );
        let mut q = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Vec<Uuid>,
                JsonValue,
                Option<String>,
                Option<Uuid>,
                JsonValue,
                chrono::DateTime<chrono::Utc>,
            ),
        >(&sql)
        .bind(frame_id);
        // Guarded, not `unwrap_or(&[])`: a `Bypass` viewer renders `" "`, so the
        // statement has no `$2` to fill.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(crate::DbError::from)?;

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
                )| FactorRow {
                    id,
                    factor_type,
                    variable_ids,
                    potential,
                    description,
                    frame_id,
                    properties,
                    created_at,
                },
            )
            .collect())
    }

    /// Move the factors in frame `from_frame` that name `claim_id` into frame
    /// `to_frame`, but only those whose EVERY variable is a claim the viewer
    /// may WRITE. Returns how many moved.
    ///
    /// The factor re-frame of `POST /api/v1/hypothesis/:id/promote`
    /// (`routes/hypothesis.rs::promote_hypothesis`, `F-SBC-A2`). The route ran
    /// `UPDATE factors SET frame_id = $3 WHERE frame_id = $1 AND $2 =
    /// ANY(variable_ids)` inline. That moved every factor mentioning the
    /// hypothesis, including factors whose other variables are claims the
    /// caller cannot write, or cannot even read. A factor's frame decides which
    /// propagation run it takes part in, so moving it changes the inputs of
    /// every claim it names, not only the hypothesis.
    ///
    /// # Why narrow, and not refuse
    ///
    /// A factor that names a claim outside the caller's write authority STAYS
    /// in `from_frame`. The whole promotion is not refused, for two reasons:
    ///
    /// * Refusing would let anyone who can create a factor linking the
    ///   hypothesis to one of their own claims block its owner's promotion
    ///   permanently.
    /// * Refusing on a variable the caller cannot READ would tell the caller
    ///   that such a claim exists.
    ///
    /// Narrowing touches nothing outside the caller's write authority and
    /// discloses nothing. The cost is that a factor shared with another
    /// owner's claim is not carried into `to_frame`. That is deliberate, and
    /// it is the same line the `claims` write draws.
    ///
    /// # No database backstop, stated
    ///
    /// `factors` has no tenancy columns and row-level security is off (measured
    /// at migration head 100: `relrowsecurity` false). Migration 077 will never
    /// guard this statement, so the `{WRITABLE:c}` predicate on the `claims`
    /// subquery is the only gate it has. A variable id that names no claim at
    /// all fails the predicate too, so a dangling factor is not moved.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn move_writable_factors_to_frame<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        from_frame: Uuid,
        to_frame: Uuid,
    ) -> Result<u64, crate::DbError> {
        let sql = viewer.splice_write(
            "UPDATE factors AS f \
                SET frame_id = $3 \
              WHERE f.frame_id = $1 \
                AND $2 = ANY(f.variable_ids) \
                AND NOT EXISTS ( \
                    SELECT 1 FROM unnest(f.variable_ids) AS v(id) \
                     WHERE NOT EXISTS ( \
                         SELECT 1 FROM claims c \
                          WHERE c.id = v.id \
                            /* {WRITABLE:c} */ \
                     ) \
                )",
            4,
        );
        let mut q = sqlx::query(&sql)
            .bind(from_frame)
            .bind(claim_id)
            .bind(to_frame);
        // Conditional, not `unwrap_or(&[])`: a `Bypass` viewer renders `" "`, so
        // the statement has no `$4` to fill.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let result = q.execute(executor).await.map_err(crate::DbError::from)?;
        Ok(result.rows_affected())
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
