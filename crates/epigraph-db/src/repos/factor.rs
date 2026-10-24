//! Factor graph persistence: factors and belief propagation messages.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::edge::EDGE_IN_FORCE;

// ── BP under atom-level belief (SPEC §6.2, D3/D4) ──────────────────────────
//
// A COMPOUND is a claim with an in-force `decomposes_to` out-edge to a claim:
// a query over its atoms, with no belief cache of its own for BP to write.

/// SQL predicate over a `factors` row aliased `f`: TRUE when belief
/// propagation may read the row, FALSE for a `decomposes_to` factor (D3).
///
/// The `edges_auto_factor` trigger mints a `directional_support` factor for
/// every `decomposes_to` edge. Read by BP, it carries an atom's evidence up
/// into its compound and back (an echo), so no BP run reads one:
///
/// * a KEYED row: `properties.relationship` is `decomposes_to` (any case);
/// * a LEGACY row, minted before the trigger keyed its rows: no
///   `relationship` key, type `directional_support` (the only type any
///   trigger version maps `decomposes_to` to), two variables, and those two
///   are the ends of an in-force `decomposes_to` edge, in either order.
///
/// Every other factor stays readable, including `evidential_support` and
/// `mutual_exclusion` rows that name a compound: read-only BP keeps them as a
/// diagnostic (D4 is stated for BP APPLY).
///
/// # The legacy arm reads `edges`, under the session's row security
///
/// Run it on a connection stamped with the caller's viewer
/// (`AppState::read_as`), never on an unstamped application connection: that
/// one sees only public edges, so a legacy row whose decomposition is private
/// to the caller's own group would be read. Stamped, the arm still cannot see
/// a decomposition the CALLER cannot see (another group's, or one co-owned
/// with a group the caller is not in), and such a legacy row stays readable
/// for that caller. Deciding the match structurally needs a read past row
/// security, which a request-serving process does not hold; the structural
/// close is removing the rows themselves (SPEC §6.2's export-and-delete of
/// `decomposes_to` factors and its sweep job, which run on the maintenance
/// connection). A KEYED row needs no edge read and is excluded for everyone.
///
/// # A directional edge parallel to a decomposition
///
/// The trigger maps `decomposes_to`, `supports` and several other
/// relationships to `directional_support`, and `idx_factors_type_vars_frame`
/// is unique on (type, sorted pair, frame), so a pair holds ONE trigger
/// factor, keyed by the edge created first. If that is the `decomposes_to`
/// edge, the parallel edge has no factor of its own and BP reads no coupling
/// for it; created the other way round, BP reads the parallel edge's factor.
/// A legacy row on a decomposition pair is excluded whichever edge minted it.
/// Known and pinned (`bp_parallel_supports_and_decomposes_to`); a migration
/// that stops the trigger minting `decomposes_to` factors removes it.
#[must_use]
pub fn bp_readable_factor_sql() -> String {
    format!(
        "NOT ( \
            lower(COALESCE(f.properties->>'relationship', '')) = 'decomposes_to' \
            OR ( NOT COALESCE(f.properties ? 'relationship', false) \
                 AND f.factor_type = 'directional_support' \
                 AND cardinality(f.variable_ids) = 2 \
                 AND EXISTS ( \
                     SELECT 1 FROM edges e \
                      WHERE e.relationship = 'decomposes_to' \
                        AND e.source_type = 'claim' AND e.target_type = 'claim' \
                        AND ( (e.source_id = f.variable_ids[1] AND e.target_id = f.variable_ids[2]) \
                           OR (e.source_id = f.variable_ids[2] AND e.target_id = f.variable_ids[1]) ) \
                        AND {EDGE_IN_FORCE} ) ) )"
    )
}

/// SQL: of the claim ids bound as `$1` (`uuid[]`), the COMPOUNDS — those with
/// an in-force `decomposes_to` out-edge to a claim. Used by BP apply, which
/// writes atoms only (D4).
///
/// # Decided over the edges the session can see
///
/// The intent is structural (SPEC §2.1: "role is structural, not secret"),
/// and the claim cache it guards is shared by every viewer. But `edges` is
/// under row security, and BP apply runs this on the caller's stamped write
/// transaction, so a decomposition the CALLER cannot see (one co-owned with a
/// group the caller is not in, say) does not make its source a compound
/// here, and apply would write that compound's cache. A structural read needs
/// either a connection past row security, which a request-serving process
/// does not hold, or a definer function, which is a migration this stage
/// does not take. BP apply is refused unless `EPIGRAPH_BP_APPLY=on` and is
/// run by hand only, so the residual is recorded here rather than closed.
#[must_use]
pub fn compound_ids_among_sql() -> String {
    format!(
        "SELECT DISTINCT e.source_id FROM edges e \
          WHERE e.source_id = ANY($1) \
            AND e.source_type = 'claim' AND e.target_type = 'claim' \
            AND e.relationship = 'decomposes_to' \
            AND {EDGE_IN_FORCE}"
    )
}

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

    /// Get the BP-readable factors that reference a given claim (variable):
    /// every factor naming it except a `decomposes_to` one
    /// ([`bp_readable_factor_sql`], SPEC §6.2 D3).
    pub async fn get_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Vec<FactorRow>, crate::DbError> {
        let rows = sqlx::query_as::<
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
        >(&format!(
            "SELECT f.id, f.factor_type, f.variable_ids, f.potential, f.description, f.frame_id, \
                        f.properties, f.created_at \
                 FROM factors f WHERE $1 = ANY(f.variable_ids) AND {}",
            bp_readable_factor_sql()
        ))
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

    /// Get every BP-readable factor, optionally filtered by frame: the
    /// whole-graph BP load, so no `decomposes_to` factor
    /// ([`bp_readable_factor_sql`], SPEC §6.2 D3).
    pub async fn get_all(
        pool: &PgPool,
        frame_id: Option<Uuid>,
    ) -> Result<Vec<FactorRow>, crate::DbError> {
        let rows = sqlx::query_as::<
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
        >(&format!(
            "SELECT f.id, f.factor_type, f.variable_ids, f.potential, f.description, f.frame_id, \
                        f.properties, f.created_at \
                 FROM factors f \
                 WHERE ($1::uuid IS NULL OR f.frame_id = $1) AND {} \
                 ORDER BY f.created_at",
            bp_readable_factor_sql()
        ))
        .bind(frame_id)
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
