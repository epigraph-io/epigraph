//! Factor graph persistence: factors and belief propagation messages.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::edge::EDGE_IN_FORCE;

// ── BP under atom-level belief (SPEC §6.2, D3/D4) ──────────────────────────
//
// A COMPOUND (`claim_role::IS_COMPOUND_SQL`: in short, a claim with an
// in-force `decomposes_to` out-edge to a current claim) is a query over its
// atoms, with no belief cache of its own for BP to write.

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

/// SQL: of the claim ids bound as `$1` (`uuid[]`), the COMPOUNDS. Used by BP
/// apply, which writes atoms only (D4).
///
/// # Decided structurally, with definer rights
///
/// The role is structure, not secret (SPEC §2.1), and the claim cache this
/// guards is shared by every viewer. BP apply runs on the caller's stamped
/// write transaction, where `edges` and `claims` are under row security, so
/// an inline read there found no compound when every child of the compound
/// was private to a group the caller is not in, and apply wrote that
/// compound's cache (backlog 77b605ce). Each id is therefore decided by
/// migration 193's definer ([`super::mass_function::IS_COMPOUND_DEFINER_CALL`],
/// whose body is [`super::claim_role::IS_COMPOUND_SQL`]), which reads the
/// whole graph on any connection: the same test the cached-belief owner
/// lookup uses (backlog 0dc20fad).
///
/// The canonical predicate is narrower than "has an in-force `decomposes_to`
/// out-edge": a child must be current, and a procedural root (a workflow
/// plan) and a rule are not compounds. Those claims own a cache of their own
/// under the same predicate everywhere else, so BP apply now treats them the
/// same way.
#[must_use]
pub fn compound_ids_among_sql() -> String {
    let call = super::mass_function::IS_COMPOUND_DEFINER_CALL.replace("$1", "cand.id");
    format!("SELECT cand.id FROM unnest($1::uuid[]) AS cand(id) WHERE {call}")
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

/// The factor graph a BP request asks for (backlog b02347c6): a frame, a
/// claim set expanded through the factor graph, or both. `claim_ids: None`
/// is the frame scope alone (every BP-readable factor of `frame_id`, or of
/// every frame when that is `None` too, which the HTTP route refuses).
#[derive(Debug, Clone, Copy)]
pub struct BpFactorScope<'a> {
    /// Only factors on this frame.
    pub frame_id: Option<Uuid>,
    /// The seed claims; `None` for a frame-only scope.
    pub claim_ids: Option<&'a [Uuid]>,
    /// Factor hops from the seeds: 1 loads the factors that name a seed, 2
    /// also those that name a variable of those, and so on. Ignored without
    /// `claim_ids`.
    pub max_hops: usize,
}

/// What [`FactorRepository::load_bp_scope`] found.
#[derive(Debug)]
pub enum BpScopeLoad {
    /// Every factor in scope, in `created_at` order.
    Loaded(Vec<FactorRow>),
    /// The scope reaches more than `cap` factors. Nothing is returned: a
    /// truncated factor graph would answer a different question with a 200.
    OverCap { cap: usize },
}

/// The `edges.id` a trigger-minted factor row `f` was derived from
/// (`properties.source_edge_id`, migration 217's `auto_create_factor_from_edge`),
/// or NULL when the row carries none or the value is not a uuid. Guarded by a
/// CASE so a malformed value is never cast.
const FACTOR_SOURCE_EDGE_ID: &str = "(CASE WHEN f.properties->>'source_edge_id' \
     ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
     THEN (f.properties->>'source_edge_id')::uuid END)";

/// The columns [`FactorRow`] is read from, over a `factors` row aliased `f`.
const FACTOR_ROW_COLUMNS: &str = "f.id, f.factor_type, f.variable_ids, f.potential,      f.description, f.frame_id, f.properties, f.created_at";

type FactorRowTuple = (
    Uuid,
    String,
    Vec<Uuid>,
    JsonValue,
    Option<String>,
    Option<Uuid>,
    JsonValue,
    chrono::DateTime<chrono::Utc>,
);

fn factor_row(t: FactorRowTuple) -> FactorRow {
    let (id, factor_type, variable_ids, potential, description, frame_id, properties, created_at) =
        t;
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
}

pub struct FactorRepository;

impl FactorRepository {
    /// Insert a new factor.
    ///
    /// Only a privileged (maintenance or superuser) pool can: since migration
    /// 217 the application role holds no INSERT on `factors`, whose rows are
    /// minted by the edge INSERT trigger (`auto_create_factor_from_edge`, a
    /// maintenance-owned definer) and by the maintenance cascades. On the
    /// application role this returns `42501`.
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

    /// The BP-readable factors ([`bp_readable_factor_sql`]) in `scope`, for
    /// `POST /api/v1/bp/propagate` (backlog b02347c6). At most `cap` rows:
    /// one more is [`BpScopeLoad::OverCap`], never a silent truncation.
    ///
    /// A claim scope is expanded hop by hop over `factors.variable_ids`
    /// (`&&`, served by the GIN index `idx_factors_variables`), applying the
    /// frame filter and the BP-readable predicate at EVERY hop, so the
    /// expansion never walks through a factor BP would not read (a
    /// `decomposes_to` echo, SPEC §6.2 D3). Each hop asks only for the rows
    /// it can still afford (`cap + 1 - loaded`).
    ///
    /// # Only factors whose every variable the viewer can read
    ///
    /// `factors` has no tenancy columns and no row security, and
    /// `variable_ids` has no foreign key to `claims`, so a factor can name a
    /// claim private to another group, or an id that is no claim at all. A BP
    /// run SERVES its result to the caller (`updated_beliefs`,
    /// `variables_count`, `factors_count`), so a factor with a variable the
    /// caller cannot read would put that claim's id, and a value computed
    /// through it, in the response, and would couple two readable claims
    /// through a node the caller cannot see (tenancy finding F-SHARD4-A2).
    /// Such a factor is not loaded, and the expansion does not walk through
    /// it. An id that is no claim cannot be told apart from a claim the caller
    /// cannot read without an existence oracle, so it is treated the same way.
    ///
    /// A row the edge trigger minted names its edge (`properties.source_edge_id`),
    /// and is loaded only while the viewer can read that edge: an edge can be
    /// private to a group while both its ends are public, and its factor would
    /// otherwise carry that group's coupling into anyone's run. A keyed row whose
    /// edge no longer exists is not loaded either.
    ///
    /// Run it on the caller's stamped connection: the predicate's legacy arm
    /// reads `edges`, which row security filters (see
    /// [`bp_readable_factor_sql`]).
    ///
    /// # Errors
    /// `DbError` when a statement fails.
    pub async fn load_bp_scope(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        scope: &BpFactorScope<'_>,
        cap: usize,
    ) -> Result<BpScopeLoad, crate::DbError> {
        let limit = |loaded: usize| i64::try_from(cap + 1 - loaded).unwrap_or(i64::MAX);
        let mut rows: Vec<FactorRow> = Vec::new();
        match scope.claim_ids {
            None => {
                let sql = viewer.splice(
                    &format!(
                        "SELECT {FACTOR_ROW_COLUMNS} FROM factors f \
                          WHERE ($1::uuid IS NULL OR f.frame_id = $1) AND {} \
                            AND NOT EXISTS (SELECT 1 FROM unnest(f.variable_ids) AS fv(id) \
                                 WHERE NOT EXISTS (SELECT 1 FROM claims bpv \
                                    WHERE bpv.id = fv.id /* {{VISIBILITY:bpv}} */)) \
                            AND (NOT (f.properties ? 'source_edge_id') \
                                 OR EXISTS (SELECT 1 FROM edges bpe \
                                             WHERE bpe.id = {FACTOR_SOURCE_EDGE_ID} \
                                             /* {{EDGE_VISIBILITY:bpe}} */)) \
                          ORDER BY f.created_at, f.id LIMIT $2",
                        bp_readable_factor_sql()
                    ),
                    3,
                );
                let mut q = sqlx::query_as::<_, FactorRowTuple>(&sql)
                    .bind(scope.frame_id)
                    .bind(limit(0));
                if let Some(g) = viewer.group_bind() {
                    q = q.bind(g);
                }
                let found = q
                    .fetch_all(&mut *conn)
                    .await
                    .map_err(crate::DbError::from)?;
                rows.extend(found.into_iter().map(factor_row));
            }
            Some(seeds) => {
                let mut seen_vars: std::collections::HashSet<Uuid> =
                    seeds.iter().copied().collect();
                let mut frontier: Vec<Uuid> = seen_vars.iter().copied().collect();
                let mut loaded_ids: Vec<Uuid> = Vec::new();
                for _ in 0..scope.max_hops {
                    if frontier.is_empty() || rows.len() > cap {
                        break;
                    }
                    let sql = viewer.splice(
                        &format!(
                            "SELECT {FACTOR_ROW_COLUMNS} FROM factors f \
                              WHERE f.variable_ids && $1::uuid[] \
                                AND NOT (f.id = ANY($2::uuid[])) \
                                AND ($3::uuid IS NULL OR f.frame_id = $3) AND {} \
                                AND NOT EXISTS (SELECT 1 FROM unnest(f.variable_ids) AS fv(id) \
                                     WHERE NOT EXISTS (SELECT 1 FROM claims bpv \
                                        WHERE bpv.id = fv.id /* {{VISIBILITY:bpv}} */)) \
                                AND (NOT (f.properties ? 'source_edge_id') \
                                     OR EXISTS (SELECT 1 FROM edges bpe \
                                                 WHERE bpe.id = {FACTOR_SOURCE_EDGE_ID} \
                                                 /* {{EDGE_VISIBILITY:bpe}} */)) \
                              ORDER BY f.created_at, f.id LIMIT $4",
                            bp_readable_factor_sql()
                        ),
                        5,
                    );
                    let mut q = sqlx::query_as::<_, FactorRowTuple>(&sql)
                        .bind(&frontier)
                        .bind(&loaded_ids)
                        .bind(scope.frame_id)
                        .bind(limit(rows.len()));
                    if let Some(g) = viewer.group_bind() {
                        q = q.bind(g);
                    }
                    let found = q
                        .fetch_all(&mut *conn)
                        .await
                        .map_err(crate::DbError::from)?;
                    frontier = Vec::new();
                    for t in found {
                        let row = factor_row(t);
                        for v in &row.variable_ids {
                            if seen_vars.insert(*v) {
                                frontier.push(*v);
                            }
                        }
                        loaded_ids.push(row.id);
                        rows.push(row);
                    }
                }
            }
        }
        if rows.len() > cap {
            return Ok(BpScopeLoad::OverCap { cap });
        }
        rows.sort_by_key(|r| (r.created_at, r.id));
        Ok(BpScopeLoad::Loaded(rows))
    }

    /// The stored BetP of each of `ids` that `viewer` can read, as BP's
    /// scalar priors: `(id, pignistic_prob)`. An id the viewer cannot read is
    /// absent, not an error.
    ///
    /// Role-blind, as the scalar engine always was: a compound's cached
    /// value seeds it like any claim's (BP apply never writes a compound).
    ///
    /// # Errors
    /// `DbError` when the statement fails.
    pub async fn bp_priors(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Option<f64>)>, crate::DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "SELECT c.id, c.pignistic_prob FROM claims c \
              WHERE c.id = ANY($1) /* {VISIBILITY:c} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<f64>)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(&mut *conn).await.map_err(crate::DbError::from)
    }

    /// The alternative-set class (migration 042's `alternative_set`) of each
    /// of `ids` that has one, as CDST BP's `AltSetMembership`:
    /// `(claim, the other claims it is mutually exclusive with)`.
    ///
    /// Seeded from `ids` and walked over `alternative_of` edges `viewer` can
    /// read, stepping only onto claims `viewer` can read. The view it
    /// replaces computed the transitive closure of every `alternative_of`
    /// edge in the corpus on every CDST run, and through the raw pool it saw
    /// only public edges (it is `security_invoker`), so a member's own
    /// group's alternative sets were silently left out.
    ///
    /// # Errors
    /// `DbError` when the statement fails.
    pub async fn bp_alternative_sets(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<(Uuid, Vec<Uuid>)>, crate::DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            "WITH RECURSIVE closure(a, b) AS ( \
                 SELECT s.id, s.id FROM unnest($1::uuid[]) AS s(id) \
                 UNION \
                 SELECT cl.a, CASE WHEN e.source_id = cl.b THEN e.target_id \
                                   ELSE e.source_id END \
                   FROM closure cl \
                   JOIN edges e ON (e.source_id = cl.b OR e.target_id = cl.b) \
                  WHERE e.relationship = 'alternative_of' \
                    AND e.source_type = 'claim' AND e.target_type = 'claim' \
                    /* {EDGE_VISIBILITY:e} */ \
                    AND EXISTS (SELECT 1 FROM claims m \
                                 WHERE m.id = CASE WHEN e.source_id = cl.b THEN e.target_id \
                                                   ELSE e.source_id END \
                                   /* {VISIBILITY:m} */) \
             ) \
             SELECT cl.a, array_agg(DISTINCT cl.b ORDER BY cl.b) \
               FROM closure cl WHERE cl.b <> cl.a GROUP BY cl.a",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Vec<Uuid>)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(&mut *conn).await.map_err(crate::DbError::from)
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
