//! Edge repository for LPG-style relationships

use crate::errors::DbError;
use sqlx::types::Json;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Canonical epistemic relationship types — claim-to-claim edges that carry
/// evidentiary weight and participate in belief propagation / sheaf
/// consistency. Mirrors `EPISTEMIC_RELATIONSHIPS` in
/// `epigraph-mcp::tools::link_epistemic` (the edge-writer's allowlist);
/// `supersedes` is intentionally excluded there and here — it has dedicated
/// semantics in `supersede_claim`, not `link_epistemic`.
///
/// Kept here (the lower `epigraph-db` layer) so DB-layer batch queries like
/// [`crate::repos::claim::ClaimRepository::in_epistemic_degree_batch`] don't
/// need to depend upward on `epigraph-mcp` for the list.
pub const EPISTEMIC_RELATIONSHIPS: &[&str] = &[
    "supports",
    "corroborates",
    "elaborates",
    "generalizes",
    "specializes",
    "contradicts",
    "refutes",
];

/// The subset of [`EPISTEMIC_RELATIONSHIPS`] that WEAKENS its target's belief.
///
/// Every other member of that list strengthens the target; these two are the
/// only ones that subtract. The distinction is not cosmetic — it decides what
/// may be re-pointed when a claim is replaced. A `refutes`/`contradicts` edge
/// is an assertion about a *specific pair of contents* ("this text refutes
/// THAT text"), so re-pointing either endpoint at a different text silently
/// re-asserts something nobody checked, and the direction of the error is
/// always suppression: `ClaimRepository::dispute_batch` turns these two
/// relationships (and only these two) into `is_contested`, which
/// `recall(exclude_contested: true)` uses to drop results.
///
/// Consumed by [`crate::repos::claim::ClaimRepository::supersede`]; kept here
/// next to `EPISTEMIC_RELATIONSHIPS` so the two sets cannot drift, and bound
/// into the SQL rather than inlined so adding a third weakening relationship
/// above automatically covers the supersede path.
pub const WEAKENING_RELATIONSHIPS: &[&str] = &["contradicts", "refutes"];

/// SQL predicate selecting edges that are currently in force.
///
/// `edges` is bitemporal via `valid_from` / `valid_to` (migration 001), but until
/// this predicate existed the column was decorative: exactly ONE query in the
/// workspace filtered on it (`get_current_edges`), and 6 of 987,857 production
/// rows carried a value. Every belief-bearing read saw retracted edges as live.
///
/// That absence is why `MatchCandidateRepo::retire` hard-DELETEs edges rather
/// than retracting them — a soft retraction that nothing honours retracts
/// nothing. Enforcing the predicate on the derivation path is the precondition
/// for making retirement non-destructive.
///
/// `valid_to IS NULL` means "ongoing or atemporal" and is the overwhelmingly
/// common case, so the predicate is written NULL-first to short-circuit.
pub const EDGE_IN_FORCE: &str = "(e.valid_to IS NULL OR e.valid_to > now())";

/// [`EDGE_IN_FORCE`] for queries that select from `edges` without an alias.
///
/// Kept as a separate constant rather than a format arg so both spellings are
/// greppable and a reviewer can see every enforcement site by searching for
/// `EDGE_IN_FORCE`.
pub const EDGE_IN_FORCE_UNALIASED: &str = "(valid_to IS NULL OR valid_to > now())";

/// A row from the edges table
#[derive(Debug, Clone)]
pub struct EdgeRow {
    pub id: Uuid,
    pub source_id: Uuid,
    pub source_type: String,
    pub target_id: Uuid,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    pub valid_to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Outcome of [`EdgeRepository::create_symmetric_if_absent_oriented`].
///
/// `source_id` / `target_id` are the endpoints AS RECORDED on the surviving
/// row, not necessarily the `(a, b)` the caller passed — on a dedup hit
/// against the reverse direction they are swapped. See that method's doc
/// comment for why belief-wiring callers must use these and not their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymmetricEdgeUpsert {
    pub edge_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// `true` when this call inserted the row, `false` on a dedup hit.
    pub was_created: bool,
}

/// Repository for Edge operations
pub struct EdgeRepository;

impl EdgeRepository {
    /// Create a new edge relationship
    ///
    /// # Arguments
    /// * `executor` - A pool, connection, or transaction handle
    /// * `source_id` - Source entity UUID
    /// * `source_type` - Source entity type (e.g., "claim", "agent")
    /// * `target_id` - Target entity UUID
    /// * `target_type` - Target entity type
    /// * `relationship` - Relationship label (e.g., "supports", "refutes")
    /// * `properties` - Optional JSONB properties for the edge
    ///
    /// # Why the executor is generic
    ///
    /// A verb-edge (`AUTHORED`, `DERIVED_FROM`, `HAS_TRACE`) is emitted about a
    /// row that the same submission just wrote. Once that row's INSERT lives in a
    /// transaction, an edge emitted on a DIFFERENT connection points at a row no
    /// other session can see yet — so the edge has to be able to join the
    /// transaction. `&PgPool` and `&mut PgConnection` both satisfy
    /// [`sqlx::PgExecutor`], so the existing pool-taking callers compile
    /// unchanged.
    ///
    /// **If you pass a transaction and want the edge to stay BEST-EFFORT, wrap it
    /// in a SAVEPOINT.** A failed statement aborts the whole PostgreSQL
    /// transaction, so a `let _ = EdgeRepository::create(&mut *tx, …)` that
    /// swallows the error does not preserve the old warn-and-continue behaviour —
    /// it defers the failure to `COMMIT`, where it surfaces as
    /// `current transaction is aborted` with the real cause gone. See
    /// `epigraph-mcp/src/claim_helper.rs::emit_verb_edge_best_effort`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(executor, properties))]
    pub async fn create<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Uuid, DbError> {
        let properties = properties.unwrap_or(serde_json::json!({}));

        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to
        )
        .fetch_one(executor)
        .await?;

        Ok(row.id)
    }

    /// Like [`create`], but if an edge with the same
    /// `(source_id, target_id, relationship)` triple already exists, returns
    /// that edge's row without inserting a duplicate. Idempotent.
    ///
    /// Returns `(EdgeRow, was_created)` where `was_created` is `true` when a
    /// new row was inserted and `false` when an existing row was returned.
    /// Mirrors `ClaimRepository::create_or_get`. Callers in API handlers gate
    /// side effects (provenance, events, DS recomputation) on `was_created`
    /// so dedup hits don't double-fire — see `routes/edges.rs::create_edge`.
    ///
    /// Uses check-then-insert in a transaction. The `edges` table has no
    /// unique index on this triple (multiple parallel edges with different
    /// `properties` are valid in the general case), so we cannot rely on
    /// `ON CONFLICT`. Two round-trips are acceptable for the ingestion
    /// path; the race window is small and edges are idempotent in practice.
    ///
    /// # Why this takes an `Acquire` rather than a `&PgPool`
    ///
    /// `edges` is tier-A under migration 077 and `edges_tenancy`'s `WITH CHECK`
    /// derives the row's tenancy from its endpoints, so on an unstamped
    /// connection this INSERT is refused on a cleanly-migrated schema (it lands
    /// in production only because of the orphan PERMISSIVE `edges_privacy`
    /// policy, which exists in no migration). A generic `Acquire` lets a
    /// converted caller pass `&mut *tx` from
    /// `ScopedPool::begin_as(author_viewer)` while the seventeen `&pool` callers
    /// compile and behave exactly as before — `&PgPool` implements `Acquire`
    /// too.
    ///
    /// `begin()` below therefore opens a real transaction when handed a pool and
    /// a **SAVEPOINT** when handed a connection already inside one, which is the
    /// property that keeps the dedup probe + INSERT atomic in both shapes
    /// without a second code path.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_not_exists(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(EdgeRow, bool), DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_if_not_exists_conn(
            &mut conn,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to,
        )
        .await
    }

    /// [`Self::create_if_not_exists`] on a connection the caller owns — the form
    /// a stamped transaction can reach.
    ///
    /// The pool-taking wrapper above delegates here, so there is one dedup probe
    /// and one INSERT. `begin()` opens a real transaction when this connection is
    /// not already in one and a **SAVEPOINT** when it is, which keeps the
    /// probe+INSERT atomic in both shapes.
    ///
    /// A concrete `&mut PgConnection` rather than a generic `Acquire` for the
    /// reason given on
    /// [`crate::ClaimRepository::create_with_id_if_absent_conn`]: under
    /// `#[tool_router]`'s boxed `dyn Future + Send` an `Acquire<'a>` bound fails
    /// to prove `for<'x> &'x mut PgConnection: Acquire<'x>`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_not_exists_conn(
        conn: &mut sqlx::PgConnection,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(EdgeRow, bool), DbError> {
        use sqlx::Acquire;
        let mut tx = conn.begin().await?;

        let existing = sqlx::query!(
            r#"
            -- VISIBILITY-EXEMPT: dedup probe inside a WRITE path
            -- (`create_or_get`). It must see an existing edge regardless of who
            -- is asking, or the "get" half silently becomes "create" and the
            -- table grows a duplicate every time a caller without read access
            -- re-asserts a link that is already there. PR-16 owns the
            -- write-side authorization that decides whether the caller may
            -- create the edge at all.
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND target_id = $2 AND relationship = $3
            LIMIT 1
            "#,
            source_id,
            target_id,
            relationship,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            tx.commit().await?;
            return Ok((
                EdgeRow {
                    id: row.id,
                    source_id: row.source_id,
                    source_type: row.source_type,
                    target_id: row.target_id,
                    target_type: row.target_type,
                    relationship: row.relationship,
                    properties: row.properties,
                    valid_from: row.valid_from,
                    valid_to: row.valid_to,
                },
                false,
            ));
        }

        let properties = properties.unwrap_or(serde_json::json!({}));
        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            relationship,
            properties,
            valid_from,
            valid_to,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((
            EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            },
            true,
        ))
    }

    /// Insert a `relationship` edge between `a` and `b` (both `claim`-typed),
    /// skipping the insert when an edge with the same relationship already
    /// connects the two in EITHER direction.
    ///
    /// This is the single home for the cross-source matcher's edge-write SQL:
    /// the `Policy::write_edge` body in `epigraph-engine` and the
    /// `decide_match_candidate` PROMOTE arm in `epigraph-mcp` both route
    /// through it so the dedup form lives in one place. The existence check is
    /// **bidirectional** — `(a,b)` and `(b,a)` with the same `relationship`
    /// count as the same edge — because CORROBORATES is semantically symmetric
    /// even though the row preserves the caller's `a,b` ordering (we do NOT
    /// canonicalize).
    ///
    /// Returns `true` when a new row was inserted, `false` on a dedup hit.
    ///
    /// Single-statement `INSERT … SELECT … WHERE NOT EXISTS`, with
    /// `ON CONFLICT DO NOTHING` behind it.
    ///
    /// # The guard is the fast path; migration 090 is what makes the answer true
    ///
    /// The `NOT EXISTS` read is not a lock. Two concurrent promote decisions
    /// over the same pair both observe an empty guard and both insert, and
    /// nothing in the schema used to stop the second one — the old note here
    /// said there was "no constraint to infer on" because migrations 017/018
    /// dropped the unique triple index. Migration 090 adds one:
    /// `edges_symmetric_relationship_uniq`, over
    /// `(LEAST(source,target), GREATEST(source,target), relationship)`, keyed on
    /// the same `(pair + properties->>'source' = 'cross_source_matcher')`
    /// identity `MatchCandidateRepo::retire` already uses and restricted to
    /// in-force claim-claim rows. Its predicate is a strict SUBSET of what this
    /// guard blocks, so it can only ever reject a row the guard would have
    /// rejected too if it had seen it — and an operator-authored edge over the
    /// same pair is untouched, which is what keeps this a dedup repair rather
    /// than a change to what `POST /edges` may write.
    ///
    /// The second case it covers is why this is a FORCE precondition
    /// (`D-PR17-read-guards-widen-under-rls`): 072 arm (d)'s no-widening rule
    /// lets an edge keep a group stamp after both of its endpoints become
    /// public, so a writer can see the endpoints and not the edge. The guard
    /// then permits a second row for the pair; the index refuses it. Latent
    /// until plan §9.2 step 11d, because until then the application connects as
    /// a role no policy applies to.
    ///
    /// `DO NOTHING` is **bare**, with no arbiter inference: inference against a
    /// partial expression index must imply the index predicate exactly, and a
    /// mismatch is a runtime error out of this `sqlx::query` that no compile
    /// step sees. Bare `DO NOTHING` also covers
    /// `edges_alternative_of_symmetric_uniq` for free. It suppresses unique and
    /// exclusion violations only — 074's tenancy RAISE and `edges_validate_refs`
    /// still propagate, which is what keeps this write fail-closed.
    ///
    /// The matcher's `are_all_current` guard stays at the MCP call site; this
    /// method is purely the write.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn create_symmetric_if_absent(
        pool: &PgPool,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<bool, DbError> {
        let result = sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties)
             SELECT $1, 'claim', $2, 'claim', $3, $4
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
             )
             ON CONFLICT DO NOTHING",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .bind(Json(properties))
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Symmetric idempotent create that also returns the edge id.
    ///
    /// Same bidirectional-dedup contract as [`Self::create_symmetric_if_absent`]
    /// (`(a,b)` and `(b,a)` with the same `relationship` are one edge), but
    /// returns `(edge_id, was_created)` so a caller can echo the id back:
    /// `was_created = true` with the freshly-inserted id, or `false` with the
    /// id of the pre-existing symmetric edge. Purpose-built for the
    /// `link_alternative` MCP tool over `alternative_of` (migration 042's
    /// `edges_alternative_of_symmetric_uniq`, narrowed to rows in force by 091).
    /// Runtime `sqlx::query*` — no `.sqlx/` prepared-cache entry.
    ///
    /// Carries the same bare `ON CONFLICT DO NOTHING` as
    /// [`Self::create_symmetric_if_absent`], and see that function for why the
    /// constraint rather than the guard is what makes the answer true. The
    /// arbiter here is migration 042's `edges_alternative_of_symmetric_uniq`
    /// (narrowed by 091), not 090 — `alternative_of` is outside 090's predicate.
    ///
    /// WHAT THE `DO NOTHING` IS AND IS NOT PROVED TO DO. When the conflicting
    /// row is visible to this connection the dedup-hit branch below reads it and
    /// the concurrent-duplicate case resolves to `(existing_id, false)` instead
    /// of a 23505 the caller maps to an internal error. When it is NOT visible,
    /// one error is traded for another, not for an answer. There is no test over
    /// this function or over its one caller, so both halves are asserted by
    /// inspection; the change is conservative because every pre-change path is
    /// unchanged.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails. On the
    /// dedup-hit branch that includes the case where the conflicting edge is not
    /// visible to this connection and there is no id to return. Note what does
    /// the filtering and when: the probe below is annotated
    /// `VISIBILITY-EXEMPT` and carries no `Viewer` splice, so it is unfiltered
    /// on the role the application connects as TODAY and becomes filtered by the
    /// database policy only from plan §9.2 step 11d, at which point that branch
    /// yields `RowNotFound`. That is a loud failure rather than a wrong answer.
    #[instrument(skip(pool, properties))]
    pub async fn create_symmetric_if_absent_returning(
        pool: &PgPool,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<(Uuid, bool), DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_symmetric_if_absent_returning_conn(&mut conn, a, b, relationship, properties)
            .await
    }

    /// [`Self::create_symmetric_if_absent_returning`] on a connection the caller
    /// owns: the form an author-stamped transaction can reach. The pool-taking
    /// function above delegates here, so there is one INSERT and one dedup probe.
    ///
    /// On a stamped transaction the dedup-hit probe is filtered by
    /// `edges_tenancy`'s USING. A conflicting edge this connection cannot see
    /// therefore still yields `RowNotFound` (a loud error), exactly as the pool
    /// form's doc describes. It is never a wrong answer.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, properties))]
    pub async fn create_symmetric_if_absent_returning_conn(
        conn: &mut sqlx::PgConnection,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<(Uuid, bool), DbError> {
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties)
             SELECT $1, 'claim', $2, 'claim', $3, $4
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
             )
             ON CONFLICT DO NOTHING
             RETURNING id",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .bind(Json(properties))
        .fetch_optional(&mut *conn)
        .await?;

        if let Some(id) = inserted {
            return Ok((id, true));
        }

        // Dedup hit — surface the id of the existing symmetric edge.
        let existing: Uuid = sqlx::query_scalar(
            "-- VISIBILITY-EXEMPT: symmetric-dedup probe inside a WRITE path;
             -- same reasoning as `create_or_get`'s.
             SELECT id FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND relationship = $3
             LIMIT 1",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .fetch_one(&mut *conn)
        .await?;

        Ok((existing, false))
    }

    /// Symmetric idempotent create that reports the STORED row's orientation.
    ///
    /// Same bidirectional-dedup contract as
    /// [`Self::create_symmetric_if_absent_returning`], but the result also
    /// carries the `(source_id, target_id)` actually recorded on the surviving
    /// row rather than the `(a, b)` the caller passed. On a fresh insert those
    /// are the same; on a dedup hit against the REVERSE direction they are
    /// swapped.
    ///
    /// That distinction is load-bearing for belief-wiring callers. The matcher
    /// paths that use the plain `create_symmetric_if_absent` never wire belief
    /// (see `routes/cross_source.rs`'s "never `auto_wire_edge_if_epistemic`"
    /// note), so orientation is inert for them. `link_epistemic` DOES wire: it
    /// materializes a BBA keyed on `edge_id` from the source claim's interval
    /// onto the target. Handing it the caller's orientation on a reverse dedup
    /// hit would attach a factor that contradicts the row it is keyed to —
    /// "B contradicts A" on disk, "A's interval restricts B" in the BBA. With
    /// the stored orientation returned, the wire always matches the row.
    ///
    /// Runtime `sqlx::query*` throughout — no `.sqlx/` prepared-cache entry.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn create_symmetric_if_absent_oriented(
        pool: &PgPool,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<SymmetricEdgeUpsert, DbError> {
        let mut conn = pool.acquire().await?;
        Self::create_symmetric_if_absent_oriented_conn(&mut conn, a, b, relationship, properties)
            .await
    }

    /// [`Self::create_symmetric_if_absent_oriented`] on a connection the caller
    /// owns, so `link_epistemic` can write the edge on the same author-stamped
    /// transaction as the belief wiring keyed on its id. The pool-taking function
    /// above delegates here, so there is one INSERT and one dedup probe.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, properties))]
    pub async fn create_symmetric_if_absent_oriented_conn(
        conn: &mut sqlx::PgConnection,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: serde_json::Value,
    ) -> Result<SymmetricEdgeUpsert, DbError> {
        let inserted: Option<(Uuid, Uuid, Uuid)> = sqlx::query_as(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties)
             SELECT $1, 'claim', $2, 'claim', $3, $4
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
             )
             RETURNING id, source_id, target_id",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .bind(Json(properties))
        .fetch_optional(&mut *conn)
        .await?;

        if let Some((edge_id, source_id, target_id)) = inserted {
            return Ok(SymmetricEdgeUpsert {
                edge_id,
                source_id,
                target_id,
                was_created: true,
            });
        }

        // Dedup hit — surface the existing row AS STORED, which may be the
        // reverse of the caller's (a, b).
        let (edge_id, source_id, target_id): (Uuid, Uuid, Uuid) = sqlx::query_as(
            "SELECT id, source_id, target_id FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND relationship = $3
             LIMIT 1",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .fetch_one(&mut *conn)
        .await?;

        Ok(SymmetricEdgeUpsert {
            edge_id,
            source_id,
            target_id,
            was_created: false,
        })
    }

    /// Get edges by source entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_source<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        source_id: Uuid,
        source_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// List the claim→claim edges leaving `source_id` that can carry an
    /// edge-factor BBA on their target, restricted to targets that are still
    /// `is_current`.
    ///
    /// Returns `(edge_id, target_id, relationship)` per edge.
    ///
    /// # Why this exists (and why the obvious query is wrong)
    /// `ClaimRepository::supersede` re-points every non-`supersedes` outgoing
    /// edge onto the **replacement** claim *inside* its transaction (grep:
    /// `Migrate outgoing edges: redirect edges FROM old claim`). A cascade
    /// that enumerates `source_id = <retracted claim>` after the commit
    /// therefore matches nothing at all — the only edge still touching the old
    /// uuid is the `supersedes` edge, whose *source* is the new claim. Callers
    /// must pass the **new** claim id here.
    ///
    /// Currency has two independent parts and BOTH are enforced here:
    /// - the TARGET claim's currency, joined from `claims.is_current`;
    /// - the EDGE's own currency, via [`EDGE_IN_FORCE`] over `valid_to`.
    ///
    /// A previous version of this comment claimed `edges` "carries no per-row
    /// currency flag ... so any query that filters on one fails at runtime",
    /// while simultaneously listing `valid_to` among the columns. That was
    /// self-contradictory: the intended point was that edges have no
    /// `is_current` column, but as written it discouraged filtering on the
    /// bitemporal column that does exist. Corrected, because this function is
    /// the retraction cascade's edge selector and is exactly where a retracted
    /// edge must stop contributing.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_current_claim_targets<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        source_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, String)>, DbError> {
        // Both filters are required and neither subsumes the other:
        // `EDGE_IN_FORCE` drops retracted edges (this function is the retraction
        // cascade's edge selector), and the VISIBILITY markers drop rows the
        // viewer cannot see. Losing either one is a silent correctness bug in
        // opposite directions — a retracted edge still cascading, or a private
        // claim leaking into a cascade.
        //
        // The markers are escaped `{{EDGE_VISIBILITY:e}}` because this string now
        // goes through `format!` first (to interpolate `EDGE_IN_FORCE`); an
        // unescaped `{EDGE_VISIBILITY:e}` would be parsed as a format argument and
        // fail to compile. `splice` then substitutes the real predicate and
        // asserts the marker was present, so a future edit that drops it fails
        // loudly rather than failing open.
        let sql = viewer.splice(
            &format!(
                r#"
            SELECT e.id, e.target_id, e.relationship
            FROM edges e
            JOIN claims c ON c.id = e.target_id AND c.is_current = true
            WHERE e.source_id = $1
              AND e.source_type = 'claim'
              AND e.target_type = 'claim'
              AND e.relationship <> 'supersedes'
              AND {EDGE_IN_FORCE}
              /* {{EDGE_VISIBILITY:e}} */ /* {{VISIBILITY:c}} */
            ORDER BY e.id
            "#
            ),
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid, String)>(&sql).bind(source_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<(Uuid, Uuid, String)> = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Retract edges by closing their validity interval instead of deleting them.
    ///
    /// This is the non-destructive counterpart to `DELETE FROM edges`. The row —
    /// and with it `properties.decided_by`, the signature, the content hash and
    /// the full provenance of who asserted what and when — survives and stays
    /// queryable; it simply stops being in force for every reader that honours
    /// [`EDGE_IN_FORCE`].
    ///
    /// Idempotent: an already-retracted edge keeps its original `valid_to`, so
    /// re-retracting does not rewrite history to a later timestamp. Returns the
    /// ids actually closed by THIS call, which is what an undo record wants.
    ///
    /// Derived artifacts (`factors`, `bp_messages`, `mass_functions`) are NOT
    /// touched here and should still be deleted by the caller: they are
    /// materializations — `factors` are built by the `edges_auto_factor` trigger,
    /// BBAs are keyed `perspective_id = edge_id` — so removing them is cache
    /// invalidation, not data loss, and they regenerate from live edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn retract(pool: &PgPool, edge_ids: &[Uuid]) -> Result<Vec<Uuid>, DbError> {
        if edge_ids.is_empty() {
            return Ok(Vec::new());
        }
        let closed: Vec<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE edges
               SET valid_to = now()
             WHERE id = ANY($1)
               AND valid_to IS NULL
            RETURNING id
            "#,
        )
        .bind(edge_ids)
        .fetch_all(pool)
        .await?;
        Ok(closed)
    }

    /// True when the edge exists and is currently in force.
    ///
    /// Used as a re-derivation guard: a retracted edge must not be woken back up
    /// into a BBA by a later recompute.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    pub async fn is_in_force<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        edge_id: Uuid,
    ) -> Result<bool, DbError> {
        let found: Option<bool> = sqlx::query_scalar(&format!(
            "SELECT true FROM edges e WHERE e.id = $1 AND {EDGE_IN_FORCE}"
        ))
        .bind(edge_id)
        .fetch_optional(executor)
        .await?;
        Ok(found.unwrap_or(false))
    }

    /// Get edges by target entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_target<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE target_id = $1 AND target_type = $2
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            ORDER BY created_at DESC
            "#,
            target_id,
            target_type,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get edges by relationship type
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_relationship<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE relationship = $1
              AND ($2::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($3::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($3::uuid[]))))
            ORDER BY created_at DESC
            "#,
            relationship,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get edges between two specific entities
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_between<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
              AND ($5::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($6::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($6::uuid[]))))
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type,
            target_id,
            target_type,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// List edges with AND-composed filters.
    ///
    /// Each parameter is optional; null parameters are skipped via the
    /// `($N::T IS NULL OR column = $N)` pattern, so callers can pass any
    /// combination of source/target/relationship/type filters and the result
    /// is the intersection. Ordered by `valid_from DESC NULLS LAST, id`
    /// for stable pagination.
    ///
    /// This replaces the legacy first-non-null filter cascade in
    /// `routes::edges::list_edges`. Drainer GET-then-POST guards rely on
    /// composing multiple filters at the SQL layer.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list_filtered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        source_id: Option<Uuid>,
        target_id: Option<Uuid>,
        relationship: Option<&str>,
        source_type: Option<&str>,
        target_type: Option<&str>,
        limit: i64,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — the static transcription of
        // `Viewer::edge_predicate_fragment` (PR-13). This site carried no
        // PR-13 comment before, which is exactly why it is called out now: an
        // implementer converting the marked sites by grep would have converted
        // six of the eleven `edges` reads in this file and left five reading on
        // `owner_group_id` alone.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE ($1::uuid IS NULL OR source_id = $1)
              AND ($2::uuid IS NULL OR target_id = $2)
              AND ($3::text IS NULL OR relationship = $3)
              AND ($4::text IS NULL OR source_type = $4)
              AND ($5::text IS NULL OR target_type = $5)
              AND ($7::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($8::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($8::uuid[]))))
            ORDER BY valid_from DESC NULLS LAST, id
            LIMIT $6
            "#,
            source_id,
            target_id,
            relationship,
            source_type,
            target_type,
            limit,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// List all edges, optionally filtered by source_type and target_type
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn list_all<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE ($2::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($3::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($3::uuid[]))))
            ORDER BY created_at DESC
            LIMIT $1
            "#,
            limit,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Get currently-valid edges for an entity with a specific relationship.
    /// Returns edges where valid_to IS NULL (ongoing or atemporal).
    #[instrument(skip(executor, viewer))]
    pub async fn get_current_edges<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        entity_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        // MACRO SITE — static bypass-bool spelling; `sqlx::query!` cannot be
        // spliced. This is the STATIC TRANSCRIPTION of
        // `Viewer::edge_predicate_fragment` (PR-13): the co-ownership
        // INTERSECTION, not the plain predicate. Same arity and the SAME two
        // binds as before — `co_owner_group_id` (migration 072) reads the group
        // array a second time. A cross-group edge is visible only to a
        // principal in BOTH groups; `co_owner_group_id IS NULL` is the
        // single-owner case and short-circuits.
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE (source_id = $1 OR target_id = $1)
              AND relationship = $2
              AND valid_to IS NULL
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            ORDER BY valid_from DESC NULLS LAST
            "#,
            entity_id,
            relationship,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| EdgeRow {
                id: row.id,
                source_id: row.source_id,
                source_type: row.source_type,
                target_id: row.target_id,
                target_type: row.target_type,
                relationship: row.relationship,
                properties: row.properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            })
            .collect())
    }

    /// Patch an edge's lifecycle fields.
    ///
    /// Sets `valid_to` (when `Some`) and shallow-merges `properties_merge`
    /// (when `Some`) via JSONB `||`. Both arguments are optional but at least
    /// one must be `Some` to do useful work — the route layer enforces that.
    ///
    /// Returns the updated row. Returns `DbError::NotFound` if `id` doesn't
    /// exist (the underlying query returns no row).
    ///
    /// # Errors
    /// - `DbError::NotFound` if the edge doesn't exist
    /// - `DbError::QueryFailed` if the database query fails
    ///
    /// # Why this takes an executor rather than a `&PgPool`
    ///
    /// `edges` is tier-A under migration 077. An UPDATE on an unstamped session
    /// can only reach a row whose `edges_tenancy` USING admits it (a public
    /// edge), and it can only keep that row if the WITH CHECK admits it too. A
    /// generic executor lets the MCP `patch_edge` tool run this on an
    /// author-stamped transaction and emit its events on the same one. The
    /// `&state.db_pool` HTTP caller compiles unchanged. One statement, so no
    /// atomicity moves with it. The SQL is byte-identical.
    #[instrument(skip(executor, properties_merge))]
    pub async fn update_valid_to_and_properties<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
        properties_merge: Option<serde_json::Value>,
    ) -> Result<EdgeRow, DbError> {
        let row = sqlx::query!(
            r#"
            UPDATE edges
            SET valid_to = COALESCE($2, valid_to),
                properties = CASE
                    WHEN $3::jsonb IS NULL THEN properties
                    ELSE properties || $3::jsonb
                END
            WHERE id = $1
            RETURNING id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            "#,
            id,
            valid_to,
            properties_merge,
        )
        .fetch_optional(executor)
        .await?
        .ok_or(DbError::NotFound {
            entity: "edge".to_string(),
            id,
        })?;

        Ok(EdgeRow {
            id: row.id,
            source_id: row.source_id,
            source_type: row.source_type,
            target_id: row.target_id,
            target_type: row.target_type,
            relationship: row.relationship,
            properties: row.properties,
            valid_from: row.valid_from,
            valid_to: row.valid_to,
        })
    }

    /// Delete an edge by ID
    ///
    /// # Returns
    /// Returns `true` if the edge was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor))]
    /// Take a single edge out of force.
    ///
    /// Named `retract_by_id` rather than `delete` because it no longer deletes:
    /// edge removal is a RETRACTION throughout this codebase. The row survives
    /// with `valid_to` closed, so `properties.decided_by`, the signature and the
    /// content hash stay queryable and the act is reversible.
    ///
    /// Returns `true` when this call closed the row, `false` when the edge does
    /// not exist OR was already retracted. Callers that raise a 404 on `false`
    /// therefore also 404 a double-retract, which matches the previous
    /// delete-twice behaviour.
    ///
    /// Generic over the executor for the same reason as
    /// [`Self::update_valid_to_and_properties`]: the MCP `delete_edge` tool runs
    /// it on an author-stamped transaction. The SQL is byte-identical.
    pub async fn retract_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            UPDATE edges
               SET valid_to = now()
             WHERE id = $1
               AND valid_to IS NULL
            "#,
            id
        )
        .execute(executor)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all edges between two entities
    ///
    /// # Returns
    /// Returns the number of edges deleted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    /// Take every edge between two entities out of force.
    ///
    /// Retraction, not deletion — see [`Self::retract_by_id`]. Currently has no
    /// callers in the workspace; converted anyway so a future caller cannot reach
    /// for a hard-delete primitive that should not exist.
    pub async fn retract_between(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            UPDATE edges
               SET valid_to = now()
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
              AND valid_to IS NULL
            "#,
            source_id,
            source_type,
            target_id,
            target_type
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count edges for an entity (as either source or target)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_for_entity<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        entity_id: Uuid,
        entity_type: &str,
    ) -> Result<i64, DbError> {
        // MACRO SITE. PARENTHESES: the pre-existing predicate is an OR chain,
        // and AND binds tighter, so the visibility term is ANDed to the whole
        // disjunction rather than to its last arm. The visibility term is the
        // static transcription of `Viewer::edge_predicate_fragment` (PR-13),
        // whose own internal parenthesisation matters for the same reason: the
        // co-ownership conjunct must bind to `owner_group_id = ANY(...)`, NOT
        // to the whole `visibility = 'public' OR ...` disjunction — otherwise a
        // PUBLIC edge would be hidden from a viewer outside its co-owner group.
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM edges
            WHERE ((source_id = $1 AND source_type = $2)
                OR (target_id = $1 AND target_type = $2))
              AND ($3::bool OR visibility = 'public'
                   OR (owner_group_id = ANY($4::uuid[])
                       AND (co_owner_group_id IS NULL
                            OR co_owner_group_id = ANY($4::uuid[]))))
            "#,
            entity_id,
            entity_type,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
        )
        .fetch_one(executor)
        .await?;

        Ok(row.count.unwrap_or(0))
    }

    /// Get claims attributed to an agent via ATTRIBUTED_TO edges.
    ///
    /// Traverses `ATTRIBUTED_TO` edges (claim → agent) to find all claims
    /// attributed to the given agent. Supports pagination and minimum truth
    /// value filtering.
    ///
    /// This implements `prov:wasAttributedTo` traversal for W3C PROV-O compliance.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `agent_id` - The agent UUID to find attributed claims for
    /// * `min_truth` - Minimum truth value filter (inclusive)
    /// * `limit` - Maximum number of results
    /// * `offset` - Number of results to skip
    ///
    /// # Returns
    /// Tuples of (claim fields, edge properties) for each attributed claim.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_claims_attributed_to<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_id: Uuid,
        min_truth: f64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AttributedClaimRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id,
                   c.trace_id, c.created_at, c.updated_at,
                   e.properties AS edge_properties
            FROM edges e
            JOIN claims c ON e.source_id = c.id
            WHERE e.target_id = $1
              AND e.target_type = 'agent'
              AND e.source_type = 'claim'
              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO')
              AND c.truth_value >= $2
              /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */
            ORDER BY c.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
            5,
        );
        let mut q = sqlx::query_as::<_, AttributedClaimRow>(&sql)
            .bind(agent_id)
            .bind(min_truth)
            .bind(limit)
            .bind(offset);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await?;

        Ok(rows)
    }

    /// Count claims attributed to an agent via ATTRIBUTED_TO edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn count_claims_attributed_to<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        agent_id: Uuid,
        min_truth: f64,
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT COUNT(*)
            FROM edges e
            JOIN claims c ON e.source_id = c.id
            WHERE e.target_id = $1
              AND e.target_type = 'agent'
              AND e.source_type = 'claim'
              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO')
              AND c.truth_value >= $2
              /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:c} */
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql)
            .bind(agent_id)
            .bind(min_truth);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: (i64,) = q.fetch_one(executor).await?;

        Ok(row.0)
    }
}

/// Row type for claims attributed to an agent via ATTRIBUTED_TO edges
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttributedClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub agent_id: Uuid,
    pub trace_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub edge_properties: serde_json::Value,
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_edge_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/edge_tests.rs
    }
}

#[cfg(test)]
mod valid_to_enforcement_tests {
    //! These pin the ONE property that makes soft retraction worth having:
    //! a retracted edge must disappear from the derivation selector. Before
    //! `EDGE_IN_FORCE`, setting `valid_to` changed nothing observable, which is
    //! precisely why retirement resorted to DELETE.

    #[test]
    fn predicate_is_null_first_and_time_bounded() {
        // Guards against a rewrite to a bare `valid_to IS NULL`, which would
        // treat a future-dated retraction as already retracted, and against a
        // bare `valid_to > now()`, which would treat every ordinary atemporal
        // edge (valid_to NULL — 987,851 of 987,857 rows) as retracted and
        // silently blank the graph.
        assert!(super::EDGE_IN_FORCE.contains("valid_to IS NULL"));
        assert!(super::EDGE_IN_FORCE.contains("valid_to > now()"));
        assert!(super::EDGE_IN_FORCE.contains(" OR "));
    }
}
