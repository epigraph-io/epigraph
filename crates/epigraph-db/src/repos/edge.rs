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

/// Why a session that can READ an edge was refused a patch, retract or delete
/// of it (migrations 115/117/120: edge writes are owner / co-owner scoped).
///
/// A refusal is named, never reported as "not found": the caller can see the
/// edge, so "not found" would misreport a denial as absence. An edge the caller
/// cannot see keeps the not-found answer, so this is no existence oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeRefusal {
    /// The edge is owned by a group this session cannot write (another
    /// writer's edge, or a group-private edge the session only reads).
    OwnedByAnotherWriter,
    /// The edge is world-owned: a legacy edge with no attributable author, an
    /// edge written without a principal, or a structural edge outside operator
    /// decision D8's scope. Only the administrative (maintenance) path changes
    /// it.
    Administrative,
}

impl EdgeRefusal {
    /// The machine-readable rule, as the refusal bodies carry it.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            Self::OwnedByAnotherWriter => "owned_by_another_writer",
            Self::Administrative => "administrative_edge",
        }
    }

    /// The caller-facing text, naming the rule. `action` is what was refused
    /// ("patch", "retract", "delete").
    #[must_use]
    pub fn message(self, id: Uuid, action: &str) -> String {
        match self {
            Self::OwnedByAnotherWriter => format!(
                "edge {id} is owned by another writer: only its owner (or co-owner) may {action} \
                 it; nothing was written"
            ),
            Self::Administrative => format!(
                "edge {id} is an administrative (world-owned) edge; admin-only: no application \
                 session may {action} it; nothing was written"
            ),
        }
    }
}

/// The reason an `edge_retract` deferral records (the server's own text; it
/// names no row and reaches the edge's owner).
pub const EDGE_RETRACT_DEFERRAL_REASON: &str =
    "the edge's owner withdrew it; any other writer's BBAs keyed on it are removed, and the \
     affected beliefs re-derived, by the maintenance replay (operator decision D1)";

/// How an application act left an edge, for [`EdgeRepository::withdraw_edge_bbas_conn`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeWithdrawal {
    /// The act set `valid_to` (a retract, or a patch that closed the window).
    /// Only a `valid_to <= now()` counts: a FUTURE-dated retraction withdraws
    /// nothing yet and records nothing (its cleanup once it passes is a
    /// follow-up).
    Retracted,
    /// The act is about to DELETE the row (the workflow step rewire). Call the
    /// cleanup BEFORE the DELETE: the deferral's act check reads the row. The
    /// cleanup closes the row's window (`valid_to = now()`) first, since the
    /// definer admits only an edge out of force.
    BeingDeleted,
}

/// What [`EdgeRepository::withdraw_edge_bbas_conn`] did in the caller's act.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct BbaCleanup {
    /// The caller's OWN edge-keyed BBAs deleted in its act.
    pub deleted: u64,
    /// The `cascade.deferred` row (cause `edge_retract`) that hands every
    /// other writer's BBAs keyed on the edge to the administrative replay;
    /// `None` when the edge carries no edge-factor perspective (so no BBA can
    /// be keyed on it) or the retraction is future-dated.
    pub deferral_event_id: Option<Uuid>,
}

/// What [`EdgeRepository::remove_withdrawn_edge_bbas_conn`] did on the
/// maintenance connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WithdrawnEdgeBbas {
    /// Whether the edge was absent or out of force at the time of the call
    /// (the state the removal requires). `false`: nothing was removed.
    pub withdrawn: bool,
    /// Edge-keyed BBAs removed.
    pub deleted: u64,
    /// The distinct claims those BBAs lived on (their belief is re-derived).
    pub claims: Vec<Uuid>,
}

/// Which existing rows the create-or-get dedup probe counts as "present".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DedupProbe {
    /// Only an in-force row ([`EDGE_IN_FORCE`]): a retracted link re-asserted
    /// is a new edge.
    InForce,
    /// Any row, retracted included: an idempotent re-run never resurrects a
    /// retracted edge.
    AnyState,
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
    /// # The probe matches IN-FORCE rows only (migration 120, D8)
    ///
    /// An edge's writer may now retract its own edge. If the probe also matched
    /// a RETRACTED row, a writer that retracts a link and then re-asserts the
    /// same `(source, target, relationship)` would get the retracted row back
    /// with `was_created = false`: a silent no-op that reports success and
    /// leaves no link in force. So a retracted row is not a duplicate here, and
    /// the re-assertion inserts a new in-force edge. A caller whose RE-RUN must
    /// never resurrect a retracted edge (an idempotent ingestion re-run, where
    /// the retraction was an owner's or the administrative cascade's decision)
    /// uses [`Self::create_if_absent_including_retracted_conn`] instead.
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
        Self::create_if_absent_conn(
            conn,
            DedupProbe::InForce,
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

    /// [`Self::create_if_absent_including_retracted_conn`] on a pool.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_absent_including_retracted(
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
        Self::create_if_absent_including_retracted_conn(
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

    /// Like [`Self::create_if_not_exists_conn`], but a RETRACTED row with the
    /// same `(source, target, relationship)` also counts as present: nothing is
    /// inserted and that row is returned with `was_created = false`.
    ///
    /// For an idempotent RE-RUN of a structural writer (document and workflow
    /// ingestion, claim decomposition) whose edge may since have been retracted
    /// by its owner or by the administrative cascade (a dedup collision, a
    /// supersede migration): re-running the ingestion must not resurrect that
    /// decision. It is the behaviour every caller had before migration 120.
    /// Never use it for a caller's own ASSERTION (a link tool, the HTTP create
    /// route): there it turns "retract, then link again" into a silent no-op.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_if_absent_including_retracted_conn(
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
        Self::create_if_absent_conn(
            conn,
            DedupProbe::AnyState,
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

    /// Does the SESSION own edge `id` (its owner or co-owner is in the
    /// session's writable set)? The `owned_by_caller` a link tool or the HTTP
    /// create route reports next to a created or re-asserted edge: after
    /// migration 120 a re-assertion of another writer's edge returns THEIR edge,
    /// which this caller can neither patch, retract nor delete.
    ///
    /// Run it on the same stamped connection as the write. An unstamped or
    /// bypass session has an empty writable set and gets `false`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn owned_by_session<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<bool, DbError> {
        Ok(sqlx::query_scalar::<_, bool>(
            "-- VISIBILITY-EXEMPT: an ownership test, not a read. It answers only \
             whether the SESSION's writable set holds the edge's owner or \
             co-owner, and a writable group is always a readable one, so it says \
             nothing about an edge this session cannot already see.\n\
             SELECT EXISTS (SELECT 1 FROM edges e \
                             WHERE e.id = $1 \
                               AND (e.owner_group_id = ANY (public.epigraph_writable_groups()) \
                                    OR e.co_owner_group_id \
                                       = ANY (public.epigraph_writable_groups())))",
        )
        .bind(id)
        .fetch_one(executor)
        .await?)
    }

    /// The one dedup probe + INSERT behind [`Self::create_if_not_exists_conn`]
    /// and [`Self::create_if_absent_including_retracted_conn`].
    #[allow(clippy::too_many_arguments)]
    async fn create_if_absent_conn(
        conn: &mut sqlx::PgConnection,
        probe: DedupProbe,
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

        // VISIBILITY-EXEMPT (both spellings): dedup probe inside a WRITE path
        // (`create_or_get`). It must see an existing edge regardless of who is
        // asking, or the "get" half silently becomes "create" and the table
        // grows a duplicate every time a caller without read access re-asserts
        // a link that is already there. PR-16 owns the write-side authorization
        // that decides whether the caller may create the edge at all.
        let sql = match probe {
            DedupProbe::InForce => format!(
                "-- VISIBILITY-EXEMPT: dedup probe inside a WRITE path (in-force rows).\n\
                 SELECT e.id, e.source_id, e.source_type, e.target_id, e.target_type, \
                        e.relationship, e.properties, e.valid_from, e.valid_to \
                   FROM edges e \
                  WHERE e.source_id = $1 AND e.target_id = $2 AND e.relationship = $3 \
                    AND {EDGE_IN_FORCE} \
                  LIMIT 1"
            ),
            DedupProbe::AnyState => "-- VISIBILITY-EXEMPT: dedup probe inside a WRITE path \
                 (retracted rows included).\n\
                 SELECT e.id, e.source_id, e.source_type, e.target_id, e.target_type, \
                        e.relationship, e.properties, e.valid_from, e.valid_to \
                   FROM edges e \
                  WHERE e.source_id = $1 AND e.target_id = $2 AND e.relationship = $3 \
                  LIMIT 1"
                .to_string(),
        };
        #[allow(clippy::type_complexity)]
        let existing: Option<(
            Uuid,
            Uuid,
            String,
            Uuid,
            String,
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        )> = sqlx::query_as(&sql)
            .bind(source_id)
            .bind(target_id)
            .bind(relationship)
            .fetch_optional(&mut *tx)
            .await?;

        if let Some(row) = existing {
            tx.commit().await?;
            return Ok((
                EdgeRow {
                    id: row.0,
                    source_id: row.1,
                    source_type: row.2,
                    target_id: row.3,
                    target_type: row.4,
                    relationship: row.5,
                    properties: row.6,
                    valid_from: row.7,
                    valid_to: row.8,
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

    /// Write the `paper -processed_by-> agent` pipeline stamp for `pipeline`,
    /// unless that exact stamp is already on the paper for that agent. Returns
    /// `true` when a new edge was inserted.
    ///
    /// The stamp is part of the dedup key. [`Self::create_if_not_exists_conn`]
    /// dedups on `(source_id, target_id, relationship)` only. When the ingest
    /// tools used it, a chunked ingest's second chapter (`...:ch3` after
    /// `...:ch1`) found the first chapter's edge and wrote nothing. The paper
    /// then carried one stamp however many chapters landed, so
    /// `check_already_ingested(pipeline_version = "...:ch3")` answered false for
    /// an ingested chapter (G8 review, backlog 02653c4a). With the stamp in the
    /// key, each chunk writes its own edge and a re-run of the same chunk
    /// writes none. No unique index constrains the triple (migrations 017, 018
    /// and 053 dropped it), so parallel `processed_by` edges are legal.
    ///
    /// Takes the caller's connection so the stamp commits in the same
    /// transaction as the walk that earned it. `begin()` opens a SAVEPOINT
    /// inside that transaction, keeping the probe and the INSERT atomic, as in
    /// [`Self::create_if_not_exists_conn`].
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[instrument(skip(conn))]
    pub async fn create_processed_by_stamp_if_absent_conn(
        conn: &mut sqlx::PgConnection,
        paper_id: Uuid,
        agent_id: Uuid,
        pipeline: &str,
        tool: &str,
    ) -> Result<bool, DbError> {
        use sqlx::Acquire;
        let mut tx = conn.begin().await?;

        let existing = sqlx::query_scalar::<_, Uuid>(
            "-- VISIBILITY-EXEMPT: dedup probe inside a WRITE path, for the reason \
             given on `create_if_not_exists_conn`: it must see an existing stamp \
             whoever is asking, or every re-run writes a duplicate.\n\
             SELECT id FROM edges \
             WHERE source_id = $1 AND source_type = 'paper' \
               AND target_id = $2 AND relationship = 'processed_by' \
               AND properties ->> 'pipeline' = $3 \
             LIMIT 1",
        )
        .bind(paper_id)
        .bind(agent_id)
        .bind(pipeline)
        .fetch_optional(&mut *tx)
        .await?;

        if existing.is_some() {
            tx.commit().await?;
            return Ok(false);
        }

        Self::create(
            &mut *tx,
            paper_id,
            "paper",
            agent_id,
            "agent",
            "processed_by",
            Some(serde_json::json!({ "pipeline": pipeline, "tool": tool })),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
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
    /// The probe matches a row in ANY state, a retracted one included: a
    /// matcher promotion over a pair whose matcher edge was retracted stays a
    /// dedup hit, as the matcher's retirement path expects. The link tools'
    /// forms ([`Self::create_symmetric_if_absent_returning_conn`],
    /// [`Self::create_symmetric_if_absent_oriented_conn`]) match rows in force
    /// only (migration 120), so a writer's retract-then-relink is a new edge.
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
        // In force only (migration 120): a retracted link asserted again is a
        // new edge, never a silent `false` onto the retracted row. 091's
        // `edges_alternative_of_symmetric_uniq` covers `valid_to IS NULL` rows
        // only, so the new row does not conflict with the retracted one.
        let insert = format!(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties)
             SELECT $1, 'claim', $2, 'claim', $3, $4
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
                   AND {EDGE_IN_FORCE_UNALIASED}
             )
             ON CONFLICT DO NOTHING
             RETURNING id"
        );
        let inserted: Option<Uuid> = sqlx::query_scalar(&insert)
            .bind(a)
            .bind(b)
            .bind(relationship)
            .bind(Json(properties))
            .fetch_optional(&mut *conn)
            .await?;

        if let Some(id) = inserted {
            return Ok((id, true));
        }

        // Dedup hit — surface the id of the existing symmetric edge in force.
        let probe = format!(
            "-- VISIBILITY-EXEMPT: symmetric-dedup probe inside a WRITE path;
             -- same reasoning as `create_or_get`'s.
             SELECT id FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND relationship = $3
               AND {EDGE_IN_FORCE_UNALIASED}
             LIMIT 1"
        );
        let existing: Uuid = sqlx::query_scalar(&probe)
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
        // In force only (migration 120), as `create_symmetric_if_absent_returning_conn`:
        // a retracted link asserted again is a new edge (and the belief wiring
        // keyed on it attaches to a row in force), never a silent
        // `was_created = false` onto the retracted row. 090's
        // `edges_symmetric_relationship_uniq` covers matcher-sourced
        // `valid_to IS NULL` rows only, so the new row does not conflict.
        let insert = format!(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties)
             SELECT $1, 'claim', $2, 'claim', $3, $4
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
                   AND {EDGE_IN_FORCE_UNALIASED}
             )
             RETURNING id, source_id, target_id"
        );
        let inserted: Option<(Uuid, Uuid, Uuid)> = sqlx::query_as(&insert)
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

        // Dedup hit — surface the existing row in force AS STORED, which may be
        // the reverse of the caller's (a, b).
        let probe = format!(
            "SELECT id, source_id, target_id FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND relationship = $3
               AND {EDGE_IN_FORCE_UNALIASED}
             LIMIT 1"
        );
        let (edge_id, source_id, target_id): (Uuid, Uuid, Uuid) = sqlx::query_as(&probe)
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

    /// Symmetric idempotent create for the HTTP route (`POST /api/v1/edges`),
    /// returning the full STORED [`EdgeRow`].
    ///
    /// Same bidirectional, in-force-only dedup as
    /// [`Self::create_symmetric_if_absent_oriented_conn`] — `(a, b)` and
    /// `(b, a)` with the same `relationship` are one edge — but shaped for the
    /// HTTP handler, which (unlike `link_epistemic`) accepts `valid_from` /
    /// `valid_to` and answers with every column of the row. On a dedup hit the
    /// returned row is the existing one AS STORED: its orientation may be the
    /// reverse of the caller's `(a, b)`, and its properties / validity window
    /// are the stored ones, not the request's. Belief-wiring callers must wire
    /// the returned `source_id` / `target_id` (see
    /// [`Self::create_symmetric_if_absent_oriented`] for why).
    ///
    /// Endpoint types are hard-coded `'claim'` / `'claim'` like the sibling
    /// functions: symmetry is only established between two claims.
    ///
    /// The dedup is best-effort, like the siblings': `INSERT ... WHERE NOT
    /// EXISTS` under READ COMMITTED with no advisory lock or unique index, so
    /// two concurrent calls `(a, b)` / `(b, a)` can both insert, and an
    /// in-force reverse edge this connection cannot see (RLS) does not block
    /// the insert. Losing either race falls back to the pre-dedup two-row
    /// behaviour; a database-level backstop waits on canonical relationship
    /// spelling (migration 090 rejected a broad unique index).
    ///
    /// Runtime `sqlx::query*` throughout — no `.sqlx/` prepared-cache entry.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails. On the
    /// dedup-hit branch that includes the case where the conflicting edge is not
    /// visible to this connection (`RowNotFound`): a loud error, never a wrong
    /// answer.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(conn, properties))]
    pub async fn create_symmetric_if_absent_row_conn(
        conn: &mut sqlx::PgConnection,
        a: Uuid,
        b: Uuid,
        relationship: &str,
        properties: Option<serde_json::Value>,
        valid_from: Option<chrono::DateTime<chrono::Utc>>,
        valid_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(EdgeRow, bool), DbError> {
        type Row = (
            Uuid,
            Uuid,
            String,
            Uuid,
            String,
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        );
        fn edge_row(r: Row) -> EdgeRow {
            EdgeRow {
                id: r.0,
                source_id: r.1,
                source_type: r.2,
                target_id: r.3,
                target_type: r.4,
                relationship: r.5,
                properties: r.6,
                valid_from: r.7,
                valid_to: r.8,
            }
        }

        // In force only (migration 120), as the other link-tool forms: a
        // retracted edge asserted again is a new edge.
        let insert = format!(
            "INSERT INTO edges (source_id, source_type, target_id, target_type,
                                relationship, properties, valid_from, valid_to)
             SELECT $1, 'claim', $2, 'claim', $3, $4, $5, $6
             WHERE NOT EXISTS (
                 SELECT 1 FROM edges
                 WHERE ((source_id = $1 AND target_id = $2)
                     OR (source_id = $2 AND target_id = $1))
                   AND relationship = $3
                   AND {EDGE_IN_FORCE_UNALIASED}
             )
             RETURNING id, source_id, source_type, target_id, target_type,
                       relationship, properties, valid_from, valid_to"
        );
        let inserted: Option<Row> = sqlx::query_as(&insert)
            .bind(a)
            .bind(b)
            .bind(relationship)
            .bind(Json(properties.unwrap_or(serde_json::json!({}))))
            .bind(valid_from)
            .bind(valid_to)
            .fetch_optional(&mut *conn)
            .await?;

        if let Some(row) = inserted {
            return Ok((edge_row(row), true));
        }

        // Dedup hit — the existing row in force AS STORED, which may be the
        // reverse of the caller's (a, b).
        let probe = format!(
            "-- VISIBILITY-EXEMPT: symmetric-dedup probe inside a WRITE path;
             -- same reasoning as `create_or_get`'s.
             SELECT id, source_id, source_type, target_id, target_type,
                    relationship, properties, valid_from, valid_to
               FROM edges
              WHERE ((source_id = $1 AND target_id = $2)
                  OR (source_id = $2 AND target_id = $1))
                AND relationship = $3
                AND {EDGE_IN_FORCE_UNALIASED}
              LIMIT 1"
        );
        let existing: Row = sqlx::query_as(&probe)
            .bind(a)
            .bind(b)
            .bind(relationship)
            .fetch_one(&mut *conn)
            .await?;

        Ok((edge_row(existing), false))
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

    /// The entity types node `node_id` carries as an edge endpoint, from the
    /// edges this viewer can see: every distinct `source_type` of an edge
    /// leaving it and `target_type` of an edge entering it, sorted.
    ///
    /// Backlog cdd8d097 / aedde855 (G9). [`Self::get_by_source`] and
    /// [`Self::get_by_target`] key on `(id, type)`, and the graph tools passed
    /// the literal `"claim"`, so a paper, workflow or agent node returned no
    /// edges at all. The edges table is the one place every endpoint type is
    /// recorded, whatever table backs it (`entity_types` is operator-extensible),
    /// so the node's real type is read from there rather than probed table by
    /// table. Normally one type; more than one only if two tables share a UUID,
    /// and then the caller reads each.
    ///
    /// Filtered by the co-owner-aware edge predicate, so it reveals a type only
    /// through an edge the viewer could already read.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn endpoint_types<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        node_id: Uuid,
    ) -> Result<Vec<String>, DbError> {
        let sql = viewer.splice(
            "SELECT t FROM ( \
                 SELECT e.source_type AS t FROM edges e \
                 WHERE e.source_id = $1 /* {EDGE_VISIBILITY:e} */ \
                 UNION \
                 SELECT e.target_type AS t FROM edges e \
                 WHERE e.target_id = $1 /* {EDGE_VISIBILITY:e} */ \
             ) types ORDER BY t",
            2,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql).bind(node_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
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

    /// Can `viewer` READ the edge `id`? The edge-visibility predicate (the
    /// owner / co-owner intersection, `Viewer::edge_predicate_fragment`), spliced.
    ///
    /// The caller-read gate for MCP `patch_edge` / `delete_edge`. Their writes
    /// run under the server agent's stamp, so without this a caller that cannot
    /// read an edge (one touching another group's private claim) could still
    /// retire or relabel it by naming its id, as long as the server agent could
    /// write it (batch H-a review, atomicity-authz). Run it on the same
    /// transaction as the write.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn visible_to<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<bool, DbError> {
        let sql = viewer.splice(
            "SELECT EXISTS (SELECT 1 FROM edges e WHERE e.id = $1 /* {EDGE_VISIBILITY:e} */)",
            2,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_one(executor).await?)
    }

    /// The edge-keyed BBA cleanup every application act that withdraws an edge
    /// runs, in the act's own transaction (migration 120; D1 names edge-keyed
    /// BBA deletes an administrative cascade).
    ///
    /// When the edge carries an edge-factor perspective (`perspectives.id =
    /// edge`, `perspective_type = 'edge'`: every BBA keyed on the edge hangs off
    /// it, by FK) and the act withdrew it (see [`EdgeWithdrawal`]):
    ///
    /// * (b) it FIRST records a `cause = 'edge_retract'` deferral through
    ///   120's `epigraph_record_cascade_deferral` (the session must own or
    ///   co-own the edge, and the edge must be out of force; the row names the
    ///   session principal). The DEFINER derives the deferral's `sources` from
    ///   state, as the claims of the session's own BBA rows keyed on the edge,
    ///   so it runs before (a) deletes them; no caller names a claim to
    ///   re-derive. The caller cannot re-derive a belief cache it does not own,
    ///   so the administrative replay re-derives those claims, together with
    ///   the claims of every OTHER writer's BBA keyed on the edge, which it
    ///   removes. Recorded even when only the caller's own BBAs existed, so
    ///   their claims are re-derived.
    /// * (a) it then deletes the caller's OWN edge-keyed BBAs, scoped
    ///   explicitly to the session's writable set (the same set the definer
    ///   read), so a privileged stamped session is held to the same owner
    ///   scope as the application role.
    ///
    /// [`EdgeWithdrawal::BeingDeleted`] first closes the row's window
    /// (`valid_to = now()`, the transaction's start, so `valid_to <= now()`
    /// holds for the rest of the act): the deferral definer admits only an edge
    /// out of force, and the row is deleted by the caller right after.
    ///
    /// A future-dated retraction, or an edge no BBA can be keyed on, does
    /// nothing.
    ///
    /// # Errors
    /// The deferral definer's refusal or any query error; the caller's act
    /// rolls back with it.
    #[instrument(skip(conn, oauth))]
    pub async fn withdraw_edge_bbas_conn(
        conn: &mut sqlx::PgConnection,
        edge_id: Uuid,
        withdrawal: EdgeWithdrawal,
        oauth: Option<&serde_json::Value>,
        reason: &str,
    ) -> Result<BbaCleanup, DbError> {
        // Reads only whether an edge-factor perspective exists for the edge the
        // caller's act touches, the edge's own `valid_to`, and whether the
        // session owns it. An edge the session does not own is left alone: the
        // act itself is refused by row security (and rolls back), and the
        // deferral definer would refuse it anyway.
        let (keyed, withdrawn, owned): (bool, bool, bool) = sqlx::query_as(
            "-- VISIBILITY-EXEMPT: the state of an edge the caller's act touches.\n\
             SELECT EXISTS (SELECT 1 FROM perspectives p \
                             WHERE p.id = $1 AND p.perspective_type = 'edge'), \
                    COALESCE((SELECT CASE WHEN $2 THEN true \
                                          ELSE e.valid_to IS NOT NULL AND e.valid_to <= now() END \
                                FROM edges e WHERE e.id = $1), false), \
                    COALESCE((SELECT public.epigraph_bypass() \
                                     OR e.owner_group_id = ANY (public.epigraph_writable_groups()) \
                                     OR e.co_owner_group_id \
                                        = ANY (public.epigraph_writable_groups()) \
                                FROM edges e WHERE e.id = $1), false)",
        )
        .bind(edge_id)
        .bind(withdrawal == EdgeWithdrawal::BeingDeleted)
        .fetch_one(&mut *conn)
        .await?;
        if !keyed || !withdrawn || !owned {
            return Ok(BbaCleanup::default());
        }
        if withdrawal == EdgeWithdrawal::BeingDeleted {
            // The row is deleted right after this returns; close its window
            // first so the deferral definer sees an edge out of force (it
            // admits no edge in force, so no deferral names a live edge).
            sqlx::query(
                "UPDATE edges SET valid_to = now() \
                  WHERE id = $1 AND (valid_to IS NULL OR valid_to > now())",
            )
            .bind(edge_id)
            .execute(&mut *conn)
            .await?;
        }
        // (b) The deferral, BEFORE (a): the definer reads the caller's own
        // rows keyed on the edge as the claims to re-derive (the caller names
        // none), and hands every other writer's rows to the replay.
        let principal: Option<Uuid> = sqlx::query_scalar("SELECT public.epigraph_principal_id()")
            .fetch_one(&mut *conn)
            .await?;
        let deferral = crate::repos::admin_cascade::record_deferral(
            &mut *conn,
            "edge_retract",
            principal,
            edge_id,
            None,
            &[],
            oauth,
            reason,
        )
        .await?;
        // (a) The caller's own rows.
        let deleted = sqlx::query(
            "DELETE FROM mass_functions \
              WHERE perspective_id = $1 \
                AND owner_group_id = ANY (public.epigraph_writable_groups())",
        )
        .bind(edge_id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        Ok(BbaCleanup {
            deleted,
            deferral_event_id: Some(deferral),
        })
    }

    /// The administrative half of an `edge_retract` cascade, on the
    /// MAINTENANCE connection: remove every BBA keyed on the edge (keyed on
    /// `perspective_type = 'edge'`, so a genuine perspective's BBAs are never
    /// touched) and return the claims they lived on.
    ///
    /// STATE-DERIVED: it acts only while the edge row is absent or out of force
    /// (`valid_to <= now()`). An edge in force at the time of the call (its
    /// owner un-retracted it, or the deferral was stale) removes nothing and
    /// reports `withdrawn = false`, so a deferral can never make it do what the
    /// edge's state does not justify. It first locks the edge row (`FOR
    /// UPDATE`), so an act in flight on the edge commits before it reads.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a query fails.
    #[instrument(skip(conn))]
    pub async fn remove_withdrawn_edge_bbas_conn(
        conn: &mut sqlx::PgConnection,
        edge_id: Uuid,
    ) -> Result<WithdrawnEdgeBbas, DbError> {
        // Lock the row (when it exists) before reading its state: an owner's
        // act on the edge holds the row until it commits, so its deferral is
        // committed, and visible to the caller's next read, once this returns.
        let in_force: Option<bool> = sqlx::query_scalar(
            "-- VISIBILITY-EXEMPT: administrative (maintenance connection).\n\
             SELECT e.valid_to IS NULL OR e.valid_to > now() \
               FROM edges e WHERE e.id = $1 FOR UPDATE",
        )
        .bind(edge_id)
        .fetch_optional(&mut *conn)
        .await?;
        let withdrawn = !in_force.unwrap_or(false);
        if !withdrawn {
            return Ok(WithdrawnEdgeBbas::default());
        }
        let claims: Vec<Uuid> = sqlx::query_scalar(
            "WITH gone AS ( \
                 DELETE FROM mass_functions mf \
                  USING perspectives p \
                  WHERE p.id = mf.perspective_id \
                    AND p.id = $1 \
                    AND p.perspective_type = 'edge' \
                 RETURNING mf.claim_id) \
             SELECT claim_id FROM gone",
        )
        .bind(edge_id)
        .fetch_all(&mut *conn)
        .await?;
        let deleted = claims.len() as u64;
        let mut distinct: Vec<Uuid> = claims;
        distinct.sort_unstable();
        distinct.dedup();
        Ok(WithdrawnEdgeBbas {
            withdrawn: true,
            deleted,
            claims: distinct,
        })
    }

    /// The edges whose BBAs outlived them: an edge-factor perspective
    /// (`perspective_type = 'edge'`) with BBAs keyed on it whose edge is absent
    /// or out of force. The one-shot legacy sweep
    /// (`replay_deferred_cascades --sweep-withdrawn-edge-bbas`) removes their
    /// BBAs through the same administrative path as an `edge_retract` replay.
    /// Maintenance connection only.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(conn))]
    pub async fn withdrawn_edges_with_bbas_conn(
        conn: &mut sqlx::PgConnection,
        limit: i64,
    ) -> Result<Vec<Uuid>, DbError> {
        Ok(sqlx::query_scalar(
            "-- VISIBILITY-EXEMPT: administrative (maintenance connection).\n\
             SELECT p.id FROM perspectives p \
              WHERE p.perspective_type = 'edge' \
                AND EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.perspective_id = p.id) \
                AND NOT EXISTS (SELECT 1 FROM edges e \
                                 WHERE e.id = p.id \
                                   AND (e.valid_to IS NULL OR e.valid_to > now())) \
              ORDER BY p.id \
              LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Why a write this session was just refused on edge `id` was refused:
    /// the edge is world-owned (administrative) or another writer's. `None`
    /// when `viewer` cannot read the edge (the caller then answers "not
    /// found", as before). Run it on the same transaction as the refused write,
    /// after [`DbError::WriteRefused`].
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn refusal_for<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<EdgeRefusal>, DbError> {
        let sql = viewer.splice(
            "SELECT e.owner_group_id = '00000000-0000-0000-0000-000000000000'::uuid \
               FROM edges e WHERE e.id = $1 /* {EDGE_VISIBILITY:e} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?.map(|world| {
            if world {
                EdgeRefusal::Administrative
            } else {
                EdgeRefusal::OwnedByAnotherWriter
            }
        }))
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
    /// `DbError::WriteRefused` (and nothing retracted) when an in-force edge
    /// this session can read was not closed: migration 117's owner-scoped
    /// UPDATE matches no row it refuses and reports success.
    /// `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn retract(pool: &PgPool, edge_ids: &[Uuid]) -> Result<Vec<Uuid>, DbError> {
        if edge_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = pool.begin().await?;
        let (closed, refused): (Vec<Uuid>, Option<Uuid>) = sqlx::query_as(
            r#"
            WITH seen AS (SELECT id FROM edges WHERE id = ANY($1) AND valid_to IS NULL),
                 done AS (
                    UPDATE edges
                       SET valid_to = now()
                     WHERE id = ANY($1)
                       AND valid_to IS NULL
                    RETURNING id)
            SELECT COALESCE((SELECT array_agg(id) FROM done), ARRAY[]::uuid[]),
                   (SELECT id FROM seen EXCEPT SELECT id FROM done LIMIT 1)
            "#,
        )
        .bind(edge_ids)
        .fetch_one(&mut *tx)
        .await?;
        if let Some(id) = refused {
            return Err(DbError::WriteRefused {
                entity: "edge".to_string(),
                id,
                action: "retract".to_string(),
            });
        }
        tx.commit().await?;
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
        // Migration 117 made UPDATE on `edges` owner-scoped with a RESTRICTIVE
        // USING clause, so an edge this session can READ but not update (a
        // world-owned edge between two public claims, another group's edge)
        // matches zero rows WITHOUT an error. `seen` reads the row under the
        // statement's snapshot, so the one statement tells "no such edge"
        // (`NotFound`) from "refused" (`WriteRefused`) instead of reporting a
        // refused patch as a missing edge.
        let row = sqlx::query!(
            r#"
            WITH seen AS (SELECT 1 FROM edges WHERE id = $1),
                 upd AS (
                    UPDATE edges
                    SET valid_to = COALESCE($2, valid_to),
                        properties = CASE
                            WHEN $3::jsonb IS NULL THEN properties
                            ELSE properties || $3::jsonb
                        END
                    WHERE id = $1
                    RETURNING id, source_id, source_type, target_id, target_type, relationship,
                              properties, valid_from, valid_to)
            SELECT upd.id AS "id?", upd.source_id AS "source_id?",
                   upd.source_type AS "source_type?", upd.target_id AS "target_id?",
                   upd.target_type AS "target_type?", upd.relationship AS "relationship?",
                   upd.properties AS "properties?", upd.valid_from AS "valid_from?",
                   upd.valid_to AS "valid_to?",
                   EXISTS (SELECT 1 FROM seen) AS "visible!"
              FROM (SELECT 1) AS one LEFT JOIN upd ON true
            "#,
            id,
            valid_to,
            properties_merge,
        )
        .fetch_one(executor)
        .await?;

        match (
            row.id,
            row.source_id,
            row.source_type,
            row.target_id,
            row.target_type,
            row.relationship,
            row.properties,
        ) {
            (
                Some(id),
                Some(source_id),
                Some(source_type),
                Some(target_id),
                Some(target_type),
                Some(relationship),
                Some(properties),
            ) => Ok(EdgeRow {
                id,
                source_id,
                source_type,
                target_id,
                target_type,
                relationship,
                properties,
                valid_from: row.valid_from,
                valid_to: row.valid_to,
            }),
            _ if row.visible => Err(DbError::WriteRefused {
                entity: "edge".to_string(),
                id,
                action: "update".to_string(),
            }),
            _ => Err(DbError::NotFound {
                entity: "edge".to_string(),
                id,
            }),
        }
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
    ///
    /// # Errors
    /// `DbError::WriteRefused` when the edge is in force and readable by this
    /// session but row security refused the retraction (migration 117's
    /// owner-scoped UPDATE matches zero rows without an error; `open` reads the
    /// row under the statement's snapshot to tell the two apart).
    pub async fn retract_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        id: Uuid,
    ) -> Result<bool, DbError> {
        let r = sqlx::query!(
            r#"
            WITH open AS (SELECT 1 FROM edges WHERE id = $1 AND valid_to IS NULL),
                 upd AS (
                    UPDATE edges
                       SET valid_to = now()
                     WHERE id = $1
                       AND valid_to IS NULL
                    RETURNING 1)
            SELECT (SELECT count(*) FROM open) AS "open!", (SELECT count(*) FROM upd) AS "closed!"
            "#,
            id
        )
        .fetch_one(executor)
        .await?;
        let (open, closed) = (r.open, r.closed);

        if closed < open {
            return Err(DbError::WriteRefused {
                entity: "edge".to_string(),
                id,
                action: "retract".to_string(),
            });
        }
        Ok(closed > 0)
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
        // Checked, in a transaction: an in-force edge this session can read
        // but not retract (migration 117) refuses the whole call.
        let mut tx = pool.begin().await?;
        let r = sqlx::query!(
            r#"
            WITH seen AS (
                    SELECT 1 FROM edges
                     WHERE source_id = $1 AND source_type = $2
                       AND target_id = $3 AND target_type = $4
                       AND valid_to IS NULL),
                 done AS (
                    UPDATE edges
                       SET valid_to = now()
                    WHERE source_id = $1 AND source_type = $2
                      AND target_id = $3 AND target_type = $4
                      AND valid_to IS NULL
                    RETURNING 1)
            SELECT (SELECT count(*) FROM seen) AS "seen!", (SELECT count(*) FROM done) AS "done!"
            "#,
            source_id,
            source_type,
            target_id,
            target_type
        )
        .fetch_one(&mut *tx)
        .await?;
        let changed =
            super::require_all_changed("edge from", source_id, "retract", (r.seen, r.done))?;
        tx.commit().await?;
        Ok(changed)
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
