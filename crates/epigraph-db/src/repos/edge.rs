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

/// Property key on a `paper -asserts-> claim` edge naming the artifact bytes
/// the claim was extracted from. Required by migration 074's
/// `edges_paper_asserts_requires_essence` trigger.
pub const ESSENCE_DIGEST_KEY: &str = "essence_digest";

/// Does `value` have the exact shape migration 074's trigger accepts —
/// 64 lowercase hex characters, i.e. a BLAKE3-256 digest?
///
/// This is the Rust mirror of the SQL regex `'^[0-9a-f]{64}$'`. Both exist on
/// purpose: the trigger is the at-rest guarantee, and this lets a caller decide
/// "already bound / not yet bound" without provoking a constraint violation.
#[must_use]
pub fn is_essence_digest_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

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

/// Repository for Edge operations
pub struct EdgeRepository;

impl EdgeRepository {
    /// Create a new edge relationship
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `source_id` - Source entity UUID
    /// * `source_type` - Source entity type (e.g., "claim", "agent")
    /// * `target_id` - Target entity UUID
    /// * `target_type` - Target entity type
    /// * `relationship` - Relationship label (e.g., "supports", "refutes")
    /// * `properties` - Optional JSONB properties for the edge
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, properties))]
    pub async fn create(
        pool: &PgPool,
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
        .fetch_one(pool)
        .await?;

        Ok(row.id)
    }

    /// Write the `paper -asserts-> claim` edge for a claim extracted from the
    /// artifact bytes whose BLAKE3-256 digest is `essence_digest`.
    ///
    /// This exists instead of a plain
    /// [`create_if_not_exists`](Self::create_if_not_exists) call because the
    /// digest is a **non-optional positional argument**: an ingestion call site
    /// physically cannot write an asserts edge and forget to say which bytes it
    /// came from. That is the compile-time half of the guarantee; migration
    /// 074's `edges_paper_asserts_requires_essence` trigger is the runtime half,
    /// and it is the load-bearing one — `routes/edges.rs` allowlists `asserts`
    /// on the generic `POST /api/v1/edges`, so a Rust-only guard is routable
    /// around.
    ///
    /// # Merge, never overwrite
    ///
    /// A plain create-if-not-exists would leave the FIRST-written edge unbound
    /// forever on a re-ingest, so an existing row that carries no digest is
    /// patched with this one. An existing row that already carries a
    /// well-formed digest is left **exactly** as it is: the edge names the
    /// bytes this claim was first extracted from, and a later rendition of the
    /// same document is a different rendition, not a correction. The verifier
    /// reports that state as `stale_binding` — a warning, because multi-
    /// rendition history is legitimate and is the whole reason the digest lives
    /// per-rendition rather than in a column on `papers`.
    ///
    /// Returns `(EdgeRow, was_created)`, `was_created = false` for both the
    /// untouched and the digest-patched existing row.
    ///
    /// # Errors
    /// - [`DbError::InvalidData`] if `properties` is present but is not a JSON
    ///   object (there would be nowhere to put the digest).
    /// - [`DbError::QueryFailed`] if any database operation fails.
    #[instrument(skip(pool, properties))]
    pub async fn upsert_asserts_edge(
        pool: &PgPool,
        paper_id: Uuid,
        claim_id: Uuid,
        essence_digest: &[u8; 32],
        properties: Option<serde_json::Value>,
    ) -> Result<(EdgeRow, bool), DbError> {
        let digest_hex = epigraph_core::blob::hash_hex(&essence_digest[..]);

        let mut tx = pool.begin().await?;

        // FOR UPDATE, unlike `create_if_not_exists`'s plain SELECT: this
        // statement can be followed by an UPDATE of the row it just read, so
        // two concurrent binders of the same (paper, claim) must serialize
        // rather than both patch.
        let existing = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND target_id = $2 AND relationship = 'asserts'
            LIMIT 1
            FOR UPDATE
            "#,
            paper_id,
            claim_id,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = existing {
            let already_bound = row
                .properties
                .get(ESSENCE_DIGEST_KEY)
                .and_then(serde_json::Value::as_str)
                .is_some_and(is_essence_digest_hex);

            let edge = if already_bound {
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
                }
            } else {
                // `||` merges, so the planner's own properties survive. The
                // key is spelled out here because a query! macro cannot
                // interpolate a Rust const; it must stay equal to
                // ESSENCE_DIGEST_KEY and to migration 074's regex subject.
                let patched = sqlx::query!(
                    r#"
                    UPDATE edges
                    SET properties = properties || jsonb_build_object('essence_digest', $2::text)
                    WHERE id = $1
                    RETURNING id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
                    "#,
                    row.id,
                    digest_hex,
                )
                .fetch_one(&mut *tx)
                .await?;
                EdgeRow {
                    id: patched.id,
                    source_id: patched.source_id,
                    source_type: patched.source_type,
                    target_id: patched.target_id,
                    target_type: patched.target_type,
                    relationship: patched.relationship,
                    properties: patched.properties,
                    valid_from: patched.valid_from,
                    valid_to: patched.valid_to,
                }
            };
            tx.commit().await?;
            return Ok((edge, false));
        }

        let mut properties = properties.unwrap_or_else(|| serde_json::json!({}));
        let Some(map) = properties.as_object_mut() else {
            return Err(DbError::InvalidData {
                reason: "asserts edge properties must be a JSON object".to_string(),
            });
        };
        map.insert(
            ESSENCE_DIGEST_KEY.to_string(),
            serde_json::Value::String(digest_hex),
        );

        let row = sqlx::query!(
            r#"
            INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties)
            VALUES ($1, 'paper', $2, 'claim', 'asserts', $3)
            RETURNING id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            "#,
            paper_id,
            claim_id,
            properties,
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
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, properties))]
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
        let mut tx = pool.begin().await?;

        let existing = sqlx::query!(
            r#"
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
    /// Single-statement `INSERT … SELECT … WHERE NOT EXISTS`; **not**
    /// `ON CONFLICT` — migrations 017/018 dropped the unique triple index, so
    /// there is no constraint to infer on. The matcher's `are_all_current`
    /// guard stays at the MCP call site; this method is purely the write.
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
             )",
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
    /// `edges_alternative_of_symmetric_uniq`). Runtime `sqlx::query*` — no
    /// `.sqlx/` prepared-cache entry.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn create_symmetric_if_absent_returning(
        pool: &PgPool,
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
             RETURNING id",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .bind(Json(properties))
        .fetch_optional(pool)
        .await?;

        if let Some(id) = inserted {
            return Ok((id, true));
        }

        // Dedup hit — surface the id of the existing symmetric edge.
        let existing: Uuid = sqlx::query_scalar(
            "SELECT id FROM edges
             WHERE ((source_id = $1 AND target_id = $2)
                 OR (source_id = $2 AND target_id = $1))
               AND relationship = $3
             LIMIT 1",
        )
        .bind(a)
        .bind(b)
        .bind(relationship)
        .fetch_one(pool)
        .await?;

        Ok((existing, false))
    }

    /// Get edges by source entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_source(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type
        )
        .fetch_all(pool)
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
    /// Currency is joined from `claims.is_current`. `edges` carries no
    /// per-row currency flag for its target — its columns are
    /// `id, source_id, target_id, source_type, target_type, relationship,
    /// labels, properties, created_at, prov_type, valid_from, valid_to,
    /// signature, signer_id, content_hash` — so any query that filters on one
    /// fails at runtime.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_current_claim_targets(
        pool: &PgPool,
        source_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid, String)>, DbError> {
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            r#"
            SELECT e.id, e.target_id, e.relationship
            FROM edges e
            JOIN claims c ON c.id = e.target_id AND c.is_current = true
            WHERE e.source_id = $1
              AND e.source_type = 'claim'
              AND e.target_type = 'claim'
              AND e.relationship <> 'supersedes'
            ORDER BY e.id
            "#,
        )
        .bind(source_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get edges by target entity
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_target(
        pool: &PgPool,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE target_id = $1 AND target_type = $2
            ORDER BY created_at DESC
            "#,
            target_id,
            target_type
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool))]
    pub async fn get_by_relationship(
        pool: &PgPool,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE relationship = $1
            ORDER BY created_at DESC
            "#,
            relationship
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool))]
    pub async fn get_between(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
            ORDER BY created_at DESC
            "#,
            source_id,
            source_type,
            target_id,
            target_type
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool))]
    pub async fn list_filtered(
        pool: &PgPool,
        source_id: Option<Uuid>,
        target_id: Option<Uuid>,
        relationship: Option<&str>,
        source_type: Option<&str>,
        target_type: Option<&str>,
        limit: i64,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE ($1::uuid IS NULL OR source_id = $1)
              AND ($2::uuid IS NULL OR target_id = $2)
              AND ($3::text IS NULL OR relationship = $3)
              AND ($4::text IS NULL OR source_type = $4)
              AND ($5::text IS NULL OR target_type = $5)
            ORDER BY valid_from DESC NULLS LAST, id
            LIMIT $6
            "#,
            source_id,
            target_id,
            relationship,
            source_type,
            target_type,
            limit,
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool))]
    pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            ORDER BY created_at DESC
            LIMIT $1
            "#,
            limit
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool))]
    pub async fn get_current_edges(
        pool: &PgPool,
        entity_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<EdgeRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, source_id, source_type, target_id, target_type, relationship, properties, valid_from, valid_to
            FROM edges
            WHERE (source_id = $1 OR target_id = $1)
              AND relationship = $2
              AND valid_to IS NULL
            ORDER BY valid_from DESC NULLS LAST
            "#,
            entity_id,
            relationship
        )
        .fetch_all(pool)
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
    #[instrument(skip(pool, properties_merge))]
    pub async fn update_valid_to_and_properties(
        pool: &PgPool,
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
        .fetch_optional(pool)
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
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM edges
            WHERE id = $1
            "#,
            id
        )
        .execute(pool)
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
    pub async fn delete_between(
        pool: &PgPool,
        source_id: Uuid,
        source_type: &str,
        target_id: Uuid,
        target_type: &str,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM edges
            WHERE source_id = $1 AND source_type = $2
              AND target_id = $3 AND target_type = $4
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
    #[instrument(skip(pool))]
    pub async fn count_for_entity(
        pool: &PgPool,
        entity_id: Uuid,
        entity_type: &str,
    ) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) as count
            FROM edges
            WHERE (source_id = $1 AND source_type = $2)
               OR (target_id = $1 AND target_type = $2)
            "#,
            entity_id,
            entity_type
        )
        .fetch_one(pool)
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
    #[instrument(skip(pool))]
    pub async fn get_claims_attributed_to(
        pool: &PgPool,
        agent_id: Uuid,
        min_truth: f64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AttributedClaimRow>, DbError> {
        let rows = sqlx::query_as::<_, AttributedClaimRow>(
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
            ORDER BY c.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(agent_id)
        .bind(min_truth)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Count claims attributed to an agent via ATTRIBUTED_TO edges.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count_claims_attributed_to(
        pool: &PgPool,
        agent_id: Uuid,
        min_truth: f64,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM edges e
            JOIN claims c ON e.source_id = c.id
            WHERE e.target_id = $1
              AND e.target_type = 'agent'
              AND e.source_type = 'claim'
              AND e.relationship IN ('attributed_to', 'ATTRIBUTED_TO')
              AND c.truth_value >= $2
            "#,
        )
        .bind(agent_id)
        .bind(min_truth)
        .fetch_one(pool)
        .await?;

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
