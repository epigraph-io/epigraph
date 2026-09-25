//! Read-only queries behind `decompose_claims --priority …` and
//! `decompose_claims --retarget`.
//!
//! # Why these exist
//!
//! [`crate::ClaimRepository::list_undecomposed`] orders `created_at ASC`, so a
//! scheduled run crawls the 2026-03 bulk import (≈87k short extracts) first and
//! never reaches the claims that conflict edges are actually aimed at. The
//! functions here select the SAME undecomposed population (the predicate is
//! transcribed verbatim into each candidate query) in a different
//! order, and add the two edge-centred reads the retarget pass needs.
//!
//! # Visibility
//!
//! Every function takes a `&Viewer` and splices it. Two rules, both inherited:
//!
//! * The `decomposes_to` `NOT EXISTS` probes of that predicate are
//!   deliberately NOT marked, exactly as in `list_undecomposed`: they are
//!   exclusion tests, and filtering them would make an invisible
//!   `decomposes_to` edge stop excluding its claim — widening the result.
//! * Every POSITIVE selection over `edges` (a conflict edge we count, return or
//!   join through) carries `/* {EDGE_VISIBILITY:<alias>} */`, never the claim
//!   spelling: `edges` has two owning groups (migration 072).
//!
//! # Relationship casing
//!
//! Conflict relationships are matched with `lower(relationship)`: the API's
//! factor side-effect upper-cases for comparison and verb edges are stored
//! upper-case, so an exact-case match on `'contradicts'` would be a guess.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

// The undecomposed-claim predicate over alias `c` appears inline in the three
// candidate queries below, transcribed verbatim from
// `ClaimRepository::list_undecomposed`, so the priority modes select exactly
// the population the `oldest` mode always has. It is inlined rather than
// shared through `format!` so every statement stays a literal the
// visibility lint can read.

/// The conflict relationships whose target this module prioritises and
/// retargets. Lower-case; compared against `lower(relationship)`.
pub const CONFLICT_RELATIONSHIPS: [&str; 2] = ["contradicts", "refutes"];

/// Ordering for [`DecompositionPriorityRepository::list_undecomposed_ordered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndecomposedOrder {
    /// `created_at ASC, id ASC` — the historical `list_undecomposed` order.
    Oldest,
    /// `created_at DESC, id DESC`.
    Recent,
}

/// One undecomposed claim, with what the eligibility filters and the
/// conflict ordering need.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct DecomposeCandidate {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub content: String,
    pub content_hash: Vec<u8>,
    pub labels: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// In-force contradicts/refutes edges from a current claim that target
    /// this claim. Zero outside the conflict ordering.
    pub conflict_edges: i64,
    /// `created_at` of the newest such edge.
    pub newest_conflict_at: Option<DateTime<Utc>>,
}

/// An in-force contradicts/refutes edge whose TARGET is a decomposed parent
/// (it has outgoing `decomposes_to` edges to current atoms).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ParentConflictEdge {
    pub edge_id: Uuid,
    /// Stored spelling, preserved so a retargeted edge repeats it exactly.
    pub relationship: String,
    pub source_id: Uuid,
    pub source_content: String,
    pub parent_id: Uuid,
    pub parent_content: String,
    pub properties: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// A current atom of a decomposed parent.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct ParentAtom {
    pub parent_id: Uuid,
    pub atom_id: Uuid,
    pub content: String,
}

/// An edge matching a `(source, target, relationship)` triple, live or retired.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct TripleEdge {
    pub id: Uuid,
    /// The stored source: tells the two orientations apart in
    /// [`DecompositionPriorityRepository::find_edges_either_direction`].
    pub source_id: Uuid,
    /// The stored spelling.
    pub relationship: String,
    pub in_force: bool,
    pub properties: serde_json::Value,
}

pub struct DecompositionPriorityRepository;

impl DecompositionPriorityRepository {
    /// The undecomposed population in `order`, with a stable id tiebreaker and
    /// the labels/content hash the caller's eligibility filters and plan file
    /// need. `conflict_edges` is 0 on every row.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn list_undecomposed_ordered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        order: UndecomposedOrder,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DecomposeCandidate>, DbError> {
        let order_by = match order {
            UndecomposedOrder::Oldest => "c.created_at ASC, c.id ASC",
            UndecomposedOrder::Recent => "c.created_at DESC, c.id DESC",
        };
        // `__ORDER_BY__` is substituted AFTER splicing, from the two fixed
        // strings above — never from caller text.
        let sql = viewer
            .splice(
                r#"
                SELECT c.id, c.agent_id, c.content, c.content_hash, c.labels, c.created_at,
                       0::bigint AS conflict_edges,
                       NULL::timestamptz AS newest_conflict_at
                FROM claims c
                WHERE
                  COALESCE(c.is_current, true) = true
                  AND length(c.content) > 10
                  AND NOT ('telemetry' = ANY(c.labels))
                  AND (c.properties ->> 'event') IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.source_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.target_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  /* {VISIBILITY:c} */
                ORDER BY __ORDER_BY__
                LIMIT $1 OFFSET $2
                "#,
                3,
            )
            .replace("__ORDER_BY__", order_by);
        let mut q = sqlx::query_as::<_, DecomposeCandidate>(&sql)
            .bind(limit.clamp(1, 1000))
            .bind(offset.max(0));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Undecomposed claims that are the TARGET of at least one in-force
    /// contradicts/refutes edge from a current, visible claim, most-contested
    /// first: `conflict_edges DESC, newest_conflict_at DESC, id ASC`.
    ///
    /// A conflict from a retired (superseded, duplicate) source is not a live
    /// dispute and is not counted, matching `ClaimRepository::dispute_batch`
    /// (`JOIN claims src ON src.id = e.source_id AND src.is_current`), the
    /// dispute signal recall shows.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn list_undecomposed_conflict_targets<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DecomposeCandidate>, DbError> {
        let sql = viewer.splice(
            r#"
                WITH conflict AS (
                    SELECT e.target_id, COUNT(*)::bigint AS n, MAX(e.created_at) AS newest
                    FROM edges e
                    JOIN claims s ON s.id = e.source_id
                    WHERE lower(e.relationship) IN ('contradicts', 'refutes')
                      AND e.source_type = 'claim' AND e.target_type = 'claim'
                      AND (e.valid_to IS NULL OR e.valid_to > now())
                      AND COALESCE(s.is_current, true) = true
                      /* {EDGE_VISIBILITY:e} */
                      /* {VISIBILITY:s} */
                    GROUP BY e.target_id
                )
                SELECT c.id, c.agent_id, c.content, c.content_hash, c.labels, c.created_at,
                       k.n AS conflict_edges, k.newest AS newest_conflict_at
                FROM claims c
                JOIN conflict k ON k.target_id = c.id
                WHERE
                  COALESCE(c.is_current, true) = true
                  AND length(c.content) > 10
                  AND NOT ('telemetry' = ANY(c.labels))
                  AND (c.properties ->> 'event') IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.source_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.target_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  /* {VISIBILITY:c} */
                ORDER BY k.n DESC, k.newest DESC, c.id ASC
                LIMIT $1 OFFSET $2
                "#,
            3,
        );
        let mut q = sqlx::query_as::<_, DecomposeCandidate>(&sql)
            .bind(limit.clamp(1, 1000))
            .bind(offset.max(0));
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The members of `ids` that satisfy the undecomposed predicate, in the
    /// order they were given. Ids that are absent, invisible, retired or
    /// already decomposed are simply not returned; the caller diffs to report
    /// them.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn list_undecomposed_by_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<DecomposeCandidate>, DbError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let sql = viewer.splice(
            r#"
                SELECT c.id, c.agent_id, c.content, c.content_hash, c.labels, c.created_at,
                       0::bigint AS conflict_edges,
                       NULL::timestamptz AS newest_conflict_at
                FROM unnest($1::uuid[]) WITH ORDINALITY AS want(id, ord)
                JOIN claims c ON c.id = want.id
                WHERE
                  COALESCE(c.is_current, true) = true
                  AND length(c.content) > 10
                  AND NOT ('telemetry' = ANY(c.labels))
                  AND (c.properties ->> 'event') IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.source_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM edges d
                      WHERE d.target_id = c.id AND d.relationship = 'decomposes_to'
                  )
                  /* {VISIBILITY:c} */
                ORDER BY want.ord
                "#,
            2,
        );
        let mut q = sqlx::query_as::<_, DecomposeCandidate>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// In-force contradicts/refutes edges (claim → claim) whose target is a
    /// current parent with at least one current atom reached through an
    /// IN-FORCE `decomposes_to` edge, oldest edge first
    /// (`created_at ASC, id ASC`).
    ///
    /// `include_marked = false` skips edges already carrying a
    /// `retargeted_to` property — the retarget pass's first idempotency guard.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn list_parent_conflict_edges<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        include_marked: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ParentConflictEdge>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.id AS edge_id, e.relationship::text AS relationship,
                   e.source_id, s.content AS source_content,
                   e.target_id AS parent_id, p.content AS parent_content,
                   e.properties, e.created_at
            FROM edges e
            JOIN claims s ON s.id = e.source_id
            JOIN claims p ON p.id = e.target_id
            WHERE lower(e.relationship) IN ('contradicts', 'refutes')
              AND e.source_type = 'claim' AND e.target_type = 'claim'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND COALESCE(s.is_current, true) = true
              AND COALESCE(p.is_current, true) = true
              AND ($3::bool OR NOT (e.properties ? 'retargeted_to'))
              AND EXISTS (
                  SELECT 1 FROM edges d
                  JOIN claims a ON a.id = d.target_id
                  WHERE d.source_id = p.id
                    AND d.relationship = 'decomposes_to'
                    AND d.target_type = 'claim'
                    AND (d.valid_to IS NULL OR d.valid_to > now())
                    AND COALESCE(a.is_current, true) = true
                    /* {EDGE_VISIBILITY:d} */
                    /* {VISIBILITY:a} */
              )
              /* {EDGE_VISIBILITY:e} */
              /* {VISIBILITY:s} */
              /* {VISIBILITY:p} */
            ORDER BY e.created_at ASC, e.id ASC
            LIMIT $1 OFFSET $2
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, ParentConflictEdge>(&sql)
            .bind(limit.clamp(1, 1000))
            .bind(offset.max(0))
            .bind(include_marked);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Current atoms of each parent in `parent_ids`, numbered in a stable
    /// order: `parent_id, atom created_at ASC, atom id ASC`. The retarget
    /// prompt's atom indices are positions in this order.
    ///
    /// Only atoms reached through an IN-FORCE `decomposes_to` edge count: an
    /// edge retired with `valid_to` (PATCH /api/v1/edges/:id can set it)
    /// removes that atom from the decomposition, so it is neither shown to the
    /// LLM nor accepted as a retarget destination. The undecomposed
    /// population's `NOT EXISTS` probes deliberately keep counting retired
    /// edges, as `list_undecomposed` does.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn list_current_atoms<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        parent_ids: &[Uuid],
    ) -> Result<Vec<ParentAtom>, DbError> {
        if parent_ids.is_empty() {
            return Ok(vec![]);
        }
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT ON (d.source_id, a.id)
                   d.source_id AS parent_id, a.id AS atom_id, a.content,
                   a.created_at
            FROM edges d
            JOIN claims a ON a.id = d.target_id
            WHERE d.source_id = ANY($1::uuid[])
              AND d.relationship = 'decomposes_to'
              AND d.target_type = 'claim'
              AND (d.valid_to IS NULL OR d.valid_to > now())
              AND COALESCE(a.is_current, true) = true
              /* {EDGE_VISIBILITY:d} */
              /* {VISIBILITY:a} */
            ORDER BY d.source_id, a.id
            "#,
            2,
        );
        #[derive(sqlx::FromRow)]
        struct Row {
            parent_id: Uuid,
            atom_id: Uuid,
            content: String,
            created_at: DateTime<Utc>,
        }
        let mut q = sqlx::query_as::<_, Row>(&sql).bind(parent_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut rows = q.fetch_all(executor).await?;
        // DISTINCT ON forces the ORDER BY prefix; re-sort into the documented
        // numbering order here so the atom index is (created_at, id) stable.
        rows.sort_by(|x, y| {
            x.parent_id
                .cmp(&y.parent_id)
                .then(x.created_at.cmp(&y.created_at))
                .then(x.atom_id.cmp(&y.atom_id))
        });
        Ok(rows
            .into_iter()
            .map(|r| ParentAtom {
                parent_id: r.parent_id,
                atom_id: r.atom_id,
                content: r.content,
            })
            .collect())
    }

    /// Every edge matching `(source_id, target_id, lower(relationship))`,
    /// live and retired, oldest first. The retarget pass's pre-create check:
    /// a live match means the atom edge already exists; a retired-only match
    /// means someone retracted exactly this edge, and the pass must not
    /// resurrect it (the API's `if_not_exists` would hand back the retired
    /// row, which never wires).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn find_edges_by_triple<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        source_id: Uuid,
        target_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<TripleEdge>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.id, e.source_id, e.relationship::text AS relationship,
                   (e.valid_to IS NULL OR e.valid_to > now()) AS in_force, e.properties
            FROM edges e
            WHERE e.source_id = $1 AND e.target_id = $2
              AND lower(e.relationship) = lower($3)
              /* {EDGE_VISIBILITY:e} */
            ORDER BY e.created_at ASC, e.id ASC
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, TripleEdge>(&sql)
            .bind(source_id)
            .bind(target_id)
            .bind(relationship);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// [`Self::find_edges_by_triple`] for a SYMMETRIC relationship: every edge
    /// `a -rel-> b` OR `b -rel-> a` (case-insensitive), live and retired,
    /// oldest first. `contradicts` is one fact in either orientation (MCP
    /// `link_epistemic`'s `SYMMETRIC_RELATIONSHIPS`), so a pre-create check that
    /// looked in one direction would create a duplicate row and a second BBA
    /// next to an existing reverse edge.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn find_edges_either_direction<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        a: Uuid,
        b: Uuid,
        relationship: &str,
    ) -> Result<Vec<TripleEdge>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.id, e.source_id, e.relationship::text AS relationship,
                   (e.valid_to IS NULL OR e.valid_to > now()) AS in_force, e.properties
            FROM edges e
            WHERE ((e.source_id = $1 AND e.target_id = $2)
                   OR (e.source_id = $2 AND e.target_id = $1))
              AND lower(e.relationship) = lower($3)
              /* {EDGE_VISIBILITY:e} */
            ORDER BY e.created_at ASC, e.id ASC
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, TripleEdge>(&sql)
            .bind(a)
            .bind(b)
            .bind(relationship);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }
}
