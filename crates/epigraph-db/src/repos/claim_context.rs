//! The document context of one claim: the paper(s) that assert it, its
//! structural parents and parts, the sibling claims under its primary parent,
//! and its epistemic edges in both directions.
//!
//! Backs `GET /api/v1/claims/:id/context`, the HTTP twin of the structural
//! block MCP `recall_with_context` adds per hit. It is a NEW module rather
//! than a move of that block's SQL (`epigraph-mcp/src/tools/recall.rs`,
//! `fetch_batched_context`), because that block orders its epistemic and
//! corroboration rows on `truth_value`, which makes it a registered
//! role-blind belief reader; calling it from a route would carry that
//! register entry onto a new surface. This module keeps the MCP semantics
//! (which tables, which edges, which level rules, which tenancy predicates)
//! and drops the parts that read belief.
//!
//! (Named `claim_context`, not `context`: `repos/context.rs` is the
//! epistemic-contexts table.)
//!
//! # Tenancy
//!
//! Every statement is filtered in SQL against the caller's [`Viewer`]:
//!
//! * every `claims` alias carries the single-owner claim predicate, and every
//!   `edges` alias carries the co-ownership edge predicate, so a co-owned
//!   `(owner G, co_owner H)` edge is visible only to a principal in BOTH
//!   groups. One statement resolves both spellings to one bind index;
//! * every list function re-checks its ANCHOR claim with a viewer-filtered
//!   `EXISTS`, so a function called with a hidden anchor returns an empty
//!   page and a zero total, whoever calls it;
//! * every edge read excludes retracted edges (`valid_to` set and past),
//!   written inline so each statement stays a literal the marker lints read;
//! * the structural and epistemic lists admit claim-to-claim edges only
//!   (both `source_type` and `target_type` are `'claim'`), so evidence,
//!   traces, perspectives, frames and every other tenanted non-claim row are
//!   never listed and never counted. The one non-claim node is a paper, which
//!   has no tenancy columns of its own and is reached only through a
//!   viewer-filtered `asserts` edge to a visible claim;
//! * every `total` and every tally is computed inside the same predicates
//!   that produce the rows, so it is the VISIBLE count by construction, never
//!   a true degree minus whatever was dropped. A true degree beside a filtered
//!   list states how many rows the viewer may not see.
//!
//! # No belief is read
//!
//! Rows project `truth_value` and nothing orders on it, compares it or folds
//! it, which is the line `crates/epigraph-db/tests/no_role_blind_belief_reads.rs`
//! draws (its module doc, "What counts as a reader"). That is the difference
//! from the MCP block, whose corroboration list orders by strength and then
//! `truth_value`. No row type here has a `belief`, `plausibility` or
//! `pignistic_prob` field: a compound claim's cached belief columns are a fold
//! of its own BBAs, and a flat list has no role to dispatch on. Callers that
//! need a claim's belief ask `GET /api/v1/claims/:id/belief`.
//!
//! # The structural parent is chosen by level
//!
//! Ingest writes a document as thesis (level 0) -> section (1) -> paragraph
//! (2) -> atom (3), joined by `decomposes_to`. Thesis, section and paragraph
//! ids are seeded per document, but an atom's id is a content hash shared by
//! every document that states it, so an atom can have one paragraph parent
//! per document plus non-structural `decomposes_to` parents (compound or
//! workflow claims, which carry other levels). [`ClaimContextRepository::first_parent`]
//! therefore takes the level it expects (child level - 1) and returns the
//! first VISIBLE parent at that level by `(created_at, id)`. Which parent is
//! "first" depends on what the viewer can see; that is per-viewer by design.
//!
//! # Paging
//!
//! Paged functions take a [`LabelCursor`] naming the last row of the previous
//! page and run a count statement and a page statement on the same
//! connection, the shape of `EgoRepository::edges`. Parents, parts and
//! siblings are ordered `(created_at, id)` ascending, papers
//! `(COALESCE(created_at, epoch), id)` ascending, and epistemic edges
//! `(edge created_at, edge id)` descending (newest first). A forged cursor
//! only moves the start of a read that stays viewer-filtered.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::claim::LabelCursor;
use crate::visibility::Viewer;

/// The epistemic relationships the context lists, lower-cased. Matching is
/// `lower(e.relationship) = ANY(..)`, so both stored spellings
/// (`SUPPORTS` / `supports`, `CORROBORATES` / `corroborates`) count.
pub const CONTEXT_EPISTEMIC_RELATIONSHIPS: &[&str] = &[
    "supports",
    "refutes",
    "contradicts",
    "specializes",
    "elaborates",
    "cites",
    "qualifies",
    "corroborates",
];

/// One claim node of the context.
///
/// `content` is cut in SQL to 1501 characters (one more than the route's
/// clip, so the route can tell that it was cut). `level` is the raw text of
/// `properties->>'level'`: `properties` is patchable JSON, so an integer cast
/// in SQL would raise on a non-numeric value; the route parses it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContextClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub is_current: bool,
    pub level: Option<String>,
    pub theme_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// One paper with a visible `asserts` edge to the anchor claim.
///
/// `doi` is cut to 257 characters and `title` to 301 in SQL. `order_at` is
/// `COALESCE(created_at, epoch)`, the cursor key.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContextPaperRow {
    pub id: Uuid,
    pub doi: String,
    pub title: Option<String>,
    pub order_at: DateTime<Utc>,
}

/// One epistemic edge of the anchor claim with its neighbour hydrated.
///
/// `relationship` is lower-cased; `direction` is `outgoing` when the anchor
/// is the edge's source and `incoming` when it is the target. `strength` is
/// the raw text of `properties->>'strength'`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContextEdgeRow {
    pub edge_id: Uuid,
    pub relationship: String,
    pub direction: String,
    pub strength: Option<String>,
    pub edge_created_at: DateTime<Utc>,
    pub neighbor_id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub is_current: bool,
    pub level: Option<String>,
    pub theme_id: Option<Uuid>,
}

/// The number of visible epistemic edges per `(relationship, direction)`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ContextEdgeTally {
    pub relationship: String,
    pub direction: String,
    pub count: i64,
}

/// One page of a list plus the visible total of the whole list.
#[derive(Debug, Clone)]
pub struct ContextPage<T> {
    pub items: Vec<T>,
    pub total: i64,
}

pub struct ClaimContextRepository;

/// The bind form of an optional cursor.
fn cursor_binds(after: Option<LabelCursor>) -> (Option<DateTime<Utc>>, Option<Uuid>) {
    match after {
        Some(c) => (Some(c.created_at), Some(c.id)),
        None => (None, None),
    }
}

/// `CONTEXT_EPISTEMIC_RELATIONSHIPS` as a text-array bind.
fn relationship_bind() -> Vec<String> {
    CONTEXT_EPISTEMIC_RELATIONSHIPS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

impl ClaimContextRepository {
    /// The anchor claim, or `None` when it does not exist **or** the viewer
    /// may not read it: the caller's 404, the same 404 either way.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn root(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<Option<ContextClaimRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id, left(c.content, 1501) AS content, c.truth_value, c.is_current,
                   c.properties->>'level' AS level, c.theme_id, c.created_at
            FROM claims c
            WHERE c.id = $1 /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ContextClaimRow>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?)
    }

    /// The papers with a visible, in-force `asserts` edge to `claim_id`,
    /// ordered `(COALESCE(created_at, epoch), id)` ascending, after `after`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the count or the page query fails.
    pub async fn papers(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
        after: Option<LabelCursor>,
        limit: i64,
    ) -> Result<ContextPage<ContextPaperRow>, DbError> {
        let count_sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT p.id)
            FROM edges e
            JOIN papers p ON p.id = e.source_id
            WHERE e.target_id = $1 AND e.target_type = 'claim'
              AND e.source_type = 'paper' AND e.relationship = 'asserts'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              /* {EDGE_VISIBILITY:e} */
            "#,
            2,
        );
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            count_q = count_q.bind(g);
        }
        let total: i64 = count_q.fetch_one(&mut *conn).await?;

        let (after_ts, after_id) = cursor_binds(after);
        let page_sql = viewer.splice(
            r#"
            SELECT DISTINCT p.id, left(p.doi, 257) AS doi, left(p.title, 301) AS title,
                   COALESCE(p.created_at, to_timestamp(0)) AS order_at
            FROM edges e
            JOIN papers p ON p.id = e.source_id
            WHERE e.target_id = $1 AND e.target_type = 'claim'
              AND e.source_type = 'paper' AND e.relationship = 'asserts'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              AND ($2::timestamptz IS NULL
                   OR (COALESCE(p.created_at, to_timestamp(0)), p.id) > ($2::timestamptz, $3::uuid))
              /* {EDGE_VISIBILITY:e} */
            ORDER BY order_at, p.id
            LIMIT $4
            "#,
            5,
        );
        let mut page_q = sqlx::query_as::<_, ContextPaperRow>(&page_sql)
            .bind(claim_id)
            .bind(after_ts)
            .bind(after_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            page_q = page_q.bind(g);
        }
        let items: Vec<ContextPaperRow> = page_q.fetch_all(&mut *conn).await?;
        Ok(ContextPage { items, total })
    }

    /// The first paper of [`Self::papers`]'s order, or `None`. Used to name
    /// the paper of the document the structural chain belongs to.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn first_paper(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<Option<ContextPaperRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT p.id, left(p.doi, 257) AS doi, left(p.title, 301) AS title,
                   COALESCE(p.created_at, to_timestamp(0)) AS order_at
            FROM edges e
            JOIN papers p ON p.id = e.source_id
            WHERE e.target_id = $1 AND e.target_type = 'claim'
              AND e.source_type = 'paper' AND e.relationship = 'asserts'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              /* {EDGE_VISIBILITY:e} */
            ORDER BY order_at, p.id
            LIMIT 1
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ContextPaperRow>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?)
    }

    /// Every visible claim that `decomposes_to` `claim_id`, at any level,
    /// ordered `(created_at, id)` ascending, after `after`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the count or the page query fails.
    pub async fn parents(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
        after: Option<LabelCursor>,
        limit: i64,
    ) -> Result<ContextPage<ContextClaimRow>, DbError> {
        let count_sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT c.id)
            FROM edges e
            JOIN claims c ON c.id = e.source_id /* {VISIBILITY:c} */
            WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim'
              AND e.relationship = 'decomposes_to'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              /* {EDGE_VISIBILITY:e} */
            "#,
            2,
        );
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            count_q = count_q.bind(g);
        }
        let total: i64 = count_q.fetch_one(&mut *conn).await?;

        let (after_ts, after_id) = cursor_binds(after);
        let page_sql = viewer.splice(
            r#"
            SELECT DISTINCT c.id, left(c.content, 1501) AS content, c.truth_value, c.is_current,
                   c.properties->>'level' AS level, c.theme_id, c.created_at
            FROM edges e
            JOIN claims c ON c.id = e.source_id /* {VISIBILITY:c} */
            WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim'
              AND e.relationship = 'decomposes_to'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              AND ($2::timestamptz IS NULL OR (c.created_at, c.id) > ($2::timestamptz, $3::uuid))
              /* {EDGE_VISIBILITY:e} */
            ORDER BY c.created_at, c.id
            LIMIT $4
            "#,
            5,
        );
        let mut page_q = sqlx::query_as::<_, ContextClaimRow>(&page_sql)
            .bind(claim_id)
            .bind(after_ts)
            .bind(after_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            page_q = page_q.bind(g);
        }
        let items: Vec<ContextClaimRow> = page_q.fetch_all(&mut *conn).await?;
        Ok(ContextPage { items, total })
    }

    /// The STRUCTURAL parent of `claim_id`: the first visible
    /// `decomposes_to` parent by `(created_at, id)` whose
    /// `properties->>'level'` equals `level`, or the first at any level when
    /// `level` is `None`.
    ///
    /// The caller passes the expected level (child level - 1) and passes
    /// `None` only when the child has no parseable level, so a compound or
    /// workflow parent that carries another level is never picked.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn first_parent(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
        level: Option<&str>,
    ) -> Result<Option<ContextClaimRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT DISTINCT c.id, left(c.content, 1501) AS content, c.truth_value, c.is_current,
                   c.properties->>'level' AS level, c.theme_id, c.created_at
            FROM edges e
            JOIN claims c ON c.id = e.source_id /* {VISIBILITY:c} */
            WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim'
              AND e.relationship = 'decomposes_to'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              AND ($2::text IS NULL OR c.properties->>'level' = $2::text)
              /* {EDGE_VISIBILITY:e} */
            ORDER BY c.created_at, c.id
            LIMIT 1
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, ContextClaimRow>(&sql)
            .bind(claim_id)
            .bind(level);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?)
    }

    /// The visible `decomposes_to` children of `parent_id`, ordered
    /// `(created_at, id)` ascending, after `after`.
    ///
    /// Serves both the anchor's parts (`level` and `exclude` `None`) and its
    /// siblings (`parent_id` the primary parent, `level` the anchor's level,
    /// `exclude` the anchor itself).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the count or the page query fails.
    pub async fn children(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        parent_id: Uuid,
        level: Option<&str>,
        exclude: Option<Uuid>,
        after: Option<LabelCursor>,
        limit: i64,
    ) -> Result<ContextPage<ContextClaimRow>, DbError> {
        let count_sql = viewer.splice(
            r#"
            SELECT COUNT(DISTINCT c.id)
            FROM edges e
            JOIN claims c ON c.id = e.target_id /* {VISIBILITY:c} */
            WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim'
              AND e.relationship = 'decomposes_to'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND ($2::text IS NULL OR c.properties->>'level' = $2::text)
              AND ($3::uuid IS NULL OR c.id <> $3::uuid)
              AND EXISTS (SELECT 1 FROM claims pc WHERE pc.id = $1 /* {VISIBILITY:pc} */)
              /* {EDGE_VISIBILITY:e} */
            "#,
            4,
        );
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql)
            .bind(parent_id)
            .bind(level)
            .bind(exclude);
        if let Some(g) = viewer.group_bind() {
            count_q = count_q.bind(g);
        }
        let total: i64 = count_q.fetch_one(&mut *conn).await?;

        let (after_ts, after_id) = cursor_binds(after);
        let page_sql = viewer.splice(
            r#"
            SELECT DISTINCT c.id, left(c.content, 1501) AS content, c.truth_value, c.is_current,
                   c.properties->>'level' AS level, c.theme_id, c.created_at
            FROM edges e
            JOIN claims c ON c.id = e.target_id /* {VISIBILITY:c} */
            WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim'
              AND e.relationship = 'decomposes_to'
              AND (e.valid_to IS NULL OR e.valid_to > now())
              AND ($2::text IS NULL OR c.properties->>'level' = $2::text)
              AND ($3::uuid IS NULL OR c.id <> $3::uuid)
              AND EXISTS (SELECT 1 FROM claims pc WHERE pc.id = $1 /* {VISIBILITY:pc} */)
              AND ($4::timestamptz IS NULL OR (c.created_at, c.id) > ($4::timestamptz, $5::uuid))
              /* {EDGE_VISIBILITY:e} */
            ORDER BY c.created_at, c.id
            LIMIT $6
            "#,
            7,
        );
        let mut page_q = sqlx::query_as::<_, ContextClaimRow>(&page_sql)
            .bind(parent_id)
            .bind(level)
            .bind(exclude)
            .bind(after_ts)
            .bind(after_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            page_q = page_q.bind(g);
        }
        let items: Vec<ContextClaimRow> = page_q.fetch_all(&mut *conn).await?;
        Ok(ContextPage { items, total })
    }

    /// The visible epistemic edges of `claim_id` counted per
    /// `(relationship, direction)`, ordered by relationship then direction.
    ///
    /// Same predicates as [`Self::epistemic_edges`], so the sum of the counts
    /// is the total of that list and the two cannot disagree.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn epistemic_tallies(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<Vec<ContextEdgeTally>, DbError> {
        // Two UNION ALL arms rather than one OR, so each arm uses its own
        // anchor index; `<> $1` keeps a self-edge out of both.
        let sql = viewer.splice(
            r#"
            WITH v AS (
              SELECT lower(e.relationship) AS relationship, 'outgoing'::text AS direction
              FROM edges e
              JOIN claims c ON c.id = e.target_id AND c.is_current /* {VISIBILITY:c} */
              WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim'
                AND e.target_id <> $1
                AND lower(e.relationship) = ANY($2::text[])
                AND (e.valid_to IS NULL OR e.valid_to > now())
                /* {EDGE_VISIBILITY:e} */
              UNION ALL
              SELECT lower(e.relationship) AS relationship, 'incoming'::text AS direction
              FROM edges e
              JOIN claims c ON c.id = e.source_id AND c.is_current /* {VISIBILITY:c} */
              WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim'
                AND e.source_id <> $1
                AND lower(e.relationship) = ANY($2::text[])
                AND (e.valid_to IS NULL OR e.valid_to > now())
                /* {EDGE_VISIBILITY:e} */
            )
            SELECT relationship, direction, COUNT(*) AS count
            FROM v
            WHERE EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
            GROUP BY relationship, direction
            ORDER BY relationship, direction
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, ContextEdgeTally>(&sql)
            .bind(claim_id)
            .bind(relationship_bind());
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// The visible epistemic edges of `claim_id`, in both directions, with
    /// the neighbour hydrated, ordered `(edge created_at, edge id)`
    /// descending (newest first), after `after`.
    ///
    /// An edge is listed only when it is in force, the viewer may read it
    /// AND its far claim, the far claim is current, and the relationship is
    /// one of [`CONTEXT_EPISTEMIC_RELATIONSHIPS`] in either case.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn epistemic_edges(
        conn: &mut sqlx::PgConnection,
        viewer: &Viewer,
        claim_id: Uuid,
        after: Option<LabelCursor>,
        limit: i64,
    ) -> Result<Vec<ContextEdgeRow>, DbError> {
        let (after_ts, after_id) = cursor_binds(after);
        let sql = viewer.splice(
            r#"
            WITH v AS (
              SELECT e.id AS edge_id, lower(e.relationship) AS relationship,
                     'outgoing'::text AS direction,
                     e.properties->>'strength' AS strength, e.created_at AS edge_created_at,
                     c.id AS neighbor_id, left(c.content, 1501) AS content, c.truth_value,
                     c.is_current, c.properties->>'level' AS level, c.theme_id
              FROM edges e
              JOIN claims c ON c.id = e.target_id AND c.is_current /* {VISIBILITY:c} */
              WHERE e.source_id = $1 AND e.source_type = 'claim' AND e.target_type = 'claim'
                AND e.target_id <> $1
                AND lower(e.relationship) = ANY($2::text[])
                AND (e.valid_to IS NULL OR e.valid_to > now())
                /* {EDGE_VISIBILITY:e} */
              UNION ALL
              SELECT e.id AS edge_id, lower(e.relationship) AS relationship,
                     'incoming'::text AS direction,
                     e.properties->>'strength' AS strength, e.created_at AS edge_created_at,
                     c.id AS neighbor_id, left(c.content, 1501) AS content, c.truth_value,
                     c.is_current, c.properties->>'level' AS level, c.theme_id
              FROM edges e
              JOIN claims c ON c.id = e.source_id AND c.is_current /* {VISIBILITY:c} */
              WHERE e.target_id = $1 AND e.target_type = 'claim' AND e.source_type = 'claim'
                AND e.source_id <> $1
                AND lower(e.relationship) = ANY($2::text[])
                AND (e.valid_to IS NULL OR e.valid_to > now())
                /* {EDGE_VISIBILITY:e} */
            )
            SELECT edge_id, relationship, direction, strength, edge_created_at, neighbor_id,
                   content, truth_value, is_current, level, theme_id
            FROM v
            WHERE EXISTS (SELECT 1 FROM claims ac WHERE ac.id = $1 /* {VISIBILITY:ac} */)
              AND ($3::timestamptz IS NULL
                   OR (edge_created_at, edge_id) < ($3::timestamptz, $4::uuid))
            ORDER BY edge_created_at DESC, edge_id DESC
            LIMIT $5
            "#,
            6,
        );
        let mut q = sqlx::query_as::<_, ContextEdgeRow>(&sql)
            .bind(claim_id)
            .bind(relationship_bind())
            .bind(after_ts)
            .bind(after_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }
}
