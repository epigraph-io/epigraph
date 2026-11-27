//! Viewer-scoped reads over RETIRED claims (`is_current = false`): the
//! predecessors a lineage walk reaches from a set of claims, and a lexical
//! search over retired rows.
//!
//! These back an opt-in historical leg of recall (backlog 28a2f938). Default
//! recall ranks current claims only; a retired row has no embedding
//! (`chk_deprecated_no_embedding`, migrations 052 and 144), so the two
//! routes that still reach one are its lineage (`claims.supersedes` and
//! `supersedes` edges) and the generated `content_tsv` column (migration 050),
//! which covers every row.
//!
//! # Visibility is checked on each returned row
//!
//! A predecessor can be more private than its successor: privatization acts
//! on one version at a time, so a public successor may name a group-private
//! predecessor. Every row these reads return therefore carries its OWN
//! `/* {VISIBILITY:…} */` predicate. Nothing is admitted because a successor
//! (or any other row) is visible.
//!
//! The lineage walk applies the predicate in its recursive term, so an
//! invisible predecessor ENDS the walk on that branch rather than being
//! walked through: returning a visible ancestor beyond a hidden one would
//! disclose the hidden revision's existence and position by the depth gap
//! (the rule `ClaimRepository::version_history` documents). The seeds are
//! gated too, so a walk starts only from claims the viewer can read; without
//! that, a guessed id of a private successor would return its public
//! predecessors and confirm the private claim exists.
//!
//! Both functions take a caller-supplied connection, the form a request
//! reaches through `ScopedPool::read_as`, so every statement runs under the
//! viewer's own session GUCs and row security agrees with the in-query
//! predicate.
//!
//! The rows carry no `truth_value`, `belief` or `plausibility`: a historical
//! row's score is the caller's to derive through the role-aware belief reads.

use crate::errors::DbError;
use crate::repos::claim::ClaimRepository;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// The deepest lineage walk [`ClaimRepository::predecessors_of`] runs; a
/// larger requested depth is clamped to this.
pub const MAX_PREDECESSOR_DEPTH: i32 = 5;

/// The most rows either read in this module returns; a larger requested cap
/// is clamped to this.
pub const MAX_HISTORY_ROWS: i64 = 200;

/// One retired predecessor [`ClaimRepository::predecessors_of`] reached.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PredecessorHit {
    /// The retired predecessor.
    pub id: Uuid,
    /// The claim the walk reached it from: one of the seeds at depth 1, a
    /// predecessor returned at the previous depth otherwise. Every successor
    /// named here is a row the viewer can read.
    pub successor_id: Uuid,
    /// Hops from the nearest seed, `1..=MAX_PREDECESSOR_DEPTH`. A claim
    /// reachable by several paths is returned once, at its least depth.
    pub depth: i32,
    pub content: String,
    /// Always `false`: the walk returns retired rows only.
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    /// The row's last write; for a claim retired by a supersession this is
    /// when it was retired.
    pub updated_at: DateTime<Utc>,
}

/// One retired claim [`ClaimRepository::search_retired_lexical`] matched.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct RetiredLexicalHit {
    pub id: Uuid,
    pub content: String,
    /// Always `false`: the search covers retired rows only.
    pub is_current: bool,
    pub created_at: DateTime<Utc>,
    /// The row's last write; for a claim retired by a supersession this is
    /// when it was retired.
    pub updated_at: DateTime<Utc>,
    /// `ts_rank_cd(content_tsv, query)`; the hits are ordered by it, highest
    /// first, ties broken by id.
    pub rank: f64,
    /// A claim that names this one as its predecessor, when one exists and
    /// the viewer can read it; the earliest created if several do. Read from
    /// an in-force `supersedes` edge to it (every writer's edge points from
    /// successor to predecessor), or from a CURRENT claim's `supersedes`
    /// column (see [`ClaimRepository::predecessors_of`] on why the column of a
    /// retired row is not read that way). `None` for a claim withdrawn with no
    /// successor, or whose successors are all invisible to this viewer.
    pub successor_id: Option<Uuid>,
}

impl ClaimRepository {
    /// The retired predecessors of `ids`, walked back along lineage up to
    /// `depth` hops (clamped to `1..=MAX_PREDECESSOR_DEPTH`), at most `cap`
    /// rows (clamped to `MAX_HISTORY_ROWS`).
    ///
    /// One hop from a claim `s` reaches a claim `p` when `s.supersedes = p`
    /// (the supersede act writes the successor's column), or when an in-force
    /// edge `s -> p` with `lower(relationship) = 'supersedes'` joins two
    /// claims (the act's own edge, a merge's edge to each source, and legacy
    /// upper-case rows). `p` must be retired.
    ///
    /// # The column points both ways
    ///
    /// The supersede act and `evolve_step` write the SUCCESSOR's column
    /// (`successor.supersedes = predecessor`), but a dedup mark and a merge
    /// write the RETIRED row's (`duplicate.supersedes = canonical`,
    /// `source.supersedes = merged`). A current claim's column is always the
    /// first kind (the other two set it only on the row they retire), and so
    /// is that of a row the walk reached through a hop, so the column is
    /// followed from those. From a RETIRED SEED it is not: its column may
    /// name the claim it was retired into, which is its successor, not its
    /// predecessor. A retired seed's predecessors are still reached through
    /// its `supersedes` edges, whose direction (successor to predecessor) every
    /// writer shares. Requiring `p` retired also keeps a live canonical out.
    ///
    /// Visibility: see the module documentation. The seeds, every predecessor
    /// and every edge hop carry the viewer predicate, so the walk stops at the
    /// first link the viewer cannot read.
    ///
    /// Rows are ordered by `(depth, id)`. A seed is never returned, even when
    /// another seed's walk reaches it. Cycles (reachable through dedup marks)
    /// are cut by the `CYCLE` clause as well as the depth bound.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn predecessors_of(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
        depth: i32,
        cap: i64,
    ) -> Result<Vec<PredecessorHit>, DbError> {
        let depth = depth.clamp(1, MAX_PREDECESSOR_DEPTH);
        let cap = cap.min(MAX_HISTORY_ROWS);
        if ids.is_empty() || cap <= 0 {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE walk AS (
                SELECT s.id,
                       NULL::uuid AS successor_id,
                       0::int4 AS depth,
                       s.content,
                       COALESCE(s.is_current, true) AS is_current,
                       s.created_at,
                       s.updated_at
                FROM claims s
                WHERE s.id = ANY($1::uuid[]) /* {VISIBILITY:s} */
              UNION ALL
                SELECT p.id,
                       w.id,
                       w.depth + 1,
                       p.content,
                       COALESCE(p.is_current, true),
                       p.created_at,
                       p.updated_at
                FROM walk w
                CROSS JOIN LATERAL (
                    SELECT c.supersedes AS pred
                    FROM claims c
                    WHERE c.id = w.id AND c.supersedes IS NOT NULL
                      AND (w.depth > 0 OR w.is_current)
                      /* {VISIBILITY:c} */
                  UNION
                    SELECT e.target_id
                    FROM edges e
                    WHERE e.source_id = w.id
                      AND e.source_type = 'claim'
                      AND e.target_type = 'claim'
                      AND lower(e.relationship) = 'supersedes'
                      AND (e.valid_to IS NULL OR e.valid_to > now())
                      /* {EDGE_VISIBILITY:e} */
                ) hop
                JOIN claims p ON p.id = hop.pred
                WHERE w.depth < $2
                  AND NOT COALESCE(p.is_current, true)
                  /* {VISIBILITY:p} */
            ) CYCLE id SET walk_is_cycle USING walk_path,
            reached AS (
                SELECT DISTINCT ON (w.id)
                       w.id, w.successor_id, w.depth, w.content, w.is_current,
                       w.created_at, w.updated_at
                FROM walk w
                WHERE w.depth > 0
                  AND NOT w.walk_is_cycle
                  AND w.id <> ALL($1::uuid[])
                ORDER BY w.id, w.depth, w.successor_id
            )
            SELECT r.id, r.successor_id, r.depth, r.content, r.is_current,
                   r.created_at, r.updated_at
            FROM reached r
            ORDER BY r.depth, r.id
            LIMIT $3
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, PredecessorHit>(&sql)
            .bind(ids)
            .bind(depth)
            .bind(cap);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// Retired claims (`is_current = false`) whose `content_tsv` matches
    /// `websearch_to_tsquery('english', query)`, ranked by `ts_rank_cd`
    /// (highest first, ties by id), at most `cap` rows (clamped to
    /// `MAX_HISTORY_ROWS`).
    ///
    /// Reaches a claim withdrawn with no successor, which a lineage walk
    /// cannot. Each returned row is filtered by its own visibility; the
    /// successor it names is looked up under the viewer predicate too, so an
    /// invisible successor reads as `None`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn search_retired_lexical(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        query: &str,
        cap: i64,
    ) -> Result<Vec<RetiredLexicalHit>, DbError> {
        let cap = cap.min(MAX_HISTORY_ROWS);
        if cap <= 0 || query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let sql = viewer.splice(
            r#"
            SELECT c.id,
                   c.content,
                   COALESCE(c.is_current, true) AS is_current,
                   c.created_at,
                   c.updated_at,
                   ts_rank_cd(c.content_tsv, q)::float8 AS rank,
                   (
                       SELECT s.id
                       FROM (
                           SELECT x.id
                           FROM claims x
                           WHERE x.supersedes = c.id
                             AND COALESCE(x.is_current, true)
                             /* {VISIBILITY:x} */
                         UNION
                           SELECT e.source_id
                           FROM edges e
                           WHERE e.target_id = c.id
                             AND e.source_type = 'claim'
                             AND e.target_type = 'claim'
                             AND lower(e.relationship) = 'supersedes'
                             AND (e.valid_to IS NULL OR e.valid_to > now())
                             /* {EDGE_VISIBILITY:e} */
                       ) cand
                       JOIN claims s ON s.id = cand.id
                       WHERE true /* {VISIBILITY:s} */
                       ORDER BY s.created_at, s.id
                       LIMIT 1
                   ) AS successor_id
            FROM claims c, websearch_to_tsquery('english', $1) q
            WHERE c.content_tsv @@ q
              AND NOT COALESCE(c.is_current, true)
              /* {VISIBILITY:c} */
            ORDER BY ts_rank_cd(c.content_tsv, q) DESC, c.id
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, RetiredLexicalHit>(&sql)
            .bind(query)
            .bind(cap);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }
}
