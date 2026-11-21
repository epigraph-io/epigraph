//! Reads behind the atomicity screen (backlogs `72850d43` and `c4a8436b`):
//! the rows `epigraph_core::atomicity::conjunct_screen` is run over, with the
//! `decomposes_to` shape of each.
//!
//! # Why a separate population
//!
//! `ClaimRepository::list_undecomposed` and the `decompose_claims` candidate
//! queries exclude every claim with a `decomposes_to` edge in either
//! direction, so an ATOM that still asserts several things (the target of a
//! `decomposes_to` edge) can never be found there. These reads select current
//! claims regardless of those edges, and report the edges instead.
//!
//! # Visibility
//!
//! Every function takes a `&Viewer` and splices it. The `decomposes_to`
//! counts and the atom-population `EXISTS` are POSITIVE probes (a parent or a
//! child the caller is told about), so each carries
//! `/* {EDGE_VISIBILITY:<alias>} */` on the edge and `/* {VISIBILITY:<alias>} */`
//! on the claim at its other end: a hidden edge or a hidden neighbour is in no
//! count. This is the opposite of `list_undecomposed`'s unmarked exclusion
//! probes, and deliberately so.
//!
//! # Paging
//!
//! The screen is computed in Rust after the read, so a page cannot be an
//! `OFFSET` into the filtered result. [`AtomicityScreenRepository::page`] is a
//! keyset walk over `(created_at, id)` of the UNFILTERED population; the
//! caller filters each page and resumes from the last row it read.
//!
//! Inside one page the walk is two statements per window (backlog
//! `9989c0a6`): the next window of visible claims in keyset order, which is a
//! range read of `idx_claims_created_at` and nothing else, then the population
//! filters and the counts over exactly those ids. One statement that filters
//! and orders together was planned on a production corpus as a scan of every
//! claim after the cursor plus a top-N sort, on EVERY page: the population
//! filters (`length(content)`, the telemetry label, `properties ->> 'event'`)
//! carry no statistics, so the planner expected a few hundred qualifying rows
//! where there were hundreds of thousands, and an index walk looked dearer
//! than reading the table. The window read has no such filter to misestimate,
//! and the filtered read is bounded by the window whatever its plan.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::errors::DbError;

/// One claim the screen is run over.
#[derive(Debug, Clone, FromRow, PartialEq)]
pub struct ScreenRow {
    pub id: Uuid,
    pub content: String,
    pub is_current: bool,
    pub labels: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// Distinct current children reached through an in-force `decomposes_to`
    /// edge, edge and child both visible to the viewer.
    pub children: i64,
    /// Distinct current parents that reach this claim through an in-force
    /// `decomposes_to` edge, edge and parent both visible to the viewer.
    pub parents: i64,
    /// [`Self::children`] further restricted to the claim's AUDIENCE: edges
    /// and children that EVERY reader of this claim can see. For a public
    /// claim that is public edges onto public children; for a group claim,
    /// also edges and children owned by its own group alone (an edge
    /// co-owned with another group is visible to fewer readers than the
    /// claim, so it does not count). Equal to `children` whenever nothing
    /// narrower than the claim is involved.
    ///
    /// What a label written on the claim may be derived from: the
    /// compound-atom sweep runs as the bypass viewer, and a label built from
    /// `children`/`parents` there would disclose, to every reader of the
    /// claim, structure some of them cannot see (review M1, backlog
    /// `72850d43`).
    pub audience_children: i64,
    /// [`Self::parents`] restricted to the claim's audience, as
    /// [`Self::audience_children`].
    pub audience_parents: i64,
}

/// Which claims [`AtomicityScreenRepository::page`] walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenPopulation {
    /// Claims with at least one visible current parent through an in-force
    /// `decomposes_to` edge: the atoms of some decomposition.
    Atoms,
    /// Every current claim, decomposed or not.
    All,
}

pub struct AtomicityScreenRepository;

/// Fewest claims [`AtomicityScreenRepository::page`] reads per window.
const PAGE_WINDOW_MIN: i64 = 200;
/// Most claims [`AtomicityScreenRepository::page`] reads per window. The
/// window is twice the page, within these bounds: about half the corpus is
/// atoms, so one window usually fills a page.
const PAGE_WINDOW_MAX: i64 = 2000;

impl AtomicityScreenRepository {
    /// The members of `ids` the viewer can read, in the given order, current
    /// or not. An id that is absent or hidden is simply not returned; the
    /// caller diffs to report it.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn rows_by_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<Vec<ScreenRow>, DbError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content,
                   COALESCE(c.is_current, true) AS is_current, c.labels, c.created_at,
                   (SELECT count(DISTINCT d.target_id) FROM edges d
                      JOIN claims k ON k.id = d.target_id
                     WHERE d.source_id = c.id
                       AND d.relationship = 'decomposes_to'
                       AND d.target_type = 'claim'
                       AND (d.valid_to IS NULL OR d.valid_to > now())
                       AND COALESCE(k.is_current, true) = true
                       /* {EDGE_VISIBILITY:d} */
                       /* {VISIBILITY:k} */) AS children,
                   (SELECT count(DISTINCT u.source_id) FROM edges u
                      JOIN claims p ON p.id = u.source_id
                     WHERE u.target_id = c.id
                       AND u.relationship = 'decomposes_to'
                       AND u.source_type = 'claim'
                       AND (u.valid_to IS NULL OR u.valid_to > now())
                       AND COALESCE(p.is_current, true) = true
                       /* {EDGE_VISIBILITY:u} */
                       /* {VISIBILITY:p} */) AS parents,
                   (SELECT count(DISTINCT xd.target_id) FROM edges xd
                      JOIN claims xk ON xk.id = xd.target_id
                     WHERE xd.source_id = c.id
                       AND xd.relationship = 'decomposes_to'
                       AND xd.target_type = 'claim'
                       AND (xd.valid_to IS NULL OR xd.valid_to > now())
                       AND COALESCE(xk.is_current, true) = true
                       /* {EDGE_VISIBILITY:xd} */
                       /* {VISIBILITY:xk} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xd.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xd.owner_group_id = c.owner_group_id
                                AND (xd.co_owner_group_id IS NULL
                                     OR xd.co_owner_group_id = c.owner_group_id)))
                       AND (xk.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xk.owner_group_id = c.owner_group_id))) AS audience_children,
                   (SELECT count(DISTINCT xu.source_id) FROM edges xu
                      JOIN claims xp ON xp.id = xu.source_id
                     WHERE xu.target_id = c.id
                       AND xu.relationship = 'decomposes_to'
                       AND xu.source_type = 'claim'
                       AND (xu.valid_to IS NULL OR xu.valid_to > now())
                       AND COALESCE(xp.is_current, true) = true
                       /* {EDGE_VISIBILITY:xu} */
                       /* {VISIBILITY:xp} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xu.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xu.owner_group_id = c.owner_group_id
                                AND (xu.co_owner_group_id IS NULL
                                     OR xu.co_owner_group_id = c.owner_group_id)))
                       AND (xp.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xp.owner_group_id = c.owner_group_id))) AS audience_parents
            FROM unnest($1::uuid[]) WITH ORDINALITY AS want(id, ord)
            JOIN claims c ON c.id = want.id
            WHERE true
              /* {VISIBILITY:c} */
            ORDER BY want.ord
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ScreenRow>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Up to `limit` rows of `population` after the keyset `after`
    /// (`created_at ASC, id ASC`), current claims only, without telemetry and
    /// content of 10 characters or fewer (the undecomposed population's own
    /// exclusions). Fewer than `limit` rows means the population is
    /// exhausted.
    ///
    /// Reads the population a window at a time (see the module's "Paging"),
    /// so it issues several statements, all on `conn` (a connection, or a
    /// transaction's).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a query fails.
    pub async fn page(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        population: ScreenPopulation,
        after: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<ScreenRow>, DbError> {
        let limit = limit.clamp(1, 1000);
        let window = (limit * 2).clamp(PAGE_WINDOW_MIN, PAGE_WINDOW_MAX);
        let mut rows: Vec<ScreenRow> = Vec::new();
        let mut cursor = after;
        loop {
            let keys = Self::window_keys(conn, viewer, cursor, window).await?;
            let Some(&last) = keys.last() else {
                break;
            };
            let ids: Vec<Uuid> = keys.iter().map(|(_, id)| *id).collect();
            let want = limit - rows.len() as i64;
            rows.extend(Self::screen_rows(conn, viewer, population, &ids, want).await?);
            if rows.len() as i64 >= limit || (keys.len() as i64) < window {
                break;
            }
            cursor = Some(last);
        }
        Ok(rows)
    }

    /// The next `window` claims the viewer can read after `after`, in
    /// `(created_at, id)` order, filtered on nothing else. A range read of
    /// `idx_claims_created_at` (incrementally sorted on `id` within a
    /// timestamp): the keyset is its only selective predicate, and its
    /// estimate comes from `created_at`'s histogram, so no misestimated filter
    /// can make a table scan look cheaper. The SQL is chosen in Rust per case,
    /// never `$n IS NULL OR …`, which a cached generic plan cannot turn into
    /// an index condition.
    async fn window_keys(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        after: Option<(DateTime<Utc>, Uuid)>,
        window: i64,
    ) -> Result<Vec<(DateTime<Utc>, Uuid)>, DbError> {
        let (keyset, first_bind) = match after {
            Some(_) => ("AND (c.created_at, c.id) > ($2::timestamptz, $3::uuid)", 4),
            None => ("", 2),
        };
        let sql = viewer.splice(
            &format!(
                r#"
                SELECT c.created_at, c.id
                  FROM claims c
                 WHERE true
                   {keyset}
                   /* {{VISIBILITY:c}} */
                 ORDER BY c.created_at ASC, c.id ASC
                 LIMIT $1
                "#
            ),
            first_bind,
        );
        let mut q = sqlx::query_as::<_, (DateTime<Utc>, Uuid)>(&sql).bind(window);
        if let Some((at, id)) = after {
            q = q.bind(at).bind(id);
        }
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(conn).await?)
    }

    /// The members of `ids` (one window) that are in `population`, in
    /// `(created_at, id)` order, at most `limit`, with their counts.
    ///
    /// The atom test is a `LATERAL … LIMIT 1` probe rather than an `EXISTS`:
    /// the planner cannot turn it into a semi-join that hashes every
    /// `decomposes_to` edge, so it stays one `idx_edges_target` lookup per
    /// window row.
    async fn screen_rows(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        population: ScreenPopulation,
        ids: &[Uuid],
        limit: i64,
    ) -> Result<Vec<ScreenRow>, DbError> {
        let atom_probe = match population {
            ScreenPopulation::Atoms => {
                r#"
                CROSS JOIN LATERAL (
                  SELECT 1 FROM edges a
                    JOIN claims ap ON ap.id = a.source_id
                   WHERE a.target_id = c.id
                     AND a.relationship = 'decomposes_to'
                     AND a.source_type = 'claim'
                     AND (a.valid_to IS NULL OR a.valid_to > now())
                     AND COALESCE(ap.is_current, true) = true
                     /* {EDGE_VISIBILITY:a} */
                     /* {VISIBILITY:ap} */
                   LIMIT 1
                ) atom"#
            }
            ScreenPopulation::All => "",
        };
        let sql = viewer.splice(
            &format!(
                r#"
            SELECT c.id, c.content, true AS is_current, c.labels, c.created_at,
                   (SELECT count(DISTINCT d.target_id) FROM edges d
                      JOIN claims k ON k.id = d.target_id
                     WHERE d.source_id = c.id
                       AND d.relationship = 'decomposes_to'
                       AND d.target_type = 'claim'
                       AND (d.valid_to IS NULL OR d.valid_to > now())
                       AND COALESCE(k.is_current, true) = true
                       /* {{EDGE_VISIBILITY:d}} */
                       /* {{VISIBILITY:k}} */) AS children,
                   (SELECT count(DISTINCT u.source_id) FROM edges u
                      JOIN claims p ON p.id = u.source_id
                     WHERE u.target_id = c.id
                       AND u.relationship = 'decomposes_to'
                       AND u.source_type = 'claim'
                       AND (u.valid_to IS NULL OR u.valid_to > now())
                       AND COALESCE(p.is_current, true) = true
                       /* {{EDGE_VISIBILITY:u}} */
                       /* {{VISIBILITY:p}} */) AS parents,
                   (SELECT count(DISTINCT xd.target_id) FROM edges xd
                      JOIN claims xk ON xk.id = xd.target_id
                     WHERE xd.source_id = c.id
                       AND xd.relationship = 'decomposes_to'
                       AND xd.target_type = 'claim'
                       AND (xd.valid_to IS NULL OR xd.valid_to > now())
                       AND COALESCE(xk.is_current, true) = true
                       /* {{EDGE_VISIBILITY:xd}} */
                       /* {{VISIBILITY:xk}} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xd.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xd.owner_group_id = c.owner_group_id
                                AND (xd.co_owner_group_id IS NULL
                                     OR xd.co_owner_group_id = c.owner_group_id)))
                       AND (xk.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xk.owner_group_id = c.owner_group_id))) AS audience_children,
                   (SELECT count(DISTINCT xu.source_id) FROM edges xu
                      JOIN claims xp ON xp.id = xu.source_id
                     WHERE xu.target_id = c.id
                       AND xu.relationship = 'decomposes_to'
                       AND xu.source_type = 'claim'
                       AND (xu.valid_to IS NULL OR xu.valid_to > now())
                       AND COALESCE(xp.is_current, true) = true
                       /* {{EDGE_VISIBILITY:xu}} */
                       /* {{VISIBILITY:xp}} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xu.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xu.owner_group_id = c.owner_group_id
                                AND (xu.co_owner_group_id IS NULL
                                     OR xu.co_owner_group_id = c.owner_group_id)))
                       AND (xp.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xp.owner_group_id = c.owner_group_id))) AS audience_parents
            FROM claims c{atom_probe}
            WHERE c.id = ANY($1::uuid[])
              AND COALESCE(c.is_current, true) = true
              AND length(c.content) > 10
              AND NOT ('telemetry' = ANY(c.labels))
              AND (c.properties ->> 'event') IS NULL
              /* {{VISIBILITY:c}} */
            ORDER BY c.created_at ASC, c.id ASC
            LIMIT $2
            "#
            ),
            3,
        );
        let mut q = sqlx::query_as::<_, ScreenRow>(&sql).bind(ids).bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(conn).await?)
    }

    /// Up to `limit` current claims carrying `label`, after the keyset
    /// `after` (`created_at ASC, id ASC`), with the same columns as
    /// [`Self::page`]. The compound-atom sweep reads its own label back with
    /// this, to take it off claims that no longer qualify.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn labelled_page<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        label: &str,
        after: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<ScreenRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id, c.content, true AS is_current, c.labels, c.created_at,
                   (SELECT count(DISTINCT d.target_id) FROM edges d
                      JOIN claims k ON k.id = d.target_id
                     WHERE d.source_id = c.id
                       AND d.relationship = 'decomposes_to'
                       AND d.target_type = 'claim'
                       AND (d.valid_to IS NULL OR d.valid_to > now())
                       AND COALESCE(k.is_current, true) = true
                       /* {EDGE_VISIBILITY:d} */
                       /* {VISIBILITY:k} */) AS children,
                   (SELECT count(DISTINCT u.source_id) FROM edges u
                      JOIN claims p ON p.id = u.source_id
                     WHERE u.target_id = c.id
                       AND u.relationship = 'decomposes_to'
                       AND u.source_type = 'claim'
                       AND (u.valid_to IS NULL OR u.valid_to > now())
                       AND COALESCE(p.is_current, true) = true
                       /* {EDGE_VISIBILITY:u} */
                       /* {VISIBILITY:p} */) AS parents,
                   (SELECT count(DISTINCT xd.target_id) FROM edges xd
                      JOIN claims xk ON xk.id = xd.target_id
                     WHERE xd.source_id = c.id
                       AND xd.relationship = 'decomposes_to'
                       AND xd.target_type = 'claim'
                       AND (xd.valid_to IS NULL OR xd.valid_to > now())
                       AND COALESCE(xk.is_current, true) = true
                       /* {EDGE_VISIBILITY:xd} */
                       /* {VISIBILITY:xk} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xd.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xd.owner_group_id = c.owner_group_id
                                AND (xd.co_owner_group_id IS NULL
                                     OR xd.co_owner_group_id = c.owner_group_id)))
                       AND (xk.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xk.owner_group_id = c.owner_group_id))) AS audience_children,
                   (SELECT count(DISTINCT xu.source_id) FROM edges xu
                      JOIN claims xp ON xp.id = xu.source_id
                     WHERE xu.target_id = c.id
                       AND xu.relationship = 'decomposes_to'
                       AND xu.source_type = 'claim'
                       AND (xu.valid_to IS NULL OR xu.valid_to > now())
                       AND COALESCE(xp.is_current, true) = true
                       /* {EDGE_VISIBILITY:xu} */
                       /* {VISIBILITY:xp} */
                       -- AUDIENCE: only what every reader of c can see.
                       AND (xu.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xu.owner_group_id = c.owner_group_id
                                AND (xu.co_owner_group_id IS NULL
                                     OR xu.co_owner_group_id = c.owner_group_id)))
                       AND (xp.visibility = 'public'
                            OR (c.visibility <> 'public'
                                AND xp.owner_group_id = c.owner_group_id))) AS audience_parents
            FROM claims c
            WHERE COALESCE(c.is_current, true) = true
              AND $2 = ANY(c.labels)
              AND ($3::timestamptz IS NULL OR (c.created_at, c.id) > ($3::timestamptz, $4::uuid))
              /* {VISIBILITY:c} */
            ORDER BY c.created_at ASC, c.id ASC
            LIMIT $1
            "#,
            5,
        );
        let (after_at, after_id) = match after {
            Some((at, id)) => (Some(at), Some(id)),
            None => (None, None),
        };
        let mut q = sqlx::query_as::<_, ScreenRow>(&sql)
            .bind(limit.clamp(1, 1000))
            .bind(label)
            .bind(after_at)
            .bind(after_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }
}
