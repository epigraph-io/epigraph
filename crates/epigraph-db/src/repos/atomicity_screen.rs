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
                       /* {VISIBILITY:p} */) AS parents
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
    /// exclusions).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn page<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        population: ScreenPopulation,
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
                       /* {VISIBILITY:p} */) AS parents
            FROM claims c
            WHERE COALESCE(c.is_current, true) = true
              AND length(c.content) > 10
              AND NOT ('telemetry' = ANY(c.labels))
              AND (c.properties ->> 'event') IS NULL
              AND (NOT $2::bool OR EXISTS (
                  SELECT 1 FROM edges a
                    JOIN claims ap ON ap.id = a.source_id
                   WHERE a.target_id = c.id
                     AND a.relationship = 'decomposes_to'
                     AND a.source_type = 'claim'
                     AND (a.valid_to IS NULL OR a.valid_to > now())
                     AND COALESCE(ap.is_current, true) = true
                     /* {EDGE_VISIBILITY:a} */
                     /* {VISIBILITY:ap} */
              ))
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
            .bind(population == ScreenPopulation::Atoms)
            .bind(after_at)
            .bind(after_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
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
                       /* {VISIBILITY:p} */) AS parents
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
