//! The serving reads of the per-team Atlas maps (Atlas W10, backlog 083c97b9):
//! which maps a viewer can see, each map's theme roots, which leaf holds a
//! claim, and which of a leaf's nodes the viewer's session can read.
//!
//! One level is [`crate::AtlasMapRepository::level_for_viewer`] (W2); this
//! module holds the reads around it. Every statement runs on the caller's
//! viewer-stamped connection and is spliced on the viewer, with row security
//! beneath, so a non-member's session finds nothing of a team map whatever it
//! asks for.
//!
//! # Staleness
//!
//! Each read that names a run reports the run's `nothing_left` flag (W2's
//! `left_n` counters: no row left the map's readable set for somewhere not
//! public since the build). What to do with it is the route's decision; none
//! of these functions returns an epoch counter.
//!
//! # The payload
//!
//! The theme-roots and claim-to-leaf reads look into the stored W10a v1
//! documents (`schema_version = 1`): a root's `name`, `switch.level_id` and
//! its children's `claim_count` (or its claim nodes, when the root is itself a
//! leaf), and a leaf's claim nodes. A document of another version is skipped,
//! never misread.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use crate::visibility::Viewer;

/// The world group: the owner of the public map's rows.
const WORLD_GROUP: Uuid = Uuid::nil();

/// The level schema version these reads look into.
const LEVEL_SCHEMA_VERSION: i32 = 1;

/// The latest finished run of one map, as a viewer may read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedRun {
    pub map: AtlasMap,
    pub run_id: Uuid,
    pub finished_at: DateTime<Utc>,
    /// No row left the map's readable set for somewhere not public since
    /// the build's snapshot ([`crate::MapLevel::nothing_left`]).
    pub nothing_left: bool,
    /// The team group's display name (a team map whose group row the viewer
    /// reads); `None` for the public map.
    pub label: Option<String>,
}

/// One theme root (a level-0 document) of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeRoot {
    pub theme_id: Uuid,
    pub hierarchy: AtlasHierarchy,
    /// The root level's group id.
    pub group_id: Uuid,
    /// The root's name: the theme's name on this map, or `None` until named.
    pub name: Option<String>,
    /// The root's `switch.level_id`: the other hierarchy's root of the theme.
    pub switch_level_id: Option<Uuid>,
    /// Claims under the root, as stored: its children's `claim_count`
    /// summed, or its claim nodes when the root is a leaf.
    pub claim_count: i64,
}

/// The serving reads. See the module documentation.
pub struct AtlasServeRepository;

type RunRow = (Uuid, Uuid, String, DateTime<Utc>, bool, Option<String>);

fn parse_hierarchy(s: &str) -> Option<AtlasHierarchy> {
    match s {
        "meaning" => Some(AtlasHierarchy::Meaning),
        "links" => Some(AtlasHierarchy::Links),
        _ => None,
    }
}

impl AtlasServeRepository {
    /// The latest finished run of every map the viewer's session can read
    /// (their team and community maps, and the public map), each with its
    /// `nothing_left` flag and label. One statement:
    /// `atlas_map_runs_latest_idx` per map, the two epoch rows, the group.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn served_runs(
        conn: &mut PgConnection,
        viewer: &Viewer,
    ) -> Result<Vec<ServedRun>, DbError> {
        let sql = viewer.splice(
            "WITH latest AS ( \
                 SELECT DISTINCT ON (r.owner_group_id, r.visibility) \
                        r.id, r.owner_group_id, r.visibility, r.finished_at, \
                        r.map_left_epoch, r.public_left_epoch \
                   FROM atlas_map_runs r \
                  WHERE r.finished_at IS NOT NULL \
                    /* {VISIBILITY:r} */ \
                  ORDER BY r.owner_group_id, r.visibility, r.finished_at DESC, r.id DESC \
             ) \
             SELECT latest.id, latest.owner_group_id, latest.visibility::text, \
                    latest.finished_at, \
                    ( latest.map_left_epoch = COALESCE(e.left_n, 0) \
                      AND latest.public_left_epoch = COALESCE(p.left_n, 0) ) AS nothing_left, \
                    g.display_name \
               FROM latest \
               LEFT JOIN atlas_map_epochs e \
                 ON e.owner_group_id = latest.owner_group_id /* {VISIBILITY:e} */ \
               LEFT JOIN atlas_map_epochs p \
                 ON p.owner_group_id = $1 AND p.visibility = 'public' /* {VISIBILITY:p} */ \
               LEFT JOIN groups g \
                 ON g.id = latest.owner_group_id AND latest.visibility = 'group' \
              ORDER BY latest.visibility = 'public', g.display_name NULLS LAST, latest.owner_group_id",
            2,
        );
        let mut q = sqlx::query_as::<_, RunRow>(&sql).bind(WORLD_GROUP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(&mut *conn).await?;
        Ok(rows
            .into_iter()
            .map(
                |(run_id, owner, visibility, finished_at, nothing_left, label)| {
                    let map = if visibility == "public" {
                        AtlasMap::Public
                    } else {
                        AtlasMap::Team(owner)
                    };
                    ServedRun {
                        map,
                        run_id,
                        finished_at,
                        nothing_left,
                        label: if map == AtlasMap::Public { None } else { label },
                    }
                },
            )
            .collect())
    }

    /// The latest finished run of `map` as the viewer may read it, or `None`
    /// when the map has none the viewer's session can read (a non-member of
    /// a team gets `None`, exactly as for a group that has no map).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn served_run(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
    ) -> Result<Option<ServedRun>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "WITH run AS ( \
                 SELECT r.id, r.owner_group_id, r.visibility, r.finished_at, \
                        r.map_left_epoch, r.public_left_epoch \
                   FROM atlas_map_runs r \
                  WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                    AND r.finished_at IS NOT NULL \
                    /* {VISIBILITY:r} */ \
                  ORDER BY r.finished_at DESC, r.id DESC \
                  LIMIT 1 \
             ) \
             SELECT run.id, run.owner_group_id, run.visibility::text, run.finished_at, \
                    ( run.map_left_epoch = COALESCE(e.left_n, 0) \
                      AND run.public_left_epoch = COALESCE(p.left_n, 0) ) AS nothing_left, \
                    g.display_name \
               FROM run \
               LEFT JOIN atlas_map_epochs e \
                 ON e.owner_group_id = $1 /* {VISIBILITY:e} */ \
               LEFT JOIN atlas_map_epochs p \
                 ON p.owner_group_id = $3 AND p.visibility = 'public' /* {VISIBILITY:p} */ \
               LEFT JOIN groups g \
                 ON g.id = run.owner_group_id AND run.visibility = 'group'",
            4,
        );
        let mut q = sqlx::query_as::<_, RunRow>(&sql)
            .bind(owner)
            .bind(visibility)
            .bind(WORLD_GROUP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?.map(
            |(run_id, _, _, finished_at, nothing_left, label)| ServedRun {
                map,
                run_id,
                finished_at,
                nothing_left,
                label: if map == AtlasMap::Public { None } else { label },
            },
        ))
    }

    /// Every theme root (level-0 document, schema v1) of `run_id` in `map`
    /// that the viewer may read, ordered by theme then hierarchy. One
    /// statement on `atlas_map_levels_theme_roots_idx`; it reads each root
    /// document's name, switch and child counts.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails (a stored count that is
    /// not an integer included).
    pub async fn theme_roots(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
    ) -> Result<Vec<ThemeRoot>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT l.theme_id, l.hierarchy, l.group_id, \
                    l.payload->>'name', \
                    CASE WHEN l.payload->'switch'->>'level_id' \
                              ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
                         THEN (l.payload->'switch'->>'level_id')::uuid END, \
                    CASE WHEN l.payload->>'kind' = 'group' \
                         THEN (SELECT COALESCE(SUM((c.value->>'claim_count')::int8), 0)::int8 \
                                 FROM jsonb_array_elements(l.payload->'children') c) \
                         ELSE (SELECT COUNT(*)::int8 \
                                 FROM jsonb_array_elements(l.payload->'nodes') n \
                                WHERE n.value->>'kind' = 'claim') END \
               FROM atlas_map_levels l \
              WHERE l.run_id = $1 AND l.level = 0 \
                AND l.owner_group_id = $2 AND l.visibility = $3 \
                AND l.schema_version = $4 \
                /* {VISIBILITY:l} */ \
              ORDER BY l.theme_id, l.hierarchy",
            5,
        );
        let mut q =
            sqlx::query_as::<_, (Uuid, String, Uuid, Option<String>, Option<Uuid>, i64)>(&sql)
                .bind(run_id)
                .bind(owner)
                .bind(visibility)
                .bind(LEVEL_SCHEMA_VERSION);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn)
            .await?
            .into_iter()
            .filter_map(
                |(theme_id, h, group_id, name, switch_level_id, claim_count)| {
                    Some(ThemeRoot {
                        theme_id,
                        hierarchy: parse_hierarchy(&h)?,
                        group_id,
                        name,
                        switch_level_id,
                        claim_count,
                    })
                },
            )
            .collect())
    }

    /// The leaf group(s) of `hierarchy` in `run_id` of `map` whose claim nodes
    /// hold `claim_id`, when the viewer's session can read the claim: the
    /// claim's current theme narrows the search to that theme's leaves of the
    /// run (a primary-key prefix scan of the run's levels, filtered on the
    /// theme, then a containment test on those leaves only). Empty when the
    /// claim is unreadable, has no theme, or is on no leaf of that theme; a
    /// claim re-themed since the build is found again after the next one.
    /// More than one group means a malformed run; the caller refuses it.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn leaves_of_claim(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
        hierarchy: AtlasHierarchy,
        claim_id: Uuid,
    ) -> Result<Vec<(Uuid, Uuid)>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT c.theme_id, l.group_id \
               FROM claims c \
               JOIN atlas_map_levels l \
                 ON l.run_id = $1 AND l.hierarchy = $2 AND l.theme_id = c.theme_id \
                AND l.owner_group_id = $4 AND l.visibility = $5 \
                AND l.schema_version = $6 \
                AND l.payload->>'kind' = 'leaf' \
                AND l.payload->'nodes' @> \
                    jsonb_build_array(jsonb_build_object('kind', 'claim', 'id', $3::text)) \
                /* {VISIBILITY:l} */ \
              WHERE c.id = $3 \
                /* {VISIBILITY:c} */ \
              ORDER BY l.group_id \
              LIMIT 2",
            7,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Uuid)>(&sql)
            .bind(run_id)
            .bind(hierarchy.as_str())
            .bind(claim_id)
            .bind(owner)
            .bind(visibility)
            .bind(LEVEL_SCHEMA_VERSION);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// Which of a leaf's node ids the viewer's own session can read, by kind:
    /// claims and evidence through their row security and the viewer's
    /// predicate, agents by existence (an `agents` row is readable by every
    /// session, migration 077). An id is only ever checked against the table
    /// of the kind the document gave it. One statement.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn readable_leaf_nodes(
        conn: &mut PgConnection,
        viewer: &Viewer,
        claims: &[Uuid],
        evidence: &[Uuid],
        agents: &[Uuid],
    ) -> Result<BTreeSet<Uuid>, DbError> {
        let sql = viewer.splice(
            "SELECT c.id FROM claims c WHERE c.id = ANY($1) /* {VISIBILITY:c} */ \
             UNION ALL \
             SELECT e.id FROM evidence e WHERE e.id = ANY($2) /* {VISIBILITY:e} */ \
             UNION ALL \
             SELECT a.id FROM agents a WHERE a.id = ANY($3)",
            4,
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(claims)
            .bind(evidence)
            .bind(agents);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?.into_iter().collect())
    }
}
