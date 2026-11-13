//! Per-team Atlas maps (migration 210, Atlas W2): the stored level documents
//! of each team's map and of the public map, and the staleness epochs that say
//! whether a stored run still matches the rows its map may draw.
//!
//! # Maps
//!
//! A map is [`AtlasMap::Team`] (a team or community group's map, rows
//! `('group', T)`, read by T's members) or [`AtlasMap::Public`] (rows
//! `('public', world)`, read by every session, an unstamped one included).
//! All three tables carry those tenancy columns under the standard
//! `<table>_tenancy` row-security policy, ENABLEd and FORCEd, so a non-member's
//! session reads no row of a team map whatever SQL it runs.
//!
//! # Two halves, two authorities (migration 197's split)
//!
//! **The build** runs on the maintenance connection: [`AtlasMapRepository::write_run`]
//! opens an unfinished run, [`AtlasMapRepository::put_level`] writes its level
//! documents and [`AtlasMapRepository::finish_run`] publishes it. The
//! application role holds SELECT only on these tables. The builder reads
//! [`AtlasMapRepository::map_epochs`] first in its REPEATABLE READ snapshot and
//! records both numbers on the run.
//!
//! **The serve** runs on the caller's viewer-stamped connection:
//! [`AtlasMapRepository::level_for_viewer`] reads one level of the latest
//! FINISHED run of one map in one statement, spliced on both tables it reads,
//! with row security beneath. It reports whether the run is still
//! [`MapLevel::current`]; what a route does with a stale run is the route's
//! decision (Atlas W10).
//!
//! # The payload
//!
//! A level document's JSON schema belongs to Atlas W10a and is versioned by
//! `schema_version`. This module stores and returns the document as an opaque
//! JSON object and reads none of its fields.

use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// The world group: the owner of the public map's rows (`TenancyDecl::instance_wide`).
const WORLD_GROUP: Uuid = Uuid::nil();

/// One Atlas map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtlasMap {
    /// The public-only map: built from public claims, readable by everyone.
    Public,
    /// One team's map: built from the team's claims plus public claims,
    /// readable by the team's members.
    Team(Uuid),
}

impl AtlasMap {
    /// `(owner_group_id, visibility)` of the map's rows.
    #[must_use]
    pub fn tenancy(self) -> (Uuid, &'static str) {
        match self {
            Self::Public => (WORLD_GROUP, "public"),
            Self::Team(g) => (g, "group"),
        }
    }
}

/// The two grouping hierarchies under each theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AtlasHierarchy {
    /// Groups of claims with similar embeddings (Atlas W4).
    Meaning,
    /// Communities in the claim graph (Atlas W5).
    Links,
}

impl AtlasHierarchy {
    /// The stored spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Meaning => "meaning",
            Self::Links => "links",
        }
    }
}

/// A map's epoch and the public map's, as one build snapshot reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapEpochs {
    /// `atlas_map_epochs.n` of the map (0 before its first bump).
    pub map: i64,
    /// `atlas_map_epochs.n` of the public map (0 before its first bump).
    pub public: i64,
}

/// A run to open, from [`AtlasMapRepository::write_run`].
#[derive(Debug, Clone)]
pub struct NewMapRun {
    pub map: AtlasMap,
    /// The builder's algorithm name, 1 to 64 characters.
    pub algo: String,
    pub params: serde_json::Value,
    /// What [`AtlasMapRepository::map_epochs`] returned in the build snapshot.
    pub epochs: MapEpochs,
}

/// One level document to store, from [`AtlasMapRepository::put_level`].
#[derive(Debug, Clone)]
pub struct LevelDoc {
    pub hierarchy: AtlasHierarchy,
    /// The group this document describes; stable across nights.
    pub group_id: Uuid,
    /// `None` exactly at level 0 (a group directly under its theme).
    pub parent_group_id: Option<Uuid>,
    pub theme_id: Uuid,
    pub level: i32,
    /// The W10a payload schema version the document follows.
    pub schema_version: i32,
    /// A JSON object; its fields are W10a's.
    pub payload: serde_json::Value,
}

/// One served level, from [`AtlasMapRepository::level_for_viewer`].
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct MapLevel {
    pub run_id: Uuid,
    pub finished_at: DateTime<Utc>,
    pub group_id: Uuid,
    pub parent_group_id: Option<Uuid>,
    pub theme_id: Uuid,
    pub level: i32,
    pub schema_version: i32,
    pub payload: serde_json::Value,
    /// Both epochs the run recorded still equal the live ones: no claim has
    /// entered or left the map's readable set since the build's snapshot.
    pub current: bool,
}

/// Per-team Atlas map storage. See the module documentation.
pub struct AtlasMapRepository;

impl AtlasMapRepository {
    // ── build side ───────────────────────────────────────────────────────────

    /// The map's epoch and the public map's, in one statement.
    ///
    /// The builder makes this the first read of its REPEATABLE READ
    /// transaction, so the snapshot it builds from and the epochs it records
    /// are the same: a move still uncommitted when the snapshot is taken bumps
    /// an epoch past the recorded one when it commits, and the run is stale on
    /// arrival rather than silently missing the move. On the maintenance
    /// connection the viewer is a system viewer and the splice is empty; on a
    /// stamped connection a non-member reads 0 for a team map.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn map_epochs(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
    ) -> Result<MapEpochs, DbError> {
        let (owner, _) = map.tenancy();
        let sql = viewer.splice(
            "SELECT COALESCE((SELECT e.n FROM atlas_map_epochs e \
                               WHERE e.owner_group_id = $1 /* {VISIBILITY:e} */), 0)::int8, \
                    COALESCE((SELECT p.n FROM atlas_map_epochs p \
                               WHERE p.owner_group_id = $2 AND p.visibility = 'public' \
                                 /* {VISIBILITY:p} */), 0)::int8",
            3,
        );
        let mut q = sqlx::query_as::<_, (i64, i64)>(&sql)
            .bind(owner)
            .bind(WORLD_GROUP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let (map_n, public_n) = q.fetch_one(&mut *conn).await?;
        Ok(MapEpochs {
            map: map_n,
            public: public_n,
        })
    }

    /// Open an unfinished run of one map and return its id. Its levels are
    /// written with [`Self::put_level`] and it is served only after
    /// [`Self::finish_run`].
    ///
    /// A team map must belong to a group of kind `team` or `community`: the
    /// staleness trigger keeps epochs for those kinds only, so a run of any
    /// other group's map could never go stale.
    ///
    /// # Errors
    /// `DbError::InvalidData` for a team map of any other group (or none);
    /// `DbError::QueryFailed` (a CHECK violation included) otherwise.
    pub async fn write_run(conn: &mut PgConnection, run: &NewMapRun) -> Result<Uuid, DbError> {
        let (owner, visibility) = run.map.tenancy();
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO atlas_map_runs \
                 (owner_group_id, visibility, algo, params, map_epoch, public_epoch) \
             SELECT $1, $2, $3, $4, $5, $6 \
             WHERE $2 = 'public' \
                OR EXISTS (SELECT 1 FROM groups g WHERE g.id = $1 \
                              AND g.kind IN ('team', 'community')) \
             RETURNING id",
        )
        .bind(owner)
        .bind(visibility)
        .bind(&run.algo)
        .bind(&run.params)
        .bind(run.epochs.map)
        .bind(run.epochs.public)
        .fetch_optional(&mut *conn)
        .await?;
        id.ok_or_else(|| DbError::InvalidData {
            reason: format!("no team or community group {owner} to build an Atlas map for"),
        })
    }

    /// Store one level document in an unfinished run, replacing the document
    /// of the same `(hierarchy, group_id)` if the run already has one. The
    /// document takes the run's tenancy (migration 210's composite foreign key
    /// pins it there).
    ///
    /// # Errors
    /// `DbError::NotFound` if no unfinished run `run_id` exists;
    /// `DbError::QueryFailed` (a CHECK violation included) otherwise.
    pub async fn put_level(
        conn: &mut PgConnection,
        run_id: Uuid,
        doc: &LevelDoc,
    ) -> Result<(), DbError> {
        let done = sqlx::query(
            "INSERT INTO atlas_map_levels \
                 (run_id, owner_group_id, visibility, hierarchy, group_id, parent_group_id, \
                  theme_id, level, schema_version, payload) \
             SELECT r.id, r.owner_group_id, r.visibility, $2, $3, $4, $5, $6, $7, $8 \
               FROM atlas_map_runs r \
              WHERE r.id = $1 AND r.finished_at IS NULL \
             ON CONFLICT (run_id, hierarchy, group_id) DO UPDATE \
                SET parent_group_id = EXCLUDED.parent_group_id, \
                    theme_id = EXCLUDED.theme_id, level = EXCLUDED.level, \
                    schema_version = EXCLUDED.schema_version, payload = EXCLUDED.payload",
        )
        .bind(run_id)
        .bind(doc.hierarchy.as_str())
        .bind(doc.group_id)
        .bind(doc.parent_group_id)
        .bind(doc.theme_id)
        .bind(doc.level)
        .bind(doc.schema_version)
        .bind(&doc.payload)
        .execute(&mut *conn)
        .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "unfinished atlas_map_run".to_string(),
                id: run_id,
            });
        }
        Ok(())
    }

    /// Publish an unfinished run: stamp `finished_at` and its level count.
    /// From then on [`Self::level_for_viewer`] serves it and
    /// [`Self::put_level`] refuses it.
    ///
    /// # Errors
    /// `DbError::NotFound` if no unfinished run `run_id` exists;
    /// `DbError::QueryFailed` otherwise.
    pub async fn finish_run(conn: &mut PgConnection, run_id: Uuid) -> Result<(), DbError> {
        let done = sqlx::query(
            "UPDATE atlas_map_runs r \
                SET finished_at = clock_timestamp(), \
                    level_count = (SELECT COUNT(*)::int4 FROM atlas_map_levels l \
                                    WHERE l.run_id = r.id) \
              WHERE r.id = $1 AND r.finished_at IS NULL",
        )
        .bind(run_id)
        .execute(&mut *conn)
        .await?;
        if done.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "unfinished atlas_map_run".to_string(),
                id: run_id,
            });
        }
        Ok(())
    }

    // ── serve ────────────────────────────────────────────────────────────────

    /// One level of the latest finished run of `map`, as `viewer` may read it:
    /// `None` when the map has no finished run the viewer can read, or that run
    /// has no document for `(hierarchy, group_id)`.
    ///
    /// One statement, on the caller's viewer-stamped connection. The run and
    /// the level are each spliced on the viewer, and row security filters both
    /// beneath the splice, so a non-member of a team gets `None` for any of its
    /// groups, exactly as for a group id that names nothing. The run lookup is
    /// `atlas_map_runs_latest_idx` and the level lookup the primary key.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn level_for_viewer(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        hierarchy: AtlasHierarchy,
        group_id: Uuid,
    ) -> Result<Option<MapLevel>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "WITH run AS ( \
                 SELECT r.id, r.finished_at, r.map_epoch, r.public_epoch \
                   FROM atlas_map_runs r \
                  WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                    AND r.finished_at IS NOT NULL \
                    /* {VISIBILITY:r} */ \
                  ORDER BY r.finished_at DESC, r.id DESC \
                  LIMIT 1 \
             ) \
             SELECT run.id AS run_id, run.finished_at, l.group_id, l.parent_group_id, \
                    l.theme_id, l.level, l.schema_version, l.payload, \
                    ( run.map_epoch = COALESCE((SELECT e.n FROM atlas_map_epochs e \
                                                 WHERE e.owner_group_id = $1 \
                                                   /* {VISIBILITY:e} */), 0) \
                      AND run.public_epoch = COALESCE((SELECT p.n FROM atlas_map_epochs p \
                                                        WHERE p.owner_group_id = $5 \
                                                          AND p.visibility = 'public' \
                                                          /* {VISIBILITY:p} */), 0) \
                    ) AS current \
               FROM run \
               JOIN atlas_map_levels l \
                 ON l.run_id = run.id AND l.hierarchy = $3 AND l.group_id = $4 \
              WHERE TRUE /* {VISIBILITY:l} */",
            6,
        );
        let mut q = sqlx::query_as::<_, MapLevel>(&sql)
            .bind(owner)
            .bind(visibility)
            .bind(hierarchy.as_str())
            .bind(group_id)
            .bind(WORLD_GROUP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?)
    }
}
