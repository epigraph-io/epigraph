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
//! application role holds SELECT only on these tables. The builder opens its
//! transaction with [`AtlasMapRepository::begin_build_snapshot`], which fixes a
//! REPEATABLE READ snapshot and reads the epochs in it, and records them on the
//! run.
//!
//! **The serve** runs on the caller's viewer-stamped connection:
//! [`AtlasMapRepository::level_for_viewer`] reads one level of the latest
//! FINISHED run of one map in one statement, spliced on both tables it reads,
//! with row security beneath. It reports two things about the run:
//! [`MapLevel::current`] (nothing entered or left the map's readable set, and
//! no level of the run was deleted) and [`MapLevel::nothing_left`] (no row left
//! it for somewhere its viewers cannot read). What a route does with either is
//! the route's decision (Atlas W10): an arrival leaves a map incomplete, a
//! departure may leave it holding a row its viewers may no longer read.
//!
//! # The epochs are not for the browser
//!
//! The world row of `atlas_map_epochs` is readable by every session, so its
//! counters say how often public rows moved. Migration 197 never hands its
//! epoch out; a route built on this module should return the two flags, not
//! the numbers.
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

/// A map's epoch counters and the public map's, as one build snapshot reads
/// them (migration 210, section 1). Every counter is 0 before its first bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapEpochs {
    /// `atlas_map_epochs.n` of the map: rows that entered or left its half.
    pub map: i64,
    /// `atlas_map_epochs.n` of the public map.
    pub public: i64,
    /// `atlas_map_epochs.left_n` of the map: rows that left its half for
    /// somewhere not public.
    pub map_left: i64,
    /// `atlas_map_epochs.left_n` of the public map.
    pub public_left: i64,
}

/// A run to open, from [`AtlasMapRepository::write_run`].
#[derive(Debug, Clone)]
pub struct NewMapRun {
    pub map: AtlasMap,
    /// The builder's algorithm name, 1 to 64 characters.
    pub algo: String,
    pub params: serde_json::Value,
    /// What [`AtlasMapRepository::begin_build_snapshot`] returned.
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
    /// Nothing changed since the build's snapshot: both `n` counters the run
    /// recorded still equal the live ones (no claim, edge or evidence row
    /// entered or left the map's readable set) and every level the run was
    /// finished with is still stored (a theme delete cascades its levels away).
    pub current: bool,
    /// No row LEFT the map's readable set for somewhere not public since the
    /// build's snapshot: both `left_n` counters still match. When false the
    /// stored map may hold a row its viewers can no longer read. Tenancy
    /// departures only: a deleted row bumps nothing.
    pub nothing_left: bool,
}

/// Per-team Atlas map storage. See the module documentation.
pub struct AtlasMapRepository;

impl AtlasMapRepository {
    // ── build side ───────────────────────────────────────────────────────────

    /// Open a build: fix a REPEATABLE READ snapshot on a fresh transaction and
    /// read `map`'s epochs in it, so the rows the build reads afterwards and the
    /// epochs it records on the run come from the same snapshot. A move still
    /// uncommitted when the snapshot is taken bumps an epoch past the recorded
    /// one when it commits, and the run is stale on arrival rather than
    /// silently missing the move.
    ///
    /// MUST be the first call on its transaction: its first statement is
    /// `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`, which PostgreSQL
    /// refuses once the transaction has run a query. Outside a transaction
    /// block that statement only warns, so the isolation level is then read
    /// back and anything weaker than REPEATABLE READ is refused.
    ///
    /// # Errors
    /// `DbError::QueryFailed` when the isolation level cannot be set (the
    /// transaction already ran a query); `DbError::InvalidData` when the
    /// connection is not in a REPEATABLE READ or SERIALIZABLE transaction.
    pub async fn begin_build_snapshot(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
    ) -> Result<MapEpochs, DbError> {
        Self::fix_repeatable_read(conn).await?;
        Self::map_epochs(conn, viewer, map).await
    }

    /// [`Self::begin_build_snapshot`]'s first half: set REPEATABLE READ on the
    /// connection's fresh transaction and refuse anything weaker.
    async fn fix_repeatable_read(conn: &mut PgConnection) -> Result<(), DbError> {
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *conn)
            .await?;
        let level: String = sqlx::query_scalar("SELECT current_setting('transaction_isolation')")
            .fetch_one(&mut *conn)
            .await?;
        if level != "repeatable read" && level != "serializable" {
            return Err(DbError::InvalidData {
                reason: format!(
                    "an Atlas map build needs a REPEATABLE READ transaction, not {level:?} \
                     (begin a transaction first)"
                ),
            });
        }
        Ok(())
    }

    /// The map's epoch counters and the public map's, in one statement, as
    /// `viewer` may read them: on a stamped connection a non-member reads 0
    /// for a team map. For a build use [`Self::begin_build_snapshot`], which
    /// also fixes the snapshot.
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
            "SELECT COALESCE(e.n, 0)::int8, COALESCE(p.n, 0)::int8, \
                    COALESCE(e.left_n, 0)::int8, COALESCE(p.left_n, 0)::int8 \
               FROM (SELECT 1) one \
               LEFT JOIN atlas_map_epochs e \
                 ON e.owner_group_id = $1 /* {VISIBILITY:e} */ \
               LEFT JOIN atlas_map_epochs p \
                 ON p.owner_group_id = $2 AND p.visibility = 'public' /* {VISIBILITY:p} */",
            3,
        );
        let mut q = sqlx::query_as::<_, (i64, i64, i64, i64)>(&sql)
            .bind(owner)
            .bind(WORLD_GROUP);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let (map, public, map_left, public_left) = q.fetch_one(&mut *conn).await?;
        Ok(MapEpochs {
            map,
            public,
            map_left,
            public_left,
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
                 (owner_group_id, visibility, algo, params, map_epoch, public_epoch, \
                  map_left_epoch, public_left_epoch) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8 \
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
        .bind(run.epochs.map_left)
        .bind(run.epochs.public_left)
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

    // ── nightly housekeeping (Atlas W9) ─────────────────────────────────────

    /// Every map with at least one finished run, as `viewer` may read them:
    /// the public map first, then the team maps by group id. The nightly
    /// refreshes these (a map with no finished run needs an operator build
    /// first).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn maps_with_finished_runs(
        conn: &mut PgConnection,
        viewer: &Viewer,
    ) -> Result<Vec<AtlasMap>, DbError> {
        let sql = viewer.splice(
            "SELECT DISTINCT r.owner_group_id, r.visibility \
               FROM atlas_map_runs r \
              WHERE r.finished_at IS NOT NULL \
                /* {VISIBILITY:r} */ \
              ORDER BY r.visibility DESC, r.owner_group_id",
            1,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String)>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|(owner, visibility)| {
                if visibility == "public" {
                    AtlasMap::Public
                } else {
                    AtlasMap::Team(owner)
                }
            })
            .collect())
    }

    /// The hierarchies run `run_id` of `map` holds levels of, sorted
    /// (`meaning` before `links`).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn run_hierarchies(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
    ) -> Result<Vec<AtlasHierarchy>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT DISTINCT l.hierarchy \
               FROM atlas_map_levels l \
              WHERE l.run_id = $1 AND l.owner_group_id = $2 AND l.visibility = $3 \
                /* {VISIBILITY:l} */",
            4,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql)
            .bind(run_id)
            .bind(owner)
            .bind(visibility);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let mut out: Vec<AtlasHierarchy> = q
            .fetch_all(&mut *conn)
            .await?
            .iter()
            .filter_map(|h| match h.as_str() {
                "meaning" => Some(AtlasHierarchy::Meaning),
                "links" => Some(AtlasHierarchy::Links),
                _ => None,
            })
            .collect();
        out.sort_by_key(|h| matches!(h, AtlasHierarchy::Links));
        Ok(out)
    }

    /// Serialise the publishers of one map until the caller's transaction
    /// ends: a transaction-level advisory lock keyed by the map. Every writer
    /// that checks "is the run I built from still the latest?" before it
    /// publishes takes it first (the nightly and the naming step's write), so
    /// the check and the publish cannot interleave with another's.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn lock_map_for_publish(
        conn: &mut PgConnection,
        map: AtlasMap,
    ) -> Result<(), DbError> {
        let (owner, visibility) = map.tenancy();
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended( \
                 'atlas-map-publish|' || $1::text || '|' || $2, 0))",
        )
        .bind(owner)
        .bind(visibility)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Delete the old runs of `map` (their levels go by `ON DELETE CASCADE`):
    /// every finished run but the newest `keep` (by `finished_at`, then id,
    /// the serving order), and every UNfinished run created before the
    /// newest finished run was. A run created after it (a build in flight)
    /// is kept. Scoped by the map's tenancy columns, so no other map's run is
    /// touched. Returns the number of runs deleted. Maintenance connection
    /// only (the application role holds SELECT only on these tables).
    ///
    /// # Errors
    /// `DbError::InvalidData` for `keep == 0` (it would delete the run being
    /// served); `DbError::QueryFailed` if the statement fails.
    pub async fn prune_runs(
        conn: &mut PgConnection,
        map: AtlasMap,
        keep: usize,
    ) -> Result<u64, DbError> {
        if keep == 0 {
            return Err(DbError::InvalidData {
                reason: "pruning must keep at least one finished run".to_string(),
            });
        }
        let keep = i64::try_from(keep).map_err(|_| DbError::InvalidData {
            reason: "keep is too large".to_string(),
        })?;
        let (owner, visibility) = map.tenancy();
        let done = sqlx::query(
            "WITH finished AS ( \
                 SELECT r.id, r.created_at, \
                        row_number() OVER (ORDER BY r.finished_at DESC, r.id DESC) AS rn \
                   FROM atlas_map_runs r \
                  WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                    AND r.finished_at IS NOT NULL \
             ) \
             DELETE FROM atlas_map_runs r \
              WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                AND ( r.id IN (SELECT f.id FROM finished f WHERE f.rn > $3) \
                      OR ( r.finished_at IS NULL \
                           AND r.created_at < (SELECT f.created_at FROM finished f \
                                                WHERE f.rn = 1) ) )",
        )
        .bind(owner)
        .bind(visibility)
        .bind(keep)
        .execute(&mut *conn)
        .await?;
        Ok(done.rows_affected())
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
    /// `atlas_map_runs_latest_idx` and the level lookup the primary key;
    /// [`MapLevel::current`] also counts the run's stored levels (a primary-key
    /// prefix scan) against the count it was finished with.
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
                 SELECT r.id, r.finished_at, r.map_epoch, r.public_epoch, \
                        r.map_left_epoch, r.public_left_epoch, r.level_count \
                   FROM atlas_map_runs r \
                  WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                    AND r.finished_at IS NOT NULL \
                    /* {VISIBILITY:r} */ \
                  ORDER BY r.finished_at DESC, r.id DESC \
                  LIMIT 1 \
             ) \
             SELECT run.id AS run_id, run.finished_at, l.group_id, l.parent_group_id, \
                    l.theme_id, l.level, l.schema_version, l.payload, \
                    ( run.map_epoch = COALESCE(e.n, 0) \
                      AND run.public_epoch = COALESCE(p.n, 0) \
                      AND run.level_count = (SELECT COUNT(*)::int4 FROM atlas_map_levels lc \
                                              WHERE lc.run_id = run.id /* {VISIBILITY:lc} */) \
                    ) AS current, \
                    ( run.map_left_epoch = COALESCE(e.left_n, 0) \
                      AND run.public_left_epoch = COALESCE(p.left_n, 0) \
                    ) AS nothing_left \
               FROM run \
               LEFT JOIN atlas_map_epochs e \
                 ON e.owner_group_id = $1 /* {VISIBILITY:e} */ \
               LEFT JOIN atlas_map_epochs p \
                 ON p.owner_group_id = $5 AND p.visibility = 'public' /* {VISIBILITY:p} */ \
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
