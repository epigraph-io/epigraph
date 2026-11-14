//! The run reads of the Atlas naming step (Atlas W8, backlog a71816e1): a
//! map's latest finished run (optionally the latest one carrying a naming
//! record in its `params`), all the level documents of one run, and the
//! names one run stored.
//!
//! The claim text a name is made from is NOT read here: it is read through
//! [`crate::AtlasMeaningRepository::claim_labels`], which carries W3/W4's map
//! predicate, so a claim the map may no longer draw feeds no name.
//!
//! Every statement is spliced on the viewer and filters on the map's own
//! tenancy columns (`owner_group_id`, `visibility`), so a run of another map is
//! never read even on the maintenance connection, where the splice renders
//! nothing and row security filters nothing.

use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::errors::DbError;
use crate::repos::atlas_map::{AtlasMap, MapEpochs};
use crate::visibility::Viewer;

/// One finished run of a map.
#[derive(Debug, Clone, PartialEq)]
pub struct FinishedRun {
    pub id: Uuid,
    pub algo: String,
    pub params: Value,
    /// The four epochs the run recorded (its build snapshot's).
    pub epochs: MapEpochs,
}

/// One stored level of a run, as written.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct RunLevel {
    pub hierarchy: String,
    pub group_id: Uuid,
    pub parent_group_id: Option<Uuid>,
    pub theme_id: Uuid,
    pub level: i32,
    pub schema_version: i32,
    pub payload: Value,
}

/// The name one level of a run stored.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StoredName {
    pub hierarchy: String,
    pub group_id: Uuid,
    pub name: Option<String>,
    pub needs_naming: bool,
}

/// The naming step's run reads. See the module documentation.
pub struct AtlasNamingRepository;

type RunRow = (Uuid, String, Value, i64, i64, i64, i64);

impl AtlasNamingRepository {
    /// The latest finished run of `map` (by `finished_at`, then id, as the
    /// serving read orders them). With `named_only`, the latest finished run
    /// whose `params` carries a `naming` record.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn latest_finished_run(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        named_only: bool,
    ) -> Result<Option<FinishedRun>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT r.id, r.algo, r.params, r.map_epoch, r.public_epoch, \
                    r.map_left_epoch, r.public_left_epoch \
               FROM atlas_map_runs r \
              WHERE r.owner_group_id = $1 AND r.visibility = $2 \
                AND r.finished_at IS NOT NULL \
                AND (NOT $3 OR r.params ? 'naming') \
                /* {VISIBILITY:r} */ \
              ORDER BY r.finished_at DESC, r.id DESC \
              LIMIT 1",
            4,
        );
        let mut q = sqlx::query_as::<_, RunRow>(&sql)
            .bind(owner)
            .bind(visibility)
            .bind(named_only);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(&mut *conn).await?.map(
            |(id, algo, params, map, public, map_left, public_left)| FinishedRun {
                id,
                algo,
                params,
                epochs: MapEpochs {
                    map,
                    public,
                    map_left,
                    public_left,
                },
            },
        ))
    }

    /// Every level document of run `run_id` of `map`, both hierarchies,
    /// ordered by hierarchy, level and group id.
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn run_levels(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
    ) -> Result<Vec<RunLevel>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT l.hierarchy, l.group_id, l.parent_group_id, l.theme_id, l.level, \
                    l.schema_version, l.payload \
               FROM atlas_map_levels l \
              WHERE l.run_id = $1 AND l.owner_group_id = $2 AND l.visibility = $3 \
                /* {VISIBILITY:l} */ \
              ORDER BY l.hierarchy, l.level, l.group_id",
            4,
        );
        let mut q = sqlx::query_as::<_, RunLevel>(&sql)
            .bind(run_id)
            .bind(owner)
            .bind(visibility);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }

    /// The name and `needs_naming` flag every level of run `run_id` of `map`
    /// stored (a projection: no document is read whole).
    ///
    /// # Errors
    /// `DbError::QueryFailed` if the statement fails.
    pub async fn run_names(
        conn: &mut PgConnection,
        viewer: &Viewer,
        map: AtlasMap,
        run_id: Uuid,
    ) -> Result<Vec<StoredName>, DbError> {
        let (owner, visibility) = map.tenancy();
        let sql = viewer.splice(
            "SELECT l.hierarchy, l.group_id, l.payload->>'name' AS name, \
                    COALESCE((l.payload->>'needs_naming')::boolean, true) AS needs_naming \
               FROM atlas_map_levels l \
              WHERE l.run_id = $1 AND l.owner_group_id = $2 AND l.visibility = $3 \
                /* {VISIBILITY:l} */ \
              ORDER BY l.hierarchy, l.group_id",
            4,
        );
        let mut q = sqlx::query_as::<_, StoredName>(&sql)
            .bind(run_id)
            .bind(owner)
            .bind(visibility);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(&mut *conn).await?)
    }
}
