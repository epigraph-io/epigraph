//! Per-frame conflict density: the counts behind the silence alarm.
//!
//! `epigraph_engine::silence_alarm::check_conflict_density` is a pure function
//! over two numbers, a frame's claim count and its contradiction count. This
//! module is the one place those numbers are read. Three callers use it:
//! `GET /api/v1/conflicts/scan` (`silence_alarms`), `GET
//! /api/v1/conflicts/silence-check`, and the `19c` silence-alarm step of
//! `POST /api/v1/beliefs/evidence`.
//!
//! No `Viewer`: this is an aggregate over counts, with no row content, read on
//! whatever executor the caller passes (today the handlers' raw pool).

use uuid::Uuid;

use crate::errors::DbError;

/// One frame's conflict density.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct FrameConflictDensity {
    pub frame_id: Uuid,
    pub frame_name: String,
    /// Distinct claims holding at least one BBA in the frame.
    pub total_claims: i64,
    /// The contradiction count fed to `check_conflict_density`. The column
    /// keeps its historical name for API compatibility.
    pub contradicts_edges: i64,
    /// Distinct non-null `source_agent_id`s among the frame's BBAs.
    pub distinct_sources: i64,
}

/// `$1` is a nullable frame-id array (NULL = every frame), `$2` the frame
/// limit. One statement serves both the scan and the single-frame read.
const FRAME_CONFLICT_DENSITY_SQL: &str = "\
SELECT f.id AS frame_id, f.name AS frame_name, \
       (SELECT COUNT(DISTINCT mf.claim_id) FROM mass_functions mf WHERE mf.frame_id = f.id) AS total_claims, \
       (SELECT COUNT(*) FROM edges e \
        JOIN mass_functions mf1 ON mf1.claim_id = e.source_id AND mf1.frame_id = f.id \
        WHERE e.relationship = 'CONTRADICTS') AS contradicts_edges, \
       (SELECT COUNT(DISTINCT mf2.source_agent_id) FROM mass_functions mf2 \
        WHERE mf2.frame_id = f.id AND mf2.source_agent_id IS NOT NULL) AS distinct_sources \
FROM frames f \
WHERE $1::uuid[] IS NULL OR f.id = ANY($1) \
ORDER BY f.id \
LIMIT $2";

/// Read-only conflict-density queries.
pub struct ConflictDensityRepository;

impl ConflictDensityRepository {
    /// Densities for the first `limit` frames in id order.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    pub async fn scan<'e, E>(executor: E, limit: i64) -> Result<Vec<FrameConflictDensity>, DbError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        let rows = sqlx::query_as::<_, FrameConflictDensity>(FRAME_CONFLICT_DENSITY_SQL)
            .bind(Option::<Vec<Uuid>>::None)
            .bind(limit)
            .fetch_all(executor)
            .await?;
        Ok(rows)
    }

    /// Densities for exactly the given frames (unknown ids are absent).
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    pub async fn for_frames<'e, E>(
        executor: E,
        frame_ids: &[Uuid],
    ) -> Result<Vec<FrameConflictDensity>, DbError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        let limit = i64::try_from(frame_ids.len()).unwrap_or(i64::MAX);
        let rows = sqlx::query_as::<_, FrameConflictDensity>(FRAME_CONFLICT_DENSITY_SQL)
            .bind(Some(frame_ids.to_vec()))
            .bind(limit)
            .fetch_all(executor)
            .await?;
        Ok(rows)
    }
}
