//! Per-frame conflict density: the counts behind the silence alarm.
//!
//! `epigraph_engine::silence_alarm::check_conflict_density` is a pure function
//! over two numbers, a frame's claim count and its contradiction count. This
//! module is the one place those numbers are read. Three callers use it:
//! `GET /api/v1/conflicts/scan` (`silence_alarms`), `GET
//! /api/v1/conflicts/silence-check`, and the `19c` silence-alarm step of
//! `POST /api/v1/frames/:id/evidence`.
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
///
/// What `contradicts_edges` counts: distinct UNORDERED claim pairs joined by a
/// live (`valid_to` unset or in the future) claim->claim `contradicts` or
/// `refutes` edge, either stored spelling, where EITHER endpoint holds a BBA
/// in the frame. Each rule closes a way the previous inline query miscounted:
///
/// * Both spellings, listed literally rather than `lower(relationship)`, so
///   the btree `idx_edges_relationship` stays usable. MCP, `semantic_link` and
///   the cross-source matcher write lower-case; the REST edge route accepts
///   upper-case `CONTRADICTS`.
/// * `source_type = 'claim' AND target_type = 'claim'`: the upper-case
///   `CONTRADICTS` rows `submit_evidence` / `assess_claim` try to write have a
///   mass-function source and are not claim disagreements.
/// * `fc` is DISTINCT (frame, claim), so a source claim with k BBAs in the
///   frame does not count its edge k times.
/// * `LEAST`/`GREATEST` + `UNION`: A->B and B->A are one pair, and so are the
///   two spellings of one pair.
/// * Either endpoint: `contradicts` is symmetric and its stored orientation is
///   arbitrary (`create_symmetric_if_absent_oriented` picks one), so testing
///   only the source made the count depend on which way the row was written.
const FRAME_CONFLICT_DENSITY_SQL: &str = "\
WITH target AS ( \
    SELECT f.id, f.name FROM frames f \
    WHERE $1::uuid[] IS NULL OR f.id = ANY($1) \
    ORDER BY f.id \
    LIMIT $2 \
), \
fc AS ( \
    SELECT DISTINCT mf.frame_id, mf.claim_id \
    FROM mass_functions mf JOIN target t ON t.id = mf.frame_id \
), \
conflict AS ( \
    SELECT e.source_id, e.target_id FROM edges e \
    WHERE e.relationship IN ('contradicts', 'CONTRADICTS', 'refutes', 'REFUTES') \
      AND e.source_type = 'claim' AND e.target_type = 'claim' \
      AND e.source_id <> e.target_id \
      AND (e.valid_to IS NULL OR e.valid_to > now()) \
), \
pairs AS ( \
    SELECT fc.frame_id, LEAST(c.source_id, c.target_id) AS a, \
           GREATEST(c.source_id, c.target_id) AS b \
    FROM conflict c JOIN fc ON fc.claim_id = c.source_id \
    UNION \
    SELECT fc.frame_id, LEAST(c.source_id, c.target_id), \
           GREATEST(c.source_id, c.target_id) \
    FROM conflict c JOIN fc ON fc.claim_id = c.target_id \
) \
SELECT t.id AS frame_id, t.name AS frame_name, \
       (SELECT COUNT(*) FROM fc WHERE fc.frame_id = t.id) AS total_claims, \
       (SELECT COUNT(*) FROM pairs p WHERE p.frame_id = t.id) AS contradicts_edges, \
       (SELECT COUNT(DISTINCT mf.source_agent_id) FROM mass_functions mf \
        WHERE mf.frame_id = t.id AND mf.source_agent_id IS NOT NULL) AS distinct_sources \
FROM target t \
ORDER BY t.id";

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
