//! Per-frame conflict density: the counts behind the silence alarm.
//!
//! `epigraph_engine::silence_alarm::check_conflict_density` is a pure function
//! over two numbers, a frame's claim count and its contradiction count. This
//! module is the one place those numbers are read. Three callers use it:
//! `GET /api/v1/conflicts/scan` (`silence_alarms`), `GET
//! /api/v1/conflicts/silence-check`, and the `19c` silence-alarm step of
//! `POST /api/v1/frames/:id/evidence`.
//!
//! The density reads take no `Viewer`: they are aggregates over counts, with no
//! row content, read on whatever executor the caller passes. Row security on a
//! stamped connection is what scopes them.
//!
//! [`ConflictDensityRepository::high_conflict_claims`] is different: it
//! projects `claims.content`, so it splices the caller's `Viewer` onto both
//! tenanted relations it reads.

use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

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
///
/// The per-frame counts are one `GROUP BY` each over `fc` and `pairs`, joined
/// to the frames, not a correlated `COUNT(*)` per frame: `fc` is referenced
/// more than once, so Postgres materializes it, and a correlated count would
/// rescan the whole materialized CTE once per frame of the 100-frame scan.
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
    WHERE mf.retracted_at IS NULL \
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
), \
fc_counts AS ( \
    SELECT frame_id, COUNT(*) AS n FROM fc GROUP BY frame_id \
), \
pair_counts AS ( \
    SELECT frame_id, COUNT(*) AS n FROM pairs GROUP BY frame_id \
) \
SELECT t.id AS frame_id, t.name AS frame_name, \
       COALESCE(fcc.n, 0) AS total_claims, \
       COALESCE(pc.n, 0) AS contradicts_edges, \
       (SELECT COUNT(DISTINCT mf.source_agent_id) FROM mass_functions mf \
        WHERE mf.frame_id = t.id AND mf.source_agent_id IS NOT NULL \
          AND mf.retracted_at IS NULL) AS distinct_sources \
FROM target t \
LEFT JOIN fc_counts fcc ON fcc.frame_id = t.id \
LEFT JOIN pair_counts pc ON pc.frame_id = t.id \
ORDER BY t.id";

/// One claim's live BBA conflict in one frame, as `GET /api/v1/conflicts/scan`
/// reports it under `high_conflict`.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct HighConflictClaim {
    pub claim_id: Uuid,
    pub frame_id: Uuid,
    /// The largest `conflict_k` among the claim's visible live BBAs in the frame.
    pub max_k: Option<f64>,
    /// How many visible live BBAs in the frame reached `min_k`.
    pub bba_count: i64,
    pub content: String,
}

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

    /// The `limit` claim/frame pairs with the highest live BBA conflict at or
    /// above `min_k`, among the BBAs and claims `viewer` may read.
    ///
    /// This was an inline statement in `epigraph-api`'s
    /// `routes/conflicts.rs::scan_conflicts`, run on the raw pool with no
    /// viewer, which returned `claims.content` for every matching claim.
    ///
    /// # Errors
    /// Returns [`DbError`] if the query fails.
    pub async fn high_conflict_claims<'e, E>(
        executor: E,
        viewer: &Viewer,
        min_k: f64,
        limit: i64,
    ) -> Result<Vec<HighConflictClaim>, DbError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        // Both markers sit in the `WHERE`, so they filter rows BEFORE the
        // `GROUP BY` and the `LIMIT`: `max_k` and `bba_count` aggregate only
        // BBAs the viewer may read, and a claim the viewer cannot read neither
        // appears nor takes a slot in the limit. The `mf` marker is defense in
        // depth (a BBA inherits its claim's tenancy under migration 070); the
        // `c` marker is what keeps the projected `content` readable.
        let sql = viewer.splice(
            "SELECT mf.claim_id, mf.frame_id, MAX(mf.conflict_k) AS max_k, \
                    COUNT(*) AS bba_count, c.content \
             FROM mass_functions mf \
             JOIN claims c ON c.id = mf.claim_id \
             WHERE mf.conflict_k >= $1 AND mf.retracted_at IS NULL \
               /* {VISIBILITY:mf} */ /* {VISIBILITY:c} */ \
             GROUP BY mf.claim_id, mf.frame_id, c.content \
             ORDER BY max_k DESC \
             LIMIT $2",
            3,
        );
        let mut q = sqlx::query_as::<_, HighConflictClaim>(&sql)
            .bind(min_k)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
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
