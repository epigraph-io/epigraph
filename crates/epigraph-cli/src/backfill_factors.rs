//! The edge-factor phases of the `backfill_factors` binary, in the library so
//! the tests in `crates/epigraph-cli/tests/` run the exact SQL and loop the
//! binary runs.
//!
//! # The rewire phase (`--phase rewire-edges`)
//!
//! An edge-factor BBA is serialized once, when its edge is wired, and every
//! combine re-reads the stored JSON. So a change to the shape
//! `auto_wire_ds_for_edge` writes never reaches rows written before it: #401
//! (open-world mass transmitted at `ow * f` instead of `ow`) left every older
//! row carrying its source's undiscounted open-world mass, and
//! `recompute_beliefs` re-reads that mass faithfully. The edge phase cannot
//! heal them either: [`EDGE_QUERY`] selects only FACTORLESS targets, and a
//! target holding such a row is not one.
//!
//! The rewire phase selects the already-wired rows instead and re-derives each
//! one through `auto_wire_ds_for_edge`, the function every edge-creation path
//! uses, so it writes exactly what a fresh wire would write today. Because it
//! re-reads the source's CURRENT interval, it is a full refresh of each edge
//! factor, not only an open-world fix: a source whose belief moved since the
//! edge was wired moves its target too.
//!
//! # Targeted mode ([`rewire_edge_targeted`], R-176(2) / R-177(4) class E)
//!
//! A targeted rewire refreshes only the edges sourced at claims a wave MOVED
//! (`crate::edge_rewire` drives the passes, the snapshots and the predict).
//! Per edge it decides BEFORE anything is deleted ([`decide_targeted`]) and
//! leaves the edge exactly as it was, counted under a [`HeldBucket`], unless
//! every guard holds:
//!
//! * the edge has exactly one live `edge_factor` row, at the wire key, no
//!   retracted row, no compound end and is not `supersedes` (OD-E5: held
//!   buckets are left to their own decisions);
//! * a fresh wire would store a row: a vacuous restriction or a factorless
//!   source is KEPT, never deleted (OD-E1, the interim F2 baseline of zero,
//!   enforced here rather than by a dry-run count);
//! * the target is fresh, its cache equal to a fold of its current rows
//!   (OD-E2), so the refold lands only this edge's delta;
//! * the stored row is the one a wire from the source's PRE-move interval
//!   writes (row class `r173`); a row stale for any other reason is `mixed`
//!   and held (OD-E3);
//! * the refold would not vacate the target (ruling R-80).
//!
//! The un-targeted phase ([`run_rewire_phase`]) is unchanged.

/// Edge-phase eligibility: factorless target claim, claim-to-claim edge with
/// epistemic relationship. The edge factor is wired under the SOURCE claim's
/// author (`agent_id`, always populated): they assert the
/// support/contradiction via the edge.
///
/// Not `edges.signer_id` (ruling R-49): that is the agent whose key ATTESTED
/// the edge, and every edge an MCP server or the API writes is attested by
/// that server's own signer agent, whoever asserted it; on legacy rows it is,
/// where set, a bulk attestation key. Since migration 120 an edge's author
/// record is its writer group, and the agent behind what it asserts is its
/// source claim's author.
pub const EDGE_QUERY: &str = r#"
SELECT e.id, src.agent_id AS agent_id,
       e.source_id, e.target_id, e.relationship
FROM edges e
JOIN claims tgt ON tgt.id = e.target_id
JOIN claims src ON src.id = e.source_id
WHERE tgt.is_current AND src.is_current
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND LOWER(e.relationship) IN (
    'supports','corroborates','contradicts','refutes','refines','undercuts','rebuts',
    'elaborates','specializes','generalizes','supersedes','informs','frame_validates'
  )
  AND NOT EXISTS (SELECT 1 FROM mass_functions mf WHERE mf.claim_id = tgt.id)
ORDER BY e.target_id, e.created_at
LIMIT $1 OFFSET $2
"#;

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use epigraph_engine::edge_factor::{CombinedBeliefPreview, EdgeBba, EdgeBbaBuild};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::belief_cache::CacheColumns;

/// One already-wired edge factor the rewire phase rewrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewireEdge {
    pub edge_id: Uuid,
    /// The `source_agent_id` the stored row is keyed on.
    pub agent_id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    /// The frame the stored row lives on.
    pub frame_id: Uuid,
}

/// Paging and safety switches for [`run_rewire_phase`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RewireOptions {
    /// At most this many edges (0 = unlimited).
    pub limit: usize,
    pub offset: usize,
    /// Select and report; write nothing.
    pub dry_run: bool,
    /// Only rows last written before this instant.
    pub written_before: Option<chrono::DateTime<chrono::Utc>>,
}

/// What [`run_rewire_phase`] did, one counter per outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewireSummary {
    pub eligible: usize,
    pub rewired: usize,
    pub removed_vacuous: usize,
    pub removed_source_factorless: usize,
    pub skipped_non_epistemic: usize,
    /// By the time the edge's turn came, the edge was retracted, an endpoint
    /// was no longer current, or the selected row was gone; nothing written.
    pub skipped_stale: usize,
    /// Rows deleted beyond each edge's one rewritten or removed row: a second
    /// agent key or another frame for the same edge, merged into one row.
    pub duplicate_rows_deleted: usize,
    pub failed: usize,
}

/// Rewire-phase selection: every in-force claim-to-claim edge that already
/// holds an `edge_factor` BBA on its target, one row per edge.
///
/// - Keyed on the STORED row's `source_agent_id`, not on the source claim's
///   author as [`EDGE_QUERY`] is: the live
///   `link_epistemic` path and migration 114's writer-owned rows store other
///   agents, and the upsert key is `(claim, frame, source_agent, perspective)`,
///   so re-wiring under a different agent would add a second BBA for the edge
///   that double-counts in combine, and the stored row would be replaced
///   rather than rewritten in place (losing its owner; see
///   [`run_rewire_phase`]).
/// - Retracted edges (`valid_to` in the past) are skipped, with the predicate
///   `SheafRepository::get_epistemic_edge_pairs` uses: `auto_wire_ds_for_edge`
///   does not check `is_in_force`, so selecting one would resurrect it.
/// - `$3` (`--written-before`) restricts to rows last written before an
///   instant. The upsert stamps `created_at = NOW()`, so a REWRITTEN or
///   REMOVED row drops out of a fixed cutoff, and so does a `skipped_stale`
///   one (no longer in force). Two outcomes do NOT drop out and come back at
///   the head of every page: `skipped_non_epistemic` (the selection has no
///   relationship filter, on purpose, so it cannot drift from
///   `restriction_kind_with_profile`) and `failed` (rolled back).
///
/// # Paging
///
/// With a fixed `--written-before`, page with `--limit N` and an `--offset`
/// that starts at 0 and advances by each page's
/// [`RewireSummary::persisting`] (skipped_non_epistemic + failed), which the
/// binary prints as the next offset. The run is done when a page makes no
/// progress ([`RewireSummary::made_progress`] is false), NOT when `eligible`
/// reaches 0: repeating offset 0 alone stalls once N persisting rows lead the
/// order. Plain `--offset N, 2N, ...` paging skips rows, because rewritten
/// rows leave the selection.
///
/// The `e.signer_id` fallback is reached only when the stored row's
/// `source_agent_id` is NULL (the column is nullable). It is kept, unlike in
/// [`EDGE_QUERY`] (ruling R-49), because this selection must re-key the row it
/// REWRITES, not choose an author: a legacy row without a recorded agent was
/// wired under the old `COALESCE(e.signer_id, src.agent_id)`, and keying its
/// rewrite under another agent would add a second BBA for the edge.
pub const REWIRE_EDGE_QUERY: &str = r#"
SELECT DISTINCT ON (e.id)
       e.id,
       COALESCE(mf.source_agent_id, e.signer_id, src.agent_id) AS agent_id,
       e.source_id, e.target_id, e.relationship, mf.frame_id
FROM mass_functions mf
JOIN edges e ON e.id = mf.perspective_id
JOIN claims tgt ON tgt.id = e.target_id
JOIN claims src ON src.id = e.source_id
WHERE mf.combination_method = 'edge_factor'
  AND mf.retracted_at IS NULL
  AND mf.claim_id = e.target_id
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND tgt.is_current AND src.is_current
  AND (e.valid_to IS NULL OR e.valid_to > now())
  AND ($3::timestamptz IS NULL OR mf.created_at < $3)
ORDER BY e.id, mf.created_at, mf.id
LIMIT $1 OFFSET $2
"#;

/// Run [`REWIRE_EDGE_QUERY`] with `opts`' paging and `--written-before`.
///
/// # Errors
/// The query's error.
pub async fn select_rewire_edges(
    pool: &PgPool,
    opts: &RewireOptions,
) -> Result<Vec<RewireEdge>, sqlx::Error> {
    let lim: i64 = if opts.limit == 0 {
        i64::MAX
    } else {
        i64::try_from(opts.limit).unwrap_or(i64::MAX)
    };
    let off: i64 = i64::try_from(opts.offset).unwrap_or(i64::MAX);
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, String, Uuid)> = sqlx::query_as(REWIRE_EDGE_QUERY)
        .bind(lim)
        .bind(off)
        .bind(opts.written_before)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(edge_id, agent_id, source_id, target_id, relationship, frame_id)| RewireEdge {
                edge_id,
                agent_id,
                source_id,
                target_id,
                relationship,
                frame_id,
            },
        )
        .collect())
}

/// What happened to one edge inside its transaction.
enum EdgeRewrite {
    Rewired,
    RemovedVacuous,
    RemovedSourceFactorless,
    SkippedNonEpistemic,
    /// No longer in force, or the selected row is gone, at the edge's turn.
    SkippedStale,
    /// Targeted mode: a guard held the edge; nothing was written.
    Held(HeldBucket),
    /// Targeted mode with `only_changed`: a fresh wire equals the stored row.
    Unchanged,
    /// Targeted mode: rewritten in place, with what it found and wrote.
    TargetedRewired(Box<RewireCapture>),
}

/// One edge's outcome plus the rows it deleted beyond the one it rewrote.
struct EdgeResult {
    outcome: EdgeRewrite,
    duplicate_rows_deleted: usize,
}

impl EdgeResult {
    fn only(outcome: EdgeRewrite) -> Self {
        Self {
            outcome,
            duplicate_rows_deleted: 0,
        }
    }
}

/// Re-derive every selected edge factor from its source's current interval.
///
/// Per edge, on one connection and one transaction:
/// 1. a relationship that no longer maps to an epistemic restriction is left
///    untouched (it cannot be re-derived, and deleting it is not this phase's
///    call);
/// 2. the edge's other `edge_factor` rows on the target (a second agent key,
///    or a frame other than `binary_truth`) are deleted and counted in
///    `duplicate_rows_deleted`, so the edge ends with ONE row;
/// 3. `auto_wire_ds_for_edge` re-wires the edge under the stored agent. Its
///    upsert is keyed on `(target, binary_truth, agent, edge)`, so the stored
///    row is rewritten IN PLACE: `ON CONFLICT DO UPDATE` leaves
///    `owner_group_id`, `visibility` and `writer_owned` alone. A
///    delete-then-insert would not: on this privileged pool migration 114's
///    insert trigger stamps the CLAIM's tenancy, which would hand a writer's
///    BBA (`writer_owned`) to the claim's owner for good. When the stored row
///    was not at that key (another frame, or a NULL agent) the wire inserts a
///    fresh row, and the selected row's tenancy is copied onto it;
/// 4. if the source is now factorless or the restriction vacuous, a fresh
///    wire would store nothing, so nothing is stored: the edge's row is
///    deleted, the target is recomputed from the BBAs that remain, and its
///    cached belief is cleared when none remain (a stale cache must not
///    outlive its last supporter).
///
/// Any error rolls that edge back (its old rows survive) and counts as failed.
/// `pool` must be privileged (the binary's maintenance pool): the deletes are
/// plain owner-scoped DELETEs.
///
/// # Errors
/// Only the selection's error; per-edge failures are counted.
pub async fn run_rewire_phase(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    opts: &RewireOptions,
) -> Result<RewireSummary, sqlx::Error> {
    let edges = select_rewire_edges(pool, opts).await?;
    let mut summary = RewireSummary {
        eligible: edges.len(),
        ..RewireSummary::default()
    };
    if opts.dry_run {
        println!(
            "DRY RUN: would rewire {} edge factors (showing first 5):",
            summary.eligible
        );
        for e in edges.iter().take(5) {
            println!(
                "  edge={} agent={} {} —[{}]→ {}",
                e.edge_id, e.agent_id, e.source_id, e.relationship, e.target_id
            );
        }
        return Ok(summary);
    }
    rewire_edges(pool, viewer, &edges, &mut summary).await;
    Ok(summary)
}

/// The write half of [`run_rewire_phase`]: rewire each of `edges` (a
/// selection, possibly minutes or hours old by the time an edge's turn comes)
/// and add the outcomes to `summary`.
pub async fn rewire_edges(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    edges: &[RewireEdge],
    summary: &mut RewireSummary,
) {
    for edge in edges {
        match rewire_one(pool, viewer, edge, None).await {
            Ok(r) => {
                summary.duplicate_rows_deleted += r.duplicate_rows_deleted;
                match r.outcome {
                    EdgeRewrite::Rewired => summary.rewired += 1,
                    EdgeRewrite::RemovedVacuous => summary.removed_vacuous += 1,
                    EdgeRewrite::RemovedSourceFactorless => {
                        summary.removed_source_factorless += 1;
                    }
                    EdgeRewrite::SkippedNonEpistemic => summary.skipped_non_epistemic += 1,
                    EdgeRewrite::SkippedStale => summary.skipped_stale += 1,
                    // Targeted outcomes only: `rewire_one` returns them only
                    // when it is handed guards, which this loop never does.
                    EdgeRewrite::Held(_)
                    | EdgeRewrite::Unchanged
                    | EdgeRewrite::TargetedRewired(_) => summary.failed += 1,
                }
            }
            Err(e) => {
                tracing::warn!(edge = %edge.edge_id, target = %edge.target_id, "edge rewire failed: {e}");
                summary.failed += 1;
            }
        }
    }
}

/// Delete `edge`'s `edge_factor` rows on its target, except the one at
/// `keep` = `(frame, source_agent_id)` when given; return each deleted row's
/// `(id, frame)`. A retracted row (migration 184) is kept for audit: the
/// rewire neither selects nor deletes it.
async fn delete_edge_rows(
    conn: &mut sqlx::PgConnection,
    edge: &RewireEdge,
    keep: Option<(Uuid, Uuid)>,
) -> Result<Vec<(Uuid, Uuid)>, String> {
    let (keep_frame, keep_agent) = keep.unzip();
    sqlx::query_as(
        "DELETE FROM mass_functions \
          WHERE perspective_id = $1 AND claim_id = $2 \
            AND combination_method = 'edge_factor' AND retracted_at IS NULL \
            AND NOT ($3::uuid IS NOT NULL AND frame_id = $3 \
                     AND source_agent_id IS NOT DISTINCT FROM $4) \
         RETURNING id, frame_id",
    )
    .bind(edge.edge_id)
    .bind(edge.target_id)
    .bind(keep_frame)
    .bind(keep_agent)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("delete edge rows: {e}"))
}

/// Recompute `target` on every frame in `frames` (deduplicated, `last`
/// recomputed last because the claim's cached scalars are last-writer-wins);
/// clear its cache when it holds no BBA at all any more.
async fn recompute_after_removal(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    target: Uuid,
    frames: &[Uuid],
    last: Uuid,
) -> Result<(), String> {
    use epigraph_db::MassFunctionRepository;
    use epigraph_engine::edge_factor::recompute_claim_belief_on_frame;

    let mut ordered: Vec<Uuid> = Vec::new();
    for f in frames.iter().copied().filter(|f| *f != last) {
        if !ordered.contains(&f) {
            ordered.push(f);
        }
    }
    if frames.contains(&last) {
        ordered.push(last);
    }
    for frame in ordered {
        recompute_claim_belief_on_frame(&mut *conn, viewer, target, frame).await?;
    }
    let remaining = MassFunctionRepository::get_for_claim(&mut *conn, viewer, target)
        .await
        .map_err(|e| format!("surviving BBAs: {e}"))?;
    if remaining.is_empty() {
        MassFunctionRepository::clear_claim_belief(&mut *conn, target)
            .await
            .map_err(|e| format!("clear unbacked belief: {e}"))?;
    }
    Ok(())
}

/// Targeted mode's inputs to [`rewire_one`]: the guards, and the callback
/// that records a rewrite before its transaction commits.
type Targeted<'a, 'g> = (
    &'a TargetedGuards<'g>,
    &'a mut (dyn FnMut(&RewireCapture) -> Result<(), String> + Send),
);

async fn rewire_one(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    edge: &RewireEdge,
    mut targeted: Option<Targeted<'_, '_>>,
) -> Result<EdgeResult, String> {
    use epigraph_engine::edge_factor::{
        auto_wire_ds_for_edge, ensure_binary_frame, EdgeFactorOutcome,
    };
    use epigraph_engine::sheaf::{
        restriction_kind_with_profile, RestrictionKind, RestrictionProfile,
    };

    if matches!(
        restriction_kind_with_profile(&edge.relationship, &RestrictionProfile::scientific()),
        RestrictionKind::Neutral
    ) {
        if targeted.is_some() {
            return Ok(EdgeResult::only(EdgeRewrite::Held(
                HeldBucket::NonEpistemic,
            )));
        }
        return Ok(EdgeResult::only(EdgeRewrite::SkippedNonEpistemic));
    }

    let mut tx = pool.begin().await.map_err(|e| format!("begin: {e}"))?;

    // The selection is a snapshot that can be hours old by now. Re-check the
    // in-force predicate of REWIRE_EDGE_QUERY here, or an edge retracted
    // since (whose BBA the retraction cascade deleted) would be re-wired:
    // auto_wire_ds_for_edge does not check it. FOR SHARE OF e holds a
    // concurrent retraction's UPDATE of valid_to until this edge commits, so
    // its cascade then deletes what we wrote. The claims are NOT locked: the
    // wire UPDATEs the target's cache in this transaction, and a SHARE lock
    // upgraded to a write deadlocks against a concurrent writer of the same
    // claim (migration 114's W6 note); a supersede racing this one statement
    // window is left to the supersede path.
    let in_force: Option<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM edges e \
           JOIN claims tgt ON tgt.id = e.target_id \
           JOIN claims src ON src.id = e.source_id \
          WHERE e.id = $1 \
            AND (e.valid_to IS NULL OR e.valid_to > now()) \
            AND tgt.is_current AND src.is_current \
          FOR SHARE OF e",
    )
    .bind(edge.edge_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("re-check edge in force: {e}"))?;
    if in_force.is_none() {
        return Ok(EdgeResult::only(EdgeRewrite::SkippedStale));
    }

    // The row the selection chose (same order as REWIRE_EDGE_QUERY's
    // DISTINCT ON), locked, with the tenancy a rewrite must keep.
    let selected: Option<(Uuid, Uuid, String, bool)> = sqlx::query_as(
        "SELECT id, owner_group_id, visibility::text, writer_owned FROM mass_functions \
          WHERE perspective_id = $1 AND claim_id = $2 AND combination_method = 'edge_factor' \
            AND retracted_at IS NULL \
          ORDER BY created_at, id LIMIT 1 FOR UPDATE",
    )
    .bind(edge.edge_id)
    .bind(edge.target_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("lock selected row: {e}"))?;
    let Some((selected_id, owner_group_id, visibility, writer_owned)) = selected else {
        return Ok(EdgeResult::only(EdgeRewrite::SkippedStale));
    };

    let binary = ensure_binary_frame(&mut tx, viewer).await?;
    // Targeted mode decides BEFORE anything is deleted: a held edge rolls
    // back here, with every row it had (OD-E1: the interim F2 baseline of
    // zero is enforced in code, not by a dry-run count).
    let mut proceed: Option<(CacheColumns, StoredEdgeRow, Option<CombinedBeliefPreview>)> = None;
    if let Some((guards, _)) = targeted.as_ref() {
        let d = decide_targeted(&mut tx, viewer, edge, binary, selected_id, guards, None).await?;
        match d.verdict {
            TargetedVerdict::Hold(bucket) => {
                tx.rollback().await.map_err(|e| format!("rollback: {e}"))?;
                return Ok(EdgeResult::only(EdgeRewrite::Held(bucket)));
            }
            TargetedVerdict::Unchanged => {
                tx.rollback().await.map_err(|e| format!("rollback: {e}"))?;
                return Ok(EdgeResult::only(EdgeRewrite::Unchanged));
            }
            TargetedVerdict::Proceed => {
                let (Some(s), Some(stored)) = (d.s, d.stored) else {
                    return Err("targeted decision proceeded without its pre-image".into());
                };
                proceed = Some((s, stored, d.w));
            }
        }
    }
    let keep = (binary, edge.agent_id);
    let others = delete_edge_rows(&mut tx, edge, Some(keep)).await?;
    if targeted.is_some() && !others.is_empty() {
        // The decision saw one live row at the key; a second appeared since.
        // Roll back: the deletes above are undone, so both rows survive.
        tx.rollback().await.map_err(|e| format!("rollback: {e}"))?;
        return Ok(EdgeResult::only(EdgeRewrite::Held(
            HeldBucket::OffKeyOrDuplicate,
        )));
    }
    // The selected row itself is replaced, not a duplicate, when it was not
    // at the key the wire writes.
    let duplicate_rows_deleted = others.iter().filter(|(id, _)| *id != selected_id).count();
    let other_frames: Vec<Uuid> = others.iter().map(|(_, f)| *f).collect();
    let outcome = auto_wire_ds_for_edge(
        &mut tx,
        viewer,
        edge.edge_id,
        edge.agent_id,
        edge.source_id,
        edge.target_id,
        &edge.relationship,
    )
    .await?;
    if targeted.is_some() && outcome != EdgeFactorOutcome::Wired {
        // The source turned vacuous or factorless between the decision and
        // the wire. Never reach the removal arm below: keep the row.
        tx.rollback().await.map_err(|e| format!("rollback: {e}"))?;
        return Ok(EdgeResult::only(EdgeRewrite::Held(
            if outcome == EdgeFactorOutcome::NonEpistemic {
                HeldBucket::NonEpistemic
            } else {
                HeldBucket::WouldRemove
            },
        )));
    }
    let result = match outcome {
        EdgeFactorOutcome::Wired => {
            // In place: a no-op. Freshly inserted: restores the selected
            // row's owner, which 114 re-stamped from the claim.
            sqlx::query(
                "UPDATE mass_functions \
                    SET owner_group_id = $5, visibility = $6, writer_owned = $7 \
                  WHERE perspective_id = $1 AND claim_id = $2 AND frame_id = $3 \
                    AND source_agent_id = $4 \
                    AND (owner_group_id, visibility::text, writer_owned) \
                        IS DISTINCT FROM ($5, $6, $7)",
            )
            .bind(edge.edge_id)
            .bind(edge.target_id)
            .bind(binary)
            .bind(edge.agent_id)
            .bind(owner_group_id)
            .bind(&visibility)
            .bind(writer_owned)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("keep the selected row's owner: {e}"))?;
            // A frame other than binary_truth that lost a row is recomputed,
            // then binary_truth again so it stays the cache's last writer
            // (the wire recomputed it before those).
            if other_frames.iter().any(|f| *f != binary) {
                let mut frames = other_frames.clone();
                frames.push(binary);
                recompute_after_removal(&mut tx, viewer, edge.target_id, &frames, binary).await?;
            }
            if let (Some((target_before, row_before, predicted)), Some((_, on_capture))) =
                (proceed.take(), targeted.as_mut())
            {
                let capture = capture_rewrite(
                    &mut tx,
                    edge,
                    binary,
                    selected_id,
                    target_before,
                    row_before,
                )
                .await?;
                if !predicted
                    .as_ref()
                    .is_some_and(|w| cache_matches_fold(&capture.target_after, w, binary, 1e-9))
                {
                    // The cache the wire wrote is not the fold the decision
                    // predicted over the same rows (the cache writer's owner
                    // guard declined, or a concurrent write): keep the edge.
                    tracing::warn!(edge = %edge.edge_id, target = %edge.target_id,
                        "targeted rewire: written cache differs from the predicted fold; rolled back");
                    tx.rollback().await.map_err(|e| format!("rollback: {e}"))?;
                    return Ok(EdgeResult::only(EdgeRewrite::Held(HeldBucket::TargetStale)));
                }
                // Recorded BEFORE the commit, so no committed rewrite lacks
                // its snapshot record.
                on_capture(&capture)?;
                tx.commit().await.map_err(|e| format!("commit: {e}"))?;
                return Ok(EdgeResult::only(EdgeRewrite::TargetedRewired(Box::new(
                    capture,
                ))));
            }
            EdgeRewrite::Rewired
        }
        EdgeFactorOutcome::Vacuous | EdgeFactorOutcome::SourceFactorless => {
            let mut frames = other_frames.clone();
            frames.extend(
                delete_edge_rows(&mut tx, edge, None)
                    .await?
                    .into_iter()
                    .map(|(_, f)| f),
            );
            frames.push(binary);
            recompute_after_removal(&mut tx, viewer, edge.target_id, &frames, binary).await?;
            if outcome == EdgeFactorOutcome::Vacuous {
                EdgeRewrite::RemovedVacuous
            } else {
                EdgeRewrite::RemovedSourceFactorless
            }
        }
        // Ruled out by the restriction check above; keep the old row.
        EdgeFactorOutcome::NonEpistemic => {
            return Ok(EdgeResult::only(EdgeRewrite::SkippedNonEpistemic));
        }
    };
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(EdgeResult {
        outcome: result,
        duplicate_rows_deleted,
    })
}

// ── Targeted mode (R-176(2) / R-177(4) class E) ─────────────────────────────

/// How close a target's stored cache must be to a fold of its current rows
/// (belief, plausibility and BetP) to count as FRESH (OD-E2).
pub const FRESH_EPSILON: f64 = 1e-6;

/// How close a stored row's masses must be to a wire from the source's
/// pre-move interval to be of row class `r173` (OD-E3).
pub const ROW_CLASS_EPSILON: f64 = 1e-9;

/// How close a fresh wire must be to the stored row, per mass, for
/// `only_changed` to leave the row alone.
pub const UNCHANGED_EPSILON: f64 = 1e-12;

/// Why a targeted rewire left an edge exactly as it was (design §1.4). Each is
/// a separate operator decision; none is ever deleted or rewritten here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldBucket {
    /// `supersedes` lineage: X-3 decides those rows (K12b).
    Supersedes,
    /// A compound source or target (atom SPEC §6, freeze F2; O3).
    CompoundEnd,
    /// Not exactly one live `edge_factor` row at the wire key
    /// `(target, binary_truth, agent, edge)`.
    OffKeyOrDuplicate,
    /// A retracted row on the edge (any key; migration 184 audit rows).
    RetractedOnEdge,
    /// The relationship no longer maps to an epistemic restriction.
    NonEpistemic,
    /// A fresh wire would store nothing (vacuous restriction or factorless
    /// source): the un-targeted phase would DELETE the row. Kept (OD-E1).
    WouldRemove,
    /// The target's cache is not a fold of its current rows (OD-E2).
    TargetStale,
    /// The stored row is stale for reasons other than the source's move
    /// (row class `mixed`, OD-E3).
    RowMixed,
    /// The refold would vacate the target (ruling R-80).
    WouldVacate,
}

impl HeldBucket {
    /// Every bucket, in report order.
    pub const ALL: [HeldBucket; 9] = [
        HeldBucket::Supersedes,
        HeldBucket::CompoundEnd,
        HeldBucket::OffKeyOrDuplicate,
        HeldBucket::RetractedOnEdge,
        HeldBucket::NonEpistemic,
        HeldBucket::WouldRemove,
        HeldBucket::TargetStale,
        HeldBucket::RowMixed,
        HeldBucket::WouldVacate,
    ];

    /// The bucket's report name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            HeldBucket::Supersedes => "supersedes",
            HeldBucket::CompoundEnd => "compound_end",
            HeldBucket::OffKeyOrDuplicate => "off_key_or_duplicate",
            HeldBucket::RetractedOnEdge => "retracted_on_edge",
            HeldBucket::NonEpistemic => "non_epistemic",
            HeldBucket::WouldRemove => "held_would_remove",
            HeldBucket::TargetStale => "target_stale",
            HeldBucket::RowMixed => "row_mixed",
            HeldBucket::WouldVacate => "would_vacate",
        }
    }
}

/// The stored columns of one edge-factor row, exactly: `masses` is the
/// database's own `jsonb` text (never round-tripped through `f64`), so a
/// restore can compare and write it back bit for bit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEdgeRow {
    pub mf_id: Uuid,
    pub masses: String,
    #[serde(with = "crate::belief_cache::exact_f64")]
    pub source_strength: Option<f64>,
    pub evidence_type: Option<String>,
    pub locality_tag: String,
    pub created_at: DateTime<Utc>,
}

/// What one targeted rewrite found and wrote, read inside its transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct RewireCapture {
    pub edge_id: Uuid,
    pub target_id: Uuid,
    pub frame_id: Uuid,
    pub agent_id: Uuid,
    pub target_before: CacheColumns,
    pub target_after: CacheColumns,
    pub row_before: StoredEdgeRow,
    pub row_after: StoredEdgeRow,
}

/// The guards a targeted rewire applies (see the module doc).
#[derive(Debug, Clone, Copy)]
pub struct TargetedGuards<'a> {
    /// Per claim, the `(belief, plausibility)` it held before it moved: the
    /// interval its stored edge rows were wired from (row class `r173`).
    pub baseline: &'a HashMap<Uuid, (f64, f64)>,
    /// Edges this run already rewrote, with the row it wrote: the reference
    /// a later pass compares the stored row with, in place of the baseline.
    pub own_rows: &'a HashMap<Uuid, StoredEdgeRow>,
    /// Leave a row alone when a fresh wire equals it.
    pub only_changed: bool,
}

/// The decision [`decide_targeted`] reaches for one edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetedVerdict {
    Hold(HeldBucket),
    Unchanged,
    Proceed,
}

/// [`decide_targeted`]'s verdict and the values it was reached from: the
/// stored row, `p0` (a wire from the source's baseline interval), `p1` (a
/// wire from its current interval), the target's stored cache `s`, the fold
/// of its current rows `r` and the fold with `p1` in place `w`.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetedDecision {
    pub verdict: TargetedVerdict,
    pub stored: Option<StoredEdgeRow>,
    pub p0: Option<EdgeBba>,
    pub p1: Option<EdgeBba>,
    pub s: Option<CacheColumns>,
    pub r: Option<CombinedBeliefPreview>,
    pub w: Option<CombinedBeliefPreview>,
}

impl TargetedDecision {
    fn hold(bucket: HeldBucket) -> Self {
        Self {
            verdict: TargetedVerdict::Hold(bucket),
            stored: None,
            p0: None,
            p1: None,
            s: None,
            r: None,
            w: None,
        }
    }
}

/// The predict's in-memory state: rows (by `mass_functions.id`) and caches an
/// earlier step predicted, read in place of the database's.
#[derive(Debug, Clone, Default)]
pub struct RewireOverlay {
    pub cache: HashMap<Uuid, CacheColumns>,
    pub rows: HashMap<Uuid, EdgeBba>,
}

/// What one targeted rewire did to one edge.
#[derive(Debug, Clone, PartialEq)]
pub enum TargetedOutcome {
    Rewired(Box<RewireCapture>),
    Unchanged,
    Held(HeldBucket),
    /// No longer in force, an endpoint no longer current, or the selected row
    /// gone, at the edge's turn.
    SkippedStale,
}

/// Targeted selection: the in-force claim-to-claim edges sourced at
/// `$1` (the claims a wave moved) that hold a live `edge_factor` row on their
/// target, one row per edge, optionally restricted to the edge ids `$2` (an
/// accepted list). Same predicates, key and order as [`REWIRE_EDGE_QUERY`];
/// what it may not touch is decided per edge by [`decide_targeted`], so every
/// held edge is counted rather than silently dropped.
pub const TARGETED_REWIRE_EDGE_QUERY: &str = r#"
SELECT DISTINCT ON (e.id)
       e.id,
       COALESCE(mf.source_agent_id, e.signer_id, src.agent_id) AS agent_id,
       e.source_id, e.target_id, e.relationship, mf.frame_id
FROM mass_functions mf
JOIN edges e ON e.id = mf.perspective_id
JOIN claims tgt ON tgt.id = e.target_id
JOIN claims src ON src.id = e.source_id
WHERE mf.combination_method = 'edge_factor'
  AND mf.retracted_at IS NULL
  AND mf.claim_id = e.target_id
  AND e.source_type = 'claim' AND e.target_type = 'claim'
  AND tgt.is_current AND src.is_current
  AND (e.valid_to IS NULL OR e.valid_to > now())
  AND e.source_id = ANY($1)
  AND ($2::uuid[] IS NULL OR e.id = ANY($2))
ORDER BY e.id, mf.created_at, mf.id
"#;

/// Run [`TARGETED_REWIRE_EDGE_QUERY`].
///
/// # Errors
/// The query's error.
pub async fn select_targeted_edges(
    conn: &mut sqlx::PgConnection,
    sources: &[Uuid],
    edges: Option<&[Uuid]>,
) -> Result<Vec<RewireEdge>, sqlx::Error> {
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, String, Uuid)> =
        sqlx::query_as(TARGETED_REWIRE_EDGE_QUERY)
            .bind(sources)
            .bind(edges)
            .fetch_all(&mut *conn)
            .await?;
    Ok(rows
        .into_iter()
        .map(
            |(edge_id, agent_id, source_id, target_id, relationship, frame_id)| RewireEdge {
                edge_id,
                agent_id,
                source_id,
                target_id,
                relationship,
                frame_id,
            },
        )
        .collect())
}

/// The structural facts the first four held buckets are decided on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeShape {
    pub supersedes: bool,
    pub compound_end: bool,
    /// Live `edge_factor` rows of the edge on its target, any key.
    pub live_rows: i64,
    /// Of those, the rows at the wire key `(binary_truth, agent)`.
    pub live_at_key: i64,
    pub retracted_on_edge: bool,
}

impl EdgeShape {
    /// The first bucket that holds the edge, if any.
    #[must_use]
    pub fn held(&self) -> Option<HeldBucket> {
        if self.supersedes {
            Some(HeldBucket::Supersedes)
        } else if self.compound_end {
            Some(HeldBucket::CompoundEnd)
        } else if self.live_rows != 1 || self.live_at_key != 1 {
            Some(HeldBucket::OffKeyOrDuplicate)
        } else if self.retracted_on_edge {
            Some(HeldBucket::RetractedOnEdge)
        } else {
            None
        }
    }
}

/// Read `edge`'s [`EdgeShape`]. The compound test is migration 193's definer
/// `public.epigraph_claim_is_compound`, decided on the whole graph whatever
/// the session can see.
///
/// # Errors
/// The read fails.
pub async fn edge_shape(
    conn: &mut sqlx::PgConnection,
    edge: &RewireEdge,
    binary: Uuid,
) -> Result<EdgeShape, String> {
    let (supersedes, compound_end, live_rows, live_at_key, retracted_on_edge): (
        bool,
        bool,
        i64,
        i64,
        bool,
    ) = sqlx::query_as(
        "SELECT lower(e.relationship) = 'supersedes', \
                public.epigraph_claim_is_compound(e.source_id) \
                  OR public.epigraph_claim_is_compound(e.target_id), \
                (SELECT count(*) FROM mass_functions m \
                  WHERE m.perspective_id = e.id AND m.claim_id = e.target_id \
                    AND m.combination_method = 'edge_factor' AND m.retracted_at IS NULL), \
                (SELECT count(*) FROM mass_functions m \
                  WHERE m.perspective_id = e.id AND m.claim_id = e.target_id \
                    AND m.combination_method = 'edge_factor' AND m.retracted_at IS NULL \
                    AND m.frame_id = $2 AND m.source_agent_id = $3), \
                EXISTS (SELECT 1 FROM mass_functions m \
                         WHERE m.perspective_id = e.id AND m.claim_id = e.target_id \
                           AND m.retracted_at IS NOT NULL) \
           FROM edges e WHERE e.id = $1",
    )
    .bind(edge.edge_id)
    .bind(binary)
    .bind(edge.agent_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("edge shape: {e}"))?;
    Ok(EdgeShape {
        supersedes,
        compound_end,
        live_rows,
        live_at_key,
        retracted_on_edge,
    })
}

/// Read one `mass_functions` row's stored edge-factor columns, exactly.
///
/// # Errors
/// The read fails or the row is gone.
pub async fn read_edge_row(
    conn: &mut sqlx::PgConnection,
    mf_id: Uuid,
) -> Result<StoredEdgeRow, String> {
    let (masses, source_strength, evidence_type, locality_tag, created_at): (
        String,
        Option<f64>,
        Option<String>,
        String,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT masses::text, source_strength, evidence_type, locality_tag, created_at \
           FROM mass_functions WHERE id = $1",
    )
    .bind(mf_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| format!("read edge row {mf_id}: {e}"))?;
    Ok(StoredEdgeRow {
        mf_id,
        masses,
        source_strength,
        evidence_type,
        locality_tag,
        created_at,
    })
}

/// The live `edge_factor` row a rewire of `edge` selects: the same row, in
/// the same order, as [`REWIRE_EDGE_QUERY`]'s `DISTINCT ON`. Not locked (the
/// predict reads it in a READ ONLY transaction).
///
/// # Errors
/// The read fails.
pub async fn selected_edge_row(
    conn: &mut sqlx::PgConnection,
    edge: &RewireEdge,
) -> Result<Option<Uuid>, String> {
    sqlx::query_scalar(
        "SELECT id FROM mass_functions \
          WHERE perspective_id = $1 AND claim_id = $2 AND combination_method = 'edge_factor' \
            AND retracted_at IS NULL \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(edge.edge_id)
    .bind(edge.target_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("selected row: {e}"))
}

/// A row's comparable shape: masses by focal key, and the three typing
/// columns.
#[derive(Debug, Clone, PartialEq)]
struct RowShape {
    masses: BTreeMap<String, f64>,
    source_strength: Option<f64>,
    evidence_type: Option<String>,
    locality_tag: String,
}

fn mass_map(v: &serde_json::Value) -> BTreeMap<String, f64> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, m)| (k.clone(), m.as_f64().unwrap_or(f64::NAN)))
                .collect()
        })
        .unwrap_or_default()
}

impl RowShape {
    fn of_stored(row: &StoredEdgeRow) -> Self {
        let masses = serde_json::from_str::<serde_json::Value>(&row.masses)
            .map(|v| mass_map(&v))
            .unwrap_or_default();
        Self {
            masses,
            source_strength: row.source_strength,
            evidence_type: row.evidence_type.clone(),
            locality_tag: row.locality_tag.clone(),
        }
    }

    fn of_built(b: &EdgeBba) -> Self {
        Self {
            masses: mass_map(&b.masses_json),
            source_strength: Some(b.source_strength),
            evidence_type: Some(b.evidence_type.clone()),
            locality_tag: b.locality_tag.to_string(),
        }
    }

    /// Masses within `eps` per focal key (an absent key is mass 0), the same
    /// `source_strength` within `eps` and the same `locality_tag`; and, when
    /// `with_type`, the same `evidence_type` spelling.
    fn matches(&self, other: &RowShape, eps: f64, with_type: bool) -> bool {
        let keys: std::collections::BTreeSet<&String> =
            self.masses.keys().chain(other.masses.keys()).collect();
        let masses_close = keys.into_iter().all(|k| {
            let a = self.masses.get(k).copied().unwrap_or(0.0);
            let b = other.masses.get(k).copied().unwrap_or(0.0);
            (a - b).abs() <= eps
        });
        let ss_close = match (self.source_strength, other.source_strength) {
            (Some(a), Some(b)) => (a - b).abs() <= eps,
            (None, None) => true,
            _ => false,
        };
        masses_close
            && ss_close
            && self.locality_tag == other.locality_tag
            && (!with_type || self.evidence_type == other.evidence_type)
    }
}

/// Whether the stored cache `s` is the fold `r` on the binary frame: its
/// frame is `binary_truth` (or unrecorded) and belief, plausibility and BetP
/// are each within `eps`.
#[must_use]
pub fn cache_matches_fold(
    s: &CacheColumns,
    r: &CombinedBeliefPreview,
    binary: Uuid,
    eps: f64,
) -> bool {
    let close = |a: Option<f64>, b: f64| a.is_some_and(|a| (a - b).abs() < eps);
    s.belief_frame_id.is_none_or(|f| f == binary)
        && close(s.belief, r.belief)
        && close(s.plausibility, r.plausibility)
        && close(s.pignistic_prob, r.pignistic_prob)
}

/// The cache a fold writes (what `recompute_combined_belief` stores).
#[must_use]
pub fn cache_of_fold(
    w: &CombinedBeliefPreview,
    binary: Uuid,
    prior: Option<&CacheColumns>,
) -> CacheColumns {
    CacheColumns {
        belief: Some(w.belief),
        plausibility: Some(w.plausibility),
        pignistic_prob: Some(w.pignistic_prob),
        mass_on_empty: Some(w.conflict_k),
        mass_on_missing: Some(w.missing_mass),
        belief_frame_id: Some(binary),
        classification: w
            .classification
            .clone()
            .or_else(|| prior.and_then(|p| p.classification.clone())),
    }
}

/// `rows` with every row named in `replace` carrying the replacement's
/// stored columns (the rest of the row untouched).
fn overlay_rows(
    mut rows: Vec<epigraph_db::MassFunctionRow>,
    replace: &HashMap<Uuid, EdgeBba>,
) -> Vec<epigraph_db::MassFunctionRow> {
    for row in &mut rows {
        if let Some(b) = replace.get(&row.id) {
            row.masses = b.masses_json.clone();
            row.source_strength = Some(b.source_strength);
            row.evidence_type = Some(b.evidence_type.clone());
            row.locality_tag = b.locality_tag.to_string();
        }
    }
    rows
}

/// The source's `(belief, plausibility, open_world_mass)`, as
/// `auto_wire_ds_for_edge` reads it, with the overlay's cache (if any) in
/// place of the stored belief and plausibility. `None` when the source is
/// factorless.
async fn source_interval(
    conn: &mut sqlx::PgConnection,
    source: Uuid,
    overlay: Option<&RewireOverlay>,
) -> Result<Option<(f64, f64, Option<f64>)>, String> {
    let cache = match overlay.and_then(|o| o.cache.get(&source)) {
        Some(c) => c.clone(),
        None => crate::belief_cache::read_cache_columns(&mut *conn, &[source])
            .await
            .map_err(|e| format!("source cache: {e}"))?
            .remove(&source)
            .ok_or_else(|| format!("source {source} not found"))?,
    };
    let ow: Option<f64> = sqlx::query_scalar("SELECT open_world_mass FROM claims WHERE id = $1")
        .bind(source)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("source open_world_mass: {e}"))?;
    Ok(match (cache.belief, cache.plausibility) {
        (Some(b), Some(p)) => Some((b, p, ow)),
        _ => None,
    })
}

/// Decide one targeted edge, writing nothing (it runs inside the rewire's
/// transaction after the row lock, and inside the predict's READ ONLY one).
/// The checks, in order, each a [`HeldBucket`] when it fails:
///
/// 1. [`EdgeShape::held`]: `supersedes`, a compound end, not exactly one live
///    row at the wire key, a retracted row on the edge;
/// 2. the relationship is epistemic, and a fresh wire from the source's
///    current interval ([`epigraph_engine::edge_factor::build_edge_bba`],
///    the pure core of the wire) stores a row (`held_would_remove`);
/// 3. with `only_changed`, a wire equal to the current row is
///    [`TargetedVerdict::Unchanged`];
/// 4. the target is fresh: its cache is the fold of its current rows
///    (`target_stale`);
/// 5. the stored row is of class `r173`: the row this run wrote, or a wire
///    from the source's baseline interval (`row_mixed`);
/// 6. the fold with the new row is not a vacate (`would_vacate`).
///
/// `overlay` (the predict only) supplies earlier steps' predicted caches and
/// rows in place of the stored ones.
///
/// # Errors
/// A read fails.
#[allow(clippy::too_many_lines)]
pub async fn decide_targeted(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    edge: &RewireEdge,
    binary: Uuid,
    selected_id: Uuid,
    guards: &TargetedGuards<'_>,
    overlay: Option<&RewireOverlay>,
) -> Result<TargetedDecision, String> {
    use epigraph_engine::belief_profile::BeliefProfile;
    use epigraph_engine::edge_factor::{
        build_edge_bba, edge_intra_locality_factor, edge_source_is_intra,
        preview_claim_belief_on_frame_adjusted,
    };

    let shape = edge_shape(&mut *conn, edge, binary).await?;
    if let Some(bucket) = shape.held() {
        return Ok(TargetedDecision::hold(bucket));
    }
    let profile = BeliefProfile::served();
    let is_intra = edge_source_is_intra(&mut *conn, edge.source_id, edge.target_id).await?;
    let intra = edge_intra_locality_factor(&mut *conn, binary, profile).await?;
    let build = |interval: (f64, f64, Option<f64>)| {
        build_edge_bba(interval, &edge.relationship, is_intra, intra, profile)
    };

    let Some(current) = source_interval(&mut *conn, edge.source_id, overlay).await? else {
        return Ok(TargetedDecision::hold(HeldBucket::WouldRemove));
    };
    let p1 = match build(current)? {
        EdgeBbaBuild::Built(b) => b,
        EdgeBbaBuild::Vacuous => return Ok(TargetedDecision::hold(HeldBucket::WouldRemove)),
        EdgeBbaBuild::NonEpistemic => {
            return Ok(TargetedDecision::hold(HeldBucket::NonEpistemic));
        }
    };
    let stored = read_edge_row(&mut *conn, selected_id).await?;
    let overlaid_row = overlay.and_then(|o| o.rows.get(&selected_id));
    let current_row = overlaid_row.map_or_else(|| RowShape::of_stored(&stored), RowShape::of_built);
    let new_row = RowShape::of_built(&p1);
    let p0 = guards
        .baseline
        .get(&edge.source_id)
        .map(|&(b, p)| build((b, p, current.2)))
        .transpose()?
        .and_then(|b| match b {
            EdgeBbaBuild::Built(b) => Some(b),
            _ => None,
        });
    let mut decision = TargetedDecision {
        verdict: TargetedVerdict::Proceed,
        stored: Some(stored.clone()),
        p0: p0.clone(),
        p1: Some(p1.clone()),
        s: None,
        r: None,
        w: None,
    };
    if guards.only_changed && current_row.matches(&new_row, UNCHANGED_EPSILON, true) {
        decision.verdict = TargetedVerdict::Unchanged;
        return Ok(decision);
    }

    // Freshness (OD-E2): the stored (or predicted) cache against the fold of
    // the current (or predicted) rows, before this edge's row changes.
    let s = match overlay.and_then(|o| o.cache.get(&edge.target_id)) {
        Some(c) => c.clone(),
        None => crate::belief_cache::read_cache_columns(&mut *conn, &[edge.target_id])
            .await
            .map_err(|e| format!("target cache: {e}"))?
            .remove(&edge.target_id)
            .ok_or_else(|| format!("target {} not found", edge.target_id))?,
    };
    let mut replace: HashMap<Uuid, EdgeBba> = overlay.map(|o| o.rows.clone()).unwrap_or_default();
    let r = preview_claim_belief_on_frame_adjusted(
        &mut *conn,
        viewer,
        edge.target_id,
        binary,
        |rows| overlay_rows(rows, &replace),
    )
    .await?;
    decision.s = Some(s.clone());
    decision.r = r.clone();
    if !r
        .as_ref()
        .is_some_and(|r| cache_matches_fold(&s, r, binary, FRESH_EPSILON))
    {
        decision.verdict = TargetedVerdict::Hold(HeldBucket::TargetStale);
        return Ok(decision);
    }

    // Row class (OD-E3): the row this run (or this predict) wrote, else a
    // wire from the source's interval before it moved. A row already equal
    // to a fresh wire is not stale for any other reason either.
    let own = guards.own_rows.get(&edge.edge_id);
    let r173 = if overlaid_row.is_some() {
        true
    } else if let Some(own) = own {
        RowShape::of_stored(&stored).matches(&RowShape::of_stored(own), UNCHANGED_EPSILON, true)
    } else {
        current_row.matches(&new_row, ROW_CLASS_EPSILON, false)
            || p0.as_ref().is_some_and(|p0| {
                current_row.matches(&RowShape::of_built(p0), ROW_CLASS_EPSILON, false)
            })
    };
    if !r173 {
        decision.verdict = TargetedVerdict::Hold(HeldBucket::RowMixed);
        return Ok(decision);
    }

    replace.insert(selected_id, p1);
    let w = preview_claim_belief_on_frame_adjusted(
        &mut *conn,
        viewer,
        edge.target_id,
        binary,
        |rows| overlay_rows(rows, &replace),
    )
    .await?;
    decision.w = w.clone();
    if w.is_none() {
        let vacate = epigraph_engine::derivation_scope::must_vacate_cache(
            &mut *conn,
            viewer,
            edge.target_id,
        )
        .await
        .map_err(|e| format!("derivation scope read: {e}"))?;
        decision.verdict = TargetedVerdict::Hold(if vacate {
            HeldBucket::WouldVacate
        } else {
            HeldBucket::TargetStale
        });
    }
    Ok(decision)
}

/// Read what a targeted rewrite wrote, inside its transaction: the target's
/// cache and the rewritten row, which must be the selected row rewritten in
/// place (one live row at the wire key, so the upsert updated it).
async fn capture_rewrite(
    conn: &mut sqlx::PgConnection,
    edge: &RewireEdge,
    binary: Uuid,
    selected_id: Uuid,
    target_before: CacheColumns,
    row_before: StoredEdgeRow,
) -> Result<RewireCapture, String> {
    let target_after = crate::belief_cache::read_cache_columns(&mut *conn, &[edge.target_id])
        .await
        .map_err(|e| format!("target cache after: {e}"))?
        .remove(&edge.target_id)
        .ok_or_else(|| format!("target {} gone", edge.target_id))?;
    let row_after = read_edge_row(&mut *conn, selected_id).await?;
    Ok(RewireCapture {
        edge_id: edge.edge_id,
        target_id: edge.target_id,
        frame_id: binary,
        agent_id: edge.agent_id,
        target_before,
        target_after,
        row_before,
        row_after,
    })
}

/// Rewire one edge under `guards` (see the module doc). `on_capture` records
/// a rewrite before its transaction commits; its error rolls the edge back.
///
/// # Errors
/// Any read or write error; the edge's transaction is rolled back.
pub async fn rewire_edge_targeted(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    edge: &RewireEdge,
    guards: &TargetedGuards<'_>,
    on_capture: &mut (dyn FnMut(&RewireCapture) -> Result<(), String> + Send),
) -> Result<TargetedOutcome, String> {
    let r = rewire_one(pool, viewer, edge, Some((guards, on_capture))).await?;
    Ok(match r.outcome {
        EdgeRewrite::TargetedRewired(c) => TargetedOutcome::Rewired(c),
        EdgeRewrite::Unchanged => TargetedOutcome::Unchanged,
        EdgeRewrite::Held(b) => TargetedOutcome::Held(b),
        EdgeRewrite::SkippedStale => TargetedOutcome::SkippedStale,
        EdgeRewrite::SkippedNonEpistemic => TargetedOutcome::Held(HeldBucket::NonEpistemic),
        EdgeRewrite::Rewired
        | EdgeRewrite::RemovedVacuous
        | EdgeRewrite::RemovedSourceFactorless => {
            return Err(format!(
                "targeted rewire of edge {} reached an un-targeted outcome",
                edge.edge_id
            ));
        }
    })
}

impl RewireSummary {
    /// Rows this page left in place that a re-selection with the same
    /// `--written-before` returns again: `skipped_non_epistemic + failed`.
    #[must_use]
    pub fn persisting(&self) -> usize {
        self.skipped_non_epistemic + self.failed
    }

    /// Whether this page rewrote or removed any edge factor.
    #[must_use]
    pub fn made_progress(&self) -> bool {
        self.rewired + self.removed_vacuous + self.removed_source_factorless > 0
    }
}

impl std::fmt::Display for RewireSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "eligible={} rewired={} removed_vacuous={} removed_source_factorless={} skipped_non_epistemic={} skipped_stale={} duplicate_rows_deleted={} failed={}",
            self.eligible,
            self.rewired,
            self.removed_vacuous,
            self.removed_source_factorless,
            self.skipped_non_epistemic,
            self.skipped_stale,
            self.duplicate_rows_deleted,
            self.failed
        )
    }
}
