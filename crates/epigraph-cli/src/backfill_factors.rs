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

use sqlx::PgPool;
use uuid::Uuid;

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
        match rewire_one(pool, viewer, edge).await {
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
/// `(id, frame)`.
async fn delete_edge_rows(
    conn: &mut sqlx::PgConnection,
    edge: &RewireEdge,
    keep: Option<(Uuid, Uuid)>,
) -> Result<Vec<(Uuid, Uuid)>, String> {
    let (keep_frame, keep_agent) = keep.unzip();
    sqlx::query_as(
        "DELETE FROM mass_functions \
          WHERE perspective_id = $1 AND claim_id = $2 \
            AND combination_method = 'edge_factor' \
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

async fn rewire_one(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    edge: &RewireEdge,
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
    let keep = (binary, edge.agent_id);
    let others = delete_edge_rows(&mut tx, edge, Some(keep)).await?;
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
