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
/// epistemic relationship. Uses `signer_id` when present, otherwise falls back
/// to the source claim's `agent_id` (always populated) — the edge factor is
/// attributable to the source claim's author since they're asserting the
/// support/contradiction via the edge.
pub const EDGE_QUERY: &str = r#"
SELECT e.id, COALESCE(e.signer_id, src.agent_id) AS agent_id,
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
    pub failed: usize,
}

/// Rewire-phase selection: every in-force claim-to-claim edge that already
/// holds an `edge_factor` BBA on its target, one row per edge.
///
/// - Keyed on the STORED row's `source_agent_id`, not on
///   `COALESCE(e.signer_id, src.agent_id)` as [`EDGE_QUERY`] is: the live
///   `link_epistemic` path and migration 114's writer-owned rows store other
///   agents, and the upsert key is `(claim, frame, source_agent, perspective)`,
///   so re-wiring under a different agent would add a second BBA for the edge
///   that double-counts in combine. (The phase also deletes the edge's rows
///   before re-wiring, so the agent decides attribution, not row count.)
/// - Retracted edges (`valid_to` in the past) are skipped, with the predicate
///   `SheafRepository::get_epistemic_edge_pairs` uses: `auto_wire_ds_for_edge`
///   does not check `is_in_force`, so selecting one would resurrect it.
/// - `$3` (`--written-before`) restricts to rows last written before an
///   instant. The upsert stamps `created_at = NOW()`, so a rewritten row drops
///   out: repeating `--limit N` at offset 0 with a fixed `--written-before`
///   pages through the population without skipping rows. Plain `--offset`
///   paging over a run that deletes rows does skip them.
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
}

/// Re-derive every selected edge factor from its source's current interval.
///
/// Per edge, on one connection and one transaction:
/// 1. a relationship that no longer maps to an epistemic restriction is left
///    untouched (it cannot be re-derived, and deleting it is not this phase's
///    call);
/// 2. the edge's stored BBA rows are deleted, then `auto_wire_ds_for_edge`
///    re-wires it under the stored agent, which writes the current shape and
///    recomputes the target;
/// 3. if the source is now factorless or the restriction vacuous, a fresh
///    wire would store nothing, so nothing is stored: the target is
///    recomputed from the BBAs that remain, and its cached belief is cleared
///    when none remain (a stale cache must not outlive its last supporter).
///
/// Any error rolls that edge back (its old row survives) and counts as failed.
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

    for edge in &edges {
        match rewire_one(pool, viewer, edge).await {
            Ok(EdgeRewrite::Rewired) => summary.rewired += 1,
            Ok(EdgeRewrite::RemovedVacuous) => summary.removed_vacuous += 1,
            Ok(EdgeRewrite::RemovedSourceFactorless) => summary.removed_source_factorless += 1,
            Ok(EdgeRewrite::SkippedNonEpistemic) => summary.skipped_non_epistemic += 1,
            Err(e) => {
                tracing::warn!(edge = %edge.edge_id, target = %edge.target_id, "edge rewire failed: {e}");
                summary.failed += 1;
            }
        }
    }
    Ok(summary)
}

async fn rewire_one(
    pool: &PgPool,
    viewer: &epigraph_db::visibility::Viewer,
    edge: &RewireEdge,
) -> Result<EdgeRewrite, String> {
    use epigraph_db::MassFunctionRepository;
    use epigraph_engine::edge_factor::{
        auto_wire_ds_for_edge, recompute_claim_belief_on_frame, EdgeFactorOutcome,
    };
    use epigraph_engine::sheaf::{
        restriction_kind_with_profile, RestrictionKind, RestrictionProfile,
    };

    if matches!(
        restriction_kind_with_profile(&edge.relationship, &RestrictionProfile::scientific()),
        RestrictionKind::Neutral
    ) {
        return Ok(EdgeRewrite::SkippedNonEpistemic);
    }

    let mut tx = pool.begin().await.map_err(|e| format!("begin: {e}"))?;
    MassFunctionRepository::delete_for_perspective(&mut *tx, edge.edge_id)
        .await
        .map_err(|e| format!("delete stale edge BBA: {e}"))?;
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
        EdgeFactorOutcome::Wired => EdgeRewrite::Rewired,
        EdgeFactorOutcome::Vacuous | EdgeFactorOutcome::SourceFactorless => {
            let backed_on_frame =
                recompute_claim_belief_on_frame(&mut tx, viewer, edge.target_id, edge.frame_id)
                    .await?;
            if !backed_on_frame {
                let remaining =
                    MassFunctionRepository::get_for_claim(&mut *tx, viewer, edge.target_id)
                        .await
                        .map_err(|e| format!("surviving BBAs: {e}"))?;
                if remaining.is_empty() {
                    MassFunctionRepository::clear_claim_belief(&mut *tx, edge.target_id)
                        .await
                        .map_err(|e| format!("clear unbacked belief: {e}"))?;
                }
            }
            if outcome == EdgeFactorOutcome::Vacuous {
                EdgeRewrite::RemovedVacuous
            } else {
                EdgeRewrite::RemovedSourceFactorless
            }
        }
        // Ruled out by the restriction check above; keep the old row.
        EdgeFactorOutcome::NonEpistemic => return Ok(EdgeRewrite::SkippedNonEpistemic),
    };
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(result)
}

impl std::fmt::Display for RewireSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "eligible={} rewired={} removed_vacuous={} removed_source_factorless={} skipped_non_epistemic={} failed={}",
            self.eligible,
            self.rewired,
            self.removed_vacuous,
            self.removed_source_factorless,
            self.skipped_non_epistemic,
            self.failed
        )
    }
}
