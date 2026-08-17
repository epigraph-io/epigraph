//! Cascading belief repair downstream of a retraction (`supersede_claim`,
//! `mark_duplicate`).
//!
//! Backlog claim `20e9ed83-c5f1-4f26-bee5-d6eb105d2635`. Formalised by MemTX
//! (arXiv:2607.23929) invariant I2, *cascade-repair completeness*: "retracting
//! a belief leaves no orphaned derived record and no uncompensated side
//! effect".
//!
//! # Why recomputation alone cannot do this
//!
//! [`crate::edge_factor::auto_wire_ds_for_edge`] freezes the supporter's
//! epistemic interval into a **stored mass shape** at wire time
//! (`restricted.to_mass_function(&frame)` → `store_with_perspective`, keyed
//! `perspective_id = edge_id`). The combine path
//! ([`crate::edge_factor::preview_claim_belief_on_frame`] and friends) loads
//! `mass_functions.masses` verbatim and re-derives only the reliability
//! discount; it never queries `claims`. So calling the ordinary
//! "recompute this claim's belief" entry point after retracting a supporter
//! returns **bit-identical** scalars — a cascade built that way reports
//! success and changes nothing.
//!
//! The required primitive is therefore **invalidation**, not recombination:
//! delete the `perspective_id = edge_id` BBA
//! ([`MassFunctionRepository::delete_for_perspective`]), optionally re-derive
//! it from whatever now sits at the edge's source, and only then recompute the
//! target from what survives. Deletion (not overwrite) is mandatory because
//! [`crate::edge_factor::auto_wire_edge_if_epistemic`] short-circuits on
//! `MassFunctionRepository::exists_for_perspective`, so a re-wire that leaves
//! the stale row behind is a permanent no-op.
//!
//! # Empty surviving set: the "unbacked" decision
//!
//! `recompute_claim_belief_on_frame` returns `Ok(false)` and writes **nothing**
//! when the claim has no BBAs left. The cached scalars on `claims` are a stale
//! cache, not a derived view, so "nothing to recompute" is not "nothing to
//! change": a claim whose sole supporter was retracted would keep believing its
//! pre-retraction number with zero evidence behind it.
//!
//! **Decision: such a claim is marked _unbacked_** — `belief`, `plausibility`,
//! `pignistic_prob`, `mass_on_empty`, `mass_on_missing` and `classification`
//! are set to `NULL` ([`MassFunctionRepository::clear_claim_belief`]). NULL is
//! the state a claim carries before it ever acquires a BBA, so readers can
//! distinguish "unbacked" from "believed at 0.79". The rejected alternative —
//! resetting to a vacuous `(0, 1, 0.5)` — writes a number the combine pipeline
//! can also legitimately produce, making the two indistinguishable.
//!
//! Claims that still hold BBAs on some *other* frame are left alone: the cached
//! scalars are frame-agnostic and last-writer-wins, so nulling them would
//! discard a live cross-frame result.
//!
//! # Structural discipline
//!
//! Mirrors the in-repo precedent
//! `epigraph-api/src/routes/edges.rs::propagate_to_dependents`:
//!
//! * **1 hop**, with an explicit `visited` set — deeper propagation on a
//!   support graph does not terminate (each pass re-derives BBAs from freshly
//!   written intervals; DS combination being a contraction is not a
//!   termination argument for a graph walk).
//! * **Best-effort.** Every failure is `tracing::warn!`-ed and collected into
//!   [`CascadeReport::errors`]; nothing here returns `Err`. The retraction
//!   transaction has *already committed* by the time the cascade runs, so
//!   surfacing a cascade error to the caller would report failure for a write
//!   that succeeded — and the retry then gets "Claim <uuid> has already been
//!   superseded", a wedged state for an autonomous agent.
//! * **Call-site orchestration.** All SQL stays in
//!   `epigraph-db/src/repos/`; this module sequences repo calls and the DS
//!   pipeline. It is awaited in-line rather than `tokio::spawn`ed: the caller
//!   must be able to report what was repaired ([`CascadeReport`]), a detached
//!   task would race `#[sqlx::test]` teardown, and the precedent above is
//!   likewise awaited. The cascade never gates the write's own success.
//!
//! # Known remaining gap (deliberately out of scope)
//!
//! `ClaimRepository::supersede` re-points *incoming* edges onto the
//! replacement claim, leaving their BBAs stranded on the retired claim — the
//! same stranding class this module repairs for `mark_duplicate`. It is not
//! repaired here: moving them would give the replacement claim an interval it
//! did not earn (`supersede` inserts it with NULL `belief`/`plausibility`),
//! silently resurrecting the retracted claim's numbers under a new id. That
//! deserves its own decision, not a side effect of this one.

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use epigraph_db::{ClaimRepository, DedupRepair, EdgeRepository, MassFunctionRepository};

use crate::edge_factor::{
    auto_wire_edge_if_epistemic, ensure_binary_frame, recompute_claim_belief_on_frame,
};

/// What a cascade actually did, so the caller can report it instead of telling
/// readers to sleep-and-hope.
///
/// A post-retraction read of a downstream claim is racy in principle; handing
/// the caller the target set and the outcome converts that into something it
/// can observe and act on.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CascadeReport {
    /// Downstream claims whose derived records the cascade touched.
    pub targets: Vec<Uuid>,
    /// Stale edge-factor BBAs deleted (invalidation, not recombination).
    pub invalidated_bbas: u64,
    /// Targets whose belief was recomputed from a non-empty surviving BBA set.
    pub recomputed: Vec<Uuid>,
    /// Targets left with no BBA at all, whose cached scalars were NULLed.
    /// Distinguished from `recomputed` precisely so "the cache was cleared
    /// because nothing backs it" is not reported as "nothing to do".
    pub unbacked: Vec<Uuid>,
    /// Best-effort failures, already logged at `warn`. Never returned as `Err`.
    pub errors: Vec<String>,
}

impl CascadeReport {
    fn note_error(&mut self, context: &str, err: impl std::fmt::Display) {
        let msg = format!("{context}: {err}");
        tracing::warn!("retraction cascade (non-fatal) {msg}");
        self.errors.push(msg);
    }
}

/// Repair belief downstream of `ClaimRepository::supersede`.
///
/// `new_claim_id` is the **replacement** claim, not the retracted one: the
/// supersede transaction re-points every non-`supersedes` outgoing edge onto
/// the replacement before it commits, so enumerating from the retracted uuid
/// finds nothing at all (see
/// [`EdgeRepository::list_current_claim_targets`]).
///
/// Never fails: see the module docs on best-effort semantics.
pub async fn cascade_after_supersede(pool: &PgPool, new_claim_id: Uuid) -> CascadeReport {
    let mut report = CascadeReport::default();

    let frame_id = match ensure_binary_frame(pool).await {
        Ok(id) => id,
        Err(e) => {
            report.note_error("ensure_binary_frame", e);
            return report;
        }
    };

    let edges = match EdgeRepository::list_current_claim_targets(pool, new_claim_id).await {
        Ok(rows) => rows,
        Err(e) => {
            report.note_error("enumerate downstream targets", e);
            return report;
        }
    };

    // Seeded with the origin so a cycle (`A supports B`, `B supports A`)
    // cannot pull the retraction's own replacement back into the walk.
    let mut visited: HashSet<Uuid> = HashSet::from([new_claim_id]);
    let targets =
        invalidate_and_rewire(pool, new_claim_id, &edges, &mut visited, &mut report).await;
    repair_targets(pool, frame_id, &targets, &mut report).await;

    tracing::info!(
        replacement = %new_claim_id,
        targets = ?report.targets,
        invalidated_bbas = report.invalidated_bbas,
        "supersede belief cascade complete"
    );
    report
}

/// Repair belief downstream of
/// [`ClaimRepository::mark_duplicate_with_repair`].
///
/// The orphaned/stranded BBA rows were already fixed inside the dedup
/// transaction; this recomputes everything whose supporter set changed, and
/// re-derives the BBAs of edges that now hang off `canonical` instead of the
/// duplicate.
///
/// Never fails: see the module docs on best-effort semantics.
pub async fn cascade_after_dedup(
    pool: &PgPool,
    canonical_id: Uuid,
    repair: &DedupRepair,
) -> CascadeReport {
    let mut report = CascadeReport::default();
    report.invalidated_bbas += repair.deleted_bbas;

    let frame_id = match ensure_binary_frame(pool).await {
        Ok(id) => id,
        Err(e) => {
            report.note_error("ensure_binary_frame", e);
            return report;
        }
    };

    // Phase 1 — rebuild the claims whose BBA set the dedup transaction already
    // changed: both endpoints, plus any third claim that lost a BBA to a
    // collision pre-delete. This runs FIRST because `canonical` has just
    // inherited the duplicate's supporters, and phase 2 re-derives edges that
    // hang off `canonical`'s interval — deriving them from the pre-merge value
    // would bake in a number that was already superseded by this same call.
    let mut visited: HashSet<Uuid> = HashSet::new();
    let endpoints: Vec<Uuid> = repair
        .stale_claims
        .iter()
        .copied()
        .filter(|id| visited.insert(*id))
        .collect();
    repair_targets(pool, frame_id, &endpoints, &mut report).await;

    // Phase 2 — edges re-sourced from `dup` onto `canonical`. Their BBAs sit on
    // the far end and still encode `dup`'s interval, so they are invalidated
    // and re-derived from `canonical`.
    let resourced = invalidate_and_rewire(
        pool,
        canonical_id,
        &repair.resourced_edges,
        &mut visited,
        &mut report,
    )
    .await;
    repair_targets(pool, frame_id, &resourced, &mut report).await;

    tracing::info!(
        canonical = %canonical_id,
        targets = ?report.targets,
        invalidated_bbas = report.invalidated_bbas,
        moved_bbas = repair.moved_bbas,
        "mark_duplicate belief cascade complete"
    );
    report
}

/// For each `(edge_id, target_id, relationship)`: delete the BBA frozen from
/// the retracted source, then attempt a re-wire from whatever now sources the
/// edge, and queue the target for recomputation.
///
/// Returns the newly queued targets (deduplicated against `visited`).
///
/// Only edges that actually carried a BBA become targets. An edge whose source
/// was factorless at wire time has no derived record to repair, so recomputing
/// its target would be a write with no cause — the cascade stays surgical.
async fn invalidate_and_rewire(
    pool: &PgPool,
    source_id: Uuid,
    edges: &[(Uuid, Uuid, String)],
    visited: &mut HashSet<Uuid>,
    report: &mut CascadeReport,
) -> Vec<Uuid> {
    let mut queued = Vec::new();
    // Attribution mirrors the edge-write path: the BBA belongs to the SOURCE
    // claim's author ("A's author asserts A SUPPORTS B"), not to whoever
    // triggered the retraction.
    let source_agent_id: Option<Uuid> =
        match sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
            .bind(source_id)
            .fetch_optional(pool)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                report.note_error("resolve source agent", e);
                None
            }
        };

    for (edge_id, target_id, relationship) in edges {
        let deleted = match MassFunctionRepository::delete_for_perspective(pool, *edge_id).await {
            Ok(n) => n,
            Err(e) => {
                report.note_error(&format!("invalidate BBA for edge {edge_id}"), e);
                continue;
            }
        };
        if deleted == 0 {
            continue;
        }
        report.invalidated_bbas += deleted;

        // Re-derive from the current source. After a supersede this is
        // normally a no-op (`SourceFactorless`) because the replacement claim
        // is inserted with NULL belief/plausibility; after a dedup the
        // canonical claim usually does have an interval, so the supporter is
        // re-established with the right provenance.
        if let Some(agent_id) = source_agent_id {
            auto_wire_edge_if_epistemic(
                pool,
                /* was_created */ false,
                *edge_id,
                source_id,
                "claim",
                *target_id,
                "claim",
                relationship,
                agent_id,
            )
            .await;
        }

        if visited.insert(*target_id) {
            queued.push(*target_id);
        }
    }
    queued
}

/// Recompute each target, or mark it unbacked when nothing survives, recording
/// both in the report.
async fn repair_targets(
    pool: &PgPool,
    frame_id: Uuid,
    targets: &[Uuid],
    report: &mut CascadeReport,
) {
    for target_id in targets {
        let target_id = *target_id;
        report.targets.push(target_id);
        match recompute_claim_belief_on_frame(pool, target_id, frame_id).await {
            Ok(true) => report.recomputed.push(target_id),
            Ok(false) => mark_unbacked_if_evidence_free(pool, target_id, report).await,
            Err(e) => report.note_error(&format!("recompute claim {target_id}"), e),
        }
    }
}

/// `Ok(false)` from the recompute means "no BBAs **on this frame**". Only NULL
/// the cache when the claim has no BBAs on *any* frame: the cached scalars are
/// frame-agnostic, so a claim still backed on another frame must keep the value
/// that frame's recompute wrote.
async fn mark_unbacked_if_evidence_free(pool: &PgPool, claim_id: Uuid, report: &mut CascadeReport) {
    match MassFunctionRepository::get_for_claim(pool, claim_id).await {
        Ok(rows) if !rows.is_empty() => {}
        Ok(_) => match MassFunctionRepository::clear_claim_belief(pool, claim_id).await {
            Ok(()) => report.unbacked.push(claim_id),
            Err(e) => report.note_error(&format!("clear unbacked belief on {claim_id}"), e),
        },
        Err(e) => report.note_error(&format!("check surviving BBAs for {claim_id}"), e),
    }
}

/// Convenience wrapper: run [`ClaimRepository::mark_duplicate_with_repair`]
/// and its cascade in one call, since every production call site wants both.
///
/// # Errors
/// Propagates only the dedup's own error. Cascade failures are reported inside
/// [`CascadeReport::errors`], never as `Err`.
pub async fn mark_duplicate_with_cascade(
    pool: &PgPool,
    dup_id: Uuid,
    canonical_id: Uuid,
) -> Result<CascadeReport, epigraph_db::DbError> {
    use epigraph_core::ClaimId;

    let repair = ClaimRepository::mark_duplicate_with_repair(
        pool,
        ClaimId::from_uuid(dup_id),
        ClaimId::from_uuid(canonical_id),
    )
    .await?;
    Ok(cascade_after_dedup(pool, canonical_id, &repair).await)
}
