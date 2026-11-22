//! The stored scoped folds of a claim (`ds_combined_beliefs`): one row per
//! `(frame, claim, scope)`, where the scope is `global` (every BBA of the
//! frame), a `perspective` (that perspective's BBAs) or a `community`.
//!
//! The REST evidence route (`POST /frames/:id/evidence`) writes them as it
//! stores a BBA. A widening act (`crate::visibility_act`) deletes a moved
//! claim's rows as folded for its old audience (migration 215) and then
//! writes them afresh here, for the new audience, so a scoped read right after
//! the act finds a value rather than nothing (backlog 4d8df0cf). Both use the
//! same folds:
//!
//! * the `global` row is [`crate::edge_factor::preview_claim_belief_on_frame`],
//!   the value the REST route stores for it ([`global_fold`]);
//! * a `perspective` or `community` row is [`fold_scope_rows`] over the
//!   scope's BBAs, which the REST route calls too.
//!
//! Every fold keeps only the BBAs the claim's stored beliefs may be computed
//! from (`crate::derivation_scope::retain_for_cache`: every source at least
//! as widely readable as the claim), read against the claim's tenancy at the
//! time of the fold.

use epigraph_db::visibility::Viewer;
use epigraph_db::{FrameRepository, MassFunctionRepository, MassFunctionRow};
use epigraph_ds::{FrameOfDiscernment, MassFunction};
use sqlx::Acquire as _;
use uuid::Uuid;

/// The conflict threshold the REST evidence route folds a scope with when
/// its request names none, and the one a recompute uses.
pub const DEFAULT_CONFLICT_THRESHOLD: f64 = 0.3;

/// The values one `ds_combined_beliefs` row stores.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedFold {
    pub belief: f64,
    pub plausibility: f64,
    pub pignistic_prob: f64,
    /// The conflict the whole fold saw (for one BBA, its own empty-set mass).
    pub mass_on_empty: f64,
    pub mass_on_missing: f64,
    /// The fold's conflict; `None` when one BBA was not folded.
    pub conflict_k: Option<f64>,
    /// The rule that produced the fold; `None` when one BBA was not folded.
    pub strategy: Option<String>,
}

/// Belief, plausibility, pignistic probability and missing mass of the
/// claim's hypothesis in `combined`. A missing, negative or out-of-range index
/// reads as hypothesis 0, as the cache writer resolves it.
#[must_use]
pub fn hypothesis_belief(
    combined: &MassFunction,
    ds_frame: &FrameOfDiscernment,
    hypothesis_index: Option<i32>,
) -> (f64, f64, f64, f64) {
    use epigraph_ds::{measures, FocalElement};

    let h_idx =
        crate::edge_factor::resolve_hypothesis_index(hypothesis_index, ds_frame.hypothesis_count());
    let supported = FocalElement::positive(std::collections::BTreeSet::from([h_idx]));
    let bel = measures::belief(combined, &supported);
    let pl = measures::plausibility(combined, &supported);
    let betp = measures::pignistic_probability(combined, h_idx);
    let m_missing = combined.mass_of_missing();
    (bel, pl, betp, m_missing)
}

/// The scoped fold of `rows` (a scope's stored BBAs of one claim and frame):
/// raw masses, no discount, restricted to the rows the claim's stored beliefs
/// may be computed from, folded by the owner-aware rule (sibling agents of one
/// human are reduced cautiously, never multiplied). `Ok(None)` when no row is
/// left or none parses on `ds_frame`.
///
/// Stored-row semantics: `mass_on_empty` and `conflict_k` are both the
/// conflict the whole fold saw; a single BBA is not folded, so its
/// `mass_on_empty` is its own conflict mass and `conflict_k` / `strategy` are
/// `None`. `strategy` is `Dempster`, or `cautious+Dempster` when a same-human
/// sibling group was reduced.
///
/// # Errors
/// A read of the rows' admissibility or sources, or the fold, fails.
pub async fn fold_scope_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    ds_frame: &FrameOfDiscernment,
    hypothesis_index: Option<i32>,
    rows: Vec<MassFunctionRow>,
    conflict_threshold: f64,
) -> Result<Option<ScopedFold>, String> {
    let mut rows = crate::derivation_scope::retain_for_cache(&mut *conn, rows)
        .await
        .map_err(|e| format!("scope rows: {e}"))?;
    rows.sort_by_key(|r| r.id);
    let rows: Vec<(MassFunctionRow, MassFunction)> = rows
        .into_iter()
        .filter_map(|row| {
            MassFunction::from_json_masses(ds_frame.clone(), &row.masses)
                .ok()
                .map(|m| (row, m))
        })
        .collect();
    if rows.is_empty() {
        return Ok(None);
    }
    let stored: Vec<MassFunctionRow> = rows.iter().map(|(r, _)| r.clone()).collect();
    let sources = crate::source_dependence::bba_sources_for_rows(&mut *conn, viewer, &stored)
        .await
        .map_err(|e| format!("scope sources: {e}"))?;
    let folded = rows.len() >= 2;
    let cautious = crate::source_dependence::has_same_owner_siblings(&sources);
    let items = sources
        .into_iter()
        .zip(rows.into_iter().map(|(_, m)| m))
        .collect();
    let (combined, k) =
        crate::source_dependence::combine_with_owner_dependence(items, conflict_threshold)
            .map_err(|e| format!("scope fold: {e}"))?;
    let (belief, plausibility, pignistic_prob, mass_on_missing) =
        hypothesis_belief(&combined, ds_frame, hypothesis_index);
    Ok(Some(ScopedFold {
        belief,
        plausibility,
        pignistic_prob,
        mass_on_empty: k,
        mass_on_missing,
        conflict_k: folded.then_some(k),
        // The rule that produced the stored fold, in the spelling `/assess`
        // stores for a cautious-then-Dempster fold.
        strategy: folded.then(|| {
            if cautious {
                "cautious+Dempster".to_string()
            } else {
                "Dempster".to_string()
            }
        }),
    }))
}

/// The `global` row of `(claim_id, frame_id)`, as the REST evidence route
/// stores it: the frame's combination by the shared pipeline
/// ([`crate::edge_factor::preview_claim_belief_on_frame`], which is full
/// ignorance where the cache would be vacated), with `conflict_k` and
/// `strategy` set only when more than one admissible BBA was folded.
/// `Ok(None)` when the preview has no value.
///
/// # Errors
/// As [`crate::edge_factor::preview_claim_belief_on_frame`].
pub async fn global_fold(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
) -> Result<Option<ScopedFold>, String> {
    let Some(preview) =
        crate::edge_factor::preview_claim_belief_on_frame(&mut *conn, viewer, claim_id, frame_id)
            .await?
    else {
        return Ok(None);
    };
    let rows = MassFunctionRepository::get_for_claim_frame(&mut *conn, viewer, claim_id, frame_id)
        .await
        .map_err(|e| format!("get_for_claim_frame: {e}"))?;
    let admitted = crate::derivation_scope::retain_for_cache(&mut *conn, rows)
        .await
        .map_err(|e| format!("derivation scope read: {e}"))?
        .len();
    let folded = admitted > 1;
    Ok(Some(ScopedFold {
        belief: preview.belief,
        plausibility: preview.plausibility,
        pignistic_prob: preview.pignistic_prob,
        mass_on_empty: preview.conflict_k,
        mass_on_missing: preview.missing_mass,
        conflict_k: folded.then_some(preview.conflict_k),
        strategy: folded.then(|| "Dempster".to_string()),
    }))
}

/// One `ds_combined_beliefs` key of a claim: `(frame_id, scope_type,
/// scope_id)`.
pub type ScopeKey = (Uuid, String, Option<Uuid>);

/// What [`refresh_scoped_beliefs`] did with a claim's keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopedRefresh {
    /// Rows written for the claim's current audience.
    pub written: usize,
    /// Keys with nothing admissible to fold: no row.
    pub empty: usize,
    /// Keys not recomputed here (a `community` scope, an unknown scope type),
    /// or whose fold or write failed (logged): no row until the next
    /// computation that stores one.
    pub skipped: usize,
}

/// Write the `ds_combined_beliefs` rows of `claim_id` at `keys` afresh, for
/// the claim's current audience, on `conn` (the caller's stamped
/// transaction). Each key is folded and written under its own SAVEPOINT, so a
/// refused or failed key is logged and skipped without aborting the caller's
/// transaction, as the REST route writes these derived rows best-effort.
///
/// `global` keys take [`global_fold`] and `perspective` keys
/// [`fold_scope_rows`] over the perspective's BBAs. A `community` key is NOT
/// recomputed: its fold depends on the community's member list and mass
/// override, which are read on the raw pool, and is counted as skipped.
///
/// # Errors
/// Only when a savepoint cannot be opened or closed (the connection is then
/// unusable).
pub async fn refresh_scoped_beliefs(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
    keys: &[ScopeKey],
) -> Result<ScopedRefresh, String> {
    let mut report = ScopedRefresh::default();
    for (frame_id, scope_type, scope_id) in keys {
        let mut sp = conn
            .begin()
            .await
            .map_err(|e| format!("open a scoped-belief savepoint: {e}"))?;
        let outcome =
            refresh_one(&mut sp, viewer, claim_id, *frame_id, scope_type, *scope_id).await;
        let close = match &outcome {
            Ok(_) => sp.commit().await,
            Err(e) => {
                tracing::warn!(
                    %claim_id, %frame_id, scope_type = %scope_type, ?scope_id,
                    "scoped belief not recomputed after the visibility act: {e}"
                );
                sp.rollback().await
            }
        };
        close.map_err(|e| format!("close a scoped-belief savepoint: {e}"))?;
        match outcome {
            Ok(Some(true)) => report.written += 1,
            Ok(Some(false)) => report.empty += 1,
            Ok(None) | Err(_) => report.skipped += 1,
        }
    }
    Ok(report)
}

/// One key: `Some(true)` written, `Some(false)` nothing admissible, `None`
/// not a scope recomputed here.
async fn refresh_one(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
    frame_id: Uuid,
    scope_type: &str,
    scope_id: Option<Uuid>,
) -> Result<Option<bool>, String> {
    let fold = match (scope_type, scope_id) {
        ("global", None) => global_fold(&mut *conn, viewer, claim_id, frame_id).await?,
        ("perspective", Some(perspective_id)) => {
            let row = FrameRepository::get_by_id(&mut *conn, viewer, frame_id)
                .await
                .map_err(|e| format!("frame get_by_id: {e}"))?
                .ok_or_else(|| format!("frame {frame_id} not found"))?;
            let ds_frame = FrameOfDiscernment::new(row.name.clone(), row.hypotheses.clone())
                .map_err(|e| format!("build frame {}: {e}", row.name))?;
            let h_idx =
                FrameRepository::get_claim_assignment(&mut *conn, viewer, claim_id, frame_id)
                    .await
                    .map_err(|e| format!("get_claim_assignment: {e}"))?
                    .and_then(|a| a.hypothesis_index);
            let rows = MassFunctionRepository::get_for_claim_frame_perspective(
                &mut *conn,
                viewer,
                claim_id,
                frame_id,
                perspective_id,
            )
            .await
            .map_err(|e| format!("get_for_claim_frame_perspective: {e}"))?;
            fold_scope_rows(
                &mut *conn,
                viewer,
                &ds_frame,
                h_idx,
                rows,
                DEFAULT_CONFLICT_THRESHOLD,
            )
            .await?
        }
        _ => return Ok(None),
    };
    let Some(f) = fold else {
        return Ok(Some(false));
    };
    epigraph_db::ScopedBeliefRepository::upsert(
        &mut *conn,
        frame_id,
        claim_id,
        scope_type,
        scope_id,
        f.belief,
        f.plausibility,
        f.mass_on_empty,
        f.mass_on_missing,
        f.conflict_k,
        f.strategy.as_deref(),
        Some(f.pignistic_prob),
    )
    .await
    .map_err(|e| format!("upsert: {e}"))?;
    Ok(Some(true))
}
