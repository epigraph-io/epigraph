//! The parallel Beta-Bernoulli track and its DS-vs-Bayesian divergence record.
//!
//! Every DS evidence write keeps two derived records beside the BBA it stores:
//!
//! 1. **The claim's Beta parameters** (`claims.beta_alpha` / `beta_beta`). The
//!    stored BBA's mass on the claim's own singleton `{h}` is added to alpha,
//!    and its remaining non-conflict mass (`1 - m({h}) - m(∅)`) to beta. The
//!    posterior is `alpha / (alpha + beta)`.
//! 2. **A `ds_bayesian_divergence` row**: the claim's pignistic probability
//!    after the write, the Beta posterior, and the Bernoulli KL divergence
//!    between them. `get_divergence` and `GET /divergence/top` read these rows.
//!
//! Both used to live inline in the REST `POST /frames/:id/evidence` handler,
//! so a claim whose evidence arrived through the MCP DS tools
//! (`submit_ds_evidence`, `update_with_evidence`) never got either one, and
//! `get_divergence` answered "no divergence data" for it (backlog f50344c0).
//! Those three writers now call the same functions.
//!
//! The other DS writers do NOT call them yet, so their claims still get no
//! row: `submit_claim`'s seed wire (`ds_auto::auto_wire_ds_for_claim`), the
//! batch ingest wire (`auto_wire_ds_batch`), the edge wire
//! (`auto_wire_ds_for_edge`), `report_workflow_outcome`
//! (`auto_wire_ds_update`) and the recompute paths. Rows older than
//! `DivergenceRepository`'s TTL are not served either.
//!
//! # A cold start records no divergence row
//!
//! A claim whose evidence was all stored by writers that do not keep this
//! track (the seed and edge wires, assess discounts, evidence older than the
//! track) still holds the `Beta(1, 1)` prior while its DS fold, and so its
//! BetP, may be mature. Its first live update then compares that BetP against
//! a posterior carrying one BBA's evidence and nothing else, which registers a
//! large divergence that says nothing about the two calculi disagreeing.
//! [`apply_beta_update`] reports such an update as a cold start
//! ([`BetaUpdate::cold_start`]), and [`record_divergence`] stores no row for
//! it, so a cold start never reaches `get_divergence` or `GET /divergence/top`.
//! The claim's next live update, from a track that holds evidence, records its
//! divergence as before. (The table has no column to flag a row with, and a
//! flagged row would only be filtered out by every reader, so the row is not
//! written.)
//!
//! [`replay_beta_params`] rebuilds the parameters from a claim's stored BBAs
//! by the same arithmetic. Its operator backfill `replay_beta_track`
//! (`epigraph-cli`'s `beta_replay`) is NOT to be applied: counting every
//! stored BBA builds a track the live writers never would have (a dry run on a
//! production-sized corpus put the replayed posteriors well below BetP and
//! would have pushed thousands of claims into the top-divergent list), so its
//! binary refuses `--apply` and only dry-runs. The cold-start rule above is
//! what keeps those claims out of the list instead.
//!
//! # Best-effort, under a SAVEPOINT
//!
//! Both records are derived. Neither may fail the submission that produced
//! them, and a refused statement must not abort the caller's transaction. So
//! each function opens its own SAVEPOINT on the caller's connection and rolls
//! back to it on a refusal (logged as a warning). `ds_bayesian_divergence` is
//! claim-derived: it inherits the claim's owner group, so its insert is refused
//! for a writer that does not write the claim's group (a non-owner attaching
//! evidence to a public claim). Only a failure to open or close the savepoint
//! itself is returned, because the connection is then unusable.

use epigraph_db::visibility::Viewer;
use epigraph_db::ClaimRepository;
use epigraph_ds::{FocalElement, MassFunction};
use sqlx::Acquire as _;
use uuid::Uuid;

/// Bernoulli KL divergence `KL(p || q)` between the DS pignistic
/// probability `p` and the Bayesian posterior `q`.
///
/// `KL(p || q) = p ln(p/q) + (1-p) ln((1-p)/(1-q))`
///
/// Inputs are clamped to `[ε, 1-ε]` to avoid `ln(0)`.
#[must_use]
pub fn kl_divergence_bernoulli(p: f64, q: f64) -> f64 {
    let eps = 1e-10;
    let p = p.clamp(eps, 1.0 - eps);
    let q = q.clamp(eps, 1.0 - eps);
    p * (p / q).ln() + (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
}

/// The Beta increments `(d_alpha, d_beta)` one stored BBA contributes for
/// the claim's hypothesis `hypothesis_index` (its `claim_frames` index).
///
/// `(0, 0)` when there is no index to address: the BBA then moves neither
/// parameter. A non-positive increment is not applied.
#[must_use]
pub fn beta_increments(bba: &MassFunction, hypothesis_index: Option<i32>) -> (f64, f64) {
    let Some(h_i) = hypothesis_index else {
        return (0.0, 0.0);
    };
    // `as usize`, not `try_from`: a negative index addresses no hypothesis,
    // so its singleton has no mass and all non-conflict mass counts against.
    // This is the REST handler's arithmetic as it stood, kept bit-for-bit.
    #[allow(clippy::cast_sign_loss)]
    let singleton = FocalElement::positive(std::iter::once(h_i as usize).collect());
    let m_support = bba.mass_of(&singleton);
    let m_complement = 1.0 - m_support - bba.mass_of_empty();
    (m_support.max(0.0), m_complement.max(0.0))
}

/// What [`apply_beta_update`] leaves: the Beta posterior, and whether it was
/// computed from a track that held no counted evidence before this write.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BetaUpdate {
    /// `alpha / (alpha + beta)` after this write's increments.
    pub posterior: f64,
    /// The parameters this posterior was computed from were still at the
    /// `Beta(1, 1)` prior before this write: the claim's first counted update,
    /// a resubmission on a claim whose track was never moved, or a refused
    /// update (whose posterior is computed from the prior). Such a posterior
    /// holds at most this one BBA's evidence, so its divergence from a mature
    /// BetP is an artefact of the empty track, and [`record_divergence`] does
    /// not record it.
    pub cold_start: bool,
}

/// How far from `1.0` a parameter may sit and still count as the prior: the
/// increments are non-negative, so a parameter within this of `1.0` has
/// counted no evidence (only rounding from `(1 + d) - d`).
const PRIOR_TOLERANCE: f64 = 1e-9;

/// A claim's Beta parameters before a write and after it.
type BeforeAfter = ((f64, f64), (f64, f64));

fn at_prior((alpha, beta): (f64, f64)) -> bool {
    (alpha - 1.0).abs() < PRIOR_TOLERANCE && (beta - 1.0).abs() < PRIOR_TOLERANCE
}

/// Add `increments` (when `Some`) to the claim's Beta parameters and return
/// the posterior `alpha / (alpha + beta)`, with whether the track was cold
/// (still at the prior) before this write ([`BetaUpdate::cold_start`]).
///
/// `increments` is `None` for a BBA that is not counted: an identical
/// resubmission, whose update was applied when it was first stored. The
/// parameters are then only read. A counted BBA passes
/// `Some(`[`beta_increments`]`(..))`.
///
/// The write is `ClaimRepository::add_beta_increments`: one gated `UPDATE`
/// that adds in SQL, so concurrent writers on one claim cannot lose each
/// other's increment. When it touches no row (a claim the viewer does not
/// write: a non-owner attaching evidence to a public claim), the stored
/// parameters are read through the viewer and the increments added here, so
/// the reported posterior includes this evidence exactly as it did before the
/// write moved into the repo layer; nothing is stored. A missing or invisible
/// claim reads as the `Beta(1, 1)` prior. A refused statement is logged and
/// rolled back to the savepoint, and the posterior is then computed from the
/// prior.
///
/// # Errors
/// Only when the savepoint cannot be opened or closed.
pub async fn apply_beta_update(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    claim_id: Uuid,
    increments: Option<(f64, f64)>,
    context: &str,
) -> Result<BetaUpdate, sqlx::Error> {
    let mut sp = conn.begin().await?;
    // The parameters before this write and after it.
    let outcome: Result<BeforeAfter, epigraph_db::DbError> = async {
        if let Some((d_alpha, d_beta)) = increments {
            if let Some(stored) =
                ClaimRepository::add_beta_increments(&mut sp, viewer, claim_id, d_alpha, d_beta)
                    .await?
            {
                // The update adds in SQL and returns only the sum; what it
                // added was exactly these increments.
                return Ok(((stored.0 - d_alpha, stored.1 - d_beta), stored));
            }
        }
        let before = ClaimRepository::get_beta_params(&mut sp, viewer, claim_id)
            .await?
            .unwrap_or((1.0, 1.0));
        Ok((before, with_increments(before, increments)))
    }
    .await;

    let (before, (alpha, beta)) = match outcome {
        Ok(params) => {
            sp.commit().await?;
            params
        }
        Err(e) => {
            tracing::warn!("{context}: Beta update refused: {e}");
            sp.rollback().await?;
            ((1.0, 1.0), with_increments((1.0, 1.0), increments))
        }
    };
    Ok(BetaUpdate {
        posterior: alpha / (alpha + beta),
        cold_start: at_prior(before),
    })
}

/// `params` with the positive parts of `increments` added. The arithmetic the
/// stored update performs, for a posterior that is reported but not stored.
fn with_increments((alpha, beta): (f64, f64), increments: Option<(f64, f64)>) -> (f64, f64) {
    match increments {
        Some((d_alpha, d_beta)) => (alpha + d_alpha.max(0.0), beta + d_beta.max(0.0)),
        None => (alpha, beta),
    }
}

/// The Beta parameters [`apply_beta_update`] leaves after counting each BBA of
/// `bbas`, in order, starting from `start`: what the live track would hold had
/// every one of those BBAs been counted when it was stored.
///
/// Each item is a BBA and the claim's hypothesis index on that BBA's frame,
/// and contributes [`beta_increments`]`(bba, index)`, added one BBA at a time
/// in the given order, exactly as successive live writes add them (floating
/// point addition is not associative, so the order is part of the result).
/// The backfill of claims whose evidence predates the MCP paths keeping this
/// track (`epigraph-cli`'s `beta_replay`) replays a claim's stored BBAs
/// through this, oldest first.
#[must_use]
pub fn replay_beta_params<'a>(
    start: (f64, f64),
    bbas: impl IntoIterator<Item = (&'a MassFunction, Option<i32>)>,
) -> (f64, f64) {
    bbas.into_iter().fold(start, |params, (bba, index)| {
        with_increments(params, Some(beta_increments(bba, index)))
    })
}

/// The version of frame `frame_id` as the viewer reads it, for a divergence
/// row's `frame_version`. Best-effort, under its own savepoint: a refused read
/// is logged and reads as `None`, and never aborts the caller's transaction.
///
/// # Errors
/// Only when the savepoint cannot be opened or closed.
pub async fn frame_version(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    frame_id: Uuid,
    context: &str,
) -> Result<Option<i32>, sqlx::Error> {
    let mut sp = conn.begin().await?;
    match epigraph_db::FrameRepository::get_by_id(&mut *sp, viewer, frame_id).await {
        Ok(row) => {
            sp.commit().await?;
            Ok(row.map(|f| f.version))
        }
        Err(e) => {
            tracing::warn!("{context}: frame version read refused: {e}");
            sp.rollback().await?;
            Ok(None)
        }
    }
}

/// Store one `ds_bayesian_divergence` row for `(claim_id, frame_id)`:
/// `pignistic_prob`, the [`apply_beta_update`] posterior `beta` and their
/// [`kl_divergence_bernoulli`]. Returns whether the row was stored.
///
/// A cold start ([`BetaUpdate::cold_start`]) stores nothing and returns
/// `false`: see the module docs. A refusal (the claim's group is not writable
/// on this session, a CHECK constraint) is logged and rolled back to the
/// savepoint.
///
/// # Errors
/// Only when the savepoint cannot be opened or closed.
pub async fn record_divergence(
    conn: &mut sqlx::PgConnection,
    claim_id: Uuid,
    frame_id: Uuid,
    pignistic_prob: f64,
    beta: BetaUpdate,
    frame_version: Option<i32>,
    context: &str,
) -> Result<bool, sqlx::Error> {
    if beta.cold_start {
        tracing::debug!(
            %claim_id,
            "{context}: no divergence row for a cold-start Beta update (the track held no \
             evidence before this write)"
        );
        return Ok(false);
    }
    let bayesian_posterior = beta.posterior;
    let kl = kl_divergence_bernoulli(pignistic_prob, bayesian_posterior);
    let mut sp = conn.begin().await?;
    let stored = epigraph_db::DivergenceRepository::store(
        &mut *sp,
        claim_id,
        frame_id,
        pignistic_prob,
        bayesian_posterior,
        kl,
        frame_version,
    )
    .await;
    match stored {
        Ok(_) => {
            sp.commit().await?;
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("{context}: divergence record refused: {e}");
            sp.rollback().await?;
            Ok(false)
        }
    }
}

/// One counted BBA write, as [`track_counted_bba`] takes it.
#[derive(Debug, Clone, Copy)]
pub struct CountedBba<'a> {
    /// The claim the BBA was stored on.
    pub claim_id: Uuid,
    /// The frame the BBA was stored on, which the divergence row names.
    pub frame_id: Uuid,
    /// The BBA as stored (undiscounted), whose [`beta_increments`] are added.
    pub bba: &'a MassFunction,
    /// The claim's hypothesis index on `frame_id` (its `claim_frames` index).
    pub hypothesis_index: Option<i32>,
    /// The claim's pignistic probability after the write, when the writer has
    /// it: the value it wrote to the claim's cache. `None` keeps the Beta
    /// track and records no divergence row.
    pub pignistic_prob: Option<f64>,
}

/// The two derived records of one BBA write the writer has decided to count:
/// [`apply_beta_update`] with [`beta_increments`]`(bba, hypothesis_index)`,
/// then, when the writer passes the claim's BetP after the write,
/// [`record_divergence`] on the BBA's frame at the version the viewer reads.
/// Returns whether a divergence row was stored (never on a cold start).
///
/// For the writers whose BBA is always counted and that need nothing back
/// from the Beta update: the seed wire, the batch ingest wire, the edge wire
/// and `report_workflow_outcome`. Deciding WHETHER the BBA is counted (a
/// re-wire or an identical resubmission is not) stays the caller's.
///
/// # Errors
/// Only when a savepoint cannot be opened or closed (see the module docs).
pub async fn track_counted_bba(
    conn: &mut sqlx::PgConnection,
    viewer: &Viewer,
    write: CountedBba<'_>,
    context: &str,
) -> Result<bool, sqlx::Error> {
    let beta = apply_beta_update(
        &mut *conn,
        viewer,
        write.claim_id,
        Some(beta_increments(write.bba, write.hypothesis_index)),
        context,
    )
    .await?;
    let Some(pignistic_prob) = write.pignistic_prob else {
        return Ok(false);
    };
    let version = frame_version(&mut *conn, viewer, write.frame_id, context).await?;
    record_divergence(
        conn,
        write.claim_id,
        write.frame_id,
        pignistic_prob,
        beta,
        version,
        context,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ds::FrameOfDiscernment;
    use std::collections::BTreeMap;

    fn binary() -> FrameOfDiscernment {
        FrameOfDiscernment::new("t", vec!["T".into(), "F".into()]).unwrap()
    }

    #[test]
    fn kl_divergence_identical_distributions_is_zero() {
        let kl = kl_divergence_bernoulli(0.7, 0.7);
        assert!(kl.abs() < 1e-8, "KL(p || p) should be ~0, got {kl}");
    }

    #[test]
    fn kl_divergence_matches_the_closed_form() {
        // 0.9 ln(0.9/0.5) + 0.1 ln(0.1/0.5)
        let expected = 0.9 * (1.8_f64).ln() + 0.1 * (0.2_f64).ln();
        let kl = kl_divergence_bernoulli(0.9, 0.5);
        assert!((kl - expected).abs() < 1e-12, "{kl} vs {expected}");
    }

    #[test]
    fn kl_divergence_extreme_values_dont_panic() {
        assert!(kl_divergence_bernoulli(0.0, 1.0).is_finite());
        assert!(kl_divergence_bernoulli(1.0, 0.0).is_finite());
    }

    #[test]
    fn kl_divergence_symmetric_for_equal_distance() {
        let kl_forward = kl_divergence_bernoulli(0.3, 0.7);
        let kl_reverse = kl_divergence_bernoulli(0.7, 0.3);
        assert!(kl_forward > 0.0);
        assert!(
            (kl_forward - kl_reverse).abs() < 1e-10,
            "symmetric case: forward={kl_forward}, reverse={kl_reverse}"
        );
    }

    /// The prior check behind [`BetaUpdate::cold_start`]: `(1 + d) - d` for a
    /// first update reads as the prior despite rounding; any counted mass, even
    /// a small one, does not.
    #[test]
    fn at_prior_tolerates_rounding_and_nothing_more() {
        let (d_alpha, d_beta) = (0.1_f64 + 0.2, 0.7_f64);
        let after = (1.0 + d_alpha, 1.0 + d_beta);
        assert!(at_prior((after.0 - d_alpha, after.1 - d_beta)));
        assert!(at_prior((1.0, 1.0)));
        assert!(!at_prior((1.0 + 1e-6, 1.0)));
        assert!(!at_prior((1.0, 1.05)));
        assert!(!at_prior((1.8, 1.2)));
    }

    #[test]
    fn beta_increments_split_support_from_the_rest() {
        let frame = binary();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive([0].into_iter().collect()), 0.6);
        masses.insert(FocalElement::theta(&frame), 0.4);
        let bba = MassFunction::new(frame, masses).unwrap();
        let (a, b) = beta_increments(&bba, Some(0));
        assert!(
            (a - 0.6).abs() < 1e-12 && (b - 0.4).abs() < 1e-12,
            "{a} {b}"
        );
        // On the other hypothesis the support becomes the complement.
        let (a, b) = beta_increments(&bba, Some(1));
        assert!(a.abs() < 1e-12 && (b - 1.0).abs() < 1e-12, "{a} {b}");
        assert_eq!(beta_increments(&bba, None), (0.0, 0.0));
    }

    /// The replay adds each BBA's increments one at a time, in order, from the
    /// start it is given: the sum successive live writes store. Expected values
    /// are written out by hand from the masses.
    #[test]
    fn replay_adds_each_bba_in_order_from_the_start() {
        let frame = binary();
        let support = |s: f64, conflict: f64| {
            let mut masses = BTreeMap::new();
            masses.insert(FocalElement::positive([0].into_iter().collect()), s);
            if conflict > 0.0 {
                masses.insert(FocalElement::conflict(), conflict);
            }
            masses.insert(FocalElement::theta(&frame), 1.0 - s - conflict);
            MassFunction::new(frame.clone(), masses).unwrap()
        };
        let a = support(0.6, 0.0); // +0.6 / +0.4
        let b = support(0.3, 0.2); // +0.3 / +0.5 (conflict counts for neither)
        let (alpha, beta) =
            replay_beta_params((1.0, 1.0), [(&a, Some(0)), (&b, Some(0)), (&a, None)]);
        assert!((alpha - 1.9).abs() < 1e-12, "alpha {alpha}");
        assert!((beta - 1.9).abs() < 1e-12, "beta {beta}");
        // On hypothesis 1 the singleton {1} carries no mass, so every
        // non-conflict unit counts against it.
        let (alpha, beta) = replay_beta_params((2.0, 3.0), [(&b, Some(1))]);
        assert!((alpha - 2.0).abs() < 1e-12 && (beta - 3.8).abs() < 1e-12);
        assert_eq!(replay_beta_params((1.0, 1.0), []), (1.0, 1.0));
    }
}
