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

/// Add `increments` (when `Some`) to the claim's Beta parameters and return
/// the posterior `alpha / (alpha + beta)`.
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
) -> Result<f64, sqlx::Error> {
    let mut sp = conn.begin().await?;
    let outcome: Result<(f64, f64), epigraph_db::DbError> = async {
        if let Some((d_alpha, d_beta)) = increments {
            if let Some(stored) =
                ClaimRepository::add_beta_increments(&mut sp, viewer, claim_id, d_alpha, d_beta)
                    .await?
            {
                return Ok(stored);
            }
        }
        let (alpha, beta) = ClaimRepository::get_beta_params(&mut sp, viewer, claim_id)
            .await?
            .unwrap_or((1.0, 1.0));
        Ok(with_increments((alpha, beta), increments))
    }
    .await;

    let (alpha, beta) = match outcome {
        Ok(params) => {
            sp.commit().await?;
            params
        }
        Err(e) => {
            tracing::warn!("{context}: Beta update refused: {e}");
            sp.rollback().await?;
            with_increments((1.0, 1.0), increments)
        }
    };
    Ok(alpha / (alpha + beta))
}

/// `params` with the positive parts of `increments` added. The arithmetic the
/// stored update performs, for a posterior that is reported but not stored.
fn with_increments((alpha, beta): (f64, f64), increments: Option<(f64, f64)>) -> (f64, f64) {
    match increments {
        Some((d_alpha, d_beta)) => (alpha + d_alpha.max(0.0), beta + d_beta.max(0.0)),
        None => (alpha, beta),
    }
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
/// `pignistic_prob`, `bayesian_posterior` and their
/// [`kl_divergence_bernoulli`]. Returns whether the row was stored.
///
/// A refusal (the claim's group is not writable on this session, a CHECK
/// constraint) is logged and rolled back to the savepoint.
///
/// # Errors
/// Only when the savepoint cannot be opened or closed.
pub async fn record_divergence(
    conn: &mut sqlx::PgConnection,
    claim_id: Uuid,
    frame_id: Uuid,
    pignistic_prob: f64,
    bayesian_posterior: f64,
    frame_version: Option<i32>,
    context: &str,
) -> Result<bool, sqlx::Error> {
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
}
