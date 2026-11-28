//! `cross_source_sweep --recent`: the short-interval drain that runs the
//! cross-source matcher over claims written in the last window (backlog
//! efc1d318, the drain half of 6ed02d04).
//!
//! # The claim row is the queue entry
//!
//! A new claim is inserted with `claims.last_match_scan_at IS NULL`, committed
//! atomically with the claim itself. That NULL stamp is the "match due" signal:
//! no job row, no new privilege, no migration, and an ingest of hundreds of
//! claims coalesces into one drain pass by construction. The drain selects
//!
//! * `is_current` claims,
//! * with a NULL `last_match_scan_at`,
//! * created within the window (default one day),
//! * carrying none of [`excluded_labels`] (the `status` marker plus every
//!   [`STATUS_CLAIM_LABELS`] entry, matched exactly),
//!
//! oldest first, capped, runs them through the SAME `run_pipeline` (same
//! `MatcherConfig`, verifier and `auto_promote`) as the default sweep, and
//! stamps them. A claim that ages out of the window unscanned still has a NULL
//! stamp, so the default sweep (NULL or older than 7 days) picks it up.
//!
//! The selection and the run-then-stamp step live here, not in the binary, so
//! a test can drive exactly what the binary runs with a mock verifier.

use std::sync::Arc;
use std::time::Duration;

use epigraph_embeddings::EmbeddingService;
use epigraph_engine::matching::calibration::MatcherConfig;
use epigraph_engine::matching::pipeline::{run_pipeline, RunInputs, RunReport};
use epigraph_engine::matching::verifier::VerifierClient;
use epigraph_mcp::tools::novelty_gate::STATUS_CLAIM_LABELS;
use sqlx::PgPool;
use uuid::Uuid;

/// The `--window` default: one day.
pub const DEFAULT_WINDOW: &str = "1d";

/// The structural marker for a status claim (alongside `telemetry`, which is
/// already in [`STATUS_CLAIM_LABELS`]).
pub const STATUS_MARKER_LABEL: &str = "status";

/// Labels that keep a claim out of the `--recent` drain: [`STATUS_MARKER_LABEL`]
/// plus every [`STATUS_CLAIM_LABELS`] entry. Matched EXACTLY, as the novelty
/// gate matches them: a topic label such as `daily-journal` is not excluded.
#[must_use]
pub fn excluded_labels() -> Vec<&'static str> {
    std::iter::once(STATUS_MARKER_LABEL)
        .chain(STATUS_CLAIM_LABELS.iter().copied())
        .collect()
}

/// Parse a `--window` value: a positive integer followed by `d`, `h` or `m`
/// (days, hours, minutes), e.g. `1d`, `6h`, `90m`.
///
/// # Errors
/// A missing or unknown unit, a non-numeric or zero count, or an overflow.
pub fn parse_window(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let err = || format!("invalid window {s:?}: expected <N>d, <N>h or <N>m with N > 0");
    let unit = s.chars().last().ok_or_else(err)?;
    let secs_per_unit: u64 = match unit {
        'd' => 86_400,
        'h' => 3_600,
        'm' => 60,
        _ => return Err(err()),
    };
    let count: u64 = s[..s.len() - 1].parse().map_err(|_| err())?;
    if count == 0 {
        return Err(err());
    }
    let secs = count.checked_mul(secs_per_unit).ok_or_else(err)?;
    Ok(Duration::from_secs(secs))
}

/// The `--recent` seed selection: current, never-scanned, non-status claims
/// created within `window`, oldest first, at most `cap`.
///
/// # Errors
/// The query failing.
pub async fn select_recent_seeds(
    pool: &PgPool,
    window: Duration,
    cap: i64,
) -> sqlx::Result<Vec<Uuid>> {
    let excluded: Vec<String> = excluded_labels().into_iter().map(String::from).collect();
    // `labels` is `text[] NOT NULL DEFAULT '{}'` (migration 001), so `&&`
    // never yields NULL here and an unlabelled claim is kept.
    sqlx::query_scalar(
        "SELECT id FROM claims
         WHERE is_current
           AND last_match_scan_at IS NULL
           AND created_at > now() - make_interval(secs => $1)
           AND NOT (labels && $2::text[])
         ORDER BY created_at ASC, id ASC
         LIMIT $3",
    )
    .bind(window.as_secs_f64())
    .bind(&excluded)
    .bind(cap)
    .fetch_all(pool)
    .await
}

/// What one sweep pass runs the matcher with. Both the default sweep and
/// `--recent` build it the same way, so the two modes share one verifier,
/// policy and threshold set.
pub struct SweepInputs {
    pub cfg: MatcherConfig,
    pub verifier: Box<dyn VerifierClient>,
    pub auto_promote: bool,
    pub probe_embedder: Option<Arc<dyn EmbeddingService>>,
    /// Stamp `last_match_scan_at` on the seeds after a successful run. False
    /// only for `--count-only`, an analysis run that must not hide the seeds
    /// from the next real sweep.
    pub stamp: bool,
}

/// Run the matcher over `seeds`, then (when `inputs.stamp`) stamp them so the
/// next sweep moves forward. A pipeline error returns before the stamp, so a
/// failed run leaves its seeds due.
///
/// # Errors
/// `run_pipeline` failing, or the stamp update failing.
pub async fn sweep_seeds(
    pool: &PgPool,
    seeds: &[Uuid],
    inputs: SweepInputs,
) -> anyhow::Result<RunReport> {
    let report = run_pipeline(
        pool,
        RunInputs {
            seeds: seeds.to_vec(),
            cfg: inputs.cfg,
            verifier: inputs.verifier,
            auto_promote: inputs.auto_promote,
            probe_embedder: inputs.probe_embedder,
        },
    )
    .await?;
    if inputs.stamp && !seeds.is_empty() {
        sqlx::query("UPDATE claims SET last_match_scan_at = now() WHERE id = ANY($1)")
            .bind(seeds)
            .execute(pool)
            .await?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_window_accepts_days_hours_minutes() {
        assert_eq!(parse_window("1d"), Ok(Duration::from_secs(86_400)));
        assert_eq!(parse_window("6h"), Ok(Duration::from_secs(21_600)));
        assert_eq!(parse_window("90m"), Ok(Duration::from_secs(5_400)));
        assert_eq!(
            parse_window(DEFAULT_WINDOW),
            Ok(Duration::from_secs(86_400))
        );
    }

    #[test]
    fn parse_window_rejects_zero_garbage_and_overflow() {
        for bad in [
            "",
            "d",
            "0d",
            "0m",
            "1",
            "24",
            "1w",
            "1s",
            "-1d",
            "1.5d",
            "abc",
            "1dd",
            "99999999999999999999d",
        ] {
            assert!(parse_window(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn excluded_labels_are_the_status_marker_and_every_status_claim_label() {
        let ex = excluded_labels();
        assert!(ex.contains(&"status"));
        assert!(ex.contains(&"telemetry"));
        for l in STATUS_CLAIM_LABELS {
            assert!(ex.contains(&l), "{l} must be excluded");
        }
        assert!(
            !ex.contains(&"daily-journal"),
            "topic labels are not status labels"
        );
    }
}
