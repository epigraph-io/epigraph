//! Contamination ledger for the cross-source verifier adjudication protocol.
//!
//! A precision figure for the LLM verifier is only meaningful over candidates
//! whose verdict nobody (model or human) has already produced: a pair that
//! already carries a `verifier_verdict`, or that a human already decided, has
//! been seen, and scoring it again measures agreement with that earlier
//! decision rather than the verifier. `tests/cross_source/prompts_v1.md` §5
//! requires those pairs to be listed BEFORE the sweep runs and excluded from
//! the headline figure. This module produces that list and splits a sweep's
//! candidate pairs against it.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

/// A pair of claim ids, in either orientation.
pub type ClaimPair = (Uuid, Uuid);

/// One `match_candidates` row that already carries a decision.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LedgerEntry {
    /// Canonical order (`claim_a < claim_b`), as the table stores it.
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub status: String,
    pub verifier_verdict: Option<String>,
    pub decided_at: Option<DateTime<Utc>>,
    /// Why the row counts as contaminated: `human_decision` when a human
    /// decided it (`decided_at` set), else `verifier_verdict` when a verifier
    /// verdict is stored, else `status:<status>` for a promoted or rejected row
    /// with neither (legacy rows).
    pub reason: String,
}

/// Every `match_candidates` row that already carries a decision: a stored
/// `verifier_verdict`, a `decided_at`, or a terminal `promoted`/`rejected`
/// status. A plain `pending` row with no verdict is NOT contaminated: nothing
/// has judged it yet. Ordered by `(claim_a, claim_b)` so two ledgers over the
/// same table diff cleanly.
pub async fn contamination_ledger(pool: &PgPool) -> Result<Vec<LedgerEntry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT claim_a, claim_b, status, verifier_verdict, decided_at
         FROM match_candidates
         WHERE verifier_verdict IS NOT NULL
            OR decided_at IS NOT NULL
            OR status IN ('promoted', 'rejected')
         ORDER BY claim_a, claim_b",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let status: String = row.try_get("status")?;
            let verifier_verdict: Option<String> = row.try_get("verifier_verdict")?;
            let decided_at: Option<DateTime<Utc>> = row.try_get("decided_at")?;
            let reason = if decided_at.is_some() {
                "human_decision".to_string()
            } else if verifier_verdict.is_some() {
                "verifier_verdict".to_string()
            } else {
                format!("status:{status}")
            };
            Ok(LedgerEntry {
                claim_a: row.try_get("claim_a")?,
                claim_b: row.try_get("claim_b")?,
                status,
                verifier_verdict,
                decided_at,
                reason,
            })
        })
        .collect()
}

/// Split `pairs` into `(clean, contaminated)` against `ledger`, preserving
/// input order within each side. Pairs are matched orientation-independently
/// (the table stores `claim_a < claim_b`; a caller's pair may be reversed).
pub fn partition_by_ledger(
    pairs: &[ClaimPair],
    ledger: &[LedgerEntry],
) -> (Vec<ClaimPair>, Vec<ClaimPair>) {
    let seen: HashSet<(Uuid, Uuid)> = ledger.iter().map(|e| (e.claim_a, e.claim_b)).collect();
    pairs
        .iter()
        .copied()
        .partition(|&(a, b)| !seen.contains(&(a.min(b), a.max(b))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(a: Uuid, b: Uuid) -> LedgerEntry {
        LedgerEntry {
            claim_a: a.min(b),
            claim_b: a.max(b),
            status: "rejected".into(),
            verifier_verdict: Some("distinct".into()),
            decided_at: None,
            reason: "verifier_verdict".into(),
        }
    }

    #[test]
    fn a_reversed_pair_is_still_matched_against_the_canonical_ledger() {
        let (x, y, z) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let ledger = vec![entry(x, y)];
        let pairs = vec![(x.max(y), x.min(y)), (x, z)];
        let (clean, dirty) = partition_by_ledger(&pairs, &ledger);
        assert_eq!(dirty, vec![(x.max(y), x.min(y))]);
        assert_eq!(clean, vec![(x, z)]);
    }
}
