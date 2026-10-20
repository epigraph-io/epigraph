//! Probe: classify would-be new claims against the current family index, with
//! the same rules a plan uses, before anything is written.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::classify::{
    classify_pair, classify_pair_ignoring_conflicts, hygiene_reason, PairVerdict,
};
use super::profile::{LabelDedupProfile, PassProfile, Tier};
use super::record::{parse_candidate, parse_record, ParsedRecord};
use super::{DedupClaim, LabelDedupError, Snapshot};

/// The most candidates one probe accepts.
pub const PROBE_MAX_CANDIDATES: usize = 100;

/// A claim a writer is about to file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCandidate {
    /// Caller-chosen, echoed back.
    pub key: String,
    pub content: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

/// The verdict for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeVerdictKind {
    /// Nothing in the index describes it: file it.
    New,
    /// An auto-merge tier matched a live member: do not file it.
    Match,
    /// Similar to a live member, uncorroborated: a human decides.
    Review,
    /// Matched only a closed signal: skip it silently.
    MatchOnly,
}

/// One probe result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeVerdict {
    pub key: String,
    pub verdict: ProbeVerdictKind,
    pub matched_id: Option<Uuid>,
    pub tier: Option<Tier>,
    pub reason: String,
    /// Live members that a veto or hard conflict kept the candidate apart
    /// from, although the rules would otherwise have paired them.
    pub vetoed_by: Vec<Uuid>,
}

/// Classify `candidates` against the live members of `index` (hygiene claims
/// excluded), then, for a candidate still `new`, against `closed_signals`.
///
/// # Errors
/// [`LabelDedupError::TooManyCandidates`] above [`PROBE_MAX_CANDIDATES`];
/// [`LabelDedupError::Truncated`] when `index` or `closed_signals` hit their
/// read cap. A twin past the cap would otherwise read as `new`, and the
/// writer would file the duplicate the probe exists to prevent.
pub fn probe(
    profile: &LabelDedupProfile,
    index: &Snapshot,
    closed_signals: Option<&Snapshot>,
    candidates: &[ProbeCandidate],
) -> Result<Vec<ProbeVerdict>, LabelDedupError> {
    if candidates.len() > PROBE_MAX_CANDIDATES {
        return Err(LabelDedupError::TooManyCandidates {
            got: candidates.len(),
            max: PROBE_MAX_CANDIDATES,
        });
    }
    if index.truncated || closed_signals.is_some_and(|s| s.truncated) {
        return Err(LabelDedupError::Truncated);
    }
    let pass = &profile.pass;
    let sorted = |snap: &Snapshot| {
        let mut v: Vec<DedupClaim> = snap.claims.clone();
        v.sort_by_key(|c| c.id);
        v.dedup_by_key(|c| c.id);
        v
    };
    let live: Vec<ParsedRecord> = sorted(index)
        .iter()
        .filter(|c| {
            !pass
                .closed_label
                .as_ref()
                .is_some_and(|l| c.labels.contains(l))
        })
        .map(|c| parse_record(pass, c))
        .filter(|r| hygiene_reason(pass, r).is_none())
        .collect();
    let closed: Vec<ParsedRecord> = closed_signals
        .map(|s| sorted(s).iter().map(|c| parse_record(pass, c)).collect())
        .unwrap_or_default();

    Ok(candidates
        .iter()
        .map(|c| classify_candidate(pass, c, &live, &closed))
        .collect())
}

fn classify_candidate(
    pass: &PassProfile,
    c: &ProbeCandidate,
    live: &[ParsedRecord],
    closed: &[ParsedRecord],
) -> ProbeVerdict {
    let r = parse_candidate(pass, &c.content, &c.labels);
    let mut best_match: Option<(Tier, Uuid, String)> = None;
    let mut best_review: Option<(f64, Uuid, String)> = None;
    let mut vetoed_by = Vec::new();
    for m in live {
        let id = m.id.unwrap_or_default();
        match classify_pair(pass, &r, m) {
            PairVerdict::Merge { tier, reason } => {
                if best_match
                    .as_ref()
                    .is_none_or(|(t, _, _)| tier.strength() > t.strength())
                {
                    best_match = Some((tier, id, reason));
                }
            }
            PairVerdict::Review { overlap, reason } => {
                if best_review.as_ref().is_none_or(|(o, _, _)| overlap > *o) {
                    best_review = Some((overlap, id, reason));
                }
            }
            PairVerdict::Conflict { .. } => {
                if !matches!(
                    classify_pair_ignoring_conflicts(pass, &r, m),
                    PairVerdict::NoMatch
                ) {
                    vetoed_by.push(id);
                }
            }
            PairVerdict::NoMatch => {}
        }
    }
    let verdict = |verdict, matched_id, tier, reason| ProbeVerdict {
        key: c.key.clone(),
        verdict,
        matched_id,
        tier,
        reason,
        vetoed_by: vetoed_by.clone(),
    };
    if let Some((tier, id, reason)) = best_match {
        return verdict(ProbeVerdictKind::Match, Some(id), Some(tier), reason);
    }
    if let Some((_, id, reason)) = best_review {
        return verdict(
            ProbeVerdictKind::Review,
            Some(id),
            Some(Tier::FuzzyReview),
            reason,
        );
    }
    let mut only: Option<(Tier, Uuid, String)> = None;
    for s in closed {
        if let PairVerdict::Merge { tier, reason } = classify_pair(pass, &r, s) {
            if only
                .as_ref()
                .is_none_or(|(t, _, _)| tier.strength() > t.strength())
            {
                only = Some((tier, s.id.unwrap_or_default(), reason));
            }
        }
    }
    if let Some((tier, id, reason)) = only {
        return verdict(ProbeVerdictKind::MatchOnly, Some(id), Some(tier), reason);
    }
    verdict(
        ProbeVerdictKind::New,
        None,
        None,
        "no live member matches".to_string(),
    )
}
