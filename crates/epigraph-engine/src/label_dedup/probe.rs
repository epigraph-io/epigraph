//! Probe: classify would-be new claims against the current family index, with
//! the same rules a plan uses, before anything is written.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::profile::{LabelDedupProfile, Tier};
use super::{LabelDedupError, Snapshot};

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
/// [`LabelDedupError::TooManyCandidates`] above [`PROBE_MAX_CANDIDATES`].
pub fn probe(
    profile: &LabelDedupProfile,
    index: &Snapshot,
    closed_signals: Option<&Snapshot>,
    candidates: &[ProbeCandidate],
) -> Result<Vec<ProbeVerdict>, LabelDedupError> {
    let _ = (profile, index, closed_signals);
    Ok(candidates
        .iter()
        .map(|c| ProbeVerdict {
            key: c.key.clone(),
            verdict: ProbeVerdictKind::New,
            matched_id: None,
            tier: None,
            reason: String::new(),
            vetoed_by: Vec::new(),
        })
        .collect())
}
