//! Claim classification (member or hygiene) and pair classification (tiers,
//! vetoes and hard conflicts).
//!
//! Pair checks run in this order; the first hit wins:
//!
//! 1. **Hard conflicts** (never merged, never reviewed): a `distinct-from`
//!    ruling on either side, a `must_agree` partition mismatch, a
//!    no-strong-id partition member paired across classes without a shared
//!    strong id.
//! 2. **Revision label**: either claim names a prefix of the other's id.
//!    Checked before the strong-id veto, so a revision that changed its id
//!    still links to its original.
//! 3. **Strong-id veto**: both claims carry strong ids and share none.
//! 4. The tiers `strong_id`, `weak_id_and_entity`, `title_and_entity`, then
//!    `fuzzy_review` (review only).

use serde::{Deserialize, Serialize};

use super::profile::{PassProfile, Tier};
use super::record::ParsedRecord;

/// Why a pair can never be in one cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ConflictKind {
    /// A human ruled the two distinct.
    DistinctLabel,
    /// Both carry labels under this prefix and the values are disjoint.
    PartitionMismatch { prefix: String },
    /// One carries this no-strong-id label, the other does not, and they
    /// share no strong id.
    NoStrongIdPartition { label: String },
    /// Both carry strong ids and share none.
    StrongIdVeto,
}

/// The classification of one pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum PairVerdict {
    /// An auto-merge tier.
    Merge { tier: Tier, reason: String },
    /// Similar, uncorroborated: a human decides.
    Review { overlap: f64, reason: String },
    /// Vetoed.
    Conflict {
        conflict: ConflictKind,
        reason: String,
    },
    /// Unrelated.
    NoMatch,
}

/// Why a family member is hygiene (leaves the family) rather than a member,
/// or `None` for a live member. Reason codes: `retired_label:<label>`,
/// `retired_flag:<FLAG>`, `non_member_label:<label>`, `non_member_body`;
/// several are joined with `; `.
#[must_use]
pub fn hygiene_reason(pass: &PassProfile, record: &ParsedRecord) -> Option<String> {
    let _ = (pass, record);
    None
}

/// Whether the record is bookkeeping (a non-member by label or body),
/// regardless of retirement.
#[must_use]
pub fn is_non_member(pass: &PassProfile, record: &ParsedRecord) -> bool {
    let _ = (pass, record);
    false
}

/// Whether the record is a partial retirement: a retired label other than
/// the closed label, or retired content.
#[must_use]
pub fn is_partially_retired(pass: &PassProfile, record: &ParsedRecord) -> bool {
    let _ = (pass, record);
    false
}

/// Classify a pair.
#[must_use]
pub fn classify_pair(pass: &PassProfile, a: &ParsedRecord, b: &ParsedRecord) -> PairVerdict {
    let _ = (pass, a, b);
    PairVerdict::NoMatch
}

/// Classify a pair as if no veto or hard conflict existed. The probe uses it
/// to name the members a veto kept a candidate apart from.
#[must_use]
pub fn classify_pair_ignoring_conflicts(
    pass: &PassProfile,
    a: &ParsedRecord,
    b: &ParsedRecord,
) -> PairVerdict {
    let _ = (pass, a, b);
    PairVerdict::NoMatch
}

/// The cross-pair check of the constrained union-find: may `a` and `b` end up
/// in one cluster? A hard conflict always forbids it; a strong-id veto
/// forbids it unless the two are linked by a revision label.
#[must_use]
pub fn cluster_conflict(
    pass: &PassProfile,
    a: &ParsedRecord,
    b: &ParsedRecord,
) -> Option<ConflictKind> {
    let _ = (pass, a, b);
    None
}
