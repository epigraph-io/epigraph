//! The revert input an apply returns, and the label writes and un-marks that
//! undo it.
//!
//! Apply records, per claim write, the labels the write ACTUALLY changed: the
//! labels it named that were absent before and present after (added), and the
//! labels it named that were present before and absent after (removed). A
//! label the write named but that was already in the requested state is not
//! recorded, so a revert never strips a label the claim carried before the
//! apply.
//!
//! [`revert_writes`] inverts that list: every change is undone, newest first,
//! by adding back what was removed and removing what was added. The order
//! matters when two units of one apply touch the same claim and the same
//! label (one adds it, a later one removes it): only the reverse order lands
//! back on the original set.
//!
//! Apply also records every duplicate it marked ([`AppliedMark`]). A revert
//! undoes the label writes first, then the marks ([`revert_marks`]), newest
//! first: an un-mark is refused while the duplicate's canonical is itself a
//! marked duplicate, so a chain comes apart from its newest link.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::plan::{DuplicateMark, LabelWrite};
use super::profile::Tier;

/// One duplicate a committed unit marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMark {
    /// The write unit the mark belongs to (`cluster:<survivor>`, ...).
    pub unit: String,
    pub dup: Uuid,
    pub canonical: Uuid,
    pub rule: Tier,
    pub matched_on: String,
    /// The dedup identity edge the act wrote, when the caller knows it.
    #[serde(default)]
    pub identity_edge: Option<Uuid>,
}

impl AppliedMark {
    /// The record of `mark`, performed by `unit`.
    #[must_use]
    pub fn from_mark(unit: &str, mark: &DuplicateMark, identity_edge: Option<Uuid>) -> Self {
        Self {
            unit: unit.to_string(),
            dup: mark.dup,
            canonical: mark.canonical,
            rule: mark.rule,
            matched_on: mark.matched_on.clone(),
            identity_edge,
        }
    }
}

/// The marks of `applied` in the order to un-mark them: newest first.
#[must_use]
pub fn revert_marks(applied: &[AppliedMark]) -> Vec<AppliedMark> {
    applied.iter().rev().cloned().collect()
}

/// The exact label change one committed write made to one claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedLabelChange {
    /// The write unit the change belongs to (`cluster:<survivor>`, ...).
    pub unit: String,
    pub claim_id: Uuid,
    pub labels_added: Vec<String>,
    pub labels_removed: Vec<String>,
}

impl AppliedLabelChange {
    /// The change `write` made, from the claim's labels read before it and the
    /// labels the write returned. Only labels the write named are considered,
    /// so a concurrent change to any other label is never attributed to it.
    #[must_use]
    pub fn from_write(unit: &str, write: &LabelWrite, before: &[String], after: &[String]) -> Self {
        let had = |l: &String| before.contains(l);
        let has = |l: &String| after.contains(l);
        Self {
            unit: unit.to_string(),
            claim_id: write.claim_id,
            labels_added: distinct(write.add.iter().filter(|l| !had(l) && has(l))),
            labels_removed: distinct(write.remove.iter().filter(|l| had(l) && !has(l))),
        }
    }

    /// Whether the write changed nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.labels_added.is_empty() && self.labels_removed.is_empty()
    }
}

/// The label writes that undo `applied`, newest change first.
#[must_use]
pub fn revert_writes(applied: &[AppliedLabelChange]) -> Vec<LabelWrite> {
    applied
        .iter()
        .rev()
        .filter(|c| !c.is_empty())
        .map(|c| LabelWrite {
            claim_id: c.claim_id,
            add: c.labels_removed.clone(),
            remove: c.labels_added.clone(),
        })
        .collect()
}

/// Sorted and de-duplicated, so a recorded change is canonical whatever order
/// the write named its labels in.
fn distinct<'a>(labels: impl Iterator<Item = &'a String>) -> Vec<String> {
    labels
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
