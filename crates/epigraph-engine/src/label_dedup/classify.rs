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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::profile::{PassProfile, Tier};
use super::record::{entities_match, split_flag, ParsedRecord};
use super::{normalize_text, overlap_coefficient};

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
/// several are joined with `; `. Retirement is reported before bookkeeping.
#[must_use]
pub fn hygiene_reason(pass: &PassProfile, record: &ParsedRecord) -> Option<String> {
    let mut reasons: Vec<String> = record
        .labels
        .iter()
        .filter(|l| pass.retired_labels.contains(l))
        .map(|l| format!("retired_label:{l}"))
        .collect();
    if let Some(flag) = retired_flag(pass, record) {
        reasons.push(format!("retired_flag:{flag}"));
    }
    if reasons.is_empty() {
        reasons = non_member_reasons(pass, record);
    }
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

/// Whether the record is bookkeeping (a non-member by label or body),
/// regardless of retirement.
#[must_use]
pub fn is_non_member(pass: &PassProfile, record: &ParsedRecord) -> bool {
    !non_member_reasons(pass, record).is_empty()
}

/// Whether the record is a partial retirement: a retired label other than
/// the closed label, or retired content.
#[must_use]
pub fn is_partially_retired(pass: &PassProfile, record: &ParsedRecord) -> bool {
    record
        .labels
        .iter()
        .any(|l| pass.retired_labels.contains(l) && pass.closed_label.as_ref() != Some(l))
        || retired_flag(pass, record).is_some()
}

fn retired_flag<'a>(pass: &'a PassProfile, record: &ParsedRecord) -> Option<&'a str> {
    let body = record.content.trim_start();
    pass.content_retired_flags
        .iter()
        .find(|f| !f.is_empty() && body.starts_with(&format!("[{f}]")))
        .map(String::as_str)
}

fn non_member_reasons(pass: &PassProfile, record: &ParsedRecord) -> Vec<String> {
    let nm = &pass.non_member;
    let labels: Vec<String> = record
        .labels
        .iter()
        .filter(|l| nm.labels_any.contains(l))
        .map(|l| format!("non_member_label:{l}"))
        .collect();
    if !labels.is_empty() {
        return labels;
    }
    // The flag is stripped first: a `[REVIEW] …` item is not a review report.
    let (_, body) = split_flag(pass, &record.content);
    let n = normalize_text(body);
    let norm = |s: &String| normalize_text(s);
    let prefixed = nm
        .body_prefixes
        .iter()
        .map(norm)
        .any(|p| !p.is_empty() && n.starts_with(&p));
    let contains = nm
        .body_contains
        .iter()
        .map(norm)
        .any(|p| !p.is_empty() && n.contains(&p));
    // Prefixes keep their trailing space (`review `), so they are matched
    // lowercased rather than normalized.
    let report = nm.completion_report.as_ref().is_some_and(|r| {
        r.prefixes
            .iter()
            .any(|p| !p.is_empty() && n.starts_with(&p.to_lowercase()))
            && r.requires_any
                .iter()
                .map(norm)
                .any(|w| !w.is_empty() && n.contains(&w))
    });
    if prefixed || contains || report {
        vec!["non_member_body".to_string()]
    } else {
        Vec::new()
    }
}

/// Classify a pair.
#[must_use]
pub fn classify_pair(pass: &PassProfile, a: &ParsedRecord, b: &ParsedRecord) -> PairVerdict {
    if let Some((conflict, reason)) = hard_conflict(pass, a, b) {
        return PairVerdict::Conflict { conflict, reason };
    }
    if tier_on(pass, Tier::RevisionLabel) && revision_linked(pass, a, b) {
        return PairVerdict::Merge {
            tier: Tier::RevisionLabel,
            reason: "a revision label links the two claims".to_string(),
        };
    }
    if strong_ids_conflict(a, b) {
        return PairVerdict::Conflict {
            conflict: ConflictKind::StrongIdVeto,
            reason: format!(
                "distinct strong ids {:?} vs {:?}",
                a.keys.strong_ids, b.keys.strong_ids
            ),
        };
    }
    classify_tiers(pass, a, b)
}

/// Classify a pair as if no veto or hard conflict existed. The probe uses it
/// to name the members a veto kept a candidate apart from.
#[must_use]
pub fn classify_pair_ignoring_conflicts(
    pass: &PassProfile,
    a: &ParsedRecord,
    b: &ParsedRecord,
) -> PairVerdict {
    if tier_on(pass, Tier::RevisionLabel) && revision_linked(pass, a, b) {
        return PairVerdict::Merge {
            tier: Tier::RevisionLabel,
            reason: "a revision label links the two claims".to_string(),
        };
    }
    classify_tiers(pass, a, b)
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
    if let Some((conflict, _)) = hard_conflict(pass, a, b) {
        return Some(conflict);
    }
    let revision = tier_on(pass, Tier::RevisionLabel) && revision_linked(pass, a, b);
    (strong_ids_conflict(a, b) && !revision).then_some(ConflictKind::StrongIdVeto)
}

fn tier_on(pass: &PassProfile, tier: Tier) -> bool {
    pass.tiers.contains(&tier)
}

fn strong_ids_conflict(a: &ParsedRecord, b: &ParsedRecord) -> bool {
    !a.keys.strong_ids.is_empty()
        && !b.keys.strong_ids.is_empty()
        && a.keys.strong_ids.is_disjoint(&b.keys.strong_ids)
}

/// The shortest id prefix a `distinct-from:` ruling may use. A ruling vetoes
/// a merge, so a short prefix that names a large slice of the family would
/// silently split real duplicates; 8 hex digits name about one id in 4e9.
pub const MIN_DISTINCT_ID_PREFIX: usize = 8;

/// `<prefix><p>` on `from`, where `<p>` is a prefix of `to`'s id at least
/// `min_len` characters long.
fn names_by_prefix(
    prefix: Option<&str>,
    from: &ParsedRecord,
    to: &ParsedRecord,
    min_len: usize,
) -> bool {
    let Some(prefix) = prefix.filter(|p| !p.is_empty()) else {
        return false;
    };
    !to.id_str.is_empty()
        && from.labels.iter().any(|l| {
            l.strip_prefix(prefix)
                .is_some_and(|p| !p.is_empty() && p.len() >= min_len && to.id_str.starts_with(p))
        })
}

/// The shortest id prefix a revision label may use. A revision link
/// auto-merges and overrides the strong-id veto, so it must name its claim as
/// precisely as a `distinct-from` ruling: a one-digit prefix would link the
/// labelled claim to one claim in sixteen.
pub const MIN_REVISION_ID_PREFIX: usize = MIN_DISTINCT_ID_PREFIX;

fn revision_linked(pass: &PassProfile, a: &ParsedRecord, b: &ParsedRecord) -> bool {
    let p = pass.revision_label_prefix.as_deref();
    names_by_prefix(p, a, b, MIN_REVISION_ID_PREFIX)
        || names_by_prefix(p, b, a, MIN_REVISION_ID_PREFIX)
}

fn label_values<'a>(
    record: &'a ParsedRecord,
    prefix: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    record
        .labels
        .iter()
        .filter_map(move |l| l.strip_prefix(prefix))
}

fn hard_conflict(
    pass: &PassProfile,
    a: &ParsedRecord,
    b: &ParsedRecord,
) -> Option<(ConflictKind, String)> {
    let distinct = pass.distinct_label_prefix.as_deref();
    if names_by_prefix(distinct, a, b, MIN_DISTINCT_ID_PREFIX)
        || names_by_prefix(distinct, b, a, MIN_DISTINCT_ID_PREFIX)
    {
        return Some((
            ConflictKind::DistinctLabel,
            "a human ruled the two distinct".to_string(),
        ));
    }
    for prefix in &pass.partition.must_agree_label_prefixes {
        let va: BTreeSet<&str> = label_values(a, prefix).collect();
        let vb: BTreeSet<&str> = label_values(b, prefix).collect();
        if !va.is_empty() && !vb.is_empty() && va.is_disjoint(&vb) {
            return Some((
                ConflictKind::PartitionMismatch {
                    prefix: prefix.clone(),
                },
                format!("{prefix} {va:?} vs {vb:?}"),
            ));
        }
    }
    let share_strong = !a.keys.strong_ids.is_disjoint(&b.keys.strong_ids);
    for label in &pass.partition.no_merge_without_strong_id_label_values {
        let (ha, hb) = (a.has_label(label), b.has_label(label));
        if ha != hb && !share_strong {
            return Some((
                ConflictKind::NoStrongIdPartition {
                    label: label.clone(),
                },
                format!("{label} pairs across classes only through a shared strong id"),
            ));
        }
    }
    None
}

fn classify_tiers(pass: &PassProfile, a: &ParsedRecord, b: &ParsedRecord) -> PairVerdict {
    let shared_strong: Vec<&String> = a.keys.strong_ids.intersection(&b.keys.strong_ids).collect();
    if tier_on(pass, Tier::StrongId) && !shared_strong.is_empty() {
        return PairVerdict::Merge {
            tier: Tier::StrongId,
            reason: format!("shared strong id {}", join(&shared_strong)),
        };
    }
    let entity_ok = entities_match(
        pass,
        a.keys.entity_tokens.as_ref(),
        b.keys.entity_tokens.as_ref(),
    );
    let shared_any: Vec<&String> = a.keys.all_ids.intersection(&b.keys.all_ids).collect();
    if tier_on(pass, Tier::WeakIdAndEntity) && entity_ok && !shared_any.is_empty() {
        return PairVerdict::Merge {
            tier: Tier::WeakIdAndEntity,
            reason: format!("shared id {} plus matching entity", join(&shared_any)),
        };
    }
    let (ka, kb) = (&a.keys.title_key, &b.keys.title_key);
    if tier_on(pass, Tier::TitleAndEntity) && entity_ok && !ka.is_empty() && ka == kb {
        return PairVerdict::Merge {
            tier: Tier::TitleAndEntity,
            reason: "identical normalized title and matching entity".to_string(),
        };
    }
    let (ta, tb) = (&a.keys.title_tokens, &b.keys.title_tokens);
    let min = pass.title_match.fuzzy_min_tokens;
    if tier_on(pass, Tier::FuzzyReview) && entity_ok && ta.len() >= min && tb.len() >= min {
        let overlap = overlap_coefficient(ta, tb);
        if overlap >= pass.title_match.fuzzy_threshold {
            return PairVerdict::Review {
                overlap,
                reason: format!(
                    "title overlap {overlap:.2} with matching entity, no corroborating id"
                ),
            };
        }
    }
    PairVerdict::NoMatch
}

fn join(ids: &[&String]) -> String {
    ids.iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}
