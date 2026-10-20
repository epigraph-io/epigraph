//! Label-family deduplication: a pure, profile-driven planning engine.
//!
//! # What it is for
//!
//! Some claim families are kept as an *index*: every live member carries one
//! family label, and readers (digests, generators, dedup passes) query that
//! label. Independent writers re-file the same real-world item, in different
//! text layouts, so the index accumulates duplicates, retired items that kept
//! the family label, and bookkeeping claims that wear it by accident.
//!
//! This module plans the clean-up. It reads a snapshot of the family (plus,
//! optionally, a signal family and a graduation index), classifies every claim,
//! clusters duplicates, picks a survivor per cluster, and emits label writes:
//!
//! - **hygiene**: retired or bookkeeping claims leave the family;
//! - **dedup**: losers leave the family and point at their survivor; the
//!   survivor receives carry labels (`<prefix><ID>`, `<field>-carried:<value>`)
//!   so nothing a loser knew is lost, without rewriting claim content;
//! - **close-out**: members whose deadline has passed gain the closed label;
//! - **lifecycle**: signals that materialized as a member, or aged out, close;
//! - **signal passes**: a second family is deduplicated on its own and its
//!   members that became a family member leave the signal family.
//!
//! # Purity
//!
//! No I/O, no clock. `as_of` is an input, never `now()`. The caller (the MCP
//! tools) performs the reads named by [`LabelDedupProfile::reads`], applies the
//! returned [`WriteUnit`]s through the ordinary stamped label-write path, and
//! recomputes the plan before applying so a stale plan is refused.
//!
//! # No deployment data in code
//!
//! Every label, alias, stopword, marker and bucket list comes from the profile
//! and defaults to empty. The only built-in defaults are generic algorithm
//! knobs (thresholds, parser layout limits, tier order).
//!
//! # Determinism
//!
//! The same snapshot always yields the same plan and the same
//! [`Plan::plan_hash`], whatever order the claims arrive in: inputs are sorted
//! by id, every serialized collection is ordered, and clustering is a
//! constrained union-find over edges processed in a fixed order.

pub mod classify;
pub mod ids;
pub mod plan;
pub mod probe;
pub mod profile;
pub mod record;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use classify::{classify_pair, hygiene_reason, PairVerdict};
pub use ids::{extract_ids, IdToken};
pub use plan::{
    compute_plan_hash, plan, Cluster, ClusterMember, Coverage, HygieneItem, LabelWrite,
    LifecycleAction, LifecycleKind, PastDue, Plan, PlanInputs, PlanRequest, ReviewPair,
    SignalDedupPlan, SignalSuperseded, VetoedChain, WriteUnit,
};
pub use probe::{probe, ProbeCandidate, ProbeVerdict, ProbeVerdictKind, PROBE_MAX_CANDIDATES};
pub use profile::{profile_hash, LabelDedupProfile, PassProfile, ReadPurpose, ReadSpec};
pub use record::{parse_record, Facts, MatchKeys, ParsedRecord};

/// The claim view the engine needs, and nothing else: no truth value, no
/// evidence, no owner. Built by the caller from a viewer-scoped read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupClaim {
    pub id: Uuid,
    pub content: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

/// One family read, already capped by the caller.
///
/// Build it with [`Snapshot::from_capped`] from a read of `cap + 1` rows, so
/// a family larger than the cap is *reported* as truncated rather than
/// silently planned on a prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub claims: Vec<DedupClaim>,
    pub truncated: bool,
}

impl Snapshot {
    /// Sort `rows` by id, keep the first `cap`, and flag truncation when more
    /// than `cap` rows were supplied.
    #[must_use]
    pub fn from_capped(mut rows: Vec<DedupClaim>, cap: usize) -> Self {
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        rows.dedup_by(|a, b| a.id == b.id);
        let truncated = rows.len() > cap;
        rows.truncate(cap);
        Self {
            claims: rows,
            truncated,
        }
    }
}

/// A plan section. Serialized in `snake_case`; ordered so a section list can
/// be normalized (sorted, de-duplicated) before it is hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Hygiene,
    Dedup,
    Closeout,
    Lifecycle,
    SignalDedup,
}

impl Section {
    /// The sections planned when the caller names none.
    #[must_use]
    pub fn default_set() -> Vec<Self> {
        vec![Self::Hygiene, Self::Dedup]
    }

    /// Sort and de-duplicate, so `[dedup, hygiene]` and `[hygiene, dedup,
    /// dedup]` hash identically. An empty list means [`Section::default_set`].
    #[must_use]
    pub fn normalize(sections: &[Self]) -> Vec<Self> {
        if sections.is_empty() {
            return Self::default_set();
        }
        let mut out = sections.to_vec();
        out.sort();
        out.dedup();
        out
    }
}

/// Refusals. Each carries a stable machine code (see [`LabelDedupError::code`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LabelDedupError {
    #[error("PROFILE_HASH_MISMATCH: expected {expected}, profile bytes hash to {actual}")]
    ProfileHashMismatch { expected: String, actual: String },
    #[error("PROFILE_SCHEMA_INVALID: {0}")]
    ProfileSchemaInvalid(String),
    #[error("AS_OF_REQUIRED: section {section:?} needs an explicit as_of date")]
    AsOfRequired { section: Section },
    #[error("SECTION_NOT_CONFIGURED: section {section:?} has no configuration in the profile")]
    SectionNotConfigured { section: Section },
    #[error("INPUT_MISSING: the plan needs the {purpose:?} read")]
    InputMissing { purpose: ReadPurpose },
    #[error("INVALID_RUN_TAG: {0}")]
    InvalidRunTag(String),
    #[error("INVALID_LABEL: {label:?}: {reason}")]
    InvalidLabel { label: String, reason: String },
    #[error("TRUNCATED: a family read hit its cap; refusing to apply a plan built on a prefix")]
    Truncated,
    #[error("TOO_MANY_CANDIDATES: {got} candidates, at most {max} per call")]
    TooManyCandidates { got: usize, max: usize },
}

impl LabelDedupError {
    /// The stable code a tool surfaces to its caller.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ProfileHashMismatch { .. } => "PROFILE_HASH_MISMATCH",
            Self::ProfileSchemaInvalid(_) => "PROFILE_SCHEMA_INVALID",
            Self::AsOfRequired { .. } => "AS_OF_REQUIRED",
            Self::SectionNotConfigured { .. } => "SECTION_NOT_CONFIGURED",
            Self::InputMissing { .. } => "INPUT_MISSING",
            Self::InvalidRunTag(_) => "INVALID_RUN_TAG",
            Self::InvalidLabel { .. } => "INVALID_LABEL",
            Self::Truncated => "TRUNCATED",
            Self::TooManyCandidates { .. } => "TOO_MANY_CANDIDATES",
        }
    }
}

/// Lowercase, collapse every non-alphanumeric run to one space, trim.
#[must_use]
pub fn normalize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.extend(ch.to_lowercase());
        } else {
            pending_space = true;
        }
    }
    out
}

/// `|A ∩ B| / min(|A|, |B|)`, or 0 when either set is empty.
///
/// Preferred over Jaccard because item titles differ widely in length, and
/// because it lets a sub-unit match its parent (`{acme}` vs `{acme, labs}`).
#[must_use]
pub fn overlap_coefficient(
    a: &std::collections::BTreeSet<String>,
    b: &std::collections::BTreeSet<String>,
) -> f64 {
    let smaller = a.len().min(b.len());
    if smaller == 0 {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    #[allow(clippy::cast_precision_loss)]
    {
        inter as f64 / smaller as f64
    }
}

/// The ISO date a field value BEGINS with, if any. `unknown`, `TBD` and prose
/// dates yield `None`: nothing in this engine infers a date. `get(..10)`, not
/// `[..10]`: a prose value can put a multi-byte character across byte 10.
#[must_use]
pub fn iso_prefix_date(value: &str) -> Option<NaiveDate> {
    let head = value.trim().get(..10)?;
    NaiveDate::parse_from_str(head, "%Y-%m-%d").ok()
}
