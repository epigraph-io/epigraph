//! Plan assembly: hygiene, constrained clustering, survivor precedence, carry
//! labels, close-out, lifecycle, the signal passes, write units and the plan
//! hash.

use chrono::NaiveDate;
use serde::Serialize;
use uuid::Uuid;

use super::classify::ConflictKind;
use super::profile::{LabelDedupProfile, SupersedeMatch, Tier};
use super::{LabelDedupError, Section, Snapshot};

/// What to plan.
#[derive(Debug, Clone, Copy)]
pub struct PlanRequest<'a> {
    pub profile: &'a LabelDedupProfile,
    /// The pinned hash the profile was loaded under; covered by the plan hash.
    pub profile_hash: &'a str,
    /// Substituted into `{run_tag}`; must be a valid label.
    pub run_tag: &'a str,
    /// Required by close-out and lifecycle. Never defaulted to today.
    pub as_of: Option<NaiveDate>,
    /// Empty means [`Section::default_set`].
    pub sections: &'a [Section],
}

/// The reads named by [`LabelDedupProfile::reads`], as performed.
#[derive(Debug, Clone, Default)]
pub struct PlanInputs {
    pub members: Snapshot,
    pub lifecycle_signals: Option<Snapshot>,
    pub lifecycle_targets: Option<Snapshot>,
    pub signal_members: Option<Snapshot>,
}

/// How much was read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub members: usize,
    pub signals: Option<usize>,
    pub targets: Option<usize>,
    pub signal_members: Option<usize>,
    /// Any read hit its cap. Apply refuses such a plan.
    pub truncated: bool,
}

/// A claim that leaves the family without clustering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HygieneItem {
    pub id: Uuid,
    pub reason: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// A cluster loser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClusterMember {
    pub id: Uuid,
    /// The tier of the first accepted edge (in processing order) touching it.
    pub tier: Tier,
    pub reason: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One item tracked by several members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cluster {
    pub survivor: Uuid,
    pub survivor_rank_explain: String,
    /// The losers, by id.
    pub members: Vec<ClusterMember>,
    /// Member disagreements a human should see.
    pub conflicts: Vec<String>,
    /// Survivor writes: `survivor_add` plus carry labels; `remove` replaces an
    /// older carried date.
    pub survivor_add: Vec<String>,
    pub survivor_remove: Vec<String>,
    /// The carry labels alone (a subset of `survivor_add`).
    pub carry_add: Vec<String>,
    /// A loser has a later date than the survivor and that date is not
    /// carried, so a later close-out would judge the survivor by its own date.
    pub stranded_due: bool,
}

/// A pair a human must decide.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewPair {
    pub left: Uuid,
    pub right: Uuid,
    pub left_title: String,
    pub right_title: String,
    pub left_entity: Option<String>,
    pub right_entity: Option<String>,
    pub overlap: f64,
    pub reason: String,
}

/// An auto-merge edge refused because joining its two components would put
/// a conflicting pair in one cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VetoedChain {
    /// The refused edge.
    pub ids: Vec<Uuid>,
    pub tier: Tier,
    /// The conflicting pair, one from each component.
    pub boundary: Vec<Uuid>,
    pub conflict: ConflictKind,
}

/// A live member whose deadline passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PastDue {
    pub id: Uuid,
    /// The date decided on (for a survivor, the latest across its cluster).
    pub due: NaiveDate,
    pub reason: String,
    pub add: Vec<String>,
}

/// Why a signal closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum LifecycleKind {
    Graduated { target: Uuid },
    AgedOut { key_date: NaiveDate },
}

/// One signal to close. Only adds labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleAction {
    pub id: Uuid,
    #[serde(flatten)]
    pub kind: LifecycleKind,
    pub add: Vec<String>,
}

/// The signal-family pass.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SignalDedupPlan {
    pub family_label: String,
    pub hygiene: Vec<HygieneItem>,
    pub clusters: Vec<Cluster>,
    pub review_pairs: Vec<ReviewPair>,
    pub vetoed_chains: Vec<VetoedChain>,
}

/// A signal that became a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalSuperseded {
    pub id: Uuid,
    pub target: Uuid,
    pub matched_by: SupersedeMatch,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One label write.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct LabelWrite {
    pub claim_id: Uuid,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One transaction: all of it applies or none of it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteUnit {
    /// `hygiene:<id>`, `cluster:<survivor>`, `closeout:<id>`,
    /// `lifecycle:<id>`, `signal_hygiene:<id>`, `signal_cluster:<survivor>`,
    /// `signal_superseded:<id>`.
    pub unit: String,
    pub writes: Vec<LabelWrite>,
}

/// A complete plan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// Covers the profile hash, run tag, as_of, sections and the write units
    /// only, so a new review pair or veto never causes a spurious drift.
    pub plan_hash: String,
    pub profile_hash: String,
    pub run_tag: String,
    pub as_of: Option<NaiveDate>,
    pub sections: Vec<Section>,
    pub coverage: Coverage,
    pub hygiene: Vec<HygieneItem>,
    pub clusters: Vec<Cluster>,
    pub review_pairs: Vec<ReviewPair>,
    pub vetoed_chains: Vec<VetoedChain>,
    pub past_due: Vec<PastDue>,
    pub lifecycle: Vec<LifecycleAction>,
    pub signal_dedup: Option<SignalDedupPlan>,
    pub signal_superseded: Vec<SignalSuperseded>,
}

impl Plan {
    /// The write units in apply order: hygiene, clusters, close-out,
    /// lifecycle, signal hygiene, signal clusters, signal supersession.
    #[must_use]
    pub fn write_units(&self) -> Vec<WriteUnit> {
        Vec::new()
    }

    /// Whether applying the plan would write nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.write_units().is_empty()
    }

    /// The reason apply must refuse this plan before writing, if any.
    #[must_use]
    pub fn apply_refusal(&self) -> Option<LabelDedupError> {
        None
    }
}

/// The plan hash: BLAKE3 over a canonical JSON document of the inputs that
/// define the writes and the writes themselves.
#[must_use]
pub fn compute_plan_hash(
    profile_hash: &str,
    run_tag: &str,
    as_of: Option<NaiveDate>,
    sections: &[Section],
    units: &[WriteUnit],
) -> String {
    let _ = (profile_hash, run_tag, as_of, sections, units);
    String::new()
}

/// Build the plan.
///
/// # Errors
/// [`LabelDedupError::InvalidRunTag`], [`LabelDedupError::AsOfRequired`],
/// [`LabelDedupError::SectionNotConfigured`], [`LabelDedupError::InputMissing`]
/// or [`LabelDedupError::InvalidLabel`] (a templated label that is not a
/// valid label after expansion).
pub fn plan(req: &PlanRequest<'_>, inputs: &PlanInputs) -> Result<Plan, LabelDedupError> {
    let _ = inputs;
    Ok(Plan {
        plan_hash: String::new(),
        profile_hash: req.profile_hash.to_string(),
        run_tag: req.run_tag.to_string(),
        as_of: req.as_of,
        sections: Vec::new(),
        coverage: Coverage::default(),
        hygiene: Vec::new(),
        clusters: Vec::new(),
        review_pairs: Vec::new(),
        vetoed_chains: Vec::new(),
        past_due: Vec::new(),
        lifecycle: Vec::new(),
        signal_dedup: None,
        signal_superseded: Vec::new(),
    })
}
