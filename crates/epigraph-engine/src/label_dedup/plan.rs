//! Plan assembly: hygiene, constrained clustering, survivor precedence, carry
//! labels, close-out, lifecycle, the signal passes, write units and the plan
//! hash.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use serde::Serialize;
use uuid::Uuid;

use super::classify::{classify_pair, cluster_conflict, hygiene_reason, ConflictKind, PairVerdict};
use super::profile::{
    expand, label_problem, Bindings, LabelDedupProfile, PassProfile, SupersedeMatch, TieBreak, Tier,
};
use super::record::{parse_record, unknown_count, ParsedRecord};
use super::{iso_prefix_date, DedupClaim, LabelDedupError, Section, Snapshot};

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
        let mut units = Vec::new();
        push_hygiene_units(&mut units, "hygiene", &self.hygiene);
        push_cluster_units(&mut units, "cluster", &self.clusters);
        for p in &self.past_due {
            push_unit(
                &mut units,
                format!("closeout:{}", p.id),
                vec![write(p.id, &p.add, &[])],
            );
        }
        for a in &self.lifecycle {
            push_unit(
                &mut units,
                format!("lifecycle:{}", a.id),
                vec![write(a.id, &a.add, &[])],
            );
        }
        if let Some(sd) = &self.signal_dedup {
            push_hygiene_units(&mut units, "signal_hygiene", &sd.hygiene);
            push_cluster_units(&mut units, "signal_cluster", &sd.clusters);
        }
        for s in &self.signal_superseded {
            push_unit(
                &mut units,
                format!("signal_superseded:{}", s.id),
                vec![write(s.id, &s.add, &s.remove)],
            );
        }
        units
    }

    /// Whether applying the plan would write nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.write_units().is_empty()
    }

    /// The reason apply must refuse this plan before writing, if any.
    #[must_use]
    pub fn apply_refusal(&self) -> Option<LabelDedupError> {
        self.coverage
            .truncated
            .then_some(LabelDedupError::Truncated)
    }
}

fn write(claim_id: Uuid, add: &[String], remove: &[String]) -> LabelWrite {
    LabelWrite {
        claim_id,
        add: add.to_vec(),
        remove: remove.to_vec(),
    }
}

fn push_unit(units: &mut Vec<WriteUnit>, unit: String, writes: Vec<LabelWrite>) {
    let writes: Vec<LabelWrite> = writes
        .into_iter()
        .filter(|w| !w.add.is_empty() || !w.remove.is_empty())
        .collect();
    if !writes.is_empty() {
        units.push(WriteUnit { unit, writes });
    }
}

fn push_hygiene_units(units: &mut Vec<WriteUnit>, kind: &str, items: &[HygieneItem]) {
    for h in items {
        push_unit(
            units,
            format!("{kind}:{}", h.id),
            vec![write(h.id, &h.add, &h.remove)],
        );
    }
}

fn push_cluster_units(units: &mut Vec<WriteUnit>, kind: &str, clusters: &[Cluster]) {
    for c in clusters {
        let mut writes = vec![write(c.survivor, &c.survivor_add, &c.survivor_remove)];
        writes.extend(c.members.iter().map(|m| write(m.id, &m.add, &m.remove)));
        push_unit(units, format!("{kind}:{}", c.survivor), writes);
    }
}

/// The plan hash: BLAKE3 over a canonical JSON document of the inputs that
/// define the writes and the writes themselves.
///
/// BLAKE3 rather than SHA-256 because the profile hash it covers is BLAKE3
/// already and the hash is opaque: apply recomputes it server-side from the
/// same inputs. Sections are normalized first, so their order never drifts it.
#[must_use]
pub fn compute_plan_hash(
    profile_hash: &str,
    run_tag: &str,
    as_of: Option<NaiveDate>,
    sections: &[Section],
    units: &[WriteUnit],
) -> String {
    #[derive(Serialize)]
    struct HashDoc<'a> {
        schema: &'static str,
        profile_hash: &'a str,
        run_tag: &'a str,
        as_of: Option<String>,
        sections: Vec<Section>,
        units: &'a [WriteUnit],
    }
    let doc = HashDoc {
        schema: "label-dedup-plan-hash/v1",
        profile_hash,
        run_tag,
        as_of: as_of.map(|d| d.format("%Y-%m-%d").to_string()),
        sections: Section::normalize(sections),
        units,
    };
    // Serializing a struct of strings, dates and vectors cannot fail.
    let bytes = serde_json::to_vec(&doc).unwrap_or_default();
    epigraph_crypto::ContentHasher::to_hex(&epigraph_crypto::ContentHasher::hash(&bytes))
}

/// Build the plan.
///
/// # Errors
/// [`LabelDedupError::InvalidRunTag`], [`LabelDedupError::AsOfRequired`],
/// [`LabelDedupError::SectionNotConfigured`], [`LabelDedupError::InputMissing`]
/// or [`LabelDedupError::InvalidLabel`] (a templated label that is not a
/// valid label after expansion).
pub fn plan(req: &PlanRequest<'_>, inputs: &PlanInputs) -> Result<Plan, LabelDedupError> {
    validate_run_tag(req.run_tag)?;
    let sections = Section::normalize(req.sections);
    let profile = req.profile;
    for s in &sections {
        profile.require_section(*s)?;
    }
    let has = |s: Section| sections.contains(&s);
    for s in [Section::Closeout, Section::Lifecycle] {
        if has(s) && req.as_of.is_none() {
            return Err(LabelDedupError::AsOfRequired { section: s });
        }
    }

    let main = run_pass(
        &profile.pass,
        &inputs.members.claims,
        req.run_tag,
        has(Section::Hygiene),
        has(Section::Dedup),
        profile
            .closeout
            .as_ref()
            .map_or("deadline", |c| c.date_field.as_str()),
    )?;

    let mut coverage = Coverage {
        members: inputs.members.claims.len(),
        truncated: inputs.members.truncated,
        ..Coverage::default()
    };
    for (snap, slot) in [
        (inputs.lifecycle_signals.as_ref(), &mut coverage.signals),
        (inputs.lifecycle_targets.as_ref(), &mut coverage.targets),
        (inputs.signal_members.as_ref(), &mut coverage.signal_members),
    ] {
        if let Some(snap) = snap {
            *slot = Some(snap.claims.len());
            coverage.truncated |= snap.truncated;
        }
    }

    let mut plan = Plan {
        plan_hash: String::new(),
        profile_hash: req.profile_hash.to_string(),
        run_tag: req.run_tag.to_string(),
        as_of: req.as_of,
        sections: sections.clone(),
        coverage,
        hygiene: main.hygiene.clone(),
        clusters: main.clusters.clone(),
        review_pairs: main.review_pairs.clone(),
        vetoed_chains: main.vetoed_chains.clone(),
        past_due: Vec::new(),
        lifecycle: Vec::new(),
        signal_dedup: None,
        signal_superseded: Vec::new(),
    };
    plan.plan_hash = compute_plan_hash(
        req.profile_hash,
        req.run_tag,
        req.as_of,
        &sections,
        &plan.write_units(),
    );
    Ok(plan)
}

fn validate_run_tag(tag: &str) -> Result<(), LabelDedupError> {
    if tag.chars().any(char::is_whitespace) {
        return Err(LabelDedupError::InvalidRunTag(format!(
            "{tag:?} contains whitespace"
        )));
    }
    if tag.chars().count() > 200 {
        return Err(LabelDedupError::InvalidRunTag(
            "longer than 200 characters".to_string(),
        ));
    }
    match label_problem(tag) {
        Some(p) => Err(LabelDedupError::InvalidRunTag(format!("{tag:?}: {p}"))),
        None => Ok(()),
    }
}

/// Expand templates and check every result is a writable label.
fn expand_all(templates: &[String], b: &Bindings<'_>) -> Result<Vec<String>, LabelDedupError> {
    let mut out: Vec<String> = Vec::with_capacity(templates.len());
    for t in templates {
        let label = expand(t, b);
        if let Some(reason) = label_problem(&label) {
            return Err(LabelDedupError::InvalidLabel {
                label,
                reason: reason.to_string(),
            });
        }
        if !out.contains(&label) {
            out.push(label);
        }
    }
    Ok(out)
}

// ── One dedup pass over one family ─────────────────────────────────────────

/// The result of one pass: what the plan reports, plus the post-plan state
/// later stages read.
#[derive(Debug, Clone, Default)]
pub(crate) struct PassResult {
    /// Live members (not closed, not hygiene), sorted by id.
    pub records: Vec<ParsedRecord>,
    pub hygiene: Vec<HygieneItem>,
    pub hygiene_ids: BTreeSet<Uuid>,
    pub clusters: Vec<Cluster>,
    pub review_pairs: Vec<ReviewPair>,
    pub vetoed_chains: Vec<VetoedChain>,
    /// Loser → survivor.
    pub loser_of: BTreeMap<Uuid, Uuid>,
    /// Survivor → the members of its cluster (survivor included).
    pub cluster_of: BTreeMap<Uuid, Vec<Uuid>>,
    /// Survivor → ids it gains through carry labels.
    pub carried_ids: BTreeMap<Uuid, BTreeSet<String>>,
}

struct Edge {
    a: usize,
    b: usize,
    tier: Tier,
    reason: String,
}

/// `date_field` is the field close-out judges by; the stranded-date check
/// watches it.
pub(crate) fn run_pass(
    pass: &PassProfile,
    claims: &[DedupClaim],
    run_tag: &str,
    emit_hygiene: bool,
    dedup: bool,
    date_field: &str,
) -> Result<PassResult, LabelDedupError> {
    let bind = Bindings {
        run_tag,
        family: &pass.family_label,
        survivor: None,
        target: None,
    };
    let mut sorted: Vec<&DedupClaim> = claims.iter().collect();
    sorted.sort_by_key(|c| c.id);
    sorted.dedup_by_key(|c| c.id);

    let mut out = PassResult::default();
    for c in sorted {
        // A closed claim is neither a member nor hygiene: the member read
        // excludes it, and a stray one in a snapshot is left alone.
        if pass
            .closed_label
            .as_ref()
            .is_some_and(|l| c.labels.contains(l))
        {
            continue;
        }
        let rec = parse_record(pass, c);
        if let Some(reason) = hygiene_reason(pass, &rec) {
            out.hygiene_ids.insert(c.id);
            if emit_hygiene {
                let tpl = pass.hygiene_write.clone().unwrap_or_default();
                out.hygiene.push(HygieneItem {
                    id: c.id,
                    reason,
                    add: expand_all(&tpl.add, &bind)?,
                    remove: expand_all(&tpl.remove, &bind)?,
                });
            }
            continue;
        }
        out.records.push(rec);
    }
    if !dedup {
        return Ok(out);
    }

    let recs = &out.records;
    let n = recs.len();
    let mut edges: Vec<Edge> = Vec::new();
    let mut review_pairs = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            match classify_pair(pass, &recs[i], &recs[j]) {
                PairVerdict::Merge { tier, reason } => edges.push(Edge {
                    a: i,
                    b: j,
                    tier,
                    reason,
                }),
                PairVerdict::Review { overlap, reason } => review_pairs.push(ReviewPair {
                    left: rid(&recs[i]),
                    right: rid(&recs[j]),
                    left_title: recs[i].facts.title.clone(),
                    right_title: recs[j].facts.title.clone(),
                    left_entity: recs[i].facts.entity.clone(),
                    right_entity: recs[j].facts.entity.clone(),
                    overlap,
                    reason,
                }),
                PairVerdict::Conflict { .. } | PairVerdict::NoMatch => {}
            }
        }
    }
    // Strongest tier first, then the smaller id pair (records are id-sorted,
    // so index order is id order). Independent of input order by construction.
    edges.sort_by(|x, y| {
        y.tier
            .strength()
            .cmp(&x.tier.strength())
            .then(x.a.cmp(&y.a))
            .then(x.b.cmp(&y.b))
    });

    let mut dsu = Dsu::new(n);
    let mut vetoed = Vec::new();
    for e in &edges {
        let (ra, rb) = (dsu.find(e.a), dsu.find(e.b));
        if ra == rb {
            continue;
        }
        let conflict = dsu.members[ra].iter().find_map(|&x| {
            dsu.members[rb]
                .iter()
                .find_map(|&y| cluster_conflict(pass, &recs[x], &recs[y]).map(|c| (x, y, c)))
        });
        if let Some((x, y, conflict)) = conflict {
            vetoed.push(VetoedChain {
                ids: sorted_pair(rid(&recs[e.a]), rid(&recs[e.b])),
                tier: e.tier,
                boundary: sorted_pair(rid(&recs[x]), rid(&recs[y])),
                conflict,
            });
        } else {
            dsu.union(ra, rb);
        }
    }

    // Which component holds each id: an id held outside a cluster is never
    // carried onto it (it would merge a kept-apart claim on the next run).
    let mut holders: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();
    for (i, r) in recs.iter().enumerate() {
        for id in &r.keys.all_ids {
            holders
                .entry(id.as_str())
                .or_default()
                .insert(dsu.find_const(i));
        }
    }

    let mut components: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        components.entry(dsu.find_const(i)).or_default().push(i);
    }
    let mut clusters = Vec::new();
    for (root, idxs) in components.into_iter().filter(|(_, v)| v.len() >= 2) {
        let cluster = build_cluster(
            pass, recs, &edges, &dsu, &idxs, root, &holders, run_tag, date_field,
        )?;
        let survivor = cluster.survivor;
        for m in &cluster.members {
            out.loser_of.insert(m.id, survivor);
        }
        let mut all: Vec<Uuid> = idxs.iter().map(|i| rid(&recs[*i])).collect();
        all.sort();
        out.cluster_of.insert(survivor, all);
        let prefix = pass.ids.carry_label_prefix.as_deref().unwrap_or_default();
        let carried: BTreeSet<String> = cluster
            .carry_add
            .iter()
            .filter_map(|l| l.strip_prefix(prefix).filter(|_| !prefix.is_empty()))
            .map(str::to_string)
            .collect();
        if !carried.is_empty() {
            out.carried_ids.insert(survivor, carried);
        }
        clusters.push(cluster);
    }
    clusters.sort_by_key(|c| c.survivor);
    out.clusters = clusters;
    out.review_pairs = review_pairs;
    out.vetoed_chains = vetoed;
    Ok(out)
}

fn rid(r: &ParsedRecord) -> Uuid {
    r.id.unwrap_or_default()
}

fn sorted_pair(a: Uuid, b: Uuid) -> Vec<Uuid> {
    if a <= b {
        vec![a, b]
    } else {
        vec![b, a]
    }
}

/// A union-find that keeps each root's members sorted, so conflict checks
/// scan in a fixed order.
struct Dsu {
    parent: Vec<usize>,
    members: Vec<Vec<usize>>,
}

impl Dsu {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            members: (0..n).map(|i| vec![i]).collect(),
        }
    }

    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }

    fn find_const(&self, mut x: usize) -> usize {
        while self.parent[x] != x {
            x = self.parent[x];
        }
        x
    }

    fn union(&mut self, ra: usize, rb: usize) {
        let (keep, gone) = if ra < rb { (ra, rb) } else { (rb, ra) };
        self.parent[gone] = keep;
        let moved = std::mem::take(&mut self.members[gone]);
        self.members[keep].extend(moved);
        self.members[keep].sort_unstable();
    }
}

/// Survivor precedence, lower first: rank group, the profile's tie-breaks,
/// then the smallest id.
fn precedence_key(pass: &PassProfile, r: &ParsedRecord) -> (usize, usize) {
    let groups = &pass.precedence.rank_label_groups;
    let rank = groups
        .iter()
        .position(|g| g.iter().any(|l| r.labels.contains(l)))
        .unwrap_or(groups.len());
    (rank, unknown_count(pass, &r.facts))
}

fn precedence_cmp(pass: &PassProfile, a: &ParsedRecord, b: &ParsedRecord) -> Ordering {
    let (ra, ua) = precedence_key(pass, a);
    let (rb, ub) = precedence_key(pass, b);
    let mut ord = ra.cmp(&rb);
    for t in &pass.precedence.then {
        ord = ord.then_with(|| match t {
            TieBreak::FewestUnknown => ua.cmp(&ub),
            TieBreak::NewestCreatedAt => b.created_at.cmp(&a.created_at),
            TieBreak::SmallestId => rid(a).cmp(&rid(b)),
        });
    }
    ord.then_with(|| rid(a).cmp(&rid(b)))
}

/// Labels carrying `<stem>-carried:` dates on a record, as dates.
fn carried_dates(r: &ParsedRecord, prefix: &str) -> Vec<(String, NaiveDate)> {
    r.labels
        .iter()
        .filter_map(|l| {
            l.strip_prefix(prefix)
                .and_then(iso_prefix_date)
                .map(|d| (l.clone(), d))
        })
        .collect()
}

fn carry_prefix(pass: &PassProfile, field: &str) -> String {
    let spec = match field {
        "entity" => Some(&pass.fields.entity),
        "deadline" => Some(&pass.fields.deadline),
        "value" => Some(&pass.fields.value),
        "class" => Some(&pass.fields.class),
        other => pass.fields.extra.get(other),
    };
    let stem = spec.and_then(|s| s.carry_label.as_deref()).unwrap_or(field);
    format!("{stem}-carried:")
}

/// A record's own date for `field`, and the later of that and any carried
/// date. `None` when the record has no date of its own and none carried.
fn effective_date(
    pass: &PassProfile,
    r: &ParsedRecord,
    field: &str,
) -> (Option<NaiveDate>, Option<NaiveDate>) {
    let own = r.facts.field(field).and_then(iso_prefix_date);
    let carried = carried_dates(r, &carry_prefix(pass, field))
        .into_iter()
        .map(|(_, d)| d)
        .max();
    (own, own.max(carried))
}

/// A value made safe to carry in a label: `$` dropped (the write path
/// refuses it), braces dropped, whitespace runs collapsed to `-`.
fn label_safe_value(v: &str) -> String {
    let cleaned: String = v
        .chars()
        .filter(|c| !matches!(c, '$' | '{' | '}'))
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join("-")
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_cluster(
    pass: &PassProfile,
    recs: &[ParsedRecord],
    edges: &[Edge],
    dsu: &Dsu,
    idxs: &[usize],
    root: usize,
    holders: &BTreeMap<&str, BTreeSet<usize>>,
    run_tag: &str,
    date_field: &str,
) -> Result<Cluster, LabelDedupError> {
    let merge = pass.merge.clone().unwrap_or_default();
    let mut ranked: Vec<&ParsedRecord> = idxs.iter().map(|i| &recs[*i]).collect();
    ranked.sort_by(|a, b| precedence_cmp(pass, a, b));
    let survivor = ranked[0];
    let survivor_id = rid(survivor);
    let survivor_str = survivor_id.to_string();
    let (rank, unknown) = precedence_key(pass, survivor);
    let survivor_rank_explain = format!(
        "rank={rank} unknown={unknown} created_at={} id={survivor_id}",
        survivor
            .created_at
            .map_or_else(|| "none".to_string(), |t| t.to_rfc3339())
    );
    let losers: Vec<&ParsedRecord> = ranked[1..].to_vec();

    // ── carry labels ──
    let mut carry_add: Vec<String> = Vec::new();
    let mut survivor_remove: Vec<String> = Vec::new();
    if let (true, Some(prefix)) = (merge.carry_ids, pass.ids.carry_label_prefix.as_deref()) {
        let have = &survivor.keys.all_ids;
        let mut add: BTreeSet<String> = BTreeSet::new();
        for l in &losers {
            for id in &l.keys.all_ids {
                let outside = holders
                    .get(id.as_str())
                    .is_some_and(|roots| roots.iter().any(|r| *r != root));
                if !have.contains(id) && !outside {
                    add.insert(format!("{prefix}{id}"));
                }
            }
        }
        carry_add.extend(add);
    }
    for field in &merge.carry_later_dates {
        let prefix = carry_prefix(pass, field);
        let (own, eff) = effective_date(pass, survivor, field);
        let Some(eff) = eff.filter(|_| own.is_some()) else {
            continue; // never invent a date for a survivor without one
        };
        let later = losers
            .iter()
            .filter_map(|l| effective_date(pass, l, field).1)
            .max();
        if let Some(later) = later.filter(|d| *d > eff) {
            carry_add.push(format!("{prefix}{}", later.format("%Y-%m-%d")));
            survivor_remove.extend(carried_dates(survivor, &prefix).into_iter().map(|(l, _)| l));
        }
    }
    for field in &merge.carry_missing {
        let prefix = carry_prefix(pass, field);
        let has_carried = survivor.labels.iter().any(|l| l.starts_with(&prefix));
        if survivor.facts.field(field).is_some() || has_carried {
            continue;
        }
        let from_loser = losers.iter().find_map(|l| {
            l.facts.field(field).map(str::to_string).or_else(|| {
                l.labels
                    .iter()
                    .find_map(|x| x.strip_prefix(&prefix).map(str::to_string))
            })
        });
        if let Some(v) = from_loser
            .map(|v| label_safe_value(&v))
            .filter(|v| !v.is_empty())
        {
            carry_add.push(format!("{prefix}{v}"));
        }
    }
    for l in &carry_add {
        if let Some(reason) = label_problem(l) {
            return Err(LabelDedupError::InvalidLabel {
                label: l.clone(),
                reason: reason.to_string(),
            });
        }
    }

    // ── conflicts a human should see ──
    let mut conflicts = Vec::new();
    let mut fields: Vec<&str> = vec!["class", "deadline", "entity"];
    fields.extend(pass.fields.extra.keys().map(String::as_str));
    for field in fields {
        let values: BTreeSet<&str> = ranked.iter().filter_map(|r| r.facts.field(field)).collect();
        if values.len() > 1 {
            conflicts.push(format!(
                "members disagree on {field}: {}",
                values.into_iter().collect::<Vec<_>>().join(" vs ")
            ));
        }
    }
    let mut stranded_due = false;
    if !merge.carry_later_dates.iter().any(|f| f == date_field) {
        let own = survivor.facts.field(date_field).and_then(iso_prefix_date);
        let later = losers
            .iter()
            .filter_map(|l| {
                l.facts
                    .field(date_field)
                    .and_then(iso_prefix_date)
                    .map(|d| (d, rid(l)))
            })
            .max_by(|x, y| x.0.cmp(&y.0).then_with(|| y.1.cmp(&x.1)));
        if let (Some(own), Some((later, loser))) = (own, later) {
            if later > own {
                stranded_due = true;
                conflicts.push(format!(
                    "stranded {date_field}: survivor has {own}, loser {loser} has {later}; \
                     the date is not carried, so a later close-out judges the survivor by {own}"
                ));
            }
        }
    }

    // ── writes ──
    let bind = Bindings {
        run_tag,
        family: &pass.family_label,
        survivor: Some(&survivor_str),
        target: None,
    };
    let mut survivor_add = expand_all(&merge.survivor_add, &bind)?;
    for l in &carry_add {
        if !survivor_add.contains(l) {
            survivor_add.push(l.clone());
        }
    }
    let loser_add = expand_all(&merge.loser_add, &bind)?;
    let loser_remove = expand_all(&merge.loser_remove, &bind)?;
    let mut members: Vec<ClusterMember> = losers
        .iter()
        .map(|l| {
            let li = recs.iter().position(|r| r.id == l.id).unwrap_or_default();
            let (tier, reason) = edges
                .iter()
                .find(|e| {
                    (e.a == li || e.b == li)
                        && dsu.find_const(e.a) == root
                        && dsu.find_const(e.b) == root
                })
                .map_or(
                    (Tier::TitleAndEntity, String::from("transitively clustered")),
                    |e| (e.tier, e.reason.clone()),
                );
            ClusterMember {
                id: rid(l),
                tier,
                reason,
                add: loser_add.clone(),
                remove: loser_remove.clone(),
            }
        })
        .collect();
    members.sort_by_key(|m| m.id);

    Ok(Cluster {
        survivor: survivor_id,
        survivor_rank_explain,
        members,
        conflicts,
        survivor_add,
        survivor_remove,
        carry_add,
        stranded_due,
    })
}
