//! Same-source dependence in BBA combination (backlog 4c42c0bf).
//!
//! Dempster's rule assumes every BBA it folds is an INDEPENDENT source. A
//! re-worded re-observation of the same page by the same agent is not: it is
//! one source read twice, and folding it as independent raises belief on every
//! repeat (claim fc5e6a60 went 0.672 -> 0.768 on a "still listed, nothing
//! changed" re-sighting). `update_with_evidence` refuses only a byte-identical
//! `evidence_data`, so the combine step is where this has to be answered.
//!
//! The rule here: BBAs that share a [`SourceKey`] — the same source agent AND
//! the same evidence `source_url` — and say the same thing (one simple-support
//! focal element) are folded with Denoeux's cautious rule
//! ([`combination::cautious_combine`]) into ONE BBA before the Dempster fold.
//! The cautious rule is idempotent, so N copies of one source's verdict carry
//! exactly the weight of one (the strongest of them). A source that changes
//! its verdict is changed content, not a repeat, and folds as before.
//!
//! What it deliberately does NOT key on:
//! - the agent alone. `report_workflow_outcome` reports every execution of a
//!   workflow through the same agent, and those are distinct trials; an edge
//!   auto-wire from N distinct source claims by one ingesting agent is N
//!   sources. A BBA whose evidence carries no `source_url` has no key and is
//!   folded as independent, exactly as before.
//! - provenance LCA between agents. Dependence between DIFFERENT agents is
//!   decided by who they act for instead: the same-human rule (ruling R-36,
//!   [`combine_with_owner_dependence`]), which also replaced the LCA test of
//!   the REST `routes/independence.rs` analysis.
//!
//! Every combine of stored BBAs goes through [`combine_with_owner_dependence`]
//! (the same-source rule plus the same-human rule): the MCP writes
//! (`ds_auto::auto_wire_ds_update`), the recompute
//! (`edge_factor::compute_combined_belief`, behind MCP `submit_ds_evidence`,
//! REST `POST /frames/:id/evidence` and every cache refresh) and the
//! compute-on-read readers (`belief_query::combine_framed_bbas`, behind framed
//! `get_belief`, `get_perspective_belief` and its batch). For a viewer who can
//! see the evidence rows its BBAs reference, the next recompute therefore
//! cannot re-inflate what the write left honest, and those readers agree with
//! the cache. The atom fold (`atom_items`) still calls
//! [`combine_with_source_dependence`] for its legacy-grouping comparison.
//!
//! Source keys are read through the caller's viewer
//! ([`source_keys_for_rows`]). A BBA can be visible while its evidence row is
//! not: `epigraph-operator hide-evidence` narrows evidence to a private group
//! and leaves `mass_functions.evidence_id` pointing at it (`epigraph-cli`
//! `operator/hide.rs`; migration 110 keeps the narrowing in place). For
//! a viewer who cannot see that evidence row, the BBA has no key and folds as
//! independent, as it did before this rule; a recompute run under such a
//! viewer can write that pre-rule value into the cache.
//!
//! Known limits of the URL key ([`normalize_source_url`]): query strings,
//! fragments and the scheme are kept, so one page reached through different
//! tracking parameters, `#anchors`, or `http` vs `https` counts as distinct
//! sources and still corroborates; those misses err toward the pre-fix
//! behaviour. The path is lowercased, which goes the other way: two URLs that
//! differ only in the case of a case-sensitive path are MERGED into one
//! source, a deliberate under-count of corroboration in exchange for catching
//! the common case-variant repeat.

use std::collections::HashMap;

use uuid::Uuid;

use epigraph_core::domain::evidence::is_placeholder_id;
use epigraph_db::{EvidenceRepository, MassFunctionRow};
use epigraph_ds::{combination, DsError, FocalElement, MassFunction};

/// Frames larger than this are folded without the cautious pass: the rule
/// walks the power set twice (`O(4^n)`), and every BBA that can carry a
/// [`SourceKey`] today is written on the two-hypothesis `binary_truth` frame.
/// A computational guard, not a belief parameter: below it the result is the
/// cautious fold, above it the cost bound applies.
// belief-profile: allow-literal (O(4^n) complexity guard, never binds on keyed BBAs today)
const MAX_CAUTIOUS_HYPOTHESES: usize = 8;

/// Identity of an evidence source for the dependence test: the agent that
/// wrote the BBA and the normalized `source_url` of the evidence it came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceKey {
    pub agent_id: Uuid,
    pub source_url: String,
}

/// Normalize a `source_url` for the dependence test: trimmed, trailing `/`
/// removed, ASCII-lowercased. Lowercasing a case-sensitive path can only MERGE
/// two distinct URLs into one source, which errs toward under-counting a
/// corroboration rather than over-counting a repeat. `None` for a blank URL.
#[must_use]
pub fn normalize_source_url(url: &str) -> Option<String> {
    let t = url.trim().trim_end_matches('/');
    if t.is_empty() {
        None
    } else {
        Some(t.to_ascii_lowercase())
    }
}

/// The [`SourceKey`] of each row, in row order. A row has a key only when it
/// names both a source agent and an evidence row whose `source_url` is set and
/// visible to `viewer`. A row whose evidence `viewer` cannot see (a hidden
/// evidence row, see the module docs) has no key and folds as independent.
///
/// Read on the caller's executor, through `viewer`, so the write path's
/// stamped transaction, the recompute's connection and the compute-on-read
/// readers' pool (`crate::belief_query`) each see the evidence rows their own
/// BBAs reference. One query, and none at all when no row can carry a key.
///
/// # Errors
/// `DbError` if the evidence read fails.
pub async fn source_keys_for_rows<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    viewer: &epigraph_db::visibility::Viewer,
    rows: &[MassFunctionRow],
) -> Result<Vec<Option<SourceKey>>, epigraph_db::DbError> {
    let evidence_ids: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.source_agent_id.is_some())
        .filter_map(|r| r.evidence_id)
        .collect();
    let urls: HashMap<Uuid, String> = if evidence_ids.is_empty() {
        HashMap::new()
    } else {
        EvidenceRepository::source_urls_by_id(executor, viewer, &evidence_ids).await?
    };
    Ok(rows
        .iter()
        .map(|r| {
            let agent_id = r.source_agent_id?;
            let url = urls.get(&r.evidence_id?)?;
            Some(SourceKey {
                agent_id,
                source_url: normalize_source_url(url)?,
            })
        })
        .collect())
}

/// The one non-Θ focal element of a simple-support BBA, or `None` when `m` is
/// not a simple support function the cautious rule can take: non-classical
/// (complement / open-world mass, which `cautious_combine` does not model), on
/// a frame larger than [`MAX_CAUTIOUS_HYPOTHESES`], vacuous, or carrying more
/// than one non-Θ focal element (legacy mixed BBAs, or conflict mass).
fn simple_support_focus(m: &MassFunction) -> Option<FocalElement> {
    if !m.is_classical() || m.frame().hypothesis_count() > MAX_CAUTIOUS_HYPOTHESES {
        return None;
    }
    let theta = FocalElement::theta(m.frame());
    let mut non_theta = m.focal_elements().filter(|(fe, _)| **fe != theta);
    let (focus, _) = non_theta.next()?;
    if non_theta.next().is_some() {
        return None;
    }
    Some(focus.clone())
}

/// Combine already-discounted BBAs, folding same-source repeats cautiously first.
///
/// `items` pairs each discounted BBA with its [`SourceKey`] (`None` = no
/// source identity, treated as independent). BBAs that share a key AND point
/// at the same focal element (the same source saying the same thing again) are
/// reduced to one by the cautious rule; for simple support functions on one
/// focal set the min-commonality fold IS Denoeux's cautious rule, i.e. the
/// strongest of the repeats. Everything else — unkeyed BBAs, a source that
/// changed its verdict (a different focal element), and BBAs that are not
/// simple support functions (see [`simple_support_focus`]) — is passed to
/// [`combination::combine_multiple`] as its own input, exactly as before.
///
/// A source that flips (supports, then refutes) is therefore folded as it was
/// on main: the cautious min-commonality rule would turn the refutation into
/// empty-set mass and normalise most of it away.
///
/// Returns the combined BBA and the conflict the fold saw: the single BBA's
/// own empty-set mass when one remains, [`combination::fold_conflict`]
/// otherwise — the same two arms both callers used before.
///
/// # Errors
/// Propagates `DsError` from the cautious or Dempster fold, including
/// `combine_multiple`'s error when `items` is empty.
pub fn combine_with_source_dependence(
    items: Vec<(Option<SourceKey>, MassFunction)>,
    conflict_threshold: f64,
) -> Result<(MassFunction, f64), DsError> {
    dempster_across_items(same_source_slots(items)?, conflict_threshold)
}

/// The same-source reduction of [`combine_with_source_dependence`], before
/// its Dempster fold: one BBA per (source, focal element) slot plus every
/// unkeyed or non-simple-support BBA on its own, in first-appearance order.
fn same_source_slots(
    items: Vec<(Option<SourceKey>, MassFunction)>,
) -> Result<Vec<MassFunction>, DsError> {
    // One slot per (source, focal element), in first-appearance order so the
    // fold input is deterministic (both rules are order-independent; logs and
    // float rounding are not). Anything without a group key is its own slot.
    type GroupKey = (SourceKey, FocalElement);
    enum Slot {
        Grouped(GroupKey),
        Alone(MassFunction),
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut groups: HashMap<GroupKey, Vec<MassFunction>> = HashMap::new();
    for (key, mf) in items {
        let group_key = key.and_then(|k| simple_support_focus(&mf).map(|f| (k, f)));
        match group_key {
            Some(gk) => {
                let members = groups.entry(gk.clone()).or_default();
                if members.is_empty() {
                    slots.push(Slot::Grouped(gk));
                }
                members.push(mf);
            }
            None => slots.push(Slot::Alone(mf)),
        }
    }

    let mut for_fold: Vec<MassFunction> = Vec::with_capacity(slots.len());
    for slot in slots {
        match slot {
            Slot::Alone(mf) => for_fold.push(mf),
            Slot::Grouped(gk) => {
                let mut it = groups.remove(&gk).unwrap_or_default().into_iter();
                if let Some(first) = it.next() {
                    let folded =
                        it.try_fold(first, |acc, m| combination::cautious_combine(&acc, &m))?;
                    for_fold.push(folded);
                }
            }
        }
    }
    Ok(for_fold)
}

// ── Same-human dependence (ruling R-36, backlog fe3ec493) ──────────────────
//
// Ruling Q-U027F-2 (agents of one human replace or contest, never aggregate)
// was enforced only by `/claims/:id/assess`'s owner slot. R-36 extends it to
// every path that combines stored BBAs, at COMBINE time: the rows stay as
// written (history kept) and the fold decides what they are worth together.
//
// The reading implemented here, chosen so that R-36 and R-37 ("agent-only
// keying stays rejected") both hold:
//
// - WITHIN one agent nothing changes: its repeats of one `source_url` fold
//   cautiously ([`same_source_slots`]) and its distinct sources (distinct
//   evidence, workflow trials, edges from distinct source claims) reinforce
//   by Dempster, as before.
// - ACROSS distinct agents of ONE owner (the live human they resolve to,
//   `epigraph_human_of(agent, true)`, else the agent itself), BBAs that say
//   the same thing (one-sided on one focal element, see [`one_sided_focus`])
//   never multiply: each agent's own fold of its rows on that focal element
//   is one input, and the group keeps the STRONGEST input (the largest mass on
//   the focal element). For classical simple supports on one focal set that
//   is exactly Denoeux's cautious rule ([`combination::cautious_combine`] is
//   min-commonality, which there keeps the larger weight); for the open-world
//   one-sided BBAs `submit_ds_evidence` callers write (`{"0": x, "~": y}`),
//   which `cautious_combine` does not model, it is the same strongest-wins
//   rule SPEC §3.3's within-group partition ([`item_partition`]) uses. A
//   second agent of the same human agreeing therefore adds nothing.
// - A sibling that says the OPPOSITE (another focal element) is a contest:
//   its BBA stays a separate Dempster input, so the disagreement shows up as
//   conflict rather than being normalised away by the min-commonality rule.
// - An agent bound to no human is its own owner and has no sibling, so its
//   rows fold exactly as before. So does a row with no `source_agent_id`, and
//   a BBA that is not one-sided (mass on both a hypothesis and its rival, as
//   `/claims/:id/assess`'s directed BBAs carry, a complement focal element,
//   or conflict mass): no reduction that keeps both sides is defined here, so
//   those fold as independent. Known limit, recorded with the ruling.

/// The one focal element a ONE-SIDED BBA commits mass to: exactly one
/// positive focal element other than Θ carries mass, besides closed- and
/// open-world ignorance. `None` for anything else (vacuous, conflict mass,
/// another complement element, or mass on two non-Θ elements).
fn one_sided_focus(m: &MassFunction) -> Option<FocalElement> {
    let frame = m.frame();
    let mut focus: Option<&FocalElement> = None;
    for (fe, _) in m.focal_elements() {
        // Ignorance, closed (Θ) or open-world (`~`, which the JSON form
        // parses to the vacuous complement element, and the missing element).
        if fe.is_theta(frame) || fe.is_missing(frame) || fe.is_vacuous_element() {
            continue;
        }
        if fe.is_conflict() || fe.complement || focus.is_some() {
            return None;
        }
        focus = Some(fe);
    }
    focus.cloned()
}

/// Who a stored BBA speaks for: its writing agent, the owner that agent
/// resolves to, and its same-source key ([`SourceKey`]), if any.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BbaSource {
    /// `mass_functions.source_agent_id`.
    pub agent_id: Option<Uuid>,
    /// The live human `agent_id` acts for, else `agent_id` itself.
    pub owner_id: Option<Uuid>,
    /// The same-source key, when the row's evidence names a `source_url`.
    pub source: Option<SourceKey>,
}

impl From<Option<SourceKey>> for BbaSource {
    fn from(source: Option<SourceKey>) -> Self {
        Self::keyed(source)
    }
}

impl BbaSource {
    /// A source with no owner: only the same-source rule applies to it.
    #[must_use]
    pub fn keyed(source: Option<SourceKey>) -> Self {
        Self {
            agent_id: source.as_ref().map(|k| k.agent_id),
            owner_id: None,
            source,
        }
    }
}

/// The [`BbaSource`] of each row, in row order: [`source_keys_for_rows`]
/// plus each source agent's owner, read in one batched lookup
/// ([`epigraph_db::AgentRepository::humans_of`], live bindings only, as
/// `/claims/:id/assess` resolves its owner). An agent bound to no live human
/// is its own owner.
///
/// Both reads run on `conn` (a stamped transaction derefs to one), so a write
/// path's stamped transaction sees the evidence rows its own BBAs reference.
///
/// # Errors
/// `DbError` if a read fails.
pub async fn bba_sources_for_rows(
    conn: &mut sqlx::PgConnection,
    viewer: &epigraph_db::visibility::Viewer,
    rows: &[MassFunctionRow],
) -> Result<Vec<BbaSource>, epigraph_db::DbError> {
    let keys = source_keys_for_rows(&mut *conn, viewer, rows).await?;
    let agents: Vec<Uuid> = rows.iter().filter_map(|r| r.source_agent_id).collect();
    let humans = epigraph_db::AgentRepository::humans_of(&mut *conn, &agents, true).await?;
    Ok(rows
        .iter()
        .zip(keys)
        .map(|(r, source)| BbaSource {
            agent_id: r.source_agent_id,
            owner_id: r
                .source_agent_id
                .map(|a| humans.get(&a).copied().unwrap_or(a)),
            source,
        })
        .collect())
}

/// The inputs of the owner-aware fold, before its final Dempster step.
struct OwnerPartition {
    /// BBAs that fold as independent evidence: everything outside a sibling
    /// group, already reduced by the same-source rule.
    independent: Vec<MassFunction>,
    /// One group per (owner, focal element) that at least two distinct agents
    /// of that owner speak to, in first-appearance order: the focal element
    /// and, per agent, that agent's own fold of its rows on it (same-source
    /// rule, then Dempster).
    sibling_groups: Vec<(FocalElement, Vec<MassFunction>)>,
}

/// Split already-discounted BBAs into independent inputs and same-owner
/// sibling groups (see the section comment above for the rule).
fn owner_partition(
    items: Vec<(BbaSource, MassFunction)>,
    conflict_threshold: f64,
) -> Result<OwnerPartition, DsError> {
    type OwnerKey = (Uuid, FocalElement);
    let owner_key = |src: &BbaSource, mf: &MassFunction| -> Option<(OwnerKey, Uuid)> {
        let agent = src.agent_id?;
        let owner = src.owner_id?;
        one_sided_focus(mf).map(|f| ((owner, f), agent))
    };

    // Which (owner, focal element) keys have at least two distinct agents.
    let mut agents_per_key: HashMap<OwnerKey, Vec<Uuid>> = HashMap::new();
    for (src, mf) in &items {
        if let Some((k, agent)) = owner_key(src, mf) {
            let agents = agents_per_key.entry(k).or_default();
            if !agents.contains(&agent) {
                agents.push(agent);
            }
        }
    }

    // Per sibling key, per agent (both in first-appearance order), that
    // agent's rows on the key; everything else stays on the legacy path.
    let mut group_order: Vec<OwnerKey> = Vec::new();
    #[allow(clippy::type_complexity)]
    let mut groups: HashMap<OwnerKey, Vec<(Uuid, Vec<(Option<SourceKey>, MassFunction)>)>> =
        HashMap::new();
    let mut rest: Vec<(Option<SourceKey>, MassFunction)> = Vec::new();
    for (src, mf) in items {
        match owner_key(&src, &mf) {
            Some((k, agent)) if agents_per_key.get(&k).is_some_and(|a| a.len() > 1) => {
                let per_agent = groups.entry(k.clone()).or_insert_with(|| {
                    group_order.push(k);
                    Vec::new()
                });
                match per_agent.iter_mut().find(|(a, _)| *a == agent) {
                    Some((_, rows)) => rows.push((src.source, mf)),
                    None => per_agent.push((agent, vec![(src.source, mf)])),
                }
            }
            _ => rest.push((src.source, mf)),
        }
    }

    let mut sibling_groups = Vec::with_capacity(group_order.len());
    for k in group_order {
        let per_agent = groups.remove(&k).unwrap_or_default();
        let mut members = Vec::with_capacity(per_agent.len());
        for (_, rows) in per_agent {
            let (agent_fold, _) =
                dempster_across_items(same_source_slots(rows)?, conflict_threshold)?;
            members.push(agent_fold);
        }
        sibling_groups.push((k.1, members));
    }

    Ok(OwnerPartition {
        independent: same_source_slots(rest)?,
        sibling_groups,
    })
}

/// [`combine_with_source_dependence`] with the same-human rule (R-36): the
/// fold every combine of stored BBAs uses. Each sibling group keeps its
/// strongest member (the largest mass on the group's focal element; the
/// first such member on a tie), then everything is Dempster-folded. Same
/// return shape: the combined BBA and the conflict the fold saw.
///
/// # Errors
/// Propagates `DsError` from the Dempster folds, including
/// `combine_multiple`'s error when `items` is empty.
pub fn combine_with_owner_dependence(
    items: Vec<(BbaSource, MassFunction)>,
    conflict_threshold: f64,
) -> Result<(MassFunction, f64), DsError> {
    let OwnerPartition {
        mut independent,
        sibling_groups,
    } = owner_partition(items, conflict_threshold)?;
    for (focus, members) in sibling_groups {
        let mut strongest: Option<MassFunction> = None;
        for m in members {
            if strongest
                .as_ref()
                .is_none_or(|s| m.mass_of(&focus) > s.mass_of(&focus))
            {
                strongest = Some(m);
            }
        }
        independent.extend(strongest);
    }
    dempster_across_items(independent, conflict_threshold)
}

// ── Canonical item key (atom-level belief, SPEC §3.3) ──────────────────────
//
// The grouping the atom fold, the compound conjunction and the framed reads
// share once atom-level folding is switched on. It does not replace
// `SourceKey` / `combine_with_source_dependence`: the legacy fold keeps its
// (agent, source_url) key unchanged, and nothing on a served path calls the
// functions below yet.

/// `combination_method` of an attribution row: an original BBA's evidence
/// re-cited onto an atom (`perspective_id` = the original evidence id for a
/// text-bearing item, the original `mass_functions.id` for a textless one).
pub const ATTRIBUTED_METHOD: &str = "attributed_v1";
/// `combination_method` of an edge-factor row (`perspective_id` = edge id).
pub const EDGE_FACTOR_METHOD: &str = "edge_factor";
/// `combination_method` of an ingest self-assertion ("paper P asserts this
/// claim"), written by the ingest batch with no perspective and no evidence.
///
/// The row shape is NOT unique to ingest: `ds_auto::auto_wire_ds_for_claim`
/// (the creation BBA of `submit_claim` / `memorize` when the caller wrote no
/// evidence row) and `ds_auto::auto_wire_ds_batch` as called from workflow
/// ingest write the same method with NULL perspective and NULL evidence.
/// Only the caller's `asserting_paper` argument to [`item_key`] tells them
/// apart; see its contract there.
pub const INGEST_ASSERTION_METHOD: &str = "auto_wire";

/// The one canonical identity of a BBA row's evidential source.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ItemKey {
    /// `doi:<normalized doi>`. Agent-free.
    Doi(String),
    /// `url:<normalized source_url>`. Agent-free.
    Url(String),
    /// `ev:<evidence id>`: cited evidence with neither doi nor url.
    Evidence(Uuid),
    /// `attr:<original mf id>`: a textless attribution row.
    Attribution(Uuid),
    /// `edge:<edge id>`: an edge-factor row.
    Edge(Uuid),
    /// `paper:<asserting paper>`: a legacy ingest self-assertion. Agent-free.
    Paper(Uuid),
    /// `row:<mf id>`: no shared identity; the row is its own item.
    Row(Uuid),
}

impl std::fmt::Display for ItemKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Doi(d) => write!(f, "doi:{d}"),
            Self::Url(u) => write!(f, "url:{u}"),
            Self::Evidence(id) => write!(f, "ev:{id}"),
            Self::Attribution(id) => write!(f, "attr:{id}"),
            Self::Edge(id) => write!(f, "edge:{id}"),
            Self::Paper(id) => write!(f, "paper:{id}"),
            Self::Row(id) => write!(f, "row:{id}"),
        }
    }
}

/// The evidence row a BBA cites, as the caller's viewer sees it: the row's
/// `evidence_id`, or its `perspective_id` when that perspective is an
/// evidence perspective. `doi` is `properties->>'doi'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemEvidence {
    pub id: Uuid,
    pub doi: Option<String>,
    pub source_url: Option<String>,
}

/// Prefixes that turn a link or a label into a bare DOI, longest first;
/// matched case-insensitively. What reaches the evidence row: ingest persists
/// its document identifier bare in `properties.doi` (a DOI, an arXiv-style
/// id, a synthesized document key, or the document's URI when it has none of
/// those) and writes no `source_url` for literature; `source_url` holds what
/// other writers passed, which may be a doi.org link, a `doi:<id>` label (the
/// spelling ingest uses for a paper's label), any other link, or free text.
// belief-profile: allow-literal (array length of a fixed prefix list)
const DOI_PREFIXES: [&str; 7] = [
    "https://www.doi.org/",
    "http://www.doi.org/",
    "https://dx.doi.org/",
    "http://dx.doi.org/",
    "https://doi.org/",
    "http://doi.org/",
    "doi:",
];

/// Strip one [`DOI_PREFIXES`] entry, if `t` starts with one.
fn strip_doi_prefix(t: &str) -> Option<&str> {
    DOI_PREFIXES.iter().find_map(|p| {
        t.get(..p.len())
            .filter(|head| head.eq_ignore_ascii_case(p))
            .map(|_| &t[p.len()..])
    })
}

/// A DOI resolver root with nothing behind it (`https://doi.org`, with or
/// without the trailing `/`).
fn is_doi_resolver_root(t: &str) -> bool {
    let t = t.trim().trim_end_matches('/');
    DOI_PREFIXES
        .iter()
        .filter(|p| p.ends_with('/'))
        .any(|p| t.eq_ignore_ascii_case(p.trim_end_matches('/')))
}

/// What is behind the DOI prefixes of `t`, all of them peeled
/// (`doi:https://doi.org/10.x` names `10.x`); `""` for a resolver root with
/// nothing behind it. `None` when `t` carries no DOI prefix.
fn peel_doi_prefixes(t: &str) -> Option<&str> {
    let mut rest = match strip_doi_prefix(t) {
        Some(r) => r,
        None if is_doi_resolver_root(t) => "",
        None => return None,
    };
    loop {
        rest = rest.trim();
        if is_doi_resolver_root(rest) {
            return Some("");
        }
        match strip_doi_prefix(rest) {
            Some(r) => rest = r,
            None => return Some(rest),
        }
    }
}

/// Normalize a DOI as evidence stores it (`properties.doi`, usually bare)
/// or links to it (`doi:<id>`, `https://doi.org/<doi>`, `dx.` / `www.`
/// variants): prefixes removed, trimmed, trailing `/` removed,
/// ASCII-lowercased (DOIs are case-insensitive). `None` for a blank result,
/// a placeholder ([`is_placeholder_id`]: "unknown", "n/a", ...; a document
/// key built on one would merge every DOI-less document) or anything that is
/// still a URL after the prefixes are removed (a web page is not a DOI).
/// Percent-encoded DOIs are not decoded, so one DOI written both ways counts
/// as two sources, which errs toward the pre-key behaviour.
#[must_use]
pub fn normalize_doi(raw: &str) -> Option<String> {
    let t = raw.trim();
    let t = peel_doi_prefixes(t)
        .unwrap_or(t)
        .trim()
        .trim_end_matches('/');
    if t.is_empty() || t.contains("://") || is_placeholder_id(t) {
        None
    } else {
        Some(t.to_ascii_lowercase())
    }
}

/// An `http://` or `https://` link with something after the scheme.
fn is_web_url(t: &str) -> bool {
    ["http://", "https://"].iter().any(|scheme| {
        t.get(..scheme.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
            && !t[scheme.len()..].trim().trim_matches('/').is_empty()
    })
}

/// A bare DOI as free text would hold one: `10.`, a 4–9 digit registrant
/// code, `/`, a non-blank suffix. "10.0.0.5/notes" and "10.5 mg dose" are not.
fn is_bare_doi(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("10.") else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    // belief-profile: allow-literal (DOI syntax: a 4-9 digit registrant code)
    (4..=9).contains(&digits)
        && rest[digits..]
            .strip_prefix('/')
            .is_some_and(|suffix| !suffix.trim().is_empty())
}

/// The source one identity value names, if any. `doi:` and `url:` are
/// agent-free, so only a real identifier is a key:
/// - a DOI link or a `doi:` label names the DOI behind it, or the web link it
///   wraps (`doi:<uri>`, the label ingest builds for a document identified by
///   its URI), or nothing (a resolver link with no DOI behind it is not a web
///   page that rows could share);
/// - an `http(s)://` link names its URL. Ingest stores a document's URI in
///   `properties.doi` when it has no DOI and no arXiv id, and a citation of
///   that document carries the same URI as its `source_url`; both must give
///   one key;
/// - a bare value names a DOI when `bare_is_doi` accepts it, else nothing.
fn named_source(raw: &str, bare_is_doi: fn(&str) -> bool) -> Option<ItemKey> {
    let t = raw.trim();
    let (t, bare) = match peel_doi_prefixes(t) {
        Some(inner) => (inner.trim(), false),
        None => (t, true),
    };
    if is_web_url(t) {
        normalize_source_url(t).map(ItemKey::Url)
    } else if !bare || bare_is_doi(t) {
        normalize_doi(t).map(ItemKey::Doi)
    } else {
        None
    }
}

/// `properties.doi` is written by ingest (a DOI, an arXiv-style id, a
/// synthesized document key or a URI), so any bare value is a document
/// identifier unless it is a placeholder ([`normalize_doi`] rejects those).
fn doi_field_key(doi: &str) -> Option<ItemKey> {
    named_source(doi, |_| true)
}

/// `source_url` holds whatever the writer passed (MCP testimony stores a
/// witness's name or a note there as often as a link), so a bare value is a
/// DOI only in the well-formed `10.` shape, and free text or a scheme-less
/// host names nothing: the row keys on its evidence id.
fn source_url_key(url: &str) -> Option<ItemKey> {
    named_source(url, is_bare_doi)
}

/// The canonical [`ItemKey`] of one BBA row (SPEC §3.3). The first rule that
/// matches wins:
///
/// 1. `doi:` — `evidence` carries a DOI in `properties.doi`, or its
///    `source_url` is a DOI link or a well-formed bare DOI ([`normalize_doi`];
///    placeholders such as "unknown" are no DOI);
/// 2. `url:` — `evidence` names an `http(s)://` link that is not a DOI link,
///    in `source_url` or (for a document ingest identified by its URI) in
///    `properties.doi` ([`normalize_source_url`]); free text names no source;
/// 3. `ev:` — `evidence` names neither, or the row cites an `evidence_id`
///    the viewer cannot see (`evidence` is `None`);
/// 4. `attr:` — an [`ATTRIBUTED_METHOD`] row citing no evidence (a textless
///    attribution; its perspective is the original BBA's id), or `edge:` — an
///    [`EDGE_FACTOR_METHOD`] row (its perspective is the edge id);
/// 5. `paper:` — an [`INGEST_ASSERTION_METHOD`] row with neither perspective
///    nor evidence, when the caller resolved its `asserting_paper`.
///    **Caller contract:** pass `asserting_paper` only for a row the caller
///    has shown came from that paper's ingest batch (for example: the row's
///    agent is the agent that ingested the paper, and the claim has that
///    paper's `asserts` / `level_3` link). The same NULL/NULL `auto_wire`
///    shape is written by `submit_claim` / `memorize` creation BBAs and by
///    workflow ingest (see [`INGEST_ASSERTION_METHOD`]); resolving a paper
///    per claim rather than per row would merge such an unrelated agent's
///    BBA into the paper's self-assertion. With `None` the row is `row:`;
/// 6. `row:` — anything else is its own item.
///
/// `doi:`, `url:` and `paper:` ignore the row's agent: one paper read by two
/// agents is one source. The agent never enters a key.
///
/// `evidence` is the row's cited evidence **as the caller's viewer sees it**:
/// the row's `evidence_id`, or its `perspective_id` when that perspective is
/// an evidence perspective. A row whose evidence is hidden from the viewer
/// gets `None` and keys `ev:<row.evidence_id>`: the id is already on the
/// visible `mass_functions` row and no evidence content is read, so this
/// discloses nothing, and rows citing that one evidence row (a `whole`
/// attribution copied onto several atoms, or two agents citing it) still fold
/// as one source instead of being counted once per row. Such a row cannot get
/// the `doi:` / `url:` key a viewer who sees the evidence gives it, so the two
/// viewers' partitions can differ; that is the per-viewer fold, not a leak.
///
/// A real lens perspective (an analytical or empirical lens, say) is never a
/// key: keying on it would make every row of one lens a single comonotone
/// item. Only the row's shape (method plus perspective) selects rules 4–5.
#[must_use]
pub fn item_key(
    row: &MassFunctionRow,
    evidence: Option<&ItemEvidence>,
    asserting_paper: Option<Uuid>,
) -> ItemKey {
    if let Some(ev) = evidence {
        let named = [
            ev.doi.as_deref().and_then(doi_field_key),
            ev.source_url.as_deref().and_then(source_url_key),
        ];
        // A DOI from either column outranks a URL from either column.
        let doi = named
            .iter()
            .flatten()
            .find(|k| matches!(k, ItemKey::Doi(_)));
        return doi
            .or_else(|| named.iter().flatten().next())
            .cloned()
            .unwrap_or(ItemKey::Evidence(ev.id));
    }
    if let Some(cited) = row.evidence_id {
        return ItemKey::Evidence(cited);
    }
    let method = row.combination_method.as_deref();
    match (method, row.perspective_id, row.evidence_id) {
        (Some(ATTRIBUTED_METHOD), Some(original), None) => ItemKey::Attribution(original),
        (Some(EDGE_FACTOR_METHOD), Some(edge), None) => ItemKey::Edge(edge),
        (Some(INGEST_ASSERTION_METHOD), None, None) => {
            asserting_paper.map_or(ItemKey::Row(row.id), ItemKey::Paper)
        }
        _ => ItemKey::Row(row.id),
    }
}

/// Which part of a key's evidence an item carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ItemSide {
    /// The key's pure-support rows.
    Support,
    /// The key's pure-refutation rows (`<key>#neg`).
    Refute,
    /// One row kept as its own single-atom item.
    Own(Uuid),
}

/// Identity of one item of an [`item_partition`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId {
    pub key: ItemKey,
    pub side: ItemSide,
}

/// A discounted BBA row with its canonical key, ready to partition.
#[derive(Debug, Clone)]
pub struct KeyedBba {
    pub row_id: Uuid,
    pub atom_id: Uuid,
    pub key: ItemKey,
    pub bba: MassFunction,
}

/// One item: the BBA it contributes on each atom it touches.
#[derive(Debug, Clone)]
pub struct KeyedItem {
    pub id: ItemId,
    pub atoms: Vec<(Uuid, MassFunction)>,
}

impl KeyedItem {
    /// The item's BBA on `atom`, if it touches it.
    #[must_use]
    pub fn on(&self, atom: Uuid) -> Option<&MassFunction> {
        self.atoms.iter().find(|(a, _)| *a == atom).map(|(_, m)| m)
    }
}

/// The side of its key a row belongs to, and its weight there.
///
/// On a 2-hypothesis frame, with t = m({0}) and f = m({1}). Index 0 is read
/// as "the claim holds": callers coarsen every row to `binary_truth` (index 0
/// = TRUE) before partitioning. A claim wired at hypothesis index 1 of an
/// axis frame must be coarsened first, or [`ItemSide::Support`] and
/// [`ItemSide::Refute`] name the opposite literals. The fold itself is
/// symmetric in the two sides, so only readers of the side labels care:
/// - f = 0: pure support, weight t. This includes a vacuous or open-world-only
///   row (weight 0), which any real support row of the key outweighs;
/// - t = 0 < f: pure refutation, weight f;
/// - t > 0 and f > 0 (a mixed row), any mass on a focal element other than
///   {0}, {1}, Θ and `~` (conflict, a complement set), or a frame of another
///   size: the row is its own item, with its exact BBA.
fn within_group_side(row_id: Uuid, m: &MassFunction) -> (ItemSide, f64) {
    let frame = m.frame();
    // belief-profile: allow-literal (the binary frame's hypothesis count)
    if frame.hypothesis_count() != 2 {
        return (ItemSide::Own(row_id), 0.0);
    }
    let t_fe = FocalElement::positive(std::collections::BTreeSet::from([0]));
    let f_fe = FocalElement::positive(std::collections::BTreeSet::from([1]));
    let theta = FocalElement::theta(frame);
    let missing = FocalElement::missing(frame);
    let unexpected = m
        .focal_elements()
        .any(|(fe, &v)| v > 0.0 && *fe != t_fe && *fe != f_fe && *fe != theta && *fe != missing);
    let (t, f) = (m.mass_of(&t_fe), m.mass_of(&f_fe));
    if unexpected || (t > 0.0 && f > 0.0) {
        (ItemSide::Own(row_id), 0.0)
    } else if f > 0.0 {
        (ItemSide::Refute, f)
    } else {
        (ItemSide::Support, t)
    }
}

/// Partition keyed, discounted rows into items, applying the within-group
/// rule (SPEC §3.3):
/// - one key's pure-support rows form ONE item; on each atom it keeps the row
///   with the largest m(TRUE) (the max, never a Dempster product of one
///   source's repeats);
/// - the key's pure-refutation rows form a SEPARATE item (`<key>#neg`,
///   [`ItemSide::Refute`]) keeping the largest m(FALSE) per atom, so a
///   lineage that both supports and refutes keeps its refutation when the
///   items are combined by Dempster;
/// - a mixed row (or one this rule cannot read, see `within_group_side`) is
///   its own single-atom item with its exact BBA.
///
/// `combination::cautious_combine` is never used here: it models no `~`
/// mass, and on a support and a refutation of one lineage it turns the
/// refutation into empty-set mass and normalizes it away.
///
/// An item spans every atom its key has rows on. Items never merge across
/// keys, so the item a row belongs to depends only on its own key and masses,
/// never on which other rows or atoms are in the query. Rows that tie on
/// weight can differ in their other masses (`~` vs Θ), so the tie goes to the
/// smaller `row_id`: the item's BBA is a function of the rows, never of the
/// order a read returned them in. Items and their atoms are listed in
/// first-appearance order. Callers pass one 2-hypothesis frame per atom (the
/// atom fold coarsens first).
#[must_use]
pub fn item_partition(rows: Vec<KeyedBba>) -> Vec<KeyedItem> {
    let mut items: Vec<KeyedItem> = Vec::new();
    // Per item, per atom (same order as `atoms`): the kept row's weight and id.
    let mut kept: Vec<Vec<(f64, Uuid)>> = Vec::new();
    let mut index: HashMap<ItemId, usize> = HashMap::new();
    for r in rows {
        let (side, w) = within_group_side(r.row_id, &r.bba);
        let id = ItemId { key: r.key, side };
        let i = *index.entry(id.clone()).or_insert_with(|| {
            items.push(KeyedItem {
                id,
                atoms: Vec::new(),
            });
            kept.push(Vec::new());
            items.len() - 1
        });
        let item = &mut items[i];
        match item.atoms.iter().position(|(a, _)| *a == r.atom_id) {
            None => {
                item.atoms.push((r.atom_id, r.bba));
                kept[i].push((w, r.row_id));
            }
            // A larger weight wins; on a tie, the smaller row id.
            Some(j)
                if w.total_cmp(&kept[i][j].0)
                    .then_with(|| kept[i][j].1.cmp(&r.row_id))
                    .is_gt() =>
            {
                item.atoms[j].1 = r.bba;
                kept[i][j] = (w, r.row_id);
            }
            Some(_) => {}
        }
    }
    items
}

/// Fold ONE atom's keyed, discounted BBAs by item: [`item_partition`], then
/// Dempster across the items. The item-keyed counterpart of
/// [`combine_with_source_dependence`], with the same return shape (the
/// combined BBA and the conflict the fold saw).
///
/// # Errors
/// Propagates `DsError` from the Dempster fold, including
/// `combine_multiple`'s error when `rows` is empty.
pub fn combine_by_item(
    rows: Vec<(Uuid, ItemKey, MassFunction)>,
    conflict_threshold: f64,
) -> Result<(MassFunction, f64), DsError> {
    let atom = Uuid::nil();
    let items = item_partition(
        rows.into_iter()
            .map(|(row_id, key, bba)| KeyedBba {
                row_id,
                atom_id: atom,
                key,
                bba,
            })
            .collect(),
    );
    let for_fold: Vec<MassFunction> = items
        .into_iter()
        .filter_map(|it| it.atoms.into_iter().next().map(|(_, m)| m))
        .collect();
    dempster_across_items(for_fold, conflict_threshold)
}

/// Combine one atom's items (one BBA per item of an [`item_partition`]) by
/// Dempster, and report the conflict the fold saw: a lone item's own
/// empty-set mass, else [`combination::fold_conflict`] over the steps. The
/// shared tail of [`combine_by_item`] and the atom evidence fold
/// (`crate::atom_items::atom_fold`).
///
/// At total conflict between dogmatic items `combine_multiple` does not fail:
/// it falls back to Yager's closed rule (the conflict mass goes to Θ).
///
/// # Errors
/// Propagates `DsError` from the Dempster fold, including
/// `combine_multiple`'s error when `items` is empty.
pub fn dempster_across_items(
    mut items: Vec<MassFunction>,
    conflict_threshold: f64,
) -> Result<(MassFunction, f64), DsError> {
    if items.len() == 1 {
        let only = items.pop().expect("len == 1");
        let k = only.mass_of_conflict();
        Ok((only, k))
    } else {
        let (combined, reports) = combination::combine_multiple(&items, conflict_threshold)?;
        let k = combination::fold_conflict(&combined, &reports);
        Ok((combined, k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_ds::{measures, FrameOfDiscernment};
    use std::collections::BTreeSet;

    fn frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()]).unwrap()
    }

    fn support(idx: usize, mass: f64, reliability: f64) -> MassFunction {
        let m = MassFunction::simple(frame(), BTreeSet::from([idx]), mass).unwrap();
        combination::discount(&m, reliability).unwrap()
    }

    fn key(agent: u128, url: &str) -> Option<SourceKey> {
        Some(SourceKey {
            agent_id: Uuid::from_u128(agent),
            source_url: normalize_source_url(url).unwrap(),
        })
    }

    fn total(m: &MassFunction) -> f64 {
        m.focal_elements().map(|(_, v)| *v).sum()
    }

    #[test]
    fn repeats_of_one_source_carry_one_copy_of_weight() {
        let one = support(0, 0.8, 0.9);
        let (single, _) =
            combine_with_source_dependence(vec![(key(1, "https://a/x"), one.clone())], 0.9)
                .unwrap();
        let (repeated, k) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(1, "https://a/x/"), one.clone()),
                (key(1, "HTTPS://A/X"), one),
            ],
            0.9,
        )
        .unwrap();
        let b1 = measures::pignistic_probability(&single, 0);
        let bn = measures::pignistic_probability(&repeated, 0);
        assert!((b1 - bn).abs() < 1e-12, "{b1} vs {bn}");
        assert!((total(&repeated) - 1.0).abs() < 1e-9);
        assert!(
            k.abs() < 1e-12,
            "agreeing repeats carry no conflict, got {k}"
        );
    }

    #[test]
    fn distinct_urls_and_unkeyed_rows_still_reinforce() {
        let one = support(0, 0.8, 0.9);
        let b1 = measures::pignistic_probability(&one, 0);
        for items in [
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(1, "https://b/y"), one.clone()),
            ],
            vec![(None, one.clone()), (None, one.clone())],
            // Same URL, different agent: two observers, two sources.
            vec![
                (key(1, "https://a/x"), one.clone()),
                (key(2, "https://a/x"), one.clone()),
            ],
        ] {
            let (c, _) = combine_with_source_dependence(items, 0.9).unwrap();
            let b2 = measures::pignistic_probability(&c, 0);
            assert!(
                b2 > b1 + 1e-6,
                "independent sources must reinforce: {b1} -> {b2}"
            );
        }
    }

    #[test]
    fn a_source_that_flips_is_changed_content_and_folds_as_before() {
        // One source supports, then refutes. That is a changed verdict, not a
        // repeat: it must fold exactly as main's Dempster fold does, and the
        // cached triple must stay ordered Bel <= BetP <= Pl.
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let (dempster, _) =
            combination::combine_multiple(&[sup.clone(), refute.clone()], 0.9).unwrap();
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), dempster.masses());
        let target = FocalElement::positive(BTreeSet::from([0]));
        let bel = measures::belief(&c, &target);
        let pl = measures::plausibility(&c, &target);
        let betp = measures::pignistic_probability(&c, 0);
        assert!(
            bel <= betp + 1e-12 && betp <= pl + 1e-12,
            "Bel {bel} <= BetP {betp} <= Pl {pl}"
        );
    }

    #[test]
    fn repeats_inside_a_flipping_source_still_collapse_per_verdict() {
        // support, support, refute from one source == support, refute.
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let (once, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup.clone()),
                (key(1, "https://a/x"), refute.clone()),
            ],
            0.9,
        )
        .unwrap();
        let (twice, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup.clone()),
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
            ],
            0.9,
        )
        .unwrap();
        let a = measures::pignistic_probability(&once, 0);
        let b = measures::pignistic_probability(&twice, 0);
        assert!((a - b).abs() < 1e-12, "{a} vs {b}");
    }

    #[test]
    fn a_stronger_repeat_keeps_the_strongest_reading_not_the_product() {
        let weak = support(0, 0.6, 0.9);
        let strong = support(0, 0.8, 0.9);
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), weak),
                (key(1, "https://a/x"), strong.clone()),
            ],
            0.9,
        )
        .unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((c.mass_of(&fe0) - strong.mass_of(&fe0)).abs() < 1e-12);
        assert!((total(&c) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn non_classical_group_members_fall_back_to_independent_folding() {
        let one = support(0, 0.8, 0.9);
        let f = frame();
        let open = MassFunction::new(
            f.clone(),
            std::collections::BTreeMap::from([
                (FocalElement::missing(&f), 0.3),
                (FocalElement::theta(&f), 0.7),
            ]),
        )
        .unwrap();
        assert!(!open.is_classical());
        let independent = combination::combine_multiple(&[one.clone(), open.clone()], 0.9)
            .unwrap()
            .0;
        let (c, _) = combine_with_source_dependence(
            vec![(key(1, "https://a/x"), one), (key(1, "https://a/x"), open)],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    #[test]
    fn a_keyed_mixed_bba_is_not_grouped_with_a_simple_support() {
        // A legacy mixed BBA (mass on {TRUE} AND {FALSE}) is not a simple
        // support function: the cautious rule's "strongest repeat" reading does
        // not apply to it, so it must fold as an independent input even when it
        // shares a source key with a simple support on either of its focal
        // elements. Both verdicts are present, so whichever focal element a
        // mis-grouping picked, it would land in a group.
        let f = frame();
        let sup = support(0, 0.8, 0.9);
        let refute = support(1, 0.5, 0.9);
        let mixed = MassFunction::new(
            f.clone(),
            std::collections::BTreeMap::from([
                (FocalElement::positive(BTreeSet::from([0])), 0.4),
                (FocalElement::positive(BTreeSet::from([1])), 0.2),
                (FocalElement::theta(&f), 0.4),
            ]),
        )
        .unwrap();
        let independent =
            combination::combine_multiple(&[sup.clone(), refute.clone(), mixed.clone()], 0.9)
                .unwrap()
                .0;
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), sup),
                (key(1, "https://a/x"), refute),
                (key(1, "https://a/x"), mixed),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    #[test]
    fn repeats_on_a_frame_too_large_for_the_cautious_pass_fold_as_before() {
        // Above MAX_CAUTIOUS_HYPOTHESES the cautious pass is skipped (it walks
        // the power set): keyed repeats on such a frame are Dempster-folded
        // exactly as they were before the rule.
        let big = FrameOfDiscernment::new(
            "nine",
            (0..=MAX_CAUTIOUS_HYPOTHESES)
                .map(|i| format!("H{i}"))
                .collect(),
        )
        .unwrap();
        assert!(big.hypothesis_count() > MAX_CAUTIOUS_HYPOTHESES);
        let m = combination::discount(
            &MassFunction::simple(big, BTreeSet::from([0]), 0.8).unwrap(),
            0.9,
        )
        .unwrap();
        let independent = combination::combine_multiple(&[m.clone(), m.clone()], 0.9)
            .unwrap()
            .0;
        let (c, _) = combine_with_source_dependence(
            vec![
                (key(1, "https://a/x"), m.clone()),
                (key(1, "https://a/x"), m),
            ],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), independent.masses());
    }

    // ── R-36: the same-human rule ──────────────────────────────────────────

    /// A row by `agent`, owned by `owner`, with no same-source key.
    fn by(agent: u128, owner: u128) -> BbaSource {
        BbaSource {
            agent_id: Some(Uuid::from_u128(agent)),
            owner_id: Some(Uuid::from_u128(owner)),
            source: None,
        }
    }

    fn m_true(m: &MassFunction) -> f64 {
        m.mass_of(&FocalElement::positive(BTreeSet::from([0])))
    }

    #[test]
    fn two_agents_of_one_human_keep_the_stronger_never_the_product() {
        // Agents 1 and 2 both act for human 9. Dempster would give
        // 1 - 0.4 * 0.3 = 0.88; first-wins 0.6, last-wins 0.7 by accident of
        // order, so both orders are checked.
        for items in [
            vec![
                (by(1, 9), support(0, 0.6, 1.0)),
                (by(2, 9), support(0, 0.7, 1.0)),
            ],
            vec![
                (by(2, 9), support(0, 0.7, 1.0)),
                (by(1, 9), support(0, 0.6, 1.0)),
            ],
        ] {
            let (c, k) = combine_with_owner_dependence(items, 0.9).unwrap();
            assert!(
                (m_true(&c) - 0.7).abs() < 1e-9,
                "got m(TRUE) = {}",
                m_true(&c)
            );
            assert!((total(&c) - 1.0).abs() < 1e-9);
            assert!(
                k.abs() < 1e-12,
                "agreeing siblings carry no conflict, got {k}"
            );
        }
    }

    #[test]
    fn one_agents_distinct_sources_still_reinforce() {
        // R-37: agent-only keying stays rejected. One agent's two distinct
        // pieces of evidence are two sources, whether it acts for a human
        // (owner 9) or for nobody (it is its own owner).
        for owner in [9, 1] {
            let (c, _) = combine_with_owner_dependence(
                vec![
                    (by(1, owner), support(0, 0.6, 1.0)),
                    (by(1, owner), support(0, 0.7, 1.0)),
                ],
                0.9,
            )
            .unwrap();
            assert!((m_true(&c) - 0.88).abs() < 1e-9, "got {}", m_true(&c));
        }
    }

    #[test]
    fn agents_of_different_humans_still_reinforce() {
        let (c, _) = combine_with_owner_dependence(
            vec![
                (by(1, 9), support(0, 0.6, 1.0)),
                (by(2, 8), support(0, 0.7, 1.0)),
            ],
            0.9,
        )
        .unwrap();
        assert!((m_true(&c) - 0.88).abs() < 1e-9, "got {}", m_true(&c));
    }

    #[test]
    fn a_siblings_refutation_is_a_contest_not_collapsed() {
        let sup = support(0, 0.8, 1.0);
        let refute = support(1, 0.5, 1.0);
        let (dempster, _) =
            combination::combine_multiple(&[sup.clone(), refute.clone()], 0.9).unwrap();
        let (c, k) =
            combine_with_owner_dependence(vec![(by(1, 9), sup), (by(2, 9), refute)], 0.9).unwrap();
        assert_eq!(c.masses(), dempster.masses());
        assert!(k > 0.3, "the contest must show as conflict, got {k}");
    }

    #[test]
    fn each_sibling_contributes_its_own_fold_and_the_strongest_wins() {
        // Agent 1 (two distinct sources: 1 - 0.4 * 0.5 = 0.8) and its sibling
        // agent 2 (0.7) give 0.8; an agent of another human (0.5) then
        // reinforces by Dempster: 1 - 0.2 * 0.5 = 0.9.
        let (c, _) = combine_with_owner_dependence(
            vec![
                (by(1, 9), support(0, 0.6, 1.0)),
                (by(2, 9), support(0, 0.7, 1.0)),
                (by(1, 9), support(0, 0.5, 1.0)),
                (by(3, 7), support(0, 0.5, 1.0)),
            ],
            0.9,
        )
        .unwrap();
        assert!((m_true(&c) - 0.9).abs() < 1e-9, "got {}", m_true(&c));
    }

    #[test]
    fn rows_without_an_agent_or_owner_fold_as_before() {
        let one = support(0, 0.6, 1.0);
        let two = support(0, 0.7, 1.0);
        let legacy =
            combine_with_source_dependence(vec![(None, one.clone()), (None, two.clone())], 0.9)
                .unwrap()
                .0;
        let (c, _) = combine_with_owner_dependence(
            vec![(BbaSource::default(), one), (BbaSource::keyed(None), two)],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), legacy.masses());
    }

    #[test]
    fn open_world_siblings_keep_the_stronger_too() {
        // `submit_ds_evidence` callers write open-world BBAs; those siblings
        // must not multiply either.
        let ow = |t: f64| {
            MassFunction::from_json_masses(frame(), &serde_json::json!({"0": t, "~": 1.0 - t}))
                .unwrap()
        };
        let (dempster, _) = combination::combine_multiple(&[ow(0.6), ow(0.7)], 0.9).unwrap();
        let (c, _) =
            combine_with_owner_dependence(vec![(by(1, 9), ow(0.6)), (by(2, 9), ow(0.7))], 0.9)
                .unwrap();
        assert_eq!(c.masses(), ow(0.7).masses());
        assert_ne!(c.masses(), dempster.masses());
    }

    #[test]
    fn two_sided_sibling_bbas_fold_independently() {
        // A documented limit: a BBA with mass on both a hypothesis and its
        // rival (an assess-built directed BBA) has no one-sided reduction, so
        // siblings' two-sided BBAs fold as before.
        let mixed = |t: f64, f: f64| {
            MassFunction::from_json_masses(
                frame(),
                &serde_json::json!({"0": t, "1": f, "0,1": 1.0 - t - f}),
            )
            .unwrap()
        };
        let legacy = combine_with_source_dependence(
            vec![(None, mixed(0.6, 0.1)), (None, mixed(0.5, 0.2))],
            0.9,
        )
        .unwrap()
        .0;
        let (c, _) = combine_with_owner_dependence(
            vec![(by(1, 9), mixed(0.6, 0.1)), (by(2, 9), mixed(0.5, 0.2))],
            0.9,
        )
        .unwrap();
        assert_eq!(c.masses(), legacy.masses());
    }

    #[test]
    fn normalize_rejects_blank_and_folds_trivial_variants() {
        assert_eq!(normalize_source_url("   "), None);
        assert_eq!(normalize_source_url("/"), None);
        assert_eq!(
            normalize_source_url(" https://Example.org/RFP/ "),
            Some("https://example.org/rfp".into())
        );
    }
}
