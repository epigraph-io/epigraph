//! The naming step over one map's level documents (pure but for the
//! backend): which claims each group samples, the names bottom-up, the
//! carry-over of unchanged names, and every name the documents repeat.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context};
use epigraph_atlas_contract::{Hierarchy, LevelDocument, MapScope, Node};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::backend::NameBackend;
use super::prompt::{
    build_prompt, clip_text, naming_key, rank, validate_reply, PromptInput, CANDIDATES,
    MAX_CHILD_NAMES, PROMPT_VERSION, SAMPLE_SIZE,
};

/// A level of one run: its hierarchy and group id.
pub type LevelKey = (Hierarchy, Uuid);

/// The record key of a level: `meaning/<id>` or `links/<id>` (W6's spelling).
#[must_use]
pub fn record_key((h, id): LevelKey) -> String {
    let h = match h {
        Hierarchy::Meaning => "meaning",
        Hierarchy::Links => "links",
    };
    format!("{h}/{id}")
}

/// What a run records under `params.naming`: the prompt version and, per
/// level named, the key its name was made under. A level whose naming failed
/// or was skipped has no entry, so it is named again next run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingRecord {
    pub prompt_version: String,
    pub keys: BTreeMap<String, String>,
}

impl NamingRecord {
    /// The record in a run's `params`, if it has one.
    ///
    /// # Errors
    /// A `naming` entry that is not a record.
    pub fn from_params(params: &serde_json::Value) -> anyhow::Result<Option<Self>> {
        match params.get("naming") {
            None => Ok(None),
            Some(v) => Ok(Some(
                serde_json::from_value(v.clone())
                    .context("params.naming is not a naming record")?,
            )),
        }
    }
}

/// The names an earlier run may lend: name by key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Previous {
    by_key: BTreeMap<String, String>,
}

impl Previous {
    /// From an earlier run's record and the names its levels stored (by
    /// record key). Only a level with both a key and a name lends one.
    #[must_use]
    pub fn new(record: &NamingRecord, names: &BTreeMap<String, String>) -> Self {
        let by_key = record
            .keys
            .iter()
            .filter_map(|(level, key)| names.get(level).map(|n| (key.clone(), n.clone())))
            .collect();
        Self { by_key }
    }

    /// No earlier run.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    fn get(&self, key: &str) -> Option<&String> {
        self.by_key.get(key)
    }
}

/// How one run of the step went.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NamingReport {
    /// Levels in the documents.
    pub levels: usize,
    /// Model calls made.
    pub calls: usize,
    /// Levels named by a call this run.
    pub named: usize,
    /// Levels that copied an earlier run's name (no call).
    pub carried: usize,
    /// Levels that shared a name with another level of this run under the
    /// same key (no call).
    pub shared: usize,
    /// Levels whose reply was refused or whose call failed.
    pub failed: usize,
    /// Levels left unnamed because the call budget ran out (or a dry run).
    pub deferred: usize,
    /// Levels with no readable member text and no named child.
    pub no_text: usize,
}

/// The step's options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamingOptions {
    /// At most this many model calls; the rest stay flagged for the next run.
    pub max_calls: Option<usize>,
    /// False for a dry run: no call at all, every level that would need one
    /// is counted as deferred.
    pub call_model: bool,
}

impl Default for NamingOptions {
    fn default() -> Self {
        Self {
            max_calls: None,
            call_model: true,
        }
    }
}

/// Each group's sample candidates: claim ids in sample order, at most
/// [`CANDIDATES`]. A leaf ranks its claim nodes by [`rank`]; an inner group
/// takes its children's lists round-robin in child order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamplePlan {
    candidates: BTreeMap<LevelKey, Vec<Uuid>>,
}

impl SamplePlan {
    /// Every claim any group may sample: the ids whose text to read.
    #[must_use]
    pub fn claim_ids(&self) -> Vec<Uuid> {
        let all: BTreeSet<Uuid> = self.candidates.values().flatten().copied().collect();
        all.into_iter().collect()
    }

    /// One group's candidates.
    #[must_use]
    pub fn candidates(&self, level: LevelKey) -> &[Uuid] {
        self.candidates.get(&level).map_or(&[], Vec::as_slice)
    }
}

fn key_of(doc: &LevelDocument) -> LevelKey {
    match doc {
        LevelDocument::Group(g) => (g.hierarchy, g.level_id),
        LevelDocument::Leaf(l) => (l.hierarchy, l.level_id),
    }
}

fn depth_of(doc: &LevelDocument) -> u8 {
    match doc {
        LevelDocument::Group(g) => g.depth,
        LevelDocument::Leaf(l) => l.depth,
    }
}

fn map_of(doc: &LevelDocument) -> (MapScope, Option<Uuid>) {
    match doc {
        LevelDocument::Group(g) => (g.map_scope, g.map_group_id),
        LevelDocument::Leaf(l) => (l.map_scope, l.map_group_id),
    }
}

fn theme_of(doc: &LevelDocument) -> Uuid {
    match doc {
        LevelDocument::Group(g) => g.theme_id,
        LevelDocument::Leaf(l) => l.theme_id,
    }
}

/// The map's spelling (`public` or `team:<uuid>`), the same as
/// `atlas_meaning::tree::map_key`.
fn map_spelling(scope: MapScope, group: Option<Uuid>) -> anyhow::Result<String> {
    match (scope, group) {
        (MapScope::Public, None) => Ok("public".to_string()),
        (MapScope::Team, Some(t)) => Ok(format!("team:{t}")),
        _ => bail!("a level's map scope and group disagree"),
    }
}

/// The map's spelling and the order to visit the documents in: deepest
/// first, so every child comes before its parent. Every level is checked to
/// appear once and every child to have a document one level deeper.
struct Index {
    order: Vec<usize>,
    map: String,
}

fn index(docs: &[LevelDocument]) -> anyhow::Result<Index> {
    let mut at = BTreeMap::new();
    let mut map: Option<(MapScope, Option<Uuid>)> = None;
    for (i, d) in docs.iter().enumerate() {
        ensure!(
            at.insert(key_of(d), i).is_none(),
            "level {:?} is in the documents twice",
            key_of(d)
        );
        let m = map_of(d);
        ensure!(
            *map.get_or_insert(m) == m,
            "the documents hold levels of more than one map"
        );
    }
    for d in docs {
        if let LevelDocument::Group(g) = d {
            for c in &g.children {
                let ci = at
                    .get(&(g.hierarchy, c.id))
                    .with_context(|| format!("child {} of {} has no document", c.id, g.level_id))?;
                ensure!(
                    depth_of(&docs[*ci]) == g.depth + 1,
                    "child {} of {} is not one level deeper",
                    c.id,
                    g.level_id
                );
            }
        }
    }
    let mut order: Vec<usize> = (0..docs.len()).collect();
    order.sort_by_key(|&i| (std::cmp::Reverse(depth_of(&docs[i])), key_of(&docs[i])));
    let map = match map {
        Some((s, g)) => map_spelling(s, g)?,
        None => String::new(),
    };
    Ok(Index { order, map })
}

/// Each group's sample candidates (claim ids only; no text is read here).
///
/// # Errors
/// Documents of more than one map, a level twice, or a child with no
/// document one level deeper.
pub fn plan_samples(docs: &[LevelDocument]) -> anyhow::Result<SamplePlan> {
    let idx = index(docs)?;
    let mut candidates: BTreeMap<LevelKey, Vec<Uuid>> = BTreeMap::new();
    for &i in &idx.order {
        let doc = &docs[i];
        let list = match doc {
            LevelDocument::Leaf(l) => {
                let mut claims: Vec<Uuid> = l
                    .nodes
                    .iter()
                    .filter_map(|n| match n {
                        Node::Claim(c) => Some(c.id),
                        Node::Agent(_) | Node::Evidence(_) => None,
                    })
                    .collect();
                claims.sort_by_key(|id| (rank(*id), *id));
                claims.dedup();
                claims.truncate(CANDIDATES);
                claims
            }
            LevelDocument::Group(g) => {
                let lists: Vec<&Vec<Uuid>> = g
                    .children
                    .iter()
                    .filter_map(|c| candidates.get(&(g.hierarchy, c.id)))
                    .collect();
                let mut seen = BTreeSet::new();
                let mut out = Vec::new();
                let longest = lists.iter().map(|l| l.len()).max().unwrap_or(0);
                'fill: for round in 0..longest {
                    for l in &lists {
                        if let Some(id) = l.get(round) {
                            if seen.insert(*id) {
                                out.push(*id);
                                if out.len() == CANDIDATES {
                                    break 'fill;
                                }
                            }
                        }
                    }
                }
                out
            }
        };
        candidates.insert(key_of(doc), list);
    }
    Ok(SamplePlan { candidates })
}

/// Name every level of `docs` and write every name the documents repeat.
///
/// `texts` holds the text of the candidates the MAP may draw now, read
/// through the map-scoped read (`read_member_texts`); a candidate absent
/// from it is skipped, so a claim that left the map's audience feeds no
/// name. The levels are visited deepest first, so an inner group is named
/// from its children's names (as named in this run) and a sample of its
/// members.
///
/// A level's name is copied from `previous` when its key is unchanged (no
/// call), shared with another level of this run under the same key (no
/// call), or asked of `backend`. A refused or failed reply, a deferred call
/// or a level with nothing to name it from leaves `name` null with
/// `needs_naming` true. Then every `children[]` entry, breadcrumb and link
/// target gets the current name of the level it points to, or null when that
/// level has none or is not in these documents.
///
/// Returns the record for the run's `params.naming` and a report.
///
/// # Errors
/// What [`plan_samples`] refuses, or a document the contract refuses after
/// naming.
pub fn name_levels(
    docs: &mut [LevelDocument],
    plan: &SamplePlan,
    texts: &BTreeMap<Uuid, String>,
    previous: &Previous,
    backend: &dyn NameBackend,
    opts: NamingOptions,
) -> anyhow::Result<(NamingRecord, NamingReport)> {
    let idx = index(docs)?;
    let mut names: BTreeMap<LevelKey, String> = BTreeMap::new();
    let mut memo: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut record = NamingRecord {
        prompt_version: PROMPT_VERSION.to_string(),
        keys: BTreeMap::new(),
    };
    let mut report = NamingReport {
        levels: docs.len(),
        ..NamingReport::default()
    };
    for &i in &idx.order {
        let doc = &docs[i];
        let level = key_of(doc);
        let child_names: Vec<String> = match doc {
            LevelDocument::Group(g) => g
                .children
                .iter()
                .filter_map(|c| names.get(&(g.hierarchy, c.id)).cloned())
                .take(MAX_CHILD_NAMES)
                .collect(),
            LevelDocument::Leaf(_) => Vec::new(),
        };
        let members: Vec<(Uuid, String)> = plan
            .candidates(level)
            .iter()
            .filter_map(|id| texts.get(id).map(|t| (*id, clip_text(t))))
            .take(SAMPLE_SIZE)
            .collect();
        let input = PromptInput {
            theme_root: depth_of(doc) == 0,
            child_names,
            members,
        };
        if input.is_empty() {
            report.no_text += 1;
            continue;
        }
        let prompt = build_prompt(&input);
        let key = naming_key(&idx.map, theme_of(doc), &input, &prompt);
        let name = if let Some(shared) = memo.get(&key) {
            report.shared += 1;
            shared.clone()
        } else if let Some(prev) = previous.get(&key) {
            report.carried += 1;
            memo.insert(key.clone(), Some(prev.clone()));
            Some(prev.clone())
        } else if !opts.call_model || opts.max_calls.is_some_and(|m| report.calls >= m) {
            report.deferred += 1;
            None
        } else {
            report.calls += 1;
            let texts: Vec<&str> = input.members.iter().map(|(_, t)| t.as_str()).collect();
            let got = backend
                .complete(&prompt)
                .map_err(|e| e.0)
                .and_then(|reply| validate_reply(&reply, &texts));
            match got {
                Ok(n) => {
                    report.named += 1;
                    memo.insert(key.clone(), Some(n.clone()));
                    Some(n)
                }
                Err(why) => {
                    tracing::warn!(level = %level.1, %why, "naming reply refused");
                    report.failed += 1;
                    memo.insert(key.clone(), None);
                    None
                }
            }
        };
        if let Some(n) = name {
            record.keys.insert(record_key(level), key);
            names.insert(level, n);
        }
    }
    for doc in docs.iter_mut() {
        apply_names(doc, &names);
        doc.validate()
            .map_err(|v| anyhow::anyhow!("level {:?} breaks the contract: {v}", key_of(doc)))?;
    }
    Ok((record, report))
}

/// Write the current names into one document: its own, each child's, each
/// breadcrumb's and each link target's.
fn apply_names(doc: &mut LevelDocument, names: &BTreeMap<LevelKey, String>) {
    match doc {
        LevelDocument::Group(g) => {
            let h = g.hierarchy;
            g.name = names.get(&(h, g.level_id)).cloned();
            g.needs_naming = g.name.is_none();
            for c in &mut g.children {
                c.name = names.get(&(h, c.id)).cloned();
                c.needs_naming = c.name.is_none();
            }
            for b in &mut g.breadcrumbs {
                b.name = names.get(&(h, b.level_id)).cloned();
            }
            for t in &mut g.targets {
                t.name = names.get(&(h, t.level_id)).cloned();
            }
        }
        LevelDocument::Leaf(l) => {
            let h = l.hierarchy;
            l.name = names.get(&(h, l.level_id)).cloned();
            l.needs_naming = l.name.is_none();
            for b in &mut l.breadcrumbs {
                b.name = names.get(&(h, b.level_id)).cloned();
            }
            for o in &mut l.outgoing {
                o.target.name = names.get(&(h, o.target.level_id)).cloned();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_meaning::docs::level_documents;
    use crate::atlas_meaning::tree::{group_id, root_id, MeaningTree, NodeBody, TreeNode};
    use crate::atlas_naming::backend::{BackendError, RecordingBackend};
    use epigraph_atlas_contract::{LinkTarget, Outgoing};
    use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};

    const MAP: AtlasMap = AtlasMap::Public;
    const THEME: Uuid = Uuid::from_u128(0x7e);

    fn ids(base: u128, n: u128) -> Vec<Uuid> {
        (0..n).map(|i| Uuid::from_u128(base + i)).collect()
    }

    /// The text of claim `id`: carries a marker `TOK<id>`.
    fn text(id: Uuid) -> String {
        format!("A claim on subject TOK{} with some words", id.as_u128())
    }

    fn texts(claims: &[Uuid]) -> BTreeMap<Uuid, String> {
        claims.iter().map(|c| (*c, text(*c))).collect()
    }

    /// A name from the first marker of the prompt's sample, so a leaked text
    /// shows in the name; `tag` tells two scripted backends apart.
    fn echo(tag: &'static str) -> RecordingBackend {
        RecordingBackend::new(move |prompt: &str| {
            let tok = prompt
                .split(|c: char| !c.is_alphanumeric())
                .find(|w| w.starts_with("TOK"))
                .unwrap_or("none");
            Ok(format!("{{\"name\": \"{tag} {tok}\"}}"))
        })
    }

    fn leaf_node(map: AtlasMap, h: AtlasHierarchy, parent: Uuid, claims: &[Uuid]) -> TreeNode {
        let set: BTreeSet<Uuid> = claims.iter().copied().collect();
        TreeNode {
            id: group_id(map, h, THEME, &set),
            parent: Some(parent),
            depth: 1,
            body: NodeBody::Leaf(set.iter().copied().collect()),
            claims: set.into_iter().collect(),
        }
    }

    /// A root group over one leaf per member list.
    fn tree(map: AtlasMap, h: AtlasHierarchy, leaves: &[&[Uuid]]) -> MeaningTree {
        let root = root_id(map, h, THEME);
        let kids: Vec<TreeNode> = leaves.iter().map(|l| leaf_node(map, h, root, l)).collect();
        let mut all: Vec<Uuid> = leaves.iter().flat_map(|l| l.iter().copied()).collect();
        all.sort_unstable();
        let mut nodes = vec![TreeNode {
            id: root,
            parent: None,
            depth: 0,
            body: NodeBody::Group(kids.iter().map(|k| k.id).collect()),
            claims: all,
        }];
        nodes.extend(kids);
        MeaningTree {
            map,
            hierarchy: h,
            theme_id: THEME,
            nodes,
        }
    }

    /// A theme that is one root leaf.
    fn root_leaf(map: AtlasMap, h: AtlasHierarchy, claims: &[Uuid]) -> MeaningTree {
        let mut c = claims.to_vec();
        c.sort_unstable();
        MeaningTree {
            map,
            hierarchy: h,
            theme_id: THEME,
            nodes: vec![TreeNode {
                id: root_id(map, h, THEME),
                parent: None,
                depth: 0,
                body: NodeBody::Leaf(c.clone()),
                claims: c,
            }],
        }
    }

    fn docs(trees: &[MeaningTree], labels: &BTreeMap<Uuid, String>) -> Vec<LevelDocument> {
        trees
            .iter()
            .flat_map(|t| level_documents(t, Uuid::nil(), labels).unwrap())
            .map(|d| serde_json::from_value(d.payload).unwrap())
            .collect()
    }

    fn run(
        docs: &mut [LevelDocument],
        texts: &BTreeMap<Uuid, String>,
        previous: &Previous,
        backend: &RecordingBackend,
        opts: NamingOptions,
    ) -> (NamingRecord, NamingReport) {
        let plan = plan_samples(docs).unwrap();
        name_levels(docs, &plan, texts, previous, backend, opts).unwrap()
    }

    fn name_of(doc: &LevelDocument) -> Option<String> {
        match doc {
            LevelDocument::Group(g) => g.name.clone(),
            LevelDocument::Leaf(l) => l.name.clone(),
        }
    }

    fn previous_of(record: &NamingRecord, docs: &[LevelDocument]) -> Previous {
        let names = docs
            .iter()
            .filter_map(|d| name_of(d).map(|n| (record_key(key_of(d)), n)))
            .collect();
        Previous::new(record, &names)
    }

    fn corpus() -> (Vec<Uuid>, Vec<Uuid>, Vec<Uuid>) {
        (ids(0x100, 8), ids(0x200, 8), ids(0x300, 5))
    }

    /// Done when: a rerun over unchanged groups makes zero model calls, and
    /// every name is copied.
    #[test]
    fn a_rerun_makes_no_call() {
        let (a, b, c) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).chain(&c).copied().collect();
        let labels = texts(&all);
        let trees = [
            tree(MAP, AtlasHierarchy::Meaning, &[&a, &b]),
            root_leaf(MAP, AtlasHierarchy::Links, &c),
        ];
        let mut first = docs(&trees, &labels);
        let fake = echo("Topic");
        let (record, report) = run(
            &mut first,
            &labels,
            &Previous::none(),
            &fake,
            NamingOptions::default(),
        );
        assert_eq!(report.calls, 4, "{report:?}");
        assert!(first.iter().all(|d| name_of(d).is_some()));

        let mut second = docs(&trees, &labels);
        let again = echo("Other");
        let (record2, report2) = run(
            &mut second,
            &labels,
            &previous_of(&record, &first),
            &again,
            NamingOptions::default(),
        );
        assert_eq!(again.calls(), 0);
        assert_eq!(report2.carried, 4, "{report2:?}");
        assert_eq!(record2, record);
        assert_eq!(
            first.iter().map(name_of).collect::<Vec<_>>(),
            second.iter().map(name_of).collect::<Vec<_>>()
        );
    }

    /// A parent's carry-over key covers its children's names: when a child is
    /// renamed, the parent is asked again even though its own sample did not
    /// change.
    #[test]
    fn a_parent_is_renamed_when_a_child_name_changes() {
        let (a, b, _) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).copied().collect();
        let labels = texts(&all);
        let trees = [tree(MAP, AtlasHierarchy::Meaning, &[&a, &b])];
        let mut first = docs(&trees, &labels);
        let (record, _) = run(
            &mut first,
            &labels,
            &Previous::none(),
            &echo("Topic"),
            NamingOptions::default(),
        );
        // Forget leaf a's name: it is asked again and answers differently.
        let leaf_a = key_of(&first[1]);
        let mut prev_record = record.clone();
        prev_record.keys.remove(&record_key(leaf_a));
        let mut second = docs(&trees, &labels);
        let fake = echo("Changed");
        run(
            &mut second,
            &labels,
            &previous_of(&prev_record, &first),
            &fake,
            NamingOptions::default(),
        );
        assert_eq!(
            fake.calls(),
            2,
            "the renamed leaf and its parent: {:?}",
            fake.prompts()
        );
        let root = second.iter().find(|d| depth_of(d) == 0).unwrap();
        assert!(
            name_of(root).unwrap().starts_with("Changed"),
            "{:?}",
            name_of(root)
        );
    }

    /// A member the map may not draw now (absent from `texts`) is never in a
    /// prompt, whatever the documents list.
    #[test]
    fn an_unreadable_member_feeds_no_prompt() {
        let (a, b, _) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).copied().collect();
        let labels = texts(&all);
        let mut d = docs(&[tree(MAP, AtlasHierarchy::Meaning, &[&a, &b])], &labels);
        let mut readable = labels.clone();
        let hidden = a[3];
        readable.remove(&hidden);
        let fake = echo("Topic");
        run(
            &mut d,
            &readable,
            &Previous::none(),
            &fake,
            NamingOptions::default(),
        );
        let marker = format!("TOK{}", hidden.as_u128());
        assert!(fake.calls() > 0);
        for p in fake.prompts() {
            assert!(!p.contains(&marker), "{p}");
        }
        assert!(d.iter().all(|x| !name_of(x).unwrap().contains(&marker)));
    }

    /// Every name a document repeats is its group's own: children,
    /// breadcrumbs, link targets. A stale input name is replaced, and a link
    /// to a level outside these documents carries no name.
    #[test]
    fn repeated_names_agree_with_each_group() {
        let (a, b, _) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).copied().collect();
        let labels = texts(&all);
        let mut d = docs(&[tree(MAP, AtlasHierarchy::Meaning, &[&a, &b])], &labels);
        let sibling = key_of(&d[2]).1;
        let outside = Uuid::from_u128(0xdead);
        if let LevelDocument::Leaf(l) = &mut d[1] {
            l.breadcrumbs[0].name = Some("Stale name".into());
            let src = l.nodes[0].id();
            for target in [sibling, outside] {
                l.outgoing.push(Outgoing {
                    target: LinkTarget {
                        level_id: target,
                        theme_id: THEME,
                        name: Some("Stale target".into()),
                        depth: 1,
                    },
                    count: 1,
                    net_sign: 1,
                    sources: vec![src],
                });
            }
        }
        run(
            &mut d,
            &labels,
            &Previous::none(),
            &echo("Topic"),
            NamingOptions::default(),
        );
        let names: BTreeMap<Uuid, Option<String>> =
            d.iter().map(|x| (key_of(x).1, name_of(x))).collect();
        for doc in &d {
            match doc {
                LevelDocument::Group(g) => {
                    for c in &g.children {
                        assert_eq!(c.name, names[&c.id]);
                        assert_eq!(c.needs_naming, c.name.is_none());
                    }
                }
                LevelDocument::Leaf(l) => {
                    for br in &l.breadcrumbs {
                        assert_eq!(br.name, names[&br.level_id]);
                    }
                    for o in &l.outgoing {
                        assert_eq!(
                            o.target.name,
                            names.get(&o.target.level_id).cloned().flatten()
                        );
                    }
                }
            }
            assert!(doc.to_stored_json().is_ok());
        }
        if let LevelDocument::Leaf(l) = &d[1] {
            assert_eq!(l.outgoing[1].target.name, None);
            assert!(l.outgoing[0].target.name.is_some());
        }
    }

    /// A refused or failed reply leaves the placeholder (null name, flagged),
    /// records no key, and is asked again on the next run.
    #[test]
    fn invalid_replies_fall_back_and_are_retried() {
        let (a, b, _) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).copied().collect();
        let labels = texts(&all);
        let trees = [tree(MAP, AtlasHierarchy::Meaning, &[&a, &b])];
        // The fourth quotes the first six words of the prompt's first sampled
        // claim.
        let quote = |p: &str| -> Result<String, BackendError> {
            let line = p.lines().find_map(|l| l.strip_prefix("1. ")).unwrap_or("");
            let w: Vec<&str> = line.split_whitespace().take(6).collect();
            Ok(format!("{{\"name\": \"{}\"}}", w.join(" ")))
        };
        type Reply = Box<dyn Fn(&str) -> Result<String, BackendError> + Send + Sync>;
        let replies: Vec<(&str, Reply)> = vec![
            (
                "not json",
                Box::new(|_: &str| Ok("not json at all".to_string())),
            ),
            (
                "newline",
                Box::new(|_: &str| Ok("{\"name\": \"two\\nlines\"}".to_string())),
            ),
            (
                "error",
                Box::new(|_: &str| Err(BackendError("timed out".into()))),
            ),
            ("quote", Box::new(quote)),
        ];
        for (reply, f) in replies {
            let mut d = docs(&trees, &labels);
            let bad = RecordingBackend::new(f);
            let (record, report) = run(
                &mut d,
                &labels,
                &Previous::none(),
                &bad,
                NamingOptions::default(),
            );
            assert!(report.failed > 0, "{reply:?}: {report:?}");
            for doc in &d {
                if let LevelDocument::Leaf(l) = doc {
                    assert_eq!(l.name, None, "{reply:?}");
                    assert!(l.needs_naming);
                }
                assert!(doc.to_stored_json().is_ok());
            }
            assert!(record
                .keys
                .keys()
                .all(|k| !k.contains(&key_of(&d[1]).1.to_string())));
            let mut again = docs(&trees, &labels);
            let good = echo("Topic");
            run(
                &mut again,
                &labels,
                &previous_of(&record, &d),
                &good,
                NamingOptions::default(),
            );
            assert!(
                good.calls() >= 2,
                "{reply:?}: the failed leaves are asked again"
            );
        }
    }

    /// `max_calls` stops calling; a dry run calls nothing. The rest stay
    /// flagged.
    #[test]
    fn the_budget_and_a_dry_run_defer_the_rest() {
        let (a, b, _) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).copied().collect();
        let labels = texts(&all);
        let trees = [tree(MAP, AtlasHierarchy::Meaning, &[&a, &b])];
        let mut d = docs(&trees, &labels);
        let fake = echo("Topic");
        let (_, report) = run(
            &mut d,
            &labels,
            &Previous::none(),
            &fake,
            NamingOptions {
                max_calls: Some(1),
                call_model: true,
            },
        );
        assert_eq!((fake.calls(), report.deferred), (1, 2), "{report:?}");
        let mut d = docs(&trees, &labels);
        let fake = echo("Topic");
        let (_, report) = run(
            &mut d,
            &labels,
            &Previous::none(),
            &fake,
            NamingOptions {
                max_calls: None,
                call_model: false,
            },
        );
        assert_eq!((fake.calls(), report.deferred), (0, 3), "{report:?}");
        assert!(d.iter().all(|x| name_of(x).is_none()));
    }

    /// Links levels are named like meaning ones; a theme that is one root
    /// leaf in both hierarchies gets ONE call and the same name in both.
    #[test]
    fn links_levels_are_named_and_an_identical_input_is_one_call() {
        let (a, b, c) = corpus();
        let all: Vec<Uuid> = a.iter().chain(&b).chain(&c).copied().collect();
        let labels = texts(&all);
        let trees = [
            root_leaf(MAP, AtlasHierarchy::Meaning, &c),
            root_leaf(MAP, AtlasHierarchy::Links, &c),
        ];
        let mut d = docs(&trees, &labels);
        let fake = echo("Topic");
        let (record, report) = run(
            &mut d,
            &labels,
            &Previous::none(),
            &fake,
            NamingOptions::default(),
        );
        assert_eq!((fake.calls(), report.shared), (1, 1), "{report:?}");
        assert_eq!(name_of(&d[0]), name_of(&d[1]));
        assert_eq!(record.keys.len(), 2);
        assert!(record.keys.keys().any(|k| k.starts_with("links/")));
    }

    /// The sample depends on the members only, not on node order, and is
    /// capped at the candidate count.
    #[test]
    fn the_sample_is_deterministic_and_order_free() {
        let many = ids(0x1000, 60);
        let labels = texts(&many);
        let t = root_leaf(MAP, AtlasHierarchy::Meaning, &many);
        let d1 = docs(std::slice::from_ref(&t), &labels);
        let mut d2 = d1.clone();
        if let LevelDocument::Leaf(l) = &mut d2[0] {
            l.nodes.reverse();
        }
        let (p1, p2) = (plan_samples(&d1).unwrap(), plan_samples(&d2).unwrap());
        assert_eq!(p1, p2);
        assert_eq!(p1.claim_ids().len(), CANDIDATES);
    }
}
