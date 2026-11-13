//! Fill the precomputed positions into one Atlas run's level documents
//! (Atlas W6, backlog f52fff97), skipping every level whose layout input has
//! not changed since the previous run.
//!
//! # What it reads
//!
//! Only the W10a level documents (schema v1), which carry everything a
//! layout needs: a leaf's nodes (ids, kinds) and edges, and a group level's
//! children (ids, `claim_count`) and the bundles between siblings. So the fill
//! does not depend on how the hierarchies (W4 by meaning, W5 by links) are
//! built: whoever assembles a run's documents calls [`fill_positions`] on them
//! before the run is written. A bundle to a group outside the level (a
//! `targets` entry) does not move a child; only sibling bundles do.
//!
//! The documents hold text (labels, names); the inputs extracted from them
//! ([`leaf_input`], [`group_input`]) and the positions put back do not. That is
//! the line along which the pure layout ([`super::force`]) may run off the box.
//!
//! # The layout record and the skip
//!
//! Each level's input hash goes into a [`LayoutRecord`], stored in the run's
//! `params` under [`PARAMS_KEY`]:
//!
//! ```json
//! {"layout": {"algo": "atlas-w6-v1", "hashes": {"meaning/<group id>": "<hex>"}}}
//! ```
//!
//! The next night builds a [`PreviousRun`] from the previous run's `params`
//! and its stored documents. A level whose hash equals the recorded one, under
//! the same algorithm, takes the previous document's positions, copied by node
//! or child id, and is not laid out again ([`FillReport::reused`]). Anything
//! else is laid out ([`FillReport::computed`]).
//!
//! `write_run` takes `params` when the run opens, so the build lays out every
//! level in memory first, then writes the run with [`FillReport::record`]
//! merged into its `params` ([`LayoutRecord::write_into`]), then its levels.
//! If the record outgrows a run row on the largest maps, the upgrade path is a
//! nullable hash column beside each stored level.

use std::collections::BTreeMap;
use std::fmt;

use epigraph_atlas_contract::{GroupLevel, Hierarchy, LeafLevel, LevelDocument, Node, NodeKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::force::{
    group_input_hash, layout_group, layout_leaf, leaf_input_hash, GroupInput, LayoutError,
    LayoutNodeKind, LeafInput, LAYOUT_ALGO,
};

/// The key of the layout record in a run's `params`.
pub const PARAMS_KEY: &str = "layout";

/// The record key of one level: `"<hierarchy>/<group id>"`.
#[must_use]
pub fn level_key(hierarchy: Hierarchy, level_id: Uuid) -> String {
    let h = match hierarchy {
        Hierarchy::Meaning => "meaning",
        Hierarchy::Links => "links",
    };
    format!("{h}/{}", level_id.hyphenated())
}

fn layout_kind(kind: NodeKind) -> LayoutNodeKind {
    match kind {
        NodeKind::Claim => LayoutNodeKind::Claim,
        NodeKind::Agent => LayoutNodeKind::Agent,
        NodeKind::Evidence => LayoutNodeKind::Evidence,
    }
}

/// A leaf document's layout input: its node ids and kinds and its edges as
/// undirected pairs. Labels, truth values and flow weights are not read.
///
/// # Errors
/// What [`LeafInput::new`] refuses (a document that passes
/// `LevelDocument::validate` never is).
pub fn leaf_input(leaf: &LeafLevel) -> Result<LeafInput, LayoutError> {
    LeafInput::new(
        leaf.nodes.iter().map(|n| (n.id(), layout_kind(n.kind()))),
        leaf.edges.iter().map(|e| (e.source, e.target)),
    )
}

/// A group document's layout input: each child with its `claim_count`, and
/// the bundles between two children with their counts. Names and bundles to
/// a `targets` entry are not read.
///
/// # Errors
/// What [`GroupInput::new`] refuses (a document that passes
/// `LevelDocument::validate` never is).
pub fn group_input(group: &GroupLevel) -> Result<GroupInput, LayoutError> {
    let children: BTreeMap<Uuid, u64> = group
        .children
        .iter()
        .map(|c| (c.id, u64::from(c.claim_count)))
        .collect();
    if children.len() != group.children.len() {
        let mut seen = std::collections::BTreeSet::new();
        let dup = group
            .children
            .iter()
            .find(|c| !seen.insert(c.id))
            .map_or(Uuid::nil(), |c| c.id);
        return Err(LayoutError::DuplicateNode(dup));
    }
    let links: Vec<(Uuid, Uuid, u64)> = group
        .bundles
        .iter()
        .filter(|b| children.contains_key(&b.source) && children.contains_key(&b.target))
        .map(|b| (b.source, b.target, u64::from(b.count)))
        .collect();
    GroupInput::new(children, links)
}

/// The input hash of one document: what the stored record keeps for it.
///
/// # Errors
/// A malformed document, as [`leaf_input`] or [`group_input`].
pub fn input_hash(doc: &LevelDocument) -> Result<String, LayoutError> {
    Ok(match doc {
        LevelDocument::Leaf(l) => leaf_input_hash(l.level_id, &leaf_input(l)?),
        LevelDocument::Group(g) => group_input_hash(g.level_id, &group_input(g)?),
    })
}

/// The layout record of one run: the algorithm and each level's input hash,
/// by [`level_key`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutRecord {
    pub algo: String,
    pub hashes: BTreeMap<String, String>,
}

impl Default for LayoutRecord {
    fn default() -> Self {
        Self {
            algo: LAYOUT_ALGO.to_string(),
            hashes: BTreeMap::new(),
        }
    }
}

impl LayoutRecord {
    /// The record a run's `params` holds under [`PARAMS_KEY`], if any. A
    /// malformed record reads as none, so its run's layouts are recomputed.
    #[must_use]
    pub fn from_params(params: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(params.get(PARAMS_KEY)?.clone()).ok()
    }

    /// Store the record in `params` under [`PARAMS_KEY`], keeping every other
    /// key. `null` becomes an object.
    ///
    /// # Errors
    /// [`FillError::ParamsNotAnObject`] when `params` is neither an object
    /// nor `null`.
    pub fn write_into(&self, params: &mut serde_json::Value) -> Result<(), FillError> {
        if params.is_null() {
            *params = serde_json::Value::Object(serde_json::Map::new());
        }
        let obj = params.as_object_mut().ok_or(FillError::ParamsNotAnObject)?;
        obj.insert(
            PARAMS_KEY.to_string(),
            serde_json::to_value(self).expect("a map of strings serialises"),
        );
        Ok(())
    }
}

/// What the previous run left: its layout record and its documents.
#[derive(Debug, Clone, Default)]
pub struct PreviousRun {
    record: Option<LayoutRecord>,
    levels: BTreeMap<(Hierarchy, Uuid), LevelDocument>,
}

impl PreviousRun {
    /// From the previous run's `params` and stored payloads. A payload that
    /// is not a schema-v1 document is left out (its level is laid out again);
    /// so is the whole record when it names another algorithm.
    #[must_use]
    pub fn new(
        params: &serde_json::Value,
        payloads: impl IntoIterator<Item = serde_json::Value>,
    ) -> Self {
        let record = LayoutRecord::from_params(params).filter(|r| r.algo == LAYOUT_ALGO);
        let levels = payloads
            .into_iter()
            .filter_map(|p| serde_json::from_value::<LevelDocument>(p).ok())
            .map(|d| ((hierarchy_of(&d), d.level_id()), d))
            .collect();
        Self { record, levels }
    }

    /// The previous positions of `doc`'s level, when its hash is the one
    /// recorded and the previous document places every node or child `doc`
    /// has.
    fn reusable(&self, doc: &LevelDocument, hash: &str) -> Option<&LevelDocument> {
        let key = level_key(hierarchy_of(doc), doc.level_id());
        let recorded = self.record.as_ref()?.hashes.get(&key)?;
        if recorded != hash {
            return None;
        }
        let prev = self.levels.get(&(hierarchy_of(doc), doc.level_id()))?;
        let covers = match (doc, prev) {
            (LevelDocument::Leaf(now), LevelDocument::Leaf(was)) => {
                let ids: std::collections::BTreeSet<Uuid> =
                    was.nodes.iter().map(Node::id).collect();
                now.nodes.iter().all(|n| ids.contains(&n.id()))
            }
            (LevelDocument::Group(now), LevelDocument::Group(was)) => {
                let ids: std::collections::BTreeSet<Uuid> =
                    was.children.iter().map(|c| c.id).collect();
                now.children.iter().all(|c| ids.contains(&c.id))
            }
            _ => false,
        };
        covers.then_some(prev)
    }
}

fn hierarchy_of(doc: &LevelDocument) -> Hierarchy {
    match doc {
        LevelDocument::Group(g) => g.hierarchy,
        LevelDocument::Leaf(l) => l.hierarchy,
    }
}

/// What [`fill_positions`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillReport {
    /// Levels laid out in this call.
    pub computed: usize,
    /// Levels that kept the previous run's positions.
    pub reused: usize,
    /// The record to store with the new run.
    pub record: LayoutRecord,
}

/// Why [`fill_positions`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// A document's layout input is malformed.
    Layout { level: String, error: LayoutError },
    /// Two documents of one run share a hierarchy and group id.
    DuplicateLevel(String),
    /// A run's `params` is neither an object nor `null`.
    ParamsNotAnObject,
}

impl fmt::Display for FillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layout { level, error } => write!(f, "level {level}: {error}"),
            Self::DuplicateLevel(level) => write!(f, "level {level} is given twice"),
            Self::ParamsNotAnObject => f.write_str("the run's params is not a JSON object"),
        }
    }
}

impl std::error::Error for FillError {}

fn set_xy(node: &mut Node, x: f64, y: f64) {
    match node {
        Node::Claim(n) => {
            n.x = x;
            n.y = y;
        }
        Node::Agent(n) | Node::Evidence(n) => {
            n.x = x;
            n.y = y;
        }
    }
}

fn node_xy(node: &Node) -> (f64, f64) {
    match node {
        Node::Claim(n) => (n.x, n.y),
        Node::Agent(n) | Node::Evidence(n) => (n.x, n.y),
    }
}

/// Fill every position of `docs`: each leaf node's `x`, `y` and each group
/// child's `x`, `y`, `r`. A level whose input hash `previous` recorded keeps
/// the previous document's positions; every other level is laid out, seeded
/// by its own group id.
///
/// The documents are otherwise untouched. Validating and measuring them
/// (`LevelDocument::to_stored_json`) stays the writer's step.
///
/// # Errors
/// [`FillError::Layout`] for a malformed document,
/// [`FillError::DuplicateLevel`] for a level given twice. Nothing is filled
/// then.
pub fn fill_positions(
    docs: &mut [LevelDocument],
    previous: Option<&PreviousRun>,
) -> Result<FillReport, FillError> {
    // Hash everything first, so a refusal leaves every document as it was.
    let mut hashes = Vec::with_capacity(docs.len());
    let mut record = LayoutRecord::default();
    for doc in docs.iter() {
        let key = level_key(hierarchy_of(doc), doc.level_id());
        let hash = input_hash(doc).map_err(|error| FillError::Layout {
            level: key.clone(),
            error,
        })?;
        if record.hashes.insert(key.clone(), hash.clone()).is_some() {
            return Err(FillError::DuplicateLevel(key));
        }
        hashes.push(hash);
    }

    let (mut computed, mut reused) = (0, 0);
    for (doc, hash) in docs.iter_mut().zip(&hashes) {
        if let Some(prev) = previous.and_then(|p| p.reusable(doc, hash)) {
            copy_positions(doc, prev);
            reused += 1;
            continue;
        }
        match doc {
            LevelDocument::Leaf(l) => {
                let input = leaf_input(l).expect("hashed above");
                let pos = layout_leaf(l.level_id, &input);
                for n in &mut l.nodes {
                    let [x, y] = pos[&n.id()];
                    set_xy(n, x, y);
                }
            }
            LevelDocument::Group(g) => {
                let input = group_input(g).expect("hashed above");
                let placed = layout_group(g.level_id, &input);
                for c in &mut g.children {
                    let p = placed[&c.id];
                    c.x = p.x;
                    c.y = p.y;
                    c.r = p.r;
                }
            }
        }
        computed += 1;
    }
    Ok(FillReport {
        computed,
        reused,
        record,
    })
}

/// Copy `prev`'s positions into `doc`, by node or child id ([`PreviousRun::reusable`]
/// checked that `prev` covers every id).
fn copy_positions(doc: &mut LevelDocument, prev: &LevelDocument) {
    match (doc, prev) {
        (LevelDocument::Leaf(now), LevelDocument::Leaf(was)) => {
            let at: BTreeMap<Uuid, (f64, f64)> =
                was.nodes.iter().map(|n| (n.id(), node_xy(n))).collect();
            for n in &mut now.nodes {
                let (x, y) = at[&n.id()];
                set_xy(n, x, y);
            }
        }
        (LevelDocument::Group(now), LevelDocument::Group(was)) => {
            let at: BTreeMap<Uuid, (f64, f64, f64)> = was
                .children
                .iter()
                .map(|c| (c.id, (c.x, c.y, c.r)))
                .collect();
            for c in &mut now.children {
                (c.x, c.y, c.r) = at[&c.id];
            }
        }
        _ => unreachable!("reusable() matched the kinds"),
    }
}

/// A W3 leaf node set's layout input (Atlas W3, `assemble_leaf`'s output).
/// W3 points its edges the way the stored row points and W10a the way belief
/// flows, which the layout does not use, so a node set and the leaf document
/// built from it give the same input and the same hash.
///
/// # Errors
/// What [`LeafInput::new`] refuses (W3's assembly never produces it).
#[cfg(feature = "db")]
pub fn leaf_input_from_node_set(
    set: &epigraph_db::repos::atlas_leaf::LeafNodeSet,
) -> Result<LeafInput, LayoutError> {
    use epigraph_db::repos::atlas_leaf::LeafNodeKind;
    let kind = |k: LeafNodeKind| match k {
        LeafNodeKind::Claim => LayoutNodeKind::Claim,
        LeafNodeKind::Agent => LayoutNodeKind::Agent,
        LeafNodeKind::Evidence => LayoutNodeKind::Evidence,
    };
    LeafInput::new(
        set.nodes.iter().map(|n| (n.id, kind(n.kind))),
        set.edges.iter().map(|e| (e.source.id, e.target.id)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use epigraph_atlas_contract::fixtures;

    /// The contract's fixture levels (two groups, two leaves) with every
    /// position at the origin: what an assembler hands the fill.
    fn unplaced() -> Vec<LevelDocument> {
        fixtures::level_fixtures()
            .into_iter()
            .map(|(_, mut d)| {
                zero(&mut d);
                d
            })
            .collect()
    }

    fn zero(d: &mut LevelDocument) {
        match d {
            LevelDocument::Leaf(l) => l.nodes.iter_mut().for_each(|n| set_xy(n, 0.0, 0.0)),
            LevelDocument::Group(g) => g.children.iter_mut().for_each(|c| {
                c.x = 0.0;
                c.y = 0.0;
                c.r = 0.5;
            }),
        }
    }

    /// Every position of a document, in document order.
    fn positions(d: &LevelDocument) -> Vec<(Uuid, f64, f64, f64)> {
        match d {
            LevelDocument::Leaf(l) => l
                .nodes
                .iter()
                .map(|n| {
                    let (x, y) = node_xy(n);
                    (n.id(), x, y, 0.0)
                })
                .collect(),
            LevelDocument::Group(g) => g.children.iter().map(|c| (c.id, c.x, c.y, c.r)).collect(),
        }
    }

    /// Distinct valid positions no layout would produce: the previous run's
    /// stored values, as far as the skip can tell.
    fn sentinel(d: &mut LevelDocument) {
        match d {
            LevelDocument::Leaf(l) => {
                for (i, n) in l.nodes.iter_mut().enumerate() {
                    set_xy(n, -0.5 + 0.0001 * i as f64, 0.25);
                }
            }
            LevelDocument::Group(g) => {
                for (i, c) in g.children.iter_mut().enumerate() {
                    c.x = 0.0003 * i as f64;
                    c.y = -0.125;
                    c.r = 0.0001;
                }
            }
        }
    }

    fn previous_from(record: &LayoutRecord, docs: &[LevelDocument]) -> PreviousRun {
        let mut params = serde_json::json!({"min_members": 1});
        record.write_into(&mut params).unwrap();
        PreviousRun::new(
            &params,
            docs.iter().map(|d| serde_json::to_value(d).unwrap()),
        )
    }

    fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
        ((a.0 - b.0) * (a.0 - b.0) + (a.1 - b.1) * (a.1 - b.1)).sqrt()
    }

    #[test]
    fn filled_fixture_levels_validate_and_keep_the_layout_bounds() {
        let mut docs = unplaced();
        let report = fill_positions(&mut docs, None).unwrap();
        assert_eq!((report.computed, report.reused), (4, 0));
        assert_eq!(report.record.hashes.len(), 4);
        for d in &docs {
            d.to_stored_json().unwrap_or_else(|v| panic!("{v}"));
            match d {
                LevelDocument::Leaf(l) => {
                    for (i, a) in l.nodes.iter().enumerate() {
                        let pa = node_xy(a);
                        assert!(dist(pa, (0.0, 0.0)) <= super::super::force::LEAF_RADIUS);
                        for b in &l.nodes[i + 1..] {
                            assert!(
                                dist(pa, node_xy(b)) >= super::super::force::LEAF_MIN_DISTANCE,
                                "{} and {} too close",
                                a.id(),
                                b.id()
                            );
                        }
                    }
                }
                LevelDocument::Group(g) => {
                    for (i, a) in g.children.iter().enumerate() {
                        assert!(dist((a.x, a.y), (0.0, 0.0)) + a.r <= 1.0);
                        for b in &g.children[i + 1..] {
                            assert!(dist((a.x, a.y), (b.x, b.y)) >= a.r + b.r);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn an_unchanged_level_reuses_the_previous_positions_and_is_not_laid_out() {
        let mut first = unplaced();
        let r1 = fill_positions(&mut first, None).unwrap();
        // The stored documents of the previous run, with positions the
        // layout would never produce: only a copy can bring them back.
        let mut stored = first.clone();
        stored.iter_mut().for_each(sentinel);
        // Stored in another node and child order: the copy goes by id.
        let mut reordered = stored.clone();
        for d in &mut reordered {
            match d {
                LevelDocument::Leaf(l) => l.nodes.reverse(),
                LevelDocument::Group(g) => g.children.reverse(),
            }
        }
        let prev = previous_from(&r1.record, &reordered);

        let mut again = unplaced();
        let r2 = fill_positions(&mut again, Some(&prev)).unwrap();
        assert_eq!((r2.computed, r2.reused), (0, 4));
        assert_eq!(r2.record, r1.record);
        for (now, was) in again.iter().zip(&stored) {
            assert_eq!(positions(now), positions(was));
        }
    }

    #[test]
    fn one_changed_leaf_is_the_only_one_laid_out_again() {
        let mut first = unplaced();
        let r1 = fill_positions(&mut first, None).unwrap();
        let mut stored = first.clone();
        stored.iter_mut().for_each(sentinel);
        let prev = previous_from(&r1.record, &stored);

        let mut again = unplaced();
        let changed = again
            .iter()
            .position(|d| matches!(d, LevelDocument::Leaf(_)))
            .unwrap();
        let LevelDocument::Leaf(l) = &mut again[changed] else {
            unreachable!()
        };
        // Drop the only edge between two claims: the node set stays valid,
        // and the pair (which the layout reads undirected) is gone.
        let pair =
            |e: &epigraph_atlas_contract::Edge| (e.source.min(e.target), e.source.max(e.target));
        let cut = l
            .edges
            .iter()
            .position(|e| {
                e.flow_basis == epigraph_atlas_contract::FlowBasis::Proxy
                    && l.edges.iter().filter(|o| pair(o) == pair(e)).count() == 1
            })
            .unwrap();
        l.edges.remove(cut);
        let r2 = fill_positions(&mut again, Some(&prev)).unwrap();
        assert_eq!((r2.computed, r2.reused), (1, 3));
        let key = level_key(hierarchy_of(&again[changed]), again[changed].level_id());
        assert_ne!(r2.record.hashes[&key], r1.record.hashes[&key]);
        for (i, (now, was)) in again.iter().zip(&stored).enumerate() {
            if i == changed {
                assert_ne!(positions(now), positions(was));
                now.validate().unwrap();
            } else {
                assert_eq!(positions(now), positions(was));
            }
        }
    }

    #[test]
    fn a_record_of_another_algorithm_or_a_missing_document_is_not_reused() {
        let mut first = unplaced();
        let r1 = fill_positions(&mut first, None).unwrap();

        let mut old = r1.record.clone();
        old.algo = "atlas-w6-v0".into();
        let prev = previous_from(&old, &first);
        let r2 = fill_positions(&mut unplaced(), Some(&prev)).unwrap();
        assert_eq!((r2.computed, r2.reused), (4, 0));

        // The hash matches but the previous document is gone.
        let prev = previous_from(&r1.record, &first[1..]);
        let r3 = fill_positions(&mut unplaced(), Some(&prev)).unwrap();
        assert_eq!((r3.computed, r3.reused), (1, 3));

        // No record at all.
        let prev = PreviousRun::new(
            &serde_json::json!({}),
            first.iter().map(|d| serde_json::to_value(d).unwrap()),
        );
        let r4 = fill_positions(&mut unplaced(), Some(&prev)).unwrap();
        assert_eq!((r4.computed, r4.reused), (4, 0));
    }

    #[test]
    fn a_previous_document_that_does_not_place_every_id_is_not_copied() {
        // A record whose hashes match, beside stored documents that do not
        // (a hand-edited or half-written previous run): each such level is
        // laid out again instead of copied with holes.
        let mut first = unplaced();
        let r1 = fill_positions(&mut first, None).unwrap();
        let mut stored = first.clone();
        let leaf = stored
            .iter()
            .position(|d| matches!(d, LevelDocument::Leaf(_)))
            .unwrap();
        let group = stored
            .iter()
            .position(|d| matches!(d, LevelDocument::Group(_)))
            .unwrap();
        if let LevelDocument::Leaf(l) = &mut stored[leaf] {
            l.nodes.pop();
        }
        if let LevelDocument::Group(g) = &mut stored[group] {
            g.children.pop();
        }
        let prev = previous_from(&r1.record, &stored);
        let mut again = unplaced();
        let r2 = fill_positions(&mut again, Some(&prev)).unwrap();
        assert_eq!((r2.computed, r2.reused), (2, 2));
        assert_eq!(positions(&again[leaf]), positions(&first[leaf]));
        assert_eq!(positions(&again[group]), positions(&first[group]));
    }

    #[test]
    fn the_hash_ignores_text_flow_and_direction_but_not_structure() {
        let docs = unplaced();
        let leaf = docs
            .iter()
            .find(|d| matches!(d, LevelDocument::Leaf(_)))
            .unwrap()
            .clone();
        let group = docs
            .iter()
            .find(|d| matches!(d, LevelDocument::Group(g) if !g.targets.is_empty()))
            .unwrap()
            .clone();
        let (hl, hg) = (input_hash(&leaf).unwrap(), input_hash(&group).unwrap());

        let mut l2 = leaf.clone();
        let LevelDocument::Leaf(l) = &mut l2 else {
            unreachable!()
        };
        for n in &mut l.nodes {
            match n {
                Node::Claim(c) => {
                    c.label = "another label".into();
                    c.truth_value = Some(0.5);
                }
                Node::Agent(p) | Node::Evidence(p) => p.label = "renamed".into(),
            }
        }
        for e in &mut l.edges {
            std::mem::swap(&mut e.source, &mut e.target);
            e.flow_weight = 0.0;
            e.relationship = "cites".into();
        }
        l.name = Some("a new name".into());
        l.outgoing.clear();
        assert_eq!(input_hash(&l2).unwrap(), hl);

        let mut g2 = group.clone();
        let LevelDocument::Group(g) = &mut g2 else {
            unreachable!()
        };
        for c in &mut g.children {
            c.name = Some("renamed".into());
        }
        let child_ids: std::collections::BTreeSet<Uuid> = g.children.iter().map(|c| c.id).collect();
        // Bundles to groups outside the level do not move a child.
        g.bundles.retain(|b| child_ids.contains(&b.target));
        g.targets.clear();
        for b in &mut g.bundles {
            std::mem::swap(&mut b.source, &mut b.target);
        }
        assert_eq!(input_hash(&g2).unwrap(), hg);

        // A child's size is an input.
        let LevelDocument::Group(g) = &mut g2 else {
            unreachable!()
        };
        g.children[0].claim_count += 1;
        assert_ne!(input_hash(&g2).unwrap(), hg);
    }

    #[test]
    fn the_record_round_trips_through_run_params_beside_other_keys() {
        let mut docs = unplaced();
        let r = fill_positions(&mut docs, None).unwrap();
        let mut params = serde_json::json!({"min_members": 3});
        r.record.write_into(&mut params).unwrap();
        assert_eq!(params["min_members"], 3);
        assert_eq!(params[PARAMS_KEY]["algo"], LAYOUT_ALGO);
        assert_eq!(LayoutRecord::from_params(&params), Some(r.record.clone()));
        let mut null = serde_json::Value::Null;
        r.record.write_into(&mut null).unwrap();
        assert_eq!(LayoutRecord::from_params(&null), Some(r.record));
        assert_eq!(
            LayoutRecord::default().write_into(&mut serde_json::json!([1])),
            Err(FillError::ParamsNotAnObject)
        );
        assert_eq!(
            LayoutRecord::from_params(&serde_json::json!({"layout": 7})),
            None
        );
    }

    #[test]
    fn a_level_given_twice_is_refused_and_nothing_is_filled() {
        let mut docs = unplaced();
        docs.push(docs[0].clone());
        let before = docs.clone();
        assert!(matches!(
            fill_positions(&mut docs, None),
            Err(FillError::DuplicateLevel(_))
        ));
        assert_eq!(docs, before);
        // One hierarchy's key is not the other's.
        let id = Uuid::from_u64_pair(1, 1);
        assert_ne!(
            level_key(Hierarchy::Meaning, id),
            level_key(Hierarchy::Links, id)
        );
    }

    #[cfg(feature = "db")]
    #[test]
    fn a_w3_node_set_and_its_leaf_document_hash_and_lay_out_alike() {
        use epigraph_db::repos::atlas_leaf::{
            LeafCounts, LeafEdge, LeafEdgeOrigin, LeafNode, LeafNodeSet,
        };
        let doc = unplaced()
            .into_iter()
            .find(|d| matches!(d, LevelDocument::Leaf(_)))
            .unwrap();
        let LevelDocument::Leaf(l) = &doc else {
            unreachable!()
        };
        let node = |n: &Node| match n.kind() {
            NodeKind::Claim => LeafNode::claim(n.id()),
            NodeKind::Agent => LeafNode::agent(n.id()),
            NodeKind::Evidence => LeafNode::evidence(n.id()),
        };
        let by_id: BTreeMap<Uuid, LeafNode> = l.nodes.iter().map(|n| (n.id(), node(n))).collect();
        // W3 points a stored claim -> evidence row as stored; W10a points
        // evidence -> claim. Reverse every edge to model that.
        let set = LeafNodeSet {
            nodes: l.nodes.iter().map(node).collect(),
            edges: l
                .edges
                .iter()
                .map(|e| LeafEdge {
                    source: by_id[&e.target],
                    target: by_id[&e.source],
                    relationship: e.relationship.clone(),
                    origin: LeafEdgeOrigin::Stored { edge_ids: vec![] },
                })
                .collect(),
            capped: vec![],
            counts: LeafCounts::default(),
        };
        let from_set = leaf_input_from_node_set(&set).unwrap();
        assert_eq!(from_set, leaf_input(l).unwrap());
        assert_eq!(
            leaf_input_hash(l.level_id, &from_set),
            input_hash(&doc).unwrap()
        );

        let mut filled = vec![doc.clone()];
        fill_positions(&mut filled, None).unwrap();
        let pos = layout_leaf(l.level_id, &from_set);
        let LevelDocument::Leaf(fl) = &filled[0] else {
            unreachable!()
        };
        for n in &fl.nodes {
            let (x, y) = node_xy(n);
            assert_eq!([x, y], pos[&n.id()]);
        }
    }
}
