//! The nightly's incremental update of one theme's two trees (pure: no
//! database). Each starts from the previous run's tree ([`super::previous`])
//! and the members the map draws now, and returns the new shape, which the
//! caller mints ([`to_wire`]) and checks with W4's `check_tree` and
//! `resolve_tree` exactly as an operator-built result is checked.
//!
//! **By meaning.** A claim that left is removed. A new claim joins the leaf
//! whose centroid (the normalised mean of its remaining members' L2-normalised
//! embeddings) is nearest by cosine, ties to the earlier leaf in pre-order.
//! Centroids are taken BEFORE any new claim is placed, so the result does not
//! depend on the order new claims are visited. A leaf over the node cap is
//! left to `resolve_tree` (W3's on-box fallback split). No UMAP, no k-means:
//! ids and embeddings only.
//!
//! **By links**, against the RESOLVED meaning tree (W5b's mirrors follow its
//! leaves). Each previous leaf keeps a role: a MIRROR when the previous run
//! recorded it as one (or, for a run with no record, when at least half its
//! surviving claims are unlinked now), else a LINKED leaf. Each meaning leaf's
//! unlinked claims form exactly one mirror (W5b), placed where the previous
//! mirror holding most of them was, or new under the root. Linked leaves keep
//! their linked claims; a new or newly linked claim joins the linked leaf
//! holding most of its counted neighbours, repeated until nothing moves; the
//! rest are cut into connected components and packed first fit into new
//! leaves under the root (a union is packed only while W3 says it fits).
//!
//! Both: empty leaves are dropped and a level left with one child is replaced
//! by that child, so no level has a single child (W4's rule); every id is
//! re-minted from the members, so an unchanged group keeps its id.

use std::collections::{BTreeMap, BTreeSet};

use epigraph_db::repos::atlas_map::{AtlasHierarchy, AtlasMap};
use uuid::Uuid;

use super::previous::{PrevBody, PrevTree};
use crate::atlas_meaning::tree::{group_id, root_id, MeaningTree, NodeBody, WireGroup, WireKind};

/// A tree before ids are minted: leaves of claims, groups of children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// A leaf's claims, sorted.
    Leaf(Vec<Uuid>),
    /// A group's children, in display order.
    Group(Vec<Shape>),
}

impl Shape {
    /// Every claim under this shape, sorted.
    #[must_use]
    pub fn claims(&self) -> BTreeSet<Uuid> {
        match self {
            Self::Leaf(c) => c.iter().copied().collect(),
            Self::Group(k) => k.iter().flat_map(Self::claims).collect(),
        }
    }
}

/// One node of a [`Draft`].
#[derive(Debug, Clone)]
enum DBody {
    Leaf(Vec<Uuid>),
    Group(Vec<usize>),
}

/// A mutable tree: an arena whose node 0 is the root. `ids` holds each
/// node's id in the previous run (`None` for a node added this night).
#[derive(Debug, Clone)]
struct Draft {
    nodes: Vec<DBody>,
    ids: Vec<Option<Uuid>>,
}

impl Draft {
    fn root_group() -> Self {
        Self {
            nodes: vec![DBody::Group(Vec::new())],
            ids: vec![None],
        }
    }

    fn from_prev(prev: &PrevTree) -> Self {
        fn add(
            prev: &PrevTree,
            id: Uuid,
            out: &mut Vec<DBody>,
            ids: &mut Vec<Option<Uuid>>,
        ) -> usize {
            let at = out.len();
            out.push(DBody::Leaf(Vec::new()));
            ids.push(Some(id));
            out[at] = match &prev.nodes[&id] {
                PrevBody::Leaf(c) => DBody::Leaf(c.clone()),
                PrevBody::Group(children) => {
                    let kids = children.iter().map(|c| add(prev, *c, out, ids)).collect();
                    DBody::Group(kids)
                }
            };
            at
        }
        let mut nodes = Vec::new();
        let mut ids = Vec::new();
        add(prev, prev.root, &mut nodes, &mut ids);
        Self { nodes, ids }
    }

    /// The leaf indices in pre-order.
    fn leaves(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![0];
        while let Some(i) = stack.pop() {
            match &self.nodes[i] {
                DBody::Leaf(_) => out.push(i),
                DBody::Group(k) => stack.extend(k.iter().rev()),
            }
        }
        out
    }

    fn claims_mut(&mut self, leaf: usize) -> &mut Vec<Uuid> {
        match &mut self.nodes[leaf] {
            DBody::Leaf(c) => c,
            DBody::Group(_) => unreachable!("a leaf index"),
        }
    }

    fn claims(&self, leaf: usize) -> &[Uuid] {
        match &self.nodes[leaf] {
            DBody::Leaf(c) => c,
            DBody::Group(_) => &[],
        }
    }

    fn retain(&mut self, keep: impl Fn(&Uuid) -> bool) {
        for n in &mut self.nodes {
            if let DBody::Leaf(c) = n {
                c.retain(&keep);
            }
        }
    }

    /// Add a leaf under the root (the root is a group here) and return it.
    fn push_leaf(&mut self, claims: Vec<Uuid>) -> usize {
        let at = self.nodes.len();
        self.nodes.push(DBody::Leaf(claims));
        self.ids.push(None);
        if let DBody::Group(k) = &mut self.nodes[0] {
            k.push(at);
        }
        at
    }

    /// The shape with empty leaves dropped and single-child levels replaced
    /// by their child; `None` when no claim is left.
    fn collapse(&self) -> Option<Shape> {
        fn go(d: &Draft, i: usize) -> Option<Shape> {
            match &d.nodes[i] {
                DBody::Leaf(c) if c.is_empty() => None,
                DBody::Leaf(c) => {
                    let mut c = c.clone();
                    c.sort_unstable();
                    c.dedup();
                    Some(Shape::Leaf(c))
                }
                DBody::Group(k) => {
                    let mut kids: Vec<Shape> = k.iter().filter_map(|c| go(d, *c)).collect();
                    match kids.len() {
                        0 => None,
                        1 => kids.pop(),
                        _ => Some(Shape::Group(kids)),
                    }
                }
            }
        }
        go(self, 0)
    }
}

fn normalised(v: &[f32]) -> Vec<f64> {
    let n: f64 = v.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
    if n == 0.0 {
        return v.iter().map(|_| 0.0).collect();
    }
    v.iter().map(|x| f64::from(*x) / n).collect()
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// What [`update_meaning`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeaningDelta {
    /// Members not in the previous tree, each placed by nearest centroid.
    pub added: usize,
    /// Claims of the previous tree that are no longer members.
    pub removed: usize,
}

/// The new "by meaning" shape of one theme: the previous tree, with the
/// claims that left removed and each member it lacks placed in the leaf with
/// the nearest centroid (module docs). `members` maps every current member to
/// its embedding. `None` when there is no member.
#[must_use]
pub fn update_meaning(
    prev: &PrevTree,
    members: &BTreeMap<Uuid, Vec<f32>>,
) -> (Option<Shape>, MeaningDelta) {
    let mut d = Draft::from_prev(prev);
    let before = prev.claims();
    let removed = before.iter().filter(|c| !members.contains_key(c)).count();
    d.retain(|c| members.contains_key(c));
    let new: Vec<Uuid> = members
        .keys()
        .filter(|c| !before.contains(c))
        .copied()
        .collect();
    let delta = MeaningDelta {
        added: new.len(),
        removed,
    };
    if new.is_empty() {
        return (d.collapse(), delta);
    }
    let leaves: Vec<usize> = d
        .leaves()
        .into_iter()
        .filter(|l| !d.claims(*l).is_empty())
        .collect();
    if leaves.is_empty() {
        // Every previous claim left: the new ones are the whole theme. The
        // root leaf is over the cap or not; `resolve_tree` decides.
        return (Some(Shape::Leaf(new)), delta);
    }
    let centroids: Vec<(usize, Vec<f64>)> = leaves
        .iter()
        .map(|&l| {
            let mut sum: Vec<f64> = Vec::new();
            for c in d.claims(l) {
                let v = normalised(&members[c]);
                if sum.is_empty() {
                    sum = v;
                } else {
                    for (s, x) in sum.iter_mut().zip(v) {
                        *s += x;
                    }
                }
            }
            #[allow(clippy::cast_possible_truncation)]
            let as32: Vec<f32> = sum.iter().map(|x| *x as f32).collect();
            (l, normalised(&as32))
        })
        .collect();
    for c in new {
        let v = normalised(&members[&c]);
        let mut best: Option<(usize, f64)> = None;
        for (l, cen) in &centroids {
            let s = dot(cen, &v);
            if best.is_none_or(|(_, b)| s > b) {
                best = Some((*l, s));
            }
        }
        let (l, _) = best.expect("at least one leaf");
        d.claims_mut(l).push(c);
    }
    (d.collapse(), delta)
}

/// What [`update_links`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinksDelta {
    /// Linked claims placed by their neighbours this night.
    pub joined: usize,
    /// New leaves of linked claims no placed neighbour reached.
    pub new_link_leaves: usize,
    /// Mirror leaves created this night (no previous mirror held their
    /// meaning leaf's unlinked claims).
    pub new_mirrors: usize,
}

/// The new "by links" shape of one theme (module docs), against `meaning`,
/// the theme's RESOLVED meaning tree (its members are the theme's members).
/// `linked` is the set of members with a counted link and `links` the
/// counted links (W5's `counted_links`). `fits` says whether a set of claims
/// fits one leaf (W3's count). A previous tree that was a single root leaf,
/// or none, starts from an empty root.
///
/// `prev_mirrors` is the set of the previous run's mirror leaves, when the
/// previous run recorded it (a nightly run does, under `params.mirrors`).
/// Without it a previous leaf is a mirror when at least half its surviving
/// claims are unlinked now: a mirror whose claims all became linked then
/// reads as a linked leaf and keeps them, where the record would have let
/// them rejoin their neighbours.
#[must_use]
pub fn update_links(
    prev: Option<&PrevTree>,
    prev_mirrors: Option<&BTreeSet<Uuid>>,
    meaning: &MeaningTree,
    linked: &BTreeSet<Uuid>,
    links: &BTreeSet<(Uuid, Uuid)>,
    fits: &dyn Fn(&[Uuid]) -> bool,
) -> (Option<Shape>, LinksDelta) {
    let members: BTreeSet<Uuid> = meaning.nodes[0].claims.iter().copied().collect();
    let mut d = match prev {
        Some(p) if !p.root_is_leaf() => Draft::from_prev(p),
        _ => Draft::root_group(),
    };
    d.retain(|c| members.contains(c));
    let mut delta = LinksDelta::default();

    // Each claim's meaning leaf, as its pre-order number.
    let mut meaning_leaf: BTreeMap<Uuid, usize> = BTreeMap::new();
    for (n, (_, claims)) in meaning.leaves().enumerate() {
        for c in claims {
            meaning_leaf.insert(*c, n);
        }
    }
    let mut desired: BTreeMap<usize, Vec<Uuid>> = BTreeMap::new();
    for c in &members {
        if !linked.contains(c) {
            desired.entry(meaning_leaf[c]).or_default().push(*c);
        }
    }

    // Roles of the previous leaves.
    let leaves = d.leaves();
    let mut chosen: BTreeMap<usize, (usize, usize)> = BTreeMap::new(); // key -> (count, leaf)
    let mut mirror_role: BTreeSet<usize> = BTreeSet::new();
    for &l in &leaves {
        let claims = d.claims(l);
        let unl: Vec<&Uuid> = claims.iter().filter(|c| !linked.contains(c)).collect();
        let mirror = match prev_mirrors {
            Some(m) => d.ids[l].is_some_and(|id| m.contains(&id)),
            None => !unl.is_empty() && unl.len() * 2 >= claims.len(),
        };
        if !mirror {
            continue;
        }
        mirror_role.insert(l);
        if unl.is_empty() {
            continue;
        }
        let mut by_key: BTreeMap<usize, usize> = BTreeMap::new();
        for c in &unl {
            *by_key.entry(meaning_leaf[*c]).or_default() += 1;
        }
        let (key, count) = by_key
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            .map(|(k, n)| (*k, *n))
            .expect("non-empty");
        match chosen.get(&key) {
            Some((n, _)) if *n >= count => {}
            _ => {
                chosen.insert(key, (count, l));
            }
        }
    }
    let chosen_leaf: BTreeMap<usize, usize> = chosen.iter().map(|(k, (_, l))| (*l, *k)).collect();
    for &l in &leaves {
        let content = if let Some(key) = chosen_leaf.get(&l) {
            desired.get(key).cloned().unwrap_or_default()
        } else if mirror_role.contains(&l) {
            Vec::new()
        } else {
            d.claims(l)
                .iter()
                .filter(|c| linked.contains(c))
                .copied()
                .collect()
        };
        *d.claims_mut(l) = content;
    }
    for (key, claims) in &desired {
        if !chosen.contains_key(key) {
            d.push_leaf(claims.clone());
            delta.new_mirrors += 1;
        }
    }

    // Linked claims: placed ones stay, the rest vote by neighbours.
    let linked_leaves: Vec<usize> = leaves
        .iter()
        .copied()
        .filter(|l| !mirror_role.contains(l))
        .collect();
    let position: BTreeMap<usize, usize> = linked_leaves
        .iter()
        .enumerate()
        .map(|(i, l)| (*l, i))
        .collect();
    let mut leaf_of: BTreeMap<Uuid, usize> = BTreeMap::new();
    for &l in &linked_leaves {
        for c in d.claims(l) {
            leaf_of.insert(*c, l);
        }
    }
    let mut adj: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();
    for (a, b) in links {
        adj.entry(*a).or_default().insert(*b);
        adj.entry(*b).or_default().insert(*a);
    }
    let mut unplaced: BTreeSet<Uuid> = linked
        .iter()
        .filter(|c| members.contains(c) && !leaf_of.contains_key(c))
        .copied()
        .collect();
    loop {
        let mut moved = false;
        for c in unplaced.clone() {
            let mut votes: BTreeMap<usize, usize> = BTreeMap::new();
            for n in adj.get(&c).into_iter().flatten() {
                if let Some(l) = leaf_of.get(n) {
                    *votes.entry(position[l]).or_default() += 1;
                }
            }
            let Some((&pos, _)) = votes.iter().max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
            else {
                continue;
            };
            let l = linked_leaves[pos];
            d.claims_mut(l).push(c);
            leaf_of.insert(c, l);
            unplaced.remove(&c);
            delta.joined += 1;
            moved = true;
        }
        if !moved {
            break;
        }
    }

    // The rest: connected components, packed first fit.
    let mut comps: Vec<Vec<Uuid>> = Vec::new();
    let mut seen: BTreeSet<Uuid> = BTreeSet::new();
    for &start in &unplaced {
        if !seen.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut stack = vec![start];
        while let Some(c) = stack.pop() {
            for n in adj.get(&c).into_iter().flatten() {
                if unplaced.contains(n) && seen.insert(*n) {
                    comp.push(*n);
                    stack.push(*n);
                }
            }
        }
        comp.sort_unstable();
        comps.push(comp);
    }
    comps.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
    let mut bins: Vec<Vec<Uuid>> = Vec::new();
    for comp in comps {
        let mut placed = false;
        for bin in &mut bins {
            let mut union = bin.clone();
            union.extend(&comp);
            union.sort_unstable();
            if fits(&union) {
                *bin = union;
                placed = true;
                break;
            }
        }
        if !placed {
            bins.push(comp);
        }
    }
    delta.new_link_leaves = bins.len();
    for bin in bins {
        d.push_leaf(bin);
    }
    (d.collapse(), delta)
}

/// Mint `shape` into the result-file groups W4's `check_tree` takes: the
/// root's id from the theme, every other group's from its claims, in
/// pre-order.
#[must_use]
pub fn to_wire(
    map: AtlasMap,
    hierarchy: AtlasHierarchy,
    theme: Uuid,
    shape: &Shape,
) -> Vec<WireGroup> {
    fn go(
        out: &mut Vec<WireGroup>,
        map: AtlasMap,
        h: AtlasHierarchy,
        theme: Uuid,
        shape: &Shape,
        parent: Option<Uuid>,
        depth: u8,
    ) -> Uuid {
        let claims = shape.claims();
        let id = if parent.is_none() {
            root_id(map, h, theme)
        } else {
            group_id(map, h, theme, &claims)
        };
        let at = out.len();
        out.push(WireGroup {
            id,
            parent,
            depth,
            kind: WireKind::Leaf,
            claim_count: u32::try_from(claims.len()).unwrap_or(u32::MAX),
            weight: 0,
            members: None,
            children: None,
        });
        match shape {
            Shape::Leaf(c) => out[at].members = Some(c.clone()),
            Shape::Group(kids) => {
                let ids = kids
                    .iter()
                    .map(|k| go(out, map, h, theme, k, Some(id), depth.saturating_add(1)))
                    .collect();
                out[at].kind = WireKind::Group;
                out[at].children = Some(ids);
            }
        }
        id
    }
    let mut out = Vec::new();
    go(&mut out, map, hierarchy, theme, shape, None, 0);
    out
}

/// A checked tree back as a shape (for a tree whose root is a single leaf
/// built without a previous run).
#[must_use]
pub fn shape_of(tree: &MeaningTree) -> Shape {
    fn go(tree: &MeaningTree, id: Uuid) -> Shape {
        let n = tree.node(id).expect("a node of the tree");
        match &n.body {
            NodeBody::Leaf(c) => Shape::Leaf(c.clone()),
            NodeBody::Group(k) => Shape::Group(k.iter().map(|c| go(tree, *c)).collect()),
        }
    }
    go(tree, tree.nodes[0].id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas_meaning::tree::check_tree;

    const TEAM: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);
    const THEME: Uuid = Uuid::from_u128(0x3c88_6e23_925e_4966_b135_a7ef_81df_30a4);
    const MAP: AtlasMap = AtlasMap::Team(TEAM);
    const M: AtlasHierarchy = AtlasHierarchy::Meaning;
    const L: AtlasHierarchy = AtlasHierarchy::Links;

    fn c(n: u128) -> Uuid {
        Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n)
    }

    fn axis(i: usize) -> Vec<f32> {
        let mut v = vec![0.0; 8];
        v[i] = 1.0;
        v
    }

    /// A previous tree of `shape`, as the stored rows would rebuild it.
    fn prev_of(h: AtlasHierarchy, shape: &Shape) -> PrevTree {
        let wire = to_wire(MAP, h, THEME, shape);
        let mut nodes = BTreeMap::new();
        for g in &wire {
            let body = match g.kind {
                WireKind::Leaf => PrevBody::Leaf(g.members.clone().unwrap()),
                WireKind::Group => PrevBody::Group(g.children.clone().unwrap()),
            };
            nodes.insert(g.id, body);
        }
        PrevTree {
            root: wire[0].id,
            nodes,
        }
    }

    fn checked(h: AtlasHierarchy, shape: &Shape) -> MeaningTree {
        let members = shape.claims();
        check_tree(MAP, h, THEME, &to_wire(MAP, h, THEME, shape), &members).expect("valid")
    }

    fn leaf(ids: &[u128]) -> Shape {
        Shape::Leaf(ids.iter().map(|n| c(*n)).collect())
    }

    /// root -> {g -> {a: 1,2 ; b: 3,4}, d: 5,6}; a on axis 0, b on 1, d on 2.
    fn meaning_shape() -> (Shape, BTreeMap<Uuid, Vec<f32>>) {
        let shape = Shape::Group(vec![
            Shape::Group(vec![leaf(&[1, 2]), leaf(&[3, 4])]),
            leaf(&[5, 6]),
        ]);
        let mut emb = BTreeMap::new();
        for (n, a) in [(1, 0), (2, 0), (3, 1), (4, 1), (5, 2), (6, 2)] {
            emb.insert(c(n), axis(a));
        }
        (shape, emb)
    }

    #[test]
    fn unchanged_members_give_the_previous_tree_back_id_for_id() {
        let (shape, emb) = meaning_shape();
        let prev = prev_of(M, &shape);
        let (got, delta) = update_meaning(&prev, &emb);
        assert_eq!(got.as_ref(), Some(&shape));
        assert_eq!(delta, MeaningDelta::default());
        assert_eq!(
            to_wire(MAP, M, THEME, &got.unwrap()),
            to_wire(MAP, M, THEME, &shape)
        );
    }

    #[test]
    fn a_new_claim_joins_the_leaf_with_the_nearest_centroid_whatever_the_leaf_order() {
        let (shape, mut emb) = meaning_shape();
        let prev = prev_of(M, &shape);
        let mut v = axis(1);
        v[0] = 0.2;
        emb.insert(c(9), v); // nearest to b (axis 1)
        let (got, delta) = update_meaning(&prev, &emb);
        assert_eq!(delta.added, 1);
        let want = Shape::Group(vec![
            Shape::Group(vec![leaf(&[1, 2]), leaf(&[3, 4, 9])]),
            leaf(&[5, 6]),
        ]);
        assert_eq!(got.unwrap(), want);
        // Every id re-minted: W4's check accepts it.
        checked(M, &want);
    }

    #[test]
    fn an_emptied_leaf_is_dropped_and_its_single_child_parent_collapses() {
        let (shape, mut emb) = meaning_shape();
        let prev = prev_of(M, &shape);
        emb.remove(&c(3));
        emb.remove(&c(4));
        let (got, delta) = update_meaning(&prev, &emb);
        assert_eq!(delta.removed, 2);
        // g had a and b; b is gone, so g is replaced by a.
        assert_eq!(
            got.unwrap(),
            Shape::Group(vec![leaf(&[1, 2]), leaf(&[5, 6])])
        );
    }

    #[test]
    fn a_theme_whose_previous_claims_all_left_is_one_root_leaf_of_the_new_ones() {
        let (shape, _) = meaning_shape();
        let prev = prev_of(M, &shape);
        let emb: BTreeMap<Uuid, Vec<f32>> = [(c(20), axis(3)), (c(21), axis(4))].into();
        let (got, _) = update_meaning(&prev, &emb);
        assert_eq!(got.unwrap(), leaf(&[20, 21]));
    }

    fn never_fits(_: &[Uuid]) -> bool {
        false
    }

    fn always_fits(_: &[Uuid]) -> bool {
        true
    }

    /// Meaning: {a: 1,2,3 ; b: 4,5,6}. Links among 1-2 and 4-5; 3 and 6
    /// unlinked. Links tree: root -> {L1: 1,2 ; L2: 4,5 ; m3: 3 ; m6: 6}.
    fn links_case() -> (MeaningTree, Shape, BTreeSet<(Uuid, Uuid)>) {
        let meaning = checked(M, &Shape::Group(vec![leaf(&[1, 2, 3]), leaf(&[4, 5, 6])]));
        let links_shape = Shape::Group(vec![leaf(&[1, 2]), leaf(&[4, 5]), leaf(&[3]), leaf(&[6])]);
        let links: BTreeSet<(Uuid, Uuid)> = [(c(1), c(2)), (c(4), c(5))].into();
        (meaning, links_shape, links)
    }

    /// The ids of the previous links tree's mirror leaves.
    fn mirrors_of(parts: &[&[u128]]) -> BTreeSet<Uuid> {
        parts
            .iter()
            .map(|p| group_id(MAP, L, THEME, &p.iter().map(|n| c(*n)).collect()))
            .collect()
    }

    fn linked_of(links: &BTreeSet<(Uuid, Uuid)>) -> BTreeSet<Uuid> {
        links.iter().flat_map(|(a, b)| [*a, *b]).collect()
    }

    #[test]
    fn unchanged_links_input_gives_the_previous_links_tree_back() {
        let (meaning, shape, links) = links_case();
        let prev = prev_of(L, &shape);
        let mirrors = mirrors_of(&[&[3], &[6]]);
        let (got, delta) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning,
            &linked_of(&links),
            &links,
            &never_fits,
        );
        assert_eq!(got.unwrap(), shape);
        assert_eq!(delta, LinksDelta::default());
    }

    #[test]
    fn a_new_unlinked_claim_lands_in_its_meaning_leafs_mirror_and_a_linked_one_by_its_neighbours() {
        let (_, shape, mut links) = links_case();
        let prev = prev_of(L, &shape);
        let mirrors = mirrors_of(&[&[3], &[6]]);
        // 7 joins meaning leaf a unlinked; 8 joins b and links to 4.
        let meaning = checked(
            M,
            &Shape::Group(vec![leaf(&[1, 2, 3, 7]), leaf(&[4, 5, 6, 8])]),
        );
        links.insert((c(4), c(8)));
        let (got, delta) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning,
            &linked_of(&links),
            &links,
            &never_fits,
        );
        assert_eq!(
            got.unwrap(),
            Shape::Group(vec![
                leaf(&[1, 2]),
                leaf(&[4, 5, 8]),
                leaf(&[3, 7]),
                leaf(&[6])
            ])
        );
        assert_eq!(delta.joined, 1);
        assert_eq!(delta.new_mirrors, 0);
    }

    #[test]
    fn a_claim_that_becomes_linked_leaves_its_mirror_and_new_components_are_packed() {
        let (meaning, shape, mut links) = links_case();
        let prev = prev_of(L, &shape);
        let mirrors = mirrors_of(&[&[3], &[6]]);
        // 3 and 6 link to each other: no placed neighbour, a new component.
        links.insert((c(3), c(6)));
        let linked = linked_of(&links);
        let (got, delta) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning,
            &linked,
            &links,
            &always_fits,
        );
        assert_eq!(
            got.unwrap(),
            Shape::Group(vec![leaf(&[1, 2]), leaf(&[4, 5]), leaf(&[3, 6])])
        );
        assert_eq!(delta.new_link_leaves, 1);
        // Two separate new pairs pack into one leaf only while it fits.
        let meaning2 = checked(
            M,
            &Shape::Group(vec![leaf(&[1, 2, 3, 10, 11]), leaf(&[4, 5, 6, 12, 13])]),
        );
        let mut links2 = links_case().2;
        links2.insert((c(10), c(11)));
        links2.insert((c(12), c(13)));
        let l2 = linked_of(&links2);
        let (packed, _) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning2,
            &l2,
            &links2,
            &always_fits,
        );
        let (apart, d2) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning2,
            &l2,
            &links2,
            &never_fits,
        );
        assert!(matches!(&packed, Some(Shape::Group(k)) if k.contains(&leaf(&[10, 11, 12, 13]))));
        assert_eq!(d2.new_link_leaves, 2);
        assert!(
            matches!(&apart, Some(Shape::Group(k)) if k.contains(&leaf(&[10, 11])) && k.contains(&leaf(&[12, 13])))
        );
    }

    #[test]
    fn a_mirror_follows_its_meaning_leaf_when_the_meaning_leaf_is_split() {
        let (_, shape, links) = links_case();
        let prev = prev_of(L, &shape);
        let mirrors = mirrors_of(&[&[3], &[6]]);
        // Meaning leaf a split into {1,2} and {3,9}; 9 is new and unlinked.
        let meaning = checked(
            M,
            &Shape::Group(vec![leaf(&[1, 2]), leaf(&[3, 9]), leaf(&[4, 5, 6])]),
        );
        let (got, _) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning,
            &linked_of(&links),
            &links,
            &never_fits,
        );
        assert_eq!(
            got.unwrap(),
            Shape::Group(vec![
                leaf(&[1, 2]),
                leaf(&[4, 5]),
                leaf(&[3, 9]),
                leaf(&[6])
            ])
        );
    }

    #[test]
    fn a_previous_root_leaf_starts_the_links_tree_afresh() {
        let meaning = checked(M, &Shape::Group(vec![leaf(&[1, 2, 3]), leaf(&[4, 5, 6])]));
        let prev = prev_of(L, &leaf(&[1, 2, 3, 4, 5, 6]));
        let mirrors = BTreeSet::new();
        let links: BTreeSet<(Uuid, Uuid)> = [(c(1), c(2)), (c(4), c(5))].into();
        let (got, d) = update_links(
            Some(&prev),
            Some(&mirrors),
            &meaning,
            &linked_of(&links),
            &links,
            &never_fits,
        );
        assert_eq!(
            got.unwrap(),
            Shape::Group(vec![leaf(&[3]), leaf(&[6]), leaf(&[1, 2]), leaf(&[4, 5])])
        );
        assert_eq!((d.new_mirrors, d.new_link_leaves), (2, 2));
    }
}
