//! Prod-sized synthetic maps for the Atlas latency gate (W12, feature
//! `check`).
//!
//! [`theme_levels`] builds every level document of one theme, in both
//! hierarchies, from REAL row ids: the claims of the theme, a pool of agents
//! and a pool of evidence rows a test has seeded. A route serving these
//! documents therefore does the work it does on a real map: `for_viewer`
//! finds the leaf's nodes readable, and the claim-to-leaf lookup finds each
//! claim in its leaf.
//!
//! The leaves come from the W10a generator ([`crate::fixtures`]'s
//! `leaf_level`), with its node ids replaced by the given ones. The shape:
//!
//! - claims are cut into leaves of [`LEAF_CLAIMS`] (the last may hold
//!   fewer), each with [`LEAF_AGENTS`] agents and [`LEAF_EVIDENCE`] evidence
//!   nodes, at most 88 nodes in all;
//! - up to [`LEAVES_PER_GROUP`] leaves hang directly under the theme root;
//!   more are grouped [`LEAVES_PER_GROUP`] to a group under it;
//! - the links hierarchy cuts the claims in another (seeded) order, so a
//!   claim's two leaves hold different neighbours, as on a real map; both
//!   trees have the same shape, so each level's switch leads to its
//!   structural twin;
//! - every outside target (a leaf's `outgoing`, a group's `targets`) is
//!   another level of the same theme and hierarchy, so every link resolves
//!   inside the set.
//!
//! Like the fixtures, names and labels are synthetic and seeded.

use std::collections::HashMap;

use uuid::Uuid;

use crate::fixtures::{group_name, leaf_level, net_sign, r4, ClaimValues, Frame, Rng};
use crate::{
    Breadcrumb, Bundle, Child, ChildKind, GroupLevel, Hierarchy, LevelDocument, LinkTarget,
    MapScope, Node, Switch, SCHEMA_VERSION,
};

/// Claims per leaf (the last leaf of a theme may hold fewer).
pub const LEAF_CLAIMS: usize = 64;
/// Agent nodes per leaf, at most.
pub const LEAF_AGENTS: usize = 8;
/// Evidence nodes per leaf, at most.
pub const LEAF_EVIDENCE: usize = 16;
/// Claim-to-claim links drawn per claim.
pub const LINKS_PER_CLAIM: usize = 4;
/// Leaves under one group.
pub const LEAVES_PER_GROUP: usize = 8;
/// Outside targets per leaf, at most.
pub const LEAF_OUTGOING: usize = 12;
/// Outside targets per group below the root, at most.
pub const GROUP_TARGETS: usize = 6;

/// The map a run belongs to.
#[derive(Debug, Clone, Copy)]
pub struct ScaleMap {
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub run_id: Uuid,
}

/// One theme's seeded rows.
#[derive(Debug, Clone, Copy)]
pub struct ScaleTheme<'a> {
    pub theme_id: Uuid,
    /// The theme's claims, in the order the meaning hierarchy cuts them.
    pub claims: &'a [Uuid],
    /// Agents a leaf may draw (at least one).
    pub agents: &'a [Uuid],
    /// Evidence rows a leaf may draw (may be empty).
    pub evidence: &'a [Uuid],
}

/// One stored level: what W2's `put_level` takes besides the run.
#[derive(Debug, Clone)]
pub struct ScaleLevel {
    pub hierarchy: Hierarchy,
    pub parent: Option<Uuid>,
    pub doc: LevelDocument,
}

impl ScaleLevel {
    pub fn depth(&self) -> u8 {
        match &self.doc {
            LevelDocument::Group(g) => g.depth,
            LevelDocument::Leaf(l) => l.depth,
        }
    }
}

/// How many levels [`theme_levels`] builds for a theme of `claims` claims,
/// both hierarchies together.
pub fn levels_for(claims: usize) -> usize {
    let leaves = claims.div_ceil(LEAF_CLAIMS);
    let groups = if leaves <= LEAVES_PER_GROUP {
        0
    } else {
        leaves.div_ceil(LEAVES_PER_GROUP)
    };
    2 * (1 + groups + leaves)
}

/// A level before its document is written.
struct Sk {
    id: Uuid,
    name: String,
    kind: ChildKind,
    depth: u8,
    parent: Option<usize>,
    children: Vec<usize>,
    /// For a leaf: its range in the hierarchy's claim order.
    claims: std::ops::Range<usize>,
    x: f64,
    y: f64,
    r: f64,
}

/// One hierarchy's tree: index 0 is the root, then the groups (if any), then
/// the leaves, in an order that is the same in both hierarchies.
fn skeleton(rng: &mut Rng, n_claims: usize) -> Vec<Sk> {
    let n_leaves = n_claims.div_ceil(LEAF_CLAIMS);
    let grouped = n_leaves > LEAVES_PER_GROUP;
    let n_groups = if grouped {
        n_leaves.div_ceil(LEAVES_PER_GROUP)
    } else {
        0
    };
    let mut sk = vec![Sk {
        id: rng.uuid(),
        name: group_name(rng),
        kind: ChildKind::Group,
        depth: 0,
        parent: None,
        children: Vec::new(),
        claims: 0..n_claims,
        x: 0.0,
        y: 0.0,
        r: 1.0,
    }];
    for _ in 0..n_groups {
        sk.push(Sk {
            id: rng.uuid(),
            name: group_name(rng),
            kind: ChildKind::Group,
            depth: 1,
            parent: Some(0),
            children: Vec::new(),
            claims: 0..0,
            x: 0.0,
            y: 0.0,
            r: 0.0,
        });
    }
    for j in 0..n_leaves {
        let parent = if grouped { 1 + j / LEAVES_PER_GROUP } else { 0 };
        let lo = j * LEAF_CLAIMS;
        sk.push(Sk {
            id: rng.uuid(),
            name: group_name(rng),
            kind: ChildKind::Leaf,
            depth: sk[parent].depth + 1,
            parent: Some(parent),
            children: Vec::new(),
            claims: lo..(lo + LEAF_CLAIMS).min(n_claims),
            x: 0.0,
            y: 0.0,
            r: 0.0,
        });
    }
    for i in 1..sk.len() {
        let p = sk[i].parent.expect("only the root has no parent");
        sk[p].children.push(i);
    }
    // A group's claim range spans its leaves (contiguous by construction).
    for g in (1..=n_groups).rev() {
        let (first, last) = (sk[g].children[0], *sk[g].children.last().unwrap());
        sk[g].claims = sk[first].claims.start..sk[last].claims.end;
    }
    // Place each level's children on a sunflower spiral in its unit circle.
    let golden = std::f64::consts::PI * (3.0 - 5f64.sqrt());
    for p in 0..sk.len() {
        let kids = sk[p].children.clone();
        let n = kids.len() as f64;
        for (i, &c) in kids.iter().enumerate() {
            let rho = 0.75 * ((i as f64 + 0.5) / n).sqrt();
            let theta = i as f64 * golden;
            let count = sk[c].claims.len() as f64;
            sk[c].x = r4(rho * theta.cos());
            sk[c].y = r4(rho * theta.sin());
            sk[c].r = r4((0.03 + 0.03 * (count / f64::from(LEAF_CLAIMS as u32)).sqrt()).min(0.4));
        }
    }
    sk
}

/// `n` distinct items of `pool` from a random start (all of it when `n` is
/// larger).
fn pick(rng: &mut Rng, pool: &[Uuid], n: usize) -> Vec<Uuid> {
    let n = n.min(pool.len());
    if n == 0 {
        return Vec::new();
    }
    let start = rng.below(pool.len());
    (0..n).map(|i| pool[(start + i) % pool.len()]).collect()
}

/// Up to `n` distinct entries of `from`, none equal to `not`.
fn others(rng: &mut Rng, from: &[usize], not: usize, n: usize) -> Vec<usize> {
    let pool: Vec<usize> = from.iter().copied().filter(|&i| i != not).collect();
    if pool.is_empty() {
        return Vec::new();
    }
    let n = n.min(pool.len());
    let start = rng.below(pool.len());
    (0..n).map(|i| pool[(start + i) % pool.len()]).collect()
}

/// Every level document of one theme, both hierarchies, parents before
/// children. Deterministic in `seed` and the inputs.
///
/// # Panics
/// When the theme has no claim or the agent pool is empty.
pub fn theme_levels(seed: u64, map: &ScaleMap, theme: &ScaleTheme<'_>) -> Vec<ScaleLevel> {
    assert!(!theme.claims.is_empty(), "a theme has at least one claim");
    assert!(!theme.agents.is_empty(), "a leaf draws at least one agent");
    let mut rng = Rng::new(seed ^ theme.theme_id.as_u64_pair().0);

    // The links hierarchy cuts the claims in a shuffled order.
    let mut links_order: Vec<Uuid> = theme.claims.to_vec();
    for i in (1..links_order.len()).rev() {
        links_order.swap(i, rng.below(i + 1));
    }
    let trees = [
        (Hierarchy::Meaning, skeleton(&mut rng, theme.claims.len())),
        (Hierarchy::Links, skeleton(&mut rng, theme.claims.len())),
    ];
    let orders: [&[Uuid]; 2] = [theme.claims, &links_order];

    let mut out = Vec::new();
    for (h, (hierarchy, sk)) in trees.iter().enumerate() {
        let twin = &trees[1 - h].1;
        let order = orders[h];
        let leaves: Vec<usize> = (0..sk.len())
            .filter(|&i| sk[i].kind == ChildKind::Leaf)
            .collect();
        let groups: Vec<usize> = (1..sk.len())
            .filter(|&i| sk[i].kind == ChildKind::Group)
            .collect();
        let target = |i: usize| LinkTarget {
            level_id: sk[i].id,
            theme_id: theme.theme_id,
            name: Some(sk[i].name.clone()),
            depth: sk[i].depth,
        };
        for i in 0..sk.len() {
            let s = &sk[i];
            let mut chain = Vec::new();
            let mut p = s.parent;
            while let Some(a) = p {
                chain.push(a);
                p = sk[a].parent;
            }
            chain.reverse();
            let f = Frame {
                map_scope: map.map_scope,
                map_group_id: map.map_group_id,
                hierarchy: *hierarchy,
                theme_id: theme.theme_id,
                run_id: map.run_id,
                level_id: s.id,
                depth: s.depth,
                name: Some(s.name.clone()),
                needs_naming: false,
                breadcrumbs: chain
                    .iter()
                    .map(|&a| Breadcrumb {
                        level_id: sk[a].id,
                        name: Some(sk[a].name.clone()),
                        depth: sk[a].depth,
                    })
                    .collect(),
                switch: Switch {
                    hierarchy: hierarchy.other(),
                    level_id: twin[i].id,
                },
            };
            let doc = match s.kind {
                ChildKind::Group => {
                    let children: Vec<Child> = s
                        .children
                        .iter()
                        .map(|&c| Child {
                            id: sk[c].id,
                            kind: sk[c].kind,
                            name: Some(sk[c].name.clone()),
                            needs_naming: false,
                            claim_count: sk[c].claims.len() as u32,
                            x: sk[c].x,
                            y: sk[c].y,
                            r: sk[c].r,
                        })
                        .collect();
                    // Outside targets: sibling groups below the root.
                    let targets: Vec<LinkTarget> = if s.depth == 0 {
                        Vec::new()
                    } else {
                        others(&mut rng, &groups, i, GROUP_TARGETS)
                            .into_iter()
                            .map(&target)
                            .collect()
                    };
                    let mut bundles = Vec::new();
                    let mut seen = std::collections::BTreeSet::new();
                    let ids: Vec<Uuid> = children.iter().map(|c| c.id).collect();
                    let mut push = |rng: &mut Rng, source: Uuid, target: Uuid| {
                        if source != target && seen.insert((source, target)) {
                            bundles.push(Bundle {
                                source,
                                target,
                                count: rng.range(1, 40) as u32,
                                net_sign: net_sign(rng),
                            });
                        }
                    };
                    for &c in &ids {
                        for _ in 0..2 {
                            let t = ids[rng.below(ids.len())];
                            push(&mut rng, c, t);
                        }
                    }
                    for t in &targets {
                        let src = ids[rng.below(ids.len())];
                        push(&mut rng, src, t.level_id);
                    }
                    LevelDocument::Group(GroupLevel {
                        schema_version: SCHEMA_VERSION,
                        map_scope: f.map_scope,
                        map_group_id: f.map_group_id,
                        hierarchy: f.hierarchy,
                        theme_id: f.theme_id,
                        run_id: f.run_id,
                        level_id: f.level_id,
                        depth: f.depth,
                        name: f.name,
                        needs_naming: f.needs_naming,
                        breadcrumbs: f.breadcrumbs,
                        switch: f.switch,
                        children,
                        bundles,
                        targets,
                    })
                }
                ChildKind::Leaf => {
                    let claims = &order[s.claims.clone()];
                    // Each agent asserts one of the leaf's claims, so a leaf
                    // of few claims draws as few agents.
                    let agents = pick(&mut rng, theme.agents, LEAF_AGENTS.min(claims.len()));
                    let evidence = pick(&mut rng, theme.evidence, LEAF_EVIDENCE);
                    let outside = others(&mut rng, &leaves, i, LEAF_OUTGOING);
                    let (mut leaf, _) = leaf_level(
                        &mut rng,
                        f,
                        (claims.len(), agents.len(), evidence.len()),
                        LINKS_PER_CLAIM,
                        outside.len(),
                        ClaimValues::AS_DRAWN,
                    );
                    // The generator's nodes are claims, then agents, then
                    // evidence: give each its real id.
                    let real = claims.iter().chain(&agents).chain(&evidence);
                    let remap: HashMap<Uuid, Uuid> =
                        leaf.nodes.iter().map(Node::id).zip(real.copied()).collect();
                    for n in &mut leaf.nodes {
                        let id = remap[&n.id()];
                        match n {
                            Node::Claim(c) => c.id = id,
                            Node::Agent(a) | Node::Evidence(a) => a.id = id,
                        }
                    }
                    for e in &mut leaf.edges {
                        e.source = remap[&e.source];
                        e.target = remap[&e.target];
                    }
                    for (o, &t) in leaf.outgoing.iter_mut().zip(&outside) {
                        o.target = target(t);
                        for src in &mut o.sources {
                            *src = remap[src];
                        }
                    }
                    LevelDocument::Leaf(leaf)
                }
            };
            out.push(ScaleLevel {
                hierarchy: *hierarchy,
                parent: s.parent.map(|p| sk[p].id),
                doc,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{NodeKind, BUDGET_GZIP_BYTES, MAX_LEAF_NODES};

    fn ids(rng: &mut Rng, n: usize) -> Vec<Uuid> {
        (0..n).map(|_| rng.uuid()).collect()
    }

    fn world(n_claims: usize) -> (ScaleMap, Uuid, Vec<Uuid>, Vec<Uuid>, Vec<Uuid>) {
        let mut rng = Rng::new(0x5CA1E);
        let map = ScaleMap {
            map_scope: MapScope::Team,
            map_group_id: Some(rng.uuid()),
            run_id: rng.uuid(),
        };
        let theme = rng.uuid();
        let claims = ids(&mut rng, n_claims);
        let agents = ids(&mut rng, 32);
        let evidence = ids(&mut rng, n_claims / 8);
        (map, theme, claims, agents, evidence)
    }

    fn build(n_claims: usize) -> (Vec<ScaleLevel>, Vec<Uuid>, Vec<Uuid>, Vec<Uuid>) {
        let (map, theme_id, claims, agents, evidence) = world(n_claims);
        let levels = theme_levels(
            7,
            &map,
            &ScaleTheme {
                theme_id,
                claims: &claims,
                agents: &agents,
                evidence: &evidence,
            },
        );
        (levels, claims, agents, evidence)
    }

    fn envelope(doc: &LevelDocument) -> (Uuid, u8, &Switch) {
        match doc {
            LevelDocument::Group(g) => (g.level_id, g.depth, &g.switch),
            LevelDocument::Leaf(l) => (l.level_id, l.depth, &l.switch),
        }
    }

    /// A prod-sized theme (1,743 claims: 366k over 210 themes) and a theme
    /// small enough to have no group layer both give valid documents within
    /// the budget, as many as [`levels_for`] predicts, with every leaf at
    /// most 100 nodes.
    #[test]
    fn every_level_is_valid_within_budget_and_counted() {
        for n in [1_743, 300, 1] {
            let (levels, _, _, _) = build(n);
            assert_eq!(levels.len(), levels_for(n), "{n} claims");
            for l in &levels {
                let body = l
                    .doc
                    .to_stored_json()
                    .unwrap_or_else(|e| panic!("{n} claims: {e}"));
                assert!(epigraph_gzip(&body) <= BUDGET_GZIP_BYTES);
                if let LevelDocument::Leaf(leaf) = &l.doc {
                    assert!(leaf.nodes.len() <= MAX_LEAF_NODES);
                }
            }
        }
    }

    fn epigraph_gzip(b: &[u8]) -> usize {
        crate::gzip_len(b)
    }

    /// Every claim is in exactly one leaf of each hierarchy, the two leaves
    /// of most claims differ (the links tree cuts another order), and every
    /// agent and evidence node is one of the given rows.
    #[test]
    fn leaves_hold_the_given_rows_once_per_hierarchy() {
        let (levels, claims, agents, evidence) = build(1_743);
        let agents: BTreeSet<Uuid> = agents.into_iter().collect();
        let evidence: BTreeSet<Uuid> = evidence.into_iter().collect();
        let mut leaf_of: [BTreeMap<Uuid, Uuid>; 2] = Default::default();
        for l in &levels {
            let LevelDocument::Leaf(leaf) = &l.doc else {
                continue;
            };
            let h = usize::from(l.hierarchy == Hierarchy::Links);
            for n in &leaf.nodes {
                match n.kind() {
                    NodeKind::Claim => {
                        assert!(
                            leaf_of[h].insert(n.id(), leaf.level_id).is_none(),
                            "a claim in two leaves of one hierarchy"
                        );
                    }
                    NodeKind::Agent => assert!(agents.contains(&n.id())),
                    NodeKind::Evidence => assert!(evidence.contains(&n.id())),
                }
            }
        }
        for (h, leaves) in leaf_of.iter().enumerate() {
            let got: BTreeSet<Uuid> = leaves.keys().copied().collect();
            assert_eq!(got, claims.iter().copied().collect(), "hierarchy {h}");
        }
        // Leaf ids differ by hierarchy anyway; compare the neighbour sets.
        let together = |h: usize, a: Uuid, b: Uuid| leaf_of[h][&a] == leaf_of[h][&b];
        let moved = claims
            .windows(2)
            .filter(|w| together(0, w[0], w[1]) != together(1, w[0], w[1]))
            .count();
        assert!(
            moved > claims.len() / 4,
            "only {moved} neighbour pairs moved"
        );
    }

    /// Every link a viewer can follow lands on a level of the set: a
    /// switch on the twin in the other hierarchy at the same depth, a
    /// child, breadcrumb, group target or leaf outgoing target on a level of
    /// the same hierarchy.
    #[test]
    fn every_link_resolves_inside_the_set() {
        let (levels, _, _, _) = build(1_743);
        let by_id: BTreeMap<(Hierarchy, Uuid), &ScaleLevel> = levels
            .iter()
            .map(|l| ((l.hierarchy, envelope(&l.doc).0), l))
            .collect();
        let has = |h: Hierarchy, id: Uuid| by_id.contains_key(&(h, id));
        let mut leaves_with_outgoing = 0;
        for l in &levels {
            let (id, depth, switch) = envelope(&l.doc);
            let twin = by_id
                .get(&(switch.hierarchy, switch.level_id))
                .unwrap_or_else(|| panic!("switch of {id} resolves"));
            assert_ne!(twin.hierarchy, l.hierarchy);
            assert_eq!(twin.depth(), depth, "the twin is at the same depth");
            assert_eq!(
                envelope(&twin.doc).2.level_id,
                id,
                "twins point at each other"
            );
            if let Some(p) = l.parent {
                assert!(has(l.hierarchy, p), "parent of {id}");
            }
            match &l.doc {
                LevelDocument::Group(g) => {
                    for c in &g.children {
                        assert!(has(l.hierarchy, c.id));
                    }
                    for t in &g.targets {
                        assert!(has(l.hierarchy, t.level_id));
                    }
                    for b in &g.breadcrumbs {
                        assert!(has(l.hierarchy, b.level_id));
                    }
                }
                LevelDocument::Leaf(leaf) => {
                    leaves_with_outgoing += usize::from(!leaf.outgoing.is_empty());
                    for o in &leaf.outgoing {
                        assert!(has(l.hierarchy, o.target.level_id));
                    }
                    for b in &leaf.breadcrumbs {
                        assert!(has(l.hierarchy, b.level_id));
                    }
                }
            }
        }
        assert!(leaves_with_outgoing > 0, "leaves link outside themselves");
    }

    /// The same inputs give the same documents.
    #[test]
    fn it_is_deterministic() {
        let a: Vec<LevelDocument> = build(500).0.into_iter().map(|l| l.doc).collect();
        let b: Vec<LevelDocument> = build(500).0.into_iter().map(|l| l.doc).collect();
        assert_eq!(a, b);
    }
}
