//! The preview hierarchy (feature `check`): a small, navigable set of
//! synthetic level documents for the Explorer's fixture preview
//! (`epigraph-explorer --atlas-fixture-preview`).
//!
//! The contract fixtures (`fixtures/`) are standalone documents whose
//! breadcrumbs, switches and targets point at ids no fixture holds, so a
//! viewer cannot move between them. The preview set is built so every link a
//! viewer can click lands on a document of the set, on the same map:
//!
//! - two maps: a team map (`FIXTURE_TEAM_GROUP_ID`) with two themes, and the
//!   public map with the first of them (themes are global; each map lays
//!   them out on its own);
//! - one tree per (map, theme, hierarchy), all of one shape: the theme root
//!   holds two groups and two leaves, each group a subgroup and a leaf, each
//!   subgroup two leaves;
//! - each level's switch leads to its structural twin in the other hierarchy;
//! - bundle targets and leaf outgoing targets are real levels of the same map
//!   and hierarchy, outside the level, one of them in the other theme when
//!   the map has two;
//! - one team leaf is a full 100-node leaf, the size of `team_leaf_dense`.
//!
//! It is not part of the contract: no route serves it outside the preview,
//! and the files live in `contract/atlas_level/v1/preview/`, apart from the
//! fixtures. Every document still passes the contract (schema, invariants,
//! budget); the crate's tests check that and that every link resolves.
//!
//! Like the fixtures, every name, label and id is synthetic and seeded. To
//! rewrite the committed files after a change here:
//!
//! ```text
//! ATLAS_CONTRACT_BLESS=1 cargo test -p epigraph-atlas-contract _are_current
//! ```

use serde_json::{json, Value};
use uuid::Uuid;

use crate::fixtures::{
    group_name, leaf_level, net_sign, r4, ClaimValues, Frame, Rng, FIXTURE_TEAM_GROUP_ID,
};
use crate::{
    Breadcrumb, Bundle, Child, ChildKind, GroupLevel, Hierarchy, LevelDocument, LinkTarget,
    MapScope, Switch, SCHEMA_VERSION,
};

/// The two hierarchies, in the order the manifest names a theme's roots.
pub const HIERARCHIES: [Hierarchy; 2] = [Hierarchy::Meaning, Hierarchy::Links];

/// One map of the preview, as its manifest entry lists it.
#[derive(Debug, Clone)]
pub struct PreviewMap {
    /// `team` or `public`: the key the page's map picker uses.
    pub key: &'static str,
    pub scope: MapScope,
    pub group_id: Option<Uuid>,
    pub label: &'static str,
    pub themes: Vec<PreviewTheme>,
}

/// A theme on one map, with its root level in each hierarchy.
#[derive(Debug, Clone)]
pub struct PreviewTheme {
    pub theme_id: Uuid,
    pub label: String,
    pub claim_count: u32,
    /// The root level id, by [`HIERARCHIES`] order (meaning, links).
    pub roots: [Uuid; 2],
}

/// The whole preview: the maps and every level document, in a fixed order.
#[derive(Debug, Clone)]
pub struct Preview {
    pub maps: Vec<PreviewMap>,
    /// Every level, with the index of its map in `maps`.
    pub levels: Vec<(usize, LevelDocument)>,
}

/// A level before its document is written.
struct Sk {
    id: Uuid,
    map: usize,
    theme: usize,
    hierarchy: Hierarchy,
    depth: u8,
    kind: ChildKind,
    name: Option<String>,
    needs_naming: bool,
    /// Claims under it (for a leaf, the claim nodes it will hold).
    claim_count: u32,
    /// For a leaf: (claims, agents, evidence) and links per claim.
    leaf_shape: Option<((usize, usize, usize), usize)>,
    parent: Option<usize>,
    children: Vec<usize>,
    /// Its place in the parent's unit circle (the root: none).
    x: f64,
    y: f64,
    r: f64,
    /// Child indices from the theme root: the same in both hierarchies.
    path: Vec<usize>,
}

/// The kinds of a group's children at each depth: the tree's shape.
fn child_kinds(depth: u8) -> &'static [ChildKind] {
    match depth {
        0 => &[
            ChildKind::Group,
            ChildKind::Group,
            ChildKind::Leaf,
            ChildKind::Leaf,
        ],
        1 => &[ChildKind::Group, ChildKind::Leaf],
        _ => &[ChildKind::Leaf, ChildKind::Leaf],
    }
}

/// The dense leaf: the team map's first theme, by meaning, the root's first
/// leaf.
fn is_dense(map: usize, theme: usize, hierarchy: Hierarchy, path: &[usize]) -> bool {
    map == 0 && theme == 0 && hierarchy == Hierarchy::Meaning && path == [2]
}

struct Builder {
    rng: Rng,
    sk: Vec<Sk>,
}

impl Builder {
    /// A level's name: forced unnamed at path [0, 1] and stale at [1, 0], so
    /// every tree shows both cases; otherwise named.
    fn naming(&mut self, path: &[usize]) -> (Option<String>, bool) {
        match path {
            [0, 1] => (None, true),
            [1, 0] => (Some(group_name(&mut self.rng)), true),
            _ => (Some(group_name(&mut self.rng)), false),
        }
    }

    /// Adds `kind` under `parent` (or a root) and, for a group, its subtree.
    /// Returns its index.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        map: usize,
        theme: usize,
        hierarchy: Hierarchy,
        parent: Option<usize>,
        path: Vec<usize>,
        kind: ChildKind,
        root_name: Option<String>,
    ) -> usize {
        let depth = path.len() as u8;
        let (name, needs_naming) = match root_name {
            Some(n) => (Some(n), false),
            None => self.naming(&path),
        };
        let leaf_shape = (kind == ChildKind::Leaf).then(|| {
            if is_dense(map, theme, hierarchy, &path) {
                ((72, 10, 18), 6)
            } else {
                // Small, so the committed set stays a few hundred KB.
                let claims = self.rng.range(6, 12);
                let agents = self.rng.range(2, 3);
                let evidence = self.rng.range(2, 4);
                ((claims, agents, evidence), 2)
            }
        });
        let idx = self.sk.len();
        self.sk.push(Sk {
            id: self.rng.uuid(),
            map,
            theme,
            hierarchy,
            depth,
            kind,
            name,
            needs_naming,
            claim_count: leaf_shape.map_or(0, |((c, _, _), _)| c as u32),
            leaf_shape,
            parent,
            children: Vec::new(),
            x: 0.0,
            y: 0.0,
            r: 1.0,
            path: path.clone(),
        });
        if kind == ChildKind::Group {
            let kinds = child_kinds(depth);
            let n = kinds.len();
            let turn = self.rng.unit() * std::f64::consts::TAU;
            let (rho, r) = if n <= 2 { (0.46, 0.42) } else { (0.5, 0.33) };
            let mut total = 0;
            for (i, k) in kinds.iter().enumerate() {
                let mut p = path.clone();
                p.push(i);
                let c = self.add(map, theme, hierarchy, Some(idx), p, *k, None);
                let a = turn + std::f64::consts::TAU * i as f64 / n as f64;
                let jitter = 0.9 + 0.1 * self.rng.unit();
                let s = &mut self.sk[c];
                s.x = r4(rho * a.cos());
                s.y = r4(rho * a.sin());
                s.r = r4(r * jitter);
                total += s.claim_count;
                self.sk[idx].children.push(c);
            }
            self.sk[idx].claim_count = total;
        }
        idx
    }

    fn ancestors(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut cur = self.sk[i].parent;
        while let Some(p) = cur {
            out.push(p);
            cur = self.sk[p].parent;
        }
        out.reverse();
        out
    }

    /// Whether `j` is `i` or lies under it.
    fn within(&self, j: usize, i: usize) -> bool {
        let mut cur = Some(j);
        while let Some(c) = cur {
            if c == i {
                return true;
            }
            cur = self.sk[c].parent;
        }
        false
    }

    fn twin(&self, i: usize) -> usize {
        let s = &self.sk[i];
        self.sk
            .iter()
            .position(|t| {
                t.map == s.map
                    && t.theme == s.theme
                    && t.hierarchy == s.hierarchy.other()
                    && t.path == s.path
            })
            .expect("every tree has a twin of the same shape")
    }

    /// Up to `n` levels outside `i` (not it, its subtree or its ancestors)
    /// on the same map and hierarchy; the first from another theme when the
    /// map has one.
    fn targets_for(&mut self, i: usize, n: usize) -> Vec<usize> {
        let s = &self.sk[i];
        let ancestors = self.ancestors(i);
        let mut other: Vec<usize> = Vec::new();
        let mut same: Vec<usize> = Vec::new();
        for (j, t) in self.sk.iter().enumerate() {
            if t.map != s.map
                || t.hierarchy != s.hierarchy
                || self.within(j, i)
                || ancestors.contains(&j)
                || t.depth == 0
            {
                continue;
            }
            if t.theme == s.theme {
                same.push(j);
            } else {
                other.push(j);
            }
        }
        let mut out = Vec::new();
        if !other.is_empty() {
            out.push(other[self.rng.below(other.len())]);
        }
        while out.len() < n && !same.is_empty() {
            let j = same.swap_remove(self.rng.below(same.len()));
            out.push(j);
        }
        out
    }

    fn link_target(&self, j: usize, themes: &[Uuid]) -> LinkTarget {
        let t = &self.sk[j];
        LinkTarget {
            level_id: t.id,
            theme_id: themes[t.theme],
            name: t.name.clone(),
            depth: t.depth,
        }
    }

    fn frame(&self, i: usize, maps: &[PreviewMap], runs: &[Uuid]) -> Frame {
        let s = &self.sk[i];
        let m = &maps[s.map];
        Frame {
            map_scope: m.scope,
            map_group_id: m.group_id,
            hierarchy: s.hierarchy,
            theme_id: m.themes[s.theme].theme_id,
            run_id: runs[s.map],
            level_id: s.id,
            depth: s.depth,
            name: s.name.clone(),
            needs_naming: s.needs_naming,
            breadcrumbs: self
                .ancestors(i)
                .into_iter()
                .map(|a| Breadcrumb {
                    level_id: self.sk[a].id,
                    name: self.sk[a].name.clone(),
                    depth: self.sk[a].depth,
                })
                .collect(),
            switch: Switch {
                hierarchy: s.hierarchy.other(),
                level_id: self.sk[self.twin(i)].id,
            },
        }
    }
}

/// A map's (key, scope, group, label, indices of the themes on it).
type MapSpec = (
    &'static str,
    MapScope,
    Option<Uuid>,
    &'static str,
    &'static [usize],
);

/// The preview set. Deterministic: the same call gives the same documents.
pub fn preview() -> Preview {
    let mut b = Builder {
        rng: Rng::new(0xA71A_7001),
        sk: Vec::new(),
    };
    let theme_ids: Vec<Uuid> = (0..2).map(|_| b.rng.uuid()).collect();
    let theme_labels: Vec<String> = (0..2).map(|_| group_name(&mut b.rng)).collect();
    let runs: Vec<Uuid> = (0..2).map(|_| b.rng.uuid()).collect();
    let specs: [MapSpec; 2] = [
        (
            "team",
            MapScope::Team,
            Some(FIXTURE_TEAM_GROUP_ID),
            "Synthetic team map",
            &[0, 1],
        ),
        (
            "public",
            MapScope::Public,
            None,
            "Public map (synthetic)",
            &[0],
        ),
    ];

    let mut maps = Vec::new();
    for (m, (key, scope, group_id, label, on_map)) in specs.iter().enumerate() {
        let mut themes = Vec::new();
        for &t in on_map.iter() {
            let mut roots = [Uuid::nil(); 2];
            let mut count = 0;
            for (h, hierarchy) in HIERARCHIES.iter().enumerate() {
                let root = b.add(
                    m,
                    themes.len(),
                    *hierarchy,
                    None,
                    Vec::new(),
                    ChildKind::Group,
                    Some(theme_labels[t].clone()),
                );
                roots[h] = b.sk[root].id;
                count = b.sk[root].claim_count;
            }
            themes.push(PreviewTheme {
                theme_id: theme_ids[t],
                label: theme_labels[t].clone(),
                claim_count: count,
                roots,
            });
        }
        maps.push(PreviewMap {
            key,
            scope: *scope,
            group_id: *group_id,
            label,
            themes,
        });
    }

    let mut levels = Vec::new();
    for i in 0..b.sk.len() {
        let f = b.frame(i, &maps, &runs);
        let theme_ids: Vec<Uuid> = maps[b.sk[i].map]
            .themes
            .iter()
            .map(|t| t.theme_id)
            .collect();
        let map = b.sk[i].map;
        let doc = match b.sk[i].kind {
            ChildKind::Group => {
                let kids = b.sk[i].children.clone();
                let children: Vec<Child> = kids
                    .iter()
                    .map(|&c| {
                        let s = &b.sk[c];
                        Child {
                            id: s.id,
                            kind: s.kind,
                            name: s.name.clone(),
                            needs_naming: s.needs_naming,
                            claim_count: s.claim_count,
                            x: s.x,
                            y: s.y,
                            r: s.r,
                        }
                    })
                    .collect();
                let mut bundles = Vec::new();
                for (k, &c) in kids.iter().enumerate() {
                    let sib = kids[(k + 1 + b.rng.below(kids.len() - 1)) % kids.len()];
                    bundles.push(Bundle {
                        source: b.sk[c].id,
                        target: b.sk[sib].id,
                        count: b.rng.range(1, 40) as u32,
                        net_sign: net_sign(&mut b.rng),
                    });
                }
                let outside = b.targets_for(i, 3);
                let targets: Vec<LinkTarget> = outside
                    .iter()
                    .map(|&j| b.link_target(j, &theme_ids))
                    .collect();
                for t in &targets {
                    let src = kids[b.rng.below(kids.len())];
                    bundles.push(Bundle {
                        source: b.sk[src].id,
                        target: t.level_id,
                        count: b.rng.range(1, 40) as u32,
                        net_sign: net_sign(&mut b.rng),
                    });
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
                let (sizes, per_claim) = b.sk[i].leaf_shape.expect("a leaf has a shape");
                let outside = b.targets_for(i, 3);
                let targets: Vec<LinkTarget> = outside
                    .iter()
                    .map(|&j| b.link_target(j, &theme_ids))
                    .collect();
                let (mut leaf, _) = leaf_level(
                    &mut b.rng,
                    f,
                    sizes,
                    per_claim,
                    targets.len(),
                    ClaimValues::AS_DRAWN,
                );
                for (o, t) in leaf.outgoing.iter_mut().zip(targets) {
                    o.target = t;
                }
                LevelDocument::Leaf(leaf)
            }
        };
        levels.push((map, doc));
    }
    Preview { maps, levels }
}

impl Preview {
    /// The manifest the preview page carries in `data-atlas-maps`: the maps a
    /// viewer may pick and each theme's root level per hierarchy. The
    /// contract defines neither (W10 supplies the real one).
    pub fn manifest(&self) -> Value {
        let maps: Vec<Value> = self
            .maps
            .iter()
            .map(|m| {
                json!({
                    "key": m.key,
                    "scope": m.scope,
                    "group_id": m.group_id,
                    "label": m.label,
                    "themes": m.themes.iter().map(|t| json!({
                        "theme_id": t.theme_id,
                        "label": t.label,
                        "claim_count": t.claim_count,
                        "roots": {"meaning": t.roots[0], "links": t.roots[1]},
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({
            "synthetic": true,
            "note": "Atlas fixture preview: synthetic levels, not real data. Generated by epigraph-atlas-contract::preview.",
            "maps": maps,
        })
    }
}

/// The preview files: `manifest.json` (pretty, final newline) and
/// `levels.jsonl` (one compact stored document per line).
pub fn preview_files() -> Vec<(String, String)> {
    let p = preview();
    let mut manifest = serde_json::to_string_pretty(&p.manifest()).expect("a Value serialises");
    manifest.push('\n');
    let mut lines = String::new();
    for (_, doc) in &p.levels {
        let bytes = doc
            .to_stored_json()
            .unwrap_or_else(|e| panic!("preview level {} is invalid: {e}", doc.level_id()));
        lines.push_str(std::str::from_utf8(&bytes).expect("JSON is UTF-8"));
        lines.push('\n');
    }
    vec![
        ("levels.jsonl".to_string(), lines),
        ("manifest.json".to_string(), manifest),
    ]
}
