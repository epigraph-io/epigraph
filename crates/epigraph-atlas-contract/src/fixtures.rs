//! The deterministic fixture generator (feature `check`).
//!
//! Every fixture is built from a fixed seed with an inline SplitMix64, so
//! the output never depends on a `rand` version. All names, labels and ids
//! are synthetic: pseudo-words made of fixed syllables and random v4 ids.
//! No fixture holds real data.
//!
//! To rewrite the committed fixtures after a change here:
//!
//! ```text
//! ATLAS_CONTRACT_BLESS=1 cargo test -p epigraph-atlas-contract fixtures_are_current
//! ```
//!
//! The worst-case builders ([`worst_case_leaf`], [`worst_case_group`]) are
//! not written to disk. They fill every array to its cap and every string to
//! its maximum length with random Latin, Greek, Cyrillic and CJK text, and
//! the budget test shows that they fit. Text that compresses worse than that
//! can still exceed the budget, which is why producers store through
//! [`crate::LevelDocument::to_stored_json`].

use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    Breadcrumb, Bundle, Child, ChildKind, ClaimNode, Edge, FlowBasis, GroupLevel, Hierarchy,
    LeafLevel, LevelDocument, LinkTarget, MapScope, Node, Outgoing, PlainNode, Switch, MAX_DEPTH,
    MAX_GROUP_BUNDLES, MAX_GROUP_CHILDREN, MAX_GROUP_TARGETS, MAX_LABEL_CHARS, MAX_LEAF_EDGES,
    MAX_LEAF_NODES, MAX_LEAF_OUTGOING, MAX_NAME_CHARS, MAX_RELATIONSHIP_CHARS, SCHEMA_VERSION,
};

/// The synthetic team group every team fixture belongs to. Route tests that
/// replay a team fixture expect this map ([`crate::check::Expected::team`]).
pub const FIXTURE_TEAM_GROUP_ID: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);

/// SplitMix64: a fixed, dependency-free stream.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (n > 0; the modulo bias is irrelevant here).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// A random version-4 id.
    pub fn uuid(&mut self) -> Uuid {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.next_u64().to_le_bytes());
        b[8..].copy_from_slice(&self.next_u64().to_le_bytes());
        uuid::Builder::from_random_bytes(b).into_uuid()
    }
}

/// Rounded to 4 decimals, as a builder storing compact documents would.
fn r4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

const SYLLABLES: &[&str] = &[
    "ka", "ro", "ve", "lin", "tor", "sa", "mi", "del", "qua", "ar", "on", "is", "ex", "ul", "pra",
    "zen", "fo", "ri", "ta", "ne", "bel", "cor", "dun", "im", "op", "sel", "thi", "vor",
];

fn word(rng: &mut Rng) -> String {
    (0..rng.range(2, 3))
        .map(|_| SYLLABLES[rng.below(SYLLABLES.len())])
        .collect()
}

fn capitalised(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// A synthetic group name of a few pseudo-words.
fn group_name(rng: &mut Rng) -> String {
    let n = rng.range(2, 5);
    let words: Vec<String> = (0..n).map(|_| word(rng)).collect();
    capitalised(&words.join(" "))
}

/// A synthetic claim sentence, clipped to the label cap.
fn claim_label(rng: &mut Rng) -> String {
    let n = rng.range(6, 30);
    let words: Vec<String> = (0..n).map(|_| word(rng)).collect();
    let mut s = capitalised(&words.join(" "));
    s.push('.');
    clip(s, MAX_LABEL_CHARS)
}

fn clip(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        s
    } else {
        s.chars().take(max).collect()
    }
}

/// A name, or (for about one child in ten) none yet, or a stale name that
/// is due for renaming.
fn naming(rng: &mut Rng) -> (Option<String>, bool) {
    let roll = rng.unit();
    if roll < 0.1 {
        (None, true)
    } else if roll < 0.15 {
        (Some(group_name(rng)), true)
    } else {
        (Some(group_name(rng)), false)
    }
}

/// -1, 0 or 1, mostly supporting.
fn net_sign(rng: &mut Rng) -> i8 {
    let roll = rng.unit();
    if roll < 0.6 {
        1
    } else if roll < 0.85 {
        0
    } else {
        -1
    }
}

/// The envelope fields shared by every fixture.
struct Frame {
    map_scope: MapScope,
    map_group_id: Option<Uuid>,
    hierarchy: Hierarchy,
    theme_id: Uuid,
    run_id: Uuid,
    level_id: Uuid,
    depth: u8,
    name: Option<String>,
    needs_naming: bool,
    breadcrumbs: Vec<Breadcrumb>,
    switch: Switch,
}

fn frame(rng: &mut Rng, map_scope: MapScope, hierarchy: Hierarchy, depth: u8) -> Frame {
    let map_group_id = match map_scope {
        MapScope::Team => Some(FIXTURE_TEAM_GROUP_ID),
        MapScope::Public => None,
    };
    let theme_id = rng.uuid();
    let run_id = rng.uuid();
    let level_id = rng.uuid();
    let breadcrumbs = (0..depth)
        .map(|d| Breadcrumb {
            level_id: rng.uuid(),
            name: Some(group_name(rng)),
            depth: d,
        })
        .collect();
    Frame {
        map_scope,
        map_group_id,
        hierarchy,
        theme_id,
        run_id,
        level_id,
        depth,
        name: Some(group_name(rng)),
        needs_naming: false,
        breadcrumbs,
        switch: Switch {
            hierarchy: hierarchy.other(),
            level_id: rng.uuid(),
        },
    }
}

/// Outside groups a level links to, spread over a few other themes.
fn outside_targets(rng: &mut Rng, n: usize) -> Vec<LinkTarget> {
    let themes: Vec<Uuid> = (0..n.div_ceil(3).max(1)).map(|_| rng.uuid()).collect();
    (0..n)
        .map(|_| {
            let (name, _) = naming(rng);
            LinkTarget {
                level_id: rng.uuid(),
                theme_id: themes[rng.below(themes.len())],
                name,
                depth: rng.range(0, 4) as u8,
            }
        })
        .collect()
}

/// A group level: `n_children` children placed on a sunflower spiral, three
/// links per child to siblings, and links to `n_targets` outside groups.
fn group_level(
    rng: &mut Rng,
    f: Frame,
    n_children: usize,
    n_leaf_children: usize,
    n_targets: usize,
) -> GroupLevel {
    let golden = std::f64::consts::PI * (3.0 - 5f64.sqrt());
    let children: Vec<Child> = (0..n_children)
        .map(|i| {
            let leaf = i >= n_children - n_leaf_children;
            let claim_count = if leaf {
                rng.range(15, 60)
            } else {
                rng.range(40, 90)
            } as u32;
            let (name, needs_naming) = naming(rng);
            let rho = 0.85 * ((i as f64 + 0.5) / n_children as f64).sqrt();
            let theta = i as f64 * golden;
            Child {
                id: rng.uuid(),
                kind: if leaf {
                    ChildKind::Leaf
                } else {
                    ChildKind::Group
                },
                name,
                needs_naming,
                claim_count,
                x: r4(rho * theta.cos()),
                y: r4(rho * theta.sin()),
                r: r4(0.04 + 0.06 * (f64::from(claim_count) / 90.0).sqrt()),
            }
        })
        .collect();
    let targets = outside_targets(rng, n_targets);

    let mut bundles = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut push = |rng: &mut Rng, source: Uuid, target: Uuid, bundles: &mut Vec<Bundle>| {
        if source != target && seen.insert((source, target)) {
            bundles.push(Bundle {
                source,
                target,
                count: rng.range(1, 40) as u32,
                net_sign: net_sign(rng),
            });
        }
    };
    for c in &children {
        for _ in 0..3 {
            let t = children[rng.below(children.len())].id;
            push(rng, c.id, t, &mut bundles);
        }
    }
    for t in &targets {
        for _ in 0..rng.range(1, 4) {
            let s = children[rng.below(children.len())].id;
            push(rng, s, t.level_id, &mut bundles);
        }
    }

    GroupLevel {
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
    }
}

/// Claim-to-claim relationship names as the `edges` table spells them, both
/// casings included: the view must not assume lower case.
const CLAIM_RELATIONSHIPS: &[(&str, i8)] = &[
    ("supports", 1),
    ("supports", 1),
    ("SUPPORTS", 1),
    ("corroborates", 1),
    ("CORROBORATES", 1),
    ("elaborates", 1),
    ("decomposes_to", 1),
    ("cites", 0),
    ("contradicts", -1),
    ("CONTRADICTS", -1),
    ("refutes", -1),
];

/// Agent-to-claim relationship names in use: no belief flow.
const AGENT_RELATIONSHIPS: &[&str] = &["AUTHORED", "authored", "asserts"];

/// A leaf: claims, the agents that asserted them and their evidence, with
/// `per_claim` claim-to-claim links per claim and `n_outgoing` outside
/// target groups.
///
/// `truth` maps each claim's drawn `truth_value` before it is stored (the
/// identity for the committed fixtures). A test can change every claim's
/// colour value this way without moving the seeded stream, and so show that
/// no edge weight depends on it.
fn leaf_level(
    rng: &mut Rng,
    f: Frame,
    (n_claims, n_agents, n_evidence): (usize, usize, usize),
    per_claim: usize,
    n_outgoing: usize,
    truth: fn(Option<f64>) -> Option<f64>,
) -> LeafLevel {
    let pos = |rng: &mut Rng| (r4(rng.unit() * 1.9 - 0.95), r4(rng.unit() * 1.9 - 0.95));
    let claims: Vec<ClaimNode> = (0..n_claims)
        .map(|_| {
            let (x, y) = pos(rng);
            // An earlier generator drew a per-claim belief here and below.
            // Proxy weights no longer use one, but the draws stay so every
            // other value in the committed fixtures is unchanged.
            let _ = rng.unit();
            let node = ClaimNode {
                id: rng.uuid(),
                label: claim_label(rng),
                x,
                y,
                truth_value: truth(if rng.chance(0.05) {
                    None
                } else {
                    Some(r4(rng.unit()))
                }),
            };
            let _ = rng.chance(0.05);
            node
        })
        .collect();
    let agents: Vec<PlainNode> = (0..n_agents)
        .map(|i| {
            let (x, y) = pos(rng);
            PlainNode {
                id: rng.uuid(),
                label: format!("Synthetic agent {:02}", i + 1),
                x,
                y,
            }
        })
        .collect();
    let evidence: Vec<PlainNode> = (0..n_evidence)
        .map(|_| {
            let (x, y) = pos(rng);
            PlainNode {
                id: rng.uuid(),
                label: clip(format!("Evidence: {}", group_name(rng)), MAX_LABEL_CHARS),
                x,
                y,
            }
        })
        .collect();

    let mut edges = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut push = |edges: &mut Vec<Edge>, e: Edge| {
        if e.source != e.target && seen.insert((e.source, e.target, e.relationship.clone())) {
            edges.push(e);
        }
    };
    // Each claim was asserted or authored by one agent: no belief flow.
    // The first agents take the first claims, so every agent is in the leaf
    // because of a claim (design §7 step 3).
    for (i, c) in claims.iter().enumerate() {
        let a = &agents[if i < agents.len() {
            i
        } else {
            rng.below(agents.len())
        }];
        push(
            &mut edges,
            Edge {
                source: a.id,
                target: c.id,
                relationship: AGENT_RELATIONSHIPS[rng.below(AGENT_RELATIONSHIPS.len())].into(),
                sign: 0,
                flow_weight: 0.0,
                flow_basis: FlowBasis::None,
            },
        );
    }
    // Evidence to claims: the exact stored mass.
    for ev in &evidence {
        for _ in 0..rng.range(2, 4) {
            let c = &claims[rng.below(claims.len())];
            let opposing = rng.chance(0.15);
            push(
                &mut edges,
                Edge {
                    source: ev.id,
                    target: c.id,
                    relationship: if opposing {
                        "refutes"
                    } else if rng.chance(0.3) {
                        "SUPPORTS"
                    } else {
                        "supports"
                    }
                    .into(),
                    sign: if opposing { -1 } else { 1 },
                    flow_weight: r4(0.05 + 0.9 * rng.unit()),
                    flow_basis: FlowBasis::Exact,
                },
            );
        }
    }
    // Claims to claims: the link's strength times its sign, and nothing
    // else. `flow_weight` is the magnitude (strength × |sign|) and `sign`
    // the direction, so a `cites` link (sign 0) weighs 0. No belief value of
    // either claim enters it.
    for c in &claims {
        for _ in 0..per_claim {
            let t = &claims[rng.below(claims.len())];
            let (rel, sign) = CLAIM_RELATIONSHIPS[rng.below(CLAIM_RELATIONSHIPS.len())];
            let strength = 0.3 + 0.7 * rng.unit();
            push(
                &mut edges,
                Edge {
                    source: c.id,
                    target: t.id,
                    relationship: rel.into(),
                    sign,
                    flow_weight: r4(strength * f64::from(sign.unsigned_abs())),
                    flow_basis: FlowBasis::Proxy,
                },
            );
        }
    }

    let outgoing = outside_targets(rng, n_outgoing)
        .into_iter()
        .map(|target| {
            let mut sources: Vec<Uuid> = Vec::new();
            for _ in 0..rng.range(1, 12) {
                let s = claims[rng.below(claims.len())].id;
                if !sources.contains(&s) {
                    sources.push(s);
                }
            }
            Outgoing {
                target,
                count: (sources.len() + rng.range(0, 20)) as u32,
                net_sign: net_sign(rng),
                sources,
            }
        })
        .collect();

    let nodes = claims
        .into_iter()
        .map(Node::Claim)
        .chain(agents.into_iter().map(Node::Agent))
        .chain(evidence.into_iter().map(Node::Evidence))
        .collect();
    LeafLevel {
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
        nodes,
        edges,
        outgoing,
    }
}

/// A team map's theme root, by meaning: about 40 children and their
/// bundles.
pub fn team_theme_root() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5001);
    let f = frame(&mut rng, MapScope::Team, Hierarchy::Meaning, 0);
    LevelDocument::Group(group_level(&mut rng, f, 40, 12, 24))
}

/// A deep group level of a team map, by links, whose own name is pending.
pub fn team_group_deep() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5002);
    let mut f = frame(&mut rng, MapScope::Team, Hierarchy::Links, 4);
    f.name = None;
    f.needs_naming = true;
    LevelDocument::Group(group_level(&mut rng, f, 12, 8, 10))
}

/// A full team leaf: 100 nodes with dense edges.
pub fn team_leaf_dense() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5003);
    let f = frame(&mut rng, MapScope::Team, Hierarchy::Meaning, 5);
    LevelDocument::Leaf(leaf_level(&mut rng, f, (72, 10, 18), 6, 30, |t| t))
}

/// A leaf of the public map.
pub fn public_leaf() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5004);
    let f = frame(&mut rng, MapScope::Public, Hierarchy::Links, 3);
    LevelDocument::Leaf(leaf_level(&mut rng, f, (45, 5, 10), 3, 10, |t| t))
}

/// A leaf built the way the committed leaf fixtures are, from any seed, with
/// `truth` applied to every claim's drawn `truth_value`. For the contract's
/// own tests of the generator's weight rule.
#[cfg(test)]
pub(crate) fn seeded_leaf(seed: u64, truth: fn(Option<f64>) -> Option<f64>) -> LeafLevel {
    let mut rng = Rng::new(seed);
    let scope = if seed.is_multiple_of(2) {
        MapScope::Team
    } else {
        MapScope::Public
    };
    let f = frame(&mut rng, scope, Hierarchy::Links, 3);
    leaf_level(&mut rng, f, (40, 6, 10), 4, 8, truth)
}

/// The kernel's answer to a viewer who is not a member of the level's map,
/// the same as for an absent level.
pub fn non_member_kernel() -> Value {
    let id = Rng::new(0xA71A_5005).uuid().to_string();
    json!({
        "status": 404,
        "body": {
            "error": "NotFound",
            "message": format!("atlas_level with ID {id} not found"),
            "details": {"entity": "atlas_level", "id": id}
        }
    })
}

/// The Explorer BFF's answer in the same case.
pub fn non_member_bff() -> Value {
    json!({
        "status": 404,
        "body": {"error": "not_found", "message": "We could not find that atlas level."}
    })
}

/// The level fixtures, by file stem.
pub fn level_fixtures() -> Vec<(&'static str, LevelDocument)> {
    vec![
        ("team_theme_root", team_theme_root()),
        ("team_group_deep", team_group_deep()),
        ("team_leaf_dense", team_leaf_dense()),
        ("public_leaf", public_leaf()),
    ]
}

/// The non-member fixtures, by file stem.
pub fn not_found_fixtures() -> Vec<(&'static str, Value)> {
    vec![
        ("non_member_kernel", non_member_kernel()),
        ("non_member_bff", non_member_bff()),
    ]
}

/// Every fixture file: `(file name, contents)`, pretty JSON with a final
/// newline.
pub fn files() -> Vec<(String, String)> {
    let render = |v: &Value| {
        let mut s = serde_json::to_string_pretty(v).expect("a Value serialises");
        s.push('\n');
        s
    };
    // Level documents are rendered from the types, so keys keep the
    // declaration order (`kind` first) rather than a `Value`'s sorted order.
    let mut out: Vec<(String, String)> = level_fixtures()
        .iter()
        .map(|(stem, doc)| {
            let mut s = serde_json::to_string_pretty(doc).expect("a document serialises");
            s.push('\n');
            (format!("{stem}.json"), s)
        })
        .collect();
    out.extend(
        not_found_fixtures()
            .iter()
            .map(|(stem, v)| (format!("{stem}.json"), render(v))),
    );
    out
}

// ---- worst cases -----------------------------------------------------------

/// A string of exactly `n` characters drawn uniformly from Latin, Greek,
/// Cyrillic and CJK: far less compressible than any real name or claim.
pub fn dense_text(rng: &mut Rng, n: usize) -> String {
    const RANGES: &[(u32, u32)] = &[
        (0x21, 0x7E),
        (0xC0, 0x24F),
        (0x391, 0x3C9),
        (0x410, 0x44F),
        (0x4E00, 0x9FFF),
    ];
    (0..n)
        .map(|_| {
            let (lo, hi) = RANGES[rng.below(RANGES.len())];
            let c = lo + rng.below((hi - lo + 1) as usize) as u32;
            char::from_u32(c).expect("the ranges hold no surrogate")
        })
        .collect()
}

/// A relationship of the maximum length: a random letter, then random
/// letters of both cases, digits and `_`.
fn dense_relationship(rng: &mut Rng) -> String {
    const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const TAIL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
    (0..MAX_RELATIONSHIP_CHARS)
        .map(|i| {
            let set = if i == 0 { LETTERS } else { TAIL };
            set[rng.below(set.len())] as char
        })
        .collect()
}

fn worst_frame(rng: &mut Rng) -> Frame {
    let mut f = frame(rng, MapScope::Team, Hierarchy::Meaning, MAX_DEPTH);
    f.name = Some(dense_text(rng, MAX_NAME_CHARS));
    for b in &mut f.breadcrumbs {
        b.name = Some(dense_text(rng, MAX_NAME_CHARS));
    }
    f
}

fn worst_target(rng: &mut Rng) -> LinkTarget {
    LinkTarget {
        level_id: rng.uuid(),
        theme_id: rng.uuid(),
        name: Some(dense_text(rng, MAX_NAME_CHARS)),
        depth: MAX_DEPTH,
    }
}

/// The largest leaf the caps allow: 100 claim nodes with full-length dense
/// labels and full-precision numbers, every edge slot used with a dense
/// relationship name, and every outgoing slot used with 100 sources.
pub fn worst_case_leaf() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5F01);
    let f = worst_frame(&mut rng);
    let claims: Vec<ClaimNode> = (0..MAX_LEAF_NODES)
        .map(|_| ClaimNode {
            id: rng.uuid(),
            label: dense_text(&mut rng, MAX_LABEL_CHARS),
            x: rng.unit() * 2.0 - 1.0,
            y: rng.unit() * 2.0 - 1.0,
            truth_value: Some(rng.unit()),
        })
        .collect();
    let ids: Vec<Uuid> = claims.iter().map(|c| c.id).collect();
    let edges = (0..MAX_LEAF_EDGES)
        .map(|i| {
            let s = i % MAX_LEAF_NODES;
            let t = (s + 1 + rng.below(MAX_LEAF_NODES - 1)) % MAX_LEAF_NODES;
            Edge {
                source: ids[s],
                target: ids[t],
                relationship: dense_relationship(&mut rng),
                sign: [-1, 1][rng.below(2)],
                flow_weight: rng.unit(),
                flow_basis: FlowBasis::Proxy,
            }
        })
        .collect();
    let outgoing = (0..MAX_LEAF_OUTGOING)
        .map(|_| {
            let mut sources = ids.clone();
            // A different order per target, so no two lists repeat verbatim.
            for i in (1..sources.len()).rev() {
                sources.swap(i, rng.below(i + 1));
            }
            Outgoing {
                target: worst_target(&mut rng),
                count: u32::MAX,
                net_sign: -1,
                sources,
            }
        })
        .collect();
    LevelDocument::Leaf(LeafLevel {
        schema_version: SCHEMA_VERSION,
        map_scope: f.map_scope,
        map_group_id: f.map_group_id,
        hierarchy: f.hierarchy,
        theme_id: f.theme_id,
        run_id: f.run_id,
        level_id: f.level_id,
        depth: f.depth,
        name: f.name,
        needs_naming: true,
        breadcrumbs: f.breadcrumbs,
        switch: f.switch,
        nodes: claims.into_iter().map(Node::Claim).collect(),
        edges,
        outgoing,
    })
}

/// The largest group level the caps allow: every child, target and bundle
/// slot used, every name full-length dense text.
pub fn worst_case_group() -> LevelDocument {
    let mut rng = Rng::new(0xA71A_5F02);
    let f = worst_frame(&mut rng);
    let children: Vec<Child> = (0..MAX_GROUP_CHILDREN)
        .map(|_| Child {
            id: rng.uuid(),
            kind: ChildKind::Group,
            name: Some(dense_text(&mut rng, MAX_NAME_CHARS)),
            needs_naming: true,
            claim_count: u32::MAX,
            x: rng.unit() * 2.0 - 1.0,
            y: rng.unit() * 2.0 - 1.0,
            r: rng.unit().max(f64::MIN_POSITIVE),
        })
        .collect();
    let targets: Vec<LinkTarget> = (0..MAX_GROUP_TARGETS)
        .map(|_| worst_target(&mut rng))
        .collect();
    let mut ends: Vec<Uuid> = children.iter().map(|c| c.id).collect();
    ends.extend(targets.iter().map(|t| t.level_id));
    // Every target first (so each is used), then distinct pairs.
    let mut bundles = Vec::with_capacity(MAX_GROUP_BUNDLES);
    let mut seen = std::collections::BTreeSet::new();
    let mut k = 0usize;
    while bundles.len() < MAX_GROUP_BUNDLES {
        let target = if k < targets.len() {
            targets[k].level_id
        } else {
            ends[rng.below(ends.len())]
        };
        let source = children[rng.below(children.len())].id;
        k += 1;
        if source != target && seen.insert((source, target)) {
            bundles.push(Bundle {
                source,
                target,
                count: u32::MAX,
                net_sign: -1,
            });
        }
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
        needs_naming: true,
        breadcrumbs: f.breadcrumbs,
        switch: f.switch,
        children,
        bundles,
        targets,
    })
}
