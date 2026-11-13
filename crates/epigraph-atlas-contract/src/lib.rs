//! The Atlas nested-level payload contract, schema v1 (backlog W10a).
//!
//! One Atlas level below a theme is one JSON document:
//!
//! - a **group level** ([`GroupLevel`]): its named children, with
//!   precomputed positions, and the cross-group link bundles aggregated to
//!   this level;
//! - a **leaf** ([`LeafLevel`]): at most [`MAX_LEAF_NODES`] claims, agents
//!   and evidence with precomputed positions, the belief-flow edges among
//!   them, and the links that leave the leaf, aggregated by target group.
//!
//! The layout builder writes the document, the layout store keeps it as one
//! `jsonb` row next to a `schema_version` column, and the kernel route and
//! the Explorer BFF serve it unchanged. The language-neutral contract is the
//! JSON Schema at `services/explorer/contract/atlas_level/v1/schema.json`.
//! It sits under `services/explorer` because the Explorer is a standalone
//! crate that cannot read outside its own directory, while the kernel can.
//! The fixtures next to it are written by [`fixtures`].
//!
//! These types are the kernel's side of that contract. Deserialising is
//! strict: an unknown key anywhere is an error, and so is a missing key,
//! nullable ones included. [`LevelDocument::validate`] checks everything
//! the schema checks, plus what a JSON Schema cannot express: references
//! between parts of the document, and which flow basis each edge may have.
//! The crate's tests prove that the strict types with `validate` and the
//! schema agree, and that the largest document the caps allow fits
//! [`BUDGET_GZIP_BYTES`] when its text is no less compressible than random
//! multi-script text. `validate` does not measure size: a producer that
//! needs the budget enforced measures the compressed body itself (as
//! [`check::check_level_body`] does).
//!
//! With the `check` feature, [`check`] validates a served body against the
//! schema and the budget. Route tests call it on real responses.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(any(test, feature = "check"))]
pub mod check;
#[cfg(any(test, feature = "check"))]
pub mod fixtures;
#[cfg(test)]
mod tests;

/// The value of every v1 document's `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;
/// The `$id` of the v1 JSON Schema.
pub const SCHEMA_ID: &str = "urn:epigraph:atlas-level:v1";
/// Each level's compact JSON, gzip-compressed, is at most this many bytes
/// (design §6: 150 KB, read as the stricter 150,000).
pub const BUDGET_GZIP_BYTES: usize = 150_000;

/// Nodes in a leaf: claims, agents and evidence counted together.
pub const MAX_LEAF_NODES: usize = 100;
/// Edges in a leaf.
pub const MAX_LEAF_EDGES: usize = 1024;
/// Target groups in a leaf's `outgoing`.
pub const MAX_LEAF_OUTGOING: usize = 64;
/// Children of a group level.
pub const MAX_GROUP_CHILDREN: usize = 128;
/// Bundles of a group level.
pub const MAX_GROUP_BUNDLES: usize = 2048;
/// Outside targets of a group level.
pub const MAX_GROUP_TARGETS: usize = 160;
/// The deepest level (the theme root is 0), and so the most breadcrumbs.
pub const MAX_DEPTH: u8 = 16;
/// Characters in a group name.
pub const MAX_NAME_CHARS: usize = 120;
/// Characters in a node label.
pub const MAX_LABEL_CHARS: usize = 160;
/// Characters in an edge relationship.
pub const MAX_RELATIONSHIP_CHARS: usize = 32;

/// Whose map a level belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapScope {
    /// A team's map: built from that team's claims plus public claims,
    /// served to its members.
    Team,
    /// The public map: public claims only.
    Public,
}

/// The two groupings under each theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hierarchy {
    /// Groups of claims with similar embeddings.
    Meaning,
    /// Communities of densely interlinked claims.
    Links,
}

impl Hierarchy {
    /// The hierarchy the switch leads to.
    pub fn other(self) -> Self {
        match self {
            Hierarchy::Meaning => Hierarchy::Links,
            Hierarchy::Links => Hierarchy::Meaning,
        }
    }
}

/// Whether a child opens onto more groups or onto a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildKind {
    Group,
    Leaf,
}

/// Where an edge's `flow_weight` comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowBasis {
    /// Evidence to claim: the stored mass.
    Exact,
    /// Claim to claim: link strength times the source claim's BetP. The view
    /// labels it an estimate.
    Proxy,
    /// No belief flow (an agent's authorship, for example): weight 0, sign 0.
    None,
}

/// An ancestor of a level, from the theme root down to the parent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Breadcrumb {
    pub level_id: Uuid,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<String>,
    pub depth: u8,
}

/// The meaning/links switch: the counterpart level in the other hierarchy
/// for the same theme. Which level that is (the best overlap, or the other
/// hierarchy's root) is the builder's choice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Switch {
    pub hierarchy: Hierarchy,
    pub level_id: Uuid,
}

/// A group a link leads to: enough to fly to it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkTarget {
    pub level_id: Uuid,
    pub theme_id: Uuid,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<String>,
    pub depth: u8,
}

/// A child of a group level, positioned in the parent's unit circle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Child {
    pub id: Uuid,
    pub kind: ChildKind,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<String>,
    pub needs_naming: bool,
    /// Claims under this child that the map draws.
    pub claim_count: u32,
    pub x: f64,
    pub y: f64,
    pub r: f64,
}

/// All links from one child to one target group, aggregated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// A child of this level.
    pub source: Uuid,
    /// A sibling child, or an entry of [`GroupLevel::targets`].
    pub target: Uuid,
    pub count: u32,
    /// -1, 0 or 1.
    pub net_sign: i8,
}

/// A claim node of a leaf.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimNode {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
    /// The colour value, as at the region and theme levels.
    #[serde(deserialize_with = "Option::deserialize")]
    pub truth_value: Option<f64>,
    /// The cached pignistic probability; proxy flows are computed from it.
    #[serde(deserialize_with = "Option::deserialize")]
    pub betp: Option<f64>,
}

/// An agent or evidence node of a leaf.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainNode {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
}

/// A node of a leaf, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Node {
    Claim(ClaimNode),
    Agent(PlainNode),
    Evidence(PlainNode),
}

impl Node {
    pub fn id(&self) -> Uuid {
        match self {
            Node::Claim(n) => n.id,
            Node::Agent(n) | Node::Evidence(n) => n.id,
        }
    }

    fn kind_str(&self) -> &'static str {
        match self {
            Node::Claim(_) => "claim",
            Node::Agent(_) => "agent",
            Node::Evidence(_) => "evidence",
        }
    }

    fn label_xy(&self) -> (&str, f64, f64) {
        match self {
            Node::Claim(n) => (&n.label, n.x, n.y),
            Node::Agent(n) | Node::Evidence(n) => (&n.label, n.x, n.y),
        }
    }
}

/// A link between two nodes of a leaf, pointing the way belief flows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub source: Uuid,
    pub target: Uuid,
    pub relationship: String,
    /// 1 supporting, -1 opposing, 0 no belief direction.
    pub sign: i8,
    /// In [0, 1].
    pub flow_weight: f64,
    pub flow_basis: FlowBasis,
}

/// All links leaving a leaf for one target group, aggregated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outgoing {
    pub target: LinkTarget,
    pub count: u32,
    pub net_sign: i8,
    /// The leaf nodes the links leave from.
    pub sources: Vec<Uuid>,
}

/// A group level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupLevel {
    pub schema_version: u32,
    pub map_scope: MapScope,
    /// The team group of a team map; `None` for the public map.
    #[serde(deserialize_with = "Option::deserialize")]
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    pub run_id: Uuid,
    pub level_id: Uuid,
    pub depth: u8,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<String>,
    pub needs_naming: bool,
    pub breadcrumbs: Vec<Breadcrumb>,
    pub switch: Switch,
    pub children: Vec<Child>,
    pub bundles: Vec<Bundle>,
    pub targets: Vec<LinkTarget>,
}

/// A leaf level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafLevel {
    pub schema_version: u32,
    pub map_scope: MapScope,
    #[serde(deserialize_with = "Option::deserialize")]
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    pub run_id: Uuid,
    pub level_id: Uuid,
    pub depth: u8,
    #[serde(deserialize_with = "Option::deserialize")]
    pub name: Option<String>,
    pub needs_naming: bool,
    pub breadcrumbs: Vec<Breadcrumb>,
    pub switch: Switch,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub outgoing: Vec<Outgoing>,
}

/// One Atlas level document, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LevelDocument {
    Group(GroupLevel),
    Leaf(LeafLevel),
}

/// The fields every level carries.
struct Envelope<'a> {
    schema_version: u32,
    map_scope: MapScope,
    map_group_id: Option<Uuid>,
    hierarchy: Hierarchy,
    level_id: Uuid,
    depth: u8,
    name: &'a Option<String>,
    needs_naming: bool,
    breadcrumbs: &'a [Breadcrumb],
    switch: &'a Switch,
}

/// What [`LevelDocument::validate`] found, one entry per broken rule, each
/// prefixed with a JSON-pointer-like path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations(pub Vec<String>);

impl std::fmt::Display for Violations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("; "))
    }
}

impl std::error::Error for Violations {}

/// Parse a body strictly and validate it: the producer-side check, with no
/// JSON Schema validator.
pub fn parse_and_validate(body: &[u8]) -> Result<LevelDocument, Violations> {
    let doc: LevelDocument =
        serde_json::from_slice(body).map_err(|e| Violations(vec![format!("decode: {e}")]))?;
    doc.validate()?;
    Ok(doc)
}

impl LevelDocument {
    pub fn level_id(&self) -> Uuid {
        match self {
            LevelDocument::Group(g) => g.level_id,
            LevelDocument::Leaf(l) => l.level_id,
        }
    }

    fn envelope(&self) -> Envelope<'_> {
        match self {
            LevelDocument::Group(g) => Envelope {
                schema_version: g.schema_version,
                map_scope: g.map_scope,
                map_group_id: g.map_group_id,
                hierarchy: g.hierarchy,
                level_id: g.level_id,
                depth: g.depth,
                name: &g.name,
                needs_naming: g.needs_naming,
                breadcrumbs: &g.breadcrumbs,
                switch: &g.switch,
            },
            LevelDocument::Leaf(l) => Envelope {
                schema_version: l.schema_version,
                map_scope: l.map_scope,
                map_group_id: l.map_group_id,
                hierarchy: l.hierarchy,
                level_id: l.level_id,
                depth: l.depth,
                name: &l.name,
                needs_naming: l.needs_naming,
                breadcrumbs: &l.breadcrumbs,
                switch: &l.switch,
            },
        }
    }

    /// Every rule of schema v1 that the types do not already enforce, plus
    /// the cross-references a JSON Schema cannot express.
    pub fn validate(&self) -> Result<(), Violations> {
        let mut v = Vec::new();
        validate_envelope(&self.envelope(), &mut v);
        match self {
            LevelDocument::Group(g) => validate_group(g, &mut v),
            LevelDocument::Leaf(l) => validate_leaf(l, &mut v),
        }
        if v.is_empty() {
            Ok(())
        } else {
            Err(Violations(v))
        }
    }
}

fn check_name(path: &str, name: &Option<String>, v: &mut Vec<String>) {
    if let Some(n) = name {
        let chars = n.chars().count();
        if chars == 0 || chars > MAX_NAME_CHARS {
            v.push(format!(
                "{path}: name has {chars} chars, not 1..={MAX_NAME_CHARS}"
            ));
        }
    }
}

fn check_unit(path: &str, x: f64, v: &mut Vec<String>) {
    if !(0.0..=1.0).contains(&x) {
        v.push(format!("{path}: {x} is outside [0, 1]"));
    }
}

fn check_coord(path: &str, x: f64, v: &mut Vec<String>) {
    if !(-1.0..=1.0).contains(&x) {
        v.push(format!("{path}: {x} is outside [-1, 1]"));
    }
}

fn check_sign(path: &str, s: i8, v: &mut Vec<String>) {
    if !(-1..=1).contains(&s) {
        v.push(format!("{path}: sign {s} is not -1, 0 or 1"));
    }
}

fn check_depth(path: &str, d: u8, v: &mut Vec<String>) {
    if d > MAX_DEPTH {
        v.push(format!("{path}: depth {d} exceeds {MAX_DEPTH}"));
    }
}

fn check_count(path: &str, c: u32, v: &mut Vec<String>) {
    if c == 0 {
        v.push(format!("{path}: count is 0"));
    }
}

fn check_max(path: &str, len: usize, max: usize, v: &mut Vec<String>) {
    if len > max {
        v.push(format!("{path}: {len} items exceed {max}"));
    }
}

fn check_target(path: &str, t: &LinkTarget, v: &mut Vec<String>) {
    check_name(&format!("{path}/name"), &t.name, v);
    check_depth(&format!("{path}/depth"), t.depth, v);
}

fn validate_envelope(e: &Envelope<'_>, v: &mut Vec<String>) {
    if e.schema_version != SCHEMA_VERSION {
        v.push(format!(
            "/schema_version: {} is not {SCHEMA_VERSION}",
            e.schema_version
        ));
    }
    match (e.map_scope, e.map_group_id) {
        (MapScope::Team, None) => v.push("/map_group_id: a team map needs its group id".into()),
        (MapScope::Public, Some(_)) => {
            v.push("/map_group_id: the public map carries no group id".into())
        }
        _ => {}
    }
    check_depth("/depth", e.depth, v);
    check_name("/name", e.name, v);
    if e.name.is_none() && !e.needs_naming {
        v.push("/needs_naming: an unnamed level must be flagged for naming".into());
    }
    check_max("/breadcrumbs", e.breadcrumbs.len(), MAX_DEPTH as usize, v);
    if e.breadcrumbs.len() != e.depth as usize {
        v.push(format!(
            "/breadcrumbs: {} ancestors for depth {}",
            e.breadcrumbs.len(),
            e.depth
        ));
    }
    for (i, b) in e.breadcrumbs.iter().enumerate() {
        check_name(&format!("/breadcrumbs/{i}/name"), &b.name, v);
        check_depth(&format!("/breadcrumbs/{i}/depth"), b.depth, v);
        if b.depth as usize != i {
            v.push(format!("/breadcrumbs/{i}/depth: {} out of order", b.depth));
        }
        if b.level_id == e.level_id {
            v.push(format!("/breadcrumbs/{i}: the level is its own ancestor"));
        }
    }
    if e.switch.hierarchy != e.hierarchy.other() {
        v.push("/switch/hierarchy: the switch must lead to the other hierarchy".into());
    }
}

fn validate_group(g: &GroupLevel, v: &mut Vec<String>) {
    if g.children.is_empty() {
        v.push("/children: a group level has at least one child".into());
    }
    check_max("/children", g.children.len(), MAX_GROUP_CHILDREN, v);
    check_max("/bundles", g.bundles.len(), MAX_GROUP_BUNDLES, v);
    check_max("/targets", g.targets.len(), MAX_GROUP_TARGETS, v);

    let mut children = BTreeSet::new();
    for (i, c) in g.children.iter().enumerate() {
        let p = format!("/children/{i}");
        if !children.insert(c.id) {
            v.push(format!("{p}/id: duplicate child"));
        }
        if c.id == g.level_id {
            v.push(format!("{p}/id: the level is its own child"));
        }
        check_name(&format!("{p}/name"), &c.name, v);
        if c.name.is_none() && !c.needs_naming {
            v.push(format!(
                "{p}/needs_naming: an unnamed child must be flagged"
            ));
        }
        check_coord(&format!("{p}/x"), c.x, v);
        check_coord(&format!("{p}/y"), c.y, v);
        if !(c.r > 0.0 && c.r <= 1.0) {
            v.push(format!("{p}/r: {} is outside (0, 1]", c.r));
        }
    }

    let mut targets = BTreeSet::new();
    for (i, t) in g.targets.iter().enumerate() {
        let p = format!("/targets/{i}");
        check_target(&p, t, v);
        if !targets.insert(t.level_id) {
            v.push(format!("{p}/level_id: duplicate target"));
        }
        if children.contains(&t.level_id) || t.level_id == g.level_id {
            v.push(format!(
                "{p}/level_id: a target is a group outside this level"
            ));
        }
    }

    let mut used = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for (i, b) in g.bundles.iter().enumerate() {
        let p = format!("/bundles/{i}");
        if !children.contains(&b.source) {
            v.push(format!("{p}/source: not a child of this level"));
        }
        if !children.contains(&b.target) && !targets.contains(&b.target) {
            v.push(format!("{p}/target: neither a child nor a listed target"));
        }
        if b.source == b.target {
            v.push(format!("{p}: a bundle from a child to itself"));
        }
        if !pairs.insert((b.source, b.target)) {
            v.push(format!("{p}: duplicate (source, target) bundle"));
        }
        check_count(&format!("{p}/count"), b.count, v);
        check_sign(&format!("{p}/net_sign"), b.net_sign, v);
        used.insert(b.target);
    }
    // A listed target no bundle leads to would carry a name for nothing.
    for (i, t) in g.targets.iter().enumerate() {
        if !used.contains(&t.level_id) {
            v.push(format!("/targets/{i}: no bundle leads to it"));
        }
    }
}

fn validate_leaf(l: &LeafLevel, v: &mut Vec<String>) {
    if l.nodes.is_empty() {
        v.push("/nodes: a leaf has at least one node".into());
    }
    check_max("/nodes", l.nodes.len(), MAX_LEAF_NODES, v);
    check_max("/edges", l.edges.len(), MAX_LEAF_EDGES, v);
    check_max("/outgoing", l.outgoing.len(), MAX_LEAF_OUTGOING, v);

    let mut kinds: BTreeMap<Uuid, &'static str> = BTreeMap::new();
    for (i, n) in l.nodes.iter().enumerate() {
        let p = format!("/nodes/{i}");
        if kinds.insert(n.id(), n.kind_str()).is_some() {
            v.push(format!("{p}/id: duplicate node"));
        }
        let (label, x, y) = n.label_xy();
        let chars = label.chars().count();
        if chars == 0 || chars > MAX_LABEL_CHARS {
            v.push(format!(
                "{p}/label: {chars} chars, not 1..={MAX_LABEL_CHARS}"
            ));
        }
        check_coord(&format!("{p}/x"), x, v);
        check_coord(&format!("{p}/y"), y, v);
        if let Node::Claim(c) = n {
            if let Some(t) = c.truth_value {
                check_unit(&format!("{p}/truth_value"), t, v);
            }
            if let Some(b) = c.betp {
                check_unit(&format!("{p}/betp"), b, v);
            }
        }
    }

    let mut triples = BTreeSet::new();
    for (i, e) in l.edges.iter().enumerate() {
        let p = format!("/edges/{i}");
        let src = kinds.get(&e.source).copied();
        let dst = kinds.get(&e.target).copied();
        if src.is_none() {
            v.push(format!("{p}/source: not a node of this leaf"));
        }
        if dst.is_none() {
            v.push(format!("{p}/target: not a node of this leaf"));
        }
        if e.source == e.target {
            v.push(format!("{p}: a self-loop"));
        }
        let rel_ok = !e.relationship.is_empty()
            && e.relationship.len() <= MAX_RELATIONSHIP_CHARS
            && e.relationship.starts_with(|c: char| c.is_ascii_lowercase())
            && e.relationship
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_');
        if !rel_ok {
            v.push(format!(
                "{p}/relationship: not a snake_case name of 1..={MAX_RELATIONSHIP_CHARS}"
            ));
        }
        if !triples.insert((e.source, e.target, e.relationship.clone())) {
            v.push(format!(
                "{p}: duplicate (source, target, relationship) edge"
            ));
        }
        check_sign(&format!("{p}/sign"), e.sign, v);
        check_unit(&format!("{p}/flow_weight"), e.flow_weight, v);
        match e.flow_basis {
            FlowBasis::Exact => {
                if src.is_some_and(|k| k != "evidence") || dst.is_some_and(|k| k != "claim") {
                    v.push(format!(
                        "{p}/flow_basis: exact flow runs from evidence to a claim"
                    ));
                }
            }
            FlowBasis::Proxy => {
                if src.is_some_and(|k| k != "claim") || dst.is_some_and(|k| k != "claim") {
                    v.push(format!(
                        "{p}/flow_basis: proxy flow runs from a claim to a claim"
                    ));
                }
            }
            FlowBasis::None => {
                if e.flow_weight != 0.0 || e.sign != 0 {
                    v.push(format!("{p}: an edge with no flow has weight 0 and sign 0"));
                }
            }
        }
    }

    let mut targets = BTreeSet::new();
    for (i, o) in l.outgoing.iter().enumerate() {
        let p = format!("/outgoing/{i}");
        check_target(&format!("{p}/target"), &o.target, v);
        if !targets.insert(o.target.level_id) {
            v.push(format!("{p}/target: duplicate target group"));
        }
        if o.target.level_id == l.level_id {
            v.push(format!(
                "{p}/target: a link leaving the leaf cannot lead back to it"
            ));
        }
        check_count(&format!("{p}/count"), o.count, v);
        check_sign(&format!("{p}/net_sign"), o.net_sign, v);
        if o.sources.is_empty() {
            v.push(format!("{p}/sources: empty"));
        }
        check_max(&format!("{p}/sources"), o.sources.len(), MAX_LEAF_NODES, v);
        let mut seen = BTreeSet::new();
        for (j, s) in o.sources.iter().enumerate() {
            if !seen.insert(*s) {
                v.push(format!("{p}/sources/{j}: duplicate"));
            }
            if !kinds.contains_key(s) {
                v.push(format!("{p}/sources/{j}: not a node of this leaf"));
            }
        }
        if (o.count as usize) < o.sources.len() {
            v.push(format!("{p}/count: fewer links than source nodes"));
        }
    }
}
