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
//! The layout builder writes the document and the layout store keeps it as
//! one `jsonb` row next to a `schema_version` column.
//!
//! **What is served is the stored document filtered for the viewer**
//! (design §5: "the serving path still filters by the viewer (RLS), so a
//! member never sees a row their own session cannot read"). The kernel
//! route reads the stored document, then calls
//! [`LevelDocument::for_viewer`] with what the viewer's own session can
//! read. That drops every node the viewer cannot read, with its edges and
//! its `outgoing` sources. A `None` result is answered with the same
//! not-found body as an absent level. The Explorer BFF serves the kernel's
//! answer as it comes. Group levels carry no claim rows and are served as
//! stored. A claim that leaves the team only changes their counts and names
//! after the next rebuild, which the per-team epoch of design §5 triggers.
//!
//! **The document holds claim text** (`label`) and LLM names, so it is
//! assembled on the prod box. Off-box stages (design §2) produce only ids,
//! positions and weights.
//!
//! The language-neutral contract is the JSON Schema at
//! `services/explorer/contract/atlas_level/v1/schema.json`. It sits under
//! `services/explorer` because the Explorer is a standalone crate that
//! cannot read outside its own directory, while the kernel can. The
//! fixtures next to it are written by [`fixtures`].
//!
//! These types are the kernel's side of that contract. Deserialising is
//! strict: an unknown key anywhere is an error, and so is a missing key,
//! nullable ones included. [`LevelDocument::validate`] checks everything the
//! schema checks. It also checks what a JSON Schema cannot express:
//! references between parts of the document, and which flow basis each
//! edge has. The crate's tests prove that the strict types with `validate`
//! agree with the schema. They also show that the largest document the caps
//! allow fits [`BUDGET_GZIP_BYTES`] when its text is no less compressible
//! than random Latin, Greek, Cyrillic and CJK text. Text that compresses
//! worse (characters from the astral planes, for example) can exceed it.
//! So the caps do not guarantee the budget: [`LevelDocument::validate`]
//! does not measure size, and a producer stores what
//! [`LevelDocument::to_stored_json`] returns, which does measure it.
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
#[cfg(any(test, feature = "check"))]
pub mod preview;
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

/// The value of every v1 claim-to-leaf answer's `schema_version`.
pub const CLAIM_LEAF_SCHEMA_VERSION: u32 = 1;

/// The claim-to-leaf lookup's answer, schema v1
/// (`services/explorer/contract/atlas_claim_leaf/v1/schema.json`): which leaf
/// of one map and hierarchy holds a claim the viewer can read, in the run the
/// level route serves. Enough for a client to fetch the leaf and its
/// breadcrumb chain. It carries no count, flag or name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLeaf {
    pub schema_version: u32,
    pub claim_id: Uuid,
    pub map_scope: MapScope,
    /// The team group of a team map; `None` for the public map.
    #[serde(deserialize_with = "Option::deserialize")]
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    /// The leaf level: `<level_url><hierarchy>/<level_id>`.
    pub level_id: Uuid,
}

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

/// Where an edge's `flow_weight` comes from. The endpoint kinds limit it:
/// claim to claim is always `proxy`, evidence to claim is `exact` or `none`,
/// and every other pair is `none` ([`FlowBasis::allows`]). So a producer
/// cannot leave out a claim-to-claim flow by marking the edge `none`.
///
/// An evidence-to-claim edge is `none` when it carries no mass the map's
/// audience can read: either that audience can read no mass row keyed by
/// that evidence on that claim (most stored evidence edges have none, so
/// this is the common case, not an error), or its relationship carries no
/// belief direction (anything but `supports` or `refutes`, compared
/// lower-cased). The contract cannot tell such an edge from one whose
/// builder dropped a readable mass; the builder (backlog W7) carries that
/// invariant and its known-mass test.
///
/// A `none` edge has sign 0 whatever its relationship, so a `refutes` edge
/// with no readable mass is served with sign 0, like a `supports` one. A
/// reader that wants the direction of such evidence takes it from
/// [`Edge::relationship`], not from [`Edge::sign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowBasis {
    /// Evidence to claim with a mass row the map's audience can read: the
    /// stored mass.
    Exact,
    /// Claim to claim, always: the link's strength times its sign, and
    /// nothing else, which the view labels an estimate. With the sign in
    /// its own field, `flow_weight` is strength × |sign|, so `sign ×
    /// flow_weight` is the signed flow. There is **no belief factor of any
    /// kind**: not the source or target claim's BetP, belief, plausibility
    /// or `truth_value`, so no served weight can be divided back into a
    /// belief. The builder (backlog W7) reads no belief to compute it: the
    /// strength comes from the link (its edge row) alone, never from a BBA
    /// or a belief fold. What keeps the weight to the map's audience is the
    /// edge-row filter on [`Edge`]: only rows that audience can read are
    /// drawn, before repeated rows are collapsed.
    ///
    /// A link with no belief direction (`cites`) is still `proxy`, with
    /// sign 0 and so weight 0; validation rejects a proxy edge with sign 0
    /// and any other weight.
    Proxy,
    /// No belief flow, so weight 0 and sign 0 whatever the relationship:
    /// every pair of kinds other than claim to claim and evidence to claim
    /// (an agent's authorship, for example), and an evidence-to-claim edge
    /// with no readable mass or with a relationship that carries no belief
    /// direction. Such an evidence node still counts as attached to the
    /// claim. A `refutes` evidence edge served `none` keeps its direction
    /// only in its relationship name.
    None,
}

impl FlowBasis {
    /// The basis an edge between these node kinds carries when belief flows
    /// along it: `exact` from evidence to a claim, `proxy` between claims,
    /// `none` otherwise. An evidence-to-claim edge with no readable mass is
    /// `none` instead; [`FlowBasis::allows`] is the rule a document must meet.
    pub fn for_kinds(source: NodeKind, target: NodeKind) -> Self {
        match (source, target) {
            (NodeKind::Evidence, NodeKind::Claim) => FlowBasis::Exact,
            (NodeKind::Claim, NodeKind::Claim) => FlowBasis::Proxy,
            _ => FlowBasis::None,
        }
    }

    /// Whether an edge between these node kinds may carry this basis: the
    /// one [`FlowBasis::for_kinds`] gives, or `none` from evidence to a claim.
    pub fn allows(self, source: NodeKind, target: NodeKind) -> bool {
        self == FlowBasis::for_kinds(source, target)
            || (self == FlowBasis::None
                && (source, target) == (NodeKind::Evidence, NodeKind::Claim))
    }
}

/// The three kinds of leaf node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeKind {
    Claim,
    Agent,
    Evidence,
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
///
/// It carries no belief value: no BetP, as on the region and theme routes.
/// A v1 leaf is drawn before the evidence behind each claim is filed as
/// stored evidence-to-claim edges, so a served BetP would rest on evidence
/// the leaf cannot show. Adding one is a later schema version. A document
/// carrying `betp` fails as an unknown key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimNode {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
    /// The colour value, as at the region and theme levels, and nothing
    /// more: the view never sorts, compares or folds it, and no flow weight
    /// is computed from it.
    #[serde(deserialize_with = "Option::deserialize")]
    pub truth_value: Option<f64>,
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

    pub fn kind(&self) -> NodeKind {
        match self {
            Node::Claim(_) => NodeKind::Claim,
            Node::Agent(_) => NodeKind::Agent,
            Node::Evidence(_) => NodeKind::Evidence,
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
///
/// **Only edge rows the map's whole audience can read** (backlog W8): an
/// edge row has its own visibility and owner and co-owner groups, apart from
/// its endpoints. The public map draws public rows only. A team map draws
/// public rows and the rows that team owns with no co-owner. A co-owned row
/// is readable only by members of both groups, so it is never drawn on a
/// single team's map (a joint view for such viewers is later work). Two
/// readable endpoints do not make a row readable, and a served edge carries no row id or visibility, so
/// [`LevelDocument::for_viewer`] cannot check this: the builder must.
///
/// The `edges` table keeps one row per submission (migration 018 dropped
/// its triple-uniqueness), so one (source, target, relationship) can have
/// several rows, and the table spells one relationship in both casings
/// (`SUPPORTS` and `supports`). After the audience filter above, the builder
/// collapses the rows that share a source, a target and a lower-cased
/// relationship into one edge with the largest `flow_weight` among them: a
/// resubmission is not more support. Filtering first matters: otherwise an
/// unreadable row's larger weight would win the collapse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub source: Uuid,
    pub target: Uuid,
    /// The relationship name, lower-cased by the builder: the `edges` table
    /// spells names in both casings (`AUTHORED` and `authored`), and the
    /// builder serves the lower-cased stored name. The name pattern still
    /// admits upper case (some fixtures keep it on purpose), so a reader
    /// compares names case-insensitively.
    pub relationship: String,
    /// The direction of the belief that flows along the edge: 1 supporting,
    /// -1 opposing, 0 none. An edge whose `flow_basis` is `none` carries no
    /// flow and so has sign 0 whatever its relationship: evidence that
    /// `refutes` a claim but has no readable mass is served with sign 0, and
    /// a reader takes its direction from `relationship`.
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

/// gzip size (flate2's default level) of `bytes`: the measure of
/// [`BUDGET_GZIP_BYTES`].
pub fn gzip_len(bytes: &[u8]) -> usize {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).expect("gzip into a Vec");
    enc.finish().expect("gzip into a Vec").len()
}

/// Whether `s` is a relationship name the contract accepts: an ASCII letter,
/// then letters, digits or `_`, at most [`MAX_RELATIONSHIP_CHARS`] long.
/// Either casing passes: builders serve names lower-cased, and the pattern
/// still admits the stored upper-case spellings (`AUTHORED`).
pub fn is_relationship_name(s: &str) -> bool {
    s.len() <= MAX_RELATIONSHIP_CHARS
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

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

    /// The compact JSON a producer stores: the document validated, then
    /// measured against [`BUDGET_GZIP_BYTES`]. The caps alone do not bound
    /// the compressed size (see the crate doc), so this measures it.
    pub fn to_stored_json(&self) -> Result<Vec<u8>, Violations> {
        self.validate()?;
        let body =
            serde_json::to_vec(self).map_err(|e| Violations(vec![format!("encode: {e}")]))?;
        let n = gzip_len(&body);
        if n > BUDGET_GZIP_BYTES {
            return Err(Violations(vec![format!(
                "budget: {n} gzip bytes exceed {BUDGET_GZIP_BYTES}"
            )]));
        }
        Ok(body)
    }

    /// The document as served to one viewer (design §5), given whether the
    /// viewer's own session can read each node (claims, agents and
    /// evidence alike; evidence has its own row security).
    ///
    /// A group level is returned as stored. From a leaf, in this order:
    /// 1. every node the viewer cannot read is dropped;
    /// 2. so is every edge with a dropped end;
    /// 3. so is every agent or evidence node left with no edge to a kept
    ///    claim, since an isolated one would show where a hidden claim was;
    /// 4. dropped nodes leave every `outgoing[].sources`, and an `outgoing`
    ///    entry left with no source is dropped.
    ///
    /// Edges are kept by their endpoints only. Whether each edge row is
    /// readable by the map's audience is settled when the builder draws the
    /// leaf (see [`Edge`]); a served edge carries nothing to check it by.
    ///
    /// Counts and signs pass through as stored: they are aggregates the
    /// team's map already shows, and `count >= sources.len()` still holds.
    /// So when a source is dropped, `count` and `net_sign` still include its
    /// links until the next rebuild. Recomputing them would need per-source
    /// counts, which v1 does not carry.
    /// `None` means no claim is left, and the route answers with the same
    /// not-found body as for an absent level. The result of a valid
    /// document is valid.
    pub fn for_viewer(&self, readable: impl Fn(Uuid) -> bool) -> Option<LevelDocument> {
        let leaf = match self {
            LevelDocument::Group(_) => return Some(self.clone()),
            LevelDocument::Leaf(l) => l,
        };
        let readable: BTreeSet<Uuid> = leaf
            .nodes
            .iter()
            .map(Node::id)
            .filter(|id| readable(*id))
            .collect();
        let claims: BTreeSet<Uuid> = leaf
            .nodes
            .iter()
            .filter(|n| n.kind() == NodeKind::Claim && readable.contains(&n.id()))
            .map(Node::id)
            .collect();
        if claims.is_empty() {
            return None;
        }
        let edges: Vec<&Edge> = leaf
            .edges
            .iter()
            .filter(|e| readable.contains(&e.source) && readable.contains(&e.target))
            .collect();
        let anchored: BTreeSet<Uuid> = edges
            .iter()
            .flat_map(|e| {
                let to_claim = claims.contains(&e.source) || claims.contains(&e.target);
                to_claim
                    .then_some([e.source, e.target])
                    .into_iter()
                    .flatten()
            })
            .collect();
        let kept: BTreeSet<Uuid> = readable
            .iter()
            .copied()
            .filter(|id| claims.contains(id) || anchored.contains(id))
            .collect();
        let mut out = leaf.clone();
        out.nodes.retain(|n| kept.contains(&n.id()));
        out.edges
            .retain(|e| kept.contains(&e.source) && kept.contains(&e.target));
        for o in &mut out.outgoing {
            o.sources.retain(|s| kept.contains(s));
        }
        out.outgoing.retain(|o| !o.sources.is_empty());
        Some(LevelDocument::Leaf(out))
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

    let mut kinds: BTreeMap<Uuid, NodeKind> = BTreeMap::new();
    for (i, n) in l.nodes.iter().enumerate() {
        let p = format!("/nodes/{i}");
        if kinds.insert(n.id(), n.kind()).is_some() {
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
        }
    }

    let mut triples = BTreeSet::new();
    let mut anchored = BTreeSet::new();
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
        if !is_relationship_name(&e.relationship) {
            v.push(format!(
                "{p}/relationship: not a name of 1..={MAX_RELATIONSHIP_CHARS} letters, digits or _"
            ));
        }
        if !triples.insert((e.source, e.target, e.relationship.clone())) {
            v.push(format!(
                "{p}: duplicate (source, target, relationship) edge"
            ));
        }
        check_sign(&format!("{p}/sign"), e.sign, v);
        check_unit(&format!("{p}/flow_weight"), e.flow_weight, v);
        if let (Some(s), Some(t)) = (src, dst) {
            if !e.flow_basis.allows(s, t) {
                let want = FlowBasis::for_kinds(s, t);
                let or_none = if want != FlowBasis::None && FlowBasis::None.allows(s, t) {
                    " or None"
                } else {
                    ""
                };
                v.push(format!(
                    "{p}/flow_basis: an edge from {s:?} to {t:?} has basis {want:?}{or_none}, not {:?}",
                    e.flow_basis
                ));
            }
            // Any edge to a claim attaches its other end, whatever its
            // basis: evidence with no readable mass (`none`) included.
            if s == NodeKind::Claim || t == NodeKind::Claim {
                anchored.insert(e.source);
                anchored.insert(e.target);
            }
        }
        if e.flow_basis == FlowBasis::None && (e.flow_weight != 0.0 || e.sign != 0) {
            v.push(format!("{p}: an edge with no flow has weight 0 and sign 0"));
        }
        // strength × |sign|: a claim-to-claim link with no direction weighs
        // 0, so it cannot carry a value such as its source's belief.
        if e.flow_basis == FlowBasis::Proxy && e.sign == 0 && e.flow_weight != 0.0 {
            v.push(format!("{p}: a proxy edge with sign 0 has weight 0"));
        }
    }
    // Agents and evidence are in a leaf because they assert, author or back
    // its claims (design §7 step 3). One with no edge to a claim would show
    // where a claim the viewer cannot read was.
    for (i, n) in l.nodes.iter().enumerate() {
        if n.kind() != NodeKind::Claim && !anchored.contains(&n.id()) {
            v.push(format!(
                "/nodes/{i}: an agent or evidence node with no edge to a claim"
            ));
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
