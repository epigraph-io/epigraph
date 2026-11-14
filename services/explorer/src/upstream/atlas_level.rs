//! Upstream DTOs for the Atlas nested levels (schema v1, backlog W10a).
//! OWNED BY THE ATLAS AREA.
//!
//! One level below a theme is one JSON document: a group level (named
//! children with positions, and the cross-group link bundles aggregated to
//! that level) or a leaf (at most 100 claims, agents and evidence with
//! positions, belief-flow edges and outgoing links). The contract is the
//! JSON Schema at `contract/atlas_level/v1/schema.json` in this crate; the
//! kernel's `epigraph-atlas-contract` crate holds the producer-side types
//! and writes the fixtures next to the schema.
//!
//! What the BFF gets from the kernel route is already filtered for the
//! viewer: the kernel drops every leaf node the viewer's session cannot
//! read, with its edges and outgoing sources (`LevelDocument::for_viewer`
//! in the kernel crate), and answers not-found when no claim is left. The
//! BFF serves that answer as it comes.
//!
//! These types mirror that crate field for field. The Explorer cannot
//! depend on a kernel crate (its own workspace, lockfile and Docker
//! context), so the mirror is tied to the contract by a test instead:
//! `tests/atlas_contract.rs` decodes every fixture and re-encodes it, and
//! any field the mirror misses or renames breaks the round trip.
//!
//! Discipline (as `upstream/types.rs`): unknown fields are ignored and every
//! field is `pub`. A field the contract requires is required here too; a
//! nullable one is `Option`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The `schema_version` of every v1 document.
pub const ATLAS_LEVEL_SCHEMA_VERSION: u32 = 1;
/// Each level's compact JSON, gzip-compressed, is at most this many bytes.
pub const ATLAS_LEVEL_BUDGET_GZIP_BYTES: usize = 150_000;
/// Nodes in a leaf: claims, agents and evidence counted together.
pub const ATLAS_LEAF_MAX_NODES: usize = 100;

/// `team` (a team's map, served to its members) or `public`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MapScope {
    Team,
    Public,
}

/// `meaning` (embedding groups) or `links` (graph communities).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Hierarchy {
    Meaning,
    Links,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildKind {
    Group,
    Leaf,
}

/// `exact` (evidence to claim with a mass the map's audience can read, the
/// stored mass), `proxy` (claim to claim, the link's strength times its sign
/// and nothing else, with no belief factor of any kind, so it can never be
/// divided back into a belief: shown as an estimate; `cites` has sign 0 and
/// so weight 0) or `none` (no belief flow, weight 0 and sign 0 whatever the
/// relationship; this includes evidence to claim with no readable mass, the
/// common case, or with a relationship other than `supports` or `refutes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowBasis {
    Exact,
    Proxy,
    None,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Breadcrumb {
    pub level_id: Uuid,
    pub name: Option<String>,
    pub depth: u8,
}

/// The meaning/links switch: the counterpart level in the other hierarchy.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Switch {
    pub hierarchy: Hierarchy,
    pub level_id: Uuid,
}

/// A group a link leads to.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LinkTarget {
    pub level_id: Uuid,
    pub theme_id: Uuid,
    pub name: Option<String>,
    pub depth: u8,
}

/// A child of a group level, in the parent's unit circle.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Child {
    pub id: Uuid,
    pub kind: ChildKind,
    pub name: Option<String>,
    pub needs_naming: bool,
    pub claim_count: u32,
    pub x: f64,
    pub y: f64,
    pub r: f64,
}

/// All links from one child to one target (a sibling or a listed target).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Bundle {
    pub source: Uuid,
    pub target: Uuid,
    pub count: u32,
    pub net_sign: i8,
}

/// A claim of a leaf. Like the region and theme routes, it carries no
/// belief value: no BetP until the evidence behind each claim is filed as
/// stored edges (a later schema version).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClaimNode {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
    /// The colour value, as at the region and theme levels.
    pub truth_value: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PlainNode {
    pub id: Uuid,
    pub label: String,
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
}

/// A link between two nodes of a leaf, pointing the way belief flows. The
/// endpoint kinds limit `flow_basis`: claim to claim is `proxy`, evidence to
/// claim is `exact` or `none` (no readable mass, or a relationship with no
/// belief direction; the evidence still counts as attached to the claim),
/// every other pair is `none`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Edge {
    pub source: Uuid,
    pub target: Uuid,
    /// Lower-cased by the builder (the `edges` table spells names in both
    /// casings); the contract still admits upper case, so compare it
    /// case-insensitively.
    pub relationship: String,
    /// 1 supporting, -1 opposing, 0 none. A `none` edge has sign 0 whatever
    /// its relationship, so a `refutes` evidence edge with no readable mass
    /// is served with sign 0: take that evidence's direction from
    /// `relationship`, not from `sign`.
    pub sign: i8,
    pub flow_weight: f64,
    pub flow_basis: FlowBasis,
}

/// All links leaving a leaf for one target group.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Outgoing {
    pub target: LinkTarget,
    pub count: u32,
    pub net_sign: i8,
    pub sources: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GroupLevel {
    pub schema_version: u32,
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    pub run_id: Uuid,
    pub level_id: Uuid,
    pub depth: u8,
    pub name: Option<String>,
    pub needs_naming: bool,
    pub breadcrumbs: Vec<Breadcrumb>,
    pub switch: Switch,
    pub children: Vec<Child>,
    pub bundles: Vec<Bundle>,
    pub targets: Vec<LinkTarget>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LeafLevel {
    pub schema_version: u32,
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub theme_id: Uuid,
    pub run_id: Uuid,
    pub level_id: Uuid,
    pub depth: u8,
    pub name: Option<String>,
    pub needs_naming: bool,
    pub breadcrumbs: Vec<Breadcrumb>,
    pub switch: Switch,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub outgoing: Vec<Outgoing>,
}

/// One Atlas level document, tagged by `kind`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AtlasLevel {
    Group(GroupLevel),
    Leaf(LeafLevel),
}
