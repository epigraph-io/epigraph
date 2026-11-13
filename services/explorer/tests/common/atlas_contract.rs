//! The Atlas nested-level contract (schema v1) as a test helper.
//!
//! W10's BFF route tests call [`check_level_body`] on every level body a
//! route serves, with the map and level the request was for, and
//! [`check_not_found`] plus [`assert_indistinguishable`] on the answer a
//! non-member gets. The schema and fixtures live in this crate at
//! `contract/atlas_level/v1/`; the kernel's `epigraph-atlas-contract` crate
//! writes the fixtures and runs the same schema. [`invariant_errors`] is a
//! port of that crate's `LevelDocument::validate` (the rules a JSON Schema
//! cannot express), so both sides refuse the same documents.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::sync::OnceLock;

use epigraph_explorer::upstream::atlas_level::{
    AtlasLevel, Breadcrumb, FlowBasis, GroupLevel, Hierarchy, LeafLevel, MapScope, Node, Switch,
    ATLAS_LEVEL_BUDGET_GZIP_BYTES,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use uuid::Uuid;

/// `contract/atlas_level/v1` of this crate.
pub const CONTRACT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/contract/atlas_level/v1");

/// The level fixtures, by file stem.
pub const LEVEL_FIXTURES: &[&str] = &[
    "team_theme_root",
    "team_group_deep",
    "team_leaf_dense",
    "public_leaf",
];

/// The synthetic team group of every team fixture: the kernel generator's
/// `FIXTURE_TEAM_GROUP_ID`.
pub const FIXTURE_TEAM_GROUP_ID: Uuid = Uuid::from_u128(0x5e5e_0000_0000_4000_8000_0000_0000_7ea0);

pub fn schema() -> &'static Value {
    static S: OnceLock<Value> = OnceLock::new();
    S.get_or_init(|| {
        let raw = std::fs::read(format!("{CONTRACT_DIR}/schema.json")).expect("read schema.json");
        serde_json::from_slice(&raw).expect("schema.json is JSON")
    })
}

/// A fixture's bytes, as committed.
pub fn fixture(stem: &str) -> Vec<u8> {
    let p = format!("{CONTRACT_DIR}/fixtures/{stem}.json");
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

pub fn fixture_value(stem: &str) -> Value {
    serde_json::from_slice(&fixture(stem)).expect("fixture is JSON")
}

/// What the request was for, as the test knows it: never read back from the
/// body under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub level_id: Uuid,
}

impl Expected {
    pub fn public(level_id: Uuid) -> Self {
        Expected {
            map_scope: MapScope::Public,
            map_group_id: None,
            level_id,
        }
    }

    pub fn team(group_id: Uuid, level_id: Uuid) -> Self {
        Expected {
            map_scope: MapScope::Team,
            map_group_id: Some(group_id),
            level_id,
        }
    }
}

fn validator(def: Option<&str>) -> jsonschema::Validator {
    let s = schema();
    let doc = match def {
        None => s.clone(),
        Some(name) => json!({
            "$schema": s["$schema"],
            "$id": format!("urn:epigraph:atlas-level:v1:{name}"),
            "$defs": s["$defs"],
            "$ref": format!("#/$defs/{name}"),
        }),
    };
    jsonschema::validator_for(&doc).expect("schema.json compiles")
}

/// Schema errors against one of the schema's `$defs`, such as
/// `claim_node`: the root's `oneOf` reports a bad node only as "no branch
/// matched", while its own def names the key that is wrong.
pub fn def_errors(def: &str, doc: &Value) -> Vec<String> {
    validator(Some(def))
        .iter_errors(doc)
        .map(|e| format!("schema #/$defs/{def}{}: {e}", e.instance_path()))
        .collect()
}

/// Keys that carry a belief value. No Atlas body carries one: the region
/// and theme routes (colour comes from `truth_value` alone) and the nested
/// levels alike, whose claim nodes carry no BetP until the evidence behind
/// them is filed as stored edges.
pub const BELIEF_KEYS: &[&str] = &[
    "belief",
    "plausibility",
    "pignistic_prob",
    "epistemic",
    "mean_betp",
    "betp",
];

/// Schema errors for a level document; empty when it validates.
pub fn schema_errors(doc: &Value) -> Vec<String> {
    static ROOT: OnceLock<jsonschema::Validator> = OnceLock::new();
    ROOT.get_or_init(|| validator(None))
        .iter_errors(doc)
        .map(|e| format!("schema {}: {e}", e.instance_path()))
        .collect()
}

pub fn gzip_len(bytes: &[u8]) -> usize {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("gzip into a Vec");
    enc.finish().expect("gzip into a Vec").len()
}

/// JSON equality with numbers compared by value, so `0` and `0.0` are the
/// same: a producer that is not serde (a Python builder) may write either.
pub fn same_json(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same_json(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_json(v, w)))
        }
        _ => a == b,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Claim,
    Agent,
    Evidence,
}

fn kind(n: &Node) -> Kind {
    match n {
        Node::Claim(_) => Kind::Claim,
        Node::Agent(_) => Kind::Agent,
        Node::Evidence(_) => Kind::Evidence,
    }
}

fn basis_for(s: Kind, t: Kind) -> FlowBasis {
    match (s, t) {
        (Kind::Evidence, Kind::Claim) => FlowBasis::Exact,
        (Kind::Claim, Kind::Claim) => FlowBasis::Proxy,
        _ => FlowBasis::None,
    }
}

fn other(h: Hierarchy) -> Hierarchy {
    match h {
        Hierarchy::Meaning => Hierarchy::Links,
        Hierarchy::Links => Hierarchy::Meaning,
    }
}

fn envelope_errors(
    level_id: Uuid,
    depth: u8,
    hierarchy: Hierarchy,
    breadcrumbs: &[Breadcrumb],
    switch: &Switch,
    e: &mut Vec<String>,
) {
    if breadcrumbs.len() != depth as usize {
        e.push(format!(
            "invariant /breadcrumbs: {} ancestors for depth {depth}",
            breadcrumbs.len()
        ));
    }
    for (i, b) in breadcrumbs.iter().enumerate() {
        if b.depth as usize != i {
            e.push(format!(
                "invariant /breadcrumbs/{i}/depth: {} out of order",
                b.depth
            ));
        }
        if b.level_id == level_id {
            e.push(format!(
                "invariant /breadcrumbs/{i}: the level is its own ancestor"
            ));
        }
    }
    if switch.hierarchy != other(hierarchy) {
        e.push("invariant /switch/hierarchy: not the other hierarchy".into());
    }
}

fn group_errors(g: &GroupLevel, e: &mut Vec<String>) {
    let mut children = BTreeSet::new();
    for (i, c) in g.children.iter().enumerate() {
        if !children.insert(c.id) {
            e.push(format!("invariant /children/{i}/id: duplicate child"));
        }
        if c.id == g.level_id {
            e.push(format!(
                "invariant /children/{i}/id: the level is its own child"
            ));
        }
    }
    let mut targets = BTreeSet::new();
    for (i, t) in g.targets.iter().enumerate() {
        if !targets.insert(t.level_id) {
            e.push(format!("invariant /targets/{i}/level_id: duplicate target"));
        }
        if children.contains(&t.level_id) || t.level_id == g.level_id {
            e.push(format!(
                "invariant /targets/{i}/level_id: a target is a group outside this level"
            ));
        }
    }
    let mut used = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for (i, b) in g.bundles.iter().enumerate() {
        if !children.contains(&b.source) {
            e.push(format!("invariant /bundles/{i}/source: not a child"));
        }
        if !children.contains(&b.target) && !targets.contains(&b.target) {
            e.push(format!(
                "invariant /bundles/{i}/target: neither a child nor a listed target"
            ));
        }
        if b.source == b.target {
            e.push(format!(
                "invariant /bundles/{i}: a bundle from a child to itself"
            ));
        }
        if !pairs.insert((b.source, b.target)) {
            e.push(format!(
                "invariant /bundles/{i}: duplicate (source, target)"
            ));
        }
        used.insert(b.target);
    }
    for (i, t) in g.targets.iter().enumerate() {
        if !used.contains(&t.level_id) {
            e.push(format!("invariant /targets/{i}: no bundle leads to it"));
        }
    }
}

fn leaf_errors(l: &LeafLevel, e: &mut Vec<String>) {
    let mut kinds: BTreeMap<Uuid, Kind> = BTreeMap::new();
    for (i, n) in l.nodes.iter().enumerate() {
        if kinds.insert(n.id(), kind(n)).is_some() {
            e.push(format!("invariant /nodes/{i}/id: duplicate node"));
        }
    }
    let mut triples = BTreeSet::new();
    let mut anchored = BTreeSet::new();
    for (i, x) in l.edges.iter().enumerate() {
        let (s, t) = (kinds.get(&x.source), kinds.get(&x.target));
        if s.is_none() {
            e.push(format!("invariant /edges/{i}/source: not a node"));
        }
        if t.is_none() {
            e.push(format!("invariant /edges/{i}/target: not a node"));
        }
        if x.source == x.target {
            e.push(format!("invariant /edges/{i}: a self-loop"));
        }
        if !triples.insert((x.source, x.target, x.relationship.clone())) {
            e.push(format!(
                "invariant /edges/{i}: duplicate (source, target, relationship)"
            ));
        }
        if let (Some(&s), Some(&t)) = (s, t) {
            let want = basis_for(s, t);
            if x.flow_basis != want {
                e.push(format!(
                    "invariant /edges/{i}/flow_basis: {s:?} to {t:?} is {want:?}, not {:?}",
                    x.flow_basis
                ));
            }
            if s == Kind::Claim || t == Kind::Claim {
                anchored.insert(x.source);
                anchored.insert(x.target);
            }
        }
    }
    for (i, n) in l.nodes.iter().enumerate() {
        if kind(n) != Kind::Claim && !anchored.contains(&n.id()) {
            e.push(format!(
                "invariant /nodes/{i}: an agent or evidence node with no edge to a claim"
            ));
        }
    }
    let mut targets = BTreeSet::new();
    for (i, o) in l.outgoing.iter().enumerate() {
        if !targets.insert(o.target.level_id) {
            e.push(format!(
                "invariant /outgoing/{i}/target: duplicate target group"
            ));
        }
        if o.target.level_id == l.level_id {
            e.push(format!(
                "invariant /outgoing/{i}/target: leads back to the leaf"
            ));
        }
        for (j, s) in o.sources.iter().enumerate() {
            if !kinds.contains_key(s) {
                e.push(format!("invariant /outgoing/{i}/sources/{j}: not a node"));
            }
        }
        if (o.count as usize) < o.sources.len() {
            e.push(format!(
                "invariant /outgoing/{i}/count: fewer links than source nodes"
            ));
        }
    }
}

/// The rules a JSON Schema cannot express: references, uniqueness, the
/// flow basis each edge's endpoint kinds fix, and the breadcrumb order.
pub fn invariant_errors(doc: &AtlasLevel) -> Vec<String> {
    let mut e = Vec::new();
    match doc {
        AtlasLevel::Group(g) => {
            envelope_errors(
                g.level_id,
                g.depth,
                g.hierarchy,
                &g.breadcrumbs,
                &g.switch,
                &mut e,
            );
            group_errors(g, &mut e);
        }
        AtlasLevel::Leaf(l) => {
            envelope_errors(
                l.level_id,
                l.depth,
                l.hierarchy,
                &l.breadcrumbs,
                &l.switch,
                &mut e,
            );
            leaf_errors(l, &mut e);
        }
    }
    e
}

fn viewer_errors(doc: &AtlasLevel, expected: &Expected) -> Vec<String> {
    let (scope, group, level) = match doc {
        AtlasLevel::Group(g) => (g.map_scope, g.map_group_id, g.level_id),
        AtlasLevel::Leaf(l) => (l.map_scope, l.map_group_id, l.level_id),
    };
    let mut errors = Vec::new();
    if (scope, group) != (expected.map_scope, expected.map_group_id) {
        errors.push(format!(
            "viewer: the body is the {scope:?} map {group:?}, the request was for the {:?} map {:?}",
            expected.map_scope, expected.map_group_id
        ));
    }
    if level != expected.level_id {
        errors.push(format!(
            "viewer: the body is level {level}, the request was for {}",
            expected.level_id
        ));
    }
    errors
}

/// Check one level body as the BFF serves it: JSON, the schema, the mirror
/// types (decode, then re-encode to the same value, numbers by value), the
/// invariants, that it is the map and level `expected` names, and the
/// budget on the bytes as served. Returns the decoded level, or every
/// failure found.
pub fn check_level_body(body: &[u8], expected: &Expected) -> Result<AtlasLevel, Vec<String>> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("not JSON: {e}")]),
    };
    let mut errors = schema_errors(&value);
    let decoded = match serde_json::from_value::<AtlasLevel>(value.clone()) {
        Ok(doc) => {
            let again = serde_json::to_value(&doc).expect("a level serialises");
            if !same_json(&again, &value) {
                errors.push("mirror: re-encoding the decoded level changes it".into());
            }
            errors.extend(invariant_errors(&doc));
            errors.extend(viewer_errors(&doc, expected));
            Some(doc)
        }
        Err(e) => {
            errors.push(format!("mirror: {e}"));
            None
        }
    };
    let served = gzip_len(body);
    if served > ATLAS_LEVEL_BUDGET_GZIP_BYTES {
        errors.push(format!(
            "budget: {served} gzip bytes as served exceed {ATLAS_LEVEL_BUDGET_GZIP_BYTES}"
        ));
    }
    match decoded {
        Some(doc) if errors.is_empty() => Ok(doc),
        _ => Err(errors),
    }
}

/// Which side answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Kernel,
    Bff,
}

/// Check the answer for a level the viewer may not see: a 404 whose body is
/// exactly the closed not-found shape, with no level key, count or name. On
/// the kernel side it names only the requested id, in `message` and
/// `details.id`.
pub fn check_not_found(
    side: Side,
    status: u16,
    body: &[u8],
    requested_id: &str,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if status != 404 {
        errors.push(format!("status {status}, not 404"));
    }
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("not JSON: {e}"));
            return Err(errors);
        }
    };
    let def = match side {
        Side::Kernel => "kernel_not_found",
        Side::Bff => "bff_not_found",
    };
    errors.extend(
        validator(Some(def))
            .iter_errors(&value)
            .map(|e| format!("schema #/$defs/{def}{}: {e}", e.instance_path())),
    );
    if side == Side::Kernel {
        if value["details"]["id"] != json!(requested_id) {
            errors.push(format!(
                "details.id {} is not the requested id {requested_id}",
                value["details"]["id"]
            ));
        }
        let message = format!("atlas_level with ID {requested_id} not found");
        if value["message"] != json!(message) {
            errors.push(format!("message {} is not `{message}`", value["message"]));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// A non-member's answer and the answer for an absent level must be the
/// same status and the same bytes.
pub fn assert_indistinguishable(non_member: (u16, &[u8]), absent: (u16, &[u8])) {
    assert_eq!(
        non_member.0, absent.0,
        "a non-member gets a different status than an absent level"
    );
    assert_eq!(
        String::from_utf8_lossy(non_member.1),
        String::from_utf8_lossy(absent.1),
        "a non-member gets a different body than an absent level"
    );
}
