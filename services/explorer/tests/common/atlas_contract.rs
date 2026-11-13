//! The Atlas nested-level contract (schema v1) as a test helper.
//!
//! W10's BFF route tests call [`check_level_body`] on every level body a
//! route serves, and [`check_not_found`] plus [`assert_indistinguishable`]
//! on the answer a non-member gets. The schema and fixtures live in this
//! crate at `contract/atlas_level/v1/`; the kernel's
//! `epigraph-atlas-contract` crate writes the fixtures and runs the same
//! schema.

use std::collections::HashSet;
use std::io::Write as _;
use std::sync::OnceLock;

use epigraph_explorer::upstream::atlas_level::{AtlasLevel, ATLAS_LEVEL_BUDGET_GZIP_BYTES};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Value};

/// `contract/atlas_level/v1` of this crate.
pub const CONTRACT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/contract/atlas_level/v1");

/// The level fixtures, by file stem.
pub const LEVEL_FIXTURES: &[&str] = &[
    "team_theme_root",
    "team_group_deep",
    "team_leaf_dense",
    "public_leaf",
];

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

/// The cross-references a JSON Schema cannot express: ids are unique, and
/// every edge, bundle and outgoing source points at something the document
/// carries.
fn reference_errors(doc: &AtlasLevel) -> Vec<String> {
    let mut errors = Vec::new();
    match doc {
        AtlasLevel::Group(g) => {
            let mut children = HashSet::new();
            for c in &g.children {
                if !children.insert(c.id) {
                    errors.push(format!("refs: duplicate child {}", c.id));
                }
            }
            let targets: HashSet<_> = g.targets.iter().map(|t| t.level_id).collect();
            for b in &g.bundles {
                if !children.contains(&b.source) {
                    errors.push(format!("refs: bundle source {} is not a child", b.source));
                }
                if !children.contains(&b.target) && !targets.contains(&b.target) {
                    errors.push(format!("refs: bundle target {} is unknown", b.target));
                }
            }
        }
        AtlasLevel::Leaf(l) => {
            let mut nodes = HashSet::new();
            for n in &l.nodes {
                if !nodes.insert(n.id()) {
                    errors.push(format!("refs: duplicate node {}", n.id()));
                }
            }
            for e in &l.edges {
                for end in [e.source, e.target] {
                    if !nodes.contains(&end) {
                        errors.push(format!("refs: edge end {end} is not a node"));
                    }
                }
            }
            for o in &l.outgoing {
                for s in &o.sources {
                    if !nodes.contains(s) {
                        errors.push(format!("refs: outgoing source {s} is not a node"));
                    }
                }
            }
        }
    }
    errors
}

/// Check one level body as the BFF serves it: JSON, the schema, the mirror
/// types (decode, then re-encode to the same value), the references, and
/// the budget on the bytes as served. Returns the decoded level, or every
/// failure found.
pub fn check_level_body(body: &[u8]) -> Result<AtlasLevel, Vec<String>> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("not JSON: {e}")]),
    };
    let mut errors = schema_errors(&value);
    let decoded = match serde_json::from_value::<AtlasLevel>(value.clone()) {
        Ok(doc) => {
            let again = serde_json::to_value(&doc).expect("a level serialises");
            if again != value {
                errors.push("mirror: re-encoding the decoded level changes it".into());
            }
            errors.extend(reference_errors(&doc));
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
/// exactly the closed not-found shape, with no level key, count or name.
pub fn check_not_found(side: Side, status: u16, body: &[u8]) -> Result<(), Vec<String>> {
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
