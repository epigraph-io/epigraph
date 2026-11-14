//! The schema test helper for real responses (feature `check`).
//!
//! W10's route tests call [`check_level_body`] on every level body a route
//! serves, with the map and level the request was for, and
//! [`check_not_found`] plus [`assert_indistinguishable`] on the answer a
//! non-member gets. Each check runs the language-neutral JSON Schema, the
//! strict types with [`LevelDocument::validate`], and the gzip budget, and
//! reports every failure it finds.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde_json::{json, Value};
use uuid::Uuid;

pub use crate::gzip_len;
use crate::{LevelDocument, MapScope, BUDGET_GZIP_BYTES, SCHEMA_ID};

/// What the request was for, as the test knows it: never read back from the
/// body under test. A route that answers with another map's level (a team's
/// leaf to a public viewer, or another team's) or another level fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    /// The map the viewer asked for: `Public`, or `Team` with its group.
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    /// The level the viewer asked for.
    pub level_id: Uuid,
}

impl Expected {
    /// A level of the public map.
    pub fn public(level_id: Uuid) -> Self {
        Expected {
            map_scope: MapScope::Public,
            map_group_id: None,
            level_id,
        }
    }

    /// A level of one team's map.
    pub fn team(group_id: Uuid, level_id: Uuid) -> Self {
        Expected {
            map_scope: MapScope::Team,
            map_group_id: Some(group_id),
            level_id,
        }
    }
}

/// The contract directory: `services/explorer/contract/atlas_level/v1`.
pub fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../services/explorer/contract/atlas_level/v1")
}

/// The v1 JSON Schema, as committed.
pub const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/explorer/contract/atlas_level/v1/schema.json"
));

/// The schema, parsed.
pub fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| serde_json::from_str(SCHEMA_JSON).expect("schema.json is JSON"))
}

/// A validator for the schema's root, or for one of its `$defs`.
fn validator(def: Option<&str>) -> jsonschema::Validator {
    let s = schema();
    let doc = match def {
        None => s.clone(),
        Some(name) => json!({
            "$schema": s["$schema"],
            "$id": format!("{SCHEMA_ID}:{name}"),
            "$defs": s["$defs"],
            "$ref": format!("#/$defs/{name}"),
        }),
    };
    jsonschema::validator_for(&doc).expect("schema.json compiles")
}

fn level_validator() -> &'static jsonschema::Validator {
    static V: OnceLock<jsonschema::Validator> = OnceLock::new();
    V.get_or_init(|| validator(None))
}

/// Schema errors for a level document; empty when it validates. When the
/// root's `oneOf` fails, the errors of the branch named by `kind` are
/// reported instead, since they say which key is wrong.
pub fn schema_errors(doc: &Value) -> Vec<String> {
    let root = level_validator();
    if root.is_valid(doc) {
        return Vec::new();
    }
    let branch = match doc.get("kind").and_then(Value::as_str) {
        Some("group") => Some("group_level"),
        Some("leaf") => Some("leaf_level"),
        _ => None,
    };
    let errors: Vec<String> = match branch {
        Some(def) => {
            let v = validator(Some(def));
            v.iter_errors(doc)
                .map(|e| format!("schema {}: {e}", e.instance_path()))
                .collect()
        }
        None => Vec::new(),
    };
    if errors.is_empty() {
        root.iter_errors(doc)
            .map(|e| format!("schema {}: {e}", e.instance_path()))
            .collect()
    } else {
        errors
    }
}

/// Schema errors against one of the schema's `$defs`.
pub fn def_errors(def: &str, doc: &Value) -> Vec<String> {
    let v = validator(Some(def));
    v.iter_errors(doc)
        .map(|e| format!("schema #/$defs/{def}{}: {e}", e.instance_path()))
        .collect()
}

/// gzip size of a document's compact serialisation, the form that is
/// stored and served.
pub fn compact_gzip_len(doc: &Value) -> usize {
    gzip_len(&serde_json::to_vec(doc).expect("a Value serialises"))
}

/// Check one served level body: JSON, the schema, the strict types and
/// [`LevelDocument::validate`], that it is the map and level `expected`
/// names, and the budget on the bytes as served. Returns the decoded
/// document, or every failure found.
pub fn check_level_body(body: &[u8], expected: &Expected) -> Result<LevelDocument, Vec<String>> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("not JSON: {e}")]),
    };
    let mut errors = schema_errors(&value);
    let decoded = match serde_json::from_value::<LevelDocument>(value.clone()) {
        Ok(doc) => {
            if let Err(v) = doc.validate() {
                errors.extend(v.0.into_iter().map(|e| format!("invariant {e}")));
            }
            errors.extend(viewer_errors(&doc, expected));
            Some(doc)
        }
        Err(e) => {
            errors.push(format!("types: {e}"));
            None
        }
    };
    let served = gzip_len(body);
    if served > BUDGET_GZIP_BYTES {
        errors.push(format!(
            "budget: {served} gzip bytes as served exceed {BUDGET_GZIP_BYTES}"
        ));
    }
    match decoded {
        Some(doc) if errors.is_empty() => Ok(doc),
        _ => Err(errors),
    }
}

/// Whether the document is the map and level the request was for.
fn viewer_errors(doc: &LevelDocument, expected: &Expected) -> Vec<String> {
    let (scope, group, level) = match doc {
        LevelDocument::Group(g) => (g.map_scope, g.map_group_id, g.level_id),
        LevelDocument::Leaf(l) => (l.map_scope, l.map_group_id, l.level_id),
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

/// Which side answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The kernel route: `{"error":"NotFound","message":..,"details":..}`.
    Kernel,
    /// The Explorer BFF route: `{"error":"not_found","message":..}`.
    Bff,
}

/// Check the answer for a level the viewer may not see: a 404 whose body is
/// exactly the closed not-found shape (no level key, no count, no name) and,
/// on the kernel side, names only the id that was asked for, in both
/// `message` and `details.id`.
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
    errors.extend(def_errors(def, &value));
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
/// same bytes with the same status: nothing tells "exists, not yours" from
/// "does not exist". Call it with both answers for the same requested id.
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

// ---- the claim-to-leaf lookup (contract atlas_claim_leaf v1) ------------------

/// The claim-to-leaf v1 JSON Schema, as committed.
pub const CLAIM_LEAF_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../services/explorer/contract/atlas_claim_leaf/v1/schema.json"
));

fn claim_leaf_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(CLAIM_LEAF_SCHEMA_JSON).expect("the claim-leaf schema is JSON")
    })
}

/// Schema errors of a value against the claim-leaf schema's root, or one of
/// its `$defs`.
pub fn claim_leaf_schema_errors(def: Option<&str>, v: &Value) -> Vec<String> {
    let s = claim_leaf_schema();
    let doc = match def {
        None => s.clone(),
        Some(name) => json!({
            "$schema": s["$schema"],
            "$id": format!("urn:epigraph:atlas-claim-leaf:v1:{name}"),
            "$defs": s["$defs"],
            "$ref": format!("#/$defs/{name}"),
        }),
    };
    let validator = jsonschema::validator_for(&doc).expect("the claim-leaf schema compiles");
    validator
        .iter_errors(v)
        .map(|e| format!("schema {}: {e}", e.instance_path()))
        .collect()
}

/// What a claim-to-leaf request was for, as the test knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimLeafExpected {
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub hierarchy: crate::Hierarchy,
    pub claim_id: Uuid,
}

/// Check one claim-to-leaf answer: JSON, the schema, the strict type, and that
/// it is the map, hierarchy and claim the request named. Returns the decoded
/// answer, or every failure found.
pub fn check_claim_leaf_body(
    body: &[u8],
    expected: &ClaimLeafExpected,
) -> Result<crate::ClaimLeaf, Vec<String>> {
    let value: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return Err(vec![format!("not JSON: {e}")]),
    };
    let mut errors = claim_leaf_schema_errors(None, &value);
    let decoded = match serde_json::from_value::<crate::ClaimLeaf>(value) {
        Ok(c) => {
            if c.schema_version != crate::CLAIM_LEAF_SCHEMA_VERSION {
                errors.push(format!("schema_version {} is not 1", c.schema_version));
            }
            if (c.map_scope, c.map_group_id) != (expected.map_scope, expected.map_group_id) {
                errors.push(format!(
                    "viewer: the answer is the {:?} map {:?}, the request was for the {:?} map {:?}",
                    c.map_scope, c.map_group_id, expected.map_scope, expected.map_group_id
                ));
            }
            if c.hierarchy != expected.hierarchy {
                errors.push(format!(
                    "the answer is in {:?}, the request was for {:?}",
                    c.hierarchy, expected.hierarchy
                ));
            }
            if c.claim_id != expected.claim_id {
                errors.push(format!(
                    "the answer is for claim {}, the request was for {}",
                    c.claim_id, expected.claim_id
                ));
            }
            Some(c)
        }
        Err(e) => {
            errors.push(format!("types: {e}"));
            None
        }
    };
    match decoded {
        Some(c) if errors.is_empty() => Ok(c),
        _ => Err(errors),
    }
}

/// Check a claim-to-leaf refusal: a 404 whose body is exactly the closed
/// not-found shape and, on the kernel side, names only the claim asked for.
pub fn check_claim_leaf_not_found(
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
    errors.extend(claim_leaf_schema_errors(Some(def), &value));
    if side == Side::Kernel {
        if value["details"]["id"] != json!(requested_id) {
            errors.push(format!(
                "details.id {} is not the requested id {requested_id}",
                value["details"]["id"]
            ));
        }
        let message = format!("atlas_claim_leaf with ID {requested_id} not found");
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
