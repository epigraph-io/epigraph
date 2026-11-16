//! The claim-to-leaf lookup (contract `atlas_claim_leaf` v1) as a test helper.
//!
//! The `/atlas` page carries the lookup's prefix in
//! `data-atlas-claim-leaf-url`; a claim's leaf is
//! `<prefix><map key>/<hierarchy>/<claim id>`. Route tests check an answer
//! with [`check_claim_leaf_body`] (the JSON Schema at
//! `contract/atlas_claim_leaf/v1/schema.json`, the closed mirror type, and
//! that it is the map, hierarchy and claim asked for) and a refusal with
//! [`check_claim_leaf_not_found`].

use std::sync::OnceLock;

use epigraph_explorer::upstream::atlas_level::{Hierarchy, MapScope};
use epigraph_explorer::upstream::atlas_maps::{ClaimLeaf, CLAIM_LEAF_SCHEMA_VERSION};
use serde_json::{json, Value};
use uuid::Uuid;

pub const CLAIM_LEAF_SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/contract/atlas_claim_leaf/v1/schema.json"
);

pub fn claim_leaf_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(&std::fs::read_to_string(CLAIM_LEAF_SCHEMA).unwrap())
            .expect("the claim-leaf schema is JSON")
    })
}

/// Schema errors of `v` against the root (`None`) or one of the `$defs`.
pub fn claim_leaf_schema_errors(def: Option<&str>, v: &Value) -> Vec<String> {
    let s = claim_leaf_schema();
    jsonschema::meta::options()
        .validate(s)
        .unwrap_or_else(|e| panic!("the claim-leaf schema is not a valid 2020-12 schema: {e}"));
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
        .map(|e| format!("{}: {e}", e.instance_path()))
        .collect()
}

/// What a claim-to-leaf request was for.
#[derive(Debug, Clone, Copy)]
pub struct ClaimLeafExpected {
    pub map_scope: MapScope,
    pub map_group_id: Option<Uuid>,
    pub hierarchy: Hierarchy,
    pub claim_id: Uuid,
}

/// Check one answer; returns it decoded, or every failure found.
pub fn check_claim_leaf_body(
    body: &[u8],
    expected: &ClaimLeafExpected,
) -> Result<ClaimLeaf, Vec<String>> {
    let v: Value = serde_json::from_slice(body).map_err(|e| vec![format!("not JSON: {e}")])?;
    let mut errs = claim_leaf_schema_errors(None, &v);
    let leaf = match serde_json::from_value::<ClaimLeaf>(v) {
        Ok(l) => l,
        Err(e) => {
            errs.push(format!("mirror: {e}"));
            return Err(errs);
        }
    };
    if leaf.schema_version != CLAIM_LEAF_SCHEMA_VERSION {
        errs.push(format!("schema_version {}", leaf.schema_version));
    }
    if (leaf.map_scope, leaf.map_group_id) != (expected.map_scope, expected.map_group_id) {
        errs.push(format!(
            "the answer is the {:?} map {:?}, not {:?} {:?}",
            leaf.map_scope, leaf.map_group_id, expected.map_scope, expected.map_group_id
        ));
    }
    if leaf.hierarchy != expected.hierarchy {
        errs.push(format!("the answer is in {:?}", leaf.hierarchy));
    }
    if leaf.claim_id != expected.claim_id {
        errs.push(format!("the answer is for claim {}", leaf.claim_id));
    }
    if errs.is_empty() {
        Ok(leaf)
    } else {
        Err(errs)
    }
}

/// Check the BFF's refusal: a 404 with exactly the `bff_not_found` body.
pub fn check_claim_leaf_not_found(status: u16, body: &[u8]) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    if status != 404 {
        errs.push(format!("status {status}, not 404"));
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => errs.extend(claim_leaf_schema_errors(Some("bff_not_found"), &v)),
        Err(e) => errs.push(format!("not JSON: {e}")),
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}
