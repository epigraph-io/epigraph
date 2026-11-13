//! The Atlas nested-level contract (schema v1, backlog W10a) on the
//! Explorer's side: the mirror types in `upstream::atlas_level` against the
//! committed schema and fixtures, and the helper W10's BFF route tests call.

mod common;

use common::atlas_contract::{
    assert_indistinguishable, check_level_body, check_not_found, fixture, fixture_value, gzip_len,
    schema, schema_errors, Side, LEVEL_FIXTURES,
};
use epigraph_explorer::upstream::atlas_level::{
    AtlasLevel, FlowBasis, MapScope, ATLAS_LEAF_MAX_NODES, ATLAS_LEVEL_BUDGET_GZIP_BYTES,
    ATLAS_LEVEL_SCHEMA_VERSION,
};
use serde_json::{json, Value};

#[test]
fn the_schema_is_v1_and_matches_the_mirror_constants() {
    let s = schema();
    assert_eq!(s["$id"], json!("urn:epigraph:atlas-level:v1"));
    for def in ["group_level", "leaf_level"] {
        assert_eq!(
            s["$defs"][def]["properties"]["schema_version"],
            json!({"const": ATLAS_LEVEL_SCHEMA_VERSION})
        );
    }
    assert_eq!(
        s["$defs"]["leaf_level"]["properties"]["nodes"]["maxItems"],
        json!(ATLAS_LEAF_MAX_NODES)
    );
}

#[test]
fn every_fixture_passes_the_helper() {
    for stem in LEVEL_FIXTURES {
        if let Err(e) = check_level_body(&fixture(stem)) {
            panic!("{stem}: {e:#?}");
        }
    }
    for (stem, side) in [
        ("non_member_kernel", Side::Kernel),
        ("non_member_bff", Side::Bff),
    ] {
        let v = fixture_value(stem);
        let body = serde_json::to_vec(&v["body"]).unwrap();
        let status = v["status"].as_u64().unwrap() as u16;
        if let Err(e) = check_not_found(side, status, &body) {
            panic!("{stem}: {e:#?}");
        }
    }
}

/// The mirror carries every field of the contract: decoding a fixture and
/// re-encoding it gives back the same document. A field the mirror lacks is
/// silently dropped on decode (the Explorer ignores unknown fields), so it
/// shows up here as a difference.
#[test]
fn the_mirror_round_trips_every_fixture() {
    for stem in LEVEL_FIXTURES {
        let v = fixture_value(stem);
        let level: AtlasLevel = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&level).unwrap(), v, "{stem}");
    }
}

#[test]
fn the_fixtures_cover_team_and_public_maps_and_every_flow_basis() {
    let mut scopes = Vec::new();
    let mut bases = Vec::new();
    for stem in LEVEL_FIXTURES {
        match serde_json::from_slice::<AtlasLevel>(&fixture(stem)).unwrap() {
            AtlasLevel::Group(g) => scopes.push(g.map_scope),
            AtlasLevel::Leaf(l) => {
                scopes.push(l.map_scope);
                bases.extend(l.edges.iter().map(|e| e.flow_basis));
                if *stem == "team_leaf_dense" {
                    assert_eq!(l.nodes.len(), ATLAS_LEAF_MAX_NODES);
                }
            }
        }
    }
    assert!(scopes.contains(&MapScope::Team) && scopes.contains(&MapScope::Public));
    for b in [FlowBasis::Exact, FlowBasis::Proxy, FlowBasis::None] {
        assert!(bases.contains(&b), "{b:?}");
    }
}

#[test]
fn the_fixtures_fit_the_budget() {
    for stem in LEVEL_FIXTURES {
        let compact = serde_json::to_vec(&fixture_value(stem)).unwrap();
        let n = gzip_len(&compact);
        assert!(n <= ATLAS_LEVEL_BUDGET_GZIP_BYTES, "{stem}: {n} gzip bytes");
    }
}

fn mutated(stem: &str, f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v = fixture_value(stem);
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn the_helper_rejects_an_extra_private_field() {
    let body = mutated("team_leaf_dense", |v| {
        v["nodes"][0]["content"] = json!("full private claim text");
    });
    let errs = check_level_body(&body).expect_err("an extra field fails");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");

    let body = mutated("team_theme_root", |v| {
        v["children"][0]["private_claim_count"] = json!(3);
    });
    assert!(check_level_body(&body).is_err());
}

#[test]
fn the_helper_rejects_an_edge_without_its_exact_or_proxy_flag() {
    let body = mutated("public_leaf", |v| {
        v["edges"][0].as_object_mut().unwrap().remove("flow_basis");
    });
    let errs = check_level_body(&body).expect_err("a missing flag fails");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");
    assert!(errs.iter().any(|e| e.starts_with("mirror")), "{errs:#?}");
}

#[test]
fn the_helper_rejects_a_dangling_reference() {
    // Schema-valid, so only the reference check can catch it.
    let body = mutated("team_leaf_dense", |v| {
        v["edges"][0]["target"] = json!("00000000-0000-4000-8000-0000000000aa");
    });
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert!(schema_errors(&v).is_empty());
    let errs = check_level_body(&body).expect_err("a dangling edge fails");
    assert!(errs.iter().any(|e| e.starts_with("refs")), "{errs:#?}");

    let body = mutated("team_theme_root", |v| {
        v["bundles"][0]["source"] = json!("00000000-0000-4000-8000-0000000000bb");
    });
    assert!(check_level_body(&body).is_err());
}

#[test]
fn the_helper_rejects_a_body_over_budget() {
    // Valid JSON with trailing whitespace, padded until it is over budget.
    let mut body = fixture("team_leaf_dense");
    let mut state: u64 = 0x5EED;
    while gzip_len(&body) <= ATLAS_LEVEL_BUDGET_GZIP_BYTES {
        for _ in 0..200_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            body.push(b" \n\t\r"[(state >> 62) as usize]);
        }
    }
    let errs = check_level_body(&body).expect_err("over budget");
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].starts_with("budget"), "{errs:#?}");
}

#[test]
fn the_not_found_answer_leaks_no_shape() {
    let bff = fixture_value("non_member_bff");
    let ok = serde_json::to_vec(&bff["body"]).unwrap();
    assert!(check_not_found(Side::Bff, 404, &ok).is_ok());
    assert!(
        check_not_found(Side::Bff, 403, &ok).is_err(),
        "a 403 says the level exists"
    );
    for (k, val) in [
        ("member_count", json!(3)),
        ("kind", json!("leaf")),
        ("name", json!("A private group name")),
    ] {
        let mut b = bff["body"].clone();
        b[k] = val;
        let body = serde_json::to_vec(&b).unwrap();
        assert!(check_not_found(Side::Bff, 404, &body).is_err(), "{k}");
    }
    let mut b = bff["body"].clone();
    b["message"] = json!("That atlas level belongs to another team.");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Bff, 404, &body).is_err());

    let kernel = fixture_value("non_member_kernel");
    let mut b = kernel["body"].clone();
    b["details"]["theme_id"] = json!("00000000-0000-4000-8000-0000000000cc");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Kernel, 404, &body).is_err());
}

#[test]
#[should_panic(expected = "different body")]
fn indistinguishable_catches_a_different_body() {
    let same = serde_json::to_vec(&fixture_value("non_member_bff")["body"]).unwrap();
    assert_indistinguishable(
        (404, &same),
        (404, br#"{"error":"not_found","message":"No such level."}"#),
    );
}
