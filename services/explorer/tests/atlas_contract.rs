//! The Atlas nested-level contract (schema v1, backlog W10a) on the
//! Explorer's side: the mirror types in `upstream::atlas_level` against the
//! committed schema and fixtures, and the helper W10's BFF route tests call.

mod common;

use common::atlas_contract::{
    assert_indistinguishable, check_level_body, check_not_found, def_errors, fixture,
    fixture_value, gzip_len, invariant_errors, same_json, schema, schema_errors, Expected, Side,
    BELIEF_KEYS, FIXTURE_TEAM_GROUP_ID, LEVEL_FIXTURES,
};
use epigraph_explorer::upstream::atlas_level::{
    AtlasLevel, FlowBasis, MapScope, ATLAS_LEAF_MAX_NODES, ATLAS_LEVEL_BUDGET_GZIP_BYTES,
    ATLAS_LEVEL_SCHEMA_VERSION,
};
use serde_json::{json, Value};
use uuid::Uuid;

/// The request a fixture answers. The map comes from the fixture's name and
/// the generator's fixed team id; the level id is the fixture's own (the
/// kernel side takes it from the generator).
fn expected(stem: &str) -> Expected {
    let level: Uuid = fixture_value(stem)["level_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    if stem.starts_with("public_") {
        Expected::public(level)
    } else {
        Expected::team(FIXTURE_TEAM_GROUP_ID, level)
    }
}

fn check_as(stem: &str, body: &[u8]) -> Result<AtlasLevel, Vec<String>> {
    check_level_body(body, &expected(stem))
}

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
        if let Err(e) = check_as(stem, &fixture(stem)) {
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
        let id = v["body"]["details"]["id"].as_str().unwrap_or("");
        if let Err(e) = check_not_found(side, status, &body, id) {
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
    let errs = check_as("team_leaf_dense", &body).expect_err("an extra field fails");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");

    let body = mutated("team_theme_root", |v| {
        v["children"][0]["private_claim_count"] = json!(3);
    });
    assert!(check_as("team_theme_root", &body).is_err());
}

/// Every object key in `v`, and every string listed under a `required`.
fn keys_in(v: &Value, out: &mut std::collections::BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                out.insert(k.clone());
                if k == "required" {
                    for r in x.as_array().into_iter().flatten() {
                        out.insert(r.as_str().unwrap_or_default().to_string());
                    }
                }
                keys_in(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| keys_in(x, out)),
        _ => {}
    }
}

/// The region and theme routes' belief-key ban holds for the nested levels
/// too: neither the schema nor any fixture names a belief key.
#[test]
fn no_schema_or_fixture_key_carries_belief() {
    let mut docs = vec![("schema.json", schema().clone())];
    for stem in LEVEL_FIXTURES
        .iter()
        .chain(&["non_member_kernel", "non_member_bff"])
    {
        docs.push((stem, fixture_value(stem)));
    }
    for (what, doc) in &docs {
        let mut keys = std::collections::BTreeSet::new();
        keys_in(doc, &mut keys);
        for k in BELIEF_KEYS {
            assert!(!keys.contains(*k), "{what} names `{k}`");
        }
    }
}

/// A leaf claim node carrying `betp` fails as an unknown key of the closed
/// `claim_node`, whatever its value, null included.
#[test]
fn the_helper_rejects_betp_on_a_leaf_claim() {
    for stem in ["team_leaf_dense", "public_leaf"] {
        for value in [json!(0.7), Value::Null] {
            let mut i = 0;
            let body = mutated(stem, |v| {
                i = v["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|n| n["kind"] == json!("claim"))
                    .expect("a leaf has a claim");
                v["nodes"][i]["betp"] = value.clone();
            });
            let errs = check_as(stem, &body).expect_err("a claim node carrying betp fails");
            assert!(
                errs.iter().any(|e| e.starts_with("schema")),
                "{stem} betp={value}: {errs:#?}"
            );
            let node = &serde_json::from_slice::<Value>(&body).unwrap()["nodes"][i];
            let def = def_errors("claim_node", node);
            assert!(
                def.iter().any(|e| e.contains("betp")),
                "{stem} betp={value}: claim_node names the extra key: {def:#?}"
            );
        }
    }
}

#[test]
fn the_helper_rejects_an_edge_without_its_exact_or_proxy_flag() {
    let body = mutated("public_leaf", |v| {
        v["edges"][0].as_object_mut().unwrap().remove("flow_basis");
    });
    let errs = check_as("public_leaf", &body).expect_err("a missing flag fails");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");
    assert!(errs.iter().any(|e| e.starts_with("mirror")), "{errs:#?}");
}

/// A proxy weight is link strength × |sign|, so a `cites` link (sign 0)
/// weighs 0. One carrying a weight (its source's belief, say) fails the
/// helper through the schema; a signed proxy link keeps any weight.
#[test]
fn the_helper_rejects_a_weighted_cites_link() {
    let leaf = fixture_value("team_leaf_dense");
    let edges = leaf["edges"].as_array().unwrap();
    let cites = (0..edges.len())
        .find(|&i| edges[i]["flow_basis"] == json!("proxy") && edges[i]["sign"] == json!(0))
        .unwrap();
    let signed = (0..edges.len())
        .find(|&i| edges[i]["flow_basis"] == json!("proxy") && edges[i]["sign"] != json!(0))
        .unwrap();
    let body = mutated("team_leaf_dense", |v| {
        v["edges"][cites]["flow_weight"] = json!(0.5);
    });
    let errs = check_as("team_leaf_dense", &body).expect_err("a weighted cites link fails");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");
    let body = mutated("team_leaf_dense", |v| {
        v["edges"][signed]["flow_weight"] = json!(0.0001);
    });
    if let Err(e) = check_as("team_leaf_dense", &body) {
        panic!("a signed proxy link may weigh 0.0001: {e:#?}");
    }
}

#[test]
fn the_helper_rejects_a_dangling_reference() {
    // Schema-valid, so only the reference check can catch it.
    let body = mutated("team_leaf_dense", |v| {
        v["edges"][0]["target"] = json!("00000000-0000-4000-8000-0000000000aa");
    });
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert!(schema_errors(&v).is_empty());
    let errs = check_as("team_leaf_dense", &body).expect_err("a dangling edge fails");
    assert!(errs.iter().any(|e| e.starts_with("invariant")), "{errs:#?}");

    let body = mutated("team_theme_root", |v| {
        v["bundles"][0]["source"] = json!("00000000-0000-4000-8000-0000000000bb");
    });
    assert!(check_as("team_theme_root", &body).is_err());
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
    let errs = check_as("team_leaf_dense", &body).expect_err("over budget");
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert!(errs[0].starts_with("budget"), "{errs:#?}");
}

#[test]
fn the_not_found_answer_leaks_no_shape() {
    let bff = fixture_value("non_member_bff");
    let ok = serde_json::to_vec(&bff["body"]).unwrap();
    assert!(check_not_found(Side::Bff, 404, &ok, "").is_ok());
    assert!(
        check_not_found(Side::Bff, 403, &ok, "").is_err(),
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
        assert!(check_not_found(Side::Bff, 404, &body, "").is_err(), "{k}");
    }
    let mut b = bff["body"].clone();
    b["message"] = json!("That atlas level belongs to another team.");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Bff, 404, &body, "").is_err());

    let kernel = fixture_value("non_member_kernel");
    let id = kernel["body"]["details"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let ok = serde_json::to_vec(&kernel["body"]).unwrap();
    assert!(check_not_found(Side::Kernel, 404, &ok, &id).is_ok());
    let mut b = kernel["body"].clone();
    b["details"]["theme_id"] = json!("00000000-0000-4000-8000-0000000000cc");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Kernel, 404, &body, &id).is_err());
    // The message names another id while details.id is right.
    let mut b = kernel["body"].clone();
    b["message"] = json!("atlas_level with ID 00000000-0000-4000-8000-0000000000ff not found");
    let body = serde_json::to_vec(&b).unwrap();
    let errs = check_not_found(Side::Kernel, 404, &body, &id).expect_err("another id");
    assert!(errs.iter().any(|e| e.starts_with("message")), "{errs:#?}");
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

/// The helper ties the body to the request: a valid level of another map
/// (a team's leaf served to a public viewer, or to another team), or of
/// another level, fails.
#[test]
fn the_helper_ties_the_body_to_the_request() {
    let team = fixture("team_leaf_dense");
    let level = expected("team_leaf_dense").level_id;
    assert!(check_level_body(&team, &Expected::team(FIXTURE_TEAM_GROUP_ID, level)).is_ok());
    let other_team = Uuid::from_u128(0x0123_4567_89ab_4cde_8f01_2345_6789_abcd);
    for (what, want) in [
        ("a public viewer", Expected::public(level)),
        ("another team", Expected::team(other_team, level)),
        (
            "another level",
            Expected::team(FIXTURE_TEAM_GROUP_ID, expected("public_leaf").level_id),
        ),
    ] {
        let errs = check_level_body(&team, &want).expect_err(what);
        assert!(
            errs.iter().all(|e| e.starts_with("viewer")),
            "{what}: {errs:#?}"
        );
    }
}

/// A producer that is not serde may write `0` for a float. The kernel's
/// types accept it, and so must this helper: numbers compare by value.
#[test]
fn an_integer_float_passes_the_helper() {
    let body = mutated("team_leaf_dense", |v| {
        let i = (0..)
            .find(|&i| v["edges"][i]["flow_basis"] == json!("none"))
            .unwrap();
        v["edges"][i]["flow_weight"] = json!(0);
        v["nodes"][0]["x"] = json!(0);
    });
    assert!(String::from_utf8_lossy(&body).contains("\"flow_weight\":0,"));
    if let Err(e) = check_as("team_leaf_dense", &body) {
        panic!("{e:#?}");
    }
    assert!(same_json(&json!({"a": [0]}), &json!({"a": [0.0]})));
    assert!(!same_json(&json!({"a": [0]}), &json!({"a": [0.5]})));
    assert!(!same_json(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
}

fn index_where(v: &Value, f: impl Fn(&Value, &Value) -> bool) -> usize {
    let nodes = v["nodes"].as_array().unwrap();
    let kind = |id: &Value| {
        nodes
            .iter()
            .find(|n| &n["id"] == id)
            .map(|n| n["kind"].clone())
            .unwrap()
    };
    (0..)
        .find(|&i| {
            f(
                &kind(&v["edges"][i]["source"]),
                &kind(&v["edges"][i]["target"]),
            )
        })
        .unwrap()
}

/// Most stored evidence-to-claim edges have no mass the map's audience can
/// read, so they are served `none`, weight 0, sign 0. A leaf whose every
/// evidence edge is such passes the helper, and its evidence nodes still
/// count as attached to their claims. With a weight or a sign, the same edge
/// fails, on the schema alone and not on its basis.
#[test]
fn the_helper_accepts_an_evidence_edge_with_no_readable_mass() {
    for stem in ["team_leaf_dense", "public_leaf"] {
        let v = fixture_value(stem);
        let n = v["edges"].as_array().unwrap().len();
        let evidence: Vec<usize> = (0..n)
            .filter(|&i| edge_is(&v, i, |s, t| s == "evidence" && t == "claim"))
            .collect();
        assert!(evidence.len() > 1, "{stem}: evidence edges to flip");
        let body = mutated(stem, |v| {
            for &i in &evidence {
                v["edges"][i]["flow_basis"] = json!("none");
                v["edges"][i]["flow_weight"] = json!(0.0);
                v["edges"][i]["sign"] = json!(0);
            }
        });
        if let Err(e) = check_as(stem, &body) {
            panic!("{stem}: {e:#?}");
        }
        let i = evidence[0];
        for (w, sign) in [(0.5, 0), (0.0, 1), (0.0, -1), (0.4, 1)] {
            let body = mutated(stem, |v| {
                v["edges"][i]["flow_basis"] = json!("none");
                v["edges"][i]["flow_weight"] = json!(w);
                v["edges"][i]["sign"] = json!(sign);
            });
            let errs = check_as(stem, &body).expect_err("a weighted or signed none edge");
            assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");
            let doc: AtlasLevel = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                invariant_errors(&doc),
                Vec::<String>::new(),
                "{stem} weight {w} sign {sign}: the basis is allowed"
            );
        }
    }
}

/// Whether the endpoint kinds of edge `i` of `v` satisfy `f`.
fn edge_is(v: &Value, i: usize, f: impl Fn(&Value, &Value) -> bool) -> bool {
    let nodes = v["nodes"].as_array().unwrap();
    let kind = |id: &Value| {
        nodes
            .iter()
            .find(|n| &n["id"] == id)
            .map(|n| n["kind"].clone())
            .unwrap()
    };
    f(
        &kind(&v["edges"][i]["source"]),
        &kind(&v["edges"][i]["target"]),
    )
}

/// Every rule the kernel's `validate` enforces beyond the schema, each as a
/// schema-valid mutation that this helper must refuse with an invariant
/// error naming it. A rule the helper stops checking fails here.
#[test]
fn the_helper_enforces_every_kernel_invariant() {
    type Mutation = fn(&mut Value);
    let cases: Vec<(&str, &str, Mutation)> = vec![
        ("team_leaf_dense", "/edges/0/target: not a node", |v| {
            v["edges"][0]["target"] = json!("00000000-0000-4000-8000-0000000000aa");
        }),
        (
            "team_leaf_dense",
            "Claim to Claim is Proxy, not Exact",
            |v| {
                let i = index_where(v, |s, t| s == "claim" && t == "claim");
                v["edges"][i]["flow_basis"] = json!("exact");
            },
        ),
        (
            "team_leaf_dense",
            "Evidence to Claim is Exact or None, not Proxy",
            |v| {
                let i = index_where(v, |s, t| s == "evidence" && t == "claim");
                v["edges"][i]["flow_basis"] = json!("proxy");
            },
        ),
        (
            "team_leaf_dense",
            "Claim to Claim is Proxy, not None",
            |v| {
                let i = index_where(v, |s, t| s == "claim" && t == "claim");
                v["edges"][i]["flow_basis"] = json!("none");
                v["edges"][i]["flow_weight"] = json!(0.0);
                v["edges"][i]["sign"] = json!(0);
            },
        ),
        (
            "team_leaf_dense",
            "Agent to Claim is None, not Exact",
            |v| {
                let i = index_where(v, |s, t| s == "agent" && t == "claim");
                v["edges"][i]["flow_basis"] = json!("exact");
            },
        ),
        ("team_leaf_dense", "a self-loop", |v| {
            let i = index_where(v, |s, t| s == "claim" && t == "claim");
            v["edges"][i]["target"] = v["edges"][i]["source"].clone();
        }),
        (
            "team_leaf_dense",
            "duplicate (source, target, relationship)",
            |v| {
                let e = v["edges"][0].clone();
                v["edges"].as_array_mut().unwrap().push(e);
            },
        ),
        ("team_leaf_dense", "/nodes/1/id: duplicate node", |v| {
            v["nodes"][1]["id"] = v["nodes"][0]["id"].clone();
        }),
        ("public_leaf", "with no edge to a claim", |v| {
            let nid = v["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["kind"] == json!("agent"))
                .unwrap()["id"]
                .clone();
            v["edges"]
                .as_array_mut()
                .unwrap()
                .retain(|e| e["source"] != nid && e["target"] != nid);
        }),
        ("team_leaf_dense", "/sources/0: not a node", |v| {
            v["outgoing"][0]["sources"][0] = json!("00000000-0000-4000-8000-0000000000bb");
        }),
        ("public_leaf", "fewer links than source nodes", |v| {
            let n = v["outgoing"][0]["sources"].as_array().unwrap().len();
            v["outgoing"][0]["sources"] = json!(v["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .take(n.max(2))
                .map(|x| x["id"].clone())
                .collect::<Vec<_>>());
            v["outgoing"][0]["count"] = json!(1);
        }),
        ("public_leaf", "leads back to the leaf", |v| {
            v["outgoing"][0]["target"]["level_id"] = v["level_id"].clone();
        }),
        (
            "team_leaf_dense",
            "/breadcrumbs: 4 ancestors for depth 5",
            |v| {
                v["breadcrumbs"].as_array_mut().unwrap().pop();
            },
        ),
        (
            "team_leaf_dense",
            "/breadcrumbs/0/depth: 1 out of order",
            |v| {
                v["breadcrumbs"][0]["depth"] = json!(1);
                v["breadcrumbs"][1]["depth"] = json!(0);
            },
        ),
        ("team_theme_root", "/source: not a child", |v| {
            v["bundles"][0]["source"] = json!("00000000-0000-4000-8000-0000000000cc");
        }),
        ("team_theme_root", "no bundle leads to it", |v| {
            let t = v["targets"][0]["level_id"].clone();
            v["bundles"]
                .as_array_mut()
                .unwrap()
                .retain(|b| b["target"] != t);
        }),
        ("team_theme_root", "a bundle from a child to itself", |v| {
            v["bundles"][0]["target"] = v["bundles"][0]["source"].clone();
        }),
        ("team_theme_root", "/children/1/id: duplicate child", |v| {
            v["children"][1]["id"] = v["children"][0]["id"].clone();
        }),
        (
            "team_theme_root",
            "a target is a group outside this level",
            |v| {
                let c = v["children"][0]["id"].clone();
                let t = v["targets"][0]["level_id"].clone();
                v["targets"][0]["level_id"] = c.clone();
                for b in v["bundles"].as_array_mut().unwrap() {
                    if b["target"] == t {
                        b["target"] = c.clone();
                    }
                }
            },
        ),
    ];
    for (stem, want, mutate) in cases {
        let mut v = fixture_value(stem);
        mutate(&mut v);
        assert!(
            schema_errors(&v).is_empty(),
            "{want}: the mutation is schema-valid"
        );
        let doc: AtlasLevel = serde_json::from_value(v.clone()).unwrap();
        let errs = invariant_errors(&doc);
        assert!(
            errs.iter().any(|e| e.contains(want)),
            "{stem}: wanted `{want}` in {errs:#?}"
        );
        let body = serde_json::to_vec(&v).unwrap();
        assert!(
            check_as(stem, &body).is_err(),
            "{want}: the helper refuses it"
        );
    }
}
