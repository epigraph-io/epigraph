//! The contract's own tests: the schema, the fixtures, the budget, and the
//! agreement between the JSON Schema and the strict types.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::check::{
    check_level_body, check_not_found, compact_gzip_len, contract_dir, schema, schema_errors, Side,
};
use crate::fixtures::{self, Rng};
use crate::*;

fn fixture_dir() -> std::path::PathBuf {
    contract_dir().join("fixtures")
}

fn read_fixture(stem: &str) -> Vec<u8> {
    let p = fixture_dir().join(format!("{stem}.json"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn read_value(stem: &str) -> Value {
    serde_json::from_slice(&read_fixture(stem)).expect("fixture is JSON")
}

const LEVEL_STEMS: &[&str] = &[
    "team_theme_root",
    "team_group_deep",
    "team_leaf_dense",
    "public_leaf",
];

/// The verdict of the strict types plus `validate`.
fn types_accept(v: &Value) -> Result<(), String> {
    let doc: LevelDocument = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    doc.validate().map_err(|e| e.to_string())
}

// ---- the schema ----------------------------------------------------------------

#[test]
fn schema_is_versioned_and_self_valid() {
    let s = schema();
    jsonschema::meta::options()
        .validate(s)
        .unwrap_or_else(|e| panic!("schema.json is not a valid 2020-12 schema: {e}"));
    assert_eq!(s["$id"], json!(SCHEMA_ID));
    for def in ["group_level", "leaf_level"] {
        assert_eq!(
            s["$defs"][def]["properties"]["schema_version"],
            json!({"const": SCHEMA_VERSION}),
            "{def} pins schema_version"
        );
        assert!(
            s["$defs"][def]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("schema_version")),
            "{def} requires schema_version"
        );
    }
}

/// Every object the schema defines is closed. A def that forgets
/// `additionalProperties: false` would let a private field through.
#[test]
fn every_schema_object_is_closed() {
    fn walk(path: &str, v: &Value, objects: &mut usize, open: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if m.get("type") == Some(&json!("object")) {
                    *objects += 1;
                    if m.get("additionalProperties") != Some(&json!(false)) {
                        open.push(path.to_string());
                    }
                }
                for (k, x) in m {
                    walk(&format!("{path}/{k}"), x, objects, open);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(&format!("{path}/{i}"), x, objects, open);
                }
            }
            _ => {}
        }
    }
    let (mut objects, mut open) = (0, Vec::new());
    walk("#", schema(), &mut objects, &mut open);
    assert!(open.is_empty(), "open objects: {open:?}");
    // breadcrumb, switch, link_target, child, bundle, claim_node,
    // plain_node, edge, outgoing, group_level, leaf_level, kernel_not_found
    // (+ its details), bff_not_found.
    assert_eq!(objects, 14);
}

/// The Rust caps and the schema's caps are the same numbers.
#[test]
fn caps_match_the_schema() {
    let d = &schema()["$defs"];
    let cap = |v: &Value| v.as_u64().unwrap_or_else(|| panic!("no cap at {v}")) as usize;
    assert_eq!(
        cap(&d["leaf_level"]["properties"]["nodes"]["maxItems"]),
        MAX_LEAF_NODES
    );
    assert_eq!(
        cap(&d["leaf_level"]["properties"]["edges"]["maxItems"]),
        MAX_LEAF_EDGES
    );
    assert_eq!(
        cap(&d["leaf_level"]["properties"]["outgoing"]["maxItems"]),
        MAX_LEAF_OUTGOING
    );
    assert_eq!(
        cap(&d["outgoing"]["properties"]["sources"]["maxItems"]),
        MAX_LEAF_NODES
    );
    assert_eq!(
        cap(&d["group_level"]["properties"]["children"]["maxItems"]),
        MAX_GROUP_CHILDREN
    );
    assert_eq!(
        cap(&d["group_level"]["properties"]["bundles"]["maxItems"]),
        MAX_GROUP_BUNDLES
    );
    assert_eq!(
        cap(&d["group_level"]["properties"]["targets"]["maxItems"]),
        MAX_GROUP_TARGETS
    );
    for def in ["group_level", "leaf_level"] {
        assert_eq!(
            cap(&d[def]["properties"]["breadcrumbs"]["maxItems"]),
            MAX_DEPTH as usize
        );
    }
    assert_eq!(cap(&d["depth"]["maximum"]), MAX_DEPTH as usize);
    assert_eq!(cap(&d["name"]["anyOf"][0]["maxLength"]), MAX_NAME_CHARS);
    assert_eq!(cap(&d["label"]["maxLength"]), MAX_LABEL_CHARS);
    assert_eq!(
        cap(&d["edge"]["properties"]["relationship"]["maxLength"]),
        MAX_RELATIONSHIP_CHARS
    );
}

// ---- the fixtures ----------------------------------------------------------------

/// The committed fixtures are exactly what the generator writes now. A type
/// or generator change that is not re-blessed fails here, and a blessed
/// change rewrites files under `services/explorer/`, which runs the
/// Explorer's mirror round-trip in its CI.
#[test]
fn fixtures_are_current() {
    let dir = fixture_dir();
    let files = fixtures::files();
    if std::env::var_os("ATLAS_CONTRACT_BLESS").is_some() {
        std::fs::create_dir_all(&dir).unwrap();
        for (name, body) in &files {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }
    let expected: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        on_disk, expected,
        "fixture files differ from the generator's set"
    );
    for (name, body) in &files {
        let committed = std::fs::read_to_string(dir.join(name)).unwrap();
        assert!(
            committed == *body,
            "{name} is stale; rerun with ATLAS_CONTRACT_BLESS=1"
        );
    }
}

#[test]
fn every_fixture_validates() {
    for stem in LEVEL_STEMS {
        if let Err(e) = check_level_body(&read_fixture(stem)) {
            panic!("{stem}: {e:#?}");
        }
    }
    for (stem, side) in [
        ("non_member_kernel", Side::Kernel),
        ("non_member_bff", Side::Bff),
    ] {
        let v = read_value(stem);
        let body = serde_json::to_vec(&v["body"]).unwrap();
        let id = v["body"]["details"]["id"].as_str().unwrap_or("");
        let status = v["status"].as_u64().unwrap() as u16;
        if let Err(e) = check_not_found(side, status, &body, id) {
            panic!("{stem}: {e:#?}");
        }
    }
}

/// The fixtures cover what W11, W12 and W10 need: a theme root with about
/// 40 children and bundles both inside and out, a deep unnamed group, a
/// full 100-node leaf with every node kind and flow basis, and a public
/// leaf.
#[test]
fn fixtures_cover_the_cases() {
    let docs: Vec<(String, LevelDocument)> = LEVEL_STEMS
        .iter()
        .map(|s| {
            (
                s.to_string(),
                serde_json::from_slice(&read_fixture(s)).unwrap(),
            )
        })
        .collect();
    let get = |s: &str| &docs.iter().find(|(n, _)| n == s).unwrap().1;

    let LevelDocument::Group(root) = get("team_theme_root") else {
        panic!("team_theme_root is a group level")
    };
    assert_eq!((root.map_scope, root.depth), (MapScope::Team, 0));
    assert!(
        root.children.len() >= 40,
        "{} children",
        root.children.len()
    );
    let children: BTreeSet<_> = root.children.iter().map(|c| c.id).collect();
    assert!(root.bundles.iter().any(|b| children.contains(&b.target)));
    assert!(root.bundles.iter().any(|b| !children.contains(&b.target)));
    assert!(root.children.iter().any(|c| c.name.is_none()));
    assert!(root.children.iter().any(|c| c.kind == ChildKind::Leaf));

    let LevelDocument::Group(deep) = get("team_group_deep") else {
        panic!("team_group_deep is a group level")
    };
    assert!(deep.depth >= 4 && deep.name.is_none() && deep.needs_naming);
    assert_eq!(deep.hierarchy, Hierarchy::Links);

    let LevelDocument::Leaf(dense) = get("team_leaf_dense") else {
        panic!("team_leaf_dense is a leaf")
    };
    assert_eq!(dense.nodes.len(), MAX_LEAF_NODES);
    let kinds: BTreeSet<_> = dense.nodes.iter().map(|n| n.kind_str()).collect();
    assert_eq!(kinds.len(), 3, "claim, agent and evidence nodes");
    for basis in [FlowBasis::Exact, FlowBasis::Proxy, FlowBasis::None] {
        assert!(
            dense.edges.iter().any(|e| e.flow_basis == basis),
            "{basis:?}"
        );
    }
    assert!(dense.edges.iter().any(|e| e.sign == -1), "an opposing edge");
    assert!(
        dense.edges.len() >= 4 * MAX_LEAF_NODES,
        "{} edges",
        dense.edges.len()
    );
    assert!(!dense.outgoing.is_empty());

    let LevelDocument::Leaf(public) = get("public_leaf") else {
        panic!("public_leaf is a leaf")
    };
    assert_eq!(
        (public.map_scope, public.map_group_id),
        (MapScope::Public, None)
    );
}

#[test]
fn fixtures_round_trip_through_the_types() {
    for stem in LEVEL_STEMS {
        let v = read_value(stem);
        let doc: LevelDocument = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&doc).unwrap(), v, "{stem}");
    }
}

// ---- the budget ------------------------------------------------------------------

#[test]
fn every_level_fixture_is_in_budget() {
    for stem in LEVEL_STEMS {
        let n = compact_gzip_len(&read_value(stem));
        assert!(n <= BUDGET_GZIP_BYTES, "{stem}: {n} gzip bytes");
    }
}

/// The largest documents the caps allow (every array full, every string at
/// its maximum length in dense multi-script text, full-precision numbers)
/// pass the contract and fit the budget, so any valid document does: the
/// budget is checked, not assumed.
#[test]
fn worst_case_documents_the_schema_allows_are_in_budget() {
    for (what, doc) in [
        ("leaf", fixtures::worst_case_leaf()),
        ("group", fixtures::worst_case_group()),
    ] {
        match &doc {
            LevelDocument::Leaf(l) => {
                assert_eq!(l.nodes.len(), MAX_LEAF_NODES);
                assert_eq!(l.edges.len(), MAX_LEAF_EDGES);
                assert_eq!(l.outgoing.len(), MAX_LEAF_OUTGOING);
                assert!(l.outgoing.iter().all(|o| o.sources.len() == MAX_LEAF_NODES));
            }
            LevelDocument::Group(g) => {
                assert_eq!(g.children.len(), MAX_GROUP_CHILDREN);
                assert_eq!(g.bundles.len(), MAX_GROUP_BUNDLES);
                assert_eq!(g.targets.len(), MAX_GROUP_TARGETS);
            }
        }
        let body = serde_json::to_vec(&doc).unwrap();
        if let Err(e) = check_level_body(&body) {
            panic!("worst-case {what} is not a valid document: {e:#?}");
        }
        let n = crate::check::gzip_len(&body);
        eprintln!(
            "worst-case {what}: {} raw bytes, {n} gzip bytes, {} headroom",
            body.len(),
            BUDGET_GZIP_BYTES - n
        );
    }
}

// ---- schema and types agree ----------------------------------------------------

/// Small documents that reach every object type of the schema: both level
/// kinds, both map scopes, every node kind and every flow basis.
fn probe_documents() -> Vec<Value> {
    fn id(v: &Value) -> String {
        v.as_str().expect("an id").to_string()
    }
    fn arr(v: &Value) -> &Vec<Value> {
        v.as_array().expect("an array")
    }
    let leaf = |stem: &str, keep_claims: usize| {
        let mut v = read_value(stem);
        let nodes = arr(&v["nodes"]);
        let mut kept: Vec<Value> = nodes.iter().take(keep_claims).cloned().collect();
        for kind in ["agent", "evidence"] {
            kept.push(
                nodes
                    .iter()
                    .find(|n| n["kind"] == json!(kind))
                    .unwrap()
                    .clone(),
            );
        }
        let ids: BTreeSet<String> = kept.iter().map(|n| id(&n["id"])).collect();
        let edges: Vec<Value> = arr(&v["edges"])
            .iter()
            .filter(|e| ids.contains(&id(&e["source"])) && ids.contains(&id(&e["target"])))
            .cloned()
            .collect();
        let outgoing: Vec<Value> = arr(&v["outgoing"])
            .iter()
            .take(2)
            .map(|o| {
                let mut o = o.clone();
                o["sources"] = json!([kept[0]["id"]]);
                o
            })
            .collect();
        v["nodes"] = Value::Array(kept);
        v["edges"] = Value::Array(edges);
        v["outgoing"] = Value::Array(outgoing);
        v
    };
    // The deep group, trimmed to its first 3 children, the bundles among
    // them and out of them, and the targets those bundles use.
    let mut g = read_value("team_group_deep");
    let kids: Vec<Value> = arr(&g["children"])[..3].to_vec();
    let kid_ids: BTreeSet<String> = kids.iter().map(|c| id(&c["id"])).collect();
    let target_ids: BTreeSet<String> = arr(&g["targets"])
        .iter()
        .map(|t| id(&t["level_id"]))
        .collect();
    let bundles: Vec<Value> = arr(&g["bundles"])
        .iter()
        .filter(|b| {
            let t = id(&b["target"]);
            kid_ids.contains(&id(&b["source"])) && (kid_ids.contains(&t) || target_ids.contains(&t))
        })
        .cloned()
        .collect();
    let used: BTreeSet<String> = bundles.iter().map(|b| id(&b["target"])).collect();
    let targets: Vec<Value> = arr(&g["targets"])
        .iter()
        .filter(|t| used.contains(&id(&t["level_id"])))
        .cloned()
        .collect();
    g["children"] = Value::Array(kids);
    g["bundles"] = Value::Array(bundles);
    g["targets"] = Value::Array(targets);
    vec![g, leaf("team_leaf_dense", 12), leaf("public_leaf", 8)]
}

/// Every place in a document a mutation can hit: (parent path, key or index).
fn slots(v: &Value, path: Vec<Value>, out: &mut Vec<Vec<Value>>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let mut p = path.clone();
                p.push(json!(k));
                out.push(p.clone());
                slots(x, p, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let mut p = path.clone();
                p.push(json!(i));
                out.push(p.clone());
                slots(x, p, out);
            }
        }
        _ => {}
    }
}

fn at<'a>(v: &'a mut Value, path: &[Value]) -> &'a mut Value {
    path.iter().fold(v, |v, k| match k {
        Value::String(s) => &mut v[s.as_str()],
        Value::Number(n) => &mut v[n.as_u64().unwrap() as usize],
        _ => unreachable!(),
    })
}

/// The proof that the strict types (with `validate`) and the JSON Schema
/// are one contract. At every key of every object in the probe documents,
/// it removes the key, adds an unknown key next to it, and replaces its
/// value with each of null, "", a 161-character string, -1, 1.5, -1.5 and
/// true. The schema's verdict must equal the types' verdict every time.
#[test]
fn schema_and_types_agree_on_every_mutation() {
    let replacements = [
        Value::Null,
        json!(""),
        json!("x".repeat(MAX_LABEL_CHARS + 1)),
        json!(-1),
        json!(1.5),
        json!(-1.5),
        json!(true),
    ];
    let mut disagreements = Vec::new();
    let (mut accepted, mut rejected) = (0usize, 0usize);
    for doc in probe_documents() {
        assert!(
            schema_errors(&doc).is_empty(),
            "probe is valid: {:?}",
            schema_errors(&doc)
        );
        types_accept(&doc).expect("probe is valid for the types");
        let mut paths = Vec::new();
        slots(&doc, Vec::new(), &mut paths);
        // Unknown key at the root and inside every object.
        let mut objects: Vec<Vec<Value>> = vec![Vec::new()];
        objects.extend(
            paths
                .iter()
                .filter(|p| {
                    let mut d = doc.clone();
                    at(&mut d, p).is_object()
                })
                .cloned(),
        );
        let mut mutants: Vec<(String, Value)> = Vec::new();
        for p in &objects {
            let mut m = doc.clone();
            at(&mut m, p)
                .as_object_mut()
                .unwrap()
                .insert("x_private".into(), json!("leak"));
            mutants.push((format!("{p:?} + x_private"), m));
        }
        for p in &paths {
            let (parent, last) = p.split_at(p.len() - 1);
            if let Value::String(key) = &last[0] {
                let mut m = doc.clone();
                at(&mut m, parent).as_object_mut().unwrap().remove(key);
                mutants.push((format!("{p:?} removed"), m));
            }
            for r in &replacements {
                let mut m = doc.clone();
                *at(&mut m, p) = r.clone();
                mutants.push((format!("{p:?} = {r}"), m));
            }
        }
        for (what, m) in mutants {
            let by_schema = schema_errors(&m).is_empty();
            let by_types = types_accept(&m);
            if by_schema != by_types.is_ok() {
                disagreements.push(format!(
                    "{what}: schema {} / types {by_types:?}",
                    if by_schema { "accepts" } else { "rejects" }
                ));
            }
            if by_schema {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} disagreements, first 20: {:#?}",
        disagreements.len(),
        &disagreements[..disagreements.len().min(20)]
    );
    // Both verdicts occur, so neither side is trivially all-accept or
    // all-reject.
    assert!(
        accepted > 50 && rejected > 1000,
        "accepted {accepted}, rejected {rejected}"
    );
}

// ---- negative cases --------------------------------------------------------------

#[test]
fn extra_private_field_is_rejected() {
    type Mutation = fn(&mut Value);
    let cases: [(&str, Mutation); 4] = [
        ("team_leaf_dense", |v| {
            v["nodes"][0]["content"] = json!("full private claim text");
        }),
        ("team_leaf_dense", |v| {
            v["member_ids"] = json!(["00000000-0000-4000-8000-000000000001"]);
        }),
        ("team_theme_root", |v| {
            v["children"][0]["private_claim_count"] = json!(12);
        }),
        ("team_theme_root", |v| {
            v["targets"][0]["group_id"] = json!("00000000-0000-4000-8000-000000000002");
        }),
    ];
    for (stem, mutate) in cases {
        let mut v = read_value(stem);
        mutate(&mut v);
        let errs = check_level_body(&serde_json::to_vec(&v).unwrap())
            .expect_err("an extra field must fail the contract");
        assert!(
            errs.iter().any(|e| e.starts_with("schema")),
            "the schema rejects it: {errs:#?}"
        );
        assert!(
            errs.iter().any(|e| e.starts_with("types")),
            "the types reject it: {errs:#?}"
        );
    }
}

#[test]
fn missing_flow_basis_is_rejected() {
    let mut v = read_value("team_leaf_dense");
    v["edges"][0].as_object_mut().unwrap().remove("flow_basis");
    let errs = check_level_body(&serde_json::to_vec(&v).unwrap())
        .expect_err("an edge without its exact/proxy flag must fail");
    assert!(errs.iter().any(|e| e.contains("flow_basis")), "{errs:#?}");
    assert!(errs.iter().any(|e| e.starts_with("schema")), "{errs:#?}");
    assert!(errs.iter().any(|e| e.starts_with("types")), "{errs:#?}");
}

#[test]
fn a_document_over_budget_is_rejected() {
    // Valid by schema and types, then padded with random whitespace (legal
    // after a JSON value, about 2 bits per byte) far past the budget.
    let mut body = serde_json::to_vec(&read_value("team_leaf_dense")).unwrap();
    let mut rng = Rng::new(7);
    body.extend((0..1_000_000).map(|_| b" \n\t\r"[rng.below(4)]));
    assert!(crate::check::gzip_len(&body) > BUDGET_GZIP_BYTES);
    let errs = check_level_body(&body).expect_err("over budget");
    assert_eq!(errs.len(), 1, "only the budget fails: {errs:#?}");
    assert!(errs[0].starts_with("budget"), "{errs:#?}");
}

#[test]
fn non_member_body_leaks_no_shape() {
    let kernel = read_value("non_member_kernel");
    let id = kernel["body"]["details"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let ok = serde_json::to_vec(&kernel["body"]).unwrap();
    check_not_found(Side::Kernel, 404, &ok, &id).unwrap();
    assert!(
        check_not_found(Side::Kernel, 403, &ok, &id).is_err(),
        "a 403 tells a non-member the level exists"
    );
    assert!(
        check_not_found(Side::Kernel, 404, &ok, "another-id").is_err(),
        "the body echoes only the requested id"
    );
    for leak in [
        ("member_count", json!(3)),
        ("children", json!([])),
        ("name", json!("A private group name")),
    ] {
        let mut b = kernel["body"].clone();
        b[leak.0] = leak.1.clone();
        let body = serde_json::to_vec(&b).unwrap();
        assert!(
            check_not_found(Side::Kernel, 404, &body, &id).is_err(),
            "kernel body with {}",
            leak.0
        );
        let mut d = kernel["body"].clone();
        d["details"][leak.0] = leak.1;
        let body = serde_json::to_vec(&d).unwrap();
        assert!(check_not_found(Side::Kernel, 404, &body, &id).is_err());
    }
    let bff = read_value("non_member_bff");
    let ok = serde_json::to_vec(&bff["body"]).unwrap();
    check_not_found(Side::Bff, 404, &ok, "").unwrap();
    let mut b = bff["body"].clone();
    b["level_kind"] = json!("leaf");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Bff, 404, &body, "").is_err());
    let mut b = bff["body"].clone();
    b["message"] = json!("That atlas level is private to its team.");
    let body = serde_json::to_vec(&b).unwrap();
    assert!(check_not_found(Side::Bff, 404, &body, "").is_err());
}

#[test]
#[should_panic(expected = "different body")]
fn indistinguishable_catches_a_different_body() {
    crate::check::assert_indistinguishable(
        (
            404,
            br#"{"error":"not_found","message":"We could not find that atlas level."}"#,
        ),
        (404, br#"{"error":"not_found","message":"No such level."}"#),
    );
}

// ---- invariants the schema cannot express ------------------------------------------

/// Each mutation keeps the document schema-valid, so only `validate`
/// catches it.
#[test]
fn invariants_catch_what_the_schema_cannot() {
    type Mutation = fn(&mut Value);
    let cases: [(&str, &str, Mutation); 10] = [
        ("team_leaf_dense", "/edges/0/target: not a node", |v| {
            v["edges"][0]["target"] = json!("00000000-0000-4000-8000-0000000000aa");
        }),
        ("team_leaf_dense", "exact flow runs from evidence", |v| {
            let i = (0..)
                .find(|&i| v["edges"][i]["flow_basis"] == json!("proxy"))
                .unwrap();
            v["edges"][i]["flow_basis"] = json!("exact");
        }),
        ("team_leaf_dense", "/nodes/1/id: duplicate node", |v| {
            v["nodes"][1]["id"] = v["nodes"][0]["id"].clone();
        }),
        ("team_leaf_dense", "/sources/0: not a node", |v| {
            v["outgoing"][0]["sources"][0] = json!("00000000-0000-4000-8000-0000000000bb");
        }),
        (
            "team_leaf_dense",
            "/breadcrumbs: 4 ancestors for depth 5",
            |v| {
                v["breadcrumbs"].as_array_mut().unwrap().pop();
            },
        ),
        ("team_theme_root", "/source: not a child", |v| {
            v["bundles"][0]["source"] = json!("00000000-0000-4000-8000-0000000000cc");
        }),
        ("team_theme_root", "no bundle leads to it", |v| {
            let t = v["targets"][0]["level_id"].clone();
            let bundles = v["bundles"].as_array_mut().unwrap();
            bundles.retain(|b| b["target"] != t);
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
    ];
    for (stem, expected, mutate) in cases {
        let mut v = read_value(stem);
        mutate(&mut v);
        let err = types_accept(&v).expect_err(expected);
        assert!(
            err.contains(expected),
            "{stem}: wanted `{expected}` in `{err}`"
        );
    }
}

/// Rules both sides enforce, checked on the types alone.
#[test]
fn invariants_enforce_the_schema_rules() {
    let mut leaf = read_value("public_leaf");
    leaf["switch"]["hierarchy"] = leaf["hierarchy"].clone();
    assert!(types_accept(&leaf)
        .unwrap_err()
        .contains("lead to the other hierarchy"));
    assert!(!schema_errors(&leaf).is_empty());

    let mut leaf = read_value("public_leaf");
    leaf["map_group_id"] = json!("00000000-0000-4000-8000-0000000000dd");
    assert!(types_accept(&leaf).unwrap_err().contains("no group id"));
    assert!(!schema_errors(&leaf).is_empty());

    let mut leaf = read_value("team_leaf_dense");
    let extra = leaf["nodes"][0].clone();
    let nodes = leaf["nodes"].as_array_mut().unwrap();
    let mut n = extra;
    n["id"] = json!("00000000-0000-4000-8000-0000000000ee");
    nodes.push(n);
    assert_eq!(nodes.len(), MAX_LEAF_NODES + 1);
    assert!(types_accept(&leaf)
        .unwrap_err()
        .contains("101 items exceed 100"));
    assert!(!schema_errors(&leaf).is_empty());

    let mut leaf = read_value("team_leaf_dense");
    let i = (0..)
        .find(|&i| leaf["edges"][i]["flow_basis"] == json!("none"))
        .unwrap();
    leaf["edges"][i]["flow_weight"] = json!(0.5);
    assert!(types_accept(&leaf)
        .unwrap_err()
        .contains("no flow has weight 0"));
    assert!(!schema_errors(&leaf).is_empty());
}
