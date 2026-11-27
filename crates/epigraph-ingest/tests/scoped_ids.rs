//! Scope-derived document ingest ids (backlog 8f56a641), pinned against
//! vectors derived independently of the Rust code: `fixtures/wfd1-vectors.json`
//! (`gen_wfd1_vectors.py`) for the shared id functions, and
//! `fixtures/scoped-id-vectors.json` (`gen_scoped_id_vectors.py`) for a whole
//! document plan, public and scoped.
//!
//! * Golden: a PUBLIC ingest's ids and stored hashes are byte-identical to the
//!   vectors every public ingest has always derived, through both
//!   `build_ingest_plan` and `build_ingest_plan_scoped(.., None)`.
//! * Scoped: a non-public ingest's ids follow the documented scheme, differ
//!   from the public ones and from another group's, and carry the marker.

use std::collections::HashSet;

use epigraph_ingest::common::ids::{
    compound_claim_id, compound_content_hash, content_hash, scoped_atom_content_hash,
    scoped_atom_id, scoped_seed, ID_SCOPE_KEY, ID_SCOPE_OWNER_GROUP,
};
use epigraph_ingest::document::{
    adopt_recorded_ids, build_ingest_plan, build_ingest_plan_scoped, DocumentExtraction,
};
use serde_json::Value;
use uuid::Uuid;

const WFD1: &str = include_str!("fixtures/wfd1-vectors.json");
const SCOPED: &str = include_str!("fixtures/scoped-id-vectors.json");

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn uuid_of(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().expect("uuid string")).expect("uuid")
}

fn vectors() -> Value {
    serde_json::from_str(SCOPED).expect("scoped vectors parse")
}

fn extraction() -> DocumentExtraction {
    serde_json::from_value(vectors()["extraction"].clone()).expect("extraction parses")
}

fn group() -> Uuid {
    uuid_of(&vectors()["group"])
}

/// `(level, content, id, stored hash)` of every claim, in plan order.
fn rows(plan: &epigraph_ingest::common::plan::IngestPlan) -> Vec<(u8, String, Uuid, Vec<u8>)> {
    plan.claims
        .iter()
        .map(|c| (c.level, c.content.clone(), c.id, c.content_hash.to_vec()))
        .collect()
}

fn expected(key: &str) -> Vec<(u8, String, Uuid, Vec<u8>)> {
    vectors()[key]
        .as_array()
        .expect("plan array")
        .iter()
        .map(|r| {
            (
                u8::try_from(r["level"].as_u64().expect("level")).expect("u8"),
                r["content"].as_str().expect("content").to_string(),
                uuid_of(&r["claim_id"]),
                hex(&r["content_hash"]),
            )
        })
        .collect()
}

/// The shared id functions with NO scope reproduce the frozen workflow
/// vectors: `scoped_atom_id(h, None)` is `atom_id`, `scoped_seed(s, None)` is
/// `s`, and the stored hashes are unchanged.
#[test]
fn unscoped_functions_reproduce_the_wfd1_vectors() {
    let v: Value = serde_json::from_str(WFD1).expect("wfd1 vectors parse");
    let canonical_name = v["ingest"]["canonical_name"].as_str().expect("name");
    let plan = v["ingest"]["plan"].as_array().expect("plan");
    assert!(plan.iter().any(|r| r["level"] == 3), "vectors hold an atom");
    assert!(
        plan.iter().any(|r| r["level"] != 3),
        "vectors hold a compound"
    );
    for r in plan {
        let h = content_hash(r["content"].as_str().expect("content"));
        let want_id = uuid_of(&r["claim_id"]);
        let want_hash = hex(&r["content_hash"]);
        if r["level"] == 3 {
            assert_eq!(scoped_atom_id(&h, None), want_id, "{r}");
            assert_eq!(
                scoped_atom_content_hash(&h, None).to_vec(),
                want_hash,
                "{r}"
            );
        } else {
            let seed = scoped_seed(canonical_name, None);
            assert_eq!(compound_claim_id(&h, &seed), want_id, "{r}");
            assert_eq!(compound_content_hash(&h, &seed).to_vec(), want_hash, "{r}");
        }
    }
}

/// GOLDEN: a public document plan's ids and stored hashes are byte-identical
/// to the independently derived vectors, and carry no scope marker.
#[test]
fn public_document_ids_are_byte_identical_to_the_golden_vectors() {
    let ex = extraction();
    let want = expected("public");
    let unscoped = build_ingest_plan(&ex);
    let scoped_none = build_ingest_plan_scoped(&ex, None);
    assert_eq!(rows(&unscoped), want, "build_ingest_plan moved a public id");
    assert_eq!(
        rows(&scoped_none),
        want,
        "build_ingest_plan_scoped(.., None) moved a public id"
    );
    for c in unscoped.claims.iter().chain(&scoped_none.claims) {
        assert_eq!(c.id_scope, None);
        assert!(
            c.properties.get(ID_SCOPE_KEY).is_none(),
            "a public claim carries no scope marker: {:?}",
            c.properties
        );
    }
}

/// A non-public document plan follows the documented scheme exactly.
#[test]
fn scoped_document_ids_follow_the_documented_scheme() {
    let plan = build_ingest_plan_scoped(&extraction(), Some(group()));
    assert_eq!(rows(&plan), expected("scoped"));
    for c in &plan.claims {
        assert_eq!(c.id_scope, Some(group()));
        assert!(
            c.id_is_document_scoped(),
            "{:?} must be written by id",
            c.content
        );
        assert_eq!(
            c.properties[ID_SCOPE_KEY], ID_SCOPE_OWNER_GROUP,
            "{:?} must carry the marker",
            c.content
        );
    }
}

/// Two groups' non-public ingests of one document share no id with each
/// other or with the public ingest, and repeat their own.
#[test]
fn scoped_ids_differ_per_group_and_from_public() {
    let ex = extraction();
    let a = Uuid::from_u128(0xA);
    let b = Uuid::from_u128(0xB);
    let ids = |scope| -> HashSet<Uuid> {
        build_ingest_plan_scoped(&ex, scope)
            .claims
            .iter()
            .map(|c| c.id)
            .collect()
    };
    let (public, ia, ib) = (ids(None), ids(Some(a)), ids(Some(b)));
    assert!(public.is_disjoint(&ia), "group A reuses a public id");
    assert!(public.is_disjoint(&ib), "group B reuses a public id");
    assert!(ia.is_disjoint(&ib), "groups A and B share an id");
    assert_eq!(ia, ids(Some(a)), "scoped ids are deterministic");
}

/// A re-ingest in a scope whose paper already records the document's GLOBAL
/// ids keeps them, claim by claim, and re-points every edge; a claim not
/// recorded keeps its scoped id.
#[test]
fn recorded_global_ids_are_adopted_claim_by_claim() {
    let ex = extraction();
    let global = build_ingest_plan(&ex);
    let scoped = build_ingest_plan_scoped(&ex, Some(group()));
    // Recorded: everything but the last paragraph (a paragraph added since).
    let last = global
        .claims
        .iter()
        .rposition(|c| c.level == 2)
        .expect("a paragraph");
    let recorded: Vec<(Uuid, Option<[u8; 32]>)> = global
        .claims
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != last)
        .map(|(_, c)| (c.id, None))
        .collect();
    let (merged, adopted) = adopt_recorded_ids(scoped, &global, &recorded);
    for (i, (m, g)) in merged.claims.iter().zip(&global.claims).enumerate() {
        if i == last {
            assert_ne!(m.id, g.id, "an unrecorded claim keeps its scoped id");
            assert_eq!(m.id_scope, Some(group()));
            assert!(!adopted.contains(&m.id));
        } else {
            assert_eq!(m.id, g.id, "a recorded claim keeps its recorded id");
            assert_eq!(m.content_hash, g.content_hash);
            assert_eq!(m.id_scope, None);
            assert!(adopted.contains(&m.id));
        }
    }
    let ids: HashSet<Uuid> = merged.claims.iter().map(|c| c.id).collect();
    for e in &merged.edges {
        if e.source_type == "claim" {
            assert!(ids.contains(&e.source_id), "edge source re-pointed: {e:?}");
        }
        assert!(ids.contains(&e.target_id), "edge target re-pointed: {e:?}");
    }
    for id in merged.path_index.values() {
        assert!(ids.contains(id), "path re-pointed");
    }
}

/// An atom the earlier ingest converged onto an existing row (so its recorded
/// id is not the content address) is adopted by its stored hash.
#[test]
fn a_recorded_atom_is_adopted_by_its_stored_hash() {
    let ex = extraction();
    let global = build_ingest_plan(&ex);
    let scoped = build_ingest_plan_scoped(&ex, Some(group()));
    let atom = global.claims.iter().find(|c| c.level == 3).expect("atom");
    let elsewhere = Uuid::new_v4();
    let (merged, adopted) =
        adopt_recorded_ids(scoped, &global, &[(elsewhere, Some(atom.content_hash))]);
    assert!(adopted.contains(&elsewhere));
    assert!(merged
        .claims
        .iter()
        .filter(|c| c.content == atom.content)
        .all(|c| c.id == elsewhere));
}

/// Nothing recorded: the scoped plan is returned as built.
#[test]
fn nothing_recorded_keeps_every_scoped_id() {
    let ex = extraction();
    let global = build_ingest_plan(&ex);
    let scoped = build_ingest_plan_scoped(&ex, Some(group()));
    let before = rows(&scoped);
    let (merged, adopted) = adopt_recorded_ids(scoped, &global, &[]);
    assert!(adopted.is_empty());
    assert_eq!(rows(&merged), before);
}
