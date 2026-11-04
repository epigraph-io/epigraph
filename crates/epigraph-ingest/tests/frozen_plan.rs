//! The frozen-plan read's pure half: the `wfd1` digest echo, the seed-aware
//! `content_hash_ok` flag and the integrity flags over a plan's `executes`
//! edges, checked against frozen vectors computed outside these crates
//! (`fixtures/wfd1-vectors.json`, written by `fixtures/gen_wfd1_vectors.py`).
//!
//! The flags exist because the order of a plan is a MUTABLE edge property: any
//! writer of the plan's group can rewrite an `executes` edge's `plan_index`
//! with `patch_edge`, or retract the edge. Nothing here repairs such a plan.
//! A plan whose stored indices are not exactly `0..n-1` gets no digest echo,
//! and a reordered one gets the digest of the order it now has. The integrity
//! anchor is a digest held OUTSIDE the server; the flags only say why the
//! server-side view no longer matches it.

use epigraph_ingest::common::ids::{compound_content_hash, content_hash};
use epigraph_ingest::workflow::build_ingest_plan;
use epigraph_ingest::workflow::frozen_plan::{
    assemble, content_hash_ok, wfd1, DigestItem, ExecutesEdge, FrozenPlanInput, PlanClaim,
};
use serde_json::{json, Value};
use uuid::Uuid;

const VECTORS: &str = include_str!("fixtures/wfd1-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors file parses")
}

fn uuid_of(v: &Value) -> Uuid {
    v.as_str().expect("uuid string").parse().expect("uuid")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn digest_items(items: &[Value]) -> Vec<(u32, DigestItem<'_>)> {
    items
        .iter()
        .map(|i| {
            (
                u32::try_from(i["plan_index"].as_u64().unwrap()).unwrap(),
                DigestItem {
                    level: u32::try_from(i["level"].as_u64().unwrap()).unwrap(),
                    claim_id: uuid_of(&i["claim_id"]),
                    content: i["content"].as_str().unwrap(),
                },
            )
        })
        .collect()
}

fn ordered(mut rows: Vec<(u32, DigestItem<'_>)>) -> Vec<DigestItem<'_>> {
    rows.sort_by_key(|(i, _)| *i);
    rows.into_iter().map(|(_, d)| d).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// The digest against the vectors
// ─────────────────────────────────────────────────────────────────────────────

/// Both cases, including the resolver's own synthetic child (whose contents
/// carry multi-byte characters, so a char-for-byte length bug cannot pass).
#[test]
fn wfd1_equals_the_frozen_vectors() {
    let v = vectors();
    for case in [&v["ingest"], &v["resolver_child"]] {
        let items = case
            .get("plan")
            .or_else(|| case.get("items"))
            .and_then(Value::as_array)
            .expect("items");
        let got = wfd1(
            case["canonical_name"].as_str().unwrap(),
            u32::try_from(case["generation"].as_u64().unwrap()).unwrap(),
            ordered(digest_items(items)),
        );
        assert_eq!(
            got,
            case["wfd1"].as_str().unwrap(),
            "{}",
            case["canonical_name"]
        );
    }
}

/// The vectors' plan is what the builder plans and the ingest records: the
/// same ids, stored hashes, levels and order. Calibration for the server-side
/// tests, which read a real ingest back and compare it with the same vectors.
#[test]
fn the_vector_plan_is_the_builders_plan() {
    let v = vectors();
    let extraction = serde_json::from_value(v["ingest"]["extraction"].clone()).expect("extraction");
    let plan = build_ingest_plan(&extraction);
    let want = v["ingest"]["plan"].as_array().unwrap();
    assert_eq!(plan.claims.len(), want.len());
    for (i, (got, want)) in plan.claims.iter().zip(want).enumerate() {
        assert_eq!(want["plan_index"].as_u64(), Some(i as u64));
        assert_eq!(got.id, uuid_of(&want["claim_id"]), "id at {i}");
        assert_eq!(
            u64::from(got.level),
            want["level"].as_u64().unwrap(),
            "level at {i}"
        );
        assert_eq!(
            got.content,
            want["content"].as_str().unwrap(),
            "content at {i}"
        );
        assert_eq!(
            got.content_hash.to_vec(),
            hex_bytes(&want["content_hash"]),
            "stored hash at {i}"
        );
    }
    assert!(
        want.iter().any(|i| i["level"] == 3),
        "the vectors exercise level-3 atoms, which every ingest executes"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// content_hash_ok: seed-aware, plain digest only on unmarked rows
// ─────────────────────────────────────────────────────────────────────────────

const NAME: &str = "acme-frozen-plan";

fn scoped_props(level: u64) -> Value {
    json!({"level": level, "source_type": "workflow", "content_hash_scope": "canonical_name"})
}

#[test]
fn content_hash_ok_is_seed_aware() {
    let text = "acme-frozen-plan \u{2014} step 1.1: read the queue";
    let plain = content_hash(text);
    let scoped = compound_content_hash(&plain, NAME);

    // A row the current builder writes: marked, compound digest under this name.
    assert!(content_hash_ok(NAME, text, &scoped, &scoped_props(2)));
    // A legacy row: no marker, plain digest.
    assert!(content_hash_ok(
        NAME,
        text,
        &plain,
        &json!({"level": 2, "source_type": "workflow"})
    ));
    // An atom: never marked, plain digest.
    assert!(content_hash_ok(
        NAME,
        "open the ACME-123456 queue",
        &content_hash("open the ACME-123456 queue"),
        &json!({"level": 3, "source_type": "workflow"})
    ));

    // A marked row whose digest is the plain one: the plain digest is accepted
    // ONLY on unmarked rows.
    assert!(!content_hash_ok(NAME, text, &plain, &scoped_props(2)));
    // An unmarked row carrying the compound digest.
    assert!(!content_hash_ok(
        NAME,
        text,
        &scoped,
        &json!({"level": 2, "source_type": "workflow"})
    ));
    // The compound digest of ANOTHER workflow's name.
    assert!(!content_hash_ok(
        NAME,
        text,
        &compound_content_hash(&plain, "acme-other-plan"),
        &scoped_props(2)
    ));
    // A tampered body under either digest.
    let tampered = "acme-frozen-plan \u{2014} step 1.1: read the queue twice";
    assert!(!content_hash_ok(NAME, tampered, &scoped, &scoped_props(2)));
    assert!(!content_hash_ok(
        NAME,
        tampered,
        &plain,
        &json!({"level": 2, "source_type": "workflow"})
    ));
    // A stored hash that is not 32 bytes.
    assert!(!content_hash_ok(
        NAME,
        text,
        &plain[..16],
        &json!({"level": 2})
    ));
    assert!(!content_hash_ok(
        NAME,
        text,
        &scoped[..16],
        &scoped_props(2)
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// assemble: the integrity flags
// ─────────────────────────────────────────────────────────────────────────────

/// The vectors' ingest plan as readable, live `executes` edges.
fn readable_edges() -> Vec<ExecutesEdge> {
    let v = vectors();
    v["ingest"]["plan"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let level = i["level"].as_u64().unwrap();
            ExecutesEdge {
                properties: json!({"level": level, "plan_index": i["plan_index"]}),
                retracted: false,
                target_id: uuid_of(&i["claim_id"]),
                target: Some(PlanClaim {
                    content: i["content"].as_str().unwrap().to_string(),
                    content_hash: hex_bytes(&i["content_hash"]),
                    properties: if level <= 2 {
                        scoped_props(level)
                    } else {
                        json!({"level": 3, "source_type": "workflow"})
                    },
                    visibility: "group".to_string(),
                    owner_group_id: Uuid::from_u128(0xb2),
                    truth_value: 0.8,
                    is_current: true,
                    heads_diverged: false,
                }),
            }
        })
        .collect()
}

fn input(edges: Vec<ExecutesEdge>) -> FrozenPlanInput {
    let v = vectors();
    FrozenPlanInput {
        workflow_id: uuid_of(&v["ingest"]["workflow_id"]),
        canonical_name: NAME.to_string(),
        generation: 0,
        goal: "Read the ACME-123456 queue once and summarise it.".to_string(),
        parent_id: None,
        truth_value: 1.0,
        submitter: Some(Uuid::from_u128(0xa1)),
        edges,
        chain_order: Vec::new(),
    }
}

fn plan_json(edges: Vec<ExecutesEdge>) -> Value {
    serde_json::to_value(assemble(input(edges))).expect("serialize")
}

fn flags(p: &Value) -> (u64, u64, u64, u64, u64) {
    (
        p["hidden_count"].as_u64().unwrap(),
        p["unindexed_edges"].as_u64().unwrap(),
        p["plan_index_gaps"].as_u64().unwrap(),
        p["duplicate_plan_indices"].as_u64().unwrap(),
        p["retracted_edges"].as_u64().unwrap(),
    )
}

fn item_ids(p: &Value) -> Vec<Uuid> {
    p["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| uuid_of(&i["claim_id"]))
        .collect()
}

#[test]
fn a_well_formed_plan_echoes_the_vector_digest_and_raises_no_flag() {
    let v = vectors();
    let p = plan_json(readable_edges());
    assert_eq!(flags(&p), (0, 0, 0, 0, 0));
    assert_eq!(p["digest_echo"], v["ingest"]["wfd1"]);
    let want: Vec<Uuid> = v["ingest"]["plan"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| uuid_of(&i["claim_id"]))
        .collect();
    assert_eq!(item_ids(&p), want, "items in plan_index order");
    let first = &p["items"][0];
    assert_eq!(
        first["content_hash"],
        v["ingest"]["plan"][0]["content_hash"]
    );
    assert_eq!(first["content_hash_ok"], json!(true));
    assert_eq!(first["visibility"], json!("group"));
    assert_eq!(
        first["owner_group_id"],
        json!(Uuid::from_u128(0xb2).to_string())
    );
    assert_eq!(p["submitter"], json!(Uuid::from_u128(0xa1).to_string()));
    assert_eq!(p["generation"], json!(0));
}

/// Input order is not plan order: the read sorts on the stored index.
#[test]
fn items_follow_the_stored_index_not_the_row_order() {
    let mut edges = readable_edges();
    edges.reverse();
    let p = plan_json(edges);
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
}

/// PM-7: a group writer exchanges two `plan_index` values. The read reports
/// the order the edges now carry, every flag stays clear (the indices are
/// still exactly `0..n-1`), and the echo is the digest of the NEW order, which
/// differs from the published one. Only a digest held outside the server can
/// tell the two apart.
#[test]
fn an_exchanged_pair_of_indices_moves_the_items_and_the_digest() {
    let v = vectors();
    let mut edges = readable_edges();
    edges[1].properties["plan_index"] = json!(2);
    edges[2].properties["plan_index"] = json!(1);
    let p = plan_json(edges);
    assert_eq!(flags(&p), (0, 0, 0, 0, 0));
    let ids = item_ids(&p);
    let want = item_ids(&plan_json(readable_edges()));
    assert_eq!((ids[1], ids[2]), (want[2], want[1]));
    assert_eq!(
        p["digest_echo"], v["ingest"]["wfd1_with_plan_index_1_and_2_swapped"],
        "the echo digests the stored order"
    );
    assert_ne!(p["digest_echo"], v["ingest"]["wfd1"]);
}

/// PM-7: `plan_index` counts only as a JSON integer >= 0 that fits in u32. A
/// string, a float, a negative number, a huge number or a missing key makes
/// the edge UNINDEXED: it is not an item (it has no position), it is counted,
/// and the plan gets no digest echo. Never a synthetic index.
#[test]
fn a_plan_index_that_is_not_a_non_negative_integer_is_unindexed() {
    for bad in [
        json!("1"),
        json!(1.0),
        json!(-1),
        json!(4_294_967_296_u64),
        Value::Null,
    ] {
        let mut edges = readable_edges();
        if bad.is_null() {
            edges[1]
                .properties
                .as_object_mut()
                .unwrap()
                .remove("plan_index");
        } else {
            edges[1].properties["plan_index"] = bad.clone();
        }
        let dropped = edges[1].target_id;
        let p = plan_json(edges);
        assert_eq!(p["unindexed_edges"], json!(1), "{bad}");
        assert_eq!(
            p["plan_index_gaps"],
            json!(1),
            "{bad}: index 1 is now missing"
        );
        assert!(
            !item_ids(&p).contains(&dropped),
            "{bad}: no item without an index"
        );
        assert_eq!(p["digest_echo"], Value::Null, "{bad}");
    }
}

/// The same rule for `level`: the digest covers it, so an edge without an
/// integer level cannot be digested either.
#[test]
fn an_edge_level_that_is_not_a_non_negative_integer_is_unindexed() {
    let mut edges = readable_edges();
    edges[2].properties["level"] = json!("2");
    let p = plan_json(edges);
    assert_eq!(p["unindexed_edges"], json!(1));
    assert_eq!(p["digest_echo"], Value::Null);
}

#[test]
fn a_duplicate_index_is_counted_and_both_items_are_kept() {
    let mut edges = readable_edges();
    edges[2].properties["plan_index"] = json!(1);
    let p = plan_json(edges);
    let (_, unindexed, gaps, dups, _) = flags(&p);
    assert_eq!((unindexed, gaps, dups), (0, 1, 1));
    assert_eq!(p["items"].as_array().unwrap().len(), 9);
    assert_eq!(p["digest_echo"], Value::Null);
}

/// A retracted `executes` edge is a plan change: not an item, counted, and the
/// plan gets no digest echo even when the remaining indices were renumbered to
/// look contiguous.
#[test]
fn a_retracted_edge_is_counted_and_not_an_item() {
    let mut edges = readable_edges();
    edges[8].retracted = true; // the last item: no gap is left behind
    let gone = edges[8].target_id;
    let p = plan_json(edges);
    assert_eq!(flags(&p), (0, 0, 0, 0, 1));
    assert!(!item_ids(&p).contains(&gone));
    assert_eq!(p["digest_echo"], Value::Null);
}

/// A live edge the viewer can see whose target it cannot read: counted, and
/// neither the target's id nor its content appears anywhere in the body.
#[test]
fn an_unreadable_target_is_a_count_and_never_an_id() {
    let mut edges = readable_edges();
    let hidden = edges[4].target_id;
    let hidden_text = edges[4].target.as_ref().unwrap().content.clone();
    edges[4].target = None;
    let p = plan_json(edges);
    assert_eq!(flags(&p), (1, 0, 1, 0, 0));
    assert_eq!(p["digest_echo"], Value::Null);
    let body = p.to_string();
    assert!(!body.contains(&hidden.to_string()), "no hidden id: {body}");
    assert!(!body.contains(&hidden_text), "no hidden content");
}

/// `content_hash_ok` is per item and does not suppress the echo: the digest is
/// over content, and the resolver decides on both.
#[test]
fn a_tampered_item_is_flagged_per_item() {
    let mut edges = readable_edges();
    edges[2].target.as_mut().unwrap().content.push('!');
    let p = plan_json(edges);
    let oks: Vec<bool> = p["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["content_hash_ok"].as_bool().unwrap())
        .collect();
    assert_eq!(oks.iter().filter(|ok| !**ok).count(), 1);
    assert!(!oks[2]);
    assert_eq!(flags(&p), (0, 0, 0, 0, 0));
    let echo = p["digest_echo"]
        .as_str()
        .unwrap_or_else(|| panic!("a per-item flag does not withhold the echo: {p}"));
    assert_ne!(echo, vectors()["ingest"]["wfd1"].as_str().unwrap());
}

/// A hidden target at the END of the plan leaves no gap, so the hidden count
/// alone withholds the echo: no other flag is raised.
#[test]
fn a_hidden_tail_target_withholds_the_echo_by_its_count_alone() {
    let mut edges = readable_edges();
    let hidden = edges[8].target_id;
    edges[8].target = None;
    let p = plan_json(edges);
    assert_eq!(flags(&p), (1, 0, 0, 0, 0));
    assert_eq!(p["items"].as_array().unwrap().len(), 8);
    assert!(!p.to_string().contains(&hidden.to_string()));
    assert_eq!(p["digest_echo"], Value::Null);
}

/// A tenth readable edge reusing the last index: a duplicate with no gap, so
/// the duplicate count alone withholds the echo.
#[test]
fn a_duplicate_tail_index_withholds_the_echo_by_its_count_alone() {
    let mut edges = readable_edges();
    let mut extra = edges[8].clone();
    extra.target_id = Uuid::from_u128(0xac0e_0001);
    edges.push(extra);
    let p = plan_json(edges);
    assert_eq!(flags(&p), (0, 0, 0, 1, 0));
    assert_eq!(p["items"].as_array().unwrap().len(), 10);
    assert_eq!(p["digest_echo"], Value::Null);
}

/// PM-7 reaches every edge property, not only `plan_index`: a group writer
/// rewrites an atom edge's integer `level` from 3 to 2. The read reports the
/// level the edge now carries (it does not cross-check the claim), raises no
/// count, and the echo moves off the published digest.
#[test]
fn a_rewritten_integer_level_is_reported_and_moves_the_digest() {
    let v = vectors();
    let mut edges = readable_edges();
    assert_eq!(
        edges[3].properties["level"],
        json!(3),
        "calibration: an atom"
    );
    edges[3].properties["level"] = json!(2);
    let p = plan_json(edges);
    assert_eq!(flags(&p), (0, 0, 0, 0, 0));
    assert_eq!(p["items"][3]["level"], json!(2));
    let echo = p["digest_echo"]
        .as_str()
        .expect("a well-formed plan echoes");
    assert_ne!(echo, v["ingest"]["wfd1"].as_str().unwrap());
}

#[test]
fn an_empty_plan_has_no_digest_echo() {
    let p = plan_json(Vec::new());
    assert_eq!(flags(&p), (0, 0, 0, 0, 0));
    assert_eq!(p["digest_echo"], Value::Null);
}
