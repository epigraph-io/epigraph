//! Marks: a cluster's losers are marked duplicates of the survivor (a graph
//! fact the apply tool writes through the dedup act), not relabelled. The
//! index loses them because a marked duplicate is not current; what they knew
//! stays on them and is read through their canonical (`DedupClaim::duplicates`,
//! the apply tool's `index_view`). Only ids, the index keys, are still carried
//! as labels.

use crate::fixtures::{
    self as f, claim, date, dedup_sections, id, plan_graph, profile, profile_value, try_plan_graph,
};
use epigraph_engine::label_dedup::{
    compute_plan_hash, DuplicateMark, LabelDedupError, LabelDedupProfile, Section, Tier, WriteUnit,
};

fn weir_pair() -> Vec<epigraph_engine::label_dedup::DedupClaim> {
    vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ]
}

#[test]
fn a_cluster_marks_each_loser_and_writes_no_loser_label() {
    let p = plan_graph(&profile(), &weir_pair(), &dedup_sections(), None);
    let units = p.write_units();
    let unit = units
        .iter()
        .find(|u| u.unit == format!("cluster:{}", id(1)))
        .expect("the cluster's unit");
    let member = &p.clusters[0].members[0];
    assert_eq!(
        unit.marks,
        vec![DuplicateMark {
            dup: id(2),
            canonical: id(1),
            rule: member.tier,
            matched_on: member.reason.clone(),
        }]
    );
    assert_eq!(member.tier, Tier::StrongId, "the pair shares a strong id");
    assert!(
        unit.writes.iter().all(|w| w.claim_id != id(2)),
        "no label write targets the loser: {:?}",
        unit.writes
    );
    // Positive control: the survivor's writes are still there.
    assert!(unit
        .writes
        .iter()
        .any(|w| w.claim_id == id(1) && w.add.contains(&"notice-survivor".to_string())));
}

#[test]
fn the_plan_hash_covers_the_marks() {
    // Same unit name and writes; only the mark differs, so nothing but the
    // mark can move the hash.
    let mark = |canonical: u32| WriteUnit {
        unit: "cluster:fixed".to_string(),
        writes: vec![],
        marks: vec![DuplicateMark {
            dup: id(9),
            canonical: id(canonical),
            rule: Tier::StrongId,
            matched_on: "shared id".to_string(),
        }],
    };
    let h = |u: WriteUnit| compute_plan_hash("ab", "a-run", None, &[Section::Dedup], &[u]);
    assert_eq!(h(mark(1)), h(mark(1)), "deterministic");
    assert_ne!(
        h(mark(1)),
        h(mark(2)),
        "a different mark is a different plan"
    );
}

#[test]
fn a_cluster_with_no_label_writes_still_carries_its_marks() {
    let mut v = profile_value();
    let merge = v["merge"].as_object_mut().expect("merge");
    merge.insert("survivor_add".into(), serde_json::json!([]));
    merge.insert("carry_ids".into(), false.into());
    let p = plan_graph(&f::load(&v), &weir_pair(), &dedup_sections(), None);
    let units = p.write_units();
    let unit = units
        .iter()
        .find(|u| u.unit.starts_with("cluster:"))
        .expect("a cluster unit with marks and no writes is still emitted");
    assert!(unit.writes.is_empty(), "{unit:?}");
    assert_eq!(unit.marks.len(), 1);
}

#[test]
fn removed_merge_knobs_are_refused_at_load() {
    for (knob, value) in [
        ("loser_add", serde_json::json!(["duplicate-of:{survivor}"])),
        ("loser_remove", serde_json::json!(["{family}"])),
        ("carry_later_dates", serde_json::json!(["deadline"])),
        ("carry_missing", serde_json::json!(["value"])),
        ("attach_loser_sources", serde_json::json!(true)),
    ] {
        let mut v = profile_value();
        v["merge"]
            .as_object_mut()
            .expect("merge")
            .insert(knob.into(), value);
        let err = LabelDedupProfile::from_json_bytes(&f::bytes(&v)).expect_err(knob);
        assert_eq!(err.code(), "PROFILE_SCHEMA_INVALID", "{knob}: {err}");
        assert!(err.to_string().contains(knob), "{knob}: {err}");
    }
}

#[test]
fn a_profile_declares_its_family_kind_and_only_an_index_is_planned() {
    let mut missing = profile_value();
    missing
        .as_object_mut()
        .expect("object")
        .remove("family_kind");
    let err = LabelDedupProfile::from_json_bytes(&f::bytes(&missing)).expect_err("required");
    assert!(err.to_string().contains("family_kind"), "{err}");

    let mut knowledge = profile_value();
    knowledge["family_kind"] = serde_json::json!("knowledge");
    let err = try_plan_graph(
        &f::load(&knowledge),
        &weir_pair(),
        &dedup_sections(),
        None,
        5000,
    )
    .expect_err("a knowledge family is never planned");
    assert!(
        matches!(err, LabelDedupError::FamilyNotIndex { .. }),
        "{err:?}"
    );
    assert_eq!(err.code(), "FAMILY_NOT_INDEX");

    // Control: the index profile plans.
    assert_eq!(
        plan_graph(&profile(), &weir_pair(), &dedup_sections(), None)
            .clusters
            .len(),
        1
    );
}

#[test]
fn no_carried_value_label_is_written() {
    let p = plan_graph(&profile(), &weir_pair(), &dedup_sections(), None);
    let labels: Vec<String> = p
        .write_units()
        .iter()
        .flat_map(|u| u.writes.iter().flat_map(|w| w.add.iter().cloned()))
        .collect();
    assert!(
        !labels.iter().any(|l| l.contains("-carried:")),
        "a later date or a missing value stays on the duplicate: {labels:?}"
    );
    // Control: carried ids (index keys) still are.
    assert!(
        labels.iter().any(|l| l.starts_with("also-id:")),
        "{labels:?}"
    );
}

#[test]
fn closeout_judges_a_canonical_by_its_duplicates_later_date() {
    // A previous run marked the later filing a duplicate of the earlier one;
    // the member read now returns only the canonical, with its duplicate.
    let mut canonical = claim(
        1,
        f::WEIR_EARLY,
        &["notice", "src-direct-a"],
        "2026-04-27T00:00:00Z",
    );
    let with_dup = {
        let mut c = canonical.clone();
        c.duplicates = vec![claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z")];
        c
    };
    let sections = [Section::Closeout];
    let as_of = Some(date("2026-07-01"));
    let p = plan_graph(&profile(), &[with_dup], &sections, as_of);
    assert!(
        p.past_due.is_empty(),
        "due 2026-06-17 on the canonical, 2026-07-15 on its duplicate: still open {:?}",
        p.past_due
    );
    // Control: without the duplicate the canonical is past due.
    canonical.duplicates.clear();
    let p = plan_graph(&profile(), &[canonical], &sections, as_of);
    assert_eq!(p.past_due.len(), 1, "{:?}", p.past_due);
}
