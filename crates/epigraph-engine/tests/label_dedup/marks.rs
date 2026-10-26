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

#[test]
fn the_plan_hash_moves_with_every_field_of_a_mark() {
    let base = DuplicateMark {
        dup: id(9),
        canonical: id(1),
        rule: Tier::StrongId,
        matched_on: "shared id".to_string(),
    };
    let unit = |m: DuplicateMark| WriteUnit {
        unit: "cluster:fixed".to_string(),
        writes: vec![],
        marks: vec![m],
    };
    let h =
        |m: DuplicateMark| compute_plan_hash("ab", "a-run", None, &[Section::Dedup], &[unit(m)]);
    let b = h(base.clone());
    for (what, m) in [
        (
            "dup",
            DuplicateMark {
                dup: id(8),
                ..base.clone()
            },
        ),
        (
            "rule",
            DuplicateMark {
                rule: Tier::TitleAndEntity,
                ..base.clone()
            },
        ),
        (
            "matched_on",
            DuplicateMark {
                matched_on: "other".to_string(),
                ..base.clone()
            },
        ),
    ] {
        assert_ne!(h(m), b, "the hash ignores the mark's {what}");
    }
}

#[test]
fn a_knowledge_family_is_refused_for_every_section_alone() {
    let mut v = profile_value();
    v["family_kind"] = serde_json::json!("knowledge");
    let p = f::load(&v);
    for sections in [
        vec![Section::Hygiene],
        vec![Section::Closeout],
        vec![Section::Lifecycle],
    ] {
        let err = try_plan_graph(&p, &weir_pair(), &sections, Some(date("2026-07-01")), 5000)
            .expect_err("refused");
        assert_eq!(err.code(), "FAMILY_NOT_INDEX", "{sections:?}: {err}");
    }
}

#[test]
fn a_knowledge_lifecycle_signal_family_is_refused_when_lifecycle_is_planned() {
    let mut v = profile_value();
    v["lifecycle"]["signal_family_kind"] = serde_json::json!("knowledge");
    let p = f::load(&v);
    let err = try_plan_graph(
        &p,
        &weir_pair(),
        &[Section::Lifecycle],
        Some(date("2026-07-01")),
        5000,
    )
    .expect_err("lifecycle writes onto the signal family");
    assert!(
        matches!(&err, LabelDedupError::FamilyNotIndex { family_label, .. } if family_label == "lead"),
        "{err:?}"
    );
    // Control: a plan without the lifecycle section never writes there.
    try_plan_graph(&p, &weir_pair(), &dedup_sections(), None, 5000).expect("dedup only plans");
}

#[test]
fn a_claims_own_later_date_wins_over_an_earlier_duplicate() {
    let mut c = claim(
        1,
        f::WEIR_LATE,
        &["notice", "src-direct-a"],
        "2026-06-20T00:00:00Z",
    );
    c.duplicates = vec![claim(2, f::WEIR_EARLY, &["notice"], "2026-04-27T00:00:00Z")];
    let sections = [Section::Closeout];
    let open = plan_graph(
        &profile(),
        &[c.clone()],
        &sections,
        Some(date("2026-07-01")),
    );
    assert!(
        open.past_due.is_empty(),
        "07-15 is its own: {:?}",
        open.past_due
    );
    let closed = plan_graph(&profile(), &[c], &sections, Some(date("2026-07-16")));
    assert_eq!(
        closed.past_due.iter().map(|p| p.due).collect::<Vec<_>>(),
        vec![date("2026-07-15")]
    );
}

#[test]
fn a_canonical_with_duplicates_that_loses_brings_them_along() {
    // Run 1 marked the late filing (D) a duplicate of C. Run 2: a newer direct
    // filing N of the same item beats C. Only C is marked (D is no member);
    // N is judged by D's date through C; after apply N reads both.
    let mut c = claim(1, f::WEIR_EARLY, &["notice"], "2026-04-27T00:00:00Z");
    c.duplicates = vec![claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z")];
    let n = claim(
        3,
        "Tender: GWX KX-4417 Granite Weir Channel Upgrade — Acme County PUA, due 2026-06-30, est. $48M.",
        &["notice", "src-direct-a"],
        "2026-07-01T00:00:00Z",
    );
    let graph = vec![c, n];
    let sections = [Section::Dedup, Section::Closeout];
    let p = plan_graph(&profile(), &graph, &sections, Some(date("2026-07-10")));
    let marks: Vec<(uuid::Uuid, uuid::Uuid)> = p
        .write_units()
        .iter()
        .flat_map(|u| u.marks.iter().map(|m| (m.dup, m.canonical)))
        .collect();
    assert_eq!(marks, vec![(id(1), id(3))]);
    assert!(
        p.past_due.is_empty(),
        "D's 07-15 through C: {:?}",
        p.past_due
    );
    let applied = f::apply_units(&graph, &p.write_units());
    let mut read: Vec<uuid::Uuid> = applied[0].duplicates.iter().map(|d| d.id).collect();
    read.sort();
    assert_eq!((applied.len(), read), (1, vec![id(1), id(2)]));
}

#[test]
fn a_nested_duplicate_is_read_at_every_level() {
    let mut b = claim(
        2,
        f::FENDER_DIRECT_NO_DUE,
        &["notice"],
        "2026-05-01T00:00:00Z",
    );
    b.duplicates = vec![claim(3, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z")];
    let mut a = claim(
        1,
        f::WEIR_EARLY,
        &["notice", "src-direct-a"],
        "2026-04-27T00:00:00Z",
    );
    a.duplicates = vec![b];
    let p = plan_graph(
        &profile(),
        &[a],
        &[Section::Closeout],
        Some(date("2026-07-01")),
    );
    assert!(
        p.past_due.is_empty(),
        "07-15 two levels down keeps it open: {:?}",
        p.past_due
    );
}

#[test]
fn a_mark_records_the_match_with_the_survivor_or_names_the_intermediate() {
    // A and B share a strong id; B and C share title and entity (C has no id).
    // A survives. B's mark is its own match with A; C never matched A, so its
    // mark names B.
    let a = claim(
        1,
        "[OPEN] Riverside Pump Station Upgrade | Acme Water Board | ref TND 55501A | due 2026-09-01 | est. unknown | pump design",
        &["notice", "src-direct-a"],
        "2026-07-01T00:00:00Z",
    );
    let b = claim(
        2,
        "[OPEN] Riverside Pump House Rebuild | Acme Water Board | ref TND 55501A | due 2026-09-01 | est. unknown | pump design",
        &["notice"],
        "2026-07-02T00:00:00Z",
    );
    let c = claim(
        3,
        "[OPEN] Riverside Pump House Rebuild | Acme Water Board | due 2026-09-01 | est. unknown | pump design",
        &["notice"],
        "2026-07-03T00:00:00Z",
    );
    let p = plan_graph(&profile(), &[a, b, c], &dedup_sections(), None);
    assert_eq!(
        f::cluster_shape(&p),
        vec![(id(1), vec![id(2), id(3)])],
        "{:?}",
        p.clusters
    );
    let marks = p.clusters[0].marks();
    let of = |d: u32| marks.iter().find(|m| m.dup == id(d)).expect("mark");
    assert_eq!((of(2).canonical, of(2).rule), (id(1), Tier::StrongId));
    assert!(!of(2).matched_on.starts_with("via "), "{:?}", of(2));
    assert_eq!((of(3).canonical, of(3).rule), (id(1), Tier::TitleAndEntity));
    assert!(
        of(3).matched_on.starts_with(&format!("via {}", id(2))),
        "{:?}",
        of(3)
    );
}

#[test]
fn only_cluster_units_carry_marks() {
    let p = plan_graph(
        &profile(),
        &f::corpus(),
        &f::all_sections(),
        Some(date("2026-10-05")),
    );
    let units = p.write_units();
    assert!(
        units.iter().any(|u| !u.marks.is_empty()),
        "calibration: some marks"
    );
    for u in units.iter().filter(|u| !u.unit.starts_with("cluster:")) {
        assert!(u.marks.is_empty(), "{}: {:?}", u.unit, u.marks);
    }
}

#[test]
fn the_removed_carry_label_knob_is_refused() {
    let mut v = profile_value();
    v["fields"]["deadline"]["carry_label"] = serde_json::json!("due");
    let err = LabelDedupProfile::from_json_bytes(&f::bytes(&v)).expect_err("removed");
    assert!(err.to_string().contains("carry_label"), "{err}");
}
