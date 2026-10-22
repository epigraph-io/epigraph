//! Write units: what apply will write, in what order, and that an applied plan
//! re-plans empty.

use epigraph_engine::label_dedup::{DedupClaim, Section};

use crate::fixtures::{
    self as f, all_sections, apply_units, claim, corpus, date, dedup_sections, id, plan_graph,
    profile, t,
};

/// The corpus plus signals, so every section has work.
fn graph() -> Vec<DedupClaim> {
    let mut g = corpus();
    g.push(claim(
        0x7000_0001,
        f::LEAD_CHILLER,
        &["lead", "src-direct-c"],
        "2026-06-29T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0002,
        f::LEAD_PERMIT_OLD,
        &["lead"],
        "2026-06-29T00:00:00Z",
    ));
    g.push(claim(
        0x7000_0003,
        f::NOTICE_CHILLER,
        &["notice", "src-direct-c"],
        "2026-10-04T00:00:00Z",
    ));
    g
}

#[test]
fn cluster_unit_marks_losers_and_never_touches_content() {
    let p = plan_graph(&profile(), &corpus(), &dedup_sections(), None);
    let units = p.write_units();
    let unit = units
        .iter()
        .find(|u| u.unit == format!("cluster:{}", id(t::WING_DIRECT)))
        .expect("wing cluster unit");
    assert!(
        unit.writes.iter().all(|w| w.claim_id != id(t::WING_FEED)),
        "the loser leaves the index by its mark, not a label: {:?}",
        unit.writes
    );
    assert!(
        unit.marks
            .iter()
            .any(|m| m.dup == id(t::WING_FEED) && m.canonical == id(t::WING_DIRECT)),
        "{:?}",
        unit.marks
    );
    let survivor = unit
        .writes
        .iter()
        .find(|w| w.claim_id == id(t::WING_DIRECT))
        .expect("survivor write");
    assert!(survivor.add.contains(&"notice-survivor".to_string()));
    assert!(
        !survivor.remove.contains(&"notice".to_string()),
        "the survivor stays in the family"
    );

    let applied = apply_units(&corpus(), &units);
    let original = corpus();
    for after in applied
        .iter()
        .chain(applied.iter().flat_map(|c| c.duplicates.iter()))
    {
        let before = original
            .iter()
            .find(|c| c.id == after.id)
            .expect("same claims");
        assert_eq!(before.content, after.content, "content is never rewritten");
    }
}

#[test]
fn units_come_in_apply_order() {
    let p = plan_graph(
        &profile(),
        &graph(),
        &all_sections(),
        Some(date("2026-10-05")),
    );
    let kinds: Vec<&str> = p
        .write_units()
        .iter()
        .map(|u| u.unit.split(':').next().unwrap_or_default().to_string())
        .map(|k| match k.as_str() {
            "hygiene" => "hygiene",
            "cluster" => "cluster",
            "closeout" => "closeout",
            "lifecycle" => "lifecycle",
            _ => "other",
        })
        .collect();
    let first = |k: &str| kinds.iter().position(|x| *x == k).unwrap_or(usize::MAX);
    let last = |k: &str| kinds.iter().rposition(|x| *x == k).unwrap_or(0);
    for k in ["hygiene", "cluster", "closeout", "lifecycle"] {
        assert!(kinds.contains(&k), "{k} has work in this graph: {kinds:?}");
    }
    assert!(last("hygiene") < first("cluster"), "{kinds:?}");
    assert!(last("cluster") < first("closeout"), "{kinds:?}");
    assert!(last("closeout") < first("lifecycle"), "{kinds:?}");
}

#[test]
fn an_applied_plan_replans_empty() {
    // The idempotency contract: losers and hygiene leave the family, closed
    // members and signals gain the closed label, so a re-plan of the applied
    // graph has nothing left to write.
    let g = graph();
    let first = plan_graph(&profile(), &g, &all_sections(), Some(date("2026-10-05")));
    assert!(!first.is_empty(), "control: there is work");
    let applied = apply_units(&g, &first.write_units());
    let second = plan_graph(
        &profile(),
        &applied,
        &all_sections(),
        Some(date("2026-10-05")),
    );
    assert!(
        second.is_empty(),
        "re-plan after apply must be empty: {:?}",
        second.write_units()
    );
}

#[test]
fn a_partial_apply_replans_exactly_the_missing_units() {
    // as_of before the wing deadline, so the failed cluster's survivor is not
    // also closed by a later unit of the same apply.
    let g = graph();
    let first = plan_graph(&profile(), &g, &all_sections(), Some(date("2026-08-01")));
    assert!(
        first.past_due.iter().all(|p| p.id != id(t::WING_DIRECT)),
        "precondition"
    );
    let units = first.write_units();
    // Apply every unit but the wing cluster (as if its transaction failed).
    let failed = format!("cluster:{}", id(t::WING_DIRECT));
    let partial: Vec<_> = units.iter().filter(|u| u.unit != failed).cloned().collect();
    let applied = apply_units(&g, &partial);
    let second = plan_graph(
        &profile(),
        &applied,
        &all_sections(),
        Some(date("2026-08-01")),
    );
    let names: Vec<_> = second.write_units().into_iter().map(|u| u.unit).collect();
    assert_eq!(names, vec![failed], "only the failed unit is planned again");
}

#[test]
fn lifecycle_unit_only_adds() {
    let p = plan_graph(
        &profile(),
        &graph(),
        &[Section::Lifecycle],
        Some(date("2026-10-05")),
    );
    let units = p.write_units();
    assert_eq!(units.len(), 2, "{units:?}");
    for u in &units {
        assert!(u.unit.starts_with("lifecycle:"));
        assert_eq!(u.writes.len(), 1);
        assert!(
            u.writes[0].remove.is_empty(),
            "a signal keeps its family label: {u:?}"
        );
        assert!(u.writes[0].add.contains(&"resolved".to_string()));
    }
    let grad = units
        .iter()
        .find(|u| u.unit == format!("lifecycle:{}", id(0x7000_0001)))
        .expect("graduation");
    assert!(
        grad.writes[0]
            .add
            .contains(&format!("graduated-to:{}", id(0x7000_0003))),
        "the target is a typed claim id: {grad:?}"
    );
}

#[test]
fn every_added_label_passes_the_write_path_validator() {
    let p = plan_graph(
        &profile(),
        &graph(),
        &all_sections(),
        Some(date("2026-10-05")),
    );
    let units = p.write_units();
    assert!(!units.is_empty());
    for u in &units {
        for w in &u.writes {
            epigraph_db::reject_unexpanded_labels(&w.add).unwrap_or_else(|e| panic!("{u:?}: {e}"));
            // A label in both lists would make the result depend on whether
            // the write path removes or adds first; the replan-empty tests
            // assume it never does.
            assert!(
                w.add.iter().all(|l| !w.remove.contains(l)),
                "add and remove overlap: {w:?}"
            );
            for l in &w.add {
                assert!(
                    !l.contains('{') && !l.contains('}'),
                    "unexpanded template: {l}"
                );
                assert_eq!(l.trim(), l, "no padding: {l:?}");
                assert!(!l.is_empty());
            }
        }
    }
}
