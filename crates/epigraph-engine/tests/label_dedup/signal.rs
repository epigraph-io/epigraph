//! The signal passes: a second family deduplicated on its own index, and its
//! members that became a family member leave the signal family.

use epigraph_engine::label_dedup::{LabelDedupProfile, Section};

use crate::fixtures::{self as f, apply_units, claim, id, plan_graph, RUN_TAG};

fn signal_profile() -> LabelDedupProfile {
    let mut v = f::profile_value();
    let o = v.as_object_mut().expect("object");
    o.remove("lifecycle");
    // `lead` is the signal family here, not bookkeeping.
    o["non_member"]["labels_any"] = serde_json::json!(["notice-run-status"]);
    o.insert(
        "signal_dedup".into(),
        serde_json::json!({
            "family_label": "lead",
            "family_kind": "index",
            "closed_label": "resolved",
            "retired_labels": ["lead-dropped", "lead-duplicate"],
            "hygiene_write": {"add": ["lead-dropped", "{run_tag}"], "remove": ["{family}"]},
            "fields": {
                "entity": {"pipe_position": 1},
                "deadline": {"keys": ["due "]}
            },
            "ids": {"reject": ["iso_date", "us_date", "bare_year", "money", "clock_time"]},
            "entity_match": {"aliases": [["amc", "acme medical center"]]},
            "merge": {
                "survivor_add": ["{run_tag}"]
            }
        }),
    );
    o.insert(
        "signal_superseded_by_member".into(),
        serde_json::json!({
            "add": ["lead-dropped", "superseded-by:{target}", "{run_tag}"],
            "remove": ["{family}"],
            "require": ["strong_id", "exact_entity_title"]
        }),
    );
    f::load(&v)
}

fn sections() -> Vec<Section> {
    vec![Section::Hygiene, Section::Dedup, Section::SignalDedup]
}

fn graph() -> Vec<epigraph_engine::label_dedup::DedupClaim> {
    vec![
        // Two signals for one item (shared strong id): a signal cluster.
        claim(1, "Cold Room Chiller Swap PRJ-009001 | AMC | early design", &["lead"], "2026-06-01T00:00:00Z"),
        claim(2, "Room chiller swap, PRJ-009001 | Acme Medical Center | update", &["lead"], "2026-07-01T00:00:00Z"),
        // A signal that became a notice (shared strong id with a member).
        claim(3, "Boathouse Reuse Options PRJ-009002 | City of Acmeton | planning", &["lead"], "2026-06-01T00:00:00Z"),
        claim(10, "[OPEN] Boathouse Reuse Options Review TND PRJ-009002 | City of Acmeton | sector:city | due 2026-11-01 | est. unknown | study", &["notice", "src-direct-a"], "2026-09-01T00:00:00Z"),
        // A signal matching a member on exact entity + title, no id.
        claim(4, "Riverside Park Restroom Replacement | City of Acmeton | early", &["lead"], "2026-06-01T00:00:00Z"),
        claim(11, "[OPEN] Riverside Park Restroom Replacement | City of Acmeton | sector:city | due 2026-12-01 | est. unknown | design", &["notice", "src-direct-a"], "2026-09-01T00:00:00Z"),
        // A retired signal that kept its family label.
        claim(5, "Old item PRJ-009005 | AMC | stale", &["lead", "lead-dropped"], "2026-03-01T00:00:00Z"),
        // A signal with nothing to match.
        claim(6, "Harbor Lighting Retrofit PRJ-009006 | Acme Port Authority | early", &["lead"], "2026-06-01T00:00:00Z"),
    ]
}

#[test]
fn the_signal_family_is_deduplicated_on_its_own_index() {
    let p = plan_graph(&signal_profile(), &graph(), &sections(), None);
    let s = p.signal_dedup.as_ref().expect("signal pass planned");
    assert_eq!(s.family_label, "lead");
    let shape: Vec<_> = s
        .clusters
        .iter()
        .map(|c| {
            (
                c.survivor,
                c.members.iter().map(|m| m.id).collect::<Vec<_>>(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![(id(2), vec![id(1)])],
        "the newer signal survives: {:?}",
        s.clusters
    );
    // The older signal is marked a duplicate of the newer one, like a family
    // member: no label is written on it.
    let marks = s.clusters[0].marks();
    assert_eq!(
        marks
            .iter()
            .map(|m| (m.dup, m.canonical))
            .collect::<Vec<_>>(),
        vec![(id(1), id(2))]
    );
    let units = p.write_units();
    let unit = units
        .iter()
        .find(|u| u.unit == format!("signal_cluster:{}", id(2)))
        .expect("the signal cluster's unit");
    assert_eq!(unit.marks, marks);
    assert!(unit.writes.iter().all(|w| w.claim_id != id(1)), "{unit:?}");
    assert_eq!(
        s.hygiene.iter().map(|h| h.id).collect::<Vec<_>>(),
        vec![id(5)]
    );
    assert_eq!(
        s.hygiene[0].add,
        vec!["lead-dropped".to_string(), RUN_TAG.to_string()]
    );
    // A signal is never clustered with a family member.
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
}

#[test]
fn a_signal_that_became_a_member_leaves_the_signal_family() {
    let p = plan_graph(&signal_profile(), &graph(), &sections(), None);
    let got: Vec<_> = p
        .signal_superseded
        .iter()
        .map(|s| (s.id, s.target))
        .collect();
    assert_eq!(
        got,
        vec![(id(3), id(10)), (id(4), id(11))],
        "{:?}",
        p.signal_superseded
    );
    let s3 = &p.signal_superseded[0];
    assert_eq!(
        s3.add,
        vec![
            "lead-dropped".to_string(),
            format!("superseded-by:{}", id(10)),
            RUN_TAG.to_string()
        ]
    );
    assert_eq!(s3.remove, vec!["lead".to_string()]);
    // The signal loser is retired as a duplicate, never also superseded; the
    // unmatched signal is untouched.
    assert!(p
        .signal_superseded
        .iter()
        .all(|s| s.id != id(1) && s.id != id(6)));
}

#[test]
fn the_signal_passes_are_idempotent() {
    let g = graph();
    let first = plan_graph(&signal_profile(), &g, &sections(), None);
    let units = first.write_units();
    let kinds: Vec<_> = units
        .iter()
        .map(|u| u.unit.split(':').next().unwrap_or_default().to_string())
        .collect();
    for k in ["signal_hygiene", "signal_cluster", "signal_superseded"] {
        assert!(kinds.iter().any(|x| x == k), "{k}: {kinds:?}");
    }
    let applied = apply_units(&g, &units);
    let second = plan_graph(&signal_profile(), &applied, &sections(), None);
    assert!(second.is_empty(), "{:?}", second.write_units());
}

#[test]
fn the_signal_section_is_opt_in() {
    let p = plan_graph(
        &signal_profile(),
        &graph(),
        &[Section::Hygiene, Section::Dedup],
        None,
    );
    assert!(p.signal_dedup.is_none());
    assert!(p.signal_superseded.is_empty());
    let err = f::try_plan_graph(&f::profile(), &graph(), &[Section::SignalDedup], None, 5000)
        .expect_err("the main fixture profile has no signal pass");
    assert_eq!(err.code(), "SECTION_NOT_CONFIGURED");
}

#[test]
fn a_knowledge_signal_family_is_refused_only_when_its_pass_is_planned() {
    let mut v = f::profile_value();
    let o = v.as_object_mut().expect("object");
    o.remove("lifecycle");
    o["non_member"]["labels_any"] = serde_json::json!(["notice-run-status"]);
    o.insert(
        "signal_dedup".into(),
        serde_json::json!({
            "family_label": "lead",
            "family_kind": "knowledge",
            "hygiene_write": {"add": ["lead-dropped", "{run_tag}"], "remove": ["{family}"]},
            "fields": {"entity": {"pipe_position": 1}},
            "merge": {"survivor_add": ["{run_tag}"]}
        }),
    );
    let p = f::load(&v);
    let err = f::try_plan_graph(&p, &graph(), &sections(), None, 5000).expect_err("refused");
    assert!(
        matches!(&err, epigraph_engine::label_dedup::LabelDedupError::FamilyNotIndex { family_label, .. } if family_label == "lead"),
        "{err:?}"
    );
    // Control: without the signal section the main family plans.
    f::try_plan_graph(
        &p,
        &graph(),
        &[Section::Hygiene, Section::Dedup],
        None,
        5000,
    )
    .expect("the signal pass is not planned");
}

#[test]
fn a_signal_cluster_touching_a_main_member_is_left_for_a_human() {
    // X carries BOTH family labels. It clusters with M in the main family and
    // with Y in the signal family. A mark retires a claim from every family, so
    // the signal cluster is not marked; it is reported instead.
    let mut g = graph();
    g.push(claim(
        20,
        "[OPEN] Imaging Suite Fit-Out TND PRJ-009077 | Acme Medical Center | sector:health | due 2026-12-01 | est. unknown | fit-out",
        &["notice", "lead", "src-direct-a"],
        "2026-08-01T00:00:00Z",
    ));
    g.push(claim(
        21,
        "[OPEN] Imaging Suite Fit-Out TND PRJ-009077 | Acme Medical Center | sector:health | due 2026-12-01 | est. unknown | fit-out (feed)",
        &["notice"],
        "2026-08-02T00:00:00Z",
    ));
    g.push(claim(
        22,
        "Imaging suite fit-out PRJ-009077 | AMC | signal",
        &["lead"],
        "2026-09-01T00:00:00Z",
    ));
    let p = plan_graph(&signal_profile(), &g, &sections(), None);
    let main_marked: Vec<_> = p
        .clusters
        .iter()
        .flat_map(|c| c.marks())
        .map(|m| m.dup)
        .collect();
    assert!(
        main_marked.contains(&id(21)),
        "calibration: the main pair merges {:?}",
        p.clusters
    );
    let s = p.signal_dedup.as_ref().expect("signal pass");
    assert!(
        s.clusters.iter().all(|c| c.survivor != id(20)
            && c.survivor != id(22)
            && c.members.iter().all(|m| m.id != id(20) && m.id != id(22))),
        "{:?}",
        s.clusters
    );
    assert_eq!(s.cross_family.len(), 1, "{:?}", s.cross_family);
    // Control: the ordinary signal cluster is still marked.
    assert!(s.clusters.iter().any(|c| c.survivor == id(2)));
}

#[test]
fn lifecycle_skips_a_signal_this_plan_marks_a_duplicate() {
    // Two signals for one item that already has a notice. Both would graduate;
    // the older one is marked a duplicate of the newer one by the signal pass,
    // so only the newer one graduates (the marked one is retired by its mark).
    let mut v = f::profile_value();
    let o = v.as_object_mut().expect("object");
    o["non_member"]["labels_any"] = serde_json::json!(["notice-run-status"]);
    o.insert(
        "signal_dedup".into(),
        serde_json::json!({
            "family_label": "lead",
            "family_kind": "index",
            "closed_label": "resolved",
            "hygiene_write": {"add": ["lead-dropped", "{run_tag}"], "remove": ["{family}"]},
            "fields": {"entity": {"pipe_position": 1}},
            "merge": {"survivor_add": ["{run_tag}"]}
        }),
    );
    let p = f::load(&v);
    let g = vec![
        claim(1, "Boathouse Reuse Options PRJ-009002 | City of Acmeton | planning", &["lead"], "2026-06-01T00:00:00Z"),
        claim(2, "Boathouse reuse options, PRJ-009002 | City of Acmeton | update", &["lead"], "2026-07-01T00:00:00Z"),
        claim(10, "[OPEN] Boathouse Reuse Options Review TND PRJ-009002 | City of Acmeton | sector:city | due 2026-11-01 | est. unknown | study", &["notice", "src-direct-a"], "2026-09-01T00:00:00Z"),
    ];
    let sections = [Section::Lifecycle, Section::SignalDedup];
    let plan = plan_graph(&p, &g, &sections, Some(f::date("2026-10-05")));
    let s = plan.signal_dedup.as_ref().expect("signal pass");
    assert_eq!(
        s.clusters
            .iter()
            .map(|c| (c.survivor, c.marks().len()))
            .collect::<Vec<_>>(),
        vec![(id(2), 1)],
        "calibration: the older signal is marked"
    );
    let graduated: Vec<_> = plan.lifecycle.iter().map(|a| a.id).collect();
    assert_eq!(graduated, vec![id(2)], "{:?}", plan.lifecycle);
}
