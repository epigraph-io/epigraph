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
