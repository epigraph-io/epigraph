//! Whole-plan behaviour over the corpus.

use epigraph_engine::label_dedup::{LabelDedupError, Section};

use crate::fixtures::{
    self as f, claim, cluster_shape, corpus, dedup_sections, id, legacy_profile, plan_graph,
    profile, t, try_plan_graph,
};

#[test]
fn corpus_plan_finds_every_known_duplicate_and_nothing_else() {
    for prof in [profile(), legacy_profile()] {
        let p = plan_graph(&prof, &corpus(), &dedup_sections(), None);
        let mut expected = vec![
            (id(t::WEIR_LATE), vec![id(t::WEIR_EARLY)]),
            (id(t::HOIST_REVIEW), vec![id(t::HOIST_LISTED)]),
            (id(t::WING_DIRECT), vec![id(t::WING_FEED)]),
            (id(t::Q23_NEW), vec![id(t::Q23_OLD)]),
            (id(t::PANEL_NEW), vec![id(t::PANEL_OLD)]),
        ];
        expected.sort();
        assert_eq!(cluster_shape(&p), expected, "exactly the five known pairs");

        let review: Vec<_> = p.review_pairs.iter().map(|r| (r.left, r.right)).collect();
        assert_eq!(review, vec![(id(t::MURAL_STD), id(t::MURAL_MSB))]);

        let hygiene: Vec<_> = p.hygiene.iter().map(|h| h.id).collect();
        assert_eq!(hygiene, vec![id(t::STATUS), id(t::DROPPED)]);

        assert_eq!(p.coverage.members, 21);
        assert!(!p.coverage.truncated);
        assert!(
            p.vetoed_chains.is_empty(),
            "no transitive veto chain in the corpus: {:?}",
            p.vetoed_chains
        );
    }
}

#[test]
fn cluster_conflicts_name_disagreeing_fields() {
    let p = plan_graph(&profile(), &corpus(), &dedup_sections(), None);
    let hoist = p
        .clusters
        .iter()
        .find(|c| c.survivor == id(t::HOIST_REVIEW))
        .expect("hoist cluster");
    assert!(
        hoist.conflicts.iter().any(|c| c.contains("class")),
        "two classes for one item: {:?}",
        hoist.conflicts
    );
    let weir = p
        .clusters
        .iter()
        .find(|c| c.survivor == id(t::WEIR_LATE))
        .expect("weir cluster");
    assert!(
        weir.conflicts.iter().any(|c| c.contains("deadline")
            && c.contains("2026-06-17")
            && c.contains("2026-07-15")),
        "an extension is flagged: {:?}",
        weir.conflicts
    );
    let wing = p
        .clusters
        .iter()
        .find(|c| c.survivor == id(t::WING_DIRECT))
        .expect("wing cluster");
    assert!(
        wing.conflicts.is_empty(),
        "identical records disagree on nothing: {:?}",
        wing.conflicts
    );
}

#[test]
fn empty_and_singleton_inputs_produce_no_writes() {
    let p = plan_graph(&profile(), &[], &dedup_sections(), None);
    assert!(p.is_empty());
    assert!(p.write_units().is_empty());
    let one = vec![claim(
        1,
        f::WING_DIRECT,
        &["notice", "src-direct-c"],
        "2026-06-29T00:00:00Z",
    )];
    let p = plan_graph(&profile(), &one, &dedup_sections(), None);
    assert!(p.is_empty());
    // Control: a pair is not empty.
    let two = vec![
        claim(
            1,
            f::WING_DIRECT,
            &["notice", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        claim(
            2,
            f::WING_FEED,
            &["notice", "src-feed"],
            "2026-06-28T00:00:00Z",
        ),
    ];
    assert!(!plan_graph(&profile(), &two, &dedup_sections(), None).is_empty());
}

#[test]
fn closeout_and_lifecycle_need_an_explicit_as_of() {
    for section in [Section::Closeout, Section::Lifecycle] {
        let err = try_plan_graph(&profile(), &corpus(), &[section], None, 5000)
            .expect_err("as_of is never defaulted");
        assert_eq!(err.code(), "AS_OF_REQUIRED", "{err}");
    }
    // Control: with a date it plans.
    try_plan_graph(
        &profile(),
        &corpus(),
        &[Section::Closeout],
        Some(f::date("2026-10-05")),
        5000,
    )
    .expect("plans with as_of");
}

#[test]
fn an_unconfigured_section_is_refused() {
    let mut v = f::profile_value();
    v.as_object_mut().expect("object").remove("lifecycle");
    v.as_object_mut().expect("object").remove("merge");
    let p = f::load(&v);
    let err = try_plan_graph(
        &p,
        &corpus(),
        &[Section::Lifecycle],
        Some(f::date("2026-10-05")),
        5000,
    )
    .expect_err("no lifecycle configured");
    assert!(
        matches!(
            err,
            LabelDedupError::SectionNotConfigured {
                section: Section::Lifecycle
            }
        ),
        "{err}"
    );
    let err = try_plan_graph(&p, &corpus(), &[Section::Dedup], None, 5000)
        .expect_err("no merge configured");
    assert!(
        matches!(
            err,
            LabelDedupError::SectionNotConfigured {
                section: Section::Dedup
            }
        ),
        "{err}"
    );
    // Control: hygiene alone needs only hygiene_write.
    let ok = try_plan_graph(&p, &corpus(), &[Section::Hygiene], None, 5000).expect("hygiene plans");
    assert_eq!(ok.hygiene.len(), 2);
}

#[test]
fn an_invalid_run_tag_is_refused() {
    let prof = profile();
    let inputs = epigraph_engine::label_dedup::PlanInputs::default();
    for bad in ["", "two words", "cost$", "{run_tag}"] {
        let req = epigraph_engine::label_dedup::PlanRequest {
            profile: &prof,
            profile_hash: "00",
            run_tag: bad,
            as_of: None,
            sections: &[],
        };
        let err = epigraph_engine::label_dedup::plan(&req, &inputs).expect_err(bad);
        assert_eq!(err.code(), "INVALID_RUN_TAG", "{bad:?}: {err}");
    }
    let req = epigraph_engine::label_dedup::PlanRequest {
        profile: &prof,
        profile_hash: "00",
        run_tag: "notice-dedup-2026-10-05",
        as_of: None,
        sections: &[],
    };
    let p = epigraph_engine::label_dedup::plan(&req, &inputs).expect("valid tag");
    assert_eq!(
        p.sections,
        vec![Section::Hygiene, Section::Dedup],
        "empty means the default set"
    );
}

/// Dedup compares every pair of members, so its cost grows with the square of
/// the family. A family past the bound is refused with RESOURCE_CAP instead of
/// running unbounded; the operator narrows the pass.
#[test]
fn a_family_past_the_pairwise_bound_is_refused() {
    let cap = epigraph_engine::label_dedup::MAX_DEDUP_FAMILY_MEMBERS;
    let graph: Vec<_> = (0..=cap as u32)
        .map(|i| {
            claim(
                0x7000_0000 + i,
                &format!("Synthetic notice number {i} for ACME-{i:06}"),
                &["notice"],
                "2026-07-01T00:00:00Z",
            )
        })
        .collect();
    let err = try_plan_graph(&profile(), &graph, &dedup_sections(), None, cap + 10)
        .expect_err("a family larger than the pairwise bound must be refused");
    assert_eq!(err.code(), "RESOURCE_CAP", "{err}");
    // Control: at the bound it plans.
    let ok = try_plan_graph(&profile(), &graph[..cap], &dedup_sections(), None, cap + 10);
    assert!(ok.is_ok(), "{:?}", ok.err());
}
