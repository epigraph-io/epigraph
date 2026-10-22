//! Past-due close-out.

use epigraph_engine::label_dedup::record::parse_content;
use epigraph_engine::label_dedup::{DedupClaim, LabelDedupProfile, Section};

use crate::fixtures::{
    self as f, claim, date, id, legacy_profile, pass, plan_graph, profile, RUN_TAG,
};

fn closeout_sections() -> Vec<Section> {
    vec![Section::Hygiene, Section::Dedup, Section::Closeout]
}

fn past_due_ids(prof: &LabelDedupProfile, graph: &[DedupClaim], as_of: &str) -> Vec<uuid::Uuid> {
    plan_graph(prof, graph, &closeout_sections(), Some(date(as_of)))
        .past_due
        .into_iter()
        .map(|p| p.id)
        .collect()
}

#[test]
fn closeout_reads_the_deadline_field_and_never_guesses() {
    // Preconditions: close-out reads the PARSED deadline, so pin it.
    let p = pass();
    assert_eq!(
        parse_content(&p, f::AGREEMENT_Q23_NEW).deadline.as_deref(),
        Some("2026-06-30")
    );
    assert_eq!(
        parse_content(&p, f::WEIR_LATE).deadline.as_deref(),
        Some("2026-07-15"),
        "the deadline field already carries the extension"
    );
    assert_eq!(parse_content(&p, f::BENCH_KEYED).deadline, None);
    assert_eq!(parse_content(&p, f::MURAL_STD).deadline, None);
    assert_eq!(
        parse_content(&p, f::KIOSK_UNIT).deadline.as_deref(),
        Some("2026-09-17")
    );
    assert_eq!(
        parse_content(&p, f::KIOSK_CAFE).deadline.as_deref(),
        Some("2026-11-23")
    );

    let graph = vec![
        claim(
            1,
            f::AGREEMENT_Q23_NEW,
            &["notice", "src-direct-a"],
            "2026-07-19T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
        claim(3, f::BENCH_KEYED, &["notice"], "2026-05-19T00:00:00Z"),
        claim(
            4,
            f::MURAL_STD,
            &["notice", "src-direct-a"],
            "2026-06-28T00:00:00Z",
        ),
        claim(
            5,
            f::KIOSK_CAFE,
            &["notice", "src-direct-a"],
            "2026-07-19T00:00:00Z",
        ),
        claim(
            6,
            f::KIOSK_UNIT,
            &["notice", "src-direct-a"],
            "2026-07-19T00:00:00Z",
        ),
        claim(
            7,
            f::PROSE_DUE_MULTIBYTE,
            &["notice", "src-direct-a"],
            "2026-09-01T00:00:00Z",
        ),
        // Retired but still wearing the family label: hygiene owns it.
        claim(
            8,
            f::AGREEMENT_Q22_NEW,
            &["notice", "notice-dropped"],
            "2026-07-19T00:00:00Z",
        ),
    ];
    for prof in [profile(), legacy_profile()] {
        // Missing, TBD, prose and future deadlines stay open; a retired claim is hygiene.
        assert_eq!(
            past_due_ids(&prof, &graph, "2026-10-05"),
            vec![id(1), id(2), id(6)]
        );
        // The deadline field (07-15) decides; the earlier date in the prose is ignored.
        assert_eq!(past_due_ids(&prof, &graph, "2026-07-01"), vec![id(1)]);
        // The comparison is strict: an item whose deadline is as_of stays open.
        assert_eq!(
            past_due_ids(&prof, &graph, "2026-09-17"),
            vec![id(1), id(2)]
        );
    }
    // No close-out section, no close-out writes.
    let p = plan_graph(
        &profile(),
        &graph,
        &[Section::Hygiene, Section::Dedup],
        Some(date("2026-10-05")),
    );
    assert!(p.past_due.is_empty());
}

#[test]
fn survivor_is_judged_by_latest_deadline_in_its_cluster() {
    // The direct claim (06-17) outranks the feed claim holding the later 07-15.
    // The survivor is judged by the latest date in its cluster, not its own.
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    for prof in [profile(), legacy_profile()] {
        let early = plan_graph(
            &prof,
            &graph,
            &closeout_sections(),
            Some(date("2026-07-01")),
        );
        assert_eq!(early.clusters.len(), 1, "the pair must cluster");
        assert_eq!(early.clusters[0].survivor, id(1));
        assert!(
            early.past_due.is_empty(),
            "the extension keeps it open on 07-01: {:?}",
            early.past_due
        );

        let later = plan_graph(
            &prof,
            &graph,
            &closeout_sections(),
            Some(date("2026-07-16")),
        );
        assert_eq!(later.past_due.len(), 1, "{:?}", later.past_due);
        assert_eq!(later.past_due[0].id, id(1), "only the survivor is closed");
        assert_eq!(later.past_due[0].due, date("2026-07-15"));
        assert!(
            later.clusters[0].members.iter().any(|m| m.id == id(2)),
            "the re-filing is retired, not closed"
        );
    }
}

#[test]
fn survivor_without_a_deadline_never_borrows_one() {
    let graph = vec![
        claim(
            1,
            f::FENDER_DIRECT_NO_DUE,
            &["notice", "src-direct-a"],
            "2026-05-01T00:00:00Z",
        ),
        claim(2, f::FENDER_FEED, &["notice"], "2026-05-10T00:00:00Z"),
    ];
    for prof in [profile(), legacy_profile()] {
        let p = plan_graph(
            &prof,
            &graph,
            &closeout_sections(),
            Some(date("2026-10-05")),
        );
        assert_eq!(p.clusters.len(), 1, "the shared id must cluster");
        assert_eq!(p.clusters[0].survivor, id(1));
        assert!(
            p.past_due.is_empty(),
            "no own ISO deadline stays open: {:?}",
            p.past_due
        );
        assert!(
            !p.clusters[0]
                .carry_add
                .iter()
                .any(|l| l.starts_with("due-carried:")),
            "no deadline is invented for a survivor without one: {:?}",
            p.clusters[0].carry_add
        );
    }
}

#[test]
fn a_disagreeing_deadline_is_reported_and_never_stranded() {
    // The loser holds the later deadline. It is reported as a disagreement,
    // and nothing is "stranded": the loser is marked a duplicate, keeps its
    // date, and the survivor is read with it.
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    let p = plan_graph(
        &profile(),
        &graph,
        &closeout_sections(),
        Some(date("2026-07-01")),
    );
    let c = &p.clusters[0];
    assert!(
        c.conflicts.iter().any(|m| m.contains("deadline")
            && m.contains("2026-06-17")
            && m.contains("2026-07-15")),
        "{:?}",
        c.conflicts
    );
    assert!(
        !c.conflicts.iter().any(|m| m.contains("stranded")),
        "{:?}",
        c.conflicts
    );
    assert_eq!(c.marks().len(), 1, "the loser is marked, not dropped");
}

#[test]
fn a_duplicates_deadline_defers_closeout_across_runs() {
    // The merge writes no date onto the survivor. After the marks apply the
    // loser is out of the index but read under the survivor, and the NEXT run
    // still judges the survivor by the loser's 07-15.
    let graph = vec![
        claim(
            1,
            f::WEIR_EARLY,
            &["notice", "src-direct-a"],
            "2026-04-27T00:00:00Z",
        ),
        claim(2, f::WEIR_LATE, &["notice"], "2026-06-20T00:00:00Z"),
    ];
    let first = plan_graph(
        &profile(),
        &graph,
        &closeout_sections(),
        Some(date("2026-07-01")),
    );
    let c = &first.clusters[0];
    assert!(
        !c.carry_add.iter().any(|l| l.contains("-carried:")),
        "{:?}",
        c.carry_add
    );
    let applied = f::apply_units(&graph, &first.write_units());
    assert_eq!(applied.len(), 1, "the loser left the index");

    let second = plan_graph(
        &profile(),
        &applied,
        &closeout_sections(),
        Some(date("2026-07-10")),
    );
    assert!(
        second.past_due.is_empty(),
        "the duplicate's 07-15 keeps it open on 07-10: {:?}",
        second.past_due
    );
    let third = plan_graph(
        &profile(),
        &applied,
        &closeout_sections(),
        Some(date("2026-07-16")),
    );
    assert_eq!(
        third
            .past_due
            .iter()
            .map(|p| (p.id, p.due))
            .collect::<Vec<_>>(),
        vec![(id(1), date("2026-07-15"))]
    );

    // Control: read WITHOUT its duplicate (an index read that does not follow
    // the identity edges), the survivor closes on 07-10 by its own 06-17.
    let mut bare = applied;
    bare[0].duplicates.clear();
    let blind = plan_graph(
        &profile(),
        &bare,
        &closeout_sections(),
        Some(date("2026-07-10")),
    );
    assert_eq!(
        blind.past_due.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![id(1)]
    );
}

#[test]
fn closeout_writes_keep_the_family_label() {
    let graph = vec![claim(
        1,
        f::AGREEMENT_Q23_NEW,
        &["notice", "src-direct-a"],
        "2026-07-19T00:00:00Z",
    )];
    let p = plan_graph(
        &profile(),
        &graph,
        &closeout_sections(),
        Some(date("2026-10-05")),
    );
    assert_eq!(p.past_due.len(), 1);
    assert!(
        !p.is_empty(),
        "a plan that closes an item changes the graph"
    );
    assert!(
        p.clusters.is_empty() && p.hygiene.is_empty(),
        "closing is not a retirement"
    );
    let units = p.write_units();
    assert_eq!(units.len(), 1, "{units:?}");
    assert_eq!(units[0].unit, format!("closeout:{}", id(1)));
    assert_eq!(units[0].writes.len(), 1);
    let w = &units[0].writes[0];
    assert_eq!(
        w.add,
        vec![
            "resolved".to_string(),
            "closed-past-due".to_string(),
            RUN_TAG.to_string()
        ]
    );
    assert!(
        w.remove.is_empty(),
        "closing keeps the family label: {:?}",
        w.remove
    );
}

#[test]
fn a_duplicates_date_alone_never_closes_a_claim() {
    // Close-out acts only on a claim whose own content carries a date; a
    // duplicate's date extends that date, it never stands in for it.
    let mut undated = claim(
        1,
        f::FENDER_DIRECT_NO_DUE,
        &["notice", "src-direct-a"],
        "2026-05-01T00:00:00Z",
    );
    undated.duplicates = vec![claim(2, f::WEIR_EARLY, &["notice"], "2026-04-01T00:00:00Z")];
    let p = plan_graph(
        &profile(),
        &[undated],
        &closeout_sections(),
        Some(date("2026-10-05")),
    );
    assert!(p.past_due.is_empty(), "{:?}", p.past_due);
    // Control: a duplicate's later date on a claim WITH its own date counts.
    let mut dated = claim(
        1,
        f::FENDER_DIRECT_HELD,
        &["notice", "src-direct-a"],
        "2026-05-01T00:00:00Z",
    );
    dated.duplicates = vec![claim(
        2,
        "Tender: Dock 4 Fender Rebuild TND 0000029912 — Acme Port Authority, due 2026-11-01.",
        &["notice"],
        "2026-05-10T00:00:00Z",
    )];
    let p = plan_graph(
        &profile(),
        std::slice::from_ref(&dated),
        &closeout_sections(),
        Some(date("2026-10-05")),
    );
    assert!(
        p.past_due.is_empty(),
        "the duplicate's 11-01 keeps it open: {:?}",
        p.past_due
    );
    let p = plan_graph(
        &profile(),
        &[dated],
        &closeout_sections(),
        Some(date("2026-11-02")),
    );
    assert_eq!(
        p.past_due.iter().map(|x| x.due).collect::<Vec<_>>(),
        vec![date("2026-11-01")]
    );
}
