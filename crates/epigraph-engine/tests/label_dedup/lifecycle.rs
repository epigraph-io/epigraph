//! Signal lifecycle: graduation into a member, or age-out.

use epigraph_engine::label_dedup::{
    plan, DedupClaim, LifecycleAction, LifecycleKind, PlanInputs, PlanRequest, Section, Snapshot,
};

use crate::fixtures::{self as f, claim, date, id, plan_graph, profile, RUN_TAG};

fn lifecycle(graph: &[DedupClaim], as_of: &str) -> Vec<LifecycleAction> {
    plan_graph(&profile(), graph, &[Section::Lifecycle], Some(date(as_of))).lifecycle
}

fn kind(acts: &[LifecycleAction], tag: u32) -> Option<LifecycleKind> {
    acts.iter()
        .find(|a| a.id == id(tag))
        .map(|a| a.kind.clone())
}

#[test]
fn graduates_on_shared_strong_id_and_ages_out_on_received_date() {
    let graph = vec![
        claim(
            1,
            f::LEAD_CHILLER,
            &["lead", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        // 193 days old by its received date.
        claim(
            2,
            f::LEAD_PERMIT_OLD,
            &["lead", "src-direct-b"],
            "2026-06-29T00:00:00Z",
        ),
        // 117 days old by its received date, 187 by created_at: the
        // received date wins.
        claim(
            3,
            f::LEAD_PERMIT_YOUNG,
            &["lead", "src-direct-b"],
            "2026-04-01T00:00:00Z",
        ),
        // An umbrella with no id, 15 days old: no action.
        claim(
            4,
            f::LEAD_FUND,
            &["lead", "src-direct-b"],
            "2026-09-20T00:00:00Z",
        ),
        claim(
            10,
            f::NOTICE_CHILLER,
            &["notice", "src-direct-c"],
            "2026-10-04T00:00:00Z",
        ),
        claim(
            11,
            f::NOTICE_SAME_US_DATE,
            &["notice", "src-direct-a"],
            "2026-10-04T00:00:00Z",
        ),
    ];
    let acts = lifecycle(&graph, "2026-10-05");
    assert_eq!(
        kind(&acts, 1),
        Some(LifecycleKind::Graduated { target: id(10) }),
        "{acts:?}"
    );
    // Sharing a calendar date with a notice is not sharing an id.
    assert_eq!(
        kind(&acts, 2),
        Some(LifecycleKind::AgedOut {
            key_date: date("2026-03-26")
        }),
        "{acts:?}"
    );
    assert_eq!(kind(&acts, 3), None, "117 days is under the cutoff");
    assert_eq!(kind(&acts, 4), None);
    assert_eq!(acts.len(), 2, "{acts:?}");
    assert_eq!(
        acts[0].add,
        vec![
            "resolved".to_string(),
            "materialized".to_string(),
            format!("graduated-to:{}", id(10)),
            RUN_TAG.to_string()
        ]
    );
    assert_eq!(
        acts[1].add,
        vec![
            "resolved".to_string(),
            "closed-past-due".to_string(),
            "aged-out".to_string(),
            RUN_TAG.to_string()
        ]
    );
}

#[test]
fn umbrella_signals_never_graduate() {
    let notice = claim(
        10,
        "[OPEN] Ridge High Roof Recover TND 02-318500 | Acme School District | sector:school | trade:arch | due 2026-11-01 | est. unknown | roof design",
        &["notice", "src-direct-b"],
        "2026-10-04T00:00:00Z",
    );
    let c = "2026-09-20T00:00:00Z";
    let leads = vec![
        claim(1, "Lead: Program office share-out list for Acme SD, item 02-318500 among many | sector:school", &["lead"], c),
        claim(2, "Lead: FUND signal — board clears Acme SD items, one is 02-318500 | sector:school", &["lead"], c),
        claim(3, "Lead: Acme SD sends a batch of 6 permit files, 02-318500 included | sector:school", &["lead"], c),
        claim(4, "Lead: County budget line names Ridge High 02-318500 for Acme SD | sector:school", &["lead"], c),
        claim(5, "Lead: New legislation lists Ridge High 02-318500 for Acme SD | sector:school", &["lead"], c),
        claim(6, "Lead: Acme SD umbrella plan covers Ridge High 02-318500 | sector:school", &["lead"], c),
        claim(7, "Lead: Acme SD bond program slate has Ridge High 02-318500 | sector:school", &["lead"], c),
        claim(8, "Lead: Acme SD bond measure vote lists Ridge High 02-318500 | sector:school", &["lead"], c),
        // Control: the same id on a single-item signal graduates.
        claim(9, "Lead: permit project roof recover at Ridge High, Acme SD | sector:school | permit App 02-318500 | Est $7,500,000 | permit state:PENDING (recv 9/1/2026)", &["lead"], c),
    ];
    let mut graph = leads;
    graph.push(notice);
    let acts = lifecycle(&graph, "2026-10-05");
    assert_eq!(
        kind(&acts, 9),
        Some(LifecycleKind::Graduated { target: id(10) }),
        "{acts:?}"
    );
    for tag in 1..=8 {
        assert_eq!(
            kind(&acts, tag),
            None,
            "signal {tag} is an umbrella: {acts:?}"
        );
    }
}

#[test]
fn age_out_is_strictly_older_than_the_cutoff() {
    let row = |tag: u32, recv: &str| {
        claim(
            tag,
            &format!("Lead: permit project ramp works at Elm School, Oak SD | sector:school | permit App 02-1{tag:05} | permit state:PENDING (recv {recv})"),
            &["lead"],
            "2026-10-01T00:00:00Z",
        )
    };
    // 120 days (06-07) stays; 121 days (06-06) ages out.
    let acts = lifecycle(&[row(1, "6/7/2026"), row(2, "6/6/2026")], "2026-10-05");
    assert_eq!(kind(&acts, 1), None, "exactly 120 days stays");
    assert_eq!(
        kind(&acts, 2),
        Some(LifecycleKind::AgedOut {
            key_date: date("2026-06-06")
        })
    );
}

#[test]
fn age_key_chain_order() {
    let created = "2026-05-01T12:00:00Z";
    let aged = |content: &str, created: Option<&str>| -> Option<LifecycleKind> {
        let mut c = claim(
            1,
            content,
            &["lead"],
            created.unwrap_or("2026-05-01T12:00:00Z"),
        );
        if created.is_none() {
            c.created_at = None;
        }
        // as_of far in the future: every keyed signal ages out, so the key
        // date it reports is the key the chain chose.
        let acts = lifecycle(&[c], "2030-01-01");
        acts.into_iter().next().map(|a| a.kind)
    };
    let key = |d: &str| Some(LifecycleKind::AgedOut { key_date: date(d) });
    assert_eq!(
        aged(f::LEAD_PERMIT_OLD, Some(created)),
        key("2026-03-26"),
        "`recv M/D/YYYY`"
    );
    assert_eq!(
        aged("Lead: permit project Court Resurface at Pine High, Birch SD | sector:school | permit 01-323022 | permit state:approved | received:4/18/2025 | est:$1,600,000 | notes:court", Some(created)),
        key("2025-04-18"),
        "`received:<date>`"
    );
    assert_eq!(
        aged(
            "Lead: permit job at Q School | permit state:APPROVED 8/11/2025 (received:4/18/2025)",
            Some(created)
        ),
        key("2025-04-18"),
        "received wins over approved"
    );
    assert_eq!(
        aged(
            "Lead: permit job at Q School | permit App 02-323456 | permit state:APPROVED 8/11/2025",
            Some(created)
        ),
        key("2025-08-11"),
        "approved only"
    );
    assert_eq!(
        aged(f::LEAD_FUND, Some(created)),
        key("2026-05-01"),
        "no keyword: created_at"
    );
    assert_eq!(
        aged(
            "Lead: permit job at R School | permit state:FILED (received date pending)",
            Some(created)
        ),
        key("2026-05-01"),
        "`received date` is not a date"
    );
    assert_eq!(
        aged(f::LEAD_FUND, None),
        None,
        "no key and no created_at: never ages out"
    );
}

#[test]
fn closed_signals_are_skipped_and_retired_members_are_never_targets() {
    // Explicit snapshots: the in-code guards must hold even when a read
    // returns rows it should have excluded.
    let signals = Snapshot::from_capped(
        vec![
            claim(
                1,
                f::LEAD_CHILLER,
                &["lead", "resolved", "materialized"],
                "2026-06-29T00:00:00Z",
            ),
            claim(
                2,
                f::LEAD_CHILLER,
                &["lead", "src-direct-c"],
                "2026-06-29T00:00:00Z",
            ),
        ],
        5000,
    );
    let targets = Snapshot::from_capped(
        vec![
            claim(
                10,
                f::NOTICE_CHILLER,
                &["notice", "notice-duplicate"],
                "2026-10-04T00:00:00Z",
            ),
            claim(
                11,
                f::NOTICE_CHILLER,
                &["notice", "notice-dropped"],
                "2026-10-04T00:00:00Z",
            ),
            claim(
                12,
                f::NOTICE_CHILLER,
                &["notice", "listed-final"],
                "2026-10-04T00:00:00Z",
            ),
            claim(
                13,
                &format!("[DROPPED] {}", f::NOTICE_CHILLER),
                &["notice"],
                "2026-10-04T00:00:00Z",
            ),
            claim(
                14,
                f::NOTICE_CHILLER,
                &["notice", "resolved", "closed-past-due"],
                "2026-10-01T00:00:00Z",
            ),
        ],
        5000,
    );
    let prof = profile();
    let req = PlanRequest {
        profile: &prof,
        profile_hash: "00",
        run_tag: RUN_TAG,
        as_of: Some(date("2026-10-05")),
        sections: &[Section::Lifecycle],
    };
    let inputs = PlanInputs {
        members: Snapshot::default(),
        lifecycle_signals: Some(signals),
        lifecycle_targets: Some(targets),
        signal_members: None,
    };
    let acts = plan(&req, &inputs).expect("plan").lifecycle;
    assert_eq!(
        kind(&acts, 1),
        None,
        "an already closed signal is not touched again: {acts:?}"
    );
    assert_eq!(
        kind(&acts, 2),
        Some(LifecycleKind::Graduated { target: id(14) }),
        "every live target is retired, so the closed one is the target: {acts:?}"
    );
}

#[test]
fn live_target_beats_closed_target() {
    let graph = vec![
        claim(
            1,
            f::LEAD_CHILLER,
            &["lead", "src-direct-c"],
            "2026-06-29T00:00:00Z",
        ),
        // The closed target sorts first; the live one must still win.
        claim(
            10,
            f::NOTICE_CHILLER,
            &["notice", "resolved", "closed-past-due"],
            "2026-10-01T00:00:00Z",
        ),
        claim(
            20,
            f::NOTICE_CHILLER,
            &["notice", "src-direct-c"],
            "2026-10-04T00:00:00Z",
        ),
    ];
    let acts = lifecycle(&graph, "2026-10-05");
    assert_eq!(
        kind(&acts, 1),
        Some(LifecycleKind::Graduated { target: id(20) }),
        "{acts:?}"
    );
}

#[test]
fn graduation_beats_age_out() {
    // Aged out instead, the signal would close without its `graduated-to:`
    // link, and a closed signal is never planned again.
    let graph = vec![
        claim(1, f::LEAD_CHILLER, &["lead"], "2026-05-01T00:00:00Z"),
        claim(
            2,
            "Lead: permit project Chiller Swap PRJ-007731 at the Cold Room, AMC | sector:univ | permit App 01-310082 | Est $2,900,000 | permit state:PENDING (recv 3/26/2026) | notes: cold room chiller swap",
            &["lead"],
            "2026-06-29T00:00:00Z",
        ),
        claim(10, f::NOTICE_CHILLER, &["notice", "src-direct-c"], "2026-10-04T00:00:00Z"),
    ];
    let acts = lifecycle(&graph, "2026-10-05");
    for tag in [1, 2] {
        assert_eq!(
            kind(&acts, tag),
            Some(LifecycleKind::Graduated { target: id(10) }),
            "{tag}: {acts:?}"
        );
    }
}

#[test]
fn ids_after_the_scan_cut_never_graduate() {
    let graph = vec![
        claim(1, "Lead: permit project Court Resurface at Pine High, Birch SD | sector:school | permit 01-323022 | permit state:pending | received:9/1/2026 | est:$1,600,000 | notes:New court Blk-C77 per Code-31 lighting", &["lead"], "2026-09-20T00:00:00Z"),
        // Control: the same token BEFORE the cut is an id.
        claim(2, "Lead: permit project Blk-C77 Court Resurface at Pine High, Birch SD | sector:school | permit 01-323023 | permit state:pending | received:9/1/2026 | est:$1,600,000 | notes:New court", &["lead"], "2026-09-20T00:00:00Z"),
        claim(10, "[OPEN] Pavilion Lighting Retrofit Blk-C77 Code-31 compliance | City of Acmeton | sector:city | trade:eng | due 2026-11-01 | est. unknown | lighting design", &["notice", "src-direct-a"], "2026-10-04T00:00:00Z"),
    ];
    let acts = lifecycle(&graph, "2026-10-05");
    assert_eq!(
        kind(&acts, 2),
        Some(LifecycleKind::Graduated { target: id(10) }),
        "{acts:?}"
    );
    assert_eq!(kind(&acts, 1), None, "{acts:?}");
}

#[test]
fn a_signal_matching_a_planned_loser_graduates_to_its_survivor() {
    // The graduation index is the post-plan state: a loser is never a target,
    // but the id it carried moves to its survivor.
    let graph = vec![
        claim(1, "Lead: permit project gym at Q School, Acme SD | sector:school | permit App 02-399001 | permit state:PENDING (recv 9/1/2026)", &["lead"], "2026-09-20T00:00:00Z"),
        // Survivor: direct source; its own text lacks the permit number.
        claim(10, "[OPEN] Q School Gym Renovation TND 77120A | Acme School District | sector:school | due 2026-11-01 | est. unknown | gym design", &["notice", "src-direct-a"], "2026-10-04T00:00:00Z"),
        // Loser: feed source, same strong id, plus the permit number.
        claim(11, "[OPEN] Q School Gym Renovation TND 77120A ref 02-399001 | Acme School District | sector:school | due 2026-11-01 | est. unknown | gym design", &["notice", "src-feed"], "2026-10-03T00:00:00Z"),
    ];
    let p = plan_graph(
        &profile(),
        &graph,
        &[Section::Hygiene, Section::Dedup, Section::Lifecycle],
        Some(date("2026-10-05")),
    );
    assert_eq!(f::cluster_shape(&p), vec![(id(10), vec![id(11)])]);
    assert_eq!(
        kind(&p.lifecycle, 1),
        Some(LifecycleKind::Graduated { target: id(10) }),
        "{:?}",
        p.lifecycle
    );
    // Control: without the dedup section the loser is still live and is the target.
    let p = plan_graph(
        &profile(),
        &graph,
        &[Section::Lifecycle],
        Some(date("2026-10-05")),
    );
    assert_eq!(
        kind(&p.lifecycle, 1),
        Some(LifecycleKind::Graduated { target: id(11) }),
        "{:?}",
        p.lifecycle
    );
}
