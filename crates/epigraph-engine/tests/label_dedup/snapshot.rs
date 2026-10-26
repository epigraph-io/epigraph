//! Capped reads: truncation is reported, never hidden, and refuses apply.

use epigraph_engine::label_dedup::{LabelDedupError, Section, Snapshot};

use crate::fixtures::{self as f, claim, corpus, dedup_sections, id, profile, try_plan_graph};

fn rows(n: u32) -> Vec<epigraph_engine::label_dedup::DedupClaim> {
    // Inserted in descending id order: the cap must keep the SMALLEST ids.
    (1..=n)
        .rev()
        .map(|i| claim(i, &format!("item {i}"), &["notice"], "2026-06-01T00:00:00Z"))
        .collect()
}

#[test]
fn a_read_under_the_cap_is_complete() {
    let s = Snapshot::from_capped(rows(150), 2000);
    assert_eq!(s.claims.len(), 150);
    assert!(!s.truncated);
    assert_eq!(s.claims[0].id, id(1), "sorted by id");
    // Exactly at the cap is complete too: the read asks for cap + 1 rows.
    let s = Snapshot::from_capped(rows(120), 120);
    assert_eq!(s.claims.len(), 120);
    assert!(!s.truncated);
}

#[test]
fn a_read_over_the_cap_is_truncated_and_reported() {
    let s = Snapshot::from_capped(rows(121), 120);
    assert_eq!(s.claims.len(), 120);
    assert!(
        s.truncated,
        "a truncated read must say so, not look complete"
    );
    assert_eq!(
        s.claims.last().map(|c| c.id),
        Some(id(120)),
        "the cap keeps the smallest ids"
    );
}

#[test]
fn a_truncated_plan_is_flagged_and_refuses_apply() {
    let p = try_plan_graph(&profile(), &corpus(), &dedup_sections(), None, 10).expect("plan");
    assert!(p.coverage.truncated);
    assert_eq!(p.coverage.members, 10);
    assert_eq!(p.apply_refusal(), Some(LabelDedupError::Truncated));
    // Control: the full read is not truncated and may be applied.
    let p = try_plan_graph(&profile(), &corpus(), &dedup_sections(), None, 5000).expect("plan");
    assert!(!p.coverage.truncated);
    assert_eq!(p.apply_refusal(), None);
    assert!(!p.is_empty(), "control: there is work to apply");
}

#[test]
fn truncation_of_any_read_refuses_apply() {
    // The member read fits, but the signal read does not.
    let mut graph = vec![claim(
        500,
        f::NOTICE_CHILLER,
        &["notice", "src-direct-c"],
        "2026-10-04T00:00:00Z",
    )];
    for i in 1..=3 {
        graph.push(claim(i, f::LEAD_FUND, &["lead"], "2026-09-20T00:00:00Z"));
    }
    let p = try_plan_graph(
        &profile(),
        &graph,
        &[Section::Lifecycle],
        Some(f::date("2026-10-05")),
        2,
    )
    .expect("plan");
    assert!(p.coverage.truncated);
    assert_eq!(p.coverage.signals, Some(2));
    assert_eq!(p.apply_refusal(), Some(LabelDedupError::Truncated));
}
