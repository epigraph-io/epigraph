//! The revert input: what an apply records per write and per mark, and the
//! writes and un-marks that undo it.
//!
//! The database write path (`update_labels`) is modelled by [`db_write`]: it
//! unions the added labels in, drops the removed ones, and stores the result
//! sorted and de-duplicated, exactly as the repository statement does. So
//! every comparison below is on sorted label SETS; the order a claim stored
//! before its first write is not restorable through that path (the MCP-level
//! test pins that limit against the real database).

use std::collections::BTreeSet;

use epigraph_engine::label_dedup::{
    revert_marks, revert_writes, AppliedLabelChange, AppliedMark, DedupClaim, DuplicateMark,
    LabelWrite, Tier, WriteUnit,
};
use uuid::Uuid;

use crate::fixtures::{self as f, all_sections, claim, corpus, date, plan_graph, profile};

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

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

/// `update_labels`' statement: `(labels ∪ add) \ remove`, sorted, distinct.
fn db_write(labels: &[String], add: &[String], remove: &[String]) -> Vec<String> {
    labels
        .iter()
        .chain(add)
        .filter(|l| !remove.contains(l))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn canonical(labels: &[String]) -> Vec<String> {
    labels
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Apply `units` to `graph` the way apply does: per unit, its marks (the
/// marked duplicate leaves the index: `marked`, duplicate → canonical), then
/// one write at a time, the change recorded from the labels before and after
/// each write.
fn apply_recording(
    graph: &mut [DedupClaim],
    marked: &mut Vec<(Uuid, Uuid)>,
    units: &[WriteUnit],
) -> (Vec<AppliedLabelChange>, Vec<AppliedMark>) {
    let mut changes = Vec::new();
    let mut marks = Vec::new();
    for unit in units {
        for m in &unit.marks {
            assert!(
                !marked.iter().any(|(d, _)| *d == m.dup),
                "a claim is marked once: {m:?}"
            );
            marked.push((m.dup, m.canonical));
            marks.push(AppliedMark::from_mark(&unit.unit, m, None));
        }
        for w in &unit.writes {
            let c = graph
                .iter_mut()
                .find(|c| c.id == w.claim_id)
                .expect("write targets a graph claim");
            let before = c.labels.clone();
            let after = db_write(&before, &w.add, &w.remove);
            changes.push(AppliedLabelChange::from_write(
                &unit.unit, w, &before, &after,
            ));
            c.labels = after;
        }
    }
    (changes, marks)
}

/// `unmark_duplicate`: refused unless `m` is the claim's live mark and its
/// canonical is not itself marked (a chain is un-marked from its newest
/// link), as the database act refuses.
fn unmark(marked: &mut Vec<(Uuid, Uuid)>, m: &AppliedMark) {
    assert!(
        !marked.iter().any(|(dup, _)| *dup == m.canonical),
        "un-mark {} first: {} is marked onto it",
        m.canonical,
        m.dup
    );
    let pos = marked
        .iter()
        .position(|pair| *pair == (m.dup, m.canonical))
        .unwrap_or_else(|| panic!("{} is not marked onto {}", m.dup, m.canonical));
    marked.remove(pos);
}

fn run_writes(graph: &mut [DedupClaim], writes: &[LabelWrite]) {
    for w in writes {
        let c = graph
            .iter_mut()
            .find(|c| c.id == w.claim_id)
            .expect("revert targets a graph claim");
        c.labels = db_write(&c.labels, &w.add, &w.remove);
    }
}

#[test]
fn revert_restores_every_label_set_after_a_full_apply() {
    let original = graph();
    let plan = plan_graph(
        &profile(),
        &original,
        &all_sections(),
        Some(date("2026-10-05")),
    );
    let units = plan.write_units();
    let mut g = original.clone();
    let mut marked = Vec::new();
    let (changes, marks) = apply_recording(&mut g, &mut marked, &units);

    // Controls: the apply really changed label sets, removed labels, and
    // added the closed label, so a revert that does nothing cannot pass.
    let changed = original
        .iter()
        .zip(&g)
        .filter(|(a, b)| canonical(&a.labels) != canonical(&b.labels))
        .count();
    assert!(
        changed >= 3,
        "the apply must relabel several claims, relabelled {changed}"
    );
    assert!(!marks.is_empty(), "the apply must mark a duplicate");
    assert!(
        changes.iter().any(|c| !c.labels_removed.is_empty()),
        "some write must have removed a label: {changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c.labels_added.contains(&"resolved".to_string())),
        "some write must have added the closed label: {changes:?}"
    );

    run_writes(&mut g, &revert_writes(&changes));
    for m in revert_marks(&marks) {
        unmark(&mut marked, &m);
    }
    assert!(marked.is_empty(), "every mark is undone: {marked:?}");
    // Sets on both sides: a claim no write touched keeps its stored order.
    for (a, b) in original.iter().zip(&g) {
        assert_eq!(
            canonical(&a.labels),
            canonical(&b.labels),
            "claim {} must be back on its original label set",
            a.id
        );
    }
}

/// Marks are undone newest first, so a chain (`b` marked onto `a`, then `a`
/// marked onto `c` by a later unit) un-marks from its newest link: `a` comes
/// back first, so `b`'s canonical is current again when `b` is un-marked, the
/// order the un-mark act requires. Each record keeps its unit, both ends and the
/// identity edge the act returned.
#[test]
fn marks_are_undone_newest_first() {
    let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
    let edge = Uuid::from_u128(99);
    let mark = |dup, canonical| DuplicateMark {
        dup,
        canonical,
        rule: Tier::StrongId,
        matched_on: "shared id".into(),
    };
    let applied = vec![
        AppliedMark::from_mark("cluster:a", &mark(b, a), Some(edge)),
        AppliedMark::from_mark("cluster:c", &mark(a, c), None),
    ];
    assert_eq!(applied[0].unit, "cluster:a");
    assert_eq!((applied[0].dup, applied[0].canonical), (b, a));
    assert_eq!(applied[0].identity_edge, Some(edge));
    assert_eq!(applied[0].rule, Tier::StrongId);

    let undo = revert_marks(&applied);
    assert_eq!(
        undo.iter().map(|m| m.dup).collect::<Vec<_>>(),
        vec![a, b],
        "the newest mark (a onto c) is undone first: {undo:?}"
    );
    let mut marked = vec![(b, a), (a, c)];
    for m in &undo {
        unmark(&mut marked, m);
    }
    assert!(marked.is_empty());
}

#[test]
fn a_label_the_claim_already_carried_is_not_recorded_and_survives_revert() {
    let id = Uuid::from_u128(7);
    let w = LabelWrite {
        claim_id: id,
        add: strings(&["kept-before", "new-one"]),
        remove: strings(&["was-there", "never-there"]),
    };
    let before = strings(&["kept-before", "was-there", "zz-other"]);
    let after = db_write(&before, &w.add, &w.remove);
    let change = AppliedLabelChange::from_write("cluster:x", &w, &before, &after);
    assert_eq!(change.unit, "cluster:x");
    assert_eq!(change.claim_id, id);
    assert_eq!(change.labels_added, strings(&["new-one"]));
    assert_eq!(change.labels_removed, strings(&["was-there"]));

    let mut g = vec![DedupClaim {
        id,
        content: String::new(),
        labels: after,
        created_at: None,
        duplicates: Vec::new(),
    }];
    run_writes(&mut g, &revert_writes(&[change]));
    assert_eq!(
        g[0].labels,
        canonical(&before),
        "kept-before stays, was-there returns"
    );
}

#[test]
fn only_labels_the_write_named_are_attributed_to_it() {
    // `zz-concurrent` appeared between the read and the write (another
    // writer). It is not this write's change, so a revert must not strip it.
    let w = LabelWrite {
        claim_id: Uuid::from_u128(8),
        add: strings(&["mine"]),
        remove: Vec::new(),
    };
    let change = AppliedLabelChange::from_write(
        "hygiene:x",
        &w,
        &strings(&["a"]),
        &strings(&["a", "mine", "zz-concurrent"]),
    );
    assert_eq!(change.labels_added, strings(&["mine"]));
    assert!(change.labels_removed.is_empty());
}

#[test]
fn revert_runs_newest_first() {
    // Unit 1 adds `x`, unit 2 removes it again: only the reverse order lands
    // on the original set (no `x`).
    let id = Uuid::from_u128(9);
    let original = strings(&["base"]);
    let w1 = LabelWrite {
        claim_id: id,
        add: strings(&["x"]),
        remove: Vec::new(),
    };
    let w2 = LabelWrite {
        claim_id: id,
        add: Vec::new(),
        remove: strings(&["x"]),
    };
    let after1 = db_write(&original, &w1.add, &w1.remove);
    let after2 = db_write(&after1, &w2.add, &w2.remove);
    let changes = vec![
        AppliedLabelChange::from_write("u1", &w1, &original, &after1),
        AppliedLabelChange::from_write("u2", &w2, &after1, &after2),
    ];
    let writes = revert_writes(&changes);
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert_eq!(
        writes[0].add,
        strings(&["x"]),
        "u2 is undone first: {writes:?}"
    );
    assert_eq!(writes[1].remove, strings(&["x"]), "{writes:?}");

    let mut g = vec![DedupClaim {
        id,
        content: String::new(),
        labels: after2,
        created_at: None,
        duplicates: Vec::new(),
    }];
    run_writes(&mut g, &writes);
    assert_eq!(g[0].labels, original);
}

#[test]
fn a_change_that_changed_nothing_yields_no_revert_write() {
    let w = LabelWrite {
        claim_id: Uuid::from_u128(10),
        add: strings(&["already"]),
        remove: strings(&["absent"]),
    };
    let labels = strings(&["already"]);
    let noop = AppliedLabelChange::from_write("u", &w, &labels, &labels);
    assert!(noop.is_empty());
    let real = AppliedLabelChange {
        unit: "u".into(),
        claim_id: Uuid::from_u128(11),
        labels_added: strings(&["y"]),
        labels_removed: Vec::new(),
    };
    let writes = revert_writes(&[noop, real]);
    assert_eq!(
        writes,
        vec![LabelWrite {
            claim_id: Uuid::from_u128(11),
            add: Vec::new(),
            remove: strings(&["y"]),
        }],
        "an empty change has nothing to undo; the label tool refuses an empty write"
    );
}
