//! The scratch graph's in-memory store (DESIGN §4.3, task E1).
//!
//! Each test drives `ScratchStore` through the operations the runner's writer
//! uses and checks the stored graph, not the return values alone: a write
//! that reported success but left the graph unchanged (or changed it twice on
//! replay) must fail here.

use chrono::{DateTime, TimeZone, Utc};
use epigraph_api::scratch::store::{
    AtomKind, BatchOutcome, CandidateVia, Direction, Evidence, NewAtom, NewEdge, Relationship,
    ScratchStore, Seed, Speaker, StoreError,
};
use uuid::Uuid;

const SCOPE: &str = "3f9a1c07be52";

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x5c4a_0000_0000_0000_0000_0000_0000_0000 + n)
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn ev(turn: u64, c: char) -> Evidence {
    Evidence {
        path: format!("turns/{turn}.json"),
        sha256: sha(c),
        span: None,
        quote: None,
    }
}

fn atom(n: u128, turn: u64, text: &str, supported: f64) -> NewAtom {
    NewAtom {
        id: id(n),
        text: text.to_string(),
        kind: AtomKind::Fact,
        speaker: Speaker::User,
        turn,
        epoch: 0,
        quote: Some(format!("anchor {n}")),
        evidence: vec![ev(turn, 'a')],
        seed: Seed { supported },
    }
}

fn store_with(atoms: Vec<NewAtom>) -> ScratchStore {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    s.put_atoms(atoms, t(1)).unwrap();
    s
}

#[test]
fn put_atoms_is_idempotent_on_id_and_never_overwrites() {
    let mut s = store_with(vec![atom(1, 3, "The pilot site has 40 beds.", 0.71)]);
    let before = s.clone();

    // A replay of the same id with DIFFERENT content: counted existing, and
    // the stored atom keeps its first content, seed and evidence.
    let mut replay = atom(1, 3, "The pilot site has 48 beds.", 0.2);
    replay.evidence = vec![ev(3, 'b')];
    let out = s
        .put_atoms(vec![replay, atom(2, 3, "Batch B-17 shipped.", 0.5)], t(5))
        .unwrap();
    assert_eq!(
        out,
        BatchOutcome {
            inserted: 1,
            existing: 1
        }
    );

    let first = s.atom(&id(1)).unwrap();
    assert_eq!(first, before.atom(&id(1)).unwrap());
    assert_eq!(first.text, "The pilot site has 40 beds.");
    assert_eq!(first.bbas.len(), 1);
    assert_eq!(first.bbas[0].supported, 0.71);
    assert_eq!(
        first.evidence,
        vec![Evidence {
            quote: Some("anchor 1".into()),
            ..ev(3, 'a')
        }]
    );
    assert_eq!(s.stats().atoms, 2);

    // A full replay of the batch changes nothing at all, built_at included.
    let snapshot_of_state = s.clone();
    let out = s
        .put_atoms(vec![atom(1, 3, "x", 0.9), atom(2, 3, "y", 0.9)], t(9))
        .unwrap();
    assert_eq!(
        out,
        BatchOutcome {
            inserted: 0,
            existing: 2
        }
    );
    assert_eq!(s, snapshot_of_state);
}

#[test]
fn a_duplicate_id_inside_one_batch_is_inserted_once() {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    let out = s
        .put_atoms(
            vec![
                atom(1, 1, "first copy", 0.5),
                atom(1, 1, "second copy", 0.9),
            ],
            t(1),
        )
        .unwrap();
    assert_eq!(
        out,
        BatchOutcome {
            inserted: 1,
            existing: 1
        }
    );
    assert_eq!(s.atom(&id(1)).unwrap().text, "first copy");
}

#[test]
fn put_atoms_rejects_a_bad_batch_whole() {
    let mut s = store_with(vec![atom(1, 1, "kept", 0.5)]);
    let before = s.clone();

    let cases: Vec<(NewAtom, StoreError)> = vec![
        (
            NewAtom {
                epoch: 1,
                ..atom(9, 2, "other epoch", 0.5)
            },
            StoreError::EpochMismatch {
                expected: 0,
                got: 1,
            },
        ),
        (atom(9, 2, "   ", 0.5), StoreError::InvalidValue("text")),
        (
            atom(9, 2, "mass above one", 1.01),
            StoreError::InvalidValue("seed.supported"),
        ),
        (
            atom(9, 2, "negative mass", -0.1),
            StoreError::InvalidValue("seed.supported"),
        ),
        (
            atom(9, 2, "nan mass", f64::NAN),
            StoreError::InvalidValue("seed.supported"),
        ),
        (
            NewAtom {
                evidence: vec![Evidence {
                    sha256: "ABC".into(),
                    ..ev(2, 'a')
                }],
                ..atom(9, 2, "bad hash", 0.5)
            },
            StoreError::InvalidValue("evidence.sha256"),
        ),
        (
            NewAtom {
                evidence: vec![Evidence {
                    path: " ".into(),
                    ..ev(2, 'a')
                }],
                ..atom(9, 2, "bad path", 0.5)
            },
            StoreError::InvalidValue("evidence.path"),
        ),
    ];
    for (bad, expected) in cases {
        // The valid atom 8 comes FIRST, so a store that applied items as it
        // validated them would have inserted it.
        let err = s
            .put_atoms(vec![atom(8, 2, "valid sibling", 0.5), bad], t(3))
            .unwrap_err();
        assert_eq!(err, expected);
        assert_eq!(
            s, before,
            "a rejected batch must change nothing ({expected:?})"
        );
    }
}

#[test]
fn masses_are_quantized_to_the_micro_grid() {
    let s = store_with(vec![
        atom(1, 1, "third", 1.0 / 3.0),
        atom(2, 1, "long", 0.712_345_678_9),
    ]);
    assert_eq!(s.atom(&id(1)).unwrap().bbas[0].supported, 0.333_333);
    assert_eq!(s.atom(&id(2)).unwrap().bbas[0].supported, 0.712_346);
}

#[test]
fn corroborate_appends_seed_and_evidence_once_per_corroboration_id() {
    let mut s = store_with(vec![atom(
        1,
        2,
        "The operator wants Friday summaries.",
        0.8,
    )]);
    let corroboration = id(100);
    let restating = vec![Evidence {
        quote: Some("again: Fridays".into()),
        ..ev(7, 'c')
    }];

    assert!(s
        .corroborate(
            corroboration,
            id(1),
            Seed { supported: 0.6 },
            restating.clone(),
            t(4)
        )
        .unwrap());
    let a = s.atom(&id(1)).unwrap();
    assert_eq!(
        a.bbas
            .iter()
            .map(|b| (b.source, b.supported))
            .collect::<Vec<_>>(),
        vec![(id(1), 0.8), (corroboration, 0.6)]
    );
    assert_eq!(a.evidence.len(), 2);
    assert_eq!(a.evidence[1], restating[0]);
    assert_eq!(a.evidence[0].path, "turns/2.json");
    assert_eq!(s.built_at(), "2026-09-21T14:13:24.000Z");

    // Replaying the same corroboration (a reap between the write and
    // mark_applied) must not combine the BBA a second time.
    let after_first = s.clone();
    assert!(!s
        .corroborate(
            corroboration,
            id(1),
            Seed { supported: 0.6 },
            restating,
            t(8)
        )
        .unwrap());
    assert_eq!(s, after_first);

    // A different corroboration id is new evidence and is combined.
    assert!(s
        .corroborate(id(101), id(1), Seed { supported: 0.5 }, vec![], t(9))
        .unwrap());
    assert_eq!(s.atom(&id(1)).unwrap().bbas.len(), 3);
}

#[test]
fn corroborate_refuses_unknown_targets_and_bad_input() {
    let mut s = store_with(vec![atom(1, 1, "kept", 0.5)]);
    let before = s.clone();
    assert_eq!(
        s.corroborate(id(100), id(42), Seed { supported: 0.5 }, vec![], t(2)),
        Err(StoreError::UnknownAtom(id(42)))
    );
    assert_eq!(
        s.corroborate(id(100), id(1), Seed { supported: 2.0 }, vec![], t(2)),
        Err(StoreError::InvalidValue("seed.supported"))
    );
    assert!(matches!(
        s.corroborate(id(1), id(1), Seed { supported: 0.5 }, vec![], t(2)),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(s, before);
}

#[test]
fn supersede_hides_the_old_atom_from_candidates_and_is_idempotent() {
    let mut s = store_with(vec![
        atom(1, 20, "The pilot site has 40 beds.", 0.7),
        NewAtom {
            kind: AtomKind::Correction,
            ..atom(
                2,
                52,
                "The pilot site has 48 beds after the extension.",
                0.9,
            )
        },
    ]);
    let before: Vec<Uuid> = s
        .candidates("pilot site beds", 10, 0)
        .iter()
        .map(|c| c.atom.id)
        .collect();
    assert!(before.contains(&id(1)) && before.contains(&id(2)));

    assert_eq!(s.supersede(id(1), id(2), t(5)), Ok(true));
    let old = s.atom(&id(1)).unwrap();
    assert!(!old.is_current);
    assert_eq!(old.superseded_by, Some(id(2)));
    assert!(s.atom(&id(2)).unwrap().is_current);
    assert_eq!(s.stats().current_atoms, 1);

    // Hidden from BM25 AND from the recent list.
    let after: Vec<Uuid> = s
        .candidates("pilot site beds", 10, 10)
        .iter()
        .map(|c| c.atom.id)
        .collect();
    assert_eq!(after, vec![id(2)]);

    // Replay is a no-op; the first superseder is kept.
    let snap = s.clone();
    assert_eq!(s.supersede(id(1), id(2), t(9)), Ok(false));
    assert_eq!(s, snap);
}

#[test]
fn supersede_refuses_self_unknown_and_hidden_replacements() {
    let mut s = store_with(vec![
        atom(1, 1, "a one", 0.5),
        atom(2, 2, "a two", 0.5),
        atom(3, 3, "a three", 0.5),
    ]);
    assert!(matches!(
        s.supersede(id(1), id(1), t(2)),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        s.supersede(id(1), id(9), t(2)),
        Err(StoreError::UnknownAtom(id(9)))
    );
    assert_eq!(
        s.supersede(id(9), id(1), t(2)),
        Err(StoreError::UnknownAtom(id(9)))
    );
    // 2 is hidden behind 3; hiding 1 behind the hidden 2 would leave the
    // claim with no current version at all.
    assert_eq!(s.supersede(id(2), id(3), t(3)), Ok(true));
    let before = s.clone();
    assert!(matches!(
        s.supersede(id(1), id(2), t(4)),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(s, before);
}

#[test]
fn add_edges_is_idempotent_and_validates_the_whole_batch() {
    let mut s = store_with(vec![atom(1, 1, "a one", 0.5), atom(2, 2, "a two", 0.5)]);
    let e = |n, source, target, rel| NewEdge {
        id: id(n),
        source: id(source),
        target: id(target),
        rel,
    };

    let out = s
        .add_edges(vec![e(50, 2, 1, Relationship::Supports)], t(2))
        .unwrap();
    assert_eq!(
        out,
        BatchOutcome {
            inserted: 1,
            existing: 0
        }
    );
    let after_first = s.clone();
    let out = s
        .add_edges(vec![e(50, 1, 2, Relationship::Refutes)], t(3))
        .unwrap();
    assert_eq!(
        out,
        BatchOutcome {
            inserted: 0,
            existing: 1
        }
    );
    assert_eq!(s, after_first, "an existing edge id is never rewritten");

    // A valid edge first, then an edge to a missing atom: nothing is added.
    let err = s
        .add_edges(
            vec![
                e(51, 1, 2, Relationship::Elaborates),
                e(52, 1, 9, Relationship::Supports),
            ],
            t(4),
        )
        .unwrap_err();
    assert_eq!(err, StoreError::UnknownAtom(id(9)));
    assert!(matches!(
        s.add_edges(vec![e(53, 1, 1, Relationship::Supports)], t(4)),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(s, after_first);

    let n1 = s.neighbors(&id(1)).unwrap();
    assert_eq!(n1.len(), 1);
    assert_eq!(
        (n1[0].0.id, n1[0].0.relationship, n1[0].1),
        (id(50), Relationship::Supports, Direction::In)
    );
    let n2 = s.neighbors(&id(2)).unwrap();
    assert_eq!(n2[0].1, Direction::Out);
    assert_eq!(s.neighbors(&id(9)), Err(StoreError::UnknownAtom(id(9))));
}

#[test]
fn mark_applied_records_each_turn_once() {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    assert!(s.mark_applied(5, t(1)));
    assert!(s.mark_applied(2, t(2)));
    assert!(!s.mark_applied(5, t(3)));
    assert_eq!(s.applied_turns().collect::<Vec<_>>(), vec![2, 5]);
    assert_eq!(s.stats().max_applied_turn, Some(5));
    // built_at moved for the two real changes, not for the replay.
    assert_eq!(s.built_at(), "2026-09-21T14:13:22.000Z");
}

#[test]
fn candidates_rank_by_bm25_then_fill_with_recent_atoms() {
    let mut atoms = vec![
        atom(
            1,
            1,
            "The greenhouse sensor rollout uses the v2 probes only.",
            0.9,
        ),
        atom(2, 2, "Weekly status summaries go out on Fridays.", 0.9),
        atom(3, 3, "Probe batch B-17 logged three dropouts.", 0.9),
    ];
    for n in 10..25u128 {
        atoms.push(atom(
            n,
            100 + n as u64,
            &format!("Unrelated filler statement number {n}."),
            0.5,
        ));
    }
    let s = store_with(atoms);

    let c = s.candidates("which probes does the greenhouse rollout use", 2, 3);
    // BM25 first. Only the greenhouse atom matches: there is no stemming, so
    // "Probe" in atom 3 does not match "probes" in the query.
    assert_eq!(c[0].atom.id, id(1));
    assert_eq!(c[0].via, CandidateVia::Bm25);
    assert!(c[0].score.unwrap() > 0.0);
    assert!(c
        .iter()
        .filter(|x| x.via == CandidateVia::Bm25)
        .all(|x| x.atom.id != id(2)));
    // Then the three most recent atoms by turn, none repeated.
    let recent: Vec<Uuid> = c
        .iter()
        .filter(|x| x.via == CandidateVia::Recent)
        .map(|x| x.atom.id)
        .collect();
    assert_eq!(recent, vec![id(24), id(23), id(22)]);
    assert!(c
        .iter()
        .all(|x| x.via == CandidateVia::Recent || x.score.is_some()));

    // A query that matches nothing still returns the recent atoms.
    let none = s.candidates("zzz qqq", 10, 2);
    assert_eq!(
        none.iter().map(|x| x.atom.id).collect::<Vec<_>>(),
        vec![id(24), id(23)]
    );
}
