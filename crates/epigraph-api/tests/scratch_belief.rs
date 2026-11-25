//! Belief over the scratch graph, slice 1 (DESIGN §4.4, task E2).
//!
//! Every expected number is a literal worked out by hand from DESIGN §3.4
//! (`m({supported}) = confidence × reliability`, Dempster's rule for
//! restatements), never recomputed with the code under test. A seed that is
//! discounted twice, discounted by the profile's locality factor, or combined
//! by an idempotent rule lands on a different literal and fails.

use chrono::{DateTime, TimeZone, Utc};
use epigraph_api::scratch::belief::{seed_row, BeliefSummary, BeliefView, SEED_LOCALITY_TAG};
use epigraph_api::scratch::store::{
    AtomKind, Evidence, NewAtom, NewEdge, Relationship, ScratchStore, Seed, SeedBba, Speaker,
};
use epigraph_engine::belief_profile::BeliefProfile;
use epigraph_engine::edge_factor::effective_source_strength_profiled;
use uuid::Uuid;

const SCOPE: &str = "3f9a1c07be52";
const EPS: f64 = 1e-12;

/// DESIGN §3.4's speaker-reliability tiers.
const TIERS: [f64; 4] = [0.95, 0.85, 0.75, 0.5];

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xbe11_0000_0000_0000_0000_0000_0000_0000 + n)
}

fn atom(n: u128, turn: u64, confidence: f64, reliability: f64) -> NewAtom {
    NewAtom {
        id: id(n),
        text: format!("Atom number {n} from turn {turn}."),
        kind: AtomKind::Fact,
        speaker: Speaker::User,
        turn,
        epoch: 0,
        quote: None,
        evidence: vec![Evidence {
            path: format!("turns/{turn}.json"),
            sha256: "cd".repeat(32),
            span: None,
            quote: None,
        }],
        seed: Seed {
            confidence,
            reliability,
        },
    }
}

fn store(atoms: Vec<NewAtom>) -> ScratchStore {
    let mut s = ScratchStore::new(SCOPE, 0, t(0));
    s.put_atoms(atoms, t(1)).unwrap();
    s
}

fn edge(n: u128, source: u128, target: u128, rel: Relationship) -> NewEdge {
    NewEdge {
        id: id(n),
        source: id(source),
        target: id(target),
        rel,
    }
}

fn assert_close(got: f64, want: f64, what: &str) {
    assert!((got - want).abs() < EPS, "{what}: got {got}, want {want}");
}

#[test]
fn a_seed_row_discounts_by_exactly_the_reliability_under_the_builtin_profile() {
    // Critic finding X6, option (a): `seed_mass` discounts by
    // `effective_source_strength_profiled(row, profile)`. For the rows belief
    // builds, that must be the speaker reliability itself, so the reliability
    // is applied once and nothing from the profile is applied on top.
    let profile = BeliefProfile::builtin();
    for r in TIERS {
        let row = seed_row(
            id(1),
            &SeedBba {
                source: id(1),
                confidence: 0.8,
                reliability: r,
            },
        )
        .unwrap();
        assert_eq!(row.locality_tag, SEED_LOCALITY_TAG);
        assert_eq!(row.locality_tag, "intra");
        assert_eq!(row.evidence_type, None);
        assert_eq!(row.source_strength, Some(r));
        assert_eq!(
            effective_source_strength_profiled(&row, &profile),
            r,
            "tier {r}"
        );
    }
}

#[test]
fn an_untyped_seed_row_keeps_the_reliability_even_where_types_are_calibrated() {
    // Why `seed_row` leaves `evidence_type` unset. The builtin profile
    // calibrates no evidence type, but its intra locality factor is 0.3, and
    // a profile that calibrates a type multiplies an intra row of that type
    // by it. The untyped row takes the stored source strength verbatim on any
    // such profile, so the pin above cannot pass by an empty table alone.
    let builtin = BeliefProfile::builtin();
    assert_eq!(builtin.reliability.intra_evidence_locality_factor, 0.3);
    let mut calibrated = builtin.clone();
    calibrated
        .reliability
        .evidence_type_weights
        .insert("testimony".into(), 1.0);
    for r in TIERS {
        let mut row = seed_row(
            id(1),
            &SeedBba {
                source: id(1),
                confidence: 0.8,
                reliability: r,
            },
        )
        .unwrap();
        assert_eq!(
            effective_source_strength_profiled(&row, &calibrated),
            r,
            "tier {r}: untyped row under a calibrating profile"
        );
        row.evidence_type = Some("testimony".into());
        assert_close(
            effective_source_strength_profiled(&row, &calibrated),
            0.3,
            &format!("tier {r}: a typed intra row gets weight 1.0 x locality 0.3"),
        );
    }
}

#[test]
fn a_seed_gives_bel_equal_to_confidence_times_reliability_for_every_tier() {
    // confidence 0.8 under each tier: Bel = 0.8 × r, Pl = 1 (nothing against),
    // BetP = Bel + (1 − Bel) / 2 on the binary frame.
    let expected = [
        (0.95, 0.76, 0.88),
        (0.85, 0.68, 0.84),
        (0.75, 0.60, 0.80),
        (0.5, 0.40, 0.70),
    ];
    let s = store(
        expected
            .iter()
            .enumerate()
            .map(|(i, (r, _, _))| atom(i as u128 + 1, 1, 0.8, *r))
            .collect(),
    );
    let view = BeliefView::compute(&s).unwrap();
    for (i, (r, bel, betp)) in expected.iter().enumerate() {
        let b = view.get(&id(i as u128 + 1)).unwrap();
        assert_close(b.bel, *bel, &format!("Bel at reliability {r}"));
        assert_close(b.pl, 1.0, &format!("Pl at reliability {r}"));
        assert_close(b.betp, *betp, &format!("BetP at reliability {r}"));
        assert!(!b.contested);
    }
}

#[test]
fn full_confidence_is_capped_by_the_reliability_and_zero_confidence_is_vacuous() {
    let s = store(vec![atom(1, 1, 1.0, 0.85), atom(2, 1, 0.0, 0.95)]);
    let view = BeliefView::compute(&s).unwrap();
    let certain = view.get(&id(1)).unwrap();
    assert_close(certain.bel, 0.85, "Bel of a certain claim by a 0.85 source");
    assert_close(certain.betp, 0.925, "its BetP");
    let none = view.get(&id(2)).unwrap();
    assert_close(none.bel, 0.0, "Bel of a zero-confidence seed");
    assert_close(none.pl, 1.0, "its Pl");
    assert_close(none.betp, 0.5, "its BetP");
}

#[test]
fn corroboration_combines_by_dempster_and_a_replay_adds_nothing() {
    // Seed 0.6 × 0.95 = 0.57. Restated with 0.5 × 0.75 = 0.375.
    // Dempster on two simple supports: 1 − (1 − 0.57)(1 − 0.375) = 0.73125.
    let mut s = store(vec![atom(1, 2, 0.6, 0.95)]);
    let before = BeliefView::compute(&s).unwrap();
    assert_close(before.get(&id(1)).unwrap().bel, 0.57, "seed Bel");

    let restated = Seed {
        confidence: 0.5,
        reliability: 0.75,
    };
    assert!(s
        .corroborate(id(100), id(1), restated, vec![], t(2))
        .unwrap());
    let once = BeliefView::compute(&s).unwrap();
    let b = once.get(&id(1)).unwrap();
    assert_close(b.bel, 0.73125, "Bel after one restatement");
    assert_close(b.pl, 1.0, "Pl after one restatement");
    assert_close(b.betp, 0.865_625, "BetP after one restatement");

    // A replayed corroboration (same id) is not new evidence.
    assert!(!s
        .corroborate(id(100), id(1), restated, vec![], t(3))
        .unwrap());
    assert_eq!(BeliefView::compute(&s).unwrap(), once);

    // A third source keeps raising it: 1 − 0.26875 × (1 − 0.4 × 0.5) = 0.785.
    let third = Seed {
        confidence: 0.4,
        reliability: 0.5,
    };
    assert!(s.corroborate(id(101), id(1), third, vec![], t(4)).unwrap());
    let thrice = BeliefView::compute(&s).unwrap();
    assert_close(
        thrice.get(&id(1)).unwrap().bel,
        0.785,
        "Bel after two restatements",
    );
}

#[test]
fn contradicts_and_refutes_mark_both_ends_contested_and_other_edges_do_not() {
    let mut s = store((1..=8).map(|n| atom(n, n as u64, 0.8, 0.75)).collect());
    s.add_edges(
        vec![
            edge(50, 1, 2, Relationship::Contradicts),
            edge(51, 3, 4, Relationship::Refutes),
            edge(52, 5, 6, Relationship::Supports),
            edge(53, 6, 7, Relationship::Elaborates),
            edge(54, 7, 8, Relationship::Corroborates),
            edge(55, 8, 5, Relationship::Supersedes),
        ],
        t(2),
    )
    .unwrap();
    let view = BeliefView::compute(&s).unwrap();
    let contested = |n: u128| view.get(&id(n)).unwrap().contested;
    let with = |n: u128| view.get(&id(n)).unwrap().contested_with.clone();

    assert!(contested(1) && contested(2), "contradicts marks both ends");
    assert_eq!((with(1), with(2)), (vec![id(2)], vec![id(1)]));
    assert!(contested(3) && contested(4), "refutes marks both ends");
    for n in 5..=8 {
        assert!(!contested(n), "atom {n} has only non-contesting edges");
        assert!(with(n).is_empty());
    }
    // Slice 1 flags a conflict; it does not move belief (E3's BP does).
    assert_close(
        view.get(&id(1)).unwrap().bel,
        0.6,
        "contested Bel unchanged",
    );
    assert_eq!(
        view.summary(&s),
        BeliefSummary {
            current_atoms: 8,
            contested: 4,
            seeds: 8,
        }
    );
}

#[test]
fn superseding_one_side_clears_contested_on_both_and_drops_it_from_the_counts() {
    // Atom 1 contradicts atom 2 and atom 3; atom 4 then corrects atom 2.
    let mut s = store((1..=4).map(|n| atom(n, n as u64, 0.8, 0.75)).collect());
    s.add_edges(
        vec![
            edge(50, 1, 2, Relationship::Contradicts),
            edge(51, 3, 1, Relationship::Contradicts),
        ],
        t(2),
    )
    .unwrap();
    let view = BeliefView::compute(&s).unwrap();
    assert_eq!(view.get(&id(1)).unwrap().contested_with, vec![id(2), id(3)]);

    assert!(s.supersede(id(2), id(4), t(3)).unwrap());
    let view = BeliefView::compute(&s).unwrap();
    let b = |n: u128| view.get(&id(n)).unwrap();
    assert!(!b(2).contested, "a superseded atom is never contested");
    assert!(b(2).contested_with.is_empty());
    assert_eq!(
        b(1).contested_with,
        vec![id(3)],
        "only the live edge remains"
    );
    assert!(b(3).contested);
    assert!(!b(4).contested, "the correction did not inherit the edge");
    assert_eq!(
        view.summary(&s),
        BeliefSummary {
            current_atoms: 3,
            contested: 2,
            seeds: 3,
        }
    );

    // Superseding the last partner clears the flag entirely.
    assert!(s.supersede(id(3), id(4), t(4)).unwrap());
    let view = BeliefView::compute(&s).unwrap();
    assert!(!view.get(&id(1)).unwrap().contested);
    assert_eq!(view.summary(&s).contested, 0);
}
