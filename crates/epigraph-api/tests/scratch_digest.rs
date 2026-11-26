//! The `digest` slices (DESIGN §5.1, task E2).
//!
//! Each test builds a small graph whose atoms sit in different turns and
//! states (evicted and applied, still in the window, evicted but unapplied,
//! superseded) and checks which atoms reach which slice. Expected scores are
//! literals computed outside the code under test from the §5.1 formula.

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use epigraph_api::scratch::belief::BeliefView;
use epigraph_api::scratch::rank::{digest, Digest};
use epigraph_api::scratch::store::{
    agent_id, AgentRole, AtomKind, Evidence, NewAgent, NewAtom, NewEdge, Relationship,
    ScratchStore, Seed,
};
use uuid::Uuid;

const SCOPE: &str = "3f9a1c07be52";

/// The one speaker agent these atoms are attributed to.
fn speaker() -> Uuid {
    agent_id(SCOPE, "Dana")
}

/// `store` with the speaker agent stored (an atom must name a stored agent).
fn with_speaker(mut store: ScratchStore) -> ScratchStore {
    store
        .put_agents(
            vec![NewAgent {
                id: speaker(),
                display_name: "Dana".into(),
                role: AgentRole::User,
                aliases: vec![],
            }],
            t(0),
        )
        .unwrap();
    store
}

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_790_000_000 + secs, 0).unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xd16e_0000_0000_0000_0000_0000_0000_0000 + n)
}

/// One atom: confidence 0.8 at reliability 0.75 unless stated (Bel 0.6,
/// BetP 0.8).
fn atom(n: u128, turn: u64, kind: AtomKind, text: &str) -> NewAtom {
    seeded(n, turn, kind, text, 0.8, 0.75)
}

fn seeded(
    n: u128,
    turn: u64,
    kind: AtomKind,
    text: &str,
    confidence: f64,
    reliability: f64,
) -> NewAtom {
    NewAtom {
        id: id(n),
        text: text.to_string(),
        kind,
        speaker_agent: speaker(),
        about: vec![],
        turn,
        epoch: 0,
        at: None,
        quote: None,
        evidence: vec![Evidence {
            path: format!("turns/{turn}.json"),
            sha256: "ef".repeat(32),
            span: None,
            quote: None,
        }],
        seed: Seed {
            confidence,
            reliability,
        },
    }
}

fn edge(n: u128, source: u128, target: u128, rel: Relationship) -> NewEdge {
    NewEdge {
        id: id(n),
        source: id(source),
        target: id(target),
        rel,
    }
}

/// A store holding `atoms`, with `applied` turns marked written.
fn graph(atoms: Vec<NewAtom>, edges: Vec<NewEdge>, applied: &[u64]) -> ScratchStore {
    let mut s = with_speaker(ScratchStore::new(SCOPE, 0, t(0)));
    s.put_atoms(atoms, t(1)).unwrap();
    s.add_edges(edges, t(2)).unwrap();
    for turn in applied {
        s.mark_applied(*turn, t(3));
    }
    s
}

fn ids(items: &[epigraph_api::scratch::rank::DigestItem<'_>]) -> Vec<Uuid> {
    items.iter().map(|i| i.id).collect()
}

/// Every atom id the digest lists anywhere, partners included.
fn listed(d: &Digest<'_>) -> BTreeSet<Uuid> {
    let mut out: BTreeSet<Uuid> = BTreeSet::new();
    for slice in [&d.standing, &d.relevant, &d.recent] {
        out.extend(slice.iter().map(|i| i.id));
    }
    for e in &d.open {
        out.insert(e.item.id);
        out.extend(e.vs.iter().map(|i| i.id));
    }
    out
}

fn run<'a>(s: &'a ScratchStore, query: &str, exclude_from: u64, k: usize) -> Digest<'a> {
    let view = BeliefView::compute(s).unwrap();
    digest(s, &view, query, exclude_from, k)
}

#[test]
fn standing_items_are_listed_whatever_the_query_ordered_by_betp_and_never_floored() {
    let s = graph(
        vec![
            // Bel 0.855, BetP 0.9275.
            seeded(
                1,
                2,
                AtomKind::Decision,
                "Use the v2 probes only.",
                0.9,
                0.95,
            ),
            // Bel 0.57, BetP 0.785; atom 5 ties it and is newer.
            seeded(
                2,
                5,
                AtomKind::Preference,
                "Summaries on Fridays.",
                0.6,
                0.95,
            ),
            seeded(3, 3, AtomKind::Fact, "The probe count is three.", 0.9, 0.95),
            // Bel 0.025: low belief is shown and marked, not dropped.
            seeded(4, 4, AtomKind::Instruction, "Copy the lab lead.", 0.05, 0.5),
            seeded(5, 6, AtomKind::Commitment, "Draft the email.", 0.6, 0.95),
        ],
        vec![],
        &[2, 3, 4, 5, 6],
    );
    let d = run(&s, "zebra xylophone", 10, 20);
    assert!(d.relevant.is_empty(), "nothing matches the query");
    assert_eq!(ids(&d.standing), vec![id(1), id(5), id(2), id(4)]);
    let low = d.standing.iter().find(|i| i.id == id(4)).unwrap();
    assert!((low.bel - 0.025).abs() < 1e-12, "{}", low.bel);
    assert_eq!(d.eligible, 5);
    assert_eq!(d.turns_archived, 5);
}

#[test]
fn atoms_still_quoted_unapplied_or_superseded_are_never_listed() {
    let s = graph(
        vec![
            atom(1, 2, AtomKind::Decision, "The pilot uses v2 probes."),
            // Applied, but turn 11 is at or after the window start (10).
            atom(2, 11, AtomKind::Decision, "The pilot probes are v2 now."),
            // Evicted (7 < 10) but its turn is not applied: still pending.
            atom(3, 7, AtomKind::Decision, "The pilot probes stay v1."),
            atom(4, 8, AtomKind::Question, "Which pilot probes ship?"),
            // Applied and evicted, but superseded below.
            atom(5, 3, AtomKind::Decision, "The pilot probes are v1."),
        ],
        vec![],
        &[2, 3, 11],
    );
    let mut s = s;
    assert!(s.supersede(id(5), id(1), t(4)).unwrap());
    let d = run(&s, "pilot probes v2 v1", 10, 20);
    assert_eq!(listed(&d), BTreeSet::from([id(1)]));
    assert_eq!(d.eligible, 1);
    assert_eq!(d.turns_archived, 2, "turns 2 and 3; 11 is in the window");
    assert_eq!(d.atoms_total, 5);
}

/// `exclude_turns_from` is the window's first turn, not the oldest quoted
/// turn: a pending turn stuck below a written one must not hide it.
#[test]
fn a_written_turn_above_a_stuck_pending_turn_is_listed() {
    // Window 17–20. Turn 15 is stuck at `captured` (never applied); turn 16
    // was evicted and written, so the runner no longer quotes it.
    let s = graph(
        vec![
            atom(1, 15, AtomKind::Decision, "STUCK-PENDING Ship batch B-18."),
            atom(2, 16, AtomKind::Decision, "Hold batch B-19 until December."),
            atom(3, 18, AtomKind::Decision, "WINDOW Batch B-20 is cancelled."),
            atom(4, 14, AtomKind::Fact, "Batch B-17 shipped."),
        ],
        vec![],
        &[14, 16, 18],
    );
    let d = run(&s, "batch", 17, 20);
    assert_eq!(
        listed(&d),
        BTreeSet::from([id(2), id(4)]),
        "turn 16 is listed; 15 (pending) and 18 (window) are not"
    );
    assert_eq!(ids(&d.standing), vec![id(2)]);
    assert_eq!(ids(&d.recent), vec![id(2), id(4)]);
    assert_eq!(d.turns_archived, 2, "turns 14 and 16");
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("STUCK-PENDING") && !json.contains("WINDOW"));
}

#[test]
fn contested_pairs_are_listed_together_and_a_quoted_partner_only_by_pointer() {
    let s = graph(
        vec![
            atom(1, 3, AtomKind::Fact, "The pilot site has 40 beds."),
            atom(2, 7, AtomKind::Fact, "The pilot site has 48 beds."),
            atom(3, 4, AtomKind::Fact, "Batch B-18 ships in November."),
            // Turn 12 is in the window: quoted verbatim, never listed.
            atom(
                4,
                12,
                AtomKind::Fact,
                "WINDOW-ONLY Batch B-18 ships in January.",
            ),
            atom(5, 6, AtomKind::Question, "Whether the supplier confirmed."),
        ],
        vec![
            edge(50, 2, 1, Relationship::Contradicts),
            edge(51, 4, 3, Relationship::Refutes),
        ],
        &[3, 4, 6, 7, 12],
    );
    let d = run(&s, "nothing", 10, 20);
    assert_eq!(d.open.len(), 3, "two conflicts and one question");

    // The conflict reaching turn 12 is the latest, so it comes first.
    let first = &d.open[0];
    assert_eq!(first.item.id, id(3));
    assert!(first.item.contested);
    assert!(first.vs.is_empty());
    assert_eq!(
        first
            .vs_unlisted
            .iter()
            .map(|p| (p.id, p.turn))
            .collect::<Vec<_>>(),
        vec![(id(4), 12)]
    );

    // Both sides of the evicted pair together; the older side heads it and
    // the newer is not repeated as a head of its own.
    let second = &d.open[1];
    assert_eq!(second.item.id, id(1));
    assert_eq!(ids(&second.vs), vec![id(2)]);
    assert!(second.vs[0].contested);
    assert!(second.vs_unlisted.is_empty());

    assert_eq!(d.open[2].item.id, id(5));
    assert_eq!(d.open[2].item.kind, AtomKind::Question);

    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("WINDOW-ONLY"), "a window atom's text leaked");

    // k_per_slice counts entries: the latest conflict alone.
    let one = run(&s, "nothing", 10, 1);
    assert_eq!(
        one.open.iter().map(|e| e.item.id).collect::<Vec<_>>(),
        vec![id(3)]
    );
}

/// Every contested pair the open slice shows, as (smaller id, larger id), in
/// entry order, duplicates kept so a test can see one.
fn open_pairs(d: &Digest<'_>) -> Vec<(Uuid, Uuid)> {
    let pair = |a: Uuid, b: Uuid| if a < b { (a, b) } else { (b, a) };
    let mut out = Vec::new();
    for e in &d.open {
        for v in &e.vs {
            out.push(pair(e.item.id, v.id));
        }
        for u in &e.vs_unlisted {
            out.push(pair(e.item.id, u.id));
        }
    }
    out
}

fn assert_each_pair_once(d: &Digest<'_>, expected: &[(u128, u128)]) {
    let got = open_pairs(d);
    let unique: BTreeSet<(Uuid, Uuid)> = got.iter().copied().collect();
    assert_eq!(unique.len(), got.len(), "a pair is shown twice: {got:?}");
    let want: BTreeSet<(Uuid, Uuid)> = expected
        .iter()
        .map(|&(a, b)| {
            let (a, b) = (id(a), id(b));
            if a < b {
                (a, b)
            } else {
                (b, a)
            }
        })
        .collect();
    assert_eq!(unique, want);
}

#[test]
fn a_partner_shown_under_another_head_still_shows_its_own_quoted_partner() {
    // A(t3) contradicts P(t5) and W(t13, window); P contradicts Q(t12,
    // window). A heads (latest conflict) with P in `vs`; P's conflict with Q
    // must still reach the digest, as a pointer.
    let s = graph(
        vec![
            atom(1, 3, AtomKind::Fact, "The pilot site has 40 beds."),
            atom(2, 5, AtomKind::Fact, "The pilot site has 48 beds."),
            atom(3, 13, AtomKind::Fact, "WINDOW The pilot site has 52 beds."),
            atom(4, 12, AtomKind::Fact, "WINDOW The extension added 4 beds."),
        ],
        vec![
            edge(50, 1, 2, Relationship::Contradicts),
            edge(51, 3, 1, Relationship::Contradicts),
            edge(52, 4, 2, Relationship::Refutes),
        ],
        &[3, 5, 12, 13],
    );
    let d = run(&s, "nothing", 10, 20);
    assert_each_pair_once(&d, &[(1, 2), (1, 3), (2, 4)]);
    let q = d
        .open
        .iter()
        .flat_map(|e| e.vs_unlisted.iter())
        .find(|u| u.id == id(4))
        .expect("Q's pointer is in the digest");
    assert_eq!(q.turn, 12);
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("WINDOW"), "a window atom's text leaked");
}

#[test]
fn every_contested_pair_is_shown_once_when_both_sides_were_listed_elsewhere() {
    // A–P, P–Q, Q–C, C–D, all evicted and applied. C's conflict with D is
    // the latest, so C heads first and lists Q; A then heads and lists P.
    // Both sides of P–Q are now listed, but under different heads: the pair
    // itself must still be shown, and no pair twice.
    let s = graph(
        vec![
            atom(1, 3, AtomKind::Fact, "Alpha."),
            atom(2, 9, AtomKind::Fact, "Papa."),
            atom(3, 5, AtomKind::Fact, "Quebec."),
            atom(4, 4, AtomKind::Fact, "Charlie."),
            atom(5, 10, AtomKind::Fact, "Delta."),
        ],
        vec![
            edge(50, 1, 2, Relationship::Contradicts),
            edge(51, 2, 3, Relationship::Contradicts),
            edge(52, 3, 4, Relationship::Contradicts),
            edge(53, 4, 5, Relationship::Contradicts),
        ],
        &[3, 4, 5, 9, 10],
    );
    let d = run(&s, "nothing", 11, 20);
    assert_each_pair_once(&d, &[(1, 2), (2, 3), (3, 4), (4, 5)]);
    assert_eq!(
        d.open.iter().map(|e| e.item.id).collect::<Vec<_>>(),
        vec![id(4), id(1), id(3)],
        "C, then A, then Q (the older side) for the pair no earlier entry showed"
    );
}

#[test]
fn relevant_pulls_in_a_one_hop_neighbour_with_no_lexical_match() {
    let s = graph(
        vec![
            atom(1, 3, AtomKind::Fact, "Firmware 1.4 reduced the dropouts."),
            atom(
                2,
                4,
                AtomKind::Fact,
                "The supplier confirmed delivery dates.",
            ),
            atom(3, 5, AtomKind::Fact, "Weekly summary drafted."),
            atom(4, 6, AtomKind::Fact, "Greenhouse humidity looked normal."),
            // In the window: never pulled in, even over a supports edge.
            atom(5, 11, AtomKind::Fact, "Calibration notes were filed."),
        ],
        vec![
            edge(50, 2, 1, Relationship::Supports),
            // Not an expansion relationship.
            edge(51, 3, 1, Relationship::Supersedes),
            edge(52, 5, 1, Relationship::Supports),
        ],
        &[3, 4, 5, 6, 11],
    );
    let d = run(&s, "firmware dropouts", 10, 20);
    assert_eq!(ids(&d.relevant), vec![id(1), id(2)]);
    // rel 1.0, d = 7: 0.55 + 0.15·0.5^(7/40) + 0.15·0.8 + 0.15·0.6.
    let x = d.relevant[0].score.unwrap();
    assert!((x - 0.892_865_127_865_354_1).abs() < 1e-9, "{x}");
    // rel 0.7 · 1.0, d = 6: 0.385 + 0.15·0.5^(6/40) + 0.12 + 0.09.
    let y = d.relevant[1].score.unwrap();
    assert!((y - 0.730_187_569_391_624_4).abs() < 1e-9, "{y}");
}

#[test]
fn recency_decays_with_turn_distance_when_all_else_is_equal() {
    // Same length, same matched terms, same kind and seed: only the turn
    // differs. Token Jaccard 2/4 keeps them from being neighbours.
    let s = graph(
        vec![
            atom(1, 10, AtomKind::Fact, "probe firmware alpha"),
            atom(2, 49, AtomKind::Fact, "probe firmware gamma"),
        ],
        vec![],
        &[10, 49],
    );
    let d = run(&s, "probe firmware", 50, 20);
    assert_eq!(ids(&d.relevant), vec![id(2), id(1)]);
    // d = 1: 0.55 + 0.15·0.5^(1/40) + 0.21.
    let newer = d.relevant[0].score.unwrap();
    assert!((newer - 0.907_423_089_781_787_7).abs() < 1e-9, "{newer}");
    // d = 40, one half-life: 0.55 + 0.075 + 0.21.
    let older = d.relevant[1].score.unwrap();
    assert!((older - 0.835).abs() < 1e-9, "{older}");
}

#[test]
fn a_near_restatement_yields_to_a_different_atom_of_similar_score() {
    // Atoms 1 and 2 share all but one token (Jaccard 5/6 ≥ 0.6) and outscore
    // atom 3 (about 0.91, 0.86, 0.57). With room for two, the coverage term
    // picks 1 then 3, not 1 then its near-copy.
    let s = graph(
        vec![
            atom(1, 9, AtomKind::Fact, "probe firmware dropout rate fell"),
            atom(
                2,
                8,
                AtomKind::Fact,
                "probe firmware dropout rate fell sharply",
            ),
            atom(3, 7, AtomKind::Fact, "firmware dropout calibration drift"),
        ],
        vec![],
        &[7, 8, 9],
    );
    let all = run(&s, "probe firmware dropout", 10, 20);
    let by_score: Vec<Uuid> = {
        let mut v: Vec<_> = all
            .relevant
            .iter()
            .map(|i| (i.score.unwrap(), i.id))
            .collect();
        v.sort_by(|a, b| b.0.total_cmp(&a.0));
        v.into_iter().map(|(_, id)| id).collect()
    };
    assert_eq!(by_score, vec![id(1), id(2), id(3)], "score order");
    let two = run(&s, "probe firmware dropout", 10, 2);
    assert_eq!(ids(&two.relevant), vec![id(1), id(3)]);
}

#[test]
fn recent_lists_the_last_eight_evicted_turns_and_their_corrections() {
    let mut s = graph(
        vec![
            atom(1, 5, AtomKind::Fact, "Two probes per bed."),
            atom(2, 11, AtomKind::Fact, "Older than the recent range."),
            atom(3, 12, AtomKind::Fact, "Oldest recent turn."),
            atom(4, 15, AtomKind::Fact, "Middle recent turn."),
            atom(5, 19, AtomKind::Correction, "Three probes per bed."),
        ],
        vec![],
        &[5, 11, 12, 15, 19],
    );
    assert!(s.supersede(id(1), id(5), t(4)).unwrap());
    let d = run(&s, "", 20, 20);
    assert_eq!(ids(&d.recent), vec![id(5), id(4), id(3)]);
    assert_eq!(d.recent_corrections.len(), 1);
    let c = d.recent_corrections[0];
    assert_eq!((c.old, c.new, c.turn), (id(1), id(5), 19));
    assert!(d.relevant.is_empty(), "an empty query ranks nothing");

    let capped = run(&s, "", 20, 2);
    assert_eq!(ids(&capped.recent), vec![id(5), id(4)]);
    let none = run(&s, "probes", 20, 0);
    assert!(none.standing.is_empty() && none.relevant.is_empty());
    assert!(none.recent.is_empty() && none.open.is_empty());
}

#[test]
fn a_recent_correction_carries_both_texts_unless_the_old_side_is_still_quoted() {
    let mut s = graph(
        vec![
            atom(1, 5, AtomKind::Fact, "Two probes per bed."),
            atom(2, 19, AtomKind::Correction, "Three probes per bed."),
            // Turn 17's atoms were put but the turn was never marked applied
            // (a reaped writer): the runner still quotes it as pending.
            atom(3, 17, AtomKind::Fact, "PENDING-OLD The supplier is Acme."),
            atom(4, 18, AtomKind::Correction, "The supplier is Bolt."),
        ],
        vec![],
        &[5, 18, 19],
    );
    assert!(s.supersede(id(1), id(2), t(4)).unwrap());
    assert!(s.supersede(id(3), id(4), t(4)).unwrap());
    let d = run(&s, "", 20, 20);
    assert_eq!(d.recent_corrections.len(), 2);

    let c = d.recent_corrections[0];
    assert_eq!((c.old, c.old_turn, c.new, c.turn), (id(1), 5, id(2), 19));
    assert_eq!(c.old_text, Some("Two probes per bed."));
    assert_eq!(c.new_text, "Three probes per bed.");

    let p = d.recent_corrections[1];
    assert_eq!((p.old, p.old_turn, p.new, p.turn), (id(3), 17, id(4), 18));
    assert_eq!(p.old_text, None, "the old side is still quoted verbatim");
    assert_eq!(p.new_text, "The supplier is Bolt.");

    let json = serde_json::to_value(&d).unwrap();
    assert!(!json.to_string().contains("PENDING-OLD"));
    assert!(json["recent_corrections"][1].get("old_text").is_none());
    assert_eq!(
        json["recent_corrections"][0]["old_text"],
        "Two probes per bed."
    );
}
