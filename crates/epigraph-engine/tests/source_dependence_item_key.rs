//! One canonical item key per BBA row, paper identity first (SPEC §3.3).
//!
//! The atom fold, the compound conjunction and the framed reads must group a
//! claim's BBAs into items the same way. These are the properties the shared
//! grouping (`source_dependence::item_key`, `item_partition`,
//! `combine_by_item`) has to hold:
//!
//! 1. rows citing one DOI share one key, whatever their perspective, agent or
//!    DOI spelling;
//! 2. one paper read by two agents is one source: the fold keeps the stronger
//!    reading instead of Dempster-reinforcing it;
//! 3. a row bridging two papers' atoms never merges those papers' items;
//! 4. adding a leaf to a query never changes another leaf's partition;
//! 5. a real lens perspective is never a key;
//! 6. a support and a refutation of one lineage keep the refutation.
//!
//! The legacy `combine_with_source_dependence` is not touched here; its own
//! unit tests (including `distinct_urls_and_unkeyed_rows_still_reinforce`)
//! pin it.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use epigraph_db::MassFunctionRow;
use epigraph_ds::{FocalElement, FrameOfDiscernment, MassFunction};
use epigraph_engine::source_dependence::{
    combine_by_item, item_key, item_partition, normalize_doi, ItemEvidence, ItemKey, ItemSide,
    KeyedBba, KeyedItem, ATTRIBUTED_METHOD, EDGE_FACTOR_METHOD, INGEST_ASSERTION_METHOD,
};
use proptest::prelude::*;
use uuid::Uuid;

const EPS: f64 = 1e-9;

fn binary() -> FrameOfDiscernment {
    FrameOfDiscernment::new("binary_truth", vec!["TRUE".into(), "FALSE".into()]).unwrap()
}

/// {TRUE: t, FALSE: f, ~: o, Θ: the rest} on `binary_truth`.
fn bba(t: f64, f: f64, o: f64) -> MassFunction {
    let fr = binary();
    let mut m = BTreeMap::new();
    if t > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([0])), t);
    }
    if f > 0.0 {
        m.insert(FocalElement::positive(BTreeSet::from([1])), f);
    }
    if o > 0.0 {
        m.insert(FocalElement::missing(&fr), o);
    }
    let rest = 1.0 - t - f - o;
    if rest > 1e-15 {
        m.insert(FocalElement::theta(&fr), rest);
    }
    MassFunction::new(fr, m).unwrap()
}

fn m_t(m: &MassFunction) -> f64 {
    m.mass_of(&FocalElement::positive(BTreeSet::from([0])))
}

fn m_f(m: &MassFunction) -> f64 {
    m.mass_of(&FocalElement::positive(BTreeSet::from([1])))
}

fn row(
    method: Option<&str>,
    agent: Option<Uuid>,
    perspective: Option<Uuid>,
    evidence: Option<Uuid>,
) -> MassFunctionRow {
    MassFunctionRow {
        id: Uuid::new_v4(),
        claim_id: Uuid::new_v4(),
        frame_id: Uuid::new_v4(),
        source_agent_id: agent,
        perspective_id: perspective,
        masses: serde_json::json!({}),
        conflict_k: None,
        combination_method: method.map(str::to_owned),
        source_strength: None,
        evidence_type: None,
        locality_tag: "unknown".into(),
        evidence_id: evidence,
        created_at: Utc::now(),
    }
}

fn evidence(doi: Option<&str>, url: Option<&str>) -> ItemEvidence {
    ItemEvidence {
        id: Uuid::new_v4(),
        doi: doi.map(str::to_owned),
        source_url: url.map(str::to_owned),
    }
}

fn uuid_of(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// The ways one DOI reaches the store: ingest's bare `properties.doi`, its
/// `https://doi.org/<doi>` source_url, a `doi:` label, a dx link, case and
/// slash variants.
const SPELLINGS: [&str; 6] = [
    "10.5555/Paper.One",
    "https://doi.org/10.5555/paper.one",
    "http://dx.doi.org/10.5555/PAPER.ONE/",
    "doi:10.5555/paper.one",
    " DOI:10.5555/Paper.One ",
    "https://www.doi.org/10.5555/paper.one",
];

/// Methods a row can carry that give it no structural key of its own.
const PLAIN_METHODS: [Option<&str>; 4] =
    [None, Some("discount"), Some("Dempster"), Some("auto_cdst")];

// ── (1) one DOI, one key ────────────────────────────────────────────────────

proptest! {
    #[test]
    fn rows_citing_one_doi_share_one_key_whatever_perspective_agent_or_spelling(
        s1 in 0usize..SPELLINGS.len(),
        s2 in 0usize..SPELLINGS.len(),
        in_url1 in any::<bool>(),
        in_url2 in any::<bool>(),
        a1 in any::<u128>(),
        a2 in any::<u128>(),
        method1 in 0usize..PLAIN_METHODS.len(),
        attributed2 in any::<bool>(),
    ) {
        // Row 1: a lens-perspective row citing evidence e1.
        let e1 = if in_url1 {
            evidence(None, Some(SPELLINGS[s1]))
        } else {
            evidence(Some(SPELLINGS[s1]), None)
        };
        let lens = Uuid::new_v4();
        let r1 = row(PLAIN_METHODS[method1], Some(uuid_of(a1)), Some(lens), Some(e1.id));
        // Row 2: another agent's row (an attribution, or an evidence
        // perspective) citing a different evidence row of the same paper.
        let e2 = if in_url2 {
            evidence(None, Some(SPELLINGS[s2]))
        } else {
            evidence(Some(SPELLINGS[s2]), None)
        };
        let method2 = if attributed2 { Some(ATTRIBUTED_METHOD) } else { Some(INGEST_ASSERTION_METHOD) };
        let r2 = row(method2, Some(uuid_of(a2)), Some(e2.id), Some(e2.id));

        let k1 = item_key(&r1, Some(&e1), None);
        let k2 = item_key(&r2, Some(&e2), None);
        prop_assert_eq!(&k1, &k2);
        prop_assert!(matches!(k1, ItemKey::Doi(_)), "a DOI-bearing row keys on the DOI: {k1}");

        // A different paper is a different key.
        let e3 = evidence(Some("10.5555/paper.two"), None);
        let r3 = row(PLAIN_METHODS[method1], Some(uuid_of(a1)), Some(lens), Some(e3.id));
        prop_assert_ne!(item_key(&r3, Some(&e3), None), k1);
    }
}

#[test]
fn doi_normalization_folds_spellings_and_rejects_non_dois() {
    let canon: BTreeSet<Option<String>> = SPELLINGS.iter().map(|s| normalize_doi(s)).collect();
    assert_eq!(
        canon.len(),
        1,
        "every spelling of one DOI normalizes alike: {canon:?}"
    );
    assert!(canon.iter().all(Option::is_some));
    for blank in ["", "   ", "doi:", "https://doi.org/", "https://doi.org"] {
        assert_eq!(normalize_doi(blank), None, "{blank:?}");
    }
    // A web page is not a DOI, even on a publisher host.
    assert_eq!(normalize_doi("https://example.org/articles/10.5555"), None);
    // Distinct DOIs stay distinct.
    assert_ne!(normalize_doi("10.5555/a"), normalize_doi("10.5555/b"));
}

// ── (2) one paper read by two agents is one source ─────────────────────────

proptest! {
    #[test]
    fn one_paper_read_by_two_agents_folds_to_the_stronger_reading(
        w_ingest in 0.01f64..0.99,
        w_attr in 0.01f64..0.99,
        spelling in 0usize..SPELLINGS.len(),
    ) {
        let ingest_agent = Uuid::new_v4();
        let citing_agent = Uuid::new_v4();
        // The ingest self-assertion, rekeyed onto the paper's level_3
        // evidence row (properties.doi).
        let e_ingest = evidence(Some("10.5555/paper.one"), None);
        let r_ingest = row(Some(INGEST_ASSERTION_METHOD), Some(ingest_agent), Some(e_ingest.id), Some(e_ingest.id));
        // Another agent's citation of the same paper, attributed onto the
        // atom: its evidence carries only a link to the paper.
        let e_cite = evidence(None, Some(SPELLINGS[spelling]));
        let r_cite = row(Some(ATTRIBUTED_METHOD), Some(citing_agent), Some(e_cite.id), Some(e_cite.id));

        let k_ingest = item_key(&r_ingest, Some(&e_ingest), None);
        let k_cite = item_key(&r_cite, Some(&e_cite), None);

        let both = combine_by_item(
            vec![
                (r_ingest.id, k_ingest.clone(), bba(w_ingest, 0.0, 0.0)),
                (r_cite.id, k_cite.clone(), bba(w_attr, 0.0, 0.0)),
            ],
            0.9,
        ).unwrap().0;
        let (strong_id, strong_key, strong_w) = if w_attr >= w_ingest {
            (r_cite.id, k_cite, w_attr)
        } else {
            (r_ingest.id, k_ingest, w_ingest)
        };
        let strongest_alone = combine_by_item(vec![(strong_id, strong_key, bba(strong_w, 0.0, 0.0))], 0.9)
            .unwrap().0;
        prop_assert!(
            (m_t(&both) - m_t(&strongest_alone)).abs() < EPS,
            "one paper must fold to its strongest reading: {} vs {}",
            m_t(&both), m_t(&strongest_alone)
        );
    }
}

#[test]
fn the_spec_example_one_paper_two_agents_is_the_max_not_dempster() {
    // SPEC §3.3: self-assertion m_T .64 plus an attributed .8 of the same
    // paper fold to .8; as two sources Dempster would give 1 − .36·.2 = .928.
    let e_ingest = evidence(Some("10.5555/paper.one"), None);
    let r_ingest = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        Some(e_ingest.id),
        Some(e_ingest.id),
    );
    let e_cite = evidence(None, Some("https://doi.org/10.5555/paper.one"));
    let r_cite = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(e_cite.id),
        Some(e_cite.id),
    );
    let (folded, _) = combine_by_item(
        vec![
            (
                r_ingest.id,
                item_key(&r_ingest, Some(&e_ingest), None),
                bba(0.64, 0.0, 0.0),
            ),
            (
                r_cite.id,
                item_key(&r_cite, Some(&e_cite), None),
                bba(0.8, 0.0, 0.0),
            ),
        ],
        0.9,
    )
    .unwrap();
    assert!((m_t(&folded) - 0.8).abs() < EPS, "got m_T {}", m_t(&folded));
}

#[test]
fn a_legacy_self_assertion_keys_on_its_paper_not_its_agent() {
    // Rule 5: an un-rekeyed ingest self-assertion (no perspective, no
    // evidence) of paper P by two different ingesting agents is one source.
    let paper = Uuid::new_v4();
    let r1 = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        None,
        None,
    );
    let r2 = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        None,
        None,
    );
    let k1 = item_key(&r1, None, Some(paper));
    assert_eq!(k1, item_key(&r2, None, Some(paper)));
    assert_ne!(
        k1,
        item_key(&r2, None, Some(Uuid::new_v4())),
        "another paper, another key"
    );
    // Without a resolved paper the row is its own item.
    assert_eq!(item_key(&r1, None, None), ItemKey::Row(r1.id));
}

// ── (3) a bridging row never merges two papers ─────────────────────────────

/// Exact Bel(every atom of `atoms` is TRUE) for independent items, each the
/// comonotone (quantile) coupling of its per-atom pure-support marginals:
/// one U per item, atom i fixed TRUE when U < w_i. Valid only for items with
/// no FALSE and no open-world mass (asserted), where Dempster has no conflict.
fn bel_all_true(items: &[KeyedItem], atoms: &[Uuid]) -> f64 {
    // Each item as its nested focal sets: (atoms fixed TRUE, probability).
    let per_item: Vec<Vec<(BTreeSet<Uuid>, f64)>> = items
        .iter()
        .map(|it| {
            let mut ws: Vec<(Uuid, f64)> = it
                .atoms
                .iter()
                .map(|(a, m)| {
                    assert!(
                        m_f(m) == 0.0 && m.mass_of_missing() == 0.0,
                        "oracle is support-only"
                    );
                    (*a, m_t(m))
                })
                .collect();
            ws.sort_by(|x, y| y.1.total_cmp(&x.1));
            let mut out = Vec::new();
            for j in 0..ws.len() {
                let next = ws.get(j + 1).map_or(0.0, |x| x.1);
                let fixed: BTreeSet<Uuid> = ws[..=j].iter().map(|x| x.0).collect();
                out.push((fixed, ws[j].1 - next));
            }
            out.push((BTreeSet::new(), 1.0 - ws.first().map_or(0.0, |x| x.1)));
            out
        })
        .collect();
    let want: BTreeSet<Uuid> = atoms.iter().copied().collect();
    let mut total = 0.0;
    let mut stack: Vec<(usize, BTreeSet<Uuid>, f64)> = vec![(0, BTreeSet::new(), 1.0)];
    while let Some((i, fixed, p)) = stack.pop() {
        if i == per_item.len() {
            if want.is_subset(&fixed) {
                total += p;
            }
            continue;
        }
        for (set, q) in &per_item[i] {
            let mut f = fixed.clone();
            f.extend(set.iter().copied());
            stack.push((i + 1, f, p * q));
        }
    }
    total
}

fn keyed(atom: Uuid, key: &ItemKey, m: MassFunction) -> KeyedBba {
    KeyedBba {
        row_id: Uuid::new_v4(),
        atom_id: atom,
        key: key.clone(),
        bba: m,
    }
}

#[test]
fn a_bridging_row_never_merges_two_other_papers() {
    let [a1, a2, a3, a4] = [
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    ];
    let p = ItemKey::Doi("10.5555/p".into());
    let q = ItemKey::Doi("10.5555/q".into());
    let bridge = ItemKey::Doi("10.5555/bridge".into());
    let rows = vec![
        keyed(a1, &p, bba(0.64, 0.0, 0.0)),
        keyed(a2, &p, bba(0.64, 0.0, 0.0)),
        keyed(a3, &q, bba(0.64, 0.0, 0.0)),
        keyed(a4, &q, bba(0.64, 0.0, 0.0)),
        // A third paper touching one atom of each.
        keyed(a2, &bridge, bba(0.5, 0.0, 0.0)),
        keyed(a3, &bridge, bba(0.5, 0.0, 0.0)),
    ];
    let items = item_partition(rows);

    // P and Q are independent and the bridge cannot fix a1 or a4, so
    // Bel(all four) is P's weight times Q's: .64 · .64 = .4096. A merged
    // (comonotone) P∪Q∪bridge item would give min = .5; per-row items .64⁴.
    let bel = bel_all_true(&items, &[a1, a2, a3, a4]);
    assert!((bel - 0.4096).abs() < EPS, "Bel over all four = {bel}");

    // Each paper is one item over exactly its own atoms.
    let atoms_of = |key: &ItemKey| -> BTreeSet<Uuid> {
        items
            .iter()
            .filter(|it| &it.id.key == key)
            .flat_map(|it| it.atoms.iter().map(|(a, _)| *a))
            .collect()
    };
    assert_eq!(
        items.len(),
        3,
        "three papers, three items: {:?}",
        items.iter().map(|i| &i.id).collect::<Vec<_>>()
    );
    assert_eq!(atoms_of(&p), BTreeSet::from([a1, a2]));
    assert_eq!(atoms_of(&q), BTreeSet::from([a3, a4]));
}

// ── (4) query independence ─────────────────────────────────────────────────

/// One random row: (atom index, key index, (t, f, o)). A third of the rows
/// are pure support, a third pure refutation and a third mixed, so the
/// grouped sides are exercised as often as the own-item side.
fn arb_row() -> impl Strategy<Value = (usize, usize, (f64, f64, f64))> {
    let o = || prop_oneof![Just(0.0), 0.0f64..0.1];
    let masses = prop_oneof![
        (0.01f64..0.9, o()).prop_map(|(w, o)| (w, 0.0, o)),
        (0.01f64..0.9, o()).prop_map(|(w, o)| (0.0, w, o)),
        (0.01f64..0.5, 0.01f64..0.4, o()).prop_map(|(t, f, o)| (t, f, o)),
    ];
    (0usize..3, 0usize..4, masses)
}

/// The items an atom sees: (id, its BBA's masses on that atom), sorted.
fn view_of(items: &[KeyedItem], atom: Uuid) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = items
        .iter()
        .filter_map(|it| {
            it.on(atom)
                .map(|m| (format!("{:?}", it.id), format!("{:?}", m.masses())))
        })
        .collect();
    v.sort();
    v
}

proptest! {
    #[test]
    fn adding_a_leaf_never_changes_another_leafs_partition(
        spec in prop::collection::vec(arb_row(), 1..14),
    ) {
        let atoms = [uuid_of(1), uuid_of(2), uuid_of(3)];
        let keys = [
            ItemKey::Doi("10.5555/x".into()),
            ItemKey::Url("https://example.org/y".into()),
            ItemKey::Evidence(uuid_of(7)),
            ItemKey::Paper(uuid_of(8)),
        ];
        let rows: Vec<KeyedBba> = spec
            .iter()
            .enumerate()
            .map(|(i, &(a, k, (t, f, o)))| KeyedBba {
                row_id: uuid_of(1000 + i as u128),
                atom_id: atoms[a],
                key: keys[k].clone(),
                bba: bba(t, f, o),
            })
            .collect();
        let whole = item_partition(rows.clone());
        for &atom in &atoms {
            let alone: Vec<KeyedBba> = rows.iter().filter(|r| r.atom_id == atom).cloned().collect();
            let part = item_partition(alone);
            prop_assert_eq!(view_of(&part, atom), view_of(&whole, atom));
        }
    }
}

// ── (5) a real lens perspective is never a key ─────────────────────────────

proptest! {
    #[test]
    fn a_lens_perspective_is_never_a_key(
        m1 in 0usize..PLAIN_METHODS.len(),
        m2 in 0usize..PLAIN_METHODS.len(),
        same_agent in any::<bool>(),
    ) {
        let lens = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let other = if same_agent { agent } else { Uuid::new_v4() };
        // Two lens rows with no evidence: two items.
        let r1 = row(PLAIN_METHODS[m1], Some(agent), Some(lens), None);
        let r2 = row(PLAIN_METHODS[m2], Some(other), Some(lens), None);
        prop_assert_ne!(item_key(&r1, None, None), item_key(&r2, None, None));
        // Two lens rows citing different evidence: keyed by the evidence.
        let e1 = evidence(None, None);
        let e2 = evidence(None, None);
        let r3 = row(PLAIN_METHODS[m1], Some(agent), Some(lens), Some(e1.id));
        let r4 = row(PLAIN_METHODS[m2], Some(other), Some(lens), Some(e2.id));
        let k3 = item_key(&r3, Some(&e1), None);
        let k4 = item_key(&r4, Some(&e2), None);
        prop_assert_ne!(&k3, &k4);
        prop_assert_eq!(k3, ItemKey::Evidence(e1.id));
    }
}

#[test]
fn structural_keys_follow_the_row_shape_and_rank_below_evidence() {
    let edge = Uuid::new_v4();
    let original_mf = Uuid::new_v4();
    // Edge-factor rows of one edge share a key; another edge does not.
    let e1 = row(
        Some(EDGE_FACTOR_METHOD),
        Some(Uuid::new_v4()),
        Some(edge),
        None,
    );
    let e2 = row(
        Some(EDGE_FACTOR_METHOD),
        Some(Uuid::new_v4()),
        Some(edge),
        None,
    );
    assert_eq!(item_key(&e1, None, None), ItemKey::Edge(edge));
    assert_eq!(item_key(&e1, None, None), item_key(&e2, None, None));
    // A textless attribution keys on the original BBA it re-cites.
    let t2 = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(original_mf),
        None,
    );
    assert_eq!(item_key(&t2, None, None), ItemKey::Attribution(original_mf));
    // An attribution whose evidence the viewer cannot see is not keyed on
    // its perspective: it cites evidence, so it falls through to its row.
    let hidden = Uuid::new_v4();
    let t1_hidden = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(hidden),
        Some(hidden),
    );
    assert_eq!(item_key(&t1_hidden, None, None), ItemKey::Row(t1_hidden.id));
    // Evidence outranks the structural keys, url outranks the bare id and
    // a DOI outranks the url.
    let ev = evidence(None, None);
    let with_ev = row(
        Some(EDGE_FACTOR_METHOD),
        Some(Uuid::new_v4()),
        Some(edge),
        Some(ev.id),
    );
    assert_eq!(
        item_key(&with_ev, Some(&ev), None),
        ItemKey::Evidence(ev.id)
    );
    let ev_url = evidence(None, Some("https://Example.org/a/"));
    let r_url = row(None, None, None, Some(ev_url.id));
    assert!(matches!(
        item_key(&r_url, Some(&ev_url), None),
        ItemKey::Url(_)
    ));
    let ev_both = evidence(Some("10.5555/z"), Some("https://example.org/a"));
    let r_both = row(None, None, None, Some(ev_both.id));
    assert!(matches!(
        item_key(&r_both, Some(&ev_both), None),
        ItemKey::Doi(_)
    ));
}

// ── (6) one lineage's support and refutation ───────────────────────────────

proptest! {
    #[test]
    fn a_lineages_refutation_survives_its_support(
        t in 0.05f64..0.95,
        f in 0.05f64..0.95,
    ) {
        let key = ItemKey::Doi("10.5555/lineage".into());
        let (folded, _) = combine_by_item(
            vec![
                (Uuid::new_v4(), key.clone(), bba(t, 0.0, 0.0)),
                (Uuid::new_v4(), key.clone(), bba(0.0, f, 0.0)),
            ],
            0.9,
        )
        .unwrap();
        prop_assert!(m_f(&folded) > 0.0, "the refutation was lost: {:?}", folded.masses());
        prop_assert!(m_t(&folded) <= t + EPS, "Bel {} above the support weight {t}", m_t(&folded));
    }
}

#[test]
fn a_lineages_support_and_refutation_are_two_items() {
    let atom = Uuid::new_v4();
    let key = ItemKey::Doi("10.5555/lineage".into());
    let items = item_partition(vec![
        keyed(atom, &key, bba(0.64, 0.0, 0.0)),
        keyed(atom, &key, bba(0.5, 0.0, 0.0)),
        keyed(atom, &key, bba(0.0, 0.41, 0.0)),
        keyed(atom, &key, bba(0.0, 0.2, 0.0)),
    ]);
    let sides: BTreeSet<ItemSide> = items.iter().map(|i| i.id.side.clone()).collect();
    assert_eq!(sides, BTreeSet::from([ItemSide::Support, ItemSide::Refute]));
    for it in &items {
        assert!(it.id.key == key);
    }
}

#[test]
fn a_mixed_row_is_its_own_item_with_its_exact_bba() {
    let atom = Uuid::new_v4();
    let key = ItemKey::Doi("10.5555/mixed".into());
    let mixed = bba(0.3, 0.2, 0.0);
    let mixed_row = KeyedBba {
        row_id: Uuid::new_v4(),
        atom_id: atom,
        key: key.clone(),
        bba: mixed.clone(),
    };
    let items = item_partition(vec![
        keyed(atom, &key, bba(0.6, 0.0, 0.0)),
        mixed_row.clone(),
    ]);
    assert_eq!(items.len(), 2);
    let own = items
        .iter()
        .find(|i| i.id.side == ItemSide::Own(mixed_row.row_id))
        .expect("the mixed row is its own item");
    assert_eq!(own.on(atom).unwrap().masses(), mixed.masses());
}

#[test]
fn distinct_keys_on_one_atom_still_reinforce() {
    let one = bba(0.64, 0.0, 0.0);
    let (alone, _) = combine_by_item(
        vec![(
            Uuid::new_v4(),
            ItemKey::Doi("10.5555/a".into()),
            one.clone(),
        )],
        0.9,
    )
    .unwrap();
    let (two, _) = combine_by_item(
        vec![
            (
                Uuid::new_v4(),
                ItemKey::Doi("10.5555/a".into()),
                one.clone(),
            ),
            (Uuid::new_v4(), ItemKey::Doi("10.5555/b".into()), one),
        ],
        0.9,
    )
    .unwrap();
    assert!(
        m_t(&two) > m_t(&alone) + 1e-6,
        "{} -> {}",
        m_t(&alone),
        m_t(&two)
    );
}
