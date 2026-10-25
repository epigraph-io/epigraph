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

#[test]
fn a_non_10_identifier_meets_its_doi_label() {
    // Ingest stores a non-`10.` identifier bare in `properties.doi` and links
    // to it as `doi:<id>`; both must give one key, and it must not be a url.
    let bare = evidence(Some("arXiv:2401.01234"), None);
    let label = evidence(None, Some("doi:arXiv:2401.01234"));
    let r1 = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        Some(bare.id),
        Some(bare.id),
    );
    let r2 = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(label.id),
        Some(label.id),
    );
    let k1 = item_key(&r1, Some(&bare), None);
    assert!(matches!(k1, ItemKey::Doi(_)), "{k1}");
    assert_eq!(k1, item_key(&r2, Some(&label), None));
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
        prop_assert_eq!(&k_ingest, &k_cite);
        let strongest = w_ingest.max(w_attr);
        prop_assert!(
            (m_t(&both) - strongest).abs() < EPS,
            "one paper must fold to its strongest reading: {} vs {strongest}",
            m_t(&both)
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
    // its perspective as a lens: it cites evidence, and the evidence id it
    // cites (already on the visible row) is its key.
    let hidden = Uuid::new_v4();
    let t1_hidden = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(hidden),
        Some(hidden),
    );
    assert_eq!(item_key(&t1_hidden, None, None), ItemKey::Evidence(hidden));
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
    // The weaker row of each side comes first AND has the smaller row id, so
    // neither "keep the first row" nor "keep the smaller id" can pass.
    let at = |id: u128, m: MassFunction| KeyedBba {
        row_id: uuid_of(id),
        atom_id: atom,
        key: key.clone(),
        bba: m,
    };
    let items = item_partition(vec![
        at(1, bba(0.5, 0.0, 0.0)),
        at(3, bba(0.0, 0.2, 0.0)),
        at(2, bba(0.64, 0.0, 0.0)),
        at(4, bba(0.0, 0.41, 0.0)),
    ]);
    let sides: BTreeSet<ItemSide> = items.iter().map(|i| i.id.side.clone()).collect();
    assert_eq!(sides, BTreeSet::from([ItemSide::Support, ItemSide::Refute]));
    for it in &items {
        assert!(it.id.key == key);
    }
    let side = |s: ItemSide| {
        items
            .iter()
            .find(|i| i.id.side == s)
            .and_then(|i| i.on(atom))
            .unwrap()
            .clone()
    };
    let support = side(ItemSide::Support);
    let refute = side(ItemSide::Refute);
    assert!((m_t(&support) - 0.64).abs() < EPS, "{:?}", support.masses());
    assert_eq!(m_f(&support), 0.0);
    assert!((m_f(&refute) - 0.41).abs() < EPS, "{:?}", refute.masses());
    assert_eq!(m_t(&refute), 0.0);
}

proptest! {
    #[test]
    fn one_keys_rows_keep_the_max_per_literal(
        ts in prop::collection::vec(0.01f64..0.95, 1..6),
        fs in prop::collection::vec(0.01f64..0.95, 1..6),
        interleave in any::<bool>(),
    ) {
        let atom = uuid_of(1);
        let key = ItemKey::Evidence(uuid_of(9));
        let support = ts.iter().map(|&t| bba(t, 0.0, 0.0));
        let refute = fs.iter().map(|&f| bba(0.0, f, 0.0));
        let masses: Vec<MassFunction> = if interleave {
            let mut v = Vec::new();
            let (mut a, mut b) = (support, refute);
            loop {
                match (a.next(), b.next()) {
                    (None, None) => break,
                    (x, y) => v.extend(x.into_iter().chain(y)),
                }
            }
            v
        } else {
            refute.chain(support).collect()
        };
        let rows: Vec<KeyedBba> = masses
            .into_iter()
            .enumerate()
            .map(|(i, m)| KeyedBba { row_id: uuid_of(100 + i as u128), atom_id: atom, key: key.clone(), bba: m })
            .collect();
        let t_max = ts.iter().copied().fold(0.0, f64::max);
        let f_max = fs.iter().copied().fold(0.0, f64::max);

        let items = item_partition(rows.clone());
        prop_assert_eq!(items.len(), 2);
        for it in &items {
            let m = it.on(atom).unwrap();
            match it.id.side {
                ItemSide::Support => prop_assert!((m_t(m) - t_max).abs() < EPS && m_f(m) == 0.0),
                ItemSide::Refute => prop_assert!((m_f(m) - f_max).abs() < EPS && m_t(m) == 0.0),
                ItemSide::Own(_) => prop_assert!(false, "no mixed row was given"),
            }
        }
        // SPEC §3.3 / plan (6): the folded atom keeps the refutation and its
        // Bel never exceeds the strongest support row of the lineage.
        let (folded, _) = combine_by_item(
            rows.into_iter().map(|r| (r.row_id, r.key, r.bba)).collect(),
            0.9,
        ).unwrap();
        prop_assert!(m_f(&folded) > 0.0);
        prop_assert!(m_t(&folded) <= t_max + EPS, "Bel {} above max support {t_max}", m_t(&folded));
    }
}

// ── rows the within-group rule cannot read are their own items ─────────────

fn ternary() -> FrameOfDiscernment {
    FrameOfDiscernment::new("ternary", vec!["A".into(), "B".into(), "C".into()]).unwrap()
}

#[test]
fn a_row_the_rule_cannot_read_is_its_own_item_with_its_exact_bba() {
    let atom = Uuid::new_v4();
    let key = ItemKey::Doi("10.5555/odd".into());
    let fr = binary();
    let t = FocalElement::positive(BTreeSet::from([0]));
    let theta = FocalElement::theta(&fr);
    // Conflict (∅) mass carried by a stored row.
    let with_conflict = MassFunction::new(
        fr.clone(),
        BTreeMap::from([
            (t.clone(), 0.5),
            (FocalElement::conflict(), 0.1),
            (theta.clone(), 0.4),
        ]),
    )
    .unwrap();
    // A CDST complement element other than `~`.
    let with_complement = MassFunction::new(
        fr.clone(),
        BTreeMap::from([
            (t.clone(), 0.3),
            (FocalElement::negative(BTreeSet::from([0])), 0.2),
            (theta, 0.5),
        ]),
    )
    .unwrap();
    // A row on a frame of another size: index 0 is not "the claim holds".
    let tf = ternary();
    let three = MassFunction::new(
        tf.clone(),
        BTreeMap::from([
            (FocalElement::positive(BTreeSet::from([0])), 0.5),
            (FocalElement::theta(&tf), 0.5),
        ]),
    )
    .unwrap();
    for odd in [with_conflict, with_complement, three] {
        let odd_row = KeyedBba {
            row_id: Uuid::new_v4(),
            atom_id: atom,
            key: key.clone(),
            bba: odd.clone(),
        };
        // Next to a weaker plain support row of the same key, which it would
        // replace if it were read as support.
        let items = item_partition(vec![keyed(atom, &key, bba(0.2, 0.0, 0.0)), odd_row.clone()]);
        assert_eq!(items.len(), 2, "{:?}", odd.masses());
        let own = items
            .iter()
            .find(|i| i.id.side == ItemSide::Own(odd_row.row_id))
            .unwrap_or_else(|| panic!("not its own item: {:?}", odd.masses()));
        assert_eq!(own.on(atom).unwrap().masses(), odd.masses());
        let support = items
            .iter()
            .find(|i| i.id.side == ItemSide::Support)
            .and_then(|i| i.on(atom))
            .unwrap();
        assert!((m_t(support) - 0.2).abs() < EPS);
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

// ── what a key must NOT merge ──────────────────────────────────────────────
//
// `doi:` and `url:` ignore the agent, so a string that names no document
// would merge unrelated sources across agents. Writers do put such strings
// in both slots: `properties.doi` can hold an ingest placeholder ("unknown",
// "n/a", ...; the ingest fix for those only stops new ones), and
// `evidence.source_url` holds whatever the caller passed (a witness name, a
// note). Each of those rows must fall to its own evidence id.

/// Placeholders a writer may leave in a DOI slot, in assorted spellings.
const PLACEHOLDERS: [&str; 10] = [
    "unknown", "UNKNOWN", " n/a ", "N/A", "na", "None", "null", "nil", "-", "TBD",
];

proptest! {
    #[test]
    fn a_placeholder_doi_names_no_paper(
        p1 in 0usize..PLACEHOLDERS.len(),
        p2 in 0usize..PLACEHOLDERS.len(),
        as_link in any::<bool>(),
    ) {
        let spell = |p: &str| if as_link { format!("https://doi.org/{}", p.trim()) } else { p.to_owned() };
        let e1 = evidence(Some(&spell(PLACEHOLDERS[p1])), None);
        let e2 = evidence(Some(&spell(PLACEHOLDERS[p2])), None);
        let r1 = row(Some(INGEST_ASSERTION_METHOD), Some(Uuid::new_v4()), Some(e1.id), Some(e1.id));
        let r2 = row(Some(INGEST_ASSERTION_METHOD), Some(Uuid::new_v4()), Some(e2.id), Some(e2.id));
        prop_assert_eq!(item_key(&r1, Some(&e1), None), ItemKey::Evidence(e1.id));
        prop_assert_eq!(item_key(&r2, Some(&e2), None), ItemKey::Evidence(e2.id));
        prop_assert_eq!(normalize_doi(PLACEHOLDERS[p1]), None);
        prop_assert_eq!(normalize_doi(&format!("doi:{}", PLACEHOLDERS[p1].trim())), None);
    }
}

#[test]
fn two_papers_with_a_placeholder_doi_still_reinforce() {
    // Two unrelated documents whose evidence both say doi "unknown" are two
    // sources: Dempster gives 1 − .36·.36 = .8704, not the max .64.
    let e1 = evidence(Some("unknown"), None);
    let e2 = evidence(Some("Unknown"), None);
    let r1 = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        Some(e1.id),
        Some(e1.id),
    );
    let r2 = row(
        Some(INGEST_ASSERTION_METHOD),
        Some(Uuid::new_v4()),
        Some(e2.id),
        Some(e2.id),
    );
    let (folded, _) = combine_by_item(
        vec![
            (r1.id, item_key(&r1, Some(&e1), None), bba(0.64, 0.0, 0.0)),
            (r2.id, item_key(&r2, Some(&e2), None), bba(0.64, 0.0, 0.0)),
        ],
        0.9,
    )
    .unwrap();
    assert!(
        (m_t(&folded) - (1.0 - 0.36 * 0.36)).abs() < EPS,
        "got m_T {}",
        m_t(&folded)
    );
}

/// `source_url` values that are not links: what callers put there when the
/// source is a person, a conversation or a note, plus two strings that only
/// look like a bare DOI.
const FREE_TEXT_URLS: [&str; 6] = [
    "unknown",
    "press release",
    "conversation with the lab lead",
    "www.example.org/no-scheme",
    "10.0.0.5/notes",
    "10.5 mg dose",
];

proptest! {
    #[test]
    fn a_free_text_source_url_is_not_a_shared_key(
        u in 0usize..FREE_TEXT_URLS.len(),
        w1 in 0.05f64..0.95,
        w2 in 0.05f64..0.95,
    ) {
        // Two agents, two unrelated testimonies with the same free text.
        let e1 = evidence(None, Some(FREE_TEXT_URLS[u]));
        let e2 = evidence(None, Some(FREE_TEXT_URLS[u]));
        let r1 = row(Some("discount"), Some(Uuid::new_v4()), Some(e1.id), Some(e1.id));
        let r2 = row(Some("discount"), Some(Uuid::new_v4()), Some(e2.id), Some(e2.id));
        let k1 = item_key(&r1, Some(&e1), None);
        let k2 = item_key(&r2, Some(&e2), None);
        prop_assert_eq!(&k1, &ItemKey::Evidence(e1.id));
        prop_assert_eq!(&k2, &ItemKey::Evidence(e2.id));
        let (folded, _) = combine_by_item(
            vec![(r1.id, k1, bba(w1, 0.0, 0.0)), (r2.id, k2, bba(w2, 0.0, 0.0))],
            0.9,
        ).unwrap();
        let dempster = 1.0 - (1.0 - w1) * (1.0 - w2);
        prop_assert!((m_t(&folded) - dempster).abs() < EPS, "{} vs {dempster}", m_t(&folded));
    }
}

#[test]
fn a_rejected_doi_link_names_nothing_not_a_url() {
    // A DOI resolver link with no DOI behind it is not the web page
    // "https://doi.org": every such row would share that one url: key.
    for link in [
        "https://doi.org/",
        "https://doi.org",
        "http://dx.doi.org",
        "https://doi.org/unknown",
        "https://doi.org/N/A",
        "doi:",
        "doi:none",
    ] {
        let in_url = evidence(None, Some(link));
        let r = row(None, Some(Uuid::new_v4()), None, Some(in_url.id));
        assert_eq!(
            item_key(&r, Some(&in_url), None),
            ItemKey::Evidence(in_url.id),
            "source_url {link:?}"
        );
        let in_doi = evidence(Some(link), None);
        let r = row(None, Some(Uuid::new_v4()), None, Some(in_doi.id));
        assert_eq!(
            item_key(&r, Some(&in_doi), None),
            ItemKey::Evidence(in_doi.id),
            "properties.doi {link:?}"
        );
    }
}

#[test]
fn a_well_formed_bare_doi_in_source_url_is_still_a_doi() {
    let e = evidence(None, Some("10.5555/Paper.One"));
    let r = row(None, Some(Uuid::new_v4()), None, Some(e.id));
    assert_eq!(
        item_key(&r, Some(&e), None),
        ItemKey::Doi("10.5555/paper.one".into())
    );
}

// ── a document identified by a URI ─────────────────────────────────────────

proptest! {
    #[test]
    fn a_uri_identified_paper_meets_its_citation_under_one_key(
        w_ingest in 0.01f64..0.99,
        w_attr in 0.01f64..0.99,
        cite_as_label in any::<bool>(),
    ) {
        // Ingest identifies a document with no DOI and no arXiv id by its URI
        // and stores that in `properties.doi`; a citation of the same
        // document carries the URI as its source_url (or the `doi:<uri>`
        // label ingest builds for a non-`10.` identifier).
        let uri = "https://example.org/reports/Report-7.pdf";
        let e_ingest = evidence(Some(uri), None);
        let r_ingest = row(Some(INGEST_ASSERTION_METHOD), Some(Uuid::new_v4()), Some(e_ingest.id), Some(e_ingest.id));
        let cited = if cite_as_label { format!("doi:{uri}") } else { uri.to_ascii_lowercase() };
        let e_cite = evidence(None, Some(&cited));
        let r_cite = row(Some(ATTRIBUTED_METHOD), Some(Uuid::new_v4()), Some(e_cite.id), Some(e_cite.id));
        let k_ingest = item_key(&r_ingest, Some(&e_ingest), None);
        let k_cite = item_key(&r_cite, Some(&e_cite), None);
        prop_assert!(matches!(k_ingest, ItemKey::Url(_)), "{k_ingest}");
        prop_assert_eq!(&k_ingest, &k_cite);
        let (folded, _) = combine_by_item(
            vec![
                (r_ingest.id, k_ingest, bba(w_ingest, 0.0, 0.0)),
                (r_cite.id, k_cite, bba(w_attr, 0.0, 0.0)),
            ],
            0.9,
        ).unwrap();
        prop_assert!((m_t(&folded) - w_ingest.max(w_attr)).abs() < EPS);
    }
}

// ── evidence the viewer cannot see ─────────────────────────────────────────

#[test]
fn rows_citing_one_hidden_evidence_row_stay_one_item() {
    // A `whole` attribution of evidence E copied onto two atoms, and an edge
    // factor that also names E, as seen by a viewer who cannot read E: the
    // evidence id is on every visible row, so they still share E's key.
    let hidden = Uuid::new_v4();
    let [a1, a2] = [Uuid::new_v4(), Uuid::new_v4()];
    let mut on_a1 = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(hidden),
        Some(hidden),
    );
    on_a1.claim_id = a1;
    let mut on_a2 = row(
        Some(ATTRIBUTED_METHOD),
        Some(Uuid::new_v4()),
        Some(hidden),
        Some(hidden),
    );
    on_a2.claim_id = a2;
    let edge_row = row(
        Some(EDGE_FACTOR_METHOD),
        Some(Uuid::new_v4()),
        Some(Uuid::new_v4()),
        Some(hidden),
    );
    let k1 = item_key(&on_a1, None, None);
    assert_eq!(k1, ItemKey::Evidence(hidden));
    assert_eq!(item_key(&on_a2, None, None), k1);
    assert_eq!(item_key(&edge_row, None, None), k1);
    // So the compound over both atoms keeps E's weight once (.8), not .8².
    let items = item_partition(vec![
        keyed(a1, &k1, bba(0.8, 0.0, 0.0)),
        keyed(a2, &k1, bba(0.8, 0.0, 0.0)),
    ]);
    let bel = bel_all_true(&items, &[a1, a2]);
    assert!((bel - 0.8).abs() < EPS, "Bel over both atoms = {bel}");
}

// ── ties ───────────────────────────────────────────────────────────────────

/// Every item as (id, its atoms with their masses), all sorted: the partition
/// with input order removed.
fn canonical(items: &[KeyedItem]) -> Vec<(String, Vec<(Uuid, String)>)> {
    let mut v: Vec<(String, Vec<(Uuid, String)>)> = items
        .iter()
        .map(|it| {
            let mut atoms: Vec<(Uuid, String)> = it
                .atoms
                .iter()
                .map(|(a, m)| (*a, format!("{:?}", m.masses())))
                .collect();
            atoms.sort();
            (format!("{:?}", it.id), atoms)
        })
        .collect();
    v.sort();
    v
}

#[test]
fn rows_that_tie_on_weight_partition_the_same_in_any_order() {
    // Two support rows of one key with equal m(TRUE) but different `~` mass:
    // which one the item keeps must not depend on the order of the read.
    let atom = Uuid::new_v4();
    let key = ItemKey::Doi("10.5555/tie".into());
    let rows = vec![
        KeyedBba {
            row_id: uuid_of(2),
            atom_id: atom,
            key: key.clone(),
            bba: bba(0.5, 0.0, 0.3),
        },
        KeyedBba {
            row_id: uuid_of(1),
            atom_id: atom,
            key: key.clone(),
            bba: bba(0.5, 0.0, 0.0),
        },
    ];
    let mut reversed = rows.clone();
    reversed.reverse();
    assert_eq!(
        canonical(&item_partition(rows)),
        canonical(&item_partition(reversed))
    );
}

/// Masses drawn from a small set, so rows of one key often tie on weight.
fn arb_tie_row() -> impl Strategy<Value = (usize, usize, (f64, f64, f64))> {
    let masses = prop_oneof![
        Just((0.5, 0.0, 0.3)),
        Just((0.5, 0.0, 0.0)),
        Just((0.5, 0.0, 0.1)),
        Just((0.0, 0.4, 0.0)),
        Just((0.0, 0.4, 0.2)),
        Just((0.0, 0.0, 0.0)),
        Just((0.0, 0.0, 0.2)),
    ];
    (0usize..2, 0usize..2, masses)
}

proptest! {
    #[test]
    fn the_partition_is_a_function_of_the_rows_not_their_order(
        spec in prop::collection::vec(arb_tie_row(), 1..10),
        rotate in 0usize..10,
    ) {
        let atoms = [uuid_of(1), uuid_of(2)];
        let keys = [ItemKey::Doi("10.5555/x".into()), ItemKey::Evidence(uuid_of(7))];
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
        let mut reversed = rows.clone();
        reversed.reverse();
        let mut rotated = rows.clone();
        let n = rotated.len();
        rotated.rotate_left(rotate % n);
        let want = canonical(&item_partition(rows));
        prop_assert_eq!(&canonical(&item_partition(reversed)), &want);
        prop_assert_eq!(&canonical(&item_partition(rotated)), &want);
    }
}
