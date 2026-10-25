//! Properties of `conjunction::conj_belief`, the item-structured conjunction
//! (R-DEP) of SPEC §3.3, its `not_all` valuation (§3.6) and the spine profile
//! (§2.2). The SPEC (the atom-level belief design) is not in this repository;
//! the rules these tests rely on are stated in `conjunction`'s documentation
//! and next to each test.
//!
//! Every expectation here comes from an independent source, never from the
//! formula the operator is implemented by:
//!
//! - the served atom fold (`combination::dempster_combine` + `measures`), for
//!   single-leaf queries (marginal consistency);
//! - a brute-force oracle over explicit world sets, in which each atom takes
//!   one of T, F or "outside the frame" (X). It builds each item's focal sets
//!   itself, from the raw per-atom masses and the quantile rule as the SPEC
//!   states it (`spec_focals`), never through `Item::focal_elements`. Focal
//!   sets are intersected as sets, and Bel / Pl / Dis / Bel(OR) are subset or
//!   overlap tests. The oracle never sees the DP's meet table;
//! - a closed-world 2ⁿ oracle for the product-frame `BetP` (standard
//!   pignistic transform over complete assignments);
//! - structural laws: independence (disjoint items factor), comonotone
//!   minimum, round trip of a `whole` item, monotonicity, polarity symmetry.

use epigraph_ds::combination::dempster_combine;
use epigraph_ds::conjunction::{
    conj_belief, joint_bel, not_all_closed_form, profile, single_negative_sibling, ConjResult,
    Item, Letter, Lit, MAX_LEAVES,
};
use epigraph_ds::measures::{belief, pignistic_probability, plausibility};
use epigraph_ds::{DsError, FocalElement, FrameOfDiscernment, MassFunction};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

const EPS: f64 = 1e-9;

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= EPS
}

// ---------------------------------------------------------------------------
// The served single-atom fold (CDST, binary frame: index 0 = true, 1 = false)
// ---------------------------------------------------------------------------

fn binary_frame() -> FrameOfDiscernment {
    FrameOfDiscernment::new("atom", vec!["true".into(), "false".into()]).unwrap()
}

/// The served-shape BBA {T t, F f, `~` o, Θ rest} on the binary frame.
fn served_bba(t: f64, f: f64, o: f64) -> MassFunction {
    let frame = binary_frame();
    let mut masses = BTreeMap::new();
    let theta = 1.0 - t - f - o;
    for (fe, v) in [
        (FocalElement::positive(BTreeSet::from([0])), t),
        (FocalElement::positive(BTreeSet::from([1])), f),
        (FocalElement::missing(&frame), o),
        (FocalElement::theta(&frame), theta),
    ] {
        if v > 0.0 {
            masses.insert(fe, v);
        }
    }
    MassFunction::new(frame, masses).unwrap()
}

/// (Bel(T), Pl(T), BetP(T), 1 − Bel(F)) as the served atom read computes them.
fn served_measures(m: &MassFunction) -> (f64, f64, f64, f64) {
    let t = FocalElement::positive(BTreeSet::from([0]));
    let f = FocalElement::positive(BTreeSet::from([1]));
    (
        belief(m, &t),
        plausibility(m, &t),
        pignistic_probability(m, 0),
        1.0 - belief(m, &f),
    )
}

// ---------------------------------------------------------------------------
// Brute-force oracle over explicit world sets
// ---------------------------------------------------------------------------

/// A set of worlds over n ≤ 5 atoms, each atom ∈ {T=0, F=1, X=2}: 3ⁿ ≤ 243 bits.
type Worlds = [u64; 4];

fn world_count(n: usize) -> usize {
    3usize.pow(n as u32)
}

fn digit(world: usize, pos: usize) -> usize {
    (world / 3usize.pow(pos as u32)) % 3
}

fn set_from(n: usize, pred: impl Fn(usize) -> bool) -> Worlds {
    let mut s = [0u64; 4];
    for w in 0..world_count(n) {
        if pred(w) {
            s[w / 64] |= 1 << (w % 64);
        }
    }
    s
}

fn and(a: &Worlds, b: &Worlds) -> Worlds {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

fn is_empty(a: &Worlds) -> bool {
    a.iter().all(|x| *x == 0)
}

fn subset(a: &Worlds, b: &Worlds) -> bool {
    a.iter().zip(b.iter()).all(|(x, y)| x & !y == 0)
}

/// Allowed digits for one atom under a letter (T=0, F=1, X=2).
fn allowed(letter: Letter) -> &'static [usize] {
    match letter {
        Letter::T => &[0],
        Letter::F => &[1],
        Letter::Theta => &[0, 1],
        Letter::O => &[2],
    }
}

/// The world set of one focal element, projected onto the query atoms.
/// An atom the focal element does not mention is unconstrained (all 3 digits).
fn focal_worlds(n: usize, atoms: &[u32], letters: &[(u32, Letter)]) -> Worlds {
    let per_pos: Vec<Option<&'static [usize]>> = atoms
        .iter()
        .map(|a| {
            letters
                .iter()
                .find(|(x, _)| x == a)
                .map(|(_, l)| allowed(*l))
        })
        .collect();
    set_from(n, |w| {
        (0..n).all(|p| match per_pos[p] {
            None => true,
            Some(ds) => ds.contains(&digit(w, p)),
        })
    })
}

/// The digit an atom takes when its literal holds.
fn lit_digit(l: &Lit<u32>) -> usize {
    if l.positive {
        0
    } else {
        1
    }
}

#[derive(Debug, Default)]
struct Oracle {
    bel: f64,
    /// Bel of the conjunction of the first two query literals, in the same joint.
    bel_first_two: f64,
    /// Per query literal, in the same joint: Bel, Pl and NR of that literal.
    leaf_bel: Vec<f64>,
    leaf_pl: Vec<f64>,
    leaf_nr: Vec<f64>,
    pl: f64,
    nr: f64,
    bel_or: f64,
    k: f64,
}

/// One extra valuation: mass `m` on "not all of these query literals hold"
/// (a positive set on the closed frame of those atoms), 1 − m on "those atoms
/// are in the frame". Positions index into the query.
struct Clause {
    m: f64,
    positions: Vec<usize>,
}

fn oracle(query: &[Lit<u32>], raws: &[Raw], clauses: &[Clause]) -> Oracle {
    let n = query.len();
    let atoms: Vec<u32> = query.iter().map(|l| l.atom).collect();
    let mut bodies: Vec<Vec<(f64, Worlds)>> = Vec::new();
    for raw in raws {
        let fs: Vec<(f64, Worlds)> = spec_focals(raw)
            .into_iter()
            .filter(|(_, letters)| letters.iter().any(|(a, _)| atoms.contains(a)))
            .map(|(mass, letters)| (mass, focal_worlds(n, &atoms, &letters)))
            .collect();
        // An item that never touches the query is vacuous on it.
        if !fs.is_empty() {
            bodies.push(fs);
        }
    }
    for c in clauses {
        let in_frame = set_from(n, |w| c.positions.iter().all(|&p| digit(w, p) != 2));
        let not_all = set_from(n, |w| {
            c.positions.iter().all(|&p| digit(w, p) != 2)
                && !c
                    .positions
                    .iter()
                    .all(|&p| digit(w, p) == lit_digit(&query[p]))
        });
        let mut fs = vec![(1.0 - c.m, in_frame)];
        if c.m > 0.0 {
            fs.push((c.m, not_all));
        }
        bodies.push(fs);
    }
    let target = set_from(n, |w| (0..n).all(|p| digit(w, p) == lit_digit(&query[p])));
    let refuted = set_from(n, |w| {
        (0..n).any(|p| digit(w, p) == 1 - lit_digit(&query[p]))
    });
    let any_holds = set_from(n, |w| (0..n).any(|p| digit(w, p) == lit_digit(&query[p])));
    let first_two = set_from(n, |w| {
        (0..n.min(2)).all(|p| digit(w, p) == lit_digit(&query[p]))
    });

    let leaf_holds: Vec<Worlds> = (0..n)
        .map(|p| set_from(n, |w| digit(w, p) == lit_digit(&query[p])))
        .collect();
    let leaf_fails: Vec<Worlds> = (0..n)
        .map(|p| set_from(n, |w| digit(w, p) == 1 - lit_digit(&query[p])))
        .collect();
    let mut acc = Oracle {
        leaf_bel: vec![0.0; n],
        leaf_pl: vec![0.0; n],
        leaf_nr: vec![0.0; n],
        ..Oracle::default()
    };
    let mut leaf_dis = vec![0.0; n];
    let mut dis = 0.0;
    // Normalize by the summed mass of non-empty intersections, not by 1 − K:
    // near total conflict, 1 − K by subtraction loses the digits the
    // comparison tolerance needs.
    let mut surviving = 0.0;
    let full = set_from(n, |_| true);
    fn walk(
        bodies: &[Vec<(f64, Worlds)>],
        i: usize,
        mass: f64,
        set: Worlds,
        f: &mut dyn FnMut(f64, &Worlds),
    ) {
        if mass == 0.0 {
            return;
        }
        if i == bodies.len() {
            f(mass, &set);
            return;
        }
        for (m, s) in &bodies[i] {
            walk(bodies, i + 1, mass * m, and(&set, s), f);
        }
    }
    walk(&bodies, 0, 1.0, full, &mut |m, s| {
        if is_empty(s) {
            acc.k += m;
            return;
        }
        surviving += m;
        if subset(s, &target) {
            acc.bel += m;
        }
        if subset(s, &first_two) {
            acc.bel_first_two += m;
        }
        if !is_empty(&and(s, &target)) {
            acc.pl += m;
        }
        if subset(s, &refuted) {
            dis += m;
        }
        if subset(s, &any_holds) {
            acc.bel_or += m;
        }
        for p in 0..n {
            if subset(s, &leaf_holds[p]) {
                acc.leaf_bel[p] += m;
            }
            if !is_empty(&and(s, &leaf_holds[p])) {
                acc.leaf_pl[p] += m;
            }
            if subset(s, &leaf_fails[p]) {
                leaf_dis[p] += m;
            }
        }
    });
    let z = surviving;
    acc.bel /= z;
    acc.bel_first_two /= z;
    acc.pl /= z;
    acc.bel_or /= z;
    acc.nr = 1.0 - dis / z;
    for b in &mut acc.leaf_bel {
        *b /= z;
    }
    for x in &mut acc.leaf_pl {
        *x /= z;
    }
    acc.leaf_nr = leaf_dis.iter().map(|d| 1.0 - d / z).collect();
    acc
}

/// Closed-world oracle (no `~`): complete assignments over n ≤ 6 atoms,
/// returning (Bel, Pl, `BetP`, K) with `BetP` the pignistic share of the target world.
fn closed_world_oracle(
    query: &[Lit<u32>],
    raws: &[Raw],
    clauses: &[Clause],
) -> (f64, f64, f64, f64) {
    let n = query.len();
    let atoms: Vec<u32> = query.iter().map(|l| l.atom).collect();
    let bit = |w: usize, p: usize| (w >> p) & 1; // 0 = T, 1 = F
    let worlds = 1usize << n;
    let mk = |pred: &dyn Fn(usize) -> bool| -> u64 {
        (0..worlds)
            .filter(|w| pred(*w))
            .fold(0u64, |s, w| s | (1 << w))
    };
    let mut bodies: Vec<Vec<(f64, u64)>> = Vec::new();
    for raw in raws {
        let fs: Vec<(f64, u64)> = spec_focals(raw)
            .into_iter()
            .filter(|(_, letters)| letters.iter().any(|(a, _)| atoms.contains(a)))
            .map(|(mass, letters)| {
                let set = mk(&|w| {
                    (0..n).all(|p| match letters.iter().find(|(a, _)| *a == atoms[p]) {
                        None | Some((_, Letter::Theta)) => true,
                        Some((_, Letter::T)) => bit(w, p) == 0,
                        Some((_, Letter::F)) => bit(w, p) == 1,
                        Some((_, Letter::O)) => panic!("closed-world oracle given `~` mass"),
                    })
                });
                (mass, set)
            })
            .collect();
        if !fs.is_empty() {
            bodies.push(fs);
        }
    }
    let target_world = (0..n).fold(0usize, |w, p| w | (lit_digit(&query[p]) << p));
    for c in clauses {
        let not_all = mk(&|w| {
            !c.positions
                .iter()
                .all(|&p| bit(w, p) == lit_digit(&query[p]))
        });
        bodies.push(vec![(1.0 - c.m, mk(&|_| true)), (c.m, not_all)]);
    }
    let target = 1u64 << target_world;
    let (mut k, mut surviving, mut bel, mut pl, mut betp) = (0.0, 0.0, 0.0, 0.0, 0.0);
    fn walk(
        bodies: &[Vec<(f64, u64)>],
        i: usize,
        mass: f64,
        set: u64,
        f: &mut dyn FnMut(f64, u64),
    ) {
        if mass == 0.0 {
            return;
        }
        if i == bodies.len() {
            f(mass, set);
            return;
        }
        for (m, s) in &bodies[i] {
            walk(bodies, i + 1, mass * m, set & s, f);
        }
    }
    let full = if worlds == 64 {
        u64::MAX
    } else {
        (1u64 << worlds) - 1
    };
    walk(&bodies, 0, 1.0, full, &mut |m, s| {
        if s == 0 {
            k += m;
            return;
        }
        surviving += m;
        if s == target {
            bel += m;
        }
        if s & target != 0 {
            pl += m;
            betp += m / f64::from(s.count_ones());
        }
    });
    (bel / surviving, pl / surviving, betp / surviving, k)
}

// ---------------------------------------------------------------------------
// Random inputs
// ---------------------------------------------------------------------------

/// A raw item description: either a comonotone item over several atoms
/// (literal, weight, open-world weight per atom) or a single-atom mixed BBA.
#[derive(Debug, Clone)]
enum Raw {
    Coupled(Vec<(u32, bool, f64, f64)>),
    Mixed(u32, f64, f64, f64),
}

fn build(raw: &Raw) -> Item<u32> {
    match raw {
        Raw::Coupled(es) => Item::new(
            es.iter()
                .map(|(a, pos, w, o)| {
                    let l = if *pos { Lit::pos(*a) } else { Lit::neg(*a) };
                    (l, *w, *o)
                })
                .collect(),
        )
        .unwrap(),
        Raw::Mixed(a, t, f, o) => Item::mixed(*a, *t, *f, *o).unwrap(),
    }
}

/// The focal elements of a raw item, built from the SPEC's statement of the
/// coupling and not from `Item::focal_elements`: a mixed row is its own BBA
/// {T t, F f, X o, Θ rest} on one atom; a coupled item draws one U on [0, 1]
/// and says, on atom i, ℓᵢ for U < wᵢ, Θ for wᵢ ≤ U < 1 − oᵢ and "outside the
/// frame" for U ≥ 1 − oᵢ. Each interval between consecutive breakpoints is one
/// focal element (adjacent equal ones are not merged; the oracle does not care).
fn spec_focals(raw: &Raw) -> Vec<(f64, Vec<(u32, Letter)>)> {
    match raw {
        Raw::Mixed(a, t, f, o) => [
            (*t, Letter::T),
            (*f, Letter::F),
            (*o, Letter::O),
            (1.0 - t - f - o, Letter::Theta),
        ]
        .into_iter()
        .filter(|(m, _)| *m > 0.0)
        .map(|(m, l)| (m, vec![(*a, l)]))
        .collect(),
        Raw::Coupled(es) => {
            let mut cuts = vec![0.0, 1.0];
            for (_, _, w, o) in es {
                cuts.extend([*w, 1.0 - o]);
            }
            cuts.sort_by(f64::total_cmp);
            cuts.dedup();
            cuts.windows(2)
                .filter(|c| c[1] > c[0])
                .map(|c| {
                    let u = 0.5 * (c[0] + c[1]);
                    let letters = es
                        .iter()
                        .map(|(a, positive, w, o)| {
                            let l = if u < *w {
                                if *positive {
                                    Letter::T
                                } else {
                                    Letter::F
                                }
                            } else if u < 1.0 - o {
                                Letter::Theta
                            } else {
                                Letter::O
                            };
                            (*a, l)
                        })
                        .collect();
                    (c[1] - c[0], letters)
                })
                .collect()
        }
    }
}

/// (w, o) with w + o ≤ 1 on a 1/1000 grid (so ties between breakpoints occur).
fn arb_wo(open_world: bool) -> impl Strategy<Value = (f64, f64)> {
    (0u32..=1000, 0u32..=1000).prop_map(move |(a, b)| {
        let w = f64::from(a) / 1000.0;
        let o = if open_world {
            f64::from(b) / 1000.0 * (1.0 - w)
        } else {
            0.0
        };
        (w, o)
    })
}

/// (t, f, o) with t + f + o ≤ 1.
fn arb_tfo(open_world: bool) -> impl Strategy<Value = (f64, f64, f64)> {
    (0u32..=1000, 0u32..=1000, 0u32..=1000, 1u32..=1000).prop_map(move |(t, f, o, th)| {
        let o = if open_world { o } else { 0 };
        let s = f64::from(t + f + o + th);
        (f64::from(t) / s, f64::from(f) / s, f64::from(o) / s)
    })
}

fn arb_raw(n: u32, open_world: bool) -> impl Strategy<Value = Raw> {
    let coupled =
        proptest::collection::btree_set(0..n, 1..=n as usize).prop_flat_map(move |atoms| {
            let len = atoms.len();
            proptest::collection::vec((any::<bool>(), arb_wo(open_world)), len).prop_map(
                move |es| {
                    Raw::Coupled(
                        atoms
                            .iter()
                            .zip(es)
                            .map(|(a, (pos, (w, o)))| (*a, pos, w, o))
                            .collect(),
                    )
                },
            )
        });
    let mixed = (0..n, arb_tfo(open_world)).prop_map(|(a, (t, f, o))| Raw::Mixed(a, t, f, o));
    prop_oneof![3 => coupled, 1 => mixed]
}

fn arb_query(n: u32) -> impl Strategy<Value = Vec<Lit<u32>>> {
    proptest::collection::vec(any::<bool>(), n as usize).prop_map(|ps| {
        ps.into_iter()
            .enumerate()
            .map(|(i, p)| {
                let a = u32::try_from(i).unwrap();
                if p {
                    Lit::pos(a)
                } else {
                    Lit::neg(a)
                }
            })
            .collect()
    })
}

/// n atoms, a query over them, and 1..=max_items raw items.
fn arb_case(
    max_n: u32,
    max_items: usize,
    open_world: bool,
) -> impl Strategy<Value = (Vec<Lit<u32>>, Vec<Raw>)> {
    (1..=max_n).prop_flat_map(move |n| {
        (
            arb_query(n),
            proptest::collection::vec(arb_raw(n, open_world), 1..=max_items),
        )
    })
}

fn positives(n: u32) -> Vec<Lit<u32>> {
    (0..n).map(Lit::pos).collect()
}

/// Near-total conflict (1 − K < 1e-6) is excluded from comparisons: the
/// 1/(1 − K) normalization amplifies rounding there.
const NEAR_TOTAL: f64 = 1.0 - 1e-6;

/// Run `conj_belief`, discarding total-conflict cases (they are an error,
/// like `dempster_combine`) and near-total ones.
fn conj(query: &[Lit<u32>], items: &[Item<u32>], not_all: f64) -> Option<ConjResult> {
    match conj_belief(query, items, not_all) {
        Ok(r) if r.k > NEAR_TOTAL => None,
        Ok(r) => Some(r),
        Err(DsError::TotalConflict) => None,
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// The first violation of the bounds chain lo ≤ Bel ≤ Pl ≤ NR ≤ hi_NR,
/// Pl ≤ hi (every value in [0, 1]), or `None` when it holds.
fn chain_violation(r: &ConjResult) -> Option<String> {
    let f = &r.frechet;
    let checks = [
        (f.lo <= r.bel + EPS, "lo > bel"),
        (r.bel <= r.pl + EPS, "bel > pl"),
        (r.pl <= r.nr + EPS, "pl > nr"),
        (r.nr <= f.hi_nr + EPS, "nr > hi_nr"),
        (r.pl <= f.hi + EPS, "pl > hi"),
    ];
    for (ok, what) in checks {
        if !ok {
            return Some(format!("{what}: {r:?}"));
        }
    }
    [r.bel, r.pl, r.nr, f.lo, f.hi, f.hi_nr]
        .iter()
        .find(|v| !(0.0..=1.0).contains(*v))
        .map(|v| format!("{v} outside [0, 1]: {r:?}"))
}

// ---------------------------------------------------------------------------
// Marginal consistency with the served CDST fold (single-leaf queries)
// ---------------------------------------------------------------------------

/// SPEC §3.3: item1 {T .5, `~` .3, Θ .2} and item2 {T .64, Θ .36} on one atom
/// fold to K .3, T ≈ .897 in the served fold, because `~` meets every touched
/// state as conflict. An "absorbing O" reading gives ≈ .628 instead.
#[test]
fn single_leaf_open_world_fixture_equals_cdst_dempster() {
    let items = vec![
        Item::mixed(0u32, 0.5, 0.0, 0.3).unwrap(),
        Item::new(vec![(Lit::pos(0u32), 0.64, 0.0)]).unwrap(),
    ];
    let r = conj_belief(&[Lit::pos(0)], &items, 0.0).unwrap();
    let served = dempster_combine(&served_bba(0.5, 0.0, 0.3), &served_bba(0.64, 0.0, 0.0)).unwrap();
    let (bel, pl, betp, nr) = served_measures(&served);
    assert!(close(r.bel, bel), "bel {} vs served {}", r.bel, bel);
    assert!(close(r.pl, pl), "pl {} vs served {}", r.pl, pl);
    assert!(close(r.betp, betp), "betp {} vs served {}", r.betp, betp);
    assert!(close(r.nr, nr), "nr {} vs served {}", r.nr, nr);
    assert!((r.bel - 0.897).abs() < 1e-3, "SPEC §3.3 value: {}", r.bel);
    assert!(
        (r.k - 0.3).abs() < 1e-12,
        "conflict from `~` meeting touched states: {}",
        r.k
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Single-leaf marginal consistency: any list of single-atom BBAs with T, F and `~` gives
    /// the served fold's Bel, Pl, BetP and 1 − Bel(F).
    #[test]
    fn single_atom_equals_served_cdst_fold(
        bbas in proptest::collection::vec(arb_tfo(true), 1..=4),
    ) {
        let mut served = served_bba(bbas[0].0, bbas[0].1, bbas[0].2);
        let mut total_conflict = false;
        for (t, f, o) in &bbas[1..] {
            match dempster_combine(&served, &served_bba(*t, *f, *o)) {
                Ok(m) => served = m,
                Err(DsError::TotalConflict) => { total_conflict = true; break; }
                Err(e) => panic!("{e}"),
            }
        }
        prop_assume!(!total_conflict);
        let items: Vec<Item<u32>> = bbas.iter().map(|(t, f, o)| Item::mixed(0, *t, *f, *o).unwrap()).collect();
        let Some(r) = conj(&[Lit::pos(0)], &items, 0.0) else { return Ok(()); };
        let (bel, pl, betp, nr) = served_measures(&served);
        prop_assert!((r.bel - bel).abs() < 1e-7, "bel {} vs {}", r.bel, bel);
        prop_assert!((r.pl - pl).abs() < 1e-7, "pl {} vs {}", r.pl, pl);
        prop_assert!((r.betp - betp).abs() < 1e-7, "betp {} vs {}", r.betp, betp);
        prop_assert!((r.nr - nr).abs() < 1e-7, "nr {} vs {}", r.nr, nr);
    }

    /// A `whole` item {T s, `~` o} copied onto n atoms reproduces the
    /// compound BBA it came from (round trip of a whole item, §3.2 point 1),
    /// `~` included.
    #[test]
    fn whole_item_round_trips_to_the_compound_value(
        n in 1u32..=8, (s, o) in arb_wo(true),
    ) {
        let item = Item::new((0..n).map(|a| (Lit::pos(a), s, o)).collect()).unwrap();
        let r = conj_belief(&positives(n), &[item], 0.0).unwrap();
        let (bel, pl, betp1, nr) = served_measures(&served_bba(s, 0.0, o));
        prop_assert!(close(r.bel, bel), "bel {} vs compound {}", r.bel, bel);
        prop_assert!(close(r.pl, pl), "pl {} vs compound {}", r.pl, pl);
        prop_assert!(close(r.nr, nr), "nr {} vs compound {}", r.nr, nr);
        // Product-frame BetP of n leaves never exceeds the 1-leaf value.
        prop_assert!(r.betp <= betp1 + EPS);
    }

    /// One comonotone item: the conjunction is as strong as its weakest
    /// conjunct (R-MIN is exact when one item supports everything).
    #[test]
    fn single_comonotone_item_bel_is_its_minimum_weight(
        ws in proptest::collection::vec(0u32..=1000, 1..=8),
    ) {
        let n = u32::try_from(ws.len()).unwrap();
        let ws: Vec<f64> = ws.iter().map(|w| f64::from(*w) / 1000.0).collect();
        let item = Item::new((0..n).map(|a| (Lit::pos(a), ws[a as usize], 0.0)).collect()).unwrap();
        let r = conj_belief(&positives(n), &[item], 0.0).unwrap();
        let min = ws.iter().copied().fold(1.0, f64::min);
        prop_assert!(close(r.bel, min), "bel {} vs min weight {}", r.bel, min);
        prop_assert!(close(r.pl, 1.0));
    }

    /// Items that share no atom are independent: the conjunction factors into
    /// the single-leaf values (R-DEP = R-IND on disjoint items).
    #[test]
    fn disjoint_items_factor_into_single_leaf_values(
        per_atom in proptest::collection::vec(proptest::collection::vec(arb_tfo(true), 1..=2), 1..=5),
        polarity in proptest::collection::vec(any::<bool>(), 5),
    ) {
        let n = per_atom.len();
        let query: Vec<Lit<u32>> = (0..n).map(|i| {
            let a = u32::try_from(i).unwrap();
            if polarity[i] { Lit::pos(a) } else { Lit::neg(a) }
        }).collect();
        let mut items = Vec::new();
        let mut singles = Vec::new();
        for (i, bbas) in per_atom.iter().enumerate() {
            let a = u32::try_from(i).unwrap();
            let its: Vec<Item<u32>> = bbas.iter().map(|(t, f, o)| Item::mixed(a, *t, *f, *o).unwrap()).collect();
            let Some(s) = conj(&[query[i]], &its, 0.0) else { return Ok(()); };
            singles.push(s);
            items.extend(its);
        }
        let r = conj(&query, &items, 0.0).expect("no single leaf is in total conflict");
        let prod = |f: &dyn Fn(&ConjResult) -> f64| singles.iter().map(f).product::<f64>();
        prop_assert!(close(r.bel, prod(&|s| s.bel)), "bel {} vs {}", r.bel, prod(&|s| s.bel));
        prop_assert!(close(r.pl, prod(&|s| s.pl)));
        prop_assert!(close(r.nr, prod(&|s| s.nr)), "nr {} vs {}", r.nr, prod(&|s| s.nr));
        prop_assert!(close(r.betp, prod(&|s| s.betp)), "betp {} vs {}", r.betp, prod(&|s| s.betp));
        prop_assert!(close(1.0 - r.bel_or, prod(&|s| 1.0 - s.bel)));
    }
}

// ---------------------------------------------------------------------------
// The gate statistic NR = 1 − Dis
// ---------------------------------------------------------------------------

/// Four leaves, each with one item {T .5, `~` .2} and no F mass. Nothing
/// refutes the conjunction, so NR is 1, while Pl (≈ .41) would drop it at a
/// .5 gate (SPEC §3.2: `~` is not refutation).
#[test]
fn open_world_mass_is_not_refutation() {
    let items: Vec<Item<u32>> = (0..4)
        .map(|a| Item::new(vec![(Lit::pos(a), 0.5, 0.2)]).unwrap())
        .collect();
    let r = conj_belief(&positives(4), &items, 0.0).unwrap();
    assert!(close(r.nr, 1.0), "nr {}", r.nr);
    assert!(r.pl < 0.5, "Pl reads `~` as doubt: {}", r.pl);
}

/// A compound whose leaves carry nothing and whose only evidence is a
/// whole-compound refutation f .7 is not refuted-free: Bel 0, Pl .3, NR .3
/// (SPEC §3.6), never Pl ≈ 1.
#[test]
fn not_all_alone_lowers_pl_and_nr() {
    let r = conj_belief(&positives(3), &[], 0.7).unwrap();
    assert!(close(r.bel, 0.0));
    assert!(close(r.pl, 0.3), "pl {}", r.pl);
    assert!(close(r.nr, 0.3), "nr {}", r.nr);
}

/// SPEC §3.6 / §11.6 worked example: a compound at Bel .64, Pl 1, refuted by
/// X (.8) through an edge with f .9 (m = .72) is served Bel .332, Pl .519.
#[test]
fn not_all_worked_example() {
    let item = Item::new((0..3).map(|a| (Lit::pos(a), 0.64, 0.0)).collect()).unwrap();
    let r = conj_belief(&positives(3), &[item], 0.9 * 0.8).unwrap();
    assert!((r.bel - 0.332).abs() < 1e-3, "bel {}", r.bel);
    assert!((r.pl - 0.519).abs() < 1e-3, "pl {}", r.pl);
}

/// The served fold's reading of a single-leaf `not_all`: (Bel, Pl, NR) of
/// `lit` after folding `bbas` with one more row that refutes `lit` at mass m
/// ({F m, Θ 1 − m} for a positive literal, {T m, Θ 1 − m} for a negated one).
/// `None` on total conflict.
fn served_with_refutation(bbas: &[(f64, f64, f64)], positive: bool, m: f64) -> Option<[f64; 3]> {
    let refutation = if positive {
        served_bba(0.0, m, 0.0)
    } else {
        served_bba(m, 0.0, 0.0)
    };
    let mut served = refutation;
    for (t, f, o) in bbas {
        match dempster_combine(&served, &served_bba(*t, *f, *o)) {
            Ok(x) => served = x,
            Err(DsError::TotalConflict) => return None,
            Err(e) => panic!("{e}"),
        }
    }
    let (holds, fails) = if positive { (0, 1) } else { (1, 0) };
    let h = FocalElement::positive(BTreeSet::from([holds]));
    let f = FocalElement::positive(BTreeSet::from([fails]));
    Some([
        belief(&served, &h),
        plausibility(&served, &h),
        1.0 - belief(&served, &f),
    ])
}

/// A `not_all` valuation is one more positive BBA, and in exact CDST (the
/// served fold, SPEC §3.3) any positive BBA meets `~` as conflict. So with
/// `~` on the leaf, a refutation can RAISE Bel and Pl: a {T .5, `~` .3} at
/// Bel .5 / Pl .7 goes to ≈ .692 / ≈ .969 under m = .1, because the `~` .3
/// is annihilated and renormalized away. The served fold does exactly the
/// same with an F .1 row on the atom. This pins the stage-1 reading (exact
/// CDST, SPEC §3.6: "the CDST meet table decides how O states meet it");
/// changing it is an operator decision, not a bug fix.
#[test]
fn not_all_with_open_world_follows_the_served_fold_even_upward() {
    let items = vec![Item::mixed(0u32, 0.5, 0.0, 0.3).unwrap()];
    let base = conj_belief(&[Lit::pos(0)], &items, 0.0).unwrap();
    let r = conj_belief(&[Lit::pos(0)], &items, 0.1).unwrap();
    let [bel, pl, nr] = served_with_refutation(&[(0.5, 0.0, 0.3)], true, 0.1).unwrap();
    assert!(close(r.bel, bel), "bel {} vs served {bel}", r.bel);
    assert!(close(r.pl, pl), "pl {} vs served {pl}", r.pl);
    assert!(close(r.nr, nr), "nr {} vs served {nr}", r.nr);
    // The sign, stated: K = .35, T .45 and Θ .18 survive.
    assert!(close(base.bel, 0.5) && close(base.pl, 0.7));
    assert!(close(r.bel, 0.45 / 0.65), "bel {}", r.bel);
    assert!(close(r.pl, 0.63 / 0.65), "pl {}", r.pl);
    assert!(r.bel > base.bel && r.pl > base.pl);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Single-leaf `not_all` equals the served fold with one more row that
    /// refutes the literal at mass m, `~` included (marginal consistency for
    /// the valuation; the world-set oracle shares the DP's reading of the
    /// valuation, so this is the independent arbiter for it).
    #[test]
    fn single_leaf_not_all_equals_served_fold_with_a_refuting_row(
        bbas in proptest::collection::vec(arb_tfo(true), 1..=3),
        positive in any::<bool>(),
        m_milli in 1u32..=999,
    ) {
        let m = f64::from(m_milli) / 1000.0;
        let Some([bel, pl, nr]) = served_with_refutation(&bbas, positive, m) else { return Ok(()); };
        let items: Vec<Item<u32>> = bbas.iter().map(|(t, f, o)| Item::mixed(0, *t, *f, *o).unwrap()).collect();
        let lit = if positive { Lit::pos(0) } else { Lit::neg(0) };
        let Some(r) = conj(&[lit], &items, m) else { return Ok(()); };
        prop_assert!((r.bel - bel).abs() < 1e-7, "bel {} vs served {}", r.bel, bel);
        prop_assert!((r.pl - pl).abs() < 1e-7, "pl {} vs served {}", r.pl, pl);
        prop_assert!((r.nr - nr).abs() < 1e-7, "nr {} vs served {}", r.nr, nr);
    }

    /// Without `~`, a stronger refutation never raises Bel, Pl or NR.
    #[test]
    fn not_all_is_non_increasing_without_open_world(
        (query, raws) in arb_case(5, 4, false),
        a_milli in 0u32..=999,
        b_milli in 0u32..=999,
    ) {
        let (lo, hi) = (a_milli.min(b_milli), a_milli.max(b_milli));
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let (Some(weak), Some(strong)) = (
            conj(&query, &items, f64::from(lo) / 1000.0),
            conj(&query, &items, f64::from(hi) / 1000.0),
        ) else { return Ok(()); };
        prop_assert!(strong.bel <= weak.bel + EPS, "bel {} -> {}", weak.bel, strong.bel);
        prop_assert!(strong.pl <= weak.pl + EPS, "pl {} -> {}", weak.pl, strong.pl);
        prop_assert!(strong.nr <= weak.nr + EPS, "nr {} -> {}", weak.nr, strong.nr);
    }
}

// ---------------------------------------------------------------------------
// The SPEC §3.1 reference case
// ---------------------------------------------------------------------------

/// Paper E at .8, attributed in full to a₀..a₂ and at k = .6 to a₃; a₃ also has
/// an independent item at .7. R-DEP counts E once (.704); the independence
/// product counts it four times; the Fréchet floor is .244.
#[test]
fn reference_case_counts_a_shared_paper_once() {
    let e = Item::new(vec![
        (Lit::pos(0u32), 0.8, 0.0),
        (Lit::pos(1), 0.8, 0.0),
        (Lit::pos(2), 0.8, 0.0),
        (Lit::pos(3), 0.8 * 0.6, 0.0),
    ])
    .unwrap();
    let other = Item::new(vec![(Lit::pos(3u32), 0.7, 0.0)]).unwrap();
    let items = vec![e, other];
    let r = conj_belief(&positives(4), &items, 0.0).unwrap();
    assert!((r.bel - 0.704).abs() < 1e-9, "R-DEP {}", r.bel);
    assert!(
        (r.frechet.lo - 0.244).abs() < 1e-9,
        "Fréchet lo {}",
        r.frechet.lo
    );
    let independent: f64 = (0..4)
        .map(|a| conj_belief(&[Lit::pos(a)], &items, 0.0).unwrap().bel)
        .product();
    assert!(
        r.bel > independent + 0.2,
        "R-IND squares the shared paper: {independent}"
    );
    assert!(r.exact);
}

// ---------------------------------------------------------------------------
// The coupling's joint structure with unequal `~` across atoms
// ---------------------------------------------------------------------------

/// Hand derivation of the quantile rule for one item that gives its two atoms
/// different open-world weights: a {T .6, `~` .3}, b {T .2, `~` .5}. With U
/// cut at .2, .5, .6, .7 its focal elements are (T,T) .2, (T,Θ) .3, (T,O) .1,
/// (Θ,O) .1 and (O,O) .3.
///
/// - Alone: Bel .2, Pl .5 (no O on either atom), NR 1, Bel(∨) .6, K 0.
/// - With an independent b {T .5}: every O state on b meets T or Θ on b as
///   ⊥ (K .5); the survivors are (T,T) .35 and (T,Θ) .15, so Bel .7, Pl 1.
/// - With an independent a {F .5} instead: K .6; the survivors are (T,T) .1,
///   (T,Θ) .15, (T,O) .05, (F,O) .05 and (Θ,O) .05 over .4, so Bel .25,
///   Pl .625, NR .875, Bel(∨) .75.
#[test]
fn coupling_with_unequal_open_world_matches_hand_derivation() {
    let coupled = Item::new(vec![(Lit::pos(0u32), 0.6, 0.3), (Lit::pos(1u32), 0.2, 0.5)]).unwrap();
    let q = positives(2);
    let check = |items: &[Item<u32>], bel: f64, pl: f64, nr: f64, bel_or: f64, k: f64| {
        let r = conj_belief(&q, items, 0.0).unwrap();
        assert!(close(r.bel, bel), "bel {} vs {bel}", r.bel);
        assert!(close(r.pl, pl), "pl {} vs {pl}", r.pl);
        assert!(close(r.nr, nr), "nr {} vs {nr}", r.nr);
        assert!(close(r.bel_or, bel_or), "bel_or {} vs {bel_or}", r.bel_or);
        assert!(close(r.k, k), "k {} vs {k}", r.k);
    };
    check(std::slice::from_ref(&coupled), 0.2, 0.5, 1.0, 0.6, 0.0);
    let b_support = Item::new(vec![(Lit::pos(1u32), 0.5, 0.0)]).unwrap();
    check(&[coupled.clone(), b_support], 0.7, 1.0, 1.0, 1.0, 0.5);
    let a_refute = Item::new(vec![(Lit::neg(0u32), 0.5, 0.0)]).unwrap();
    check(&[coupled, a_refute], 0.25, 0.625, 0.875, 0.75, 0.6);
}

// ---------------------------------------------------------------------------
// OR is computed directly, never by De Morgan
// ---------------------------------------------------------------------------

/// For L = {a} with a = {T .5, `~` .3}: Bel(a) is .5, while 1 − Pl(¬a) is .8,
/// because the O states fall outside Pl.
#[test]
fn or_is_not_de_morgan_under_open_world() {
    let items = vec![Item::new(vec![(Lit::pos(0u32), 0.5, 0.3)]).unwrap()];
    let or = conj_belief(&[Lit::pos(0)], &items, 0.0).unwrap();
    let neg = conj_belief(&[Lit::neg(0)], &items, 0.0).unwrap();
    assert!(close(or.bel_or, 0.5), "bel_or {}", or.bel_or);
    assert!(close(1.0 - neg.pl, 0.8));
}

// ---------------------------------------------------------------------------
// Brute-force oracles
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Exact CDST over the five-letter alphabet, up to n = 5: Bel, Pl, NR,
    /// Bel(OR) and K equal a world-set enumeration, with negated literals and
    /// with and without a `not_all` valuation.
    #[test]
    fn dp_equals_world_set_oracle_with_open_world(
        (query, raws) in arb_case(5, 4, true),
        m_milli in prop_oneof![Just(0u32), 1u32..=1000],
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let clauses = if m > 0.0 {
            vec![Clause { m, positions: (0..query.len()).collect() }]
        } else { vec![] };
        let o = oracle(&query, &raws, &clauses);
        prop_assume!(o.k < NEAR_TOTAL);
        let r = conj(&query, &items, m).expect("oracle says not total conflict");
        prop_assert!(r.exact);
        prop_assert!((r.bel - o.bel).abs() < 1e-9, "bel {} vs {}", r.bel, o.bel);
        prop_assert!((r.pl - o.pl).abs() < 1e-9, "pl {} vs {}", r.pl, o.pl);
        prop_assert!((r.nr - o.nr).abs() < 1e-9, "nr {} vs {}", r.nr, o.nr);
        prop_assert!((r.bel_or - o.bel_or).abs() < 1e-9, "bel_or {} vs {}", r.bel_or, o.bel_or);
        prop_assert!((r.k - o.k).abs() < 1e-9, "k {} vs {}", r.k, o.k);
    }

    /// The exact-case Fréchet envelope is built from each leaf's marginal in
    /// the same joint (not from the leaf queried alone), so it bounds the
    /// joint under conflict too: lo = max(0, Σ Belᵢ − (n − 1)), hi = min Plᵢ,
    /// hi_NR = min NRᵢ with the marginals read off the world-set oracle.
    #[test]
    fn frechet_envelope_uses_in_joint_leaf_marginals(
        (query, raws) in arb_case(5, 4, true),
        m_milli in prop_oneof![Just(0u32), 1u32..=1000],
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let clauses = if m > 0.0 {
            vec![Clause { m, positions: (0..query.len()).collect() }]
        } else { vec![] };
        let o = oracle(&query, &raws, &clauses);
        prop_assume!(o.k < NEAR_TOTAL);
        let r = conj(&query, &items, m).expect("oracle says not total conflict");
        let n = o.leaf_bel.len() as f64;
        let lo = (o.leaf_bel.iter().sum::<f64>() - (n - 1.0)).max(0.0);
        let hi = o.leaf_pl.iter().copied().fold(1.0, f64::min);
        let hi_nr = o.leaf_nr.iter().copied().fold(1.0, f64::min);
        prop_assert!((r.frechet.lo - lo).abs() < 1e-9, "lo {} vs {}", r.frechet.lo, lo);
        prop_assert!((r.frechet.hi - hi).abs() < 1e-9, "hi {} vs {}", r.frechet.hi, hi);
        prop_assert!((r.frechet.hi_nr - hi_nr).abs() < 1e-9, "hi_nr {} vs {}", r.frechet.hi_nr, hi_nr);
    }

    /// Without `~`, up to n = 6: Bel, Pl and the product-frame BetP equal the
    /// complete-assignment oracle (BetP = pignistic share of the target world).
    #[test]
    fn dp_equals_complete_assignment_oracle_without_open_world(
        (query, raws) in arb_case(6, 4, false),
        m_milli in prop_oneof![Just(0u32), 1u32..=1000],
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let clauses = if m > 0.0 {
            vec![Clause { m, positions: (0..query.len()).collect() }]
        } else { vec![] };
        let (bel, pl, betp, k) = closed_world_oracle(&query, &raws, &clauses);
        prop_assume!(k < NEAR_TOTAL);
        let r = conj(&query, &items, m).expect("oracle says not total conflict");
        prop_assert!((r.bel - bel).abs() < 1e-9, "bel {} vs {}", r.bel, bel);
        prop_assert!((r.pl - pl).abs() < 1e-9, "pl {} vs {}", r.pl, pl);
        prop_assert!((r.betp - betp).abs() < 1e-9, "betp {} vs {}", r.betp, betp);
    }

    /// The `not_all` closed form (SPEC §3.6) equals the DP with the valuation
    /// added as an item, at ow = 0.
    #[test]
    fn not_all_closed_form_equals_dp_without_open_world(
        (query, raws) in arb_case(5, 4, false),
        m_milli in 1u32..=999,
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let Some(base) = conj(&query, &items, 0.0) else { return Ok(()); };
        let Some(dp) = conj(&query, &items, m) else { return Ok(()); };
        let cf = not_all_closed_form(&base, m).unwrap();
        prop_assert!((cf.bel - dp.bel).abs() < 1e-9, "bel {} vs {}", cf.bel, dp.bel);
        prop_assert!((cf.pl - dp.pl).abs() < 1e-9, "pl {} vs {}", cf.pl, dp.pl);
        prop_assert!((cf.nr - dp.nr).abs() < 1e-9, "nr {} vs {}", cf.nr, dp.nr);
        prop_assert!((cf.betp - dp.betp).abs() < 1e-9, "betp {} vs {}", cf.betp, dp.betp);
        prop_assert!((cf.bel_or - dp.bel_or).abs() < 1e-9, "bel_or {} vs {}", cf.bel_or, dp.bel_or);
        prop_assert!((cf.k - dp.k).abs() < 1e-9, "k {} vs {}", cf.k, dp.k);
        // The envelope floor follows the valuation: each leaf's in-joint Bel
        // drops to (Belᵢ − K')/(1 − K'), and the DP reads it off the joint.
        prop_assert!((cf.frechet.lo - dp.frechet.lo).abs() < 1e-9, "lo {} vs {}", cf.frechet.lo, dp.frechet.lo);
    }

    /// Both closed forms keep the bounds chain lo ≤ Bel ≤ Pl ≤ NR ≤ hi_NR and
    /// Pl ≤ hi, as the DP does.
    #[test]
    fn closed_forms_keep_the_bounds_chain(
        (query, raws) in arb_case(5, 4, false),
        rotate in any::<usize>(),
        m_milli in 1u32..=999,
    ) {
        let n = query.len();
        let mut query = query;
        query.rotate_left(rotate % n);
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let Some(base) = conj(&query, &items, 0.0) else { return Ok(()); };
        let cf = not_all_closed_form(&base, m).unwrap();
        prop_assert!(chain_violation(&cf).is_none(), "not_all: {:?}", chain_violation(&cf));
        if n >= 2 {
            let pair_bel = joint_bel(&query, &items, 0.0, &[0, 1]).unwrap();
            if let Ok(sib) = single_negative_sibling(&base, pair_bel, m) {
                prop_assert!(chain_violation(&sib).is_none(), "sibling: {:?}", chain_violation(&sib));
            }
        }
    }

    /// The single-negative-sibling closed form (SPEC §3.3) equals the oracle
    /// with the sibling edge as an explicit "not both" focal set, at ow = 0.
    /// The pair's Bel is taken in the same joint as the compound
    /// (`joint_bel`), which the oracle also confirms.
    #[test]
    fn single_negative_sibling_equals_oracle(
        (query, raws) in arb_case(5, 4, false),
        rotate in any::<usize>(),
        m_milli in 1u32..=999,
    ) {
        let n = query.len();
        prop_assume!(n >= 2);
        // The sibling pair is the first two literals of a rotated query.
        let mut query = query;
        query.rotate_left(rotate % n);
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let Some(base) = conj(&query, &items, 0.0) else { return Ok(()); };
        let plain = oracle(&query, &raws, &[]);
        let pair_bel = joint_bel(&query, &items, 0.0, &[0, 1]).unwrap();
        prop_assert!((pair_bel - plain.bel_first_two).abs() < 1e-9, "pair {} vs {}", pair_bel, plain.bel_first_two);
        let clauses = [Clause { m, positions: vec![0, 1] }];
        let o = oracle(&query, &raws, &clauses);
        prop_assume!(o.k < NEAR_TOTAL);
        let (_, _, betp, _) = closed_world_oracle(&query, &raws, &clauses);
        let cf = single_negative_sibling(&base, pair_bel, m).unwrap();
        prop_assert!((cf.bel - o.bel).abs() < 1e-9, "bel {} vs {}", cf.bel, o.bel);
        prop_assert!((cf.pl - o.pl).abs() < 1e-9, "pl {} vs {}", cf.pl, o.pl);
        prop_assert!((cf.nr - o.nr).abs() < 1e-9, "nr {} vs {}", cf.nr, o.nr);
        prop_assert!((cf.bel_or - o.bel_or).abs() < 1e-9, "bel_or {} vs {}", cf.bel_or, o.bel_or);
        prop_assert!((cf.k - o.k).abs() < 1e-9, "k {} vs {}", cf.k, o.k);
        prop_assert!((cf.betp - betp).abs() < 1e-9, "betp {} vs {}", cf.betp, betp);
    }

    /// The closed forms are the ow = 0 case of SPEC §3.3 / §3.6. When some
    /// item gives `~` mass on a query atom they are not exact CDST, so they
    /// must say so (`exact: false`); without `~` they stay exact.
    #[test]
    fn closed_forms_are_exact_only_without_open_world(
        (query, raws) in arb_case(5, 4, true),
        m_milli in 1u32..=999,
    ) {
        let n = query.len();
        prop_assume!(n >= 2);
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let m = f64::from(m_milli) / 1000.0;
        let Some(base) = conj(&query, &items, 0.0) else { return Ok(()); };
        let carries_open_world = raws.iter().any(|r| match r {
            Raw::Coupled(es) => es.iter().any(|(_, _, _, o)| *o > 0.0),
            Raw::Mixed(_, _, _, o) => *o > 0.0,
        });
        let cf = not_all_closed_form(&base, m).unwrap();
        prop_assert_eq!(cf.exact, !carries_open_world, "not_all closed form");
        let pair_bel = joint_bel(&query, &items, 0.0, &[0, 1]).unwrap();
        if let Ok(sib) = single_negative_sibling(&base, pair_bel, m) {
            prop_assert_eq!(sib.exact, !carries_open_world, "sibling closed form");
        }
    }
}

/// a {T .6, `~` .4}, b {T 1}: Bel(a ∧ b) = Bel(a ∧ b in the pair) = .6. A
/// sibling edge at m = .5 gives the closed form Bel .6·.5/.7 ≈ .429, but in
/// exact CDST the valuation's frame part annihilates a's `~` and Bel is 1
/// (the DP's `not_all` over the same two leaves agrees). The closed form must
/// not label that value exact.
#[test]
fn closed_forms_with_open_world_are_not_exact() {
    let items = vec![
        Item::new(vec![(Lit::pos(0u32), 0.6, 0.4)]).unwrap(),
        Item::new(vec![(Lit::pos(1u32), 1.0, 0.0)]).unwrap(),
    ];
    let q = positives(2);
    let base = conj_belief(&q, &items, 0.0).unwrap();
    assert!(close(base.bel, 0.6) && base.exact);
    let pair_bel = joint_bel(&q, &items, 0.0, &[0, 1]).unwrap();
    let sib = single_negative_sibling(&base, pair_bel, 0.5).unwrap();
    let cf = not_all_closed_form(&base, 0.5).unwrap();
    let dp = conj_belief(&q, &items, 0.5).unwrap();
    assert!(close(sib.bel, 0.3 / 0.7), "closed form {}", sib.bel);
    assert!(close(dp.bel, 1.0), "exact CDST {}", dp.bel);
    assert!(dp.exact, "the DP is exact CDST under `~`");
    assert!(!sib.exact, "sibling closed form under `~` claimed exact");
    assert!(!cf.exact, "not_all closed form under `~` claimed exact");
}

// ---------------------------------------------------------------------------
// Order, bounds, monotonicity, symmetry, visibility
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Fréchet lo ≤ Bel ≤ Pl ≤ NR ≤ hi_NR, Pl ≤ hi, and BetP ∈ [Bel, Pl].
    #[test]
    fn bounds_chain_holds(
        (query, raws) in arb_case(6, 5, true),
        m_milli in prop_oneof![Just(0u32), 1u32..=1000],
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let Some(r) = conj(&query, &items, f64::from(m_milli) / 1000.0) else { return Ok(()); };
        let f = &r.frechet;
        prop_assert!(f.lo <= r.bel + EPS, "lo {} > bel {}", f.lo, r.bel);
        prop_assert!(r.bel <= r.pl + EPS);
        prop_assert!(r.pl <= r.nr + EPS, "pl {} > nr {}", r.pl, r.nr);
        prop_assert!(r.nr <= f.hi_nr + EPS, "nr {} > hi_nr {}", r.nr, f.hi_nr);
        prop_assert!(r.pl <= f.hi + EPS, "pl {} > hi {}", r.pl, f.hi);
        prop_assert!(r.bel - EPS <= r.betp && r.betp <= r.pl + EPS, "betp {} not in [{}, {}]", r.betp, r.bel, r.pl);
        prop_assert!(r.bel <= r.bel_or + EPS);
        for v in [r.bel, r.pl, r.nr, r.betp, r.bel_or, r.k, f.lo, f.hi, f.hi_nr] {
            prop_assert!((0.0..=1.0).contains(&v), "{v} outside [0, 1]");
        }
    }

    /// Adding an item that supports query literals (no `~`, no opposing
    /// mass) never lowers Bel.
    #[test]
    fn bel_is_monotone_in_supporting_items(
        (query, raws) in arb_case(5, 4, true),
        support in proptest::collection::vec(0u32..=1000, 1..=5),
    ) {
        let mut items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let Some(before) = conj(&query, &items, 0.0) else { return Ok(()); };
        let entries: Vec<(Lit<u32>, f64, f64)> = query.iter().zip(&support)
            .map(|(l, w)| (*l, f64::from(*w) / 1000.0, 0.0)).collect();
        items.push(Item::new(entries).unwrap());
        let Some(after) = conj(&query, &items, 0.0) else { return Ok(()); };
        prop_assert!(after.bel >= before.bel - EPS, "{} -> {}", before.bel, after.bel);
    }

    /// Flipping one query literal and swapping T and F on that atom in every
    /// item changes nothing.
    #[test]
    fn negated_literal_symmetry(
        (query, raws) in arb_case(5, 4, true),
        pick in any::<usize>(),
        m_milli in prop_oneof![Just(0u32), 1u32..=1000],
    ) {
        let flip = u32::try_from(pick % query.len()).unwrap();
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let mirrored: Vec<Item<u32>> = raws.iter().map(|r| build(&match r.clone() {
            Raw::Coupled(es) => Raw::Coupled(es.into_iter().map(|(a, p, w, o)| (a, if a == flip { !p } else { p }, w, o)).collect()),
            Raw::Mixed(a, t, f, o) if a == flip => Raw::Mixed(a, f, t, o),
            other => other,
        })).collect();
        let q2: Vec<Lit<u32>> = query.iter().map(|l| if l.atom == flip { l.negated() } else { *l }).collect();
        let m = f64::from(m_milli) / 1000.0;
        let (Some(a), Some(b)) = (conj(&query, &items, m), conj(&q2, &mirrored, m)) else { return Ok(()); };
        for (x, y) in [(a.bel, b.bel), (a.pl, b.pl), (a.nr, b.nr), (a.betp, b.betp), (a.bel_or, b.bel_or), (a.k, b.k)] {
            prop_assert!((x - y).abs() < 1e-9, "{x} vs {y}");
        }
    }

    /// Dempster is commutative: item order does not matter.
    #[test]
    fn item_order_does_not_matter((query, raws) in arb_case(5, 5, true)) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let reversed: Vec<Item<u32>> = items.iter().rev().cloned().collect();
        let (Some(a), Some(b)) = (conj(&query, &items, 0.0), conj(&query, &reversed, 0.0)) else { return Ok(()); };
        for (x, y) in [(a.bel, b.bel), (a.pl, b.pl), (a.nr, b.nr), (a.betp, b.betp), (a.bel_or, b.bel_or)] {
            prop_assert!((x - y).abs() < 1e-9, "{x} vs {y}");
        }
    }

    /// Atoms outside the query (for example, leaves the viewer cannot see)
    /// never influence the result: entries on them and items that only touch
    /// them are ignored.
    #[test]
    fn atoms_outside_the_query_are_ignored(
        (query, raws) in arb_case(4, 4, true),
        hidden in proptest::collection::vec(arb_tfo(true), 1..=3),
    ) {
        let items: Vec<Item<u32>> = raws.iter().map(build).collect();
        let Some(a) = conj(&query, &items, 0.0) else { return Ok(()); };
        let hidden_atom = 99u32;
        let mut widened: Vec<Item<u32>> = raws.iter().map(|r| build(&match r {
            Raw::Coupled(es) => {
                let mut es = es.clone();
                es.push((hidden_atom, false, 0.9, 0.05));
                Raw::Coupled(es)
            }
            other => other.clone(),
        })).collect();
        widened.extend(hidden.iter().map(|(t, f, o)| Item::mixed(hidden_atom, *t, *f, *o).unwrap()));
        let b = conj(&query, &widened, 0.0).expect("hidden atoms add no conflict");
        for (x, y) in [(a.bel, b.bel), (a.pl, b.pl), (a.nr, b.nr), (a.betp, b.betp), (a.bel_or, b.bel_or), (a.k, b.k)] {
            prop_assert!((x - y).abs() < 1e-12, "{x} vs {y}");
        }
    }

    /// The comonotone coupling: on each atom it touches, an item's focal
    /// elements marginalize to that atom's own BBA {ℓ w, `~` o, Θ rest}.
    #[test]
    fn item_marginals_are_the_per_atom_bbas(raw in arb_raw(6, true)) {
        let item = build(&raw);
        let fes = item.focal_elements();
        let total: f64 = fes.iter().map(|f| f.mass).sum();
        prop_assert!((total - 1.0).abs() < 1e-12);
        let per_atom: Vec<(u32, f64, f64, f64)> = match &raw {
            Raw::Coupled(es) => es.iter().map(|(a, p, w, o)| if *p { (*a, *w, 0.0, *o) } else { (*a, 0.0, *w, *o) }).collect(),
            Raw::Mixed(a, t, f, o) => vec![(*a, *t, *f, *o)],
        };
        for (a, t, f, o) in per_atom {
            let mass_of = |want: Letter| -> f64 {
                fes.iter().filter(|fe| fe.letters.iter().any(|(x, l)| *x == a && *l == want)).map(|fe| fe.mass).sum()
            };
            prop_assert!((mass_of(Letter::T) - t).abs() < 1e-12);
            prop_assert!((mass_of(Letter::F) - f).abs() < 1e-12);
            prop_assert!((mass_of(Letter::O) - o).abs() < 1e-12);
            prop_assert!((mass_of(Letter::Theta) - (1.0 - t - f - o)).abs() < 1e-9);
        }
    }
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

/// More than 16 leaves: R-IND + R-FRE, flagged inexact.
#[test]
fn over_the_leaf_cap_is_inexact() {
    let n = u32::try_from(MAX_LEAVES).unwrap() + 1;
    let items: Vec<Item<u32>> = (0..n)
        .map(|a| Item::new(vec![(Lit::pos(a), 0.9, 0.0)]).unwrap())
        .collect();
    let r = conj_belief(&positives(n), &items, 0.0).unwrap();
    assert!(!r.exact);
    assert!(close(r.bel, 0.9f64.powi(i32::try_from(n).unwrap())));
    // At the cap the DP still runs.
    let at_cap = positives(n - 1);
    assert!(conj_belief(&at_cap, &items, 0.0).unwrap().exact);
}

/// Over the leaf cap the result is R-IND: one whole item at .9 shared by all
/// 17 leaves counts once in R-DEP (.9) but once per leaf here (.9¹⁷).
#[test]
fn over_the_leaf_cap_a_shared_item_is_counted_per_leaf() {
    let n = u32::try_from(MAX_LEAVES).unwrap() + 1;
    let whole = Item::new((0..n).map(|a| (Lit::pos(a), 0.9, 0.0)).collect()).unwrap();
    let r = conj_belief(&positives(n), &[whole], 0.0).unwrap();
    assert!(!r.exact);
    assert!(
        close(r.bel, 0.9f64.powi(i32::try_from(n).unwrap())),
        "bel {}",
        r.bel
    );
    assert!(close(r.pl, 1.0));
}

/// Over the leaf cap with a `not_all` valuation, the served value still sits
/// inside its own envelope: 17 leaves at T .99 have R-IND Bel ≈ .843 and a
/// pre-valuation floor of 17·.99 − 16 = .83; m = .5 lowers Bel to ≈ .728, so
/// the floor must follow it down.
#[test]
fn over_the_leaf_cap_a_valuation_keeps_the_bounds_chain() {
    let n = u32::try_from(MAX_LEAVES).unwrap() + 1;
    let items: Vec<Item<u32>> = (0..n)
        .map(|a| Item::new(vec![(Lit::pos(a), 0.99, 0.0)]).unwrap())
        .collect();
    let r = conj_belief(&positives(n), &items, 0.5).unwrap();
    assert!(!r.exact);
    assert!(
        r.bel < 0.99f64.powi(17),
        "the valuation lowers Bel: {}",
        r.bel
    );
    assert_eq!(chain_violation(&r), None);

    // With `~` on every leaf the fallback still applies the closed-world
    // closed form to the R-IND product, so it lowers Bel (the exact DP under
    // `~` would not; the fallback is labelled inexact).
    let open: Vec<Item<u32>> = (0..n)
        .map(|a| Item::new(vec![(Lit::pos(a), 0.5, 0.2)]).unwrap())
        .collect();
    let base = conj_belief(&positives(n), &open, 0.0).unwrap();
    let r = conj_belief(&positives(n), &open, 0.3).unwrap();
    assert!(!r.exact);
    assert!(r.bel <= base.bel && r.pl <= base.pl && r.nr <= base.nr);
    assert_eq!(chain_violation(&r), None);
}

/// Too many live states (mixed evidence on 12 leaves gives 3¹² > 10⁵): inexact.
#[test]
fn over_the_state_cap_is_inexact() {
    let items: Vec<Item<u32>> = (0..12)
        .map(|a| Item::mixed(a, 0.4, 0.2, 0.0).unwrap())
        .collect();
    let r = conj_belief(&positives(12), &items, 0.0).unwrap();
    assert!(!r.exact);
    assert_eq!(chain_violation(&r), None);
    let r = conj_belief(&positives(12), &items, 0.5).unwrap();
    assert!(!r.exact);
    assert_eq!(chain_violation(&r), None);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[test]
fn total_conflict_is_an_error_like_dempster() {
    let items = vec![
        Item::new(vec![(Lit::pos(0u32), 1.0, 0.0)]).unwrap(),
        Item::new(vec![(Lit::neg(0u32), 1.0, 0.0)]).unwrap(),
    ];
    assert_eq!(
        conj_belief(&[Lit::pos(0)], &items, 0.0).unwrap_err(),
        DsError::TotalConflict
    );
}

#[test]
fn malformed_inputs_are_rejected() {
    assert!(
        Item::new(vec![(Lit::pos(0u32), 0.7, 0.4)]).is_err(),
        "w + o > 1"
    );
    assert!(Item::new(vec![(Lit::pos(0u32), -0.1, 0.0)]).is_err());
    assert!(Item::new(vec![(Lit::pos(0u32), f64::NAN, 0.0)]).is_err());
    assert!(
        Item::new(vec![(Lit::pos(0u32), 0.5, 0.0), (Lit::neg(0u32), 0.2, 0.0)]).is_err(),
        "one atom twice"
    );
    assert!(Item::<u32>::new(vec![]).is_err());
    assert!(Item::mixed(0u32, 0.5, 0.4, 0.2).is_err());
    let item = Item::new(vec![(Lit::pos(0u32), 0.5, 0.0)]).unwrap();
    assert!(
        conj_belief::<u32>(&[], std::slice::from_ref(&item), 0.0).is_err(),
        "empty query"
    );
    assert!(
        conj_belief(
            &[Lit::pos(0u32), Lit::neg(0)],
            std::slice::from_ref(&item),
            0.0
        )
        .is_err(),
        "atom twice in query"
    );
    assert!(
        conj_belief(&[Lit::pos(0u32)], &[item], 1.5).is_err(),
        "not_all outside [0, 1]"
    );
}

// ---------------------------------------------------------------------------
// Profile (spine and over-cap nodes, SPEC §2.2)
// ---------------------------------------------------------------------------

#[test]
fn profile_summarizes_leaves_without_a_conjunction() {
    // Leaves 0..4 supported, leaf 4 refuted (Pl .3 < .5), leaf 5 untouched.
    let mut items: Vec<Item<u32>> = (0..4)
        .map(|a| Item::new(vec![(Lit::pos(a), 0.2 + 0.2 * f64::from(a), 0.0)]).unwrap())
        .collect();
    items.push(Item::new(vec![(Lit::neg(4u32), 0.7, 0.0)]).unwrap());
    let leaves: Vec<u32> = (0..6).collect();
    let p = profile(&leaves, &items).unwrap();
    assert_eq!(p.rule, "profile_v1");
    assert_eq!(p.n, 6);
    assert_eq!(p.evidenced, 5, "the untouched leaf is not evidenced");
    assert_eq!(p.contested, 1, "only the refuted leaf has Pl < .5");
    // Leaf Bel: .2, .4, .6, .8, 0 (refuted), 0 (untouched). Sorted
    // 0, 0, .2, .4, .6, .8: the even-count median is (.2 + .4)/2.
    assert!(close(p.bel.min, 0.0));
    assert!(close(p.bel.median, 0.3), "bel median {}", p.bel.median);
    assert!(close(p.bel.max, 0.8), "strongest leaf {}", p.bel.max);
    // Leaf BetP = Bel + Θ/2: .6, .7, .8, .9, then .15 for the refuted leaf
    // (F .7, Θ .3) and .5 for the untouched one. Sorted .15, .5, .6, .7, .8,
    // .9: median .65.
    assert!(close(p.betp.min, 0.15), "betp min {}", p.betp.min);
    assert!(close(p.betp.median, 0.65), "betp median {}", p.betp.median);
    assert!(close(p.betp.max, 0.9), "betp max {}", p.betp.max);
    // The weakest leaf caps the envelope: the refuted leaf (F .7) has
    // Pl .3, every other leaf has Pl 1. Its floor is 0 (Σ Bel = 2 over six
    // leaves); its NR cap is the refuted leaf's 1 − .7.
    assert!(close(p.frechet.hi, 0.3), "hi {}", p.frechet.hi);
    assert!(close(p.frechet.hi_nr, 0.3), "hi_nr {}", p.frechet.hi_nr);
    assert!(
        close(p.frechet.lo, 0.0),
        "six leaves at ≤ .8 have no Fréchet floor"
    );

    // Odd count (leaves 0..=4): Bel sorted 0, .2, .4, .6, .8 has median .4;
    // BetP sorted .15, .6, .7, .8, .9 has median .7.
    let odd = profile(&leaves[..5], &items).unwrap();
    assert_eq!(odd.n, 5);
    assert!(
        close(odd.bel.median, 0.4),
        "odd bel median {}",
        odd.bel.median
    );
    assert!(
        close(odd.betp.median, 0.7),
        "odd betp median {}",
        odd.betp.median
    );
}
