//! Item-structured conjunction (R-DEP) over atom-level evidence items.
//!
//! A compound claim carries no evidence of its own: its belief is the belief
//! that every one of its leaves (atoms) holds, derived from the atoms'
//! evidence items. The same operator serves rule antecedents, which is why
//! literals may be negated.
//!
//! # Items
//!
//! An [`Item`] is one evidence source (one canonical key) as it bears on one
//! or more atoms. On each atom i it touches it has a literal ℓᵢ, a weight wᵢ
//! (mass on ℓᵢ) and an open-world weight oᵢ (mass on `~`, "the truth may lie
//! outside this frame"). Across atoms the item is the **comonotone
//! (quantile) coupling** of its per-atom marginals: draw one U on [0, 1]; on
//! atom i the item says ℓᵢ for U < wᵢ, Θ for wᵢ ≤ U < 1 − oᵢ, and O for
//! U ≥ 1 − oᵢ. On one atom this is exactly the item's own BBA, and a
//! `whole` item {T s, `~` o} copied onto n atoms reproduces the compound BBA
//! it came from. A row with mass on both T and F is a single-atom item
//! ([`Item::mixed`]) with its exact BBA.
//!
//! # Open world: exact CDST
//!
//! The served atom fold (`combination::dempster_combine`) meets `~` with any
//! positive focal element as genuine conflict (`cdst_intersect`: {T} ∩ `~`
//! and Θ ∩ `~` are positive(∅)), and `~` ∩ `~` = `~`. The DP reproduces that
//! with a per-atom alphabet {`*` untouched, Θ touched, T, F, O} ∪ {⊥}:
//!
//! ```text
//! * ∧ x = x      Θ ∧ Θ = Θ      Θ ∧ ℓ = ℓ      ℓ ∧ ℓ = ℓ      T ∧ F = ⊥
//! O ∧ O = O      O ∧ {Θ, T, F} = ⊥
//! ```
//!
//! Θ and `*` differ only on atoms that some item gives O mass; elsewhere they
//! are merged, which keeps the state space small.
//!
//! # Measures (L = the query literals, K = mass of ⊥)
//!
//! ```text
//! Bel(L)  = mass(states fixing every literal as L says) / (1 − K)
//! Dis(L)  = mass(states contradicting a literal of L, or carrying not_all) / (1 − K)
//! NR(L)   = 1 − Dis(L)                       the "not refuted" gate statistic
//! Pl(L)   = mass(states contradicting no literal, no O on L, no not_all) / (1 − K)
//! BetP(L) = Σ mass(s)·2^(−#free(s)) over the Pl states / (1 − K)   (product frame)
//! Bel(∨L) = mass(states fixing at least one literal as L says) / (1 − K)
//! ```
//!
//! `~` is never redistributed (as in `measures`), so Pl ≤ NR: an
//! open-world state is neither support nor refutation. OR is computed
//! directly; 1 − Pl(∧¬L) is not Bel(∨L) once `~` exists.
//!
//! The SPEC sections this implements are §3.3 (R-DEP, the DP, the cap and the
//! single negative sibling), §3.6 (the `not_all` valuation) and §2.2 (the
//! spine profile). The SPEC is the atom-level belief design document, which
//! is not part of this repository: every rule of it that this module relies
//! on is stated here and on the items below, so the section numbers are
//! cross-references only.

use crate::errors::DsError;
use std::collections::BTreeSet;

/// Tolerance for mass sums and probability bounds.
const TOL: f64 = 1e-9;

/// A literal: an atom, asserted (`positive`) or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Lit<A> {
    /// The atom the literal is about.
    pub atom: A,
    /// `true` for "the atom holds", `false` for "the atom does not hold".
    pub positive: bool,
}

impl<A> Lit<A> {
    /// The literal "`atom` holds".
    pub const fn pos(atom: A) -> Self {
        Self {
            atom,
            positive: true,
        }
    }

    /// The literal "`atom` does not hold".
    pub const fn neg(atom: A) -> Self {
        Self {
            atom,
            positive: false,
        }
    }

    /// The opposite literal on the same atom.
    #[must_use]
    pub fn negated(self) -> Self {
        Self {
            atom: self.atom,
            positive: !self.positive,
        }
    }
}

/// What one focal element of an item says about one atom it touches.
///
/// `T` and `F` are truth values of the atom (not of a literal), `Theta` is
/// "in the frame, unconstrained" and `O` is the open-world element `~`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Letter {
    /// Touched, unconstrained (closed-world ignorance).
    Theta,
    /// The atom is true.
    T,
    /// The atom is false.
    F,
    /// Open world: the truth may lie outside the atom's frame.
    O,
}

/// One focal element of an item: its mass and its letter on every atom the
/// item touches.
#[derive(Debug, Clone, PartialEq)]
pub struct Focal<A> {
    /// Mass of this focal element.
    pub mass: f64,
    /// The letter on each touched atom, in the item's atom order.
    pub letters: Vec<(A, Letter)>,
}

/// One atom's marginal inside an item: mass on T, on F and on `~`
/// (Θ takes the rest).
#[derive(Debug, Clone, PartialEq)]
struct Entry<A> {
    atom: A,
    t: f64,
    f: f64,
    o: f64,
}

impl<A> Entry<A> {
    /// The letter this entry gives at quantile `u`.
    fn letter_at(&self, u: f64) -> Letter {
        if u < self.t {
            Letter::T
        } else if u < self.t + self.f {
            Letter::F
        } else if u < 1.0 - self.o {
            Letter::Theta
        } else {
            Letter::O
        }
    }

    /// Whether the entry carries any mass other than Θ.
    fn is_evidence(&self) -> bool {
        self.t + self.f + self.o > 0.0
    }
}

/// One evidence item: the comonotone coupling of its per-atom marginals.
#[derive(Debug, Clone, PartialEq)]
pub struct Item<A> {
    entries: Vec<Entry<A>>,
}

fn check_mass(value: f64) -> Result<(), DsError> {
    if value.is_finite() && (0.0..=1.0 + TOL).contains(&value) {
        Ok(())
    } else {
        Err(DsError::InvalidProbability { value })
    }
}

fn check_sum(sum: f64) -> Result<(), DsError> {
    if sum <= 1.0 + TOL {
        Ok(())
    } else {
        Err(DsError::InvalidMassSum { sum })
    }
}

impl<A: Ord + Clone> Item<A> {
    /// A comonotone item: on each listed atom, weight `w` on the literal and
    /// `o` on `~` (Θ takes the rest).
    ///
    /// # Errors
    /// - `InvalidProbability` if a weight is NaN or outside [0, 1];
    /// - `InvalidMassSum` if w + o > 1 on an atom;
    /// - `InvalidConjunction` if the list is empty or names an atom twice.
    pub fn new(entries: Vec<(Lit<A>, f64, f64)>) -> Result<Self, DsError> {
        if entries.is_empty() {
            return Err(DsError::InvalidConjunction {
                reason: "an item must touch at least one atom".into(),
            });
        }
        let mut seen = BTreeSet::new();
        let mut out = Vec::with_capacity(entries.len());
        for (lit, w, o) in entries {
            check_mass(w)?;
            check_mass(o)?;
            check_sum(w + o)?;
            if !seen.insert(lit.atom.clone()) {
                return Err(DsError::InvalidConjunction {
                    reason: "an item names the same atom twice".into(),
                });
            }
            let (t, f) = if lit.positive { (w, 0.0) } else { (0.0, w) };
            out.push(Entry {
                atom: lit.atom,
                t,
                f,
                o,
            });
        }
        Ok(Self { entries: out })
    }

    /// A single-atom item with its exact BBA {T t, F f, `~` o, Θ rest}: the
    /// shape of a row with mass on both T and F.
    ///
    /// # Errors
    /// `InvalidProbability` for a NaN or out-of-range mass, `InvalidMassSum`
    /// if t + f + o > 1.
    pub fn mixed(atom: A, t: f64, f: f64, o: f64) -> Result<Self, DsError> {
        check_mass(t)?;
        check_mass(f)?;
        check_mass(o)?;
        check_sum(t + f + o)?;
        Ok(Self {
            entries: vec![Entry { atom, t, f, o }],
        })
    }

    /// The atoms this item touches, in its own order.
    pub fn atoms(&self) -> impl Iterator<Item = &A> {
        self.entries.iter().map(|e| &e.atom)
    }

    /// Whether the item carries mass other than Θ on `atom`.
    pub fn is_evidence_on(&self, atom: &A) -> bool {
        self.entries
            .iter()
            .any(|e| &e.atom == atom && e.is_evidence())
    }

    /// The focal elements of the coupling: the cylinders between consecutive
    /// breakpoints of U. Masses sum to 1; on each touched atom they
    /// marginalize to that atom's own BBA.
    #[must_use]
    pub fn focal_elements(&self) -> Vec<Focal<A>> {
        let mut cuts: Vec<f64> = vec![0.0, 1.0];
        for e in &self.entries {
            cuts.push(e.t);
            cuts.push(e.t + e.f);
            cuts.push(1.0 - e.o);
        }
        for c in &mut cuts {
            *c = c.clamp(0.0, 1.0);
        }
        cuts.sort_by(f64::total_cmp);
        cuts.dedup();

        let mut out: Vec<Focal<A>> = Vec::new();
        for win in cuts.windows(2) {
            let (lo, hi) = (win[0], win[1]);
            let mass = hi - lo;
            if mass <= 0.0 {
                continue;
            }
            let u = 0.5 * (lo + hi);
            let letters: Vec<(A, Letter)> = self
                .entries
                .iter()
                .map(|e| (e.atom.clone(), e.letter_at(u)))
                .collect();
            match out.last_mut() {
                Some(prev) if prev.letters == letters => prev.mass += mass,
                _ => out.push(Focal { mass, letters }),
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The exact DP
// ---------------------------------------------------------------------------

/// Most leaves the exact DP takes (SPEC §3.3 cap; the spine cutoff).
pub const MAX_LEAVES: usize = 16;

/// Most live states the exact DP keeps before it gives up (SPEC §3.3 cap).
pub const MAX_STATES: usize = 100_000;

/// Fréchet envelope of a conjunction: the bounds that hold whatever the
/// dependence between leaves, given their marginals.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Frechet {
    /// max(0, Σ Belᵢ − (n − 1)).
    pub lo: f64,
    /// min Plᵢ.
    pub hi: f64,
    /// min NRᵢ (the upper bound on NR).
    pub hi_nr: f64,
}

/// The result of a conjunction query.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConjResult {
    /// Bel(∧L): proven.
    pub bel: f64,
    /// Pl(∧L): consistent with the evidence, and not open-world.
    pub pl: f64,
    /// NR(∧L) = 1 − Dis(∧L): not refuted (the gate statistic); Pl ≤ NR.
    pub nr: f64,
    /// Product-frame `BetP`(∧L): ½ per free leaf. Display only.
    pub betp: f64,
    /// Bel(∨L), computed directly.
    pub bel_or: f64,
    /// Mass of ⊥ before normalization (conflict, including `~` annihilated
    /// by touched states, as in the served fold).
    pub k: f64,
    /// Fréchet envelope; lo ≤ Bel ≤ Pl ≤ hi and NR ≤ `hi_nr` always hold.
    /// From the DP it is built from the leaves' marginals in the same joint.
    /// Over the cap it is built from each leaf queried alone. After a
    /// closed-form negative valuation (including the over-cap `not_all`), lo
    /// follows the valuation and hi, `hi_nr` keep their pre-valuation values,
    /// which remain upper bounds because a negative valuation only shrinks
    /// Pl and NR.
    pub frechet: Frechet,
    /// `false` when the cap was hit and the result is R-IND + R-FRE, or when
    /// a closed form was applied to a base with [`open_world`] set.
    ///
    /// [`open_world`]: ConjResult::open_world
    pub exact: bool,
    /// Some item gives `~` mass on a query atom. The closed forms
    /// ([`not_all_closed_form`], [`single_negative_sibling`]) are exact only
    /// when this is `false`; with `~`, only [`conj_belief`]'s own `not_all`
    /// is exact CDST.
    pub open_world: bool,
}

/// Letter codes inside a DP state (3 bits per query position).
const STAR: u8 = 0;
const THETA: u8 = 1;
const LT: u8 = 2;
const LF: u8 = 3;
const LO: u8 = 4;
/// Flag bit: the state also carries the `not_all` valuation ¬(∧L).
const NOT_ALL: u64 = 1 << 63;

const fn code(letter: Letter) -> u8 {
    match letter {
        Letter::Theta => THETA,
        Letter::T => LT,
        Letter::F => LF,
        Letter::O => LO,
    }
}

/// The meet table of SPEC §3.3; `None` is ⊥.
const fn meet(a: u8, b: u8) -> Option<u8> {
    if a == STAR {
        return Some(b);
    }
    if b == STAR {
        return Some(a);
    }
    if a == LO || b == LO {
        return if a == b { Some(LO) } else { None };
    }
    if a == THETA {
        return Some(b);
    }
    if b == THETA || a == b {
        return Some(a);
    }
    None
}

fn get(state: u64, pos: usize) -> u8 {
    // Truncation is the intent: one 3-bit field.
    #[allow(clippy::cast_possible_truncation)]
    let v = ((state >> (3 * pos)) & 0b111) as u8;
    v
}

fn put(state: u64, pos: usize, letter: u8) -> u64 {
    (state & !(0b111 << (3 * pos))) | (u64::from(letter) << (3 * pos))
}

/// One focal element projected onto the query: its mass and a letter code
/// per query position it touches.
type ProjectedFocal = (f64, Vec<(usize, u8)>);

/// A query and its items, projected onto the query's positions.
struct Prepared {
    /// Letter code that makes each query literal hold (T or F).
    holds: Vec<u8>,
    /// Whether some item gives O mass on this position. Where none does, Θ
    /// is written as `*` (they meet everything alike there).
    open: Vec<bool>,
    /// Per item: its focal elements as (mass, [(position, letter code)]).
    items: Vec<Vec<ProjectedFocal>>,
}

impl Prepared {
    fn n(&self) -> usize {
        self.holds.len()
    }

    const fn fails(holds: u8) -> u8 {
        if holds == LT {
            LF
        } else {
            LT
        }
    }

    /// Θ as written at `pos` (merged into `*` where no O can occur).
    fn theta(&self, pos: usize) -> u8 {
        if self.open[pos] {
            THETA
        } else {
            STAR
        }
    }
}

fn prepare<A: Ord + Clone>(query: &[Lit<A>], items: &[Item<A>]) -> Result<Prepared, DsError> {
    if query.is_empty() {
        return Err(DsError::InsufficientSources);
    }
    let mut position = std::collections::BTreeMap::new();
    for (i, lit) in query.iter().enumerate() {
        if position.insert(lit.atom.clone(), i).is_some() {
            return Err(DsError::InvalidConjunction {
                reason: "an atom appears twice in the query".into(),
            });
        }
    }
    let holds: Vec<u8> = query
        .iter()
        .map(|l| if l.positive { LT } else { LF })
        .collect();
    let mut open = vec![false; query.len()];
    for item in items {
        for e in &item.entries {
            if let Some(&p) = position.get(&e.atom) {
                open[p] |= e.o > 0.0;
            }
        }
    }
    let mut prepared = Prepared {
        holds,
        open,
        items: Vec::new(),
    };
    for item in items {
        // Atoms outside the query (for example, leaves the viewer cannot
        // see) are projected away; an item touching none is vacuous here.
        if !item.atoms().any(|a| position.contains_key(a)) {
            continue;
        }
        let mut focals: Vec<ProjectedFocal> = Vec::new();
        for f in item.focal_elements() {
            let assign: Vec<(usize, u8)> = f
                .letters
                .iter()
                .filter_map(|(a, l)| {
                    position.get(a).map(|&p| {
                        let c = code(*l);
                        (p, if c == THETA { prepared.theta(p) } else { c })
                    })
                })
                .collect();
            match focals.iter_mut().find(|(_, x)| *x == assign) {
                Some((m, _)) => *m += f.mass,
                None => focals.push((f.mass, assign)),
            }
        }
        prepared.items.push(focals);
    }
    Ok(prepared)
}

/// Settle a state carrying `not_all`: drop the flag once a literal is
/// contradicted, turn it into ⊥ once every literal holds, and resolve it
/// when exactly one literal is still open (that literal must fail).
///
/// A flagged state never holds O: the valuation starts every open position
/// at Θ (touched), and Θ ∧ O = ⊥. So an open literal here is `*` or Θ, and
/// forcing it to fail is always a meet, never a clash.
fn settle(p: &Prepared, state: u64) -> Option<u64> {
    if state & NOT_ALL == 0 {
        return Some(state);
    }
    let mut open_pos = None;
    let mut open_count = 0;
    for pos in 0..p.n() {
        let l = get(state, pos);
        if l == Prepared::fails(p.holds[pos]) {
            return Some(state & !NOT_ALL);
        }
        if l != p.holds[pos] {
            open_count += 1;
            open_pos = Some(pos);
        }
    }
    match (open_count, open_pos) {
        (0, _) => None,
        (1, Some(pos)) => Some(put(state, pos, Prepared::fails(p.holds[pos])) & !NOT_ALL),
        _ => Some(state),
    }
}

/// Final DP states (mass not yet normalized) and the conflict mass.
struct Joint {
    states: Vec<(u64, f64)>,
    k: f64,
}

/// Run the DP. `Ok(None)` means the live-state cap was hit.
fn run_dp(p: &Prepared, not_all: f64) -> Result<Option<Joint>, DsError> {
    let mut states: std::collections::BTreeMap<u64, f64> = std::collections::BTreeMap::new();
    let mut k = 0.0;
    if not_all > 0.0 {
        // The valuation is one more item over the product frame of L's
        // atoms: ¬(∧L) with mass m, the frame itself with 1 − m. Both are
        // closed-world sets on L's atoms, so they meet O as ⊥ (exact CDST).
        let base = (0..p.n()).fold(0u64, |s, pos| put(s, pos, p.theta(pos)));
        if not_all < 1.0 {
            states.insert(base, 1.0 - not_all);
        }
        match settle(p, base | NOT_ALL) {
            Some(s) => *states.entry(s).or_insert(0.0) += not_all,
            None => k += not_all,
        }
    } else {
        states.insert(0, 1.0);
    }
    for focals in &p.items {
        let mut next: std::collections::BTreeMap<u64, f64> = std::collections::BTreeMap::new();
        for (&s, &ms) in &states {
            'focal: for (mf, assign) in focals {
                let mass = ms * mf;
                if mass == 0.0 {
                    continue;
                }
                let mut t = s;
                for &(pos, letter) in assign {
                    if let Some(l) = meet(get(t, pos), letter) {
                        t = put(t, pos, l);
                    } else {
                        k += mass;
                        continue 'focal;
                    }
                }
                match settle(p, t) {
                    Some(t) => *next.entry(t).or_insert(0.0) += mass,
                    None => k += mass,
                }
            }
            // Checked per source state, not once the item is done: one item
            // can multiply the live states by its focal count (up to 3n + 1),
            // so a check after the item lets `next` grow far past the cap.
            if next.len() > MAX_STATES {
                return Ok(None);
            }
        }
        states = next;
    }
    let total: f64 = states.values().sum();
    if total < TOL {
        return Err(DsError::TotalConflict);
    }
    Ok(Some(Joint {
        states: states.into_iter().collect(),
        k,
    }))
}

fn unit(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

fn check_not_all(m: f64) -> Result<(), DsError> {
    if m.is_finite() && (0.0..=1.0).contains(&m) {
        Ok(())
    } else {
        Err(DsError::InvalidProbability { value: m })
    }
}

/// Evaluate every measure on the final DP states.
fn evaluate(p: &Prepared, joint: &Joint) -> ConjResult {
    let n = p.n();
    let total: f64 = joint.states.iter().map(|(_, m)| m).sum();
    let (mut bel, mut pl, mut dis, mut betp, mut bel_or) = (0.0, 0.0, 0.0, 0.0, 0.0);
    let mut bel_i = vec![0.0; n];
    let mut pl_i = vec![0.0; n];
    let mut dis_i = vec![0.0; n];
    for &(s, m) in &joint.states {
        let not_all = s & NOT_ALL != 0;
        let (mut all, mut any, mut refuted, mut open_world, mut free) =
            (true, false, false, false, 0i32);
        for pos in 0..n {
            let l = get(s, pos);
            let fails = Prepared::fails(p.holds[pos]);
            // A settled not_all state has at least two open literals and none
            // refuted, so each leaf's own marginal reads it as unflagged.
            if l == p.holds[pos] {
                any = true;
                bel_i[pos] += m;
            } else {
                all = false;
            }
            if l == fails {
                refuted = true;
                dis_i[pos] += m;
            } else if l != LO {
                pl_i[pos] += m;
            }
            open_world |= l == LO;
            if l == STAR || l == THETA {
                free += 1;
            }
        }
        if all {
            bel += m;
        }
        if any {
            bel_or += m;
        }
        if refuted || not_all {
            dis += m;
        }
        if !refuted && !open_world && !not_all {
            pl += m;
            betp += m * 0.5f64.powi(free);
        }
    }
    let frechet = envelope(
        bel_i.iter().map(|b| b / total),
        pl_i.iter().map(|x| x / total),
        dis_i.iter().map(|d| 1.0 - d / total),
    );
    ConjResult {
        bel: unit(bel / total),
        pl: unit(pl / total),
        nr: unit(1.0 - dis / total),
        betp: unit(betp / total),
        bel_or: unit(bel_or / total),
        k: unit(joint.k),
        frechet,
        exact: true,
        open_world: p.open.iter().any(|o| *o),
    }
}

fn envelope(
    bels: impl Iterator<Item = f64>,
    pls: impl Iterator<Item = f64>,
    nrs: impl Iterator<Item = f64>,
) -> Frechet {
    let (mut sum, mut n) = (0.0, 0.0);
    for b in bels {
        sum += b;
        n += 1.0;
    }
    Frechet {
        lo: unit(sum - (n - 1.0)),
        hi: unit(pls.fold(1.0, f64::min)),
        hi_nr: unit(nrs.fold(1.0, f64::min)),
    }
}

/// R-DEP: belief in the conjunction of `query`, from the items over its
/// atoms, with an optional `not_all` valuation m on ¬(∧L) (SPEC §3.6; pass
/// 0 for none).
///
/// Exact (`exact: true`) up to [`MAX_LEAVES`] leaves and [`MAX_STATES`] live
/// states. Above either cap it returns R-IND over each leaf queried alone,
/// with the Fréchet envelope of those leaves, and the `not_all` closed form
/// applied on top (`exact: false`).
///
/// Entries on atoms outside the query are ignored. The `not_all` valuation
/// is a closed-world set on the query's atoms, so when it is present (m > 0)
/// it meets open-world states on those atoms as conflict, exactly as any
/// positive BBA does in the served fold; with m = 0 it is absent.
///
/// **Sign under `~`.** Without `~` on the query's atoms, Bel, Pl and NR are
/// non-increasing in `not_all`. With `~`, a refutation can *raise* Bel and
/// Pl: the annihilated O mass is renormalized away. A leaf {T .5, `~` .3,
/// Θ .2} goes from Bel .5 / Pl .7 at m = 0 to ≈ .692 / ≈ .969 at m = .1, so
/// the result is also discontinuous as m → 0⁺. The served fold does exactly
/// the same with a refuting row on the atom; this is the exact-CDST reading
/// of the valuation, not a separate rule. Over the cap the closed-world closed
/// form is applied to the R-IND product instead, which always lowers them,
/// so the sign can differ between 16 and 17 leaves (the latter is
/// `exact: false`).
///
/// # Errors
/// - `InsufficientSources` for an empty query;
/// - `InvalidConjunction` if an atom appears twice in the query;
/// - `InvalidProbability` if `not_all` is NaN or outside [0, 1];
/// - `TotalConflict` if the evidence is in total conflict (as
///   `dempster_combine`).
pub fn conj_belief<A: Ord + Clone>(
    query: &[Lit<A>],
    items: &[Item<A>],
    not_all: f64,
) -> Result<ConjResult, DsError> {
    check_not_all(not_all)?;
    let p = prepare(query, items)?;
    if p.n() <= MAX_LEAVES {
        if let Some(joint) = run_dp(&p, not_all)? {
            return Ok(evaluate(&p, &joint));
        }
    }
    independent_fallback(query, items, not_all)
}

/// R-IND + R-FRE over each leaf queried alone (the over-cap path).
fn independent_fallback<A: Ord + Clone>(
    query: &[Lit<A>],
    items: &[Item<A>],
    not_all: f64,
) -> Result<ConjResult, DsError> {
    let mut singles = Vec::with_capacity(query.len());
    for lit in query {
        let p = prepare(std::slice::from_ref(lit), items)?;
        let joint = run_dp(&p, 0.0)?.ok_or(DsError::ConjunctionOverCap {
            leaves: 1,
            states: MAX_STATES,
        })?;
        singles.push(evaluate(&p, &joint));
    }
    let prod = |f: fn(&ConjResult) -> f64| singles.iter().map(f).product::<f64>();
    let base = ConjResult {
        bel: unit(prod(|s| s.bel)),
        pl: unit(prod(|s| s.pl)),
        nr: unit(prod(|s| s.nr)),
        betp: unit(prod(|s| s.betp)),
        bel_or: unit(1.0 - prod(|s| 1.0 - s.bel)),
        k: unit(1.0 - prod(|s| 1.0 - s.k)),
        frechet: envelope(
            singles.iter().map(|s| s.bel),
            singles.iter().map(|s| s.pl),
            singles.iter().map(|s| s.nr),
        ),
        exact: false,
        open_world: singles.iter().any(|s| s.open_world),
    };
    if not_all > 0.0 {
        apply_negative_valuation(&base, base.bel, not_all)
    } else {
        Ok(base)
    }
}

/// Bel of the conjunction of the query literals at `positions`, taken in the
/// joint over the whole query (same items, same conflict, same `not_all`).
/// This is the `Bel_DEP(aᵢ ∧ aⱼ)` that [`single_negative_sibling`] needs:
/// a two-leaf query on its own can differ when items conflict on other
/// leaves.
///
/// # Errors
/// As [`conj_belief`], plus `InvalidConjunction` for an empty, repeated or
/// out-of-range position and `ConjunctionOverCap` above the exact cap.
pub fn joint_bel<A: Ord + Clone>(
    query: &[Lit<A>],
    items: &[Item<A>],
    not_all: f64,
    positions: &[usize],
) -> Result<f64, DsError> {
    check_not_all(not_all)?;
    let distinct: BTreeSet<usize> = positions.iter().copied().collect();
    if positions.is_empty()
        || distinct.len() != positions.len()
        || positions.iter().any(|&i| i >= query.len())
    {
        return Err(DsError::InvalidConjunction {
            reason: "positions must be distinct indices into the query".into(),
        });
    }
    let p = prepare(query, items)?;
    let over = DsError::ConjunctionOverCap {
        leaves: query.len(),
        states: MAX_STATES,
    };
    if p.n() > MAX_LEAVES {
        return Err(over);
    }
    let joint = run_dp(&p, not_all)?.ok_or(over)?;
    let total: f64 = joint.states.iter().map(|(_, m)| m).sum();
    let fixed: f64 = joint
        .states
        .iter()
        .filter(|(s, _)| positions.iter().all(|&i| get(*s, i) == p.holds[i]))
        .map(|(_, m)| m)
        .sum();
    Ok(unit(fixed / total))
}

/// Combine `base` with a negative valuation of mass `m` on ¬(∧C), where C
/// is a subset of the query literals and `covered_bel` = Bel(∧C) in the
/// same joint (C = L for `not_all`, a sibling pair for a negative edge).
///
/// The closed-world (ow = 0) form of SPEC §3.3 / §3.6. States that fix C
/// meet ¬(∧C) as ⊥ (mass m·`covered_bel` = K'); every other surviving
/// state that carries the valuation refutes ∧L, because ∧L ⊆ ∧C:
///
/// ```text
/// Bel   = Bel·(1 − m)/(1 − K')        Pl = Pl·(1 − m)/(1 − K')
/// BetP  = BetP·(1 − m)/(1 − K')
/// Dis   = ((1 − m)·Dis + m·(1 − Bel(∧C)))/(1 − K'),  NR = 1 − Dis
/// Bel(∨L) = (Bel(∨L) − K')/(1 − K')
/// K     = K + (1 − K)·K'
/// lo    = max(0, (lo − K')/(1 − K'))
/// ```
///
/// The envelope floor follows the valuation. Each leaf's Bel inside the new
/// joint is (Belᵢ − m·Bel(aᵢ ∧ ∧C))/(1 − K') ≥ (Belᵢ − K')/(1 − K'), with
/// equality for the leaves of C, so the floor above is exact for `not_all`
/// (C = L) and a sound floor for a sibling pair. `hi` and `hi_nr` are kept:
/// Pl and NR only shrink, by (1 − m)/(1 − K') ≤ 1, so the pre-valuation
/// bounds still hold, though they can be looser than the DP's.
fn apply_negative_valuation(
    base: &ConjResult,
    covered_bel: f64,
    m: f64,
) -> Result<ConjResult, DsError> {
    check_not_all(m)?;
    check_mass(covered_bel)?;
    if covered_bel + TOL < base.bel {
        return Err(DsError::InvalidConjunction {
            reason: "Bel of a sub-conjunction cannot be below Bel of the whole".into(),
        });
    }
    let k_prime = m * covered_bel;
    let z = 1.0 - k_prime;
    if z < TOL {
        return Err(DsError::TotalConflict);
    }
    let keep = (1.0 - m) / z;
    let dis = ((1.0 - m) * (1.0 - base.nr) + m * (1.0 - covered_bel)) / z;
    Ok(ConjResult {
        bel: unit(base.bel * keep),
        pl: unit(base.pl * keep),
        nr: unit(1.0 - dis),
        betp: unit(base.betp * keep),
        bel_or: unit((base.bel_or - k_prime) / z),
        k: unit(base.k + (1.0 - base.k) * k_prime),
        frechet: Frechet {
            lo: unit((base.frechet.lo - k_prime) / z),
            ..base.frechet
        },
        // The closed form is the ow = 0 case: with `~` on a query atom it is
        // not what exact CDST gives (the valuation's frame part would meet
        // the O states as conflict), so it is labelled inexact.
        exact: base.exact && !base.open_world,
        open_world: base.open_world,
    })
}

// ---------------------------------------------------------------------------
// Closed forms for negative valuations (ow = 0)
// ---------------------------------------------------------------------------

/// The `not_all` closed form of SPEC §3.6: `base` (an R-DEP result without
/// the valuation) combined with mass `m` on ¬(∧L).
///
/// It equals [`conj_belief`] with `not_all = m` whenever no leaf carries
/// open-world mass. With `~` present (`base.open_world`), the result is
/// returned with `exact: false`; use the DP ([`conj_belief`] with
/// `not_all = m`), which lets the CDST meet table decide how O states meet
/// the valuation.
///
/// # Errors
/// `InvalidProbability` if `m` is outside [0, 1]; `TotalConflict` if
/// m = 1 and Bel = 1.
pub fn not_all_closed_form(base: &ConjResult, m: f64) -> Result<ConjResult, DsError> {
    apply_negative_valuation(base, base.bel, m)
}

/// The single-negative-sibling closed form of SPEC §3.3: one contradicts or
/// refutes edge of strength `m` between two leaves aᵢ, aⱼ of the compound.
///
/// `base` is R-DEP over the compound with that edge's own BBA dropped from
/// the target atom's items, and `pair_bel` is Bel(aᵢ ∧ aⱼ) **in the same
/// joint** ([`joint_bel`] with the two positions). With K' = m·`pair_bel`,
/// Bel and Pl scale by (1 − m)/(1 − K'); NR, `BetP`, Bel(∨L) and K follow
/// the same valuation. Two or more negative siblings have no closed form
/// here (the SPEC serves R-FRE with `internally_contested`).
///
/// **Precondition: no `~` on the query's atoms** (ow = 0). When
/// `base.open_world` is set the value is not exact CDST and is returned with
/// `exact: false`. This module has no exact path for a valuation over a
/// subset of the query; a caller that needs one under `~` must add it.
///
/// # Errors
/// `InvalidProbability` for `m` or `pair_bel` outside [0, 1];
/// `InvalidConjunction` if `pair_bel` < `base.bel` (a pair cannot be less
/// believed than a conjunction that contains it); `TotalConflict` if
/// K' = 1.
pub fn single_negative_sibling(
    base: &ConjResult,
    pair_bel: f64,
    m: f64,
) -> Result<ConjResult, DsError> {
    apply_negative_valuation(base, pair_bel, m)
}

// ---------------------------------------------------------------------------
// Profile (spine and over-cap nodes)
// ---------------------------------------------------------------------------

/// The rule tag of a [`Profile`].
pub const PROFILE_RULE: &str = "profile_v1";

/// Minimum, median and maximum of a per-leaf statistic.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    /// Smallest value.
    pub min: f64,
    /// Median (mean of the two middle values for an even count).
    pub median: f64,
    /// Largest value.
    pub max: f64,
}

impl Summary {
    fn of(mut values: Vec<f64>) -> Self {
        values.sort_by(f64::total_cmp);
        let n = values.len();
        let median = if n % 2 == 1 {
            values[n / 2]
        } else {
            0.5 * (values[n / 2 - 1] + values[n / 2])
        };
        Self {
            min: values[0],
            median,
            max: values[n - 1],
        }
    }
}

/// A profile of a node's leaves, served instead of a conjunction for spine
/// nodes (SPEC §2.2): "the whole paper is true" has Bel ≈ 0 by construction,
/// so a conjunction there carries no information.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Always [`PROFILE_RULE`].
    pub rule: &'static str,
    /// Number of leaves.
    pub n: usize,
    /// Leaves that some item touches with mass other than Θ.
    pub evidenced: usize,
    /// Per-leaf Bel.
    pub bel: Summary,
    /// Per-leaf `BetP`.
    pub betp: Summary,
    /// Leaves with Pl < 0.5.
    pub contested: usize,
    /// Fréchet envelope of the leaves, each queried alone.
    pub frechet: Frechet,
}

/// Profile `leaves` (each read as its positive literal, alone) from `items`.
///
/// # Errors
/// `InsufficientSources` for no leaves, `InvalidConjunction` for a repeated
/// leaf, `TotalConflict` if a leaf's own evidence is in total conflict.
pub fn profile<A: Ord + Clone>(leaves: &[A], items: &[Item<A>]) -> Result<Profile, DsError> {
    if leaves.is_empty() {
        return Err(DsError::InsufficientSources);
    }
    let distinct: BTreeSet<&A> = leaves.iter().collect();
    if distinct.len() != leaves.len() {
        return Err(DsError::InvalidConjunction {
            reason: "a leaf appears twice in the profile".into(),
        });
    }
    let mut singles = Vec::with_capacity(leaves.len());
    for a in leaves {
        singles.push(conj_belief(&[Lit::pos(a.clone())], items, 0.0)?);
    }
    let evidenced = leaves
        .iter()
        .filter(|a| items.iter().any(|it| it.is_evidence_on(a)))
        .count();
    Ok(Profile {
        rule: PROFILE_RULE,
        n: leaves.len(),
        evidenced,
        bel: Summary::of(singles.iter().map(|s| s.bel).collect()),
        betp: Summary::of(singles.iter().map(|s| s.betp).collect()),
        contested: singles.iter().filter(|s| s.pl < 0.5).count(),
        frechet: envelope(
            singles.iter().map(|s| s.bel),
            singles.iter().map(|s| s.pl),
            singles.iter().map(|s| s.nr),
        ),
    })
}
