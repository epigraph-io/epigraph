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
//! spine profile).

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
