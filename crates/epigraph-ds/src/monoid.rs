//! Algebraic monoid structure for epistemic combination.
//!
//! A monoid has an identity element and an associative binary operation.
//! This module makes the algebraic properties of DS combination rules
//! explicit and checkable at compile time.

use crate::combination;
use crate::errors::DsError;
use crate::frame::FrameOfDiscernment;
use crate::mass::MassFunction;

/// Monoid over mass functions with a fixed combination strategy.
///
/// Laws (enforced by tests, not the type system):
/// - Identity: `combine(x, identity()) == x`
/// - Associativity: `combine(combine(a, b), c) == combine(a, combine(b, c))`
pub trait EpistemicMonoid: Sized {
    /// The identity element (vacuous mass for DS).
    fn identity(frame: FrameOfDiscernment) -> Self;

    /// Combine two mass functions.
    fn combine(&self, other: &Self) -> Result<Self, DsError>;

    /// Whether this combination rule is associative.
    fn is_associative() -> bool;

    /// Whether this combination rule is commutative.
    fn is_commutative() -> bool;

    /// Extract the inner mass function.
    fn mass_function(&self) -> &MassFunction;
}

/// Dempster's rule combination: normalizes by 1 - K_c.
/// Associative and commutative when K_c < 1.
#[derive(Debug, Clone)]
pub struct DempsterMonoid(pub MassFunction);

impl EpistemicMonoid for DempsterMonoid {
    fn identity(frame: FrameOfDiscernment) -> Self {
        Self(MassFunction::vacuous(frame))
    }

    fn combine(&self, other: &Self) -> Result<Self, DsError> {
        combination::dempster_combine(&self.0, &other.0).map(Self)
    }

    fn is_associative() -> bool {
        true
    }

    fn is_commutative() -> bool {
        true
    }

    fn mass_function(&self) -> &MassFunction {
        &self.0
    }
}

/// Raw conjunctive combination: preserves conflict mass.
/// Always associative and commutative.
#[derive(Debug, Clone)]
pub struct ConjunctiveMonoid(pub MassFunction);

impl EpistemicMonoid for ConjunctiveMonoid {
    fn identity(frame: FrameOfDiscernment) -> Self {
        Self(MassFunction::vacuous(frame))
    }

    fn combine(&self, other: &Self) -> Result<Self, DsError> {
        combination::conjunctive_combine(&self.0, &other.0).map(Self)
    }

    fn is_associative() -> bool {
        true
    }

    fn is_commutative() -> bool {
        true
    }

    fn mass_function(&self) -> &MassFunction {
        &self.0
    }
}

/// Fold a sequence using the monoid's combine operation.
/// Returns identity for empty input.
pub fn fold_monoid<M: EpistemicMonoid>(
    items: &[M],
    frame: FrameOfDiscernment,
) -> Result<M, DsError> {
    let mut acc = M::identity(frame);
    for item in items {
        acc = acc.combine(item)?;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn binary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("test", vec!["h0".into(), "h1".into()]).unwrap()
    }

    fn simple_mass(frame: &FrameOfDiscernment, support: f64) -> MassFunction {
        MassFunction::simple(frame.clone(), BTreeSet::from([0]), support).unwrap()
    }

    fn masses_approx_eq(a: &MassFunction, b: &MassFunction) -> bool {
        let a_map = a.masses();
        let b_map = b.masses();
        if a_map.len() != b_map.len() {
            return false;
        }
        for (k, v) in a_map {
            match b_map.get(k) {
                Some(bv) => {
                    if (v - bv).abs() > 1e-9 {
                        return false;
                    }
                }
                None => {
                    if v.abs() > 1e-9 {
                        return false;
                    }
                }
            }
        }
        true
    }

    #[test]
    fn test_dempster_identity() {
        let frame = binary_frame();
        let m = simple_mass(&frame, 0.7);
        let dm = DempsterMonoid(m.clone());
        let id = DempsterMonoid::identity(frame);
        let result = dm.combine(&id).unwrap();
        assert!(masses_approx_eq(&m, result.mass_function()));
    }

    #[test]
    fn test_dempster_associativity() {
        let frame = binary_frame();
        let a = DempsterMonoid(simple_mass(&frame, 0.6));
        let b = DempsterMonoid(simple_mass(&frame, 0.7));
        let c =
            DempsterMonoid(MassFunction::simple(frame.clone(), BTreeSet::from([1]), 0.5).unwrap());

        // (a ⊕ b) ⊕ c
        let ab = a.combine(&b).unwrap();
        let abc_left = ab.combine(&c).unwrap();

        // a ⊕ (b ⊕ c)
        let bc = b.combine(&c).unwrap();
        let abc_right = a.combine(&bc).unwrap();

        assert!(masses_approx_eq(
            abc_left.mass_function(),
            abc_right.mass_function()
        ));
    }

    #[test]
    fn test_dempster_commutativity() {
        let frame = binary_frame();
        let a = DempsterMonoid(simple_mass(&frame, 0.6));
        let b =
            DempsterMonoid(MassFunction::simple(frame.clone(), BTreeSet::from([1]), 0.4).unwrap());

        let ab = a.combine(&b).unwrap();
        let ba = b.combine(&a).unwrap();
        assert!(masses_approx_eq(ab.mass_function(), ba.mass_function()));
    }

    #[test]
    fn test_conjunctive_identity() {
        let frame = binary_frame();
        let m = simple_mass(&frame, 0.7);
        let cm = ConjunctiveMonoid(m.clone());
        let id = ConjunctiveMonoid::identity(frame);
        let result = cm.combine(&id).unwrap();
        assert!(masses_approx_eq(&m, result.mass_function()));
    }

    #[test]
    fn test_fold_monoid_empty() {
        let frame = binary_frame();
        let items: Vec<DempsterMonoid> = vec![];
        let result = fold_monoid(&items, frame.clone()).unwrap();
        let vacuous = MassFunction::vacuous(frame);
        assert!(masses_approx_eq(result.mass_function(), &vacuous));
    }

    #[test]
    fn test_fold_monoid_matches_sequential() {
        let frame = binary_frame();
        let a = DempsterMonoid(simple_mass(&frame, 0.5));
        let b = DempsterMonoid(simple_mass(&frame, 0.6));
        let c = DempsterMonoid(simple_mass(&frame, 0.7));

        // fold
        let folded = fold_monoid(&[a.clone(), b.clone(), c.clone()], frame).unwrap();

        // sequential
        let ab = a.combine(&b).unwrap();
        let abc = ab.combine(&c).unwrap();

        assert!(masses_approx_eq(
            folded.mass_function(),
            abc.mass_function()
        ));
    }
}
