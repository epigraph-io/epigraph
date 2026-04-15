//! Complementary Dempster-Shafer Theory (CDST) math for `EpiGraph`
//!
//! This crate provides the pure mathematical foundation for epistemic
//! reasoning using CDST (Skau et al., ISIPTA 2023):
//!
//! - **Frames of discernment**: Sets of mutually exclusive hypotheses
//! - **Focal elements**: Subset + complement flag distinguishing conflict from incompleteness
//! - **Mass functions** (BBAs): Belief mass assignments over CDST focal elements
//! - **Combination rules**: Conjunctive (primitive), Dempster, Yager, Dubois-Prade, Inagaki
//! - **Measures**: Belief, plausibility, pignistic probability
//!
//! # Design Principles
//!
//! - **CDST-native**: Focal elements carry complement flags distinguishing
//!   genuine conflict `(empty, false)` from missing propositions `(Omega, true)`.
//! - **Pure math**: No database, no persistence. That stays in `epigraph-db`.
//! - **Explicit ignorance**: The belief-plausibility interval captures what
//!   we *don't* know, and CDST separates conflict from incompleteness.
//!
//! # Quick Start
//!
//! ```
//! use epigraph_ds::{FrameOfDiscernment, MassFunction, FocalElement, combination, measures};
//! use std::collections::BTreeSet;
//!
//! // Define a frame: is the material stable?
//! let frame = FrameOfDiscernment::new(
//!     "stability",
//!     vec!["stable".into(), "unstable".into()],
//! ).unwrap();
//!
//! // Source 1: 80% confident it's stable
//! let m1 = MassFunction::simple(frame.clone(), BTreeSet::from([0]), 0.8).unwrap();
//!
//! // Source 2: 60% confident it's stable
//! let m2 = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();
//!
//! // Combine using Dempster's rule
//! let combined = combination::dempster_combine(&m1, &m2).unwrap();
//!
//! // Get belief interval
//! let fe = FocalElement::positive(BTreeSet::from([0]));
//! let (bel, pl) = measures::belief_interval(&combined, &fe);
//! assert!(bel > 0.8); // Combined evidence strengthens belief
//! ```

pub mod combination;
pub mod errors;
pub mod frame;
pub mod mass;
pub mod measures;
pub mod monoid;

// Re-export primary types
pub use errors::DsError;
pub use frame::FrameOfDiscernment;
pub use mass::{focal_serde, FocalElement, MassFunction};

// Re-export combination types
pub use combination::{
    select_combination_rule, CombinationMethod, CombinationReport, CombinationRule,
};

// Re-export monoid types
pub use monoid::{fold_monoid, ConjunctiveMonoid, DempsterMonoid, EpistemicMonoid};
