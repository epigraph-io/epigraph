//! Mass function (Basic Belief Assignment) with CDST extensions
//!
//! A mass function m: 2^Theta -> [0,1] assigns belief mass to focal elements.
//! In classical DS, focal elements are plain subsets. In Complementary DST
//! (Skau et al., ISIPTA 2023), each focal element carries a boolean complement
//! flag that distinguishes genuine conflict from frame incompleteness:
//!
//! - `(u, complement=false)` — "truth is within u" (standard DS)
//! - `(u, complement=true)` — "truth is outside u, including unknown propositions"
//!
//! Key semantic distinctions:
//! - `(empty, false)` = genuine conflict (irreconcilable evidence)
//! - `(Omega, true)` = missing propositions (frame may be incomplete)
//! - `(empty, true)` = total open-world ignorance
//! - `(Omega, false)` = closed-world ignorance (standard DS vacuous)

use crate::errors::DsError;
use crate::frame::FrameOfDiscernment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Tolerance for floating-point sum validation
const SUM_TOLERANCE: f64 = 1e-9;

/// A focal element in Complementary Dempster-Shafer Theory (CDST)
///
/// Pairs a subset of the frame with a complement flag:
/// - `complement = false` → "truth is within `subset`" (positive/standard)
/// - `complement = true` → "truth is outside `subset`" (negative/complement)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FocalElement {
    /// The subset of hypothesis indices
    pub subset: BTreeSet<usize>,
    /// Whether this is a complement element
    pub complement: bool,
}

impl FocalElement {
    /// Standard DS element: "truth is within `subset`"
    #[must_use]
    pub const fn positive(subset: BTreeSet<usize>) -> Self {
        Self {
            subset,
            complement: false,
        }
    }

    /// Complement element: "truth is outside `subset`"
    #[must_use]
    pub const fn negative(subset: BTreeSet<usize>) -> Self {
        Self {
            subset,
            complement: true,
        }
    }

    /// Genuine conflict: `(empty, false)` — irreconcilable evidence
    #[must_use]
    pub const fn conflict() -> Self {
        Self {
            subset: BTreeSet::new(),
            complement: false,
        }
    }

    /// Missing propositions: `(Omega, true)` — frame may be incomplete
    #[must_use]
    pub fn missing(frame: &FrameOfDiscernment) -> Self {
        Self {
            subset: frame.full_set(),
            complement: true,
        }
    }

    /// Total open-world ignorance: `(empty, true)`
    #[must_use]
    pub const fn vacuous() -> Self {
        Self {
            subset: BTreeSet::new(),
            complement: true,
        }
    }

    /// Closed-world ignorance: `(Omega, false)` — standard DS vacuous
    #[must_use]
    pub fn theta(frame: &FrameOfDiscernment) -> Self {
        Self {
            subset: frame.full_set(),
            complement: false,
        }
    }

    /// Check if this is a positive (standard DS) element
    #[must_use]
    pub const fn is_positive(&self) -> bool {
        !self.complement
    }

    /// Check if this represents genuine conflict: `(empty, false)`
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        !self.complement && self.subset.is_empty()
    }

    /// Check if this represents missing propositions: `(Omega, true)`
    #[must_use]
    pub fn is_missing(&self, frame: &FrameOfDiscernment) -> bool {
        self.complement && self.subset == frame.full_set()
    }

    /// Check if this represents open-world vacuous: `(empty, true)`
    #[must_use]
    pub fn is_vacuous_element(&self) -> bool {
        self.complement && self.subset.is_empty()
    }

    /// Check if this represents closed-world ignorance: `(Omega, false)`
    #[must_use]
    pub fn is_theta(&self, frame: &FrameOfDiscernment) -> bool {
        !self.complement && self.subset == frame.full_set()
    }
}

impl std::fmt::Display for FocalElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = if self.complement { "~" } else { "" };
        let indices: Vec<String> = self.subset.iter().map(ToString::to_string).collect();
        write!(f, "{prefix}{{{}}}", indices.join(","))
    }
}

/// Custom serialization for `BTreeMap<FocalElement, f64>` as JSON.
///
/// JSON requires string keys. Positive elements use comma-separated indices
/// (e.g. `"0,1"`). Complement elements use `~`-prefix (e.g. `"~0,1"`).
/// Empty set: `""` (conflict) or `"~"` (open-world vacuous).
mod mass_map_serde {
    use super::FocalElement;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::{BTreeMap, BTreeSet};

    fn focal_to_key(fe: &FocalElement) -> String {
        let indices: String = fe
            .subset
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if fe.complement {
            format!("~{indices}")
        } else {
            indices
        }
    }

    fn key_to_focal(key: &str) -> Result<FocalElement, String> {
        let (complement, idx_str) = key
            .strip_prefix('~')
            .map_or((false, key), |rest| (true, rest));

        let subset: BTreeSet<usize> = if idx_str.is_empty() {
            BTreeSet::new()
        } else {
            idx_str
                .split(',')
                .map(|s| {
                    s.parse::<usize>()
                        .map_err(|e| format!("Invalid index '{s}': {e}"))
                })
                .collect::<Result<BTreeSet<usize>, String>>()?
        };

        Ok(FocalElement { subset, complement })
    }

    pub fn serialize<S>(map: &BTreeMap<FocalElement, f64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string_map: BTreeMap<String, f64> =
            map.iter().map(|(k, v)| (focal_to_key(k), *v)).collect();
        string_map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<FocalElement, f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map = BTreeMap::<String, f64>::deserialize(deserializer)?;
        string_map
            .into_iter()
            .map(|(k, v)| {
                key_to_focal(&k)
                    .map(|fe| (fe, v))
                    .map_err(serde::de::Error::custom)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    // Expose for use by masses_to_json / from_json_masses and external crates
    pub fn focal_to_key_pub(fe: &FocalElement) -> String {
        focal_to_key(fe)
    }

    pub fn key_to_focal_pub(key: &str) -> Result<FocalElement, String> {
        key_to_focal(key)
    }
}

/// Public re-exports of mass key serialization helpers for external crates.
pub mod focal_serde {
    pub use super::mass_map_serde::focal_to_key_pub as focal_to_key;
    pub use super::mass_map_serde::key_to_focal_pub as key_to_focal;
}

/// A Basic Belief Assignment (BBA) / mass function over a frame
///
/// Maps focal elements (CDST extended subsets) to mass values in [0, 1].
/// All masses must sum to 1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MassFunction {
    frame: FrameOfDiscernment,
    #[serde(with = "mass_map_serde")]
    masses: BTreeMap<FocalElement, f64>,
}

impl MassFunction {
    /// Create a new mass function with validation
    ///
    /// # Errors
    /// - `DsError::NegativeMass` if any mass is negative
    /// - `DsError::ElementOutsideFrame` if a positive subset contains invalid indices
    /// - `DsError::InvalidMassSum` if masses don't sum to 1.0
    pub fn new(
        frame: FrameOfDiscernment,
        masses: BTreeMap<FocalElement, f64>,
    ) -> Result<Self, DsError> {
        for (fe, &mass) in &masses {
            if mass < 0.0 {
                return Err(DsError::NegativeMass { value: mass });
            }
            // Validate: positive elements must have indices within frame
            if !fe.complement && !frame.is_valid_subset(&fe.subset) {
                return Err(DsError::ElementOutsideFrame {
                    element: format!("{fe}"),
                });
            }
            // Negative elements: subset indices must also be within frame
            if fe.complement && !frame.is_valid_subset(&fe.subset) {
                return Err(DsError::ElementOutsideFrame {
                    element: format!("{fe}"),
                });
            }
        }

        let sum: f64 = masses.values().sum();
        if (sum - 1.0).abs() > SUM_TOLERANCE {
            return Err(DsError::InvalidMassSum { sum });
        }

        Ok(Self { frame, masses })
    }

    /// Create a vacuous mass function (total ignorance): m(Theta) = 1.0
    ///
    /// Uses closed-world ignorance `(Omega, false)` — standard DS vacuous.
    #[must_use]
    pub fn vacuous(frame: FrameOfDiscernment) -> Self {
        let theta = FocalElement::theta(&frame);
        let mut masses = BTreeMap::new();
        masses.insert(theta, 1.0);
        Self { frame, masses }
    }

    /// Create a categorical mass function: m({h}) = 1.0 (certainty)
    ///
    /// # Errors
    /// Returns `DsError::ElementOutsideFrame` if `hypothesis_idx` is invalid.
    pub fn categorical(frame: FrameOfDiscernment, hypothesis_idx: usize) -> Result<Self, DsError> {
        if !frame.is_valid_index(hypothesis_idx) {
            return Err(DsError::ElementOutsideFrame {
                element: format!("index {hypothesis_idx}"),
            });
        }
        let mut masses = BTreeMap::new();
        masses.insert(
            FocalElement::positive(BTreeSet::from([hypothesis_idx])),
            1.0,
        );
        Ok(Self { frame, masses })
    }

    /// Create a simple mass function: m(A) = mass, m(Theta) = 1 - mass
    ///
    /// Both focal elements are positive (standard DS).
    ///
    /// # Errors
    /// Returns error if `mass` is not in [0, 1] or `subset` is invalid.
    pub fn simple(
        frame: FrameOfDiscernment,
        subset: BTreeSet<usize>,
        mass: f64,
    ) -> Result<Self, DsError> {
        if mass < 0.0 {
            return Err(DsError::NegativeMass { value: mass });
        }
        if mass > 1.0 + SUM_TOLERANCE {
            return Err(DsError::InvalidMassSum { sum: mass });
        }
        if !frame.is_valid_subset(&subset) {
            return Err(DsError::ElementOutsideFrame {
                element: format!("{subset:?}"),
            });
        }

        let theta = FocalElement::theta(&frame);
        let focal = FocalElement::positive(subset);
        let mut masses = BTreeMap::new();

        if (mass - 1.0).abs() < SUM_TOLERANCE {
            masses.insert(focal, 1.0);
        } else if mass.abs() < SUM_TOLERANCE || focal == theta {
            masses.insert(theta, 1.0);
        } else {
            masses.insert(focal, mass);
            masses.insert(theta, 1.0 - mass);
        }

        Ok(Self { frame, masses })
    }

    /// Create a simple negative mass function: m(~A) = mass, m(Theta) = 1 - mass
    ///
    /// Evidence that truth is *outside* subset.
    ///
    /// # Errors
    /// Returns error if `mass` is not in [0, 1] or `subset` is invalid.
    pub fn simple_negative(
        frame: FrameOfDiscernment,
        subset: BTreeSet<usize>,
        mass: f64,
    ) -> Result<Self, DsError> {
        if mass < 0.0 {
            return Err(DsError::NegativeMass { value: mass });
        }
        if mass > 1.0 + SUM_TOLERANCE {
            return Err(DsError::InvalidMassSum { sum: mass });
        }
        if !frame.is_valid_subset(&subset) {
            return Err(DsError::ElementOutsideFrame {
                element: format!("{subset:?}"),
            });
        }

        let theta = FocalElement::theta(&frame);
        let neg = FocalElement::negative(subset);
        let mut masses = BTreeMap::new();

        if (mass - 1.0).abs() < SUM_TOLERANCE {
            masses.insert(neg, 1.0);
        } else if mass.abs() < SUM_TOLERANCE {
            masses.insert(theta, 1.0);
        } else {
            masses.insert(neg, mass);
            masses.insert(theta, 1.0 - mass);
        }

        Ok(Self { frame, masses })
    }

    /// Get the mass of a specific focal element (0.0 if not present)
    #[must_use]
    pub fn mass_of(&self, fe: &FocalElement) -> f64 {
        self.masses.get(fe).copied().unwrap_or(0.0)
    }

    /// Get the mass assigned to genuine conflict: m((empty, false))
    #[must_use]
    pub fn mass_of_conflict(&self) -> f64 {
        self.masses
            .get(&FocalElement::conflict())
            .copied()
            .unwrap_or(0.0)
    }

    /// Get the mass assigned to the empty set (alias for `mass_of_conflict`)
    ///
    /// Preserved for backward compatibility with existing code that uses
    /// `mass_of_empty()`. In CDST, this specifically means genuine conflict
    /// `(empty, false)`, not open-world ignorance `(empty, true)`.
    #[must_use]
    pub fn mass_of_empty(&self) -> f64 {
        self.mass_of_conflict()
    }

    /// Get the mass on missing propositions: m((Omega, true))
    #[must_use]
    pub fn mass_of_missing(&self) -> f64 {
        self.masses
            .get(&FocalElement::missing(&self.frame))
            .copied()
            .unwrap_or(0.0)
    }

    /// Fraction of total mass on complement (open-world) focal elements
    ///
    /// Sums mass on all focal elements with `complement = true`, which
    /// represent beliefs that truth lies outside the named frame hypotheses.
    /// Returns 0.0 for classical (closed-world) mass functions.
    #[must_use]
    pub fn open_world_fraction(&self) -> f64 {
        self.masses
            .iter()
            .filter(|(fe, _)| fe.complement)
            .map(|(_, &m)| m)
            .sum()
    }

    /// Check if all focal elements are positive (standard DS, no complements)
    #[must_use]
    pub fn is_classical(&self) -> bool {
        self.masses.keys().all(|fe| !fe.complement)
    }

    /// Iterate over focal elements (entries with mass > 0)
    pub fn focal_elements(&self) -> impl Iterator<Item = (&FocalElement, &f64)> {
        self.masses.iter().filter(|(_, &m)| m > 0.0)
    }

    /// Number of focal elements
    #[must_use]
    pub fn focal_count(&self) -> usize {
        self.masses.values().filter(|&&m| m > 0.0).count()
    }

    /// Check if this is a vacuous mass function (only Theta has mass)
    #[must_use]
    pub fn is_vacuous(&self) -> bool {
        let theta = FocalElement::theta(&self.frame);
        self.focal_count() == 1 && self.mass_of(&theta) > 1.0 - SUM_TOLERANCE
    }

    /// Check if this is dogmatic (Theta has zero mass — no room for updating)
    #[must_use]
    pub fn is_dogmatic(&self) -> bool {
        let theta = FocalElement::theta(&self.frame);
        self.mass_of(&theta) < SUM_TOLERANCE
    }

    /// Get a reference to the frame
    #[must_use]
    pub const fn frame(&self) -> &FrameOfDiscernment {
        &self.frame
    }

    /// Get a reference to the internal mass map
    #[must_use]
    pub const fn masses(&self) -> &BTreeMap<FocalElement, f64> {
        &self.masses
    }

    /// Serialize the masses map to JSON for database storage
    ///
    /// Uses comma-separated index strings as keys (e.g. `"0,1"` for positive `{0, 1}`).
    /// Complement elements use `~` prefix (e.g. `"~0,1"`).
    /// Empty set: `""` (conflict) or `"~"` (open-world vacuous).
    #[must_use]
    pub fn masses_to_json(&self) -> serde_json::Value {
        let string_map: BTreeMap<String, f64> = self
            .masses
            .iter()
            .map(|(k, v)| (mass_map_serde::focal_to_key_pub(k), *v))
            .collect();
        serde_json::to_value(string_map).unwrap_or(serde_json::Value::Null)
    }

    /// Reconstruct from a frame and JSON masses (from database)
    ///
    /// Parses the key format produced by `masses_to_json()`.
    /// Existing data without `~` prefixes is treated as positive elements
    /// — forward-compatible with pre-CDST JSONB data.
    ///
    /// # Errors
    /// Returns error if JSON structure is invalid.
    pub fn from_json_masses(
        frame: FrameOfDiscernment,
        masses_json: &serde_json::Value,
    ) -> Result<Self, String> {
        let string_map: BTreeMap<String, f64> =
            serde_json::from_value(masses_json.clone()).map_err(|e| e.to_string())?;

        let masses: BTreeMap<FocalElement, f64> = string_map
            .into_iter()
            .map(|(k, v)| {
                let fe = mass_map_serde::key_to_focal_pub(&k)
                    .unwrap_or_else(|_| FocalElement::positive(BTreeSet::new()));
                (fe, v)
            })
            .collect();

        Ok(Self::from_raw(frame, masses))
    }

    /// Reindex this mass function to a target frame
    ///
    /// Maps each focal element's indices from the current frame to the target frame.
    /// Both frames must share all hypotheses (current is subframe of target).
    ///
    /// # Errors
    /// Returns error if any hypothesis in current frame is missing from target.
    pub fn reindex_to_frame(&self, target: &FrameOfDiscernment) -> Result<Self, DsError> {
        let mapping = self.frame.index_mapping_to(target)?;

        let mut new_masses: BTreeMap<FocalElement, f64> = BTreeMap::new();
        for (fe, &mass) in &self.masses {
            let new_subset: BTreeSet<usize> = fe
                .subset
                .iter()
                .filter_map(|&idx| mapping.get(&idx).copied())
                .collect();
            let new_fe = FocalElement {
                subset: new_subset,
                complement: fe.complement,
            };
            *new_masses.entry(new_fe).or_insert(0.0) += mass;
        }

        Ok(Self {
            frame: target.clone(),
            masses: new_masses,
        })
    }

    /// Evaluate CDST mass function on its own frame to produce classical BPA
    ///
    /// Converts complement elements to their classical equivalents:
    /// - `(u, false)` -> mass on `u` (unchanged)
    /// - `(u, true)` -> mass on `Omega \ u`
    ///
    /// The result is a classical (positive-only) mass function.
    #[must_use]
    pub fn evaluate_to_classical(&self) -> Self {
        if self.is_classical() {
            return self.clone();
        }

        let full = self.frame.full_set();
        let mut classical: BTreeMap<FocalElement, f64> = BTreeMap::new();

        for (fe, &mass) in &self.masses {
            if mass == 0.0 {
                continue;
            }
            if fe.complement {
                // Complement element (u, true) -> Omega \ u
                let complement_set: BTreeSet<usize> =
                    full.difference(&fe.subset).copied().collect();
                let classical_fe = FocalElement::positive(complement_set);
                *classical.entry(classical_fe).or_insert(0.0) += mass;
            } else {
                // Positive element — keep as-is
                *classical.entry(fe.clone()).or_insert(0.0) += mass;
            }
        }

        classical.retain(|_, v| *v > 0.0);

        Self {
            frame: self.frame.clone(),
            masses: classical,
        }
    }

    /// Create a mass function from raw parts without validation
    ///
    /// Caller MUST ensure masses sum to 1.0 and elements are valid.
    /// Use this only for trusted data (e.g. from database or combination results).
    #[must_use]
    pub const fn from_raw(frame: FrameOfDiscernment, masses: BTreeMap<FocalElement, f64>) -> Self {
        Self { frame, masses }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("test", vec!["true".into(), "false".into()]).unwrap()
    }

    fn ternary_frame() -> FrameOfDiscernment {
        FrameOfDiscernment::new("tri", vec!["a".into(), "b".into(), "c".into()]).unwrap()
    }

    // ======== FocalElement constructors ========

    #[test]
    fn focal_element_positive() {
        let fe = FocalElement::positive(BTreeSet::from([0, 1]));
        assert!(!fe.complement);
        assert_eq!(fe.subset, BTreeSet::from([0, 1]));
        assert!(fe.is_positive());
    }

    #[test]
    fn focal_element_negative() {
        let fe = FocalElement::negative(BTreeSet::from([0]));
        assert!(fe.complement);
        assert!(!fe.is_positive());
    }

    #[test]
    fn focal_element_conflict() {
        let fe = FocalElement::conflict();
        assert!(fe.is_conflict());
        assert!(!fe.complement);
        assert!(fe.subset.is_empty());
    }

    #[test]
    fn focal_element_missing() {
        let frame = binary_frame();
        let fe = FocalElement::missing(&frame);
        assert!(fe.is_missing(&frame));
        assert!(fe.complement);
        assert_eq!(fe.subset, frame.full_set());
    }

    #[test]
    fn focal_element_vacuous_element() {
        let fe = FocalElement::vacuous();
        assert!(fe.is_vacuous_element());
        assert!(fe.complement);
        assert!(fe.subset.is_empty());
    }

    #[test]
    fn focal_element_theta() {
        let frame = binary_frame();
        let fe = FocalElement::theta(&frame);
        assert!(fe.is_theta(&frame));
        assert!(!fe.complement);
        assert_eq!(fe.subset, frame.full_set());
    }

    #[test]
    fn focal_element_ordering() {
        // Verify BTreeMap key stability: positive before negative for same subset
        let pos = FocalElement::positive(BTreeSet::from([0]));
        let neg = FocalElement::negative(BTreeSet::from([0]));
        assert!(
            pos < neg,
            "Positive (complement=false) should sort before negative (complement=true)"
        );

        // Different subsets: smaller subset first
        let small = FocalElement::positive(BTreeSet::from([0]));
        let large = FocalElement::positive(BTreeSet::from([0, 1]));
        assert!(small < large);
    }

    // ======== MassFunction constructors ========

    #[test]
    fn vacuous_mass_function() {
        let m = MassFunction::vacuous(binary_frame());
        assert!(m.is_vacuous());
        assert!(!m.is_dogmatic());
        assert!(m.is_classical());
        let theta = FocalElement::theta(m.frame());
        assert_eq!(m.mass_of(&theta), 1.0);
        assert_eq!(m.mass_of(&FocalElement::positive(BTreeSet::from([0]))), 0.0);
        assert_eq!(m.focal_count(), 1);
    }

    #[test]
    fn categorical_mass_function() {
        let m = MassFunction::categorical(binary_frame(), 0).unwrap();
        assert_eq!(m.mass_of(&FocalElement::positive(BTreeSet::from([0]))), 1.0);
        assert_eq!(m.mass_of(&FocalElement::positive(BTreeSet::from([1]))), 0.0);
        assert!(m.is_dogmatic());
        assert!(!m.is_vacuous());
    }

    #[test]
    fn categorical_invalid_index() {
        let result = MassFunction::categorical(binary_frame(), 5);
        assert!(result.is_err());
    }

    #[test]
    fn simple_mass_function() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        let theta = FocalElement::theta(m.frame());
        assert!((m.mass_of(&fe0) - 0.7).abs() < 1e-10);
        assert!((m.mass_of(&theta) - 0.3).abs() < 1e-10);
        assert_eq!(m.focal_count(), 2);
        assert!(m.is_classical());
    }

    #[test]
    fn simple_mass_vacuous_case() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.0).unwrap();
        assert!(m.is_vacuous());
    }

    #[test]
    fn simple_mass_certain_case() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 1.0).unwrap();
        assert!(m.is_dogmatic());
        assert_eq!(m.mass_of(&FocalElement::positive(BTreeSet::from([0]))), 1.0);
    }

    #[test]
    fn simple_negative_constructor() {
        let frame = binary_frame();
        let m = MassFunction::simple_negative(frame, BTreeSet::from([1]), 0.6).unwrap();
        let neg = FocalElement::negative(BTreeSet::from([1]));
        let theta = FocalElement::theta(m.frame());
        assert!((m.mass_of(&neg) - 0.6).abs() < 1e-10);
        assert!((m.mass_of(&theta) - 0.4).abs() < 1e-10);
        assert!(!m.is_classical());
    }

    #[test]
    fn reject_negative_mass() {
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::from([0])), -0.1);
        masses.insert(FocalElement::theta(&frame), 1.1);
        let result = MassFunction::new(frame, masses);
        assert!(matches!(result, Err(DsError::NegativeMass { .. })));
    }

    #[test]
    fn reject_invalid_sum() {
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.5);
        masses.insert(FocalElement::positive(BTreeSet::from([1])), 0.3);
        let result = MassFunction::new(frame, masses);
        assert!(matches!(result, Err(DsError::InvalidMassSum { .. })));
    }

    #[test]
    fn reject_element_outside_frame() {
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::positive(BTreeSet::from([5])), 1.0);
        let result = MassFunction::new(frame, masses);
        assert!(matches!(result, Err(DsError::ElementOutsideFrame { .. })));
    }

    #[test]
    fn mass_of_conflict_and_missing() {
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::conflict(), 0.2);
        masses.insert(FocalElement::missing(&frame), 0.1);
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.4);
        masses.insert(FocalElement::theta(&frame), 0.3);
        let m = MassFunction::new(frame, masses).unwrap();
        assert!((m.mass_of_conflict() - 0.2).abs() < 1e-10);
        assert!((m.mass_of_empty() - 0.2).abs() < 1e-10); // backward compat
        assert!((m.mass_of_missing() - 0.1).abs() < 1e-10);
        assert!(!m.is_classical()); // has complement element (missing)
    }

    #[test]
    fn focal_elements_iteration() {
        let frame = ternary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.6).unwrap();
        let focal: Vec<_> = m.focal_elements().collect();
        assert_eq!(focal.len(), 2);
    }

    // ======== Tolerance boundary test ========

    #[test]
    fn mass_function_at_epsilon_boundary() {
        let frame = binary_frame();
        let eps = 1e-9;

        // Sum = 1.0 + eps/2 -> accepted (within SUM_TOLERANCE)
        let mut masses_ok = BTreeMap::new();
        masses_ok.insert(FocalElement::positive(BTreeSet::from([0])), 0.7 + eps / 2.0);
        masses_ok.insert(FocalElement::theta(&frame), 0.3);
        let result = MassFunction::new(frame.clone(), masses_ok);
        assert!(result.is_ok(), "Sum within EPSILON should be accepted");

        // Sum = 1.0 + 2*EPSILON -> rejected
        let mut masses_bad = BTreeMap::new();
        masses_bad.insert(FocalElement::positive(BTreeSet::from([0])), 0.7 + 2.0 * eps);
        masses_bad.insert(FocalElement::theta(&frame), 0.3 + 2.0 * eps);
        let result = MassFunction::new(frame, masses_bad);
        assert!(
            result.is_err(),
            "Sum outside EPSILON tolerance should be rejected"
        );
    }

    // ======== Serialization ========

    #[test]
    fn serialization_roundtrip() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: MassFunction = serde_json::from_str(&json).unwrap();
        assert!((parsed.mass_of(&FocalElement::positive(BTreeSet::from([0]))) - 0.7).abs() < 1e-10);
    }

    #[test]
    fn negative_serde_roundtrip() {
        let frame = binary_frame();
        let m = MassFunction::simple_negative(frame, BTreeSet::from([1]), 0.6).unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: MassFunction = serde_json::from_str(&json).unwrap();
        let neg = FocalElement::negative(BTreeSet::from([1]));
        assert!((parsed.mass_of(&neg) - 0.6).abs() < 1e-10);
    }

    #[test]
    fn json_masses_roundtrip() {
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::conflict(), 0.1);
        masses.insert(FocalElement::negative(BTreeSet::from([1])), 0.3);
        masses.insert(FocalElement::positive(BTreeSet::from([0])), 0.4);
        masses.insert(FocalElement::theta(&frame), 0.2);
        let m = MassFunction::new(frame.clone(), masses).unwrap();

        let json = m.masses_to_json();
        let restored = MassFunction::from_json_masses(frame, &json).unwrap();

        assert!((restored.mass_of_conflict() - 0.1).abs() < 1e-10);
        assert!(
            (restored.mass_of(&FocalElement::negative(BTreeSet::from([1]))) - 0.3).abs() < 1e-10
        );
        assert!(
            (restored.mass_of(&FocalElement::positive(BTreeSet::from([0]))) - 0.4).abs() < 1e-10
        );
    }

    #[test]
    fn legacy_json_forward_compatible() {
        // Pre-CDST JSON (no ~ prefixes) should parse as all-positive
        let frame = binary_frame();
        let json = serde_json::json!({"0": 0.7, "0,1": 0.3});
        let m = MassFunction::from_json_masses(frame, &json).unwrap();
        assert!((m.mass_of(&FocalElement::positive(BTreeSet::from([0]))) - 0.7).abs() < 1e-10);
        assert!(m.is_classical());
    }

    #[test]
    fn is_classical_positive_only() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        assert!(m.is_classical());
    }

    #[test]
    fn is_not_classical_with_negative() {
        let frame = binary_frame();
        let m = MassFunction::simple_negative(frame, BTreeSet::from([1]), 0.5).unwrap();
        assert!(!m.is_classical());
    }

    // ======== evaluate_to_classical ========

    #[test]
    fn evaluate_classical_positive_only_is_identity() {
        let frame = binary_frame();
        let m = MassFunction::simple(frame, BTreeSet::from([0]), 0.7).unwrap();
        let classical = m.evaluate_to_classical();
        assert!(classical.is_classical());
        assert!(
            (classical.mass_of(&FocalElement::positive(BTreeSet::from([0]))) - 0.7).abs() < 1e-10
        );
    }

    #[test]
    fn evaluate_classical_converts_complement() {
        // m(~{1}, true) = 0.6, m(Theta, false) = 0.4
        // ~{1} on binary frame {0,1} -> Omega\{1} = {0}
        let frame = binary_frame();
        let m = MassFunction::simple_negative(frame, BTreeSet::from([1]), 0.6).unwrap();
        let classical = m.evaluate_to_classical();

        assert!(classical.is_classical());
        // ~{1} became {0}
        let fe0 = FocalElement::positive(BTreeSet::from([0]));
        assert!((classical.mass_of(&fe0) - 0.6).abs() < 1e-10);
    }

    #[test]
    fn evaluate_classical_missing_becomes_empty() {
        // m((Omega, true)) -> Omega \ Omega = empty set
        let frame = binary_frame();
        let mut masses = BTreeMap::new();
        masses.insert(FocalElement::missing(&frame), 0.3);
        masses.insert(FocalElement::theta(&frame), 0.7);
        let m = MassFunction::from_raw(frame, masses);
        let classical = m.evaluate_to_classical();

        // (Omega, true) -> (empty, false) = conflict
        assert!((classical.mass_of_conflict() - 0.3).abs() < 1e-10);
    }

    // ======== reindex_to_frame ========

    #[test]
    fn reindex_to_superset_frame() {
        let f1 = FrameOfDiscernment::new("f1", vec!["a".into(), "b".into()]).unwrap();
        let f2 = FrameOfDiscernment::new("f2", vec!["x".into(), "a".into(), "b".into()]).unwrap();

        let m = MassFunction::simple(f1, BTreeSet::from([0]), 0.7).unwrap();
        let reindexed = m.reindex_to_frame(&f2).unwrap();

        // {0} in f1 ("a") -> {1} in f2 ("a" is at index 1)
        let fe1 = FocalElement::positive(BTreeSet::from([1]));
        assert!((reindexed.mass_of(&fe1) - 0.7).abs() < 1e-10);

        // Theta {0,1} in f1 -> {1,2} in f2
        let theta_f1_reindexed = FocalElement::positive(BTreeSet::from([1, 2]));
        assert!((reindexed.mass_of(&theta_f1_reindexed) - 0.3).abs() < 1e-10);
    }
}
