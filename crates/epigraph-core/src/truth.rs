//! Truth value type with bounded semantics
//!
//! Truth values in `EpiGraph` are probabilistic, not binary.
//! This module provides a type-safe bounded float for truth values.

use crate::errors::CoreError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A truth value bounded to [0.0, 1.0]
///
/// # `EpiGraph` Semantics
///
/// - 0.0: Definitely false
/// - 0.5: Maximum uncertainty (no evidence either way)
/// - 1.0: Definitely true
///
/// Truth values should rarely reach 0.0 or 1.0 - these represent absolute certainty.
/// Most claims will have truth values in the range [0.1, 0.9].
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct TruthValue(f64);

impl TruthValue {
    /// Minimum valid truth value
    pub const MIN: f64 = 0.0;

    /// Maximum valid truth value
    pub const MAX: f64 = 1.0;

    /// Default truth value representing maximum uncertainty
    pub const UNCERTAIN: f64 = 0.5;

    /// Threshold above which a claim is considered "verified true"
    pub const VERIFIED_TRUE_THRESHOLD: f64 = 0.8;

    /// Threshold below which a claim is considered "verified false"
    pub const VERIFIED_FALSE_THRESHOLD: f64 = 0.2;

    /// Create a new truth value with bounds checking
    ///
    /// # Errors
    /// Returns `CoreError::InvalidTruthValue` if value is outside [0.0, 1.0] or NaN.
    pub fn new(value: f64) -> Result<Self, CoreError> {
        if value.is_nan() || !(Self::MIN..=Self::MAX).contains(&value) {
            return Err(CoreError::InvalidTruthValue { value });
        }
        Ok(Self(value))
    }

    /// Create a truth value, clamping to valid bounds
    ///
    /// NaN values become 0.5 (uncertain).
    #[must_use]
    pub const fn clamped(value: f64) -> Self {
        if value.is_nan() {
            Self(Self::UNCERTAIN)
        } else {
            Self(value.clamp(Self::MIN, Self::MAX))
        }
    }

    /// Create a truth value representing maximum uncertainty
    #[must_use]
    pub const fn uncertain() -> Self {
        Self(Self::UNCERTAIN)
    }

    /// Get the raw f64 value
    #[must_use]
    pub const fn value(&self) -> f64 {
        self.0
    }

    /// Check if this truth value indicates "verified true"
    #[must_use]
    pub fn is_verified_true(&self) -> bool {
        self.0 >= Self::VERIFIED_TRUE_THRESHOLD
    }

    /// Check if this truth value indicates "verified false"
    #[must_use]
    pub fn is_verified_false(&self) -> bool {
        self.0 <= Self::VERIFIED_FALSE_THRESHOLD
    }

    /// Check if this truth value is in the uncertain range
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        self.0 > Self::VERIFIED_FALSE_THRESHOLD && self.0 < Self::VERIFIED_TRUE_THRESHOLD
    }

    /// Calculate the complement (1 - value)
    #[must_use]
    pub fn complement(&self) -> Self {
        Self(1.0 - self.0)
    }
}

impl Default for TruthValue {
    fn default() -> Self {
        Self::uncertain()
    }
}

impl fmt::Display for TruthValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.0)
    }
}

impl TryFrom<f64> for TruthValue {
    type Error = CoreError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TruthValue> for f64 {
    fn from(tv: TruthValue) -> Self {
        tv.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_truth_values() {
        assert!(TruthValue::new(0.0).is_ok());
        assert!(TruthValue::new(0.5).is_ok());
        assert!(TruthValue::new(1.0).is_ok());
        assert!(TruthValue::new(0.73).is_ok());
    }

    #[test]
    fn invalid_truth_values() {
        assert!(TruthValue::new(-0.1).is_err());
        assert!(TruthValue::new(1.1).is_err());
        assert!(TruthValue::new(f64::NAN).is_err());
        assert!(TruthValue::new(f64::INFINITY).is_err());
    }

    #[test]
    fn clamped_handles_out_of_bounds() {
        assert_eq!(TruthValue::clamped(-5.0).value(), 0.0);
        assert_eq!(TruthValue::clamped(10.0).value(), 1.0);
        assert_eq!(TruthValue::clamped(f64::NAN).value(), 0.5);
    }

    #[test]
    fn verification_thresholds() {
        assert!(TruthValue::new(0.9).unwrap().is_verified_true());
        assert!(!TruthValue::new(0.7).unwrap().is_verified_true());

        assert!(TruthValue::new(0.1).unwrap().is_verified_false());
        assert!(!TruthValue::new(0.3).unwrap().is_verified_false());

        assert!(TruthValue::new(0.5).unwrap().is_uncertain());
    }

    #[test]
    fn complement() {
        let tv = TruthValue::new(0.3).unwrap();
        assert!((tv.complement().value() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn serialization() {
        let tv = TruthValue::new(0.75).unwrap();
        let json = serde_json::to_string(&tv).unwrap();
        assert_eq!(json, "0.75");

        let parsed: TruthValue = serde_json::from_str("0.75").unwrap();
        assert_eq!(parsed, tv);
    }

    #[test]
    fn deserialization_rejects_invalid() {
        let result: Result<TruthValue, _> = serde_json::from_str("1.5");
        assert!(result.is_err());
    }
}
