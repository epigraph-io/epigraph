//! Property-based tests for epigraph-core invariants
//!
//! These tests use proptest to verify that critical epistemic invariants
//! hold across the entire input domain, not just hand-picked examples.
//!
//! # Invariants Verified
//!
//! 1. `TruthValue::new()` either succeeds with value in [0.0, 1.0] or returns Err
//! 2. `TruthValue::clamped()` always produces a valid value in [0.0, 1.0]
//! 3. Content hashing is deterministic: same content -> same hash

use epigraph_core::TruthValue;
use proptest::prelude::*;

// =============================================================================
// TRUTH VALUE INVARIANTS
// =============================================================================

proptest! {
    /// For ANY f64 input, `TruthValue::new()` either:
    /// - Succeeds with a value in [0.0, 1.0], or
    /// - Returns an error
    ///
    /// It must NEVER produce a `TruthValue` outside bounds.
    #[test]
    fn truth_value_new_always_bounded_or_error(value in any::<f64>()) {
        match TruthValue::new(value) {
            Ok(tv) => {
                let v = tv.value();
                prop_assert!(
                    (0.0..=1.0).contains(&v),
                    "TruthValue::new({}) produced out-of-bounds value: {}",
                    value, v
                );
                // Also verify that NaN did not sneak through
                prop_assert!(
                    !v.is_nan(),
                    "TruthValue::new({}) produced NaN",
                    value
                );
            }
            Err(_) => {
                // Error is expected for out-of-bounds, NaN, infinity, etc.
                // Verify that valid inputs are NOT rejected
                if (0.0..=1.0).contains(&value) && !value.is_nan() {
                    prop_assert!(
                        false,
                        "TruthValue::new({}) returned Err for a valid input",
                        value
                    );
                }
            }
        }
    }

    /// `TruthValue::new()` must reject NaN
    #[test]
    fn truth_value_rejects_nan(_dummy in 0..1u8) {
        let result = TruthValue::new(f64::NAN);
        prop_assert!(result.is_err(), "TruthValue::new(NaN) must return Err");
    }

    /// `TruthValue::new()` must reject positive infinity
    #[test]
    fn truth_value_rejects_positive_infinity(_dummy in 0..1u8) {
        let result = TruthValue::new(f64::INFINITY);
        prop_assert!(result.is_err(), "TruthValue::new(INFINITY) must return Err");
    }

    /// `TruthValue::new()` must reject negative infinity
    #[test]
    fn truth_value_rejects_negative_infinity(_dummy in 0..1u8) {
        let result = TruthValue::new(f64::NEG_INFINITY);
        prop_assert!(result.is_err(), "TruthValue::new(NEG_INFINITY) must return Err");
    }

    /// `TruthValue::new()` must reject values below 0.0
    #[test]
    fn truth_value_rejects_negative(value in f64::MIN..0.0_f64) {
        // Filter out -0.0 which is == 0.0
        prop_assume!(value < 0.0);
        let result = TruthValue::new(value);
        prop_assert!(
            result.is_err(),
            "TruthValue::new({}) should return Err for negative value",
            value
        );
    }

    /// `TruthValue::new()` must reject values above 1.0
    #[test]
    fn truth_value_rejects_above_one(value in 1.0_f64..f64::MAX) {
        prop_assume!(value > 1.0);
        let result = TruthValue::new(value);
        prop_assert!(
            result.is_err(),
            "TruthValue::new({}) should return Err for value above 1.0",
            value
        );
    }

    /// `TruthValue::new()` must accept all values in [0.0, 1.0]
    #[test]
    fn truth_value_accepts_valid_range(value in 0.0..=1.0_f64) {
        let result = TruthValue::new(value);
        prop_assert!(
            result.is_ok(),
            "TruthValue::new({}) should succeed for value in [0.0, 1.0]",
            value
        );
        let tv = result.unwrap();
        prop_assert!(
            (tv.value() - value).abs() < f64::EPSILON,
            "TruthValue::new({}) should preserve exact value, got {}",
            value, tv.value()
        );
    }

    /// `TruthValue::clamped()` ALWAYS produces a value in [0.0, 1.0], for any f64 input.
    /// This is the safety net when we need to guarantee bounds without error handling.
    #[test]
    fn truth_value_clamped_always_bounded(value in any::<f64>()) {
        let tv = TruthValue::clamped(value);
        let v = tv.value();
        prop_assert!(
            (0.0..=1.0).contains(&v),
            "TruthValue::clamped({}) produced out-of-bounds value: {}",
            value, v
        );
        prop_assert!(
            !v.is_nan(),
            "TruthValue::clamped({}) produced NaN",
            value
        );
    }

    /// `TruthValue::clamped()` maps NaN to 0.5 (maximum uncertainty)
    #[test]
    fn truth_value_clamped_nan_becomes_uncertain(_dummy in 0..1u8) {
        let tv = TruthValue::clamped(f64::NAN);
        prop_assert!(
            (tv.value() - 0.5).abs() < f64::EPSILON,
            "TruthValue::clamped(NaN) should produce 0.5, got {}",
            tv.value()
        );
    }

    /// `complement()` always produces a valid `TruthValue` and is self-inverse
    #[test]
    fn truth_value_complement_is_valid_and_involutory(value in 0.0..=1.0_f64) {
        let tv = TruthValue::new(value).unwrap();
        let comp = tv.complement();
        let v = comp.value();
        prop_assert!(
            (0.0..=1.0).contains(&v),
            "complement of {} produced out-of-bounds value: {}",
            value, v
        );
        // complement is involutory: complement(complement(x)) == x
        let double_comp = comp.complement();
        prop_assert!(
            (double_comp.value() - value).abs() < 1e-10,
            "Double complement of {} should return {}, got {}",
            value, value, double_comp.value()
        );
    }
}

// =============================================================================
// CONTENT HASH DETERMINISM
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Content hashing is deterministic: same Claim content produces the same hash.
    /// This is critical for content-addressable storage integrity.
    #[test]
    fn claim_content_hash_deterministic(
        content in "[a-zA-Z0-9 ]{1,100}",
        truth_val in 0.0..=1.0_f64,
    ) {
        use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
        use epigraph_core::ContentAddressable;
        use chrono::Utc;

        let id = ClaimId::new();
        let agent_id = AgentId::new();
        let trace_id = TraceId::new();
        let truth = TruthValue::new(truth_val).unwrap();
        let now = Utc::now();
        let public_key = [0u8; 32];
        let content_hash = [0u8; 32];

        let claim1 = Claim::with_id(
            id,
            content.clone(),
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            truth,
            now,
            now,
        );

        let claim2 = Claim::with_id(
            id,
            content,
            agent_id,
            public_key,
            content_hash,
            Some(trace_id),
            None,
            truth,
            now,
            now,
        );

        let hash1 = claim1.compute_hash().expect("hash computation should succeed");
        let hash2 = claim2.compute_hash().expect("hash computation should succeed");

        prop_assert_eq!(
            hash1, hash2,
            "Same claim content must produce the same content hash"
        );
    }
}
