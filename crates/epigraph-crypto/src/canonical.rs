//! Canonical serialization for deterministic hashing
//!
//! JSON key ordering is not guaranteed by the spec. This module ensures
//! deterministic serialization by sorting keys recursively.
//!
//! # Why This Matters
//!
//! Without canonical serialization:
//! - `{"a":1,"b":2}` and `{"b":2,"a":1}` produce different hashes
//! - Signatures become non-reproducible across systems
//! - Content addressing breaks

use crate::errors::CryptoError;
use serde::Serialize;
use serde_json::{Map, Value};

/// Trait for types that can be canonically serialized
///
/// Implementors should ensure that `canonical_bytes()` produces
/// identical output for semantically identical data.
pub trait Canonical {
    /// Returns the canonical byte representation for signing/hashing
    ///
    /// # Errors
    /// Returns `CryptoError::SerializationError` if serialization fails.
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError>;
}

/// Blanket implementation for all Serialize types
impl<T: Serialize> Canonical for T {
    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        to_canonical_bytes(self)
    }
}

/// Recursively sort JSON object keys for deterministic serialization
#[must_use]
pub fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Map<String, Value> = Map::new();
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    sorted.insert(key, canonicalize_value(v.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

/// Serialize a value to canonical JSON string
///
/// Keys are sorted recursively, no pretty printing, no trailing whitespace.
///
/// # Errors
/// Returns `CryptoError::SerializationError` if serialization fails.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, CryptoError> {
    let json_value = serde_json::to_value(value)?;
    let canonical = canonicalize_value(json_value);
    Ok(serde_json::to_string(&canonical)?)
}

/// Serialize a value to canonical bytes (UTF-8 encoded JSON)
///
/// # Errors
/// Returns `CryptoError::SerializationError` if serialization fails.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    Ok(to_canonical_json(value)?.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys() {
        let obj1 = json!({"z": 1, "a": 2, "m": 3});
        let obj2 = json!({"a": 2, "m": 3, "z": 1});

        let canonical1 = to_canonical_json(&obj1).unwrap();
        let canonical2 = to_canonical_json(&obj2).unwrap();

        assert_eq!(canonical1, canonical2);
        assert_eq!(canonical1, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_sorts_nested_keys() {
        let obj = json!({
            "outer": {
                "z": 1,
                "a": 2
            },
            "first": true
        });

        let canonical = to_canonical_json(&obj).unwrap();
        assert_eq!(canonical, r#"{"first":true,"outer":{"a":2,"z":1}}"#);
    }

    #[test]
    fn canonical_preserves_arrays() {
        let obj = json!({"items": [3, 1, 2]});
        let canonical = to_canonical_json(&obj).unwrap();
        // Arrays maintain order (they're ordered by definition)
        assert_eq!(canonical, r#"{"items":[3,1,2]}"#);
    }

    #[test]
    fn canonical_handles_special_values() {
        let obj = json!({
            "null_val": null,
            "bool_val": true,
            "num_val": 42.5,
            "str_val": "hello"
        });

        let canonical = to_canonical_json(&obj).unwrap();
        assert!(canonical.contains("null"));
        assert!(canonical.contains("true"));
        assert!(canonical.contains("42.5"));
        assert!(canonical.contains("hello"));
    }
}
