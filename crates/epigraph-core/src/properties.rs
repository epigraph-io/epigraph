//! Property storage for nodes and edges
//!
//! Properties enable flexible, schema-less attribute storage on graph elements.

use crate::errors::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A typed property value that can be stored on nodes or edges
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PropertyValue {
    /// Null/missing value
    Null,
    /// Boolean value
    Bool(bool),
    /// Integer value (i64 for wide range)
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// String value
    String(String),
    /// Array of property values
    Array(Vec<Self>),
    /// Nested object (for complex properties)
    Object(HashMap<String, Self>),
}

impl PropertyValue {
    /// Check if this value is null
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Try to get this value as a boolean
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to get this value as an integer
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Try to get this value as a float
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            #[allow(clippy::cast_precision_loss)]
            Self::Integer(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Try to get this value as a string reference
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the type name of this value (for error messages)
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Integer(_) => "integer",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}

impl From<bool> for PropertyValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<i64> for PropertyValue {
    fn from(v: i64) -> Self {
        Self::Integer(v)
    }
}

impl From<i32> for PropertyValue {
    fn from(v: i32) -> Self {
        Self::Integer(i64::from(v))
    }
}

impl From<f64> for PropertyValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<String> for PropertyValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for PropertyValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}

impl<T: Into<Self>> From<Vec<T>> for PropertyValue {
    fn from(v: Vec<T>) -> Self {
        Self::Array(v.into_iter().map(Into::into).collect())
    }
}

impl From<serde_json::Value> for PropertyValue {
    fn from(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(n) => {
                #[allow(clippy::option_if_let_else)]
                if let Some(i) = n.as_i64() {
                    Self::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    Self::Float(f)
                } else {
                    // Numbers that cannot be represented as i64 or f64
                    // (e.g., extremely large numbers) become Null to prevent
                    // silent data corruption. Callers should handle this explicitly.
                    Self::Null
                }
            }
            serde_json::Value::String(s) => Self::String(s),
            serde_json::Value::Array(arr) => Self::Array(arr.into_iter().map(Into::into).collect()),
            serde_json::Value::Object(obj) => {
                Self::Object(obj.into_iter().map(|(k, v)| (k, v.into())).collect())
            }
        }
    }
}

/// A map of property key-value pairs
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PropertyMap(HashMap<String, PropertyValue>);

impl PropertyMap {
    /// Create an empty property map
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Create a property map with initial capacity
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Insert a property value
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<PropertyValue>) {
        self.0.insert(key.into(), value.into());
    }

    /// Get a property value by key
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&PropertyValue> {
        self.0.get(key)
    }

    /// Remove a property value by key
    pub fn remove(&mut self, key: &str) -> Option<PropertyValue> {
        self.0.remove(key)
    }

    /// Check if a property exists
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Get the number of properties
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the map is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over properties
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PropertyValue)> {
        self.0.iter()
    }

    /// Get a required string property or error
    ///
    /// # Errors
    /// Returns error if property is missing or not a string.
    pub fn require_string(&self, key: &str, entity_type: &str) -> Result<&str, CoreError> {
        match self.get(key) {
            Some(PropertyValue::String(s)) => Ok(s),
            Some(other) => Err(CoreError::PropertyTypeMismatch {
                key: key.to_string(),
                expected: "string".to_string(),
                actual: other.type_name().to_string(),
            }),
            None => Err(CoreError::MissingProperty {
                key: key.to_string(),
                entity_type: entity_type.to_string(),
            }),
        }
    }

    /// Get a required float property or error
    ///
    /// # Errors
    /// Returns error if property is missing or not numeric.
    pub fn require_float(&self, key: &str, entity_type: &str) -> Result<f64, CoreError> {
        let v = self.get(key).ok_or_else(|| CoreError::MissingProperty {
            key: key.to_string(),
            entity_type: entity_type.to_string(),
        })?;
        v.as_float().ok_or_else(|| CoreError::PropertyTypeMismatch {
            key: key.to_string(),
            expected: "float".to_string(),
            actual: v.type_name().to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::approx_constant)]
mod tests {
    use super::*;

    // ==================== PropertyValue Tests ====================

    #[test]
    fn property_value_type_conversions() {
        let bool_val: PropertyValue = true.into();
        assert_eq!(bool_val.as_bool(), Some(true));

        let int_val: PropertyValue = 42i64.into();
        assert_eq!(int_val.as_integer(), Some(42));

        let float_val: PropertyValue = 3.14.into();
        assert!((float_val.as_float().unwrap() - 3.14).abs() < f64::EPSILON);

        let str_val: PropertyValue = "hello".into();
        assert_eq!(str_val.as_str(), Some("hello"));
    }

    #[test]
    fn property_value_null_and_is_null() {
        let null_val = PropertyValue::Null;
        assert!(null_val.is_null());
        assert!(null_val.as_bool().is_none());
        assert!(null_val.as_integer().is_none());
        assert!(null_val.as_float().is_none());
        assert!(null_val.as_str().is_none());
    }

    #[test]
    fn property_value_type_names() {
        assert_eq!(PropertyValue::Null.type_name(), "null");
        assert_eq!(PropertyValue::Bool(true).type_name(), "bool");
        assert_eq!(PropertyValue::Integer(1).type_name(), "integer");
        assert_eq!(PropertyValue::Float(1.0).type_name(), "float");
        assert_eq!(PropertyValue::String("x".to_string()).type_name(), "string");
        assert_eq!(PropertyValue::Array(vec![]).type_name(), "array");
        assert_eq!(PropertyValue::Object(HashMap::new()).type_name(), "object");
    }

    #[test]
    fn property_value_integer_as_float() {
        // Integer should be convertible to float
        let int_val = PropertyValue::Integer(42);
        assert_eq!(int_val.as_float(), Some(42.0));
    }

    #[test]
    fn property_value_from_i32() {
        let val: PropertyValue = 42i32.into();
        assert_eq!(val.as_integer(), Some(42));
    }

    #[test]
    fn property_value_from_vec() {
        let val: PropertyValue = vec![1i64, 2i64, 3i64].into();
        if let PropertyValue::Array(arr) = val {
            assert_eq!(arr.len(), 3);
        } else {
            panic!("Expected Array");
        }
    }

    #[test]
    fn property_value_from_json_object() {
        let json = serde_json::json!({
            "name": "test",
            "count": 42,
            "active": true,
            "data": null,
            "items": [1, 2, 3]
        });

        let prop: PropertyValue = json.into();
        if let PropertyValue::Object(map) = prop {
            assert!(matches!(map.get("name"), Some(PropertyValue::String(_))));
            assert!(matches!(map.get("count"), Some(PropertyValue::Integer(42))));
            assert!(matches!(map.get("active"), Some(PropertyValue::Bool(true))));
            assert!(matches!(map.get("data"), Some(PropertyValue::Null)));
            assert!(matches!(map.get("items"), Some(PropertyValue::Array(_))));
        } else {
            panic!("Expected Object");
        }
    }

    #[test]
    fn property_value_from_json_number_float() {
        let json = serde_json::json!(3.14159);
        let prop: PropertyValue = json.into();
        if let PropertyValue::Float(f) = prop {
            assert!((f - 3.14159).abs() < f64::EPSILON);
        } else {
            panic!("Expected Float");
        }
    }

    // ==================== PropertyMap Tests ====================

    #[test]
    fn property_map_operations() {
        let mut props = PropertyMap::new();
        props.insert("name", "test");
        props.insert("count", 42i64);

        assert_eq!(props.get("name").and_then(|v| v.as_str()), Some("test"));
        assert_eq!(
            props
                .get("count")
                .and_then(super::PropertyValue::as_integer),
            Some(42)
        );
        assert!(props.get("missing").is_none());
    }

    #[test]
    fn property_map_with_capacity() {
        let props = PropertyMap::with_capacity(10);
        assert!(props.is_empty());
        assert_eq!(props.len(), 0);
    }

    #[test]
    fn property_map_remove() {
        let mut props = PropertyMap::new();
        props.insert("key", "value");

        assert!(props.contains("key"));
        let removed = props.remove("key");
        assert!(removed.is_some());
        assert!(!props.contains("key"));
    }

    #[test]
    fn property_map_contains() {
        let mut props = PropertyMap::new();
        props.insert("exists", true);

        assert!(props.contains("exists"));
        assert!(!props.contains("not_exists"));
    }

    #[test]
    fn property_map_len_and_is_empty() {
        let mut props = PropertyMap::new();
        assert!(props.is_empty());
        assert_eq!(props.len(), 0);

        props.insert("a", 1i64);
        assert!(!props.is_empty());
        assert_eq!(props.len(), 1);

        props.insert("b", 2i64);
        assert_eq!(props.len(), 2);
    }

    #[test]
    fn property_map_iter() {
        let mut props = PropertyMap::new();
        props.insert("one", 1i64);
        props.insert("two", 2i64);

        let keys: Vec<&String> = props.iter().map(|(k, _)| k).collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&&"one".to_string()));
        assert!(keys.contains(&&"two".to_string()));
    }

    // ==================== require_string Tests ====================

    #[test]
    fn property_map_require_string_success() {
        let mut props = PropertyMap::new();
        props.insert("name", "Alice");

        let result = props.require_string("name", "User");
        assert_eq!(result.unwrap(), "Alice");
    }

    #[test]
    fn property_map_require_string_missing() {
        let props = PropertyMap::new();

        let result = props.require_string("name", "User");
        assert!(result.is_err());

        if let Err(CoreError::MissingProperty { key, entity_type }) = result {
            assert_eq!(key, "name");
            assert_eq!(entity_type, "User");
        } else {
            panic!("Expected MissingProperty error");
        }
    }

    #[test]
    fn property_map_require_string_wrong_type() {
        let mut props = PropertyMap::new();
        props.insert("name", 123i64); // Integer, not string

        let result = props.require_string("name", "User");
        assert!(result.is_err());

        if let Err(CoreError::PropertyTypeMismatch {
            key,
            expected,
            actual,
        }) = result
        {
            assert_eq!(key, "name");
            assert_eq!(expected, "string");
            assert_eq!(actual, "integer");
        } else {
            panic!("Expected PropertyTypeMismatch error");
        }
    }

    // ==================== require_float Tests ====================

    #[test]
    fn property_map_require_float_success() {
        let mut props = PropertyMap::new();
        props.insert("score", 3.14);

        let result = props.require_float("score", "Score");
        assert!((result.unwrap() - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn property_map_require_float_from_integer() {
        let mut props = PropertyMap::new();
        props.insert("count", 42i64);

        // Integer should be convertible to float
        let result = props.require_float("count", "Count");
        assert!((result.unwrap() - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn property_map_require_float_missing() {
        let props = PropertyMap::new();

        let result = props.require_float("score", "Score");
        assert!(result.is_err());

        if let Err(CoreError::MissingProperty { key, entity_type }) = result {
            assert_eq!(key, "score");
            assert_eq!(entity_type, "Score");
        } else {
            panic!("Expected MissingProperty error");
        }
    }

    #[test]
    fn property_map_require_float_wrong_type() {
        let mut props = PropertyMap::new();
        props.insert("score", "not a number"); // String, not float

        let result = props.require_float("score", "Score");
        assert!(result.is_err());

        if let Err(CoreError::PropertyTypeMismatch {
            key,
            expected,
            actual,
        }) = result
        {
            assert_eq!(key, "score");
            assert_eq!(expected, "float");
            assert_eq!(actual, "string");
        } else {
            panic!("Expected PropertyTypeMismatch error");
        }
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn property_map_serialization() {
        let mut props = PropertyMap::new();
        props.insert("name", "test");
        props.insert("count", 42i64);

        let json = serde_json::to_string(&props).unwrap();
        let deserialized: PropertyMap = serde_json::from_str(&json).unwrap();

        assert_eq!(
            deserialized.get("name").and_then(|v| v.as_str()),
            Some("test")
        );
        assert_eq!(
            deserialized
                .get("count")
                .and_then(super::PropertyValue::as_integer),
            Some(42)
        );
    }
}
