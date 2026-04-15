//! Type-safe identifiers for graph entities
//!
//! Using newtype wrappers prevents accidental confusion between node and edge IDs.
//! `UUIDv7` is preferred for time-ordered, sortable identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Unique identifier for a node in the graph
///
/// Wraps UUID to provide type safety - prevents accidentally using an `EdgeId` where `NodeId` is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(Uuid);

impl NodeId {
    /// Create a new random `NodeId` (`UUIDv4`)
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `NodeId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Create a nil (all zeros) `NodeId` - useful for testing
    #[must_use]
    pub const fn nil() -> Self {
        Self(Uuid::nil())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node:{}", self.0)
    }
}

impl From<Uuid> for NodeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<NodeId> for Uuid {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

/// Unique identifier for an edge in the graph
///
/// Wraps UUID to provide type safety - prevents accidentally using a `NodeId` where `EdgeId` is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdgeId(Uuid);

impl EdgeId {
    /// Create a new random `EdgeId` (`UUIDv4`)
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create an `EdgeId` from an existing UUID
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Create a nil (all zeros) `EdgeId` - useful for testing
    #[must_use]
    pub const fn nil() -> Self {
        Self(Uuid::nil())
    }
}

impl Default for EdgeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "edge:{}", self.0)
    }
}

impl From<Uuid> for EdgeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<EdgeId> for Uuid {
    fn from(id: EdgeId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_and_edge_id_are_distinct_types() {
        let node_id = NodeId::new();
        let edge_id = EdgeId::new();

        // This would fail to compile if types were the same:
        // let _: NodeId = edge_id; // ERROR

        // But we can compare their underlying UUIDs if needed
        assert_ne!(node_id.as_uuid(), edge_id.as_uuid());
    }

    #[test]
    fn ids_serialize_as_uuid_strings() {
        let node_id = NodeId::from_uuid(Uuid::nil());
        let json = serde_json::to_string(&node_id).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    #[test]
    fn ids_display_with_prefix() {
        let node_id = NodeId::nil();
        let edge_id = EdgeId::nil();

        assert!(node_id.to_string().starts_with("node:"));
        assert!(edge_id.to_string().starts_with("edge:"));
    }
}
