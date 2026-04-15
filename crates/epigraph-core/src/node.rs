//! Node type for the label property graph
//!
//! Nodes are vertices in the graph that can have multiple labels and properties.

use crate::ids::NodeId;
use crate::labels::Label;
use crate::properties::PropertyMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A node in the label property graph
///
/// Nodes can have:
/// - Multiple labels (for multi-classification)
/// - Arbitrary properties (key-value pairs)
/// - Timestamps for auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Unique identifier for this node
    pub id: NodeId,

    /// Set of labels classifying this node
    /// A node can have multiple labels (e.g., "Claim" + "Verified")
    pub labels: HashSet<Label>,

    /// Properties stored on this node
    pub properties: PropertyMap,

    /// When this node was created
    pub created_at: DateTime<Utc>,

    /// When this node was last modified
    pub updated_at: DateTime<Utc>,
}

impl Node {
    /// Create a new node with a single label
    #[must_use]
    pub fn new(label: &Label) -> Self {
        let now = Utc::now();
        let mut labels = HashSet::new();
        labels.insert(label.clone());

        Self {
            id: NodeId::new(),
            labels,
            properties: PropertyMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a new node with a specific ID and label
    #[must_use]
    pub fn with_id(id: NodeId, label: &Label) -> Self {
        let now = Utc::now();
        let mut labels = HashSet::new();
        labels.insert(label.clone());

        Self {
            id,
            labels,
            properties: PropertyMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a label to this node
    pub fn add_label(&mut self, label: &Label) {
        self.labels.insert(label.clone());
        self.updated_at = Utc::now();
    }

    /// Remove a label from this node
    pub fn remove_label(&mut self, label: &Label) -> bool {
        let removed = self.labels.remove(label);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Check if this node has a specific label
    #[must_use]
    pub fn has_label(&self, label: &Label) -> bool {
        self.labels.contains(label)
    }

    /// Set a property on this node
    pub fn set_property(
        &mut self,
        key: impl Into<String>,
        value: impl Into<crate::properties::PropertyValue>,
    ) {
        self.properties.insert(key, value);
        self.updated_at = Utc::now();
    }

    /// Get a property from this node
    #[must_use]
    pub fn get_property(&self, key: &str) -> Option<&crate::properties::PropertyValue> {
        self.properties.get(key)
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Node {}

impl std::hash::Hash for Node {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::well_known;

    #[test]
    fn create_node_with_label() {
        let node = Node::new(well_known::claim());
        assert!(node.has_label(well_known::claim()));
        assert!(!node.has_label(well_known::evidence()));
    }

    #[test]
    fn create_node_with_id() {
        let id = NodeId::new();
        let node = Node::with_id(id, well_known::claim());

        assert_eq!(node.id, id);
        assert!(node.has_label(well_known::claim()));
    }

    #[test]
    fn node_multiple_labels() {
        let mut node = Node::new(well_known::claim());
        let verified = Label::new("Verified").unwrap();
        node.add_label(&verified);

        assert!(node.has_label(well_known::claim()));
        assert!(node.has_label(&verified));
        assert_eq!(node.labels.len(), 2);
    }

    #[test]
    fn node_remove_label() {
        let mut node = Node::new(well_known::claim());
        let verified = Label::new("Verified").unwrap();
        node.add_label(&verified);

        assert_eq!(node.labels.len(), 2);

        // Remove the Verified label
        let removed = node.remove_label(&verified);
        assert!(removed);
        assert!(!node.has_label(&verified));
        assert_eq!(node.labels.len(), 1);

        // Try to remove non-existent label
        let not_removed = node.remove_label(well_known::evidence());
        assert!(!not_removed);
    }

    #[test]
    fn node_remove_label_updates_timestamp() {
        let mut node = Node::new(well_known::claim());
        let verified = Label::new("Verified").unwrap();
        node.add_label(&verified);

        let original_updated = node.updated_at;
        std::thread::sleep(std::time::Duration::from_millis(10));

        node.remove_label(&verified);

        assert!(node.updated_at > original_updated);
    }

    #[test]
    fn node_properties() {
        let mut node = Node::new(well_known::claim());
        node.set_property("statement", "The sky is blue");
        node.set_property("truth_value", 0.95);

        assert_eq!(
            node.get_property("statement").and_then(|v| v.as_str()),
            Some("The sky is blue")
        );
        assert_eq!(
            node.get_property("truth_value")
                .and_then(super::super::properties::PropertyValue::as_float),
            Some(0.95)
        );
    }

    #[test]
    fn node_set_property_updates_timestamp() {
        let mut node = Node::new(well_known::claim());
        let original_updated = node.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        node.set_property("key", "value");

        assert!(node.updated_at > original_updated);
    }

    #[test]
    fn node_add_label_updates_timestamp() {
        let mut node = Node::new(well_known::claim());
        let original_updated = node.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        node.add_label(well_known::evidence());

        assert!(node.updated_at > original_updated);
    }

    #[test]
    fn node_equality_by_id() {
        let id = NodeId::new();
        let node1 = Node::with_id(id, well_known::claim());
        let node2 = Node::with_id(id, well_known::evidence()); // Different label, same ID

        assert_eq!(node1, node2, "Nodes with same ID should be equal");
    }

    #[test]
    fn node_hash_by_id() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let id = NodeId::new();
        let node1 = Node::with_id(id, well_known::claim());
        let node2 = Node::with_id(id, well_known::evidence());

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        node1.hash(&mut hasher1);
        node2.hash(&mut hasher2);

        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "Nodes with same ID should have same hash"
        );
    }

    #[test]
    fn node_serialization() {
        let mut node = Node::new(well_known::claim());
        node.set_property("test", "value");

        let json = serde_json::to_string(&node).unwrap();
        let deserialized: Node = serde_json::from_str(&json).unwrap();

        assert_eq!(node.id, deserialized.id);
        assert!(deserialized.has_label(well_known::claim()));
    }
}
