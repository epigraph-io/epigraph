//! Graph trait and in-memory implementation
//!
//! Defines the core operations for a label property graph.

use crate::edge::Edge;
use crate::errors::CoreError;
use crate::ids::{EdgeId, NodeId};
use crate::labels::Label;
use crate::node::Node;

/// Core trait for label property graph operations
pub trait Graph {
    /// Add a node to the graph
    fn add_node(&mut self, node: Node) -> NodeId;

    /// Get a node by ID
    fn get_node(&self, id: NodeId) -> Option<&Node>;

    /// Get a mutable reference to a node
    fn get_node_mut(&mut self, id: NodeId) -> Option<&mut Node>;

    /// Remove a node and all its edges
    fn remove_node(&mut self, id: NodeId) -> Option<Node>;

    /// Add an edge to the graph
    ///
    /// # Errors
    /// Returns error if source or target nodes don't exist.
    fn add_edge(&mut self, edge: Edge) -> Result<EdgeId, CoreError>;

    /// Get an edge by ID
    fn get_edge(&self, id: EdgeId) -> Option<&Edge>;

    /// Remove an edge
    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge>;

    /// Find all nodes with a specific label
    fn nodes_with_label(&self, label: &Label) -> Vec<&Node>;

    /// Find all edges from a node
    fn edges_from(&self, node_id: NodeId) -> Vec<&Edge>;

    /// Find all edges to a node
    fn edges_to(&self, node_id: NodeId) -> Vec<&Edge>;

    /// Find edges between two nodes
    fn edges_between(&self, source: NodeId, target: NodeId) -> Vec<&Edge>;

    /// Count of nodes in the graph
    fn node_count(&self) -> usize;

    /// Count of edges in the graph
    fn edge_count(&self) -> usize;
}

/// In-memory implementation of the label property graph
///
/// Suitable for testing and small graphs. For production use with persistence,
/// implement the Graph trait backed by `PostgreSQL`.
#[derive(Debug, Default)]
pub struct InMemoryGraph {
    nodes: std::collections::HashMap<NodeId, Node>,
    edges: std::collections::HashMap<EdgeId, Edge>,
}

impl InMemoryGraph {
    /// Create a new empty graph
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Graph for InMemoryGraph {
    fn add_node(&mut self, node: Node) -> NodeId {
        let id = node.id;
        self.nodes.insert(id, node);
        id
    }

    fn get_node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    fn get_node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(&id)
    }

    fn remove_node(&mut self, id: NodeId) -> Option<Node> {
        // Remove all edges connected to this node
        self.edges.retain(|_, e| e.source != id && e.target != id);
        self.nodes.remove(&id)
    }

    fn add_edge(&mut self, edge: Edge) -> Result<EdgeId, CoreError> {
        // Verify both nodes exist
        if !self.nodes.contains_key(&edge.source) {
            return Err(CoreError::NodeNotFound(edge.source.as_uuid()));
        }
        if !self.nodes.contains_key(&edge.target) {
            return Err(CoreError::NodeNotFound(edge.target.as_uuid()));
        }

        let id = edge.id;
        self.edges.insert(id, edge);
        Ok(id)
    }

    fn get_edge(&self, id: EdgeId) -> Option<&Edge> {
        self.edges.get(&id)
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.edges.remove(&id)
    }

    fn nodes_with_label(&self, label: &Label) -> Vec<&Node> {
        self.nodes.values().filter(|n| n.has_label(label)).collect()
    }

    fn edges_from(&self, node_id: NodeId) -> Vec<&Edge> {
        self.edges
            .values()
            .filter(|e| e.source == node_id)
            .collect()
    }

    fn edges_to(&self, node_id: NodeId) -> Vec<&Edge> {
        self.edges
            .values()
            .filter(|e| e.target == node_id)
            .collect()
    }

    fn edges_between(&self, source: NodeId, target: NodeId) -> Vec<&Edge> {
        self.edges
            .values()
            .filter(|e| e.source == source && e.target == target)
            .collect()
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::relationships;
    use crate::labels::well_known;

    #[test]
    fn graph_add_and_retrieve_nodes() {
        let mut graph = InMemoryGraph::new();

        let node = Node::new(well_known::claim());
        let id = graph.add_node(node);

        assert!(graph.get_node(id).is_some());
        assert_eq!(graph.node_count(), 1);
    }

    #[test]
    fn graph_get_node_mut() {
        let mut graph = InMemoryGraph::new();

        let mut node = Node::new(well_known::claim());
        node.set_property("initial", "value");
        let id = graph.add_node(node);

        // Modify node through mutable reference
        if let Some(node) = graph.get_node_mut(id) {
            node.set_property("modified", "new_value");
        }

        // Verify modification persisted
        let node = graph.get_node(id).unwrap();
        assert_eq!(
            node.get_property("modified").and_then(|v| v.as_str()),
            Some("new_value")
        );
    }

    #[test]
    fn graph_get_node_mut_nonexistent() {
        let mut graph = InMemoryGraph::new();
        let fake_id = NodeId::new();

        assert!(graph.get_node_mut(fake_id).is_none());
    }

    #[test]
    fn graph_add_edge_requires_existing_nodes() {
        let mut graph = InMemoryGraph::new();

        let source = NodeId::new();
        let target = NodeId::new();

        let edge = Edge::new(source, target, relationships::SUPPORTS).unwrap();
        let result = graph.add_edge(edge);

        assert!(matches!(result, Err(CoreError::NodeNotFound(_))));
    }

    #[test]
    fn graph_add_edge_source_missing() {
        let mut graph = InMemoryGraph::new();

        // Only add target node
        let target_node = Node::new(well_known::claim());
        let target_id = graph.add_node(target_node);

        let source_id = NodeId::new(); // Not in graph
        let edge = Edge::new(source_id, target_id, relationships::SUPPORTS).unwrap();
        let result = graph.add_edge(edge);

        assert!(matches!(result, Err(CoreError::NodeNotFound(_))));
    }

    #[test]
    fn graph_add_edge_target_missing() {
        let mut graph = InMemoryGraph::new();

        // Only add source node
        let source_node = Node::new(well_known::claim());
        let source_id = graph.add_node(source_node);

        let target_id = NodeId::new(); // Not in graph
        let edge = Edge::new(source_id, target_id, relationships::SUPPORTS).unwrap();
        let result = graph.add_edge(edge);

        assert!(matches!(result, Err(CoreError::NodeNotFound(_))));
    }

    #[test]
    fn graph_edges_between_nodes() {
        let mut graph = InMemoryGraph::new();

        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());

        let id1 = graph.add_node(claim1);
        let id2 = graph.add_node(claim2);

        let edge = Edge::new(id1, id2, relationships::SUPPORTS).unwrap();
        graph.add_edge(edge).unwrap();

        assert_eq!(graph.edges_from(id1).len(), 1);
        assert_eq!(graph.edges_to(id2).len(), 1);
        assert_eq!(graph.edges_between(id1, id2).len(), 1);
    }

    #[test]
    fn graph_nodes_with_label() {
        let mut graph = InMemoryGraph::new();

        // Add multiple nodes with different labels
        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());
        let evidence = Node::new(well_known::evidence());

        graph.add_node(claim1);
        graph.add_node(claim2);
        graph.add_node(evidence);

        // Query by label
        let claims = graph.nodes_with_label(well_known::claim());
        assert_eq!(claims.len(), 2);

        let evidences = graph.nodes_with_label(well_known::evidence());
        assert_eq!(evidences.len(), 1);

        let agents = graph.nodes_with_label(well_known::agent());
        assert_eq!(agents.len(), 0);
    }

    #[test]
    fn graph_nodes_with_label_multi_label_node() {
        let mut graph = InMemoryGraph::new();

        // Create a node with multiple labels
        let mut node = Node::new(well_known::claim());
        let verified = Label::new("Verified").unwrap();
        node.add_label(&verified);
        graph.add_node(node);

        // Should be found by both labels
        let claims = graph.nodes_with_label(well_known::claim());
        assert_eq!(claims.len(), 1);

        let verified_nodes = graph.nodes_with_label(&verified);
        assert_eq!(verified_nodes.len(), 1);
    }

    #[test]
    fn remove_node_removes_connected_edges() {
        let mut graph = InMemoryGraph::new();

        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());

        let id1 = graph.add_node(claim1);
        let id2 = graph.add_node(claim2);

        let edge = Edge::new(id1, id2, relationships::SUPPORTS).unwrap();
        graph.add_edge(edge).unwrap();

        assert_eq!(graph.edge_count(), 1);

        graph.remove_node(id1);

        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.node_count(), 1);
    }

    #[test]
    fn remove_node_removes_incoming_edges() {
        let mut graph = InMemoryGraph::new();

        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());

        let id1 = graph.add_node(claim1);
        let id2 = graph.add_node(claim2);

        // Edge points TO id2
        let edge = Edge::new(id1, id2, relationships::SUPPORTS).unwrap();
        graph.add_edge(edge).unwrap();

        // Remove the target node
        graph.remove_node(id2);

        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.node_count(), 1);
    }

    #[test]
    fn graph_get_edge() {
        let mut graph = InMemoryGraph::new();

        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());
        let id1 = graph.add_node(claim1);
        let id2 = graph.add_node(claim2);

        let edge = Edge::new(id1, id2, relationships::SUPPORTS).unwrap();
        let edge_id = graph.add_edge(edge).unwrap();

        let retrieved = graph.get_edge(edge_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().source, id1);
        assert_eq!(retrieved.unwrap().target, id2);
    }

    #[test]
    fn graph_remove_edge() {
        let mut graph = InMemoryGraph::new();

        let claim1 = Node::new(well_known::claim());
        let claim2 = Node::new(well_known::claim());
        let id1 = graph.add_node(claim1);
        let id2 = graph.add_node(claim2);

        let edge = Edge::new(id1, id2, relationships::SUPPORTS).unwrap();
        let edge_id = graph.add_edge(edge).unwrap();

        assert_eq!(graph.edge_count(), 1);

        let removed = graph.remove_edge(edge_id);
        assert!(removed.is_some());
        assert_eq!(graph.edge_count(), 0);

        // Nodes should still exist
        assert_eq!(graph.node_count(), 2);
    }

    #[test]
    fn graph_edges_from_empty() {
        let mut graph = InMemoryGraph::new();

        let node = Node::new(well_known::claim());
        let id = graph.add_node(node);

        let edges = graph.edges_from(id);
        assert!(edges.is_empty());
    }

    #[test]
    fn graph_edges_to_empty() {
        let mut graph = InMemoryGraph::new();

        let node = Node::new(well_known::claim());
        let id = graph.add_node(node);

        let edges = graph.edges_to(id);
        assert!(edges.is_empty());
    }
}
