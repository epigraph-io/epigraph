//! DAG validation for reasoning graphs
//!
//! Ensures the reasoning graph maintains acyclicity.
//! Cycles in reasoning are invalid (circular logic).

use crate::errors::EngineError;
use petgraph::algo::is_cyclic_directed;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// DAG validator for reasoning graphs
pub struct DagValidator {
    /// Internal graph representation for validation
    graph: DiGraph<Uuid, ()>,
    /// Map from UUID to graph node index
    node_map: HashMap<Uuid, NodeIndex>,
}

impl DagValidator {
    /// Create a new empty validator
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    /// Add a node to the validation graph
    pub fn add_node(&mut self, id: Uuid) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&id) {
            return idx;
        }
        let idx = self.graph.add_node(id);
        self.node_map.insert(id, idx);
        idx
    }

    /// Add an edge (reasoning dependency) to the graph
    ///
    /// # Arguments
    /// * `from` - Source node (the claim being supported)
    /// * `to` - Target node (the supporting evidence/claim)
    ///
    /// # Returns
    /// Ok if the edge doesn't create a cycle, Err otherwise
    ///
    /// # Errors
    /// Returns `EngineError::CycleDetected` if adding this edge would create a cycle.
    pub fn add_edge(&mut self, from: Uuid, to: Uuid) -> Result<(), EngineError> {
        let from_idx = self.add_node(from);
        let to_idx = self.add_node(to);

        // Temporarily add edge and check for cycles
        let edge_idx = self.graph.add_edge(from_idx, to_idx, ());

        if is_cyclic_directed(&self.graph) {
            // Remove the edge that caused the cycle
            self.graph.remove_edge(edge_idx);

            // Find the cycle path for error reporting
            let path = self.find_cycle_path(from);

            return Err(EngineError::CycleDetected { path });
        }

        Ok(())
    }

    /// Check if adding an edge would create a cycle (without modifying graph)
    #[must_use]
    pub fn would_create_cycle(&self, from: Uuid, to: Uuid) -> bool {
        // Check if there's already a path from `to` to `from`
        // If so, adding from -> to would create a cycle
        let Some(&from_idx) = self.node_map.get(&from) else {
            return false; // New node can't create cycle
        };

        let Some(&to_idx) = self.node_map.get(&to) else {
            return false; // New node can't create cycle
        };

        // Use DFS to check if there's a path from to -> from
        petgraph::algo::has_path_connecting(&self.graph, to_idx, from_idx, None)
    }

    /// Validate that the entire graph is a valid DAG
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !is_cyclic_directed(&self.graph)
    }

    /// Get topological order of nodes (if valid DAG)
    ///
    /// Returns nodes in dependency order: leaves first, roots last.
    ///
    /// # Errors
    /// Returns `EngineError::CycleDetected` if the graph contains a cycle.
    pub fn topological_order(&self) -> Result<Vec<Uuid>, EngineError> {
        if !self.is_valid() {
            return Err(EngineError::CycleDetected {
                path: self.find_any_cycle(),
            });
        }

        let order = petgraph::algo::toposort(&self.graph, None).map_err(|_| {
            EngineError::CycleDetected {
                path: self.find_any_cycle(),
            }
        })?;

        Ok(order.into_iter().map(|idx| self.graph[idx]).collect())
    }

    /// Find a cycle path starting from a given node using DFS.
    ///
    /// Performs a depth-first search from `start`, tracking the current DFS
    /// stack. When a back-edge is found (a neighbor already on the stack),
    /// the cycle is extracted by slicing the stack from that node's position
    /// to the current node (inclusive), giving the full cycle path.
    ///
    /// Returns the cycle as a `Vec<Uuid>` from the cycle-entry point back to
    /// where it closes. Falls back to `vec![start]` if no back-edge is found
    /// (e.g., the graph has changed between the cycle check and this call).
    fn find_cycle_path(&self, start: Uuid) -> Vec<Uuid> {
        let Some(&start_idx) = self.node_map.get(&start) else {
            return vec![start];
        };

        // DFS iterative: stack holds (node, iterator-position-in-neighbors)
        let mut path: Vec<NodeIndex> = Vec::new();
        let mut on_stack: HashSet<NodeIndex> = HashSet::new();
        let mut visited: HashSet<NodeIndex> = HashSet::new();

        // Iterative DFS using an explicit call stack of (node, neighbor_iter)
        let mut call_stack: Vec<(NodeIndex, usize)> = vec![(start_idx, 0)];
        path.push(start_idx);
        on_stack.insert(start_idx);
        visited.insert(start_idx);

        while let Some((node, neighbor_pos)) = call_stack.last_mut() {
            let node = *node;
            let neighbors: Vec<NodeIndex> = self.graph.neighbors(node).collect();
            if *neighbor_pos < neighbors.len() {
                let next = neighbors[*neighbor_pos];
                *neighbor_pos += 1;
                if on_stack.contains(&next) {
                    // Back-edge found: extract the cycle from path
                    if let Some(pos) = path.iter().position(|&n| n == next) {
                        let cycle: Vec<Uuid> = path[pos..].iter().map(|&n| self.graph[n]).collect();
                        return cycle;
                    }
                } else if !visited.contains(&next) {
                    visited.insert(next);
                    on_stack.insert(next);
                    path.push(next);
                    call_stack.push((next, 0));
                }
            } else {
                // Exhausted neighbors: backtrack
                on_stack.remove(&node);
                path.pop();
                call_stack.pop();
            }
        }

        // Fallback: cycle must exist (caller verified it) but DFS didn't find
        // a back-edge from this start node; return just the start.
        vec![start]
    }

    /// Find any cycle in the graph using DFS.
    ///
    /// Iterates over all nodes as potential DFS roots, skipping already-visited
    /// ones. Returns the first cycle found, or an empty `Vec` if the graph is
    /// acyclic (which should not happen when called after `is_cyclic_directed`).
    fn find_any_cycle(&self) -> Vec<Uuid> {
        let mut globally_visited: HashSet<NodeIndex> = HashSet::new();

        for &start_idx in self.node_map.values() {
            if globally_visited.contains(&start_idx) {
                continue;
            }

            let mut path: Vec<NodeIndex> = Vec::new();
            let mut on_stack: HashSet<NodeIndex> = HashSet::new();
            let mut call_stack: Vec<(NodeIndex, usize)> = vec![(start_idx, 0)];
            path.push(start_idx);
            on_stack.insert(start_idx);
            globally_visited.insert(start_idx);

            while let Some((node, neighbor_pos)) = call_stack.last_mut() {
                let node = *node;
                let neighbors: Vec<NodeIndex> = self.graph.neighbors(node).collect();
                if *neighbor_pos < neighbors.len() {
                    let next = neighbors[*neighbor_pos];
                    *neighbor_pos += 1;
                    if on_stack.contains(&next) {
                        // Back-edge found: extract cycle
                        if let Some(pos) = path.iter().position(|&n| n == next) {
                            let cycle: Vec<Uuid> =
                                path[pos..].iter().map(|&n| self.graph[n]).collect();
                            return cycle;
                        }
                    } else if !globally_visited.contains(&next) {
                        globally_visited.insert(next);
                        on_stack.insert(next);
                        path.push(next);
                        call_stack.push((next, 0));
                    }
                } else {
                    on_stack.remove(&node);
                    path.pop();
                    call_stack.pop();
                }
            }
        }

        Vec::new()
    }

    /// Get the number of nodes in the validation graph
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of edges in the validation graph
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

impl Default for DagValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn linear_chain_is_valid() {
        let mut validator = DagValidator::new();

        // A -> B -> C (linear chain)
        validator.add_edge(uuid(1), uuid(2)).unwrap();
        validator.add_edge(uuid(2), uuid(3)).unwrap();

        assert!(validator.is_valid());
    }

    #[test]
    fn diamond_is_valid() {
        let mut validator = DagValidator::new();

        // Diamond: A -> B, A -> C, B -> D, C -> D
        validator.add_edge(uuid(1), uuid(2)).unwrap();
        validator.add_edge(uuid(1), uuid(3)).unwrap();
        validator.add_edge(uuid(2), uuid(4)).unwrap();
        validator.add_edge(uuid(3), uuid(4)).unwrap();

        assert!(validator.is_valid());
    }

    #[test]
    fn simple_cycle_rejected() {
        let mut validator = DagValidator::new();

        // A -> B -> A (cycle)
        validator.add_edge(uuid(1), uuid(2)).unwrap();
        let result = validator.add_edge(uuid(2), uuid(1));

        assert!(matches!(result, Err(EngineError::CycleDetected { .. })));
    }

    #[test]
    fn indirect_cycle_rejected() {
        let mut validator = DagValidator::new();

        // A -> B -> C -> A (indirect cycle)
        validator.add_edge(uuid(1), uuid(2)).unwrap();
        validator.add_edge(uuid(2), uuid(3)).unwrap();
        let result = validator.add_edge(uuid(3), uuid(1));

        assert!(matches!(result, Err(EngineError::CycleDetected { .. })));
    }

    #[test]
    fn self_loop_rejected() {
        let mut validator = DagValidator::new();

        // A -> A (self loop)
        let result = validator.add_edge(uuid(1), uuid(1));

        assert!(matches!(result, Err(EngineError::CycleDetected { .. })));
    }

    #[test]
    fn would_create_cycle_detects_potential_cycle() {
        let mut validator = DagValidator::new();

        validator.add_edge(uuid(1), uuid(2)).unwrap();
        validator.add_edge(uuid(2), uuid(3)).unwrap();

        // Adding 3 -> 1 would create a cycle
        assert!(validator.would_create_cycle(uuid(3), uuid(1)));

        // Adding 1 -> 3 would not (it's the same direction)
        assert!(!validator.would_create_cycle(uuid(1), uuid(3)));
    }

    #[test]
    fn topological_order_valid_for_dag() {
        let mut validator = DagValidator::new();

        validator.add_edge(uuid(1), uuid(2)).unwrap();
        validator.add_edge(uuid(2), uuid(3)).unwrap();

        let order = validator.topological_order().unwrap();
        assert_eq!(order.len(), 3);
    }
}
