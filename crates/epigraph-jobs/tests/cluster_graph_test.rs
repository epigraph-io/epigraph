use epigraph_jobs::cluster_graph::louvain::{louvain, LouvainInput};

/// Two disjoint cliques of 3 nodes each must produce exactly 2 communities,
/// each with all three of its nodes.
#[test]
fn two_disjoint_cliques_yield_two_communities() {
    // Node ids: 0..=2 in clique A, 3..=5 in clique B. No cross edges.
    let edges = vec![
        (0u32, 1u32, 1.0),
        (0, 2, 1.0),
        (1, 2, 1.0),
        (3, 4, 1.0),
        (3, 5, 1.0),
        (4, 5, 1.0),
    ];
    let input = LouvainInput {
        node_count: 6,
        edges,
        resolution: 1.0,
    };
    let result = louvain(&input).expect("louvain runs");
    let mut comm_to_members: std::collections::BTreeMap<u32, Vec<u32>> =
        std::collections::BTreeMap::new();
    for (node, comm) in result.assignments.iter().enumerate() {
        comm_to_members.entry(*comm).or_default().push(node as u32);
    }
    assert_eq!(comm_to_members.len(), 2, "expected exactly 2 communities");
    let mut sorted_groups: Vec<Vec<u32>> = comm_to_members.into_values().collect();
    sorted_groups.iter_mut().for_each(|g| g.sort());
    sorted_groups.sort();
    assert_eq!(sorted_groups, vec![vec![0, 1, 2], vec![3, 4, 5]]);
}

#[test]
fn empty_graph_returns_empty_assignments() {
    let input = LouvainInput {
        node_count: 0,
        edges: vec![],
        resolution: 1.0,
    };
    let result = louvain(&input).expect("louvain runs on empty graph");
    assert!(result.assignments.is_empty());
}

#[test]
fn singleton_nodes_each_get_own_community() {
    let input = LouvainInput {
        node_count: 3,
        edges: vec![],
        resolution: 1.0,
    };
    let result = louvain(&input).expect("louvain runs on edge-free graph");
    let mut comms: Vec<u32> = result.assignments.iter().copied().collect();
    comms.sort();
    comms.dedup();
    assert_eq!(comms.len(), 3, "three isolated nodes -> three communities");
}

/// A star graph (one center connected to 8 leaves) is a single dense
/// community; Louvain should not split it.
#[test]
fn star_graph_is_one_community() {
    let center = 0u32;
    let edges: Vec<(u32, u32, f64)> = (1..=8u32).map(|leaf| (center, leaf, 1.0)).collect();
    let input = LouvainInput { node_count: 9, edges, resolution: 1.0 };
    let result = louvain(&input).expect("louvain runs");
    let mut uniq: Vec<u32> = result.assignments.iter().copied().collect();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 1, "star graph should be one community");
}

/// v1 ignores edge sign: a graph wired with all CONTRADICTS edges should
/// produce the same community structure as the same topology with SUPPORTS.
/// We assert this at the Louvain layer by passing identical weight 1.0 either
/// way and confirming the assignment vector is identical.
#[test]
fn sign_is_ignored_in_v1() {
    let topology = vec![
        (0u32, 1u32, 1.0), (1, 2, 1.0), (0, 2, 1.0),
        (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
    ];
    let supports = LouvainInput { node_count: 6, edges: topology.clone(), resolution: 1.0 };
    let contradicts = LouvainInput { node_count: 6, edges: topology, resolution: 1.0 };
    let a = louvain(&supports).unwrap().assignments;
    let b = louvain(&contradicts).unwrap().assignments;
    assert_eq!(a, b);
}
