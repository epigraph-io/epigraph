//! Verifies the Louvain watchdog terminates the run before iter=32 on slow graphs.

use epigraph_jobs::cluster_graph::louvain::{louvain, LouvainConfig, LouvainInput};

fn complete_graph(n: usize) -> LouvainInput {
    let mut edges = Vec::new();
    for a in 0..n as u32 {
        for b in (a + 1)..n as u32 {
            edges.push((a, b, 1.0));
        }
    }
    LouvainInput {
        node_count: n,
        edges,
        resolution: 1.0,
    }
}

#[test]
fn watchdog_fires_before_32_iters_on_complete_graph() {
    let input = complete_graph(200);
    let cfg = LouvainConfig {
        timeout_secs: Some(0.0),
        max_iter: 32,
    };
    let result = louvain(&input, &cfg).expect("louvain should not error on valid input");

    assert!(
        result.timed_out,
        "watchdog should have fired (timeout=0.0) but timed_out=false"
    );
    // community count assertion is now meaningful: we didn't iterate, so all nodes
    // are their own singleton communities
    let unique: std::collections::HashSet<u32> = result.assignments.iter().copied().collect();
    assert_eq!(
        unique.len(),
        200,
        "with timeout=0.0, no sweep ran; expect 200 singleton communities"
    );
}

#[test]
fn no_timeout_completes_normally_on_sparse_graph() {
    let edges: Vec<(u32, u32, f64)> = (0..49u32).map(|i| (i, i + 1, 1.0)).collect();
    let input = LouvainInput {
        node_count: 50,
        edges,
        resolution: 1.0,
    };
    let cfg = LouvainConfig {
        timeout_secs: None,
        max_iter: 32,
    };
    let result = louvain(&input, &cfg).expect("louvain on path graph");

    // assert watchdog did NOT fire, AND clustering actually merged nodes
    assert!(
        !result.timed_out,
        "path graph with no timeout should not time out"
    );
    assert_eq!(result.assignments.len(), 50);
    // A 50-node path graph should be grouped into fewer than 50 communities.
    let unique: std::collections::HashSet<u32> = result.assignments.iter().copied().collect();
    assert!(
        unique.len() < 50,
        "Louvain on a path graph should merge some nodes; got {} communities",
        unique.len()
    );
}
