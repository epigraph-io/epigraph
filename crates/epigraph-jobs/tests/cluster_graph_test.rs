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
    let mut comms: Vec<u32> = result.assignments.to_vec();
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
    let input = LouvainInput {
        node_count: 9,
        edges,
        resolution: 1.0,
    };
    let result = louvain(&input).expect("louvain runs");
    let mut uniq: Vec<u32> = result.assignments.to_vec();
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
        (0u32, 1u32, 1.0),
        (1, 2, 1.0),
        (0, 2, 1.0),
        (3, 4, 1.0),
        (4, 5, 1.0),
        (3, 5, 1.0),
    ];
    let supports = LouvainInput {
        node_count: 6,
        edges: topology.clone(),
        resolution: 1.0,
    };
    let contradicts = LouvainInput {
        node_count: 6,
        edges: topology,
        resolution: 1.0,
    };
    let a = louvain(&supports).unwrap().assignments;
    let b = louvain(&contradicts).unwrap().assignments;
    assert_eq!(a, b);
}

#[cfg(feature = "integration")]
mod integration {
    #[allow(unused_imports)]
    use super::*;
    use epigraph_jobs::cluster_graph::runner::{run_clustering, RunConfig};
    use sqlx::PgPool;
    use uuid::Uuid;

    /// Runs on its own database, created and migrated from empty by
    /// `#[sqlx::test]` (so `DATABASE_URL` must name a role that may create
    /// one). `run_clustering` clusters EVERY claim in the database it is
    /// given, so "exactly two clusters" is only true where the fixture's six
    /// claims are the only claims; and a fresh database is what lets the
    /// fixture keep fixed ids and still be seeded on every run.
    #[sqlx::test(migrations = "../../migrations")]
    async fn end_to_end_two_cliques_produce_two_clusters(pool: PgPool) {
        let seed = include_str!("fixtures/seed_two_cliques.sql");
        sqlx::raw_sql(seed).execute(&pool).await.unwrap();

        let summary = run_clustering(
            &pool,
            &RunConfig {
                resolution: 1.0,
                retain_runs: 3,
            },
        )
        .await
        .unwrap();
        assert_eq!(summary.cluster_count, 2);
        assert!(!summary.degraded);

        // The two clusters are the two cliques: a1..a3 share one, b1..b3 the
        // other. The fixture's claim ids are 1..=6.
        let mut clusters = Vec::new();
        for clique in [[1u128, 2, 3], [4, 5, 6]] {
            let members: Vec<Uuid> = clique.into_iter().map(Uuid::from_u128).collect();
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT DISTINCT cluster_id FROM claim_cluster_membership \
                  WHERE run_id = $1 AND claim_id = ANY($2)",
            )
            .bind(summary.run_id)
            .bind(&members)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(ids.len(), 1, "a clique is one cluster: {clique:?}");
            clusters.push(ids);
        }
        assert_ne!(clusters[0], clusters[1], "the cliques are two clusters");

        // The governance edge was stored, and it is the only edge between
        // the cliques...
        let (occupies,): (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM edges WHERE relationship = 'OCCUPIES'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(occupies, 1, "the fixture seeds one governance edge");

        // ...so zero cluster_edges rows for this run means it was excluded:
        // counted, it would be one inter-cluster edge of weight 1.
        let (n,): (i64,) =
            sqlx::query_as("SELECT COUNT(*)::bigint FROM cluster_edges WHERE run_id = $1")
                .bind(summary.run_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 0, "no inter-cluster edges expected");
    }
}
