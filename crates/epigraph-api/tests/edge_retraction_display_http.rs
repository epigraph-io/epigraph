#![cfg(feature = "db")]
//! The HTTP graph views hide an edge removed with `DELETE /api/v1/edges/:id`.
//!
//! The DELETE handler has retracted rather than deleted since a6adf739 (the
//! row keeps `valid_to`) and still answers 204. Until the display tier honoured
//! `valid_to`, `GET /api/v1/claims/:id/neighborhood`, `GET /api/v1/graph/edges`
//! and `GET /api/v1/graph/full` all went on serving the "deleted" edge — and
//! the neighbourhood BFS walked through it to nodes reachable only that way.
//!
//! Handlers are driven directly (the `shard6_routes_scoped_read.rs` pattern),
//! and the edge is removed through the `delete_edge` HANDLER itself, so the
//! test exercises exactly the path a client takes. Every absence assertion has
//! its precondition asserted first.

#[path = "viewer_fixture.rs"]
mod viewer_fixture;

use axum::extract::{Path, Query, State};
use epigraph_api::middleware::bearer::ViewerExtractor;
use epigraph_api::routes::edges::{
    claim_neighborhood, delete_edge, graph_edges, graph_full, GraphAccessParams, NeighborhoodParams,
};
use epigraph_api::state::{ApiConfig, AppState};
use sqlx::PgPool;
use uuid::Uuid;
use viewer_fixture::{public_viewer, scoped_pool, seed_agent_with_group, seed_public_claim};

async fn state(pool: &PgPool) -> AppState {
    let mut state = AppState::with_db(pool.clone(), ApiConfig::default());
    state.scoped = Some(scoped_pool(pool).await);
    state
}

async fn edge(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'claim', $2, 'claim', $3) RETURNING id",
    )
    .bind(source)
    .bind(target)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("seed edge")
}

async fn http_delete(state: &AppState, edge_id: Uuid) {
    let status = delete_edge(State(state.clone()), None, Path(edge_id))
        .await
        .expect("DELETE /api/v1/edges/:id succeeds");
    assert_eq!(status, axum::http::StatusCode::NO_CONTENT);
}

async fn neighborhood(
    state: &AppState,
    pool: &PgPool,
    centre: Uuid,
    include_retracted: Option<bool>,
) -> epigraph_api::routes::edges::NeighborhoodResponse {
    claim_neighborhood(
        ViewerExtractor(public_viewer(pool).await),
        State(state.clone()),
        Path(centre),
        Query(NeighborhoodParams {
            depth: Some(2),
            agent_id: None,
            include_retracted,
        }),
    )
    .await
    .expect("neighbourhood serves")
    .0
}

fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn claim_neighborhood_neither_returns_nor_walks_a_deleted_edge(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "http-nbhd-retraction").await;
    let centre = seed_public_claim(&pool, agent, "centre").await;
    let near = seed_public_claim(&pool, agent, "near, still linked").await;
    let behind = seed_public_claim(&pool, agent, "behind the deleted edge").await;
    let past = seed_public_claim(&pool, agent, "reachable only through `behind`").await;
    let live = edge(&pool, centre, near, "supports").await;
    let gone = edge(&pool, centre, behind, "supports").await;
    let second_hop = edge(&pool, behind, past, "supports").await;
    let state = state(&pool).await;

    let before = neighborhood(&state, &pool, centre, None).await;
    assert_eq!(
        sorted(before.edges.iter().map(|e| e.id).collect()),
        sorted(vec![live, gone, second_hop]),
        "precondition: the 2-hop neighbourhood reaches `past` through `behind`"
    );

    http_delete(&state, gone).await;

    let after = neighborhood(&state, &pool, centre, None).await;
    assert_eq!(
        after.edges.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![live],
        "the deleted edge is gone, and so is the hop it was the only route to"
    );
    assert_eq!(
        after.connected_entity_ids,
        vec![near],
        "`behind` and `past` were reachable only through the deleted edge"
    );

    // Opt-in: everything again, and the deleted edge identifiable by valid_to.
    let audit = neighborhood(&state, &pool, centre, Some(true)).await;
    assert_eq!(
        sorted(audit.edges.iter().map(|e| e.id).collect()),
        sorted(vec![live, gone, second_hop])
    );
    for e in &audit.edges {
        assert_eq!(
            e.valid_to.is_some(),
            e.id == gone,
            "only the deleted edge carries a valid_to: {e:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn graph_edges_and_graph_full_omit_a_deleted_edge(pool: PgPool) {
    let (agent, _g) = seed_agent_with_group(&pool, "http-graph-retraction").await;
    let a = seed_public_claim(&pool, agent, "A").await;
    let b = seed_public_claim(&pool, agent, "B, linked only by the deleted edge").await;
    let c = seed_public_claim(&pool, agent, "C").await;
    let gone = edge(&pool, a, b, "supports").await;
    let live = edge(&pool, a, c, "supports").await;
    let state = state(&pool).await;

    let edges_view = |state: AppState, pool: PgPool| async move {
        graph_edges(
            ViewerExtractor(public_viewer(&pool).await),
            State(state),
            Query(GraphAccessParams { agent_id: None }),
        )
        .await
        .expect("graph/edges serves")
        .0
    };
    let full_view = |state: AppState, pool: PgPool| async move {
        graph_full(
            ViewerExtractor(public_viewer(&pool).await),
            State(state),
            Query(GraphAccessParams { agent_id: None }),
        )
        .await
        .expect("graph/full serves")
        .0
    };

    let before = edges_view(state.clone(), pool.clone()).await;
    assert_eq!(
        sorted(before.edges.iter().map(|e| e.id).collect()),
        sorted(vec![gone, live]),
        "precondition: graph/edges serves both edges before the delete"
    );
    let full_before = full_view(state.clone(), pool.clone()).await;
    assert_eq!(full_before.total_nodes, 3, "precondition: A, B and C");

    http_delete(&state, gone).await;

    let after = edges_view(state.clone(), pool.clone()).await;
    assert_eq!(
        after.edges.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![live],
        "graph/edges must not serve the deleted edge"
    );
    assert_eq!(after.total, 1);

    let full = full_view(state.clone(), pool.clone()).await;
    assert_eq!(
        full.edges.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![live],
        "graph/full must not serve the deleted edge"
    );
    assert_eq!(
        sorted(full.nodes.iter().map(|n| n.id).collect()),
        sorted(vec![a, c]),
        "B was in the graph only through the deleted edge"
    );
}
