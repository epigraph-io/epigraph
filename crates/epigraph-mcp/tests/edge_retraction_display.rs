//! `get_neighborhood` and `traverse` hide an edge removed with `delete_edge`.
//!
//! `delete_edge` has retracted rather than deleted since a6adf739 — the row
//! stays with `valid_to` set — and replies `deleted: true`. Until the display
//! tier honoured `valid_to`, both graph tools went on returning the "deleted"
//! edge with nothing marking it, so an agent that re-checked the neighbourhood
//! re-found it and tried to delete it again (which then reports "not found").
//!
//! Every test asserts its precondition — the edge IS visible before the
//! delete — so an absence assertion cannot pass on a fixture that never
//! produced the edge. The edge is removed through `do_delete_edge`, the same
//! function the rmcp dispatcher calls.

mod common;

#[path = "viewer_fixture.rs"]
mod fixture;

use common::{build_test_server, first_text};
use epigraph_mcp::tools::edge_mutation::do_delete_edge;
use epigraph_mcp::tools::graph::{get_neighborhood, traverse};
use epigraph_mcp::types::{DeleteEdgeParams, GetNeighborhoodParams, TraverseParams};
use epigraph_mcp::EpiGraphMcpFull;
use sqlx::PgPool;
use uuid::Uuid;

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

async fn delete(server: &EpiGraphMcpFull, edge_id: Uuid) {
    do_delete_edge(
        server,
        DeleteEdgeParams {
            edge_id: edge_id.to_string(),
        },
    )
    .await
    .expect("delete_edge succeeds");
}

fn nbhd_params(
    node: Uuid,
    direction: &str,
    include_retracted: Option<bool>,
) -> GetNeighborhoodParams {
    GetNeighborhoodParams {
        node_id: node.to_string(),
        relationship: None,
        direction: Some(direction.to_string()),
        limit: None,
        include_retracted,
    }
}

fn traverse_params(start: Uuid, include_retracted: Option<bool>) -> TraverseParams {
    TraverseParams {
        start_id: start.to_string(),
        max_depth: Some(3),
        relationship: None,
        min_truth: None,
        limit: None,
        include_retracted,
    }
}

fn edge_ids(resp: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = resp["edges"]
        .as_array()
        .expect("edges array")
        .iter()
        .map(|e| e["edge_id"].as_str().expect("edge_id").to_string())
        .collect();
    v.sort();
    v
}

fn node_ids(resp: &serde_json::Value) -> Vec<String> {
    let mut v: Vec<String> = resp["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["id"].as_str().expect("id").to_string())
        .collect();
    v.sort();
    v
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_hides_a_deleted_edge_and_flags_it_on_opt_in(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "nbhd-retraction").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B").await;
    let c = fixture::seed_public_claim(&pool, agent, "C").await;
    let gone = edge(&pool, a, b, "supports").await;
    let live = edge(&pool, a, c, "supports").await;
    let viewer = fixture::public_viewer(&pool).await;

    let before = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", None))
            .await
            .expect("neighbourhood before"),
    );
    assert_eq!(
        edge_ids(&before),
        sorted(vec![gone.to_string(), live.to_string()]),
        "precondition: both edges are visible before the delete"
    );

    delete(&server, gone).await;

    let after = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", None))
            .await
            .expect("neighbourhood after"),
    );
    assert_eq!(
        edge_ids(&after),
        vec![live.to_string()],
        "the deleted edge must be gone from the default neighbourhood"
    );
    assert_eq!(after["edge_count"], 1);
    let only = &after["edges"][0];
    assert!(
        only.get("retracted").is_none() && only.get("valid_to").is_none(),
        "an in-force edge with no end date serialises exactly as before: {only}"
    );

    // The far end, read inward, must not see it either.
    let from_b = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(b, "incoming", None))
            .await
            .expect("incoming at B"),
    );
    assert_eq!(edge_ids(&from_b), Vec::<String>::new());

    // Opt-in: both edges, the deleted one flagged.
    let audit = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "both", Some(true)))
            .await
            .expect("neighbourhood, include_retracted"),
    );
    assert_eq!(
        edge_ids(&audit),
        sorted(vec![gone.to_string(), live.to_string()])
    );
    for e in audit["edges"].as_array().expect("edges") {
        let is_gone = e["edge_id"] == gone.to_string();
        assert_eq!(
            e.get("retracted").and_then(serde_json::Value::as_bool),
            if is_gone { Some(true) } else { None },
            "only the deleted edge carries `retracted: true`: {e}"
        );
        assert_eq!(
            e.get("valid_to").is_some(),
            is_gone,
            "only the deleted edge carries a valid_to: {e}"
        );
    }
}

/// A future-dated `valid_to` is "in force until then": shown by default, with
/// its end date, and not flagged retracted.
#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_keeps_a_future_dated_edge_unflagged(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "nbhd-future").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B").await;
    let e = edge(&pool, a, b, "supports").await;
    sqlx::query("UPDATE edges SET valid_to = now() + interval '1 year' WHERE id = $1")
        .bind(e)
        .execute(&pool)
        .await
        .expect("future-date");
    let viewer = fixture::public_viewer(&pool).await;

    let resp = first_text(
        &get_neighborhood(&server, &viewer, nbhd_params(a, "outgoing", None))
            .await
            .expect("neighbourhood"),
    );
    assert_eq!(edge_ids(&resp), vec![e.to_string()]);
    let only = &resp["edges"][0];
    assert!(
        only.get("valid_to").is_some(),
        "the end date is reported: {only}"
    );
    assert!(
        only.get("retracted").is_none(),
        "but it is not retracted: {only}"
    );
}

/// The traversal filters at the READ: a deleted edge is neither returned nor
/// followed, so the node behind it (and everything past it) is not reached.
#[sqlx::test(migrations = "../../migrations")]
async fn traverse_neither_returns_nor_follows_a_deleted_edge(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let (agent, _g) = fixture::seed_agent_with_group(&pool, "traverse-retraction").await;
    let a = fixture::seed_public_claim(&pool, agent, "A").await;
    let b = fixture::seed_public_claim(&pool, agent, "B behind the deleted edge").await;
    let c = fixture::seed_public_claim(&pool, agent, "C").await;
    let d = fixture::seed_public_claim(&pool, agent, "D past B").await;
    let gone = edge(&pool, a, b, "supports").await;
    edge(&pool, a, c, "supports").await;
    edge(&pool, b, d, "supports").await;
    let viewer = fixture::public_viewer(&pool).await;

    let before = first_text(
        &traverse(&server, &viewer, traverse_params(a, None))
            .await
            .expect("traverse before"),
    );
    assert_eq!(
        node_ids(&before),
        sorted(vec![
            a.to_string(),
            b.to_string(),
            c.to_string(),
            d.to_string()
        ]),
        "precondition: B and D are reached through A→B before the delete"
    );

    delete(&server, gone).await;

    let after = first_text(
        &traverse(&server, &viewer, traverse_params(a, None))
            .await
            .expect("traverse after"),
    );
    assert_eq!(
        node_ids(&after),
        sorted(vec![a.to_string(), c.to_string()]),
        "B is reachable only through the deleted edge, and D only through B"
    );
    let pairs: Vec<(String, String)> = after["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .map(|e| {
            (
                e["source_id"].as_str().unwrap().to_string(),
                e["target_id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(pairs, vec![(a.to_string(), c.to_string())]);

    // Opt-in walks it again and flags the edge.
    let audit = first_text(
        &traverse(&server, &viewer, traverse_params(a, Some(true)))
            .await
            .expect("traverse, include_retracted"),
    );
    assert_eq!(
        node_ids(&audit),
        sorted(vec![
            a.to_string(),
            b.to_string(),
            c.to_string(),
            d.to_string()
        ])
    );
    let flagged: Vec<&serde_json::Value> = audit["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .filter(|e| e.get("retracted").and_then(serde_json::Value::as_bool) == Some(true))
        .collect();
    assert_eq!(flagged.len(), 1, "exactly the deleted edge is flagged");
    assert_eq!(flagged[0]["source_id"], a.to_string());
    assert_eq!(flagged[0]["target_id"], b.to_string());
    assert!(flagged[0].get("valid_to").is_some());
}
