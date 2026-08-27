//! Regression fixture for the per-node edge bound `traverse` acquired in
//! 63e4ddd (the cdd8d097 paper-node fix).
//!
//! That commit swapped `EdgeRepository::get_by_source` (no SQL `LIMIT`) for
//! `list_filtered` (mandatory `LIMIT`) and passed the tool's `node_limit` —
//! the bound on how many NODES may be reported — as the per-node edge-fetch
//! bound. Those two budgets are not interchangeable:
//!
//! * `list_filtered` truncates in SQL, i.e. BEFORE `min_truth` is evaluated in
//!   Rust (`tools/graph.rs`, the `if tv < min_truth { continue; }` arm).
//! * A below-threshold target hits that `continue` WITHOUT being pushed to
//!   `nodes`, so it never consumes node budget — the `nodes.len() >=
//!   node_limit` break cannot fire on its account, and the BFS instead drains
//!   its already-truncated queue.
//!
//! So a hub whose fan-out exceeds `limit` silently loses qualifying
//! neighbours. And because `edges.valid_from` has no column default
//! (migrations/001_initial_schema.sql:765) the `ORDER BY valid_from DESC NULLS
//! LAST, id` degenerates to `gen_random_uuid()` id order, making *which*
//! neighbours vanish effectively random in production.
//!
//! This is a pure claim->claim path — nothing to do with paper nodes — so the
//! fixture seeds only claims and claim->claim edges, and pins the edge ids
//! explicitly so the id-order tiebreak is deterministic rather than random.

mod common;

use common::{build_test_server, seed_claim};
use epigraph_mcp::tools::graph::traverse;
use epigraph_mcp::types::TraverseParams;
use rmcp::model::CallToolResult;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

fn body(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("at least one text content block");
    serde_json::from_str(&text).expect("valid JSON")
}

/// Insert a claim->claim edge with an EXPLICIT id.
///
/// `list_filtered` orders by `valid_from DESC NULLS LAST, id` and these rows
/// leave `valid_from` NULL, so the id is the whole sort key. Pinning it is
/// what makes "the qualifying neighbour sorts last, and is therefore the one a
/// `LIMIT` would cut" a deterministic assertion instead of a coin flip.
async fn insert_claim_edge_with_id(pool: &PgPool, id: Uuid, source: Uuid, target: Uuid) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES ($1, $2, 'claim', $3, 'claim', 'supports', '{}'::jsonb)",
    )
    .bind(id)
    .bind(source)
    .bind(target)
    .execute(pool)
    .await
    .expect("insert claim edge");
}

fn edge_id(nth: u8) -> Uuid {
    Uuid::from_bytes([0x13, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, nth])
}

/// A start claim with five neighbours — four below `min_truth`, one above —
/// and a `limit` of 2. The one qualifying neighbour sorts LAST by edge id, so
/// a per-node fetch bounded by `limit` cuts exactly the row that matters.
///
/// The four rejected neighbours never enter `nodes`, so they cannot be what
/// exhausts the node budget: `traverse` must still report the 0.95 claim.
#[sqlx::test(migrations = "../../migrations")]
async fn traverse_min_truth_keeps_qualifying_neighbour_beyond_the_node_limit(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let start = seed_claim(&pool, "fan-out bound: start", 0.9).await;
    let mut below = Vec::new();
    for i in 0..4u8 {
        below.push(seed_claim(&pool, &format!("fan-out bound: below {i}"), 0.10).await);
    }
    let above = seed_claim(&pool, "fan-out bound: above threshold", 0.95).await;

    // Edge ids 1..4 for the below-threshold targets, 9 for the qualifying one,
    // so the qualifying edge is last in `ORDER BY ... id` and a `LIMIT 2`
    // keeps only below-threshold rows.
    for (i, target) in below.iter().enumerate() {
        insert_claim_edge_with_id(&pool, edge_id(i as u8 + 1), start, *target).await;
    }
    insert_claim_edge_with_id(&pool, edge_id(9), start, above).await;

    // Sanity: all five rows are in the table, so a miss below is the tool's
    // bound, not a failed seed.
    let raw: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1")
        .bind(start)
        .fetch_one(&pool)
        .await
        .expect("count seeded edges");
    assert_eq!(raw, 5, "fixture must seed exactly five outgoing edges");

    let result = traverse(
        &server,
        TraverseParams {
            start_id: start.to_string(),
            max_depth: Some(1),
            relationship: None,
            min_truth: Some(0.5),
            limit: Some(2),
        },
    )
    .await
    .expect("traverse");

    let json = body(&result);
    let ids: Vec<&str> = json["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .filter_map(|n| n["id"].as_str())
        .collect();

    assert!(
        ids.contains(&above.to_string().as_str()),
        "traverse(min_truth=0.5) must report the 0.95 neighbour: the four \
         below-threshold neighbours are skipped without consuming node budget, \
         so the per-node edge fetch must not be sized by `limit`; got {json}"
    );
    for (i, rejected) in below.iter().enumerate() {
        assert!(
            !ids.contains(&rejected.to_string().as_str()),
            "min_truth must still exclude below-threshold neighbour {i}; got {json}"
        );
    }
    assert_eq!(
        json["edges"].as_array().map(Vec::len),
        Some(5),
        "the full fan-out must be reported, not `limit` of it; got {json}"
    );
}

/// The same decoupling without `min_truth` in the picture: `limit` bounds the
/// reported NODES, and must not silently bound the edges walked out of a
/// single node. With `limit: 1` the BFS reports only the start claim, but its
/// three outgoing edges are all still reported.
#[sqlx::test(migrations = "../../migrations")]
async fn traverse_reports_full_fan_out_when_node_limit_is_one(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let start = seed_claim(&pool, "fan-out bound: node-limit start", 0.8).await;
    for i in 0..3u8 {
        let target = seed_claim(&pool, &format!("fan-out bound: neighbour {i}"), 0.8).await;
        insert_claim_edge_with_id(&pool, edge_id(0x20 + i), start, target).await;
    }

    let result = traverse(
        &server,
        TraverseParams {
            start_id: start.to_string(),
            max_depth: Some(1),
            relationship: None,
            min_truth: None,
            limit: Some(1),
        },
    )
    .await
    .expect("traverse");

    let json = body(&result);
    assert_eq!(
        json["nodes"].as_array().map(Vec::len),
        Some(1),
        "`limit` must still cap the reported node set; got {json}"
    );
    assert_eq!(
        json["edges"].as_array().map(Vec::len),
        Some(3),
        "`limit` is a node budget, not a per-node edge budget; got {json}"
    );
}
