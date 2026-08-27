//! Regression fixture for backlog cdd8d097 — `get_neighborhood` and `traverse`
//! must resolve edges incident to NON-claim nodes.
//!
//! `tools/graph.rs` hardcodes `"claim"` as the entity type in all three edge
//! lookups (`get_by_source` twice, `get_by_target` once). Those repo methods
//! put the type straight into the WHERE clause (`source_type = $2`), so a
//! `paper -> claim` `asserts` edge — the edge every document ingestion writes,
//! and the exact relationship the tool's own `schemars` description advertises
//! ("Filter by relationship type (e.g. 'asserts', 'authored', ...)") — is
//! invisible. The tool does not error; it reports `edge_count: 0`, so a caller
//! cannot distinguish "paper has no neighbours" from "tool cannot see papers".
//!
//! These tests seed a real `papers` row (the `edges_validate_refs` trigger
//! requires one) plus claims, wire `paper --asserts--> claim` and
//! `claim --supports--> claim`, and assert the tools surface them.

mod common;

use common::{build_test_server, seed_agent, seed_claim};
use epigraph_mcp::tools::graph::{get_neighborhood, traverse};
use epigraph_mcp::types::{GetNeighborhoodParams, TraverseParams};
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

async fn seed_paper(pool: &PgPool, doi: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>("INSERT INTO papers (doi, title) VALUES ($1, $2) RETURNING id")
        .bind(doi)
        .bind("cdd8d097 paper-node fixture")
        .fetch_one(pool)
        .await
        .expect("seed paper")
}

async fn insert_edge(
    pool: &PgPool,
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
) {
    sqlx::query(
        "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, '{}'::jsonb)",
    )
    .bind(source)
    .bind(source_type)
    .bind(target)
    .bind(target_type)
    .bind(relationship)
    .execute(pool)
    .await
    .expect("insert edge");
}

/// A paper that asserts two claims must report two outgoing edges.
#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_sees_paper_asserts_edges(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let paper = seed_paper(&pool, "10.1234/cdd8d097-outgoing").await;
    let a = seed_claim(&pool, "cdd8d097 asserted claim A", 0.7).await;
    let b = seed_claim(&pool, "cdd8d097 asserted claim B", 0.7).await;

    insert_edge(&pool, paper, "paper", a, "claim", "asserts").await;
    insert_edge(&pool, paper, "paper", b, "claim", "asserts").await;

    // Sanity: the rows really are in the table, so a zero below is the tool's
    // filter, not a failed seed.
    let raw: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges WHERE source_id = $1")
        .bind(paper)
        .fetch_one(&pool)
        .await
        .expect("count seeded edges");
    assert_eq!(raw, 2, "fixture must seed exactly two paper->claim edges");

    let result = get_neighborhood(
        &server,
        GetNeighborhoodParams {
            node_id: paper.to_string(),
            relationship: None,
            direction: Some("outgoing".to_string()),
            limit: None,
        },
    )
    .await
    .expect("get_neighborhood");

    let json = body(&result);
    assert_eq!(
        json["edge_count"].as_u64(),
        Some(2),
        "get_neighborhood must resolve paper->claim `asserts` edges; got {json}"
    );
}

/// The incoming half of the same hardcode. `get_by_target(node, "claim")`
/// filters `target_type = 'claim'`, so it happens to find `paper --asserts-->
/// claim` when the *claim* is the node (control assertion below), but never
/// finds `agent --authored--> paper` when the *paper* is the node.
#[sqlx::test(migrations = "../../migrations")]
async fn get_neighborhood_sees_incoming_authored_edge_on_paper(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let paper = seed_paper(&pool, "10.1234/cdd8d097-incoming").await;
    let author = seed_agent(&pool).await;
    let claim = seed_claim(&pool, "cdd8d097 claim with a paper parent", 0.6).await;

    insert_edge(&pool, author, "agent", paper, "paper", "authored").await;
    insert_edge(&pool, paper, "paper", claim, "claim", "asserts").await;

    // Control: the claim-typed target still resolves today. This half is NOT
    // broken, and must stay working after the fix.
    let control = get_neighborhood(
        &server,
        GetNeighborhoodParams {
            node_id: claim.to_string(),
            relationship: None,
            direction: Some("incoming".to_string()),
            limit: None,
        },
    )
    .await
    .expect("get_neighborhood (control)");
    let control = body(&control);
    assert_eq!(
        control["edge_count"].as_u64(),
        Some(1),
        "control: incoming lookup on a claim already resolves its paper; got {control}"
    );

    let result = get_neighborhood(
        &server,
        GetNeighborhoodParams {
            node_id: paper.to_string(),
            relationship: None,
            direction: Some("incoming".to_string()),
            limit: None,
        },
    )
    .await
    .expect("get_neighborhood");

    let json = body(&result);
    assert_eq!(
        json["edge_count"].as_u64(),
        Some(1),
        "incoming lookup on a paper must surface its `authored` edge; got {json}"
    );
    assert_eq!(
        json["edges"][0]["source_type"].as_str(),
        Some("agent"),
        "the incoming edge's source_type must be `agent`; got {json}"
    );
}

/// BFS from a paper must walk paper->claim then claim->claim.
#[sqlx::test(migrations = "../../migrations")]
async fn traverse_from_paper_reaches_asserted_claims(pool: PgPool) {
    let server = build_test_server(pool.clone());

    let paper = seed_paper(&pool, "10.1234/cdd8d097-traverse").await;
    let a = seed_claim(&pool, "cdd8d097 traverse hop 1", 0.8).await;
    let b = seed_claim(&pool, "cdd8d097 traverse hop 2", 0.8).await;

    insert_edge(&pool, paper, "paper", a, "claim", "asserts").await;
    insert_edge(&pool, a, "claim", b, "claim", "supports").await;

    let result = traverse(
        &server,
        TraverseParams {
            start_id: paper.to_string(),
            max_depth: Some(2),
            relationship: None,
            min_truth: None,
            limit: None,
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
        ids.contains(&a.to_string().as_str()),
        "traverse from a paper must reach the claim it asserts; got {json}"
    );
    assert!(
        ids.contains(&b.to_string().as_str()),
        "traverse must continue claim->claim past the paper hop; got {json}"
    );
    assert_eq!(
        json["edges"].as_array().map(Vec::len),
        Some(2),
        "traverse must report both the asserts and the supports edge; got {json}"
    );
}
