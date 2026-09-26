//! `get_neighborhood` and `traverse` on non-claim nodes (backlogs cdd8d097 +
//! aedde855, G9).
//!
//! Both tools read edges with `EdgeRepository::get_by_source/get_by_target(..,
//! "claim")`, so a paper, workflow or agent node returned 0 edges, and
//! `traverse` typed every non-claim node 'unknown'. The fixtures come from the
//! REAL write paths — `do_ingest_document` for a paper (paper -asserts-> claim)
//! and `store_workflow` for a workflow (workflow -executes-> claim) — so the
//! endpoint types under test are the ones production records.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_ingest::schema::DocumentExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::types::StoreWorkflowParams;
use sqlx::PgPool;
use uuid::Uuid;

const PAPER: &str = r#"{
  "source": {
    "title": "G9 graph read paper",
    "doi": "10.1234/g9-graph-read",
    "source_type": "Paper",
    "authors": [{"name": "Alice Author", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "G9 thesis about graph reads",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Intro",
    "paragraphs": [{
      "text": "G9 paragraph for the graph read test",
      "atoms": ["G9 atom for the graph read test"],
      "generality": [3],
      "confidence": 0.8
    }]
  }],
  "relationships": []
}"#;

async fn neighborhood(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    node: Uuid,
    direction: &str,
) -> serde_json::Value {
    first_text(
        &tools::graph::get_neighborhood(
            server,
            viewer,
            serde_json::from_value(serde_json::json!({
                "node_id": node.to_string(),
                "direction": direction,
                "limit": 200,
            }))
            .unwrap(),
        )
        .await
        .expect("get_neighborhood"),
    )
}

async fn traverse(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    start: Uuid,
) -> serde_json::Value {
    first_text(
        &tools::graph::traverse(
            server,
            viewer,
            serde_json::from_value(serde_json::json!({
                "start_id": start.to_string(),
                "max_depth": 1,
                "limit": 100,
            }))
            .unwrap(),
        )
        .await
        .expect("traverse"),
    )
}

fn edges_with(n: &serde_json::Value, relationship: &str) -> usize {
    n["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .filter(|e| e["relationship"] == relationship)
        .count()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_paper_node_has_a_neighborhood_and_a_walk(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let extraction: DocumentExtraction = serde_json::from_str(PAPER).unwrap();
    let out = tools::ingestion::do_ingest_document(&server, &viewer, &extraction)
        .await
        .expect("ingest");
    let paper: Uuid = first_text(&out)["paper_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // MEASURED ground truth, independent of the tools under test.
    let (asserts,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND source_type = 'paper' \
         AND relationship = 'asserts'",
    )
    .bind(paper)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        asserts >= 3,
        "fixture: the paper asserts its claims ({asserts})"
    );

    let n = neighborhood(&server, &viewer, paper, "both").await;
    assert_eq!(n["node_types"], serde_json::json!(["paper"]), "{n}");
    assert_eq!(
        edges_with(&n, "asserts") as i64,
        asserts,
        "every asserts edge of the paper must come back: {n}"
    );

    let t = traverse(&server, &viewer, paper).await;
    let nodes = t["nodes"].as_array().unwrap();
    let start = nodes
        .iter()
        .find(|x| x["id"] == paper.to_string())
        .expect("start node");
    assert_eq!(start["node_type"], "paper", "{t}");
    assert!(
        nodes
            .iter()
            .any(|x| x["node_type"] == "claim" && x["depth"] == 1),
        "the walk must leave the paper over its asserts edges: {t}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_workflow_nodes_executes_edge_is_visible_with_direction_both(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let stored = first_text(
        &tools::workflows::store_workflow(
            &server,
            &viewer,
            StoreWorkflowParams {
                goal: format!("g9 workflow neighborhood probe {}", Uuid::new_v4()),
                steps: vec!["first g9 step".into(), "second g9 step".into()],
                prerequisites: None,
                expected_outcome: None,
                confidence: None,
                tags: None,
            },
        )
        .await
        .expect("store_workflow"),
    );
    let workflow: Uuid = stored["workflow_id"].as_str().unwrap().parse().unwrap();

    let (executes,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND source_type = 'workflow' \
         AND relationship = 'executes'",
    )
    .bind(workflow)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        executes >= 1,
        "fixture: store_workflow wrote executes edges"
    );

    let n = neighborhood(&server, &viewer, workflow, "both").await;
    assert_eq!(n["node_types"], serde_json::json!(["workflow"]), "{n}");
    assert_eq!(
        edges_with(&n, "executes") as i64,
        executes,
        "direction=both must return the workflow's executes edges: {n}"
    );

    let t = traverse(&server, &viewer, workflow).await;
    let start = t["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == workflow.to_string())
        .cloned()
        .expect("start node");
    assert_eq!(start["node_type"], "workflow", "{t}");
    assert!(
        t["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["relationship"] == "executes"),
        "the walk must follow executes: {t}"
    );
}

/// REGRESSION GUARD for the viewer splice, not a fail-before test (pre-fix the
/// paper returned 0 edges to everyone): once the node's type is resolved, an
/// edge the caller cannot see must still be neither returned nor used to type
/// the node, on either tool.
#[sqlx::test(migrations = "../../migrations")]
async fn a_private_edge_is_not_returned_to_a_stranger(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let public = fixture::public_viewer(&pool).await;
    let extraction: DocumentExtraction = serde_json::from_str(PAPER).unwrap();
    let out = tools::ingestion::do_ingest_document(&server, &public, &extraction)
        .await
        .expect("ingest");
    let paper: Uuid = first_text(&out)["paper_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        edges_with(
            &neighborhood(&server, &public, paper, "both").await,
            "asserts"
        ) > 0,
        "calibration: the public viewer sees the edges before they are privatised"
    );

    // Force every edge touching the paper private to a group the public viewer
    // is not in. An UPDATE of the tenancy columns alone does not fire migration
    // 070's trigger (see `viewer_fixture::seed_edge_owned_by`).
    let (_agent, group) = fixture::seed_agent_with_group(&pool, "g9-stranger-test").await;
    let changed = sqlx::query(
        "UPDATE edges SET visibility = 'group', owner_group_id = $2, co_owner_group_id = NULL \
         WHERE source_id = $1 OR target_id = $1",
    )
    .bind(paper)
    .bind(group)
    .execute(&pool)
    .await
    .expect("privatise the paper's edges")
    .rows_affected();
    assert!(changed > 0);

    let n = neighborhood(&server, &public, paper, "both").await;
    assert_eq!(n["edge_count"], 0, "{n}");
    assert_eq!(n["node_types"], serde_json::json!([]), "{n}");
    let t = traverse(&server, &public, paper).await;
    assert_eq!(t["edges"], serde_json::json!([]), "{t}");
}
