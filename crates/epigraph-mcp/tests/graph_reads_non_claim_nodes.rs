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
    let out = tools::ingestion::do_ingest_document(&server, &viewer, &extraction, None)
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
            None,
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
    let out = tools::ingestion::do_ingest_document(&server, &public, &extraction, None)
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

// ── traverse emits only edges between returned nodes (backlog cdd8d097, U010) ──
//
// `traverse` capped NODES at `limit` but pushed EVERY outgoing edge of each
// expanded node, admitted target or not. Live: traverse(paper, asserts,
// max_depth=1, limit=3) returned 3 nodes and 4,561 edges (744,289 chars, over
// the MCP output limit). These fixtures reproduce that shape at small scale
// through the real ingest path.

/// A paper whose one paragraph carries 8 atoms, so it asserts well over the
/// `limit: 3` the live repro used.
const HIGH_DEGREE_PAPER: &str = r#"{
  "source": {
    "title": "U010 high degree traverse paper",
    "doi": "10.1234/u010-traverse-edge-cap",
    "source_type": "Paper",
    "authors": [{"name": "Bob Author", "affiliations": [], "roles": ["author"]}]
  },
  "thesis": "U010 thesis about bounded traverse edges",
  "thesis_derivation": "TopDown",
  "sections": [{
    "title": "Body",
    "paragraphs": [{
      "text": "U010 paragraph whose atoms fan out from the paper",
      "atoms": [
        "U010 atom one about edge caps",
        "U010 atom two about node admission",
        "U010 atom three about breadth first order",
        "U010 atom four about dangling targets",
        "U010 atom five about output limits",
        "U010 atom six about omitted counts",
        "U010 atom seven about min truth drops",
        "U010 atom eight about paper fan out"
      ],
      "generality": [3, 3, 3, 3, 3, 3, 3, 3],
      "confidence": 0.8
    }]
  }],
  "relationships": []
}"#;

async fn ingest_high_degree_paper(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
) -> Uuid {
    let extraction: DocumentExtraction = serde_json::from_str(HIGH_DEGREE_PAPER).unwrap();
    let out = tools::ingestion::do_ingest_document(server, viewer, &extraction, None)
        .await
        .expect("ingest");
    first_text(&out)["paper_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// MEASURED ground truth, independent of the tool under test.
async fn paper_asserts_targets(pool: &PgPool, paper: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar(
        "SELECT target_id FROM edges WHERE source_id = $1 AND source_type = 'paper' \
         AND relationship = 'asserts'",
    )
    .bind(paper)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn traverse_with(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    params: serde_json::Value,
) -> serde_json::Value {
    first_text(
        &tools::graph::traverse(server, viewer, serde_json::from_value(params).unwrap())
            .await
            .expect("traverse"),
    )
}

fn node_ids(t: &serde_json::Value) -> std::collections::HashSet<String> {
    t["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|n| n["id"].as_str().expect("node id").to_string())
        .collect()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_high_degree_paper_walk_returns_only_edges_between_returned_nodes(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let paper = ingest_high_degree_paper(&server, &viewer).await;

    let asserts = paper_asserts_targets(&pool, paper).await.len();
    assert!(
        asserts > 3,
        "calibration: the paper must assert more claims than the node limit ({asserts})"
    );

    // The live repro's arguments.
    let t = traverse_with(
        &server,
        &viewer,
        serde_json::json!({
            "start_id": paper.to_string(),
            "relationship": "asserts",
            "max_depth": 1,
            "limit": 3,
        }),
    )
    .await;

    let nodes = node_ids(&t);
    assert_eq!(nodes.len(), 3, "the node cap holds: {t}");
    assert!(nodes.contains(&paper.to_string()), "start node: {t}");

    let edges = t["edges"].as_array().expect("edges");
    for e in edges {
        assert!(
            nodes.contains(e["source_id"].as_str().unwrap())
                && nodes.contains(e["target_id"].as_str().unwrap()),
            "edge {e} points outside the returned nodes {nodes:?} \
             ({} edges for {} nodes)",
            edges.len(),
            nodes.len()
        );
    }
    // Each admitted claim is reached by exactly one asserts edge from the paper.
    assert_eq!(edges.len(), 2, "{t}");
    assert_eq!(
        t["edges_omitted"],
        serde_json::json!(asserts - 2),
        "the response must say how many edges were left out: {t}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_min_truth_filtered_node_leaves_no_dangling_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let paper = ingest_high_degree_paper(&server, &viewer).await;

    let targets = paper_asserts_targets(&pool, paper).await;
    assert!(
        targets.len() > 3,
        "calibration: fan-out ({})",
        targets.len()
    );

    // Refute ONE asserted claim, on both the DS cache (which `min_truth` reads
    // when present) and `truth_value` (its fallback), so it falls under the
    // gate whichever column is consulted.
    let refuted = targets[0];
    let changed = sqlx::query(
        "UPDATE claims SET truth_value = 0.01, belief = 0.01, plausibility = 0.01, \
         pignistic_prob = 0.01 WHERE id = $1",
    )
    .bind(refuted)
    .execute(&pool)
    .await
    .expect("refute one claim")
    .rows_affected();
    assert_eq!(changed, 1);

    let t = traverse_with(
        &server,
        &viewer,
        serde_json::json!({
            "start_id": paper.to_string(),
            "relationship": "asserts",
            "max_depth": 1,
            "limit": 100,
            "min_truth": 0.05,
        }),
    )
    .await;

    // Calibration: the gate dropped exactly the refuted claim and admitted the
    // rest, so a pass below cannot come from an empty or over-filtered walk.
    let nodes = node_ids(&t);
    assert!(
        !nodes.contains(&refuted.to_string()),
        "calibration: min_truth must drop the refuted claim: {t}"
    );
    assert_eq!(
        nodes.len(),
        targets.len(),
        "calibration: the paper plus every other asserted claim is admitted: {t}"
    );

    let edges = t["edges"].as_array().expect("edges");
    assert!(
        edges
            .iter()
            .all(|e| e["target_id"] != refuted.to_string() && e["source_id"] != refuted.to_string()),
        "no edge may point at the node min_truth dropped: {t}"
    );
    assert_eq!(edges.len(), targets.len() - 1, "{t}");
    assert_eq!(t["edges_omitted"], serde_json::json!(1), "{t}");
}

/// MEASURED ground truth: the public claim->claim edges (plan edges such as
/// `decomposes_to`) whose source AND target the paper asserts.
async fn edges_among_asserted_claims(pool: &PgPool, paper: Uuid) -> Vec<(Uuid, Uuid, String)> {
    sqlx::query_as(
        "SELECT e.source_id, e.target_id, e.relationship FROM edges e \
         WHERE e.source_type = 'claim' AND e.target_type = 'claim' \
           AND e.visibility = 'public' \
           AND e.source_id IN (SELECT target_id FROM edges WHERE source_id = $1 \
                               AND source_type = 'paper' AND relationship = 'asserts') \
           AND e.target_id IN (SELECT target_id FROM edges WHERE source_id = $1 \
                               AND source_type = 'paper' AND relationship = 'asserts')",
    )
    .bind(paper)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The filter must keep an edge between two RETURNED nodes even when its target
/// was already visited, i.e. a cross-edge in the BFS. A depth-2 walk from the
/// paper reaches every asserted claim at depth 1 over `asserts`, then follows
/// the claim->claim plan edges between them at depth 1 -> already-visited
/// targets. Emitting an edge only on a target's first visit would drop all of
/// those, and no depth-1 fan-out test can see it.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unclipped_depth_two_walk_keeps_edges_between_already_visited_nodes(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let paper = ingest_high_degree_paper(&server, &viewer).await;

    let cross = edges_among_asserted_claims(&pool, paper).await;
    assert!(
        !cross.is_empty(),
        "calibration: ingest must write claim->claim edges between asserted claims"
    );

    let t = traverse_with(
        &server,
        &viewer,
        serde_json::json!({
            "start_id": paper.to_string(),
            "max_depth": 2,
            "limit": 100,
        }),
    )
    .await;

    let nodes = node_ids(&t);
    assert!(
        nodes.len() < 100,
        "calibration: the walk must not reach the node cap ({}): {t}",
        nodes.len()
    );
    for (s, d, _) in &cross {
        assert!(
            nodes.contains(&s.to_string()) && nodes.contains(&d.to_string()),
            "calibration: both endpoints of {s} -> {d} must be returned: {t}"
        );
    }

    let returned: std::collections::HashSet<(String, String, String)> = t["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .map(|e| {
            (
                e["source_id"].as_str().unwrap().to_string(),
                e["target_id"].as_str().unwrap().to_string(),
                e["relationship"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for (s, d, rel) in &cross {
        assert!(
            returned.contains(&(s.to_string(), d.to_string(), rel.clone())),
            "edge {s} -{rel}-> {d} joins two returned nodes and must be returned: {t}"
        );
    }
    // Nothing was clipped (no node cap reached, no min_truth), so the field is
    // present and zero rather than absent.
    assert_eq!(t["edges_omitted"], serde_json::json!(0), "{t}");
}
