//! Workflow references, backlog 41d7b27a (the half after `invokes` and
//! `depends_on` landed).
//!
//! Before: `related_to` was no relationship any tool wrote, and
//! `link_alternative` took claims only (its endpoint types were not
//! caller-controllable). These drive the tools on the stdio path against workflows stored
//! through `store_workflow`, the rows a live plan reads.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_alternative::do_link_alternative;
use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkAlternativeParams, LinkHierarchicalParams, StoreWorkflowParams};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

async fn store(server: &epigraph_mcp::EpiGraphMcpFull, steps: &[&str]) -> Uuid {
    let viewer = own_viewer(server).await;
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(stdio_public_tenancy(server).await),
            goal: format!("workflow reference reader probe {}", Uuid::new_v4()),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
            force_new: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    parse_uuid_field(&first_text(&stored), "workflow_id")
}

/// In-force `relationship` edges between `a` and `b`, in EITHER direction.
async fn pair_edges(pool: &PgPool, a: Uuid, b: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges \
          WHERE ((source_id = $1 AND target_id = $2) OR (source_id = $2 AND target_id = $1)) \
            AND relationship = $3 AND (valid_to IS NULL OR valid_to > now())",
    )
    .bind(a)
    .bind(b)
    .bind(relationship)
    .fetch_one(pool)
    .await
    .expect("count edges")
}

fn link(
    source: Uuid,
    source_type: &str,
    target: Uuid,
    target_type: &str,
    relationship: &str,
) -> LinkHierarchicalParams {
    LinkHierarchicalParams {
        source_claim_id: source.to_string(),
        target_claim_id: target.to_string(),
        relationship: relationship.to_string(),
        source_type: Some(source_type.to_string()),
        target_type: Some(target_type.to_string()),
        ..Default::default()
    }
}

fn rivals(a: Uuid, b: Uuid) -> LinkAlternativeParams {
    LinkAlternativeParams {
        claim_a: a.to_string(),
        claim_b: b.to_string(),
        source_type: Some("workflow".to_string()),
        target_type: Some("workflow".to_string()),
        ..Default::default()
    }
}

/// A server whose stdio agent is a DIFFERENT declared signer from
/// `build_scoped_test_server`'s, on the same database.
fn outsider_server(pool: PgPool, scoped: epigraph_db::ScopedPool) -> epigraph_mcp::EpiGraphMcpFull {
    let signer = epigraph_crypto::AgentSigner::from_bytes(&[0x5C; 32]).expect("signer");
    let embedder =
        epigraph_mcp::embed::McpEmbedder::new(pool.clone(), None).with_scoped_pool(scoped.clone());
    epigraph_mcp::EpiGraphMcpFull::new(pool, signer, embedder, false).with_scoped_pool(scoped)
}

/// The stdio server's own viewer: it reads the group rows its agent writes.
async fn own_viewer(server: &epigraph_mcp::EpiGraphMcpFull) -> epigraph_db::visibility::Viewer {
    epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer")
}

async fn make_private(pool: &PgPool, workflow: Uuid) -> Uuid {
    sqlx::query_scalar(
        "UPDATE workflows SET visibility = 'group' WHERE id = $1 RETURNING owner_group_id",
    )
    .bind(workflow)
    .fetch_one(pool)
    .await
    .expect("make the workflow group-private in its owner group")
}

/// `related_to` is a loose, symmetric see-also between two workflows: one
/// edge per unordered pair, so naming the pair the other way round returns
/// the same edge. It links workflows only, refuses a group-private workflow
/// (it would be stored public), and takes the workflow-source authority gate.
#[sqlx::test(migrations = "../../migrations")]
async fn related_to_is_one_symmetric_reference_between_public_workflows(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["w1 step"]).await;
    let w2 = store(&server, &["w2 step"]).await;

    let first = do_link_hierarchical(
        &server,
        &viewer,
        link(w1, "workflow", w2, "workflow", "related_to"),
        None,
    )
    .await
    .expect("W1 related_to W2 is written");
    let first = first_text(&first);
    assert_eq!(first["created"], Value::Bool(true), "{first}");
    let again = do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", w1, "workflow", "related_to"),
        None,
    )
    .await
    .expect("W2 related_to W1 is the same reference");
    let again = first_text(&again);
    assert_eq!(again["created"], Value::Bool(false), "{again}");
    assert_eq!(again["edge_id"], first["edge_id"], "one edge per pair");
    assert_eq!(pair_edges(&pool, w1, w2, "related_to").await, 1);
    // Migration 353 backs the dedup: a second in-force row for the pair (what
    // two concurrent writers past the in-statement guard would insert) is
    // refused by the unique index, in either order.
    let dup = sqlx::query(
        "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship) \
         VALUES ($1, 'workflow', $2, 'workflow', 'related_to')",
    )
    .bind(w2)
    .bind(w1)
    .execute(&pool)
    .await
    .expect_err("a second related_to for the pair violates the symmetric index");
    assert!(
        dup.to_string().contains("edges_related_to_symmetric_uniq"),
        "{dup}"
    );
    let types: (String, String) = sqlx::query_as(
        "SELECT source_type::text, target_type::text FROM edges WHERE id = $1::uuid",
    )
    .bind(first["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the edge");
    assert_eq!(
        (types.0.as_str(), types.1.as_str()),
        ("workflow", "workflow")
    );

    // Claims are not linked by it.
    let a = seed_claim(&pool, "related a", 0.5).await;
    let b = seed_claim(&pool, "related b", 0.5).await;
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "claim", b, "claim", "related_to"),
        None,
    )
    .await
    .expect_err("related_to between claims is refused");
    assert!(
        err.message.contains("does not link claim -> claim"),
        "{}",
        err.message
    );
    assert_eq!(pair_edges(&pool, a, b, "related_to").await, 0);

    // A group-private workflow, either end.
    let private = store(&server, &["private step"]).await;
    make_private(&pool, private).await;
    for (s, t) in [(w1, private), (private, w1)] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "related_to"),
            None,
        )
        .await
        .expect_err("a related_to touching a private workflow is refused");
        assert!(err.message.contains("is not public"), "{}", err.message);
    }
    assert_eq!(pair_edges(&pool, w1, private, "related_to").await, 0);

    // Another agent with no authority over the source workflow.
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let w3 = store(&server, &["w3 step"]).await;
    let err = do_link_hierarchical(
        &outsider,
        &outsider_viewer,
        link(w3, "workflow", w1, "workflow", "related_to"),
        None,
    )
    .await
    .expect_err("an outsider cannot attach a see-also to another agent's workflow");
    assert!(err.message.contains("submitter"), "{}", err.message);
    assert_eq!(pair_edges(&pool, w3, w1, "related_to").await, 0);
}

/// Two rival workflows reaching the same goal are an `alternative_of` pair,
/// written by `link_alternative` with both endpoint types `workflow`: one edge
/// per unordered pair, typed workflow -> workflow. A mixed pair, a private
/// workflow and a caller without authority over `claim_a`'s workflow are each
/// refused with nothing written; the claim pair (the default) is unchanged.
#[sqlx::test(migrations = "../../migrations")]
async fn link_alternative_marks_two_rival_workflows(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let viewer = own_viewer(&server).await;
    let w1 = store(&server, &["route one"]).await;
    let w2 = store(&server, &["route two"]).await;

    let first = do_link_alternative(&server, &viewer, rivals(w1, w2), None)
        .await
        .expect("two rival workflows are linked");
    let first = first_text(&first);
    assert_eq!(first["created"], Value::Bool(true), "{first}");
    let again = do_link_alternative(&server, &viewer, rivals(w2, w1), None)
        .await
        .expect("the reverse order is the same pair");
    let again = first_text(&again);
    assert_eq!(again["created"], Value::Bool(false), "{again}");
    assert_eq!(again["edge_id"], first["edge_id"]);
    assert_eq!(pair_edges(&pool, w1, w2, "alternative_of").await, 1);
    let types: (String, String) = sqlx::query_as(
        "SELECT source_type::text, target_type::text FROM edges WHERE id = $1::uuid",
    )
    .bind(first["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the edge");
    assert_eq!(
        (types.0.as_str(), types.1.as_str()),
        ("workflow", "workflow")
    );

    // A mixed pair.
    let claim = seed_claim(&pool, "a claim, not a workflow", 0.5).await;
    let mut mixed = rivals(w1, claim);
    mixed.target_type = Some("claim".to_string());
    let err = do_link_alternative(&server, &viewer, mixed, None)
        .await
        .expect_err("a workflow and a claim are no alternative pair");
    assert!(
        err.message.contains("workflow <-> workflow"),
        "{}",
        err.message
    );
    assert_eq!(pair_edges(&pool, w1, claim, "alternative_of").await, 0);

    // A workflow id that names no workflow (a claim's id) is not found.
    let err = do_link_alternative(&server, &viewer, rivals(w1, claim), None)
        .await
        .expect_err("a claim id is no workflow");
    assert!(err.message.contains("not found"), "{}", err.message);

    // A group-private workflow, either end.
    let private = store(&server, &["private route"]).await;
    make_private(&pool, private).await;
    for (a, b) in [(w1, private), (private, w1)] {
        let err = do_link_alternative(&server, &viewer, rivals(a, b), None)
            .await
            .expect_err("an alternative touching a private workflow is refused");
        assert!(err.message.contains("is not public"), "{}", err.message);
    }
    assert_eq!(pair_edges(&pool, w1, private, "alternative_of").await, 0);

    // Another agent with no authority over claim_a's workflow.
    let outsider = outsider_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let outsider_viewer = own_viewer(&outsider).await;
    let w3 = store(&server, &["route three"]).await;
    let err = do_link_alternative(&outsider, &outsider_viewer, rivals(w3, w1), None)
        .await
        .expect_err("an outsider cannot mark another agent's workflow as a rival");
    assert!(err.message.contains("submitter"), "{}", err.message);
    assert_eq!(pair_edges(&pool, w3, w1, "alternative_of").await, 0);

    // The default claim pair still works.
    let c1 = seed_claim(&pool, "rival claim one", 0.5).await;
    let c2 = seed_claim(&pool, "rival claim two", 0.5).await;
    do_link_alternative(
        &server,
        &viewer,
        LinkAlternativeParams {
            claim_a: c1.to_string(),
            claim_b: c2.to_string(),
            ..Default::default()
        },
        None,
    )
    .await
    .expect("a claim pair is linked as before");
    assert_eq!(pair_edges(&pool, c1, c2, "alternative_of").await, 1);
}
