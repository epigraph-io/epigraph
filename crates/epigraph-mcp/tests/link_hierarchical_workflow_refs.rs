//! `link_hierarchical`'s typed endpoints and workflow references (backlogs
//! 03d87e3a and 41d7b27a).
//!
//! Before: both endpoints were claims and not caller-controllable, so a
//! dropped `workflow -executes-> claim` edge could not be repaired from MCP,
//! and no tool wrote a workflow-to-workflow reference (`invokes`,
//! `depends_on`). These drive `do_link_hierarchical` on the stdio path
//! against workflows stored through `store_workflow`, the same rows a live
//! plan reads.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;
use common::*;

use epigraph_mcp::tools::link_hierarchical::do_link_hierarchical;
use epigraph_mcp::types::{LinkHierarchicalParams, StoreWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

async fn store(server: &epigraph_mcp::EpiGraphMcpFull, steps: &[&str]) -> Uuid {
    let viewer = epigraph_mcp::tools::viewer::request_viewer(server, None)
        .await
        .expect("stdio viewer");
    let stored = epigraph_mcp::tools::workflows::store_workflow(
        server,
        &viewer,
        StoreWorkflowParams {
            tenancy: Some(stdio_public_tenancy(server).await),
            goal: format!("workflow reference probe {}", Uuid::new_v4()),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
        None,
    )
    .await
    .expect("store_workflow");
    parse_uuid_field(&first_text(&stored), "workflow_id")
}

async fn step_claim(pool: &PgPool, workflow: Uuid, content: &str) -> (Uuid, Uuid) {
    sqlx::query_as(
        "SELECT e.id, c.id FROM edges e JOIN claims c ON c.id = e.target_id \
         WHERE e.source_id = $1 AND e.relationship = 'executes' AND c.content = $2 \
           AND e.valid_to IS NULL",
    )
    .bind(workflow)
    .bind(content)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("executes edge for {content:?}: {e}"))
}

async fn in_force(pool: &PgPool, source: Uuid, target: Uuid, relationship: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM edges WHERE source_id = $1 AND target_id = $2 \
           AND relationship = $3 AND (valid_to IS NULL OR valid_to > now())",
    )
    .bind(source)
    .bind(target)
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

/// The 03d87e3a incident shape: a workflow's `executes` edge to a live step
/// claim is gone (retracted here), the claims are intact, and the repair must
/// be possible from MCP. The restored row is a `workflow -> claim` edge, typed
/// as such, and the plan reads the step again.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dropped_executes_edge_is_repaired_from_mcp(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let workflow = store(&server, &["gather inputs", "publish output"]).await;
    let (dropped, step) = step_claim(&pool, workflow, "publish output").await;
    sqlx::query("UPDATE edges SET valid_to = now() WHERE id = $1")
        .bind(dropped)
        .execute(&pool)
        .await
        .expect("drop the executes edge");
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 0);

    let mut params = link(workflow, "workflow", step, "claim", "executes");
    params.properties = Some(serde_json::json!({"plan_index": 1}));
    let repaired = do_link_hierarchical(&server, &viewer, params, None)
        .await
        .expect("link_hierarchical repairs a workflow -> claim executes edge");
    let repaired = first_text(&repaired);
    assert_eq!(repaired["created"], serde_json::json!(true), "{repaired}");

    let (source_type, target_type, plan_index): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT source_type, target_type, (properties->>'plan_index')::bigint FROM edges \
         WHERE id = $1::uuid AND valid_to IS NULL",
    )
    .bind(repaired["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("the repaired edge is in force");
    assert_eq!(
        (source_type.as_str(), target_type.as_str()),
        ("workflow", "claim")
    );
    assert_eq!(plan_index, Some(1));
    assert_eq!(in_force(&pool, workflow, step, "executes").await, 1);
}

/// The type pair is the relationship's, not the caller's: `executes` from a
/// claim, and an unregistered type, are refused with nothing written.
#[sqlx::test(migrations = "../../migrations")]
async fn executes_refuses_a_claim_source_and_unknown_types(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let a = seed_claim(&pool, "not a workflow", 0.5).await;
    let b = seed_claim(&pool, "a step", 0.5).await;

    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "claim", b, "claim", "executes"),
        None,
    )
    .await
    .expect_err("executes from a claim is refused");
    assert!(
        err.message.contains("does not link claim -> claim"),
        "{}",
        err.message
    );
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(a, "no_such_type", b, "claim", "executes"),
        None,
    )
    .await
    .expect_err("an unregistered type is refused");
    assert!(
        err.message.contains("not a registered entity type"),
        "{}",
        err.message
    );
    // The document-structure relationships stay claim to claim.
    let w = store(&server, &["only step"]).await;
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w, "workflow", b, "claim", "decomposes_to"),
        None,
    )
    .await
    .expect_err("decomposes_to from a workflow is refused");
    assert!(err.message.contains("does not link"), "{}", err.message);
    assert_eq!(in_force(&pool, a, b, "executes").await, 0);
    assert_eq!(in_force(&pool, w, b, "decomposes_to").await, 0);
}

/// `depends_on` is a prerequisite: `W1 depends_on W2` then `W2 depends_on W1`
/// is a cycle and the second is refused; a third workflow closing a longer
/// loop is refused too.
#[sqlx::test(migrations = "../../migrations")]
async fn depends_on_refuses_a_cycle(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w1 = store(&server, &["w1 step"]).await;
    let w2 = store(&server, &["w2 step"]).await;
    let w3 = store(&server, &["w3 step"]).await;

    for (s, t) in [(w1, w2), (w2, w3)] {
        let ok = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "depends_on"),
            None,
        )
        .await
        .expect("an acyclic depends_on is written");
        assert_eq!(first_text(&ok)["created"], serde_json::json!(true));
    }
    for (s, t) in [(w2, w1), (w3, w1)] {
        let err = do_link_hierarchical(
            &server,
            &viewer,
            link(s, "workflow", t, "workflow", "depends_on"),
            None,
        )
        .await
        .expect_err("a depends_on closing a cycle is refused");
        assert!(
            err.message.contains("would close a cycle"),
            "{}",
            err.message
        );
        assert_eq!(
            in_force(&pool, s, t, "depends_on").await,
            0,
            "nothing written"
        );
    }
}

/// `invokes` from a step claim belongs to the workflow executing that step:
/// `W1 -executes-> S1 -invokes-> W2` makes `W2 invokes W1` a cycle. A
/// workflow-level `invokes` keeps its `at_step`.
#[sqlx::test(migrations = "../../migrations")]
async fn invokes_through_a_step_claim_refuses_the_closing_edge(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let w1 = store(&server, &["call the sub-workflow"]).await;
    let w2 = store(&server, &["sub step"]).await;
    let (_, s1) = step_claim(&pool, w1, "call the sub-workflow").await;

    do_link_hierarchical(
        &server,
        &viewer,
        link(s1, "claim", w2, "workflow", "invokes"),
        None,
    )
    .await
    .expect("a step claim invokes a sub-workflow");
    let err = do_link_hierarchical(
        &server,
        &viewer,
        link(w2, "workflow", w1, "workflow", "invokes"),
        None,
    )
    .await
    .expect_err("W2 invokes W1 closes W1 -executes-> S1 -invokes-> W2");
    assert!(
        err.message.contains("would close a cycle"),
        "{}",
        err.message
    );
    assert_eq!(in_force(&pool, w2, w1, "invokes").await, 0);

    let mut params = link(w1, "workflow", w2, "workflow", "invokes");
    params.at_step = Some(0);
    let ok = do_link_hierarchical(&server, &viewer, params, None)
        .await
        .expect("W1 invokes W2 is acyclic");
    let at_step: Option<i64> = sqlx::query_scalar(
        "SELECT (properties->>'at_step')::bigint FROM edges WHERE id = $1::uuid",
    )
    .bind(first_text(&ok)["edge_id"].as_str().expect("edge_id"))
    .fetch_one(&pool)
    .await
    .expect("read at_step");
    assert_eq!(at_step, Some(0));

    let mut bad = link(w1, "workflow", w2, "workflow", "depends_on");
    bad.at_step = Some(0);
    let err = do_link_hierarchical(&server, &viewer, bad, None)
        .await
        .expect_err("at_step belongs to invokes only");
    assert!(err.message.contains("at_step"), "{}", err.message);
}
