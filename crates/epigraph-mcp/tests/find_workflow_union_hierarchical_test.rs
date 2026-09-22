//! `find_workflow` must be able to return what `store_workflow` produced
//! (backlog 18168514).
//!
//! The two tools sat on disjoint stores. `store_workflow` writes a row in the
//! hierarchical `workflows` table and, via
//! `epigraph-ingest-executor/src/workflow.rs`, labels every claim it creates
//! `["claim", kind]` where kind is `workflow_thesis` / `workflow_step` — never
//! `workflow`. Both of `find_workflow`'s passes were scoped to the `workflow`
//! label, so a workflow created via `store_workflow` was permanently invisible
//! to `find_workflow` at any similarity, while `get_claim` on the returned id
//! 404s because a `workflows` row is not a claim. That combination is a silent
//! trap: `find_workflow(goal: "…")` is the long-standing convention in epiclaw
//! scheduled-task prompts.

#[rustfmt::skip]
use epigraph_mcp::tools::workflows::__test_only::find_workflow_with_pgvec;
use epigraph_mcp::types::{FindWorkflowParams, StoreWorkflowParams};
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

#[path = "viewer_fixture.rs"]
mod fixture;

/// A 1536-d pgvector literal with all weight on one component, so two such
/// vectors on different components are orthogonal (cosine similarity 0) and
/// one on the same component is identical (similarity 1).
fn axis_pgvec_1536(axis: usize) -> String {
    let mut v = vec!["0.0"; 1536];
    v[axis] = "1.0";
    format!("[{}]", v.join(","))
}

async fn store(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    goal: &str,
    steps: &[&str],
) -> Uuid {
    let result = epigraph_mcp::tools::workflows::store_workflow(
        server,
        viewer,
        StoreWorkflowParams {
            goal: goal.to_string(),
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            prerequisites: None,
            expected_outcome: None,
            confidence: None,
            tags: None,
        },
    )
    .await
    .expect("store_workflow");
    let body = first_text(&result);
    Uuid::parse_str(body["workflow_id"].as_str().expect("workflow_id"))
        .expect("workflow_id is a UUID")
}

/// The core regression: a workflow written by `store_workflow` must come back
/// from `find_workflow`, carrying its real steps.
///
/// Drives the ILIKE leg (the test embedder has no API key, so `generate`
/// errors and the embedding legs are skipped) — which is the configuration a
/// deployment with a dead embedder also lands in.
#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_returns_a_workflow_that_store_workflow_created(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let goal = format!("cumulative theme maintenance probe {}", Uuid::new_v4());
    let steps = [
        "recall recent theme claims",
        "cluster without wipe_first",
        "record the outcome",
    ];
    let workflow_id = store(&server, &viewer, &goal, &steps).await;

    let result = epigraph_mcp::tools::workflows::find_workflow(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: goal.clone(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow");

    let arr = first_text(&result);
    let arr = arr.as_array().expect("result is an array").clone();
    let hit = arr
        .iter()
        .find(|r| r["workflow_id"].as_str() == Some(&workflow_id.to_string()))
        .unwrap_or_else(|| {
            panic!(
                "find_workflow must return the workflow store_workflow just \
                 created (id {workflow_id}); got {}",
                serde_json::to_string(&arr).unwrap()
            )
        });

    // Steps are the whole point of the result — see
    // `hierarchical_workflow_result`'s doc comment on the 2026-08-18 incident.
    let returned_steps: Vec<&str> = hit["steps"]
        .as_array()
        .expect("steps array")
        .iter()
        .map(|s| s.as_str().expect("step is a string"))
        .collect();
    assert_eq!(
        returned_steps, steps,
        "the hierarchical workflow's steps must be resolved from its `executes` \
         edges, in plan order — an empty or reordered array is the failure this \
         union exists to avoid"
    );
    assert_eq!(hit["goal"].as_str(), Some(goal.as_str()));
}

/// A hierarchical workflow whose steps cannot be resolved must be WITHHELD,
/// not returned with `steps: []`.
///
/// This is the guard against the union reintroducing the 2026-08-18 failure at
/// scale: `workflows` rows carry no inline steps, so a naive merge emits an
/// empty array for every step-less row. An agent told to "follow the
/// best-matching workflow steps" that receives `[]` does not stop — in the
/// recorded incident it fell back to a bare `theme_cluster` with
/// `wipe_first=true` and destroyed 76 themes.
#[sqlx::test(migrations = "../../migrations")]
async fn hierarchical_workflow_with_no_steps_is_withheld(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let goal = format!("stepless hierarchical probe {}", Uuid::new_v4());
    let workflow_id = store(&server, &viewer, &goal, &[]).await;

    // Precondition: the row really exists and really has no step claims, so a
    // "not returned" result below cannot be explained by the row being absent.
    let steps_map = epigraph_db::WorkflowRepository::step_texts_for_hierarchical(
        &pool,
        &viewer,
        &[workflow_id],
    )
    .await
    .expect("step lookup");
    assert!(
        steps_map.get(&workflow_id).is_none_or(Vec::is_empty),
        "precondition: this workflow must have no resolvable steps"
    );
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workflows WHERE id = $1)")
        .bind(workflow_id)
        .fetch_one(&pool)
        .await
        .expect("existence check");
    assert!(exists, "precondition: the workflows row was written");

    let result = epigraph_mcp::tools::workflows::find_workflow(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: goal.clone(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow");

    let body = first_text(&result);
    let arr = body.as_array().expect("result is an array");
    assert!(
        !arr.iter()
            .any(|r| r["workflow_id"].as_str() == Some(&workflow_id.to_string())),
        "a step-less hierarchical workflow must be withheld rather than \
         returned with an empty steps array; got {}",
        serde_json::to_string(arr).unwrap()
    );
    for r in arr {
        assert!(
            !r["steps"].as_array().is_some_and(Vec::is_empty),
            "no result may carry an empty steps array: {r}"
        );
    }
}

/// Ranking, not just presence: a closer hierarchical workflow must OUTRANK a
/// more distant flat workflow claim.
///
/// Appending the hierarchical leg after the flat leg had consumed the budget
/// would satisfy "find_workflow can return it" while changing nothing about
/// the behaviour the backlog actually measured — the flat store's two
/// content-free junk records outranking everything for theme-maintenance
/// queries. Here the flat claim is ORTHOGONAL to the query (similarity 0) and
/// the hierarchical row is IDENTICAL to it (similarity 1), so a correct merge
/// must put the hierarchical row first.
#[sqlx::test(migrations = "../../migrations")]
async fn closer_hierarchical_workflow_outranks_a_distant_flat_claim(pool: PgPool) {
    let server = build_test_server(pool.clone());
    let viewer = fixture::public_viewer(&pool).await;
    let query_pgvec = axis_pgvec_1536(0);

    // Flat workflow claim, embedded ORTHOGONALLY to the query.
    let agent_id = seed_agent(&pool).await;
    let flat_id = Uuid::new_v4();
    let hash: Vec<u8> = flat_id
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(32)
        .collect();
    let flat_content = serde_json::json!({
        "goal": "unrelated flat workflow",
        "steps": ["step-a", "step-b", "step-c"],
    })
    .to_string();
    sqlx::query(
        "INSERT INTO claims \
         (id, content, content_hash, truth_value, agent_id, is_current, labels, embedding) \
         VALUES ($1, $2, $3, 0.9, $4, true, ARRAY['workflow']::text[], $5::vector)",
    )
    .bind(flat_id)
    .bind(&flat_content)
    .bind(&hash)
    .bind(agent_id)
    .bind(axis_pgvec_1536(7))
    .execute(&pool)
    .await
    .expect("seed flat workflow claim");

    // Hierarchical workflow, embedded EXACTLY on the query vector. The test
    // embedder cannot generate, so `store_workflow`'s own `set_goal_embedding`
    // is a no-op and we set the vector explicitly.
    let hier_goal = format!("nightly cumulative theme maintenance {}", Uuid::new_v4());
    let hier_id = store(
        &server,
        &viewer,
        &hier_goal,
        &["recall theme claims", "cluster incrementally"],
    )
    .await;
    let unit: Vec<f32> = (0..1536).map(|i| if i == 0 { 1.0 } else { 0.0 }).collect();
    epigraph_db::WorkflowRepository::set_goal_embedding(&pool, hier_id, &unit)
        .await
        .expect("set goal embedding");

    // Query text matches NEITHER record textually, so anything returned here
    // arrived through the vector path rather than either ILIKE leg.
    let result = find_workflow_with_pgvec(
        &server,
        &viewer,
        FindWorkflowParams {
            goal: "qqzzx_union_rank_probe".to_string(),
            limit: Some(5),
            min_truth: Some(0.0),
        },
        Some(query_pgvec),
    )
    .await
    .expect("find_workflow_with_pgvec");

    let body = first_text(&result);
    let arr = body.as_array().expect("result is an array");
    assert!(
        arr.len() >= 2,
        "both stores must contribute a candidate; got {}",
        serde_json::to_string(arr).unwrap()
    );
    assert_eq!(
        arr[0]["workflow_id"].as_str(),
        Some(hier_id.to_string().as_str()),
        "the hierarchical row is identical to the query vector and the flat \
         claim is orthogonal to it, so a merge that ranks by similarity must \
         put the hierarchical row FIRST. Appending the hierarchical leg after \
         the flat leg would leave this order unchanged and the measured \
         failure unfixed. Got {}",
        serde_json::to_string(arr).unwrap()
    );
    assert!(
        arr[0]["similarity"].as_f64().unwrap_or(0.0) > 0.99,
        "the top hit must carry the real cosine similarity, not the 0.0 the \
         ILIKE legs emit"
    );
    assert!(
        arr.iter()
            .any(|r| r["workflow_id"].as_str() == Some(&flat_id.to_string())),
        "the flat store must still be searched — the union adds a store, it \
         does not replace one"
    );
}
