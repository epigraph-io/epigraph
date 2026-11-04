//! MCP `get_workflow_plan`: the frozen-plan read on the MCP transport.
//!
//! The route-level behaviour (tenancy, integrity counts, a group writer's
//! reorder) is pinned on the production pool shape in
//! `epigraph-api/tests/workflow_frozen_plan_read.rs`. These tests pin what is
//! the MCP tool's own: that it reads as the caller's viewer, returns the same
//! plan and digest the vectors fix, answers not-found without naming anything
//! for a caller who can see none of the plan, and that the real
//! `deprecate_workflow` kill switch shows as the row's truth while the frozen
//! items and their digest stay exactly what was published.

#[path = "viewer_fixture.rs"]
mod fixture;

mod common;

use common::{build_scoped_test_server, first_text, seed_caller};
use epigraph_db::repos::privatization::PrivatizationRepository;
use epigraph_db::GroupRepository;
use epigraph_ingest::workflow::WorkflowExtraction;
use epigraph_mcp::tools;
use epigraph_mcp::types::{DeprecateWorkflowParams, GetWorkflowPlanParams, IngestWorkflowParams};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const VECTORS: &str = include_str!("../../epigraph-ingest/tests/fixtures/wfd1-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("the vectors file parses")
}

fn uuid_of(v: &Value) -> Uuid {
    v.as_str().expect("uuid string").parse().expect("uuid")
}

async fn ingest_vectors(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    token: &epigraph_auth::AuthContext,
) -> Uuid {
    let extraction: WorkflowExtraction =
        serde_json::from_value(vectors()["ingest"]["extraction"].clone()).expect("extraction");
    tools::workflow_ingest::ingest_workflow(
        server,
        viewer,
        IngestWorkflowParams {
            extraction,
            tenancy: None,
            embed: None,
        },
        Some(token),
    )
    .await
    .expect("ingest");
    uuid_of(&vectors()["ingest"]["workflow_id"])
}

async fn plan(
    server: &epigraph_mcp::EpiGraphMcpFull,
    viewer: &epigraph_db::visibility::Viewer,
    wf: Uuid,
) -> Result<Value, epigraph_mcp::errors::McpError> {
    let r = tools::workflow_plan::get_workflow_plan(
        server,
        viewer,
        GetWorkflowPlanParams {
            workflow_id: wf.to_string(),
        },
    )
    .await?;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    Ok(first_text(&r))
}

fn assert_items_are_the_vectors(p: &Value) {
    let items = p["items"].as_array().expect("items");
    let want = vectors()["ingest"]["plan"].as_array().unwrap().clone();
    assert_eq!(items.len(), want.len());
    for (got, want) in items.iter().zip(&want) {
        for key in ["plan_index", "level", "claim_id", "content", "content_hash"] {
            assert_eq!(got[key], want[key], "{key} of item {}", want["plan_index"]);
        }
    }
}

/// Another caller reads the public plan through the tool: the vectors' items,
/// order and digest, and the ingesting caller as the recorded submitter.
#[sqlx::test(migrations = "../../migrations")]
async fn the_tool_reads_the_vector_plan_and_digest(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest_vectors(&server, &viewer, &token).await;
    let (_other, _, other_viewer) = seed_caller(&pool, &["claims:read"]).await;

    let p = plan(&server, &other_viewer, wf).await.expect("plan");
    assert_items_are_the_vectors(&p);
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    assert_eq!(p["hidden_count"], json!(0));
    assert_eq!(p["unindexed_edges"], json!(0));
    assert_eq!(p["submitter"], json!(owner.to_string()));
}

/// `deprecate_workflow` writes the kill switch: the row reads 0.05 and the
/// thesis, phase and step claims are no longer current. The frozen items and
/// their digest are unchanged: deprecation retires, it never rewrites.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deprecated_workflow_reads_truth_0_05_with_its_frozen_items(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest_vectors(&server, &viewer, &token).await;
    let before = plan(&server, &viewer, wf).await.expect("plan");
    assert_eq!(before["truth_value"], json!(1.0), "calibration: live row");

    tools::workflows::deprecate_workflow(
        &server,
        &viewer,
        DeprecateWorkflowParams {
            workflow_id: wf.to_string(),
            reason: "workflow-plan retired".into(),
            cascade: Some(false),
        },
        Some(&token),
    )
    .await
    .expect("the submitter deprecates its own workflow");

    let p = plan(&server, &viewer, wf).await.expect("plan");
    assert_eq!(p["truth_value"], json!(0.05), "{p}");
    assert_items_are_the_vectors(&p);
    assert_eq!(p["digest_echo"], vectors()["ingest"]["wfd1"]);
    for item in p["items"].as_array().unwrap() {
        let structural = item["level"].as_u64().unwrap() <= 2;
        assert_eq!(item["is_current"], json!(!structural), "{item}");
        // Deprecation retires without writing a new head, so no item's
        // lineage diverged, current or not.
        assert_eq!(item["heads_diverged"], json!(false), "{item}");
    }
}

/// A caller who can see none of the plan's `executes` edges gets not-found,
/// and the error names no claim and quotes no content. Calibrated by a member
/// of the plan's group reading it through the same tool.
#[sqlx::test(migrations = "../../migrations")]
async fn a_caller_who_sees_no_edge_gets_not_found_and_nothing_else(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest_vectors(&server, &viewer, &token).await;
    let (member, _, _) = seed_caller(&pool, &["claims:read"]).await;
    let g = Uuid::new_v4();
    GroupRepository::create_with_admin(
        &pool,
        g,
        Some("workflow-plan role group"),
        &format!("did:epigraph:test:workflow-plan:{g}"),
        blake3::hash(g.as_bytes()).as_bytes(),
        None,
        member,
    )
    .await
    .expect("the group");
    let claims: Vec<Uuid> = vectors()["ingest"]["plan"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| uuid_of(&i["claim_id"]))
        .collect();
    let mut conn = pool.acquire().await.expect("acquire");
    PrivatizationRepository::restrict_claims_conn(&mut conn, &claims, g)
        .await
        .expect("restrict");
    drop(conn);

    let (_stranger, _, stranger_viewer) = seed_caller(&pool, &["claims:read"]).await;
    let err = plan(&server, &stranger_viewer, wf)
        .await
        .expect_err("a non-member has no plan to read");
    let text = err.message.to_string();
    assert!(text.contains("not found"), "{text}");
    for item in vectors()["ingest"]["plan"].as_array().unwrap() {
        assert!(!text.contains(item["claim_id"].as_str().unwrap()), "{text}");
        assert!(!text.contains(item["content"].as_str().unwrap()), "{text}");
    }

    let member_viewer = epigraph_db::visibility::Viewer::resolve(&pool, member)
        .await
        .expect("member viewer");
    let p = plan(&server, &member_viewer, wf)
        .await
        .expect("the member reads it");
    assert_items_are_the_vectors(&p);
    assert!(p["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["owner_group_id"] == json!(g.to_string())));
}

/// The body's `chain_order`, insisting on an array of claim ids.
fn chain_order(p: &Value) -> Vec<Uuid> {
    p["chain_order"]
        .as_array()
        .unwrap_or_else(|| panic!("chain_order is an array in {p}"))
        .iter()
        .map(uuid_of)
        .collect()
}

/// The body with `chain_order` removed, serialized.
fn without_chain_order(p: &Value) -> Vec<u8> {
    let mut p = p.clone();
    p.as_object_mut()
        .expect("a plan object")
        .remove("chain_order");
    serde_json::to_vec(&p).expect("serialize")
}

/// The MCP twin of the REST `chain_order` pin (ruling R-81): after the
/// `step_follows` edge between steps 1.1 and 1.2 is re-pointed (harness
/// write), the tool's `chain_order` follows the chain, equal to the walk every
/// plan-order reader uses, while the items keep stored `plan_index` order,
/// every other byte of the body is unchanged and the echo is still the
/// independently computed `wfd1`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_tool_reports_chain_order_outside_the_items_and_digest(pool: PgPool) {
    let server = build_scoped_test_server(pool.clone(), fixture::scoped_pool(&pool).await);
    let (_owner, token, viewer) = seed_caller(&pool, &["claims:write"]).await;
    let wf = ingest_vectors(&server, &viewer, &token).await;
    let plan_items = vectors()["ingest"]["plan"].as_array().unwrap().clone();
    let [s11, s12, s21] = [2, 5, 7].map(|i| uuid_of(&plan_items[i]["claim_id"]));

    let before = plan(&server, &viewer, wf).await.expect("plan");
    assert_eq!(chain_order(&before), vec![s11, s12, s21], "{before}");

    let moved = sqlx::query(
        "UPDATE edges SET source_id = $2, target_id = $1 \
          WHERE source_id = $1 AND target_id = $2 AND relationship = 'step_follows'",
    )
    .bind(s11)
    .bind(s12)
    .execute(&pool)
    .await
    .expect("harness: reverse the step_follows edge")
    .rows_affected();
    assert_eq!(moved, 1, "calibration: one 1.1 -> 1.2 step_follows edge");

    let after = plan(&server, &viewer, wf).await.expect("plan");
    assert_eq!(chain_order(&after), vec![s12, s11, s21], "{after}");
    let mut conn = pool.acquire().await.expect("acquire");
    let readers = epigraph_ingest_executor::workflow_steps::ordered_steps(&mut conn, wf)
        .await
        .expect("ordered_steps");
    assert_eq!(chain_order(&after), readers);
    assert_items_are_the_vectors(&after);
    assert_eq!(after["digest_echo"], vectors()["ingest"]["wfd1"]);
    assert_eq!(without_chain_order(&after), without_chain_order(&before));
}
