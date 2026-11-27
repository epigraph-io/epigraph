//! `find_workflow` labels the basis of its `promotable` flag (backlog
//! 74eedb3a). The flag is the Wilson gate's verdict over a workflow's
//! recorded executions, and those are outcome reports the callers submit
//! themselves (`report_workflow_outcome` / `report_hierarchical_outcome`);
//! nothing reviews them independently. So wherever `promotable` appears, a
//! `promotion_basis: "self_reported"` appears next to it, and an unevaluated
//! workflow carries neither.
//!
//! Verified to fail on the tree before the field existed: the promoted
//! workflow's result carried `promotable: true` and no `promotion_basis`.

#[path = "viewer_fixture.rs"]
mod fixture;

use epigraph_core::ClaimId;
use epigraph_db::ClaimRepository;
use sqlx::PgPool;
use uuid::Uuid;

mod common;
use common::*;

/// Every JSON object in `v` whose `workflow_id` is `id`.
fn results_for(v: &serde_json::Value, id: Uuid, out: &mut Vec<serde_json::Value>) {
    match v {
        serde_json::Value::Object(m) => {
            if m.get("workflow_id").and_then(serde_json::Value::as_str) == Some(&id.to_string()) {
                out.push(v.clone());
            }
            for child in m.values() {
                results_for(child, id, out);
            }
        }
        serde_json::Value::Array(a) => {
            for child in a {
                results_for(child, id, out);
            }
        }
        _ => {}
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_workflow_labels_promotable_as_self_reported(pool: PgPool) {
    let viewer = fixture::public_viewer(&pool).await;
    let phrase = format!("promotion-basis-{}", Uuid::new_v4());
    let evaluated = seed_workflow_claim(&pool, &format!("{phrase} evaluated"), &["a", "b"]).await;
    let unevaluated =
        seed_workflow_claim(&pool, &format!("{phrase} unevaluated"), &["c", "d"]).await;
    // What `refresh_workflow_promotion` writes onto the variant claim.
    ClaimRepository::merge_properties(
        &pool,
        ClaimId::from_uuid(evaluated),
        &serde_json::json!({"promotion": {"promotable": true, "lower_bound": 0.72}}),
    )
    .await
    .expect("write the promotion verdict");

    let server = build_test_server(pool.clone());
    let result = epigraph_mcp::tools::workflows::find_workflow(
        &server,
        &viewer,
        epigraph_mcp::types::FindWorkflowParams {
            goal: phrase.clone(),
            limit: Some(10),
            min_truth: Some(0.0),
        },
    )
    .await
    .expect("find_workflow");
    let json = first_text(&result);

    let mut hits = Vec::new();
    results_for(&json, evaluated, &mut hits);
    assert!(!hits.is_empty(), "the evaluated workflow is found: {json}");
    for hit in &hits {
        assert_eq!(
            hit["promotable"], true,
            "CALIBRATION: the flag is read: {hit}"
        );
        assert_eq!(
            hit["promotion_basis"], "self_reported",
            "promotable must carry its basis: {hit}"
        );
    }

    let mut plain = Vec::new();
    results_for(&json, unevaluated, &mut plain);
    assert!(
        !plain.is_empty(),
        "the unevaluated workflow is found: {json}"
    );
    for hit in &plain {
        assert!(
            hit.get("promotable").is_none() && hit.get("promotion_basis").is_none(),
            "a never-evaluated workflow carries neither field: {hit}"
        );
    }
}

/// The discovery and gate tools say the flag is advisory and self-reported, so
/// an agent reading only the description weighs it as a hint.
#[test]
fn the_promotion_tools_describe_the_flag_as_advisory_and_self_reported() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    for name in [
        "find_workflow",
        "evaluate_workflow_promotion",
        "refresh_workflow_promotion",
    ] {
        let d = tools
            .as_array()
            .expect("array")
            .iter()
            .find(|t| t["name"] == name)
            .and_then(|t| t["description"].as_str())
            .unwrap_or_else(|| panic!("{name} is registered with a description"))
            .to_string();
        for needle in [
            "advisory",
            "self_reported",
            "outcome reports callers submitted",
        ] {
            assert!(d.contains(needle), "{name} must say {needle:?}: {d}");
        }
    }
}
