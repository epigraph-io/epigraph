//! The OpenAPI document for `GET /api/v1/workflows/hierarchical/search` must
//! state the `resolve_to_latest` ordering a REST consumer gets, as the MCP
//! `find_workflow_hierarchical` schema does: a live lineage head leads its
//! group, a deprecated head (truth below `min_truth`) sorts after the live
//! rows of its group. It must also document `min_truth`, the bound that
//! decides which is which.

use epigraph_api::openapi::openapi_spec;

fn search_param(spec: &serde_json::Value, name: &str) -> serde_json::Value {
    spec["paths"]["/api/v1/workflows/hierarchical/search"]["get"]["parameters"]
        .as_array()
        .expect("hierarchical search documents its parameters")
        .iter()
        .find(|p| p["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("hierarchical search must document `{name}`"))
}

#[test]
fn hierarchical_search_documents_the_deprecated_head_order() {
    let spec = serde_json::to_value(openapi_spec()).expect("spec serializes");

    let resolve = search_param(&spec, "resolve_to_latest");
    let d = resolve["description"]
        .as_str()
        .expect("resolve_to_latest carries a description");
    for needle in [
        "a live head leads its lineage group",
        "a deprecated head (truth below min_truth) sorts after the live rows of its group",
        "lineage_head_deprecated",
    ] {
        assert!(
            d.contains(needle),
            "resolve_to_latest must say {needle:?}; got: {d}"
        );
    }

    let min_truth = search_param(&spec, "min_truth");
    let d = min_truth["description"]
        .as_str()
        .expect("min_truth carries a description");
    assert!(
        d.contains("0.3"),
        "min_truth must state its default; got: {d}"
    );
}
