//! The agent-facing text for `submit_ds_evidence` must describe the combine
//! the server actually runs (drain unit U025, backlog 9d4821c1).
//!
//! Since U025 `combination::combine_multiple` folds with Dempster's rule at
//! every step and reports the fold's aggregate conflict; it no longer picks a
//! rule adaptively per step. The tool description and the
//! `combination_method` parameter description used to say "adaptive
//! combine", which is what MCP clients (stdio and HTTP) read from
//! `tools/list`. Asserted against `EpiGraphMcpFull::all_tools_json()`, the
//! same router-derived JSON `tools/list` serves. No DB.

use epigraph_mcp::EpiGraphMcpFull;

fn tool(tools: &serde_json::Value, name: &str) -> serde_json::Value {
    tools
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("tool `{name}` is not registered on the router"))
        .clone()
}

#[test]
fn submit_ds_evidence_text_names_the_dempster_fold() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let t = tool(&tools, "submit_ds_evidence");

    let description = t["description"].as_str().expect("tool description");
    assert!(
        description.contains("a Dempster fold over the claim's BBAs")
            && description.contains("aggregate conflict as mass_on_conflict"),
        "submit_ds_evidence's description must name the Dempster fold: {description}"
    );
    assert!(
        !description.contains("adaptive combine"),
        "stale 'adaptive combine' text in submit_ds_evidence: {description}"
    );

    let method = t["inputSchema"]["properties"]["combination_method"]["description"]
        .as_str()
        .expect("combination_method description");
    assert!(
        method.contains("shared Dempster fold that recompute_beliefs uses"),
        "combination_method's description must name the Dempster fold: {method}"
    );
    assert!(
        !method.contains("adaptive"),
        "stale 'adaptive' text in combination_method: {method}"
    );
}
