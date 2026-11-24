//! `success` on the two workflow-outcome tools must say what it MEANS.
//!
//! Backlog 563165f2 (second half): the field read only "true if the workflow
//! succeeded, false if it failed". Nothing said whether that is "the goal and
//! its gates/checks were achieved" or "the procedure ran to completion", and a
//! run whose every gate FAILED was recorded with `success=true`. The counters
//! and affinity scores both tools feed are only as good as that flag, and the
//! schema description is the only contract an agent reads before setting it.
//!
//! Asserted against `EpiGraphMcpFull::all_tools_json()`, the router-derived
//! schema `tools/list` hands a client.

fn tool(tools: &serde_json::Value, name: &str) -> serde_json::Value {
    tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("tool `{name}` is registered"))
        .clone()
}

fn success_description(tools: &serde_json::Value, name: &str) -> String {
    tool(tools, name)["inputSchema"]["properties"]["success"]["description"]
        .as_str()
        .unwrap_or_else(|| panic!("`{name}.success` carries a description"))
        .to_string()
}

#[test]
fn success_is_defined_as_goal_achieved_not_procedure_completed() {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    for name in ["report_workflow_outcome", "report_hierarchical_outcome"] {
        let d = success_description(&tools, name);
        for needle in [
            "goal or expected outcome was achieved",
            "every gate and check passed",
            "ran every step but a gate or check failed is success=false",
        ] {
            assert!(
                d.contains(needle),
                "`{name}.success` must say {needle:?}; got: {d}"
            );
        }
    }

    // Both tool descriptions too, not only the parameter: backlog a4914433
    // (1) found `report_hierarchical_outcome`'s description, which a caller
    // using the hierarchical tool directly reads, still without the definition.
    for name in ["report_workflow_outcome", "report_hierarchical_outcome"] {
        let desc = tool(&tools, name)["description"]
            .as_str()
            .unwrap_or_else(|| panic!("`{name}` has a description"))
            .to_string();
        for needle in [
            "success=true means the workflow's goal was achieved",
            "every gate and check passed",
            "not merely that every step ran",
            "a run whose gates or checks failed is success=false",
        ] {
            assert!(
                desc.contains(needle),
                "`{name}`'s description must say {needle:?}; got: {desc}"
            );
        }
    }
}
