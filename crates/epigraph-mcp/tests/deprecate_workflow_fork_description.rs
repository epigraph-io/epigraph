//! `deprecate_workflow`'s description says what a cascade does NOT reach
//! (backlog aa2fb722, ruling e5f6a9d7): a fork of the workflow under another
//! canonical_name, private to a group the caller cannot read, belongs to that
//! group. The cascade neither deprecates it nor tells the caller it exists,
//! and it is not a reason to refuse the cascade (only a hidden generation of
//! the SAME lineage is). An agent reading the old text could not tell that
//! "deprecated with cascade" leaves such a fork live.
//!
//! No DB: asserted against the router-derived tool JSON `tools/list` serves.

fn description() -> String {
    epigraph_mcp::EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "deprecate_workflow")
        .and_then(|t| t["description"].as_str())
        .expect("deprecate_workflow is registered with a description")
        .to_string()
}

#[test]
fn deprecate_workflow_says_a_hidden_fork_under_another_name_is_left_alone() {
    let d = description();
    for needle in [
        "A fork under another canonical_name that you cannot read",
        "belongs to its own group",
        "neither deprecates it nor reports it",
    ] {
        assert!(
            d.contains(needle),
            "deprecate_workflow's description must say {needle:?}; got: {d}"
        );
    }
}
