//! The agent-facing text for `evolve_step` must describe what `supersedes`
//! now does (backlog 8d3b4527): it records the supersession and runs the
//! Supersede admin cascade, reported in the new `cascade` response field, and
//! leaves a fixed set of edges on the retired step. Agents choose tools by
//! these strings; `supersede_claim`'s description already documents its
//! cascade. Asserted against `EpiGraphMcpFull::all_tools_json()`, the same
//! router-derived JSON `tools/list` serves. No DB.

use epigraph_mcp::EpiGraphMcpFull;

#[test]
fn evolve_step_description_names_the_supersede_cascade_and_what_stays() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let t = tools
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some("evolve_step"))
        .expect("evolve_step is registered on the router")
        .clone();
    let description = t["description"].as_str().expect("tool description");

    for needle in [
        "Supersede cascade",
        "`cascade`",
        "deferred",
        "`belief_cascade`",
        "`executes`",
        "`step_follows`",
        "`phase_follows`",
        "`asserts`",
        "'revises' retires nothing and runs no cascade",
    ] {
        assert!(
            description.contains(needle),
            "evolve_step's description must name {needle:?}: {description}"
        );
    }
}
