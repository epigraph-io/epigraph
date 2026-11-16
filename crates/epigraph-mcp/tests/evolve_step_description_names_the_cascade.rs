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

/// Backlog c0ab097a (part 1), as migration 219 changes it: the lineage
/// authority gate read the workflows executing a lineage under the caller's
/// row security, so a workflow whose `executes` edge or lineage member the
/// caller could not see was not checked (the residual the old description
/// stated, and the one 219 would have widened: a group plan's `executes`
/// edge onto a public step is hidden from a non-member). The gates now also
/// read the whole set unfiltered through 219's definer and check every
/// workflow in it, so the residual is CLOSED (pinned by
/// `epigraph-api/tests/workflow_hidden_id_masking.rs`, the split-lineage
/// test), and the description states the rule where agents choose the tool.
#[test]
fn evolve_step_description_states_that_every_executing_workflow_is_checked() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let description = tools
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == "evolve_step")
        .and_then(|t| t["description"].as_str())
        .expect("evolve_step is registered with a description");

    for needle in [
        "Every workflow that executes the lineage is checked",
        "whose `executes` edge, lineage member or row you cannot see",
        "never naming it",
    ] {
        assert!(
            description.contains(needle),
            "evolve_step's description must state that every executing workflow is checked \
             ({needle:?}): {description}"
        );
    }
    assert!(
        !description.contains("Accepted residual"),
        "the residual is closed; the description must not still state it: {description}"
    );
}
