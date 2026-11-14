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
/// authority gate reads the workflows executing a lineage under the caller's
/// row security, and since 219 a group plan's `executes` edge onto a public
/// step is hidden from a non-member. The gate also asks a definer whether a
/// workflow the caller cannot read executes the lineage, and refuses without
/// naming it. The description states that rule where agents choose the tool
/// (it used to state the residual this closes).
#[test]
fn evolve_step_description_states_that_a_hidden_executor_refuses() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let description = tools
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some("evolve_step"))
        .and_then(|t| t["description"].as_str().map(str::to_string))
        .expect("evolve_step is registered with a description");

    for needle in [
        "A workflow you cannot read that executes the lineage refuses the evolve too",
        "even when its `executes` edge is hidden from you",
        "without naming it",
    ] {
        assert!(
            description.contains(needle),
            "evolve_step's description must state the hidden-executor rule ({needle:?}): \
             {description}"
        );
    }
    assert!(
        !description.contains("Accepted residual"),
        "the residual is closed; the description must not still state it: {description}"
    );
}
