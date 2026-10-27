//! U033 / I229: the hierarchical outcome tools' descriptions are the only
//! place a caller learns the write contract. After U033 a report is
//! all-or-nothing, refuses an out-of-range `quality`, and embeds its goal; the
//! descriptions used to say the opposite of the first and the last. No DB:
//! the descriptions are static router metadata.

fn tool(name: &str) -> serde_json::Value {
    epigraph_mcp::EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} is registered"))
        .clone()
}

fn description(tool: &serde_json::Value) -> String {
    tool["description"]
        .as_str()
        .expect("tool has a description")
        .to_string()
}

fn goal_text_description(tool: &serde_json::Value) -> String {
    tool["inputSchema"]["properties"]["goal_text"]["description"]
        .as_str()
        .unwrap_or_else(|| panic!("goal_text has a description: {}", tool["inputSchema"]))
        .to_string()
}

#[test]
fn report_hierarchical_outcome_describes_an_all_or_nothing_write() {
    let d = description(&tool("report_hierarchical_outcome"));
    for needle in [
        "All-or-nothing",
        "an error (including a step row the database refuses) writes nothing",
        "`quality` outside [0, 1] is refused",
        "NOT idempotent",
    ] {
        assert!(d.contains(needle), "missing {needle:?}; got: {d}");
    }
    for stale in ["Not all-or-nothing", "a per-step row that fails is skipped"] {
        assert!(
            !d.contains(stale),
            "stale text {stale:?} survives; got: {d}"
        );
    }
}

#[test]
fn report_workflow_outcome_describes_its_hierarchical_branch_as_all_or_nothing() {
    let d = description(&tool("report_workflow_outcome"));
    assert!(
        d.contains("counters plus per-step rows written all-or-nothing"),
        "got: {d}"
    );
}

#[test]
fn goal_text_descriptions_say_a_hierarchical_goal_is_embedded() {
    let h = goal_text_description(&tool("report_hierarchical_outcome"));
    assert!(
        h.contains("embedded onto every step row"),
        "report_hierarchical_outcome.goal_text: {h}"
    );
    assert!(!h.contains("stores no goal embedding"), "stale: {h}");

    let w = goal_text_description(&tool("report_workflow_outcome"));
    assert!(
        w.contains("improves future affinity matching on both paths"),
        "report_workflow_outcome.goal_text: {w}"
    );
    assert!(!w.contains("stores no goal embedding"), "stale: {w}");
}

/// A caller that reads none of a workflow's plan is refused like an unknown
/// id; the description says so, since a caller cannot otherwise tell why a
/// workflow it found by name answers "not found".
#[test]
fn report_hierarchical_outcome_describes_the_unreadable_plan_refusal() {
    let d = description(&tool("report_hierarchical_outcome"));
    assert!(
        d.contains(
            "a caller that can read none of its steps (no step executes edge; a visible thesis, \
             phase or shared operation atom does not count, so a plan with no steps is refused to \
             every caller) gets the same not-found error as an unknown id, and nothing is written"
        ),
        "got: {d}"
    );
}
