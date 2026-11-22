//! Every text that explains an unresolved `step_index` names all THREE causes.
//!
//! Backlog 0f35c13b: `WorkflowRepository::plan_step_claim_ids` returns only
//! the plan prefix whose positions the reporter can PROVE, so a step the
//! reporter can read is also reported unresolved when its position cannot be
//! established (it follows an ordinal the reporter cannot read, or it is an
//! unordered step after a plan the reporter cannot read). The tool
//! description, the warning in the response, and the warning both transports
//! log named only "out of range" and "not visible", which sends a reporter who
//! CAN open the step looking for the wrong problem.
//!
//! The three causes stay deliberately indistinguishable (telling them apart
//! would disclose a step the reporter cannot read); only the list of
//! possibilities grows.
//!
//! Asserted against `EpiGraphMcpFull::all_tools_json()` (the schema
//! `tools/list` hands a client), `unresolved_steps_warning` (the response
//! warning both transports return) and `UNRESOLVED_STEPS_LOG` (the message both
//! transports log).

use epigraph_mcp::tools::workflow_hierarchical::{unresolved_steps_warning, UNRESOLVED_STEPS_LOG};

/// The unprovable-position cause, as each text words it.
const POSITION_CAUSE: &str = "position in the plan cannot be established from the steps";

fn hierarchical_description() -> String {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == "report_hierarchical_outcome")
        .expect("report_hierarchical_outcome is registered")["description"]
        .as_str()
        .expect("report_hierarchical_outcome has a description")
        .to_string()
}

#[test]
fn the_tool_description_names_the_unprovable_position_cause() {
    let d = hierarchical_description();
    for needle in ["out of range", "not visible to you", POSITION_CAUSE] {
        assert!(
            d.contains(needle),
            "report_hierarchical_outcome's description must name {needle:?}; got: {d}"
        );
    }
    assert!(
        d.contains("the three causes are not told apart"),
        "the description must still say the causes are not told apart; got: {d}"
    );
}

#[test]
fn the_response_warning_names_the_unprovable_position_cause() {
    let w = unresolved_steps_warning(&[1]).expect("an unresolved index gets a warning");
    for needle in ["out of range", "not visible to you", POSITION_CAUSE] {
        assert!(
            w.contains(needle),
            "the warning must name {needle:?}; got: {w}"
        );
    }
}

#[test]
fn the_logged_warning_names_the_unprovable_position_cause() {
    for needle in [
        "out of range",
        "not visible to the reporter",
        POSITION_CAUSE,
    ] {
        assert!(
            UNRESOLVED_STEPS_LOG.contains(needle),
            "the logged warning must name {needle:?}; got: {UNRESOLVED_STEPS_LOG}"
        );
    }
}
