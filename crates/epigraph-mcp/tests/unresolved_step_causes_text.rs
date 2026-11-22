//! Every text that explains an unresolved `step_index` names all THREE causes.
//!
//! Backlog 0f35c13b: `WorkflowRepository::plan_step_claim_ids` returns only
//! the plan prefix whose positions the reporter can PROVE, so a step the
//! reporter can read is also reported unresolved when its position cannot be
//! established: an ORDINAL step after a gap in the ordinals the reporter can
//! read, or an unordered step when the reporter reads no ordinal edge (nor,
//! for a plan written before the ordinal, a phase edge) of the plan. (An
//! unordered step after HIDDEN TRAILING ordinals is not one of these: it is
//! listed, on the wrong index; that resolution gap is backlog 6f634609 and
//! is not closed here.) The tool
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
//! transports log), plus a source check that both transports' `tracing::warn!`
//! calls log that constant rather than an inline copy of the old text.

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

/// The old two-cause log text, as each transport inlined it before the shared
/// constant. Only `UNRESOLVED_STEPS_LOG`'s own definition may carry it.
const INLINE_LOG_FRAGMENT: &str = "rows recorded with a NULL step_claim_id";

fn source(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn both_transports_log_the_shared_constant_not_an_inline_copy() {
    // (file, how many times the old inline text may appear: the MCP tool file
    // holds the constant's definition, the HTTP route holds none)
    for (rel, allowed) in [
        ("src/tools/workflow_hierarchical.rs", 1),
        ("../epigraph-api/src/routes/workflows.rs", 0),
    ] {
        let src = source(rel);
        let inline = src.matches(INLINE_LOG_FRAGMENT).count();
        assert_eq!(
            inline, allowed,
            "{rel}: the unresolved-step log text must come from UNRESOLVED_STEPS_LOG, \
             not an inline string ({inline} occurrence(s) of {INLINE_LOG_FRAGMENT:?})"
        );
        let uses = src
            .matches("UNRESOLVED_STEPS_LOG")
            .count()
            .saturating_sub(usize::from(src.contains("pub const UNRESOLVED_STEPS_LOG")));
        assert!(
            uses >= 1,
            "{rel}: the unresolved-step tracing::warn! must log UNRESOLVED_STEPS_LOG"
        );
    }
}
