//! The agent-facing text for `theme_cluster` must state the wipe rules the
//! server enforces (backlog 5abe23de).
//!
//! The old tool description said "Default `wipe_first=true` ensures clean
//! rebuilds on each call", and agents (the 2026-09-23 sweep probe among them)
//! called the tool bare and wiped the live theme set. The server now defaults
//! to an additive run and admits a wipe only for `claims:admin` on the
//! canonical `"auto"` family; this pins that MCP clients are told so.
//! Asserted against `EpiGraphMcpFull::all_tools_json()`, the same
//! router-derived JSON `tools/list` serves. No DB.

use epigraph_mcp::scope_map::CLAIMS_ADMIN;
use epigraph_mcp::EpiGraphMcpFull;

fn theme_cluster_tool() -> serde_json::Value {
    EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some("theme_cluster"))
        .expect("theme_cluster is registered on the router")
        .clone()
}

#[test]
fn theme_cluster_description_states_the_additive_default_and_the_wipe_gate() {
    let t = theme_cluster_tool();
    let description = t["description"].as_str().expect("tool description");

    assert!(
        description.contains("wipe_first=false (additive"),
        "the description must name the additive default: {description}"
    );
    assert!(
        description.contains(&format!(
            "requires {CLAIMS_ADMIN} and the canonical label_prefix \"auto\""
        )),
        "the description must state what a wipe needs: {description}"
    );
    assert!(
        description.contains("deletes EVERY existing theme, whatever its prefix"),
        "the description must say a wipe is not scoped to label_prefix: {description}"
    );
    assert!(
        !description.contains("Default `wipe_first=true`"),
        "stale wipe-by-default text in theme_cluster: {description}"
    );
}

#[test]
fn wipe_first_parameter_text_states_the_default_and_the_gate() {
    let t = theme_cluster_tool();
    let wipe_first = t["inputSchema"]["properties"]["wipe_first"]["description"]
        .as_str()
        .expect("wipe_first parameter description");

    assert!(
        wipe_first.contains("**Default `false`.**"),
        "wipe_first's description must name the false default: {wipe_first}"
    );
    assert!(
        wipe_first.contains(&format!("`{CLAIMS_ADMIN}`"))
            && wipe_first.contains("canonical `label_prefix` `\"auto\"`"),
        "wipe_first's description must state what a wipe needs: {wipe_first}"
    );
    assert!(
        !wipe_first.contains("Default `true`"),
        "stale wipe-by-default text in wipe_first: {wipe_first}"
    );
}
