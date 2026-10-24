//! The agent-facing text for `supersede_claim` must say what happens to the
//! old claim's labels (backlog b447b4a5: it was unclear whether labels carry
//! over to the replacement): they carry, except the novelty gate's
//! per-submission `near-duplicate` flag. Asserted against
//! `EpiGraphMcpFull::all_tools_json()`, the same router-derived JSON
//! `tools/list` serves. No DB.

use epigraph_mcp::EpiGraphMcpFull;

#[test]
fn supersede_claim_description_says_labels_carry_except_near_duplicate() {
    let tools = EpiGraphMcpFull::all_tools_json();
    let t = tools
        .as_array()
        .expect("all_tools_json must return an array")
        .iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some("supersede_claim"))
        .expect("supersede_claim is registered on the router")
        .clone();
    let description = t["description"].as_str().expect("tool description");
    for needle in [
        "NEW CLAIM INHERITS THE OLD CLAIM'S LABELS",
        "except near-duplicate",
    ] {
        assert!(
            description.contains(needle),
            "supersede_claim's description must say {needle:?}: {description}"
        );
    }
}
