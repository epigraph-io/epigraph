//! Ruling R-38 (backlog ca30e645): plan order is the `step_follows` chain,
//! not `plan_index`. The served descriptions are the only place an agent
//! learns which slot `add_step(position = i)` lands in and which slot a
//! `step_index` names, so they must say the chain, say where the chain does
//! not apply (fork/cycle fallback, `get_workflow_plan`'s stored order), and no
//! longer say an added step "comes after every indexed step". No DB: the
//! descriptions are static router metadata.

fn tool(name: &str) -> serde_json::Value {
    epigraph_mcp::EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} is registered"))
        .clone()
}

fn description(name: &str) -> String {
    tool(name)["description"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a description"))
        .to_string()
}

/// The `step_index` description inside `tool`'s input schema, wherever the
/// step-execution item type is defined (inline or under `$defs`).
fn step_index_description(name: &str) -> String {
    let schema = tool(name)["inputSchema"].clone();
    let mut found = Vec::new();
    collect_step_index(&schema, &mut found);
    assert_eq!(
        found.len(),
        1,
        "{name}'s schema defines step_index exactly once: {schema}"
    );
    found.remove(0)
}

fn collect_step_index(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(d) = map
                .get("properties")
                .and_then(|p| p.get("step_index"))
                .and_then(|s| s.get("description"))
                .and_then(serde_json::Value::as_str)
            {
                out.push(d.to_string());
            }
            for child in map.values() {
                collect_step_index(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_step_index(child, out);
            }
        }
        _ => {}
    }
}

const STALE: &str = "comes after every indexed step";
const FALLBACK: &str = "fall back to stored plan_index order";

#[test]
fn add_step_says_the_chain_is_plan_order_and_plan_index_is_only_the_stored_ordinal() {
    let d = description("add_step");
    for needle in [
        "inserts at the 0-indexed slot i of the `step_follows` chain",
        "Plan order for find_workflow, find_workflow_hierarchical and the step_index of \
         report_workflow_outcome / report_hierarchical_outcome is the step_follows chain, not \
         plan_index",
        "plan_index in the response is only the stored ordinal",
        "get_workflow_plan reports the stored plan_index order",
        FALLBACK,
    ] {
        assert!(d.contains(needle), "missing {needle:?}; got: {d}");
    }
    // The sentence the branch first left in place: plan_index named as the
    // order get_workflow_plan and the step_index readers use.
    assert!(
        !d.contains("plan_index in the response is where the step sits in plan order"),
        "stale plan_index-is-plan-order sentence survives: {d}"
    );
    assert!(!d.contains(STALE), "{d}");
}

#[test]
fn report_hierarchical_outcome_maps_step_index_through_the_chain() {
    let d = description("report_hierarchical_outcome");
    for needle in [
        "the step_follows chain, so a step add_step inserted at slot i is step i",
        FALLBACK,
    ] {
        assert!(d.contains(needle), "missing {needle:?}; got: {d}");
    }
    assert!(!d.contains(STALE), "{d}");
}

#[test]
fn both_step_index_schemas_name_the_chain_and_its_fallback() {
    for name in ["report_workflow_outcome", "report_hierarchical_outcome"] {
        let d = step_index_description(name);
        for needle in [
            "step_follows chain",
            "a step add_step inserted at slot i is step i",
            FALLBACK,
        ] {
            assert!(
                d.contains(needle),
                "{name}.step_index missing {needle:?}; got: {d}"
            );
        }
        assert!(!d.contains(STALE), "{name}.step_index stale: {d}");
    }
}

#[test]
fn add_step_position_schema_names_the_exceptions() {
    let schema = tool("add_step")["inputSchema"].clone();
    let d = schema["properties"]["position"]["description"]
        .as_str()
        .unwrap_or_else(|| panic!("position has a description: {schema}"))
        .to_string();
    for needle in [
        "walk\nthe `step_follows` chain",
        "fall back to stored `plan_index`",
        "`get_workflow_plan` always reports\nstored order",
    ] {
        let flat = needle.replace('\n', " ");
        assert!(
            d.replace('\n', " ").contains(&flat),
            "position missing {flat:?}; got: {d}"
        );
    }
}
