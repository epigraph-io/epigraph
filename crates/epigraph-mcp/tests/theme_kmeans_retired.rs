//! The k-means theme prototype is retired (backlog a0ed0180, operator ruling
//! R-29 as revised 2026-10-26): the theme layer is the UMAP pipeline
//! (`scripts/cluster_claims.py`, `scripts/maintain_themes.py` and the REST
//! routes they call), not `epigraph_engine::theme_kmeans`.
//!
//! The MCP `theme_cluster` tool existed only to run that prototype. A
//! scheduled agent prompt can still reach it (the `theme-maintenance` task's
//! fallback, `docs/ops/theme-v2-promotion-runbook.md`), so per the ruling the
//! name stays registered as a REFUSAL that names the replacement, rather than
//! disappearing into an unknown-tool error. The theme READERS stay.
//!
//! No DB: asserted against the router-derived tool JSON `tools/list` serves,
//! and the refusal the tool body returns.

use epigraph_mcp::EpiGraphMcpFull;

fn tools() -> Vec<serde_json::Value> {
    EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("all_tools_json returns an array")
        .clone()
}

fn tool(name: &str) -> serde_json::Value {
    tools()
        .into_iter()
        .find(|t| t.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("{name} is registered on the router"))
}

/// `theme_cluster` is served only as a retirement notice: its description
/// says so and names the replacement, and it takes none of the old k-means
/// parameters. The theme readers are still served.
#[test]
fn theme_cluster_is_served_only_as_a_retirement_notice() {
    for reader in ["list_themes", "get_theme"] {
        let _ = tool(reader);
    }
    let t = tool("theme_cluster");
    let description = t["description"].as_str().expect("description");
    assert!(
        description.starts_with("RETIRED."),
        "theme_cluster must describe itself as retired: {description}"
    );
    for needle in ["maintain_themes.py", "list_themes", "nothing written"] {
        assert!(
            description.contains(needle),
            "theme_cluster's description must name {needle:?}: {description}"
        );
    }
    let props = t["inputSchema"]
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .map(|p| p.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        props.is_empty(),
        "the retired tool must not advertise the k-means parameters: {props:?}"
    );
}

/// Nothing else an agent reads may still point it at the retired tool.
#[test]
fn no_other_served_schema_recommends_theme_cluster() {
    for t in tools() {
        let name = t["name"].as_str().unwrap_or_default().to_string();
        if name == "theme_cluster" {
            continue;
        }
        let text = t.to_string();
        assert!(
            !text.contains("theme_cluster"),
            "{name}'s served schema still names theme_cluster: {text}"
        );
    }
}

/// The refusal is a caller-error (`INVALID_REQUEST`, not retried as an
/// internal error) whose message and machine-readable `data` name the
/// replacement.
#[test]
fn the_refusal_names_the_umap_pipeline_and_is_not_retryable() {
    let e = epigraph_mcp::tools::themes::theme_cluster_retired();
    assert_eq!(e.code, rmcp::model::ErrorCode::INVALID_REQUEST);
    assert!(
        e.message.contains("retired") && e.message.contains("maintain_themes.py"),
        "{}",
        e.message
    );
    let data = e.data.expect("machine-readable data");
    assert_eq!(data["status"], "retired");
    assert_eq!(data["retryable"], false);
}
