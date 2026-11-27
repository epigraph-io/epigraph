//! The k-means theme prototype is retired (backlog a0ed0180): the theme layer
//! is the UMAP pipeline (`scripts/cluster_claims.py`,
//! `scripts/maintain_themes.py` and the REST routes they call), not
//! `epigraph_engine::theme_kmeans`.
//!
//! The MCP `theme_cluster` tool existed only to run that prototype. It was
//! first kept as a registered refusal; backlog 90993e95 (ruling ea3a3d0c)
//! removed it outright, together with `stage_claims` (a length check that
//! validated nothing `submit_claim` would refuse). Neither name is served,
//! mapped to a scope, or recommended by any other tool's schema. The theme
//! READERS stay.
//!
//! No DB: asserted against the router-derived tool JSON `tools/list` serves
//! and the static scope map. `theme_cluster_retired_dispatch.rs` drives a
//! stale call through the real HTTP dispatch path.

use epigraph_mcp::EpiGraphMcpFull;

/// The two tools backlog 90993e95 removed.
const REMOVED: [&str; 2] = ["theme_cluster", "stage_claims"];

fn tools() -> Vec<serde_json::Value> {
    EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("all_tools_json returns an array")
        .clone()
}

fn names() -> Vec<String> {
    tools()
        .iter()
        .filter_map(|t| t.get("name").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

/// Neither removed tool is on the router, so `tools/list` and
/// `list_mcp_tools` no longer advertise them. The theme readers still are.
#[test]
fn the_removed_tools_are_not_served() {
    let served = names();
    for name in REMOVED {
        assert!(
            !served.iter().any(|n| n == name),
            "{name} must not be registered on the router; served: {served:?}"
        );
    }
    for reader in ["list_themes", "get_theme"] {
        assert!(
            served.iter().any(|n| n == reader),
            "{reader} must still be served"
        );
    }
}

/// The scope map no longer maps either name, so the HTTP scope gate refuses
/// a call to them before any tool body runs (an unmapped tool fails closed).
#[test]
fn the_removed_tools_have_no_scope_mapping() {
    for name in REMOVED {
        assert_eq!(
            epigraph_mcp::scope_map::required_scope(name),
            None,
            "{name} must have no SCOPE_MAP row"
        );
    }
    // Calibration: a served reader is still mapped, so `None` above is the
    // removal and not a broken lookup.
    assert_eq!(
        epigraph_mcp::scope_map::required_scope("list_themes"),
        Some("claims:read")
    );
}

/// Whether `text` names `ident` as a whole identifier: an occurrence not
/// flanked by another identifier character, so `theme_clustering` or
/// `prestage_claims` do not count as naming `theme_cluster` / `stage_claims`.
fn names_identifier(text: &str, ident: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(ident).any(|(i, m)| {
        let before = text[..i].chars().next_back();
        let after = text[i + m.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

#[test]
fn names_identifier_matches_whole_identifiers_only() {
    assert!(names_identifier("call theme_cluster now", "theme_cluster"));
    assert!(names_identifier("\"theme_cluster\"", "theme_cluster"));
    assert!(names_identifier("theme_cluster", "theme_cluster"));
    assert!(!names_identifier("theme_clustering runs", "theme_cluster"));
    assert!(!names_identifier("prestage_claims", "stage_claims"));
}

/// Nothing an agent reads may still point it at a removed tool.
#[test]
fn no_served_schema_names_a_removed_tool() {
    for t in tools() {
        let name = t["name"].as_str().unwrap_or_default().to_string();
        let text = t.to_string();
        for removed in REMOVED {
            assert!(
                !names_identifier(&text, removed),
                "{name}'s served schema still names {removed}: {text}"
            );
        }
    }
}
