//! `docs/architecture/mcp-tool-overlaps.md` is the decision table for the MCP
//! tool families whose jobs overlap (backlog 4e2ce1c4): which tool to call,
//! what each returns, and which are deprecated or removed. The two entry
//! points an agent most often confuses with a sibling (`get_provenance`,
//! `recall`) name it in their descriptions, so the table is reachable from the
//! text an agent actually reads.
//!
//! No DB: the doc is read from the repository and the descriptions from the
//! router-derived tool JSON `tools/list` serves.

use std::path::PathBuf;

const POINTER: &str = "See docs/architecture/mcp-tool-overlaps.md";

fn doc() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/architecture/mcp-tool-overlaps.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()))
}

/// The Status cell of a table row: `| Tool | Job | Output | Status | Prefer when |`.
fn status(row: &str) -> String {
    row.split('|').nth(4).unwrap_or_default().trim().to_string()
}

fn description(name: &str) -> String {
    epigraph_mcp::EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .find(|t| t["name"] == name)
        .and_then(|t| t["description"].as_str())
        .unwrap_or_else(|| panic!("{name} is registered with a description"))
        .to_string()
}

/// Every tool of the four families has a row (a table line naming it in
/// backticks), and the doc states each status the table uses.
#[test]
fn the_doc_has_a_row_for_every_tool_of_the_four_families() {
    let d = doc();
    let rows: Vec<&str> = d.lines().filter(|l| l.starts_with('|')).collect();
    for tool in [
        // provenance
        "get_provenance",
        "get_provenance_chain",
        "export_provenance_prov_o",
        // recall
        "recall",
        "recall_with_context",
        // ingest
        "ingest_document",
        "ingest_document_inline",
        "ingest_document_spine",
        "structure_source",
        // claim writes
        "submit_claim",
        "memorize",
        "batch_submit_claims",
        "stage_claims",
    ] {
        let needle = format!("| `{tool}` |");
        assert!(
            rows.iter().any(|r| r.starts_with(&needle)),
            "the doc must have a table row for {tool}"
        );
    }
    // stage_claims is listed as removed, not as a tool to call.
    let stage = rows
        .iter()
        .find(|r| r.starts_with("| `stage_claims` |"))
        .expect("stage_claims row");
    assert!(status(stage).starts_with("removed"), "{stage}");
}

/// Each tool the table lists as callable is still served, so the table cannot
/// silently point at a tool that was removed or renamed.
#[test]
fn every_current_row_names_a_served_tool() {
    let served: Vec<String> = epigraph_mcp::EpiGraphMcpFull::all_tools_json()
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    for row in doc().lines().filter(|l| l.starts_with("| `")) {
        let name = row
            .trim_start_matches("| `")
            .split('`')
            .next()
            .unwrap_or_default();
        let status = status(row);
        assert!(
            ["current", "deprecated", "removed"]
                .iter()
                .any(|s| status.starts_with(s)),
            "{name}'s status must be current, deprecated or removed: {row}"
        );
        if status.starts_with("removed") {
            assert!(
                !served.iter().any(|s| s == name),
                "{name} is marked removed but still served"
            );
        } else {
            assert!(
                served.iter().any(|s| s == name),
                "{name} has a row but is not served: {row}"
            );
        }
    }
}

/// The two descriptions point at the table.
#[test]
fn get_provenance_and_recall_descriptions_name_the_table() {
    for tool in ["get_provenance", "recall"] {
        let d = description(tool);
        assert!(
            d.contains(POINTER),
            "{tool}'s description must say {POINTER:?}; got: {d}"
        );
    }
}
