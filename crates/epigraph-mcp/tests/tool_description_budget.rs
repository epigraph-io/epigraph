//! A ratchet on the size of the MCP tool descriptions (backlog 77037030,
//! split 1/4 of 52ede4f1).
//!
//! Every client that lists this server's tools pays for every description,
//! on every session, before it has asked a single question. The descriptions
//! grew one sentence at a time with nothing to push back, so this test holds
//! the line where it is today:
//!
//! * the sum of every tool's description is at most [`TOTAL_CEILING`];
//! * each tool in [`OVERSIZE_ALLOWLIST`] is at most its listed ceiling;
//! * every other tool is at most [`PER_TOOL_CAP`].
//!
//! THE CEILINGS ONLY GO DOWN (backlog 52ede4f1). When a description is
//! trimmed, lower its ceiling here (or drop its entry once it fits under
//! [`PER_TOOL_CAP`]) and lower [`TOTAL_CEILING`] with it. Never raise one to
//! make a longer description pass: trim the description, or justify the
//! exception in review. The final target is NO allowlist and a
//! [`TOTAL_CEILING`] of 100,000.
//!
//! Lengths are counted in characters (`char`s), not bytes: an em-dash costs a
//! reader one character whatever its UTF-8 width.

use std::collections::HashMap;

/// The ceiling on the sum of every tool's description, in characters.
/// Ratchets down only; the target is 100_000.
///
/// Set at the measured total when this ratchet was introduced (165,905
/// characters), rounded up to the next 1,000. The backlog item proposed
/// 160,000, which today's descriptions already exceed; reaching it is
/// description trimming, the later splits of 52ede4f1.
const TOTAL_CEILING: usize = 168_000;

/// The cap on any one tool's description that is not in
/// [`OVERSIZE_ALLOWLIST`], in characters.
const PER_TOOL_CAP: usize = 1_500;

/// Every tool whose description was over [`PER_TOOL_CAP`] when this ratchet
/// was introduced, each at its length then, rounded up to the next 100.
/// Entries only shrink or leave; none is ever added or raised. ONE exception,
/// recorded here: the 2026-11-28 staging merge re-measured six entries (and
/// added `find_workflow`) at the sizes the same batch's PRs reached when they
/// documented new behaviour in the same change as this ratchet (the ingest
/// `wait` default, recall's `route`, the contradiction guard, the hidden
/// deprecate_workflow fork, the self-reported promotion flag); every one is
/// trimming work under backlog 52ede4f1, not a precedent.
const OVERSIZE_ALLOWLIST: &[(&str, usize)] = &[
    ("add_step", 4_300),
    ("apply_label_dedup", 2_000),
    ("batch_submit_claims", 1_800),
    ("check_already_ingested", 1_800),
    ("consolidate_claims", 2_700),
    ("delete_step", 2_300),
    ("deprecate_workflow", 3_200),
    ("evolve_step", 3_100),
    ("export_provenance_prov_o", 1_700),
    ("find_agent", 4_000),
    ("find_workflow", 1_600),
    ("get_claim", 3_300),
    ("get_workflow_plan", 2_500),
    ("improve_workflow_hierarchy", 3_400),
    ("ingest_document", 6_000),
    ("ingest_document_inline", 9_200),
    ("ingest_document_spine", 6_300),
    ("ingest_workflow", 5_600),
    ("link_epistemic", 5_900),
    ("link_hierarchical", 2_600),
    ("list_workflows", 1_800),
    ("mark_duplicate", 3_600),
    ("memorize", 1_700),
    ("patch_claim", 1_600),
    ("patch_edge", 1_600),
    ("plan_label_dedup", 2_000),
    ("recall", 2_700),
    ("recall_with_context", 3_500),
    ("recompute_beliefs", 1_700),
    ("report_hierarchical_outcome", 2_400),
    ("report_workflow_outcome", 1_700),
    ("resolve_backlog_item", 1_900),
    ("retract_bba", 1_800),
    ("store_workflow", 3_100),
    ("submit_claim", 2_100),
    ("submit_ds_evidence", 4_200),
    ("supersede_claim", 1_700),
    ("unmark_duplicate", 1_700),
    ("update_with_evidence", 2_900),
    ("verify_claim", 2_400),
];

/// Every tool's name and description length in characters (a tool with no
/// description counts 0).
fn description_lengths() -> Vec<(String, usize)> {
    let tools = epigraph_mcp::EpiGraphMcpFull::all_tools_json();
    tools
        .as_array()
        .expect("all_tools_json returns an array")
        .iter()
        .map(|t| {
            let name = t["name"]
                .as_str()
                .expect("every tool has a name")
                .to_string();
            let len = t["description"].as_str().map_or(0, |d| d.chars().count());
            (name, len)
        })
        .collect()
}

/// Every way `lengths` breaks the budget, one message per breach (empty when
/// it fits). Each message names the tool (or the total) and its size.
fn budget_violations(lengths: &[(String, usize)]) -> Vec<String> {
    let allow: HashMap<&str, usize> = OVERSIZE_ALLOWLIST.iter().copied().collect();
    let mut out = Vec::new();
    for (name, len) in lengths {
        match allow.get(name.as_str()) {
            Some(&ceiling) if *len > ceiling => out.push(format!(
                "tool `{name}`: description is {len} chars, over its allowlisted ceiling of \
                 {ceiling}. Trim it (the ceilings only go down, backlog 52ede4f1), or justify \
                 the exception in review"
            )),
            Some(_) => {}
            None if *len > PER_TOOL_CAP => out.push(format!(
                "tool `{name}`: description is {len} chars, over the {PER_TOOL_CAP}-char cap. \
                 Trim it, or justify the exception in review (the allowlist only shrinks, \
                 backlog 52ede4f1)"
            )),
            None => {}
        }
    }
    let total: usize = lengths.iter().map(|(_, len)| len).sum();
    if total > TOTAL_CEILING {
        out.push(format!(
            "all tool descriptions total {total} chars, over TOTAL_CEILING = {TOTAL_CEILING}. \
             Trim descriptions rather than raise the ceiling (backlog 52ede4f1)"
        ));
    }
    out
}

#[test]
fn tool_descriptions_fit_the_budget() {
    let lengths = description_lengths();
    assert!(
        lengths.len() > 50,
        "CALIBRATION: expected the full kernel tool list, got {} tools",
        lengths.len()
    );
    let violations = budget_violations(&lengths);
    let mut oversize: Vec<&(String, usize)> = lengths
        .iter()
        .filter(|(_, len)| *len > PER_TOOL_CAP)
        .collect();
    oversize.sort();
    assert!(
        violations.is_empty(),
        "MCP tool descriptions are over budget:\n  {}\n(oversize tools now: {oversize:?}; \
         total {})",
        violations.join("\n  "),
        lengths.iter().map(|(_, len)| len).sum::<usize>()
    );
}

/// Every allowlist entry names a registered tool, so a renamed or deleted tool
/// cannot leave a stale ceiling behind for a new tool of the old name.
#[test]
fn every_allowlisted_tool_is_registered() {
    let names: Vec<String> = description_lengths().into_iter().map(|(n, _)| n).collect();
    for (name, _) in OVERSIZE_ALLOWLIST {
        assert!(
            names.iter().any(|n| n == name),
            "OVERSIZE_ALLOWLIST names `{name}`, which is not a registered tool: drop the entry"
        );
    }
}

/// The ratchet bites for EVERY tool: appending 2,000 characters to any one
/// description is a breach whose message names that tool. Run over the real
/// lengths, so an allowlist ceiling set with too much headroom (or a tool
/// missing from the check) fails here.
#[test]
fn growing_any_one_description_by_2000_chars_is_refused_by_name() {
    let lengths = description_lengths();
    assert!(
        budget_violations(&lengths).is_empty(),
        "CALIBRATION: the real descriptions must fit before growing one"
    );
    for i in 0..lengths.len() {
        let mut grown = lengths.clone();
        grown[i].1 += 2_000;
        let name = &grown[i].0;
        let violations = budget_violations(&grown);
        assert!(
            violations
                .iter()
                .any(|v| v.starts_with(&format!("tool `{name}`:"))),
            "appending 2,000 chars to `{name}` was not refused by name: {violations:?}"
        );
    }
}
