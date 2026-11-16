//! The `query_claims_by_label` tool-level description must tell an agent how
//! to page (backlog b444e39f, part 3).
//!
//! The tool gained a keyset cursor: pass `after` (`""` for the first page) and
//! the response becomes `{claims, next_cursor}`; pass each `next_cursor` back
//! until it is null. Omitting `after` keeps the legacy bare array, which
//! `offset` pages and which drifts under concurrent writes. The tool-level text
//! still read only "Find claims by label using PostgreSQL array containment",
//! so an agent that reads tool descriptions and not every parameter schema kept
//! paging by `offset`, re-reading rows.

fn query_claims_by_label_description() -> String {
    epigraph_mcp::server::EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == "query_claims_by_label")
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .expect("query_claims_by_label is in the manifest and has a description")
}

#[test]
fn query_claims_by_label_description_names_the_keyset_cursor() {
    let d = query_claims_by_label_description();
    for needle in ["`after`", "`next_cursor`", "`offset`"] {
        assert!(d.contains(needle), "description must name {needle}: {d}");
    }
    assert!(
        d.contains("\"\""),
        "description must say the first page passes an empty `after`: {d}"
    );
    assert!(
        d.contains("{claims, next_cursor}"),
        "description must name the keyset response shape: {d}"
    );
}

#[test]
fn query_claims_by_label_description_says_omitting_after_keeps_the_bare_array() {
    let d = query_claims_by_label_description();
    assert!(
        d.contains("bare array"),
        "description must say the legacy shape without `after` is a bare array: {d}"
    );
}
