//! The agent-facing text for `mark_duplicate` must say how a mark is undone
//! (backlog e8113079; supersede spec K9b). It used to tell an agent to treat
//! a mark as one-way, because no shipped process could complete an un-mark:
//! the request-serving servers hold no administrative (maintenance)
//! connection and an un-mark has no deferred form. The operator CLI
//! `unmark_duplicate` (epigraph-cli) now completes one on the maintenance
//! connection, so the description names that path beside the tool and HTTP
//! route that run it where the connection is held, and no longer says
//! one-way.
//!
//! Asserted against `EpiGraphMcpFull::static_tools()`, the router-derived
//! manifest `tools/list` serves. No DB.

use epigraph_mcp::server::EpiGraphMcpFull;

fn mark_duplicate_description() -> String {
    EpiGraphMcpFull::static_tools()
        .iter()
        .find(|t| t.name == "mark_duplicate")
        .and_then(|t| t.description.as_deref().map(str::to_string))
        .expect("mark_duplicate is in the manifest and has a description")
}

#[test]
fn mark_duplicate_description_names_the_unmark_paths() {
    let d = mark_duplicate_description();
    for needle in [
        // The route that reverses a mark where the administrative connection
        // is held (the MCP tool twin is pinned against the manifest below).
        "POST /api/v1/claims/:id/undedup",
        // Where it is not (every request-serving server): the operator CLI on
        // the maintenance connection.
        "`unmark_duplicate` CLI",
        "maintenance DSN",
        "takes an operator",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
}

#[test]
fn mark_duplicate_description_no_longer_says_a_mark_is_one_way() {
    let d = mark_duplicate_description().to_ascii_lowercase();
    // The old advice, and the rewordings that would restore it.
    for phrase in ["one-way", "one way", "irreversib", "cannot be undone"] {
        assert!(
            !d.contains(phrase),
            "a mark can be un-marked (by an operator on a request server), so the description \
             must not call it {phrase:?}: {d}"
        );
    }
}

/// Regression pin: the description sends an agent to `unmark_duplicate`, so
/// the served manifest must carry a tool of that name. A rename or removal
/// would otherwise leave the description pointing at nothing.
#[test]
fn the_unmark_tool_the_description_names_is_served() {
    assert!(
        EpiGraphMcpFull::static_tools()
            .iter()
            .any(|t| t.name == "unmark_duplicate"),
        "mark_duplicate's description names unmark_duplicate, which tools/list must serve"
    );
}
