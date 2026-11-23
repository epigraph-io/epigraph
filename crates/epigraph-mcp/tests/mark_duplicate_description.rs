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

/// The cascade the description promises must be the one the repair runs
/// (backlog 89a1d071 part 3; supersede SPEC K9b). It used to say "the
/// duplicate's edges move to the canonical" with no exception, while the
/// repair leaves every edge that records the duplicate itself on it (K1,
/// K2): an agent's authorship, a supersede act edge, retracted and lineage
/// edges, the identity edge, the ingest's own edges and a non-public
/// duplicate's `executes`. An agent reading the old text expected
/// its authorship to follow the canonical.
#[test]
fn mark_duplicate_description_names_the_edges_that_stay_on_the_duplicate() {
    let d = mark_duplicate_description();
    assert!(
        !d.contains("the duplicate's edges move to the canonical and"),
        "the unqualified edge-move sentence is back: {d}"
    );
    for needle in [
        "except the edges that record the duplicate itself, which stay on it",
        "an agent's authorship of it",
        "a supersede act edge",
        "retracted edges",
        "lineage (supersedes, in any case) edges",
        "the same_as identity edge",
        "the document ingest's own edges",
        "a non-public duplicate's executes edges",
        "retracted instead of moved",
    ] {
        assert!(d.contains(needle), "description lacks {needle:?}: {d}");
    }
}
