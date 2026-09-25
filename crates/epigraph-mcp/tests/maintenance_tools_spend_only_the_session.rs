//! Source ratchet: the three MCP maintenance tools run every statement on the
//! `MaintenanceSession` they are handed, and name no server pool.
//!
//! # Why this exists
//!
//! The three tools (`recompute_beliefs`, `sweep_semantic_duplicates`,
//! `backfill_embeddings`) spend a BYPASS viewer, which emits no SQL predicate.
//! Spent on the server's application pool, that viewer is filtered by RLS into
//! zero rows and zero updates with no error: the privileged-viewer /
//! ordinary-pool hybrid. `crates/epigraph-db/tests/no_hybrid_bypass_spend.rs`
//! cannot see these sites, by its own known limit (b): the mint
//! (`maintenance::maintenance_viewer`, called from `server.rs`) and the spend
//! (`src/tools/`) are in different files. This lint closes that gap for
//! these three by construction. Each tool's body must take the session and
//! must not name `server.pool` (or `.pool` on its server argument) anywhere in
//! comment-stripped source.
//!
//! A revert that routes one statement back onto the pool fails here, naming
//! the tool. MEASURED at the time of writing: re-inserting
//! `&server.pool` into `backfill_embeddings`'s selection makes
//! `the_three_maintenance_tools_name_no_server_pool` fail on
//! `tools/embeddings.rs::backfill_embeddings`.

use std::path::Path;

/// `(file under src/tools, function)` for each maintenance tool.
const MAINTENANCE_TOOLS: &[(&str, &str)] = &[
    ("cdst_maintenance.rs", "recompute_beliefs"),
    ("dedup_sweep.rs", "sweep_semantic_duplicates"),
    ("embeddings.rs", "backfill_embeddings"),
];

/// Drop `//` line comments (including `///` and `//!`). String literals are
/// kept: a literal naming the pool field would be a finding, which is the
/// conservative direction (see `no_hybrid_bypass_spend.rs` limit (b2)).
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            // Not inside a string literal on this line (good enough for this
            // source, which has no `//` inside literals in these functions;
            // `the_stripper_keeps_code` pins the case that matters).
            Some(i) if !l[..i].contains('"') => &l[..i],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The body of `pub async fn <name>(` up to the next top-level item.
fn function_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("`pub async fn {name}(` not found"));
    let rest = &src[start..];
    let end = rest[1..]
        .find("\npub ")
        .or_else(|| rest[1..].find("\nfn "))
        .or_else(|| rest[1..].find("\n#[cfg(test)]"))
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

fn tools_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools")
}

#[test]
fn the_three_maintenance_tools_name_no_server_pool() {
    let mut findings = Vec::new();
    for (file, func) in MAINTENANCE_TOOLS {
        let src = std::fs::read_to_string(tools_dir().join(file)).expect("read tool source");
        let stripped = strip_line_comments(&src);
        let body = function_body(&stripped, func);
        for needle in [
            "server.pool",
            "_server.pool",
            ".pool.acquire",
            ".pool.begin",
        ] {
            if body.contains(needle) {
                findings.push(format!("tools/{file}::{func} names `{needle}`"));
            }
        }
        assert!(
            body.contains("MaintenanceSession"),
            "tools/{file}::{func} no longer takes a MaintenanceSession; the bypass viewer and \
             its connection must arrive as one value"
        );
        assert!(
            body.contains("session.split()"),
            "tools/{file}::{func} must take its connection and viewer from the session"
        );
    }
    assert!(
        findings.is_empty(),
        "a maintenance tool reaches the server's application pool, where its bypass viewer \
         reads and writes ZERO rows with no error:\n  {}",
        findings.join("\n  ")
    );
}

/// Calibration: the matcher sees a pool spend inside a body and ignores one in
/// a comment, so a green run means "none there" rather than "matcher broken".
#[test]
fn the_stripper_keeps_code() {
    let src = "pub async fn backfill_embeddings(\n    // not this: &server.pool\n    let r = f(&server.pool);\n}\npub fn next() {}\n";
    let stripped = strip_line_comments(src);
    let body = function_body(&stripped, "backfill_embeddings");
    assert_eq!(body.matches("server.pool").count(), 1, "body was: {body}");
    assert!(
        !body.contains("next"),
        "the body must stop at the next item"
    );
}
