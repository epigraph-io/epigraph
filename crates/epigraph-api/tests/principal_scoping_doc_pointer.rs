//! The REST reads and edge writes that act as the token's principal point at
//! the tenancy section that explains why (backlog f0a817fb).
//!
//! `GET /api/v1/claims/by-labels` and `POST /api/v1/edges` run on a
//! connection stamped with the caller's viewer, so a client-credentials
//! service token sees fewer claims than a person's own MCP session: a claim
//! in a group the token does not read is absent from by-labels, and an edge
//! to it is answered 404. That was reported as a filter bug; it is the
//! existence-hiding rule. `docs/tenancy.md`, "Same query, different
//! principal", states it, and each handler's doc comment names that section,
//! so a reader of either handler finds the explanation.
//!
//! What is pinned: the doc comment of each handler names the section, and the
//! section exists under that exact heading and names both endpoints. A
//! renamed heading, a dropped pointer or a section that stops covering one of
//! the endpoints fails here. Source text only: no feature and no database.

use std::path::{Path, PathBuf};

const SECTION: &str = "Same query, different principal";
const POINTER: &str = "`docs/tenancy.md`, \"Same query, different principal\"";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `///` doc comment directly above the FIRST `pub async fn <name>(` in
/// `src`, attribute lines skipped, as one string (the `///` prefixes removed,
/// lines joined with a space so a phrase wrapped across lines still matches).
fn doc_comment_of(src: &str, name: &str) -> String {
    let sig = format!("pub async fn {name}(");
    let lines: Vec<&str> = src.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with(&sig))
        .unwrap_or_else(|| panic!("no `{sig}` in the source"));
    let mut doc = Vec::new();
    for line in lines[..at].iter().rev() {
        let t = line.trim_start();
        if t.starts_with("#[") {
            continue;
        }
        match t.strip_prefix("///") {
            Some(rest) => doc.push(rest.trim()),
            None => break,
        }
    }
    doc.reverse();
    assert!(!doc.is_empty(), "`{name}` has no doc comment");
    doc.join(" ")
}

/// The body of the `### <heading>` section of `md`, up to the next heading.
fn section(md: &str, heading: &str) -> String {
    let wanted = format!("### {heading}");
    let mut lines = md.lines();
    lines
        .by_ref()
        .find(|l| l.trim_end() == wanted)
        .unwrap_or_else(|| panic!("docs/tenancy.md has no `{wanted}` heading"));
    lines
        .take_while(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn list_by_labels_doc_points_at_the_principal_section() {
    let doc = doc_comment_of(
        &read("crates/epigraph-api/src/routes/claims.rs"),
        "list_by_labels",
    );
    assert!(
        doc.contains(POINTER),
        "list_by_labels' doc comment must name {POINTER}; it reads:\n{doc}"
    );
}

#[test]
fn create_edge_doc_points_at_the_principal_section() {
    let doc = doc_comment_of(
        &read("crates/epigraph-api/src/routes/edges.rs"),
        "create_edge",
    );
    assert!(
        doc.contains(POINTER),
        "create_edge's doc comment must name {POINTER}; it reads:\n{doc}"
    );
}

#[test]
fn the_principal_section_exists_and_covers_both_endpoints() {
    let body = section(&read("docs/tenancy.md"), SECTION);
    for endpoint in ["GET /api/v1/claims/by-labels", "POST /api/v1/edges"] {
        assert!(
            body.contains(endpoint),
            "the `{SECTION}` section must name `{endpoint}`"
        );
    }
}
