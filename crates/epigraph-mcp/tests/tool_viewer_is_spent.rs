//! Source lint: an MCP tool function that takes a `&Viewer` and runs SQL must
//! actually spend it.
//!
//! # The gap this closes
//!
//! `epigraph-db/tests/visibility_lint.rs` enforces exactly this property — and
//! scans `crates/epigraph-db/src/repos/` only. That was the whole SQL surface
//! when it was written. It is not any more: PR-09 leaves 37 `sqlx::` sites
//! under `crates/epigraph-mcp/src/tools/` (see
//! `no_inline_sql_in_tools.rs`'s ratchet), and twelve of them are the
//! visibility predicates in `recall.rs`.
//!
//! Those twelve were protected by **nothing**. Walk the three controls:
//!
//! * `Viewer::splice`'s missing-marker panic cannot fire — `recall.rs` uses
//!   `sqlx::query!`, which needs a compile-time literal of fixed arity and so
//!   cannot be spliced. The predicates are hand-written in the static
//!   three-bind form instead.
//! * `visibility_lint.rs` never looks at this directory.
//! * `no_inline_sql_in_tools.rs` counts sites; a site with its predicate
//!   deleted counts the same as one with it.
//!
//! `fetch_batched_context` is the reason that matters. It is, by its own doc,
//! "the single largest fail-open the MCP surface had": ten statements, four of
//! which select `c.content` directly. It now takes a `&Viewer` and spends it
//! entirely through hand-written text — which is exactly the shape the splice
//! mechanism exists to prevent, a read that holds a viewer and can silently
//! stop using it. Add an eleventh enrichment statement, or refactor one and
//! drop its three-bind clause, and every gate in the tree stays green while a
//! `recall_with_context` caller starts receiving private sibling-paragraph and
//! atom content verbatim.
//!
//! # Why a sibling rather than widening `visibility_lint.rs`'s scan root
//!
//! Two allowlists that are reviewed for different reasons should not share one
//! constant. `visibility_lint.rs`'s exemptions are corpus-wide maintenance
//! enumerators and write paths; this file's are write-path helpers and test
//! modules. Merging them would mean a reviewer of one has to reason about the
//! other, and `EXPECTED_EXEMPTIONS` is asserted as an exact set precisely so
//! that a new entry is a visible, reviewable diff.
//!
//! The detector is deliberately identical: `.splice(` or the literal
//! `visibility = 'public'` (the static three-bind spelling `visibility.rs`'s
//! module doc names as the accepted macro-site equivalent), or an explicit
//! `VISIBILITY-EXEMPT:` reason. `group_bind()` is NOT accepted, for the reason
//! `visibility_lint.rs` gives: binding an array proves a parameter was
//! supplied, not that the SQL reads it.

use std::path::{Path, PathBuf};

/// Every viewer-taking fn under `src/tools/` that runs SQL and carries a
/// `VISIBILITY-EXEMPT:` reason, as measured on **2026-09-03**.
///
/// Asserted as an exact set, not counted. A NEW exemption is then a diff that
/// names the function, which is the point: an exemption appearing on a READ
/// path is almost always a leak being annotated instead of fixed.
const EXPECTED_EXEMPTIONS: &[(&str, &str)] = &[
    // `papers` (bibliographic records, no `owner_group_id`) and `claim_themes`
    // (plan §2.4's registered `tenancy_exempt` table). Both reasons are written
    // at the site. The `claim_themes` one explicitly records that §2.4's stated
    // control — viewer-scoped clustering — is NOT delivered by PR-09.
    ("recall.rs", "compute_corpus_scope"),
    // `workflows` carries neither `visibility` nor `owner_group_id` (it is not
    // in migration 062's `tier_a`), so the routing probe
    // `SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1)` has nothing to
    // filter on. One boolean leaves the function; both branches it selects
    // between do their own viewer-scoped reads.
    ("workflows.rs", "report_workflow_outcome"),
];

// Four sites that were NOT exempted, recorded because the alternative was
// tempting and wrong.
//
// `ds.rs::submit_ds_evidence`, `ds_auto.rs::auto_wire_ds_update`,
// `link_epistemic.rs::do_link_epistemic` and `workflows.rs::deprecate_workflow`
// each ran a `SELECT <scalar> FROM claims WHERE id = $1` keyed on a
// caller-supplied uuid — a per-id oracle for belief value, authorship or
// label membership, not a bulk read. They sit on write paths, and locked
// decision Q6 assigns write-path authorisation to PR-16, so "annotate and
// defer" had a defensible-sounding case. It was refused: these are READ
// authorisation sites that happen to be reached from a write path, the
// predicate is one line each, and an exemption whose real reason is "we did
// not get to it" is the failure mode `the_exemption_set_is_exactly_what_was_reviewed`
// exists to catch. All four are filtered. What PR-16 still owns is the
// *write* half — whether a viewer who cannot read a claim may write against
// it — which none of these four decides.
const EXEMPT_MARKER: &str = "VISIBILITY-EXEMPT:";

/// The two ways a body can legitimately spend its viewer. Same list, same
/// order, same reasoning as `visibility_lint.rs::SPENT_MARKERS`.
const SPENT_MARKERS: &[&str] = &[".splice(", "visibility = 'public'"];

fn tools_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools")
}

fn tool_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(tools_dir()).expect("read tools dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        out.push((
            name,
            std::fs::read_to_string(&path).expect("read tool file"),
        ));
    }
    out.sort();
    assert!(
        out.len() > 30,
        "expected the tools directory to hold the whole MCP tool surface, \
         found {} files — the lint is looking in the wrong place and would \
         pass vacuously",
        out.len()
    );
    out
}

/// The balanced region starting at `src[start]`, which must be `open`.
///
/// Skips string literals (normal and raw), char literals and line comments, so
/// braces or parens inside SQL text cannot unbalance the count. Ported from
/// `visibility_lint.rs::balanced`; the two must behave identically or the two
/// halves of one property are measured by two different parsers.
fn balanced(src: &str, start: usize, open: u8, close: u8) -> &str {
    let b = src.as_bytes();
    debug_assert_eq!(b[start], open);
    let n = src.len();
    let mut j = start;
    let mut depth = 0usize;
    while j < n {
        if b[j] == b'r' && j + 1 < n && (b[j + 1] == b'#' || b[j + 1] == b'"') {
            let mut k = j + 1;
            let mut hashes = 0usize;
            while k < n && b[k] == b'#' {
                hashes += 1;
                k += 1;
            }
            if k < n && b[k] == b'"' {
                let mut term = String::from('"');
                for _ in 0..hashes {
                    term.push('#');
                }
                j = match src[k + 1..].find(&term) {
                    Some(e) => k + 1 + e + term.len(),
                    None => n,
                };
                continue;
            }
        }
        match b[j] {
            b'"' => {
                let mut k = j + 1;
                while k < n {
                    if b[k] == b'\\' {
                        k += 2;
                        continue;
                    }
                    if b[k] == b'"' {
                        break;
                    }
                    k += 1;
                }
                j = k + 1;
                continue;
            }
            b'\'' if j + 2 < n && b[j + 2] == b'\'' => {
                j += 3;
                continue;
            }
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            c if c == open => depth += 1,
            c if c == close => {
                depth -= 1;
                if depth == 0 {
                    let mut e = j + 1;
                    while e < n && !src.is_char_boundary(e) {
                        e += 1;
                    }
                    return &src[start..e];
                }
            }
            _ => {}
        }
        j += 1;
    }
    &src[start..]
}

struct ViewerFn {
    file: String,
    line: usize,
    name: String,
    body: String,
}

/// Every `fn` under `src/tools/` whose parameter list mentions `Viewer`.
fn viewer_taking_fns() -> Vec<ViewerFn> {
    let mut out = Vec::new();
    for (file, src) in tool_files() {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("fn ") {
            let at = from + rel;
            from = at + 3;

            if at > 0 {
                let prev = src.as_bytes()[at - 1];
                if prev.is_ascii_alphanumeric() || prev == b'_' {
                    continue;
                }
            }

            let after = &src[at + 3..];
            let name_end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            if name_end == 0 {
                continue;
            }
            let name = after[..name_end].to_string();

            let mut cursor = at + 3 + name_end;
            let rest = src[cursor..].trim_start();
            if rest.starts_with('<') {
                let lt = src[cursor..].find('<').expect("just matched") + cursor;
                let generics = balanced(&src, lt, b'<', b'>');
                cursor = lt + generics.len();
            }
            let Some(paren_rel) = src[cursor..].find('(') else {
                continue;
            };
            let paren = cursor + paren_rel;
            if !src[cursor..paren].trim().is_empty() {
                continue;
            }
            let params = balanced(&src, paren, b'(', b')');
            if !params.contains("Viewer") {
                continue;
            }

            let Some(brace_rel) = src[paren + params.len()..].find('{') else {
                continue;
            };
            let brace = paren + params.len() + brace_rel;
            let body = balanced(&src, brace, b'{', b'}').to_string();

            out.push(ViewerFn {
                file: file.clone(),
                line: src[..at].matches('\n').count() + 1,
                name,
                body,
            });
        }
    }
    out
}

#[test]
fn the_scanner_finds_the_tool_surface_rather_than_passing_vacuously() {
    let fns = viewer_taking_fns();
    assert!(
        fns.len() > 40,
        "found only {} viewer-taking fns under src/tools/ — PR-06 and PR-09 \
         between them thread a viewer through far more than that, so the \
         scanner is not matching declarations and every assertion below would \
         be vacuous",
        fns.len()
    );
    // The specific function this lint was written for must be in the set, or
    // the scan is finding the wrong things.
    assert!(
        fns.iter()
            .any(|f| f.file == "recall.rs" && f.name == "fetch_batched_context"),
        "`recall.rs::fetch_batched_context` — the ten-statement enrichment read \
         this lint exists to watch — is not in the scanned set"
    );
}

#[test]
fn every_viewer_taking_tool_fn_that_runs_sql_spends_the_viewer() {
    let fns = viewer_taking_fns();
    let mut offenders = Vec::new();
    for f in &fns {
        if !f.body.contains("sqlx::query") && !f.body.contains("sqlx::raw_sql") {
            // Delegating wrapper: its callee is subject to this lint or to
            // `visibility_lint.rs`.
            continue;
        }
        let spends = SPENT_MARKERS.iter().any(|m| f.body.contains(m));
        let exempt = f.body.contains(EXEMPT_MARKER);
        if !spends && !exempt {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese MCP tool functions take a `&Viewer`, run SQL, and never \
         spend it:\n{}\n\n\
         A read that accepts read authority and ignores it is a fail-open that \
         compiles and returns MORE rows, not fewer — so it passes every \
         \"a stranger cannot read\" test. Spend it with a spliced \
         `/* {{VISIBILITY:<alias>}} */` marker, or (for a `sqlx::query!` macro, \
         which cannot be spliced) the static three-bind form \
         `($N::bool OR <a>.visibility = 'public' OR <a>.owner_group_id = \
         ANY($M::uuid[]))`, or annotate a `VISIBILITY-EXEMPT:` reason and add \
         it to EXPECTED_EXEMPTIONS.\n",
        offenders.join("\n")
    );
}

#[test]
fn the_exemption_set_is_exactly_what_was_reviewed() {
    let mut found: Vec<(String, String)> = viewer_taking_fns()
        .into_iter()
        .filter(|f| {
            (f.body.contains("sqlx::query") || f.body.contains("sqlx::raw_sql"))
                && f.body.contains(EXEMPT_MARKER)
        })
        .map(|f| (f.file, f.name))
        .collect();
    found.sort();
    found.dedup();

    let expected: Vec<(String, String)> = EXPECTED_EXEMPTIONS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();

    assert_eq!(
        found, expected,
        "\n\nThe set of VISIBILITY-EXEMPT tool functions changed.\n\
         An exemption is a leak that was ARGUED rather than fixed, so the set \
         is pinned by name. If the new one is correct, add it to \
         EXPECTED_EXEMPTIONS in the same commit and say at the site why no \
         predicate can be written — and if the reason cites a compensating \
         control, make sure that control exists in this tree.\n"
    );
}
