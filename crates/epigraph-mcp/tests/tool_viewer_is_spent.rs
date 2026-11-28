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

//!
//! # Since backlog ada8ee55: which statement, not only whether
//!
//! Spending the viewer once is not enough: a fn can spend it on a count while
//! the read whose rows it returns runs without it, and every check above
//! passes. [`REVIEWED_CALLS`] closes that the way
//! `epigraph-api/tests/viewer_spend_lint.rs` does for the routes: every
//! database call in a viewer-holding tool fn whose arguments and statement do
//! not spend the viewer is named, with a reason class, as an exact register.
//! The scanner is shared with `epigraph-db/tests/visibility_lint.rs`, which
//! keeps the same register for the repo layer (`viewer_calls/mod.rs`).

use std::path::{Path, PathBuf};

/// Every viewer-taking fn under `src/tools/` that runs SQL and carries a
/// `VISIBILITY-EXEMPT:` reason, as measured on **2026-09-03**.
///
/// Asserted as an exact set, not counted. A NEW exemption is then a diff that
/// names the function, which is the point: an exemption appearing on a READ
/// path is almost always a leak being annotated instead of fixed.
const EXPECTED_EXEMPTIONS: &[(&str, &str)] = &[
    // `claim_themes` (plan §2.4's registered `tenancy_exempt` table); the
    // reason is written at the site, and explicitly records that §2.4's stated
    // control — viewer-scoped clustering — is NOT delivered by PR-09. (`papers`
    // left this site's exemption with migration 246: its count now carries the
    // viewer predicate.)
    ("recall.rs", "compute_corpus_scope"),
    // (`workflow_hierarchical.rs::do_report_hierarchical_outcome_as` left this
    // set with backlog c34a0643: its `workflows` counter read-modify-write
    // moved to `WorkflowRepository::record_hierarchical_outcome`, which
    // splices the viewer, so the tool runs no inline SQL to exempt.)
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

/// Does `body` spend its viewer?
///
/// Each marker is matched only where it can take effect, through
/// [`spend_views`]: the method-call marker (`.splice(`) against the body's
/// CODE — Rust comments removed and string contents blanked — and the SQL-text
/// marker (`visibility = 'public'`) against its LIVE SQL — Rust comments
/// removed, string contents kept minus their own `--` / `/* */` comments. So a
/// commented-out call, a log line naming the method, and a predicate commented
/// out of the statement all fail to count.
///
/// Only the spend side is stripped. [`EXEMPT_MARKER`] is read from the raw body
/// on purpose: `VISIBILITY-EXEMPT:` is a comment convention, and stripping it
/// would turn a reviewed exemption into an offender.
fn spends_viewer(body: &str) -> bool {
    let (code, live_sql) = spend_views(body);
    SPENT_MARKERS.iter().any(|m| {
        let is_call = m.starts_with('.') && m.ends_with('(');
        let view = if is_call { &code } else { &live_sql };
        view.contains(m)
    })
}

/// The two texts a SPEND check reads, returned as `(code, live_sql)`.
///
/// A copy of `epigraph-db/tests/lint_text/mod.rs::spend_views`, with a
/// byte-identical body. It lives in this file rather than in this crate's
/// `lint_text` module because `tool_viewer_coverage.rs` also compiles that
/// module and has no spend check, so it would be dead code there.
///
///
/// * **`code`** — Rust comments removed and string-literal CONTENTS blanked,
///   the quotes kept. A method-call marker (`.splice(`, `.splice_write(`)
///   counts only here: written inside a string — a log line, an error
///   message — it calls nothing.
/// * **`live_sql`** — Rust comments removed, string-literal contents kept minus
///   the comments of the SQL they carry: `--` up to the end of its line (a real
///   newline or a `\n` escape) and `/* */` spans. A SQL-text marker
///   (`visibility = 'public'`) counts only here: a predicate commented out of
///   the statement is not one the database evaluates.
///
/// One pass over the RAW source, with the comment and char-literal rules of
/// `lint_text::strip_comments`. It does not run on that function's output,
/// because that output drops the byte after each `\` escape — the byte that
/// tells `\n` (an SQL newline) from any other escape.
///
/// Limits, stated so a green run is not read as more than it is:
///
/// * A `--` inside a SQL quoted literal (`'--'`) is read as a comment. That
///   over-strips: it can only hide a marker and report a function as unspent,
///   a loud failure.
/// * An SQL comment is ended at the close of its Rust string. Where one
///   statement is assembled from several literals with no newline between
///   them, a comment that runs on into the next literal is not followed.
/// * Raw strings are read with ordinary-string rules, as `strip_comments`
///   reads them. The `"` pairs of sqlx `AS "col!"` overrides inside an
///   `r#"…"#` statement keep the state in sync at the literal's end; the
///   override name between them is read as code, in both views alike.
///
/// The `VISIBILITY-EXEMPT:` marker reads neither view: it is a comment
/// convention by design and is read from the raw body.
fn spend_views(src: &str) -> (String, String) {
    let b = src.as_bytes();
    let mut code = String::with_capacity(b.len());
    let mut sql = String::with_capacity(b.len());
    let mut i = 0;
    let (mut in_line, mut in_block, mut in_str) = (false, false, false);
    let (mut sql_line, mut sql_block) = (false, false);
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if in_line {
            if c == b'\n' {
                in_line = false;
                code.push('\n');
                sql.push('\n');
            }
        } else if in_block {
            if c == b'*' && next == Some(b'/') {
                in_block = false;
                i += 1;
            }
        } else if in_str {
            if c == b'\\' {
                // An escape is never a delimiter. `\n` is an SQL newline, so it
                // ends an SQL line comment; `\` + a real newline is a Rust line
                // continuation, which removes the newline, so it does not.
                if sql_line && next == Some(b'n') {
                    sql_line = false;
                }
                if !sql_line && !sql_block {
                    sql.push('\\');
                    if let Some(n) = next {
                        sql.push(n as char);
                    }
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                (in_str, sql_line, sql_block) = (false, false, false);
                code.push('"');
                sql.push('"');
            } else if sql_line {
                if c == b'\n' {
                    sql_line = false;
                    sql.push('\n');
                }
            } else if sql_block {
                if c == b'*' && next == Some(b'/') {
                    sql_block = false;
                    i += 1;
                }
            } else if c == b'-' && next == Some(b'-') {
                sql_line = true;
                i += 1;
            } else if c == b'/' && next == Some(b'*') {
                sql_block = true;
                i += 1;
            } else {
                sql.push(c as char);
            }
        } else if c == b'/' && next == Some(b'/') {
            in_line = true;
            i += 1;
        } else if c == b'/' && next == Some(b'*') {
            in_block = true;
            i += 1;
        } else if c == b'\'' {
            // The char-literal SHAPE rule of `strip_comments`, for the same
            // reason: a lifetime tick must not open a string, and the contents
            // of `'"'` must not either.
            let close = if next == Some(b'\\') {
                (i + 2..(i + 14).min(b.len())).find(|&k| b[k] == b'\'')
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(i + 2)
            } else {
                None
            };
            let end = close.unwrap_or(i);
            for &x in &b[i..=end] {
                code.push(x as char);
                sql.push(x as char);
            }
            i = end;
        } else {
            if c == b'"' {
                in_str = true;
            }
            code.push(c as char);
            sql.push(c as char);
        }
        i += 1;
    }
    (code, sql)
}

/// One line per viewer-taking fn that runs SQL, does not spend its viewer and
/// carries no `VISIBILITY-EXEMPT:` reason — the verdict
/// [`every_viewer_taking_tool_fn_that_runs_sql_spends_the_viewer`] asserts empty.
fn unspent_offenders(fns: &[ViewerFn]) -> Vec<String> {
    let mut offenders = Vec::new();
    for f in fns {
        if !f.body.contains("sqlx::query") && !f.body.contains("sqlx::raw_sql") {
            // Delegating wrapper: its callee is subject to this lint or to
            // `visibility_lint.rs`.
            continue;
        }
        let spends = spends_viewer(&f.body);
        let exempt = f.body.contains(EXEMPT_MARKER);
        if !spends && !exempt {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }
    offenders
}

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
    tool_files()
        .into_iter()
        .flat_map(|(file, src)| viewer_taking_fns_in(&file, &src))
        .collect()
}

/// [`viewer_taking_fns`] over ONE source string, so the verdict can be
/// exercised on synthetic sources that do not exist under `src/tools/`.
fn viewer_taking_fns_in(file: &str, src: &str) -> Vec<ViewerFn> {
    let mut out = Vec::new();
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
            let generics = balanced(src, lt, b'<', b'>');
            cursor = lt + generics.len();
        }
        let Some(paren_rel) = src[cursor..].find('(') else {
            continue;
        };
        let paren = cursor + paren_rel;
        if !src[cursor..paren].trim().is_empty() {
            continue;
        }
        let params = balanced(src, paren, b'(', b')');
        if !params.contains("Viewer") {
            continue;
        }

        let Some(brace_rel) = src[paren + params.len()..].find('{') else {
            continue;
        };
        let brace = paren + params.len() + brace_rel;
        let body = balanced(src, brace, b'{', b'}').to_string();

        out.push(ViewerFn {
            file: file.to_string(),
            line: src[..at].matches('\n').count() + 1,
            name,
            body,
        });
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
    let offenders = unspent_offenders(&viewer_taking_fns());

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

/// A spend marker counts only where it is CODE, never where it is prose.
///
/// The fixtures are synthetic source strings run through the same selector and
/// the same verdict as the real scan, so this test cannot be satisfied by
/// editing `src/tools/`.
#[test]
fn spend_markers_count_only_in_code_not_in_comments() {
    // 1. Markers present only in comments (line, block, doc): the SQL runs
    //    with no predicate, so the function must be reported.
    let commented = r#"
        pub async fn list_titles(pool: &PgPool, viewer: &Viewer) -> Result<Vec<String>, McpError> {
            // let sql = viewer.splice("SELECT c.content FROM claims c WHERE /* {VISIBILITY:c} */");
            /* previously: AND (c.visibility = 'public' OR ...) */
            /// TODO restore viewer.splice( here
            let rows = sqlx::query_scalar("SELECT content FROM claims")
                .fetch_all(pool)
                .await?;
            Ok(rows)
        }
    "#;
    let fns = viewer_taking_fns_in("synthetic.rs", commented);
    assert_eq!(fns.len(), 1, "the fixture must be selected: {}", fns.len());
    let offenders = unspent_offenders(&fns);
    assert_eq!(
        offenders.len(),
        1,
        "a viewer-taking fn whose only `.splice(` / `visibility = 'public'` \
         text is inside comments runs its SQL unfiltered and must be reported, \
         got {offenders:?}"
    );
    assert!(offenders[0].contains("list_titles"), "{}", offenders[0]);

    // 2. A real `.splice(` call spends the viewer.
    let spliced = r#"
        pub async fn list_titles(pool: &PgPool, viewer: &Viewer) -> Result<Vec<String>, McpError> {
            let sql = viewer.splice("SELECT c.content FROM claims c WHERE /* {VISIBILITY:c} */", 1);
            let rows = sqlx::query_scalar(&sql).fetch_all(pool).await?;
            Ok(rows)
        }
    "#;
    assert!(
        unspent_offenders(&viewer_taking_fns_in("synthetic.rs", spliced)).is_empty(),
        "a spliced statement must count as spending the viewer"
    );

    // 3. The static three-bind predicate lives INSIDE the SQL string literal,
    //    so string contents must stay visible to the spend check.
    let three_bind = r#"
        pub async fn list_titles(pool: &PgPool, viewer: &Viewer) -> Result<Vec<String>, McpError> {
            let rows = sqlx::query_scalar!(
                "SELECT c.content FROM claims c WHERE ($1::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($2::uuid[]))",
                viewer.bypass_bind(),
                &viewer.group_bind()
            )
            .fetch_all(pool)
            .await?;
            Ok(rows)
        }
    "#;
    assert!(
        unspent_offenders(&viewer_taking_fns_in("synthetic.rs", three_bind)).is_empty(),
        "the static three-bind predicate inside a SQL literal must count as \
         spending the viewer"
    );

    // 4. `VISIBILITY-EXEMPT:` is a comment convention by design, including a
    //    Rust line comment: it must still exempt (and stay in the reviewed
    //    exemption set, which reads the same raw body).
    let exempt = r#"
        pub async fn corpus_size(pool: &PgPool, viewer: &Viewer) -> Result<i64, McpError> {
            // VISIBILITY-EXEMPT: corpus-cardinality scalar, no row content leaves.
            let n = sqlx::query_scalar("SELECT COUNT(*) FROM claims").fetch_one(pool).await?;
            Ok(n)
        }
    "#;
    assert!(
        unspent_offenders(&viewer_taking_fns_in("synthetic.rs", exempt)).is_empty(),
        "a `// VISIBILITY-EXEMPT:` line comment must still exempt the function"
    );
}

/// A synthetic viewer-taking tool function whose body is `body`, for the
/// SQL-text spend fixtures below.
fn viewer_fn_fixture(body: &str) -> String {
    format!(
        "
        pub async fn titles(pool: &PgPool, viewer: &Viewer) -> Result<Vec<String>, McpError> {{
            {body}
        }}
    "
    )
}

/// The verdict for one synthetic function: is it reported as unspent?
fn fixture_is_unspent(body: &str) -> bool {
    let fns = viewer_taking_fns_in("synthetic.rs", &viewer_fn_fixture(body));
    assert_eq!(fns.len(), 1, "the fixture must be selected: {}", fns.len());
    unspent_offenders(&fns).len() == 1
}

/// `visibility = 'public'` commented out INSIDE the SQL text with `--` is not a
/// predicate the database evaluates, so it must not spend the viewer.
#[test]
fn a_predicate_inside_an_sql_line_comment_does_not_spend() {
    assert!(
        fixture_is_unspent(
            r#"Ok(sqlx::query_scalar("SELECT c.content FROM claims c WHERE c.id = $1 -- AND ($2::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($3::uuid[]))").fetch_all(pool).await?)"#
        ),
        "a three-bind predicate after an in-SQL `--` is commented out of the \
         statement and must not count as spending the viewer"
    );
}

/// The same for an in-SQL `/* */` comment.
#[test]
fn a_predicate_inside_an_sql_block_comment_does_not_spend() {
    assert!(
        fixture_is_unspent(
            r#"Ok(sqlx::query_scalar("SELECT c.content FROM claims c /* WHERE c.visibility = 'public' */").fetch_all(pool).await?)"#
        ),
        "a predicate inside an in-SQL `/* */` comment must not count as \
         spending the viewer"
    );
}

/// `.splice(` is a METHOD CALL: written inside a string
/// literal (a log line, an error message) it calls nothing.
#[test]
fn a_splice_call_named_only_inside_a_string_does_not_spend() {
    let body = r#"tracing::debug!("not yet routed through viewer.splice( here");
            Ok(sqlx::query_scalar("SELECT c.content FROM claims c").fetch_all(pool).await?)"#;
    assert!(
        fixture_is_unspent(body),
        "`.splice(` inside a string literal is not a call and must not count \
         as spending the viewer"
    );
}

/// The over-strip guard for the two tests above: an in-SQL `--` comment ends at
/// the end of ITS line, so a live predicate on the next line of the same
/// literal — a real newline or a `\n` escape — still spends the viewer.
#[test]
fn an_sql_comment_does_not_hide_a_live_predicate_on_a_later_line() {
    let multi_line = r#"Ok(sqlx::query_scalar(
                "SELECT c.content FROM claims c
                 -- visibility: the static three-bind form
                 WHERE ($1::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($2::uuid[]))",
            ).fetch_all(pool).await?)"#;
    assert!(
        !fixture_is_unspent(multi_line),
        "a `--` line must not hide the live predicate on the next line"
    );

    let escaped = r#"Ok(sqlx::query_scalar("SELECT c.content FROM claims c -- read path\n WHERE ($1::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($2::uuid[]))").fetch_all(pool).await?)"#;
    assert!(
        !fixture_is_unspent(escaped),
        "a `\\n` escape ends an in-SQL `--` comment like a real newline does"
    );

    let after_block = r#"Ok(sqlx::query_scalar("SELECT c.content FROM claims c /* read path */ WHERE ($1::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($2::uuid[]))").fetch_all(pool).await?)"#;
    assert!(
        !fixture_is_unspent(after_block),
        "an in-SQL `/* */` comment must not hide the predicate after it"
    );

    let char_quote = r#"let _q = '"';
            Ok(sqlx::query_scalar("SELECT c.content FROM claims c WHERE ($1::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($2::uuid[]))").fetch_all(pool).await?)"#;
    assert!(
        !fixture_is_unspent(char_quote),
        "a `'\"'` char literal must not desynchronise the string state"
    );
}

// ── the per-call register (backlog ada8ee55) ────────────────────────────────

#[path = "../../epigraph-db/tests/viewer_calls/mod.rs"]
mod viewer_calls;

use viewer_calls::{Measured, Population, Surface};

/// The MCP tools' database handles, for the per-call scanner.
const TOOLS: Surface = Surface {
    state_types: &["EpiGraphMcpFull"],
    // `scoped` is the server's `ScopedPool`: it runs nothing without a viewer
    // or a maintenance lease, but a helper handed it can resolve another
    // principal's viewer (`write_recall_audit`), so a call handed it is a
    // database call like one handed `pool`.
    pool_fields: &["pool", "scoped"],
    state_db_methods: &["read_as"],
    viewer_ctors: &[
        "request_viewer(",
        "caller_viewer(",
        "maintenance_viewer(",
        "Viewer::resolve(",
        "Viewer::resolve_elevated(",
    ],
    // The maintenance session a cascade runs on, opened directly or through
    // the supersede helpers that return it beside a deferral status.
    conn_ctors: &[
        "admin_cascade_session(",
        "maintenance_tool_session(",
        "admin_session_or_deferral(",
        "supersede_session_or_deferral(",
    ],
    conn_closure_macros: &[],
    marker_spend: call_spends_viewer,
};

/// The per-call marker spend: the statement's live SQL (comments removed) puts
/// `visibility = 'public'` in predicate position. See
/// [`viewer_calls::predicate_spend`].
fn call_spends_viewer(region: &str) -> bool {
    let (_, live_sql) = spend_views(region);
    viewer_calls::predicate_spend(&live_sql)
}

/// Every database call in a viewer-holding tool fn that does not spend the
/// fn's viewer, as measured and reviewed on **2026-11-22** (backlog ada8ee55):
/// the per-call register `epigraph-api/tests/viewer_spend_lint.rs` keeps for
/// the routes, for the MCP tools. The fn-level check above passes a fn that
/// spends its viewer ONCE; this names every other call, so a content read
/// running beside the spend without it cannot pass unseen.
///
/// The population is every fn under `src/tools/`, and in the crate-root files
/// a tool hands its viewer to (`claim_helper.rs`, `maintenance.rs`, ..; see
/// [`root_files`]), that takes a `Viewer` or binds one (`request_viewer`,
/// `Viewer::resolve`, a `unwrap_or(viewer)` fallback, or a field destructured
/// from a viewer-carrier struct such as `label_dedup.rs::UnitContext`; see
/// [`viewer_carrier_structs_are_reviewed`]). The `#[tool]` methods
/// in `server.rs` are not in it: each resolves the viewer and hands it to a fn
/// here, and none touches a pool, a connection or a repository itself
/// (measured 2026-11-22). Viewer-taking fns in other crates a tool calls are
/// not followed: a call that hands one the viewer counts as viewed here, and
/// the callee's own body is measured by its crate's register
/// (`epigraph-engine/tests/viewer_calls_register.rs`,
/// `epigraph-ingest-executor/tests/viewer_calls_register.rs`, backlog
/// 37e68f5b; the repo layer's is `epigraph-db/tests/visibility_lint.rs`).
///
/// Asserted as an exact multiset per fn. The comment above each entry is the
/// review, by reason class:
///
/// * **write** — the call writes, on the author-stamped transaction the fn
///   opened (or on `server.pool`, where the entry says "Raw pool"), a row
///   about a target the fn read through its viewer first. Write
///   authority is the stamp's `WITH CHECK` plus the write registers
///   (`residual_unstamped_writes.rs`; the few writes on `server.pool` are
///   named in `raw_pool_register.rs`). A write returns at most the ids and
///   flags it wrote.
/// * **opener** — opens the transaction a write runs on, stamped from the
///   AUTHOR (`begin_author_stamped_tx`, `begin_caller_workflow_tx`,
///   `begin_ingest_tx`), or returns the server's `ScopedPool` (`scoped`). It
///   is handed the server, not the viewer, by design, and reads no content.
/// * **authority** — decides whether the caller may act on a target it has
///   already read through its viewer: ownership and operator links
///   (`require_owner_or_admin`, the workflow-authority arms), the target's
///   tenancy or the caller's own default (`tenancy_on_session_conn`,
///   `default_decl_for_author`), a hidden-row or foreign-owner boolean. It
///   returns allow or refuse, never row content.
/// * **stamped or raw-pool fallback** — a `stamped` read that, on a server
///   built without a `ScopedPool` (a fixture), falls back to `server.pool`,
///   as `raw_pool_register.rs` registers it.
/// * **stamped** — a read on the caller's viewer-stamped connection
///   (`server.read_as`) or author-stamped transaction, of a table whose forced
///   row security carries its tenancy (`workflows`, migration 183), or of the
///   caller's own rows (its bug reports, its elevation, its memberships), or a
///   boolean about an edge the fn just read or wrote. Stamping is not a spend
///   (row security only), so each is listed.
/// * **untenanted** — the table has no tenancy columns: `agents`,
///   `entities` and `entity_types`, `claim_themes`, `match_candidates`.
///   (`papers` carries tenancy since migration 246 and `behavioral_executions`
///   since migration 240: a read of either is stamped or viewed.)
/// * **narrows** — `derivation_scope::retain_for_cache` filters rows the fn
///   already read through the viewer; it can drop a row, never add one.
/// * **audit** — records the caller's own act (an event, a recall audit row,
///   a workflow-write record, a cascade deferral).
/// * **maintenance** — opens the admin cascade session, or records its
///   deferral, after the act's gate; the cascade runs there by design.
///   "maintenance (counts only)" is a cascade run on that session without the
///   caller's viewer whose result reaches the response only as counts.
/// * **resolves** — `Viewer::resolve`, the membership read that builds the
///   viewer itself.
/// * **no SQL** — handed the server for something that is not a tenancy read:
///   an embedding stored on the author's stamp, the label-dedup profile and
///   its limits, the evidence-type vocabulary.
///
/// No entry reads content into a response without the viewer: the review
/// found nothing to fix. Do not add an entry to make the build pass. Read the
/// call; if it reads something the caller may not read, give it the viewer.
const REVIEWED_CALLS: &[(&str, &str, &[&str])] = &[
    // write: `CountersignRepository::countersign_conn`; opener: `scoped`.
    (
        "agent_lookup.rs",
        "countersign_authorship",
        &["CountersignRepository::countersign_conn", "scoped"],
    ),
    // opener: `scoped`.
    ("agent_lookup.rs", "find_agent", &["scoped"]),
    // opener: `scoped`.
    ("agent_lookup.rs", "get_agent", &["scoped"]),
    // write: `MassFunctionRepository::retract_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`.
    (
        "bba_retract.rs",
        "retract_bba",
        &[
            "MassFunctionRepository::retract_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `MassFunctionRepository::unretract_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`.
    (
        "bba_retract.rs",
        "unretract_bba",
        &[
            "MassFunctionRepository::unretract_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // stamped: `BugReportRepository::list_mine_conn`.
    (
        "bug_report.rs",
        "list_my_bug_reports",
        &["BugReportRepository::list_mine_conn"],
    ),
    // write: `BugReportRepository::submit_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority:
    // `BugReportRepository::preflight_conn`.
    (
        "bug_report.rs",
        "submit_bug_report",
        &[
            "BugReportRepository::preflight_conn",
            "BugReportRepository::submit_conn",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `ChallengeRepository::create`; opener: `claim_helper::begin_author_stamped_tx`;
    // audit: `EventRepository::publish_or_log_conn`.
    (
        "challenges.rs",
        "challenge_claim",
        &[
            "ChallengeRepository::create",
            "EventRepository::publish_or_log_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `ChallengeRepository::resolve_as_claim_owner`; opener:
    // `claim_helper::begin_author_stamped_tx`.
    (
        "challenges.rs",
        "resolve_challenge",
        &[
            "ChallengeRepository::resolve_as_claim_owner",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // no SQL: `submission_evidence` builds the submission's evidence row in memory and signs it
    // with the server's key (the server is handed over for its signer); it reads nothing.
    (
        "claims.rs",
        "corroborate_submission",
        &["submission_evidence"],
    ),
    // no SQL: `claim_helper::embed_claim_author_stamped`.
    (
        "claims.rs",
        "finish_submission",
        &["claim_helper::embed_claim_author_stamped"],
    ),
    // authority: `require_owner_or_admin`.
    (
        "claims.rs",
        "gate_retirement_label",
        &["require_owner_or_admin"],
    ),
    // write: `ClaimRepository::patch_claim_atomic_conn`, `admin_write::admin_patch`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority: `require_owner_or_admin`.
    (
        "claims.rs",
        "patch_claim",
        &[
            "ClaimRepository::patch_claim_atomic_conn",
            "admin_write::admin_patch",
            "claim_helper::begin_author_stamped_tx",
            "require_owner_or_admin",
        ],
    ),
    // authority: `claim_helper::resolve_claim_visibility`.
    (
        "claims.rs",
        "prepare_submission",
        &["claim_helper::resolve_claim_visibility"],
    ),
    // write: `ClaimRepository::update_labels_conn`, `admin_write::admin_patch`; authority:
    // `require_owner_or_admin`.
    (
        "claims.rs",
        "relabel_claim",
        &[
            "ClaimRepository::update_labels_conn",
            "admin_write::admin_patch",
            "require_owner_or_admin",
        ],
    ),
    // write: `ClaimRepository::update_labels_conn`,
    // `EdgeRepository::create_if_not_exists_signed_conn`, `admin_write::admin_patch`; opener:
    // `claim_helper::begin_author_stamped_tx`, `claim_helper::begin_author_stamped_tx_for`;
    // authority: `ClaimRepository::default_decl_for_author`,
    // `ClaimRepository::tenancy_on_session_conn`, `require_owner_or_admin`.
    (
        "claims.rs",
        "resolve_backlog_item",
        &[
            "ClaimRepository::default_decl_for_author",
            "ClaimRepository::tenancy_on_session_conn",
            "ClaimRepository::update_labels_conn",
            "EdgeRepository::create_if_not_exists_signed_conn",
            "admin_write::admin_patch",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::begin_author_stamped_tx_for",
            "require_owner_or_admin",
            "require_owner_or_admin",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx_for`.
    (
        "claims.rs",
        "submit_claim_response",
        &["claim_helper::begin_author_stamped_tx_for"],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`.
    (
        "claims.rs",
        "update_labels",
        &["claim_helper::begin_author_stamped_tx"],
    ),
    // write: `ClaimRepository::update_labels_conn`, `ClaimRepository::update_truth_value_conn`,
    // `EvidenceRepository::create_with_source_url`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority:
    // `foreign_attach::is_foreign_public_claim`, `require_owner_or_admin`. (The DS wiring and
    // its divergence record run in `wire_attached_evidence_in_tx`, entry below.)
    (
        "claims.rs",
        "update_with_evidence",
        &[
            "ClaimRepository::update_labels_conn",
            "ClaimRepository::update_truth_value_conn",
            "EvidenceRepository::create_with_source_url",
            "claim_helper::begin_author_stamped_tx",
            "foreign_attach::is_foreign_public_claim",
            "require_owner_or_admin",
        ],
    ),
    // untenanted: `AgentRepository::key_kind_of_public_key`, the `agents.key_kind` of the
    // signer's public key of a claim the fn already read through the viewer, on the caller's
    // stamped read; it returns a key kind (is the bare key a signature verifier), never a row.
    (
        "claims.rs",
        "verify_claim_report",
        &["AgentRepository::key_kind_of_public_key"],
    ),
    // write: `ds_divergence::record_divergence`, the divergence row of the BBA this fn just
    // combined, on the caller's author-stamped connection (`update_with_evidence`'s and the
    // novelty gate's corroboration share this core); the claim was read through the viewer
    // by its caller, and the frame reads here take the viewer.
    (
        "claims.rs",
        "wire_attached_evidence_in_tx",
        &["ds_divergence::record_divergence"],
    ),
    // write: `ClaimRepository::update_labels_conn`, `ClaimRepository::update_trace_id_conn`,
    // `EvidenceRepository::create_with_source_url`,
    // `ReasoningTraceRepository::create_with_reasoning_type`,
    // `claim_helper::emit_verb_edge_best_effort`; authority:
    // `claim_helper::claim_tenancy_report`; no SQL: `submission_evidence` (builds and signs
    // the evidence row in memory).
    (
        "claims.rs",
        "write_submission",
        &[
            "ClaimRepository::update_labels_conn",
            "ClaimRepository::update_trace_id_conn",
            "EvidenceRepository::create_with_source_url",
            "ReasoningTraceRepository::create_with_reasoning_type",
            "claim_helper::claim_tenancy_report",
            "claim_helper::emit_verb_edge_best_effort",
            "claim_helper::emit_verb_edge_best_effort",
            "submission_evidence",
        ],
    ),
    // write: `ClaimRepository::consolidate_act_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; maintenance:
    // `supersede::admin_session_or_deferral`; maintenance (counts only):
    // `admin_cascade::apply_after_consolidate` migrates the retired sources'
    // edges on the admin session and returns only `edges_migrated` /
    // `edges_deduped` counts (the ids stay in the audit row); no SQL:
    // `claim_helper::embed_claim_author_stamped`.
    (
        "consolidate.rs",
        "consolidate_claims",
        &[
            "ClaimRepository::consolidate_act_conn",
            "admin_cascade::apply_after_consolidate",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::embed_claim_author_stamped",
            "supersede::admin_session_or_deferral",
        ],
    ),
    // write: `FrameRepository::assign_claim`, `MassFunctionRepository::store_with_perspective`,
    // `ds_divergence::record_divergence`; opener: `claim_helper::begin_author_stamped_tx`;
    // authority: `foreign_attach::is_foreign_public_claim`; no SQL: `evidence_type_resolves`.
    (
        "ds.rs",
        "submit_ds_evidence",
        &[
            "FrameRepository::assign_claim",
            "MassFunctionRepository::store_with_perspective",
            "claim_helper::begin_author_stamped_tx",
            "ds_divergence::record_divergence",
            "evidence_type_resolves",
            "foreign_attach::is_foreign_public_claim",
        ],
    ),
    // write: `FrameRepository::assign_claim`, `MassFunctionRepository::store_with_perspective`,
    // `MassFunctionRepository::update_claim_belief`; stamped: `optional_read_under_savepoint`.
    (
        "ds_auto.rs",
        "auto_wire_ds_for_claim",
        &[
            "FrameRepository::assign_claim",
            "MassFunctionRepository::store_with_perspective",
            "MassFunctionRepository::update_claim_belief",
            "optional_read_under_savepoint",
            "optional_read_under_savepoint",
        ],
    ),
    // write: `FrameRepository::assign_claim`, `MassFunctionRepository::store_for_evidence`
    // (the evidence slot, migration 267), `MassFunctionRepository::store_with_perspective`,
    // `MassFunctionRepository::update_claim_belief`; stamped:
    // `optional_read_under_savepoint`; narrows: `derivation_scope::retain_for_cache`.
    (
        "ds_auto.rs",
        "auto_wire_ds_update_filed_on",
        &[
            "FrameRepository::assign_claim",
            "FrameRepository::assign_claim",
            "MassFunctionRepository::store_for_evidence",
            "MassFunctionRepository::store_with_perspective",
            "MassFunctionRepository::update_claim_belief",
            "derivation_scope::retain_for_cache",
            "optional_read_under_savepoint",
            "optional_read_under_savepoint",
            "optional_read_under_savepoint",
        ],
    ),
    // write: `FrameRepository::create`.
    (
        "ds_auto.rs",
        "ensure_axis_frame",
        &["FrameRepository::create"],
    ),
    // write: `FrameRepository::assign_claim`, `MassFunctionRepository::store_with_perspective`.
    (
        "ds_auto.rs",
        "wire_single_batch_entry",
        &[
            "FrameRepository::assign_claim",
            "MassFunctionRepository::store_with_perspective",
        ],
    ),
    // write: `EdgeRepository::retract_by_id`, `EdgeRepository::withdraw_edge_bbas_conn`;
    // opener: `claim_helper::begin_author_stamped_tx`; audit:
    // `EventRepository::publish_or_log_conn`.
    (
        "edge_mutation.rs",
        "do_delete_edge",
        &[
            "EdgeRepository::retract_by_id",
            "EdgeRepository::withdraw_edge_bbas_conn",
            "EventRepository::publish_or_log_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `EdgeRepository::update_valid_to_and_properties`,
    // `EdgeRepository::withdraw_edge_bbas_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; audit: `EventRepository::publish_or_log_conn`.
    (
        "edge_mutation.rs",
        "do_patch_edge",
        &[
            "EdgeRepository::update_valid_to_and_properties",
            "EdgeRepository::withdraw_edge_bbas_conn",
            "EventRepository::publish_or_log_conn",
            "EventRepository::publish_or_log_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // opener: `scoped`.
    ("elevation.rs", "propose_admin_act", &["scoped"]),
    // write: `ElevationCeremony::create_ticket`; opener: `scoped`.
    (
        "elevation.rs",
        "sudo",
        &["ElevationCeremony::create_ticket", "scoped"],
    ),
    // write: `ElevationCeremony::end`; opener: `scoped`; stamped: `ElevationCeremony::live`.
    (
        "elevation.rs",
        "unsudo",
        &[
            "ElevationCeremony::end",
            "ElevationCeremony::live",
            "scoped",
        ],
    ),
    // audit: `EventRepository::insert`. Raw pool: `EventRepository::insert` runs on
    // `server.pool` (registered in `raw_pool_register.rs`).
    ("events.rs", "publish_event", &["EventRepository::insert"]),
    // write: `ClaimRepository::evolve_step_conn`; opener: `claim_helper::begin_author_stamped_tx`;
    // audit: `record_lineage_writes`; maintenance: `supersede::admin_session_or_deferral`; no SQL:
    // `workflow_ingest::embed_created_workflow_claims`. With no ScopedPool the opener refuses
    // (backlog 4cbd4192 removed the `server.pool.begin()` fallback). `require_lineage_authority`
    // now takes the viewer (its own entry).
    (
        "evolve_step.rs",
        "evolve_step",
        &[
            "ClaimRepository::evolve_step_conn",
            "claim_helper::begin_author_stamped_tx",
            "record_lineage_writes",
            "supersede::admin_session_or_deferral",
            "workflow_ingest::embed_created_workflow_claims",
        ],
    ),
    // stamped: `WorkflowRepository::workflows_executing_step_lineage`, on the write transaction
    // under the `workflows` table's forced row security; authority:
    // `WorkflowRepository::step_lineage_executors`, the definer that returns every executing
    // workflow to the server only, which answers a hidden one as an unknown parent, never by id
    // (backlog c831df4a).
    (
        "evolve_step.rs",
        "require_lineage_authority",
        &[
            "WorkflowRepository::step_lineage_executors",
            "WorkflowRepository::workflows_executing_step_lineage",
        ],
    ),
    // write (a lock): `WorkflowRepository::lock_step_lineage_for_evolve` locks the parent's step
    // row and takes its lineage's advisory lock on the evolve's own write transaction, between
    // two viewer-threaded `require_lineage_authority` passes (backlog bf2e9aa6); it returns
    // nothing.
    (
        "evolve_step.rs",
        "require_lineage_authority_locked",
        &["WorkflowRepository::lock_step_lineage_for_evolve"],
    ),
    // authority: `check_explicit_author_ids`.
    (
        "ingest_authors.rs",
        "preflight_document_authors",
        &["check_explicit_author_ids"],
    ),
    // write: `AgentRepository::create_seed_derived_conn`; authority: `attributions`,
    // `check_explicit_author_ids`; untenanted: `AgentLookupRepository::author_nodes`,
    // `AgentLookupRepository::exact_name_candidates`, `AgentRepository::get_by_public_key`,
    // `SystemAgentRepository::registered_agent_ids`; stamped:
    // `AgentDisclosureRepository::disclosure` (migration 309's rule on the walk's
    // stamped transaction, a definer that applies its own audience).
    (
        "ingest_authors.rs",
        "resolve_document_authors",
        &[
            "AgentDisclosureRepository::disclosure",
            "AgentLookupRepository::author_nodes",
            "AgentLookupRepository::exact_name_candidates",
            "AgentRepository::create_seed_derived_conn",
            "AgentRepository::get_by_public_key",
            "SystemAgentRepository::registered_agent_ids",
            "attributions",
            "check_explicit_author_ids",
        ],
    ),
    // untenanted: `AgentRepository::get_by_public_key`.
    (
        "ingest_authors.rs",
        "retract_replaced_name_nodes",
        &["AgentRepository::get_by_public_key"],
    ),
    // write (locks): `ClaimRepository::lock_new_content_hash_agents` takes, in key order, the
    // (content hash, ingesting agent) dedup lock of every NEW atom in the plan before the walk
    // takes any claim row lock (backlog 5b587ae8, #1029); advisory locks only, it reads nothing.
    // write: `ClaimIngestRepository::record_signed_conn`,
    // `ClaimRepository::set_properties_conn`, `ClaimRepository::update_labels_conn`,
    // `ClaimRepository::update_trace_id_conn`,
    // `EdgeRepository::create_if_absent_including_retracted_signed_conn`,
    // `EdgeRepository::create_processed_by_stamp_if_absent_signed_conn`,
    // `EvidenceRepository::create`, `PaperRepository::get_or_create_stored`,
    // `ReasoningTraceRepository::create`,
    // `epigraph_db::create_ingest_written_edge_if_absent_conn`, `label_resolved_claim`,
    // `persist_planned_claim`; opener: `begin_ingest_tx`; authority:
    // `resolve_ingest_visibility`; stamped: `PaperRepository::licence`, read by the id the
    // write returned on the same stamped transaction; no SQL: `spawn_ingest_embeds`. Since
    // migration 246 `PaperRepository::get_or_create_stored` writes `papers` in the ingest's declared
    // scope on that stamped transaction (`begin_ingest_tx`), not on `server.pool`; since
    // backlog b995f117 it is the only write of that row on the detached path too. The body of
    // `do_ingest_document_reporting` (a thin wrapper now, with no SQL of its own). stamped:
    // `ingest_plan_for_scope` (backlog 8f56a641) reads `PaperRepository::asserted_claims_conn`
    // on the same stamped transaction, for the paper row the walk got or created in its own
    // declared scope: the ids that scope's earlier ingest of the document recorded; then
    // `PaperRepository::own_group_legacy_claims_conn`, the owning group's own non-public rows
    // under the global plan's ids or hashes (scoped in its SQL), for a pre-246 ingest; then
    // `PaperRepository::public_twin_recorded_claims_conn`, what the document key's public row
    // recorded, gated and filtered to the group's own and public rows in its SQL.
    (
        "ingestion.rs",
        "ingest_document_walk_reporting",
        &[
            "ClaimIngestRepository::record_signed_conn",
            "ClaimIngestRepository::record_signed_conn",
            "ClaimRepository::lock_new_content_hash_agents",
            "ClaimRepository::set_properties_conn",
            "ClaimRepository::update_labels_conn",
            "ClaimRepository::update_trace_id_conn",
            "EdgeRepository::create_if_absent_including_retracted_signed_conn",
            "EdgeRepository::create_processed_by_stamp_if_absent_signed_conn",
            "EvidenceRepository::create",
            "PaperRepository::get_or_create_stored",
            "PaperRepository::licence",
            "ReasoningTraceRepository::create",
            "begin_ingest_tx",
            "begin_ingest_tx",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "ingest_plan_for_scope",
            "label_resolved_claim",
            "persist_planned_claim",
            "resolve_ingest_visibility",
            "spawn_ingest_embeds",
        ],
    ),
    // write: `ClaimIngestRepository::record_signed_conn`,
    // `ClaimRepository::set_properties_conn`, `ClaimRepository::update_labels_conn`,
    // `ClaimRepository::update_trace_id_conn`,
    // `EdgeRepository::create_if_absent_including_retracted_signed_conn`,
    // `EdgeRepository::create_processed_by_stamp_if_absent_signed_conn`,
    // `EvidenceRepository::create`, `PaperRepository::get_or_create_stored`,
    // `ReasoningTraceRepository::create`,
    // `epigraph_db::create_ingest_written_edge_if_absent_conn`, `label_resolved_claim`,
    // `persist_planned_claim`; opener: `begin_ingest_tx`; authority:
    // `resolve_ingest_visibility`; stamped: `PaperRepository::licence`, read by the id the
    // write returned on the same stamped transaction; no SQL: `spawn_ingest_embeds`. Since
    // migration 246 `PaperRepository::get_or_create_stored` writes `papers` in the ingest's declared
    // scope on that stamped transaction (`begin_ingest_tx`), not on `server.pool`. stamped:
    // `ingest_plan_for_scope`, as in `ingest_document_walk_reporting` above.
    (
        "ingestion.rs",
        "do_ingest_document_spine",
        &[
            "ClaimIngestRepository::record_signed_conn",
            "ClaimIngestRepository::record_signed_conn",
            "ClaimRepository::set_properties_conn",
            "ClaimRepository::update_labels_conn",
            "ClaimRepository::update_trace_id_conn",
            "EdgeRepository::create_if_absent_including_retracted_signed_conn",
            "EdgeRepository::create_processed_by_stamp_if_absent_signed_conn",
            "EvidenceRepository::create",
            "PaperRepository::get_or_create_stored",
            "PaperRepository::licence",
            "ReasoningTraceRepository::create",
            "begin_ingest_tx",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "epigraph_db::create_ingest_written_edge_if_absent_conn",
            "ingest_plan_for_scope",
            "label_resolved_claim",
            "persist_planned_claim",
            "resolve_ingest_visibility",
            "spawn_ingest_embeds",
        ],
    ),
    // opener: `begin_ingest_tx`; authority: `resolve_ingest_visibility`; stamped:
    // `PaperRepository::planned`, the `papers` row of the ingest's own declared scope on its
    // stamped transaction (forced row security since migration 246); it returns the id the write
    // would reuse, never another scope's row, or the id a new row is to take (derived for a public
    // row, random for a group's copy), read-only.
    (
        "ingestion.rs",
        "preflight_write_authority",
        &[
            "PaperRepository::planned",
            "begin_ingest_tx",
            "resolve_ingest_visibility",
        ],
    ),
    // The viewer arrives inside `UnitContext` and is destructured. write:
    // `ClaimRepository::mark_duplicate_act_attributed_conn`, on the
    // author-stamped transaction, after `cross_owner`, `member_not_owned` and
    // `canonical_refusal` read every member and canonical through the viewer;
    // it returns the identity edge's id. opener:
    // `claim_helper::begin_author_stamped_tx`. maintenance:
    // `maintenance::admin_cascade_session`; audit:
    // `admin_cascade::record_deferral` (the deferral row on the act's own
    // transaction). The cascade itself (`apply_after_dedup`) is handed the
    // viewer and filters its report to the caller.
    (
        "label_dedup.rs",
        "apply_unit",
        &[
            "ClaimRepository::mark_duplicate_act_attributed_conn",
            "admin_cascade::record_deferral",
            "claim_helper::begin_author_stamped_tx",
            "maintenance::admin_cascade_session",
        ],
    ),
    // authority: `owner_of`.
    ("label_dedup.rs", "cross_owner", &["owner_of"]),
    // authority: `is_foreign_duplicate`.
    (
        "label_dedup.rs",
        "label_dedup_index_view",
        &["is_foreign_duplicate"],
    ),
    // authority: `claims::require_owner_or_admin`.
    (
        "label_dedup.rs",
        "member_not_owned",
        &["claims::require_owner_or_admin"],
    ),
    // authority: `is_foreign_duplicate`.
    ("label_dedup.rs", "read_family", &["is_foreign_duplicate"]),
    // opener: `claim_helper::begin_author_stamped_tx`; maintenance:
    // `maintenance::admin_cascade_session`.
    (
        "label_dedup.rs",
        "revert_label_dedup",
        &[
            "claim_helper::begin_author_stamped_tx",
            "maintenance::admin_cascade_session",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`; authority:
    // `claims::require_owner_or_admin`.
    (
        "label_dedup.rs",
        "write_check",
        &[
            "claim_helper::begin_author_stamped_tx",
            "claims::require_owner_or_admin",
            "claims::require_owner_or_admin",
        ],
    ),
    // write: `EdgeRepository::create_symmetric_if_absent_returning_signed_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; audit: `workflow_authority::record_workflow_write`
    // (a rival-workflow pair, backlog 41d7b27a; its gate `rival_workflows_gate` reads both
    // workflows through the viewer).
    (
        "link_alternative.rs",
        "do_link_alternative",
        &[
            "EdgeRepository::create_symmetric_if_absent_returning_signed_conn",
            "claim_helper::begin_author_stamped_tx",
            "workflow_authority::record_workflow_write",
        ],
    ),
    // write: `EdgeRepository::create_if_not_exists_signed_conn`,
    // `EdgeRepository::create_symmetric_if_absent_oriented_signed_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority: `EdgeRepository::owned_by_session`;
    // stamped: `EdgeRepository::is_in_force`; audit: `EventRepository::publish_or_log_conn`.
    (
        "link_epistemic.rs",
        "do_link_epistemic",
        &[
            "EdgeRepository::create_if_not_exists_signed_conn",
            "EdgeRepository::create_symmetric_if_absent_oriented_signed_conn",
            "EdgeRepository::is_in_force",
            "EdgeRepository::owned_by_session",
            "EventRepository::publish_or_log_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `EdgeRepository::create_if_not_exists_signed_conn`,
    // `EdgeRepository::create_symmetric_if_absent_returning_signed_conn` (the symmetric
    // `related_to`, backlog 41d7b27a); opener:
    // `claim_helper::begin_author_stamped_tx`; authority: `AgentRepository::speaks_for` (the
    // `asserts` verb's source-agent rule, an allow or refuse over untenanted `agents` and operator
    // links), `EdgeRepository::owned_by_session`, `WorkflowRepository::submitter_of`; stamped:
    // `EdgeRepository::reaches_in_force_conn` (migration 254's cycle-walk definer, which answers a
    // boolean), `WorkflowRepository::canonical_names_of`, `WorkflowRepository::head_by_canonical`,
    // `WorkflowRepository::workflows_executing_step_lineage`; untenanted:
    // `EntityTypeRepository::get_by_name_conn`; audit:
    // `workflow_authority::record_workflow_write`.
    // `workflow_authority::require_workflow_authority` now takes the viewer (its own entry).
    (
        "link_hierarchical.rs",
        "do_link_hierarchical",
        &[
            "AgentRepository::speaks_for",
            "EdgeRepository::create_if_not_exists_signed_conn",
            "EdgeRepository::create_symmetric_if_absent_returning_signed_conn",
            "EdgeRepository::owned_by_session",
            "EdgeRepository::reaches_in_force_conn",
            "EntityTypeRepository::get_by_name_conn",
            "WorkflowRepository::canonical_names_of",
            "WorkflowRepository::canonical_names_of",
            "WorkflowRepository::head_by_canonical",
            "WorkflowRepository::submitter_of",
            "WorkflowRepository::workflows_executing_step_lineage",
            "WorkflowRepository::workflows_executing_step_lineage",
            "claim_helper::begin_author_stamped_tx",
            "workflow_authority::record_workflow_write",
        ],
    ),
    // untenanted: `AgentRepository::get_by_id` for an `agent` endpoint (`agents` has no tenancy;
    // existence only); the claim and workflow arms read through the viewer.
    (
        "link_hierarchical.rs",
        "endpoint_exists",
        &["AgentRepository::get_by_id"],
    ),
    // write: `MatchCandidateRepo::promote_if_pending_conn`,
    // `MatchCandidateRepo::reject_if_pending`; opener: `claim_helper::begin_author_stamped_tx`;
    // untenanted: `MatchCandidateRepo::get`, `MatchCandidateRepo::new`. Raw pool: the
    // `MatchCandidateRepo` is built on `server.pool` (registered in `raw_pool_register.rs`).
    (
        "matching.rs",
        "decide_match_candidate",
        &[
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::new",
            "MatchCandidateRepo::promote_if_pending_conn",
            "MatchCandidateRepo::reject_if_pending",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`; untenanted: `MatchCandidateRepo::get`,
    // `MatchCandidateRepo::new`; audit: `admin_cascade::record_deferral`; maintenance:
    // `maintenance::admin_cascade_session`. Raw pool: the `MatchCandidateRepo` is built on
    // `server.pool` (registered in `raw_pool_register.rs`).
    (
        "matching.rs",
        "retire_match_candidate",
        &[
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::get",
            "MatchCandidateRepo::new",
            "admin_cascade::record_deferral",
            "claim_helper::begin_author_stamped_tx",
            "maintenance::admin_cascade_session",
        ],
    ),
    // write: `ClaimRepository::update_labels_conn`, `ClaimRepository::update_trace_id_conn`,
    // `EvidenceRepository::create`, `ReasoningTraceRepository::create`; opener:
    // `claim_helper::begin_author_stamped_tx_for`; authority:
    // `claim_helper::claim_tenancy_report`, `claim_helper::resolve_claim_visibility`; no SQL:
    // `claim_helper::embed_claim_author_stamped`.
    (
        "memory.rs",
        "memorize",
        &[
            "ClaimRepository::update_labels_conn",
            "ClaimRepository::update_trace_id_conn",
            "EvidenceRepository::create",
            "ReasoningTraceRepository::create",
            "claim_helper::begin_author_stamped_tx_for",
            "claim_helper::claim_tenancy_report",
            "claim_helper::embed_claim_author_stamped",
            "claim_helper::resolve_claim_visibility",
        ],
    ),
    // audit: `recall::write_recall_audit`, handed `server.scoped`: the
    // caller's own recall event, written on a transaction stamped as the
    // caller (`principal`), which resolves only the caller's owner group.
    (
        "memory.rs",
        "recall_post_embed",
        &["recall::write_recall_audit"],
    ),
    // write: `EvidenceRepository::create_with_source_url` (the caller's corroborating evidence
    // on the matched claim), `claim_helper::emit_verb_edge_best_effort` (its AUTHORED edge), both
    // on the author-stamped transaction, after the claim's tenancy was read through the viewer
    // (`ClaimRepository::tenancy_of_conn`); opener: `claim_helper::begin_author_stamped_tx_for`;
    // authority: `ClaimRepository::claims_not_writable_on_session` (may the session write the
    // claim's group: ids only) and `foreign_attach::is_foreign_public_claim` (a boolean).
    (
        "novelty_gate.rs",
        "corroborate",
        &[
            "ClaimRepository::claims_not_writable_on_session",
            "EvidenceRepository::create_with_source_url",
            "claim_helper::begin_author_stamped_tx_for",
            "claim_helper::emit_verb_edge_best_effort",
            "foreign_attach::is_foreign_public_claim",
        ],
    ),
    // write: `EdgeRepository::create_signed`, `PerspectiveRepository::create`. Raw pool: both
    // writes run on `server.pool` (registered in `raw_pool_register.rs`).
    (
        "perspectives.rs",
        "create_perspective",
        &[
            "EdgeRepository::create_signed",
            "PerspectiveRepository::create",
        ],
    ),
    // write: `PerspectiveRepository::set_source_reliability_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority: `claims::require_owner_or_admin`.
    (
        "perspectives.rs",
        "set_source_reliability",
        &[
            "PerspectiveRepository::set_source_reliability_conn",
            "claim_helper::begin_author_stamped_tx",
            "claims::require_owner_or_admin",
        ],
    ),
    // untenanted: `EntityRepository::find_by_name_and_type`, `EntityRepository::get`.
    (
        "rdf.rs",
        "entity_neighborhood",
        &[
            "EntityRepository::find_by_name_and_type",
            "EntityRepository::get",
        ],
    ),
    // untenanted: `EntityRepository::find_by_name_and_type`.
    (
        "rdf.rs",
        "query_triples",
        &[
            "EntityRepository::find_by_name_and_type",
            "EntityRepository::find_by_name_and_type",
        ],
    ),
    // stamped: `GroupMembershipRepository::visible_personal_group_conn`; resolves:
    // `Viewer::resolve`.
    (
        "recall.rs",
        "recall_audit_owner_group",
        &[
            "GroupMembershipRepository::visible_personal_group_conn",
            "Viewer::resolve",
        ],
    ),
    // audit: `spawn_recall_audit`.
    (
        "recall.rs",
        "recall_with_context_core",
        &["spawn_recall_audit", "spawn_recall_audit"],
    ),
    // ── crate-root helpers a tool hands its viewer to (`src/*.rs`) ──
    //
    // The author's own viewer, resolved from the author id for a write stamped
    // from it; the two writes are on the author-stamped transaction, after the
    // claim was read or created through the viewer.
    // resolves: `Viewer::resolve`.
    (
        "epigraph-service/src/ctx.rs",
        "author_write_authority",
        &["Viewer::resolve"],
    ),
    // write: `emit_verb_edge_best_effort`.
    (
        "src/claim_helper.rs",
        "create_claim_idempotent",
        &["emit_verb_edge_best_effort"],
    ),
    // write: `ClaimRepository::update_truth_value_conn`.
    (
        "src/claim_helper.rs",
        "wire_ds_for_new_claim_in_tx",
        &["ClaimRepository::update_truth_value_conn"],
    ),
    // resolves: `Viewer::resolve`.
    ("src/claim_helper.rs", "write_viewer", &["Viewer::resolve"]),
    // write: `epigraph_ingest_executor::add_step`,
    // `epigraph_ingest_executor::record_caller_authorship`; opener:
    // `claim_helper::begin_caller_workflow_tx`; audit:
    // `workflow_authority::record_workflow_write`; no SQL:
    // `workflow_ingest::embed_created_workflow_claims`. `require_authority_over` now takes the
    // viewer (its own entry).
    (
        "step_ops.rs",
        "add_step",
        &[
            "claim_helper::begin_caller_workflow_tx",
            "epigraph_ingest_executor::add_step",
            "epigraph_ingest_executor::record_caller_authorship",
            "workflow_authority::record_workflow_write",
            "workflow_ingest::embed_created_workflow_claims",
        ],
    ),
    // write: `epigraph_ingest_executor::delete_step`; opener:
    // `claim_helper::begin_caller_workflow_tx`; audit:
    // `workflow_authority::record_workflow_write`. `require_authority_over` now takes the viewer
    // (its own entry).
    (
        "step_ops.rs",
        "delete_step",
        &[
            "claim_helper::begin_caller_workflow_tx",
            "epigraph_ingest_executor::delete_step",
            "workflow_authority::record_workflow_write",
        ],
    ),
    // stamped: `WorkflowRepository::head_by_canonical`, the lineage head on the caller's workflow
    // transaction under the `workflows` table's forced row security; the authority decision then
    // takes the viewer.
    (
        "step_ops.rs",
        "require_authority_over",
        &["WorkflowRepository::head_by_canonical"],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`; authority:
    // `admin_borrowed_server_identity`, `claims::require_owner_or_admin`.
    (
        "supersede.rs",
        "begin_claim_act",
        &[
            "admin_borrowed_server_identity",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::begin_author_stamped_tx",
            "claims::require_owner_or_admin",
        ],
    ),
    // write: `ClaimRepository::mark_duplicate_act_attributed_conn`; maintenance:
    // `admin_session_or_deferral`.
    (
        "supersede.rs",
        "mark_duplicate_pair",
        &[
            "ClaimRepository::mark_duplicate_act_attributed_conn",
            "admin_session_or_deferral",
        ],
    ),
    // write: `ClaimRepository::lock_dedup_sources_conn` (row locks),
    // `ClaimRepository::mark_duplicate_act_attributed_conn`, each on the one transaction
    // `begin_claim_act` (viewer) opened; authority: `claims::require_owner_or_admin`, every link
    // grant the gates made decided again on that transaction under the link lock (backlog
    // 9a5bc055); maintenance: `maintenance::admin_cascade_session`,
    // `admin_cascade::record_deferral`, after the acts' gates.
    (
        "supersede.rs",
        "mark_duplicates_onto",
        &[
            "ClaimRepository::lock_dedup_sources_conn",
            "ClaimRepository::mark_duplicate_act_attributed_conn",
            "admin_cascade::record_deferral",
            "claims::require_owner_or_admin",
            "maintenance::admin_cascade_session",
        ],
    ),
    // write: `ClaimRepository::supersede_act_conn`; maintenance:
    // `supersede_session_or_deferral`; no SQL: `claim_helper::embed_claim_author_stamped`.
    (
        "supersede.rs",
        "supersede_claim",
        &[
            "ClaimRepository::supersede_act_conn",
            "claim_helper::embed_claim_author_stamped",
            "supersede_session_or_deferral",
        ],
    ),
    // maintenance: `maintenance::admin_cascade_session`; no SQL:
    // `claim_helper::embed_claim_author_stamped`.
    (
        "supersede.rs",
        "unmark_duplicate_expecting",
        &[
            "claim_helper::embed_claim_author_stamped",
            "maintenance::admin_cascade_session",
        ],
    ),
    // authority: `ClaimRepository::session_may_unmark_conn`.
    (
        "supersede.rs",
        "unmark_gate",
        &[
            "ClaimRepository::session_may_unmark_conn",
            "ClaimRepository::session_may_unmark_conn",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`; write: the migration 263 definers
    // (`PersonTeamGroupRepository::create_conn` / `invite_conn` / `accept_conn` /
    // `decline_conn`) on that author-stamped transaction, which act only for the stamped
    // principal (a live admin of a person-made group invites; only the invitee answers) and
    // return the ids they wrote (backlog triage T75, #1024).
    (
        "team_groups.rs",
        "accept_group_invitation",
        &[
            "PersonTeamGroupRepository::accept_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    (
        "team_groups.rs",
        "create_team_group",
        &[
            "PersonTeamGroupRepository::create_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    (
        "team_groups.rs",
        "decline_group_invitation",
        &[
            "PersonTeamGroupRepository::decline_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    (
        "team_groups.rs",
        "invite_to_group",
        &[
            "PersonTeamGroupRepository::invite_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // stamped: `PersonTeamGroupRepository::my_groups_conn` and `my_invitations_conn` run on the
    // caller's viewer-stamped transaction (`ScopedPool::begin_as`, rolled back) and read only the
    // stamped principal's own rows through 263's definers (its live memberships, its pending
    // invitations).
    (
        "team_groups.rs",
        "list_my_groups",
        &[
            "PersonTeamGroupRepository::my_groups_conn",
            "PersonTeamGroupRepository::my_invitations_conn",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`.
    (
        "visibility.rs",
        "publicize_claims",
        &["claim_helper::begin_author_stamped_tx"],
    ),
    // write: `ClaimRepository::set_agent_default_conn`; opener:
    // `claim_helper::begin_author_stamped_tx`; stamped: `ClaimRepository::writable_teams`.
    (
        "visibility.rs",
        "set_default_group",
        &[
            "ClaimRepository::set_agent_default_conn",
            "ClaimRepository::writable_teams",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // write: `AgentRepository::set_profile_visibility_conn` (310's definer, the
    // stamped principal's own row); opener: `claim_helper::begin_author_stamped_tx`.
    (
        "visibility.rs",
        "set_profile_visibility",
        &[
            "AgentRepository::set_profile_visibility_conn",
            "claim_helper::begin_author_stamped_tx",
        ],
    ),
    // opener: `claim_helper::begin_author_stamped_tx`.
    (
        "visibility.rs",
        "share_claims_with_team",
        &["claim_helper::begin_author_stamped_tx"],
    ),
    // authority: the workflow authority rule's arms (`admin_arm`, `claims::operator_arm_allows`,
    // `delegate_arm`, `owner_group_arm`, `unrecorded_row_owner_group_arm`,
    // `viewer::live_delegation_on`), each an allow or refuse on `conn`; stamped:
    // `WorkflowRepository::submitter_of`, the `workflows` row on the caller's connection under
    // its forced row security. (`caller_view_of` is handed the viewer since backlog bdc96181,
    // and reads through it on `conn` instead of resolving one on `server.pool`.)
    (
        "workflow_authority.rs",
        "require_workflow_authority",
        &[
            "WorkflowRepository::submitter_of",
            "admin_arm",
            "admin_arm",
            "claims::operator_arm_allows",
            "delegate_arm",
            "owner_group_arm",
            "unrecorded_row_owner_group_arm",
            "viewer::live_delegation_on",
        ],
    ),
    // authority: `claims::operator_arm_allows`, `delegate_arm`, `owner_group_arm`,
    // `unrecorded_row_owner_group_arm`; resolves: `Viewer::resolve`. Raw pool:
    // `Viewer::resolve` reads memberships on `server.pool`.
    (
        "workflow_authority.rs",
        "stdio_workflow_authority",
        &[
            "Viewer::resolve",
            "claims::operator_arm_allows",
            "delegate_arm",
            "owner_group_arm",
            "unrecorded_row_owner_group_arm",
        ],
    ),
    // write: `BehavioralExecutionRepository::create`.
    (
        "workflow_hierarchical.rs",
        "do_report_hierarchical_outcome_as",
        &["BehavioralExecutionRepository::create"],
    ),
    // stamped: `WorkflowRepository::find_hierarchical_by_embedding`,
    // `WorkflowRepository::search_hierarchical_by_text`.
    (
        "workflow_hierarchical.rs",
        "find_workflow_hierarchical",
        &[
            "WorkflowRepository::find_hierarchical_by_embedding",
            "WorkflowRepository::search_hierarchical_by_text",
        ],
    ),
    // stamped: `WorkflowRepository::list_hierarchical_lineage_heads` (on the caller's
    // `read_as`; `workflows` row security returns exactly the rows the stamp reads).
    (
        "workflow_hierarchical.rs",
        "list_workflows",
        &["WorkflowRepository::list_hierarchical_lineage_heads"],
    ),
    // resolves: `Viewer::resolve`. Raw pool: `Viewer::resolve` reads memberships on
    // `server.pool`.
    ("workflow_ingest.rs", "caller_viewer", &["Viewer::resolve"]),
    // no SQL: `embed_created_workflow_claims`, `store_workflow_goal_embedding`.
    (
        "workflow_ingest.rs",
        "do_ingest_workflow",
        &[
            "embed_created_workflow_claims",
            "store_workflow_goal_embedding",
        ],
    ),
    // write: `epigraph_ingest_executor::execute_workflow_ingest_plan`.
    (
        "workflow_ingest.rs",
        "do_ingest_workflow_via_pool",
        &["epigraph_ingest_executor::execute_workflow_ingest_plan"],
    ),
    // write: `WorkflowRepository::record_submitter`,
    // `epigraph_ingest_executor::record_caller_authorship`; opener:
    // `claim_helper::begin_caller_workflow_tx`; stamped: `WorkflowRepository::ingest_anchors`;
    // audit: `workflow_authority::audit_admin_workflow_write`,
    // `workflow_authority::record_caller_workflow_write`.
    // `workflow_authority::require_workflow_authority` now takes the viewer (its own entry).
    (
        "workflow_ingest.rs",
        "execute_workflow_ingest_with_inserted",
        &[
            "WorkflowRepository::ingest_anchors",
            "WorkflowRepository::record_submitter",
            "claim_helper::begin_caller_workflow_tx",
            "claim_helper::begin_caller_workflow_tx",
            "epigraph_ingest_executor::record_caller_authorship",
            "workflow_authority::audit_admin_workflow_write",
            "workflow_authority::record_caller_workflow_write",
        ],
    ),
    // no SQL: `embed_created_workflow_claims`, `store_workflow_goal_embedding`.
    (
        "workflow_ingest.rs",
        "improve_workflow_hierarchy",
        &[
            "embed_created_workflow_claims",
            "store_workflow_goal_embedding",
        ],
    ),
    // stamped: `WorkflowRepository::max_generation_by_canonical`.
    (
        "workflow_ingest.rs",
        "improve_workflow_hierarchy_via_pool",
        &["WorkflowRepository::max_generation_by_canonical"],
    ),
    // stamped: `WorkflowRepository::max_generation_by_canonical`, on the caller's `read_as`
    // (a server with no ScopedPool is refused there; backlog 4cbd4192 removed the raw-pool
    // fallback).
    (
        "workflow_ingest.rs",
        "lineage_max_generation",
        &["WorkflowRepository::max_generation_by_canonical"],
    ),
    // write: `ClaimRepository::retire_for_workflow_deprecation`,
    // `WorkflowRepository::admin_deprecate_row` (migration 237's audited admin definer),
    // `WorkflowRepository::lock_lineages_for_deprecation`,
    // `WorkflowRepository::set_truth_value_if_changed`; opener:
    // `claim_helper::begin_caller_workflow_tx`; stamped: `WorkflowRepository::canonical_names_of`,
    // `executed_structural_claims`, `lineage_descendants`, on the caller's transaction under the
    // `workflows` forced row security; authority: `WorkflowRepository::name_has_hidden_rows_conn`
    // (a boolean that refuses a name with hidden rows) and `refuse_a_live_row_left_behind`
    // (refuses unless the row now reads deprecated); audit:
    // `workflow_authority::record_workflow_write`.
    (
        "workflows.rs",
        "deprecate_hierarchical_workflow",
        &[
            "ClaimRepository::retire_for_workflow_deprecation",
            "WorkflowRepository::admin_deprecate_row",
            "WorkflowRepository::canonical_names_of",
            "WorkflowRepository::executed_structural_claims",
            "WorkflowRepository::lineage_descendants",
            "WorkflowRepository::lock_lineages_for_deprecation",
            "WorkflowRepository::name_has_hidden_rows_conn",
            "WorkflowRepository::set_truth_value_if_changed",
            "claim_helper::begin_caller_workflow_tx",
            "refuse_a_live_row_left_behind",
            "workflow_authority::record_workflow_write",
        ],
    ),
    // write: `ClaimRepository::deprecate_claim_if_current`, `WorkflowRepository::set_truth_value`,
    // `WorkflowRepository::set_truth_value_if_changed`; opener:
    // `claim_helper::begin_author_stamped_tx`; stamped: `WorkflowRepository::exists`; authority:
    // `refuse_a_live_row_left_behind` (refuses unless the row now reads deprecated).
    // `deprecate_hierarchical_workflow` now takes the viewer (its own entry).
    (
        "workflows.rs",
        "deprecate_workflow",
        &[
            "ClaimRepository::deprecate_claim_if_current",
            "ClaimRepository::deprecate_claim_if_current",
            "WorkflowRepository::exists",
            "WorkflowRepository::set_truth_value",
            "WorkflowRepository::set_truth_value_if_changed",
            "claim_helper::begin_author_stamped_tx",
            "refuse_a_live_row_left_behind",
        ],
    ),
    // untenanted: `BehavioralExecutionRepository::rolling_success_rate`.
    (
        "workflows.rs",
        "enrich_workflow_result",
        &["BehavioralExecutionRepository::rolling_success_rate"],
    ),
    // stamped: `WorkflowRepository::search_hierarchical_by_text`; untenanted:
    // `BehavioralExecutionRepository::behavioral_affinity_hierarchical`.
    (
        "workflows.rs",
        "find_workflow_post_embed",
        &[
            "BehavioralExecutionRepository::behavioral_affinity_hierarchical",
            "WorkflowRepository::search_hierarchical_by_text",
        ],
    ),
    // stamped: `WorkflowRepository::max_generation_by_canonical`.
    (
        "workflows.rs",
        "hierarchical_workflow_result",
        &["WorkflowRepository::max_generation_by_canonical"],
    ),
    // opener: `claim_helper::begin_caller_workflow_tx`. Since backlog triage T85 (#1031) the
    // match itself (the head lookups, the hidden-row and caller-owner checks) runs in
    // `epigraph_ingest_executor::matching_workflow_conn`, which is handed the caller's viewer,
    // on that transaction, rolled back after the read.
    (
        "workflows.rs",
        "matching_workflow",
        &["claim_helper::begin_caller_workflow_tx"],
    ),
    // write: `ClaimRepository::merge_properties`. Raw pool: `merge_properties` writes the
    // `promotion` property on `server.pool` after the viewer-gated assessment (registered in
    // `raw_pool_register.rs`; a write-authority question, not a read).
    (
        "workflows.rs",
        "refresh_workflow_promotion",
        &["ClaimRepository::merge_properties"],
    ),
    // write: `BehavioralExecutionRepository::create` (since migration 240 on the author's stamped
    // transaction, the second opener: the run carries its workflow's tenancy),
    // `ClaimRepository::update_truth_value_conn`, `EvidenceRepository::create`; opener:
    // `claim_helper::begin_author_stamped_tx`; authority:
    // `foreign_attach::is_foreign_public_claim`. The dispatch probe is
    // `WorkflowRepository::viewer_reads_row` on the caller's `read_as` (backlog 4cbd4192 removed
    // the no-ScopedPool `WorkflowRepository::exists` fallback on `server.pool`).
    (
        "workflows.rs",
        "report_workflow_outcome",
        &[
            "BehavioralExecutionRepository::create",
            "ClaimRepository::update_truth_value_conn",
            "EvidenceRepository::create",
            "claim_helper::begin_author_stamped_tx",
            "claim_helper::begin_author_stamped_tx",
            "foreign_attach::is_foreign_public_claim",
        ],
    ),
    // no SQL: `workflow_ingest::embed_created_workflow_claims`,
    // `workflow_ingest::store_workflow_goal_embedding`.
    (
        "workflows.rs",
        "store_workflow",
        &[
            "workflow_ingest::embed_created_workflow_claims",
            "workflow_ingest::store_workflow_goal_embedding",
        ],
    ),
];

/// The crate-root helpers a tool hands its viewer to (`claim_helper.rs`,
/// `maintenance.rs`, `write_identity.rs`, ..), keyed `src/<name>.rs` so they
/// cannot collide with a `tools/` file. Without them a tool's call that passes
/// the viewer into one would count as viewed with the helper's own body never
/// read. `server.rs` is left out: its `#[tool]` methods take `&self` and only
/// resolve the viewer and delegate to `src/tools/` (measured 2026-11-22).
///
/// The service crate's root files are read too, keyed
/// `epigraph-service/src/<name>.rs`: the tenancy entry points the tools hand
/// their viewer and their server to (`author_write_authority`, `read_as`,
/// `write_identity`) moved there from `claim_helper.rs`, `tools/viewer.rs` and
/// `server.rs` (backlog 30133ca8), and a scan of this crate alone would stop
/// reading their bodies.
fn root_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let roots = [
        (Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), "src"),
        (
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../epigraph-service/src"),
            "epigraph-service/src",
        ),
    ];
    for (dir, key) in roots {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 file name")
                .to_string();
            if key == "src" && name == "server.rs" {
                continue;
            }
            out.push((
                format!("{key}/{name}"),
                std::fs::read_to_string(&path).expect("read src file"),
            ));
        }
    }
    out.sort();
    out
}

fn measure_tools() -> (Measured, usize, usize, Population) {
    let mut out = Measured::new();
    let mut pop = Population::new();
    let (mut n_fns, mut n_calls) = (0, 0);
    for (file, src) in tool_files().into_iter().chain(root_files()) {
        let (f, c) = viewer_calls::measure_source(&file, &src, &TOOLS, &mut out, &mut pop);
        n_fns += f;
        n_calls += c;
    }
    (out, n_fns, n_calls, pop)
}

/// In a tool fn that holds a viewer, every database call whose arguments and
/// statement do not spend that viewer is named in [`REVIEWED_CALLS`] (backlog
/// ada8ee55).
#[test]
fn every_unviewed_database_call_in_a_viewer_tool_fn_is_reviewed() {
    let (measured, _, _, _) = measure_tools();
    let report = viewer_calls::drift(&measured, &viewer_calls::register(REVIEWED_CALLS));
    assert!(
        report.is_empty(),
        "viewer-holding MCP tool fns' unviewed database calls drifted from REVIEWED_CALLS.\n\
         A NEW call is a repo call, statement or helper handed the server, in a fn that \
         holds a viewer, with neither the viewer in its arguments nor a spend marker in \
         its statement: give it the viewer, or read it and register it with a reason \
         class. A GONE call must be removed from REVIEWED_CALLS.\n{report}"
    );
}

/// The population is the tool layer's viewer surface, not a corner of it.
#[test]
fn the_per_call_scanner_sees_the_whole_tool_viewer_surface() {
    let (measured, fns, calls, pop) = measure_tools();
    eprintln!(
        "population: {fns} viewer-holding tool fns, {calls} database calls, {} with an \
         unviewed call, {} unviewed calls",
        measured.len(),
        measured.values().map(Vec::len).sum::<usize>()
    );
    for (file, f) in [
        // The ten-statement enrichment read this file was written for.
        ("recall.rs", "fetch_batched_context"),
        // A viewer resolved in the body (`Viewer::resolve`), not a parameter.
        ("recall.rs", "recall_audit_owner_group"),
        ("workflow_authority.rs", "stdio_workflow_authority"),
        // A viewer destructured from a struct (`let UnitContext { server,
        // viewer, .. } = *ctx;`), not a parameter.
        ("label_dedup.rs", "apply_unit"),
    ] {
        assert!(
            pop.contains(&(file.to_string(), f.to_string())),
            "{file}::{f} holds a viewer and must be in the measured population"
        );
    }
    // A maintenance session (`admin_cascade_session`) and a raw-pool write are
    // database handles the scanner must see.
    let key = (
        "label_dedup.rs".to_string(),
        "revert_label_dedup".to_string(),
    );
    assert!(
        measured
            .get(&key)
            .is_some_and(|l| l.iter().any(|x| x == "maintenance::admin_cascade_session")),
        "the maintenance-session open in revert_label_dedup must be measured: {:?}",
        measured.get(&key)
    );
    // Floors about 2% under the measurement: a scanner regression that drops
    // fns with no unviewed call (which the register cannot see) fails here.
    // Removing real tool code can trip them too; re-measure and lower them in
    // the same change, with the new numbers.
    assert!(
        fns >= 206,
        "found {fns} viewer-holding tool fns; measured 211 on 2026-11-22 (199 under \
         src/tools/, 12 in the crate-root helpers)"
    );
    assert!(
        calls >= 773,
        "found {calls} database calls in them; measured 789 on 2026-11-22"
    );
}

fn tool_unviewed(src: &str) -> Measured {
    let mut out = Measured::new();
    viewer_calls::measure_source("fixture.rs", src, &TOOLS, &mut out, &mut Population::new());
    out
}

fn tool_labels(m: &Measured, f: &str) -> Vec<String> {
    m.get(&("fixture.rs".to_string(), f.to_string()))
        .cloned()
        .unwrap_or_default()
}

/// The defect the per-call register exists for, which the fn-level check
/// above cannot see: a viewer spent on one statement while the content read
/// beside it runs without it.
#[test]
fn the_per_call_register_sees_a_viewer_spent_on_the_wrong_statement() {
    let src = r##"
pub async fn content_beside_a_count(
    server: &EpiGraphMcpFull,
    viewer: &Viewer,
    id: Uuid,
) -> Result<CallToolResult, McpError> {
    let mut read = server.read_as(viewer, "content_beside_a_count").await?;
    let sql = viewer.splice("SELECT count(*) FROM claims c WHERE true /* {VISIBILITY:c} */", 1);
    let n: i64 = sqlx::query_scalar(&sql).fetch_one(&mut *read).await?;
    let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&server.pool)
        .await?;
    success_json(&(n, content))
}
"##;
    assert!(
        unspent_offenders(&viewer_taking_fns_in("fixture.rs", src)).is_empty(),
        "the fn-level check passes this fn: it spends its viewer once"
    );
    assert_eq!(
        tool_labels(&tool_unviewed(src), "content_beside_a_count"),
        vec!["sqlx::query_scalar(SELECT).fetch_one"],
        "the per-call scan reports exactly the unviewed content read"
    );
}

/// The tool layer's handle shapes: the server's pool, its stamped read, a
/// helper handed the server, a maintenance session, a transaction returned in
/// a tuple, and a viewer the fn resolves itself.
#[test]
fn the_per_call_scanner_reads_the_tool_layer_shapes() {
    let src = r##"
pub async fn handles(server: &EpiGraphMcpFull, viewer: &epigraph_db::visibility::Viewer, id: Uuid) -> R {
    let a = Repo::get(&server.pool, id).await?;
    let b = Repo::get_as(&server.pool, viewer, id).await?;
    let mut read = server.read_as(viewer, "handles").await?;
    let c = Repo::get(&mut *read, id).await?;
    let d = helper(server, id).await?;
    let e = helper_as(server, viewer, id).await?;
    let f = Repo::get_in(&mut *read, viewer.writable_groups()).await?;
    read.commit().await?;
    Ok((a, b, c, d, e, f))
}

pub async fn sessions(server: &EpiGraphMcpFull, viewer: &Viewer, id: Uuid) -> R {
    let (mut tx, actor, _) = begin_claim_act(server, viewer, id).await?;
    let g = Repo::write(&mut tx, id).await?;
    let session = crate::maintenance::admin_cascade_session(server).await;
    let h = Repo::cascade(&mut session, id).await?;
    Ok((g, h, actor))
}

pub async fn resolves_its_own(server: &EpiGraphMcpFull, caller: Uuid) -> R {
    let viewer = epigraph_db::visibility::Viewer::resolve(&server.pool, caller).await?;
    let i = Repo::get_as(&server.pool, &viewer, caller).await?;
    let j = Repo::get(&server.pool, caller).await?;
    Ok((i, j))
}

pub async fn holds_no_viewer(server: &EpiGraphMcpFull, id: Uuid) -> R {
    Repo::get(&server.pool, id).await
}
"##;
    let m = tool_unviewed(src);
    assert_eq!(
        tool_labels(&m, "handles"),
        vec!["Repo::get", "Repo::get", "Repo::get_in", "helper"],
        "a raw-pool read, a read on the stamped connection that does not pass the \
         viewer (stamping is not a spend), a helper handed the server, and a scalar \
         projection of the viewer are all unviewed"
    );
    assert_eq!(
        tool_labels(&m, "sessions"),
        vec![
            "Repo::cascade",
            "Repo::write",
            "maintenance::admin_cascade_session"
        ],
        "a transaction opened by a `begin*` helper (handed the viewer, so viewed) and \
         returned in a tuple, and a maintenance session opened from the server, are \
         connections; the session open is itself a call handed the server"
    );
    assert_eq!(
        tool_labels(&m, "resolves_its_own"),
        vec!["Repo::get", "Viewer::resolve"],
        "a fn that resolves its own viewer holds it: its calls are measured against it"
    );
    assert!(
        !m.contains_key(&("fixture.rs".to_string(), "holds_no_viewer".to_string())),
        "a fn that holds no viewer is not in the population"
    );
}

/// A viewer that arrives inside a struct and is destructured (`let Ctx {
/// server, viewer, .. } = *ctx;`) is held: the fn is in the population and the
/// destructured server's pool is a database handle. `label_dedup.rs::apply_unit`
/// has this shape.
#[test]
fn the_per_call_scanner_reads_a_viewer_destructured_from_a_struct() {
    let src = r##"
struct Ctx<'a> {
    server: &'a EpiGraphMcpFull,
    viewer: &'a epigraph_db::visibility::Viewer,
    #[allow(dead_code)]
    pub(crate) run_tag: &'a str,
}

async fn apply(ctx: &Ctx<'_>, id: Uuid) -> R {
    let Ctx { server, viewer, .. } = *ctx;
    let n = Repo::count_as(&server.pool, viewer).await?;
    let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&server.pool)
        .await?;
    Ok((n, content))
}

async fn renamed(ctx: &Ctx<'_>, id: Uuid) -> R {
    let Ctx {
        server: s,
        viewer: v,
        ..
    } = *ctx;
    let c = Repo::get(&s.pool, id).await?;
    let d = Repo::get_as(&s.pool, v, id).await?;
    Ok((c, d))
}
"##;
    let m = tool_unviewed(src);
    assert_eq!(
        tool_labels(&m, "apply"),
        vec!["sqlx::query_scalar(SELECT).fetch_one"],
        "a destructured viewer is held, and the unviewed content read on the \
         destructured server's pool is reported"
    );
    assert_eq!(
        tool_labels(&m, "renamed"),
        vec!["Repo::get"],
        "a field bound under another name (`server: s`, `viewer: v`) is classified \
         by the field's declared type"
    );
}

/// `server.scoped` is a database handle (a helper handed it runs SQL), an
/// `Option` test on it is not a call, and a maintenance session returned by
/// the supersede helpers beside a deferral status is a connection.
#[test]
fn the_per_call_scanner_reads_the_scoped_pool_and_returned_maintenance_sessions() {
    let src = r##"
pub async fn audit_on_scoped(server: &EpiGraphMcpFull, viewer: &Viewer, principal: Option<Uuid>) -> R {
    let rows = Repo::list_as(&server.pool, viewer).await?;
    if server.scoped.is_some() {
        tracing::debug!("stamped");
    }
    let scoped = server.scoped.clone();
    write_audit(scoped.as_ref(), principal).await?;
    Ok(rows)
}

pub async fn cascade_after_gate(server: &EpiGraphMcpFull, viewer: &Viewer, id: Uuid) -> R {
    let mut tx = begin_claim_write(server, viewer).await?;
    let (mut session, deferred) = if id.is_nil() {
        (None, None)
    } else {
        let (session, status) =
            crate::tools::supersede::admin_session_or_deferral(server, &mut tx, &id).await?;
        (session, Some(status))
    };
    let report = match (session.as_mut(), deferred) {
        (Some(session), _) => Some(admin_cascade::apply_after(session.conn(), &id).await),
        (None, _) => None,
    };
    Ok(report)
}
"##;
    let m = tool_unviewed(src);
    assert_eq!(
        tool_labels(&m, "audit_on_scoped"),
        vec!["write_audit"],
        "a helper handed `server.scoped` is a database call; `scoped.is_some()` is not"
    );
    assert_eq!(
        tool_labels(&m, "cascade_after_gate"),
        vec![
            "admin_cascade::apply_after",
            "supersede::admin_session_or_deferral"
        ],
        "the session `admin_session_or_deferral` returns is a connection, so the \
         cascade run on it without the viewer is reported"
    );
}

/// The per-call marker counts `visibility = 'public'` only as a filter. In a
/// projection it hides no row; on another receiver `.splice(` is not this
/// fn's viewer.
#[test]
fn the_per_call_marker_counts_only_a_filtering_predicate() {
    let src = r##"
pub async fn projected(server: &EpiGraphMcpFull, viewer: &Viewer, id: Uuid) -> R {
    let _ = viewer;
    let row: (String, bool) = sqlx::query_as(
        "SELECT c.content, c.visibility = 'public' FROM claims c WHERE c.id = $1",
    )
    .bind(id)
    .fetch_one(&server.pool)
    .await?;
    Ok(row)
}

pub async fn filtered(server: &EpiGraphMcpFull, viewer: &Viewer, id: Uuid) -> R {
    let row: (String,) = sqlx::query_as(
        "SELECT c.content FROM claims c WHERE c.id = $1 \
         AND ($2::bool OR c.visibility = 'public' OR c.owner_group_id = ANY($3))",
    )
    .bind(id)
    .bind(viewer.is_bypass())
    .fetch_one(&server.pool)
    .await?;
    Ok(row)
}
"##;
    let m = tool_unviewed(src);
    assert_eq!(
        tool_labels(&m, "projected"),
        vec!["sqlx::query_as(SELECT).fetch_one"],
        "a raw-pool content read whose only marker is a projected column is unviewed"
    );
    assert_eq!(
        tool_labels(&m, "filtered"),
        Vec::<String>::new(),
        "the marker in predicate position is a spend"
    );
}

/// Viewer-carrier structs (a struct with a `Viewer` field) are an exact,
/// reviewed set, and every fn that takes one as a parameter is in the
/// population. A carrier read through field access (`ctx.viewer`) rather than
/// destructured would not be: adding one fails here first.
#[test]
fn viewer_carrier_structs_are_reviewed() {
    let files: Vec<(String, String)> = tool_files().into_iter().chain(root_files()).collect();
    let mut carriers = Vec::new();
    for (file, src) in &files {
        let (code, _) = viewer_calls::views(src);
        for name in viewer_calls::viewer_carriers(&viewer_calls::struct_fields(&code)) {
            carriers.push((file.clone(), name));
        }
    }
    assert_eq!(
        carriers,
        vec![("label_dedup.rs".to_string(), "UnitContext".to_string())],
        "the structs that carry a viewer into a tool fn changed; check that every fn \
         receiving one is measured (destructure it, or teach the scanner its access \
         shape), then update this list"
    );
    let (_, _, _, pop) = measure_tools();
    let mut takers = Vec::new();
    for (file, src) in &files {
        let (code, sql) = viewer_calls::views(src);
        for h in viewer_calls::fn_headers(&code, &sql) {
            let takes = h.params.iter().any(|(_, ty)| {
                carriers
                    .iter()
                    .any(|(_, c)| ty.trim_start_matches('&').starts_with(c.as_str()))
            });
            if takes {
                takers.push((file.clone(), h.name.clone()));
                assert!(
                    pop.contains(&(file.clone(), h.name.clone())),
                    "{file}::{} takes a viewer-carrier struct but is not in the measured \
                     population",
                    h.name
                );
            }
        }
    }
    assert!(
        takers.contains(&("label_dedup.rs".to_string(), "apply_unit".to_string())),
        "the carrier check found no taker: {takers:?}"
    );
}

/// Tool fns that bind a maintenance viewer beside another viewer. The per-call
/// check counts a call spent with ANY viewer a fn holds as viewed, so in such
/// a fn a statement spent with the maintenance viewer would pass for one
/// spent with the caller's.
fn maintenance_beside_another_viewer(file: &str, src: &str) -> Vec<String> {
    let (code, sql) = viewer_calls::views(src);
    let structs = viewer_calls::struct_fields(&code);
    viewer_calls::holders(&code, &sql, &TOOLS, &structs)
        .into_iter()
        .filter(|h| code[h.body.0..h.body.1].contains("maintenance_viewer(") && h.viewers.len() > 1)
        .map(|h| format!("{file}::{} holds {:?}", h.name, h.viewers))
        .collect()
}

/// No tool fn holds a maintenance viewer beside the caller's (measured
/// 2026-11-22: none does). If one must, split it, so the per-call register
/// stays a statement about the caller's viewer.
#[test]
fn no_tool_fn_holds_a_maintenance_viewer_beside_another() {
    let fixture = r##"
pub async fn both(server: &EpiGraphMcpFull, viewer: &Viewer) -> R {
    let admin = crate::maintenance::maintenance_viewer(server, SystemReason::X).await?;
    Repo::sweep_as(&server.pool, &admin).await
}
"##;
    assert_eq!(
        maintenance_beside_another_viewer("fixture.rs", fixture).len(),
        1,
        "the check sees a maintenance viewer bound beside the caller's"
    );
    let offenders: Vec<String> = tool_files()
        .into_iter()
        .chain(root_files())
        .flat_map(|(f, src)| maintenance_beside_another_viewer(&f, &src))
        .collect();
    assert!(offenders.is_empty(), "{offenders:#?}");
}
