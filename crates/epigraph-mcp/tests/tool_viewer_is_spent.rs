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
    // The hierarchical outcome report's own SQL is the `workflows` counter
    // read-modify-write (no tenancy columns, same reason as the next entry).
    // It takes a viewer to STAMP its transaction and spends it in the
    // repository step lookup (`WorkflowRepository::plan_step_claim_ids`, which
    // splices), so the claim read it performs is filtered; this scan sees only
    // the inline SQL.
    (
        "workflow_hierarchical.rs",
        "do_report_hierarchical_outcome_as",
    ),
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
