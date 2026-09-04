//! Source lint: a repo function that takes a `&Viewer` and runs SQL must
//! actually spend it.
//!
//! # Why this file exists — and why its absence was itself the defect
//!
//! `crates/epigraph-db/src/visibility.rs` cites this file three times as the
//! mechanism that stops the lint and the repo layer drifting to two spellings
//! of "this query is filtered". `repos/lineage.rs` cites it seven times,
//! `repos/claim.rs` twice ("visibility_lint.rs — which checks that a marker is
//! present, not where"), and `docs/tenancy/FINAL-PLAN.md` lists it as PR-06's
//! gate.
//!
//! **It did not exist.** That is the same defect PR-07's own commit message
//! indicts in acceptance criterion #1: a verification cited in prose, never
//! written. It is written here.
//!
//! # The gap it closes
//!
//! `Viewer::splice`'s missing-marker panic is the primary control, and it is
//! a good one — but it only fires if `splice` is CALLED. A repo function that
//! takes a `&Viewer`, never calls `splice`, and runs its own `sqlx::query` is
//! caught by nothing. That is exactly how `belief.rs::frame_claims_sorted`
//! evaded every control PR-06 shipped: it held a viewer, built its statement
//! with `format!`, and never spliced.
//!
//! `frame_claims_sorted` lived in the route layer, where
//! `crates/epigraph-api/tests/viewer_route_table_lint.rs` now watches for it.
//! This file is the repo-layer half of the same property.
//!
//! # What it checks
//!
//! For every `fn` under `crates/epigraph-db/src/repos/` whose parameter list
//! mentions `Viewer`: if the body runs SQL (`sqlx::query…`), the body must
//! contain at least one of
//!
//! * `.splice(` — the marker path,
//! * the literal `visibility = 'public'` — the static three-bind spelling the
//!   `sqlx::query!` macro sites use, which `visibility.rs`'s module doc names
//!   as the accepted equivalent (the macro needs a compile-time literal of
//!   fixed arity and so cannot be spliced), or
//! * a `VISIBILITY-EXEMPT:` comment carrying a reason.
//!
//! The third of those is a convention the repo layer already used in a dozen
//! places before this file existed — as a `-- VISIBILITY-EXEMPT:` line inside
//! the SQL literal. Nothing read it. An exemption convention with no ratchet
//! behind it is a comment style, not a control, so
//! [`the_exemption_set_is_exactly_what_was_reviewed`] pins the exact set.
//!
//! # What it checks since PR-13: WHICH fragment, not only that there is one
//!
//! `edges` has two owning groups as of migration 072, so it takes a different
//! predicate — [`epigraph_db::visibility::Viewer::edge_predicate_fragment`],
//! spelled `/* {EDGE_VISIBILITY:<alias>} */`. Every check above is satisfied by
//! an `edges` read that uses the SINGLE-OWNER predicate: it spends its viewer,
//! it contains `visibility = 'public'`, it calls `.splice(`. It just shows a
//! cross-group edge to a principal in only one of its two owning groups.
//!
//! [`every_edges_marker_uses_the_edge_spelling_and_no_others_do`] closes that
//! by resolving each marker's alias to the table it names and requiring the two
//! to agree — in both directions, since the edge fragment names a column no
//! other table has. It is a textual approximation of a SQL parser and is
//! calibrated by [`the_edge_marker_scanner_is_not_vacuous`], because a scanner
//! that resolved every alias to `None` would be silently vacuous.
//!
//! # What it deliberately does NOT check
//!
//! **Where** the marker sits. A marker in the wrong clause — inside a `LEFT
//! JOIN`'s ON versus its WHERE, say — is a semantic question this lint cannot
//! answer, and pretending otherwise would be the same over-claim that got the
//! previous citations into trouble. `repos/claim.rs::count_all_evidence_for_claim`
//! carries a comment explaining its placement for that reason. What this lint
//! guarantees is the weaker but checkable property: **a viewer parameter is
//! never silently ignored**.
//!
//! It also cannot see a function that delegates its SQL to another function —
//! those have no `sqlx::query` in their own body and are correctly skipped,
//! because the callee is itself subject to this lint.

use std::path::{Path, PathBuf};

/// Every viewer-taking repo function carrying a `VISIBILITY-EXEMPT:` marker,
/// as measured on **2026-09-02**.
///
/// The marker convention already existed in the tree — `claim.rs`, `edge.rs`,
/// `frame.rs`, `claim_theme.rs`, `mass_function.rs` and `triple.rs` all use it,
/// mostly as a `-- VISIBILITY-EXEMPT:` comment inside the SQL literal. What did
/// not exist was anything that READ it. An exemption convention with no ratchet
/// behind it is a comment style, not a control: nothing stopped a leak being
/// annotated rather than fixed.
///
/// Three categories, all reviewed:
///
/// * **Corpus-wide maintenance enumerators** — `find_claims_needing_embeddings`,
///   `list_claim_ids`, the three `claim_theme` centroid functions. A `Scoped`
///   viewer here is not safer, it is WRONG: the enumerator would silently skip
///   every other tenant's rows, leaving them unembedded or their beliefs stale
///   forever, and report success. A theme centroid computed per-viewer would
///   give each tenant a different value for the same row.
/// * **Corpus cardinality** — `triple.rs::index_counts`, three scalars used for
///   index health.
/// * **Write paths PR-16 owns** — `evidence.rs::delete`,
///   `semantic_link.rs::retract`.
///
/// The set is asserted exactly, not just counted, so a NEW exemption is a
/// visible diff naming the function. That matters more than the total: an
/// exemption appearing on a READ path is almost always a leak being annotated.
const EXPECTED_EXEMPTIONS: &[(&str, &str)] = &[
    ("claim.rs", "find_claims_needing_embeddings"),
    ("claim_theme.rs", "assign_unthemed_batch"),
    ("claim_theme.rs", "recompute_all_centroids"),
    ("claim_theme.rs", "recompute_centroid_for_theme"),
    // PR-09. `agents` is not in migration 062's `tier_a` array — it has
    // `profile_visibility` and `default_group_id`, no `owner_group_id` — so
    // there is nothing to filter on. Corpus cardinality, same category as
    // `triple.rs::index_counts`; one scalar leaves the function.
    ("corpus_stats.rs", "agent_count"),
    ("evidence.rs", "delete"),
    ("mass_function.rs", "list_claim_ids"),
    ("semantic_link.rs", "retract"),
    ("triple.rs", "index_counts"),
];

/// The one spelling of an accepted exemption, kept next to the accepted
/// spellings of a filter so all of them are read together.
const EXEMPT_MARKER: &str = "VISIBILITY-EXEMPT:";

/// The two ways a body can legitimately spend its viewer.
///
/// `.splice(` is the marker path. `visibility = 'public'` is the leading
/// disjunct of the static three-bind form the four `sqlx::query!` macro sites
/// use — those cannot take a spliced literal, because the macro needs a
/// compile-time literal of fixed arity, so they carry the predicate verbatim.
///
/// **`group_bind()` / `bypass_bind()` are deliberately NOT on this list**, even
/// though an earlier draft accepted them. Binding a group array proves the
/// caller supplied a parameter; it does not prove the SQL has a predicate that
/// reads it. A `frame_claims_sorted`-shaped fail-open — `format!` the statement,
/// omit the predicate, bind the array anyway — would pass a lint keyed on the
/// accessor and fail this one. Requiring the predicate TEXT is what makes this
/// check about the query rather than about the call.
const SPENT_MARKERS: &[&str] = &[".splice(", "visibility = 'public'"];

fn repos_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repos")
}

fn repo_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repos_dir()).expect("read repos dir") {
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
            std::fs::read_to_string(&path).expect("read repo file"),
        ));
    }
    out.sort();
    assert!(
        out.len() > 30,
        "expected the repos directory to hold the whole SQL surface, found {} \
         files — the lint is probably looking in the wrong place and would pass \
         vacuously",
        out.len()
    );
    out
}

/// The balanced region starting at `src[start]`, which must be `open`.
///
/// Skips string literals (normal and raw) and line comments, so braces or
/// parens inside SQL text cannot unbalance the count.
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
                // A char literal such as `'{'`. Skip it wholesale so its
                // contents cannot move the depth.
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

/// Every `fn` under `src/repos/` whose parameter list mentions `Viewer`.
fn viewer_taking_fns() -> Vec<ViewerFn> {
    let mut out = Vec::new();
    for (file, src) in repo_files() {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("fn ") {
            let at = from + rel;
            from = at + 3;

            // `fn` must be a whole token.
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

            // Skip an optional generic list, then require the parameter list.
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
            // Anything other than whitespace between the name and `(` means
            // this is not a declaration we can read.
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

/// A viewer parameter must never be silently ignored by a function that runs
/// SQL.
#[test]
fn every_viewer_taking_repo_fn_that_runs_sql_spends_the_viewer() {
    let fns = viewer_taking_fns();
    assert!(
        fns.len() > 100,
        "found only {} viewer-taking repo fns — PR-06 converted ~190, so the \
         scanner is not matching declarations and this lint would pass \
         vacuously",
        fns.len()
    );

    let mut offenders = Vec::new();
    for f in &fns {
        if !f.body.contains("sqlx::query") && !f.body.contains("sqlx::raw_sql") {
            // Delegating wrapper: the callee is subject to this same lint.
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
        "\n\nThese repo functions take a `&Viewer`, run SQL, and never spend \
         it:\n{}\n\n\
         A read that accepts read authority and ignores it is a fail-open that \
         compiles, passes every \"a stranger cannot read\" test (it returns \
         MORE, not less), and is invisible in a diff. `Viewer::splice`'s \
         missing-marker panic cannot catch this class, because it only fires \
         when `splice` is called at all — which is precisely how \
         `belief.rs::frame_claims_sorted` leaked.\n\n\
         Fix: add `/* {{VISIBILITY:<alias>}} */` to the SQL and wrap it in \
         `viewer.splice(..)`; or, at a `sqlx::query!` macro site, write the \
         static form `AND ($N::bool OR visibility = 'public' OR owner_group_id \
         = ANY($M::uuid[]))` and bind `viewer.bypass_bind()` / \
         `viewer.group_bind()`. If the function is a write path PR-16 owns, add \
         a `{EXEMPT_MARKER}` comment WITH A REASON and raise the count in \
         EXPECTED_EXEMPTIONS.\n",
        offenders.join("\n")
    );
}

/// The exemption list is a ratchet, not a category.
///
/// Without this, `VISIBILITY-EXEMPT:` would be a comment anyone can type to
/// silence the lint above. Asserting the exact set makes every new exemption a
/// visible diff in review.
#[test]
fn the_exemption_set_is_exactly_what_was_reviewed() {
    let mut actual: Vec<(String, String)> = viewer_taking_fns()
        .into_iter()
        .filter(|f| f.body.contains(EXEMPT_MARKER))
        .map(|f| (f.file, f.name))
        .collect();
    actual.sort();

    let mut want: Vec<(String, String)> = EXPECTED_EXEMPTIONS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    want.sort();

    assert_eq!(
        actual, want,
        "\n\nThe `{EXEMPT_MARKER}` set changed. Every current entry is either a \
         corpus-wide maintenance enumerator (where a Scoped viewer would be \
         WRONG, not safer), a corpus-cardinality scalar, or a write path PR-16 \
         owns. A new exemption on a READ path is almost certainly a leak being \
         annotated rather than fixed.\n"
    );
}

/// The lint and the repo layer must not drift to spellings of the marker that
/// only one of them knows.
///
/// There are exactly TWO spellings, and both are constants in `visibility.rs`:
/// [`epigraph_db::visibility::VISIBILITY_MARKER_PREFIX`] and, since PR-13,
/// [`epigraph_db::visibility::EDGE_VISIBILITY_MARKER_PREFIX`]. The second exists
/// because the marker's alias is a text substitution and not a dispatch key —
/// `e` names `edges` in `repos/structural.rs` and `evidence` in
/// `repos/evidence.rs`, so the `edges` co-ownership fragment cannot be selected
/// by alias. See `visibility.rs`'s module docs.
///
/// WIDENED, NOT WEAKENED. A `.splice(` body carrying NEITHER spelling is still
/// an offender, which is the whole assertion: `splice` panics at runtime on a
/// marker-free literal, and this test turns that into a compile-time-shaped
/// failure. What changed is only that an `edges`-only statement is now
/// legitimate rather than reported.
#[test]
fn every_spliced_statement_carries_the_canonical_marker_spelling() {
    let prefix = epigraph_db::visibility::VISIBILITY_MARKER_PREFIX;
    let edge_prefix = epigraph_db::visibility::EDGE_VISIBILITY_MARKER_PREFIX;
    // Statements built with `format!` double their braces, so the marker reads
    // `/* {{VISIBILITY:` in source. Accept both spellings of the same thing.
    let doubled = prefix.replace('{', "{{");
    let edge_doubled = edge_prefix.replace('{', "{{");

    // The two prefixes must stay disjoint strings. If `EDGE_VISIBILITY` ever
    // became a superstring of `VISIBILITY` (or vice versa), `splice`'s two
    // substitution passes would capture each other's markers and this test
    // would accept a statement that filters nothing.
    assert!(
        !edge_prefix.contains(prefix) && !prefix.contains(edge_prefix),
        "the two marker spellings must not contain one another: \
         {prefix} / {edge_prefix}"
    );

    let mut offenders = Vec::new();
    for f in viewer_taking_fns() {
        if !f.body.contains(".splice(") {
            continue;
        }
        let carries = f.body.contains(prefix)
            || f.body.contains(&doubled)
            || f.body.contains(edge_prefix)
            || f.body.contains(&edge_doubled);
        if !carries {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese functions call `Viewer::splice` on SQL that carries neither \
         `{prefix}` nor `{edge_prefix}` (nor their `format!`-doubled forms \
         `{doubled}` / `{edge_doubled}`):\n{}\n\n\
         `splice` panics at runtime on a marker-free literal, so this would be \
         caught the first time the query executes — but only if a test touches \
         it. Catching it here makes it a compile-time-shaped failure.\n",
        offenders.join("\n")
    );
}

/// Every `edges` read that filters must use the EDGE spelling, and no other
/// table may.
///
/// This is the ratchet PR-13's conversion needs and the plain lint cannot give:
/// `visibility = 'public'` appears in both fragments, so a statement that
/// filters `edges` with the SINGLE-OWNER predicate spends its viewer, carries a
/// canonical marker, and passes every existing assertion here — while a
/// cross-group edge remains visible to a principal in only one of its two
/// owning groups. That is a leak that looks exactly like compliance.
///
/// The scan is textual and deliberately crude: for each marker, find the
/// nearest preceding binding of its alias inside the same statement and check
/// which table it names. It is therefore an approximation of the SQL parser
/// nobody wants to write here, and it is calibrated by
/// [`the_edge_marker_scanner_is_not_vacuous`] below.
///
/// # Two bounds this does NOT cover — state them rather than imply completeness
///
/// **1. Directory.** It reads [`repo_files`], i.e. `crates/epigraph-db/src/repos`
/// only. The other `.splice(` call sites in the workspace —
/// `epigraph-mcp/src/tools/{ds_auto,workflows,ds,link_epistemic}.rs` and
/// `epigraph-api/src/routes/cross_source.rs` — are outside it. Every one of
/// those filters `claims` today, so this is a reach limit and not a live leak;
/// an `edges` read added to a route handler or an MCP tool would evade it in
/// both directions. `epigraph-mcp/tests/tool_viewer_is_spent.rs` and
/// `epigraph-api/tests/viewer_route_table_lint.rs` already scan those trees and
/// are where the check would be widened.
///
/// **2. Marker sites only.** It resolves markers, so it is structurally blind
/// to the static `sqlx::query!` / `query_as!` transcriptions, which carry no
/// marker and spell the predicate inline. Those are the majority of PR-13's
/// converted `edges` surface (`edge.rs`, `paper.rs`, `provenance_chain.rs`,
/// `claim.rs`). A future `edges` read written as a macro with the single-owner
/// spelling spends its viewer, contains `visibility = 'public'`, carries no
/// `.splice(` and carries no marker — so it passes every check in this file,
/// including this one. The conversion is complete TODAY (no `edges` read
/// outside the documented exemptions still uses the single-owner form); it is
/// the RATCHET that covers the marker half only.
#[test]
fn every_edges_marker_uses_the_edge_spelling_and_no_others_do() {
    let mut plain_on_edges = Vec::new();
    let mut edge_on_other = Vec::new();

    for (file, src) in repo_files() {
        for (line, alias, is_edge, table) in markers_with_their_tables(&src) {
            match (table.as_deref(), is_edge) {
                (Some("edges"), false) => plain_on_edges.push(format!(
                    "  {file}:{line} — alias `{alias}` names `edges` but takes \
                     the single-owner predicate"
                )),
                (Some(t), true) if t != "edges" => edge_on_other.push(format!(
                    "  {file}:{line} — alias `{alias}` names `{t}`, which has no \
                     co_owner_group_id column"
                )),
                _ => {}
            }
        }
    }

    assert!(
        plain_on_edges.is_empty(),
        "\n\nThese `edges` reads filter on `owner_group_id` alone:\n{}\n\n\
         An edge whose endpoints are private to different groups G and H is \
         stored as (owner = G, co_owner = H) since migration 072. The \
         single-owner predicate shows it to any principal in G, including one \
         with no access to H's endpoint. Use `/* {{EDGE_VISIBILITY:<alias>}} */`.\n",
        plain_on_edges.join("\n")
    );
    assert!(
        edge_on_other.is_empty(),
        "\n\nThese non-`edges` reads use the EDGE marker:\n{}\n\n\
         `co_owner_group_id` exists only on `edges`; the rendered predicate \
         would be a runtime `column does not exist` error, which is \
         compile-time-clean.\n",
        edge_on_other.join("\n")
    );
}

/// The scanner above is an approximation, so it is calibrated rather than
/// trusted: a scanner that resolved every alias to `None` would make the
/// ratchet vacuous and stay green forever.
#[test]
fn the_edge_marker_scanner_is_not_vacuous() {
    let plain = "let sql = viewer.splice(\"SELECT 1 FROM claims c \
                 WHERE true /* {VISIBILITY:c} */\", 2);";
    let edges = "let sql = viewer.splice(\"SELECT 1 FROM edges e \
                 WHERE true /* {EDGE_VISIBILITY:e} */\", 2);";
    let mixed = "let sql = viewer.splice(\"SELECT 1 FROM evidence e JOIN edges ed \
                 ON ed.source_id = e.id /* {EDGE_VISIBILITY:ed} */ \
                 WHERE true /* {VISIBILITY:e} */\", 3);";

    let got = markers_with_their_tables(plain);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].2, got[0].3.as_deref()), (false, Some("claims")));

    let got = markers_with_their_tables(edges);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].2, got[0].3.as_deref()), (true, Some("edges")));

    // The collision that motivates the second spelling: `e` is `evidence` and
    // `ed` is `edges`, in ONE statement.
    let got = markers_with_their_tables(mixed);
    assert_eq!(got.len(), 2, "{got:?}");
    let by_alias: std::collections::HashMap<_, _> = got
        .iter()
        .map(|(_, a, is_edge, t)| (a.clone(), (*is_edge, t.clone())))
        .collect();
    assert_eq!(
        by_alias["ed"],
        (true, Some("edges".to_string())),
        "{by_alias:?}"
    );
    assert_eq!(
        by_alias["e"],
        (false, Some("evidence".to_string())),
        "{by_alias:?}"
    );
}

/// `(line, alias, is_edge_spelling, table_the_alias_names)` for every marker.
///
/// The statement window is bounded at the nearest preceding `.splice(`,
/// `sqlx::query`, or `format!` so a binding from an unrelated statement earlier
/// in the file cannot answer for this one. `None` means the scan could not
/// resolve the alias; unresolved aliases are ignored by the caller rather than
/// reported, because a false accusation here is worse than a miss the runtime
/// panic and `splice`'s own assertions already cover.
fn markers_with_their_tables(src: &str) -> Vec<(usize, String, bool, Option<String>)> {
    const ANCHORS: &[&str] = &[".splice(", "sqlx::query", "format!"];
    let mut out = Vec::new();
    let mut idx = 0usize;

    while let Some(rel) = src[idx..].find("VISIBILITY:") {
        let at = idx + rel;
        idx = at + "VISIBILITY:".len();

        // Distinguish `{EDGE_VISIBILITY:` from `{VISIBILITY:`; skip anything
        // that is neither (prose, constant names).
        let before = &src[..at];
        let is_edge = before.ends_with("{EDGE_") || before.ends_with("{{EDGE_");
        let is_plain = before.ends_with('{');
        if !is_edge && !is_plain {
            continue;
        }

        let Some(end) = src[idx..].find('}') else {
            continue;
        };
        let alias = src[idx..idx + end].trim().to_string();
        if alias.is_empty()
            || !alias
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }

        let win_start = ANCHORS
            .iter()
            .filter_map(|a| before.rfind(a))
            .max()
            .unwrap_or(0);
        let window = &src[win_start..at];

        // Last `FROM <table> <alias>` / `JOIN <table> <alias>` in the window,
        // falling back to an unaliased `FROM <alias>` (the marker alias IS the
        // table name, e.g. `/* {EDGE_VISIBILITY:edges} */`).
        let table = last_binding(window, &alias);
        out.push((before.matches('\n').count() + 1, alias, is_edge, table));
    }
    out
}

fn last_binding(window: &str, alias: &str) -> Option<String> {
    let mut found: Option<String> = None;
    let words: Vec<&str> = window.split_whitespace().collect();
    for i in 0..words.len() {
        let kw = words[i].trim_start_matches(['(', ',']);
        if !kw.eq_ignore_ascii_case("FROM") && !kw.eq_ignore_ascii_case("JOIN") {
            continue;
        }
        let Some(tbl_raw) = words.get(i + 1) else {
            continue;
        };
        let tbl = tbl_raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_');
        if tbl.is_empty() {
            continue;
        }
        // `FROM edges` with no alias: the marker alias is the table itself.
        if tbl == alias {
            found = Some(tbl.to_string());
            continue;
        }
        let next = words
            .get(i + 2)
            .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_'));
        let aliased = match next {
            Some(n) if n.eq_ignore_ascii_case("AS") => words
                .get(i + 3)
                .map(|w| w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')),
            other => other,
        };
        if aliased == Some(alias) {
            found = Some(tbl.to_string());
        }
    }
    found
}
