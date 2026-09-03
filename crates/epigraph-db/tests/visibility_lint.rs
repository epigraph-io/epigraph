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

/// The lint and the repo layer must not drift to two spellings of the marker.
///
/// `visibility.rs`'s module doc claims [`epigraph_db::visibility::VISIBILITY_MARKER_PREFIX`]
/// is "the single spelling of the marker, shared with
/// `crates/epigraph-db/tests/visibility_lint.rs`, so the lint and the repo
/// layer cannot drift apart". This test is what makes that sentence true:
/// every `.splice(` call site must carry the marker spelled the way the
/// constant spells it.
#[test]
fn every_spliced_statement_carries_the_canonical_marker_spelling() {
    let prefix = epigraph_db::visibility::VISIBILITY_MARKER_PREFIX;
    // Statements built with `format!` double their braces, so the marker reads
    // `/* {{VISIBILITY:` in source. Accept both spellings of the same thing.
    let doubled = prefix.replace('{', "{{");

    let mut offenders = Vec::new();
    for f in viewer_taking_fns() {
        if !f.body.contains(".splice(") {
            continue;
        }
        if !f.body.contains(prefix) && !f.body.contains(&doubled) {
            offenders.push(format!("  {}:{} — {}", f.file, f.line, f.name));
        }
    }

    assert!(
        offenders.is_empty(),
        "\n\nThese functions call `Viewer::splice` on SQL that does not carry \
         `{prefix}` (or its `format!`-doubled form `{doubled}`):\n{}\n\n\
         `splice` panics at runtime on a marker-free literal, so this would be \
         caught the first time the query executes — but only if a test touches \
         it. Catching it here makes it a compile-time-shaped failure.\n",
        offenders.join("\n")
    );
}
