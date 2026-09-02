//! Source lint implementing PR-07 acceptance criterion #1:
//! *"no handler that returns claim content lacks a `ViewerExtractor`
//! (route-table test)"*.
//!
//! # Why this file exists
//!
//! PR-07 originally cited `public_router_allowlist.rs` as the verification for
//! that criterion. It is not: that test asserts public-vs-protected router
//! *membership* and makes no assertion whatsoever about `ViewerExtractor`
//! presence on handlers. The criterion was asserted only in prose — and it was
//! false, with two live counterexamples in `belief.rs` (`claims_by_belief`,
//! which had no `ViewerExtractor` at all, and `frame_claims_sorted`, which held
//! one and never filtered on it). Both are fixed; this file is the ratchet that
//! stops the class recurring.
//!
//! # Why a source lint and not a runtime route-table walk
//!
//! axum erases handler signatures into boxed `Handler` impls at registration
//! time, so a `Router` cannot be asked at runtime which extractors a handler
//! declared. The property is only visible in the source. That makes this a
//! grep with a spine rather than an integration test, and it is deliberately
//! written to fail loudly with the offending file, line and snippet rather than
//! to report a bare count.
//!
//! # What it actually checks
//!
//! **The real invariant is not "a handler mentions `ViewerExtractor`" — that is
//! trivially satisfiable and was satisfied by `frame_claims_sorted` while it
//! leaked.** The invariant is that no claim-content read happens in the route
//! layer at all. Content reads live in `crates/epigraph-db/src/repos/`, where
//! the `/* {VISIBILITY:...} */` marker convention applies and
//! `Viewer::splice`'s missing-marker panic can enforce it. A handler cannot
//! splice a predicate into SQL it does not own.
//!
//! So: **no `sqlx::query*` call in `crates/epigraph-api/src/routes/` may select
//! claim content**, except for the sites on the dated exemption list below.
//! Checking the structural property (where the SQL lives) rather than the
//! syntactic one (does the word `ViewerExtractor` appear) is what makes this
//! lint catch the defect that motivated it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Sites that still read claim content inline in the route layer, as measured
/// on **2026-09-02**, at the close of PR-07.
///
/// This list is a debt register, not a permission slip. Every entry is a
/// handler whose claim-content read is still unfiltered by a `Viewer`; each is
/// latent rather than live only because migration 062 defaults
/// `claims.visibility` to `'public'` and nothing transcribes ownership into the
/// tenancy columns until **PR-12**. The compensating control is the per-row
/// `check_content_access` pass, which **PR-14 deletes**. That is the deadline.
///
/// PR-07 removed these files from the list by moving their statements into the
/// repo layer: `belief.rs` (2), `search.rs` (2), `graph_query_utils.rs` (2),
/// `assess.rs` (1), `graph_neighborhood.rs`, `graph.rs`, `rag.rs`.
///
/// The count is asserted exactly, so this ratchet is monotone: adding a new
/// inline claim-content read fails the build, and removing one fails it too
/// until the number here is lowered. Do not raise it.
const INLINE_CLAIM_CONTENT_READS: &[(&str, usize)] = &[
    ("claims.rs", 2),
    ("conflicts.rs", 1),
    ("conventions.rs", 1),
    ("cross_source.rs", 1),
    ("edges.rs", 1),
    ("experiments.rs", 1),
    ("gaps.rs", 1),
    ("hypothesis.rs", 3),
    ("policies.rs", 1),
    ("reasoning.rs", 2),
    ("versioning.rs", 1),
    ("voids.rs", 3),
    ("workflows.rs", 5),
];

/// Fail-open scope-check sites: `if let Some(..) = auth_ctx { check_scopes(..) }`
/// with no `else`, which performs no authorization at all when `AuthContext` is
/// absent. Measured on **2026-09-02**.
///
/// The plan's §4.13 puts this at 39; the verbatim idiom counts 37 in the tree
/// after PR-07 converted `crud.rs::get_theme_embeddings` (see the PR-07 entry in
/// `docs/tenancy/progress.json` for the full reconciliation). The remainder are
/// predominantly **write** paths and are assigned to PR-16.
///
/// Asserted exactly for the same monotonicity reason as above.
const FAIL_OPEN_SCOPE_SITES: &[(&str, usize)] = &[
    ("agent_keys.rs", 3),
    ("agents.rs", 2),
    ("audit.rs", 1),
    ("claims.rs", 2),
    ("crud.rs", 11),
    ("edges.rs", 9),
    ("papers.rs", 1),
    ("tasks.rs", 6),
    ("webhooks.rs", 2),
];

fn routes_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes")
}

fn route_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(routes_dir()).expect("read routes dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        let body = std::fs::read_to_string(&path).expect("read route file");
        out.push((name, body));
    }
    out.sort();
    assert!(
        out.len() > 40,
        "expected the routes directory to hold the whole HTTP surface, found {} files — \
         the lint is probably looking in the wrong place and would pass vacuously",
        out.len()
    );
    out
}

/// Byte offsets of every `sqlx::query`/`query_as`/`query_scalar` **invocation**.
///
/// The tail after `sqlx::query` must open a call — `(`, or a turbofish that
/// eventually does. Requiring invocation syntax is what keeps prose out of the
/// count: `// Row types for sqlx::query_as` in `graph_query_utils.rs` is a bare
/// mention, and an early version of this lint charged it as a violation because
/// the 2500-byte window downstream of it swept up a doc comment that quotes the
/// very SQL this PR deleted.
fn sqlx_call_offsets(src: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find("sqlx::query") {
        let at = from + rel;
        from = at + "sqlx::query".len();

        // Skip the `_as` / `_scalar` suffix, then any turbofish, then require `(`.
        let mut tail = &src[from..];
        for suffix in ["_as", "_scalar"] {
            if let Some(rest) = tail.strip_prefix(suffix) {
                tail = rest;
                break;
            }
        }
        let tail = tail.trim_start();
        let opens_call = if let Some(rest) = tail.strip_prefix("::<") {
            // Turbofish: find its close, then require `(`.
            rest.find('>')
                .is_some_and(|gt| rest[gt + 1..].trim_start().starts_with('('))
        } else {
            tail.starts_with('(')
        };
        if opens_call {
            out.push(at);
        }
    }
    out
}

/// Does the argument region of a `sqlx::query*` call read claim content?
///
/// Deliberately over-approximate on the SQL side (any mention of `claims` plus
/// a `content` column) and bounded on the scan side (the next 2500 bytes, which
/// comfortably covers every statement in this tree). A false positive here
/// costs one exemption-list entry; a false negative costs a leak.
fn reads_claim_content(region: &str) -> bool {
    let low = region.to_ascii_lowercase();
    let touches_claims = low.contains("from claims") || low.contains("join claims");
    if !touches_claims {
        return false;
    }
    // `content` as a column reference, not as part of a longer identifier.
    low.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| tok == "content" || tok.ends_with(".content"))
}

fn measure_inline_claim_content_reads() -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let mut n = 0usize;
        for at in sqlx_call_offsets(&src) {
            let end = (at + 2500).min(src.len());
            // Slice on a char boundary; route files contain non-ASCII in comments.
            let mut e = end;
            while e > at && !src.is_char_boundary(e) {
                e -= 1;
            }
            if reads_claim_content(&src[at..e]) {
                n += 1;
            }
        }
        if n > 0 {
            counts.insert(name, n);
        }
    }
    counts
}

fn measure_fail_open_scope_sites() -> BTreeMap<String, usize> {
    let needle = "if let Some(axum::Extension(ref auth)) = auth_ctx";
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let n = src.matches(needle).count();
        if n > 0 {
            counts.insert(name, n);
        }
    }
    counts
}

fn expected(list: &[(&str, usize)]) -> BTreeMap<String, usize> {
    list.iter().map(|(f, n)| ((*f).to_string(), *n)).collect()
}

/// Report the exact per-file delta, so a failure names the file to look at
/// rather than only a total that moved.
fn diff_report(actual: &BTreeMap<String, usize>, want: &BTreeMap<String, usize>) -> String {
    let mut lines = Vec::new();
    let mut files: Vec<&String> = actual.keys().chain(want.keys()).collect();
    files.sort();
    files.dedup();
    for f in files {
        let a = actual.get(f).copied().unwrap_or(0);
        let w = want.get(f).copied().unwrap_or(0);
        if a != w {
            let verdict = if a > w { "REGRESSION" } else { "improved" };
            lines.push(format!("  {f}: expected {w}, found {a}  [{verdict}]"));
        }
    }
    lines.join("\n")
}

#[test]
fn no_new_inline_claim_content_reads_in_the_route_layer() {
    let actual = measure_inline_claim_content_reads();
    let want = expected(INLINE_CLAIM_CONTENT_READS);
    assert_eq!(
        actual,
        want,
        "\n\nPR-07 acceptance #1 ratchet failed.\n{}\n\n\
         A `sqlx::query*` call in crates/epigraph-api/src/routes/ selects claim \
         content. Route handlers cannot carry a `/* {{VISIBILITY:...}} */` \
         marker, so such a read is unfilterable by a `Viewer` no matter how many \
         extractors the handler declares — `frame_claims_sorted` held a viewer \
         and leaked anyway, which is why this lint checks WHERE the SQL lives \
         rather than whether the word `ViewerExtractor` appears.\n\n\
         Fix: move the statement into crates/epigraph-db/src/repos/, add the \
         marker, and call `viewer.splice`. If you have genuinely removed a site, \
         LOWER the number in INLINE_CLAIM_CONTENT_READS. Never raise it.\n",
        diff_report(&actual, &want)
    );
}

#[test]
fn fail_open_scope_check_sites_do_not_increase() {
    let actual = measure_fail_open_scope_sites();
    let want = expected(FAIL_OPEN_SCOPE_SITES);
    assert_eq!(
        actual,
        want,
        "\n\nFail-open scope-check ratchet failed.\n{}\n\n\
         `if let Some(axum::Extension(ref auth)) = auth_ctx {{ check_scopes(..) }}` \
         performs NO authorization when `AuthContext` is absent. Where it is \
         currently harmless, that is only because a `ViewerExtractor` earlier in \
         the same signature 401s first — which makes an authz control depend on \
         axum parameter ORDER.\n\n\
         Fix: `let auth = auth_ctx.ok_or(ApiError::Unauthorized {{ .. }})?.0;` \
         then check scopes unconditionally (see \
         `crud.rs::get_theme_embeddings`). Then LOWER the number here.\n",
        diff_report(&actual, &want)
    );
}

#[test]
fn the_two_handlers_pr07_fixed_stay_fixed() {
    // Targeted regression guards for the two named counterexamples, so a
    // revert is caught by name rather than only by a count moving.
    let src = std::fs::read_to_string(routes_dir().join("belief.rs")).expect("read belief.rs");

    let by_belief = src
        .find("pub async fn claims_by_belief")
        .expect("claims_by_belief handler still exists");
    let window = &src[by_belief..(by_belief + 900).min(src.len())];
    assert!(
        window.contains("ViewerExtractor"),
        "claims_by_belief lost its ViewerExtractor; it is a paginated, \
         content-returning corpus scan and was PR-07's live counterexample to \
         acceptance criterion #1"
    );

    let frame_sorted = src
        .find("pub async fn frame_claims_sorted")
        .expect("frame_claims_sorted handler still exists");
    let window = &src[frame_sorted..(frame_sorted + 3000).min(src.len())];
    assert!(
        window.contains("ClaimRepository::frame_claims_sorted"),
        "frame_claims_sorted no longer routes through the viewer-spliced repo \
         function; holding a Viewer and building the content query inline is the \
         exact fail-open PR-07 fixed"
    );
    assert!(
        !window.contains("JOIN claims c ON c.id = cf.claim_id"),
        "frame_claims_sorted has an inline claims join again"
    );
}
