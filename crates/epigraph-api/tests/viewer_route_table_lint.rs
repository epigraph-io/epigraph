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
//!
//! # Two ways this lint was blind, and how it is measured now
//!
//! The first revision of this file **could not have caught `frame_claims_sorted`
//! either**, despite the paragraph above claiming that is what it is for. Two
//! independent holes, both closed in PR-07's follow-up:
//!
//! 1. **It scanned only FORWARD from the `sqlx::query*` token**, over a fixed
//!    2500-byte window. `frame_claims_sorted`'s shape is
//!    `let query = format!(…); … sqlx::query_as(&query)` — the SQL literal sits
//!    ABOVE the call, so the window never saw it. Replayed against
//!    `origin/integration/tenancy` the old algorithm scored `belief.rs: 1`,
//!    counting the one inline literal and missing the `format!` one. The hole
//!    was still live in PR-07's own tree: `routes/search.rs` builds `full_sql`
//!    with `format!` and calls `sqlx::query(&full_sql)`, and the old lint
//!    measured `search.rs: 0`.
//!
//!    [`resolved_region`] now resolves `sqlx::query*(&ident)` back to the
//!    `let <ident> = …` binding above it and scans that too.
//!    [`a_format_built_statement_is_counted`] pins the fix.
//!
//! 2. **`reads_claim_content` recognised one table and one column** — `claims`
//!    plus a bare `content` token — so it could not see reads of `evidence`,
//!    `challenges.explanation`, `claim_versions.content`, `claims.properties`
//!    or `claims.embedding`. PR-07's own acceptance criteria cover all of
//!    those: embeddings are treated as approximately invertible to content,
//!    and challenge `explanation`s are criterion #3's subject. It now
//!    recognises the `tier_a` projections.
//!
//! # And the fixed window is gone
//!
//! The 2500-byte forward window also **over**-counted: it swept up whatever
//! statement happened to follow. `conventions.rs`'s `SELECT labels FROM claims`
//! was charged as a content read because the handler's `content: claim.content`
//! response field sat eleven lines below it, and `reasoning.rs` was charged 2
//! for an in-file `#[cfg(test)]` INSERT fixture. Those are false positives, and
//! a debt register full of them is not a register — it is noise that makes the
//! real entries unreviewable, which is the same failure the entries' own
//! justification had.
//!
//! [`arg_region`] replaces the window with the call's balanced-paren argument
//! region, skipping string literals so SQL parens cannot unbalance it. The
//! region is therefore exactly the statement, and every entry below was
//! hand-checked against its source line.
//!
//! # The numbers below were RE-BASELINED, not raised
//!
//! Widening the predicate and fixing the scan is a redefinition of the
//! measurement, not a regression in the tree. The counts were re-derived under
//! the new measurement on **2026-09-02**; the ratchet is monotone from that
//! baseline forward. Fixing the newly-surfaced sites is PR-12/PR-14/PR-16 work.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Sites that still read claim content inline in the route layer, as measured
/// on **2026-09-02**, under the corrected measurement described in the module
/// docs (balanced-paren argument region + `let`-binding resolution + the
/// `tier_a` column set).
///
/// This list is a debt register, not a permission slip. Every entry is a
/// handler whose `tier_a` read is still unfiltered by a `Viewer`, and each is
/// latent rather than live only because migration 062 defaults `visibility` to
/// `'public'` and nothing transcribes ownership into the tenancy columns until
/// **PR-12**.
///
/// # The compensating control does not exist for most of these
///
/// An earlier revision of this comment said "the compensating control is the
/// per-row `check_content_access` pass, which PR-14 deletes — that is the
/// deadline". That was asserted, never checked, and it is false for most of the
/// register. `grep -c check_content_access` over `src/routes/` returns a
/// non-zero count for **`claims.rs` and `edges.rs` only**; `clusters.rs`,
/// `conflicts.rs`, `cross_source.rs`, `embeddings.rs`, `hypothesis.rs`,
/// `policies.rs`, `political.rs`, `search.rs` and `workflows.rs` each return 0.
/// (`cross_source.rs` belongs in THIS list and not in
/// [`UNCOMPENSATED_INLINE_READS`] below: the two registers measure different
/// things, and PR-09 briefly deleted it from both. Its
/// `check_content_access` count was 0 before PR-09 and is 0 after.)
///
/// So the register is split. For [`UNCOMPENSATED_INLINE_READS`] there is no
/// second line of defence at all today, and the deadline is **PR-12** (when
/// ownership lands in the columns), not PR-14.
///
/// Even for the two compensated files this comment asserts only that the file
/// contains `check_content_access` calls — NOT that the call sits on the return
/// path of the specific counted statement. Establishing that per site is PR-14's
/// job, and claiming it here without checking is how the previous version of
/// this paragraph went wrong.
///
/// PR-07 removed these files from the list by moving their statements into the
/// repo layer: `belief.rs` (2), `search.rs` (2 of 3), `graph_query_utils.rs` (2),
/// `assess.rs` (1), `graph_neighborhood.rs`, `graph.rs`, `rag.rs`, and — in the
/// follow-up — `voids.rs` (3), `gaps.rs` (1), `experiments.rs` (2),
/// `computation.rs` (1) and one of `hypothesis.rs`'s.
///
/// The count is asserted exactly, so this ratchet is monotone: adding a new
/// inline `tier_a` read fails the build, and removing one fails it too until
/// the number here is lowered. Do not raise it.
const COMPENSATED_INLINE_READS: &[(&str, usize)] = &[("claims.rs", 3), ("edges.rs", 4)];

/// The register entries with NO `check_content_access` anywhere in the file.
///
/// Deadline **PR-12**, not PR-14: these become live disclosure the moment
/// ownership is transcribed into the tenancy columns, with nothing behind them.
const UNCOMPENSATED_INLINE_READS: &[(&str, usize)] = &[
    ("clusters.rs", 2),
    ("conflicts.rs", 1),
    // `cross_source.rs` was 1 until PR-09 and is now 0, so it is gone from the
    // register entirely. The site was `SELECT id, content FROM claims WHERE id
    // = ANY($1)` in `list_candidates`, hydrating excerpts for the candidate
    // queue; it is now
    // `ClaimRepository::contents_by_ids(&state.db_pool, &viewer, ..)`. PR-09
    // also removed the file's other unfiltered read — the `CORROBORATES` edge
    // scan in `get_cross_source_matches`, which this lint never counted because
    // it projects edge columns, not `tier_a` content — into
    // `MatchCandidateRepo::corroborates_edges_for_claim`. Both were byte-for-byte
    // duplicates of SQL in `epigraph-mcp/src/tools/matching.rs`; there is now
    // one copy, in the repo layer, filtered.
    ("embeddings.rs", 1),
    ("hypothesis.rs", 1),
    ("policies.rs", 2),
    ("political.rs", 1),
    // `search.rs`'s remaining site is the `format!`-built `full_sql` the old
    // forward-only scan could not see. Its in-code comment argues it is not a
    // live leak — the ids come from the viewer-filtered
    // `candidates_in_themes_at_dim` — and that derivation looks sound. It is
    // registered anyway: the argument is a caller-side invariant with nothing
    // enforcing it, which is precisely the kind of reasoning this register
    // exists to keep visible rather than to accept silently.
    ("search.rs", 1),
    ("workflows.rs", 4),
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
    // `("webhooks.rs", 2)` REMOVED by PR-10, which converted both sites in
    // `delete_webhook` to the prescribed
    // `auth_ctx.ok_or(ApiError::Unauthorized { .. })?` shape and made the scope
    // check unconditional. Removed rather than set to `0`: this constant is
    // compared as a whole `BTreeMap` against `measure_fail_open_scope_sites`,
    // which only inserts a key when its count is non-zero, so a `0` row is a
    // key the measurement can never produce and the assertion would fail on a
    // correct fix.
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

/// The balanced-paren argument region of the `sqlx::query*` call at `at`.
///
/// This replaces the old fixed 2500-byte forward window, which both
/// over-counted (it swept up whatever statement followed) and under-counted
/// (see [`resolved_region`]). String literals — normal and raw — are skipped so
/// that parentheses inside the SQL text cannot unbalance the depth count.
fn arg_region(src: &str, at: usize) -> &str {
    let b = src.as_bytes();
    let Some(open) = src[at..].find('(').map(|i| at + i) else {
        return &src[at..];
    };
    let n = src.len();
    let mut j = open + 1;
    let mut depth = 1usize;
    while j < n && depth > 0 {
        // Raw string: r"…", r#"…"#, r##"…"##
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
            b'/' if j + 1 < n && b[j + 1] == b'/' => {
                j = src[j..].find('\n').map_or(n, |e| j + e + 1);
                continue;
            }
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        j += 1;
    }
    // Clamp to a char boundary: route files contain non-ASCII in comments.
    let mut e = j.min(n);
    while e > open && !src.is_char_boundary(e) {
        e -= 1;
    }
    &src[open..e]
}

/// Extract `ident` from an argument region shaped `(&ident` / `(&ident,`.
fn borrowed_ident(region: &str) -> Option<&str> {
    let rest = region.strip_prefix('(')?.trim_start();
    let rest = rest.strip_prefix('&')?.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let ident = &rest[..end];
    let tail = rest[end..].trim_start();
    if tail.starts_with(',') || tail.starts_with(')') {
        Some(ident)
    } else {
        None
    }
}

/// The region to scan for one `sqlx::query*` call.
///
/// [`arg_region`] plus — when the sole SQL argument is a borrowed local, i.e.
/// `sqlx::query(&sql)` — the text of the `let <ident> = …` binding that built
/// it. That is the `frame_claims_sorted` shape: `let query = format!(…);` above
/// the call, invisible to any forward-only scan.
fn resolved_region(src: &str, at: usize) -> String {
    let region = arg_region(src, at);
    let Some(ident) = borrowed_ident(region) else {
        return region.to_string();
    };

    // The LAST `let <ident>` before the call: with two functions each binding
    // `sql`, the one in scope is the nearer one.
    let head = &src[..at];
    let mut best: Option<usize> = None;
    let mut from = 0usize;
    while let Some(rel) = head[from..].find("let ") {
        let pos = from + rel;
        from = pos + 4;
        let after = head[pos + 4..].trim_start();
        let after = after.strip_prefix("mut ").map_or(after, str::trim_start);
        if let Some(rest) = after.strip_prefix(ident) {
            if !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                best = Some(pos);
            }
        }
    }
    match best {
        Some(pos) => format!("{}{region}", &src[pos..at]),
        None => region.to_string(),
    }
}

/// `tier_a` tables whose projections this lint treats as claim content.
///
/// Migration 062 puts all four in its `tier_a` array, so all four carry
/// `visibility`/`owner_group_id` and all four are filterable today.
const CONTENT_TABLES: &[&str] = &["claims", "evidence", "challenges", "claim_versions"];

/// Column names that carry, or are approximately invertible to, claim content.
///
/// `explanation` is `challenges`' content column and is acceptance criterion
/// #3's subject; `embedding` is included because PR-07's own acceptance
/// criteria treat a raw vector as approximately invertible to the text it
/// encodes (that is why `/themes/:id/embeddings` returns none); `properties`
/// carries free-text payloads (`hypothesis_status`, `scope_limitations`,
/// evidence captions) and was the field `hypothesis_status` leaked alongside
/// `content`.
const CONTENT_COLUMNS: &[&str] = &["content", "explanation", "properties", "embedding"];

/// Does this region read `tier_a` content?
///
/// Deliberately over-approximate on the SQL side (any of [`CONTENT_TABLES`] in
/// a FROM/JOIN plus any of [`CONTENT_COLUMNS`] as a bare token) and precise on
/// the scan side. A false positive here costs one register entry; a false
/// negative costs a leak.
fn reads_claim_content(region: &str) -> bool {
    let low = region.to_ascii_lowercase();
    let touches = CONTENT_TABLES
        .iter()
        .any(|t| low.contains(&format!("from {t}")) || low.contains(&format!("join {t}")));
    if !touches {
        return false;
    }
    low.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| CONTENT_COLUMNS.contains(&tok))
}

fn measure_inline_claim_content_reads() -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for (name, src) in route_files() {
        let mut n = 0usize;
        for at in sqlx_call_offsets(&src) {
            if reads_claim_content(&resolved_region(&src, at)) {
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
    let mut want = expected(COMPENSATED_INLINE_READS);
    want.extend(expected(UNCOMPENSATED_INLINE_READS));
    assert_eq!(
        actual,
        want,
        "\n\nPR-07 acceptance #1 ratchet failed.\n{}\n\n\
         A `sqlx::query*` call in crates/epigraph-api/src/routes/ selects \
         `tier_a` content (claims / evidence / challenges / claim_versions, \
         projecting content / explanation / properties / embedding). Route \
         handlers cannot carry a `/* {{VISIBILITY:...}} */` marker, so such a \
         read is unfilterable by a `Viewer` no matter how many extractors the \
         handler declares — `frame_claims_sorted` held a viewer and leaked \
         anyway, which is why this lint checks WHERE the SQL lives rather than \
         whether the word `ViewerExtractor` appears.\n\n\
         Fix: move the statement into crates/epigraph-db/src/repos/, add the \
         marker, and call `viewer.splice`. If you have genuinely removed a \
         site, LOWER the number in COMPENSATED_INLINE_READS or \
         UNCOMPENSATED_INLINE_READS. Never raise it.\n",
        diff_report(&actual, &want)
    );
}

/// The two registers must not both claim the same file.
///
/// A file cannot be simultaneously compensated and uncompensated, and a stray
/// duplicate would silently drop one of the two counts when the maps are
/// merged — turning the ratchet's exact-count assertion into an under-count.
#[test]
fn the_two_registers_are_disjoint() {
    for (f, _) in COMPENSATED_INLINE_READS {
        assert!(
            !UNCOMPENSATED_INLINE_READS.iter().any(|(g, _)| g == f),
            "{f} appears in both registers"
        );
    }
}

/// **The self-test for the blind spot that made the first revision of this file
/// unable to catch the defect it was written for.**
///
/// `frame_claims_sorted`'s shape was `let query = format!(…); … sqlx::query_as(&query)`:
/// the SQL literal ABOVE the call, invisible to a forward-only scan. Without
/// this test nothing stops that hole reopening — a future refactor of
/// [`resolved_region`] would go green against the current tree and quietly stop
/// measuring the very shape the module doc claims it catches.
///
/// The fixture is a synthetic source string rather than a real file, so the
/// test cannot be made to pass by editing the routes directory.
#[test]
fn a_format_built_statement_is_counted() {
    let forward = r#"
        let rows = sqlx::query_as("SELECT c.content FROM claims c WHERE c.id = $1")
            .bind(id).fetch_all(pool).await?;
    "#;
    assert_eq!(
        sqlx_call_offsets(forward).len(),
        1,
        "the inline form must still be recognised as a call"
    );
    assert!(
        reads_claim_content(&resolved_region(forward, sqlx_call_offsets(forward)[0])),
        "an inline literal must still be counted"
    );

    let deferred = r#"
        let query = format!("SELECT c.content FROM claims c ORDER BY {sort}");
        let rows = sqlx::query_as(&query).bind(id).fetch_all(pool).await?;
    "#;
    let offsets = sqlx_call_offsets(deferred);
    assert_eq!(offsets.len(), 1, "the deferred form is still one call");
    assert!(
        reads_claim_content(&resolved_region(deferred, offsets[0])),
        "a `let sql = format!(..); sqlx::query_as(&sql)` statement MUST be \
         counted — this is the `frame_claims_sorted` shape, and a forward-only \
         scan scores it clean. If this assertion is failing, the lint has \
         regressed to measuring less than its own doc comment claims."
    );

    // …and the argument region must not bleed into the NEXT statement: this is
    // the over-counting half, which charged `conventions.rs` for a
    // `SELECT labels FROM claims` because a `content:` response field followed.
    let bleed = r#"
        let labels = sqlx::query_scalar("SELECT labels FROM claims WHERE id = $1")
            .bind(id).fetch_one(pool).await?;
        Ok(Json(Response { content: claim.content }))
    "#;
    let offsets = sqlx_call_offsets(bleed);
    assert_eq!(offsets.len(), 1);
    assert!(
        !reads_claim_content(&resolved_region(bleed, offsets[0])),
        "a non-content statement must not be charged because a later line \
         mentions `content`"
    );

    // A raw string carrying unbalanced-looking SQL parens must not derail the
    // region scan.
    let raw =
        "let rows = sqlx::query_as(r#\"SELECT c.content FROM claims c WHERE (a > 1)\"#).bind(x);";
    let offsets = sqlx_call_offsets(raw);
    assert_eq!(offsets.len(), 1);
    assert!(reads_claim_content(&resolved_region(raw, offsets[0])));
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
