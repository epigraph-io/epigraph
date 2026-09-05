//! Source lint: inline SQL under `crates/epigraph-mcp/src/tools/` is a ratchet,
//! not a free-for-all.
//!
//! # What CLAUDE.md asks for, and what PR-09 actually delivered
//!
//! CLAUDE.md: *"All SQL stays in `crates/epigraph-db/src/repos/`. HTTP routes
//! and MCP tools both call the repo layer; do not duplicate SQL between them."*
//! `docs/tenancy/FINAL-PLAN.md`'s PR-09 acceptance line says this file
//! *"passes at zero"*.
//!
//! **It does not pass at zero, and saying so is the point of this file.**
//! PR-09 moved the reads that were leaking — `system_stats`'s eight corpus
//! counts, `embedding_neighborhood_density`'s two scans,
//! `suggest_alternative_sets`' three-way claim join, `find_cross_source_matches`'
//! edge scan, `list_events` — into `crates/epigraph-db/src/repos/`. What it
//! did not move is `recall.rs::fetch_batched_context` (ten `sqlx::query!`
//! macros, six anonymous row shapes and the `BatchedContext` type, one caller)
//! and a handful of one-line read-backs. Those were *filtered* in place instead:
//! the security property is the predicate, not the file path.
//!
//! An "acceptance criterion" that is asserted-but-false is worse than one that
//! is recorded-and-true, so this is written the way the tree already writes
//! this kind of control — as an **exact-set ratchet**, in the style of
//! `epigraph-db/tests/visibility_lint.rs::the_exemption_set_is_exactly_what_was_reviewed`
//! and `epigraph-api/tests/viewer_route_table_lint.rs::fail_open_scope_check_sites_do_not_increase`.
//! A new inline query anywhere under `tools/` fails the build; the residue is
//! named, counted, and cannot quietly grow.
//!
//! # The two scope decisions, stated rather than assumed
//!
//! **1. Scan root.** Only `crates/epigraph-mcp/src/tools/`. This mirrors
//! `epigraph-api/tests/no_bypass_in_handlers.rs::scan_roots`, which walks the
//! same directory. It is a *choice*: `claim_helper.rs`, `embed.rs` and
//! `server.rs` sit outside it. Measured at the time of writing, each of those
//! three contains exactly one `sqlx::` token and it is `use sqlx::PgPool;` —
//! zero queries — so the narrower root costs nothing today.
//! [`the_scan_root_choice_is_still_free`] fails if that stops being true,
//! rather than leaving the choice to age silently.
//!
//! **2. `#[cfg(test)]`.** Test modules are **counted**, not exempt. Same rule
//! as `visibility_lint.rs::repo_files`, which reads each file entire. Exempting
//! them would have let `workflow_ingest.rs` (10 sites, all in its test module)
//! and `novelty_gate.rs` (2, likewise) report zero, and "passes at zero" would
//! then mean nothing. The prod/test split is recorded per file in
//! [`EXPECTED_INLINE_SQL`] and asserted separately by
//! [`no_inline_sql_migrates_from_a_test_module_into_production`], so SQL cannot
//! cross from a test module into a production path without a visible diff.
//!
//! # Why comment lines are stripped
//!
//! `recall.rs`'s module doc explains *why* its macros cannot be spliced, and
//! says `sqlx::query!` twice while doing so. Counting prose would make the
//! ratchet punish documentation.

use std::path::{Path, PathBuf};

/// Every inline-SQL site under `crates/epigraph-mcp/src/tools/`, as
/// `(file, production_sites, cfg_test_sites)`, measured on **2026-09-03** after
/// PR-09's conversions.
///
/// Four groups, all reviewed:
///
/// * **`recall.rs` (12, all production).** `fetch_batched_context`'s ten
///   statements plus `paragraph_3072_population` and `compute_corpus_scope`.
///   All twelve are viewer-filtered as of PR-09 — they carry the static
///   three-bind `visibility = 'public' OR owner_group_id = ANY(...)` form,
///   because `sqlx::query!` needs a compile-time literal of fixed arity and so
///   cannot take a `Viewer::splice` result. Relocation to the repo layer is
///   outstanding; the leak is not.
/// * **`workflow_hierarchical.rs` (3 production).** One read, one `UPDATE
///   workflows`, one `edges ⨝ claims` read on the
///   `report_hierarchical_outcome` write path. Write paths are PR-16's, so
///   PR-09 left them alone rather than half-converting a write. (PR-16
///   correction: the parenthetical here used to read "`viewer.writable_bind()`,
///   which does not exist yet". It has existed since PR-04 and is consumed by
///   `pool.rs::apply_session_gucs`; what is missing is the SQL half — the
///   write-side predicate and `WITH CHECK` — and PR-16a does not add it.)
/// * **One-line read-backs (`ds.rs`, `ds_auto.rs`, `link_epistemic.rs`,
///   `workflows.rs` — 5 production).** Each re-reads a scalar of a row the
///   caller just wrote, or probes existence by id. Not content reads.
/// * **Test modules (`workflow_ingest.rs` 10, `novelty_gate.rs` 2,
///   `workflow_hierarchical.rs` 3).** Fixture assertions inside
///   `#[cfg(test)] mod tests`. Counted so the total means something.
const EXPECTED_INLINE_SQL: &[(&str, usize, usize)] = &[
    ("ds.rs", 1, 0),
    ("ds_auto.rs", 1, 0),
    ("link_epistemic.rs", 1, 0),
    ("novelty_gate.rs", 0, 2),
    ("recall.rs", 12, 0),
    ("workflow_hierarchical.rs", 3, 3),
    ("workflow_ingest.rs", 0, 10),
    ("workflows.rs", 2, 0),
];

/// The token that marks an inline query. `sqlx::query`, `sqlx::query_as`,
/// `sqlx::query_scalar` and their `!` macro forms all start with it.
const QUERY_TOKEN: &str = "sqlx::query";

fn tools_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools")
}

fn rs_files(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 file name")
            .to_string();
        out.push((name, std::fs::read_to_string(&path).expect("read file")));
    }
    out.sort();
    out
}

/// `(production_sites, cfg_test_sites)` for one file.
///
/// The `#[cfg(test)]` boundary is taken as the FIRST such attribute in the
/// file. That is exact rather than heuristic for this directory: in both
/// `workflow_ingest.rs` and `workflow_hierarchical.rs` the `#[cfg(test)] mod
/// tests` block is the last item in the file and no production `fn` follows it.
/// [`the_cfg_test_boundary_is_the_last_item_in_every_file_that_has_one`] pins
/// that, so the split cannot silently become wrong.
fn count_sites(src: &str) -> (usize, usize) {
    let cut = src.find("#[cfg(test)]").unwrap_or(src.len());
    let (mut prod, mut test) = (0usize, 0usize);
    let mut offset = 0usize;
    for line in src.split('\n') {
        if !line.trim_start().starts_with("//") {
            let mut from = 0usize;
            while let Some(at) = line[from..].find(QUERY_TOKEN) {
                let abs = offset + from + at;
                if abs < cut {
                    prod += 1;
                } else {
                    test += 1;
                }
                from += at + QUERY_TOKEN.len();
            }
        }
        offset += line.len() + 1;
    }
    (prod, test)
}

/// The ratchet. A new inline query under `tools/` fails here.
#[test]
fn inline_sql_in_tools_is_exactly_the_reviewed_residue() {
    let mut actual: Vec<(String, usize, usize)> = rs_files(&tools_dir())
        .into_iter()
        .filter_map(|(name, src)| {
            let (prod, test) = count_sites(&src);
            (prod + test > 0).then_some((name, prod, test))
        })
        .collect();
    actual.sort();

    let mut want: Vec<(String, usize, usize)> = EXPECTED_INLINE_SQL
        .iter()
        .map(|(f, p, t)| ((*f).to_string(), *p, *t))
        .collect();
    want.sort();

    assert_eq!(
        actual, want,
        "\n\nInline SQL under crates/epigraph-mcp/src/tools/ changed.\n\
         Entries are (file, production_sites, cfg_test_sites).\n\n\
         If you ADDED a query: don't. Put it in crates/epigraph-db/src/repos/ \
         and call it from here (CLAUDE.md), where visibility_lint.rs can see \
         whether it spends its Viewer.\n\n\
         If you REMOVED one by moving it to the repo layer: thank you — update \
         EXPECTED_INLINE_SQL in the same commit, and check whether the moved \
         function now needs a VISIBILITY-EXEMPT entry in \
         epigraph-db/tests/visibility_lint.rs.\n"
    );
}

/// SQL must not cross from a `#[cfg(test)]` module into a production path
/// without a visible diff.
///
/// Separate from the ratchet above because the totals could stay constant while
/// a test-module query migrated into production — which is exactly the change
/// that turns an inert fixture assertion into a live unfiltered read.
#[test]
fn no_inline_sql_migrates_from_a_test_module_into_production() {
    for (name, src) in rs_files(&tools_dir()) {
        let (prod, _) = count_sites(&src);
        let expected_prod = EXPECTED_INLINE_SQL
            .iter()
            .find(|(f, _, _)| *f == name)
            .map_or(0, |(_, p, _)| *p);
        assert_eq!(
            prod, expected_prod,
            "production-path inline SQL count changed in tools/{name}: \
             expected {expected_prod}, found {prod}"
        );
    }
}

/// The `#[cfg(test)]` boundary used by [`count_sites`] is a real boundary.
///
/// [`count_sites`] treats the first `#[cfg(test)]` as the start of test-only
/// code. That is only sound if no production item follows it. Rather than
/// asserting the general property (which needs a parser), this asserts the
/// specific one that matters: in every `tools/` file containing both a
/// `#[cfg(test)]` and an inline query after it, the attribute introduces a
/// `mod tests` and the file ends with that module.
#[test]
fn the_cfg_test_boundary_is_the_last_item_in_every_file_that_has_one() {
    for (name, src) in rs_files(&tools_dir()) {
        let Some(cut) = src.find("#[cfg(test)]") else {
            continue;
        };
        let tail = &src[cut..];
        assert!(
            tail.starts_with("#[cfg(test)]\nmod tests {"),
            "tools/{name}: the first #[cfg(test)] does not introduce `mod tests`; \
             count_sites' production/test split would be wrong"
        );
        assert_eq!(
            tail.matches("\n#[cfg(test)]").count(),
            0,
            "tools/{name}: a second #[cfg(test)] follows the first; count_sites \
             assumes exactly one boundary"
        );
    }
}

/// The scan-root choice (`tools/` only) is still free.
///
/// `claim_helper.rs`, `embed.rs` and `server.rs` are `epigraph-mcp` sources
/// outside the scanned directory. Scoping the lint to `tools/` costs nothing
/// only while they hold no queries. When one of them grows a query, this fails
/// and the choice gets re-made deliberately instead of expiring in silence.
#[test]
fn the_scan_root_choice_is_still_free() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for (name, src) in rs_files(&src_dir) {
        let (prod, test) = count_sites(&src);
        if prod + test > 0 {
            offenders.push(format!("  src/{name}: {prod} production, {test} test"));
        }
    }
    assert!(
        offenders.is_empty(),
        "\n\ncrates/epigraph-mcp/src/*.rs now contains inline SQL, but this lint \
         only scans src/tools/:\n{}\n\nEither move the query to \
         crates/epigraph-db/src/repos/, or widen tools_dir() and extend \
         EXPECTED_INLINE_SQL to cover the new root.\n",
        offenders.join("\n")
    );
}

/// The measurement's own blind spots, pinned against synthetic input.
///
/// PR-07's lint shipped twice because its first version's counting was wrong in
/// ways no production file happened to exercise. Same failure mode is available
/// here, so the counter is tested directly.
#[test]
fn count_sites_measures_what_it_claims_to() {
    let synthetic = "\
fn a() { sqlx::query(\"SELECT 1\"); }
// sqlx::query in a line comment must not count
/// sqlx::query! in a doc comment must not count
fn b() { let _ = sqlx::query_as::<_, i64>(\"x\"); sqlx::query_scalar(\"y\"); }
#[cfg(test)]
mod tests {
    fn t() { sqlx::query(\"SELECT 2\"); }
}
";
    assert_eq!(
        count_sites(synthetic),
        (3, 1),
        "expected 3 production sites (one in `a`, two on one line in `b`) and \
         1 test site; comment lines must be ignored and two hits on a single \
         line must both count"
    );
}
