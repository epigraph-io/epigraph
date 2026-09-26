//! Source lint: every content-reading MCP tool acquires a `Viewer`.
//!
//! # Why the plan's version of this test cannot work
//!
//! `docs/tenancy/FINAL-PLAN.md` §6.4 sketches this as a scan over the tool
//! *modules*, asserting each `crates/epigraph-mcp/src/tools/<x>.rs` contains
//! `mcp_viewer(`. Measured on this tree, **the only file under `src/tools/`
//! that calls `request_viewer` is `viewer.rs`, which defines it.** Viewer
//! acquisition happens in the `#[tool_router]` bodies in `src/server.rs`, on
//! the other side of the dispatch boundary, and the tool module receives an
//! already-resolved `&Viewer` as a parameter. The sketched test fails for
//! every tool before PR-09 and every tool after, so it measures nothing. The
//! `TOOL_MODULE_MAP` it calls for is unnecessary.
//!
//! (An earlier revision of this paragraph said "all 86 tools", twice. The tree
//! has 83 `#[tool(` attributes and the number is not what the argument turns
//! on, so it is stated as a rule rather than re-pinned to a count that will
//! drift again. [`the_three_categories_partition_every_tool`] is where the
//! live count is actually asserted.)
//!
//! What actually carries the property is the dispatch body, so that is what
//! this file parses: walk `#[tool(` → `async fn <name>` → the next `#[tool(`,
//! and classify the span by whether it CALLS `request_viewer(` or
//! `maintenance_viewer(` — over comment-stripped source, so prose naming either
//! helper is not an acquisition. See [`server_src`] for why both narrowings are
//! there.
//!
//! # The ratchet
//!
//! [`EXPECTED_TOOLS_WITHOUT_A_VIEWER`] is an exact set, not a count. Adding a
//! tool that reads content without acquiring a viewer fails the build; removing
//! a name from the set is a visible diff that a reviewer can check against the
//! tool's actual body.
//!
//! # What this CANNOT tell you
//!
//! That the acquired viewer is *spent*. A dispatch body may call
//! `request_viewer`, pass the result to a tool function, and have that function
//! ignore it — which is precisely what `tools/batch.rs::system_stats` did
//! before PR-09 (it held a `&Viewer`, used it for one call, and issued eight
//! raw `SELECT COUNT(*)` statements beside it). The repo-layer half of that
//! property is `epigraph-db/tests/visibility_lint.rs`; the inline-SQL half is
//! `no_inline_sql_in_tools.rs`. This file is only the acquisition half, and
//! saying so is part of not over-claiming it.

mod lint_text;

use lint_text::strip_comments;
use std::path::{Path, PathBuf};

/// Tools whose dispatch body acquires **no** viewer, as measured on
/// **2026-09-03** after PR-09, minus the two PR-11 converted.
///
/// Three groups:
///
/// * **Write / decide paths (15).** The count went **17 → 15**, not 18 → 15:
///   PR-11 removed two names, and the "(18)" this doc previously carried was a
///   pre-existing miscount — the base array held 17 write-group entries. The
///   array length is what the test asserts, so nothing was broken by it; it is
///   corrected here rather than silently absorbed. Converting one needs write
///   authority —
///   member-with-write-role, not merely member-who-can-read. That mechanism
///   turned out to **already exist**: `Viewer::resolve` has split `writable`
///   out by role since PR-03 and `Viewer::writable_bind()` has been public
///   since PR-04, so this const's previous claim that it "does not exist yet"
///   was false when it was written. What PR-16 still owns is the *SQL* half —
///   the write-side predicate and `WITH CHECK` — and `progress.json`'s
///   `Q7_failopen_scope_site_ownership` assigns the 35 `check_scopes` route
///   sites there. PR-11 built the Rust half (`crates/epigraph-authz`) and spent
///   it on the two declassification tools, which is why `assign_ownership` and
///   `update_partition` are no longer in this list.
/// * **Pure-CPU, no DB (2).** `stage_claims` validates strings and takes
///   `_server`; `list_mcp_tools` reads the compiled-in manifest. A viewer here
///   would be a parameter with nothing to filter.
/// * **Reads PR-09 did not convert (2), each with a named owner.** This was 3
///   until PR-14 deleted `get_ownership`.
///   - `get_workflow_executions` — `behavioral_executions` and `workflows` are
///     both outside migration 062's `tier_a` array, so there is no
///     `owner_group_id` anywhere on the path and no claim to derive one from.
///     A real fix needs a tenancy column, i.e. a migration, and PR-09 is
///     code-only. Backlog.
///   - `get_ownership` — **RESOLVED BY DELETION IN PR-14, entry removed.** It
///     was carried here as an explicitly "accepted residual": it read the
///     legacy `ownership` table with no `Viewer`, and PR-09/PR-11 declined to
///     filter a surface already scheduled for removal. The residual it named
///     was real — that read, its HTTP twin, and HTTP `owned_nodes` disclosed
///     `owner_id`, which is the field the write gate's own decision turns on.
///     PR-14 deleted all three surfaces together with the write gate they fed,
///     so the finding `F-PR11-ownership-reads-are-an-owner-oracle` closes by
///     removal rather than by filtering — the resolution its own
///     `suggested_fix` named. Recorded in `docs/tenancy/progress.json` under
///     `closed_findings`.
///   - `theme_cluster` — the corpus-wide `FROM claims` is in
///     `epigraph-engine/src/theme_kmeans.rs::run_theme_kmeans`, not in the MCP
///     tool, and that function has a second caller: the HTTP twin
///     `epigraph-api/src/routes/crud.rs::build_themes_from_corpus`. Threading a
///     `Viewer` through it changes an `epigraph-engine` public signature and
///     must land with both callers, or MCP hardens while HTTP keeps clustering
///     corpus-wide — a parity violation of exactly the kind §8.4 #16 exists to
///     catch. Deferred as a unit, deliberately. Note this leaves plan §2.4's
///     `claim_themes` `tenancy_exempt` residual **without its stated control**;
///     that is the single largest thing PR-09 does not deliver.
const EXPECTED_TOOLS_WITHOUT_A_VIEWER: &[&str] = &[
    // Batch H-b removed `challenge_claim`, `create_perspective`,
    // `ingest_document_spine` and `retire_match_candidate`: each now authors or
    // records its acting agent as the request's principal
    // (`EpiGraphMcpFull::write_identity`), which is read off the viewer. It
    // also removed `add_step` and `delete_step`, which now check the caller's
    // authority over the workflow (H3).
    // write / decide — PR-16 owns the SQL write-side predicate for these.
    // `assign_ownership` and `update_partition` left this list in PR-11: they
    // now acquire a viewer, spend its `writable_groups()`/principal on
    // `epigraph_authz::GroupPolicyGate`, and refuse a caller who is neither the
    // node's owner nor a writer in its owning group.
    // The batch H-b review removed `publish_event` (over HTTP its actor must be
    // the request's principal, read off the viewer) and
    // `set_source_reliability` (read, owned and written as that principal).
    "create_frame",
    "report_hierarchical_outcome",
    "structure_source",
    // pure-CPU, no DB
    "list_mcp_tools",
    "stage_claims",
    // reads not converted by PR-09 — see the module doc for the owner of each.
    // `get_ownership` was here until PR-14 deleted the tool.
    "get_workflow_executions",
    "theme_cluster",
];

/// Tools that deliberately bypass tenancy with a `MaintenanceLease`.
///
/// Each has an enumerated `SystemReason` and is already covered by
/// `epigraph-db/tests/viewer_ratchet.rs`. Listed here so the three-way
/// partition below is total and a tool cannot move between categories
/// unnoticed.
const EXPECTED_MAINTENANCE_TOOLS: &[&str] = &[
    "backfill_embeddings",
    "recompute_beliefs",
    "sweep_semantic_duplicates",
];

fn server_rs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs")
}

/// `src/server.rs` as the scanners must see it: **comments removed**.
///
/// Every classification in this file is a substring search over a dispatch
/// body, so unstripped it cannot tell an acquisition from a comment mentioning
/// one. That defect has already been paid for twice over, in opposite
/// directions:
///
/// * **Loud** — `viewer_acquisition_lives_in_server_rs_not_in_the_tool_modules`
///   went red on a doc paragraph in `tools/perspectives.rs` that explained which
///   principal the stdio transport resolves. The fix was to reword prose. A lint
///   a comment can break trains contributors not to name what they document.
/// * **Silent, and the one that matters** — [`tools`] classifies a dispatch span
///   as having acquired a viewer on the same kind of substring. A tool whose
///   body merely MENTIONED the helper would be counted as having acquired one,
///   never reach [`EXPECTED_TOOLS_WITHOUT_A_VIEWER`], and leave
///   `every_content_reading_tool_derives_a_viewer` green. A coverage control
///   that can be satisfied by prose is the "looks like a control, measures
///   nothing" shape this whole file exists to avoid.
///
/// Only the first was reported. Both are closed here, because they are one
/// mechanism in one function and fixing the reported half alone would have left
/// the unreported half in the same file.
///
/// **Stripping moved no number.** Measured before the change: 83 `#[tool(`
/// attributes, 61 `Request` / 3 `Maintenance` / 19 `None`, and the tool-module
/// mention set `["viewer.rs"]` — all byte-identical stripped and unstripped. The
/// hazard is closed without re-baselining anything.
fn server_src() -> String {
    strip_comments(&std::fs::read_to_string(server_rs()).expect("read server.rs"))
}

#[derive(Debug, PartialEq, Eq)]
enum Acquisition {
    Request,
    Maintenance,
    None,
}

/// `(tool_name, acquisition)` for every `#[tool(` in `src/server.rs`.
///
/// A tool's span runs from its `#[tool(` attribute to the next one (or EOF for
/// the last). That is exact for this file because `#[tool(` appears nowhere
/// else in it — [`the_span_delimiter_is_unambiguous`] checks that rather than
/// assuming it.
///
/// **`src` must be comment-stripped** — pass [`server_src`], not a raw read.
/// The acquisition test below is a substring search, and on raw source a
/// dispatch body that mentions the helper in prose while acquiring nothing would
/// be classified as having acquired one.
///
/// The needles require the CALL position (`request_viewer(`), not the bare
/// identifier, which narrows a PROSE mention of the helper to one that also
/// writes the open parenthesis.
///
/// **It does not rule out a string literal, and an earlier revision of this
/// paragraph claimed it did.** `strip_comments` preserves string contents by
/// design, so a `tracing` format string, an error message or a
/// `#[tool(description = ...)]` blob containing the call text WOULD classify the
/// span as [`Acquisition::Request`] — the silent direction, because such a tool
/// never reaches `EXPECTED_TOOLS_WITHOUT_A_VIEWER` and
/// [`every_content_reading_tool_derives_a_viewer`] stays green. Measured on the
/// tree as it stands: every `request_viewer` occurrence in `server.rs` is a real
/// call, and both non-call `maintenance_viewer` hits are doc comments, which
/// stripping removes. So the population is clean today and the residual is
/// stated rather than closed; blanking string contents as well as comments is
/// the fix, and it would move this crate's registers, so it is not folded in
/// beside a doc correction.
fn tools(src: &str) -> Vec<(String, Acquisition)> {
    let mut starts: Vec<usize> = src.match_indices("#[tool(").map(|(i, _)| i).collect();
    starts.push(src.len());

    let mut out = Vec::new();
    for w in starts.windows(2) {
        let body = &src[w[0]..w[1]];
        let Some(at) = body.find("async fn ") else {
            continue;
        };
        let rest = &body[at + "async fn ".len()..];
        let end = rest
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let name = rest[..end].to_string();

        let acq = if body.contains("request_viewer(") {
            Acquisition::Request
        } else if body.contains("maintenance_viewer(") {
            Acquisition::Maintenance
        } else {
            Acquisition::None
        };
        out.push((name, acq));
    }
    out
}

#[test]
fn every_content_reading_tool_derives_a_viewer() {
    let src = server_src();
    let all = tools(&src);

    let mut without: Vec<String> = all
        .iter()
        .filter(|(_, a)| *a == Acquisition::None)
        .map(|(n, _)| n.clone())
        .collect();
    without.sort();

    let mut want: Vec<String> = EXPECTED_TOOLS_WITHOUT_A_VIEWER
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    want.sort();

    assert_eq!(
        without, want,
        "\n\nThe set of MCP tools that acquire NO viewer changed.\n\n\
         If you added a tool: acquire one in its dispatch body —\n\
         `let auth = extensions.get::<epigraph_auth::AuthContext>();`\n\
         `let viewer = &crate::tools::viewer::request_viewer(self, auth).await?;`\n\
         — and pass it to the tool function. A tool that genuinely reads nothing \
         from the database belongs in EXPECTED_TOOLS_WITHOUT_A_VIEWER with a \
         reason in the const's doc comment.\n\n\
         If you converted one: remove its name here in the same commit.\n"
    );
}

#[test]
fn the_maintenance_bypass_set_is_exactly_what_was_reviewed() {
    let src = server_src();
    let mut maint: Vec<String> = tools(&src)
        .iter()
        .filter(|(_, a)| *a == Acquisition::Maintenance)
        .map(|(n, _)| n.clone())
        .collect();
    maint.sort();

    let mut want: Vec<String> = EXPECTED_MAINTENANCE_TOOLS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    want.sort();

    assert_eq!(
        maint, want,
        "\n\nThe set of tools minting a maintenance (bypass) viewer changed. \
         A bypass reads every tenant's rows; each one needs an enumerated \
         SystemReason and a line in epigraph-db/tests/viewer_ratchet.rs.\n"
    );
}

/// The partition is total: every tool falls in exactly one of the three
/// categories, and the counts add up to the number of `#[tool(` attributes.
///
/// Without this, a parsing bug that silently dropped tools would make both
/// assertions above pass on a shrinking population.
#[test]
fn the_three_categories_partition_every_tool() {
    let src = server_src();
    let all = tools(&src);
    let attrs = src.matches("#[tool(").count();

    assert_eq!(
        all.len(),
        attrs,
        "every #[tool( attribute must resolve to an `async fn`; {} of {attrs} did not",
        attrs - all.len()
    );

    let with = all
        .iter()
        .filter(|(_, a)| *a == Acquisition::Request)
        .count();
    let maint = all
        .iter()
        .filter(|(_, a)| *a == Acquisition::Maintenance)
        .count();
    let without = all.iter().filter(|(_, a)| *a == Acquisition::None).count();

    assert_eq!(with + maint + without, attrs);
    assert_eq!(maint, EXPECTED_MAINTENANCE_TOOLS.len());
    assert_eq!(without, EXPECTED_TOOLS_WITHOUT_A_VIEWER.len());
}

/// The span delimiter is unambiguous.
///
/// [`tools`] slices `server.rs` on `#[tool(`. If that token appeared inside a
/// tool description string — every one of these tools carries a long prose
/// `description = "..."` — a span would end early and the classification would
/// be wrong for the tool before it. This checks the token count against the
/// count of `#[tool(` occurrences that begin a line (modulo indentation), which
/// is what an attribute always does and a string literal never does.
#[test]
fn the_span_delimiter_is_unambiguous() {
    // RAW, deliberately. This is a property of the file as written, and reading
    // it through `server_src` would let comment stripping conceal exactly the
    // ambiguity being checked.
    let src = std::fs::read_to_string(server_rs()).expect("read server.rs");
    let total = src.matches("#[tool(").count();
    let line_initial = src
        .split('\n')
        .filter(|l| l.trim_start().starts_with("#[tool("))
        .count();
    assert_eq!(
        total, line_initial,
        "`#[tool(` occurs {total} times but only {line_initial} of those start a \
         line — one is inside a string or comment, and the span parser would \
         mis-slice there"
    );

    // The delimiter must also survive stripping unchanged. If the two counts
    // ever diverge, a `#[tool(` lives in a comment: the scanners below would
    // slice one set of spans and this test would have certified another, so the
    // two halves of the file would be reasoning about different populations.
    assert_eq!(
        total,
        server_src().matches("#[tool(").count(),
        "the `#[tool(` count changes when comments are stripped, so at least \
         one delimiter is inside a comment. Span slicing and this delimiter \
         check would then disagree about how many tools exist."
    );
}

/// The plan's own version of this test is unsatisfiable, and this records why.
///
/// Plan §6.4 asserts each tool module contains `mcp_viewer(`. If someone
/// re-reads the plan and re-derives that test, this failure explains the
/// situation instead of letting them "fix" the source to match.
///
/// # Two defects fixed here, neither of which changed the result
///
/// It scanned RAW source for the bare identifier, so a doc paragraph naming the
/// helper failed the test — which is what happened during PR-11's land phase,
/// and the remedy was to reword prose rather than to change any code. It now
/// scans stripped source for the CALL position.
///
/// It also compared an unsorted `Vec` built from `read_dir` order against a
/// literal. With one match that could not be observed; with two it would compare
/// order-dependently against directory order and fail or pass by accident. The
/// list is sorted before the comparison.
#[test]
fn viewer_acquisition_lives_in_server_rs_not_in_the_tool_modules() {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools");
    let mut mentioning = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(&tools_dir).expect("read tools dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        scanned += 1;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();
        if strip_comments(&std::fs::read_to_string(&path).expect("read"))
            .contains("request_viewer(")
        {
            mentioning.push(name);
        }
    }
    mentioning.sort();

    // A scan that found nothing is a broken scanner, not a clean tree — and
    // `viewer.rs` itself is the witness that the needle can match at all.
    assert!(
        scanned > 10,
        "scanned only {scanned} files under src/tools/; the scan root is wrong \
         and this lint would assert nothing"
    );

    assert_eq!(
        mentioning,
        vec!["viewer.rs".to_string()],
        "plan §6.4 sketches this coverage test as a scan of the tool modules for \
         a `mcp_viewer(` call. Acquisition happens in server.rs's #[tool_router] \
         bodies; the only tools/ file that CALLS request_viewer is the one that \
         defines it. If that changes, revisit every_content_reading_tool_derives_a_viewer."
    );
}
