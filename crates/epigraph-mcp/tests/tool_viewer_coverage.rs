//! Source lint: every content-reading MCP tool acquires a `Viewer`.
//!
//! # Why the plan's version of this test cannot work
//!
//! `docs/tenancy/FINAL-PLAN.md` §6.4 sketches this as a scan over the tool
//! *modules*, asserting each `crates/epigraph-mcp/src/tools/<x>.rs` contains
//! `mcp_viewer(`. Measured on this tree, **the only file under `src/tools/`
//! that mentions `request_viewer` is `viewer.rs`, which defines it.** Viewer
//! acquisition happens in the `#[tool_router]` bodies in `src/server.rs`, on
//! the other side of the dispatch boundary, and the tool module receives an
//! already-resolved `&Viewer` as a parameter. The sketched test fails for all
//! 86 tools before PR-09 and all 86 after, so it measures nothing. The
//! `TOOL_MODULE_MAP` it calls for is unnecessary.
//!
//! What actually carries the property is the dispatch body, so that is what
//! this file parses: walk `#[tool(` → `async fn <name>` → the next `#[tool(`,
//! and classify the span by which of `request_viewer` / `maintenance_viewer` it
//! contains.
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

use std::path::{Path, PathBuf};

/// Tools whose dispatch body acquires **no** viewer, as measured on
/// **2026-09-03** after PR-09.
///
/// Three groups:
///
/// * **Write / decide paths (18).** Converting one needs
///   `viewer.writable_bind()` — member-with-write-role, not merely
///   member-who-can-read — which is **PR-16**'s mechanism and does not exist
///   yet. `progress.json`'s `Q7_failopen_scope_site_ownership` assigns them.
///   Acquiring a read viewer here would be theatre.
/// * **Pure-CPU, no DB (2).** `stage_claims` validates strings and takes
///   `_server`; `list_mcp_tools` reads the compiled-in manifest. A viewer here
///   would be a parameter with nothing to filter.
/// * **Reads PR-09 did not convert (3), each with a named owner.**
///   - `get_workflow_executions` — `behavioral_executions` and `workflows` are
///     both outside migration 062's `tier_a` array, so there is no
///     `owner_group_id` anywhere on the path and no claim to derive one from.
///     A real fix needs a tenancy column, i.e. a migration, and PR-09 is
///     code-only. Backlog.
///   - `get_ownership` — reads the legacy `ownership` table, which **PR-14
///     deletes** along with `routes/ownership.rs` and MCP `assign_ownership` /
///     `update_partition`. Filtering a surface that is being removed two PRs
///     from now is churn.
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
    // write / decide — PR-16 (and PR-11 for the authz gate)
    "add_step",
    "assign_ownership",
    "challenge_claim",
    "create_frame",
    "create_perspective",
    "delete_edge",
    "delete_step",
    "ingest_document_spine",
    "patch_claim",
    "patch_edge",
    "publish_event",
    "report_hierarchical_outcome",
    "retire_match_candidate",
    "set_source_reliability",
    "structure_source",
    "update_labels",
    "update_partition",
    // pure-CPU, no DB
    "list_mcp_tools",
    "stage_claims",
    // reads not converted by PR-09 — see the module doc for the owner of each
    "get_ownership",
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

        let acq = if body.contains("request_viewer") {
            Acquisition::Request
        } else if body.contains("maintenance_viewer") {
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
    let src = std::fs::read_to_string(server_rs()).expect("read server.rs");
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
    let src = std::fs::read_to_string(server_rs()).expect("read server.rs");
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
    let src = std::fs::read_to_string(server_rs()).expect("read server.rs");
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
}

/// The plan's own version of this test is unsatisfiable, and this records why.
///
/// Plan §6.4 asserts each tool module contains `mcp_viewer(`. If someone
/// re-reads the plan and re-derives that test, this failure explains the
/// situation instead of letting them "fix" the source to match.
#[test]
fn viewer_acquisition_lives_in_server_rs_not_in_the_tool_modules() {
    let tools_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools");
    let mut mentioning = Vec::new();
    for entry in std::fs::read_dir(&tools_dir).expect("read tools dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();
        if std::fs::read_to_string(&path)
            .expect("read")
            .contains("request_viewer")
        {
            mentioning.push(name);
        }
    }
    assert_eq!(
        mentioning,
        vec!["viewer.rs".to_string()],
        "plan §6.4 sketches this coverage test as a scan of the tool modules for \
         a `mcp_viewer(` call. Acquisition happens in server.rs's #[tool_router] \
         bodies; the only tools/ file that names request_viewer is the one that \
         defines it. If that changes, revisit every_content_reading_tool_derives_a_viewer."
    );
}
