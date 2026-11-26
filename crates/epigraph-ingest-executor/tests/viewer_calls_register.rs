//! The per-call viewer-spend register for `epigraph-ingest-executor` (backlog
//! 37e68f5b).
//!
//! `epigraph-db/tests/visibility_lint.rs` (the repo layer) and
//! `epigraph-mcp/tests/tool_viewer_is_spent.rs` (the MCP tools) each name, per
//! viewer-holding fn, every database call that does not spend the fn's viewer
//! (backlog ada8ee55). Neither followed a call into this crate: the workflow
//! ingest walk, the store-time workflow match and the frozen-plan read are
//! handed the caller's viewer by both transports, and their own bodies were
//! read by no register. This file measures every viewer-holding fn under
//! `src/` with the same scanner (`epigraph-db/tests/viewer_calls/mod.rs`) and
//! asserts its unviewed calls against an exact, reviewed register.
//!
//! The walk takes its caller as an `Option<&Viewer>` (`None` only for the
//! caller-less fixture entry point); the scanner reads an optional viewer as a
//! viewer, so the walk is in the population.

#[path = "../../epigraph-db/tests/viewer_calls/mod.rs"]
mod viewer_calls;

#[path = "../../epigraph-db/tests/lint_text/mod.rs"]
mod lint_text;

use std::path::{Path, PathBuf};

use viewer_calls::{Measured, Population, Surface};

/// The executor's database handles, for the per-call scanner: its pool,
/// connection, transaction and executor PARAMETERS (by type), and the
/// connections a body opens on them. It has no application handle.
const EXECUTOR: Surface = Surface {
    state_types: &[],
    pool_fields: &[],
    state_db_methods: &[],
    viewer_ctors: &["Viewer::resolve("],
    conn_ctors: &[],
    marker_spend: call_spends_viewer,
};

/// The per-call marker spend: the statement's live SQL (comments removed) puts
/// `visibility = 'public'` in predicate position. See
/// [`viewer_calls::predicate_spend`].
fn call_spends_viewer(region: &str) -> bool {
    let (_, live_sql) = lint_text::spend_views(region);
    viewer_calls::predicate_spend(&live_sql)
}

/// Every database call in a viewer-holding executor fn that does not spend
/// the fn's viewer, as measured and reviewed on **2026-11-26** (backlog
/// 37e68f5b).
///
/// Asserted as an exact multiset per fn. The comment above each entry is the
/// review, by reason class:
///
/// * **system** — the workflow-ingest system agent deciding its OWN write
///   authority: its `agents` row (untenanted), its own memberships read on a
///   connection stamped from its own viewer, and the one provisioning of its
///   own personal group. No caller's row is read.
/// * **stamped** — a `workflows` or `edges` read on the transaction stamped
///   from the AUTHOR (the caller on every request path: MCP
///   `begin_caller_workflow_tx`, REST `begin_caller_workflow_tx`), where
///   forced row security (migration 183 for `workflows`) carries the tenancy.
///   Each returns ids, a tenancy pair or a flag the walk decides on; what the
///   caller is TOLD about rows it did not write is read through its viewer
///   (`tenancy_of_conn`, `row_as_viewer`, `tenancy_as_viewer`).
/// * **authority** — decides whether the caller may write: hidden rows under a
///   name (`epigraph_workflow_name_has_hidden_rows`, one boolean), whether it
///   writes a group NOW (`owner::caller_writes_group_now`, the live membership
///   definer), the owner a new lineage takes (`owner::resolve_caller_owner`,
///   `default_decl_for_author`), the stamp's own view of reused claims'
///   tenancy (`tenancy_on_session_conn`), refusing before any write.
/// * **untenanted** — `agents` (an author's name-derived agent, the registry
///   of system agents, the system agent itself).
/// * **write** — the walk's inserts and updates on the author-stamped
///   transaction, whose `WITH CHECK` is the authority (the `workflows` row,
///   claims, edges, an author agent, a revived deprecation, the claims'
///   properties), each keyed on a deterministic id.
/// * **session** — the walk's savepoint.
///
/// No entry reads content into a response without the viewer: the review
/// found nothing to fix. `workflow_plan.rs::frozen_plan`, the fix sketch's
/// example, hands the viewer to its one repo read and so has no entry. Do not
/// add an entry to make the build pass.
const REVIEWED_CALLS: &[(&str, &str, &[&str])] = &[
    // system
    (
        "system_agent.rs",
        "system_agent_write_authority",
        &[
            "AgentRepository::ensure_personal_group",
            "Memberships::count_own_revoked_rows_conn",
            "Memberships::visible_personal_group_conn",
            "get_or_create_system_agent",
        ],
    ),
    // stamped: the `executes` targets of a row on the author's stamp decide
    // the idempotency gate; the caller is told only how many of them it reads
    // through its viewer (`tenancy_of_conn`).
    (
        "workflow.rs",
        "already_ingested_result",
        &["sqlx::query_scalar(SELECT).fetch_all"],
    ),
    // The ingest walk on the author-stamped transaction:
    // * write: `create_seed_derived_conn`, `create_with_id_if_absent_conn`,
    //   the three edge inserts, `insert_root`, `revive_deprecation_retired`,
    //   the `UPDATE claims` of the step properties;
    // * authority: `name_has_hidden_rows_conn`, `caller_writes_group_now`
    //   (twice), `resolve_caller_owner`, `default_decl_for_author`,
    //   `tenancy_on_session_conn`;
    // * stamped: `find_root_by_canonical` (twice), `resolve_ingest_parent`,
    //   `inherited_generation_tenancy` (ids and tenancy pairs of the lineage);
    // * untenanted: `get_by_public_key`, `registered_agent_ids`,
    //   `get_or_create_system_agent`.
    (
        "workflow.rs",
        "execute_plan",
        &[
            "AgentRepository::create_seed_derived_conn",
            "AgentRepository::get_by_public_key",
            "ClaimRepository::create_with_id_if_absent_conn",
            "ClaimRepository::default_decl_for_author",
            "ClaimRepository::tenancy_on_session_conn",
            "EdgeRepository::create_if_absent_including_retracted_signed_conn",
            "EdgeRepository::create_if_absent_including_retracted_signed_conn",
            "EdgeRepository::create_if_absent_including_retracted_signed_conn",
            "SystemAgentRepository::registered_agent_ids",
            "WorkflowRepository::find_root_by_canonical",
            "WorkflowRepository::find_root_by_canonical",
            "WorkflowRepository::insert_root",
            "WorkflowRepository::name_has_hidden_rows_conn",
            "WorkflowRepository::resolve_ingest_parent",
            "get_or_create_system_agent",
            "inherited_generation_tenancy",
            "owner::caller_writes_group_now",
            "owner::caller_writes_group_now",
            "owner::resolve_caller_owner",
            "revive_deprecation_retired",
            "sqlx::query(UPDATE).execute",
        ],
    ),
    // session
    (
        "workflow.rs",
        "execute_workflow_ingest_plan_in_group",
        &[
            "sqlx::query(RELEASE).execute",
            "sqlx::query(RELEASE).execute",
            "sqlx::query(ROLLBACK).execute",
            "sqlx::query(SAVEPOINT).execute",
        ],
    ),
    // On the caller-stamped transaction (both transports'
    // `begin_caller_workflow_tx`):
    // * stamped: `head_by_canonical` (twice) returns a head's id, which the
    //   match then reads through the viewer (`row_as_viewer`,
    //   `tenancy_as_viewer`) before it reports anything;
    // * authority: `name_has_hidden_rows_conn` (twice), `resolve_caller_owner`.
    (
        "workflow_match.rs",
        "matching_workflow_conn",
        &[
            "WorkflowRepository::head_by_canonical",
            "WorkflowRepository::head_by_canonical",
            "WorkflowRepository::name_has_hidden_rows_conn",
            "WorkflowRepository::name_has_hidden_rows_conn",
            "owner::resolve_caller_owner",
        ],
    ),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let rel = path
                .strip_prefix(root)
                .expect("a path under src")
                .to_str()
                .expect("utf-8 path")
                .replace('\\', "/");
            out.push((rel, std::fs::read_to_string(&path).expect("read src file")));
        }
    }
}

/// Every `.rs` file under `src/`, keyed by its path relative to `src/`.
fn executor_files() -> Vec<(String, String)> {
    let root = src_dir();
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    assert!(
        out.iter().any(|(f, _)| f == "workflow.rs"),
        "expected the executor's source tree, found {:?}",
        out.iter().map(|(f, _)| f).collect::<Vec<_>>()
    );
    out
}

fn measure_executor() -> (Measured, usize, usize, Population) {
    let mut out = Measured::new();
    let mut pop = Population::new();
    let (mut n_fns, mut n_calls) = (0, 0);
    for (file, src) in executor_files() {
        let (f, c) = viewer_calls::measure_source(&file, &src, &EXECUTOR, &mut out, &mut pop);
        n_fns += f;
        n_calls += c;
    }
    (out, n_fns, n_calls, pop)
}

/// In an executor fn that holds a viewer, every database call whose arguments
/// and statement do not spend that viewer is named in [`REVIEWED_CALLS`]
/// (backlog 37e68f5b).
#[test]
fn every_unviewed_database_call_in_a_viewer_executor_fn_is_reviewed() {
    let (measured, _, _, _) = measure_executor();
    let report = viewer_calls::drift(&measured, &viewer_calls::register(REVIEWED_CALLS));
    assert!(
        report.is_empty(),
        "viewer-holding executor fns' unviewed database calls drifted from \
         REVIEWED_CALLS.\nA NEW call is a statement, repo call or helper handed a \
         database handle, in a fn that holds a viewer, with neither the viewer in its \
         arguments nor a spend marker in its statement: give it the viewer, or read it \
         and register it with a reason class. A GONE call must be removed from \
         REVIEWED_CALLS.\n{report}"
    );
}

/// The population is the executor's whole viewer surface. It is small, so it
/// is asserted as an exact set: a fn that starts or stops holding a viewer is
/// a reviewed diff here.
#[test]
fn the_per_call_scanner_sees_the_whole_executor_viewer_surface() {
    let (measured, fns, calls, pop) = measure_executor();
    eprintln!(
        "population: {fns} viewer-holding executor fns, {calls} database calls, {} with an \
         unviewed call, {} unviewed calls",
        measured.len(),
        measured.values().map(Vec::len).sum::<usize>()
    );
    let got: Vec<(&str, &str)> = pop.iter().map(|(f, n)| (f.as_str(), n.as_str())).collect();
    assert_eq!(
        got,
        vec![
            // A viewer resolved in the body (`Viewer::resolve`).
            ("system_agent.rs", "system_agent_write_authority"),
            // The walk's two `Option<&Viewer>` fns.
            ("workflow.rs", "already_ingested_result"),
            ("workflow.rs", "execute_plan"),
            ("workflow.rs", "execute_workflow_ingest_plan_in_group"),
            // No database handle: in the population, with no calls.
            ("workflow.rs", "require_caller_writes_group"),
            ("workflow.rs", "reused_with_another_tenancy"),
            ("workflow_match.rs", "matching_workflow_conn"),
            ("workflow_plan.rs", "frozen_plan"),
        ],
        "the executor's viewer-holding fns changed: review the new fn's calls"
    );
    // Floor at the measurement: a scanner regression that stops recognising
    // calls in the fns above fails here.
    assert!(
        calls >= 47,
        "found {calls} database calls in them; measured 47 on 2026-11-26"
    );
}

/// The one struct under `src/` that carries a viewer is the system agent's
/// authority, which this crate BUILDS and returns (`system_agent_write_authority`)
/// and no fn here takes: its callers (the MCP and REST workflow writes) stamp
/// their transaction with `authority.viewer`. A fn here that took it and read
/// `authority.viewer` would be outside the population.
#[test]
fn the_viewer_carrier_structs_are_reviewed() {
    let files = executor_files();
    let mut carriers = Vec::new();
    for (file, src) in &files {
        let (code, _) = viewer_calls::views(src);
        for name in viewer_calls::viewer_carriers(&viewer_calls::struct_fields(&code)) {
            carriers.push((file.clone(), name));
        }
    }
    assert_eq!(
        carriers,
        vec![(
            "system_agent.rs".to_string(),
            "SystemAgentAuthority".to_string()
        )],
        "the structs that carry a viewer changed; check that every fn receiving one is \
         measured, then update this list"
    );
    let mut takers = Vec::new();
    for (file, src) in &files {
        let (code, sql) = viewer_calls::views(src);
        for h in viewer_calls::fn_headers(&code, &sql) {
            if h.params.iter().any(|(_, ty)| {
                carriers.iter().any(|(_, c)| {
                    let bare = ty.trim_start_matches('&').trim_start_matches("mut");
                    bare == c.as_str() || bare.ends_with(&format!("::{c}"))
                })
            }) {
                takers.push(format!("{file}::{}", h.name));
            }
        }
    }
    assert_eq!(
        takers,
        Vec::<String>::new(),
        "a fn here now takes a viewer-carrier struct: measure it (destructure the viewer, \
         or teach the scanner its access shape)"
    );
}

/// A real executor fn whose viewer handoff is removed by a one-word edit is
/// reported: `frozen_plan`, the fix sketch's example, hands the viewer to its
/// one repo read.
#[test]
fn the_per_call_scanner_reports_a_real_fn_whose_viewer_handoff_is_removed() {
    let src =
        std::fs::read_to_string(src_dir().join("workflow_plan.rs")).expect("read workflow_plan.rs");
    let key = ("workflow_plan.rs".to_string(), "frozen_plan".to_string());
    let mut clean = Measured::new();
    viewer_calls::measure_source(
        "workflow_plan.rs",
        &src,
        &EXECUTOR,
        &mut clean,
        &mut Population::new(),
    );
    assert!(
        !clean.contains_key(&key),
        "frozen_plan hands the viewer to its read: {:?}",
        clean.get(&key)
    );
    let handoff = "WorkflowRepository::frozen_plan(conn, viewer, workflow_id)";
    assert!(src.contains(handoff), "the read is in the file");
    let mutated = src.replacen(
        handoff,
        "WorkflowRepository::frozen_plan(conn, workflow_id)",
        1,
    );
    let mut broken = Measured::new();
    viewer_calls::measure_source(
        "workflow_plan.rs",
        &mutated,
        &EXECUTOR,
        &mut broken,
        &mut Population::new(),
    );
    assert_eq!(
        broken.get(&key).cloned().unwrap_or_default(),
        vec!["WorkflowRepository::frozen_plan".to_string()],
        "the same read without the viewer is unviewed"
    );
}

/// An optional viewer (`Option<&Viewer>`, the walk's caller-or-none) puts its
/// fn in the population: a content read beside it that does not take it is
/// reported, and one that does is viewed.
#[test]
fn an_optional_viewer_parameter_is_measured() {
    let src = r##"
async fn walk(
    conn: &mut sqlx::PgConnection,
    caller: Option<&epigraph_db::visibility::Viewer>,
    id: Uuid,
) -> R {
    let content: String = sqlx::query_scalar("SELECT content FROM claims WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    let seen = match caller {
        Some(caller) => ClaimRepository::tenancy_of_conn(&mut *conn, caller, &[id]).await?,
        None => Vec::new(),
    };
    Ok((content, seen))
}
"##;
    let mut out = Measured::new();
    let mut pop = Population::new();
    viewer_calls::measure_source("fixture.rs", src, &EXECUTOR, &mut out, &mut pop);
    assert!(
        pop.contains(&("fixture.rs".to_string(), "walk".to_string())),
        "a fn holding an `Option<&Viewer>` is in the population"
    );
    assert_eq!(
        out.get(&("fixture.rs".to_string(), "walk".to_string()))
            .cloned()
            .unwrap_or_default(),
        vec!["sqlx::query_scalar(SELECT).fetch_one".to_string()],
        "the content read is unviewed; the read handed `caller` is viewed"
    );
}
