//! Source ratchet: every place `epigraph-mcp` and `epigraph-engine` production
//! code can reach a RAW (unstamped) pool is registered here by
//! `(file, function)`, with a measured count and a reason, and the register
//! may only shrink.
//!
//! # Why this lint exists
//!
//! Since the 2026-10-26 tenancy deploy, FORCEd row security on the application
//! login admits public rows plus the rows of the groups STAMPED on the
//! connection (`ScopedPool::acquire_as` / `begin_as` / `read_as`). Work done on
//! the raw pool silently sees public rows only: the repo layer's in-query
//! viewer predicate admits a member's group-private row and the session's
//! policy drops it, with no error. That hid every private claim from every MCP
//! user until the read-conversion PR, and it hid four dedup and idempotency
//! probes after it (`submit_claim` / `memorize`'s exact-resubmit probe, the
//! novelty gate, `decide_match_candidate`'s guard and edge, fixed in the change
//! that added this file).
//!
//! None of the existing lints asked which connection a viewer-filtered read
//! runs on. `residual_unstamped_writes.rs` registers WRITE-shaped callees on
//! `server.pool`; `epigraph-db/tests/no_unscoped_pool.rs` covers
//! `epigraph-api`'s `.db_pool` only and names `epigraph-mcp` as out of its
//! scope; `epigraph-db/tests/visibility_lint.rs` checks that a repo function
//! TAKES a viewer, not what connection its caller passes. This file is the
//! connection half, for the two crates that serve MCP.
//!
//! # What counts as a site
//!
//! Over production source (comments, string literals and every `#[cfg(test)]`
//! item blanked out first), in `crates/epigraph-mcp/src` and
//! `crates/epigraph-engine/src`:
//!
//! 1. a field access `<expr>.pool` (`server.pool`, `self.pool`, `srv.pool`,
//!    `x.pool.clone()`), once per occurrence;
//! 2. each USE of a local alias bound by `let x = &<expr>.pool;` or
//!    `let x = <expr>.pool.clone();`, within the function that binds it;
//! 3. each `&PgPool` PARAMETER of a function that also takes a `Viewer`: the
//!    shape that hands a caller-filtered read a raw pool no matter what the
//!    caller holds.
//!
//! Sites are grouped by the innermost enclosing `fn`.
//!
//! # The rule for authors
//!
//! * Counts are asserted EXACTLY, in both directions. Converting sites means
//!   lowering the row in the same commit; a row driven to zero is DELETED (the
//!   scanner never produces a `0`). A NEW site is a failure: convert it (a read
//!   onto the caller's stamped read, a write onto `begin_author_stamped_tx`),
//!   or register it with a reason that survives the question "what does row
//!   security do to this on `epigraph_app`?".
//! * [`HIGH_WATER`] is the never-raised ceiling on the total, so growth fails
//!   structurally and not only by a reviewer noticing an edited literal.
//! * The register was SEEDED against `origin/main` 7520793d plus the raw-pool
//!   residual fixes: 215 sites in 126 rows, 130 of the sites viewer-filtered
//!   reads still on the raw pool (a `READ_PENDING` class). It was re-measured
//!   after merging the read-conversion change that runs every content-read
//!   tool on `EpiGraphMcpFull::read_as`, reading the new counts off this
//!   test's own failure output, never by subtraction: no row of that class
//!   remained, so the class was removed. A new viewer-filtered read on a raw
//!   pool is converted onto the caller's stamped read, not registered.
//!
//! # What a green run does NOT mean
//!
//! It means no UNREGISTERED raw-pool site exists in these two crates. It does
//! not mean the registered ones are safe: [`ENGINE_POOL_PARAM`] rows are
//! signatures that hand a caller-filtered read a raw pool whenever a caller
//! passes one, and [`REGISTERED_WRITE`] rows are unstamped writes, both listed
//! so they cannot grow. Nor does it see a pool reached by any other name (a
//! `PgPool` returned from a function, `ScopedPool::inner()`), and it cannot
//! tell a connection stamped from the WRONG viewer from a right one; the
//! app-role tests (`dedup_probes_app_role.rs` and the `*_app_role.rs` family)
//! are the instrument for that.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ===========================================================================
// Reasons. One per class of site, so a row's reason is a decision a reader
// can check, not prose that drifts per row.
// ===========================================================================

/// The table read or written carries no row security, so the stamp changes
/// nothing about which rows are admitted.
const NO_ROW_SECURITY: &str = "NO_ROW_SECURITY: every statement here reads or writes \
     tables without tenancy row security (papers, match_candidates, events, \
     behavioral_executions, agents and the like), so an unstamped session is admitted \
     exactly as a stamped one would be.";

/// A write's visibility resolution, run before the stamped transaction it
/// parameterises, through definer functions.
const DEFINER_RESOLUTION: &str = "DEFINER_RESOLUTION: resolves a write's visibility choice for \
     its author (ClaimRepository::resolve_write_decl / resolve_visibility_choice) BEFORE the \
     author-stamped transaction it parameterises; every read in it is a migration 206 or 107 \
     SECURITY DEFINER function, so the unstamped pool answers as a stamped one would.";

/// Membership or identity resolution that must run before any viewer exists,
/// through SECURITY DEFINER functions that answer without a stamp.
const PRE_VIEWER: &str = "PRE_VIEWER: resolves an identity or a viewer (Viewer::resolve over \
     epigraph_live_memberships, the server agent's own row, a delegation's liveness) BEFORE \
     a viewer exists to stamp from; the definer reads answer without a stamp, so stamping \
     first would be circular.";

/// The arm a server built WITHOUT a `ScopedPool` takes (a development
/// superuser, or a test fixture). A deployed server always has one.
const NO_SCOPED_POOL_FALLBACK: &str = "NO_SCOPED_POOL_FALLBACK: the arm taken only when the \
     server has no ScopedPool (a development superuser or a fixture). Every deployed server \
     is built with_scoped_pool, so this arm never runs on epigraph_app.";

/// A write registered, with its own reason, in `residual_unstamped_writes.rs`.
const REGISTERED_WRITE: &str = "REGISTERED_WRITE: an unstamped write carried, with its own \
     measured reason, by residual_unstamped_writes.rs's RESIDUAL_UNSTAMPED_WRITES; this row \
     only counts the pool access the write needs.";

/// A pool handed to something that stamps by itself (the embedder's declared
/// store path, the author-stamped helpers' read pool, a ScopedPool owner).
const DELEGATES_THE_STAMP: &str = "DELEGATES_THE_STAMP: the pool is handed to a component that \
     stamps its own statements or resolves the author's viewer on it before stamping \
     (claim_helper's author-stamped helpers, McpEmbedder's declared store path), so the raw \
     pool carries no tenancy-filtered statement here.";

/// Corpus-wide work with no caller, or with a caller whose view must not
/// scope it: boot, gauges, the server-agent provisioning.
const NO_CALLER: &str = "NO_CALLER: boot, provisioning or corpus-wide maintenance with no \
     request principal to stamp from (the server agent's own row and personal group, \
     tool.invoked events, a detached task).";

/// An engine function that takes a `&PgPool` next to a `Viewer`: the caller
/// decides which pool, and the engine cannot stamp it.
const ENGINE_POOL_PARAM: &str = "ENGINE_POOL_PARAM: an engine function taking `&PgPool` beside \
     a Viewer. Whatever the viewer says, a raw application pool admits public rows only; \
     callers on a request path must pass a stamped connection instead, so this signature \
     should move to `&mut PgConnection` (or a PgExecutor) as its callers convert.";

// ===========================================================================
// THE REGISTER: `(file, function, sites, reason)`. Paths are relative to the
// workspace's `crates/` directory.
// ===========================================================================
/// The cross-source matcher pipeline's own edge write.
const MATCHER_POLICY_EDGE: &str = "MATCHER_POLICY_EDGE: the matcher pipeline's auto-promote \
     edge write, on the pool its Policy captured. Between two PUBLIC claims migration 120 \
     makes the edge world-owned and edges_tenancy's world arm admits it unstamped; an edge \
     touching a group-private claim would be refused here (the MCP promote path no longer \
     comes this way: it uses promote_if_pending_conn on the author-stamped transaction).";

/// The `OPERATED_BY` auth-lineage edge.
const AUTH_LINEAGE_EDGE: &str = "AUTH_LINEAGE_EDGE: the OPERATED_BY edge joins two agents, a \
     structural edge migration 120 makes ('public', world) whoever writes it, so the \
     unstamped insert is admitted; dedup_probes_app_role.rs's \
     the_auth_lineage_edge_lands_on_the_application_role pins it on epigraph_app, so the \
     warn-only failure branch is not hiding a refusal.";

/// Frames are an instance-wide registry.
const INSTANCE_REGISTRY_READ: &str = "INSTANCE_REGISTRY_READ: reads a frame's per-frame \
     evidence-type weights; `frames` is one of migration 077's instance-wide registries, \
     whose policy admits every session, so a stamp changes nothing.";

/// `#[sqlx::test]` fixture entry points kept in production source.
const FIXTURE_ENTRY: &str = "FIXTURE_ENTRY: a `*_via_pool` entry point that exists for \
     `#[sqlx::test]` fixtures on a superuser pool (residual_unstamped_writes.rs's \
     EXECUTOR_CALL_REGISTER records its unstamped executor call). No tool routes through it; \
     every production ingest takes the stamped path.";

const REGISTER: &[(&str, &str, usize, &str)] = &[
    // ── epigraph-engine ──────────────────────────────────────────────────
    (
        "epigraph-engine/src/belief_query.rs",
        "for_perspective",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_belief",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_belief_scoped",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_perspective_belief",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_perspective_belief_batch",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_perspective_belief_batch_scoped",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "get_perspective_belief_scoped",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "scope_conn",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/belief_query.rs",
        "shadow_belief",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/diverse_retrieval.rs",
        "candidates_in_themes_at_dim",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/diverse_retrieval.rs",
        "candidates_in_themes_at_dim_since",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/diverse_retrieval.rs",
        "run_diverse_pipeline",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/export/prov.rs",
        "export_provenance_prov_o",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/matching/policy.rs",
        "write_edge",
        1,
        MATCHER_POLICY_EDGE,
    ),
    (
        "epigraph-engine/src/recall.rs",
        "annotate_disputes",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/recall.rs",
        "effective_beliefs",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/recall.rs",
        "log_recall_event",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/recall.rs",
        "recall",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/recall.rs",
        "text_search_fallback",
        1,
        ENGINE_POOL_PARAM,
    ),
    (
        "epigraph-engine/src/source_dependence.rs",
        "bba_sources_for_rows_on_pool",
        1,
        ENGINE_POOL_PARAM,
    ),
    // ── epigraph-mcp: identity, auth, plumbing ───────────────────────────
    ("epigraph-mcp/src/auth.rs", "is_revoked", 1, PRE_VIEWER),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "begin_author_stamped_tx_for",
        1,
        DELEGATES_THE_STAMP,
    ),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "embed_claim_author_stamped_for",
        1,
        DELEGATES_THE_STAMP,
    ),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "resolve_claim_visibility",
        1,
        DEFINER_RESOLUTION,
    ),
    (
        "epigraph-mcp/src/claim_helper.rs",
        "write_viewer",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/embed.rs",
        "store_vector",
        4,
        "DELEGATES_THE_STAMP, two arms: StorePath::PrivilegedPool stores directly on a DECLARED \
         BYPASSRLS maintenance pool (the operator ingest CLI); StorePath::AuthorStamped resolves \
         the claim's author on the plain pool as the PUBLIC viewer and stores on that author's \
         stamp. The public-only author read is a known limit (CLAUDE.md's declared-tenancy \
         note: a group-private claim's author is not resolvable here, and \
         workflow_ingest::store_ingest_embedding stores through the known author instead).",
    ),
    (
        "epigraph-mcp/src/operator.rs",
        "refuse_human_http_signer",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/operator.rs",
        "refuse_linked_http_signer",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/operator.rs",
        "refuse_operator_http_signer",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/operator.rs",
        "self_link",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/server.rs",
        "admin_scope_posture",
        1,
        PRE_VIEWER,
    ),
    ("epigraph-mcp/src/server.rs", "agent_id", 4, NO_CALLER),
    (
        "epigraph-mcp/src/server.rs",
        "emit_tool_invoked",
        1,
        NO_CALLER,
    ),
    (
        "epigraph-mcp/src/server.rs",
        "holds_elevating_role",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/server.rs",
        "record_auth_lineage",
        1,
        AUTH_LINEAGE_EDGE,
    ),
    (
        "epigraph-mcp/src/tools/viewer.rs",
        "read_delegation",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/viewer.rs",
        "request_viewer",
        2,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/viewer.rs",
        "resolve_http",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/workflow_authority.rs",
        "caller_view_of",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/workflow_authority.rs",
        "stdio_workflow_authority",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "execute_workflow_ingest_with_inserted",
        1,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/claims.rs",
        "operator_arm_allows",
        2,
        PRE_VIEWER,
    ),
    (
        "epigraph-mcp/src/tools/claims.rs",
        "delegate_arm_allows",
        1,
        PRE_VIEWER,
    ),
    // ── epigraph-mcp: tables without row security ────────────────────────
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "check_already_ingested",
        1,
        NO_ROW_SECURITY,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "paper_already_ingested",
        1,
        NO_ROW_SECURITY,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "preflight_write_authority",
        1,
        NO_ROW_SECURITY,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "resolve_ingest_visibility",
        1,
        DEFINER_RESOLUTION,
    ),
    (
        "epigraph-mcp/src/tools/memory.rs",
        "recall_post_embed",
        1,
        "NO_ROW_SECURITY: the `&server.pool` argument to themes::resolve_theme_selector, for its \
         claim_themes label lookup (a registry with no tenancy); every claim-derived read of \
         the page runs on the caller's stamped read.",
    ),
    (
        "epigraph-mcp/src/tools/paper_queries.rs",
        "query_paper",
        1,
        "NO_ROW_SECURITY: the `papers` lookup (find_paper_by_document_key); every claim-derived \
         read below it runs on the caller's stamped read.",
    ),
    (
        "epigraph-mcp/src/tools/themes.rs",
        "get_theme",
        1,
        "NO_ROW_SECURITY: the `&server.pool` argument to resolve_theme_selector, for its \
         claim_themes label lookup; the summary and member reads run on the caller's stamped \
         read.",
    ),
    (
        "epigraph-mcp/src/tools/themes.rs",
        "list_themes",
        1,
        "NO_ROW_SECURITY: ClaimThemeRepository::count_summaries over claim_themes, corpus-wide by \
         design; the page itself runs on the caller's stamped read.",
    ),
    (
        "epigraph-mcp/src/tools/themes.rs",
        "resolve_theme_selector",
        1,
        "NO_ROW_SECURITY: its `pool` parameter serves only ClaimThemeRepository::find_by_label \
         over claim_themes; the viewer-filtered summary read takes the caller's stamped `conn`.",
    ),
    (
        "epigraph-mcp/src/tools/matching.rs",
        "decide_match_candidate",
        1,
        NO_ROW_SECURITY,
    ),
    (
        "epigraph-mcp/src/tools/matching.rs",
        "retire_match_candidate",
        1,
        NO_ROW_SECURITY,
    ),
    (
        "epigraph-mcp/src/tools/ds.rs",
        "evidence_type_resolves",
        1,
        INSTANCE_REGISTRY_READ,
    ),
    // ── epigraph-mcp: writes registered in residual_unstamped_writes.rs ──
    (
        "epigraph-mcp/src/tools/ds.rs",
        "create_frame",
        2,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/events.rs",
        "publish_event",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "begin_ingest_tx",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document_reporting",
        2,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "do_ingest_document_spine",
        2,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/ingestion.rs",
        "ensure_paper_node",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/perspectives.rs",
        "create_perspective",
        2,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "store_workflow_goal_embedding",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/workflows.rs",
        "refresh_workflow_promotion",
        1,
        REGISTERED_WRITE,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "store_ingest_embedding",
        1,
        DELEGATES_THE_STAMP,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "do_ingest_workflow_via_pool",
        1,
        FIXTURE_ENTRY,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "improve_workflow_hierarchy_via_pool",
        1,
        FIXTURE_ENTRY,
    ),
    (
        "epigraph-mcp/src/tools/workflow_ingest.rs",
        "lineage_max_generation",
        1,
        NO_SCOPED_POOL_FALLBACK,
    ),
    (
        "epigraph-mcp/src/tools/recall.rs",
        "detect_centroid_dim",
        1,
        "TEST_ONLY_WRAPPER: `recall::__test_only::detect_centroid_dim`, a #[doc(hidden)] \
         wrapper taking `&PgPool` so a #[sqlx::test] can pin the centroid-dimension decision; \
         no tool routes through it (the tool's own detect_centroid_dim takes the stamped \
         read).",
    ),
    (
        "epigraph-mcp/src/tools/evolve_step.rs",
        "evolve_step",
        1,
        "REGISTERED_WRITE: the server.pool.begin() fallback for a server with no ScopedPool (a \
         fixture; every deployed server is built with_scoped_pool). The step-name resolution \
         that was the second site now runs on the caller's stamped read.",
    ),
    (
        "epigraph-mcp/src/tools/workflows.rs",
        "report_workflow_outcome",
        2,
        "One NO_SCOPED_POOL_FALLBACK (WorkflowRepository::exists without a ScopedPool; with one \
         the existence check is viewer_reads_row on read_as) and one REGISTERED_WRITE \
         (BehavioralExecutionRepository::create, a table with no tenancy).",
    ),
];

/// The never-raised ceiling on the register's total site count.
const HIGH_WATER: usize = 84;

// ===========================================================================
// The scanner.
// ===========================================================================

const SCAN_ROOTS: &[&str] = &["epigraph-mcp/src", "epigraph-engine/src"];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Blank out comments and the CONTENTS of string and char literals with
/// spaces, keeping every newline and every byte offset.
///
/// Strings first-class, not after comments: a `"https://…"` literal holds a
/// `//`, and a comment stripper that does not know about strings cuts the rest
/// of that line. Raw strings (`r"…"`, `r#"…"#`) and byte strings are handled;
/// a lifetime (`'a`) is told from a char literal (`'a'`, `'\n'`).
fn sanitize(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = b.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for c in out.iter_mut().take(to).skip(from) {
            if *c != '\n' {
                *c = ' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            let start = i;
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            blank(&mut out, start, i);
        } else if c == '/' && next == Some('*') {
            let start = i;
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            blank(&mut out, start, i);
        } else if (c == 'r' || (c == 'b' && next == Some('r')))
            && (i == 0 || !(b[i - 1].is_alphanumeric() || b[i - 1] == '_'))
            && {
                let mut j = i + if c == 'b' { 2 } else { 1 };
                while b.get(j) == Some(&'#') {
                    j += 1;
                }
                b.get(j) == Some(&'"')
            }
        {
            let mut j = i + if c == 'b' { 2 } else { 1 };
            let mut hashes = 0;
            while b[j] == '#' {
                hashes += 1;
                j += 1;
            }
            let body = j + 1;
            let mut k = body;
            'scan: while k < b.len() {
                if b[k] == '"' && (0..hashes).all(|h| b.get(k + 1 + h) == Some(&'#')) {
                    break 'scan;
                }
                k += 1;
            }
            blank(&mut out, body, k);
            i = k + 1 + hashes;
        } else if c == '"' {
            let body = i + 1;
            let mut k = body;
            while k < b.len() && b[k] != '"' {
                if b[k] == '\\' {
                    k += 1;
                }
                k += 1;
            }
            blank(&mut out, body, k);
            i = k + 1;
        } else if c == '\'' {
            if next == Some('\\') {
                // Past the escaped character itself, so `'\''` ends at its
                // fourth character rather than its third.
                let mut k = i + 3;
                while k < b.len() && b[k] != '\'' {
                    k += 1;
                }
                blank(&mut out, i + 1, k);
                i = k + 1;
            } else if b.get(i + 2) == Some(&'\'') {
                blank(&mut out, i + 1, i + 2);
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out.into_iter().collect()
}

/// Index of the brace closing the one at `open`.
fn matching_brace(b: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, c) in b.iter().enumerate().skip(open) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    b.len()
}

/// Blank every item gated on `#[cfg(test)]` (or `cfg(all(test, …))`): the
/// attribute up to the end of the item it decorates.
fn blank_test_items(s: &str) -> String {
    let mut b: Vec<char> = s.chars().collect();
    let text: String = b.iter().collect();
    let mut starts: Vec<usize> = Vec::new();
    for pat in ["#[cfg(test)]", "#[cfg(all(test"] {
        for (byte, _) in text.match_indices(pat) {
            starts.push(text[..byte].chars().count());
        }
    }
    starts.sort_unstable();
    for start in starts {
        if b[start] == ' ' {
            continue; // already blanked by an enclosing test item
        }
        let mut k = start;
        while k < b.len() && b[k] != '{' && b[k] != ';' {
            k += 1;
        }
        let end = if k < b.len() && b[k] == '{' {
            matching_brace(&b, k)
        } else {
            k
        };
        let len = b.len();
        for c in b.iter_mut().take((end + 1).min(len)).skip(start) {
            if *c != '\n' {
                *c = ' ';
            }
        }
    }
    b.into_iter().collect()
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// A function's name, its signature span and its body span.
struct FnSpan {
    name: String,
    sig: (usize, usize),
    body: (usize, usize),
}

fn fn_spans(b: &[char]) -> Vec<FnSpan> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < b.len() {
        let at_fn =
            b[i] == 'f' && b[i + 1] == 'n' && b[i + 2] == ' ' && (i == 0 || !is_ident(b[i - 1]));
        if !at_fn {
            i += 1;
            continue;
        }
        let mut j = i + 3;
        let name: String = b[j..].iter().take_while(|c| is_ident(**c)).collect();
        j += name.len();
        if name.is_empty() {
            i += 1;
            continue;
        }
        // The body opens at the first `{` outside parens/brackets/angles, unless
        // a `;` comes first (a declaration with no body).
        let mut depth = 0i32;
        let mut k = j;
        let mut open = None;
        while k < b.len() {
            match b[k] {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth == 0 => {
                    open = Some(k);
                    break;
                }
                ';' if depth == 0 => break,
                _ => {}
            }
            k += 1;
        }
        if let Some(open) = open {
            out.push(FnSpan {
                name,
                sig: (j, open),
                body: (open, matching_brace(b, open)),
            });
        }
        i = j;
    }
    out
}

/// The innermost function whose body contains `at`.
fn enclosing(spans: &[FnSpan], at: usize) -> Option<&FnSpan> {
    spans
        .iter()
        .filter(|s| s.body.0 <= at && at <= s.body.1)
        .min_by_key(|s| s.body.1 - s.body.0)
}

/// `(file, function) -> sites` for one file's text.
fn scan_text(rel: &str, src: &str, found: &mut BTreeMap<(String, String), usize>) {
    let clean = blank_test_items(&sanitize(src));
    let b: Vec<char> = clean.chars().collect();
    let spans = fn_spans(&b);
    let mut add = |at: usize| {
        let name = enclosing(&spans, at).map_or_else(|| "<item>".to_string(), |s| s.name.clone());
        *found.entry((rel.to_string(), name)).or_insert(0) += 1;
    };

    // 1. `<expr>.pool` field accesses.
    let mut field_sites = Vec::new();
    for i in 0..b.len().saturating_sub(5) {
        if b[i] == '.'
            && b[i + 1..i + 5] == ['p', 'o', 'o', 'l']
            && !b.get(i + 5).is_some_and(|c| is_ident(*c) || *c == '(')
            && i > 0
            && (is_ident(b[i - 1]) || b[i - 1] == ')')
        {
            field_sites.push(i);
            add(i);
        }
    }

    // 2. Uses of `let x = &<expr>.pool;` / `let x = <expr>.pool.clone();`.
    for &site in &field_sites {
        let Some(span) = enclosing(&spans, site) else {
            continue;
        };
        // Walk back over `&recv` to the `=` of a `let` on the same statement.
        let line_start = b[..site]
            .iter()
            .rposition(|c| *c == ';' || *c == '{' || *c == '}')
            .map_or(0, |p| p + 1);
        let stmt: String = b[line_start..site].iter().collect();
        let stmt = stmt.trim();
        let Some(rest) = stmt.strip_prefix("let ") else {
            continue;
        };
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let alias: String = rest.chars().take_while(|c| is_ident(*c)).collect();
        let after_alias = rest[alias.len()..].trim_start();
        let Some(rhs) = after_alias.strip_prefix('=') else {
            continue;
        };
        let rhs = rhs.trim_start();
        let tail: String = b[site + 5..].iter().take(10).collect();
        let whole = (rhs.starts_with('&') && tail.trim_start().starts_with(';'))
            || tail.starts_with(".clone();");
        if alias.is_empty() || !whole {
            continue;
        }
        let a: Vec<char> = alias.chars().collect();
        let stmt_end = b[site..]
            .iter()
            .position(|c| *c == ';')
            .map_or(b.len(), |p| site + p);
        let mut k = stmt_end;
        while k + a.len() <= span.body.1 {
            let hit = b[k..k + a.len()] == a[..]
                && !is_ident(b[k - 1])
                && b[k - 1] != '.'
                && !b.get(k + a.len()).is_some_and(|c| is_ident(*c));
            if hit {
                add(k);
                k += a.len();
            } else {
                k += 1;
            }
        }
    }

    // 3. `&PgPool` parameters of functions that also take a `Viewer`.
    for span in &spans {
        let sig: String = b[span.sig.0..span.sig.1].iter().collect();
        let Some(open) = sig.find('(') else { continue };
        let mut depth = 0i32;
        let mut close = sig.len();
        for (k, c) in sig.char_indices().skip(open) {
            match c {
                '(' | '<' => depth += 1,
                ')' | '>' => {
                    depth -= 1;
                    if depth == 0 && c == ')' {
                        close = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let params = &sig[open + 1..close];
        let mut parts = Vec::new();
        let (mut d, mut last) = (0i32, 0usize);
        for (k, c) in params.char_indices() {
            match c {
                '(' | '<' | '[' => d += 1,
                ')' | '>' | ']' => d -= 1,
                ',' if d == 0 => {
                    parts.push(&params[last..k]);
                    last = k + 1;
                }
                _ => {}
            }
        }
        parts.push(&params[last..]);
        // `(is a reference, last path segment)` of a parameter's type:
        // `&'a sqlx::PgPool` -> (true, "PgPool"), `&Viewer` -> (true, "Viewer").
        let base = |p: &str| -> Option<(bool, String)> {
            let (_, t) = p.split_once(':')?;
            let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
            let is_ref = t.starts_with('&');
            let mut t = t.trim_start_matches('&');
            if let Some(rest) = t.strip_prefix('\'') {
                t = rest.trim_start_matches(is_ident);
            }
            let t = t.strip_prefix("mut").unwrap_or(t);
            Some((is_ref, t.rsplit("::").next().unwrap_or(t).to_string()))
        };
        let takes_viewer = parts
            .iter()
            .filter_map(|p| base(p))
            .any(|(_, last)| last == "Viewer");
        if !takes_viewer {
            continue;
        }
        for p in &parts {
            if let Some((true, last)) = base(p) {
                if last == "PgPool" {
                    add(span.body.0);
                }
            }
        }
    }
}

fn measure() -> BTreeMap<(String, String), usize> {
    let root = crates_root();
    let mut found = BTreeMap::new();
    for scan_root in SCAN_ROOTS {
        for path in rust_files(&root.join(scan_root)) {
            let rel = path
                .strip_prefix(&root)
                .expect("strip prefix")
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&path).expect("read source");
            scan_text(&rel, &src, &mut found);
        }
    }
    found
}

fn seed_listing(measured: &BTreeMap<(String, String), usize>) -> String {
    measured
        .iter()
        .map(|((f, n), c)| format!("    (\"{f}\", \"{n}\", {c}, REASON),"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// **The ratchet.** The measured register must be EXACTLY the register.
#[test]
fn the_raw_pool_register_is_exactly_what_was_measured() {
    let measured = measure();
    let registered: BTreeMap<(String, String), usize> = REGISTER
        .iter()
        .map(|(f, n, c, _)| (((*f).to_string(), (*n).to_string()), *c))
        .collect();
    assert_eq!(
        REGISTER.len(),
        registered.len(),
        "a (file, function) appears twice in REGISTER"
    );
    if measured != registered {
        let mut diff = Vec::new();
        for (k, v) in &measured {
            match registered.get(k) {
                None => diff.push(format!("  NEW       {}::{} = {v}", k.0, k.1)),
                Some(r) if r != v => {
                    diff.push(format!(
                        "  CHANGED   {}::{}: recorded {r}, measured {v}",
                        k.0, k.1
                    ));
                }
                _ => {}
            }
        }
        for (k, r) in &registered {
            if !measured.contains_key(k) {
                diff.push(format!("  GONE      {}::{} (recorded {r})", k.0, k.1));
            }
        }
        panic!(
            "\nThe raw-pool sites in epigraph-mcp / epigraph-engine production source changed:\n{}\n\n\
             * NEW: a function reaches a raw pool that nobody registered. Convert it (reads onto \
               the caller's stamped read, writes onto begin_author_stamped_tx) or register it \
               with a reason.\n\
             * CHANGED / GONE: sites were converted or moved; lower or delete the row (never \
               leave a 0).\n\nThe full measured table, for reference:\n{}\n",
            diff.join("\n"),
            seed_listing(&measured)
        );
    }
}

/// Growth fails structurally: the register's total may not exceed
/// [`HIGH_WATER`], and the two agree, so lowering a row means lowering this.
#[test]
fn the_register_total_is_the_high_water_mark() {
    let total: usize = REGISTER.iter().map(|(_, _, c, _)| *c).sum();
    assert_eq!(
        total, HIGH_WATER,
        "REGISTER sums to {total} but HIGH_WATER is {HIGH_WATER}. Lower HIGH_WATER with the rows \
         you converted; never raise it."
    );
}

/// Every row names a reason a reader can act on.
#[test]
fn every_registered_site_states_why() {
    for (file, func, count, reason) in REGISTER {
        assert!(
            *count > 0,
            "{file}::{func} is registered at 0; delete the row"
        );
        assert!(
            reason.len() > 80,
            "{file}::{func} needs a reason a reader can act on: {reason}"
        );
    }
}

/// The scanner is not vacuous: each of its three arms finds a known site on
/// the real tree.
#[test]
fn the_scanner_is_not_vacuous() {
    let measured = measure();
    assert!(
        measured.len() >= 20,
        "only {} functions measured; the matcher broke",
        measured.len()
    );
    // Arm 1 (field access): the server agent's own provisioning.
    assert!(
        measured.contains_key(&(
            "epigraph-mcp/src/server.rs".to_string(),
            "agent_id".to_string()
        )),
        "server.rs::agent_id reads self.pool; the field-access arm is broken"
    );
    // Arm 3 (pool parameter beside a Viewer) somewhere in the engine.
    assert!(
        measured
            .keys()
            .any(|(f, _)| f.starts_with("epigraph-engine/src/")),
        "no epigraph-engine site found; the parameter arm or the scan root is broken"
    );
}

/// Calibration on a fixture, so the arms keep being tested whatever the tree
/// looks like: comments and strings are not sites, `#[cfg(test)]` items are
/// not production, an alias's uses count, and a pool parameter counts only
/// beside a viewer.
#[test]
fn the_scanner_arms_are_calibrated() {
    let fixture = r##"
/// A doc comment naming `server.pool` is not a site.
fn commented(server: &S) {
    // nor is a line comment: server.pool
    let url = "https://example.org/a//b server.pool";
    let raw = r#"server.pool"#;
    let c = '{';
    real(&server.pool);
}
fn aliased(server: &S) {
    let pool = &server.pool;
    one(pool);
    two(pool, pool);
    not_it(pool_x);
}
fn param_with_viewer(pool: &PgPool, viewer: &Viewer) {}
fn param_with_qualified_viewer(p: &sqlx::PgPool, v: &epigraph_db::visibility::Viewer) {}
fn param_without_viewer(pool: &PgPool) {}
#[cfg(test)]
mod tests {
    fn hidden(server: &S) { real(&server.pool); }
}
fn after_tests(srv: &S) { srv.pool.clone(); }
"##;
    let mut found = BTreeMap::new();
    scan_text("f.rs", fixture, &mut found);
    let got: Vec<(String, usize)> = found.into_iter().map(|((_, n), c)| (n, c)).collect();
    assert_eq!(
        got,
        vec![
            ("after_tests".to_string(), 1),
            ("aliased".to_string(), 4),
            ("commented".to_string(), 1),
            ("param_with_qualified_viewer".to_string(), 1),
            ("param_with_viewer".to_string(), 1),
        ],
        "aliased = the binding's own field access + three uses"
    );
}
