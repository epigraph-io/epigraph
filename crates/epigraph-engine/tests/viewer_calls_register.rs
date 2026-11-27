//! The per-call viewer-spend register for `epigraph-engine` (backlog 37e68f5b).
//!
//! # The gap this closes
//!
//! `epigraph-db/tests/visibility_lint.rs` (the repo layer) and
//! `epigraph-mcp/tests/tool_viewer_is_spent.rs` (the MCP tools) each name, per
//! viewer-holding fn, every database call that does not spend the fn's viewer
//! (backlog ada8ee55). Neither follows a call into this crate: a tool or a
//! route that hands an engine fn its viewer counts that call as viewed, and
//! nothing read the engine fn's own body. An engine fn could spend its viewer
//! on one statement while the read whose rows it returns ran without it, and
//! every check in the tree stayed green.
//!
//! This file measures every viewer-holding fn under `src/` with the same
//! scanner (`epigraph-db/tests/viewer_calls/mod.rs`) and asserts its unviewed
//! calls against an exact, reviewed register, the shape the repo and tool
//! registers have.
//!
//! # Two viewers in one fn
//!
//! The scanner counts a call handed ANY viewer the fn holds as viewed. The
//! administrative cascade (`admin_cascade.rs`) holds two by design: the
//! maintenance connection's bypass viewer (`admin_viewer`), which runs the
//! cascade, and the caller's (`caller`), which filters what the caller is told.
//! So a read handed only `admin_viewer` would pass for one handed the caller's.
//! [`SPLIT_CALLS`] closes that: for every fn holding more than one viewer, the
//! calls ONE of them covers alone are named, keyed by the viewer that does not
//! cover them, as a second exact register.

#[path = "../../epigraph-db/tests/viewer_calls/mod.rs"]
mod viewer_calls;

#[path = "../../epigraph-db/tests/lint_text/mod.rs"]
mod lint_text;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use viewer_calls::{Measured, Population, Surface};

/// The engine's database handles, for the per-call scanner: its pool,
/// connection, transaction and executor PARAMETERS (by type), and the
/// connections a body opens on them. The engine has no application handle.
const ENGINE: Surface = Surface {
    state_types: &[],
    pool_fields: &[],
    state_db_methods: &[],
    viewer_ctors: &["Viewer::resolve("],
    conn_ctors: &[],
    // The cascade's repair closures run on the transaction the macro opens.
    conn_closure_macros: &["repair_with_audit!"],
    marker_spend: call_spends_viewer,
};

/// The per-call marker spend: the statement's live SQL (comments removed) puts
/// `visibility = 'public'` in predicate position. See
/// [`viewer_calls::predicate_spend`].
fn call_spends_viewer(region: &str) -> bool {
    let (_, live_sql) = lint_text::spend_views(region);
    viewer_calls::predicate_spend(&live_sql)
}

/// Every database call in a viewer-holding engine fn that does not spend the
/// fn's viewer, as measured and reviewed on **2026-11-26** (backlog 37e68f5b).
///
/// Asserted as an exact multiset per fn. The comment above each group is the
/// review, by reason class:
///
/// * **maintenance** — runs on the privileged maintenance connection, by the
///   rule `admin_cascade.rs`'s module doc states: the cascade's repairs, its
///   audit rows (`failed`, `obsolete`, `record_belief`, `audit::*`) and the
///   replays and sweeps of operator binaries. A caller is told only what
///   `report_for_caller` / `retirement_for_caller` filter through its own
///   viewer (both are viewed calls), and counts.
/// * **privileged** — refuses unless its viewer is the bypass viewer, or is
///   reached only from an operator binary on the maintenance connection (the
///   `supersede_delta` dry runs: `supersede_belief_delta`, `k10_retro`,
///   `cache_owner_audit`; no route or tool calls them, and each statement
///   carries its `VISIBILITY-EXEMPT:` reason).
/// * **session** — a transaction or session setting (read-only transaction,
///   statement timeout, savepoint, the bypass-session assertion): it reads no
///   row.
/// * **write** — writes a row (the act itself, a BBA, a frame assignment, a
///   cached belief or classification, a divergence row, the binary frame)
///   about a claim or edge the fn read through its viewer or the write gate
///   admitted. It returns at most counts, ids and flags.
/// * **audit** — records the caller's own act (its recall event).
/// * **calibration** — a per-frame calibration scalar out of
///   `frames.properties` (the repo's `VISIBILITY-EXEMPT:` reason), consumed by
///   the fold and never returned.
/// * **narrows** — `derivation_scope::retain_for_cache` /
///   `DerivationScopeRepository::cache_admissible` filter rows the fn already
///   read through its viewer: they can drop a row, never add one.
/// * **untenanted** — no tenancy columns, or a definer that applies its own
///   audience: `claim_themes` (a registered `tenancy_exempt` table; the theme
///   ids only select candidates that are then read through the viewer), the
///   agent-to-human binding (`epigraph_human_of`, for the same-human fold rule;
///   the human id never leaves the fold), and agent names through migration
///   309's `epigraph_agent_disclosure` on the caller's stamped connection.
/// * **keyed** — a scalar or boolean about a claim or edge the fn has just
///   read (or written) through its viewer: in force, `is_current`, holds a
///   cache. Or a write guard's whole-graph compound check (migration 193's
///   definer, by design), whose visible part is then read through the viewer.
/// * **derive** — the edge factor's source interval and its intra-source
///   locality, read on the edge writer's transaction for the BBA the edge
///   derives on its target. Every request path wires on a transaction stamped
///   from the caller or the author, so `claims` row security bounds the read:
///   REST `routes/edges.rs` (the caller's stamped transaction, after reading
///   the source through the viewer) and `routes/workflows.rs`
///   (`begin_caller_workflow_tx`); MCP `link_epistemic`
///   (`begin_author_stamped_tx`), `workflow_ingest` (`begin_caller_workflow_tx`;
///   its `*_via_pool` forms are `#[sqlx::test]` fixtures) and `ingestion`
///   (`begin_ingest_tx`). The value is written into the derived row; only
///   the outcome (wired, or no source interval) is reported, and that row's
///   readability is decided at read by `derivation_scope` (an edge-factor row
///   is admitted only when the edge's source claim is visible). The operator
///   backfills run it on the maintenance connection.
///
/// No entry reads content into a response without the viewer: the review
/// found nothing to fix. The fix sketch's two named examples,
/// `bba_retract.rs::read` (`RetractCacheBefore::read`) and the executor's
/// `workflow_plan::frozen_plan`, hand the viewer to every call they make and
/// so have no entry. Do not add an entry to make the build pass.
const REVIEWED_CALLS: &[(&str, &str, &[&str])] = &[
    // maintenance: the repair itself, inside the `repair_with_audit!` closure
    // on the transaction the macro opens on the maintenance connection (the
    // dedup repair, the edge-keyed BBA removal and its open deferrals, the
    // supersede factor regeneration, the match retirement), and the cascade's
    // failure, belief and obsolete audit rows. The repair's output reaches the
    // caller only as `counts_only` in the status, and through the
    // `report_for_caller` / `retirement_for_caller` filters.
    (
        "admin_cascade.rs",
        "apply_after_dedup",
        &[
            "ClaimRepository::repair_marked_duplicate_conn",
            "failed",
            "record_belief",
        ],
    ),
    (
        "admin_cascade.rs",
        "apply_after_edge_retract",
        &[
            "EdgeRepository::remove_withdrawn_edge_bbas_conn",
            "audit::open_edge_retract_sources",
            "failed",
            "record_belief",
        ],
    ),
    (
        "admin_cascade.rs",
        "apply_after_supersede",
        &[
            "ClaimRepository::regenerate_superseded_edge_factors_conn",
            "failed",
            "record_belief",
        ],
    ),
    (
        "admin_cascade.rs",
        "apply_match_retire",
        &[
            "MatchCandidateRepo::retire_conn",
            "failed",
            "obsolete",
            "record_belief",
        ],
    ),
    // maintenance: the un-mark's reversal, its revert record and open
    // cascades, and the caller's precondition (`UnmarkPrecondition::check`,
    // an authority re-check under the link lock), on the maintenance
    // transaction. The caller gets counts and the report_for_caller filter.
    (
        "admin_cascade.rs",
        "apply_unmark_checked",
        &[
            "ClaimRepository::reverse_marked_duplicate_conn",
            "ClaimRepository::reverse_marked_duplicate_conn",
            "audit::dedup_revert_record",
            "audit::open_dedup_cascades",
            "audit::record",
            "audit::retire_pending",
            "check",
            "record_belief",
        ],
    ),
    // maintenance: the deferred-cascade replay (operator CLI
    // `replay_deferred_cascades`) and the withdrawn-edge sweep.
    (
        "admin_cascade.rs",
        "replay_deferred",
        &[
            "apply_after_consolidate",
            "audit::pending_replays",
            "audit::stuck_replays",
        ],
    ),
    (
        "admin_cascade.rs",
        "sweep_withdrawn_edge_bbas",
        &["EdgeRepository::withdrawn_edges_with_bbas_conn"],
    ),
    // untenanted + calibration: the same-human binding of the rows' writers,
    // and the frame's calibration overrides, for the fold.
    (
        "atom_items.rs",
        "key_and_discount_two_sided",
        &[
            "AgentRepository::humans_of",
            "FrameRepository::get_intra_evidence_locality_factor",
            "FrameRepository::get_per_frame_evidence_type_weights",
        ],
    ),
    // narrows
    (
        "atom_items.rs",
        "select_atom_rows",
        &["DerivationScopeRepository::cache_admissible"],
    ),
    // calibration
    (
        "belief_query.rs",
        "resolve",
        &[
            "FrameRepository::get_intra_evidence_locality_factor",
            "FrameRepository::get_per_frame_evidence_type_weights",
        ],
    ),
    // keyed: the write guard's whole-graph compound check (migration 193).
    ("compound_write_guard.rs", "decide", &["is_compound"]),
    // narrows
    (
        "derivation_scope.rs",
        "must_vacate_cache",
        &["DerivationScopeRepository::cache_admissible"],
    ),
    // untenanted: `claim_themes`; the candidates in those themes are read
    // through the viewer (`candidates_in_themes_at_dim`).
    (
        "diverse_retrieval.rs",
        "run_diverse_pipeline_conn",
        &["ClaimThemeRepository::find_similar_themes_at_dim"],
    ),
    // narrows
    (
        "ds_divergence.rs",
        "rebuild_beta_track",
        &["DerivationScopeRepository::cache_admissible"],
    ),
    // write: the divergence row of a BBA the fn just counted.
    (
        "ds_divergence.rs",
        "track_counted_bba",
        &["record_divergence"],
    ),
    // derive (the source interval and its locality) + write (the frame
    // assignment and the BBA in the edge's slot) + calibration.
    (
        "edge_factor.rs",
        "auto_wire_ds_for_edge",
        &[
            "FrameRepository::assign_claim",
            "MassFunctionRepository::store_in_slot",
            "edge_intra_locality_factor",
            "edge_source_is_intra",
            "sqlx::query_as(SELECT).fetch_optional",
        ],
    ),
    // keyed: whether the edge the caller just wrote is in force.
    (
        "edge_factor.rs",
        "auto_wire_edge_if_epistemic",
        &["EdgeRepository::is_in_force"],
    ),
    // calibration (`fold_profile`) + narrows.
    (
        "edge_factor.rs",
        "compute_combined_belief",
        &["fold_profile"],
    ),
    (
        "edge_factor.rs",
        "compute_combined_belief_over",
        &["derivation_scope::retain_for_cache", "fold_profile"],
    ),
    // write: the canonical binary frame, created once.
    (
        "edge_factor.rs",
        "ensure_binary_frame_row",
        &["FrameRepository::create"],
    ),
    // calibration
    ("edge_factor.rs", "frame_fold_profile", &["fold_profile"]),
    // write: the cache of a claim the fn folded through its viewer.
    (
        "edge_factor.rs",
        "recompute_combined_belief",
        &[
            "MassFunctionRepository::update_claim_belief",
            "MassFunctionRepository::update_claim_classification",
        ],
    ),
    // keyed: `is_current` of the claim `roles_batch` just read through the
    // viewer (an unreadable claim answers `NotVisible` before it).
    (
        "edge_factor.rs",
        "vacate_refusal",
        &["sqlx::query_scalar(SELECT).fetch_optional"],
    ),
    // write
    (
        "edge_factor.rs",
        "write_atom_cache",
        &[
            "MassFunctionRepository::update_claim_belief",
            "MassFunctionRepository::update_claim_classification",
        ],
    ),
    // untenanted: agent names through migration 309's disclosure definer, on
    // the caller's stamped connection (MCP `server.read_as`).
    (
        "export/prov.rs",
        "export_provenance_prov_o",
        &["AgentDisclosureRepository::names"],
    ),
    // audit: the caller's own recall event, written as its own principal.
    (
        "recall.rs",
        "log_recall_event",
        &["RecallEventRepository::log", "write_as_principal"],
    ),
    // session: a bypass viewer's connection must be the bypass session.
    ("recall.rs", "recall", &["assert_conn_spends_bypass"]),
    // untenanted: `claim_themes`.
    (
        "recall.rs",
        "theme_leg_reads",
        &["ClaimThemeRepository::find_similar_themes_at_dim"],
    ),
    // audit: the principal's own personal group on its own stamp, then its
    // event.
    (
        "recall.rs",
        "write_as_principal",
        &[
            "GroupMembershipRepository::visible_personal_group_conn",
            "RecallEventRepository::log",
        ],
    ),
    // maintenance: the supersede cascade's stayed-edge BBAs
    // (`RETIRED_SOURCE_EDGE_BBAS_SQL`).
    (
        "retraction_cascade.rs",
        "cascade_after_supersede",
        &["supersede_delta::retired_source_edge_bbas"],
    ),
    // write: the cascade's invalidations and repairs.
    (
        "retraction_cascade.rs",
        "invalidate_and_rewire",
        &["MassFunctionRepository::delete_for_edge"],
    ),
    (
        "retraction_cascade.rs",
        "invalidate_only",
        &[
            "MassFunctionRepository::delete_for_edge",
            "delete_exact_edge_rows",
        ],
    ),
    (
        "retraction_cascade.rs",
        "mark_duplicate_with_cascade",
        &["ClaimRepository::mark_duplicate_with_repair_conn"],
    ),
    // write + keyed: the clear, then whether the claim (whose BBAs the fn
    // just read through its viewer) still holds a cache.
    (
        "retraction_cascade.rs",
        "mark_unbacked_if_evidence_free",
        &[
            "MassFunctionRepository::clear_claim_belief",
            "claim_holds_belief_cache",
        ],
    ),
    (
        "retraction_cascade.rs",
        "repair_one",
        &["MassFunctionRepository::clear_claim_belief"],
    ),
    // narrows
    (
        "scoped_belief.rs",
        "fold_scope_rows",
        &["derivation_scope::retain_for_cache"],
    ),
    (
        "scoped_belief.rs",
        "global_fold",
        &["derivation_scope::retain_for_cache"],
    ),
    // write
    (
        "scoped_belief.rs",
        "refresh_one",
        &["ScopedBeliefRepository::upsert"],
    ),
    // untenanted: the same-human binding.
    (
        "source_dependence.rs",
        "bba_sources_for_rows",
        &["AgentRepository::humans_of"],
    ),
    // privileged: the supersede dry-run delta and its K10/R-131/R-173 blocks.
    (
        "supersede_delta.rs",
        "delta_block",
        &["sqlx::query_as(dynamic).fetch_all"],
    ),
    (
        "supersede_delta.rs",
        "measure",
        &[
            "r131_report",
            "sqlx::query_as(SELECT).fetch_one",
            "sqlx::query_as(dynamic).fetch_all",
            "supersedes_edge_bbas",
        ],
    ),
    (
        "supersede_delta.rs",
        "measure_k10_retro",
        &[
            "retired_source_edge_bbas",
            "sqlx::query_scalar(dynamic).fetch_one",
        ],
    ),
    // privileged + session
    (
        "supersede_delta.rs",
        "r173_chunked",
        &[
            "begin_read_only",
            "begin_read_only",
            "begin_read_only",
            "r173::candidates",
            "r173::snapshot",
            "r173::snapshot",
            "set_statement_timeout",
            "set_statement_timeout",
            "set_statement_timeout",
        ],
    ),
    (
        "supersede_delta.rs",
        "r173_in_one",
        &["r173::candidates", "r173::snapshot"],
    ),
    // session
    (
        "supersede_delta.rs",
        "run_read_only",
        &["begin_read_only", "set_statement_timeout"],
    ),
    // privileged
    (
        "supersede_delta/r173.rs",
        "stored_and_roles",
        &["sqlx::query_as(dynamic).fetch_all"],
    ),
    // write: the act, after `scoped_keys` read the claims through the viewer;
    // the repo act decides the caller's authority itself.
    (
        "visibility_act.rs",
        "publicize_claims",
        &["ClaimRepository::publicize_conn"],
    ),
    // untenanted: the act's own definer classifies the claims the walk read
    // through the viewer (`EdgeRepository::claim_neighbors_for_selection`),
    // against the STAMPED session's readable groups, never acting: one extra
    // id that names no claim makes it return before it writes, inside a
    // savepoint always rolled back (`ClaimRepository::preview_*_conn`). It
    // returns only the ids it was handed, with an outcome word; an unreadable
    // root is `not_found` and answered as missing (backlog 02d9e9a1).
    (
        "visibility_act.rs",
        "plan",
        &["preview", "preview", "preview"],
    ),
    // session: the savepoint a dry run's trial of the act runs in, always
    // rolled back and released (backlog 02d9e9a1); the act and the reads
    // before and after it are handed the viewer.
    (
        "visibility_act.rs",
        "trial",
        &[
            "sqlx::query(RELEASE).execute",
            "sqlx::query(ROLLBACK).execute",
            "sqlx::query(SAVEPOINT).execute",
        ],
    ),
    // privileged: refuses a non-bypass viewer before any statement.
    (
        "visibility_act.rs",
        "rebuild_moved_beta_tracks",
        &[
            "sqlx::query(DELETE).execute",
            "sqlx::query_as(SELECT).fetch_optional",
            "sqlx::query_scalar(SELECT).fetch_all",
        ],
    ),
    // keyed: which of the claims the act just moved the session cannot write.
    (
        "visibility_act.rs",
        "refold_moved",
        &["ClaimRepository::claims_not_writable_on_session"],
    ),
    // write
    (
        "visibility_act.rs",
        "share_claims_with_team",
        &["ClaimRepository::share_with_team_conn"],
    ),
];

/// For every engine fn that holds more than one viewer, the calls that ONE of
/// its viewers covers alone, keyed `(file, fn, viewer)` by the viewer that
/// does NOT cover them: what that viewer would leave unviewed if the fn held
/// it alone. Measured and reviewed on **2026-11-26**.
///
/// Every such fn today is an `admin_cascade.rs` entry point holding the
/// maintenance connection's bypass viewer (`admin_viewer`) and the caller's
/// (`caller`):
///
/// * under `caller` (handed only `admin_viewer`): the cascade itself, on the
///   maintenance connection (the module doc's rule), the supersede edge
///   migration inside its `repair_with_audit!` closure, and the un-mark act it
///   re-reads there. Their result reaches the caller only as counts and
///   through `report_for_caller` / `retirement_for_caller`.
/// * under `admin_viewer` (handed only `caller`): exactly those two filters.
///
/// A fn absent here has no call that only one of its viewers covers. A NEW
/// read handed `admin_viewer` alone shows up as a new label under `caller`.
const SPLIT_CALLS: &[(&str, &str, &str, &[&str])] = &[
    (
        "admin_cascade.rs",
        "apply_after_dedup",
        "admin_viewer",
        &["report_for_caller"],
    ),
    (
        "admin_cascade.rs",
        "apply_after_dedup",
        "caller",
        &["cascade_after_dedup"],
    ),
    (
        "admin_cascade.rs",
        "apply_after_supersede",
        "admin_viewer",
        &["report_for_caller"],
    ),
    (
        "admin_cascade.rs",
        "apply_after_supersede",
        "caller",
        &[
            "ClaimRepository::migrate_superseded_edges_to_head_conn",
            "cascade_after_supersede",
        ],
    ),
    (
        "admin_cascade.rs",
        "apply_match_retire",
        "admin_viewer",
        &["report_for_caller", "retirement_for_caller"],
    ),
    (
        "admin_cascade.rs",
        "apply_match_retire",
        "caller",
        &["retraction_cascade::cascade_after_edge_withdrawal"],
    ),
    (
        "admin_cascade.rs",
        "apply_unmark_checked",
        "admin_viewer",
        &["report_for_caller"],
    ),
    (
        "admin_cascade.rs",
        "apply_unmark_checked",
        "caller",
        &[
            "ClaimRepository::unmark_duplicate_act_authorized_conn",
            "cascade_after_dedup",
        ],
    ),
];

/// The multi-viewer fns [`SPLIT_CALLS`] covers, including those whose split is
/// empty (every call is handed both viewers): the population that register is
/// a statement about.
const MULTI_VIEWER_FNS: &[(&str, &str)] = &[
    ("admin_cascade.rs", "apply_after_dedup"),
    ("admin_cascade.rs", "apply_after_supersede"),
    ("admin_cascade.rs", "apply_match_retire"),
    ("admin_cascade.rs", "apply_unmark"),
    ("admin_cascade.rs", "apply_unmark_authorized"),
    ("admin_cascade.rs", "apply_unmark_checked"),
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

/// Every `.rs` file under `src/`, keyed by its path relative to `src/`
/// (`supersede_delta/r173.rs`).
fn engine_files() -> Vec<(String, String)> {
    let root = src_dir();
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    assert!(
        out.len() > 40,
        "expected the engine's whole source tree, found {} files",
        out.len()
    );
    out
}

fn measure_engine() -> (Measured, usize, usize, Population) {
    let mut out = Measured::new();
    let mut pop = Population::new();
    let (mut n_fns, mut n_calls) = (0, 0);
    for (file, src) in engine_files() {
        let (f, c) = viewer_calls::measure_source(&file, &src, &ENGINE, &mut out, &mut pop);
        n_fns += f;
        n_calls += c;
    }
    (out, n_fns, n_calls, pop)
}

/// For every fn in `src` holding more than one viewer: into `out`,
/// `(file, fn, viewer) -> sorted labels` of the calls the fn views that
/// `viewer` alone would leave unviewed (those only its other viewers cover);
/// into `multi`, the fn.
fn split_source(
    file: &str,
    src: &str,
    out: &mut BTreeMap<(String, String, String), Vec<String>>,
    multi: &mut BTreeSet<(String, String)>,
) {
    let (code, sql) = viewer_calls::views(src);
    let holders = viewer_calls::holders(&code, &sql, &ENGINE, &viewer_calls::struct_fields(&code));
    for h in &holders {
        if h.viewers.len() < 2 {
            continue;
        }
        multi.insert((file.to_string(), h.name.clone()));
        let nested: Vec<(usize, usize)> = holders
            .iter()
            .map(|o| o.body)
            .filter(|&(x, y)| h.body.0 < x && y < h.body.1)
            .collect();
        let all = viewer_calls::db_calls(src, &code, &sql, h, &nested, &ENGINE);
        for others in &h.viewers {
            // The calls a holder that kept every viewer BUT `others` leaves
            // unviewed, which the full holder views: those `others` alone
            // covers. Reported under the viewer it covers them for.
            let rest: Vec<String> = h.viewers.iter().filter(|v| v != &others).cloned().collect();
            let without = viewer_calls::Holder {
                name: h.name.clone(),
                viewers: rest.clone(),
                body: h.body,
                pools: h.pools.clone(),
                conns: h.conns.clone(),
                states: h.states.clone(),
            };
            let measured = viewer_calls::db_calls(src, &code, &sql, &without, &nested, &ENGINE);
            assert_eq!(
                all.len(),
                measured.len(),
                "the viewer set does not change which calls are found"
            );
            let mut only: Vec<String> = all
                .iter()
                .zip(&measured)
                .filter(|(a, b)| a.1 && !b.1)
                .map(|(a, _)| a.0.clone())
                .collect();
            if only.is_empty() {
                continue;
            }
            only.sort();
            // Keyed by the viewer(s) the call is NOT covered by: for a
            // two-viewer fn, the one left after removing `others`.
            out.insert((file.to_string(), h.name.clone(), rest.join("+")), only);
        }
    }
}

/// In an engine fn that holds a viewer, every database call whose arguments
/// and statement do not spend that viewer is named in [`REVIEWED_CALLS`]
/// (backlog 37e68f5b). See the register's doc for the reason classes and
/// `epigraph-db/tests/viewer_calls/mod.rs` for what the scanner counts.
#[test]
fn every_unviewed_database_call_in_a_viewer_engine_fn_is_reviewed() {
    let (measured, _, _, _) = measure_engine();
    let report = viewer_calls::drift(&measured, &viewer_calls::register(REVIEWED_CALLS));
    assert!(
        report.is_empty(),
        "viewer-holding engine fns' unviewed database calls drifted from REVIEWED_CALLS.\n\
         A NEW call is a statement, repo call or helper handed a database handle, in a fn \
         that holds a viewer, with neither the viewer in its arguments nor a spend marker \
         in its statement: give it the viewer, or read it and register it with a reason \
         class. A GONE call must be removed from REVIEWED_CALLS.\n{report}"
    );
}

/// In an engine fn that holds two viewers, the calls only one of them covers
/// are exactly [`SPLIT_CALLS`], so a read handed the maintenance viewer cannot
/// pass for one handed the caller's.
#[test]
fn every_call_one_viewer_of_a_multi_viewer_engine_fn_covers_alone_is_reviewed() {
    let mut measured = BTreeMap::new();
    let mut multi = BTreeSet::new();
    for (file, src) in engine_files() {
        split_source(&file, &src, &mut measured, &mut multi);
    }
    let want_multi: BTreeSet<(String, String)> = MULTI_VIEWER_FNS
        .iter()
        .map(|(f, n)| ((*f).to_string(), (*n).to_string()))
        .collect();
    assert_eq!(
        multi, want_multi,
        "the engine fns holding more than one viewer changed: review each call only one \
         viewer covers and update MULTI_VIEWER_FNS and SPLIT_CALLS"
    );
    let mut want = BTreeMap::new();
    for (file, name, viewer, labels) in SPLIT_CALLS {
        let mut v: Vec<String> = labels.iter().map(|l| (*l).to_string()).collect();
        v.sort();
        let prev = want.insert(
            (
                (*file).to_string(),
                (*name).to_string(),
                (*viewer).to_string(),
            ),
            v,
        );
        assert!(
            prev.is_none(),
            "SPLIT_CALLS lists {file}::{name} {viewer} twice"
        );
    }
    assert_eq!(
        measured, want,
        "the calls only one viewer of a multi-viewer engine fn covers drifted from \
         SPLIT_CALLS (keyed by the viewer that does NOT cover them). A new label under \
         `caller` is a call handed only the maintenance viewer: read it, and give it the \
         caller's viewer if its result reaches the caller."
    );
}

/// The population is the engine's viewer surface, not a corner of it. A
/// scanner that stopped recognising fns or calls would pass the exact-set test
/// above with an empty register.
#[test]
fn the_per_call_scanner_sees_the_whole_engine_viewer_surface() {
    let (measured, fns, calls, pop) = measure_engine();
    eprintln!(
        "population: {fns} viewer-holding engine fns, {calls} database calls, {} with an \
         unviewed call, {} unviewed calls",
        measured.len(),
        measured.values().map(Vec::len).sum::<usize>()
    );
    for (file, f) in [
        // The fix sketch's example: a viewer-taking associated fn in an impl.
        ("bba_retract.rs", "read"),
        // A file under a subdirectory.
        ("supersede_delta/r173.rs", "stored_and_roles"),
        // A two-viewer cascade entry point.
        ("admin_cascade.rs", "apply_after_supersede"),
        // The recall pipeline on one connection.
        ("recall.rs", "recall_on"),
        // The diverse-retrieval pipeline on one connection.
        ("diverse_retrieval.rs", "run_diverse_pipeline_conn"),
    ] {
        assert!(
            pop.contains(&(file.to_string(), f.to_string())),
            "{file}::{f} holds a viewer and must be in the measured population"
        );
    }
    // Floors about 2% under the measurement: a scanner regression that drops
    // fns with no unviewed call (which the register cannot see) fails here.
    // Removing real engine code can trip them too; re-measure and lower them in
    // the same change, with the new numbers.
    assert!(
        fns >= 137,
        "found {fns} viewer-holding engine fns; measured 140 on 2026-11-26"
    );
    assert!(
        calls >= 375,
        "found {calls} database calls in them; measured 383 on 2026-11-26"
    );
}

/// No struct under `src/` carries a viewer into an engine fn. The scanner
/// sees a viewer field only when a fn destructures it (`let Ctx { viewer, ..
/// } = ..`); a fn that took such a struct and read `ctx.viewer` would be
/// outside the population. If one is added, measure its takers.
#[test]
fn no_engine_struct_carries_a_viewer() {
    let mut carriers = Vec::new();
    for (file, src) in engine_files() {
        let (code, _) = viewer_calls::views(&src);
        for name in viewer_calls::viewer_carriers(&viewer_calls::struct_fields(&code)) {
            carriers.push((file.clone(), name));
        }
    }
    assert_eq!(
        carriers,
        Vec::<(String, String)>::new(),
        "an engine struct now carries a viewer: check that every fn receiving one is \
         measured (destructure it, or teach the scanner its access shape)"
    );
}

/// A real engine fn whose viewer handoff is removed by a one-word edit is
/// reported: `RetractCacheBefore::read`, the fix sketch's example, hands the
/// viewer to each of its three reads.
#[test]
fn the_per_call_scanner_reports_a_real_fn_whose_viewer_handoff_is_removed() {
    let src =
        std::fs::read_to_string(src_dir().join("bba_retract.rs")).expect("read bba_retract.rs");
    let key = ("bba_retract.rs".to_string(), "read".to_string());
    let mut clean = Measured::new();
    viewer_calls::measure_source(
        "bba_retract.rs",
        &src,
        &ENGINE,
        &mut clean,
        &mut Population::new(),
    );
    assert!(
        !clean.contains_key(&key),
        "RetractCacheBefore::read hands the viewer to every read: {:?}",
        clean.get(&key)
    );
    let handoff = "MassFunctionRepository::get_by_id(&mut *conn, viewer, mass_function_id)";
    assert!(src.contains(handoff), "the read is in the file");
    let mutated = src.replacen(
        handoff,
        "MassFunctionRepository::get_by_id(&mut *conn, mass_function_id)",
        1,
    );
    let mut broken = Measured::new();
    viewer_calls::measure_source(
        "bba_retract.rs",
        &mutated,
        &ENGINE,
        &mut broken,
        &mut Population::new(),
    );
    assert_eq!(
        broken.get(&key).cloned().unwrap_or_default(),
        vec!["MassFunctionRepository::get_by_id".to_string()],
        "the same read without the viewer is unviewed"
    );
}

/// The two-viewer split catches what the plain register cannot: a content read
/// handed only the maintenance viewer, in a fn that also holds the caller's.
#[test]
fn the_split_reports_a_read_handed_only_the_maintenance_viewer() {
    let src = r##"
pub async fn apply_after_x(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    caller: &Viewer,
    id: Uuid,
) -> R {
    let report = cascade_after_x(&mut *admin, admin_viewer, id).await;
    let leaked = ClaimRepository::get_content(&mut *admin, admin_viewer, id).await?;
    Ok((report_for_caller(admin, caller, &report).await, leaked))
}
"##;
    let mut plain = Measured::new();
    viewer_calls::measure_source(
        "fixture.rs",
        src,
        &ENGINE,
        &mut plain,
        &mut Population::new(),
    );
    assert!(
        plain.is_empty(),
        "the plain register counts every call here as viewed: {plain:?}"
    );
    let mut split = BTreeMap::new();
    let mut multi = BTreeSet::new();
    split_source("fixture.rs", src, &mut split, &mut multi);
    let key = |v: &str| {
        (
            "fixture.rs".to_string(),
            "apply_after_x".to_string(),
            v.to_string(),
        )
    };
    assert_eq!(
        split.get(&key("caller")).cloned().unwrap_or_default(),
        vec![
            "ClaimRepository::get_content".to_string(),
            "cascade_after_x".to_string()
        ],
        "under the caller's viewer alone, the maintenance-only read is unviewed"
    );
    assert_eq!(
        split.get(&key("admin_viewer")).cloned().unwrap_or_default(),
        vec!["report_for_caller".to_string()],
    );
}

/// Every engine macro that takes a closure-shaped argument (`|$x:ident|`) is
/// on [`ENGINE`]'s `conn_closure_macros`: today `repair_with_audit!`, which
/// binds the transaction it opens to that parameter. A macro left off the list
/// hides every call its closures make on `&mut tx`.
#[test]
fn every_engine_macro_binding_a_closure_connection_is_on_the_surface() {
    let mut found: Vec<String> = engine_files()
        .iter()
        .flat_map(|(_, src)| viewer_calls::closure_conn_macros(&viewer_calls::views(src).0))
        .collect();
    found.sort();
    let want: Vec<String> = ENGINE
        .conn_closure_macros
        .iter()
        .map(|m| (*m).to_string())
        .collect();
    assert_eq!(
        found, want,
        "an engine macro takes a closure-shaped argument (`|$x:ident|`): if it binds a \
         connection to it, add it to ENGINE.conn_closure_macros and review the calls its \
         closures make"
    );
}

/// The calls inside a `repair_with_audit!` closure, on the transaction the
/// macro opens (`|tx| Repo::f(&mut tx, ..)`), are measured: one handed no
/// viewer is in the plain register, and one handed only the maintenance
/// viewer is in the split under `caller`. Without the macro on the surface,
/// neither is seen (the gap this closes).
#[test]
fn the_per_call_scanner_follows_the_transaction_into_a_repair_closure() {
    let src = r##"
pub async fn apply_after_x(
    admin: &mut sqlx::PgConnection,
    admin_viewer: &Viewer,
    caller: &Viewer,
    trigger: &CascadeTrigger,
    id: Uuid,
) -> R {
    let repaired = repair_with_audit!(
        admin,
        trigger,
        |tx| async {
            let leaked = ClaimRepository::get_content(&mut tx, admin_viewer, id).await?;
            let bare = ClaimRepository::get_by_id(&mut tx, id).await?;
            Ok::<_, DbError>((leaked, bare))
        },
        |r| serde_json::json!({ "n": r.0.len() })
    );
    let report = cascade_after_x(&mut *admin, admin_viewer, id).await;
    Ok((report_for_caller(admin, caller, &report).await, repaired))
}
"##;
    let key = |v: &str| {
        (
            "fixture.rs".to_string(),
            "apply_after_x".to_string(),
            v.to_string(),
        )
    };
    let fn_key = ("fixture.rs".to_string(), "apply_after_x".to_string());

    let mut plain = Measured::new();
    viewer_calls::measure_source(
        "fixture.rs",
        src,
        &ENGINE,
        &mut plain,
        &mut Population::new(),
    );
    assert_eq!(
        plain.get(&fn_key).cloned().unwrap_or_default(),
        vec!["ClaimRepository::get_by_id".to_string()],
        "the viewer-less read in the repair closure is unviewed"
    );
    let mut split = BTreeMap::new();
    let mut multi = BTreeSet::new();
    split_source("fixture.rs", src, &mut split, &mut multi);
    assert_eq!(
        split.get(&key("caller")).cloned().unwrap_or_default(),
        vec![
            "ClaimRepository::get_content".to_string(),
            "cascade_after_x".to_string()
        ],
        "the closure's read handed only the maintenance viewer is under `caller`"
    );

    // The same source with the macro off the surface: the closure's `tx` is an
    // unknown name, and both reads vanish.
    let blind = Surface {
        conn_closure_macros: &[],
        ..ENGINE
    };
    let mut unseen = Measured::new();
    viewer_calls::measure_source(
        "fixture.rs",
        src,
        &blind,
        &mut unseen,
        &mut Population::new(),
    );
    assert!(
        !unseen.contains_key(&fn_key),
        "without the macro on the surface the closure is not measured: {unseen:?}"
    );
}
