//! **The role-blind belief-read ratchet** (SPEC §7.3, DONE criterion D5).
//!
//! A compound's cached belief columns are a fold of its own BBAs, not a
//! value derived from its leaves, so every reader that serves or computes
//! with `claims.belief` / `plausibility` / `pignistic_prob` (or with
//! `truth_value` as a belief) must know the claim's role. This file refuses
//! any NEW reader that does not.
//!
//! # What counts as a reader
//!
//! A **unit** is the innermost `fn` (Rust), the `const` / `static` item, or
//! the Python `def` holding the text; `<module>` otherwise. A unit is a
//! reader when either:
//!
//! * **SQL text**: a string literal that is SQL (UPPER-case keywords, see
//!   `belief_lint::is_sql`), with its SQL comments removed, names
//!   `pignistic_prob`, `plausibility`, `c.belief` / `claims.belief`, or
//!   `truth_value` in a belief context: compared (`<`, `>`, `BETWEEN`),
//!   ordered on (`ORDER BY`), or inside `COALESCE(` / `GREATEST(` / `LEAST(`
//!   / `AVG(`. A `truth_value` that is only projected or assigned is not a
//!   belief read. Scanned: `crates/*/src/**/*.rs` and `scripts/**/*.py`.
//! * **Field read** (Rust only): a `.belief` / `.plausibility` /
//!   `.pignistic_prob` access in a unit that names a **claim row type** or
//!   calls one of its producers. The claim row types are DERIVED, not listed:
//!   a struct in `crates/epigraph-db/src` with one of those fields that some
//!   `epigraph-db` fn returns, that fn not itself dispatching on role
//!   ([`ROW_TYPES`] pins the derived set). A struct only role-dispatched fns
//!   return (such as the non-compound `AtomCache`, whose one producer splices
//!   the compound predicate) holds rows the role already filtered, so its
//!   field reads are not role-blind. Files whose path names `belief_view`
//!   are the sanctioned home of these reads and are not scanned for them.
//! * **Column list** (Rust only, backlog 4e4d6ad4): the unit uses a list of
//!   cache column names (`CACHE_COLUMN_NAMES`, a `const COLS: &str =
//!   "belief, pignistic_prob"`, a fn-local array) that it splices into SQL
//!   with `format!`, directly or through a text-returning helper of its file
//!   (see Known limits for the exact shapes). No SQL literal names the
//!   column, so without this a unit that reads only through such a list
//!   measures as write-only.
//!
//! # Classified, registered, or a finding
//!
//! * A unit whose CODE (not a comment, not a string) names
//!   `IS_COMPOUND_SQL`, `CLAIM_ROLE_SQL`, `is_compound_sql`,
//!   `claim_role_sql`, `claim_role::` or `IS_COMPOUND_DEFINER_CALL` (migration
//!   193's role definer) dispatches on role: it is classified and must NOT be
//!   registered.
//! * Every other reader must be in [`REGISTER`], an exact set keyed
//!   `(path, unit)`. A reader is tagged with the plan PR that converts it
//!   ([`Tag::Todo`]); a unit that only WRITES the columns is tagged
//!   [`Tag::Writer`], and the writer tag is checked: a unit with any non-write
//!   SQL hit or any field read cannot carry it.
//! * **D5 passes only when the register holds writer entries alone**
//!   ([`d5_status`] reports the count, it does not assert it).
//!
//! # Known limits, stated so a green run is not read as more
//!
//! * A role marker classifies the whole unit, not each statement in it, and
//!   a producer's marker takes its row type out of the claim row types,
//!   whichever way the predicate filters (the marker is not parsed).
//! * SQL kept in a `const` is classified by the `const`, which cannot carry
//!   a role marker (the predicate needs `render`); move the role splice to
//!   the fn that builds the statement and the `const` stays registered.
//! * A field read is attributed only when the unit that reads it also names
//!   the row type or calls its producer; a row handed to a helper that names
//!   neither is not seen. Units with the same name in one file share a key.
//! * Lower-case SQL is not SQL to this scan; the tree has none today.
//! * A column list assembled at runtime is measured in these shapes only.
//!   The list is a string literal of identifiers, each optionally qualified,
//!   separated by commas or whitespace, one naming a cache column
//!   (`"belief"`, `"c.belief, c.pignistic_prob"`; SQL text is the SQL
//!   rule's), held by a `const` / `static` (module-, `impl`- or fn-level) or
//!   by a string-only array literal inside a fn (a `let` array, `vec![..]`).
//!   A module- or `impl`-level list is read by every unit, in any file, whose
//!   code names it or whose format string captures it (`"{COLS}"`); a
//!   fn-level one by its fn. A unit calling a fn OF THE SAME FILE that reads
//!   a list and returns text (`String`, `&str`, `Cow`) reads it too,
//!   transitively; propagation stops at a fn returning anything else, which
//!   ran the statement itself. Not seen: a bare literal in a fn outside a
//!   `const` or array (`json!({"belief": x})` is not a list), a list of
//!   `truth_value` (a belief only in context), a list built from parts
//!   (`concat!`, pushed into a `Vec`) or read from elsewhere, a text helper
//!   called from another file, or the callers of a helper that returns the
//!   array itself rather than text. A whole `#[cfg(test)]` module file is
//!   out of scope for this rule.

mod belief_lint;

use belief_lint::{
    balanced_end, find_words, has_word, is_sql, is_write_sql, python_unit_at, python_view,
    rust_fns, rust_sources, rust_view, script_sources, sql_without_comments, with_scratch,
    RustUnits, Source, View,
};
use std::collections::{BTreeMap, BTreeSet};

/// Code tokens that mark a unit as role-dispatched (SPEC §7.3).
const ROLE_MARKERS: &[&str] = &[
    "IS_COMPOUND_SQL",
    "CLAIM_ROLE_SQL",
    "is_compound_sql",
    "claim_role_sql",
    "claim_role::",
    // Migration 193's definer (`public.epigraph_claim_is_compound`), the
    // cache owner rule's own role test, decided on the whole graph with
    // definer rights (backlog bbece56a).
    "IS_COMPOUND_DEFINER_CALL",
];

/// The claim row fields a field read names.
const FIELDS: &[&str] = &["belief", "plausibility", "pignistic_prob"];

/// The claim row types as derived from `crates/epigraph-db/src` (see the
/// module doc). Pinned so a new row type is a visible diff.
const ROW_TYPES: &[&str] = &[
    "AtomicNodeRow",
    "BeliefBoundedClaimHit",
    "ClaimBeliefColumns",
    "CompoundNeighborRow",
    "CompoundNodeRow",
    "DivergenceRow",
    "FrameClaimBeliefHit",
    "GraphNodeRow",
    "GroundedNeighbor",
    "ScopedBeliefRow",
    "SemanticFlatHit",
    "SemanticSelectedClaim",
    "SubgraphClaimRow",
];

/// The plan PRs a reader may be tagged with (IMPL-PLAN rows that convert a
/// reader), plus `unassigned` for a reader no plan row converts yet.
const PLAN_PRS: &[&str] = &[
    "PR-1",
    "PR-5b1",
    "PR-5b2",
    "PR-C2",
    "PR-F2",
    "PR-M1",
    "PR-M2",
    "PR-R1a",
    "PR-R1b",
    "PR-R2",
    "PR-R3",
    "PR-R5",
    "PR-W1a",
    "PR-W1b",
    "PR-W1c",
    "PR-W4",
    "unassigned",
];

#[derive(Clone, Copy, Debug)]
enum Tag {
    /// Writes the columns and reads none of them for a decision.
    Writer(&'static str),
    /// A reader, converted by the named plan PR.
    Todo { pr: &'static str, why: &'static str },
    /// A reader that stays role-blind BY DESIGN, on an operator ruling: it
    /// must read every claim's raw cache columns, compounds included, for a
    /// bit-exact record or restore. Not D5 debt; the reason names the ruling.
    ByDesign(&'static str),
}

/// Every role-blind belief reader (and writer) in the tree today, measured
/// on this branch. A reader names the plan PR that converts it; `unassigned`
/// marks a reader no plan row converts yet (D5 cannot pass while one is
/// left). Sorted by path, then unit.
const REGISTER: &[(&str, &str, Tag)] = &[
    // --- epigraph-api -------------------------------------------------------
    ("crates/epigraph-api/src/routes/belief.rs", "claim_divergence", Tag::Todo { pr: "PR-R1b", why: "REST divergence serves a compound's BetP divergence; SPEC §7.2 reads it as derived, see leaves" }),
    ("crates/epigraph-api/src/routes/belief.rs", "claims_by_belief", Tag::Todo { pr: "PR-R3", why: "REST claims_by_belief range list reads cached Bel/Pl rows; SPEC §7.2 role predicate, compounds by floor row or omitted" }),
    ("crates/epigraph-api/src/routes/belief.rs", "frame_claims_sorted", Tag::Todo { pr: "PR-R3", why: "REST frame_claims_sorted serves cached Bel/Pl rows; SPEC §7.2 role predicate" }),
    ("crates/epigraph-api/src/routes/belief.rs", "get_claim_belief", Tag::Todo { pr: "PR-R1b", why: "REST GET /claims/:id/belief serves the cache columns; SPEC §7.2 BeliefView" }),
    ("crates/epigraph-api/src/routes/belief.rs", "scoped_belief_to_entry", Tag::Todo { pr: "PR-R1b", why: "REST all_scopes_belief maps scoped rows; SPEC §7.2 filters the constant derived scope rows" }),
    ("crates/epigraph-api/src/routes/belief.rs", "submit_evidence", Tag::Todo { pr: "PR-W1a", why: "REST frames/:id/evidence reads and reports the cache around a textless BBA write; SPEC §4.1 W3 guard" }),
    ("crates/epigraph-api/src/routes/belief.rs", "top_divergence", Tag::Todo { pr: "PR-R1b", why: "REST top divergence lists compound BetP divergence rows; SPEC §7.2 derived, see leaves" }),
    ("crates/epigraph-api/src/routes/computation.rs", "apply_bp_updates", Tag::Writer("BP apply writes the cache columns from BP marginals; PR-1 refuses it by default and skips compounds (SPEC D4)")),
    ("crates/epigraph-api/src/routes/experiments.rs", "hypothesize", Tag::Todo { pr: "PR-R5", why: "reads Bel/Pl of semantic_search_flat rows; SPEC §7.2 atoms by cache, compounds by BeliefView" }),
    ("crates/epigraph-api/src/routes/gaps.rs", "gap_analysis", Tag::Todo { pr: "PR-R5", why: "picks work by ignorance from semantic_search_flat rows with a truth_value fallback; SPEC §7.2 excludes compounds" }),
    ("crates/epigraph-api/src/routes/graph.rs", "expand", Tag::Todo { pr: "PR-R3", why: "graph expand serves cluster node BetP; SPEC §7.2 graph view derives compound nodes per viewer" }),
    ("crates/epigraph-api/src/routes/graph_neighborhood.rs", "atomic_response", Tag::Todo { pr: "PR-R3", why: "graph neighbourhood node BetP; SPEC §7.2 graph view" }),
    ("crates/epigraph-api/src/routes/graph_neighborhood.rs", "compound_response", Tag::Todo { pr: "PR-R3", why: "graph neighbourhood compound node BetP is the compound's own cache; SPEC §7.2 derived per viewer" }),
    ("crates/epigraph-api/src/routes/graph_query_utils.rs", "load_subgraph_conn", Tag::Todo { pr: "PR-R5", why: "graph_query / graph / edges subgraph nodes copy the cache columns; SPEC §7.2 BeliefView for compound nodes" }),
    ("crates/epigraph-api/src/routes/hypothesis.rs", "create_hypothesis", Tag::Todo { pr: "PR-W4", why: "hypothesis prior from grounded neighbours' cached Bel/Pl, compounds included (arithmetic: SPEC §7.2 excludes); SPEC §4.1 W13" }),
    ("crates/epigraph-api/src/routes/search.rs", "semantic_search", Tag::Todo { pr: "PR-R5", why: "REST /search/semantic maps c.belief / c.plausibility per hit; SPEC §7.2 BeliefView per hit" }),
    // --- epigraph-cli -------------------------------------------------------
    ("crates/epigraph-cli/src/belief_cache.rs", "cache_equals", Tag::ByDesign("the same operator ruling as write_snapshot: stays role-blind by design; builds restore_wave_with's compare-and-swap probe, every cache column of CACHE_COLUMN_NAMES compared with the wave file's values, and serves no belief")),
    ("crates/epigraph-cli/src/belief_cache.rs", "read_cache_columns", Tag::ByDesign("operator ruling D5 (2026-10-25): stays role-blind by design; reads the raw cache columns of listed claims for a bit-exact record (the wave writer's before/after rows that the CAS restore takes as input) and serves no belief")),
    ("crates/epigraph-cli/src/belief_cache.rs", "restore_scoped", Tag::ByDesign("operator ruling D5 (2026-10-25): stays role-blind by design; PR-C2's compare-and-swap restore of a wave's ds_combined_beliefs rows by row id, whose probe compares the raw stored columns; it serves no belief")),
    ("crates/epigraph-cli/src/belief_cache.rs", "restore_wave_with", Tag::ByDesign("the same operator ruling as write_snapshot: stays role-blind by design; PR-C1's compare-and-swap restore writes a wave's before values back where the columns still equal what it wrote, and its probe reads the stored columns through CACHE_COLUMN_NAMES (measured as a read since backlog 4e4d6ad4); it serves no belief")),
    ("crates/epigraph-cli/src/belief_cache.rs", "write_snapshot", Tag::ByDesign("operator ruling D5 (2026-10-25): stays role-blind by design; the snapshot copies every current claim's raw cache columns, compounds included (the compound-cache cleanup NULLs them only after a snapshot), so it must be bit-exact")),
    ("crates/epigraph-cli/src/bin/analyze_graph.rs", "main", Tag::Todo { pr: "unassigned", why: "operator analysis report buckets claims by truth_value; no plan row converts it" }),
    ("crates/epigraph-cli/src/bin/dekg.rs", "handle_migrate", Tag::Todo { pr: "PR-W4", why: "dekg migrate reads claim Pl to bootstrap raw BBAs; SPEC §4.1 W13" }),
    ("crates/epigraph-cli/src/bin/hypothesis.rs", "create", Tag::Todo { pr: "PR-W4", why: "CLI hypothesis prior from neighbours' cached Bel/Pl; SPEC §4.1 W13" }),
    // --- epigraph-db --------------------------------------------------------
    ("crates/epigraph-db/src/repos/alternative_set.rs", "scan_candidates", Tag::Todo { pr: "PR-R5", why: "suggest_alternative_sets scores pairs by LEAST(COALESCE(pignistic_prob, 0)); SPEC §7.2 excludes compounds, no NULL as 0" }),
    ("crates/epigraph-db/src/repos/analysis.rs", "get_claims_for_analysis", Tag::Todo { pr: "unassigned", why: "analysis selection ordered on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/behavioral_execution.rs", "behavioral_affinity_hierarchical", Tag::Todo { pr: "unassigned", why: "workflow selection gated on truth_value; procedural trees are out of scope (SPEC §4.1 W11), no plan row splices the role" }),
    ("crates/epigraph-db/src/repos/behavioral_execution.rs", "behavioral_affinity_lineage", Tag::Todo { pr: "unassigned", why: "workflow selection gated on truth_value; procedural, no plan row splices the role" }),
    ("crates/epigraph-db/src/repos/claim.rs", "const EFFECTIVE_BELIEF_SCORE_SQL", Tag::Todo { pr: "PR-R1a", why: "the effective-belief choke point (recall, traverse, query_claims); SPEC §7.2 dispatches on role" }),
    ("crates/epigraph-db/src/repos/claim.rs", "const FILTER_WHERE", Tag::Todo { pr: "unassigned", why: "ClaimRepository::list min/max truth filter on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/claim.rs", "dispute_batch", Tag::Todo { pr: "PR-R2", why: "recall's dispute read orders contradicting sources by truth_value; SPEC §7.2 dispute roll-up" }),
    ("crates/epigraph-db/src/repos/claim.rs", "frame_claims_sorted", Tag::Todo { pr: "PR-R3", why: "range list on c.belief / c.plausibility; SPEC §7.2 role predicate" }),
    ("crates/epigraph-db/src/repos/claim.rs", "get_belief_columns", Tag::Todo { pr: "PR-R1a", why: "the cache read under get_belief; SPEC §7.2 choke point" }),
    ("crates/epigraph-db/src/repos/claim.rs", "get_high_truth", Tag::Todo { pr: "unassigned", why: "list gated on truth_value; no non-test caller and no plan row" }),
    ("crates/epigraph-db/src/repos/claim.rs", "get_low_truth", Tag::Todo { pr: "unassigned", why: "list gated on truth_value; no non-test caller and no plan row" }),
    ("crates/epigraph-db/src/repos/claim.rs", "grounded_neighborhood", Tag::Todo { pr: "PR-W4", why: "hypothesis neighbourhood returns c.belief / c.plausibility; SPEC §4.1 W13" }),
    ("crates/epigraph-db/src/repos/claim.rs", "list_by_belief_bounds", Tag::Todo { pr: "PR-R3", why: "range list on c.belief / c.plausibility; SPEC §7.2 floor row or omitted" }),
    ("crates/epigraph-db/src/repos/claim.rs", "list_by_labels", Tag::Todo { pr: "unassigned", why: "query_claims_by_label min-truth gate on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/claim.rs", "rag_hybrid_context", Tag::Todo { pr: "unassigned", why: "RAG context ranked and gated on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/claim.rs", "retire_for_workflow_deprecation", Tag::Writer("one UPDATE retires a workflow claim and records its own prior truth_value in properties for a later revival (backlog 1767f2ae); it serves no belief")),
    ("crates/epigraph-db/src/repos/claim.rs", "search_by_label_and_text", Tag::Todo { pr: "unassigned", why: "workflow text search gated on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/claim.rs", "semantic_graph_neighbors", Tag::Todo { pr: "PR-R5", why: "semantic search graph expansion returns c.belief / c.plausibility; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim.rs", "semantic_search_flat_on", Tag::Todo { pr: "PR-R5", why: "the semantic_search_flat row carries c.belief / c.plausibility (the statement moved into the connection form, backlog 28b79b1e); SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim.rs", "semantic_selected_claims", Tag::Todo { pr: "PR-R5", why: "the diverse /search/semantic row carries c.belief / c.plausibility, the read moved out of routes/search.rs's inline full_sql (backlog 67c905a3); SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim.rs", "sql_expr", Tag::Todo { pr: "PR-R3", why: "BeliefSort column for frame_claims_sorted; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim_visibility.rs", "mirror_refolded_cache_into_truth_conn", Tag::Writer("one UPDATE copies a widened claim's refolded pignistic_prob into its own truth_value on the act's stamped transaction (backlog 0d9dfd24); it serves no belief")),
    ("crates/epigraph-db/src/repos/divergence.rs", "get_latest", Tag::Todo { pr: "PR-R1b", why: "divergence row BetP; SPEC §7.2 derived, see leaves" }),
    ("crates/epigraph-db/src/repos/divergence.rs", "store", Tag::Writer("writes ds_bayesian_divergence.pignistic_prob; reads no claim belief")),
    ("crates/epigraph-db/src/repos/divergence.rs", "top_divergent", Tag::Todo { pr: "PR-R1b", why: "divergence rows ordered by BetP gap; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/edge.rs", "count_claims_attributed_to", Tag::Todo { pr: "unassigned", why: "agent attribution count gated on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/edge.rs", "get_claims_attributed_to", Tag::Todo { pr: "unassigned", why: "agent attribution list gated on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/factor.rs", "bp_priors", Tag::Todo { pr: "PR-1", why: "BP propagation seeds from cached BetP, compounds included; SPEC D4 (BP machinery excludes compounds). Moved from routes/computation.rs::propagate_beliefs (backlog 073d24a3). Also serves graph/compose's node beliefs, compounds included, which was routes/computation.rs::compose_subgraphs' own unassigned Todo until backlog 52b96600 moved its read here" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "compound_neighbors", Tag::Todo { pr: "PR-R3", why: "graph view compound neighbour BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "expand_cluster_nodes", Tag::Todo { pr: "PR-R3", why: "graph view cluster node BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "neighborhood_atomic_nodes", Tag::Todo { pr: "PR-R3", why: "graph view node BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "neighborhood_compound_nodes", Tag::Todo { pr: "PR-R3", why: "graph view compound node BetP is the compound's own cache; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "subgraph_claims", Tag::Todo { pr: "PR-R5", why: "subgraph rows behind graph_query_utils carry the cache columns; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "theme_neighborhoods", Tag::Todo { pr: "PR-R3", why: "graph view neighbourhood mean BetP over the viewer's readable members, compounds included; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/mass_function.rs", "clear_claim_belief", Tag::Writer("NULLs the cache columns; reads none (SPEC §4.2 stops calling it on atoms)")),
    ("crates/epigraph-db/src/repos/mass_function.rs", "update_claim_belief", Tag::Writer("writes the cache columns; reads none")),
    ("crates/epigraph-db/src/repos/method.rs", "get_evidence_strength", Tag::Todo { pr: "PR-M2", why: "aggregates BetP / truth_value over claims, compounds included; SPEC §7.2 excludes compounds" }),
    ("crates/epigraph-db/src/repos/policy.rs", "list_active_network", Tag::Todo { pr: "unassigned", why: "policy claims gated and ordered on truth_value; no plan row converts it (moved from routes/policies.rs::list_network_policies)" }),
    ("crates/epigraph-db/src/repos/scoped_belief.rs", "get", Tag::Todo { pr: "PR-R1b", why: "scoped belief row read; SPEC §7.2 filters the constant derived scope rows" }),
    ("crates/epigraph-db/src/repos/scoped_belief.rs", "list_for_claim", Tag::Todo { pr: "PR-R1b", why: "returns every scoped row; SPEC §7.2 filters the constant derived scope rows" }),
    ("crates/epigraph-db/src/repos/scoped_belief.rs", "list_for_scope", Tag::Todo { pr: "PR-R1b", why: "scoped rows per scope; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/scoped_belief.rs", "upsert", Tag::Writer("writes ds_combined_beliefs rows (SPEC §8 T3 floor-row writer); reads none")),
    ("crates/epigraph-db/src/repos/sheaf.rs", "get_claim_neighbor_betp_pairs", Tag::Todo { pr: "PR-M1", why: "sheaf neighbour BetP pairs include compound endpoints; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/sheaf.rs", "get_epistemic_edge_pairs", Tag::Todo { pr: "PR-M1", why: "sheaf edge pairs include compound endpoints; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/structural.rs", "belief_intervals", Tag::Todo { pr: "PR-M2", why: "structural belief intervals over claims, compounds included; SPEC §7.2 excludes compounds" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "executed_structural_claims", Tag::Todo { pr: "unassigned", why: "workflow claims gated on truth_value; procedural (SPEC §4.1 W11), no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "find_by_embedding", Tag::Todo { pr: "unassigned", why: "workflow search gated and scored on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "find_by_text", Tag::Todo { pr: "unassigned", why: "workflow search gated and scored on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "find_hierarchical_by_embedding", Tag::Todo { pr: "unassigned", why: "workflow search gated on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "list", Tag::Todo { pr: "unassigned", why: "workflow list ordered on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "list_hierarchical_lineage_heads", Tag::Todo { pr: "unassigned", why: "workflow lineage enumeration gated on its generations' truth_value (deprecation, highest live generation); procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "search_hierarchical_by_embedding_scored", Tag::Todo { pr: "unassigned", why: "workflow search scored on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "search_hierarchical_by_text", Tag::Todo { pr: "unassigned", why: "workflow search scored on truth_value; procedural, no plan row" }),
    // --- epigraph-engine ----------------------------------------------------
    ("crates/epigraph-engine/src/belief_query.rs", "get_belief_conn", Tag::Todo { pr: "PR-R1a", why: "the get_belief choke point (body in get_belief_conn; the pool forms delegate) serves the cache columns; SPEC §7.2 dispatches on role" }),
    ("crates/epigraph-engine/src/edge_factor.rs", "auto_wire_ds_for_edge", Tag::Todo { pr: "PR-F2", why: "builds an edge BBA from the source's cached Bel/Pl, compound sources included; SPEC §4.1 W8" }),
    ("crates/epigraph-engine/src/retraction_cascade.rs", "claim_holds_belief_cache", Tag::Todo { pr: "unassigned", why: "the retraction cascade's report reads whether a claim still holds any cache column (the columns clear_claim_belief's guard tests) to tell a declined clear from nothing to clear, compounds included; it decides only the report's bucket and serves no belief" }),
    ("crates/epigraph-engine/src/supersede_delta.rs", "delta_block", Tag::Todo { pr: "unassigned", why: "the supersede dry-run delta (supersede SPEC §11 K0) reads the raw cache that the supersede cascade's repair recomputes, compounds included, to report old beside new; role-aware when that repair is" }),
    // --- epigraph-jobs ------------------------------------------------------
    ("crates/epigraph-jobs/src/cluster_graph/neighborhood.rs", "run_one_theme", Tag::Todo { pr: "unassigned", why: "theme neighbourhood BetP; SPEC §7.2 calls it atoms-only, but the predicate is not the IS_COMPOUND_SQL spelling" }),
    ("crates/epigraph-jobs/src/cluster_graph/runner.rs", "run_clustering", Tag::Todo { pr: "PR-M2", why: "cluster mean_betp over claims, compounds included; SPEC §7.2" }),
    // --- epigraph-mcp -------------------------------------------------------
    ("crates/epigraph-mcp/src/tools/claims.rs", "update_with_evidence", Tag::Todo { pr: "PR-5b1", why: "reads the cache for the monotonicity clamp and the response; SPEC §4.1 W1" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "get_divergence", Tag::Todo { pr: "PR-R1b", why: "MCP divergence serves BetP; SPEC §7.2" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "scoped_belief", Tag::Todo { pr: "PR-R1b", why: "MCP scoped_belief serves scoped rows; SPEC §7.2" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "submit_ds_evidence", Tag::Todo { pr: "PR-W1a", why: "reads and reports the cache around a textless BBA write; SPEC §4.1 W3" }),
    ("crates/epigraph-mcp/src/tools/ds_auto.rs", "auto_wire_ds_update_filed_on", Tag::Todo { pr: "PR-5b1", why: "reads the cached BetP as the clamp's prior; SPEC §4.1 W1" }),
    ("crates/epigraph-mcp/src/tools/link_epistemic.rs", "do_link_epistemic", Tag::Todo { pr: "PR-W1b", why: "reads the source's cache to wire an edge and reports the target's; SPEC §4.1 W7" }),
    ("crates/epigraph-mcp/src/tools/recall.rs", "fetch_batched_context", Tag::Todo { pr: "PR-R2", why: "recall_with_context context rows gated on truth_value; SPEC §7.2" }),
    // --- scripts ------------------------------------------------------------
    ("scripts/label_themes_llm.py", "load_neighborhoods_with_samples", Tag::Todo { pr: "unassigned", why: "orders a neighbourhood's public sample claims by cached BetP for the labelling prompt, compounds included; no plan row converts it" }),
    ("scripts/migrate_provenance_bba.py", "census", Tag::Todo { pr: "PR-W4", why: "seed-migration census on truth_value; SPEC §4.1 W13 script, frozen" }),
];

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// What a unit reads, as the ratchet measured it.
#[derive(Debug, Default)]
struct Unit {
    /// SQL kinds and `.field` reads found.
    kinds: BTreeSet<String>,
    /// Some hit is a read: a non-write SQL statement, or a field read.
    reads: bool,
    /// The unit names a role marker in code.
    marked: bool,
}

type Measured = BTreeMap<(String, String), Unit>;

/// Is `truth_value` used as a belief in this SQL? Compared, ordered on, or
/// an argument of a fallback / aggregate function.
fn truth_value_as_belief(sql: &str) -> bool {
    let b = sql.as_bytes();
    find_words(sql, "truth_value").into_iter().any(|at| {
        let after = sql[at + "truth_value".len()..].trim_start();
        if after.starts_with('<') || after.starts_with('>') || after.starts_with("BETWEEN") {
            return true;
        }
        let mut q = at;
        if q >= 1 && b[q - 1] == b'.' {
            q -= 1;
            while q > 0 && (b[q - 1].is_ascii_alphanumeric() || b[q - 1] == b'_') {
                q -= 1;
            }
        }
        let before = sql[..q].trim_end();
        let before = before.strip_suffix('=').unwrap_or(before);
        if before.ends_with('<') || before.ends_with('>') {
            return true;
        }
        if let Some(ob) = sql[..at].rfind("ORDER BY") {
            let between = &sql[ob..at];
            if !["SELECT", "FROM", "WHERE", "LIMIT", ";", ")"]
                .iter()
                .any(|k| between.contains(k))
            {
                return true;
            }
        }
        ["COALESCE(", "GREATEST(", "LEAST(", "AVG("]
            .iter()
            .any(|f| {
                sql[..at].rfind(f).is_some_and(|p| {
                    let span = &sql[p..at];
                    span.matches('(').count() > span.matches(')').count()
                })
            })
    })
}

/// The belief columns this SQL reads (or writes).
fn sql_kinds(sql: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for col in ["pignistic_prob", "plausibility"] {
        if has_word(sql, col) {
            out.insert(col.to_string());
        }
    }
    let b = sql.as_bytes();
    if find_words(sql, "belief").into_iter().any(|at| {
        ["c.", "claims."].iter().any(|q| {
            at >= q.len()
                && &sql[at - q.len()..at] == *q
                && (at == q.len()
                    || !(b[at - q.len() - 1].is_ascii_alphanumeric()
                        || b[at - q.len() - 1] == b'_'))
        })
    }) {
        out.insert("claims.belief".to_string());
    }
    if truth_value_as_belief(sql) {
        out.insert("truth_value".to_string());
    }
    out
}

/// The claim row types and their producers, derived from the
/// `crates/epigraph-db/src` sources in `rust`: `(row types, producers)`,
/// a producer being `(impl type, fn name)`. A fn whose code names a role
/// marker is role-dispatched and produces no claim row type: a struct only
/// such fns return is not one.
fn claim_row_types(rust: &[Source]) -> (BTreeSet<String>, BTreeSet<(Option<String>, String)>) {
    let mut candidates = BTreeSet::new();
    let mut fns_by_file = Vec::new();
    for s in rust
        .iter()
        .filter(|s| s.path.starts_with("crates/epigraph-db/src/"))
    {
        let view = rust_view(&s.text);
        let code = &view.code;
        for at in find_words(code, "struct") {
            let rest = &code[at + "struct".len()..];
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let Some(open_rel) = rest.find(['{', ';', '(']) else {
                continue;
            };
            if rest.as_bytes()[open_rel] != b'{' || name.is_empty() {
                continue;
            }
            let open = at + "struct".len() + open_rel;
            let end = belief_lint::balanced_end(code, open, b'{', b'}');
            let body = &code[open..end];
            let has_field = FIELDS.iter().any(|f| {
                find_words(body, f).into_iter().any(|p| {
                    let after = body[p + f.len()..].trim_start();
                    after.starts_with(':') && !after.starts_with("::")
                })
            });
            if has_field {
                candidates.insert(name);
            }
        }
        fns_by_file.push((view.code.clone(), rust_fns(&view.code)));
    }
    let mut types = BTreeSet::new();
    let mut producers = BTreeSet::new();
    for (code, fns) in &fns_by_file {
        for f in fns {
            let text = f.text(code);
            if ROLE_MARKERS.iter().any(|m| text.contains(m)) {
                continue;
            }
            let ret = f.return_type(code);
            for t in &candidates {
                if has_word(ret, t) {
                    types.insert(t.clone());
                    producers.insert((f.impl_type.clone(), f.name.clone()));
                }
            }
        }
    }
    (types, producers)
}

/// Does `text` call `name` as `::name(` / `.name(` (turbofish allowed)?
fn calls(text: &str, name: &str) -> bool {
    find_words(text, name).into_iter().any(|at| {
        let before = text[..at].trim_end();
        let qualified =
            before.ends_with("::") || (before.ends_with('.') && !before.ends_with(".."));
        let after = text[at + name.len()..].trim_start();
        let after = after
            .strip_prefix("::<")
            .map(|r| r.find('>').map_or("", |e| r[e + 1..].trim_start()))
            .unwrap_or(after);
        qualified && after.starts_with('(')
    })
}

/// Offsets of `.belief` / `.plausibility` / `.pignistic_prob` field reads
/// (not method calls) in a code view, with the field name.
fn field_reads(code: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for f in FIELDS {
        for at in find_words(code, f) {
            let before = code[..at].trim_end();
            if !before.ends_with('.') || before.ends_with("..") {
                continue;
            }
            if code[at + f.len()..].trim_start().starts_with('(') {
                continue;
            }
            out.push((at, *f));
        }
    }
    out
}

/// The files of `rust` that are whole `#[cfg(test)]` modules: `<name>.rs`
/// declared `#[cfg(test)] mod <name>;` by its parent module (such as
/// `epigraph-atlas-contract/src/tests.rs`). `rust_view` blanks a test item
/// inside a file, not a test module kept in a file of its own, and a unit
/// test's fixture list is not a served read.
fn test_module_files(rust: &[Source]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in rust {
        // The raw text: `rust_view` blanks the `#[cfg(test)]` declaration
        // itself.
        let code = &s.text;
        for at in find_words(code, "mod") {
            let Some(attr) = code[..at].trim_end().strip_suffix(']') else {
                continue;
            };
            let attr = attr.trim_end();
            let attr = attr.strip_suffix("pub(crate)").unwrap_or(attr).trim_end();
            if !attr.ends_with("#[cfg(test)") {
                continue;
            }
            let rest = code[at + 3..].trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || !rest[name.len()..].trim_start().starts_with(';') {
                continue; // an inline `mod name { .. }`, already blanked
            }
            let (dir, file) = s.path.rsplit_once('/').unwrap_or(("", &s.path));
            let parent = match file {
                "lib.rs" | "main.rs" | "mod.rs" => dir.to_string(),
                f => format!("{dir}/{}", f.trim_end_matches(".rs")),
            };
            out.insert(format!("{parent}/{name}.rs"));
        }
    }
    out
}

/// Is `lit` a column list naming a cache column: one or more identifiers,
/// each optionally qualified (`c.belief`), separated by commas or
/// whitespace, one of them ending in a [`FIELDS`] name? `"belief"` and
/// `"belief, pignistic_prob"` are; a statement is not (an UPPER-case
/// keyword token: the SQL rule reads it, and a SQL `const` is registered as
/// itself), nor is any other text.
fn is_column_list_text(lit: &str) -> bool {
    let keyword = |t: &str| t.chars().all(|c| c.is_ascii_uppercase());
    let ident = |p: &str| {
        p.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let toks: Vec<&str> = lit
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
        .collect();
    !toks.is_empty()
        && toks.iter().all(|t| !keyword(t) && t.split('.').all(ident))
        && toks
            .iter()
            .any(|t| FIELDS.contains(&t.rsplit('.').next().unwrap_or(t)))
}

/// The column lists of `rust`: every module-level (or `impl`-level) `const` /
/// `static` item holding a column-list literal ([`is_column_list_text`]),
/// such as `belief_cache.rs`'s `CACHE_COLUMN_NAMES` or a
/// `const COLS: &str = "belief, pignistic_prob"`. Such a list is spliced into
/// SQL at runtime (`format!` over the array, or `{COLS}` in the format
/// string), so no SQL literal names the column and the SQL scan cannot see
/// the read. A list local to a fn is [`local_column_lists`]'s.
fn column_list_consts(rust: &[Source], test_files: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for s in rust.iter().filter(|s| !test_files.contains(&s.path)) {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        for lit in &view.literals {
            if !is_column_list_text(&lit.text) {
                continue;
            }
            if let Some(name) = units.unit_at(lit.start).0.strip_prefix("const ") {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Is the literal whose content starts at `at` an element of an array
/// literal that holds string literals only (`["belief", "pignistic_prob"]`,
/// `vec![..]`), and not an index (`row["belief"]`)? On a code view, where a
/// literal's contents are blanked and its quotes kept.
fn in_string_array(code: &str, at: usize) -> bool {
    let filler = |c: char| matches!(c, ' ' | '\n' | '\t' | '\r' | ',' | '"');
    let Some(open) = code[..at].rfind(|c: char| !filler(c)) else {
        return false;
    };
    if code.as_bytes()[open] != b'[' {
        return false;
    }
    let indexed = code[..open]
        .trim_end()
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == ')' || c == ']');
    let end = balanced_end(code, open, b'[', b']');
    !indexed && end > open + 1 && code[open + 1..end - 1].chars().all(filler)
}

/// The column lists local to a fn of one Rust view: `(offset, label)` per
/// column-list literal ([`is_column_list_text`]) inside a fn that is held by
/// a fn-local `const` / `static` (labelled by its name) or is an element of
/// a string-only array literal, such as a `let` array (labelled `fn-local
/// array`). The enclosing fn reads it; [`column_list_readers`] credits it.
/// A bare literal in a fn (`json!({"belief": x})`, `("belief", v)`) is not
/// a list.
fn local_column_lists(view: &View, units: &RustUnits) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for lit in &view.literals {
        let Some(f) = units.fn_at(lit.start) else {
            continue;
        };
        if !is_column_list_text(&lit.text) {
            continue;
        }
        let local_const = units
            .const_at(lit.start)
            .filter(|(_, s, _)| *s > f.sig_start)
            .map(|(name, _, _)| name.to_string());
        if let Some(name) = local_const {
            out.push((lit.start, name));
        } else if in_string_array(&view.code, lit.start) {
            out.push((lit.start, "fn-local array".to_string()));
        }
    }
    out
}

/// Does format-string text `lit` capture `name` inline (`{name}`,
/// `{name:?}`), not as an escaped `{{name}`?
fn captures(lit: &str, name: &str) -> bool {
    let pat = format!("{{{name}");
    lit.match_indices(&pat).any(|(i, _)| {
        let after = &lit[i + pat.len()..];
        (after.starts_with('}') || after.starts_with(':')) && !lit[..i].ends_with('{')
    })
}

/// Does a fn returning `ret` hand back text (`String`, `&str`, `Cow<str>`)?
/// Only such a helper carries a column list on to its callers: a fn that
/// returns anything else has already used the text itself.
fn returns_text(ret: &str) -> bool {
    ["String", "str", "Cow"].iter().any(|t| has_word(ret, t))
}

/// Is `code[at..]` the name of a call: `name(` or `name::<..>(`, and not the
/// `fn name` that defines it?
fn is_call_at(code: &str, at: usize, name: &str) -> bool {
    let before = code[..at].trim_end();
    if before.ends_with("fn")
        && before[..before.len() - 2]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    {
        return false;
    }
    let after = code[at + name.len()..].trim_start();
    let after = after
        .strip_prefix("::<")
        .map(|r| r.find('>').map_or("", |e| r[e + 1..].trim_start()))
        .unwrap_or(after);
    after.starts_with('(')
}

/// One column-list reader: `(unit, its code span, the list it reads)`.
type ColumnListReader = (String, Option<(usize, usize)>, String);

/// The units of one Rust view that read a column list: `(unit, span,
/// list)`. A unit reads one when its code names the list (or a `const` of the
/// same file that names it), when one of its format strings captures it
/// inline (`"SELECT {COLS} FROM claims"`), when it holds a list local to it
/// ([`local_column_lists`]), or when it calls a fn of the same file that
/// reads one and returns text (such as `belief_cache.rs`'s `cache_equals`),
/// transitively. Propagation stops at the first fn that does not return
/// text: that fn builds and runs the statement, so it is the reader, not its
/// callers.
fn column_list_readers(
    view: &View,
    units: &RustUnits,
    lists: &BTreeSet<String>,
) -> Vec<ColumnListReader> {
    let code = view.code.as_str();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut done = BTreeSet::new();
    // (name, is a fn, the column list it carries)
    let mut queue: Vec<(String, bool, String)> = lists
        .iter()
        .map(|l| (l.clone(), false, l.clone()))
        .collect();
    for (at, list) in local_column_lists(view, units) {
        let Some(f) = units.fn_at(at) else {
            continue;
        };
        if seen.insert(f.name.clone()) {
            out.push((f.name.clone(), Some((f.sig_start, f.end)), list.clone()));
        }
        if returns_text(f.return_type(code)) {
            queue.push((f.name.clone(), true, list));
        }
    }
    while let Some((name, is_fn, list)) = queue.pop() {
        if !done.insert((name.clone(), is_fn)) {
            continue;
        }
        let mut hits: Vec<usize> = find_words(code, &name)
            .into_iter()
            .filter(|&at| !is_fn || is_call_at(code, at, &name))
            .collect();
        if !is_fn {
            hits.extend(
                view.literals
                    .iter()
                    .filter(|l| captures(&l.text, &name))
                    .map(|l| l.start),
            );
        }
        for at in hits {
            let (unit, span) = units.unit_at(at);
            if unit == "<module>" || unit == format!("const {name}") {
                continue; // a `use`, or the item's own definition
            }
            if let Some(c) = unit.strip_prefix("const ") {
                queue.push((c.to_string(), false, list.clone()));
            } else if let Some(f) = units.fn_at(at) {
                if returns_text(f.return_type(code)) {
                    queue.push((f.name.clone(), true, list.clone()));
                }
            }
            if seen.insert(unit.clone()) {
                out.push((unit, span, list.clone()));
            }
        }
    }
    out
}

/// The measured role-blind readers, keyed `(path, unit)`.
fn measure(rust: &[Source], scripts: &[Source]) -> Measured {
    let (row_types, producers) = claim_row_types(rust);
    let test_files = test_module_files(rust);
    let column_lists = column_list_consts(rust, &test_files);
    let mut out: Measured = BTreeMap::new();

    for s in rust {
        let view = rust_view(&s.text);
        let units = RustUnits::new(&view.code);
        let marked = |span: Option<(usize, usize)>| {
            span.is_some_and(|(a, e)| ROLE_MARKERS.iter().any(|m| view.code[a..e].contains(m)))
        };
        for lit in &view.literals {
            if !is_sql(&lit.text) {
                continue;
            }
            let sql = sql_without_comments(&lit.text);
            let kinds = sql_kinds(&sql);
            if kinds.is_empty() {
                continue;
            }
            let (unit, span) = units.unit_at(lit.start);
            let u = out.entry((s.path.clone(), unit)).or_default();
            u.kinds.extend(kinds);
            u.reads |= !is_write_sql(&sql);
            u.marked |= marked(span);
        }
        // A whole `#[cfg(test)]` module file is out of scope: a unit test's
        // fixture list, module-level or fn-local, is not a served read.
        if !test_files.contains(&s.path) {
            for (unit, span, list) in column_list_readers(&view, &units, &column_lists) {
                let u = out.entry((s.path.clone(), unit)).or_default();
                u.kinds.insert(format!("column list {list}"));
                u.reads = true;
                u.marked |= marked(span);
            }
        }
        if s.path.contains("belief_view") {
            continue;
        }
        for (at, field) in field_reads(&view.code) {
            let Some(f) = units.fn_at(at) else {
                continue;
            };
            let text = f.text(&view.code);
            let triggered = row_types.iter().any(|t| has_word(text, t))
                || producers.iter().any(|(imp, name)| {
                    imp.as_ref().is_none_or(|i| has_word(text, i)) && calls(text, name)
                });
            if !triggered {
                continue;
            }
            let u = out.entry((s.path.clone(), f.name.clone())).or_default();
            u.kinds.insert(format!(".{field}"));
            u.reads = true;
            u.marked |= marked(Some((f.sig_start, f.end)));
        }
    }

    for s in scripts.iter().filter(|s| s.path.ends_with(".py")) {
        let view = python_view(&s.text);
        for lit in &view.literals {
            if !is_sql(&lit.text) {
                continue;
            }
            let sql = sql_without_comments(&lit.text);
            let kinds = sql_kinds(&sql);
            if kinds.is_empty() {
                continue;
            }
            let unit = python_unit_at(&view.code, lit.start);
            let u = out.entry((s.path.clone(), unit)).or_default();
            u.kinds.extend(kinds);
            u.reads |= !is_write_sql(&sql);
        }
    }
    out
}

/// The ratchet's verdict over `measured`, one line per finding.
fn findings(measured: &Measured) -> Vec<String> {
    let mut out = Vec::new();
    let mut register: BTreeMap<(&str, &str), Tag> = BTreeMap::new();
    for (path, unit, tag) in REGISTER {
        if register.insert((path, unit), *tag).is_some() {
            out.push(format!("  {path}::{unit}: registered twice"));
        }
    }
    for ((path, unit), u) in measured {
        let entry = register.get(&(path.as_str(), unit.as_str()));
        match (u.marked, entry) {
            (true, Some(_)) => out.push(format!(
                "  {path}::{unit}: dispatches on role now; REMOVE its register entry"
            )),
            (true, None) => {}
            (false, None) => out.push(format!(
                "  {path}::{unit}: NEW role-blind belief reader ({}).\n    \
                 Dispatch on role (splice IS_COMPOUND_SQL / CLAIM_ROLE_SQL, or call \
                 claim_role::), or, if it only writes, register it as a Writer with a reason.",
                u.kinds.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
            (false, Some(Tag::Writer(_))) if u.reads => out.push(format!(
                "  {path}::{unit}: tagged Writer but it READS ({}); tag it with the PR that \
                 converts it",
                u.kinds.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
            (false, Some(_)) => {}
        }
    }
    for (path, unit) in register.keys() {
        if !measured.contains_key(&(path.to_string(), unit.to_string())) {
            out.push(format!(
                "  {path}::{unit}: registered but measures nothing; REMOVE the entry"
            ));
        }
    }
    out
}

fn names(findings: &[String], path: &str) -> bool {
    findings.iter().any(|f| f.contains(path))
}

/// The register's D5 standing: the number of non-writer entries left.
fn d5_status() -> (usize, usize) {
    let writers = REGISTER
        .iter()
        .filter(|(_, _, t)| matches!(t, Tag::Writer(_)))
        .count();
    let by_design = REGISTER
        .iter()
        .filter(|(_, _, t)| matches!(t, Tag::ByDesign(_)))
        .count();
    (writers, REGISTER.len() - writers - by_design)
}

// ---------------------------------------------------------------------------
// The ratchet
// ---------------------------------------------------------------------------

/// The live tree passes: every role-blind reader is registered, every entry
/// still measures, and no Writer entry reads.
#[test]
fn the_tree_has_no_unregistered_role_blind_reader() {
    let f = findings(&measure(&rust_sources(), &script_sources()));
    assert!(
        f.is_empty(),
        "the role-blind belief-read register is out of date. {} finding(s):\n{}",
        f.len(),
        f.join("\n")
    );
}

const SCRATCH_READER_PATH: &str = "crates/epigraph-api/src/routes/scratch_belief_reader.rs";

/// A new raw `c.pignistic_prob` reader fails; the same reader with the
/// compound predicate spliced passes.
#[test]
fn a_raw_pignistic_reader_fails_and_its_role_spliced_twin_passes() {
    let rust = rust_sources();
    let scripts = script_sources();

    let raw = r#"
pub async fn scratch_low_belief(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    sqlx::query_scalar("SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_READER_PATH, raw),
        &scripts,
    ));
    assert!(
        names(&f, SCRATCH_READER_PATH),
        "a new role-blind `c.pignistic_prob` reader must be a finding; got {f:#?}"
    );

    let spliced = r#"
use epigraph_db::repos::claim_role::{render, IS_COMPOUND_SQL};
pub async fn scratch_low_belief(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    let sql = format!(
        "SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3 AND NOT {}",
        render(IS_COMPOUND_SQL, "c")
    );
    sqlx::query_scalar(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_READER_PATH, spliced),
        &scripts,
    ));
    assert!(
        !names(&f, SCRATCH_READER_PATH),
        "a reader that splices IS_COMPOUND_SQL is classified; got {f:#?}"
    );
}

/// A field read on the row type `ClaimRepository::semantic_search_flat`
/// returns fails: SQL-text scanning alone cannot see this consumer.
#[test]
fn a_field_read_on_the_semantic_search_flat_row_fails() {
    let path = "crates/epigraph-api/src/routes/scratch_flat_reader.rs";
    let src = r#"
pub async fn scratch_mean_belief(
    pool: &sqlx::PgPool,
    viewer: &epigraph_db::Viewer,
    embedding: &str,
) -> f64 {
    let rows = epigraph_db::ClaimRepository::semantic_search_flat(
        pool, viewer, embedding, 0.0, None, None, None, None, 10,
    )
    .await
    .unwrap_or_default();
    rows.iter().map(|row| row.belief.unwrap_or(0.0)).sum::<f64>()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, src),
        &script_sources(),
    ));
    assert!(
        names(&f, path),
        "a `.belief` read on a semantic_search_flat row must be a finding; got {f:#?}"
    );
}

// ---------------------------------------------------------------------------
// Calibration: a green run means "nothing unregistered", not "nothing seen"
// ---------------------------------------------------------------------------

/// Both trees are read, and the scan finds the readers it should.
#[test]
fn the_scan_reads_both_trees() {
    let rust = rust_sources();
    let scripts = script_sources();
    assert!(
        rust.len() > 500,
        "expected >500 Rust sources, found {}",
        rust.len()
    );
    let py = scripts.iter().filter(|s| s.path.ends_with(".py")).count();
    assert!(
        py > 20,
        "expected >20 Python scripts under scripts/, found {py}"
    );
    let measured = measure(&rust, &scripts);
    assert!(
        measured.len() > 50,
        "expected >50 role-blind readers today, measured {}: a scanner that suddenly finds \
         almost nothing has broken, not been fixed",
        measured.len()
    );
}

/// Every reader SPEC §7.2 names by path, and that reads belief on this tree,
/// is measured. (`voids.rs` is named there too but reads only similarity and
/// statement text from its `semantic_search_flat` rows, so it is absent by
/// measurement, not by omission.)
#[test]
fn the_spec_named_readers_are_measured() {
    let measured = measure(&rust_sources(), &script_sources());
    for (path, unit) in [
        (
            "crates/epigraph-api/src/routes/search.rs",
            "semantic_search",
        ),
        ("crates/epigraph-api/src/routes/gaps.rs", "gap_analysis"),
        (
            "crates/epigraph-api/src/routes/experiments.rs",
            "hypothesize",
        ),
        (
            "crates/epigraph-api/src/routes/graph_query_utils.rs",
            "load_subgraph_conn",
        ),
        (
            "crates/epigraph-db/src/repos/alternative_set.rs",
            "scan_candidates",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "const EFFECTIVE_BELIEF_SCORE_SQL",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "list_by_belief_bounds",
        ),
        (
            "crates/epigraph-db/src/repos/claim.rs",
            "frame_claims_sorted",
        ),
        (
            "crates/epigraph-db/src/repos/graph_view.rs",
            "neighborhood_compound_nodes",
        ),
        (
            "crates/epigraph-db/src/repos/graph_view.rs",
            "compound_neighbors",
        ),
        (
            "crates/epigraph-db/src/repos/graph_view.rs",
            "expand_cluster_nodes",
        ),
        (
            "crates/epigraph-db/src/repos/scoped_belief.rs",
            "list_for_claim",
        ),
        (
            "crates/epigraph-db/src/repos/sheaf.rs",
            "get_claim_neighbor_betp_pairs",
        ),
        (
            "crates/epigraph-db/src/repos/sheaf.rs",
            "get_epistemic_edge_pairs",
        ),
        (
            "crates/epigraph-db/src/repos/structural.rs",
            "belief_intervals",
        ),
        (
            "crates/epigraph-db/src/repos/method.rs",
            "get_evidence_strength",
        ),
        (
            "crates/epigraph-engine/src/belief_query.rs",
            "get_belief_conn",
        ),
        (
            "crates/epigraph-jobs/src/cluster_graph/runner.rs",
            "run_clustering",
        ),
    ] {
        assert!(
            measured.contains_key(&(path.to_string(), unit.to_string())),
            "SPEC §7.2 names {path}::{unit} as a belief reader, and the scan does not see it"
        );
    }
}

/// The claim row types are derived from `epigraph-db`, and the derived set
/// is pinned: a new row type is a diff here, and a struct that is only ever
/// constructed (writer input such as `CachedBelief`) is not one.
#[test]
fn the_claim_row_types_are_the_derived_set() {
    let (types, producers) = claim_row_types(&rust_sources());
    let want: BTreeSet<String> = ROW_TYPES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        types, want,
        "the derived claim row types changed; update ROW_TYPES"
    );
    assert!(!types.contains("CachedBelief"));
    assert!(
        producers.contains(&(
            Some("ClaimRepository".to_string()),
            "semantic_search_flat".to_string()
        )),
        "semantic_search_flat must be a producer of a claim row type"
    );
}

/// A struct only role-dispatched fns return is not a claim row type, so
/// reading its fields is not a finding; one unmarked producer of it makes it
/// a row type again, and its readers findings. `AtomCache` is that struct
/// today: its one producer, `atom_cache_batch`, splices the compound
/// predicate, and the compound derivation reads its fields.
#[test]
fn a_row_type_is_role_blind_once_one_producer_is_unmarked() {
    let rust = rust_sources();
    let scripts = script_sources();
    let reader = (
        "crates/epigraph-engine/src/compound_belief.rs".to_string(),
        "legacy_item".to_string(),
    );
    let (types, _) = claim_row_types(&rust);
    assert!(!types.contains("AtomCache"), "{types:?}");
    assert!(
        !measure(&rust, &scripts).contains_key(&reader),
        "a field read on rows a role-dispatched producer returns is not role-blind"
    );

    let path = "crates/epigraph-db/src/repos/scratch_atom_cache.rs";
    let src = r#"
use super::compound_valuation::AtomCache;
pub async fn every_cache(pool: &sqlx::PgPool) -> Vec<AtomCache> {
    let _ = sqlx::query("SELECT c.belief, c.plausibility FROM claims c").fetch_all(pool).await;
    Vec::new()
}
"#;
    let rust = with_scratch(&rust, path, src);
    let (types, _) = claim_row_types(&rust);
    assert!(types.contains("AtomCache"), "{types:?}");
    let f = findings(&measure(&rust, &scripts));
    assert!(
        f.iter()
            .any(|l| l.contains("compound_belief.rs::legacy_item")),
        "with an unmarked producer, legacy_item's AtomCache field reads are role-blind; got {f:#?}"
    );
}

/// Each register entry is tagged consistently with what it measures: a
/// writer reads nothing (checked by `findings`), a reader really reads, and
/// every reader names a plan PR and a reason.
#[test]
fn every_entry_is_tagged_with_a_plan_pr_and_a_reason() {
    let measured = measure(&rust_sources(), &script_sources());
    let mut bad = Vec::new();
    for (path, unit, tag) in REGISTER {
        let reads = measured
            .get(&(path.to_string(), unit.to_string()))
            .is_some_and(|u| u.reads);
        match tag {
            Tag::Writer(why) if why.len() <= 20 => {
                bad.push(format!("{path}::{unit}: a Writer needs a reason"));
            }
            Tag::Writer(_) => {}
            Tag::ByDesign(why) => {
                if !why.contains("operator ruling") || why.len() <= 40 {
                    bad.push(format!(
                        "{path}::{unit}: a ByDesign entry names the operator ruling and its reason"
                    ));
                }
                if !reads {
                    bad.push(format!(
                        "{path}::{unit} is tagged ByDesign (a reader) but measures as write-only; tag it Writer"
                    ));
                }
            }
            Tag::Todo { pr, why } => {
                if !PLAN_PRS.contains(pr) {
                    bad.push(format!(
                        "{path}::{unit}: {pr} is not a plan PR that converts readers"
                    ));
                }
                if why.len() <= 20 {
                    bad.push(format!("{path}::{unit}: a reason is required, not a label"));
                }
                if !reads {
                    bad.push(format!(
                        "{path}::{unit} is tagged as a reader but measures as write-only; tag it Writer"
                    ));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let (writers, readers) = d5_status();
    let by_design = REGISTER
        .iter()
        .filter(|(_, _, t)| matches!(t, Tag::ByDesign(_)))
        .count();
    assert_eq!(writers + readers + by_design, REGISTER.len());
    assert!(
        writers > 0,
        "the cache writers are registered as writers, so D5 has a defined end state"
    );
}

/// A role marker counts only in code: in a comment or a log string it
/// classifies nothing.
#[test]
fn a_role_marker_in_a_comment_or_string_does_not_classify() {
    let rust = rust_sources();
    let scripts = script_sources();
    let src = r#"
pub async fn scratch_low_belief(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    // TODO: splice IS_COMPOUND_SQL here (claim_role::is_compound_sql)
    tracing::debug!("not yet CLAIM_ROLE_SQL aware");
    sqlx::query_scalar("SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_READER_PATH, src),
        &scripts,
    ));
    assert!(
        names(&f, SCRATCH_READER_PATH),
        "a marker in a comment or a string must not classify the reader; got {f:#?}"
    );
}

/// `truth_value` is a belief read when compared, ordered on or used as a
/// fallback, and not when it is only projected or assigned.
#[test]
fn truth_value_counts_only_where_it_is_used_as_a_belief() {
    for read in [
        "SELECT id FROM claims WHERE truth_value >= $1",
        "SELECT id FROM claims c WHERE $1 <= c.truth_value",
        "SELECT id FROM claims c ORDER BY c.truth_value DESC LIMIT 5",
        "SELECT COALESCE(c.pignistic_prob, c.truth_value) FROM claims c",
        "SELECT id FROM claims WHERE truth_value BETWEEN $1 AND $2",
    ] {
        assert!(
            sql_kinds(read).contains("truth_value"),
            "a belief use of truth_value: {read}"
        );
    }
    for not_read in [
        "SELECT id, content, truth_value FROM claims WHERE id = $1",
        "UPDATE claims SET truth_value = $2 WHERE id = $1",
        "INSERT INTO claims (content, truth_value) VALUES ($1, $2)",
        "SELECT id FROM claims ORDER BY created_at DESC LIMIT 5 -- not truth_value",
    ] {
        let sql = sql_without_comments(not_read);
        assert!(
            !sql_kinds(&sql).contains("truth_value"),
            "not a belief use of truth_value: {not_read}"
        );
    }
}

/// `belief_view` is where the row fields are meant to be read: the same
/// field read that fails elsewhere is not a finding there.
#[test]
fn a_belief_view_module_may_read_row_fields() {
    let src = r#"
pub async fn view_rows(pool: &sqlx::PgPool, viewer: &epigraph_db::Viewer) -> Vec<f64> {
    let rows = epigraph_db::ClaimRepository::semantic_search_flat(
        pool, viewer, "[0]", 0.0, None, None, None, None, 10,
    )
    .await
    .unwrap_or_default();
    rows.iter().map(|row| row.belief.unwrap_or(0.0)).collect()
}
"#;
    for (path, allowed) in [
        ("crates/epigraph-engine/src/belief_view.rs", true),
        ("crates/epigraph-engine/src/scratch_view.rs", false),
    ] {
        let f = findings(&measure(
            &with_scratch(&rust_sources(), path, src),
            &script_sources(),
        ));
        assert_eq!(
            !names(&f, path),
            allowed,
            "{path}: belief_view may read row fields, nothing else may; got {f:#?}"
        );
    }
}

/// A `#[cfg(test)]` item is out of scope, and only that item: production
/// code AFTER a test module is still scanned.
#[test]
fn only_the_test_item_is_out_of_scope() {
    let path = "crates/epigraph-db/src/repos/scratch_after_tests.rs";
    let test_only = r#"
#[cfg(test)]
mod tests {
    fn fixture() -> &'static str { "SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3" }
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, test_only),
        &script_sources(),
    ));
    assert!(
        !names(&f, path),
        "a test-module fixture is not a reader; got {f:#?}"
    );

    let after = format!(
        "{test_only}\npub fn after_tests() -> &'static str {{ \"SELECT c.id FROM claims c WHERE c.pignistic_prob < 0.3\" }}\n"
    );
    let f = findings(&measure(
        &with_scratch(&rust_sources(), path, &after),
        &script_sources(),
    ));
    assert!(
        f.iter()
            .any(|l| l.contains(&format!("{path}::after_tests"))),
        "a reader after a test module is still a reader; got {f:#?}"
    );
}

/// A writer tag is checked: a registered cache writer that starts reading a
/// belief column is a finding.
#[test]
fn a_writer_entry_that_starts_reading_is_a_finding() {
    let path = "crates/epigraph-db/src/repos/mass_function.rs";
    let mut rust = rust_sources();
    let src = rust
        .iter_mut()
        .find(|s| s.path == path)
        .expect("mass_function.rs is scanned");
    let anchor = "pub async fn update_claim_belief";
    let at = src.text.find(anchor).expect("update_claim_belief exists");
    let brace = at + src.text[at..].find('{').expect("a body");
    src.text.insert_str(
        brace + 1,
        "\n let _prior = \"SELECT pignistic_prob FROM claims WHERE id = $1\";\n",
    );
    let f = findings(&measure(&rust, &script_sources()));
    assert!(
        f.iter()
            .any(|l| l.contains("update_claim_belief") && l.contains("tagged Writer but it READS")),
        "a Writer entry that reads must be a finding; got {f:#?}"
    );
}

/// A Python docstring is prose; the same text executed is SQL.
#[test]
fn a_python_docstring_is_not_a_reader_but_an_executed_string_is() {
    let path = "scripts/scratch_report.py";
    let doc = r#"
def report(cur):
    """Prints claims WHERE pignistic_prob is low, FROM the cache."""
    return None
"#;
    let f = findings(&measure(
        &rust_sources(),
        &with_scratch(&script_sources(), path, doc),
    ));
    assert!(
        !names(&f, path),
        "a docstring is not a statement; got {f:#?}"
    );

    let exec = r#"
def report(cur):
    cur.execute("""SELECT id FROM claims WHERE pignistic_prob < 0.3""")
    return cur.fetchall()
"#;
    let f = findings(&measure(
        &rust_sources(),
        &with_scratch(&script_sources(), path, exec),
    ));
    assert!(
        f.iter().any(|l| l.contains(&format!("{path}::report"))),
        "an executed triple-quoted statement is a reader; got {f:#?}"
    );
}

// ---------------------------------------------------------------------------
// Column lists built at runtime (backlog 4e4d6ad4)
// ---------------------------------------------------------------------------

const SCRATCH_LIST_PATH: &str = "crates/epigraph-cli/src/scratch_column_list.rs";

/// A belief read whose column list is a `const` array spliced in with
/// `format!` names no column in any SQL literal. It is still a new
/// role-blind reader, and so is a text helper that builds the predicate
/// from the array AND the fn that runs the helper's text; the role-spliced
/// twin is classified.
#[test]
fn a_format_built_column_list_read_fails_unless_registered() {
    let rust = rust_sources();
    let scripts = script_sources();

    let direct = r#"
const SCRATCH_COLUMNS: [&str; 2] = ["belief", "pignistic_prob"];
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    let sql = format!("SELECT {} FROM claims c", SCRATCH_COLUMNS.join(", "));
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let measured = measure(&with_scratch(&rust, SCRATCH_LIST_PATH, direct), &scripts);
    let unit = measured
        .get(&(
            SCRATCH_LIST_PATH.to_string(),
            "scratch_list_read".to_string(),
        ))
        .unwrap_or_else(|| panic!("the format!-built read is not measured"));
    assert!(unit.reads, "a read through a column list is a read");
    assert!(
        unit.kinds.contains("column list SCRATCH_COLUMNS"),
        "{:?}",
        unit.kinds
    );
    let f = findings(&measured);
    assert!(
        f.iter()
            .any(|l| l.contains(&format!("{SCRATCH_LIST_PATH}::scratch_list_read: NEW"))),
        "a new format!-built belief read must be a finding; got {f:#?}"
    );

    let through_a_helper = r#"
const SCRATCH_COLUMNS: [&str; 2] = ["plausibility", "classification"];
fn scratch_equal(prefix: &str) -> String {
    SCRATCH_COLUMNS
        .iter()
        .map(|c| format!("c.{c} = w.{prefix}_{c}"))
        .collect::<Vec<_>>()
        .join(" AND ")
}
pub async fn scratch_probe(pool: &sqlx::PgPool) -> Vec<uuid::Uuid> {
    let sql = format!("SELECT c.id FROM claims c, w WHERE {}", scratch_equal("w"));
    sqlx::query_scalar(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_LIST_PATH, through_a_helper),
        &scripts,
    ));
    for unit in ["scratch_equal", "scratch_probe"] {
        assert!(
            f.iter()
                .any(|l| l.contains(&format!("{SCRATCH_LIST_PATH}::{unit}: NEW"))),
            "{unit} reads the column list (the helper builds it, the caller runs it); \
             got {f:#?}"
        );
    }

    let spliced = r#"
use epigraph_db::repos::claim_role::{render, IS_COMPOUND_SQL};
const SCRATCH_COLUMNS: [&str; 2] = ["belief", "pignistic_prob"];
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    let sql = format!(
        "SELECT {} FROM claims c WHERE NOT {}",
        SCRATCH_COLUMNS.join(", "),
        render(IS_COMPOUND_SQL, "c")
    );
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_LIST_PATH, spliced),
        &scripts,
    ));
    assert!(
        !names(&f, SCRATCH_LIST_PATH),
        "a column-list reader that splices IS_COMPOUND_SQL is classified; got {f:#?}"
    );
}

/// The column-list rule is bounded: a `const` array naming no cache column
/// is not a column list, and the caller of a fn that reads a column list but
/// returns no text is not a reader (the fn ran the statement; its caller only
/// gets its result), so `belief_cache::restore_wave` is not measured beside
/// `restore_wave_with`.
#[test]
fn a_column_list_taints_only_its_readers() {
    let rust = rust_sources();
    let scripts = script_sources();

    let unrelated = r#"
const SCRATCH_COLUMNS: [&str; 2] = ["statement", "created_at"];
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<String> {
    let sql = format!("SELECT {} FROM claims c", SCRATCH_COLUMNS.join(", "));
    sqlx::query_scalar(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let measured = measure(&with_scratch(&rust, SCRATCH_LIST_PATH, unrelated), &scripts);
    assert!(
        !measured.keys().any(|(p, _)| p == SCRATCH_LIST_PATH),
        "a list naming no cache column is not a belief read"
    );

    let wrapped = r#"
const SCRATCH_COLUMNS: [&str; 1] = ["pignistic_prob"];
pub async fn scratch_run(pool: &sqlx::PgPool) -> anyhow::Result<Vec<f64>> {
    let sql = format!("SELECT {} FROM claims c", SCRATCH_COLUMNS.join(", "));
    Ok(sqlx::query_scalar(&sql).fetch_all(pool).await?)
}
pub async fn scratch_outer(pool: &sqlx::PgPool) -> usize {
    scratch_run(pool).await.map(|v| v.len()).unwrap_or(0)
}
"#;
    let measured = measure(&with_scratch(&rust, SCRATCH_LIST_PATH, wrapped), &scripts);
    let key = |u: &str| (SCRATCH_LIST_PATH.to_string(), u.to_string());
    assert!(measured.contains_key(&key("scratch_run")));
    assert!(
        !measured.contains_key(&key("scratch_outer")),
        "the caller of a non-text fn is not a column-list reader"
    );

    let live = measure(&rust, &scripts);
    let cache = "crates/epigraph-cli/src/belief_cache.rs";
    for unit in ["cache_equals", "restore_wave_with"] {
        assert!(
            live.get(&(cache.to_string(), unit.to_string()))
                .is_some_and(|u| u.reads && u.kinds.contains("column list CACHE_COLUMN_NAMES")),
            "{cache}::{unit} reads CACHE_COLUMN_NAMES"
        );
    }
    assert!(
        !live.contains_key(&(cache.to_string(), "restore_wave".to_string())),
        "{cache}::restore_wave only calls restore_wave_with"
    );
    // A unit test's fixture list in a `#[cfg(test)]` module file (the
    // atlas contract's banned belief keys) is not a served read.
    let contract_tests = "crates/epigraph-atlas-contract/src/tests.rs";
    assert!(
        test_module_files(&rust).contains(contract_tests),
        "{contract_tests} is a #[cfg(test)] module file"
    );
    assert!(
        !live.keys().any(|(p, _)| p == contract_tests),
        "{contract_tests} is out of scope"
    );
}

/// The other shapes a column list may take, each a new role-blind reader
/// that must be a finding: an array or a `const` local to the fn, and a
/// comma-separated list in one `const` string, spliced positionally or
/// captured inline (`{COLS}`, which no code token names). The fn-local
/// twin that splices the role predicate is classified.
#[test]
fn every_column_list_shape_fails_unless_registered() {
    let rust = rust_sources();
    let scripts = script_sources();
    let new_reader = |label: &str, text: &str, unit: &str| {
        let f = findings(&measure(
            &with_scratch(&rust, SCRATCH_LIST_PATH, text),
            &scripts,
        ));
        assert!(
            f.iter()
                .any(|l| l.contains(&format!("{SCRATCH_LIST_PATH}::{unit}: NEW"))),
            "{label}: {unit} reads a column list and must be a finding; got {f:#?}"
        );
    };

    new_reader(
        "fn-local const array",
        r#"
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    const COLS: [&str; 2] = ["belief", "pignistic_prob"];
    let sql = format!("SELECT {} FROM claims c", COLS.join(", "));
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#,
        "scratch_list_read",
    );
    new_reader(
        "fn-local let array",
        r#"
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    let cols = vec!["plausibility", "belief"];
    let sql = format!("SELECT {} FROM claims c", cols.join(", "));
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#,
        "scratch_list_read",
    );
    let inline = r#"
const SCRATCH_COLS: &str = "belief, pignistic_prob";
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    let sql = format!("SELECT {SCRATCH_COLS} FROM claims c");
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    new_reader(
        "module const string, inline capture",
        inline,
        "scratch_list_read",
    );
    new_reader(
        "module const string, positional",
        &inline.replace(
            r#"format!("SELECT {SCRATCH_COLS} FROM claims c")"#,
            r#"format!("SELECT {} FROM claims c", SCRATCH_COLS)"#,
        ),
        "scratch_list_read",
    );
    // A fn-local list in a text helper taints the helper's caller too.
    let helper = r#"
fn scratch_select() -> String {
    const COLS: &str = "pignistic_prob";
    format!("SELECT {COLS} FROM claims c")
}
pub async fn scratch_run(pool: &sqlx::PgPool) -> Vec<f64> {
    sqlx::query_scalar(&scratch_select()).fetch_all(pool).await.unwrap_or_default()
}
"#;
    new_reader("fn-local list in a text helper", helper, "scratch_select");
    new_reader("caller of that helper", helper, "scratch_run");

    let spliced = r#"
use epigraph_db::repos::claim_role::{render, IS_COMPOUND_SQL};
pub async fn scratch_list_read(pool: &sqlx::PgPool) -> Vec<(f64, f64)> {
    let cols = ["belief", "pignistic_prob"];
    let sql = format!(
        "SELECT {} FROM claims c WHERE NOT {}",
        cols.join(", "),
        render(IS_COMPOUND_SQL, "c")
    );
    sqlx::query_as(&sql).fetch_all(pool).await.unwrap_or_default()
}
"#;
    let f = findings(&measure(
        &with_scratch(&rust, SCRATCH_LIST_PATH, spliced),
        &scripts,
    ));
    assert!(
        !names(&f, SCRATCH_LIST_PATH),
        "a fn-local column-list reader that splices IS_COMPOUND_SQL is classified; got {f:#?}"
    );
}

/// The widened shapes stay bounded: a cache column name as a JSON key, a
/// tuple element or an index, and a SQL `const` (the SQL rule's, registered
/// as itself), are not column lists; the live tree gains no reader.
#[test]
fn a_bare_cache_column_literal_is_not_a_column_list() {
    let rust = rust_sources();
    let scripts = script_sources();
    let quiet = r#"
const SCRATCH_SQL: &str = "SELECT id FROM claims WHERE pignistic_prob IS NULL";
pub fn scratch_report(bel: f64, row: &serde_json::Value) -> serde_json::Value {
    let pairs = [("belief", bel), ("plausibility", bel)];
    let old = &row["delta"]["belief"];
    let sql = SCRATCH_SQL.to_string();
    serde_json::json!({"belief": bel, "pairs": pairs.len(), "old": old, "sql": sql})
}
"#;
    let measured = measure(&with_scratch(&rust, SCRATCH_LIST_PATH, quiet), &scripts);
    let key = |u: &str| (SCRATCH_LIST_PATH.to_string(), u.to_string());
    assert!(
        !measured.contains_key(&key("scratch_report")),
        "no column list is read here: {:?}",
        measured.get(&key("scratch_report"))
    );
    assert!(
        measured.contains_key(&key("const SCRATCH_SQL")),
        "the SQL const is still the SQL rule's reader"
    );
    assert!(is_column_list_text("belief"));
    assert!(is_column_list_text("c.belief, c.pignistic_prob"));
    assert!(is_column_list_text("plausibility classification"));
    assert!(!is_column_list_text("believe"));
    assert!(!is_column_list_text("belief = $1"));
    assert!(!is_column_list_text("SELECT belief FROM claims"));
    assert!(captures("SELECT {COLS} FROM", "COLS"));
    assert!(captures("SELECT {COLS:?} FROM", "COLS"));
    assert!(!captures("SELECT {{COLS}} FROM", "COLS"));
    assert!(!captures("SELECT {COLS_X} FROM", "COLS"));
}
