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
//!
//! # Classified, registered, or a finding
//!
//! * A unit whose CODE (not a comment, not a string) names
//!   `IS_COMPOUND_SQL`, `CLAIM_ROLE_SQL`, `is_compound_sql`,
//!   `claim_role_sql` or `claim_role::` dispatches on role: it is classified
//!   and must NOT be registered.
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

mod belief_lint;

use belief_lint::{
    find_words, has_word, is_sql, is_write_sql, python_unit_at, python_view, rust_fns,
    rust_sources, rust_view, script_sources, sql_without_comments, with_scratch, RustUnits, Source,
};
use std::collections::{BTreeMap, BTreeSet};

/// Code tokens that mark a unit as role-dispatched (SPEC §7.3).
const ROLE_MARKERS: &[&str] = &[
    "IS_COMPOUND_SQL",
    "CLAIM_ROLE_SQL",
    "is_compound_sql",
    "claim_role_sql",
    "claim_role::",
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
    ("crates/epigraph-api/src/routes/computation.rs", "compose_subgraphs", Tag::Todo { pr: "unassigned", why: "subgraph composition reads cached BetP of every node, compounds included; no plan row converts it" }),
    ("crates/epigraph-api/src/routes/computation.rs", "propagate_beliefs", Tag::Todo { pr: "PR-1", why: "BP propagation seeds from cached BetP, compounds included; SPEC D4 (BP machinery excludes compounds)" }),
    ("crates/epigraph-api/src/routes/experiments.rs", "hypothesize", Tag::Todo { pr: "PR-R5", why: "reads Bel/Pl of semantic_search_flat rows; SPEC §7.2 atoms by cache, compounds by BeliefView" }),
    ("crates/epigraph-api/src/routes/gaps.rs", "gap_analysis", Tag::Todo { pr: "PR-R5", why: "picks work by ignorance from semantic_search_flat rows with a truth_value fallback; SPEC §7.2 excludes compounds" }),
    ("crates/epigraph-api/src/routes/graph.rs", "expand", Tag::Todo { pr: "PR-R3", why: "graph expand serves cluster node BetP; SPEC §7.2 graph view derives compound nodes per viewer" }),
    ("crates/epigraph-api/src/routes/graph_neighborhood.rs", "atomic_response", Tag::Todo { pr: "PR-R3", why: "graph neighbourhood node BetP; SPEC §7.2 graph view" }),
    ("crates/epigraph-api/src/routes/graph_neighborhood.rs", "compound_response", Tag::Todo { pr: "PR-R3", why: "graph neighbourhood compound node BetP is the compound's own cache; SPEC §7.2 derived per viewer" }),
    ("crates/epigraph-api/src/routes/graph_query_utils.rs", "load_subgraph_conn", Tag::Todo { pr: "PR-R5", why: "graph_query / graph / edges subgraph nodes copy the cache columns; SPEC §7.2 BeliefView for compound nodes" }),
    ("crates/epigraph-api/src/routes/hypothesis.rs", "create_hypothesis", Tag::Todo { pr: "PR-W4", why: "hypothesis prior from grounded neighbours' cached Bel/Pl, compounds included (arithmetic: SPEC §7.2 excludes); SPEC §4.1 W13" }),
    ("crates/epigraph-api/src/routes/policies.rs", "list_network_policies", Tag::Todo { pr: "unassigned", why: "policy claims gated and ordered on truth_value; no plan row converts it" }),
    ("crates/epigraph-api/src/routes/policies.rs", "record_outcome", Tag::Writer("one UPDATE moves a policy claim's truth_value from its own value; it serves no belief")),
    ("crates/epigraph-api/src/routes/policies.rs", "resolve_challenge", Tag::Writer("one UPDATE moves a challenged claim's truth_value from its own value; it serves no belief")),
    ("crates/epigraph-api/src/routes/search.rs", "semantic_search", Tag::Todo { pr: "PR-R5", why: "REST /search/semantic maps c.belief / c.plausibility per hit; SPEC §7.2 BeliefView per hit" }),
    // --- epigraph-cli -------------------------------------------------------
    ("crates/epigraph-cli/src/belief_cache.rs", "read_cache_columns", Tag::Todo { pr: "unassigned", why: "PR-C1's CAS restore reads every listed claim's raw cache columns to compare bit-exact; it must stay role-blind (compound caches are restored too); D5 counts it until the operator rules on snapshot tooling" }),
    ("crates/epigraph-cli/src/belief_cache.rs", "restore_wave_with", Tag::Writer("PR-C1's compare-and-swap restore writes a wave's before values back where the columns still equal what it wrote; it serves no belief")),
    ("crates/epigraph-cli/src/belief_cache.rs", "write_snapshot", Tag::Todo { pr: "unassigned", why: "PR-C1's snapshot copies every current claim's raw cache columns, compounds included (the compound-cache cleanup NULLs them only after a snapshot); must stay role-blind; D5 counts it until the operator rules" }),
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
    ("crates/epigraph-db/src/repos/claim.rs", "search_by_label_and_text", Tag::Todo { pr: "unassigned", why: "workflow text search gated on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/claim.rs", "semantic_graph_neighbors", Tag::Todo { pr: "PR-R5", why: "semantic search graph expansion returns c.belief / c.plausibility; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim.rs", "semantic_search_flat", Tag::Todo { pr: "PR-R5", why: "the semantic_search_flat row carries c.belief / c.plausibility; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/claim.rs", "sql_expr", Tag::Todo { pr: "PR-R3", why: "BeliefSort column for frame_claims_sorted; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/divergence.rs", "get_latest", Tag::Todo { pr: "PR-R1b", why: "divergence row BetP; SPEC §7.2 derived, see leaves" }),
    ("crates/epigraph-db/src/repos/divergence.rs", "store", Tag::Writer("writes ds_bayesian_divergence.pignistic_prob; reads no claim belief")),
    ("crates/epigraph-db/src/repos/divergence.rs", "top_divergent", Tag::Todo { pr: "PR-R1b", why: "divergence rows ordered by BetP gap; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/edge.rs", "count_claims_attributed_to", Tag::Todo { pr: "unassigned", why: "agent attribution count gated on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/edge.rs", "get_claims_attributed_to", Tag::Todo { pr: "unassigned", why: "agent attribution list gated on truth_value; no plan row converts it" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "compound_neighbors", Tag::Todo { pr: "PR-R3", why: "graph view compound neighbour BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "expand_cluster_nodes", Tag::Todo { pr: "PR-R3", why: "graph view cluster node BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "neighborhood_atomic_nodes", Tag::Todo { pr: "PR-R3", why: "graph view node BetP; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "neighborhood_compound_nodes", Tag::Todo { pr: "PR-R3", why: "graph view compound node BetP is the compound's own cache; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/graph_view.rs", "subgraph_claims", Tag::Todo { pr: "PR-R5", why: "subgraph rows behind graph_query_utils carry the cache columns; SPEC §7.2" }),
    ("crates/epigraph-db/src/repos/mass_function.rs", "clear_claim_belief", Tag::Writer("NULLs the cache columns; reads none (SPEC §4.2 stops calling it on atoms)")),
    ("crates/epigraph-db/src/repos/mass_function.rs", "update_claim_belief", Tag::Writer("writes the cache columns; reads none")),
    ("crates/epigraph-db/src/repos/method.rs", "get_evidence_strength", Tag::Todo { pr: "PR-M2", why: "aggregates BetP / truth_value over claims, compounds included; SPEC §7.2 excludes compounds" }),
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
    ("crates/epigraph-db/src/repos/workflow.rs", "search_hierarchical_by_embedding_scored", Tag::Todo { pr: "unassigned", why: "workflow search scored on truth_value; procedural, no plan row" }),
    ("crates/epigraph-db/src/repos/workflow.rs", "search_hierarchical_by_text", Tag::Todo { pr: "unassigned", why: "workflow search scored on truth_value; procedural, no plan row" }),
    // --- epigraph-engine ----------------------------------------------------
    ("crates/epigraph-engine/src/belief_query.rs", "get_belief", Tag::Todo { pr: "PR-R1a", why: "the get_belief choke point serves the cache columns; SPEC §7.2 dispatches on role" }),
    ("crates/epigraph-engine/src/edge_factor.rs", "auto_wire_ds_for_edge", Tag::Todo { pr: "PR-F2", why: "builds an edge BBA from the source's cached Bel/Pl, compound sources included; SPEC §4.1 W8" }),
    // --- epigraph-jobs ------------------------------------------------------
    ("crates/epigraph-jobs/src/cluster_graph/neighborhood.rs", "run_one_theme", Tag::Todo { pr: "unassigned", why: "theme neighbourhood BetP; SPEC §7.2 calls it atoms-only, but the predicate is not the IS_COMPOUND_SQL spelling" }),
    ("crates/epigraph-jobs/src/cluster_graph/runner.rs", "run_clustering", Tag::Todo { pr: "PR-M2", why: "cluster mean_betp over claims, compounds included; SPEC §7.2" }),
    // --- epigraph-mcp -------------------------------------------------------
    ("crates/epigraph-mcp/src/tools/claims.rs", "update_with_evidence", Tag::Todo { pr: "PR-5b1", why: "reads the cache for the monotonicity clamp and the response; SPEC §4.1 W1" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "get_divergence", Tag::Todo { pr: "PR-R1b", why: "MCP divergence serves BetP; SPEC §7.2" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "scoped_belief", Tag::Todo { pr: "PR-R1b", why: "MCP scoped_belief serves scoped rows; SPEC §7.2" }),
    ("crates/epigraph-mcp/src/tools/ds.rs", "submit_ds_evidence", Tag::Todo { pr: "PR-W1a", why: "reads and reports the cache around a textless BBA write; SPEC §4.1 W3" }),
    ("crates/epigraph-mcp/src/tools/ds_auto.rs", "auto_wire_ds_update", Tag::Todo { pr: "PR-5b1", why: "reads the cached BetP as the clamp's prior; SPEC §4.1 W1" }),
    ("crates/epigraph-mcp/src/tools/link_epistemic.rs", "do_link_epistemic", Tag::Todo { pr: "PR-W1b", why: "reads the source's cache to wire an edge and reports the target's; SPEC §4.1 W7" }),
    ("crates/epigraph-mcp/src/tools/recall.rs", "fetch_batched_context", Tag::Todo { pr: "PR-R2", why: "recall_with_context context rows gated on truth_value; SPEC §7.2" }),
    // --- scripts ------------------------------------------------------------
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

/// The measured role-blind readers, keyed `(path, unit)`.
fn measure(rust: &[Source], scripts: &[Source]) -> Measured {
    let (row_types, producers) = claim_row_types(rust);
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
    (writers, REGISTER.len() - writers)
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
        ("crates/epigraph-engine/src/belief_query.rs", "get_belief"),
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
    assert_eq!(writers + readers, REGISTER.len());
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
