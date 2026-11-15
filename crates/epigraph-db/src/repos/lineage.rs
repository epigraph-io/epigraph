//! Lineage repository for recursive CTE-based claim provenance queries
//!
//! This module provides efficient traversal of claim lineage using PostgreSQL
//! recursive CTEs. It returns claims, evidence, and reasoning traces in
//! topological order (ancestors before descendants).
//!
//! # Evidence
//! - IMPLEMENTATION_PLAN.md specifies claim provenance tracking
//! - Recursive CTE pattern required for arbitrary depth traversal
//!
//! # Reasoning
//! - PostgreSQL WITH RECURSIVE provides efficient graph traversal
//! - Topological order ensures ancestors always precede descendants
//! - Diamond dependencies and cycles require proper deduplication. Every walk
//!   that reports a claim's SHORTEST depth is a breadth-first search with a
//!   visited set INSIDE one recursive statement (one row per layer: the
//!   frontier and every claim visited so far), so each claim enters once, at
//!   its shortest depth, a cycle ends the walk, and the work is bounded by the
//!   claims and edges reached rather than by the number of paths (backlog
//!   f889c86f)

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use tracing::instrument;
use uuid::Uuid;

// ============================================================================
// Public Data Structures
// ============================================================================

/// Result of a Lowest Common Ancestor query
#[derive(Debug, Clone)]
pub struct LcaResult {
    pub ancestor_id: Uuid,
    pub depth_from_a: i32,
    pub depth_from_b: i32,
    pub total_depth: i32,
}

/// Represents a node in the lineage result
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LineageNode {
    pub claim_id: Uuid,
    pub depth: i32,
    pub path: Vec<Uuid>,
}

/// Full lineage result including claims, evidence, and traces
#[derive(Debug, Clone, Default)]
pub struct LineageResult {
    /// Claims in the lineage, keyed by claim_id
    pub claims: HashMap<Uuid, LineageClaim>,
    /// Evidence items, keyed by evidence_id
    pub evidence: HashMap<Uuid, LineageEvidence>,
    /// Reasoning traces, keyed by trace_id
    pub traces: HashMap<Uuid, LineageTrace>,
    /// Nodes in topological order (ancestors first)
    pub topological_order: Vec<Uuid>,
    /// Whether the RETURNED claims contain a cycle through their
    /// `parent_ids`: the claims after the `max_depth` bound and any
    /// `max_nodes` cap, linked by the edges the walk follows (derivation edges
    /// for [`LineageRepository::get_lineage`], every claim-to-claim edge for
    /// [`LineageRepository::get_descendants`]) that the viewer can read. A
    /// cycle that lies partly past the cut is not reported; a walk still ends
    /// on a cycle and lists each claim once. For a check over the whole
    /// reachable ancestor graph and every relationship, see
    /// [`LineageRepository::detect_cycles`].
    pub cycle_detected: bool,
    /// Maximum depth reached
    pub max_depth_reached: i32,
    /// Whether this result was truncated, either because a claim the viewer can
    /// read lies past `max_depth` (the walk looks exactly one layer further and
    /// discards that layer, so a complete walk that ends AT `max_depth` is not
    /// truncated), or because a caller-supplied `max_nodes` cap cut the
    /// topological order down to fewer entries than were actually reachable.
    /// Defaults to `false`.
    pub truncated: bool,
}

/// Claim data in lineage result
#[derive(Debug, Clone)]
pub struct LineageClaim {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    /// The claim's author, projected by the walk itself so a caller needs no
    /// per-node point read to serve it.
    pub agent_id: Uuid,
    /// When the claim was created; projected by the walk for the same reason.
    pub created_at: DateTime<Utc>,
    pub depth: i32,
    pub parent_ids: Vec<Uuid>,
    pub evidence_ids: Vec<Uuid>,
    pub trace_id: Option<Uuid>,
}

/// Evidence data in lineage result
#[derive(Debug, Clone)]
pub struct LineageEvidence {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub evidence_type: String,
    pub content_hash: Vec<u8>,
}

/// Trace data in lineage result
#[derive(Debug, Clone)]
pub struct LineageTrace {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub reasoning_type: String,
    pub confidence: f64,
    pub parent_trace_ids: Vec<Uuid>,
}

// ============================================================================
// Row types for database queries (internal)
// ============================================================================

/// Row returned from lineage CTE query
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)] // Fields populated by sqlx::FromRow, used via struct destructuring
struct LineageRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    agent_id: Uuid,
    created_at: DateTime<Utc>,
    trace_id: Option<Uuid>,
    depth: i32,
}

/// Row for edge queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct EdgeQueryRow {
    source_id: Uuid,
    target_id: Uuid,
}

/// Row for `get_lineage_conn`'s parent-edge query. Carries the relationship
/// because a parent link's direction depends on it: an incoming derivation
/// edge names its SOURCE as the parent, a `supersedes` edge its TARGET.
#[derive(Debug, Clone, sqlx::FromRow)]
struct LineageEdgeRow {
    source_id: Uuid,
    target_id: Uuid,
    relationship: String,
}

/// Relationships whose ancestor sits behind an INCOMING edge
/// (`ancestor -> claim`), as walked by [`LineageRepository::get_lineage_conn`]
/// (MCP `get_provenance`, REST `GET /lineage/:claim_id`).
///
/// This is [`crate::repos::provenance_chain::PROVENANCE_INCOMING`] minus
/// `corroborates`: a cross-source corroboration (the matcher writes
/// `CORROBORATES`) is independent support for a claim, not a claim it was
/// derived from, and lineage answers "what was this derived from". Compared
/// lower-cased, so `SUPPORTS` / `supports` are one relationship. The
/// outgoing set is [`crate::repos::provenance_chain::PROVENANCE_OUTGOING`]
/// itself (`supersedes`, written new->old), so the two walks cannot drift on
/// direction.
pub const LINEAGE_INCOMING: &[&str] = &["supports", "elaborates", "decomposes_to"];

/// Row for evidence queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct EvidenceQueryRow {
    id: Uuid,
    claim_id: Uuid,
    evidence_type: String,
    content_hash: Vec<u8>,
}

/// Row for trace queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct TraceQueryRow {
    id: Uuid,
    claim_id: Uuid,
    reasoning_type: String,
    confidence: f64,
}

/// Row for trace parent queries
#[derive(Debug, Clone, sqlx::FromRow)]
struct TraceParentRow {
    trace_id: Uuid,
    parent_id: Uuid,
}

/// The depth bound a walk's CTE is run with: ONE layer past `max_depth`.
///
/// The extra layer is a probe. Its rows pass through the same `VISIBILITY` and
/// `EDGE_VISIBILITY` predicates as every other layer, so "a claim lies past
/// `max_depth`" is decided only over claims and edges the viewer can read, and
/// [`drop_probe_layer`] removes them before anything else reads the rows.
fn probe_depth(max_depth: i32) -> i32 {
    max_depth.saturating_add(1)
}

/// Split a walk's rows (fetched to [`probe_depth`]) into the rows within
/// `max_depth` and whether any visible claim lay beyond it.
///
/// The walk returns each claim once, at its SHORTEST depth (the breadth-first
/// layer it first entered), so a row survives past `max_depth` only when that
/// claim is not reachable within it. Such a row is exactly "the walk stopped
/// before this claim", which is what `truncated` reports; a complete walk that
/// ends exactly at `max_depth` produces none.
fn drop_probe_layer(rows: Vec<LineageRow>, max_depth: i32) -> (Vec<LineageRow>, bool) {
    let fetched = rows.len();
    let kept: Vec<LineageRow> = rows.into_iter().filter(|r| r.depth <= max_depth).collect();
    let cut = kept.len() != fetched;
    (kept, cut)
}

/// The furthest shortest-depth layer [`LineageRepository::detect_cycles`] and
/// [`LineageRepository::get_depth`] walk to: the bound their path-enumerating
/// forms had. It bounds the stored layer rows (each carries the visited set),
/// not the answer's cost on a dense graph, which is the claims and edges
/// reached.
const SHAPE_WALK_MAX_DEPTH: i32 = 1000;

/// A directed graph over claims, its edges pointing the way a walk follows
/// them, and the strongly connected components that decide both "is there a
/// cycle" and "how long is the longest chain" in time linear in its size.
///
/// Neither question can be answered by enumerating paths (exponential on a
/// dense DAG), nor from a breadth-first walk's shortest depths: a lattice
/// reaches every claim many times over without a cycle, and a shortcut makes
/// a claim's shortest depth smaller than its longest chain.
struct ClaimDigraph {
    index: HashMap<Uuid, usize>,
    /// Deduplicated successors per node.
    adj: Vec<Vec<usize>>,
    /// `comp[v]`: v's strongly connected component. Components are numbered
    /// in Tarjan's emission order, so every edge between two components goes
    /// from a HIGHER number to a lower one.
    comp: Vec<usize>,
    comp_count: usize,
}

impl ClaimDigraph {
    /// Build from `(from, to)` edges. Repeated pairs (two relationships on the
    /// same claims) collapse to one edge.
    fn new(edges: impl IntoIterator<Item = (Uuid, Uuid)>) -> Self {
        let mut index: HashMap<Uuid, usize> = HashMap::new();
        let mut pairs: HashSet<(usize, usize)> = HashSet::new();
        for (from, to) in edges {
            let next = index.len();
            let f = *index.entry(from).or_insert(next);
            let next = index.len();
            let t = *index.entry(to).or_insert(next);
            pairs.insert((f, t));
        }
        let mut adj = vec![Vec::new(); index.len()];
        for (f, t) in pairs {
            adj[f].push(t);
        }
        let (comp, comp_count) = tarjan_scc(&adj);
        Self {
            index,
            adj,
            comp,
            comp_count,
        }
    }

    /// Whether any edge lies on a cycle: a component of two or more claims,
    /// or a claim with an edge to itself.
    fn has_cycle(&self) -> bool {
        let mut size = vec![0usize; self.comp_count];
        for &c in &self.comp {
            size[c] += 1;
        }
        size.iter().any(|&n| n > 1) || self.adj.iter().enumerate().any(|(v, s)| s.contains(&v))
    }

    /// The longest chain of edges from `root`, counting each strongly
    /// connected component as ONE step: exact on a DAG (where every component
    /// is a single claim), and a well-defined, deterministic answer on a graph
    /// with cycles, where the longest SIMPLE path is NP-hard. `0` when `root`
    /// has no edges.
    fn longest_chain_from(&self, root: Uuid) -> i32 {
        let Some(&r) = self.index.get(&root) else {
            return 0;
        };
        let mut members: Vec<Vec<usize>> = vec![Vec::new(); self.comp_count];
        for (v, &c) in self.comp.iter().enumerate() {
            members[c].push(v);
        }
        // Components in topological order are the descending numbers (see
        // `comp`), so a component's chain length is final before any edge
        // leaves it.
        let mut chain: Vec<Option<i32>> = vec![None; self.comp_count];
        chain[self.comp[r]] = Some(0);
        let mut longest = 0;
        for c in (0..self.comp_count).rev() {
            let Some(here) = chain[c] else { continue };
            longest = longest.max(here);
            for &v in &members[c] {
                for &w in &self.adj[v] {
                    let cw = self.comp[w];
                    if cw != c {
                        let via = here.saturating_add(1);
                        chain[cw] = Some(chain[cw].map_or(via, |x| x.max(via)));
                    }
                }
            }
        }
        longest
    }
}

/// Tarjan's strongly connected components, iteratively (a recursive form
/// would recurse as deep as the longest chain). Returns each node's component
/// and the component count; components are numbered in emission order, which
/// is a reverse topological order of the condensation.
fn tarjan_scc(adj: &[Vec<usize>]) -> (Vec<usize>, usize) {
    const UNSEEN: usize = usize::MAX;
    let n = adj.len();
    let mut order = vec![UNSEEN; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut comp = vec![UNSEEN; n];
    let mut stack: Vec<usize> = Vec::new();
    // (node, index of its next successor to look at)
    let mut calls: Vec<(usize, usize)> = Vec::new();
    let mut next_order = 0usize;
    let mut comp_count = 0usize;
    for start in 0..n {
        if order[start] != UNSEEN {
            continue;
        }
        order[start] = next_order;
        low[start] = next_order;
        next_order += 1;
        stack.push(start);
        on_stack[start] = true;
        calls.push((start, 0));
        while let Some(&(v, i)) = calls.last() {
            if let Some(&w) = adj[v].get(i) {
                if let Some(top) = calls.last_mut() {
                    top.1 += 1;
                }
                if order[w] == UNSEEN {
                    order[w] = next_order;
                    low[w] = next_order;
                    next_order += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    calls.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(order[w]);
                }
                continue;
            }
            calls.pop();
            if let Some(&(parent, _)) = calls.last() {
                low[parent] = low[parent].min(low[v]);
            }
            if low[v] == order[v] {
                while let Some(w) = stack.pop() {
                    on_stack[w] = false;
                    comp[w] = comp_count;
                    if w == v {
                        break;
                    }
                }
                comp_count += 1;
            }
        }
    }
    (comp, comp_count)
}

/// Whether the `child -> parent_ids` links of a walk's returned claims
/// contain a cycle: what [`LineageResult::cycle_detected`] reports. Every
/// parent named is itself a returned claim (the parent-edge query constrains
/// both ends to them), so this is a cycle among the returned claims.
fn parent_links_have_cycle(parent_map: &HashMap<Uuid, Vec<Uuid>>) -> bool {
    ClaimDigraph::new(
        parent_map
            .iter()
            .flat_map(|(child, parents)| parents.iter().map(move |p| (*child, *p))),
    )
    .has_cycle()
}

// ============================================================================
// Repository Implementation
// ============================================================================

/// Repository for claim lineage queries using recursive CTEs
///
/// This repository provides efficient graph traversal for claim provenance,
/// returning all ancestors, evidence, and reasoning traces in topological order.
///
/// # Example
///
/// ```rust,no_run
/// use epigraph_db::{LineageRepository, create_pool};
/// use epigraph_db::visibility::Viewer;
/// use uuid::Uuid;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let pool = create_pool("postgres://...").await?;
///     let claim_id = Uuid::new_v4();
///
///     // PR-06: reads carry a `Viewer`, and the predicate it emits is applied
///     // inside the recursive CTE — a claim the viewer cannot see is absent from
///     // the lineage rather than present with its content blanked.
///     let viewer = Viewer::resolve(&pool, Uuid::nil()).await?;
///
///     // Max depth of 10, no node cap. `max_nodes` bounds the RESULT SIZE,
///     // which `max_depth` does not: a heavily-corroborated claim can return an
///     // unbounded ancestor set at any depth. `None` keeps the pre-cap
///     // behaviour; see `LineageResult.truncated` for how a caller learns it
///     // got a partial answer.
///     let lineage =
///         LineageRepository::get_lineage(&pool, &viewer, claim_id, Some(10), None).await?;
///
///     // Process claims in topological order (ancestors first)
///     for claim_id in &lineage.topological_order {
///         let claim = lineage.claims.get(claim_id).unwrap();
///         println!("Claim at depth {}: {}", claim.depth, claim.content);
///     }
///
///     Ok(())
/// }
/// ```
pub struct LineageRepository;

impl LineageRepository {
    /// Query lineage for a claim using recursive CTE
    ///
    /// Returns all ancestor claims, their evidence, and reasoning traces
    /// in topological order (ancestors before descendants).
    ///
    /// "Ancestor" means reached over DERIVATION edges only, each in the
    /// direction its relationship is written: [`LINEAGE_INCOMING`]
    /// (`supports`, `elaborates`, `decomposes_to`) names the edge's SOURCE as
    /// the ancestor, and `supersedes` (written new->old) names its TARGET,
    /// the predecessor. `contradicts`, `refutes`, cross-source
    /// `CORROBORATES` and every other relationship are not ancestry and are
    /// not walked. Relationship names are compared case-insensitively.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to trace lineage from
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    /// * `max_nodes` - Optional cap on the number of nodes kept in the
    ///   result. `topological_order` is ancestors-first / target-last, so
    ///   naively keeping the first `n` entries would keep the *furthest*
    ///   ancestors while discarding the target claim itself. Instead, when
    ///   the full result exceeds `max_nodes`, this keeps the target claim
    ///   plus its `max_nodes - 1` nearest ancestors — i.e. the last `n`
    ///   entries of `topological_order`. The trim happens right after the
    ///   walk, BEFORE the edges/evidence/traces statements, so a dropped
    ///   claim is never fetched by them and `claims`/`evidence`/`traces`
    ///   hold the kept set only. Each kept claim's `parent_ids` therefore
    ///   names kept claims only, so every id in it is a key of `claims`. (`parent_trace_ids`
    ///   is not pruned: it can name traces outside the lineage even
    ///   uncapped.) `None` disables the cap entirely.
    ///
    /// # Returns
    /// * `LineageResult` containing all claims, evidence, and traces in the
    ///   lineage. `LineageResult::truncated` is `true` when either a visible
    ///   ancestor lies past `max_depth` (the CTE is run to `max_depth + 1` and
    ///   that probe layer is discarded before anything else reads the rows,
    ///   so the flag is exact rather than inferred from `max_depth_reached`)
    ///   or `max_nodes` trimmed the result.
    ///
    /// # SQL Pattern
    /// One recursive statement that is a breadth-first search with a visited
    /// set: each row is one LAYER, carrying the layer's claims (`frontier`) and
    /// every claim visited so far. Each claim is then hydrated once, at its
    /// shortest depth:
    /// ```sql
    /// WITH RECURSIVE lineage(frontier, visited, depth) AS (
    ///     SELECT ARRAY[id], ARRAY[id], 0 FROM claims WHERE id = $1
    ///     UNION ALL
    ///     SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
    ///     FROM lineage w
    ///     CROSS JOIN LATERAL (SELECT ARRAY(
    ///         SELECT c.id
    ///         FROM unnest(w.frontier) AS l(id)
    ///         JOIN edges e
    ///           ON e.source_type = 'claim' AND e.target_type = 'claim'
    ///          AND ( (e.target_id = l.id AND lower(e.relationship) = ANY($3))  -- LINEAGE_INCOMING
    ///             OR (e.source_id = l.id AND lower(e.relationship) = ANY($4)) ) -- supersedes
    ///         JOIN claims c
    ///           ON c.id = CASE WHEN e.target_id = l.id THEN e.source_id ELSE e.target_id END
    ///         EXCEPT SELECT unnest(w.visited)               -- never revisit
    ///     ) AS ids) nxt
    ///     WHERE w.depth < $2                                -- $2 = max_depth + 1
    ///       AND cardinality(nxt.ids) > 0                    -- frontier exhausted
    /// ),
    /// walked AS (SELECT u.id, w.depth FROM lineage w, unnest(w.frontier) AS u(id))
    /// SELECT c.*, s.depth FROM walked s JOIN claims c ON c.id = s.id ORDER BY s.id;
    /// ```
    ///
    /// A claim enters the visited set in the first layer that reaches it, which
    /// is its shortest depth, and never re-enters: the walk's work is bounded by
    /// the claims and edges it reaches, it stops as soon as a layer adds no new
    /// claim, and a cycle ends it rather than carrying it to the depth bound.
    /// Two earlier forms were worse (backlog f889c86f): the path-enumerating
    /// form (`UNION ALL` carrying `ARRAY[id] as path`, then `DISTINCT ON (id)`)
    /// did one row per PATH, exponential in depth on a dense DAG; a `UNION`
    /// over `(id, depth)` rows bounded that, but re-emitted every claim on a
    /// cycle at every depth up to the bound. The set difference is `EXCEPT`
    /// (hashed or sorted), not `<> ALL(visited)`, which scans the array per
    /// candidate and is quadratic on a wide layer.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    ///
    /// # This is a THIN WRAPPER; the body lives in [`Self::get_lineage_conn`]
    ///
    /// PR-26 inverted the usual `*_conn` shape rather than copying ~180 lines of
    /// SQL into a twin. A duplicated sibling is how `get_by_id_conn` came to
    /// project seven columns where `get_by_id` projected nine — a divergence
    /// invisible to every gate, because a dropped column defaults to a plausible
    /// value rather than erroring. One body cannot drift from itself, and
    /// `visibility_lint.rs` has one SQL text to police instead of two.
    ///
    /// Kept (rather than replaced by the connection-taking form) because
    /// `epigraph-mcp/src/tools/provenance.rs::get_provenance` calls it with a
    /// bare `&PgPool`, and because ~20 assertions in
    /// `epigraph-db/tests/lineage_tests.rs` call it unchanged — which is what
    /// makes those tests a regression check on the inversion.
    ///
    /// That MCP caller is an UNCONVERTED caller-facing lineage read, and
    /// documenting it here as a reason to keep the API is not the same as
    /// registering it. `no_unscoped_pool.rs`'s scan root is
    /// `crates/epigraph-api/src`, so no counter can reach `epigraph-mcp` at all;
    /// it is named with an owner in `docs/tenancy/progress.json`'s `prs.next`,
    /// alongside `epigraph-mcp/src/tools/events.rs`, which is the only control
    /// available for a site outside the scan root.
    ///
    /// Note what the wrapper does and does not buy: it acquires ONE connection
    /// for all five statements, so they can no longer interleave with another
    /// request's writes across five separate checkouts. It does not open a
    /// transaction. A caller that needs the transaction arm reaches
    /// [`Self::get_lineage_conn`] through `ScopedPool::read_as`.
    ///
    /// No `#[instrument]`: the primitive it delegates to carries one with the
    /// same fields, and a span here would double every pool-path call's span
    /// volume for nothing. The ~50 shards that copy this template should not
    /// each add a second identical span.
    pub async fn get_lineage(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
        max_nodes: Option<usize>,
    ) -> Result<LineageResult, DbError> {
        // `ConnectionFailed`, not the `From<sqlx::Error>` catch-all, which sends
        // `PoolTimedOut` to `QueryFailed` and mislabels pool exhaustion as a
        // failing query in the operator's log. Matches
        // `ScopedPool::unscoped_for_maintenance` and every acquire in `pool.rs`.
        let mut conn = pool
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        Self::get_lineage_conn(&mut conn, viewer, claim_id, max_depth, max_nodes).await
    }

    /// [`Self::get_lineage`] on a caller-supplied connection.
    ///
    /// THE PRIMITIVE. All five statements run on `conn`, so a request path that
    /// obtained it from `AppState::read_as` gets the whole walk on one
    /// viewer-stamped connection: the in-query `$V` predicate and the session
    /// GUCs migration 077's policies read are then populated from the same
    /// `Viewer` value, for every statement rather than for the first one.
    ///
    /// The `&Viewer` is not optional decoration — `visibility_lint.rs::every_conn_taking_repo_fn_takes_a_viewer_or_is_exempt`
    /// exists because a `*_conn` sibling written without one would pass BOTH
    /// controls: that lint would not inspect it, and `no_unscoped_pool.rs` would
    /// count its call site as converted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    #[instrument(skip(conn, viewer))]
    pub async fn get_lineage_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
        max_nodes: Option<usize>,
    ) -> Result<LineageResult, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        // The derivation relationships the walk follows, by direction (see
        // [`LINEAGE_INCOMING`]). Already lower-case; the SQL lower-cases the
        // stored relationship, so an upper-case verb edge matches too.
        let incoming: Vec<String> = LINEAGE_INCOMING.iter().map(|r| (*r).to_string()).collect();
        let outgoing: Vec<String> = crate::repos::provenance_chain::PROVENANCE_OUTGOING
            .iter()
            .map(|r| (*r).to_string())
            .collect();

        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE lineage(frontier, visited, depth) AS (
                -- Base case: start with the target claim. One row per BFS
                -- layer: `frontier` is the layer, `visited` every claim of
                -- this and the earlier layers (see the SQL pattern on
                -- `get_lineage`).
                SELECT ARRAY[c.id], ARRAY[c.id], 0
                FROM claims c
                WHERE c.id = $1
                  /* {VISIBILITY:c} */

                UNION ALL

                -- Recursive case: the next layer is the parent claims of the
                -- frontier via DERIVATION edges, minus every claim already
                -- visited, so each claim enters once, at its SHORTEST depth,
                -- and a cycle ends the walk instead of re-entering it.
                -- Direction is a property of the relationship: an incoming
                -- derivation edge ($3) names its source as the parent; a
                -- `supersedes` edge ($4, written new->old) names its target.
                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM lineage w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS l(id)
                        JOIN edges e
                          ON e.source_type = 'claim'
                         AND e.target_type = 'claim'
                         AND ( (e.target_id = l.id AND lower(e.relationship) = ANY($3::text[]))
                            OR (e.source_id = l.id AND lower(e.relationship) = ANY($4::text[])) )
                        JOIN claims c
                          ON c.id = CASE WHEN e.target_id = l.id THEN e.source_id ELSE e.target_id END
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        -- EXCEPT, not `<> ALL(visited)`: a hashed or sorted
                        -- set difference, linear in the layer plus the
                        -- visited set (an array scan per candidate is
                        -- quadratic on a wide layer). It also dedups the layer.
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $2
                  AND cardinality(nxt.ids) > 0
            ),
            -- Each claim once (the walk never revisits), at its SHORTEST depth.
            walked AS (
                SELECT u.id, w.depth
                FROM lineage w
                CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            )
            -- Hydrate once per claim. The predicate is redundant with the
            -- walk's (every id passed it) and costs no bind: every marker
            -- resolves to the same `$5`. `ORDER BY s.id` is load-bearing: the
            -- `max_nodes` cut and `topological_order` stable-sort these rows
            -- by depth, so id order breaks ties inside a depth layer.
            SELECT
                c.id,
                c.content,
                c.truth_value,
                c.agent_id,
                c.created_at,
                c.trace_id,
                s.depth
            FROM walked s
            JOIN claims c ON c.id = s.id
            WHERE true /* {VISIBILITY:c} */
            ORDER BY s.id
            "#,
            5,
        );
        let mut lq = sqlx::query_as::<_, LineageRow>(&sql)
            .bind(claim_id)
            .bind(probe_depth(max_depth))
            .bind(&incoming)
            .bind(&outgoing);
        if let Some(g) = viewer.group_bind() {
            lq = lq.bind(g);
        }
        let lineage_rows: Vec<LineageRow> = lq.fetch_all(&mut *conn).await?;
        // Drop the probe layer FIRST: nothing below may see a row past
        // `max_depth`, so every follow-up query, map and order is built from
        // the same rows as before and only `truncated` learns about the probe.
        let (lineage_rows, truncated_by_depth) = drop_probe_layer(lineage_rows, max_depth);

        // This describes the WALK, so it is measured before the node cap
        // below trims it. `cycle_detected`, by contrast, describes the
        // RETURNED claims and is computed from their `parent_ids` below.
        let max_depth_reached = lineage_rows.iter().map(|r| r.depth).max().unwrap_or(0);

        // Depth-based truncation is exact: the probe layer found a visible
        // ancestor past `max_depth` (see `drop_probe_layer`).
        let mut truncated = truncated_by_depth;

        // Apply the optional node cap BEFORE any follow-up statement, so the
        // cap bounds what is fetched and not only what is returned.
        //
        // topological_order is ancestors-first / target-last, so keeping the
        // *first* n entries would keep the furthest ancestors while dropping
        // the target claim itself. Instead we keep the LAST n entries of that
        // order: the target claim plus its (n - 1) nearest ancestors. The
        // order is computed here with the SAME stable sort used to build
        // `topological_order` below, over rows in the CTE's order, so the kept
        // set is exactly the one the late trim used to keep.
        //
        // Every map below is then built from the kept rows only, and the edges
        // query constrains both ends to them, so `parent_ids` cannot name a
        // claim outside `claims`.
        let mut lineage_rows = lineage_rows;
        if let Some(n) = max_nodes {
            if lineage_rows.len() > n {
                let mut order: Vec<(Uuid, i32)> =
                    lineage_rows.iter().map(|r| (r.id, r.depth)).collect();
                order.sort_by_key(|b| std::cmp::Reverse(b.1)); // Descending depth
                let kept_ids: HashSet<Uuid> =
                    order[order.len() - n..].iter().map(|(id, _)| *id).collect();
                lineage_rows.retain(|r| kept_ids.contains(&r.id));
                truncated = true;
            }
        }

        // Collect claim IDs for subsequent queries
        let claim_ids: Vec<Uuid> = lineage_rows.iter().map(|r| r.id).collect();

        if claim_ids.is_empty() {
            // No row at all (an invisible or missing root) or a cap of zero:
            // the walk's own measurements still stand, and no claim means no
            // cycle.
            return Ok(LineageResult {
                cycle_detected: false,
                max_depth_reached,
                truncated,
                ..LineageResult::default()
            });
        }

        // Query edges to build parent relationships: the same derivation set
        // the walk follows, so `parent_ids` names derivation parents only.
        let esql = viewer.splice(
            r#"
            SELECT source_id, target_id, relationship
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
              AND source_id = ANY($1)
              AND target_id = ANY($1)
              AND (lower(relationship) = ANY($2::text[])
                   OR lower(relationship) = ANY($3::text[]))
              /* {EDGE_VISIBILITY:edges} */
            "#,
            4,
        );
        let mut eq = sqlx::query_as::<_, LineageEdgeRow>(&esql)
            .bind(&claim_ids)
            .bind(&incoming)
            .bind(&outgoing);
        if let Some(g) = viewer.group_bind() {
            eq = eq.bind(g);
        }
        let edges: Vec<LineageEdgeRow> = eq.fetch_all(&mut *conn).await?;

        // Build parent map. An incoming derivation edge `parent -> child`
        // names its source; a `supersedes` edge `new -> old` names its target,
        // the predecessor, as the parent of the claim that replaced it.
        let mut parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for edge in &edges {
            let (child, parent) = if outgoing.contains(&edge.relationship.to_lowercase()) {
                (edge.source_id, edge.target_id)
            } else {
                (edge.target_id, edge.source_id)
            };
            parent_map.entry(child).or_default().push(parent);
        }
        let cycle_detected = parent_links_have_cycle(&parent_map);

        // Query all evidence for claims in lineage
        let vsql = viewer.splice(
            r#"
            SELECT id, claim_id, evidence_type, content_hash
            FROM evidence
            WHERE claim_id = ANY($1)
              /* {VISIBILITY:evidence} */
            "#,
            2,
        );
        let mut vq = sqlx::query_as::<_, EvidenceQueryRow>(&vsql).bind(&claim_ids);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let evidence_rows: Vec<EvidenceQueryRow> = vq.fetch_all(&mut *conn).await?;

        // Build evidence map
        let mut evidence_map: HashMap<Uuid, LineageEvidence> = HashMap::new();
        let mut claim_evidence_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in evidence_rows {
            let evidence = LineageEvidence {
                id: row.id,
                claim_id: row.claim_id,
                evidence_type: row.evidence_type,
                content_hash: row.content_hash,
            };
            evidence_map.insert(row.id, evidence);
            claim_evidence_map
                .entry(row.claim_id)
                .or_default()
                .push(row.id);
        }

        // Query all reasoning traces for claims in lineage
        let trace_ids: Vec<Uuid> = lineage_rows.iter().filter_map(|r| r.trace_id).collect();

        let tsql = viewer.splice(
            r#"
            SELECT id, claim_id, reasoning_type, confidence
            FROM reasoning_traces
            WHERE claim_id = ANY($1)
              /* {VISIBILITY:reasoning_traces} */
            "#,
            2,
        );
        let mut tq = sqlx::query_as::<_, TraceQueryRow>(&tsql).bind(&claim_ids);
        if let Some(g) = viewer.group_bind() {
            tq = tq.bind(g);
        }
        let trace_rows: Vec<TraceQueryRow> = tq.fetch_all(&mut *conn).await?;

        // Query trace parents for DAG structure.
        //
        // `F-PR26-trace-parents-followup` (docs/tenancy/progress.json):
        // `trace_parents` has no tenancy columns, so the parent side is joined
        // to `reasoning_traces` and the viewer predicate is spliced there.
        let trace_parent_rows: Vec<TraceParentRow> = if !trace_ids.is_empty() {
            let psql = viewer.splice(
                r#"
                SELECT tp.trace_id, tp.parent_id
                FROM trace_parents tp
                JOIN reasoning_traces pt ON pt.id = tp.parent_id
                WHERE tp.trace_id = ANY($1)
                  /* {VISIBILITY:pt} */
                "#,
                2,
            );
            let mut pq = sqlx::query_as::<_, TraceParentRow>(&psql).bind(&trace_ids);
            if let Some(g) = viewer.group_bind() {
                pq = pq.bind(g);
            }
            pq.fetch_all(&mut *conn).await?
        } else {
            Vec::new()
        };

        // Build trace parent map
        let mut trace_parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in trace_parent_rows {
            trace_parent_map
                .entry(row.trace_id)
                .or_default()
                .push(row.parent_id);
        }

        // Build trace map
        let mut trace_map: HashMap<Uuid, LineageTrace> = HashMap::new();
        for row in trace_rows {
            let trace = LineageTrace {
                id: row.id,
                claim_id: row.claim_id,
                reasoning_type: row.reasoning_type,
                confidence: row.confidence,
                parent_trace_ids: trace_parent_map.get(&row.id).cloned().unwrap_or_default(),
            };
            trace_map.insert(row.id, trace);
        }

        // Build claims map
        let mut claims_map: HashMap<Uuid, LineageClaim> = HashMap::new();
        for row in &lineage_rows {
            let claim = LineageClaim {
                id: row.id,
                content: row.content.clone(),
                truth_value: row.truth_value,
                agent_id: row.agent_id,
                created_at: row.created_at,
                depth: row.depth,
                parent_ids: parent_map.get(&row.id).cloned().unwrap_or_default(),
                evidence_ids: claim_evidence_map.get(&row.id).cloned().unwrap_or_default(),
                trace_id: row.trace_id,
            };
            claims_map.insert(row.id, claim);
        }

        // Build topological order (sorted by depth descending, so ancestors come first)
        let mut topological_order: Vec<(Uuid, i32)> =
            lineage_rows.iter().map(|r| (r.id, r.depth)).collect();
        topological_order.sort_by_key(|b| std::cmp::Reverse(b.1)); // Descending depth
        let topological_order: Vec<Uuid> =
            topological_order.into_iter().map(|(id, _)| id).collect();

        Ok(LineageResult {
            claims: claims_map,
            evidence: evidence_map,
            traces: trace_map,
            topological_order,
            cycle_detected,
            max_depth_reached,
            truncated,
        })
    }

    /// Detect cycles in the lineage graph
    ///
    /// Returns `true` iff the claims reachable from `claim_id` by walking its
    /// ancestors over EVERY claim-to-claim edge (`target -> source`, any
    /// relationship, unlike the derivation-only lineage walks) contain a
    /// cycle, whether or not it passes through `claim_id`. Only claims and
    /// edges the viewer can read take part, so an edge the viewer cannot read
    /// can neither close a cycle nor be inferred from the answer.
    ///
    /// The walk is a breadth-first search with a visited set inside one
    /// statement (as `get_ancestor_ids`), which also returns the edges among
    /// the claims it reached; the cycle check is then a strongly connected
    /// components pass in memory. Both are linear in the claims and edges
    /// reached, never in the number of paths (backlog c07884a9). Claims more
    /// than 1000 shortest hops away are not examined (the bound the
    /// path-enumerating form had).
    ///
    /// # Arguments
    /// * `executor` - Database executor
    /// * `claim_id` - The claim to check for cycles from
    ///
    /// # Returns
    /// * `true` if a cycle is detected, `false` otherwise
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn detect_cycles<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        let graph = Self::ancestor_graph(executor, viewer, claim_id).await?;
        Ok(graph.has_cycle())
    }

    /// Get the depth of a claim's lineage
    ///
    /// Returns the length of the LONGEST chain of ancestors from the given
    /// claim, walking every claim-to-claim edge (`target -> source`, any
    /// relationship) the viewer can read. On a DAG that is the longest path;
    /// on a graph with cycles each strongly connected component (each set of
    /// claims that derive from one another) counts as ONE step, since the
    /// longest simple path is NP-hard and the path-enumerating form that
    /// computed it was exponential on a dense DAG (backlog c07884a9). Claims
    /// more than 1000 shortest hops away are not examined.
    ///
    /// # Arguments
    /// * `executor` - Database executor
    /// * `claim_id` - The claim to check depth for
    ///
    /// # Returns
    /// * Length of the longest ancestor chain (0 if the claim has no parents,
    ///   or is missing or unreadable)
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_depth<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<i32, DbError> {
        let graph = Self::ancestor_graph(executor, viewer, claim_id).await?;
        Ok(graph.longest_chain_from(claim_id))
    }

    /// The claims reachable from `claim_id` by walking ancestors over every
    /// claim-to-claim edge, as a [`ClaimDigraph`] of the readable edges among
    /// them, pointing `child -> parent` (the walk's direction). One statement.
    async fn ancestor_graph<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<ClaimDigraph, DbError> {
        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it. The edge read after the
        // walk is marked too: an edge the viewer cannot read must not close a
        // cycle among claims it can.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE lineage(frontier, visited, depth) AS (
                SELECT ARRAY[claims.id], ARRAY[claims.id], 0
                FROM claims WHERE id = $1
                  /* {VISIBILITY:claims} */

                -- One row per BFS layer; the next layer is the frontier's
                -- parents minus every claim already visited (see the SQL
                -- pattern on `get_lineage`), so a claim enters once and a
                -- cycle ends the walk.
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM lineage w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS l(id)
                        JOIN edges e ON e.target_id = l.id AND e.target_type = 'claim'
                        JOIN claims c ON e.source_id = c.id AND e.source_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $2
                  AND cardinality(nxt.ids) > 0
            ),
            reached AS (
                SELECT u.id
                FROM lineage w
                CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            )
            -- Every readable claim-to-claim edge with both ends reached, as
            -- (child, parent): the edges the walk followed or found already
            -- visited, and only those.
            SELECT DISTINCT re.target_id AS source_id, re.source_id AS target_id
            FROM edges re
            JOIN reached child ON child.id = re.target_id
            JOIN reached parent ON parent.id = re.source_id
            WHERE re.source_type = 'claim'
              AND re.target_type = 'claim'
              /* {EDGE_VISIBILITY:re} */
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, EdgeQueryRow>(&sql)
            .bind(claim_id)
            .bind(SHAPE_WALK_MAX_DEPTH);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let edges: Vec<EdgeQueryRow> = q.fetch_all(executor).await?;
        Ok(ClaimDigraph::new(
            edges.into_iter().map(|e| (e.source_id, e.target_id)),
        ))
    }

    /// Get ancestor claim IDs only (without full data)
    ///
    /// Returns just the UUIDs of all ancestor claims, useful for
    /// quick membership checks without fetching full claim data.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to get ancestors for
    /// * `max_depth` - Maximum depth to traverse
    ///
    /// # Returns
    /// * Vector of ancestor claim UUIDs in topological order
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_ancestor_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Vec<Uuid>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct IdDepthRow {
            id: Uuid,
            depth: i32,
        }

        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE lineage(frontier, visited, depth) AS (
                SELECT ARRAY[claims.id], ARRAY[claims.id], 0
                FROM claims WHERE id = $1
                  /* {VISIBILITY:claims} */

                -- One row per BFS layer; the next layer is the frontier's
                -- neighbours minus every claim already visited (see the SQL pattern
                -- on `get_lineage`), so a claim enters once, at its shortest depth,
                -- and a cycle ends the walk (f889c86f).
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM lineage w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS l(id)
                        JOIN edges e ON e.target_id = l.id AND e.target_type = 'claim'
                        JOIN claims c ON e.source_id = c.id AND e.source_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $2
                  AND cardinality(nxt.ids) > 0
            )
            SELECT u.id, w.depth
            FROM lineage w
            CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            ORDER BY u.id
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, IdDepthRow>(&sql)
            .bind(claim_id)
            .bind(max_depth);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<IdDepthRow> = q.fetch_all(executor).await?;

        // Sort by depth descending (ancestors first)
        let mut sorted: Vec<(Uuid, i32)> = rows.iter().map(|r| (r.id, r.depth)).collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));

        Ok(sorted.into_iter().map(|(id, _)| id).collect())
    }

    /// Query descendant lineage for a claim using recursive CTE
    ///
    /// Returns all descendant claims (claims that depend on this claim),
    /// their evidence, and reasoning traces in topological order.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to trace descendants from
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    ///
    /// # Returns
    /// * `LineageResult` containing all claims, evidence, and traces in the
    ///   descendant lineage. `truncated` is exact, as in [`Self::get_lineage`]:
    ///   `true` iff a visible descendant lies past `max_depth`.
    ///
    /// # SQL Pattern
    /// The breadth-first walk of [`Self::get_lineage`] (one row per layer, a
    /// visited set, each claim at its shortest depth), following edges in the
    /// opposite direction:
    /// ```sql
    /// WITH RECURSIVE descendants(frontier, visited, depth) AS (
    ///     SELECT ARRAY[id], ARRAY[id], 0 FROM claims WHERE id = $1
    ///     UNION ALL
    ///     SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
    ///     FROM descendants w
    ///     CROSS JOIN LATERAL (SELECT ARRAY(
    ///         SELECT c.id
    ///         FROM unnest(w.frontier) AS d(id)
    ///         JOIN edges e ON e.source_id = d.id AND e.source_type = 'claim'
    ///         JOIN claims c ON e.target_id = c.id AND e.target_type = 'claim'
    ///         EXCEPT SELECT unnest(w.visited)
    ///     ) AS ids) nxt
    ///     WHERE w.depth < $2 AND cardinality(nxt.ids) > 0   -- $2 = max_depth + 1
    /// ),
    /// walked AS (SELECT u.id, w.depth FROM descendants w, unnest(w.frontier) AS u(id))
    /// SELECT c.*, s.depth FROM walked s JOIN claims c ON c.id = s.id ORDER BY s.id;
    /// ```
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    ///
    /// # This is a THIN WRAPPER; the body lives in [`Self::get_descendants_conn`]
    ///
    /// See [`Self::get_lineage`] for why the connection-taking form is the
    /// primitive rather than a copy-pasted twin. This wrapper has no caller
    /// outside `epigraph-api` today (measured by grep over `crates/`), and is
    /// kept anyway: `epigraph-db/tests/lineage_tests.rs` calls it unedited, and
    /// symmetry between the two walks is what stops a later author from
    /// "restoring" one of them by duplicating the body.
    ///
    /// No `#[instrument]`, for the reason given on [`Self::get_lineage`].
    pub async fn get_descendants(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<LineageResult, DbError> {
        // `ConnectionFailed`, not the `From<sqlx::Error>` catch-all — see
        // [`Self::get_lineage`].
        let mut conn = pool
            .acquire()
            .await
            .map_err(|source| DbError::ConnectionFailed { source })?;
        Self::get_descendants_conn(&mut conn, viewer, claim_id, max_depth).await
    }

    /// [`Self::get_descendants`] on a caller-supplied connection. THE PRIMITIVE.
    ///
    /// The descendant walk is NOT interchangeable with the ancestor one and must
    /// not be unified with it: it sorts `topological_order` by depth ASCENDING
    /// where `get_lineage` sorts DESCENDING, and it has no `max_nodes` cap, so
    /// its `truncated` is the depth probe's alone. Each is paired with its own
    /// primitive; only the wrapper/primitive duplication was removed.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database query fails.
    #[instrument(skip(conn, viewer))]
    pub async fn get_descendants_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<LineageResult, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE descendants(frontier, visited, depth) AS (
                -- Base case: start with the source claim
                SELECT ARRAY[c.id], ARRAY[c.id], 0
                FROM claims c
                WHERE c.id = $1
                  /* {VISIBILITY:c} */

                -- One row per BFS layer; the next layer is the frontier's
                -- neighbours minus every claim already visited (see the SQL pattern
                -- on `get_lineage`), so a claim enters once, at its shortest depth,
                -- and a cycle ends the walk (f889c86f).
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM descendants w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS d(id)
                        JOIN edges e ON e.source_id = d.id AND e.source_type = 'claim'
                        JOIN claims c ON e.target_id = c.id AND e.target_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $2
                  AND cardinality(nxt.ids) > 0
            ),
            -- Each claim once (the walk never revisits), at its SHORTEST depth.
            walked AS (
                SELECT u.id, w.depth
                FROM descendants w
                CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            )
            SELECT
                c.id,
                c.content,
                c.truth_value,
                c.agent_id,
                c.created_at,
                c.trace_id,
                s.depth
            FROM walked s
            JOIN claims c ON c.id = s.id
            WHERE true /* {VISIBILITY:c} */
            ORDER BY s.id
            "#,
            3,
        );
        let mut dq = sqlx::query_as::<_, LineageRow>(&sql)
            .bind(claim_id)
            .bind(probe_depth(max_depth));
        if let Some(g) = viewer.group_bind() {
            dq = dq.bind(g);
        }
        let lineage_rows: Vec<LineageRow> = dq.fetch_all(&mut *conn).await?;
        // The probe layer goes first, as in `get_lineage_conn`.
        let (lineage_rows, truncated_by_depth) = drop_probe_layer(lineage_rows, max_depth);

        let max_depth_reached = lineage_rows.iter().map(|r| r.depth).max().unwrap_or(0);

        // Collect claim IDs for subsequent queries
        let claim_ids: Vec<Uuid> = lineage_rows.iter().map(|r| r.id).collect();

        if claim_ids.is_empty() {
            return Ok(LineageResult::default());
        }

        // Query edges to build parent relationships (for descendants, parents are in reverse)
        let esql = viewer.splice(
            r#"
            SELECT source_id, target_id
            FROM edges
            WHERE source_type = 'claim'
              AND target_type = 'claim'
              AND source_id = ANY($1)
              AND target_id = ANY($1)
              /* {EDGE_VISIBILITY:edges} */
            "#,
            2,
        );
        let mut eq = sqlx::query_as::<_, EdgeQueryRow>(&esql).bind(&claim_ids);
        if let Some(g) = viewer.group_bind() {
            eq = eq.bind(g);
        }
        let edges: Vec<EdgeQueryRow> = eq.fetch_all(&mut *conn).await?;

        // Build parent map (source supports target)
        let mut parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for edge in &edges {
            parent_map
                .entry(edge.target_id)
                .or_default()
                .push(edge.source_id);
        }
        let cycle_detected = parent_links_have_cycle(&parent_map);

        // Query all evidence for claims in lineage
        let vsql = viewer.splice(
            r#"
            SELECT id, claim_id, evidence_type, content_hash
            FROM evidence
            WHERE claim_id = ANY($1)
              /* {VISIBILITY:evidence} */
            "#,
            2,
        );
        let mut vq = sqlx::query_as::<_, EvidenceQueryRow>(&vsql).bind(&claim_ids);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let evidence_rows: Vec<EvidenceQueryRow> = vq.fetch_all(&mut *conn).await?;

        // Build evidence map
        let mut evidence_map: HashMap<Uuid, LineageEvidence> = HashMap::new();
        let mut claim_evidence_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in evidence_rows {
            let evidence = LineageEvidence {
                id: row.id,
                claim_id: row.claim_id,
                evidence_type: row.evidence_type,
                content_hash: row.content_hash,
            };
            evidence_map.insert(row.id, evidence);
            claim_evidence_map
                .entry(row.claim_id)
                .or_default()
                .push(row.id);
        }

        // Query all reasoning traces for claims in lineage
        let trace_ids: Vec<Uuid> = lineage_rows.iter().filter_map(|r| r.trace_id).collect();

        let tsql = viewer.splice(
            r#"
            SELECT id, claim_id, reasoning_type, confidence
            FROM reasoning_traces
            WHERE claim_id = ANY($1)
              /* {VISIBILITY:reasoning_traces} */
            "#,
            2,
        );
        let mut tq = sqlx::query_as::<_, TraceQueryRow>(&tsql).bind(&claim_ids);
        if let Some(g) = viewer.group_bind() {
            tq = tq.bind(g);
        }
        let trace_rows: Vec<TraceQueryRow> = tq.fetch_all(&mut *conn).await?;

        // Query trace parents for DAG structure.
        //
        // `F-PR26-trace-parents-followup` (docs/tenancy/progress.json):
        // `trace_parents` has no tenancy columns, so the parent side is joined
        // to `reasoning_traces` and the viewer predicate is spliced there.
        let trace_parent_rows: Vec<TraceParentRow> = if !trace_ids.is_empty() {
            let psql = viewer.splice(
                r#"
                SELECT tp.trace_id, tp.parent_id
                FROM trace_parents tp
                JOIN reasoning_traces pt ON pt.id = tp.parent_id
                WHERE tp.trace_id = ANY($1)
                  /* {VISIBILITY:pt} */
                "#,
                2,
            );
            let mut pq = sqlx::query_as::<_, TraceParentRow>(&psql).bind(&trace_ids);
            if let Some(g) = viewer.group_bind() {
                pq = pq.bind(g);
            }
            pq.fetch_all(&mut *conn).await?
        } else {
            Vec::new()
        };

        // Build trace parent map
        let mut trace_parent_map: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for row in trace_parent_rows {
            trace_parent_map
                .entry(row.trace_id)
                .or_default()
                .push(row.parent_id);
        }

        // Build trace map
        let mut trace_map: HashMap<Uuid, LineageTrace> = HashMap::new();
        for row in trace_rows {
            let trace = LineageTrace {
                id: row.id,
                claim_id: row.claim_id,
                reasoning_type: row.reasoning_type,
                confidence: row.confidence,
                parent_trace_ids: trace_parent_map.get(&row.id).cloned().unwrap_or_default(),
            };
            trace_map.insert(row.id, trace);
        }

        // Build claims map
        let mut claims_map: HashMap<Uuid, LineageClaim> = HashMap::new();
        for row in &lineage_rows {
            let claim = LineageClaim {
                id: row.id,
                content: row.content.clone(),
                truth_value: row.truth_value,
                agent_id: row.agent_id,
                created_at: row.created_at,
                depth: row.depth,
                parent_ids: parent_map.get(&row.id).cloned().unwrap_or_default(),
                evidence_ids: claim_evidence_map.get(&row.id).cloned().unwrap_or_default(),
                trace_id: row.trace_id,
            };
            claims_map.insert(row.id, claim);
        }

        // Build topological order (sorted by depth ascending for descendants)
        let mut topological_order: Vec<(Uuid, i32)> =
            lineage_rows.iter().map(|r| (r.id, r.depth)).collect();
        topological_order.sort_by_key(|a| a.1); // Ascending depth for descendants
        let topological_order: Vec<Uuid> =
            topological_order.into_iter().map(|(id, _)| id).collect();

        Ok(LineageResult {
            claims: claims_map,
            evidence: evidence_map,
            traces: trace_map,
            topological_order,
            cycle_detected,
            max_depth_reached,
            truncated: truncated_by_depth,
        })
    }

    /// Get descendant claim IDs only (without full data)
    ///
    /// Returns just the UUIDs of all descendant claims, useful for
    /// quick membership checks without fetching full claim data.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_id` - The claim to get descendants for
    /// * `max_depth` - Maximum depth to traverse
    ///
    /// # Returns
    /// * Vector of descendant claim UUIDs
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_descendant_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Vec<Uuid>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct IdDepthRow {
            id: Uuid,
            depth: i32,
        }

        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE descendants(frontier, visited, depth) AS (
                SELECT ARRAY[claims.id], ARRAY[claims.id], 0
                FROM claims WHERE id = $1
                  /* {VISIBILITY:claims} */

                -- One row per BFS layer; the next layer is the frontier's
                -- neighbours minus every claim already visited (see the SQL pattern
                -- on `get_lineage`), so a claim enters once, at its shortest depth,
                -- and a cycle ends the walk (f889c86f).
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM descendants w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS d(id)
                        JOIN edges e ON e.source_id = d.id AND e.source_type = 'claim'
                        JOIN claims c ON e.target_id = c.id AND e.target_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $2
                  AND cardinality(nxt.ids) > 0
            )
            SELECT u.id, w.depth
            FROM descendants w
            CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            ORDER BY u.id
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, IdDepthRow>(&sql)
            .bind(claim_id)
            .bind(max_depth);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows: Vec<IdDepthRow> = q.fetch_all(executor).await?;

        // Sort by depth ascending (root first)
        let mut sorted: Vec<(Uuid, i32)> = rows.iter().map(|r| (r.id, r.depth)).collect();
        sorted.sort_by_key(|a| a.1);

        Ok(sorted.into_iter().map(|(id, _)| id).collect())
    }

    /// Find the Lowest Common Ancestor of two claims in the provenance DAG.
    ///
    /// Uses two recursive CTEs to compute ancestor sets, then finds the
    /// shared ancestor with minimum total depth.
    ///
    /// Returns None if the claims have no common ancestor.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claim_a` - First claim UUID
    /// * `claim_b` - Second claim UUID
    /// * `max_depth` - Maximum depth to traverse (None for default of 100)
    ///
    /// # Returns
    /// * `Some(LcaResult)` with the closest common ancestor, or `None` if none exists
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_lca<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_a: Uuid,
        claim_b: Uuid,
        max_depth: Option<i32>,
    ) -> Result<Option<LcaResult>, DbError> {
        let max_depth = max_depth.unwrap_or(100);

        #[derive(sqlx::FromRow)]
        struct LcaRow {
            ancestor_id: Uuid,
            depth_a: i32,
            depth_b: i32,
            total_depth: i32,
        }

        // RECURSIVE CTE. The predicate is on the ANCHOR term, on the
        // RECURSIVE term's `claims` alias, AND on the `edges` join that carries
        // the walk. Marking only the anchor is the classic half-conversion: an
        // invisible claim re-enters through the recursive arm and is returned
        // in full, and `visibility_lint.rs` -- which checks that a marker is
        // present, not where -- would not catch it.
        // TWO recursive CTEs: six markers, all resolving to the same bind.
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE ancestors_a(frontier, visited, depth) AS (
                -- Ancestor set for claim A
                SELECT ARRAY[claims.id], ARRAY[claims.id], 0
                FROM claims WHERE id = $1
                  /* {VISIBILITY:claims} */

                -- One row per BFS layer; the next layer is the frontier's
                -- neighbours minus every claim already visited (see the SQL pattern
                -- on `get_lineage`), so a claim enters once, at its shortest depth,
                -- and a cycle ends the walk (f889c86f).
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM ancestors_a w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS f(id)
                        JOIN edges e ON e.target_id = f.id AND e.target_type = 'claim'
                        JOIN claims c ON e.source_id = c.id AND e.source_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $3
                  AND cardinality(nxt.ids) > 0
            ),
            ancestors_b(frontier, visited, depth) AS (
                -- Ancestor set for claim B
                SELECT ARRAY[claims.id], ARRAY[claims.id], 0
                FROM claims WHERE id = $2
                  /* {VISIBILITY:claims} */

                -- One row per BFS layer; the next layer is the frontier's
                -- neighbours minus every claim already visited (see the SQL pattern
                -- on `get_lineage`), so a claim enters once, at its shortest depth,
                -- and a cycle ends the walk (f889c86f).
                UNION ALL

                SELECT nxt.ids, w.visited || nxt.ids, w.depth + 1
                FROM ancestors_b w
                CROSS JOIN LATERAL (
                    SELECT ARRAY(
                        SELECT c.id
                        FROM unnest(w.frontier) AS f(id)
                        JOIN edges e ON e.target_id = f.id AND e.target_type = 'claim'
                        JOIN claims c ON e.source_id = c.id AND e.source_type = 'claim'
                        WHERE true
                          /* {VISIBILITY:c} */ /* {EDGE_VISIBILITY:e} */
                        EXCEPT
                        SELECT unnest(w.visited)
                    ) AS ids
                ) nxt
                WHERE w.depth < $3
                  AND cardinality(nxt.ids) > 0
            ),
            -- Each ancestor once, at its shortest depth from A (resp. B).
            reach_a AS (
                SELECT u.id, w.depth
                FROM ancestors_a w
                CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            ),
            reach_b AS (
                SELECT u.id, w.depth
                FROM ancestors_b w
                CROSS JOIN LATERAL unnest(w.frontier) AS u(id)
            )
            SELECT
                a.id AS ancestor_id,
                a.depth AS depth_a,
                b.depth AS depth_b,
                (a.depth + b.depth) AS total_depth
            FROM reach_a a
            INNER JOIN reach_b b ON a.id = b.id
            ORDER BY total_depth ASC
            LIMIT 1
            "#,
            4,
        );
        let mut q = sqlx::query_as::<_, LcaRow>(&sql)
            .bind(claim_a)
            .bind(claim_b)
            .bind(max_depth);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let row: Option<LcaRow> = q.fetch_optional(executor).await?;

        Ok(row.map(|r| LcaResult {
            ancestor_id: r.ancestor_id,
            depth_from_a: r.depth_a,
            depth_from_b: r.depth_b,
            total_depth: r.total_depth,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` fresh ids, so a test can name nodes by index.
    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    fn graph(v: &[Uuid], edges: &[(usize, usize)]) -> ClaimDigraph {
        ClaimDigraph::new(edges.iter().map(|&(f, t)| (v[f], v[t])))
    }

    #[test]
    fn digraph_dag_has_no_cycle_and_its_longest_chain() {
        // 0 -> 1 -> 2 -> 3 plus the shortcut 0 -> 3 and a diamond 0 -> 4 -> 3.
        let v = ids(5);
        let g = graph(&v, &[(0, 1), (1, 2), (2, 3), (0, 3), (0, 4), (4, 3)]);
        assert!(!g.has_cycle(), "a diamond and a shortcut are not cycles");
        assert_eq!(g.longest_chain_from(v[0]), 3, "past the shortcut");
        assert_eq!(g.longest_chain_from(v[1]), 2);
        assert_eq!(g.longest_chain_from(v[3]), 0, "a sink");
        assert_eq!(g.longest_chain_from(Uuid::new_v4()), 0, "not in the graph");
    }

    #[test]
    fn digraph_repeated_edge_counts_once() {
        let v = ids(2);
        let g = graph(&v, &[(0, 1), (0, 1), (0, 1)]);
        assert!(!g.has_cycle());
        assert_eq!(g.longest_chain_from(v[0]), 1);
    }

    #[test]
    fn digraph_self_loop_is_a_cycle() {
        let v = ids(2);
        let g = graph(&v, &[(0, 1), (1, 1)]);
        assert!(g.has_cycle());
        assert_eq!(g.longest_chain_from(v[0]), 1, "the loop adds no step");
    }

    #[test]
    fn digraph_cycle_away_from_the_root_is_found_and_counted_once() {
        // 0 -> 1 -> {2 <-> 3 -> 4 -> 2} -> 5, and 3 -> 5 as a second exit.
        let v = ids(6);
        let g = graph(
            &v,
            &[(0, 1), (1, 2), (2, 3), (3, 4), (4, 2), (4, 5), (3, 5)],
        );
        assert!(g.has_cycle());
        assert_eq!(
            g.longest_chain_from(v[0]),
            3,
            "0, 1, the component {{2, 3, 4}}, 5"
        );
        assert_eq!(g.longest_chain_from(v[5]), 0);
    }

    #[test]
    fn digraph_long_chain_does_not_recurse() {
        // A recursive SCC pass would overflow the stack on a long chain.
        let v = ids(200_000);
        let edges: Vec<(usize, usize)> = (0..v.len() - 1).map(|i| (i, i + 1)).collect();
        let g = graph(&v, &edges);
        assert!(!g.has_cycle());
        assert_eq!(g.longest_chain_from(v[0]), 199_999);
        // Close it into a ring: one component, no step.
        let mut ring = edges;
        ring.push((v.len() - 1, 0));
        let g = graph(&v, &ring);
        assert!(g.has_cycle());
        assert_eq!(g.longest_chain_from(v[0]), 0);
    }

    #[test]
    fn parent_links_cycle_follows_the_links() {
        let v = ids(3);
        let mut links: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        links.insert(v[0], vec![v[1], v[2]]);
        links.insert(v[1], vec![v[2]]);
        assert!(!parent_links_have_cycle(&links));
        links.insert(v[2], vec![v[0]]);
        assert!(parent_links_have_cycle(&links));
        assert!(!parent_links_have_cycle(&HashMap::new()));
    }

    /// Create a test agent in the database and return its UUID.
    async fn create_test_agent(pool: &PgPool) -> Uuid {
        let agent_id = Uuid::new_v4();
        let mut pk = [0u8; 32];
        pk[..16].copy_from_slice(agent_id.as_bytes());
        sqlx::query(
            "INSERT INTO agents (id, display_name, public_key) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
        )
        .bind(agent_id)
        .bind(format!("lca-test-{}", &agent_id.to_string()[..8]))
        .bind(&pk[..])
        .execute(pool)
        .await
        .unwrap();
        agent_id
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lineage_repository_exists(_pool: sqlx::PgPool) {
        // Verifies the repository compiles correctly; full integration tests are in tests/lineage_tests.rs
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_shared_parent(pool: sqlx::PgPool) {
        // Setup: parent_claim <-- child_a, parent_claim <-- child_b
        // Expected: LCA of child_a and child_b is parent_claim at depth (1, 1)
        let test_agent = create_test_agent(&pool).await;

        let parent_id = Uuid::new_v4();
        let child_a = Uuid::new_v4();
        let child_b = Uuid::new_v4();

        // Insert claims
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(parent_id)
            .bind("Parent claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(child_a)
            .bind("Child A")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(child_b)
            .bind("Child B")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        // Insert edges: parent -> child_a, parent -> child_b
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(parent_id)
            .bind(child_a)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(parent_id)
            .bind(child_b)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            child_a,
            child_b,
            None,
        )
        .await
        .unwrap();

        assert!(result.is_some(), "Expected a common ancestor");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, parent_id);
        assert_eq!(lca.depth_from_a, 1);
        assert_eq!(lca.depth_from_b, 1);
        assert_eq!(lca.total_depth, 2);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_no_common_ancestor(pool: sqlx::PgPool) {
        // Setup: two unrelated claims with no shared ancestry
        // Expected: get_lca returns None
        let test_agent = create_test_agent(&pool).await;

        let claim_a = Uuid::new_v4();
        let claim_b = Uuid::new_v4();

        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(claim_a)
            .bind("Isolated claim A")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(claim_b)
            .bind("Isolated claim B")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            claim_a,
            claim_b,
            None,
        )
        .await
        .unwrap();

        assert!(
            result.is_none(),
            "Expected no common ancestor for unrelated claims"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_diamond(pool: sqlx::PgPool) {
        // Setup: diamond graph
        //     root
        //    /    \
        //  mid_a  mid_b
        //    \    /
        //     leaf
        // Expected: LCA of leaf via mid_a and leaf via mid_b converges at root,
        // but we query LCA(mid_a, mid_b) which should be root at depth (1, 1)
        let test_agent = create_test_agent(&pool).await;

        let root = Uuid::new_v4();
        let mid_a = Uuid::new_v4();
        let mid_b = Uuid::new_v4();

        // Insert claims
        for (id, content) in [(root, "Root claim"), (mid_a, "Mid A"), (mid_b, "Mid B")] {
            sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
                .bind(id)
                .bind(content)
                .bind(test_agent)
                .execute(&pool)
                .await
                .unwrap();
        }

        // Edges: root -> mid_a, root -> mid_b
        for target in [mid_a, mid_b] {
            sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
                .bind(Uuid::new_v4())
                .bind(root)
                .bind(target)
                .execute(&pool)
                .await
                .unwrap();
        }

        let result = LineageRepository::get_lca(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            mid_a,
            mid_b,
            None,
        )
        .await
        .unwrap();

        assert!(result.is_some(), "Expected root as LCA in diamond");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, root);
        assert_eq!(lca.total_depth, 2); // depth 1 from each
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_lca_self_ancestor(pool: sqlx::PgPool) {
        // Setup: A -> B (A is ancestor/parent of B)
        // Expected: LCA(A, B) is A, with depth_from_a=0, depth_from_b=1
        let test_agent = create_test_agent(&pool).await;

        let ancestor = Uuid::new_v4();
        let descendant = Uuid::new_v4();

        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(ancestor)
            .bind("Ancestor claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO claims (id, content, content_hash, truth_value, agent_id) VALUES ($1, $2, sha256($1::text::bytea), 0.5, $3)")
            .bind(descendant)
            .bind("Descendant claim")
            .bind(test_agent)
            .execute(&pool)
            .await
            .unwrap();

        // Edge: ancestor -> descendant
        sqlx::query("INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship) VALUES ($1, $2, 'claim', $3, 'claim', 'supports')")
            .bind(Uuid::new_v4())
            .bind(ancestor)
            .bind(descendant)
            .execute(&pool)
            .await
            .unwrap();

        let result = LineageRepository::get_lca(
            &pool,
            &crate::visibility::Viewer::test_scoped(uuid::Uuid::nil(), vec![]),
            ancestor,
            descendant,
            None,
        )
        .await
        .unwrap();

        assert!(result.is_some(), "Expected ancestor as LCA");
        let lca = result.unwrap();
        assert_eq!(lca.ancestor_id, ancestor);
        assert_eq!(lca.depth_from_a, 0);
        assert_eq!(lca.depth_from_b, 1);
        assert_eq!(lca.total_depth, 1);
    }
}
