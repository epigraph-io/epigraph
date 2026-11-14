//! Viewer-filtered reads backing the graph-visualisation endpoints
//! (`routes/graph.rs`, `routes/graph_neighborhood.rs`).
//!
//! # Why this module exists
//!
//! These statements lived inline in `crates/epigraph-api/src/routes/` until
//! PR-07, which is both a CLAUDE.md violation ("All SQL stays in
//! `crates/epigraph-db/src/repos/`") and the reason they were never filtered:
//! the `{VISIBILITY:...}` marker convention is a *repo-layer* convention, and a
//! handler cannot splice a predicate it never writes.
//!
//! The graph endpoints are a soft target precisely because they do not look
//! like claim reads. They are named for clusters, neighborhoods and layouts,
//! but every one of them joins `claims` to fetch a human-readable `label` —
//! which is `claims.content`, verbatim. An unfiltered graph expansion is a
//! corpus dump with a force-directed diagram on top.
//!
//! # What is filtered here, and what is deliberately not
//!
//! Three groups of tables appear in these statements. They are listed
//! separately because they have genuinely different reasons, and an earlier
//! version of this comment collapsed them into one sentence that read as
//! though the membership tables were exempt.
//!
//! 1. **`claims` — filtered.** Every node projection joins it for the
//!    human-readable `label`, which is `claims.content` verbatim.
//!
//! 2. **`claim_cluster_membership` and `claim_neighborhood_membership` —
//!    filtered.** Both ARE in migration 062's `tier_a` array (alongside
//!    `claim_clusters`), so both carry `owner_group_id` and `visibility`. Every
//!    function here traverses one of them, and all four join sites now splice
//!    `/* {VISIBILITY:m} */`. Leaving them unfiltered would have disclosed
//!    *which* claims a private cluster or neighborhood contains even where the
//!    claim rows themselves were withheld.
//!
//! 3. **Cluster/run/neighborhood metadata — NOT filtered, and correctly so.**
//!    `graph_cluster_runs`, `graph_clusters`, `graph_neighborhoods`,
//!    `cluster_edges` and `neighborhood_edges` are absent from the `tier_a`
//!    array — they have no `owner_group_id` column to filter on — and they hold
//!    precomputed layout aggregates, not claim content. They stay in the
//!    handlers. Note this is a different set of tables from group 2 despite the
//!    similar names; `claim_clusters` (tenancy-bearing) is not `graph_clusters`
//!    (not tenancy-bearing).
//!
//! # The `edges` traversals — filtered
//!
//! [`subgraph_edges`] has been filtered since PR-07 (finding M8), with
//! [`Viewer::edge_predicate_fragment`] via `/* {EDGE_VISIBILITY:edges} */`
//! since PR-13. The `edges` joins *inside the node projections* —
//! [`expand_cluster_nodes`], [`neighborhood_compound_nodes`],
//! [`neighborhood_atomic_nodes`], [`neighborhood_compound_groups`] and
//! [`compound_neighbors`] — carried no marker until backlog batch B08 added one
//! to each (`F-edges-unfiltered`). They disclosed *structure* (which ids relate
//! to which, and degree counts), never content, because the returned rows were
//! already claims-filtered.
//!
//! Each marker's placement follows one rule: the result must equal what the
//! statement returns on a graph WITHOUT the edges the viewer cannot read.
//!
//! * In a `JOIN`'s `WHERE`, or a scalar subquery's `WHERE`, the edge simply is
//!   not walked.
//! * In a `LEFT JOIN ... ON` that COUNTS or MAPS (`expand_cluster_nodes`'s
//!   degree, `compound_neighbors`' projection onto a parent compound), the
//!   predicate goes in the `ON`: in `WHERE` it would drop the left row, a
//!   readable claim, whenever every edge it has is hidden.
//! * Inside a `NOT EXISTS` that CLASSIFIES a readable row (`standalone_nodes`,
//!   `center_atoms`), the predicate goes inside it. A hidden edge then no
//!   longer changes the classification, which is the point: the row being
//!   classified is already readable, so no unreadable row is admitted by the
//!   suppression failing to fire. This is NOT the fail-open shape the
//!   `visibility.rs` module doc warns about, where a filtered `LEFT JOIN` is
//!   used to SUPPRESS a row that must stay suppressed.
//!
//! [`subgraph_edges`]: GraphViewRepository::subgraph_edges
//! [`expand_cluster_nodes`]: GraphViewRepository::expand_cluster_nodes
//! [`neighborhood_compound_nodes`]: GraphViewRepository::neighborhood_compound_nodes
//! [`neighborhood_atomic_nodes`]: GraphViewRepository::neighborhood_atomic_nodes
//! [`neighborhood_compound_groups`]: GraphViewRepository::neighborhood_compound_groups
//! [`compound_neighbors`]: GraphViewRepository::compound_neighbors
//! [`Viewer::edge_predicate_fragment`]: crate::visibility::Viewer::edge_predicate_fragment

use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;
use crate::visibility::Viewer;

/// A graph node as the visualisation endpoints render it.
///
/// `label` is `COALESCE(claims.content, id::text)` — i.e. claim content.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GraphNodeRow {
    pub id: Uuid,
    pub label: String,
    pub entity_type: String,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub conflict_k: Option<f64>,
}

/// A node of an atomic (claim-level) neighborhood expansion.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AtomicNodeRow {
    pub id: Uuid,
    pub label: String,
    pub compound_id: Option<Uuid>,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

/// A node of a compound-mode neighborhood expansion: either a compound (a
/// claim with `decomposes_to` children in the neighborhood) or a standalone
/// claim.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CompoundNodeRow {
    pub id: Uuid,
    pub label: String,
    pub kind: String,
    pub atom_count: i32,
    pub pignistic_prob: Option<f64>,
    pub frame_id: Option<Uuid>,
}

/// A claim node in a `load_subgraph` response.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubgraphClaimRow {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub confidence: Option<f64>,
    pub methodology: Option<String>,
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
    pub mass_on_missing: Option<f64>,
}

/// An evidence node in a `load_subgraph` response.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubgraphEvidenceRow {
    pub id: Uuid,
    pub source_url: Option<String>,
    pub properties: serde_json::Value,
}

/// An edge in a `load_subgraph` response.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubgraphEdgeRow {
    pub id: Uuid,
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub source_type: String,
    pub target_type: String,
    pub relationship: String,
    pub properties: serde_json::Value,
}

/// A parent compound and the neighborhood atoms it decomposes to.
/// Result row for [`GraphViewRepository::subgraph_traces`].
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubgraphTraceRow {
    pub id: Uuid,
    pub methodology: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CompoundGroupRow {
    pub compound_id: Uuid,
    pub label: String,
    pub member_atom_ids: Vec<Uuid>,
}

/// A neighbouring compound in the compound-neighborhood projection.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CompoundNeighborRow {
    pub id: Uuid,
    pub content: String,
    pub relationship: String,
    pub atom_edge_count: i64,
    pub total_strength: f64,
    pub pignistic_prob: Option<f64>,
}

/// The node table `POST /api/v1/graph/query` anchors on (a closed set: no
/// caller string ever reaches a table name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GqlNodeTable {
    Claims,
    Evidence,
    Agents,
    ReasoningTraces,
}

impl GqlNodeTable {
    const fn table(self) -> &'static str {
        match self {
            Self::Claims => "claims",
            Self::Evidence => "evidence",
            Self::Agents => "agents",
            Self::ReasoningTraces => "reasoning_traces",
        }
    }

    /// `agents` carries no tenancy columns (it is not in migration 062's
    /// `tier_a`), so it is the one anchor with no predicate to splice.
    const fn tenanted(self) -> bool {
        !matches!(self, Self::Agents)
    }
}

/// A column a graph-query condition may name.
#[derive(Debug, Clone, PartialEq)]
pub enum GqlColumn {
    TruthValue,
    /// `(properties->>'confidence')::float8`.
    Confidence,
    /// `properties->>'<name>'`; `name` must be ASCII alphanumeric or `_`.
    Property(String),
}

/// A graph-query comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GqlOp {
    Eq,
    Gt,
    Lt,
    Gte,
    Lte,
}

/// A graph-query comparison value. Numbers and text are bound; a boolean is
/// written into the statement (it is one of two fixed tokens).
#[derive(Debug, Clone, PartialEq)]
pub enum GqlValue {
    Number(f64),
    Text(String),
    Bool(bool),
}

/// One `WHERE` condition on the anchor table.
#[derive(Debug, Clone, PartialEq)]
pub struct GqlCondition {
    pub column: GqlColumn,
    pub op: GqlOp,
    pub value: GqlValue,
}

/// Which way a graph-query walk follows `edges`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GqlDirection {
    Outgoing,
    Incoming,
    Any,
}

/// The `edges` walk of a graph query with an edge pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GqlWalk<'a> {
    /// Already checked against the route's relationship allowlist; bound, not
    /// written into the statement.
    pub relationship: Option<&'a str>,
    pub direction: GqlDirection,
    pub min_hops: usize,
    pub max_hops: usize,
}

/// Reads for the graph-visualisation endpoints.
pub struct GraphViewRepository;

impl GraphViewRepository {
    /// Nodes of one cluster in the latest graph-cluster run, ordered by
    /// allowlisted-relationship degree then pignistic probability.
    ///
    /// Backs `GET /api/v1/graph/clusters/:id/expand`. `degree_relationships`
    /// is the relationship allowlist used for the degree ordering.
    ///
    /// The degree counts only edges the viewer can read. The edge predicate is
    /// in the `LEFT JOIN`'s `ON`, not in `WHERE`: a member whose every edge is
    /// hidden keeps a degree of 0 instead of being dropped.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, degree_relationships))]
    pub async fn expand_cluster_nodes<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        cluster_id: Uuid,
        run_id: Uuid,
        degree_relationships: &[String],
        budget: i64,
    ) -> Result<Vec<GraphNodeRow>, DbError> {
        let sql = viewer.splice(
            "WITH degree AS (
                SELECT m.claim_id, COUNT(e.*) AS deg
                FROM claim_cluster_membership m
                LEFT JOIN edges e ON (e.source_id = m.claim_id OR e.target_id = m.claim_id)
                                  AND e.relationship = ANY($3)
                                  /* {EDGE_VISIBILITY:e} */
                WHERE m.cluster_id = $1 AND m.run_id = $2 /* {VISIBILITY:m} */
                GROUP BY m.claim_id
            )
            SELECT c.id,
                   COALESCE(c.content, c.id::text) AS label,
                   'claim'::text AS entity_type,
                   c.pignistic_prob,
                   (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id,
                   $1::uuid AS cluster_id,
                   NULL::float8 AS conflict_k
            FROM degree d
            JOIN claims c ON c.id = d.claim_id
            WHERE true /* {VISIBILITY:c} */
            ORDER BY d.deg DESC NULLS LAST, c.pignistic_prob DESC NULLS LAST
            LIMIT $4",
            5,
        );
        let mut q = sqlx::query_as::<_, GraphNodeRow>(&sql)
            .bind(cluster_id)
            .bind(run_id)
            .bind(degree_relationships)
            .bind(budget);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Compound-mode nodes of one precomputed neighborhood: each compound that
    /// owns atoms in the neighborhood, plus each standalone atom.
    ///
    /// Both arms of the `UNION ALL` project `claims.content` as `label`, so
    /// **both** carry a visibility marker. A predicate on only one arm would
    /// look filtered in review and leak through the other — which is why the
    /// marker is written per-`FROM`, not per-statement.
    ///
    /// Every `edges` read carries `{EDGE_VISIBILITY:e}`, including the two
    /// `NOT EXISTS` probes in `standalone_nodes`: an atom whose only
    /// `decomposes_to` edge is hidden is served as standalone, exactly as if
    /// the edge did not exist. Unfiltered, the probe would drop that readable
    /// atom from the response, and its absence would tell the viewer a hidden
    /// edge exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn neighborhood_compound_nodes<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        neighborhood_id: Uuid,
    ) -> Result<Vec<CompoundNodeRow>, DbError> {
        let sql = viewer.splice(
            r#"
            WITH atoms AS (
                SELECT m.claim_id
                FROM claim_neighborhood_membership m
                WHERE m.neighborhood_id = $1 /* {VISIBILITY:m} */
            ),
            compound_to_atoms AS (
                SELECT e.source_id AS compound_id, e.target_id AS atom_id
                FROM edges e
                JOIN atoms a ON a.claim_id = e.target_id
                WHERE e.relationship = 'decomposes_to' /* {EDGE_VISIBILITY:e} */
            ),
            compound_nodes AS (
                SELECT cta.compound_id AS id, COUNT(*)::int AS atom_count
                FROM compound_to_atoms cta
                GROUP BY cta.compound_id
            ),
            standalone_nodes AS (
                SELECT a.claim_id AS id
                FROM atoms a
                WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.target_id = a.claim_id AND e.relationship = 'decomposes_to' /* {EDGE_VISIBILITY:e} */)
                  AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.source_id = a.claim_id AND e.relationship = 'decomposes_to' /* {EDGE_VISIBILITY:e} */)
            )
            SELECT c.id, COALESCE(c.content, c.id::text) AS label, 'compound'::text AS kind,
                   cn.atom_count, c.pignistic_prob,
                   (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id
            FROM compound_nodes cn JOIN claims c ON c.id = cn.id
            WHERE true /* {VISIBILITY:c} */
            UNION ALL
            SELECT c.id, COALESCE(c.content, c.id::text), 'standalone'::text, 0, c.pignistic_prob,
                   (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1)
            FROM standalone_nodes s JOIN claims c ON c.id = s.id
            WHERE true /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, CompoundNodeRow>(&sql).bind(neighborhood_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Claim-level nodes belonging to one precomputed neighborhood.
    ///
    /// `compound_id` is a projected identifier, so its subquery walks only a
    /// `decomposes_to` edge the viewer can read.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn neighborhood_atomic_nodes<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        neighborhood_id: Uuid,
    ) -> Result<Vec<AtomicNodeRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id,
                   COALESCE(c.content, c.id::text) AS label,
                   (SELECT e.source_id FROM edges e
                    WHERE e.target_id = c.id AND e.relationship = 'decomposes_to'
                      /* {EDGE_VISIBILITY:e} */
                    LIMIT 1) AS compound_id,
                   c.pignistic_prob,
                   (SELECT cf.frame_id FROM claim_frames cf WHERE cf.claim_id = c.id LIMIT 1) AS frame_id
            FROM claim_neighborhood_membership m
            JOIN claims c ON c.id = m.claim_id
            WHERE m.neighborhood_id = $1 /* {VISIBILITY:c} */ /* {VISIBILITY:m} */
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, AtomicNodeRow>(&sql).bind(neighborhood_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The compound groupings of an atomic neighborhood: each parent compound
    /// with its member atom ids.
    ///
    /// `label` is the compound's `claims.content`, which is why this is
    /// filtered even though the row is nominally an edge aggregate. It sits in
    /// the same handler as [`Self::neighborhood_atomic_nodes`]; converting only
    /// the node projection would have left the compound labels leaking from
    /// the same response body.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn neighborhood_compound_groups<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        neighborhood_id: Uuid,
    ) -> Result<Vec<CompoundGroupRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT e.source_id AS compound_id,
                   COALESCE(c.content, c.id::text) AS label,
                   array_agg(e.target_id ORDER BY e.target_id) AS member_atom_ids
            FROM edges e
            JOIN claims c ON c.id = e.source_id
            JOIN claim_neighborhood_membership m ON m.claim_id = e.target_id AND m.neighborhood_id = $1
            WHERE e.relationship = 'decomposes_to'
              /* {VISIBILITY:c} */ /* {VISIBILITY:m} */ /* {EDGE_VISIBILITY:e} */
            GROUP BY 1, 2
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, CompoundGroupRow>(&sql).bind(neighborhood_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The centre claim's content for a compound-neighborhood expansion.
    ///
    /// `Ok(None)` when the claim does not exist **or the viewer cannot see
    /// it**; the caller renders both as 404 so the endpoint is not an
    /// existence oracle.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn compound_center_content<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            "SELECT content FROM claims WHERE id = $1 /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(executor).await?)
    }

    /// Compounds adjacent to `claim_id` through positive-weight epistemic
    /// edges, aggregated by (compound, relationship).
    ///
    /// Both endpoints of every epistemic edge are projected to their parent
    /// compound (or themselves if standalone); the centre's own projection is
    /// excluded so the result carries no self-loops.
    ///
    /// All four `edges` reads are filtered. `center_atoms`' positive arm and
    /// its `NOT EXISTS` carry the SAME predicate, so the centre is "its
    /// readable children, or itself when it has none". The projection
    /// `LEFT JOIN edges d` carries it in the `ON`: an atom whose parent edge is
    /// hidden stands as itself rather than projecting onto that parent.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn compound_neighbors<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        claim_id: Uuid,
        limit: i64,
    ) -> Result<Vec<CompoundNeighborRow>, DbError> {
        let sql = viewer.splice(
            r#"
            WITH seed AS (
                SELECT $1::uuid AS center
            ),
            center_atoms AS (
                SELECT e.target_id AS atom_id
                FROM edges e, seed
                WHERE e.source_id = seed.center AND e.relationship = 'decomposes_to'
                  /* {EDGE_VISIBILITY:e} */
                UNION
                SELECT seed.center FROM seed
                WHERE NOT EXISTS (
                    SELECT 1 FROM edges ce WHERE ce.source_id = (SELECT center FROM seed)
                    AND ce.relationship = 'decomposes_to' /* {EDGE_VISIBILITY:ce} */
                )
            ),
            epistemic_edges AS (
                SELECT
                    CASE WHEN ca.atom_id = e.source_id THEN e.target_id ELSE e.source_id END AS other_atom_id,
                    e.relationship,
                    ft.forward_strength
                FROM edges e
                JOIN edge_to_factor_type(e.relationship) ft ON ft.forward_strength > 0
                JOIN center_atoms ca
                    ON ca.atom_id = e.source_id OR ca.atom_id = e.target_id
                WHERE e.source_id != e.target_id /* {EDGE_VISIBILITY:e} */
            ),
            projected AS (
                SELECT
                    COALESCE(d.source_id, ee.other_atom_id) AS compound_id,
                    ee.relationship,
                    ee.forward_strength
                FROM epistemic_edges ee
                LEFT JOIN edges d
                    ON d.target_id = ee.other_atom_id
                    AND d.relationship = 'decomposes_to'
                    /* {EDGE_VISIBILITY:d} */
            )
            SELECT
                c.id,
                c.content,
                p.relationship,
                COUNT(*)::bigint AS atom_edge_count,
                SUM(p.forward_strength)::double precision AS total_strength,
                c.pignistic_prob
            FROM projected p
            JOIN claims c ON c.id = p.compound_id
            WHERE p.compound_id != $1::uuid /* {VISIBILITY:c} */
            GROUP BY c.id, c.content, p.relationship, c.pignistic_prob
            ORDER BY atom_edge_count DESC, c.id
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, CompoundNeighborRow>(&sql)
            .bind(claim_id)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Claim nodes of an arbitrary id set, for `load_subgraph`.
    ///
    /// # Why this exists
    ///
    /// `routes/graph_query_utils.rs::load_subgraph` is a **shared helper**
    /// reached from three handlers (`graph_query.rs` twice, `edges.rs` once).
    /// It took no `Viewer` and ran
    /// `SELECT id, content, ... FROM claims WHERE id = ANY($1)` unfiltered,
    /// building each node's `label` from `content`. Because the helper's
    /// signature had no viewer in it, there was nothing at any call site for a
    /// reviewer to notice — every caller looked filtered and none was. That is
    /// what makes it worth its own repo function rather than a fix in place.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, node_ids))]
    pub async fn subgraph_claims<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        node_ids: &[Uuid],
    ) -> Result<Vec<SubgraphClaimRow>, DbError> {
        let sql = viewer.splice(
            "SELECT id, content, truth_value, \
                    (properties->>'confidence')::float8 AS confidence, \
                    properties->>'methodology' AS methodology, \
                    belief, plausibility, pignistic_prob, mass_on_missing \
             FROM claims \
             WHERE id = ANY($1) /* {VISIBILITY:claims} */",
            2,
        );
        let mut q = sqlx::query_as::<_, SubgraphClaimRow>(&sql).bind(node_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Evidence nodes of an arbitrary id set, for `load_subgraph`.
    ///
    /// `evidence` is a `tier_a` root in migration 062 and carries its own
    /// tenancy columns, so it is filtered on its own predicate rather than
    /// being inferred from the claims it supports.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, node_ids))]
    pub async fn subgraph_evidence<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        node_ids: &[Uuid],
    ) -> Result<Vec<SubgraphEvidenceRow>, DbError> {
        let sql = viewer.splice(
            "SELECT id, source_url, properties \
             FROM evidence \
             WHERE id = ANY($1) /* {VISIBILITY:evidence} */",
            2,
        );
        let mut q = sqlx::query_as::<_, SubgraphEvidenceRow>(&sql).bind(node_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Edges wholly inside an id set, for `load_subgraph`.
    ///
    /// `edges` is a `tier_a` root and carries tenancy columns, so unlike the
    /// structural traversals elsewhere in this module this one CAN be filtered
    /// on its own predicate today, and is.
    ///
    /// # The caller must pass SURVIVING ids
    ///
    /// This doc previously asserted that "the caller additionally narrows
    /// `node_ids` to the ids that survived the node projections". No caller
    /// did: `load_subgraph` fetched edges FIRST, before any node projection had
    /// run, and never recomputed the set — so the response's `edges` array
    /// enumerated ids the `nodes` projection had withheld (an id-enumeration
    /// oracle, since `edges.visibility` defaults to `'public'` under migration
    /// 062 and the edge predicate therefore matches every row today). PR-07's
    /// follow-up reordered `load_subgraph` so the narrowing the doc described
    /// actually happens.
    ///
    /// The obligation is on the caller and cannot be enforced by a signature,
    /// so it is stated here as a precondition rather than implied: pass the ids
    /// that survived the node projections, not the caller's raw request set.
    /// Both endpoints must be in the set for an edge to be returned, so an edge
    /// survives exactly when both of its endpoints did.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, node_ids))]
    pub async fn subgraph_edges<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        node_ids: &[Uuid],
    ) -> Result<Vec<SubgraphEdgeRow>, DbError> {
        let sql = viewer.splice(
            "SELECT id, source_id, target_id, source_type, target_type, \
                    relationship, properties \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1) \
               /* {EDGE_VISIBILITY:edges} */",
            2,
        );
        let mut q = sqlx::query_as::<_, SubgraphEdgeRow>(&sql).bind(node_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Reasoning-trace nodes of an arbitrary id set, for `load_subgraph`.
    ///
    /// `reasoning_traces` IS in migration 062's `tier_a` array — it is listed
    /// beside `challenges` and `experiment_triples` — and therefore carries
    /// `owner_group_id` and `visibility` like every other `tier_a` table. The
    /// projection was left inline and unfiltered in `graph_query_utils.rs` on
    /// the recorded grounds that the table "has no `owner_group_id` to filter
    /// on", which is false. The disclosure is small (a methodology label and a
    /// confidence float) but the justification was wrong, and a wrong
    /// justification is what stops a site from ever being revisited.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, node_ids))]
    pub async fn subgraph_traces<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        node_ids: &[Uuid],
    ) -> Result<Vec<SubgraphTraceRow>, DbError> {
        let sql = viewer.splice(
            "SELECT id, reasoning_type AS methodology, confidence              FROM reasoning_traces              WHERE id = ANY($1) /* {VISIBILITY:reasoning_traces} */",
            2,
        );
        let mut q = sqlx::query_as::<_, SubgraphTraceRow>(&sql).bind(node_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// The node ids a graph query selects: the anchor rows matching
    /// `conditions` (newest first, `limit` of them), or, with a `walk`, every
    /// node the walk reaches from those anchors at a depth in
    /// `min_hops..=max_hops`. The caller projects the ids through
    /// `load_subgraph`, which filters each node table again.
    ///
    /// # Viewer
    ///
    /// Both halves are filtered, and they have to be (backlog 4815dcf7). This
    /// statement lived inline in `routes/graph_query.rs` and spent no viewer:
    /// only the final projection did. So a caller-chosen property predicate
    /// matched rows the caller cannot read and the walk returned their readable
    /// neighbours, the walk crossed edges the caller cannot read, and
    /// unreadable rows filled the `LIMIT` window before the projection dropped
    /// them. The anchor table carries `{VISIBILITY:n}` (except `agents`, which
    /// has no tenancy columns, as in `load_subgraph`), and the recursive step
    /// carries `{EDGE_VISIBILITY:e}`, so the walk follows only edges the viewer
    /// can read. Both markers bind the same group array.
    ///
    /// # Errors
    /// `DbError::InvalidData` for a property name outside `[A-Za-z0-9_]`;
    /// `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, conditions))]
    pub async fn graph_query_node_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &Viewer,
        table: GqlNodeTable,
        conditions: &[GqlCondition],
        limit: i64,
        walk: Option<GqlWalk<'_>>,
    ) -> Result<Vec<Uuid>, DbError> {
        enum Bind<'b> {
            Number(f64),
            Text(&'b str),
        }
        let mut binds: Vec<Bind<'_>> = Vec::new();
        let mut filters = String::new();
        for c in conditions {
            let column = match &c.column {
                GqlColumn::TruthValue => "truth_value".to_string(),
                GqlColumn::Confidence => "(properties->>'confidence')::float8".to_string(),
                GqlColumn::Property(name) => {
                    if name.is_empty()
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(DbError::InvalidData {
                            reason: format!("invalid graph-query property name: {name}"),
                        });
                    }
                    format!("properties->>'{name}'")
                }
            };
            let op = match c.op {
                GqlOp::Eq => "=",
                GqlOp::Gt => ">",
                GqlOp::Lt => "<",
                GqlOp::Gte => ">=",
                GqlOp::Lte => "<=",
            };
            let rhs = match &c.value {
                GqlValue::Number(n) => {
                    binds.push(Bind::Number(*n));
                    format!("${}", binds.len())
                }
                GqlValue::Text(t) => {
                    binds.push(Bind::Text(t));
                    format!("${}", binds.len())
                }
                GqlValue::Bool(b) => b.to_string(),
            };
            filters.push_str(&format!(" AND {column} {op} {rhs}"));
        }
        let name = table.table();
        let anchor_marker = if table.tenanted() {
            " /* {VISIBILITY:n} */"
        } else {
            ""
        };
        let anchor = format!(
            "SELECT n.id FROM {name} n WHERE true{filters}{anchor_marker} \
             ORDER BY n.created_at DESC, n.id LIMIT {limit}"
        );
        let sql = match walk {
            None => anchor,
            Some(w) => {
                let rel = match w.relationship {
                    Some(r) => {
                        binds.push(Bind::Text(r));
                        format!(" AND e.relationship = ${}", binds.len())
                    }
                    None => String::new(),
                };
                // The recursive step filters the EDGE it crosses, not the node
                // it passes through: an intermediate node is hidden only
                // because an edge touching it inherits its endpoints' tenancy
                // (migration 070's trigger, the endpoint meet), so a walk never
                // crosses an edge onto or off a node the viewer cannot read. An
                // edge whose tenancy was changed without re-stamping breaks
                // that; F-edges-unfiltered in docs/tenancy/progress.json owns
                // the residual.
                let join = match w.direction {
                    GqlDirection::Outgoing => "e.source_id = p.id",
                    GqlDirection::Incoming => "e.target_id = p.id",
                    GqlDirection::Any => "(e.source_id = p.id OR e.target_id = p.id)",
                };
                format!(
                    "WITH RECURSIVE paths(id, depth) AS ( \
                       (SELECT a.id, 0 FROM ({anchor}) a) \
                       UNION \
                       SELECT CASE WHEN e.source_id = p.id THEN e.target_id ELSE e.source_id END, \
                              p.depth + 1 \
                       FROM edges e JOIN paths p ON {join} \
                       WHERE p.depth < {max}{rel} /* {{EDGE_VISIBILITY:e}} */ \
                     ) \
                     SELECT DISTINCT id FROM paths WHERE depth >= {min}",
                    max = w.max_hops,
                    min = w.min_hops,
                )
            }
        };
        let marked = table.tenanted() || walk.is_some();
        let sql = if marked {
            viewer.splice(&sql, binds.len() + 1)
        } else {
            sql
        };
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql);
        for b in &binds {
            q = match b {
                Bind::Number(n) => q.bind(*n),
                Bind::Text(t) => q.bind(*t),
            };
        }
        if marked {
            if let Some(g) = viewer.group_bind() {
                q = q.bind(g);
            }
        }
        Ok(q.fetch_all(executor).await?)
    }
}
