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
//! # Residual: `edges` traversals
//!
//! The `edges` traversals *inside* these projections are unfiltered, and
//! `edges` does carry tenancy columns, so this is a real gap rather than an
//! absence of one. It is bounded: the returned rows are claims-filtered, so it
//! discloses *structure* (which ids relate to which) and never content. Full
//! edge filtering needs `Viewer::edge_predicate_fragment` and the
//! `edges.co_owner_group_id` co-ownership INTERSECTION, which migration and
//! helper both land in **PR-13**. Recorded as an open finding in
//! `docs/tenancy/progress.json` and assigned there, rather than left as a
//! comment nobody owns.

use sqlx::PgPool;
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

/// Reads for the graph-visualisation endpoints.
pub struct GraphViewRepository;

impl GraphViewRepository {
    /// Nodes of one cluster in the latest graph-cluster run, ordered by
    /// allowlisted-relationship degree then pignistic probability.
    ///
    /// Backs `GET /api/v1/graph/clusters/:id/expand`. `degree_relationships`
    /// is the relationship allowlist used for the degree ordering.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer, degree_relationships))]
    pub async fn expand_cluster_nodes(
        pool: &PgPool,
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
        Ok(q.fetch_all(pool).await?)
    }

    /// Compound-mode nodes of one precomputed neighborhood: each compound that
    /// owns atoms in the neighborhood, plus each standalone atom.
    ///
    /// Both arms of the `UNION ALL` project `claims.content` as `label`, so
    /// **both** carry a visibility marker. A predicate on only one arm would
    /// look filtered in review and leak through the other — which is why the
    /// marker is written per-`FROM`, not per-statement.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn neighborhood_compound_nodes(
        pool: &PgPool,
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
                WHERE e.relationship = 'decomposes_to'
            ),
            compound_nodes AS (
                SELECT cta.compound_id AS id, COUNT(*)::int AS atom_count
                FROM compound_to_atoms cta
                GROUP BY cta.compound_id
            ),
            standalone_nodes AS (
                SELECT a.claim_id AS id
                FROM atoms a
                WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.target_id = a.claim_id AND e.relationship = 'decomposes_to')
                  AND NOT EXISTS (SELECT 1 FROM edges e WHERE e.source_id = a.claim_id AND e.relationship = 'decomposes_to')
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
        Ok(q.fetch_all(pool).await?)
    }

    /// Claim-level nodes belonging to one precomputed neighborhood.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn neighborhood_atomic_nodes(
        pool: &PgPool,
        viewer: &Viewer,
        neighborhood_id: Uuid,
    ) -> Result<Vec<AtomicNodeRow>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT c.id,
                   COALESCE(c.content, c.id::text) AS label,
                   (SELECT e.source_id FROM edges e
                    WHERE e.target_id = c.id AND e.relationship = 'decomposes_to' LIMIT 1) AS compound_id,
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
        Ok(q.fetch_all(pool).await?)
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
    #[instrument(skip(pool, viewer))]
    pub async fn neighborhood_compound_groups(
        pool: &PgPool,
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
            WHERE e.relationship = 'decomposes_to' /* {VISIBILITY:c} */ /* {VISIBILITY:m} */
            GROUP BY 1, 2
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, CompoundGroupRow>(&sql).bind(neighborhood_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// The centre claim's content for a compound-neighborhood expansion.
    ///
    /// `Ok(None)` when the claim does not exist **or the viewer cannot see
    /// it**; the caller renders both as 404 so the endpoint is not an
    /// existence oracle.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn compound_center_content(
        pool: &PgPool,
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
        Ok(q.fetch_optional(pool).await?)
    }

    /// Compounds adjacent to `claim_id` through positive-weight epistemic
    /// edges, aggregated by (compound, relationship).
    ///
    /// Both endpoints of every epistemic edge are projected to their parent
    /// compound (or themselves if standalone); the centre's own projection is
    /// excluded so the result carries no self-loops.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn compound_neighbors(
        pool: &PgPool,
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
                UNION
                SELECT seed.center FROM seed
                WHERE NOT EXISTS (
                    SELECT 1 FROM edges WHERE source_id = (SELECT center FROM seed)
                    AND relationship = 'decomposes_to'
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
                WHERE e.source_id != e.target_id
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
        Ok(q.fetch_all(pool).await?)
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
    #[instrument(skip(pool, viewer, node_ids))]
    pub async fn subgraph_claims(
        pool: &PgPool,
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
        Ok(q.fetch_all(pool).await?)
    }

    /// Evidence nodes of an arbitrary id set, for `load_subgraph`.
    ///
    /// `evidence` is a `tier_a` root in migration 062 and carries its own
    /// tenancy columns, so it is filtered on its own predicate rather than
    /// being inferred from the claims it supports.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer, node_ids))]
    pub async fn subgraph_evidence(
        pool: &PgPool,
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
        Ok(q.fetch_all(pool).await?)
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
    #[instrument(skip(pool, viewer, node_ids))]
    pub async fn subgraph_edges(
        pool: &PgPool,
        viewer: &Viewer,
        node_ids: &[Uuid],
    ) -> Result<Vec<SubgraphEdgeRow>, DbError> {
        let sql = viewer.splice(
            "SELECT id, source_id, target_id, source_type, target_type, \
                    relationship, properties \
             FROM edges \
             WHERE source_id = ANY($1) AND target_id = ANY($1) \
               /* {VISIBILITY:edges} */",
            2,
        );
        let mut q = sqlx::query_as::<_, SubgraphEdgeRow>(&sql).bind(node_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
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
    #[instrument(skip(pool, viewer, node_ids))]
    pub async fn subgraph_traces(
        pool: &PgPool,
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
        Ok(q.fetch_all(pool).await?)
    }
}
