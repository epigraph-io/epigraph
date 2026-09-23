//! Sheaf consistency queries.
//!
//! Joins claims with their edge neighbors to compute sheaf sections.

use uuid::Uuid;

/// Raw row: a claim and one of its neighbors' BetP values.
#[derive(Debug, sqlx::FromRow)]
pub struct ClaimNeighborBetpRow {
    pub claim_id: Uuid,
    pub claim_betp: Option<f64>,
    pub claim_belief: Option<f64>,
    pub claim_plausibility: Option<f64>,
    pub claim_open_world: Option<f64>,
    pub neighbor_id: Uuid,
    pub neighbor_betp: Option<f64>,
    pub neighbor_open_world: Option<f64>,
    pub relationship: String,
    pub direction: String,
}

/// Raw row: an epistemic edge pair for cohomology computation.
#[derive(Debug, sqlx::FromRow)]
pub struct EpistemicEdgePairRow {
    pub source_id: Uuid,
    pub target_id: Uuid,
    pub relationship: String,
    pub source_betp: Option<f64>,
    pub target_betp: Option<f64>,
    pub source_open_world: Option<f64>,
    pub target_open_world: Option<f64>,
    pub source_belief: Option<f64>,
    pub source_plausibility: Option<f64>,
    pub target_belief: Option<f64>,
    pub target_plausibility: Option<f64>,
}

pub struct SheafRepository;

impl SheafRepository {
    /// Fetch claim-neighbor pairs for sheaf consistency computation.
    ///
    /// Returns pairs of (claim, neighbor) where the edge is epistemic
    /// (supports, refutes, contradicts, corroborates, elaborates, specializes, generalizes,
    /// frame_validates).
    pub async fn get_claim_neighbor_betp_pairs<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        _frame_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<ClaimNeighborBetpRow>, crate::DbError> {
        // Three aliases, three markers: the claim, the neighbour, and the edge
        // between them. Filtering only `c` would still disclose that an
        // invisible claim `n` exists and what its belief interval is.
        let sql = viewer.splice(
            r#"
            SELECT
                c.id AS claim_id,
                c.pignistic_prob AS claim_betp,
                c.belief AS claim_belief,
                c.plausibility AS claim_plausibility,
                c.open_world_mass AS claim_open_world,
                n.id AS neighbor_id,
                n.pignistic_prob AS neighbor_betp,
                n.open_world_mass AS neighbor_open_world,
                e.relationship,
                CASE WHEN e.source_id = c.id THEN 'outgoing' ELSE 'incoming' END AS direction
            FROM claims c
            JOIN edges e ON (
                (e.source_id = c.id AND e.source_type = 'claim' AND e.target_type = 'claim')
                OR
                (e.target_id = c.id AND e.source_type = 'claim' AND e.target_type = 'claim')
            )
            JOIN claims n ON n.id = CASE WHEN e.source_id = c.id THEN e.target_id ELSE e.source_id END
            WHERE e.relationship IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes', 'frame_validates')
            AND c.pignistic_prob IS NOT NULL
            AND n.pignistic_prob IS NOT NULL
            /* {VISIBILITY:c} */ /* {VISIBILITY:n} */ /* {EDGE_VISIBILITY:e} */
            ORDER BY c.id
            LIMIT $1
            "#,
            2,
        );
        let mut q = sqlx::query_as::<_, ClaimNeighborBetpRow>(&sql).bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(crate::DbError::from)?;

        Ok(rows)
    }

    /// Fetch all claim-to-claim epistemic edges with both endpoints' BetP.
    pub async fn get_epistemic_edge_pairs<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        _frame_id: Option<Uuid>,
    ) -> Result<Vec<EpistemicEdgePairRow>, crate::DbError> {
        let sql = viewer.splice(
            r#"
            SELECT
                e.source_id,
                e.target_id,
                e.relationship,
                src.pignistic_prob AS source_betp,
                tgt.pignistic_prob AS target_betp,
                src.open_world_mass AS source_open_world,
                tgt.open_world_mass AS target_open_world,
                src.belief AS source_belief,
                src.plausibility AS source_plausibility,
                tgt.belief AS target_belief,
                tgt.plausibility AS target_plausibility
            FROM edges e
            JOIN claims src ON src.id = e.source_id
            JOIN claims tgt ON tgt.id = e.target_id
            WHERE e.source_type = 'claim'
            AND e.target_type = 'claim'
            AND e.relationship IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes', 'frame_validates')
            -- A retracted edge must not manufacture a sheaf obstruction: the
            -- assertion has been withdrawn, so the inconsistency it implied is
            -- no longer claimed by anyone.
            AND (e.valid_to IS NULL OR e.valid_to > now())
            AND src.pignistic_prob IS NOT NULL
            AND tgt.pignistic_prob IS NOT NULL
            /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:src} */ /* {VISIBILITY:tgt} */
            "#,
            1,
        );
        let mut q = sqlx::query_as::<_, EpistemicEdgePairRow>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(crate::DbError::from)?;

        Ok(rows)
    }

    /// The ids of every claim within `max_depth` epistemic hops of `center`,
    /// walking only claims and edges the viewer may read. `center` itself is
    /// included.
    ///
    /// The neighborhood read of `POST /api/v1/graph/compose`
    /// (`routes/computation.rs::compose_subgraphs`, `F-SHARD4-A1`), which ran
    /// this recursive CTE inline on the raw pool, in a route-layer helper that
    /// took a `&PgPool`, with no viewer predicate at all.
    ///
    /// # Three predicates, and why each is needed
    ///
    /// * **The seed** (`{VISIBILITY:seed}`). The old CTE seeded `$1` as a bare
    ///   literal, so an id the viewer cannot read, or one that names no claim,
    ///   was still counted as a node. Now an unreadable center yields an EMPTY
    ///   result. A readable center is always in its own neighborhood, so the
    ///   caller can read "empty" as "not found" without a second statement.
    /// * **The edge** (`{EDGE_VISIBILITY:e}`). A group-private edge between two
    ///   public claims stays private under migration 070's no-widening rule.
    ///   Walking it would put a claim in the neighborhood only because of an
    ///   edge the caller cannot see.
    /// * **The far endpoint** (`{VISIBILITY:far}`). A public edge can still
    ///   reach a private claim. Filtering the edge alone would count that claim
    ///   and then walk THROUGH it, so a public claim two hops away would be
    ///   reached only by way of a node the caller cannot see. The far endpoint
    ///   is joined to `claims` so the walk stops at it. The join also drops an
    ///   endpoint that names no claim at all. That is forced: under migration
    ///   077's policies a missing claim and an unreadable one are the same
    ///   empty join.
    ///
    /// All three markers resolve to `$3`: `$1` is the center and `$2` is the
    /// depth bound.
    ///
    /// # What is deliberately unchanged
    ///
    /// The relationship set and the walk itself (edges in either direction,
    /// `claim`-to-`claim` only) are what the route used before. So is the
    /// treatment of retracted edges: an edge with `valid_to` set still widens
    /// the neighborhood, where [`Self::get_epistemic_edge_pairs`] drops it.
    /// That is a belief question, not a tenancy one, and is left out of this
    /// change on purpose.
    ///
    /// # Errors
    ///
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn epistemic_neighborhood_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        center: Uuid,
        max_depth: i32,
    ) -> Result<Vec<Uuid>, crate::DbError> {
        let sql = viewer.splice(
            r#"
            WITH RECURSIVE neighborhood AS (
                SELECT seed.id AS node_id, 0 AS depth
                  FROM claims seed
                 WHERE seed.id = $1
                   /* {VISIBILITY:seed} */
                UNION
                SELECT far.id, n.depth + 1
                  FROM neighborhood n
                  JOIN edges e ON (
                      (e.source_id = n.node_id AND e.source_type = 'claim' AND e.target_type = 'claim')
                      OR (e.target_id = n.node_id AND e.source_type = 'claim' AND e.target_type = 'claim')
                  )
                  JOIN claims far
                    ON far.id = CASE WHEN e.source_id = n.node_id THEN e.target_id ELSE e.source_id END
                 WHERE n.depth < $2
                   AND e.relationship IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes')
                   /* {EDGE_VISIBILITY:e} */ /* {VISIBILITY:far} */
            )
            SELECT DISTINCT node_id FROM neighborhood
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql)
            .bind(center)
            .bind(max_depth);
        // Guarded, not `unwrap_or(&[])`: a `Bypass` viewer renders no
        // predicate, so the statement has no `$3` to fill.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(crate::DbError::from)?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}
