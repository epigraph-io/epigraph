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
    /// The neighbour's Bel / Pl, so a consumer builds its real interval (a
    /// Positive restriction's floor is `f * Bel_n`, not `f * BetP_n`).
    pub neighbor_belief: Option<f64>,
    pub neighbor_plausibility: Option<f64>,
    pub neighbor_open_world: Option<f64>,
    /// As stored. Matching is case-insensitive, so this may be `SUPPORTS`;
    /// `epigraph_engine::restriction_kind_with_profile` lowercases it.
    pub relationship: String,
    /// `outgoing` when `claim_id` is the edge's source, else `incoming`.
    pub direction: String,
}

/// Raw row: an epistemic edge pair for cohomology computation.
#[derive(Debug, sqlx::FromRow)]
pub struct EpistemicEdgePairRow {
    pub source_id: Uuid,
    pub target_id: Uuid,
    /// As stored. Matching is case-insensitive, so this may be `SUPPORTS`;
    /// `epigraph_engine::restriction_kind_with_profile` lowercases it.
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
    /// Fetch every visible claim's whole epistemic neighbourhood for sheaf
    /// consistency: one row per (claim, in-force incident edge), read from
    /// each endpoint's side, for edges whose relationship is epistemic
    /// (supports, refutes, contradicts, corroborates, elaborates, specializes,
    /// generalizes, frame_validates), compared CASE-INSENSITIVELY.
    ///
    /// A full scan (drain U030): the old `ORDER BY c.id LIMIT $1` read only a
    /// UUID-prefix slice of the corpus and cut the last claim's neighbour list
    /// mid-claim. Callers truncate their OUTPUT instead. Measured on prod
    /// 2026-10-12: 21,717 claim<->claim epistemic edges (case-insensitive), so
    /// about 43k rows; `get_epistemic_edge_pairs` already full-scans the same set.
    ///
    /// Case-insensitive because most prod edges carry UPPER-case spellings
    /// (4,409 match the lowercase list exactly; 21,717 case-insensitively).
    /// Two spellings of one relationship between the same pair are two rows.
    pub async fn get_claim_neighbor_betp_pairs<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        _frame_id: Option<Uuid>,
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
                n.belief AS neighbor_belief,
                n.plausibility AS neighbor_plausibility,
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
            WHERE lower(e.relationship) IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes', 'frame_validates')
            -- A retracted edge is no longer asserted by anyone, so it must not
            -- manufacture an inconsistency (as in get_epistemic_edge_pairs).
            AND (e.valid_to IS NULL OR e.valid_to > now())
            AND c.pignistic_prob IS NOT NULL
            AND n.pignistic_prob IS NOT NULL
            /* {VISIBILITY:c} */ /* {VISIBILITY:n} */ /* {EDGE_VISIBILITY:e} */
            ORDER BY c.id
            "#,
            1,
        );
        let mut q = sqlx::query_as::<_, ClaimNeighborBetpRow>(&sql);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(executor).await.map_err(crate::DbError::from)?;

        Ok(rows)
    }

    /// Fetch all in-force claim-to-claim epistemic edges with both endpoints'
    /// BetP: one row per edge, for MCP `sheaf_cohomology` and `reconcile_sheaf`.
    ///
    /// The relationship list is compared CASE-INSENSITIVELY, exactly as in
    /// [`Self::get_claim_neighbor_betp_pairs`], so the cohomology scan and the
    /// consistency scan see the same edge set. Writers store both `supports`
    /// and `SUPPORTS` (likewise `corroborates` / `CORROBORATES`); an exact
    /// match skipped every upper-case edge. The relationship is returned as
    /// stored, and two spellings of one relationship between the same pair
    /// are two rows.
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
            AND lower(e.relationship) IN ('supports', 'refutes', 'contradicts', 'corroborates', 'elaborates', 'specializes', 'generalizes', 'frame_validates')
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
}
