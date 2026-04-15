//! Sheaf consistency queries.
//!
//! Joins claims with their edge neighbors to compute sheaf sections.

use sqlx::PgPool;
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
    pub async fn get_claim_neighbor_betp_pairs(
        pool: &PgPool,
        _frame_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<ClaimNeighborBetpRow>, crate::DbError> {
        let rows = sqlx::query_as::<_, ClaimNeighborBetpRow>(
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
            ORDER BY c.id
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(rows)
    }

    /// Fetch all claim-to-claim epistemic edges with both endpoints' BetP.
    pub async fn get_epistemic_edge_pairs(
        pool: &PgPool,
        _frame_id: Option<Uuid>,
    ) -> Result<Vec<EpistemicEdgePairRow>, crate::DbError> {
        let rows = sqlx::query_as::<_, EpistemicEdgePairRow>(
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
            AND src.pignistic_prob IS NOT NULL
            AND tgt.pignistic_prob IS NOT NULL
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(crate::DbError::from)?;

        Ok(rows)
    }
}
