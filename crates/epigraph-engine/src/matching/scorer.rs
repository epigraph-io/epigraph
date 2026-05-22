//! Pair scorer: computes 7 match features and a weighted combined score.
//!
//! See `docs/superpowers/specs/2026-05-21-cross-source-matching-design.md`
//! Tasks 11 + 12.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// All computed features for a candidate pair plus the combined score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchFeatures {
    /// Cosine similarity of claim embeddings: `1 - (a.embedding <=> b.embedding)`.
    /// Returns `0.0` if either embedding is NULL.
    pub embed_cosine: f32,
    /// Jaccard over `(subject_id, predicate)` triples.
    pub triple_overlap: f32,
    /// Jaccard over entity IDs in subject ∪ object columns per claim.
    pub entity_jaccard: f32,
    /// Whether `properties->>'method_id'` is equal and non-null in both claims.
    pub method_match: bool,
    /// Jaccard over `claim_clusters.cluster_id` sets (0 or 1 row each).
    pub nbhd_overlap: f32,
    /// Jaccard over `edges.target_id` where `relationship = 'cites'`.
    pub citation_overlap: f32,
    /// `|days(a.created_at - b.created_at)|`; reported but not in score.
    pub temporal_dist_days: i32,
    /// Normalized weighted sum of the six similarity features.
    pub score: f32,
}

/// Weights for the six features that contribute to `score`.
///
/// `temporal_dist_days` is reported but deferred to calibration.
#[derive(Debug, Clone, Deserialize)]
pub struct Weights {
    pub embed_cosine: f32,
    pub triple_overlap: f32,
    pub entity_jaccard: f32,
    pub method_match: f32,
    pub nbhd_overlap: f32,
    pub citation_overlap: f32,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            embed_cosine: 0.40,
            triple_overlap: 0.20,
            entity_jaccard: 0.15,
            method_match: 0.10,
            nbhd_overlap: 0.10,
            citation_overlap: 0.05,
        }
    }
}

/// Compute all 7 features for the claim pair `(a, b)` and combine them.
///
/// Uses three focused queries to keep each one readable and debuggable:
/// 1. Embedding cosine + scalar fields (method_match, temporal_dist_days).
/// 2. Jaccard features (triple_overlap, entity_jaccard, nbhd_overlap, citation_overlap).
pub async fn score_pair(
    pool: &PgPool,
    a: Uuid,
    b: Uuid,
    w: &Weights,
) -> Result<MatchFeatures, sqlx::Error> {
    // ------------------------------------------------------------------
    // Query 1: embedding cosine + scalar features
    // ------------------------------------------------------------------
    let row1 = sqlx::query(
        r#"
        WITH a AS (SELECT embedding, properties, created_at FROM claims WHERE id = $1),
             b AS (SELECT embedding, properties, created_at FROM claims WHERE id = $2)
        SELECT
            COALESCE(
                (1.0 - ((SELECT embedding FROM a) <=> (SELECT embedding FROM b)))::real,
                0.0::real
            ) AS embed_cosine,
            COALESCE(
                (SELECT properties->>'method_id' FROM a) IS NOT NULL
                AND (SELECT properties->>'method_id' FROM a)
                    = (SELECT properties->>'method_id' FROM b),
                false
            ) AS method_match,
            COALESCE(
                ABS(EXTRACT(DAY FROM (
                    (SELECT created_at FROM a) - (SELECT created_at FROM b)
                )))::int,
                0
            ) AS temporal_dist_days
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;

    let embed_cosine: f32 = row1.try_get("embed_cosine")?;
    let method_match: bool = row1.try_get("method_match")?;
    let temporal_dist_days: i32 = row1.try_get("temporal_dist_days")?;

    // ------------------------------------------------------------------
    // Query 2: Jaccard features
    // ------------------------------------------------------------------
    let row2 = sqlx::query(
        r#"
        WITH
            -- Subject-predicate pairs per claim
            ta_sp AS (
                SELECT subject_id, predicate FROM triples WHERE claim_id = $1
            ),
            tb_sp AS (
                SELECT subject_id, predicate FROM triples WHERE claim_id = $2
            ),
            -- Entity sets (subject ∪ object) per claim
            ta_ent AS (
                SELECT subject_id AS e FROM triples WHERE claim_id = $1
                UNION
                SELECT object_id  AS e FROM triples WHERE claim_id = $1 AND object_id IS NOT NULL
            ),
            tb_ent AS (
                SELECT subject_id AS e FROM triples WHERE claim_id = $2
                UNION
                SELECT object_id  AS e FROM triples WHERE claim_id = $2 AND object_id IS NOT NULL
            ),
            -- Cluster IDs per claim (at most 1 row each)
            cca AS (SELECT cluster_id FROM claim_clusters WHERE claim_id = $1),
            ccb AS (SELECT cluster_id FROM claim_clusters WHERE claim_id = $2),
            -- Citation targets per claim
            cita AS (
                SELECT target_id FROM edges
                WHERE source_id = $1 AND relationship = 'cites'
            ),
            citb AS (
                SELECT target_id FROM edges
                WHERE source_id = $2 AND relationship = 'cites'
            )
        SELECT
            -- triple_overlap: Jaccard(ta_sp, tb_sp)
            COALESCE(
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp INTERSECT SELECT * FROM tb_sp) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp UNION SELECT * FROM tb_sp) u),
                    0
                ),
                0.0
            )::real AS triple_overlap,
            -- entity_jaccard: Jaccard(ta_ent, tb_ent)
            COALESCE(
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_ent INTERSECT SELECT * FROM tb_ent) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_ent UNION SELECT * FROM tb_ent) u),
                    0
                ),
                0.0
            )::real AS entity_jaccard,
            -- nbhd_overlap: Jaccard(cca.cluster_id, ccb.cluster_id)
            COALESCE(
                (SELECT COUNT(*)::real FROM (SELECT * FROM cca INTERSECT SELECT * FROM ccb) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM cca UNION SELECT * FROM ccb) u),
                    0
                ),
                0.0
            )::real AS nbhd_overlap,
            -- citation_overlap: Jaccard(cita.target_id, citb.target_id)
            COALESCE(
                (SELECT COUNT(*)::real FROM (SELECT * FROM cita INTERSECT SELECT * FROM citb) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM cita UNION SELECT * FROM citb) u),
                    0
                ),
                0.0
            )::real AS citation_overlap
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;

    let triple_overlap: f32 = row2.try_get("triple_overlap")?;
    let entity_jaccard: f32 = row2.try_get("entity_jaccard")?;
    let nbhd_overlap: f32 = row2.try_get("nbhd_overlap")?;
    let citation_overlap: f32 = row2.try_get("citation_overlap")?;

    // ------------------------------------------------------------------
    // Combined score: normalized weighted sum (temporal_dist_days excluded)
    // ------------------------------------------------------------------
    let raw = w.embed_cosine * embed_cosine
        + w.triple_overlap * triple_overlap
        + w.entity_jaccard * entity_jaccard
        + w.method_match * if method_match { 1.0_f32 } else { 0.0_f32 }
        + w.nbhd_overlap * nbhd_overlap
        + w.citation_overlap * citation_overlap;
    let denom = w.embed_cosine
        + w.triple_overlap
        + w.entity_jaccard
        + w.method_match
        + w.nbhd_overlap
        + w.citation_overlap;
    let score = (raw / denom).clamp(0.0, 1.0);

    Ok(MatchFeatures {
        embed_cosine,
        triple_overlap,
        entity_jaccard,
        method_match,
        nbhd_overlap,
        citation_overlap,
        temporal_dist_days,
        score,
    })
}
