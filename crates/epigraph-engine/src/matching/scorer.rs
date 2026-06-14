//! Pair scorer: computes 9 match features and a weighted combined score.
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
    /// The `0.0`-on-NULL default is deliberate (not the neutral-`0.5` fallback `belief_alignment`/`theme_proximity` use): a missing embedding on an `is_current` non-telemetry claim violates the embedding invariant, so similarity is suppressed rather than guessed — and since the default weights sum to `1.0`, the max score with `embed_cosine = 0` is `0.65`, below the default `0.85` high band, so such a pair never auto-promotes.
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
    /// Adamic-Adar over claim↔claim edges (any relationship), tanh-normalized
    /// to (0, 1). Common neighbors weighted by 1/ln(degree), so rare shared
    /// neighbors count more than hub-connected ones. Tested orthogonal to
    /// `embed_cosine` on SciFact — adds match-recall without false positives
    /// because easy negatives almost never share graph neighbors.
    pub graph_overlap: f32,
    /// Stance alignment from stored CDST mass functions: `1 - 2|BetP_a - BetP_b|`
    /// clamped to `[0, 1]`. Both-supported or both-unsupported pairs → ~1;
    /// support-vs-deny → ~0. Returns 1.0 (no signal) if either claim has no
    /// mass function. Designed to break the cosine+graph precision ceiling
    /// at hard-negative same-topic-opposite-stance pairs.
    pub belief_alignment: f32,
    /// Topic-cluster proximity from semantic themes (`claim_themes`).
    /// 1.0 when both claims share `theme_id`; otherwise cosine similarity
    /// of the two themes' centroids. 0.5 (neutral) when either claim is
    /// unthemed. Captures macro-topic signal beyond per-claim cosine —
    /// e.g. two claims both about "DNA origami" but with different
    /// phrasings cluster to the same theme even when their per-claim
    /// embeddings drift.
    pub theme_proximity: f32,
    /// `|days(a.created_at - b.created_at)|`; reported but not in score.
    pub temporal_dist_days: i32,
    /// Normalized weighted sum of the nine similarity features.
    pub score: f32,
}

/// Weights for the nine features that contribute to `score`.
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
    #[serde(default = "default_graph_overlap")]
    pub graph_overlap: f32,
    #[serde(default = "default_belief_alignment")]
    pub belief_alignment: f32,
    #[serde(default = "default_theme_proximity")]
    pub theme_proximity: f32,
}

fn default_graph_overlap() -> f32 {
    0.10
}
fn default_belief_alignment() -> f32 {
    0.15
}
fn default_theme_proximity() -> f32 {
    0.10
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            embed_cosine: 0.35,
            triple_overlap: 0.15,
            entity_jaccard: 0.10,
            method_match: 0.05,
            nbhd_overlap: 0.05,
            citation_overlap: 0.05,
            graph_overlap: 0.10,
            belief_alignment: 0.10,
            theme_proximity: 0.05,
        }
    }
}

/// Weighted average over only the features that produced a real signal.
///
/// Each entry is `(weight, Some(value))` when the feature fired, or
/// `(weight, None)` when it had no data to compare — `None` features are
/// excluded from BOTH the numerator and the denominator (renormalization).
/// This is the fix for cross-source score dilution (backlog 9b50c331): the
/// old combiner divided by the sum of all nine weights even though the
/// structural features are ~0 by construction for cross-source pairs.
///
/// `embed_cosine` is always passed as `Some` (its `0.0`-on-NULL is deliberate
/// suppression, not missing data), so `denom >= w.embed_cosine > 0` always
/// holds; the `denom == 0` branch is defensive only.
fn renormalized_score(weighted: &[(f32, Option<f32>)]) -> f32 {
    let mut num = 0.0_f32;
    let mut den = 0.0_f32;
    for (w, v) in weighted {
        if let Some(val) = v {
            num += w * val;
            den += w;
        }
    }
    if den == 0.0 {
        0.0
    } else {
        (num / den).clamp(0.0, 1.0)
    }
}

/// Compute all 9 features for the claim pair `(a, b)` and combine them.
///
/// Uses five focused queries to keep each one readable and debuggable:
/// 1. Embedding cosine + scalar fields (method_match, temporal_dist_days).
/// 2. Jaccard features (triple_overlap, entity_jaccard, nbhd_overlap, citation_overlap).
/// 3. Adamic-Adar graph_overlap over claim↔claim edges.
/// 4. belief_alignment from stored CDST mass functions.
/// 5. theme_proximity from claims.theme_id + claim_themes.centroid.
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
            CASE
                WHEN (SELECT properties->>'method_id' FROM a) IS NULL
                  OR (SELECT properties->>'method_id' FROM b) IS NULL
                    THEN NULL
                ELSE (SELECT properties->>'method_id' FROM a)
                     = (SELECT properties->>'method_id' FROM b)
            END AS method_match,
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
    let method_match_opt: Option<bool> = row1.try_get("method_match")?;
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
            (
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp INTERSECT SELECT * FROM tb_sp) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_sp UNION SELECT * FROM tb_sp) u),
                    0
                )
            )::real AS triple_overlap,
            -- entity_jaccard: Jaccard(ta_ent, tb_ent)
            (
                (SELECT COUNT(*)::real FROM (SELECT * FROM ta_ent INTERSECT SELECT * FROM tb_ent) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM ta_ent UNION SELECT * FROM tb_ent) u),
                    0
                )
            )::real AS entity_jaccard,
            -- nbhd_overlap: Jaccard(cca.cluster_id, ccb.cluster_id)
            (
                (SELECT COUNT(*)::real FROM (SELECT * FROM cca INTERSECT SELECT * FROM ccb) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM cca UNION SELECT * FROM ccb) u),
                    0
                )
            )::real AS nbhd_overlap,
            -- citation_overlap: Jaccard(cita.target_id, citb.target_id)
            (
                (SELECT COUNT(*)::real FROM (SELECT * FROM cita INTERSECT SELECT * FROM citb) i)
                / NULLIF(
                    (SELECT COUNT(*)::real FROM (SELECT * FROM cita UNION SELECT * FROM citb) u),
                    0
                )
            )::real AS citation_overlap
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;

    let triple_overlap_opt: Option<f32> = row2.try_get("triple_overlap")?;
    let entity_jaccard_opt: Option<f32> = row2.try_get("entity_jaccard")?;
    let nbhd_overlap_opt: Option<f32> = row2.try_get("nbhd_overlap")?;
    let citation_overlap_opt: Option<f32> = row2.try_get("citation_overlap")?;

    // ------------------------------------------------------------------
    // Query 3: Adamic-Adar on claim↔claim edges (any relationship).
    //
    // Common neighbors of (a, b) weighted by 1/ln(degree), so a rare shared
    // neighbor counts more than a hub. tanh-normalizes the unbounded sum
    // into (0, 1). Heavy-looking SQL but the inner subquery is bounded by
    // claim degree (typically small), and the existing
    // (source_id) / (target_id) indexes on `edges` cover the neighbor scan.
    // ------------------------------------------------------------------
    let row3 = sqlx::query(
        r#"
        WITH na AS (
            SELECT target_id AS nbr FROM edges
                WHERE source_id = $1 AND source_type = 'claim' AND target_type = 'claim'
            UNION
            SELECT source_id FROM edges
                WHERE target_id = $1 AND source_type = 'claim' AND target_type = 'claim'
        ),
        nb AS (
            SELECT target_id AS nbr FROM edges
                WHERE source_id = $2 AND source_type = 'claim' AND target_type = 'claim'
            UNION
            SELECT source_id FROM edges
                WHERE target_id = $2 AND source_type = 'claim' AND target_type = 'claim'
        ),
        common AS (
            SELECT na.nbr FROM na JOIN nb USING (nbr)
            WHERE na.nbr <> $1 AND na.nbr <> $2
        ),
        deg AS (
            SELECT c.nbr, (
                SELECT COUNT(*) FROM edges
                WHERE (source_id = c.nbr OR target_id = c.nbr)
                  AND source_type = 'claim' AND target_type = 'claim'
            ) AS d FROM common c
        )
        SELECT
            TANH(SUM(1.0 / GREATEST(LN(d::float8), 0.5)))::real AS graph_overlap
        FROM deg
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;
    let graph_overlap_opt: Option<f32> = row3.try_get("graph_overlap")?;

    // ------------------------------------------------------------------
    // Query 4: belief_alignment from stored CDST mass functions.
    //
    // Pulls the most recent mass_functions row per claim, computes BetP
    // for the supported hypothesis: m({0}) + 0.5 * m({0,1}). Then
    // alignment = clamp(1 - 2|BetP_a - BetP_b|, 0, 1). When either claim
    // has no mass function, alignment = 1.0 (neutral — no signal either
    // way; let other features decide).
    //
    // The frame is binary {supported, unsupported} per cdst_bp's
    // BINARY_FRAME; keys in `masses` JSONB are comma-separated focal-set
    // indices: "0" = {supported}, "1" = {unsupported}, "0,1" = θ.
    // ------------------------------------------------------------------
    let row4 = sqlx::query(
        r#"
        WITH
            ma AS (
                SELECT masses FROM mass_functions
                WHERE claim_id = $1
                ORDER BY created_at DESC
                LIMIT 1
            ),
            mb AS (
                SELECT masses FROM mass_functions
                WHERE claim_id = $2
                ORDER BY created_at DESC
                LIMIT 1
            )
        SELECT
            (SELECT COALESCE((masses->>'0')::float8, 0.0)
                  + 0.5 * COALESCE((masses->>'0,1')::float8, 0.0)
             FROM ma) AS betp_a,
            (SELECT COALESCE((masses->>'0')::float8, 0.0)
                  + 0.5 * COALESCE((masses->>'0,1')::float8, 0.0)
             FROM mb) AS betp_b
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;
    let betp_a: Option<f64> = row4.try_get("betp_a")?;
    let betp_b: Option<f64> = row4.try_get("betp_b")?;
    let belief_alignment_opt: Option<f32> = match (betp_a, betp_b) {
        (Some(pa), Some(pb)) => Some((1.0 - 2.0 * (pa - pb).abs()).clamp(0.0, 1.0) as f32),
        // No mass function on at least one side → not applicable (excluded
        // from the renormalized denominator, rather than a neutral 0.5 that
        // would dilute the score).
        _ => None,
    };

    // ------------------------------------------------------------------
    // Query 5: theme_proximity via claims.theme_id + claim_themes.centroid.
    //
    // Shared-theme pairs → 1.0 (strong same-topic signal). Different-theme
    // pairs → centroid cosine, which compresses semantically-distant
    // themes (marketing vs. astronomy) to near-0 even when individual
    // embeddings drift toward overlap. Either claim unthemed → 0.5
    // (neutral, same rationale as belief_alignment missing case). The
    // HNSW index on `idx_claim_themes_centroid` makes the centroid lookup
    // O(1) per side.
    // ------------------------------------------------------------------
    let row5 = sqlx::query(
        r#"
        WITH a AS (SELECT theme_id FROM claims WHERE id = $1),
             b AS (SELECT theme_id FROM claims WHERE id = $2)
        SELECT
            CASE
                WHEN (SELECT theme_id FROM a) IS NULL
                  OR (SELECT theme_id FROM b) IS NULL
                    THEN NULL
                WHEN (SELECT theme_id FROM a) = (SELECT theme_id FROM b)
                    THEN 1.0::real
                ELSE
                    COALESCE(
                        (1.0 - (
                            (SELECT centroid FROM claim_themes
                                WHERE id = (SELECT theme_id FROM a))
                            <=>
                            (SELECT centroid FROM claim_themes
                                WHERE id = (SELECT theme_id FROM b))
                        ))::real,
                        0.5::real
                    )
            END AS theme_proximity
        "#,
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?;
    let tp_opt: Option<f32> = row5.try_get("theme_proximity")?;
    let theme_proximity_opt: Option<f32> = tp_opt.map(|v| v.clamp(0.0, 1.0));

    // ------------------------------------------------------------------
    // Combined score: renormalized weighted average over fired features.
    // method_match contributes 1.0/0.0 when both claims have a method_id,
    // and is excluded (None) when either lacks one.
    // ------------------------------------------------------------------
    let method_match_val: Option<f32> = method_match_opt.map(|m| if m { 1.0_f32 } else { 0.0_f32 });

    let score = renormalized_score(&[
        (w.embed_cosine, Some(embed_cosine)),
        (w.triple_overlap, triple_overlap_opt),
        (w.entity_jaccard, entity_jaccard_opt),
        (w.method_match, method_match_val),
        (w.nbhd_overlap, nbhd_overlap_opt),
        (w.citation_overlap, citation_overlap_opt),
        (w.graph_overlap, graph_overlap_opt),
        (w.belief_alignment, belief_alignment_opt),
        (w.theme_proximity, theme_proximity_opt),
    ]);

    Ok(MatchFeatures {
        embed_cosine,
        // Reported feature values keep their pre-change sentinels so the
        // telemetry vector (match_candidates.features) is unchanged; only the
        // `score` math changed.
        triple_overlap: triple_overlap_opt.unwrap_or(0.0),
        entity_jaccard: entity_jaccard_opt.unwrap_or(0.0),
        method_match: method_match_opt.unwrap_or(false),
        nbhd_overlap: nbhd_overlap_opt.unwrap_or(0.0),
        citation_overlap: citation_overlap_opt.unwrap_or(0.0),
        graph_overlap: graph_overlap_opt.unwrap_or(0.0),
        belief_alignment: belief_alignment_opt.unwrap_or(0.5),
        theme_proximity: theme_proximity_opt.unwrap_or(0.5),
        temporal_dist_days,
        score,
    })
}
