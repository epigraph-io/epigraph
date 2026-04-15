//! Claim theme persistence for hierarchical retrieval.
//! Themes are topic clusters; each claim belongs to at most one theme.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimThemeRow {
    pub id: Uuid,
    pub label: String,
    pub description: String,
    pub claim_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A claim flagged as potentially misplaced by cluster-level metrics.
#[derive(Debug, Clone)]
pub struct BoundaryClaimRow {
    pub claim_id: Uuid,
    pub theme_id: Option<Uuid>,
    pub boundary_ratio: f64,
    pub centroid_distance: f64,
    pub content_preview: String,
}

/// A theme that may need splitting due to high intra-cluster variance.
#[derive(Debug, Clone)]
pub struct SplitCandidateRow {
    pub theme_id: Uuid,
    pub label: String,
    pub claim_count: i32,
    pub avg_distance: f64,
    pub max_distance: f64,
}

/// A theme with distant assigned claims, suggesting a new theme may be needed.
#[derive(Debug, Clone)]
pub struct DistantClaimsRow {
    pub source_theme: String,
    pub distant_claims: i64,
    pub avg_distance: f64,
}

/// Result of a centroid recomputation for a single theme.
#[derive(Debug, Clone)]
pub struct RecomputedThemeRow {
    pub id: Uuid,
    pub label: String,
    pub claim_count: i32,
}

pub struct ClaimThemeRepository;

impl ClaimThemeRepository {
    /// Create a new theme (centroid stored separately via raw SQL for vector type)
    pub async fn create(
        pool: &PgPool,
        label: &str,
        description: &str,
    ) -> Result<ClaimThemeRow, DbError> {
        let row = sqlx::query_as::<_, ClaimThemeRow>(
            "INSERT INTO claim_themes (label, description) VALUES ($1, $2) \
             RETURNING id, label, description, claim_count, created_at, updated_at",
        )
        .bind(label)
        .bind(description)
        .fetch_one(pool)
        .await
        .map_err(DbError::from)?;
        Ok(row)
    }

    /// Store the centroid vector for a theme.
    /// `centroid_pgvec` is a pgvector string literal, e.g. "[0.1,0.2,...]"
    pub async fn set_centroid(
        pool: &PgPool,
        theme_id: Uuid,
        centroid_pgvec: &str,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE claim_themes SET centroid = $2::vector, updated_at = NOW() WHERE id = $1",
        )
        .bind(theme_id)
        .bind(centroid_pgvec)
        .execute(pool)
        .await
        .map_err(DbError::from)?;
        Ok(())
    }

    /// Assign a single claim to a theme
    pub async fn assign_claim(
        pool: &PgPool,
        claim_id: Uuid,
        theme_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query("UPDATE claims SET theme_id = $2, updated_at = NOW() WHERE id = $1")
            .bind(claim_id)
            .bind(theme_id)
            .execute(pool)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Bulk assign a slice of claims to a theme
    pub async fn bulk_assign(
        pool: &PgPool,
        claim_ids: &[Uuid],
        theme_id: Uuid,
    ) -> Result<u64, DbError> {
        let result =
            sqlx::query("UPDATE claims SET theme_id = $2, updated_at = NOW() WHERE id = ANY($1)")
                .bind(claim_ids)
                .bind(theme_id)
                .execute(pool)
                .await
                .map_err(DbError::from)?;
        Ok(result.rows_affected())
    }

    /// Update the denormalized claim count for a theme
    pub async fn update_count(pool: &PgPool, theme_id: Uuid, count: i32) -> Result<(), DbError> {
        sqlx::query("UPDATE claim_themes SET claim_count = $2, updated_at = NOW() WHERE id = $1")
            .bind(theme_id)
            .bind(count)
            .execute(pool)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// List all themes ordered by claim_count DESC
    pub async fn list(pool: &PgPool) -> Result<Vec<ClaimThemeRow>, DbError> {
        let rows = sqlx::query_as::<_, ClaimThemeRow>(
            "SELECT id, label, description, claim_count, created_at, updated_at \
             FROM claim_themes ORDER BY claim_count DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;
        Ok(rows)
    }

    /// Find themes whose centroids are most similar to the query vector.
    ///
    /// Returns `(theme_id, label, similarity)` tuples ordered by descending similarity.
    /// Uses the pgvector `<=>` cosine distance operator; similarity = 1 - distance.
    pub async fn find_similar_themes(
        pool: &PgPool,
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let rows = sqlx::query(
            "SELECT id, label, (1 - (centroid <=> $1::vector))::float8 AS similarity \
             FROM claim_themes \
             WHERE centroid IS NOT NULL \
             ORDER BY centroid <=> $1::vector \
             LIMIT $2",
        )
        .bind(query_vec)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let label: String = row.get("label");
                let similarity: f64 = row.get("similarity");
                (id, label, similarity)
            })
            .collect();
        Ok(results)
    }

    /// Get claims within the specified themes, ranked by similarity to the query vector.
    ///
    /// Returns `(claim_id, content, similarity)` tuples ordered by descending similarity.
    pub async fn claims_in_themes(
        pool: &PgPool,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let rows = sqlx::query(
            "SELECT c.id, c.content, (1 - (c.embedding <=> $2::vector))::float8 AS similarity \
             FROM claims c \
             WHERE c.theme_id = ANY($1) \
               AND c.embedding IS NOT NULL \
             ORDER BY c.embedding <=> $2::vector \
             LIMIT $3",
        )
        .bind(theme_ids)
        .bind(query_vec)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let content: String = row.get("content");
                let similarity: f64 = row.get("similarity");
                (id, content, similarity)
            })
            .collect();
        Ok(results)
    }

    /// Delete all themes and unassign all claims (for re-clustering).
    ///
    /// Returns the number of deleted theme rows.
    pub async fn delete_all(pool: &PgPool) -> Result<u64, DbError> {
        // Unassign claims first to satisfy the foreign-key constraint
        sqlx::query("UPDATE claims SET theme_id = NULL WHERE theme_id IS NOT NULL")
            .execute(pool)
            .await
            .map_err(DbError::from)?;

        let result = sqlx::query("DELETE FROM claim_themes")
            .execute(pool)
            .await
            .map_err(DbError::from)?;

        Ok(result.rows_affected())
    }

    /// Find claims with high boundary_ratio and centroid_distance from claim_clusters.
    ///
    /// These are candidates for theme reassignment — they sit on cluster boundaries
    /// and are far from their assigned centroid.
    pub async fn find_boundary_claims(
        pool: &PgPool,
        min_boundary_ratio: f64,
        min_centroid_distance: f64,
        limit: i64,
    ) -> Result<Vec<BoundaryClaimRow>, DbError> {
        let rows = sqlx::query(
            "SELECT cc.claim_id, c.theme_id, cc.boundary_ratio, cc.centroid_distance, \
                    LEFT(c.content, 120) AS content_preview \
             FROM claim_clusters cc \
             JOIN claims c ON c.id = cc.claim_id \
             WHERE cc.boundary_ratio > $1 \
               AND cc.centroid_distance > $2 \
             ORDER BY cc.boundary_ratio DESC \
             LIMIT $3",
        )
        .bind(min_boundary_ratio)
        .bind(min_centroid_distance)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| BoundaryClaimRow {
                claim_id: row.get("claim_id"),
                theme_id: row.get("theme_id"),
                boundary_ratio: row.get("boundary_ratio"),
                centroid_distance: row.get("centroid_distance"),
                content_preview: row.get("content_preview"),
            })
            .collect();
        Ok(results)
    }

    /// Unassign a claim from its theme (set theme_id = NULL).
    ///
    /// Used when no existing theme is a good fit — the claim becomes an outlier
    /// that Phase 5 (detect new theme candidates) can pick up.
    pub async fn unassign_claim(pool: &PgPool, claim_id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE claims SET theme_id = NULL, updated_at = NOW() WHERE id = $1")
            .bind(claim_id)
            .execute(pool)
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    /// Get the cosine distance from a claim's embedding to its current theme centroid.
    ///
    /// Returns `None` if the claim has no theme, no embedding, or the theme has no centroid.
    pub async fn get_claim_theme_distance(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<f64>, DbError> {
        let row = sqlx::query(
            "SELECT (ct.centroid <=> c.embedding)::float8 AS distance \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.id = $1 \
               AND c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL",
        )
        .bind(claim_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<f64, _>("distance")))
    }

    /// Get a claim's embedding as a pgvector string for use in find_similar_themes.
    ///
    /// Returns `None` if the claim has no embedding.
    pub async fn get_claim_embedding_str(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let row = sqlx::query(
            "SELECT embedding::text AS emb_str FROM claims WHERE id = $1 AND embedding IS NOT NULL",
        )
        .bind(claim_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<String, _>("emb_str")))
    }

    /// Assign one batch of unthemed claims to their nearest theme centroid.
    ///
    /// Uses a CTE: find claims with embeddings but no theme_id, assign each
    /// to the nearest theme centroid via pgvector `<=>`. Returns count assigned.
    /// Call in a loop until it returns 0.
    pub async fn assign_unthemed_batch(pool: &PgPool, batch_size: i64) -> Result<i64, DbError> {
        let row = sqlx::query(
            "WITH unthemed AS ( \
                SELECT id, embedding \
                FROM claims \
                WHERE embedding IS NOT NULL AND theme_id IS NULL \
                LIMIT $1 \
            ), \
            nearest AS ( \
                SELECT u.id AS claim_id, \
                       (SELECT ct.id FROM claim_themes ct \
                        WHERE ct.centroid IS NOT NULL \
                        ORDER BY ct.centroid <=> u.embedding \
                        LIMIT 1) AS theme_id \
                FROM unthemed u \
            ) \
            UPDATE claims c \
            SET theme_id = n.theme_id, updated_at = NOW() \
            FROM nearest n \
            WHERE c.id = n.claim_id AND n.theme_id IS NOT NULL \
            RETURNING c.id",
        )
        .bind(batch_size)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row.len() as i64)
    }

    /// Recompute centroid and claim_count for a single theme.
    ///
    /// Centroid = avg(member embeddings)::vector(1536). Returns (label, count).
    /// Returns None if the theme has no claims with embeddings.
    pub async fn recompute_centroid_for_theme(
        pool: &PgPool,
        theme_id: Uuid,
    ) -> Result<Option<(String, i32)>, DbError> {
        let count_row = sqlx::query(
            "SELECT ct.label, COUNT(c.id)::int4 AS n \
             FROM claim_themes ct \
             LEFT JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             WHERE ct.id = $1 \
             GROUP BY ct.label",
        )
        .bind(theme_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)?;

        let (label, count): (String, i32) = match count_row {
            Some(row) => (row.get("label"), row.get("n")),
            None => return Ok(None),
        };

        if count == 0 {
            return Ok(Some((label, 0)));
        }

        sqlx::query(
            "UPDATE claim_themes SET \
                centroid = (SELECT avg(c.embedding)::vector(1536) \
                            FROM claims c \
                            WHERE c.theme_id = $1 AND c.embedding IS NOT NULL), \
                claim_count = $2, \
                updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(theme_id)
        .bind(count)
        .execute(pool)
        .await
        .map_err(DbError::from)?;

        Ok(Some((label, count)))
    }

    /// Recompute centroids for all themes. Returns list of (id, label, count).
    pub async fn recompute_all_centroids(
        pool: &PgPool,
    ) -> Result<Vec<RecomputedThemeRow>, DbError> {
        let themes = sqlx::query(
            "SELECT ct.id, ct.label, COUNT(c.id)::int4 AS n \
             FROM claim_themes ct \
             LEFT JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             GROUP BY ct.id, ct.label \
             ORDER BY n DESC",
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let mut results = Vec::new();
        for row in &themes {
            let id: Uuid = row.get("id");
            let label: String = row.get("label");
            let count: i32 = row.get("n");

            if count > 0 {
                sqlx::query(
                    "UPDATE claim_themes SET \
                        centroid = (SELECT avg(c.embedding)::vector(1536) \
                                    FROM claims c \
                                    WHERE c.theme_id = $1 AND c.embedding IS NOT NULL), \
                        claim_count = $2, \
                        updated_at = NOW() \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(count)
                .execute(pool)
                .await
                .map_err(DbError::from)?;
            }

            results.push(RecomputedThemeRow {
                id,
                label,
                claim_count: count,
            });
        }

        Ok(results)
    }

    /// Find themes with high intra-cluster variance (candidates for splitting).
    pub async fn find_split_candidates(
        pool: &PgPool,
        variance_threshold: f64,
        min_claims: i64,
        limit: i64,
    ) -> Result<Vec<SplitCandidateRow>, DbError> {
        let rows = sqlx::query(
            "SELECT ct.id, ct.label, ct.claim_count, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_distance, \
                    max(ct.centroid <=> c.embedding)::float8 AS max_distance \
             FROM claim_themes ct \
             JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             WHERE ct.claim_count >= $1 AND ct.centroid IS NOT NULL \
             GROUP BY ct.id, ct.label, ct.claim_count \
             HAVING avg(ct.centroid <=> c.embedding) > $2 \
             ORDER BY avg(ct.centroid <=> c.embedding) DESC \
             LIMIT $3",
        )
        .bind(min_claims)
        .bind(variance_threshold)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| SplitCandidateRow {
                theme_id: row.get("id"),
                label: row.get("label"),
                claim_count: row.get("claim_count"),
                avg_distance: row.get("avg_distance"),
                max_distance: row.get("max_distance"),
            })
            .collect();
        Ok(results)
    }

    /// Find themes with many claims far from their centroid (new theme candidates).
    pub async fn find_distant_claims(
        pool: &PgPool,
        distance_threshold: f64,
        min_cluster_size: i64,
        limit: i64,
    ) -> Result<Vec<DistantClaimsRow>, DbError> {
        let rows = sqlx::query(
            "SELECT ct.label, COUNT(*)::int8 AS n_distant, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_dist \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL \
               AND (ct.centroid <=> c.embedding) > $1 \
             GROUP BY ct.id, ct.label \
             HAVING COUNT(*) >= $2 \
             ORDER BY COUNT(*) DESC \
             LIMIT $3",
        )
        .bind(distance_threshold)
        .bind(min_cluster_size)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| DistantClaimsRow {
                source_theme: row.get("label"),
                distant_claims: row.get("n_distant"),
                avg_distance: row.get("avg_dist"),
            })
            .collect();
        Ok(results)
    }

    /// Get claim IDs and embeddings for a theme (for client-side k-means).
    ///
    /// Returns embeddings as pgvector text format. The API handler converts
    /// to JSON arrays for the response.
    pub async fn get_theme_embeddings(
        pool: &PgPool,
        theme_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let rows = sqlx::query(
            "SELECT id, embedding::text AS emb_str \
             FROM claims \
             WHERE theme_id = $1 AND embedding IS NOT NULL \
             LIMIT $2",
        )
        .bind(theme_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        let results = rows
            .iter()
            .map(|row| {
                let id: Uuid = row.get("id");
                let emb: String = row.get("emb_str");
                (id, emb)
            })
            .collect();
        Ok(results)
    }
}
