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

/// Validate `centroid_dim` and return the `(theme_centroid_col,
/// claim_embedding_col)` pair for the SQL builders below.
///
/// Returns `None` for unsupported dims. This is the *only* path by which a
/// pgvector column name reaches the dim-aware `format!`-interpolated SQL in
/// this module — keeping the mapping here means the layering test in
/// `epigraph-engine` does not need to know column names exist, while the
/// SQL stays injection-safe.
#[must_use]
pub fn centroid_columns_for_dim(centroid_dim: u32) -> Option<(&'static str, &'static str)> {
    match centroid_dim {
        1536 => Some(("centroid", "embedding")),
        3072 => Some(("centroid_3072", "embedding_3072")),
        _ => None,
    }
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

    /// Set a theme's centroid to the mean of the given claims' 1536-d
    /// embeddings, computed in the database.
    ///
    /// # Why this exists
    ///
    /// `scripts/maintain_themes.py` used to compute sub-theme centroids
    /// client-side from the raw vectors `GET /themes/:id/embeddings` handed
    /// back. PR-07 stops that endpoint disclosing raw vectors (plan §4.9 row
    /// 4), so the averaging moves here — the server already holds the vectors,
    /// and this is the only remaining reason a caller needed them.
    ///
    /// The read is viewer-filtered: a centroid is an aggregate *of claim
    /// content*, so averaging rows the caller cannot see would leak their
    /// position in embedding space. `Bypass` viewers average everything, which
    /// is what a maintenance job wants.
    ///
    /// Returns the number of claims that contributed. Zero means no visible
    /// claim in `claim_ids` had an embedding, and the centroid is left unset
    /// rather than written as NULL.
    pub async fn set_centroid_from_claims(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        claim_ids: &[Uuid],
    ) -> Result<i64, DbError> {
        let sql = viewer.splice(
            "UPDATE claim_themes t \
             SET centroid = agg.centroid, updated_at = NOW() \
             FROM ( \
                 SELECT AVG(c.embedding)::vector AS centroid, COUNT(*) AS n \
                 FROM claims c \
                 WHERE c.id = ANY($2) AND c.embedding IS NOT NULL \
                   /* {VISIBILITY:c} */ \
             ) agg \
             WHERE t.id = $1 AND agg.n > 0 \
             RETURNING agg.n",
            3,
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql)
            .bind(theme_id)
            .bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let n = q.fetch_optional(pool).await.map_err(DbError::from)?;
        Ok(n.unwrap_or(0))
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
    ///
    /// Legacy 1536d-only convenience over [`Self::find_similar_themes_at_dim`].
    /// New callers should use the dim-aware variant.
    pub async fn find_similar_themes(
        pool: &PgPool,
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::find_similar_themes_at_dim(pool, query_vec, limit, 1536).await
    }

    /// Dim-aware variant of [`Self::find_similar_themes`] for the diverse-retrieval
    /// pipeline.
    ///
    /// `centroid_dim` selects the pgvector column inside `claim_themes`:
    /// `1536` → `centroid`, `3072` → `centroid_3072`. Any other value returns
    /// `DbError::InvalidData` — the dim gate is the *only* path by which a
    /// column name is interpolated, which is what makes the `format!`-built
    /// SQL injection-safe.
    pub async fn find_similar_themes_at_dim(
        pool: &PgPool,
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let (theme_col, _) =
            centroid_columns_for_dim(centroid_dim).ok_or_else(|| DbError::InvalidData {
                reason: format!("unsupported centroid_dim: {centroid_dim} (must be 1536 or 3072)"),
            })?;

        let sql = format!(
            "SELECT id, label, (1 - ({theme_col} <=> $1::vector))::float8 AS similarity \
             FROM claim_themes \
             WHERE {theme_col} IS NOT NULL \
             ORDER BY {theme_col} <=> $1::vector \
             LIMIT $2"
        );

        let rows = sqlx::query(&sql)
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
    ///
    /// Legacy 1536d-only convenience over [`Self::claims_in_themes_at_dim`].
    pub async fn claims_in_themes(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::claims_in_themes_at_dim(pool, viewer, theme_ids, query_vec, limit, 1536, false).await
    }

    /// Dim-aware variant of [`Self::claims_in_themes`].
    ///
    /// `centroid_dim` selects the per-claim embedding column: `1536` →
    /// `claims.embedding`, `3072` → `claims.embedding_3072`. Any other value
    /// returns `DbError::InvalidData`. The same dim gate that protects
    /// `find_similar_themes_at_dim` protects this method — column names
    /// reach the SQL only through the `1536|3072` match in
    /// [`centroid_columns_for_dim`], so the `format!`-interpolated string
    /// cannot carry user input.
    ///
    /// When `paragraph_only` is true, restricts to `level=2` claims (the
    /// hierarchical-paragraph level), used by MCP `recall_with_context`
    /// where the downstream batched-context fetch assumes paragraphs.
    /// REST passes `false` to match its historical behaviour.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::claims_in_themes_at_dim_since`], so the REST
    /// `/api/v1/search/semantic?diverse=true` route (which reaches this
    /// through `epigraph_engine::diverse_retrieval::candidates_in_themes_at_dim`)
    /// keeps the call it already has.
    pub async fn claims_in_themes_at_dim(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
        paragraph_only: bool,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        Self::claims_in_themes_at_dim_since(
            pool,
            viewer,
            theme_ids,
            query_vec,
            limit,
            centroid_dim,
            paragraph_only,
            None,
        )
        .await
    }

    /// [`Self::claims_in_themes_at_dim`] plus an optional
    /// `created_at >= since` window.
    ///
    /// This is the diverse-retrieval candidate source, and it bypasses
    /// `ClaimRepository::search_by_embedding` entirely — so a `since` wired
    /// only into the flat ANN would be silently ignored whenever
    /// `diverse=true`. That is precisely the bug class the existing
    /// `paper_doi_filter` `TODO(diverse-recall)` already exhibits on this
    /// path; the window must not become the second instance of it.
    #[allow(clippy::too_many_arguments)]
    pub async fn claims_in_themes_at_dim_since(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        theme_ids: &[Uuid],
        query_vec: &str,
        limit: i32,
        centroid_dim: u32,
        paragraph_only: bool,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<(Uuid, String, f64)>, DbError> {
        let (_, claim_col) =
            centroid_columns_for_dim(centroid_dim).ok_or_else(|| DbError::InvalidData {
                reason: format!("unsupported centroid_dim: {centroid_dim} (must be 1536 or 3072)"),
            })?;

        let level_clause = if paragraph_only {
            " AND (c.properties->>'level')::int = 2"
        } else {
            ""
        };

        let sql = format!(
            "SELECT c.id, c.content, (1 - (c.{claim_col} <=> $2::vector))::float8 AS similarity \
             FROM claims c \
             WHERE c.theme_id = ANY($1) \
               AND c.{claim_col} IS NOT NULL \
               AND ($4::timestamptz IS NULL OR c.created_at >= $4::timestamptz)\
               {level_clause} \
               /* {{VISIBILITY:c}} */ \
             ORDER BY c.{claim_col} <=> $2::vector \
             LIMIT $3"
        );
        // Doubled braces above: this is a `format!` template, so `{{` emits the
        // single brace `Viewer::splice` looks for.
        let sql = viewer.splice(&sql, 5);

        let mut vq = sqlx::query(&sql)
            .bind(theme_ids)
            .bind(query_vec)
            .bind(limit)
            .bind(since);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(pool).await.map_err(DbError::from)?;

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
        viewer: &crate::visibility::Viewer,
        min_boundary_ratio: f64,
        min_centroid_distance: f64,
        limit: i64,
    ) -> Result<Vec<BoundaryClaimRow>, DbError> {
        let sql = viewer.splice(
            "SELECT cc.claim_id, c.theme_id, cc.boundary_ratio, cc.centroid_distance, \
                    LEFT(c.content, 120) AS content_preview \
             FROM claim_clusters cc \
             JOIN claims c ON c.id = cc.claim_id \
             WHERE cc.boundary_ratio > $1 \
               AND cc.centroid_distance > $2 \
               /* {VISIBILITY:c} */ /* {VISIBILITY:cc} */ \
             ORDER BY cc.boundary_ratio DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(min_boundary_ratio)
            .bind(min_centroid_distance)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(pool).await.map_err(DbError::from)?;

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
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<f64>, DbError> {
        let sql = viewer.splice(
            "SELECT (ct.centroid <=> c.embedding)::float8 AS distance \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.id = $1 \
               AND c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL \
               /* {VISIBILITY:c} */",
            2,
        );
        let mut vq = sqlx::query(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row = vq.fetch_optional(pool).await.map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<f64, _>("distance")))
    }

    /// Get a claim's embedding as a pgvector string for use in find_similar_themes.
    ///
    /// Returns `None` if the claim has no embedding.
    pub async fn get_claim_embedding_str(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let sql = viewer.splice(
            "SELECT embedding::text AS emb_str FROM claims WHERE id = $1 AND embedding IS NOT NULL /* {VISIBILITY:claims} */",
            2,
        );
        let mut vq = sqlx::query(&sql).bind(claim_id);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let row = vq.fetch_optional(pool).await.map_err(DbError::from)?;

        Ok(row.map(|r| r.get::<String, _>("emb_str")))
    }

    /// Assign one batch of unthemed claims to their nearest theme centroid.
    ///
    /// Uses a CTE: find claims with embeddings but no theme_id, assign each
    /// to the nearest theme centroid via pgvector `<=>`. Returns count assigned.
    /// Call in a loop until it returns 0.
    pub async fn assign_unthemed_batch(
        pool: &PgPool,
        _viewer: &crate::visibility::Viewer,
        batch_size: i64,
    ) -> Result<i64, DbError> {
        let row = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             WITH unthemed AS ( \
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
        _viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
    ) -> Result<Option<(String, i32)>, DbError> {
        let count_row = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             SELECT ct.label, COUNT(c.id)::int4 AS n \
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
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             UPDATE claim_themes SET \
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
        _viewer: &crate::visibility::Viewer,
    ) -> Result<Vec<RecomputedThemeRow>, DbError> {
        let themes = sqlx::query(
            "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim.\n             SELECT ct.id, ct.label, COUNT(c.id)::int4 AS n \
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
                    "-- VISIBILITY-EXEMPT: corpus-wide theme clustering maintenance, SystemReason::ThemeClustering.\n             -- A theme centroid is an average over EVERY member claim; computing it\n             -- per-viewer would give each tenant a different, wrong centroid for the\n             -- same theme row and make assignment non-deterministic. Takes a viewer\n             -- so the exemption is visible at the call site.\n             UPDATE claim_themes SET \
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
        viewer: &crate::visibility::Viewer,
        variance_threshold: f64,
        min_claims: i64,
        limit: i64,
    ) -> Result<Vec<SplitCandidateRow>, DbError> {
        let sql = viewer.splice(
            "SELECT ct.id, ct.label, ct.claim_count, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_distance, \
                    max(ct.centroid <=> c.embedding)::float8 AS max_distance \
             FROM claim_themes ct \
             JOIN claims c ON c.theme_id = ct.id AND c.embedding IS NOT NULL \
             WHERE ct.claim_count >= $1 AND ct.centroid IS NOT NULL \
               /* {VISIBILITY:c} */ \
             GROUP BY ct.id, ct.label, ct.claim_count \
             HAVING avg(ct.centroid <=> c.embedding) > $2 \
             ORDER BY avg(ct.centroid <=> c.embedding) DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(min_claims)
            .bind(variance_threshold)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(pool).await.map_err(DbError::from)?;

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
        viewer: &crate::visibility::Viewer,
        distance_threshold: f64,
        min_cluster_size: i64,
        limit: i64,
    ) -> Result<Vec<DistantClaimsRow>, DbError> {
        let sql = viewer.splice(
            "SELECT ct.label, COUNT(*)::int8 AS n_distant, \
                    avg(ct.centroid <=> c.embedding)::float8 AS avg_dist \
             FROM claims c \
             JOIN claim_themes ct ON c.theme_id = ct.id \
             WHERE c.embedding IS NOT NULL \
               AND ct.centroid IS NOT NULL \
               AND (ct.centroid <=> c.embedding) > $1 \
               /* {VISIBILITY:c} */ \
             GROUP BY ct.id, ct.label \
             HAVING COUNT(*) >= $2 \
             ORDER BY COUNT(*) DESC \
             LIMIT $3",
            4,
        );
        let mut vq = sqlx::query(&sql)
            .bind(distance_threshold)
            .bind(min_cluster_size)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(pool).await.map_err(DbError::from)?;

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
        viewer: &crate::visibility::Viewer,
        theme_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let sql = viewer.splice(
            "SELECT id, embedding::text AS emb_str \
             FROM claims \
             WHERE theme_id = $1 AND embedding IS NOT NULL \
               /* {VISIBILITY:claims} */ \
             LIMIT $2",
            3,
        );
        let mut vq = sqlx::query(&sql).bind(theme_id).bind(limit);
        if let Some(g) = viewer.group_bind() {
            vq = vq.bind(g);
        }
        let rows = vq.fetch_all(pool).await.map_err(DbError::from)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centroid_columns_validates_dim() {
        assert_eq!(
            centroid_columns_for_dim(1536),
            Some(("centroid", "embedding"))
        );
        assert_eq!(
            centroid_columns_for_dim(3072),
            Some(("centroid_3072", "embedding_3072"))
        );
        assert!(centroid_columns_for_dim(1024).is_none());
        assert!(centroid_columns_for_dim(0).is_none());
    }
}
