//! Entity repository for NER/RDF entity canonicalization

use crate::errors::DbError;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A row from the entities table
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EntityRow {
    pub id: Uuid,
    pub canonical_name: String,
    pub type_top: String,
    pub type_sub: Option<String>,
    pub properties: serde_json::Value,
    pub is_canonical: bool,
    pub merged_into: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Repository for Entity operations
pub struct EntityRepository;

impl EntityRepository {
    /// Upsert an entity by (canonical_name, type_top).
    ///
    /// Uses the unique partial index `idx_entities_canonical_pair` (on
    /// `lower(canonical_name), type_top WHERE is_canonical = true`) to
    /// resolve conflicts idempotently.  On conflict the canonical_name is
    /// refreshed (case-normalisation) and properties are merged via
    /// `jsonb_strip_nulls(properties || EXCLUDED.properties)`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, embedding, properties))]
    pub async fn upsert(
        pool: &PgPool,
        canonical_name: &str,
        type_top: &str,
        type_sub: Option<&str>,
        embedding: Option<&[f32]>,
        properties: serde_json::Value,
    ) -> Result<EntityRow, DbError> {
        // Build the pgvector literal "[v1,v2,...]" when an embedding is provided.
        let embedding_str: Option<String> = embedding.map(|v| {
            let inner: Vec<String> = v.iter().map(|x| x.to_string()).collect();
            format!("[{}]", inner.join(","))
        });

        let row = if let Some(ref emb) = embedding_str {
            sqlx::query!(
                r#"
                INSERT INTO entities (canonical_name, type_top, type_sub, embedding, properties)
                VALUES ($1, $2, $3, $4::vector, $5)
                ON CONFLICT (lower(canonical_name), type_top) WHERE is_canonical = true
                DO UPDATE SET
                    canonical_name = EXCLUDED.canonical_name,
                    properties     = jsonb_strip_nulls(entities.properties || EXCLUDED.properties),
                    embedding      = EXCLUDED.embedding
                RETURNING id, canonical_name, type_top, type_sub, properties, is_canonical,
                          merged_into, created_at
                "#,
                canonical_name,
                type_top,
                type_sub,
                emb as &str,
                properties
            )
            .fetch_one(pool)
            .await
            .map(|r| EntityRow {
                id: r.id,
                canonical_name: r.canonical_name,
                type_top: r.type_top,
                type_sub: r.type_sub,
                properties: r.properties,
                is_canonical: r.is_canonical,
                merged_into: r.merged_into,
                created_at: r.created_at,
            })?
        } else {
            sqlx::query!(
                r#"
                INSERT INTO entities (canonical_name, type_top, type_sub, properties)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (lower(canonical_name), type_top) WHERE is_canonical = true
                DO UPDATE SET
                    canonical_name = EXCLUDED.canonical_name,
                    properties     = jsonb_strip_nulls(entities.properties || EXCLUDED.properties)
                RETURNING id, canonical_name, type_top, type_sub, properties, is_canonical,
                          merged_into, created_at
                "#,
                canonical_name,
                type_top,
                type_sub,
                properties
            )
            .fetch_one(pool)
            .await
            .map(|r| EntityRow {
                id: r.id,
                canonical_name: r.canonical_name,
                type_top: r.type_top,
                type_sub: r.type_sub,
                properties: r.properties,
                is_canonical: r.is_canonical,
                merged_into: r.merged_into,
                created_at: r.created_at,
            })?
        };

        Ok(row)
    }

    /// Find a canonical entity by name and top-level type (case-insensitive name match).
    ///
    /// Returns `None` when no matching canonical entity exists.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_by_name_and_type(
        pool: &PgPool,
        canonical_name: &str,
        type_top: &str,
    ) -> Result<Option<EntityRow>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, canonical_name, type_top, type_sub, properties, is_canonical,
                   merged_into, created_at
            FROM entities
            WHERE lower(canonical_name) = lower($1)
              AND type_top = $2
              AND is_canonical = true
            "#,
            canonical_name,
            type_top
        )
        .fetch_optional(pool)
        .await?
        .map(|r| EntityRow {
            id: r.id,
            canonical_name: r.canonical_name,
            type_top: r.type_top,
            type_sub: r.type_sub,
            properties: r.properties,
            is_canonical: r.is_canonical,
            merged_into: r.merged_into,
            created_at: r.created_at,
        });

        Ok(row)
    }

    /// Get an entity by its UUID.
    ///
    /// Returns `None` when the entity does not exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<EntityRow>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, canonical_name, type_top, type_sub, properties, is_canonical,
                   merged_into, created_at
            FROM entities
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await?
        .map(|r| EntityRow {
            id: r.id,
            canonical_name: r.canonical_name,
            type_top: r.type_top,
            type_sub: r.type_sub,
            properties: r.properties,
            is_canonical: r.is_canonical,
            merged_into: r.merged_into,
            created_at: r.created_at,
        });

        Ok(row)
    }

    /// Find entities similar to the given embedding using pgvector cosine distance.
    ///
    /// Returns up to `limit` canonical entities of `type_top` sorted by descending
    /// cosine similarity, together with the similarity score
    /// `1 - (embedding <=> query_vector)`.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `embedding` - Query vector as a slice of f32 values
    /// * `type_top` - Optional type filter; pass `None` to search across all types
    /// * `min_similarity` - Minimum cosine similarity threshold (inclusive)
    /// * `limit` - Maximum number of results to return
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, embedding))]
    pub async fn find_similar(
        pool: &PgPool,
        embedding: &[f32],
        type_top: Option<&str>,
        min_similarity: f64,
        limit: i64,
    ) -> Result<Vec<(EntityRow, f64)>, DbError> {
        // Format embedding as pgvector literal
        let inner: Vec<String> = embedding.iter().map(|x| x.to_string()).collect();
        let embedding_str = format!("[{}]", inner.join(","));

        // Two variants: with and without type_top filter.
        // Using query! requires the SQL to be statically known, so we branch.
        if let Some(type_filter) = type_top {
            let rows = sqlx::query!(
                r#"
                SELECT id, canonical_name, type_top, type_sub, properties, is_canonical,
                       merged_into, created_at,
                       (1.0 - (embedding <=> $1::vector)) AS similarity
                FROM entities
                WHERE is_canonical = true
                  AND embedding IS NOT NULL
                  AND type_top = $2
                  AND (1.0 - (embedding <=> $1::vector)) >= $3
                ORDER BY embedding <=> $1::vector
                LIMIT $4
                "#,
                &embedding_str as &str,
                type_filter,
                min_similarity,
                limit
            )
            .fetch_all(pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|r| {
                    (
                        EntityRow {
                            id: r.id,
                            canonical_name: r.canonical_name,
                            type_top: r.type_top,
                            type_sub: r.type_sub,
                            properties: r.properties,
                            is_canonical: r.is_canonical,
                            merged_into: r.merged_into,
                            created_at: r.created_at,
                        },
                        r.similarity.unwrap_or(0.0),
                    )
                })
                .collect())
        } else {
            let rows = sqlx::query!(
                r#"
                SELECT id, canonical_name, type_top, type_sub, properties, is_canonical,
                       merged_into, created_at,
                       (1.0 - (embedding <=> $1::vector)) AS similarity
                FROM entities
                WHERE is_canonical = true
                  AND embedding IS NOT NULL
                  AND (1.0 - (embedding <=> $1::vector)) >= $2
                ORDER BY embedding <=> $1::vector
                LIMIT $3
                "#,
                &embedding_str as &str,
                min_similarity,
                limit
            )
            .fetch_all(pool)
            .await?;

            Ok(rows
                .into_iter()
                .map(|r| {
                    (
                        EntityRow {
                            id: r.id,
                            canonical_name: r.canonical_name,
                            type_top: r.type_top,
                            type_sub: r.type_sub,
                            properties: r.properties,
                            is_canonical: r.is_canonical,
                            merged_into: r.merged_into,
                            created_at: r.created_at,
                        },
                        r.similarity.unwrap_or(0.0),
                    )
                })
                .collect())
        }
    }

    /// Mark `loser_id` as merged into `survivor_id`.
    ///
    /// This operation is non-destructive: the loser row is preserved but
    /// `is_canonical` is set to `false` and `merged_into` points to the
    /// survivor.  Callers are responsible for re-pointing any foreign keys
    /// (entity_mentions, triples) to the survivor.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn merge_into(
        pool: &PgPool,
        loser_id: Uuid,
        survivor_id: Uuid,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE entities
            SET is_canonical = false,
                merged_into  = $2
            WHERE id = $1
            "#,
            loser_id,
            survivor_id
        )
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_entity_repository_placeholder(_pool: sqlx::PgPool) {
        // Full CRUD coverage is in integration tests once the pipeline is wired.
    }
}
