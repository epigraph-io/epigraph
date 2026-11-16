//! Database repository for embedding storage
//!
//! Handles persistence and retrieval of embeddings using `PostgreSQL` with pgvector.
//! Embeddings are stored inline on the `claims` table (`claims.embedding` column).

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::EmbeddingError;
use crate::service::SimilarClaim;

/// Format an embedding vector as a pgvector string literal "[0.1,0.2,...]"
fn format_pgvector(embedding: &[f32]) -> String {
    format!(
        "[{}]",
        embedding
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Repository for embedding database operations
pub struct EmbeddingRepository {
    /// Database connection pool
    pool: PgPool,
    /// Expected embedding dimension
    dimension: usize,
}

impl EmbeddingRepository {
    /// Create a new repository with the given pool and dimension
    #[must_use]
    pub const fn new(pool: PgPool, dimension: usize) -> Self {
        Self { pool, dimension }
    }

    /// Store an embedding for a claim that is not sealed
    ///
    /// The `NOT EXISTS (… claim_encryption …)` predicate is the one every
    /// other writer of `claims.embedding` carries (`ClaimRepository::
    /// store_embedding` and `store_embedding_if_unsealed`): a sealed claim's
    /// content is ciphertext, and a vector computed from its plaintext must not
    /// survive on it (backlog f78526ad). Keyed on `claim_encryption`, never on
    /// `visibility`: a group-private claim is ordinary plaintext and is still
    /// embedded.
    ///
    /// The predicate is only as good as the session's view of
    /// `claim_encryption`, which 077's policy shows only to the sealing group
    /// (or a row-security-bypassing role). This pool is unstamped, so on a
    /// role subject to row security the subquery sees no encryption row and
    /// excludes nothing; migration 212's row trigger is then what refuses the
    /// write, and a sealed claim comes back as `Err` (a database error,
    /// SQLSTATE 42501), not `Ok(false)`.
    ///
    /// # Arguments
    /// * `claim_id` - The claim's UUID
    /// * `embedding` - The embedding vector
    ///
    /// # Returns
    /// * `Ok(true)` - Stored
    /// * `Ok(false)` - No row matched: no such claim, or a sealed claim the
    ///   session can see is sealed
    /// * `Err(EmbeddingError::DatabaseError)` - Includes 212's refusal of a sealed
    ///   claim the session cannot see is sealed
    /// * `Err(EmbeddingError::DimensionMismatch)` - If dimension is wrong
    pub async fn store(&self, claim_id: Uuid, embedding: &[f32]) -> Result<bool, EmbeddingError> {
        if embedding.len() != self.dimension {
            return Err(EmbeddingError::DimensionMismatch {
                expected: self.dimension,
                actual: embedding.len(),
            });
        }

        let vector_str = format_pgvector(embedding);

        let result = sqlx::query(
            r"
            UPDATE claims SET embedding = $2::vector, updated_at = NOW()
            WHERE id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM claim_encryption ce WHERE ce.claim_id = claims.id
              )
            ",
        )
        .bind(claim_id)
        .bind(&vector_str)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Retrieve an embedding for a claim
    ///
    /// # Arguments
    /// * `claim_id` - The claim's UUID
    ///
    /// # Returns
    /// * `Ok(Vec<f32>)` - The embedding vector
    /// * `Err(EmbeddingError::NotFound)` - If no embedding exists
    pub async fn get(&self, claim_id: Uuid) -> Result<Vec<f32>, EmbeddingError> {
        let row: Option<(String,)> = sqlx::query_as(
            r"
            SELECT embedding::text
            FROM claims
            WHERE id = $1 AND embedding IS NOT NULL
            ",
        )
        .bind(claim_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((vector_str,)) => {
                let embedding = Self::parse_vector(&vector_str)?;
                Ok(embedding)
            }
            None => Err(EmbeddingError::NotFound { claim_id }),
        }
    }

    /// Find similar claims using cosine similarity
    ///
    /// # Arguments
    /// * `embedding` - The query embedding
    /// * `k` - Maximum number of results
    /// * `min_similarity` - Minimum similarity threshold
    ///
    /// # Returns
    /// Similar claims sorted by similarity (descending)
    pub async fn similar(
        &self,
        embedding: &[f32],
        k: usize,
        min_similarity: f32,
    ) -> Result<Vec<SimilarClaim>, EmbeddingError> {
        if embedding.len() != self.dimension {
            return Err(EmbeddingError::DimensionMismatch {
                expected: self.dimension,
                actual: embedding.len(),
            });
        }

        let vector_str = format_pgvector(embedding);

        // Use cosine distance (<=> operator in pgvector)
        // Similarity = 1 - distance
        let rows: Vec<(Uuid, f32)> = sqlx::query_as(
            r"
            SELECT
                id,
                (1 - (embedding <=> $1::vector))::float4 as similarity
            FROM claims
            WHERE embedding IS NOT NULL
              AND 1 - (embedding <=> $1::vector) >= $2
            ORDER BY embedding <=> $1::vector
            LIMIT $3
            ",
        )
        .bind(&vector_str)
        .bind(min_similarity)
        .bind(k as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(claim_id, similarity)| SimilarClaim::new(claim_id, similarity))
            .collect())
    }

    /// Delete an embedding
    ///
    /// # Arguments
    /// * `claim_id` - The claim's UUID
    ///
    /// # Returns
    /// `true` if an embedding was deleted, `false` if none existed
    pub async fn delete(&self, claim_id: Uuid) -> Result<bool, EmbeddingError> {
        let result = sqlx::query(
            r"
            UPDATE claims SET embedding = NULL WHERE id = $1 AND embedding IS NOT NULL
            ",
        )
        .bind(claim_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if an embedding exists for a claim
    pub async fn exists(&self, claim_id: Uuid) -> Result<bool, EmbeddingError> {
        let row: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM claims WHERE id = $1 AND embedding IS NOT NULL
            )
            ",
        )
        .bind(claim_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0)
    }

    /// Parse a pgvector string representation to Vec<f32>
    fn parse_vector(vector_str: &str) -> Result<Vec<f32>, EmbeddingError> {
        // pgvector format: "[0.1,0.2,0.3]"
        let trimmed = vector_str.trim_start_matches('[').trim_end_matches(']');

        trimmed
            .split(',')
            .map(|s| {
                s.trim()
                    .parse::<f32>()
                    .map_err(|e| EmbeddingError::DatabaseError(e.to_string()))
            })
            .collect()
    }
}
