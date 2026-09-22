//! Evidence repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceId, EvidenceType};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Evidence operations
pub struct EvidenceRepository;

/// Filter set for [`EvidenceRepository::list_filtered`] /
/// [`EvidenceRepository::count_filtered`].
///
/// Every field is `None` by default, which means "no predicate" — a
/// `Default`-constructed filter selects the whole `evidence` table.
#[derive(Debug, Default, Clone, Copy)]
pub struct EvidenceListFilter<'a> {
    /// Restrict to evidence attached to this claim, via the `evidence.claim_id`
    /// foreign key (`NOT NULL` since migration 001).
    pub claim_id: Option<Uuid>,
    /// Exact match on the `evidence.evidence_type` **text column**.
    ///
    /// That column — not the `properties` JSONB blob — is what
    /// [`EvidenceRepository::evidence_type_to_db_string`] writes, and its
    /// vocabulary is pinned by the `evidence_type_valid` CHECK constraint in
    /// migration 001: `document`, `observation`, `testimony`, `computation`,
    /// `reference`, `figure`, `conversational`. Note that the Rust
    /// `EvidenceType` variant names do **not** all match: `Literature` is
    /// stored as `reference` and `Consensus` as `computation`. Callers filter
    /// with the stored spelling.
    pub evidence_type: Option<&'a str>,
    /// Case-insensitive substring match on `raw_content`.
    ///
    /// `raw_content` is nullable and `NULL ILIKE '%x%'` is NULL, not true, so
    /// this predicate silently excludes every row with no stored transcript.
    /// That is the intended behaviour for a content sweep, but it means
    /// `total` under this filter is not comparable with the unfiltered total.
    pub content_contains: Option<&'a str>,
}

/// One row of [`EvidenceRepository::list_filtered`].
///
/// Deliberately a row struct rather than the domain [`Evidence`] type: the
/// `source_url` column and the raw `properties` JSONB (which carries the
/// figure `caption`) are both needed by the HTTP read route for field-level
/// redaction, and neither survives the round-trip through `Evidence`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EvidenceListRow {
    pub id: Uuid,
    pub claim_id: Uuid,
    /// The stored `evidence_type` text column (see
    /// [`EvidenceListFilter::evidence_type`] for the vocabulary).
    pub evidence_type: String,
    pub raw_content: Option<String>,
    pub content_hash: Vec<u8>,
    pub source_url: Option<String>,
    pub properties: serde_json::Value,
    /// `NULL` for unsigned evidence (DB constraint
    /// `evidence_signature_requires_signer`).
    pub signer_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Build Evidence from database row data.
///
/// This helper function handles the crypto fields that may not exist in
/// the database yet (public_key). It uses placeholder values for
/// the public key until the database schema is migrated.
#[allow(clippy::too_many_arguments)]
fn evidence_from_row(
    id: Uuid,
    agent_id: Uuid,
    content_hash: [u8; 32],
    evidence_type: EvidenceType,
    raw_content: Option<String>,
    claim_id: Uuid,
    signature: Option<[u8; 64]>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Evidence {
    // Placeholder public key - will be populated when DB schema includes it
    let public_key = [0u8; 32];

    Evidence::with_id(
        EvidenceId::from_uuid(id),
        AgentId::from_uuid(agent_id),
        public_key,
        content_hash,
        evidence_type,
        raw_content,
        ClaimId::from_uuid(claim_id),
        signature,
        created_at,
    )
}

impl EvidenceRepository {
    /// Create new evidence in the database
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, evidence))]
    pub async fn create(pool: &PgPool, evidence: &Evidence) -> Result<Evidence, DbError> {
        let id: Uuid = evidence.id.into();
        let agent_id: Uuid = evidence.agent_id.into();
        let claim_id: Uuid = evidence.claim_id.into();
        let content_hash = &evidence.content_hash;
        let raw_content = evidence.raw_content.as_deref();
        let created_at = evidence.created_at;

        // Extract evidence type string and serialize full type to JSONB
        let evidence_type_str = Self::evidence_type_to_db_string(&evidence.evidence_type);
        let evidence_type_json = serde_json::to_value(&evidence.evidence_type)?;

        // Handle signature and signer
        let signature = evidence.signature.as_ref().map(|s| s.as_slice());
        let signer_id: Option<Uuid> = evidence.signature.as_ref().map(|_| agent_id);

        let row = sqlx::query!(
            r#"
            INSERT INTO evidence (
                id, content_hash, evidence_type, source_url, raw_content,
                claim_id, signature, signer_id, properties, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, content_hash, evidence_type, raw_content, claim_id,
                      signature, signer_id, properties, created_at
            "#,
            id,
            content_hash.as_slice(),
            evidence_type_str,
            None::<String>, // source_url extracted from evidence_type if needed
            raw_content,
            claim_id,
            signature,
            signer_id,
            evidence_type_json,
            created_at
        )
        .fetch_one(pool)
        .await?;

        // Parse content_hash
        let content_hash: [u8; 32] =
            row.content_hash
                .try_into()
                .map_err(|_| DbError::InvalidData {
                    reason: "content_hash is not 32 bytes".to_string(),
                })?;

        // Parse evidence type from JSONB
        let evidence_type: EvidenceType = serde_json::from_value(row.properties)?;

        // Parse signature if present
        let signature: Option<[u8; 64]> = match row.signature {
            Some(sig) => Some(sig.try_into().map_err(|_| DbError::InvalidData {
                reason: "signature is not 64 bytes".to_string(),
            })?),
            None => None,
        };

        Ok(evidence_from_row(
            row.id,
            row.signer_id.unwrap_or(agent_id),
            content_hash,
            evidence_type,
            row.raw_content,
            row.claim_id,
            signature,
            row.created_at,
        ))
    }

    /// Get evidence by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: EvidenceId) -> Result<Option<Evidence>, DbError> {
        let uuid: Uuid = id.into();

        let row = sqlx::query!(
            r#"
            SELECT id, content_hash, evidence_type, raw_content, claim_id,
                   signature, signer_id, properties, created_at
            FROM evidence
            WHERE id = $1
            "#,
            uuid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let content_hash: [u8; 32] =
                    row.content_hash
                        .try_into()
                        .map_err(|_| DbError::InvalidData {
                            reason: "content_hash is not 32 bytes".to_string(),
                        })?;

                let evidence_type: EvidenceType = serde_json::from_value(row.properties.clone())
                    .unwrap_or_else(|_| EvidenceType::Document {
                        source_url: None,
                        mime_type: "application/octet-stream".to_string(),
                        checksum: None,
                    });

                let signature: Option<[u8; 64]> = match row.signature {
                    Some(sig) => Some(sig.try_into().map_err(|_| DbError::InvalidData {
                        reason: "signature is not 64 bytes".to_string(),
                    })?),
                    None => None,
                };

                // Unsigned evidence has signer_id = NULL (DB constraint:
                // evidence_signature_requires_signer). Use nil UUID as fallback.
                let agent_id = row.signer_id.unwrap_or(Uuid::nil());

                Ok(Some(evidence_from_row(
                    row.id,
                    agent_id,
                    content_hash,
                    evidence_type,
                    row.raw_content,
                    row.claim_id,
                    signature,
                    row.created_at,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get all evidence for a claim
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_claim(pool: &PgPool, claim_id: ClaimId) -> Result<Vec<Evidence>, DbError> {
        let uuid: Uuid = claim_id.into();

        let rows = sqlx::query!(
            r#"
            SELECT id, content_hash, evidence_type, raw_content, claim_id,
                   signature, signer_id, properties, created_at
            FROM evidence
            WHERE claim_id = $1
            ORDER BY created_at DESC
            "#,
            uuid
        )
        .fetch_all(pool)
        .await?;

        let mut evidence_list = Vec::with_capacity(rows.len());

        for row in rows {
            let content_hash: [u8; 32] =
                row.content_hash
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "content_hash is not 32 bytes".to_string(),
                    })?;

            let evidence_type: EvidenceType = serde_json::from_value(row.properties.clone())
                .unwrap_or_else(|_| EvidenceType::Document {
                    source_url: None,
                    mime_type: "application/octet-stream".to_string(),
                    checksum: None,
                });

            let signature: Option<[u8; 64]> = match row.signature {
                Some(sig) => Some(sig.try_into().map_err(|_| DbError::InvalidData {
                    reason: "signature is not 64 bytes".to_string(),
                })?),
                None => None,
            };

            // Unsigned evidence has signer_id = NULL (DB constraint:
            // evidence_signature_requires_signer). Use nil UUID as fallback.
            let agent_id = row.signer_id.unwrap_or(Uuid::nil());

            evidence_list.push(evidence_from_row(
                row.id,
                agent_id,
                content_hash,
                evidence_type,
                row.raw_content,
                row.claim_id,
                signature,
                row.created_at,
            ));
        }

        Ok(evidence_list)
    }

    /// Delete evidence by ID
    ///
    /// # Returns
    /// Returns `true` if the evidence was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: EvidenceId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query!(
            r#"
            DELETE FROM evidence
            WHERE id = $1
            "#,
            uuid
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Shared `WHERE` clause for [`Self::list_filtered`] and
    /// [`Self::count_filtered`], mirroring `ClaimRepository::FILTER_WHERE`.
    ///
    /// One clause, one bind helper: the count and the page it describes cannot
    /// drift apart, because there is only one place either could change.
    const FILTER_WHERE: &'static str = r#"
            WHERE ($1::uuid IS NULL OR claim_id = $1)
              AND ($2::text IS NULL OR evidence_type = $2)
              AND ($3::text IS NULL OR raw_content ILIKE $3)
    "#;

    /// Bind `$1..$3` of [`Self::FILTER_WHERE`], in order.
    ///
    /// Generic over the output type so the row query and the count query share
    /// one implementation.
    fn bind_filter<'q, O>(
        query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
        filter: &EvidenceListFilter<'_>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        query
            .bind(filter.claim_id)
            .bind(filter.evidence_type.map(str::to_owned))
            .bind(filter.content_contains.map(|s| format!("%{s}%")))
    }

    /// Count the evidence rows matching `filter` — a real `COUNT(*)`
    /// evaluated by PostgreSQL over the whole table.
    ///
    /// Paired with [`Self::list_filtered`], which applies the identical
    /// predicates before `LIMIT`/`OFFSET`. A caller reporting
    /// `rows.len()` as the total would understate any result larger than one
    /// page, which is the defect this pair exists to avoid (backlog
    /// `d7aab418`).
    ///
    /// Uses the runtime `query_as` form deliberately: no compile-time `.sqlx`
    /// cache entry, so this change needs no `cargo sqlx prepare`.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] if the database query fails.
    #[instrument(skip(pool, filter))]
    pub async fn count_filtered(
        pool: &PgPool,
        filter: &EvidenceListFilter<'_>,
    ) -> Result<i64, DbError> {
        let sql = format!("SELECT COUNT(*) FROM evidence{}", Self::FILTER_WHERE);
        // `query_scalar` is `query_as` over a 1-tuple; going through the tuple
        // form lets `bind_filter` serve both methods.
        let (count,): (i64,) = Self::bind_filter(sqlx::query_as::<_, (i64,)>(&sql), filter)
            .fetch_one(pool)
            .await?;
        Ok(count)
    }

    /// List the evidence rows matching `filter`, paginated **in SQL**.
    ///
    /// All predicates run before `LIMIT`/`OFFSET`, so a matching row is
    /// reachable regardless of how old it is — the property that makes the
    /// 123k-row `evidence` table sweepable through the API at all.
    ///
    /// `ORDER BY created_at DESC, id DESC` carries an `id` tiebreaker so paging
    /// is stable across rows sharing a `created_at` (bulk ingestion writes many
    /// evidence rows inside one transaction, all with the same timestamp — an
    /// unstable sort there would both duplicate and skip rows across pages).
    ///
    /// Uses the runtime `query_as` form; see [`Self::count_filtered`].
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] if the database query fails.
    #[instrument(skip(pool, filter))]
    pub async fn list_filtered(
        pool: &PgPool,
        filter: &EvidenceListFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EvidenceListRow>, DbError> {
        let sql = format!(
            r#"
            SELECT id, claim_id, evidence_type, raw_content, content_hash,
                   source_url, properties, signer_id, created_at
            FROM evidence{where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT $4 OFFSET $5
            "#,
            where_clause = Self::FILTER_WHERE,
        );

        let rows = Self::bind_filter(sqlx::query_as::<_, EvidenceListRow>(&sql), filter)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;

        Ok(rows)
    }

    /// Convert EvidenceType enum to database string
    fn evidence_type_to_db_string(evidence_type: &EvidenceType) -> &'static str {
        match evidence_type {
            EvidenceType::Document { .. } => "document",
            EvidenceType::Observation { .. } => "observation",
            EvidenceType::Testimony { .. } => "testimony",
            EvidenceType::Literature { .. } => "reference",
            EvidenceType::Consensus { .. } => "computation",
            EvidenceType::Figure { .. } => "figure",
        }
    }

    /// Store an embedding vector for an evidence item
    ///
    /// Accepts a pgvector-formatted string (e.g., "[0.1,0.2,...]") and stores
    /// it in the evidence embedding column.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, embedding_pgvector))]
    pub async fn store_embedding(
        pool: &PgPool,
        id: EvidenceId,
        embedding_pgvector: &str,
    ) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query("UPDATE evidence SET embedding = $1::vector WHERE id = $2")
            .bind(embedding_pgvector)
            .bind(uuid)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Search evidence by vector similarity using cosine distance
    ///
    /// Returns evidence IDs and similarity scores for the closest matches.
    /// Excludes evidence whose attached claim has been superseded
    /// (`claims.is_current = false`) so that supersede flows do not silently
    /// keep the old claim surfaced to semantic-search consumers. Note that
    /// `supersedes` is NOT used as an exclusion predicate — the new claim
    /// populates `supersedes = $old` to record lineage, so filtering on
    /// `supersedes IS NULL` would drop the replacement.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<EvidenceSearchResult>, DbError> {
        let rows = sqlx::query_as::<_, EvidenceSearchResult>(
            r#"
            SELECT
                e.id,
                e.claim_id,
                e.raw_content,
                1 - (e.embedding <=> $1::vector) AS similarity
            FROM evidence e
            WHERE e.embedding IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM claims c
                  WHERE c.id = e.claim_id
                    AND COALESCE(c.is_current, true) = true
              )
            ORDER BY e.embedding <=> $1::vector
            LIMIT $2
            "#,
        )
        .bind(query_embedding_pgvector)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Batch create multiple evidence items in a single transaction
    ///
    /// Uses PostgreSQL multi-value INSERT for efficiency. All evidence items are
    /// inserted atomically - if any insert fails, the entire batch is rolled back.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `evidence` - Slice of evidence items to insert
    ///
    /// # Returns
    /// Vector of created evidence items with server-generated data
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    /// Returns `DbError::DuplicateKey` if any evidence ID already exists.
    ///
    /// # Performance
    /// - Batch size is limited internally to prevent memory issues
    /// - For very large batches (>1000), consider chunking externally
    #[instrument(skip(pool, evidence), fields(batch_size = evidence.len()))]
    pub async fn batch_create(
        pool: &PgPool,
        evidence: &[Evidence],
    ) -> Result<Vec<Evidence>, DbError> {
        if evidence.is_empty() {
            return Ok(Vec::new());
        }

        // Limit batch size to prevent memory issues (Architect review requirement)
        const MAX_BATCH_SIZE: usize = 1000;
        if evidence.len() > MAX_BATCH_SIZE {
            tracing::warn!(
                "Batch size {} exceeds recommended maximum {}. Consider chunking.",
                evidence.len(),
                MAX_BATCH_SIZE
            );
        }

        // Use a transaction for atomicity
        let mut tx = pool.begin().await?;

        // Build multi-value INSERT query dynamically
        // Evidence table has: id, content_hash, evidence_type, source_url, raw_content,
        //                     claim_id, signature, signer_id, properties, created_at
        let mut query_builder = String::from(
            r#"INSERT INTO evidence (id, content_hash, evidence_type, source_url, raw_content, claim_id, signature, signer_id, properties, created_at)
               VALUES "#,
        );

        // Build parameter placeholders
        let mut param_idx = 1;
        for (i, _) in evidence.iter().enumerate() {
            if i > 0 {
                query_builder.push_str(", ");
            }
            query_builder.push_str(&format!(
                "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                param_idx,
                param_idx + 1,
                param_idx + 2,
                param_idx + 3,
                param_idx + 4,
                param_idx + 5,
                param_idx + 6,
                param_idx + 7,
                param_idx + 8,
                param_idx + 9
            ));
            param_idx += 10;
        }

        query_builder.push_str(
            " RETURNING id, content_hash, evidence_type, raw_content, claim_id, signature, signer_id, properties, created_at",
        );

        // Build the query with all parameters
        let mut query = sqlx::query_as::<_, EvidenceRow>(&query_builder);

        for e in evidence {
            let id: Uuid = e.id.into();
            let agent_id: Uuid = e.agent_id.into();
            let claim_id: Uuid = e.claim_id.into();
            let evidence_type_str = Self::evidence_type_to_db_string(&e.evidence_type);
            let evidence_type_json = serde_json::to_value(&e.evidence_type)?;
            let signature = e.signature.as_ref().map(|s| s.as_slice());
            let signer_id: Option<Uuid> = e.signature.as_ref().map(|_| agent_id);

            query = query
                .bind(id)
                .bind(e.content_hash.as_slice())
                .bind(evidence_type_str)
                .bind(None::<String>) // source_url extracted from evidence_type if needed
                .bind(e.raw_content.as_deref())
                .bind(claim_id)
                .bind(signature)
                .bind(signer_id) // NULL when unsigned (matches evidence_signature_requires_signer constraint)
                .bind(evidence_type_json)
                .bind(e.created_at);
        }

        let rows = query.fetch_all(&mut *tx).await?;

        tx.commit().await?;

        // Convert rows to Evidence
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let content_hash: [u8; 32] =
                row.content_hash
                    .try_into()
                    .map_err(|_| DbError::InvalidData {
                        reason: "content_hash is not 32 bytes".to_string(),
                    })?;

            let evidence_type: EvidenceType = serde_json::from_value(row.properties.clone())
                .unwrap_or_else(|_| EvidenceType::Document {
                    source_url: None,
                    mime_type: "application/octet-stream".to_string(),
                    checksum: None,
                });

            let signature: Option<[u8; 64]> = match row.signature {
                Some(sig) => Some(sig.try_into().map_err(|_| DbError::InvalidData {
                    reason: "signature is not 64 bytes".to_string(),
                })?),
                None => None,
            };

            // Unsigned evidence has signer_id = NULL
            let agent_id = row.signer_id.unwrap_or(Uuid::nil());

            result.push(evidence_from_row(
                row.id,
                agent_id,
                content_hash,
                evidence_type,
                row.raw_content,
                row.claim_id,
                signature,
                row.created_at,
            ));
        }

        Ok(result)
    }
}

/// Result from evidence embedding similarity search
#[derive(Debug, sqlx::FromRow)]
pub struct EvidenceSearchResult {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub raw_content: Option<String>,
    pub similarity: f64,
}

/// Row struct for batch query results
#[derive(sqlx::FromRow)]
struct EvidenceRow {
    id: Uuid,
    content_hash: Vec<u8>,
    #[allow(dead_code)]
    evidence_type: String,
    raw_content: Option<String>,
    claim_id: Uuid,
    signature: Option<Vec<u8>>,
    signer_id: Option<Uuid>,
    properties: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_evidence_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/evidence_tests.rs
    }
}
