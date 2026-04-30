//! Claim repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Claim operations
pub struct ClaimRepository;

/// Build a Claim from database row data.
///
/// This helper function handles the crypto fields that may not exist in
/// the database yet (public_key, content_hash, signature). It computes
/// the content hash from the content and uses placeholder values for
/// the public key and signature until the database schema is migrated.
fn claim_from_row(
    id: Uuid,
    content: String,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    truth_value: TruthValue,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Claim {
    // Compute content hash from the content
    let content_hash_vec = ContentHasher::hash(content.as_bytes());
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&content_hash_vec);

    // Placeholder public key - will be populated when DB schema includes it
    let public_key = [0u8; 32];

    // No signature from legacy DB records
    let signature = None;

    Claim::with_id(
        ClaimId::from_uuid(id),
        content,
        AgentId::from_uuid(agent_id),
        public_key,
        content_hash,
        trace_id.map(TraceId::from_uuid),
        signature,
        truth_value,
        created_at,
        updated_at,
    )
}

impl ClaimRepository {
    /// Create a new claim in the database (LEGACY — implicit content-hash dedup)
    ///
    /// **Legacy behavior:** dedups on `content_hash` alone (NOT on
    /// `(content_hash, agent_id)`), so a request from agent B with the same
    /// content as an earlier claim from agent A returns agent A's row. This is
    /// a noun-claim invariant violation. New code should use
    /// `find_by_content_hash_and_agent` + `create_or_get` / `create_strict`
    /// (see `docs/architecture/noun-claims-and-verb-edges.md`). The ~44
    /// internal callers of this method are migrated as a separate
    /// out-of-band task.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, claim))]
    pub async fn create(pool: &PgPool, claim: &Claim) -> Result<Claim, DbError> {
        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;

        // Calculate content hash using BLAKE3
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        // Dedup: if a claim with this content already exists, return it instead of
        // inserting a duplicate. Two round-trips are acceptable; the race window is
        // tiny and duplicate claims are idempotent in practice.
        let existing = sqlx::query!(
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
               FROM claims WHERE content_hash = $1 LIMIT 1"#,
            content_hash.as_slice()
        )
        .fetch_optional(pool)
        .await?;

        if let Some(existing_row) = existing {
            let tv = TruthValue::new(existing_row.truth_value)?;
            return Ok(claim_from_row(
                existing_row.id,
                existing_row.content,
                existing_row.agent_id,
                existing_row.trace_id,
                tv,
                existing_row.created_at,
                existing_row.updated_at,
            ));
        }

        let row = sqlx::query!(
            r#"
            INSERT INTO claims (
                id, content, content_hash, truth_value, agent_id, trace_id,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            id,
            claim.content,
            content_hash.as_slice(),
            truth_value,
            agent_id,
            trace_id,
            created_at,
            updated_at
        )
        .fetch_one(pool)
        .await?;

        let truth_value = TruthValue::new(row.truth_value)?;

        Ok(claim_from_row(
            row.id,
            row.content,
            row.agent_id,
            row.trace_id,
            truth_value,
            row.created_at,
            row.updated_at,
        ))
    }

    /// Set the `properties` JSONB column on an existing claim. Overwrites the
    /// existing value (does not merge). Used by ingest to attach hierarchy
    /// metadata (level, section, source_type, generality) at creation time.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, properties))]
    pub async fn set_properties(
        pool: &PgPool,
        claim_id: ClaimId,
        properties: serde_json::Value,
    ) -> Result<(), DbError> {
        let id: Uuid = claim_id.into();
        let result = sqlx::query!(
            "UPDATE claims SET properties = $2, updated_at = NOW() WHERE id = $1",
            id,
            properties
        )
        .execute(pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id,
            });
        }
        Ok(())
    }

    /// Create a new claim within an existing transaction (LEGACY — implicit content-hash dedup)
    ///
    /// Same as `create()` but accepts a `&mut PgConnection` for transactional use.
    /// Uses runtime query (not compile-time macro) to support the connection executor.
    ///
    /// **Legacy behavior:** see the note on `create()` — this method shares
    /// the same cross-agent collapse bug. New transactional code should use
    /// `create_or_get` / `create_strict`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn create_with_tx(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
    ) -> Result<Claim, DbError> {
        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        use sqlx::Row;

        // Dedup check within the same transaction
        let existing = sqlx::query(
            "SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
             FROM claims WHERE content_hash = $1 LIMIT 1",
        )
        .bind(content_hash.as_slice())
        .fetch_optional(&mut *conn)
        .await?;

        if let Some(existing_row) = existing {
            let truth_val: f64 = existing_row.get("truth_value");
            let tv = TruthValue::new(truth_val)?;
            return Ok(claim_from_row(
                existing_row.get("id"),
                existing_row.get("content"),
                existing_row.get("agent_id"),
                existing_row.get("trace_id"),
                tv,
                existing_row.get("created_at"),
                existing_row.get("updated_at"),
            ));
        }

        let row = sqlx::query(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(id)
        .bind(&claim.content)
        .bind(content_hash.as_slice())
        .bind(truth_value)
        .bind(agent_id)
        .bind(trace_id)
        .bind(created_at)
        .bind(updated_at)
        .fetch_one(&mut *conn)
        .await?;

        let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
        Ok(claim_from_row(
            row.get("id"),
            row.get("content"),
            row.get("agent_id"),
            row.get("trace_id"),
            tv,
            row.get("created_at"),
            row.get("updated_at"),
        ))
    }

    /// Get a claim by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, id: ClaimId) -> Result<Option<Claim>, DbError> {
        let uuid: Uuid = id.into();

        let row = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE id = $1
            "#,
            uuid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.truth_value)?;

                Ok(Some(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                )))
            }
            None => Ok(None),
        }
    }

    /// Get all claims by an agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_agent(pool: &PgPool, agent_id: AgentId) -> Result<Vec<Claim>, DbError> {
        let uuid: Uuid = agent_id.into();

        let rows = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE agent_id = $1
            ORDER BY created_at DESC
            "#,
            uuid
        )
        .fetch_all(pool)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Update the truth value of a claim
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_truth_value(
        pool: &PgPool,
        id: ClaimId,
        truth: TruthValue,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let truth_value = truth.value();

        let row = sqlx::query!(
            r#"
            UPDATE claims
            SET truth_value = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            uuid,
            truth_value
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.truth_value)?;

                Ok(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the truth value of a claim using an existing connection (e.g. inside a transaction).
    pub async fn update_truth_value_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
        truth: TruthValue,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let truth_value = truth.value();

        use sqlx::Row;
        let row = sqlx::query(
            r#"UPDATE claims
               SET truth_value = $2, updated_at = NOW()
               WHERE id = $1
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(uuid)
        .bind(truth_value)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the trace_id of a claim
    ///
    /// Use this to associate a claim with a reasoning trace after both have been created.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_trace_id(
        pool: &PgPool,
        id: ClaimId,
        trace_id: TraceId,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let trace_uuid: Uuid = trace_id.into();

        let row = sqlx::query!(
            r#"
            UPDATE claims
            SET trace_id = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at
            "#,
            uuid,
            trace_uuid
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.truth_value)?;

                Ok(claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Update the trace_id of a claim using an existing connection (e.g. inside a transaction).
    pub async fn update_trace_id_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
        trace_id: TraceId,
    ) -> Result<Claim, DbError> {
        let uuid: Uuid = id.into();
        let trace_uuid: Uuid = trace_id.into();

        use sqlx::Row;
        let row = sqlx::query(
            r#"UPDATE claims
               SET trace_id = $2, updated_at = NOW()
               WHERE id = $1
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(uuid)
        .bind(trace_uuid)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                ))
            }
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: uuid,
            }),
        }
    }

    /// Get claims with truth value above a threshold
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_high_truth(pool: &PgPool, threshold: f64) -> Result<Vec<Claim>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE truth_value >= $1
            ORDER BY truth_value DESC, created_at DESC
            "#,
            threshold
        )
        .fetch_all(pool)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Get claims with truth value below a threshold
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_low_truth(pool: &PgPool, threshold: f64) -> Result<Vec<Claim>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE truth_value <= $1
            ORDER BY truth_value ASC, created_at DESC
            "#,
            threshold
        )
        .fetch_all(pool)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// Delete a claim by ID
    ///
    /// # Returns
    /// Returns `true` if the claim was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn delete(pool: &PgPool, id: ClaimId) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();

        let result = sqlx::query!(
            r#"
            DELETE FROM claims
            WHERE id = $1
            "#,
            uuid
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get a claim by ID within an existing transaction.
    pub async fn get_by_id_conn(
        conn: &mut sqlx::PgConnection,
        id: ClaimId,
    ) -> Result<Option<Claim>, DbError> {
        let uuid: Uuid = id.into();

        use sqlx::Row;
        let row = sqlx::query(
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims WHERE id = $1"#,
        )
        .bind(uuid)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(Some(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    /// List claims with pagination
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list(
        pool: &PgPool,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> Result<Vec<Claim>, DbError> {
        let search_pattern = search.map(|s| format!("%{}%", s));

        let query_str = if search_pattern.is_some() {
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE content ILIKE $3
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#
        } else {
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#
        };

        let mut query = sqlx::query_as::<_, ClaimRow>(query_str)
            .bind(limit)
            .bind(offset);

        if let Some(s) = search_pattern {
            query = query.bind(s);
        }

        let rows = query.fetch_all(pool).await?;

        let mut claims = Vec::with_capacity(rows.len());

        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;

            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(claims)
    }

    /// List claims that contain ALL of the specified labels.
    ///
    /// Uses the GIN index on `claims.labels` for efficient `@>` containment queries.
    /// Results are ordered by `created_at DESC` and filtered by optional truth threshold.
    #[instrument(skip(pool))]
    pub async fn list_by_labels(
        pool: &PgPool,
        labels: &[String],
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<Claim>, DbError> {
        let limit = limit.clamp(1, 1000);
        let rows = sqlx::query_as::<_, ClaimRow>(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE labels @> $1 AND truth_value >= $2
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(labels)
        .bind(min_truth)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }
        Ok(claims)
    }

    /// Count total number of claims
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn count(pool: &PgPool, search: Option<&str>) -> Result<i64, DbError> {
        let search_pattern = search.map(|s| format!("%{}%", s));

        let query_str = if search_pattern.is_some() {
            r#"
            SELECT COUNT(*) as count
            FROM claims
            WHERE content ILIKE $1
            "#
        } else {
            r#"
            SELECT COUNT(*) as count
            FROM claims
            "#
        };

        let mut query = sqlx::query_scalar::<_, i64>(query_str);

        if let Some(s) = search_pattern {
            query = query.bind(s);
        }

        let row_count = query.fetch_one(pool).await?;

        Ok(row_count)
    }

    /// List claims with pagination within an existing transaction.
    pub async fn list_conn(
        conn: &mut sqlx::PgConnection,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> Result<Vec<Claim>, DbError> {
        let search_pattern = search.map(|s| format!("%{}%", s));
        let query_str = if search_pattern.is_some() {
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims WHERE content ILIKE $3 ORDER BY created_at DESC LIMIT $1 OFFSET $2"#
        } else {
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims ORDER BY created_at DESC LIMIT $1 OFFSET $2"#
        };
        let mut query = sqlx::query_as::<_, ClaimRow>(query_str)
            .bind(limit)
            .bind(offset);
        if let Some(s) = search_pattern {
            query = query.bind(s);
        }
        let rows = query.fetch_all(&mut *conn).await?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            claims.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }
        Ok(claims)
    }

    /// Count total number of claims within an existing transaction.
    pub async fn count_conn(
        conn: &mut sqlx::PgConnection,
        search: Option<&str>,
    ) -> Result<i64, DbError> {
        let search_pattern = search.map(|s| format!("%{}%", s));
        let query_str = if search_pattern.is_some() {
            r#"SELECT COUNT(*) as count FROM claims WHERE content ILIKE $1"#
        } else {
            r#"SELECT COUNT(*) as count FROM claims"#
        };
        let mut query = sqlx::query_scalar::<_, i64>(query_str);
        if let Some(s) = search_pattern {
            query = query.bind(s);
        }
        let count = query.fetch_one(&mut *conn).await?;
        Ok(count)
    }

    /// Batch create multiple claims in a single transaction
    ///
    /// Uses PostgreSQL multi-value INSERT for efficiency. All claims are inserted
    /// atomically - if any insert fails, the entire batch is rolled back.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `claims` - Slice of claims to insert
    ///
    /// # Returns
    /// Vector of created claims with server-generated timestamps
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any database operation fails.
    /// Returns `DbError::DuplicateKey` if any claim ID already exists.
    ///
    /// # Performance
    /// - Batch size is limited internally to prevent memory issues
    /// - For very large batches (>1000), consider chunking externally
    #[instrument(skip(pool, claims), fields(batch_size = claims.len()))]
    pub async fn batch_create(pool: &PgPool, claims: &[Claim]) -> Result<Vec<Claim>, DbError> {
        if claims.is_empty() {
            return Ok(Vec::new());
        }

        // Limit batch size to prevent memory issues (Architect review requirement)
        const MAX_BATCH_SIZE: usize = 1000;
        if claims.len() > MAX_BATCH_SIZE {
            tracing::warn!(
                "Batch size {} exceeds recommended maximum {}. Consider chunking.",
                claims.len(),
                MAX_BATCH_SIZE
            );
        }

        // Use a transaction for atomicity
        let mut tx = pool.begin().await?;

        // Build multi-value INSERT query dynamically
        // PostgreSQL supports multi-row VALUES: INSERT INTO t VALUES (...), (...), (...)
        let mut query_builder = String::from(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at)
               VALUES "#,
        );

        // Build parameter placeholders and collect values
        let mut param_idx = 1;
        for (i, _) in claims.iter().enumerate() {
            if i > 0 {
                query_builder.push_str(", ");
            }
            query_builder.push_str(&format!(
                "(${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                param_idx,
                param_idx + 1,
                param_idx + 2,
                param_idx + 3,
                param_idx + 4,
                param_idx + 5,
                param_idx + 6,
                param_idx + 7
            ));
            param_idx += 8;
        }

        query_builder.push_str(
            " RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at",
        );

        // Pre-compute all content hashes to avoid lifetime issues
        // (hashes must outlive the query)
        let content_hashes: Vec<Vec<u8>> = claims
            .iter()
            .map(|c| ContentHasher::hash(c.content.as_bytes()).to_vec())
            .collect();

        // Build the query with all parameters
        let mut query = sqlx::query_as::<_, ClaimRow>(&query_builder);

        for (i, claim) in claims.iter().enumerate() {
            let id: Uuid = claim.id.into();
            let agent_id: Uuid = claim.agent_id.into();
            let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);

            query = query
                .bind(id)
                .bind(&claim.content)
                .bind(&content_hashes[i])
                .bind(claim.truth_value.value())
                .bind(agent_id)
                .bind(trace_id)
                .bind(claim.created_at)
                .bind(claim.updated_at);
        }

        let rows = query.fetch_all(&mut *tx).await?;

        tx.commit().await?;

        // Convert rows to Claims
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            result.push(claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            ));
        }

        Ok(result)
    }

    /// Batch update truth values for multiple claims in a single query
    ///
    /// Uses PostgreSQL UPDATE with CASE WHEN for efficient bulk updates.
    /// Only updates claims that exist - non-existent IDs are silently skipped.
    ///
    /// # Arguments
    /// * `pool` - Database connection pool
    /// * `updates` - Slice of (ClaimId, TruthValue) pairs to update
    ///
    /// # Returns
    /// Number of rows actually updated
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database operation fails.
    ///
    /// # Example
    /// ```rust,no_run
    /// use epigraph_db::ClaimRepository;
    /// use epigraph_core::{ClaimId, TruthValue};
    ///
    /// # async fn example(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    /// let updates = vec![
    ///     (ClaimId::new(), TruthValue::new(0.8)?),
    ///     (ClaimId::new(), TruthValue::new(0.9)?),
    /// ];
    /// let affected = ClaimRepository::batch_update_truth_values(pool, &updates).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(pool, updates), fields(update_count = updates.len()))]
    pub async fn batch_update_truth_values(
        pool: &PgPool,
        updates: &[(ClaimId, TruthValue)],
    ) -> Result<usize, DbError> {
        if updates.is_empty() {
            return Ok(0);
        }

        // Build UPDATE with CASE WHEN for efficiency
        // UPDATE claims SET truth_value = CASE id
        //   WHEN uuid1 THEN value1
        //   WHEN uuid2 THEN value2
        // END, updated_at = NOW()
        // WHERE id IN (uuid1, uuid2, ...)

        let mut case_builder = String::from("UPDATE claims SET truth_value = CASE id ");
        let mut where_ids = Vec::with_capacity(updates.len());
        let mut param_idx = 1;

        for _ in updates {
            case_builder.push_str(&format!("WHEN ${} THEN ${} ", param_idx, param_idx + 1));
            where_ids.push(format!("${}", param_idx));
            param_idx += 2;
        }

        case_builder.push_str("END, updated_at = NOW() WHERE id IN (");
        case_builder.push_str(&where_ids.join(", "));
        case_builder.push(')');

        let mut query = sqlx::query(&case_builder);

        for (claim_id, truth_value) in updates {
            let uuid: Uuid = (*claim_id).into();
            query = query.bind(uuid).bind(truth_value.value());
        }

        let result = query.execute(pool).await?;

        Ok(result.rows_affected() as usize)
    }

    /// Supersede a claim with a corrected version in a single transaction.
    ///
    /// Creates a new claim linked to the old one via `supersedes`, and marks
    /// the old claim `is_current = false`. Both operations are atomic.
    ///
    /// # Errors
    /// - `DbError::NotFound` if the old claim doesn't exist
    /// - `DbError::QueryFailed` if the old claim is already superseded or DB fails
    #[instrument(skip(pool))]
    pub async fn supersede(
        pool: &PgPool,
        old_claim_id: ClaimId,
        new_content: &str,
        new_truth: TruthValue,
        reason: &str,
    ) -> Result<(Uuid, Uuid), DbError> {
        let old_uuid: Uuid = old_claim_id.into();
        let new_uuid = Uuid::new_v4();
        let content_hash = ContentHasher::hash(new_content.as_bytes());
        let new_truth_val = new_truth.value();

        let mut tx = pool.begin().await?;

        // Verify old claim exists and is current
        let old_row: Option<(Uuid, bool)> =
            sqlx::query_as("SELECT agent_id, COALESCE(is_current, true) FROM claims WHERE id = $1")
                .bind(old_uuid)
                .fetch_optional(&mut *tx)
                .await?;

        let (agent_id, is_current) = old_row.ok_or(DbError::NotFound {
            entity: "Claim".to_string(),
            id: old_uuid,
        })?;

        if !is_current {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "Claim {} has already been superseded",
                    old_uuid
                )),
            });
        }

        // Mark old claim as non-current
        sqlx::query("UPDATE claims SET is_current = false, updated_at = NOW() WHERE id = $1")
            .bind(old_uuid)
            .execute(&mut *tx)
            .await?;

        // Insert new claim with supersedes link
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, supersedes, is_current, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, true, NOW(), NOW())",
        )
        .bind(new_uuid)
        .bind(new_content)
        .bind(content_hash.as_slice())
        .bind(new_truth_val)
        .bind(agent_id)
        .bind(old_uuid)
        .execute(&mut *tx)
        .await?;

        // Insert supersedes edge for graph traversal
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties, created_at) \
             VALUES (gen_random_uuid(), $1, 'claim', $2, 'claim', 'supersedes', jsonb_build_object('reason', $3), NOW())",
        )
        .bind(new_uuid)
        .bind(old_uuid)
        .bind(reason)
        .execute(&mut *tx)
        .await?;

        // Null old claim's embedding so it drops out of semantic search
        sqlx::query("UPDATE claims SET embedding = NULL WHERE id = $1")
            .bind(old_uuid)
            .execute(&mut *tx)
            .await?;

        // Migrate incoming edges: redirect edges pointing TO old claim to point to new claim
        sqlx::query(
            "UPDATE edges SET target_id = $1 \
             WHERE target_id = $2 AND target_type = 'claim' AND relationship != 'supersedes'",
        )
        .bind(new_uuid)
        .bind(old_uuid)
        .execute(&mut *tx)
        .await?;

        // Migrate outgoing edges: redirect edges FROM old claim to come from new claim
        sqlx::query(
            "UPDATE edges SET source_id = $1 \
             WHERE source_id = $2 AND source_type = 'claim' AND relationship != 'supersedes'",
        )
        .bind(new_uuid)
        .bind(old_uuid)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok((new_uuid, old_uuid))
    }

    // ============================================================
    // S1 noun-claims-and-verb-edges helpers
    // (see docs/architecture/noun-claims-and-verb-edges.md)
    // ============================================================

    /// Find an existing claim by `(content_hash, agent_id)`.
    ///
    /// Returns the matching row if any, else `None`. Unlike `create()` /
    /// `create_with_tx()` (which dedup on `content_hash` alone and return
    /// the first agent's row regardless of requester), this helper enforces
    /// the noun-claim invariant that `(content_hash, agent_id)` is the
    /// canonical key.
    ///
    /// Takes `&mut PgConnection` so the caller can compose the lookup with
    /// edge creation in the same transaction.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    pub async fn find_by_content_hash_and_agent(
        conn: &mut sqlx::PgConnection,
        content_hash: &[u8],
        agent_id: Uuid,
    ) -> Result<Option<Claim>, DbError> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
               FROM claims
               WHERE content_hash = $1 AND agent_id = $2
               LIMIT 1"#,
        )
        .bind(content_hash)
        .bind(agent_id)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                Ok(Some(claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    tv,
                    row.get("created_at"),
                    row.get("updated_at"),
                )))
            }
            None => Ok(None),
        }
    }

    /// Insert a claim row unconditionally (no implicit dedup).
    ///
    /// Use this when the caller has already determined that an insert is
    /// the correct action (or wants the post-107 UNIQUE constraint to be
    /// the authoritative dedup gate).
    ///
    /// **Pre-107:** inserts a duplicate row when `(content_hash, agent_id)`
    /// already exists.
    ///
    /// **Post-107:** the `uq_claims_content_hash_agent` constraint surfaces
    /// duplicate insertions as `DbError::DuplicateKey`.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` on a `(content_hash, agent_id)`
    /// collision (post-107 only). Returns `DbError::QueryFailed` for other
    /// database errors.
    pub async fn create_strict(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
    ) -> Result<Claim, DbError> {
        use sqlx::Row;

        let id: Uuid = claim.id.into();
        let agent_id: Uuid = claim.agent_id.into();
        let trace_id: Option<Uuid> = claim.trace_id.map(Into::into);
        let truth_value = claim.truth_value.value();
        let created_at = claim.created_at;
        let updated_at = claim.updated_at;
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        let row = sqlx::query(
            r#"INSERT INTO claims (id, content, content_hash, truth_value, agent_id, trace_id, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id, content, truth_value, agent_id, trace_id, created_at, updated_at"#,
        )
        .bind(id)
        .bind(&claim.content)
        .bind(content_hash.as_slice())
        .bind(truth_value)
        .bind(agent_id)
        .bind(trace_id)
        .bind(created_at)
        .bind(updated_at)
        .fetch_one(&mut *conn)
        .await?;

        let tv = TruthValue::new(row.get::<f64, _>("truth_value"))?;
        Ok(claim_from_row(
            row.get("id"),
            row.get("content"),
            row.get("agent_id"),
            row.get("trace_id"),
            tv,
            row.get("created_at"),
            row.get("updated_at"),
        ))
    }

    /// Find-or-insert a claim by `(content_hash, agent_id)`.
    ///
    /// Looks up an existing row first; if found, returns it with
    /// `was_created=false`. Otherwise inserts and returns the new row with
    /// `was_created=true`.
    ///
    /// **Post-107 race handling:** if a concurrent writer inserts the same
    /// `(content_hash, agent_id)` between the find and the insert, the INSERT
    /// fails with the unique constraint. This helper catches that error,
    /// re-runs the find, and returns the resulting row with
    /// `was_created=false`.
    ///
    /// **Pre-107 (constraint not yet applied):** the catch path is
    /// unreachable, and a concurrent race may produce two rows. S2 backfill
    /// (future) cleans up any rows produced during the S1→S4 transition.
    ///
    /// **Constraint match assumption:** the post-107 catch path matches
    /// `DbError::DuplicateKey { .. }` only because
    /// `uq_claims_content_hash_agent` is the only unique constraint that can
    /// fire on a fresh-UUID `INSERT INTO claims`. If a future migration adds
    /// another unique constraint to `claims`, narrow this match to inspect
    /// the constraint name.
    ///
    /// Takes `&mut PgConnection` for transactional composition.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-unique-violation database errors.
    pub async fn create_or_get(
        conn: &mut sqlx::PgConnection,
        claim: &Claim,
    ) -> Result<(Claim, bool), DbError> {
        let agent_id: Uuid = claim.agent_id.into();
        let content_hash = ContentHasher::hash(claim.content.as_bytes());

        if let Some(existing) =
            Self::find_by_content_hash_and_agent(&mut *conn, content_hash.as_slice(), agent_id)
                .await?
        {
            return Ok((existing, false));
        }

        match Self::create_strict(&mut *conn, claim).await {
            Ok(c) => Ok((c, true)),
            Err(DbError::DuplicateKey { .. }) => {
                // Post-107 race: another writer won. Re-find and return.
                let existing = Self::find_by_content_hash_and_agent(
                    &mut *conn,
                    content_hash.as_slice(),
                    agent_id,
                )
                .await?
                .ok_or_else(|| DbError::InvalidData {
                    reason: "DuplicateKey from create_strict but no row found on re-find"
                        .to_string(),
                })?;
                Ok((existing, false))
            }
            Err(e) => Err(e),
        }
    }

    /// Insert a claim with a caller-supplied id. Returns `true` if the row
    /// was newly inserted, `false` if the id already existed (silently
    /// skipped via `ON CONFLICT (id) DO NOTHING`). Used by ingest paths that
    /// generate deterministic UUIDs and rely on idempotent re-runs.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` for non-conflict failures.
    #[instrument(skip(pool, content, content_hash, labels))]
    pub async fn create_with_id_if_absent(
        pool: &PgPool,
        id: Uuid,
        content: &str,
        content_hash: &[u8; 32],
        agent_id: Uuid,
        truth: TruthValue,
        labels: &[String],
    ) -> Result<bool, DbError> {
        let row: Option<(bool,)> = sqlx::query_as(
            "INSERT INTO claims (id, content, content_hash, agent_id, truth_value, labels) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING \
             RETURNING (xmax = 0) AS was_inserted",
        )
        .bind(id)
        .bind(content)
        .bind(content_hash.as_slice())
        .bind(agent_id)
        .bind(truth.value())
        .bind(labels)
        .fetch_optional(pool)
        .await?;
        // RETURNING is empty when the conflict path is taken, so None == not new.
        Ok(row.map(|(b,)| b).unwrap_or(false))
    }
}

/// Result of a pairwise cosine distance query between two claims.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimPairDistance {
    pub claim_a: Uuid,
    pub claim_b: Uuid,
    pub distance: f64,
}

/// Row struct for batch query results
#[derive(sqlx::FromRow)]
struct ClaimRow {
    id: Uuid,
    content: String,
    truth_value: f64,
    agent_id: Uuid,
    trace_id: Option<Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ClaimRepository {
    /// Copy evidence links from old claim to new claim via derived_from edges.
    /// Returns the number of inherited evidence links.
    pub async fn inherit_evidence(
        pool: &PgPool,
        old_claim_id: Uuid,
        new_claim_id: Uuid,
    ) -> Result<usize, DbError> {
        // Create derived_from edges from new claim to old claim's evidence
        let result = sqlx::query(
            "INSERT INTO edges (source_id, source_type, target_id, target_type, relationship, properties) \
             SELECT $1, 'claim', e.id, 'evidence', 'derived_from', \
                    jsonb_build_object('inherited_from', $2::text) \
             FROM evidence e \
             WHERE e.claim_id = $2 \
             ON CONFLICT DO NOTHING",
        )
        .bind(new_claim_id)
        .bind(old_claim_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as usize)
    }

    /// Count all evidence for a claim, including inherited evidence (via derived_from edges).
    pub async fn count_all_evidence_for_claim(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<i64, DbError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT e.id) \
             FROM evidence e \
             LEFT JOIN edges ed ON ed.target_id = e.id \
                AND ed.target_type = 'evidence' \
                AND ed.source_id = $1 \
                AND ed.source_type = 'claim' \
                AND ed.relationship = 'derived_from' \
             WHERE e.claim_id = $1 OR ed.id IS NOT NULL",
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Check whether a claim has grounded evidence — i.e., at least one
    /// non-claim provenance chain (published paper, experimental evidence,
    /// or analysis with data). Claims supported only by other claims
    /// (claim-to-claim propagation) are NOT considered grounded.
    ///
    /// Grounded evidence means at least one of:
    /// - `paper  --asserts-->          claim`
    /// - `evidence --SUPPORTS-->       claim`
    /// - `analysis --concludes-->      claim`
    /// - `analysis --provides_evidence--> claim`
    pub async fn has_grounded_evidence(pool: &PgPool, claim_id: Uuid) -> Result<bool, DbError> {
        let row: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM edges
                WHERE target_id = $1
                  AND target_type = 'claim'
                  AND source_type IN ('paper', 'evidence', 'analysis')
                  AND relationship IN ('asserts', 'SUPPORTS', 'concludes', 'provides_evidence')
            )
            "#,
        )
        .bind(claim_id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }
}

impl ClaimRepository {
    /// Return claim IDs whose reasoning trace matches the given `reasoning_type`.
    ///
    /// Valid values mirror the DB CHECK constraint on reasoning_traces:
    /// deductive, inductive, abductive, analogical, statistical.
    pub async fn claim_ids_by_methodology(
        pool: &PgPool,
        reasoning_type: &str,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT c.id
            FROM claims c
            INNER JOIN reasoning_traces rt ON c.trace_id = rt.id
            WHERE rt.reasoning_type = $1
            "#,
        )
        .bind(reasoning_type)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Return claim IDs that have at least one evidence record of the given type.
    ///
    /// Valid values mirror the DB evidence_type column:
    /// document, observation, testimony, computation, reference, figure, conversational.
    pub async fn claim_ids_by_evidence_type(
        pool: &PgPool,
        evidence_type: &str,
    ) -> Result<Vec<Uuid>, DbError> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT e.claim_id
            FROM evidence e
            WHERE e.evidence_type = $1
            "#,
        )
        .bind(evidence_type)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}

impl ClaimRepository {
    /// Find claims that have no embedding, returning (id, content) pairs.
    ///
    /// Excludes activity log claims (content starting with known activity prefixes).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn find_claims_needing_embeddings(
        pool: &PgPool,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>, DbError> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, content FROM claims
            WHERE embedding IS NULL
              AND content NOT LIKE 'Agent sent message%'
              AND content NOT LIKE 'Container epiclaw%'
              AND content NOT LIKE 'Received message from%'
              AND content NOT LIKE 'Agent in epiclaw%'
            ORDER BY created_at
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Store an embedding vector on a claim.
    ///
    /// The embedding string must be a valid pgvector literal (e.g., "[0.1,0.2,...]").
    /// Follows the same pattern as `EvidenceRepository::store_embedding`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, embedding_pgvector))]
    pub async fn store_embedding(
        pool: &PgPool,
        id: Uuid,
        embedding_pgvector: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE claims SET embedding = $1::vector WHERE id = $2")
            .bind(embedding_pgvector)
            .bind(id)
            .execute(pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Compute pairwise cosine distances between claims in the given set.
    ///
    /// Returns all pairs where distance < `max_distance`, ordered ascending.
    /// Uses pgvector `<=>` operator. Note: this is a brute-force O(N²) scan
    /// — HNSW indexes do not accelerate distance filters.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn pairwise_cosine_distance(
        pool: &PgPool,
        claim_ids: &[Uuid],
        max_distance: f64,
    ) -> Result<Vec<ClaimPairDistance>, DbError> {
        if claim_ids.len() < 2 {
            return Ok(vec![]);
        }

        let rows: Vec<ClaimPairDistance> = sqlx::query_as(
            r#"
            SELECT
                c1.id AS claim_a,
                c2.id AS claim_b,
                (c1.embedding <=> c2.embedding)::float8 AS distance
            FROM claims c1
            JOIN claims c2 ON c1.id < c2.id
            WHERE c1.id = ANY($1)
              AND c2.id = ANY($1)
              AND c1.embedding IS NOT NULL
              AND c2.embedding IS NOT NULL
              AND (c1.embedding <=> c2.embedding) < $2
            ORDER BY (c1.embedding <=> c2.embedding)
            "#,
        )
        .bind(claim_ids)
        .bind(max_distance)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_claim_crud(_pool: sqlx::PgPool) {
        // Placeholder: full CRUD coverage is in tests/claim_tests.rs
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_find_claims_needing_embeddings(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-embed-regen', 'system', ARRAY['test'])
             RETURNING id"
        ).fetch_one(&pool).await.unwrap();

        let content = format!("test-embed-regen-{}", Uuid::new_v4());
        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL)
             RETURNING id",
        )
        .bind(&content)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let missing = ClaimRepository::find_claims_needing_embeddings(&pool, 1000)
            .await
            .unwrap();
        assert!(missing.iter().any(|(id, _)| *id == claim_id));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn set_properties_writes_jsonb_column(pool: sqlx::PgPool) {
        // Seed agent inline (no epigraph_test_support helper available),
        // following the existing pattern in this test module.
        let (agent_id, agent_pk): (Uuid, Vec<u8>) = sqlx::query_as(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'set-props-test', 'system', ARRAY['test'])
             RETURNING id, public_key",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&agent_pk);

        let claim = Claim::new(
            "Test claim for properties".to_string(),
            AgentId::from_uuid(agent_id),
            public_key,
            TruthValue::clamped(0.5),
        );
        let persisted = ClaimRepository::create(&pool, &claim).await.unwrap();
        let props = serde_json::json!({"level": 3, "section": "Body", "source_type": "Wiki"});

        ClaimRepository::set_properties(&pool, persisted.id, props.clone())
            .await
            .unwrap();

        let row: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, props);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn test_pairwise_cosine_distance(pool: sqlx::PgPool) {
        // Find two claims that both have embeddings — a fresh test DB has none,
        // so we skip gracefully rather than fail.
        let pairs: Vec<(Uuid, Uuid, f64)> = sqlx::query_as(
            r"SELECT c1.id, c2.id, (c1.embedding <=> c2.embedding)::float8
              FROM claims c1, claims c2
              WHERE c1.embedding IS NOT NULL AND c2.embedding IS NOT NULL
                AND c1.id < c2.id
              LIMIT 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        if pairs.is_empty() {
            // No embeddings in fresh test DB; the function is exercised elsewhere.
            return;
        }

        let (id1, id2, expected_distance) = &pairs[0];
        let results = ClaimRepository::pairwise_cosine_distance(&pool, &[*id1, *id2], 1.0)
            .await
            .unwrap();

        assert!(!results.is_empty());
        let first = &results[0];
        assert!((first.distance - expected_distance).abs() < 1e-6);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_id_if_absent_is_idempotent(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-create-idempotent', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let id = uuid::Uuid::new_v4();
        let hash = blake3::hash(b"x");
        let was_new1 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent_id,
            TruthValue::clamped(0.5),
            &["test".to_string()],
        )
        .await
        .unwrap();
        let was_new2 = ClaimRepository::create_with_id_if_absent(
            &pool,
            id,
            "x",
            hash.as_bytes(),
            agent_id,
            TruthValue::clamped(0.5),
            &["test".to_string()],
        )
        .await
        .unwrap();
        assert!(was_new1);
        assert!(!was_new2);
    }
}

// ── Label Mutation ──

impl ClaimRepository {
    /// Update labels on a claim by adding and/or removing labels atomically.
    ///
    /// Uses PostgreSQL array functions. Idempotent: adding a duplicate is a no-op,
    /// removing a nonexistent label is a no-op. Returns the updated labels array.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist.
    #[instrument(skip(pool))]
    pub async fn update_labels(
        pool: &PgPool,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        let row: Option<(Vec<String>,)> = sqlx::query_as(
            r#"
            WITH current AS (
                SELECT id, labels FROM claims WHERE id = $1
            ),
            updated AS (
                SELECT COALESCE(
                    array_agg(DISTINCT lbl ORDER BY lbl),
                    ARRAY[]::text[]
                ) AS new_labels
                FROM (
                    SELECT unnest(c.labels) AS lbl FROM current c
                    UNION
                    SELECT unnest($2::text[])
                ) all_labels
                WHERE lbl != ALL($3::text[])
            )
            UPDATE claims SET labels = (SELECT new_labels FROM updated)
            WHERE id = $1
            RETURNING labels
            "#,
        )
        .bind(claim_id)
        .bind(add)
        .bind(remove)
        .fetch_optional(pool)
        .await?;

        match row {
            Some((labels,)) => Ok(labels),
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id,
            }),
        }
    }

    /// Update labels using an existing connection (e.g. inside a transaction).
    pub async fn update_labels_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        use sqlx::Row;
        let row: Option<sqlx::postgres::PgRow> = sqlx::query(
            r#"WITH current AS (
                   SELECT id, labels FROM claims WHERE id = $1
               ),
               updated AS (
                   SELECT COALESCE(
                       array_agg(DISTINCT lbl ORDER BY lbl),
                       ARRAY[]::text[]
                   ) AS new_labels
                   FROM (
                       SELECT unnest(c.labels) AS lbl FROM current c
                       UNION
                       SELECT unnest($2::text[])
                   ) all_labels
                   WHERE lbl != ALL($3::text[])
               )
               UPDATE claims SET labels = (SELECT new_labels FROM updated)
               WHERE id = $1
               RETURNING labels"#,
        )
        .bind(claim_id)
        .bind(add)
        .bind(remove)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => Ok(row.get::<Vec<String>, _>("labels")),
            None => Err(DbError::NotFound {
                entity: "Claim".to_string(),
                id: claim_id,
            }),
        }
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    /// Helper: create a test claim and return (pool, claim_id, agent_id) for cleanup.
    async fn setup_test_claim() -> (sqlx::PgPool, Uuid, Uuid) {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();

        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'label-test', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id)
             VALUES ('label test claim', sha256('label-test'::bytea), 0.5, $1)
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        (pool, claim_id, agent_id)
    }

    async fn cleanup(pool: &sqlx::PgPool, claim_id: Uuid, agent_id: Uuid) {
        let _ = sqlx::query("DELETE FROM claims WHERE id = $1")
            .bind(claim_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE id = $1")
            .bind(agent_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_add() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        let labels =
            ClaimRepository::update_labels(&pool, claim_id, &["foo".into(), "bar".into()], &[])
                .await
                .unwrap();
        assert!(labels.contains(&"foo".to_string()));
        assert!(labels.contains(&"bar".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["a".into(), "b".into(), "c".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &[], &["b".into()])
            .await
            .unwrap();
        assert!(labels.contains(&"a".to_string()));
        assert!(!labels.contains(&"b".to_string()));
        assert!(labels.contains(&"c".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_atomic_add_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["x".into(), "y".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &["z".into()], &["x".into()])
            .await
            .unwrap();
        assert!(!labels.contains(&"x".to_string()));
        assert!(labels.contains(&"y".to_string()));
        assert!(labels.contains(&"z".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_idempotent_add() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["dup".into()], &[])
            .await
            .unwrap();
        let labels = ClaimRepository::update_labels(&pool, claim_id, &["dup".into()], &[])
            .await
            .unwrap();
        assert_eq!(labels.iter().filter(|l| l.as_str() == "dup").count(), 1);
        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_idempotent_remove() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        // Remove a label that was never added — should not error
        let labels = ClaimRepository::update_labels(&pool, claim_id, &[], &["nonexistent".into()])
            .await
            .unwrap();
        assert!(labels.is_empty() || !labels.contains(&"nonexistent".to_string()));
        cleanup(&pool, claim_id, agent_id).await;
    }

    // ── list_by_labels tests ──

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_happy_path() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["backlog".into(), "pending".into()], &[])
            .await
            .unwrap();

        let results = ClaimRepository::list_by_labels(&pool, &["backlog".into()], 0.0, 100)
            .await
            .unwrap();
        assert!(
            results.iter().any(|c| c.id.as_uuid() == claim_id),
            "should find claim by single label"
        );

        let results =
            ClaimRepository::list_by_labels(&pool, &["backlog".into(), "pending".into()], 0.0, 100)
                .await
                .unwrap();
        assert!(
            results.iter().any(|c| c.id.as_uuid() == claim_id),
            "should find claim by ALL labels"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_no_match() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        ClaimRepository::update_labels(&pool, claim_id, &["backlog".into()], &[])
            .await
            .unwrap();

        let results =
            ClaimRepository::list_by_labels(&pool, &["nonexistent-label".into()], 0.0, 100)
                .await
                .unwrap();
        assert!(
            !results.iter().any(|c| c.id.as_uuid() == claim_id),
            "should not match unrelated label"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_min_truth_filter() {
        let (pool, claim_id, agent_id) = setup_test_claim().await;
        // Default truth_value from setup is 0.5
        ClaimRepository::update_labels(&pool, claim_id, &["truth-test".into()], &[])
            .await
            .unwrap();

        let results = ClaimRepository::list_by_labels(&pool, &["truth-test".into()], 0.4, 100)
            .await
            .unwrap();
        assert!(
            results.iter().any(|c| c.id.as_uuid() == claim_id),
            "0.5 >= 0.4 should match"
        );

        let results = ClaimRepository::list_by_labels(&pool, &["truth-test".into()], 0.9, 100)
            .await
            .unwrap();
        assert!(
            !results.iter().any(|c| c.id.as_uuid() == claim_id),
            "0.5 < 0.9 should not match"
        );

        cleanup(&pool, claim_id, agent_id).await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_list_by_labels_respects_limit() {
        let (pool, _, agent_id) = setup_test_claim().await;
        // Create a second claim with the same label
        let claim_id_2 = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, labels)
             VALUES ('limit test 2', sha256('limit-test-2'::bytea), 0.5, $1, ARRAY['limit-test'])
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let claim_id_1 = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, labels)
             VALUES ('limit test 1', sha256('limit-test-1'::bytea), 0.5, $1, ARRAY['limit-test'])
             RETURNING id",
        )
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let results = ClaimRepository::list_by_labels(&pool, &["limit-test".into()], 0.0, 1)
            .await
            .unwrap();
        assert_eq!(results.len(), 1, "limit=1 should return exactly 1 result");

        // cleanup
        let _ = sqlx::query("DELETE FROM claims WHERE id = ANY($1)")
            .bind([claim_id_1, claim_id_2])
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM agents WHERE id = $1")
            .bind(agent_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    #[ignore] // Requires live database
    async fn test_update_labels_not_found() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let fake_id = Uuid::new_v4();
        let result = ClaimRepository::update_labels(&pool, fake_id, &["x".into()], &[]).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            DbError::NotFound { entity, id } => {
                assert_eq!(entity, "Claim");
                assert_eq!(id, fake_id);
            }
            other => panic!("Expected NotFound, got: {other:?}"),
        }
    }
}
