//! Evidence repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceId, EvidenceType};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Evidence operations
pub struct EvidenceRepository;

/// Result row for [`EvidenceRepository::provided_for_claim_as_of`].
///
/// `evidence_type` and `created_at` are projected even though today's only
/// caller replays `properties` alone: a row type that silently drops columns
/// invites the next caller to add an inline statement beside this one rather
/// than extending it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EvidenceAtTimeRow {
    pub id: Uuid,
    pub evidence_type: String,
    pub properties: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result row for [`EvidenceRepository::detail_by_id`].
///
/// The flattened projection `GET /api/v1/evidence/:id` returns. It lived as an
/// inline `sqlx::query_as` in `epigraph-api/src/routes/edges.rs::get_evidence`
/// until PR-14; that statement had no `Viewer` and its only control was a
/// post-fetch `check_content_access` pass on the *linked claim*, which PR-14
/// deletes. Moving it here puts the predicate on the row itself.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EvidenceDetailRow {
    pub id: Uuid,
    pub raw_content: Option<String>,
    pub content_hash: Vec<u8>,
    pub source_url: Option<String>,
    pub properties: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result row for [`EvidenceRepository::by_relationship_for_claim`].
///
/// Was an inline `sqlx::query_as` in
/// `epigraph-api/src/routes/edges.rs::evidence_by_relationship`, projecting
/// `ev.raw_content` — a full second copy of the claim body — with no `Viewer`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EvidenceEdgeRow {
    pub edge_id: Uuid,
    pub evidence_id: Uuid,
    pub raw_content: Option<String>,
    pub strength: Option<f64>,
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
    #[instrument(skip(pool, viewer))]
    pub async fn get_by_id(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        id: EvidenceId,
    ) -> Result<Option<Evidence>, DbError> {
        let uuid: Uuid = id.into();

        // MACRO SITE — static three-bind spelling. `evidence` carries its own
        // tenancy columns (migration 062), so the predicate is on the row.
        let row = sqlx::query!(
            r#"
            SELECT id, content_hash, evidence_type, raw_content, claim_id,
                   signature, signer_id, properties, created_at
            FROM evidence
            WHERE id = $1
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            "#,
            uuid,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
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
    #[instrument(skip(pool, viewer))]
    pub async fn get_by_claim(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: ClaimId,
    ) -> Result<Vec<Evidence>, DbError> {
        let uuid: Uuid = claim_id.into();

        // MACRO SITE — static three-bind spelling. The change inventory
        // expected a joined `claims` alias here; the query reads `evidence`
        // alone, and the claim-side check belongs to the caller that already
        // resolved the claim id.
        let rows = sqlx::query!(
            r#"
            SELECT id, content_hash, evidence_type, raw_content, claim_id,
                   signature, signer_id, properties, created_at
            FROM evidence
            WHERE claim_id = $1
              AND ($2::bool OR visibility = 'public' OR owner_group_id = ANY($3::uuid[]))
            ORDER BY created_at DESC
            "#,
            uuid,
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
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

    /// Evidence linked to a claim by a `provides_evidence`-shaped edge, as of a
    /// point in time — viewer-filtered on BOTH `evidence` and `edges`.
    ///
    /// # Why this exists
    ///
    /// `routes/computation.rs::belief_at_time` held a `ViewerExtractor`, spent
    /// it on an existence check (`ClaimRepository::get_by_id`), and then read
    /// the evidence it actually replays with an inline unfiltered statement.
    /// Both `evidence` and `edges` are `tier_a` in migration 062 and both carry
    /// `visibility`/`owner_group_id`, so both were filterable and neither was
    /// filtered. The handler returns `evidence_count` plus a truth value
    /// replayed from `properties->confidence`, i.e. an inference oracle over
    /// evidence rows the viewer may not own, gated only by the visibility of the
    /// parent claim.
    ///
    /// It was also invisible to `viewer_route_table_lint.rs` as that lint was
    /// originally written: `reads_claim_content` required `from claims` /
    /// `join claims`, and this statement names neither. PR-07's follow-up
    /// widened the predicate to the `tier_a` projections for exactly this
    /// reason.
    ///
    /// The `edges` marker sits in the JOIN's ON clause, matching
    /// [`crate::ClaimRepository::count_all_evidence_for_claim`]. It is the
    /// `/* {EDGE_VISIBILITY:ed} */` spelling (PR-13) while `e` — `evidence`, not
    /// `edges` — keeps the plain one. This statement is the reason the edge
    /// fragment needs its own marker rather than an alias-keyed dispatch: `e`
    /// names `evidence` here and `edges` in `repos/structural.rs`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn provided_for_claim_as_of(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        as_of: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EvidenceAtTimeRow>, DbError> {
        let sql = viewer.splice(
            "SELECT e.id, e.evidence_type, e.properties, e.created_at \
             FROM evidence e \
             JOIN edges ed ON ed.source_id = e.id \
                AND ed.target_type = 'claim' \
                AND ed.target_id = $1 \
                /* {EDGE_VISIBILITY:ed} */ \
             WHERE e.created_at <= $2 \
               /* {VISIBILITY:e} */ \
             ORDER BY e.created_at ASC",
            3,
        );
        let mut q = sqlx::query_as::<_, EvidenceAtTimeRow>(&sql)
            .bind(claim_id)
            .bind(as_of);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Fetch the flattened detail projection for a single evidence row.
    ///
    /// Returns `None` both when the row does not exist and when it exists but
    /// this `Viewer` may not read it — the two are deliberately the same value,
    /// so `GET /api/v1/evidence/:id` cannot be used to confirm the existence of
    /// evidence attached to a claim the caller cannot see (§8.5).
    ///
    /// `evidence` carries its own `visibility`/`owner_group_id`, kept in step
    /// with its parent claim by `epigraph_propagate_tenancy` (migration 070/071
    /// lists `evidence` among the claim_id-derived tables), so the predicate is
    /// on the row and no join to `claims` is needed.
    ///
    /// # The SUBJECT of the gate moved, not just its location
    ///
    /// Said plainly because "moved into the repo layer" would otherwise imply a
    /// pure relocation. The deleted control was
    /// `check_content_access(pool, claim_edge.source_id, requester)`, where
    /// `claim_edge` came from `SELECT source_id FROM edges WHERE target_id = $1
    /// AND target_type = 'evidence' AND source_type = 'claim' LIMIT 1` — the
    /// claim reached through an EDGE. The new control is the row's own tenancy,
    /// which 070 derives from `evidence.claim_id`. Those are the same claim at
    /// every production write site (`routes/crud.rs`, `mcp/tools/claims.rs::submit_claim`
    /// both create the `DERIVED_FROM` edge from the owning claim), but nothing
    /// in the schema requires it: `POST /api/v1/claims/:id/relate` and MCP
    /// `link_epistemic` let any writer add a claim→evidence edge from an
    /// arbitrary claim.
    ///
    /// The move is a TIGHTENING rather than a swap, and the old form's
    /// unordered `LIMIT 1` is why. With several claims linked to one evidence
    /// row, the old gate picked an arbitrary one — so evidence belonging to a
    /// private claim could be waved through on a public sibling, nondeterministically.
    /// The row's own `claim_id`-derived tenancy has no such choice to make. In
    /// the reverse case (evidence private under a public claim) the old form
    /// disclosed and this one does not.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn detail_by_id(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        id: Uuid,
    ) -> Result<Option<EvidenceDetailRow>, DbError> {
        let sql = viewer.splice(
            "SELECT e.id, e.raw_content, e.content_hash, e.source_url, \
                    e.properties, e.created_at \
             FROM evidence e \
             WHERE e.id = $1 \
               /* {VISIBILITY:e} */",
            2,
        );
        let mut q = sqlx::query_as::<_, EvidenceDetailRow>(&sql).bind(id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_optional(pool).await?)
    }

    /// Evidence linked to `claim_id` by an edge with the given `relationship`.
    ///
    /// Backs `GET /api/v1/claims/:id/supporting-evidence` and
    /// `…/contradicting-evidence`. Both the edge and the evidence row are
    /// filtered: an edge the viewer cannot see must not surface its endpoint,
    /// and evidence the viewer cannot see must not surface its `raw_content`
    /// even if the edge is visible. `ed` takes the `EDGE_VISIBILITY` spelling
    /// and `ev` the plain one; both resolve to the same `$V`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool, viewer))]
    pub async fn by_relationship_for_claim(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        relationship: &str,
    ) -> Result<Vec<EvidenceEdgeRow>, DbError> {
        let sql = viewer.splice(
            "SELECT ed.id as edge_id, ev.id as evidence_id, \
                    ev.raw_content, (ed.properties->>'strength')::float8 as strength, \
                    ev.created_at \
             FROM edges ed \
             JOIN evidence ev ON ev.id = ed.source_id \
                /* {VISIBILITY:ev} */ \
             WHERE ed.target_id = $1 \
               AND ed.target_type = 'claim' \
               AND ed.source_type = 'evidence' \
               AND ed.relationship = $2 \
               /* {EDGE_VISIBILITY:ed} */ \
             ORDER BY ev.created_at DESC \
             LIMIT 100",
            3,
        );
        let mut q = sqlx::query_as::<_, EvidenceEdgeRow>(&sql)
            .bind(claim_id)
            .bind(relationship);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(pool).await?)
    }

    /// Delete evidence by ID
    ///
    /// # Returns
    /// Returns `true` if the evidence was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    /// Takes a viewer it does not yet use: WRITE path, PR-16 owns the
    /// write-side predicate. The parameter exists so the hook is already at
    /// every call site.
    #[instrument(skip(pool, _viewer))]
    pub async fn delete(
        pool: &PgPool,
        _viewer: &crate::visibility::Viewer,
        id: EvidenceId,
    ) -> Result<bool, DbError> {
        // VISIBILITY-EXEMPT: PR-16 owns the write-side predicate.
        // Recognised by `crates/epigraph-db/tests/visibility_lint.rs`, which
        // otherwise fails any fn taking a `&Viewer` and running SQL without
        // splicing or binding it. The exemption count is itself a ratchet
        // there, so adding a third one is a visible diff.
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
    #[instrument(skip(pool, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<EvidenceSearchResult>, DbError> {
        let sql = viewer.splice(
            r#"
            SELECT
                e.id,
                e.claim_id,
                e.raw_content,
                e.evidence_type,
                1 - (e.embedding <=> $1::vector) AS similarity
            FROM evidence e
            WHERE e.embedding IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM claims c
                  WHERE c.id = e.claim_id
                    AND COALESCE(c.is_current, true) = true
                    /* {VISIBILITY:c} */
              )
              /* {VISIBILITY:e} */
            ORDER BY e.embedding <=> $1::vector
            LIMIT $2
            "#,
            3,
        );
        let mut q = sqlx::query_as::<_, EvidenceSearchResult>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let rows = q.fetch_all(pool).await?;

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
    /// Carried so `GET /api/v1/search/evidence` can render its result rows from
    /// this (viewer-filtered) repo read instead of the unfiltered inline query
    /// it used before PR-07.
    pub evidence_type: String,
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
