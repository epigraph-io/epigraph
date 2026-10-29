//! Evidence repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, ClaimId, Evidence, EvidenceId, EvidenceType};
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Evidence operations
pub struct EvidenceRepository;

/// What names an evidence row's source, for the canonical item key
/// ([`EvidenceRepository::source_identity_by_id`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSourceIdentity {
    /// `properties->>'doi'`.
    pub doi: Option<String>,
    /// `source_url`.
    pub source_url: Option<String>,
}

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

/// What [`EvidenceRepository::record_derivation_conn`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationEvidence {
    /// A new derivation evidence row, with its id.
    Recorded(Uuid),
    /// The parent's text was already evidence on the claim; nothing written.
    AlreadyPresent,
    /// The claim names itself as its parent; nothing written.
    SelfReference,
    /// The parent is absent, retired, non-public, or invisible to the viewer;
    /// nothing written. The caller must not distinguish these.
    ParentUnavailable,
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
    /// Create new evidence in the database.
    ///
    /// # Why the connection is generic
    ///
    /// Same reason as
    /// [`ReasoningTraceRepository::create`](crate::ReasoningTraceRepository::create),
    /// and see that doc for the full argument: an `evidence` INSERT belongs in
    /// the SAME transaction as the claim it derives from, and a `&PgPool`
    /// parameter made that impossible to express. `&PgPool` and
    /// `&mut PgConnection` both satisfy [`sqlx::Acquire`], so existing
    /// pool-taking callers are unaffected. `Acquire` rather than an executor,
    /// because the write and its de-duplication are one unit: a transaction
    /// on a pool, a savepoint inside the caller's transaction.
    ///
    /// # De-duplicated per owner, in the application
    ///
    /// Evidence has no unique key over its body (migration 171). An identical
    /// body on the same claim, under the owner and visibility this row gets, is
    /// refused as [`DbError::DuplicateKey`] and writes nothing; see
    /// [`Self::same_tenancy_duplicate`]. A body another owner holds is never
    /// consulted, so a write cannot learn whether one exists.
    ///
    /// `evidence` differs from `reasoning_traces` in one respect worth naming so
    /// nobody concludes this change was unnecessary: a deployment may carry an
    /// orphan PERMISSIVE `evidence_privacy` policy (present in no migration of
    /// the 077 series) whose unconditional `USING` is reused as its `WITH CHECK`,
    /// which is the only reason an UNSTAMPED evidence INSERT succeeds there. That
    /// is an accident of a deployment, not a property of the schema, and it is
    /// what made the 42501 look like a `reasoning_traces`-only defect.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` for a same-owner duplicate (nothing is
    /// written), `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, evidence))]
    pub async fn create<'c, A: sqlx::Acquire<'c, Database = sqlx::Postgres>>(
        conn: A,
        evidence: &Evidence,
    ) -> Result<Evidence, DbError> {
        Self::create_with_source_url(conn, evidence, Self::source_url_of(&evidence.evidence_type))
            .await
    }

    /// The URL an evidence type carries that belongs in `evidence.source_url`:
    /// a `Document`'s `source_url`, and nothing else.
    ///
    /// A `Testimony`'s `source` is free text (a person's name, or the MCP
    /// default `"unknown"`), and `Literature`/`Figure` carry a DOI rather than
    /// a URL, so none of those is a column value.
    #[must_use]
    pub fn source_url_of(evidence_type: &EvidenceType) -> Option<&str> {
        match evidence_type {
            EvidenceType::Document { source_url, .. } => source_url.as_deref(),
            _ => None,
        }
    }

    /// [`Self::create`] with an explicit `evidence.source_url`.
    ///
    /// For callers that hold a URL the evidence type has no slot for: MCP
    /// `empirical` evidence is stored as `EvidenceType::Observation`, so its
    /// caller-supplied URL can only live in the column (backlog 43ab8c73).
    /// MCP `submit_claim` and `update_with_evidence` pass the caller's URL here
    /// whatever the evidence type: it is also the source identity the combine
    /// step uses to recognise a re-observation of the SAME source
    /// (`epigraph_engine::source_dependence`, backlog 4c42c0bf).
    ///
    /// # Errors
    /// As [`Self::create`].
    #[instrument(skip(conn, evidence))]
    pub async fn create_with_source_url<'c, A: sqlx::Acquire<'c, Database = sqlx::Postgres>>(
        conn: A,
        evidence: &Evidence,
        source_url: Option<&str>,
    ) -> Result<Evidence, DbError> {
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

        let mut tx = conn.begin().await?;
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
            source_url,
            raw_content,
            claim_id,
            signature,
            signer_id,
            evidence_type_json,
            created_at
        )
        .fetch_one(&mut *tx)
        .await?;

        if Self::same_tenancy_duplicate(&mut tx, row.id, &row.content_hash, row.claim_id).await? {
            tx.rollback().await?;
            return Err(Self::duplicate());
        }
        tx.commit().await?;

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

    /// Record that `claim_id` was derived from `parent_id`'s text: one
    /// `document` evidence row whose `raw_content` is the parent's content and
    /// whose `properties` carry `derived_from_claim` and `method`.
    ///
    /// This is derivation PROVENANCE, not support: no mass function is written
    /// and the claim's truth value is not touched (backlog 3590a2d8, U041
    /// option A). A decomposition atom's only warrant at birth is "the parent
    /// states it", and when the parent is itself evidence-free any belief
    /// given to the atom would be laundered from it.
    ///
    /// # The parent is read through `viewer`, and must be PUBLIC
    ///
    /// The row inherits the claim's tenancy (migration 070 arm (c)), and the
    /// only claims this is written for are public (`if_not_exists` is
    /// public-tier only). Copying a group-private parent's text into a public
    /// row would republish it, so a parent that is not current, not public, not
    /// visible to `viewer`, or absent all answer
    /// [`DerivationEvidence::ParentUnavailable`] — one answer, so the caller
    /// cannot use it as an existence oracle.
    ///
    /// # Idempotent on `(content_hash, claim_id)` within the row's owner
    ///
    /// `content_hash` is BLAKE3 of the parent text, and the same-tenancy
    /// de-duplication every evidence write takes ([`Self::same_tenancy_duplicate`])
    /// undoes the INSERT when the same text is already evidence on the claim
    /// under the owner and visibility this row gets — a re-applied plan line or
    /// a concurrent duplicate request. There is no unique key to name in an
    /// `ON CONFLICT` (migration 171; the long-lived database never had one, so
    /// the `ON CONFLICT (content_hash, claim_id)` this used to carry failed
    /// 42P10 there). A second parent with DIFFERENT text gets its own row, so an
    /// atom stated by two parents names both.
    ///
    /// The key is the parent's TEXT, not its id, and that has two known
    /// consequences: two parents with byte-identical text (legacy imports
    /// labelled `deduped` can be) share ONE row, naming whichever parent came
    /// first; and an existing evidence row on the claim, in the same tenancy,
    /// whose raw text equals the parent's suppresses the derivation row
    /// ([`DerivationEvidence::AlreadyPresent`]).
    /// Keying on `properties->>'derived_from_claim'` instead would break the
    /// `content_hash` = BLAKE3(`raw_content`) convention every evidence row
    /// follows. `properties` is the serialized
    /// [`EvidenceType::Document`] plus the two derivation keys, so every reader
    /// that parses `properties` as an [`EvidenceType`] still does.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if a statement fails.
    #[instrument(skip(conn, viewer))]
    pub async fn record_derivation_conn(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        claim_id: Uuid,
        parent_id: Uuid,
        method: &str,
    ) -> Result<DerivationEvidence, DbError> {
        if claim_id == parent_id {
            return Ok(DerivationEvidence::SelfReference);
        }
        let sql = viewer.splice(
            r#"
            SELECT c.content
            FROM claims c
            WHERE c.id = $1
              AND COALESCE(c.is_current, true) = true
              AND c.visibility = 'public'
              /* {VISIBILITY:c} */
            "#,
            2,
        );
        let mut q = sqlx::query_scalar::<_, String>(&sql).bind(parent_id);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        let Some(parent_content) = q.fetch_optional(&mut *conn).await? else {
            return Ok(DerivationEvidence::ParentUnavailable);
        };

        let content_hash = epigraph_crypto::ContentHasher::hash(parent_content.as_bytes());
        let mut properties = serde_json::to_value(EvidenceType::Document {
            source_url: None,
            mime_type: "text/plain".to_string(),
            checksum: None,
        })?;
        if let Some(obj) = properties.as_object_mut() {
            obj.insert(
                "derived_from_claim".to_string(),
                serde_json::Value::String(parent_id.to_string()),
            );
            obj.insert(
                "method".to_string(),
                serde_json::Value::String(method.to_string()),
            );
        }

        let mut tx = sqlx::Acquire::begin(&mut *conn).await?;
        let inserted = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO evidence (content_hash, evidence_type, raw_content, claim_id, properties)
            VALUES ($1, 'document', $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(content_hash.as_slice())
        .bind(&parent_content)
        .bind(claim_id)
        .bind(&properties)
        .fetch_one(&mut *tx)
        .await;
        let id = match inserted.map_err(DbError::from) {
            Ok(id) => id,
            // A database below migration 171 still carries 001's
            // `(content_hash, claim_id)` key, and this binary deploys first: the
            // same text already on the claim is the duplicate it always was.
            // The savepoint keeps the caller's transaction usable.
            Err(DbError::DuplicateKey { .. }) => {
                tx.rollback().await?;
                return Ok(DerivationEvidence::AlreadyPresent);
            }
            Err(e) => return Err(e),
        };

        if Self::same_tenancy_duplicate(&mut tx, id, content_hash.as_slice(), claim_id).await? {
            tx.rollback().await?;
            return Ok(DerivationEvidence::AlreadyPresent);
        }
        tx.commit().await?;
        Ok(DerivationEvidence::Recorded(id))
    }

    /// Whether the evidence row `id`, just written in `conn`'s transaction,
    /// duplicates another row: the same `content_hash` on the same claim, with
    /// the same owner AND visibility.
    ///
    /// The de-duplication contract of every evidence write (backlog 12b68201,
    /// operator ruling R-77). Migration 001's `evidence_content_hash_claim_unique
    /// UNIQUE (content_hash, claim_id)` spanned owners, so a write that
    /// collided with a row another group holds, unreadable to the writer, was
    /// refused, and the refusal confirmed that row and its body. The long-lived
    /// database never had the key and holds same-owner duplicates, so
    /// migration 171 drops it everywhere and the contract lives here, as 150
    /// moved the claim dedup into `ClaimRepository::lock_content_hash_agent`.
    ///
    /// # Order: write, read the tenancy, lock, look
    ///
    /// The row's owner and visibility are whatever the tenancy triggers gave
    /// it (inherited from the claim, or the writer's, migration 114), so they
    /// are read back AFTER the write statement (070's AFTER INSERT statement
    /// trigger may re-stamp what `RETURNING` reported). Then a
    /// transaction-scoped advisory lock on `(content_hash, claim_id, owner)`,
    /// then the lookup, as separate statements: under READ COMMITTED the
    /// lookup's snapshot is taken after the lock is held, so a concurrent first
    /// write of the same body either committed before (and is found) or waits
    /// for this transaction to end. The caller undoes its write (a savepoint)
    /// when this answers `true`.
    ///
    /// # Why a duplicate never discloses anything
    ///
    /// Only a row in the SAME tenancy as the one just written counts. The
    /// caller was allowed to write a row with that owner and visibility, so a
    /// public match is readable by anyone and a group match is in a group the
    /// caller can write. A body another owner holds, or the same owner holds
    /// under a narrower visibility (a pinned row), is never consulted: such a
    /// write lands exactly as a fresh body does. Existing same-tenancy
    /// duplicates (the long-lived database holds them) stay valid; a third copy
    /// is simply refused.
    ///
    /// A row the session cannot read back (no such row, or RLS) is not
    /// de-duplicated: there is no tenancy to key the lock on.
    async fn same_tenancy_duplicate(
        conn: &mut sqlx::PgConnection,
        id: Uuid,
        content_hash: &[u8],
        claim_id: Uuid,
    ) -> Result<bool, DbError> {
        let tenancy: Option<(Uuid, String)> =
            sqlx::query_as("SELECT owner_group_id, visibility::text FROM evidence WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?;
        let Some((owner, visibility)) = tenancy else {
            return Ok(false);
        };
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtext('epigraph.evidence_dedup'), \
                    hashtext(encode($1, 'hex') || $2::text || $3::text))",
        )
        .bind(content_hash)
        .bind(claim_id)
        .bind(owner)
        .execute(&mut *conn)
        .await?;
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM evidence \
                             WHERE content_hash = $1 AND claim_id = $2 \
                               AND owner_group_id = $3 AND visibility::text = $4 \
                               AND id <> $5)",
        )
        .bind(content_hash)
        .bind(claim_id)
        .bind(owner)
        .bind(&visibility)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?)
    }

    /// The answer a same-tenancy duplicate gets: the `DbError` a unique
    /// violation maps to, so callers see what they saw under 001's key.
    fn duplicate() -> DbError {
        DbError::DuplicateKey {
            entity: "entity".to_string(),
        }
    }

    /// Get evidence by ID
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        .fetch_optional(executor)
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
    #[instrument(skip(executor, viewer))]
    pub async fn get_by_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        .fetch_all(executor)
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
    #[instrument(skip(executor, viewer))]
    pub async fn provided_for_claim_as_of<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        Ok(q.fetch_all(executor).await?)
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
    #[instrument(skip(executor, viewer))]
    pub async fn detail_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        Ok(q.fetch_optional(executor).await?)
    }

    /// The link of each evidence row attached to each of `claim_ids`, keyed by
    /// claim, in evidence `created_at` order, deduplicated per claim. A claim
    /// with no linked evidence has no entry.
    ///
    /// Backs `get_claim`'s `source_urls` and `query_claims_by_label`'s opt-in
    /// `include_source_urls` (backlog 43ab8c73): one batched query rather than
    /// a `get_provenance` per claim.
    ///
    /// The `evidence.source_url` column wins when it holds an `http(s)` URL.
    /// It may hold free text instead: MCP `testimonial` evidence stores the
    /// caller's `source_url` parameter there, and that parameter is the
    /// witness's name as often as a link. Rows written before that column
    /// was populated (it was always NULL) fall back to `properties`: a
    /// Document's `source_url`, a Testimony's `source` only when it is an
    /// `http(s)` URL (otherwise it is free text such as `"unknown"`), and a
    /// Literature/Figure DOI as `https://doi.org/<doi>` only when it is a DOI
    /// (`10.` prefix; ingestion spells any other identifier `doi:<id>`, which
    /// has no doi.org link).
    ///
    /// Filtered PER EVIDENCE ROW (`{VISIBILITY:e}`), not per claim: a hidden
    /// evidence row may hang off a public claim (operator hide, foreign
    /// attach), and its URL must not reach a viewer outside its group.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, claim_ids))]
    pub async fn source_urls_by_claim_ids<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<String>>, DbError> {
        let mut out: std::collections::HashMap<Uuid, Vec<String>> =
            std::collections::HashMap::new();
        if claim_ids.is_empty() {
            return Ok(out);
        }
        let sql = viewer.splice(
            "SELECT e.claim_id, \
                    COALESCE( \
                      CASE WHEN e.source_url ~* '^https?://' THEN e.source_url END, \
                      CASE e.properties->>'type' \
                        WHEN 'document' THEN e.properties->>'source_url' \
                        WHEN 'testimony' THEN \
                          CASE WHEN e.properties->>'source' ~* '^https?://' \
                               THEN e.properties->>'source' END \
                        WHEN 'literature' THEN \
                          CASE WHEN e.properties->>'doi' ~ '^10\\.' \
                               THEN 'https://doi.org/' || (e.properties->>'doi') END \
                        WHEN 'figure' THEN \
                          CASE WHEN e.properties->>'doi' ~ '^10\\.' \
                               THEN 'https://doi.org/' || (e.properties->>'doi') END \
                      END) AS url \
             FROM evidence e \
             WHERE e.claim_id = ANY($1) \
               /* {VISIBILITY:e} */ \
             ORDER BY e.claim_id, e.created_at, e.id",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<String>)>(&sql).bind(claim_ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        for (claim_id, url) in q.fetch_all(executor).await? {
            let Some(url) = url.filter(|u| !u.is_empty()) else {
                continue;
            };
            let urls = out.entry(claim_id).or_default();
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
        Ok(out)
    }

    /// The source identity of each of `ids` that `viewer` can see
    /// ([`EvidenceSourceIdentity`]), keyed by evidence id. An id the
    /// viewer cannot see, or that names no evidence row, is absent.
    ///
    /// Backs the canonical item key of the atom fold
    /// (`epigraph_engine::source_dependence::item_key`, SPEC §3.3), which
    /// reads a DOI first and a URL second.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, ids))]
    pub async fn source_identity_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, EvidenceSourceIdentity>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let sql = viewer.splice(
            "SELECT e.id, e.properties->>'doi', e.source_url \
             FROM evidence e \
             WHERE e.id = ANY($1) \
               /* {VISIBILITY:e} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, Option<String>, Option<String>)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor)
            .await?
            .into_iter()
            .map(|(id, doi, source_url)| (id, EvidenceSourceIdentity { doi, source_url }))
            .collect())
    }

    /// `source_url` of each of `ids` that has one and that `viewer` can see,
    /// keyed by evidence id. Rows with a NULL or invisible `source_url` are
    /// simply absent.
    ///
    /// Backs `epigraph_engine::source_dependence::source_keys_for_rows`: the
    /// combine step's same-source test (backlog 4c42c0bf).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(executor, viewer, ids))]
    pub async fn source_urls_by_id<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, String>, DbError> {
        let sql = viewer.splice(
            "SELECT e.id, e.source_url \
             FROM evidence e \
             WHERE e.id = ANY($1) \
               AND e.source_url IS NOT NULL \
               /* {VISIBILITY:e} */",
            2,
        );
        let mut q = sqlx::query_as::<_, (Uuid, String)>(&sql).bind(ids);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?.into_iter().collect())
    }

    /// Evidence linked to `claim_id` by an edge with the given `relationship`.
    ///
    /// A case-folded relationship (`epigraph_core::edge::relationships::
    /// CASE_FOLDED_RELATIONSHIPS`) matches BOTH stored spellings: the routes
    /// pass `"SUPPORTS"` / `"CONTRADICTS"`, the DS writers store upper case and
    /// MCP stores lower case, and both are the same relationship. Any other
    /// relationship still matches byte-exactly. The spellings bind as an array
    /// so the btree index on `edges.relationship` stays usable.
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
    #[instrument(skip(executor, viewer))]
    pub async fn by_relationship_for_claim<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
               AND ed.relationship = ANY($2) \
               /* {EDGE_VISIBILITY:ed} */ \
             ORDER BY ev.created_at DESC \
             LIMIT 100",
            3,
        );
        let spellings = epigraph_core::edge::relationships::relationship_spellings(relationship);
        let mut q = sqlx::query_as::<_, EvidenceEdgeRow>(&sql)
            .bind(claim_id)
            .bind(&spellings);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        Ok(q.fetch_all(executor).await?)
    }

    /// Backfill `raw_content` on an evidence row the viewer may WRITE.
    ///
    /// **The first production call site of the write-side predicate** (PR-16,
    /// delivered as 16b). The statement carries `/* {WRITABLE:e} */`, spliced by
    /// [`crate::visibility::Viewer::splice_write`], which renders
    /// `AND e.owner_group_id = ANY($3::uuid[])` and takes its array from
    /// [`crate::visibility::Viewer::writable_bind`] — the `admin`/`writer`
    /// subset — **not** from `group_bind()`.
    ///
    /// That distinction is the whole control, and it is invisible at a glance:
    /// binding `group_bind()` here would compile, keep the fragment and the
    /// bind arity identical, refuse every stranger exactly as it should, and
    /// silently let a principal who can only READ a group rewrite that group's
    /// evidence. `write_gate_evidence_update.rs` exists to fail in precisely
    /// that case.
    ///
    /// # What this does NOT constrain
    ///
    /// A `WHERE` predicate decides which ROW a statement may touch. It says
    /// nothing about the VALUES the `SET` clause assigns. This function only
    /// ever assigns `raw_content` and the `content_hash` derived from it, so
    /// the gap is not reachable here — but a future write fn that lets a
    /// caller assign `owner_group_id` is not made safe by carrying this marker.
    ///
    /// # `content_hash` moves with the body
    ///
    /// `content_hash` is set to BLAKE3(`raw_content`) in the same statement
    /// (backlog 9e7a9a96). `POST /api/v1/evidence` refuses a stored digest
    /// that disagrees with its body; rewriting the body alone left exactly
    /// that row behind, where no create-time check could see it. Computed
    /// here, not in the handler, so no caller can update one column without
    /// the other. A new body equal to a sibling row's on the same claim, in
    /// the same tenancy, is refused as `DbError::DuplicateKey`, writing nothing
    /// (the de-duplication every evidence write takes,
    /// [`Self::same_tenancy_duplicate`]); a body only another owner holds is
    /// not consulted, so the rewrite lands. A rewrite to the body the row
    /// already holds creates no new duplicate and is never refused, so a
    /// member of a same-owner duplicate pair stored before migration 171 stays
    /// writable. Backfilling a body onto
    /// external evidence (stored with `raw_content` NULL and a caller-supplied
    /// digest) replaces that digest with BLAKE3(body), deliberately: the row
    /// then describes, and can be checked against, the body it holds.
    ///
    /// A row holding the seal sentinel (its claim is sealed) is not
    /// rewritten and reports `false`, like an unwritable row.
    ///
    /// # Returns
    ///
    /// `true` when a row was updated. `false` when no row matched — which is
    /// **either** "no such evidence" **or** "you may not write it", deliberately
    /// indistinguishable: the caller maps it to 404, because a 403 would confirm
    /// the existence of evidence in a group the caller cannot write to.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` for a same-tenancy duplicate (nothing is
    /// written), `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, viewer, raw_content))]
    pub async fn update_raw_content<'c, A: sqlx::Acquire<'c, Database = sqlx::Postgres>>(
        conn: A,
        viewer: &crate::visibility::Viewer,
        id: EvidenceId,
        raw_content: &str,
    ) -> Result<bool, DbError> {
        // `$4` is the seal sentinel: a sealed claim's evidence is refused like
        // an unwritable row. Unseal writes the original body back and keeps
        // the original digest, so a PUT here would leave plaintext over a seal
        // and, after unseal, a digest that is not BLAKE3(raw_content).
        let sql = viewer.splice_write(
            "UPDATE evidence AS e SET raw_content = $2, content_hash = $3 \
             WHERE e.id = $1 \
               AND e.raw_content IS DISTINCT FROM $4 \
               /* {WRITABLE:e} */ \
             RETURNING e.claim_id",
            5,
        );
        let uuid: Uuid = id.into();
        let content_hash = blake3::hash(raw_content.as_bytes());
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql)
            .bind(uuid)
            .bind(raw_content)
            .bind(content_hash.as_bytes().as_slice())
            .bind(crate::repos::privatization::SEAL_EVIDENCE_SENTINEL);
        // Conditional, not `unwrap_or(&[])`: a `Bypass` viewer renders `" "` and
        // the statement therefore has no `$5` to fill. Binding unconditionally
        // would over-supply the maintenance path by one parameter.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }

        let mut tx = conn.begin().await?;
        let previous: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT content_hash FROM evidence WHERE id = $1")
                .bind(uuid)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(claim_id) = q.fetch_optional(&mut *tx).await? else {
            tx.rollback().await?;
            return Ok(false);
        };
        let digest = content_hash.as_bytes().as_slice();
        if previous.as_deref() != Some(digest)
            && Self::same_tenancy_duplicate(&mut tx, uuid, digest, claim_id).await?
        {
            tx.rollback().await?;
            return Err(Self::duplicate());
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Delete evidence by ID
    ///
    /// # Returns
    /// Returns `true` if the evidence was deleted, `false` if this session
    /// cannot read it.
    ///
    /// # Errors
    /// `DbError::WriteRefused` when it is readable but row security refused
    /// the delete; `DbError::QueryFailed` if the database query fails.
    /// Takes a viewer it does not yet use: WRITE path, PR-16 owns the
    /// write-side predicate. The parameter exists so the hook is already at
    /// every call site.
    #[instrument(skip(executor, _viewer))]
    pub async fn delete<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        _viewer: &crate::visibility::Viewer,
        id: EvidenceId,
    ) -> Result<bool, DbError> {
        // VISIBILITY-EXEMPT: PR-16 owns the write-side predicate.
        // Recognised by `crates/epigraph-db/tests/visibility_lint.rs`, which
        // otherwise fails any fn taking a `&Viewer` and running SQL without
        // splicing or binding it. The exemption count is itself a ratchet
        // there, so adding a third one is a visible diff.
        let uuid: Uuid = id.into();

        // Checked: migration 115's owner-scoped DELETE matches no row it
        // refuses and reports success. Evidence this session can read but not
        // delete (another writer's, 114) is a refusal, not "did not exist".
        let r = sqlx::query!(
            r#"
            WITH seen AS (SELECT 1 FROM evidence WHERE id = $1),
                 done AS (DELETE FROM evidence WHERE id = $1 RETURNING 1)
            SELECT (SELECT count(*) FROM seen) AS "seen!", (SELECT count(*) FROM done) AS "done!"
            "#,
            uuid
        )
        .fetch_one(executor)
        .await?;

        Ok(super::require_all_changed("evidence", uuid, "delete", (r.seen, r.done))? > 0)
    }

    /// Shared `WHERE` clause for [`Self::list_filtered`] and
    /// [`Self::count_filtered`], mirroring `ClaimRepository::FILTER_WHERE`.
    ///
    /// One clause, one bind helper: the count and the page it describes cannot
    /// drift apart, because there is only one place either could change.
    ///
    /// The visibility marker is NOT here — each statement appends its own,
    /// immediately after interpolating this constant.
    ///
    /// That is deliberate and it is not a weakening. The marker was originally
    /// written into this shared clause, which reads better but is invisible to
    /// `visibility_lint.rs::every_spliced_statement_carries_the_canonical_marker_spelling`:
    /// that lint scans the BODY of each fn that calls `Viewer::splice`, so a
    /// marker inherited from a `const` declared elsewhere makes both statements
    /// look marker-free and the lint fails them. Keeping the marker at each
    /// splice site is what keeps the two statements under the lint's eye, so a
    /// future edit that drops one is a build failure rather than a silent
    /// widening. The FILTER predicates still live here exactly once.
    ///
    /// `splice` takes its bind index at the CALL site, so the two statements
    /// carry the same marker at different `$n` — `$4` for the count, `$6` for
    /// the page after `LIMIT`/`OFFSET`.
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
    #[instrument(skip(executor, viewer, filter))]
    pub async fn count_filtered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        filter: &EvidenceListFilter<'_>,
    ) -> Result<i64, DbError> {
        // Marker doubled because this is a `format!` literal; it renders as
        // `/* {VISIBILITY:evidence} */`.
        let sql = format!(
            "SELECT COUNT(*) FROM evidence{} /* {{VISIBILITY:evidence}} */",
            Self::FILTER_WHERE
        );
        // Viewer bind is $4, after `bind_filter`'s $1..$3, and LAST because it
        // is conditional: a Bypass viewer renders no placeholder and binds
        // nothing.
        let sql = viewer.splice(&sql, 4);
        // `query_scalar` is `query_as` over a 1-tuple; going through the tuple
        // form lets `bind_filter` serve both methods.
        let mut q = Self::bind_filter(sqlx::query_as::<_, (i64,)>(&sql), filter);
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $4
        }
        let (count,): (i64,) = q.fetch_one(executor).await?;
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
    #[instrument(skip(executor, viewer, filter))]
    pub async fn list_filtered<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        viewer: &crate::visibility::Viewer,
        filter: &EvidenceListFilter<'_>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EvidenceListRow>, DbError> {
        let sql = format!(
            r#"
            SELECT id, claim_id, evidence_type, raw_content, content_hash,
                   source_url, properties, signer_id, created_at
            FROM evidence{where_clause} /* {{VISIBILITY:evidence}} */
            ORDER BY created_at DESC, id DESC
            LIMIT $4 OFFSET $5
            "#,
            where_clause = Self::FILTER_WHERE,
        );
        // Viewer bind is $6 — after `bind_filter`'s $1..$3 AND after
        // `LIMIT`/`OFFSET`'s $4/$5, because the viewer bind is conditional and
        // must therefore be last. `count_filtered` splices the SAME marker at
        // $4; the shared clause is what keeps the two predicates identical.
        let sql = viewer.splice(&sql, 6);

        let mut q = Self::bind_filter(sqlx::query_as::<_, EvidenceListRow>(&sql), filter)
            .bind(limit) // $4
            .bind(offset); // $5
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g); // $6
        }
        let rows = q.fetch_all(executor).await?;

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

    /// Store an embedding vector on an evidence row `viewer` may write, and
    /// only while the row carries no ciphertext.
    ///
    /// The request-path twin of [`Self::store_embedding`], for a caller that
    /// holds a connection stamped with `viewer`
    /// (`AppState::store_evidence_embedding_as`). `evidence` is under the
    /// generic tenancy policy, whose `WITH CHECK` refuses this UPDATE on an
    /// unstamped connection; the `{WRITABLE:e}` splice keeps the statement's
    /// own qual in agreement with the stamp. Keyed on `evidence_encryption`, the
    /// row's own ciphertext: a sealed row must never carry a vector derived
    /// from its plaintext.
    ///
    /// # Returns
    /// `true` when a row was updated; `false` when none matched (no such row, a
    /// sealed row, or a row `viewer` may not write).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(conn, viewer, embedding_pgvector))]
    pub async fn store_embedding_as(
        conn: &mut sqlx::PgConnection,
        viewer: &crate::visibility::Viewer,
        id: EvidenceId,
        embedding_pgvector: &str,
    ) -> Result<bool, DbError> {
        let uuid: Uuid = id.into();
        let sql = viewer.splice_write(
            "UPDATE evidence AS e SET embedding = $2::vector \
              WHERE e.id = $1 \
                AND NOT EXISTS ( \
                    SELECT 1 FROM evidence_encryption ee WHERE ee.evidence_id = e.id \
                ) \
                /* {WRITABLE:e} */",
            3,
        );
        let mut q = sqlx::query(&sql).bind(uuid).bind(embedding_pgvector);
        // Conditional: a `Bypass` viewer renders no `$3` to fill.
        if let Some(w) = viewer.writable_bind() {
            q = q.bind(w);
        }
        let result = q.execute(&mut *conn).await?;
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
    #[instrument(skip(executor, viewer, query_embedding_pgvector))]
    pub async fn search_by_embedding<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        let rows = q.fetch_all(executor).await?;

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
    /// Returns `DbError::DuplicateKey` if any evidence ID already exists, or any
    /// row duplicates another in its tenancy ([`Self::same_tenancy_duplicate`]);
    /// nothing is written then.
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
                .bind(Self::source_url_of(&e.evidence_type))
                .bind(e.raw_content.as_deref())
                .bind(claim_id)
                .bind(signature)
                .bind(signer_id) // NULL when unsigned (matches evidence_signature_requires_signer constraint)
                .bind(evidence_type_json)
                .bind(e.created_at);
        }

        let rows = query.fetch_all(&mut *tx).await?;

        // The same de-duplication as `create`, row by row, in key order so two
        // batches lock in the same order. Any duplicate refuses the whole
        // batch, as a unique violation did: `tx` rolls back on return.
        let mut in_key_order: Vec<&EvidenceRow> = rows.iter().collect();
        in_key_order.sort_by(|a, b| {
            (&a.content_hash, a.claim_id, a.id).cmp(&(&b.content_hash, b.claim_id, b.id))
        });
        for row in in_key_order {
            if Self::same_tenancy_duplicate(&mut tx, row.id, &row.content_hash, row.claim_id)
                .await?
            {
                return Err(Self::duplicate());
            }
        }
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
