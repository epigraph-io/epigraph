//! Claim repository for database operations

use crate::errors::DbError;
use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Claim operations
pub struct ClaimRepository;

/// Cached Dempster–Shafer belief columns for a claim, as read by
/// [`ClaimRepository::get_belief_columns`].
///
/// Each field is `Option` because the column is NULL on claims that have never
/// had a BBA combined onto them (the edge-wiring recompute populates them).
#[derive(Debug, Clone, Copy, sqlx::FromRow, serde::Serialize)]
pub struct ClaimBeliefColumns {
    pub belief: Option<f64>,
    pub plausibility: Option<f64>,
    pub pignistic_prob: Option<f64>,
}

/// Result row for [`ClaimRepository::search_by_embedding`].
///
/// `similarity` is `1 - cosine_distance`, in `[0, 1]` for non-degenerate
/// vectors (and matching the convention used by callers in `epigraph-mcp`).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ClaimEmbeddingHit {
    pub claim_id: Uuid,
    pub similarity: f64,
}

/// One fused hit from [`ClaimRepository::search_hybrid_scoped`] /
/// [`ClaimRepository::search_lexical_scoped`].
///
/// `rrf_score` is the Reciprocal Rank Fusion score (higher = better; sums
/// `1/(k+rank)` across the legs the claim appeared in). `dense_similarity` is
/// `Some(1 - cosine_distance)` when the claim was in the dense (embedding) leg,
/// `None` for lexical-only hits. `in_lexical` is true when it appeared in the
/// lexical (`content_tsv`) leg.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct HybridHit {
    pub claim_id: Uuid,
    pub rrf_score: f64,
    pub dense_similarity: Option<f64>,
    pub in_lexical: bool,
}

/// Result row for [`ClaimRepository::latest_in_lineage`].
///
/// Represents a head of a step lineage: a claim with `step_lineage_id = $1`
/// and no incoming `supersedes` edge. See spec §3.1 in
/// `docs/superpowers/specs/2026-05-05-step-level-versioning-design.md`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LineageHead {
    pub id: Uuid,
    pub content: String,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Result of a successful [`ClaimRepository::evolve_step`] call.
#[derive(Debug)]
pub struct EvolveStepResult {
    pub new_claim_id: Uuid,
    pub step_lineage_id: Uuid,
    pub edge_type: String,
    pub edge_id: Uuid,
}

/// Input for [`ClaimRepository::patch_claim_atomic_conn`].
#[derive(Debug, Clone, Default)]
pub struct PatchClaimInput {
    pub trace_id: Option<Uuid>,
    pub properties: Option<serde_json::Value>,
    pub add_labels: Vec<String>,
    pub remove_labels: Vec<String>,
}

/// Diff produced by [`ClaimRepository::patch_claim_atomic_conn`].
#[derive(Debug)]
pub struct PatchClaimDiff {
    pub before_labels: Vec<String>,
    pub after_labels: Vec<String>,
    pub before_props: serde_json::Value,
    pub after_props: serde_json::Value,
    pub before_trace: Option<Uuid>,
    pub after_trace: Option<Uuid>,
}

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

        // Fire-and-forget claim.created event (closes #61). This is the
        // central emit for ALL writers that go through ClaimRepository::create
        // (MCP ingestion paths, API conventions, paper repo, tests). The
        // dedup early-return above does NOT emit, so resubmissions of an
        // existing content_hash do not pollute the audit log.
        let _ = crate::repos::EventRepository::publish_or_log(
            pool,
            "claim.created",
            Some(row.agent_id),
            &serde_json::json!({
                "claim_id": row.id,
                "agent_id": row.agent_id,
                "truth_value": row.truth_value,
            }),
        )
        .await;

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

    /// Read a claim's workflow-promotion flag
    /// (`properties->'promotion'->>'promotable'`). `None` when the claim was
    /// never evaluated (or does not exist); `Some(bool)` otherwise. Used by
    /// `find_workflow` to surface whether a variant has been promoted.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn promotion_flag(pool: &PgPool, claim_id: ClaimId) -> Result<Option<bool>, DbError> {
        let id: Uuid = claim_id.into();
        let flag: Option<Option<bool>> = sqlx::query_scalar(
            "SELECT (properties->'promotion'->>'promotable')::bool FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(flag.flatten())
    }

    /// Read a claim's cached Dempster–Shafer belief columns
    /// (`belief`, `plausibility`, `pignistic_prob`).
    ///
    /// These are the columns the edge-wiring recompute path
    /// (`MassFunctionRepository::update_claim_belief`) writes — distinct from
    /// `truth_value`, which the recompute leaves untouched. Callers that need
    /// the *post-wire* combined belief (e.g. the MCP `link_epistemic` readback)
    /// must read these columns, NOT `truth_value`; the unframed
    /// `belief_query::get_belief` path reads `truth_value` and so does not
    /// reflect a recompute.
    ///
    /// Returns `Ok(None)` when the claim does not exist; the columns inside
    /// [`ClaimBeliefColumns`] are individually `Option` (NULL when the claim
    /// has never had a BBA combined onto it).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_belief_columns(
        pool: &PgPool,
        claim_id: ClaimId,
    ) -> Result<Option<ClaimBeliefColumns>, DbError> {
        let id: Uuid = claim_id.into();
        let row: Option<ClaimBeliefColumns> =
            sqlx::query_as("SELECT belief, plausibility, pignistic_prob FROM claims WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        Ok(row)
    }

    /// Shallow-merge `patch` into the claim's `properties` JSONB (`||`),
    /// preserving keys not present in `patch` and overwriting those that are.
    /// Unlike [`set_properties`] (which replaces the whole object), this is for
    /// incrementally attaching/refreshing a sub-object — e.g. the workflow
    /// promotion verdict — without clobbering hierarchy metadata like `level`.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no claim has `claim_id`;
    /// `DbError::QueryFailed` on other database errors.
    #[instrument(skip(pool, patch))]
    pub async fn merge_properties(
        pool: &PgPool,
        claim_id: ClaimId,
        patch: &serde_json::Value,
    ) -> Result<(), DbError> {
        let id: Uuid = claim_id.into();
        let result = sqlx::query(
            "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $2, \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(patch)
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

        let row_id: Uuid = row.get("id");
        let row_agent_id: Uuid = row.get("agent_id");
        let row_truth_value: f64 = row.get("truth_value");

        // Fire-and-forget claim.created event (closes #61). Same rationale
        // as the create() method: emitted only on the post-INSERT branch
        // (the dedup early-return above does not reach here). Uses
        // publish_or_log_conn so the event rides the caller's transaction.
        let _ = crate::repos::EventRepository::publish_or_log_conn(
            &mut *conn,
            "claim.created",
            Some(row_agent_id),
            &serde_json::json!({
                "claim_id": row_id,
                "agent_id": row_agent_id,
                "truth_value": row_truth_value,
            }),
        )
        .await;

        let tv = TruthValue::new(row_truth_value)?;
        Ok(claim_from_row(
            row_id,
            row.get("content"),
            row_agent_id,
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
            SELECT id, content, truth_value, agent_id, trace_id,
                   created_at, updated_at, is_current, supersedes
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
                let mut claim = claim_from_row(
                    row.id,
                    row.content,
                    row.agent_id,
                    row.trace_id,
                    truth_value,
                    row.created_at,
                    row.updated_at,
                );
                // Post-fix retirement state so callers see real DB values
                // instead of `claim_from_row`'s defaults (is_current=true,
                // supersedes=None). sqlx::query! returns is_current as a
                // plain bool here because the schema marks it NOT NULL with
                // a DEFAULT — the macro trusts the NOT NULL annotation.
                claim.is_current = row.is_current;
                claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
                Ok(Some(claim))
            }
            None => Ok(None),
        }
    }

    /// Fetch only the labels for a single claim. Used by MCP `get_claim` to
    /// surface labels without re-fetching the whole Claim.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_labels(pool: &PgPool, id: ClaimId) -> Result<Vec<String>, DbError> {
        let row: Option<(Vec<String>,)> = sqlx::query_as("SELECT labels FROM claims WHERE id = $1")
            .bind(id.as_uuid())
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|(l,)| l).unwrap_or_default())
    }

    /// Get a claim by ID together with its labels in a single SQL statement.
    ///
    /// `get_by_id` followed by `get_labels` is two independent round trips
    /// against the shared pool: a concurrent `update_labels` between them can
    /// return labels inconsistent with the already-read claim row (TOCTOU).
    /// A single-statement, single-row `SELECT` is inherently consistent under
    /// Postgres MVCC, so this is the atomic alternative for callers (e.g. MCP
    /// `get_claim`) that need both together.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id_with_labels(
        pool: &PgPool,
        id: ClaimId,
    ) -> Result<Option<(Claim, Vec<String>)>, DbError> {
        let uuid: Uuid = id.into();

        use sqlx::Row;
        let row = sqlx::query(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id,
                   created_at, updated_at, is_current, supersedes, labels
            FROM claims
            WHERE id = $1
            "#,
        )
        .bind(uuid)
        .fetch_optional(pool)
        .await?;

        match row {
            Some(row) => {
                let truth_value = TruthValue::new(row.get::<f64, _>("truth_value"))?;
                let mut claim = claim_from_row(
                    row.get("id"),
                    row.get("content"),
                    row.get("agent_id"),
                    row.get("trace_id"),
                    truth_value,
                    row.get("created_at"),
                    row.get("updated_at"),
                );
                // Post-fix retirement state so callers see real DB values
                // instead of `claim_from_row`'s defaults, mirroring `get_by_id`.
                claim.is_current = row.get::<bool, _>("is_current");
                claim.supersedes = row
                    .get::<Option<Uuid>, _>("supersedes")
                    .map(ClaimId::from_uuid);
                let labels: Vec<String> = row.get("labels");
                Ok(Some((claim, labels)))
            }
            None => Ok(None),
        }
    }

    /// kNN search over `claims.embedding` (1536d) or `claims.embedding_3072`,
    /// restricted to paragraph-level (level=2) claims, optionally filtered by
    /// the paper that asserts the claim. Results are ordered by cosine
    /// similarity descending (= cosine distance ascending), and rows whose
    /// chosen embedding column is NULL are excluded.
    ///
    /// `query_embedding_pgvector` is a pgvector text literal, e.g. `"[0.1,0.2,...]"`.
    /// `paper_doi_filter`, when set, restricts results to claims that have an
    /// incoming `'asserts'` edge from a `papers` row with the given DOI.
    ///
    /// The `dim=1536` path is index-aligned with the partial HNSW
    /// `idx_claims_paragraph_embedding` introduced in migration 029. The
    /// `dim=3072` path is intentionally seq-scan (paragraph counts ≤ 10⁴; see
    /// the `recall_with_context` design doc).
    ///
    /// # Errors
    /// * [`DbError::InvalidData`] if `dim` is neither 1536 nor 3072.
    /// * [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        dim: u32,
        limit: i64,
        paper_doi_filter: Option<&str>,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        let column = match dim {
            1536 => "embedding",
            3072 => "embedding_3072",
            _ => {
                return Err(DbError::InvalidData {
                    reason: format!("unsupported centroid_dim: {dim} (must be 1536 or 3072)"),
                });
            }
        };

        // Two query shapes — paper-filter vs no-filter — to keep both
        // index-friendly. The shared WHERE predicate matches the partial
        // HNSW index from migration 029 for the 1536d path.
        let sql = if paper_doi_filter.is_some() {
            format!(
                r#"
                SELECT c.id AS claim_id,
                       1 - (c.{column} <=> $1::vector) AS similarity
                FROM claims c
                WHERE (c.properties->>'level')::int = 2
                  AND c.{column} IS NOT NULL
                  AND EXISTS (
                      SELECT 1 FROM edges e
                      JOIN papers p ON p.id = e.source_id
                      WHERE e.target_id = c.id
                        AND e.relationship = 'asserts'
                        AND p.doi = $3
                  )
                ORDER BY c.{column} <=> $1::vector
                LIMIT $2
                "#
            )
        } else {
            format!(
                r#"
                SELECT c.id AS claim_id,
                       1 - (c.{column} <=> $1::vector) AS similarity
                FROM claims c
                WHERE (c.properties->>'level')::int = 2
                  AND c.{column} IS NOT NULL
                ORDER BY c.{column} <=> $1::vector
                LIMIT $2
                "#
            )
        };

        let mut q = sqlx::query_as::<_, ClaimEmbeddingHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit);
        if let Some(doi) = paper_doi_filter {
            q = q.bind(doi);
        }

        Ok(q.fetch_all(pool).await?)
    }

    /// Search **current** claims by embedding similarity across **all levels**.
    ///
    /// This is the search backing the simple `recall` MCP tool. Unlike
    /// [`search_by_embedding`] — which is paper-paragraph-primary and
    /// restricts to `(properties->>'level')::int = 2` — memorized claims have
    /// no `level` property and store their vector on the 1536d
    /// `claims.embedding` column. `recall` therefore needs a search with no
    /// level restriction, limited to `is_current` so superseded/retired claims
    /// are not resurfaced. (`recall` previously queried
    /// `EvidenceRepository::search_by_embedding`, i.e. `evidence.embedding`,
    /// which is unpopulated — so its semantic path returned nothing.)
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding_current(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        Self::search_by_embedding_scoped(pool, query_embedding_pgvector, limit, None, None).await
    }

    /// [`search_by_embedding_current`] with optional scope predicates pushed
    /// into the query: `tags` requires label containment (`c.labels @> $tags`,
    /// the claim must carry ALL given tags) and `agent_id` requires authorship.
    /// A `None`/empty filter does not restrict (the `$n IS NULL OR …` idiom),
    /// so the two compose with AND. Scoping at the DB keeps it correct and
    /// index-friendly rather than over-fetching and filtering in Rust.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding_scoped(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        // Empty tag slice scopes to nothing meaningful (`@> '{}'` is all rows);
        // collapse it to None so the IS NULL branch short-circuits.
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let rows = sqlx::query_as::<_, ClaimEmbeddingHit>(
            r#"
            SELECT c.id AS claim_id,
                   1 - (c.embedding <=> $1::vector) AS similarity
            FROM claims c
            WHERE c.embedding IS NOT NULL
              AND c.is_current
              AND ($3::text[] IS NULL OR c.labels @> $3::text[])
              AND ($4::uuid IS NULL OR c.agent_id = $4::uuid)
            ORDER BY c.embedding <=> $1::vector
            LIMIT $2
            "#,
        )
        .bind(query_embedding_pgvector)
        .bind(limit)
        .bind(tags_owned)
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Hybrid retrieval over current claims: RRF-fuse a dense
    /// (`claims.embedding`, HNSW) leg and a lexical (`content_tsv`, GIN) leg in
    /// one round-trip. Both legs share the `is_current` / `labels @> tags` /
    /// `agent_id` predicates, so the only difference is the relevance signal.
    /// `candidate_pool` caps each leg before fusion; `k_rrf` is the RRF constant.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let rows = sqlx::query_as::<_, HybridHit>(
            r#"
            WITH dense AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY c.embedding <=> $1::vector) AS rank,
                       1 - (c.embedding <=> $1::vector) AS cos
                FROM claims c
                WHERE c.embedding IS NOT NULL AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                ORDER BY c.embedding <=> $1::vector
                LIMIT $3
            ),
            lex AS (
                SELECT c.id,
                       row_number() OVER (ORDER BY ts_rank_cd(c.content_tsv, q) DESC) AS rank
                FROM claims c, websearch_to_tsquery('english', $2) q
                WHERE c.content_tsv @@ q AND c.is_current
                  AND ($6::text[] IS NULL OR c.labels @> $6::text[])
                  AND ($7::uuid IS NULL OR c.agent_id = $7::uuid)
                ORDER BY ts_rank_cd(c.content_tsv, q) DESC
                LIMIT $3
            )
            SELECT COALESCE(d.id, l.id) AS claim_id,
                   (COALESCE(1.0/($4 + d.rank), 0)
                    + COALESCE(1.0/($4 + l.rank), 0))::float8 AS rrf_score,
                   d.cos::float8 AS dense_similarity,
                   (l.rank IS NOT NULL) AS in_lexical
            FROM dense d
            FULL OUTER JOIN lex l ON d.id = l.id
            ORDER BY rrf_score DESC
            LIMIT $5
            "#,
        )
        .bind(query_embedding_pgvector) // $1
        .bind(query_text) // $2
        .bind(candidate_pool) // $3
        .bind(k_rrf) // $4
        .bind(limit) // $5
        .bind(tags_owned) // $6
        .bind(agent_id) // $7
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Lexical-only retrieval over current claims (`content_tsv` / GIN), ranked
    /// by `ts_rank_cd`. Returns `HybridHit`s with `dense_similarity = None` and
    /// `in_lexical = true`; `rrf_score = 1/(k_rrf + rank)` keeps the score scale
    /// consistent with the hybrid path. Used as `recall`'s embedder-down
    /// fallback — unlike an ILIKE scan it honors the tag/agent scope in SQL.
    pub async fn search_lexical_scoped(
        pool: &PgPool,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        let tags_owned: Option<Vec<String>> = match tags {
            Some(t) if !t.is_empty() => Some(t.to_vec()),
            _ => None,
        };

        let rows = sqlx::query_as::<_, HybridHit>(
            r#"
            SELECT c.id AS claim_id,
                   (1.0 / ($2 + row_number() OVER (
                       ORDER BY ts_rank_cd(c.content_tsv, q) DESC)))::float8 AS rrf_score,
                   NULL::float8 AS dense_similarity,
                   true AS in_lexical
            FROM claims c, websearch_to_tsquery('english', $1) q
            WHERE c.content_tsv @@ q AND c.is_current
              AND ($4::text[] IS NULL OR c.labels @> $4::text[])
              AND ($5::uuid IS NULL OR c.agent_id = $5::uuid)
            ORDER BY ts_rank_cd(c.content_tsv, q) DESC
            LIMIT $3
            "#,
        )
        .bind(query_text) // $1
        .bind(k_rrf) // $2
        .bind(limit) // $3
        .bind(tags_owned) // $4
        .bind(agent_id) // $5
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Maximum number of claims returned by [`get_by_agent`](Self::get_by_agent) in a single
    /// call. Prevents loading an arbitrarily large `Vec<Claim>` into heap for agents with many
    /// claims. Callers that need pagination should use `list_by_truth_range` with explicit
    /// offset/limit.
    pub const MAX_AGENT_CLAIMS: i64 = 500;

    /// Get all claims by an agent
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_agent(pool: &PgPool, agent_id: AgentId) -> Result<Vec<Claim>, DbError> {
        let uuid: Uuid = agent_id.into();

        let rows = sqlx::query_as::<_, ClaimRow>(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE agent_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(uuid)
        .bind(Self::MAX_AGENT_CLAIMS)
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

    /// List claims whose `truth_value` falls within `[min_truth, max_truth]`,
    /// most-recent first. The range filter is applied in SQL **before**
    /// `LIMIT`, so matching claims are reachable regardless of how recently
    /// they were created.
    ///
    /// This exists because the obvious `list()` + post-query filter can only
    /// ever inspect the first `limit` most-recent rows — a matching claim
    /// outside that window is silently invisible (backlog bug `5a55a48e`:
    /// `query_claims(max_truth=0.75)` returned empty while matching claims
    /// existed).
    pub async fn list_by_truth_range(
        pool: &PgPool,
        min_truth: f64,
        max_truth: f64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Claim>, DbError> {
        let rows = sqlx::query_as::<_, ClaimRow>(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE truth_value >= $1 AND truth_value <= $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(min_truth)
        .bind(max_truth)
        .bind(limit)
        .bind(offset)
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

    /// Returns `true` iff **every** id in `ids` exists AND has
    /// `is_current = true`.
    ///
    /// A missing id, a superseded claim (`is_current = false` via
    /// [`Self::supersede`]), or a duplicate (via [`Self::mark_duplicate`])
    /// all yield `false`. Used to guard structural-edge creation against
    /// stale/duplicate endpoints — e.g. a CORROBORATES edge must not point at
    /// a claim that has already been retired (backlog bug `5c7fc645`).
    pub async fn are_all_current(pool: &PgPool, ids: &[uuid::Uuid]) -> Result<bool, DbError> {
        if ids.is_empty() {
            return Ok(true);
        }
        let live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM claims \
             WHERE id = ANY($1) AND COALESCE(is_current, true) = true",
        )
        .bind(ids)
        .fetch_one(pool)
        .await?;
        // Distinct ids must each be present-and-current. A missing or
        // non-current id lowers the count below the distinct cardinality.
        let distinct: std::collections::HashSet<&uuid::Uuid> = ids.iter().collect();
        Ok(live as usize == distinct.len())
    }

    /// Fetch `(id, content)` for a batch of claim ids, current rows only.
    ///
    /// Lightweight companion to the structural enrichment in
    /// `epigraph-mcp`'s `fetch_batched_context`: the rerank pipeline needs
    /// the candidate *text* to score query-relevance, but must NOT pay for
    /// siblings/corroborates/neighbor joins until AFTER it has truncated the
    /// widened pool down to the final `limit`. Returns a `HashMap` so the
    /// caller can look up content by id in any order (ANN result order is
    /// not preserved by `id = ANY(...)`). Missing/non-current ids are simply
    /// absent from the map.
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry)
    /// to keep `cargo sqlx prepare` out of this change's footprint.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn contents_by_ids(
        pool: &PgPool,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashMap<uuid::Uuid, String>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query_as::<_, (uuid::Uuid, String)>(
            "SELECT id, content FROM claims \
             WHERE id = ANY($1) AND COALESCE(is_current, true) = true",
        )
        .bind(ids)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Fetch `labels` for a batch of claim ids in one round-trip.
    ///
    /// Batch companion to [`Self::get_labels`], used by MCP `query_claims` to
    /// populate `ClaimResponse.labels` without an N+1 fan-out of per-claim
    /// `get_labels` calls (backlog bug `babd5904`: `query_claims` hardcoded
    /// `labels: Vec::new()`).
    ///
    /// Deliberately does **NOT** filter on `is_current`. `query_claims` runs
    /// [`Self::list_by_truth_range`], which returns superseded rows, and the
    /// single-claim label source it mirrors (`get_labels` →
    /// `SELECT labels FROM claims WHERE id = $1`) has no `is_current` clause
    /// either. Filtering here would silently re-drop labels for superseded
    /// claims — the same bug class, narrowed. A missing id is simply absent
    /// from the map (caller treats absence as "no labels").
    ///
    /// Uses the runtime `query_as` form (no compile-time `.sqlx` cache entry)
    /// to keep `cargo sqlx prepare` out of this change's footprint.
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    pub async fn labels_by_ids(
        pool: &PgPool,
        ids: &[uuid::Uuid],
    ) -> Result<std::collections::HashMap<uuid::Uuid, Vec<String>>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query_as::<_, (uuid::Uuid, Vec<String>)>(
            "SELECT id, COALESCE(labels, ARRAY[]::text[]) FROM claims WHERE id = ANY($1)",
        )
        .bind(ids)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// List claims that contain ALL of the specified labels.
    ///
    /// Uses the GIN index on `claims.labels` for efficient `@>` containment queries.
    /// Results are ordered by `created_at DESC` and filtered by optional truth threshold.
    ///
    /// # Filters
    /// - `exclude_labels`: drop any claim whose label set intersects this
    ///   collection (PostgreSQL `&&` overlap operator). Empty slice = no
    ///   exclusion.
    /// - `current_only`: when true, restrict to `is_current = true` (drops
    ///   superseded rows).
    ///
    /// # Returns
    /// Pairs of `(Claim, labels)`. The returned `Claim` is post-fixed with the
    /// row's `is_current` and `supersedes` values so callers can distinguish
    /// live, resolved, and superseded claims without re-querying.
    ///
    /// The inline `Row` struct keeps the global [`ClaimRow`] (used by other
    /// queries that don't need these columns) untouched, and we don't widen
    /// `claim_from_row`'s signature — its other ~20 callers don't care about
    /// retirement state.
    #[instrument(skip(pool))]
    pub async fn list_by_labels(
        pool: &PgPool,
        labels: &[String],
        exclude_labels: &[String],
        current_only: bool,
        min_truth: f64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<(Claim, Vec<String>)>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
            labels: Vec<String>,
            is_current: bool,
            supersedes: Option<Uuid>,
        }

        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id,
                   created_at, updated_at, labels, is_current, supersedes
            FROM claims
            WHERE labels @> $1
              AND truth_value >= $2
              AND ($3::text[] = '{}'::text[] OR NOT (labels && $3))
              AND ($4 = false OR COALESCE(is_current, true) = true)
            ORDER BY created_at DESC
            LIMIT $5
            OFFSET $6
            "#,
        )
        .bind(labels)
        .bind(min_truth)
        .bind(exclude_labels)
        .bind(current_only)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let truth_value = TruthValue::new(row.truth_value)?;
            let mut claim = claim_from_row(
                row.id,
                row.content,
                row.agent_id,
                row.trace_id,
                truth_value,
                row.created_at,
                row.updated_at,
            );
            claim.is_current = row.is_current;
            claim.supersedes = row.supersedes.map(ClaimId::from_uuid);
            out.push((claim, row.labels));
        }
        Ok(out)
    }

    /// List claims that have NEVER been touched by decomposition: claims that
    /// are neither the source (parent) nor the target (child) of any
    /// `decomposes_to` edge.
    ///
    /// `decomposes_to` is parent -> child (source = compound/parent, target =
    /// atom/child) — see `epigraph_ingest::common::edges::decomposes_edge`
    /// ("Build a decomposes_to edge between two claim nodes ... for parent ->
    /// child relationships"). A leaf atom therefore has only an *incoming*
    /// decomposes_to edge, so an outgoing-only predicate would wrongly
    /// re-select every atom for re-decomposition. We exclude BOTH directions —
    /// matching V2 `scripts/export_decomposition_input.py`'s
    /// `NOT EXISTS (... source_id = c.id ...) AND NOT EXISTS (... target_id =
    /// c.id ...)` predicate — so only standalone claims created via
    /// non-hierarchical paths (`memorize`, `submit_claim`, workflow outputs,
    /// legacy imports) are returned.
    ///
    /// Excludes host-telemetry claims (the `telemetry` label OR a
    /// `properties->>'event'` marker) per the repo embedding policy — these
    /// are container/task lifecycle noise with no decomposable propositional
    /// content, and replace V2's brittle `content LIKE 'Agent sent message%'`
    /// skip-patterns. Also drops trivially short content (`length > 10`), the
    /// one filter ported verbatim from V2.
    ///
    /// Ordered `created_at ASC` (oldest first) so a bounded batch makes
    /// monotonic progress through the backlog across scheduled runs.
    pub async fn list_undecomposed(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Claim>, DbError> {
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            content: String,
            truth_value: f64,
            agent_id: Uuid,
            trace_id: Option<Uuid>,
            created_at: chrono::DateTime<chrono::Utc>,
            updated_at: chrono::DateTime<chrono::Utc>,
        }

        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        let rows = sqlx::query_as::<_, Row>(
            r#"
            SELECT c.id, c.content, c.truth_value, c.agent_id, c.trace_id,
                   c.created_at, c.updated_at
            FROM claims c
            WHERE COALESCE(c.is_current, true) = true
              AND length(c.content) > 10
              AND NOT ('telemetry' = ANY(c.labels))
              AND (c.properties ->> 'event') IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.source_id = c.id AND e.relationship = 'decomposes_to'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.target_id = c.id AND e.relationship = 'decomposes_to'
              )
            ORDER BY c.created_at ASC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
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

    /// Search workflow-tagged claims by content text match.
    ///
    /// Used by find_workflow MCP tool as a fallback when semantic search via
    /// evidence embeddings returns insufficient results. Workflow claims are
    /// the canonical storage; the legacy `workflows` table is mostly empty.
    ///
    /// Excludes superseded claims (`is_current = false`) so callers never
    /// receive a deprecated workflow definition while a newer version exists.
    /// `supersedes` itself is NOT used as an exclusion predicate — the new
    /// claim populates `supersedes = $old` to record lineage, so filtering on
    /// `supersedes IS NULL` would silently drop the replacement.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn search_by_label_and_text(
        pool: &PgPool,
        labels: &[String],
        text: &str,
        min_truth: f64,
        limit: i64,
    ) -> Result<Vec<Claim>, DbError> {
        let limit = limit.clamp(1, 1000);
        // Use the GIN-indexed `content_tsv` column so the text filter can hit
        // the `idx_claims_content_tsv` index (migration 050) instead of forcing
        // a sequential scan with a leading-wildcard ILIKE. `websearch_to_tsquery`
        // accepts free-form query strings and handles quoting internally.
        let rows = sqlx::query_as::<_, ClaimRow>(
            r#"
            SELECT id, content, truth_value, agent_id, trace_id, created_at, updated_at
            FROM claims
            WHERE labels @> $1
              AND content_tsv @@ websearch_to_tsquery('english', $2)
              AND truth_value >= $3
              AND COALESCE(is_current, true) = true
            ORDER BY truth_value DESC, created_at DESC
            LIMIT $4
            "#,
        )
        .bind(labels)
        .bind(text)
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
    ///
    /// # Implementation Notes
    /// The UPDATE that marks the old claim `is_current = false` also sets
    /// `embedding = NULL` in the **same statement**.  This is required by the
    /// CHECK constraint `chk_deprecated_no_embedding` (migration 052), which
    /// fires per-statement rather than per-transaction: splitting the two
    /// assignments across two UPDATE statements would violate the constraint
    /// between statements.  Any future caller — REST handlers, CLI tools, tests
    /// — must preserve this single-statement invariant.  See also
    /// [`ClaimRepository::mark_duplicate`] which is subject to the same
    /// constraint.
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

        // Verify old claim exists and is current; also pull labels so the new
        // claim can inherit them. Without the label carry, downstream consumers
        // that filter by labels (e.g. find_workflow's `labels @> ['workflow']`
        // predicate) silently lose the replacement. Properties are NOT carried
        // forward: if the supersession is fixing something that lived in
        // `properties` (e.g. a stale `confidence_source`), blanket copy would
        // propagate the bug the supersede was meant to correct. Callers that
        // want to preserve specific properties on the new claim should set
        // them via a follow-up `patch_claim`.
        let old_row: Option<(Uuid, bool, Vec<String>)> = sqlx::query_as(
            "SELECT agent_id, COALESCE(is_current, true), \
                    COALESCE(labels, ARRAY[]::text[]) \
             FROM claims WHERE id = $1",
        )
        .bind(old_uuid)
        .fetch_optional(&mut *tx)
        .await?;

        let (agent_id, is_current, old_labels) = old_row.ok_or(DbError::NotFound {
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

        // Mark old claim as non-current and null its embedding in one statement.
        // Combining both in a single UPDATE is required by the CHECK constraint
        // `chk_deprecated_no_embedding` (migration 052) which fires per-statement,
        // not per-transaction: a two-step update would violate it between statements.
        sqlx::query(
            "UPDATE claims SET is_current = false, embedding = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(old_uuid)
        .execute(&mut *tx)
        .await?;

        // Insert new claim with supersedes link, carrying forward only labels
        // from the old row. Embeddings are intentionally NOT copied: the new
        // claim's content differs and any stale vector would mislead semantic
        // search. Properties are NOT copied either (see above) — callers must
        // re-set them explicitly if needed.
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, \
                                 supersedes, is_current, labels, \
                                 created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, true, $7, NOW(), NOW())",
        )
        .bind(new_uuid)
        .bind(new_content)
        .bind(content_hash.as_slice())
        .bind(new_truth_val)
        .bind(agent_id)
        .bind(old_uuid)
        .bind(&old_labels)
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

        let row_id: Uuid = row.get("id");
        let row_agent_id: Uuid = row.get("agent_id");
        let row_truth_value: f64 = row.get("truth_value");

        // Fire-and-forget claim.created event (closes #61). Emitted from
        // create_strict (not create_or_get) so:
        //   (a) `claims.rs::create_strict(...)` direct callers also emit,
        //   (b) create_or_get's success branch is exactly when create_strict
        //       returned Ok — no duplicate emit needed there,
        //   (c) the DuplicateKey/race branch in create_or_get correctly
        //       does NOT emit (no row was actually inserted).
        // Uses publish_or_log_conn so the event INSERT participates in the
        // caller's transaction — if the caller rolls back, neither the claim
        // nor the event lands.
        let _ = crate::repos::EventRepository::publish_or_log_conn(
            &mut *conn,
            "claim.created",
            Some(row_agent_id),
            &serde_json::json!({
                "claim_id": row_id,
                "agent_id": row_agent_id,
                "truth_value": row_truth_value,
            }),
        )
        .await;

        let tv = TruthValue::new(row_truth_value)?;
        Ok(claim_from_row(
            row_id,
            row.get("content"),
            row_agent_id,
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
        let was_inserted = row.map(|(b,)| b).unwrap_or(false);

        // Fire-and-forget claim.created event (closes #61), gated on actual
        // insertion. ON CONFLICT (id) DO NOTHING swallows duplicate-id paths,
        // and we rely on `was_inserted` (xmax=0 only on freshly-inserted rows)
        // to skip emission for idempotent re-runs.
        if was_inserted {
            let truth_value = truth.value();
            let _ = crate::repos::EventRepository::publish_or_log(
                pool,
                "claim.created",
                Some(agent_id),
                &serde_json::json!({
                    "claim_id": id,
                    "agent_id": agent_id,
                    "truth_value": truth_value,
                }),
            )
            .await;
        }

        Ok(was_inserted)
    }

    /// Walks `supersedes` edges on a step lineage. Returns one row per head:
    /// claims with `step_lineage_id = $1` and NO incoming `supersedes` edge.
    /// Multiple heads = unmerged concurrent branches (created via `revises`).
    /// Empty = no claims have this `step_lineage_id`.
    ///
    /// `revises` does NOT remove head status — only `supersedes` does. See
    /// `docs/superpowers/specs/2026-05-05-step-level-versioning-design.md` §3.1.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn latest_in_lineage(
        pool: &PgPool,
        lineage_id: Uuid,
    ) -> Result<Vec<LineageHead>, DbError> {
        let rows = sqlx::query_as::<_, LineageHead>(
            r#"
            SELECT c.id, c.content, c.truth_value, c.created_at
            FROM claims c
            WHERE c.step_lineage_id = $1
              AND NOT EXISTS (
                  SELECT 1 FROM edges e
                  WHERE e.target_id = c.id
                    AND e.relationship = 'supersedes'
              )
            ORDER BY c.created_at DESC
            "#,
        )
        .bind(lineage_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
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
        // Exclude host-provenance telemetry (epiclaw-host ProvenanceRecorder
        // signs every observable event as an immutable claim — container
        // lifecycle, task execution, agent output, messages). These are
        // intentionally NOT embedded (no semantic value, one OpenAI call each)
        // and dominate the is_current embedding gap; embedding them would
        // pollute semantic recall. They carry the `telemetry` label (added by
        // provenance.rs) and a `properties->>'event'` marker — filter on both
        // so pre-label-backfill rows and any label-PATCH-failure rows are still
        // excluded. Also restrict to current claims: per the embedding
        // invariant, `is_current = false` rows should have `embedding = NULL`
        // by design, so they never "need" an embedding. (backlog a4aaa487)
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT id, content FROM claims
            WHERE embedding IS NULL
              AND COALESCE(is_current, true) = true
              AND NOT ('telemetry' = ANY(labels))
              AND (properties->>'event') IS NULL
            ORDER BY created_at
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Read a claim's cached CDST classification label (`supported` |
    /// `contradicted` | `not_enough_info`), or `None` if unclassified or the
    /// claim does not exist. Written by `recompute_combined_belief` via
    /// `MassFunctionRepository::update_claim_classification`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_classification(
        pool: &PgPool,
        claim_id: Uuid,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT classification FROM claims WHERE id = $1")
                .bind(claim_id)
                .fetch_optional(pool)
                .await?;
        Ok(row.and_then(|(c,)| c))
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

    /// Maximum number of claim IDs accepted by [`pairwise_cosine_distance`](Self::pairwise_cosine_distance).
    /// At N=1000 the O(N²) cross-join produces ~500 k pair comparisons in Postgres; beyond
    /// this threshold query time becomes unreasonable and the result set itself is huge.
    pub const MAX_PAIRWISE_IDS: usize = 1_000;

    /// Compute pairwise cosine distances between claims in the given set.
    ///
    /// Returns all pairs where distance < `max_distance`, ordered ascending.
    /// Uses pgvector `<=>` operator. Note: this is a brute-force O(N²) scan
    /// — HNSW indexes do not accelerate distance filters.
    ///
    /// # Errors
    /// - `DbError::QueryFailed` if `claim_ids.len() > MAX_PAIRWISE_IDS`
    /// - `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn pairwise_cosine_distance(
        pool: &PgPool,
        claim_ids: &[Uuid],
        max_distance: f64,
    ) -> Result<Vec<ClaimPairDistance>, DbError> {
        if claim_ids.len() < 2 {
            return Ok(vec![]);
        }
        if claim_ids.len() > Self::MAX_PAIRWISE_IDS {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "pairwise_cosine_distance: {} ids exceeds MAX_PAIRWISE_IDS={}; \
                     split the input into smaller batches",
                    claim_ids.len(),
                    Self::MAX_PAIRWISE_IDS,
                )),
            });
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

// ── Step Evolution ──

impl ClaimRepository {
    /// Atomically create a new step claim that supersedes or revises a parent.
    ///
    /// `edge_type` must be `"supersedes"` (linear; flips parent.is_current=false)
    /// or `"revises"` (parallel branch; both heads stay current).
    ///
    /// The new claim inherits the parent's `step_lineage_id`. If the parent has
    /// no lineage id yet, one is generated and back-filled onto the parent first.
    /// `level` defaults to 2 (step). The `properties` JSONB on the new claim
    /// includes `level` and `step_lineage_id` so existing find_workflow_hierarchical
    /// queries (which filter on `properties->>'level' = '2'`) still work.
    #[instrument(skip(pool))]
    pub async fn evolve_step(
        pool: &PgPool,
        parent: ClaimId,
        new_content: &str,
        edge_type: &str,
        reason: Option<&str>,
        level: u32,
        agent_id: Uuid,
    ) -> Result<EvolveStepResult, DbError> {
        if !matches!(edge_type, "supersedes" | "revises") {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "evolve_step: edge_type must be 'supersedes' or 'revises', got {edge_type}"
                )),
            });
        }
        let parent_uuid: Uuid = parent.into();
        let mut tx = pool.begin().await?;

        let row: Option<(Option<Uuid>, bool)> =
            sqlx::query_as("SELECT step_lineage_id, COALESCE(is_current, true) FROM claims WHERE id = $1 FOR UPDATE")
                .bind(parent_uuid)
                .fetch_optional(&mut *tx)
                .await?;
        let (existing_lineage, parent_current) = row.ok_or(DbError::NotFound {
            entity: "Claim".into(),
            id: parent_uuid,
        })?;
        if edge_type == "supersedes" && !parent_current {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "evolve_step: cannot supersede a non-current step {parent_uuid}"
                )),
            });
        }
        let lineage_id = match existing_lineage {
            Some(l) => l,
            None => {
                let new_lineage = Uuid::new_v4();
                sqlx::query("UPDATE claims SET step_lineage_id = $1 WHERE id = $2")
                    .bind(new_lineage)
                    .bind(parent_uuid)
                    .execute(&mut *tx)
                    .await?;
                new_lineage
            }
        };

        let new_uuid = Uuid::new_v4();
        let hash = ContentHasher::hash(new_content.as_bytes());
        let properties = serde_json::json!({
            "level": level,
            "step_lineage_id": lineage_id.to_string(),
        });
        sqlx::query(
            "INSERT INTO claims (id, content, content_hash, truth_value, agent_id, is_current, labels, properties, step_lineage_id) \
             VALUES ($1, $2, $3, 0.5, $4, true, ARRAY[]::text[], $5, $6)",
        )
        .bind(new_uuid)
        .bind(new_content)
        .bind(hash.as_slice())
        .bind(agent_id)
        .bind(&properties)
        .bind(lineage_id)
        .execute(&mut *tx)
        .await?;

        let edge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO edges (id, source_id, source_type, target_id, target_type, relationship, properties) \
             VALUES ($1, $2, 'claim', $3, 'claim', $4, jsonb_build_object('reason', $5))",
        )
        .bind(edge_id)
        .bind(new_uuid)
        .bind(parent_uuid)
        .bind(edge_type)
        .bind(reason.unwrap_or(""))
        .execute(&mut *tx)
        .await?;

        if edge_type == "supersedes" {
            // Also null the embedding so the retired step drops out of semantic
            // search. Mirrors the invariant enforced by supersede() and
            // mark_duplicate(): is_current=false → embedding=NULL.
            sqlx::query(
                "UPDATE claims SET is_current = false, embedding = NULL, updated_at = NOW() \
                 WHERE id = $1",
            )
            .bind(parent_uuid)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(EvolveStepResult {
            new_claim_id: new_uuid,
            step_lineage_id: lineage_id,
            edge_type: edge_type.to_string(),
            edge_id,
        })
    }

    /// Mark `dup` as a duplicate of `canonical` without creating a new claim.
    /// Sets `supersedes = canonical, is_current = false` on `dup` only.
    /// Refuses if `dup.supersedes` is already set.
    ///
    /// # Implementation Notes
    /// The UPDATE that sets `is_current = false` on the duplicate also sets
    /// `embedding = NULL` in the **same statement**, satisfying the CHECK
    /// constraint `chk_deprecated_no_embedding` (migration 052).  This
    /// constraint fires per-statement, so any split across two UPDATE statements
    /// would violate it between them.  Any future caller must preserve this
    /// single-statement invariant.  See also [`ClaimRepository::supersede`]
    /// which has the same requirement.
    #[instrument(skip(pool))]
    pub async fn mark_duplicate(
        pool: &PgPool,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<(), DbError> {
        let dup_uuid: Uuid = dup.into();
        let canon_uuid: Uuid = canonical.into();
        if dup_uuid == canon_uuid {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol("mark_duplicate: dup == canonical".into()),
            });
        }
        let mut tx = pool.begin().await?;
        let canon_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM claims WHERE id = $1)")
                .bind(canon_uuid)
                .fetch_one(&mut *tx)
                .await?;
        if !canon_exists {
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: canon_uuid,
            });
        }
        let row: Option<(Option<Uuid>,)> =
            sqlx::query_as("SELECT supersedes FROM claims WHERE id = $1 FOR UPDATE")
                .bind(dup_uuid)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((existing,)) = row else {
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: dup_uuid,
            });
        };
        if existing.is_some() {
            return Err(DbError::QueryFailed {
                source: sqlx::Error::Protocol(format!(
                    "Claim {dup_uuid} already superseded; refusing to overwrite"
                )),
            });
        }
        // Null the embedding in the same statement as is_current=false so the
        // CHECK constraint chk_deprecated_no_embedding (migration 052) is not
        // violated mid-transaction. Dropping it from semantic search is the same
        // invariant as supersede() and deprecate_claim().
        sqlx::query(
            "UPDATE claims \
             SET supersedes = $1, is_current = false, embedding = NULL, updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .execute(&mut *tx)
        .await?;

        // Migrate edges off the now-non-current duplicate onto the canonical
        // claim, mirroring supersede()'s edge migration — otherwise edges to/from
        // third claims dangle at a claim that no longer surfaces. Unlike supersede
        // (which targets a freshly-minted claim with no pre-existing edges), the
        // canonical here already exists, so we must guard against two collision
        // classes before running the UPDATEs:
        //
        //   1. Self-loops: `dup→canonical` or `canonical→dup` edges that would
        //      become `canonical→canonical` after migration (handled by the
        //      `AND NOT (... = $1)` filters in the UPDATE clauses below).
        //
        //   2. Diamond duplicates: a third claim T that has edges to *both* dup
        //      and canonical with the same relationship — e.g.
        //      `T→[CORROBORATES]→dup` AND `T→[CORROBORATES]→canonical`.
        //      Migrating the dup edge to point at canonical would produce a
        //      second `T→[CORROBORATES]→canonical` triple, tripping the partial
        //      unique index `idx_edges_unique_triple_non_authored`
        //      (migration 017, covers all relationship types except AUTHORED)
        //      and rolling back the whole transaction before `is_current` is
        //      flipped.  Pre-delete the redundant dup edges so the UPDATE only
        //      touches survivors.  AUTHORED edges are excluded because the
        //      partial index does not cover them, and they are meant to
        //      accumulate (migration 017 explicitly allows multiple AUTHORED
        //      edges per triple).
        //
        // The 'supersedes' edges (dedup/lineage trail) are preserved throughout.

        // Drop incoming dup-edges whose migrated triple already exists on canonical.
        // Alias the outer table as `e` so the correlated subquery references
        // `e.source_id`, `e.source_type`, `e.relationship` unambiguously.
        // Without the alias, unqualified column names inside the EXISTS bind to
        // `edges e2` (innermost scope in PostgreSQL), making the predicate
        // tautological and causing false-positive deletions of edges that should
        // be migrated.
        sqlx::query(
            "DELETE FROM edges AS e \
             WHERE e.target_id = $2 AND e.target_type = 'claim' \
               AND e.relationship != 'supersedes' AND e.relationship != 'AUTHORED' \
               AND e.source_type = 'claim' AND e.source_id != $1 \
               AND EXISTS ( \
                   SELECT 1 FROM edges e2 \
                   WHERE e2.source_id = e.source_id \
                     AND e2.source_type = e.source_type \
                     AND e2.target_id = $1 \
                     AND e2.target_type = 'claim' \
                     AND e2.relationship = e.relationship \
               )",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .execute(&mut *tx)
        .await?;

        // Drop outgoing dup-edges whose migrated triple already exists on canonical.
        // Same aliasing discipline: `e.target_id`, `e.target_type`, `e.relationship`
        // must refer to the outer (being-deleted) row, not the subquery table.
        sqlx::query(
            "DELETE FROM edges AS e \
             WHERE e.source_id = $2 AND e.source_type = 'claim' \
               AND e.relationship != 'supersedes' AND e.relationship != 'AUTHORED' \
               AND e.target_type = 'claim' AND e.target_id != $1 \
               AND EXISTS ( \
                   SELECT 1 FROM edges e2 \
                   WHERE e2.source_id = $1 \
                     AND e2.source_type = 'claim' \
                     AND e2.target_id = e.target_id \
                     AND e2.target_type = e.target_type \
                     AND e2.relationship = e.relationship \
               )",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE edges SET target_id = $1 \
             WHERE target_id = $2 AND target_type = 'claim' AND relationship != 'supersedes' \
               AND NOT (source_type = 'claim' AND source_id = $1)",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE edges SET source_id = $1 \
             WHERE source_id = $2 AND source_type = 'claim' AND relationship != 'supersedes' \
               AND NOT (target_type = 'claim' AND target_id = $1)",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Apply a patch atomically inside the supplied transaction. Returns a diff so
    /// callers can build provenance or HTTP responses. No provenance writing here.
    pub async fn patch_claim_atomic_conn<'c>(
        tx: &mut sqlx::Transaction<'c, sqlx::Postgres>,
        id: ClaimId,
        patch: &PatchClaimInput,
    ) -> Result<PatchClaimDiff, DbError> {
        use sqlx::Row as _;
        let id_uuid: Uuid = id.into();
        let row = sqlx::query(
            "SELECT trace_id, COALESCE(labels, ARRAY[]::text[]) AS labels, COALESCE(properties, '{}'::jsonb) AS properties \
             FROM claims WHERE id = $1 FOR UPDATE",
        )
        .bind(id_uuid).fetch_optional(&mut **tx).await?
        .ok_or(DbError::NotFound { entity: "Claim".into(), id: id_uuid })?;
        let before_labels: Vec<String> = row.get("labels");
        let before_props: serde_json::Value = row.get("properties");
        let before_trace: Option<Uuid> = row.get("trace_id");

        let mut after_trace = before_trace;
        if let Some(t) = patch.trace_id {
            sqlx::query("UPDATE claims SET trace_id = $1 WHERE id = $2")
                .bind(t)
                .bind(id_uuid)
                .execute(&mut **tx)
                .await?;
            after_trace = Some(t);
        }

        let mut after_props = before_props.clone();
        if let Some(p) = &patch.properties {
            sqlx::query(
                "UPDATE claims SET properties = COALESCE(properties, '{}'::jsonb) || $1 WHERE id = $2"
            )
            .bind(p).bind(id_uuid).execute(&mut **tx).await?;
            if let (Some(merged), Some(po)) = (after_props.as_object_mut(), p.as_object()) {
                for (k, v) in po {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }

        let mut after_labels = before_labels.clone();
        if !patch.add_labels.is_empty() || !patch.remove_labels.is_empty() {
            after_labels =
                Self::update_labels_conn(tx, id_uuid, &patch.add_labels, &patch.remove_labels)
                    .await?;
        }

        Ok(PatchClaimDiff {
            before_labels,
            after_labels,
            before_props,
            after_props,
            before_trace,
            after_trace,
        })
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

        // Host-provenance telemetry must be EXCLUDED: one via the `telemetry`
        // label, one via the `properties->>'event'` marker (covers rows whose
        // label back-fill / post-submit PATCH never landed). (backlog a4aaa487)
        let tele_labeled = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, labels)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL, ARRAY['telemetry','epiclaw'])
             RETURNING id",
        )
        .bind(format!(
            "Container epiclaw-x exited code 0 after 5ms {}",
            Uuid::new_v4()
        ))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let tele_event_prop = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, embedding, properties)
             VALUES ($1, sha256($1::bytea), 0.5, $2, NULL, '{\"event\":\"task_executed\"}'::jsonb)
             RETURNING id",
        )
        .bind(format!("Task t-{} executed, status: completed", Uuid::new_v4()))
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let missing = ClaimRepository::find_claims_needing_embeddings(&pool, 1000)
            .await
            .unwrap();
        assert!(
            missing.iter().any(|(id, _)| *id == claim_id),
            "substantive claim must be returned"
        );
        assert!(
            !missing.iter().any(|(id, _)| *id == tele_labeled),
            "telemetry-labeled claim must be excluded"
        );
        assert!(
            !missing.iter().any(|(id, _)| *id == tele_event_prop),
            "event-property telemetry claim must be excluded"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn contents_by_ids_returns_current_only_and_skips_missing(pool: sqlx::PgPool) {
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'test-contents-by-ids', 'system', ARRAY['test'])
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let current_text = format!("current-claim-{}", Uuid::new_v4());
        let current_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, true)
             RETURNING id",
        )
        .bind(&current_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        // A superseded (is_current = false) row must NOT be returned — the
        // rerank pool must never score retired claim text.
        let stale_text = format!("stale-claim-{}", Uuid::new_v4());
        let stale_id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current)
             VALUES ($1, sha256($1::bytea), 0.5, $2, false)
             RETURNING id",
        )
        .bind(&stale_text)
        .bind(agent_id)
        .fetch_one(&pool)
        .await
        .unwrap();

        let absent_id = Uuid::new_v4();
        let map = ClaimRepository::contents_by_ids(&pool, &[current_id, stale_id, absent_id])
            .await
            .unwrap();

        assert_eq!(
            map.get(&current_id).map(String::as_str),
            Some(current_text.as_str()),
            "current claim content must be returned verbatim"
        );
        assert!(
            !map.contains_key(&stale_id),
            "non-current (superseded) claim must be absent from the map"
        );
        assert!(
            !map.contains_key(&absent_id),
            "id with no matching row must be absent from the map"
        );
        assert_eq!(
            map.len(),
            1,
            "only the single current claim should be present"
        );

        // Empty input short-circuits to an empty map without touching the DB.
        let empty = ClaimRepository::contents_by_ids(&pool, &[]).await.unwrap();
        assert!(empty.is_empty());
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

    /// `merge_properties` shallow-merges a patch into `properties`, preserving
    /// untouched keys and OVERWRITING the patched key on a repeat call. This is
    /// what makes the workflow-promotion flag bidirectional: re-running the
    /// pass with promotable=false replaces a prior promotable=true rather than
    /// leaving a stale mark, while sibling keys (e.g. `level`) survive.
    #[sqlx::test(migrations = "../../migrations")]
    async fn merge_properties_preserves_siblings_and_overwrites_target(pool: sqlx::PgPool) {
        let (agent_id, agent_pk): (Uuid, Vec<u8>) = sqlx::query_as(
            "INSERT INTO agents (public_key, display_name, agent_type, labels)
             VALUES (sha256(gen_random_uuid()::text::bytea), 'merge-props-test', 'system', ARRAY['test'])
             RETURNING id, public_key",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&agent_pk);
        let claim = Claim::new(
            "Test claim for merge".to_string(),
            AgentId::from_uuid(agent_id),
            public_key,
            TruthValue::clamped(0.5),
        );
        let persisted = ClaimRepository::create(&pool, &claim).await.unwrap();
        ClaimRepository::set_properties(&pool, persisted.id, serde_json::json!({"level": 2}))
            .await
            .unwrap();

        // Merge a promotion verdict — `level` must survive.
        ClaimRepository::merge_properties(
            &pool,
            persisted.id,
            &serde_json::json!({"promotion": {"promotable": true, "lower_bound": 0.72}}),
        )
        .await
        .unwrap();
        let row: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0["level"], 2, "sibling key preserved");
        assert_eq!(row.0["promotion"]["promotable"], true);

        // Re-merge with promotable=false (a demotion) — overwrites the promotion
        // sub-object, `level` still preserved.
        ClaimRepository::merge_properties(
            &pool,
            persisted.id,
            &serde_json::json!({"promotion": {"promotable": false}}),
        )
        .await
        .unwrap();
        let row2: (serde_json::Value,) =
            sqlx::query_as("SELECT properties FROM claims WHERE id = $1")
                .bind(Uuid::from(persisted.id))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            row2.0["level"], 2,
            "sibling key still preserved after re-merge"
        );
        assert_eq!(
            row2.0["promotion"]["promotable"], false,
            "promotion sub-object overwritten — bidirectional, no stale mark"
        );
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
    /// Deprecate a single claim: drop its truth to the 0.05 sentinel, flip
    /// `is_current = false`, and NULL its embedding in one statement.
    ///
    /// This is the canonical deprecation primitive for workflow claims. It is
    /// the THIRD `is_current = false` cleanup path (alongside `supersede` and
    /// `mark_duplicate`); per CLAUDE.md "Embedding policy → Cleanup paths",
    /// any path flipping `is_current = false` MUST null the embedding in the
    /// same statement so the row drops out of semantic recall and does not
    /// inflate the `stale_present` audit count.
    ///
    /// Returns the number of rows affected (0 when `id` does not exist).
    /// Idempotent: re-running on an already-deprecated claim is a no-op flip
    /// plus a no-op NULL — safe to call twice (used as the post-deploy
    /// remediation path for claims deprecated by the pre-fix binary).
    ///
    /// Uses the runtime `sqlx::query` (string) form — NOT the compile-time
    /// `query!` macro — to match the existing deprecation call-sites and to
    /// avoid touching `.sqlx/` (no `cargo sqlx prepare` required).
    ///
    /// # Errors
    /// Returns `DbError` if the database query fails.
    pub async fn deprecate_claim(pool: &PgPool, id: ClaimId) -> Result<u64, DbError> {
        let uuid: Uuid = id.into();
        let result = sqlx::query(
            "UPDATE claims \
             SET truth_value = 0.05, is_current = false, embedding = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(uuid)
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

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

        let results =
            ClaimRepository::list_by_labels(&pool, &["backlog".into()], &[], false, 0.0, 100, 0)
                .await
                .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "should find claim by single label"
        );

        let results = ClaimRepository::list_by_labels(
            &pool,
            &["backlog".into(), "pending".into()],
            &[],
            false,
            0.0,
            100,
            0,
        )
        .await
        .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
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

        let results = ClaimRepository::list_by_labels(
            &pool,
            &["nonexistent-label".into()],
            &[],
            false,
            0.0,
            100,
            0,
        )
        .await
        .unwrap();
        assert!(
            !results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
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

        let results =
            ClaimRepository::list_by_labels(&pool, &["truth-test".into()], &[], false, 0.4, 100, 0)
                .await
                .unwrap();
        assert!(
            results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
            "0.5 >= 0.4 should match"
        );

        let results =
            ClaimRepository::list_by_labels(&pool, &["truth-test".into()], &[], false, 0.9, 100, 0)
                .await
                .unwrap();
        assert!(
            !results.iter().any(|(c, _)| c.id.as_uuid() == claim_id),
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

        let results =
            ClaimRepository::list_by_labels(&pool, &["limit-test".into()], &[], false, 0.0, 1, 0)
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

    /// Verify `pairwise_cosine_distance` enforces the `MAX_PAIRWISE_IDS` cap.
    /// No DB required: the size guard fires before the query is issued.
    #[tokio::test]
    async fn pairwise_cosine_distance_rejects_oversized_input() {
        use sqlx::postgres::PgPoolOptions;
        // We need a (dummy) pool even though the guard fires before any query.
        // Use a non-existent URL — `connect_lazy` does not dial at construction time.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://invalid-host/nodb")
            .unwrap();
        let too_many: Vec<Uuid> = (0..=ClaimRepository::MAX_PAIRWISE_IDS)
            .map(|_| Uuid::new_v4())
            .collect();
        let result = ClaimRepository::pairwise_cosine_distance(&pool, &too_many, 0.5).await;
        assert!(
            result.is_err(),
            "should return Err when claim_ids exceeds MAX_PAIRWISE_IDS"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("MAX_PAIRWISE_IDS"),
            "error message should mention MAX_PAIRWISE_IDS; got: {err_msg}"
        );
    }

    #[test]
    fn max_agent_claims_constant_is_positive() {
        assert!(ClaimRepository::MAX_AGENT_CLAIMS > 0);
    }
}
