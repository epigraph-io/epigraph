//! Claim repository for database operations

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::{AgentId, Claim, ClaimId, TraceId, TruthValue};
use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// Repository for Claim operations
pub struct ClaimRepository;

/// `MAX_AGENT_CLAIMS` is bound as a `LIMIT` in `get_by_agent`; a zero or
/// negative value would turn that query into a silent "return nothing" (or a
/// Postgres error) rather than a cap. Enforced at compile time.
const _: () = assert!(ClaimRepository::MAX_AGENT_CLAIMS > 0);

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

/// Result row for [`ClaimRepository::nearest_by_embedding`].
///
/// `distance` is raw pgvector cosine distance (`<=>`), in `[0, 2]`, 0 =
/// identical direction. Unlike [`ClaimEmbeddingHit::similarity`] this is NOT
/// inverted, because the write-side novelty gate (backlog `1bcaed94`)
/// thresholds directly on distance (`dist < 0.05` / `dist < 0.15`).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct NearestClaimHit {
    pub claim_id: Uuid,
    pub distance: f64,
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

/// What [`ClaimRepository::mark_duplicate_with_repair`] repaired in-transaction,
/// and what the caller still has to re-derive outside it.
///
/// The repo layer can fix *where* a derived record lives (delete BBAs whose
/// edge is gone, move BBAs whose edge moved) with pure SQL. It cannot
/// recompute belief: that needs the Dempster-Shafer combine pipeline, which
/// lives in `epigraph-engine`. So this struct is the hand-off.
#[derive(Debug, Clone, Default)]
pub struct DedupRepair {
    /// Claims whose cached DS scalars no longer match their surviving BBA set:
    /// both dedup endpoints, plus every third claim that lost a BBA to the
    /// collision pre-deletes.
    pub stale_claims: Vec<Uuid>,
    /// `(edge_id, target_id, relationship)` for claim→claim edges re-sourced
    /// from `dup` onto `canonical`. Their BBAs encode `dup`'s interval, frozen
    /// at wire time; the caller must invalidate and re-wire them from
    /// `canonical`.
    pub resourced_edges: Vec<(Uuid, Uuid, String)>,
    /// BBAs deleted because their edge was deleted (orphan repair).
    pub deleted_bbas: u64,
    /// BBAs moved from `dup` to `canonical` because their edge was re-pointed
    /// (stranding repair).
    pub moved_bbas: u64,
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

    /// Read the writer-declared confidence scope block
    /// (`properties->'confidence_declaration'`) for one claim.
    ///
    /// `None` when the claim has no declaration, `properties` is SQL NULL, or
    /// the row does not exist. Runtime query (not `query_scalar!`) so the
    /// workspace still builds under `SQLX_OFFLINE=true` with no `.sqlx`
    /// regeneration.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_confidence_declaration(
        pool: &PgPool,
        claim_id: ClaimId,
    ) -> Result<Option<serde_json::Value>, DbError> {
        let id: Uuid = claim_id.into();
        // The doubled `Option` steers inference and is not redundant: the outer
        // layer is "row present" (`fetch_optional`), the inner is "column was
        // SQL NULL". `.flatten()` collapses both to the same `None`.
        let value: Option<Option<serde_json::Value>> = sqlx::query_scalar(
            "SELECT properties -> 'confidence_declaration' FROM claims WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(value.flatten())
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

    /// The authoring agent of a claim, or `None` when no such claim exists.
    ///
    /// Narrow read for callers that need attribution without paying for a full
    /// [`Claim`] hydration — notably
    /// `epigraph_engine::retraction_cascade::invalidate_and_rewire`, which
    /// re-derives an edge-factor BBA and must attribute it the way the
    /// edge-write path does ("A's author asserts A SUPPORTS B"), i.e. to the
    /// **source** claim's author rather than to whoever triggered the
    /// retraction.
    ///
    /// Exists as a repo function rather than an inline query at the call site
    /// because `CLAUDE.md` keeps all SQL in `crates/epigraph-db/src/repos/`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_agent_id(pool: &PgPool, id: Uuid) -> Result<Option<Uuid>, DbError> {
        let agent_id: Option<Uuid> =
            sqlx::query_scalar("SELECT agent_id FROM claims WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        Ok(agent_id)
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
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_by_embedding_since`]; `None` = no window = today's
    /// behaviour.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        dim: u32,
        limit: i64,
        paper_doi_filter: Option<&str>,
    ) -> Result<Vec<ClaimEmbeddingHit>, DbError> {
        Self::search_by_embedding_since(
            pool,
            query_embedding_pgvector,
            dim,
            limit,
            paper_doi_filter,
            None,
        )
        .await
    }

    /// [`Self::search_by_embedding`] plus an optional `created_at >= since`
    /// window.
    ///
    /// The predicate sits in the same WHERE clause as the level/NULL guards,
    /// i.e. before `ORDER BY … LIMIT`, so the window narrows the candidate
    /// pool rather than trimming an already-truncated top-K (see
    /// [`Self::search_hybrid_scoped_since`] for why that distinction decides
    /// correctness rather than performance).
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn search_by_embedding_since(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        dim: u32,
        limit: i64,
        paper_doi_filter: Option<&str>,
        since: Option<DateTime<Utc>>,
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
        //
        // `since` is bound at a FIXED $3 in BOTH shapes and the conditional
        // DOI moves to $4. Appending `since` after a conditionally-bound
        // parameter would leave the no-filter shape with a bind-count
        // mismatch — a runtime error, not a compile error.
        let sql = if paper_doi_filter.is_some() {
            format!(
                r#"
                SELECT c.id AS claim_id,
                       1 - (c.{column} <=> $1::vector) AS similarity
                FROM claims c
                WHERE (c.properties->>'level')::int = 2
                  AND c.{column} IS NOT NULL
                  AND ($3::timestamptz IS NULL OR c.created_at >= $3::timestamptz)
                  AND EXISTS (
                      SELECT 1 FROM edges e
                      JOIN papers p ON p.id = e.source_id
                      WHERE e.target_id = c.id
                        AND e.relationship = 'asserts'
                        AND p.doi = $4
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
                  AND ($3::timestamptz IS NULL OR c.created_at >= $3::timestamptz)
                ORDER BY c.{column} <=> $1::vector
                LIMIT $2
                "#
            )
        };

        let mut q = sqlx::query_as::<_, ClaimEmbeddingHit>(&sql)
            .bind(query_embedding_pgvector)
            .bind(limit)
            .bind(since);
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

    /// ANN lookup backing the write-side semantic novelty gate (backlog
    /// `1bcaed94`, Task 6.4): the `limit` nearest `is_current` claims to
    /// `query_embedding_pgvector`, ordered closest-first by cosine distance
    /// (`<=>`, matching `idx_claims_embedding_hnsw`'s `vector_cosine_ops` and
    /// every other ANN query in this repo — the backlog plan's SQL sketch
    /// wrote `<->` (L2), but L2 is neither index-accelerated here nor
    /// calibrated for the 0.05/0.15 thresholds).
    ///
    /// Excludes `embedding IS NULL` (no defined distance) and
    /// `is_current = false` rows (superseded/retired claims must never
    /// suppress a new near-paraphrase insert).
    ///
    /// # Errors
    /// Returns [`DbError::QueryFailed`] on database errors.
    #[instrument(skip(pool, query_embedding_pgvector))]
    pub async fn nearest_by_embedding(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        limit: i64,
    ) -> Result<Vec<NearestClaimHit>, DbError> {
        let rows = sqlx::query_as::<_, NearestClaimHit>(
            r#"
            SELECT id AS claim_id,
                   (embedding <=> $1::vector)::float8 AS distance
            FROM claims
            WHERE embedding IS NOT NULL
              AND is_current
            ORDER BY embedding <=> $1::vector
            LIMIT $2
            "#,
        )
        .bind(query_embedding_pgvector)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Hybrid retrieval over current claims: RRF-fuse a dense
    /// (`claims.embedding`, HNSW) leg and a lexical (`content_tsv`, GIN) leg in
    /// one round-trip. Both legs share the `is_current` / `labels @> tags` /
    /// `agent_id` predicates, so the only difference is the relevance signal.
    /// `candidate_pool` caps each leg before fusion; `k_rrf` is the RRF constant.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_hybrid_scoped_since`] so existing callers
    /// (`epigraph-mcp`'s `McpEmbedder::search_hybrid_scoped` novelty path)
    /// keep the call they already have. `None` = no creation-time window,
    /// which is the pre-existing behaviour exactly.
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
        Self::search_hybrid_scoped_since(
            pool,
            query_embedding_pgvector,
            query_text,
            candidate_pool,
            k_rrf,
            limit,
            tags,
            agent_id,
            None,
        )
        .await
    }

    /// [`Self::search_hybrid_scoped`] plus an optional creation-time window.
    ///
    /// `since` is pushed into the WHERE clause of **both** the `dense` and
    /// `lex` CTEs, i.e. ABOVE their `LIMIT $3`. This placement is the whole
    /// point: each leg caps its candidate pool before fusion, so a window
    /// applied to the fused output would first let `candidate_pool`
    /// pre-window rows consume the entire pool and then discard them,
    /// returning `[]` for a query that has a real answer. An empty result
    /// reads to the caller as "nothing changed" — the exact inverse of the
    /// truth — so this is a correctness requirement, not an optimisation.
    ///
    /// The predicate is `created_at`, never `updated_at`:
    /// [`Self::batch_update_truth_values`] bumps `updated_at` on every claim a
    /// belief recomputation touches without changing its content, so an
    /// `updated_at` window would report the whole recomputed corpus as new.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_hybrid_scoped_since(
        pool: &PgPool,
        query_embedding_pgvector: &str,
        query_text: &str,
        candidate_pool: i64,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
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
                  AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
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
                  AND ($8::timestamptz IS NULL OR c.created_at >= $8::timestamptz)
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
        .bind(since) // $8
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Lexical-only retrieval over current claims (`content_tsv` / GIN), ranked
    /// by `ts_rank_cd`. Returns `HybridHit`s with `dense_similarity = None` and
    /// `in_lexical = true`; `rrf_score = 1/(k_rrf + rank)` keeps the score scale
    /// consistent with the hybrid path. Used as `recall`'s embedder-down
    /// fallback — unlike an ILIKE scan it honors the tag/agent scope in SQL.
    ///
    /// Retained at its original arity as a delegating wrapper over
    /// [`Self::search_lexical_scoped_since`]; `None` = no window = today's
    /// behaviour.
    pub async fn search_lexical_scoped(
        pool: &PgPool,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<HybridHit>, DbError> {
        Self::search_lexical_scoped_since(pool, query_text, k_rrf, limit, tags, agent_id, None)
            .await
    }

    /// [`Self::search_lexical_scoped`] plus an optional `created_at >= since`
    /// window, applied in the WHERE clause above `LIMIT` for the same
    /// pool-saturation reason documented on
    /// [`Self::search_hybrid_scoped_since`]. This is the surface `recall`
    /// falls back to when the embedder is down; a window that held on the
    /// hybrid path but not here would silently widen on embedder failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn search_lexical_scoped_since(
        pool: &PgPool,
        query_text: &str,
        k_rrf: i64,
        limit: i64,
        tags: Option<&[String]>,
        agent_id: Option<Uuid>,
        since: Option<DateTime<Utc>>,
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
              AND ($6::timestamptz IS NULL OR c.created_at >= $6::timestamptz)
            ORDER BY ts_rank_cd(c.content_tsv, q) DESC
            LIMIT $3
            "#,
        )
        .bind(query_text) // $1
        .bind(k_rrf) // $2
        .bind(limit) // $3
        .bind(tags_owned) // $4
        .bind(agent_id) // $5
        .bind(since) // $6
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
    /// Thin wrapper over [`ClaimRepository::mark_duplicate_with_repair`],
    /// discarding the repair report. Existing callers that do not need to run
    /// a downstream belief cascade keep the exact pre-cascade signature and
    /// behaviour.
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
        Self::mark_duplicate_with_repair(pool, dup, canonical)
            .await
            .map(|_| ())
    }

    /// [`ClaimRepository::mark_duplicate`] plus in-transaction repair of the
    /// **derived-record layer**, returning what the caller must re-derive.
    ///
    /// # Why the edge migration alone corrupts belief
    /// Edge-factor BBAs are stored on the edge's **target** claim keyed
    /// `perspective_id = edge_id` (`auto_wire_ds_for_edge` →
    /// `store_with_perspective(pool, target_id, ...)`). Before this function
    /// existed, dedup touched only `edges` and `claims`, which left two
    /// distinct classes of wreckage — both instances of the MemTX I2
    /// violation "retracting a belief leaves an orphaned derived record":
    ///
    /// * **Orphaned.** The three collision pre-deletes below remove edges
    ///   whose BBA rows survive: `mass_functions_perspective_id_fkey`
    ///   references `perspectives(id)`, and `perspectives` rows minted by
    ///   `ensure_edge_perspective` have no FK back to `edges`, so nothing
    ///   cascades. The phantom supporter keeps being combined forever.
    /// * **Stranded.** `UPDATE edges SET target_id = canonical` re-points an
    ///   edge while its BBA stays on `dup`, so `canonical` **under-counts**
    ///   that supporter permanently — and it can never self-heal, because
    ///   `MassFunctionRepository::exists_for_perspective` is keyed on
    ///   `perspective_id` alone and ignores `claim_id`, so
    ///   `auto_wire_edge_if_epistemic` short-circuits on it forever.
    ///
    /// Both repairs run inside the same transaction as the edge mutation, so
    /// there is no window in which the graph is observably inconsistent.
    ///
    /// The returned [`DedupRepair`] carries the claims whose cached scalars
    /// are now stale and the edges whose BBAs must be re-derived from
    /// `canonical`'s interval instead of `dup`'s. Recombining those existing
    /// BBA rows would be a numeric no-op — their `masses` were frozen at wire
    /// time — so the caller-side cascade
    /// (`epigraph_engine::retraction_cascade`) invalidates and re-wires them.
    ///
    /// # Errors
    /// Same as [`ClaimRepository::mark_duplicate`].
    #[instrument(skip(pool))]
    pub async fn mark_duplicate_with_repair(
        pool: &PgPool,
        dup: ClaimId,
        canonical: ClaimId,
    ) -> Result<DedupRepair, DbError> {
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
        // `RETURNING id, target_id` (here and on the two pre-deletes below) is
        // the only addition to these statements: the edge rows are about to be
        // gone, and their `perspective_id = id` BBAs — which live on
        // `target_id` — have to be deleted with them, so the ids must be
        // captured before the DELETE commits.
        let mut deleted_edges: Vec<(Uuid, Uuid)> = sqlx::query_as(
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
               ) \
             RETURNING e.id, e.target_id",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *tx)
        .await?;

        // Drop outgoing dup-edges whose migrated triple already exists on canonical.
        // Same aliasing discipline: `e.target_id`, `e.target_type`, `e.relationship`
        // must refer to the outer (being-deleted) row, not the subquery table.
        deleted_edges.extend(
            sqlx::query_as::<_, (Uuid, Uuid)>(
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
                   ) \
                 RETURNING e.id, e.target_id",
            )
            .bind(canon_uuid)
            .bind(dup_uuid)
            .fetch_all(&mut *tx)
            .await?,
        );

        // Symmetric-collision guard for `alternative_of` (migration 042).
        //
        // That relationship is governed by `edges_alternative_of_symmetric_uniq`,
        // a UNIQUE index on `(LEAST(source_id,target_id), GREATEST(source_id,target_id))`
        // — so the pair {A,B} is unique *regardless of direction*.  The two
        // directional pre-deletes above only recognise same-`(source,target,
        // relationship)` triples, so they miss the case where `dup` and
        // `canonical` are joined to a common third claim T by `alternative_of`
        // edges of *opposite* orientation (e.g. `dup→T` and `T→canonical`).
        // Migrating `dup→canonical` would then rewrite `dup→T` into `canonical→T`,
        // whose symmetric key {canonical,T} collides with the existing `T→canonical`
        // edge, tripping the unique index and rolling the whole transaction back
        // before `is_current` is flipped (backlog 2905150e / issue #286).
        //
        // Pre-delete the redundant dup-side `alternative_of` edge whenever
        // `canonical` already shares a symmetric `alternative_of` edge with the
        // same third claim.  Edges where `canonical` is itself an endpoint are
        // left for the self-loop guards in the migration UPDATEs below.
        deleted_edges.extend(
            sqlx::query_as::<_, (Uuid, Uuid)>(
                "DELETE FROM edges AS e \
                 WHERE e.relationship = 'alternative_of' \
                   AND e.source_type = 'claim' AND e.target_type = 'claim' \
                   AND (e.source_id = $2 OR e.target_id = $2) \
                   AND e.source_id != $1 AND e.target_id != $1 \
                   AND EXISTS ( \
                       SELECT 1 FROM edges e2 \
                       WHERE e2.relationship = 'alternative_of' \
                         AND e2.source_type = 'claim' AND e2.target_type = 'claim' \
                         AND e2.id <> e.id \
                         AND LEAST(e2.source_id, e2.target_id) = \
                             LEAST($1, CASE WHEN e.source_id = $2 THEN e.target_id ELSE e.source_id END) \
                         AND GREATEST(e2.source_id, e2.target_id) = \
                             GREATEST($1, CASE WHEN e.source_id = $2 THEN e.target_id ELSE e.source_id END) \
                   ) \
                 RETURNING e.id, e.target_id",
            )
            .bind(canon_uuid)
            .bind(dup_uuid)
            .fetch_all(&mut *tx)
            .await?,
        );

        // ── Derived-record repair, part 1: no ORPHANS ────────────────────────
        // Every edge the three guards just dropped takes its edge-factor BBA
        // with it. Without this, the BBA outlives its edge (nothing cascades
        // from `edges` to `mass_functions`) and keeps being combined into the
        // target's belief forever.
        let deleted_edge_ids: Vec<Uuid> = deleted_edges.iter().map(|(id, _)| *id).collect();
        let deleted_bbas = if deleted_edge_ids.is_empty() {
            0
        } else {
            sqlx::query("DELETE FROM mass_functions WHERE perspective_id = ANY($1)")
                .bind(&deleted_edge_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        };

        let retargeted: Vec<(Uuid,)> = sqlx::query_as(
            "UPDATE edges SET target_id = $1 \
             WHERE target_id = $2 AND target_type = 'claim' AND relationship != 'supersedes' \
               AND NOT (source_type = 'claim' AND source_id = $1) \
             RETURNING id",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *tx)
        .await?;

        // ── Derived-record repair, part 2: no STRANDINGS ─────────────────────
        // Those edges now point at `canonical`, but their BBAs still sit on
        // `dup`. Move them, so `canonical` counts the supporters its edges say
        // it has.
        let retargeted_ids: Vec<Uuid> = retargeted.into_iter().map(|(id,)| id).collect();
        let mut moved_bbas = 0_u64;
        if !retargeted_ids.is_empty() {
            // `canonical` must be assigned to every frame whose BBAs it is
            // about to inherit, or the frame-scoped read paths
            // (`claim_frames.hypothesis_index`) would not see them.
            sqlx::query(
                "INSERT INTO claim_frames (claim_id, frame_id, hypothesis_index) \
                 SELECT $1, cf.frame_id, cf.hypothesis_index FROM claim_frames cf \
                 WHERE cf.claim_id = $2 \
                 ON CONFLICT (claim_id, frame_id) DO NOTHING",
            )
            .bind(canon_uuid)
            .bind(dup_uuid)
            .execute(&mut *tx)
            .await?;

            // Guard `mass_functions_unique_per_perspective`
            // (claim_id, frame_id, source_agent_id, perspective_id, NULLS NOT
            // DISTINCT — migration 034): if `canonical` somehow already holds
            // a row for an incoming perspective, the move would raise and roll
            // the whole dedup back, i.e. an existing caller would acquire a
            // brand-new failure mode. Drop the canonical-side duplicate first;
            // the row arriving from `dup` is the one whose edge survived.
            sqlx::query(
                "DELETE FROM mass_functions mf \
                 WHERE mf.claim_id = $1 AND mf.perspective_id = ANY($3) \
                   AND EXISTS ( \
                       SELECT 1 FROM mass_functions m2 \
                       WHERE m2.claim_id = $2 \
                         AND m2.perspective_id = mf.perspective_id \
                         AND m2.frame_id = mf.frame_id \
                         AND m2.source_agent_id IS NOT DISTINCT FROM mf.source_agent_id \
                   )",
            )
            .bind(canon_uuid)
            .bind(dup_uuid)
            .bind(&retargeted_ids)
            .execute(&mut *tx)
            .await?;

            moved_bbas = sqlx::query(
                "UPDATE mass_functions SET claim_id = $1 \
                 WHERE claim_id = $2 AND perspective_id = ANY($3)",
            )
            .bind(canon_uuid)
            .bind(dup_uuid)
            .bind(&retargeted_ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }

        // Outgoing edges are re-sourced at `canonical`. Their BBAs live on the
        // far end and are unmoved, but their *content* was frozen from `dup`'s
        // interval at wire time, so they now misattribute. They cannot be
        // fixed by recombination — the caller re-derives them (see
        // `DedupRepair::resourced_edges`).
        let resourced_rows: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
            "UPDATE edges SET source_id = $1 \
             WHERE source_id = $2 AND source_type = 'claim' AND relationship != 'supersedes' \
               AND NOT (target_type = 'claim' AND target_id = $1) \
             RETURNING id, target_id, relationship, target_type",
        )
        .bind(canon_uuid)
        .bind(dup_uuid)
        .fetch_all(&mut *tx)
        .await?;
        let resourced_edges: Vec<(Uuid, Uuid, String)> = resourced_rows
            .into_iter()
            .filter(|(_, _, _, target_type)| target_type == "claim")
            .map(|(id, target_id, relationship, _)| (id, target_id, relationship))
            .collect();

        tx.commit().await?;

        // Claims whose cached scalars no longer match their BBA set: the two
        // dedup endpoints, plus every third claim that lost a BBA above.
        let mut stale_claims = vec![canon_uuid, dup_uuid];
        for (_, target) in &deleted_edges {
            if !stale_claims.contains(target) {
                stale_claims.push(*target);
            }
        }

        Ok(DedupRepair {
            stale_claims,
            resourced_edges,
            deleted_bbas,
            moved_bbas,
        })
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

// ── Graph-expanded recall (Task 6.1 / claim 29e789fd) ──

/// Epistemic relationship types followed by [`ClaimRepository::graph_expand_seeds`].
///
/// Matches the traversal set named in claim 29e789fd's design sketch
/// (supports/corroborates/elaborates) — the "argument-chain" subset of
/// `link_epistemic`'s full `EPISTEMIC_RELATIONSHIPS` allowlist. `contradicts`/
/// `refutes`/`generalizes`/`specializes` are intentionally excluded: expansion
/// is meant to pull in claims that reinforce a seed's argument, not claims
/// that merely relate to it in some other epistemic sense.
pub const EXPANSION_RELATIONSHIPS: &[&str] = &["supports", "corroborates", "elaborates"];

/// One claim reached by [`ClaimRepository::graph_expand_seeds`], with the hop
/// count at which it was first discovered (BFS order, so this is the shortest
/// path length from any seed).
#[derive(Debug, Clone, Copy, sqlx::FromRow)]
pub struct GraphExpansionHit {
    pub claim_id: Uuid,
    pub hops: i32,
}

impl ClaimRepository {
    /// Hard cap on the number of distinct claims [`Self::graph_expand_seeds`]
    /// will discover, mirroring the `traverse` MCP tool's `node_limit`
    /// (`.clamp(1, 100)`, default 50). Depth-clamping alone does NOT bound
    /// the work: supports/corroborates/elaborates fan-out over up to 4 hops
    /// on a dense graph can reach thousands of claims, each costing one
    /// sequential `EdgeRepository::get_by_source` round-trip inside a
    /// synchronous `recall_with_context` call. The caller's final
    /// `raw_hits.truncate(want)` bounds the OUTPUT size, not the work done
    /// to produce it — this cap bounds the work itself.
    const MAX_EXPANSION_NODES: usize = 200;

    /// Hard cap on the number of distinct claims [`Self::graph_expand_seeds`]
    /// will *visit* when a `since` window is in force — as opposed to
    /// [`Self::MAX_EXPANSION_NODES`], which caps how many it *emits*.
    ///
    /// Two budgets are needed because out-of-window claims are legitimate
    /// BRIDGES: with one shared budget, 200 pre-window neighbours exhaust the
    /// cap before the walk ever reaches the in-window claim behind them, and
    /// the call returns `[]`. Unwindowed, emitted == visited, so
    /// `MAX_EXPANSION_NODES` binds first and behaviour is bit-identical to
    /// before this budget existed. Windowed, the walk may cost up to
    /// `MAX_EXPANSION_VISITS` sequential `get_by_source` round-trips — 5× the
    /// old worst case, paid only on the path where the old bound produced
    /// wrong answers rather than slow ones.
    const MAX_EXPANSION_VISITS: usize = 1_000;

    /// Bounded multi-hop BFS from a set of seed claims, following outgoing
    /// edges whose relationship is in [`EXPANSION_RELATIONSHIPS`].
    ///
    /// Mirrors what the `traverse` MCP tool does internally (BFS over
    /// `EdgeRepository::get_by_source`, filtering relationship in Rust) rather
    /// than round-tripping through the MCP tool layer — `traverse` only
    /// supports a single relationship string and returns a serialized
    /// `CallToolResult`, neither of which fit a per-seed multi-relationship
    /// expansion called from inside `recall_with_context`.
    ///
    /// Seed IDs themselves are never included in the result (callers already
    /// have them as ANN hits); a claim reachable from more than one seed, or
    /// at more than one hop count, is returned once at its shortest hop
    /// count. `max_depth` is clamped to `[1, 4]` to match `traverse`'s depth
    /// bound; the number of DISTINCT claims EMITTED is separately capped at
    /// [`Self::MAX_EXPANSION_NODES`] (mirroring `traverse`'s `node_limit`) so
    /// a dense graph can't turn one `recall_with_context` call into an
    /// unbounded sequential BFS. When the cap is hit mid-frontier the BFS
    /// stops immediately — same tradeoff `traverse` makes.
    ///
    /// Retained at its original three-argument arity as a delegating wrapper
    /// over [`Self::graph_expand_seeds_since`]; `None` = no window = today's
    /// behaviour, so out-of-workspace callers keep the call they have.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any underlying edge query fails.
    #[instrument(skip(pool, seed_ids))]
    pub async fn graph_expand_seeds(
        pool: &PgPool,
        seed_ids: &[Uuid],
        max_depth: u32,
    ) -> Result<Vec<GraphExpansionHit>, DbError> {
        Self::graph_expand_seeds_since(pool, seed_ids, max_depth, None).await
    }

    /// [`Self::graph_expand_seeds`] plus an optional `created_at >= since`
    /// window on the EMITTED destinations.
    ///
    /// The reached claims are folded into `recall_with_context`'s top-level
    /// `results`, so they must satisfy the caller's window like any other
    /// hit. Two things follow, and they pull in opposite directions:
    ///
    /// 1. **The walk is not pruned.** A claim created in 2024 is a perfectly
    ///    legitimate BRIDGE to a claim created yesterday; stopping at it would
    ///    sever reachability the unwindowed call would have found. So the BFS
    ///    traverses through out-of-window nodes and filters only what it
    ///    emits.
    /// 2. **Out-of-window nodes therefore must not consume the emission
    ///    budget.** Membership is resolved per BFS level, in one batched
    ///    set-membership query, and only in-window destinations count toward
    ///    [`Self::MAX_EXPANSION_NODES`]; the walk itself is bounded separately
    ///    by [`Self::MAX_EXPANSION_VISITS`]. A single shared budget would let
    ///    200 pre-window neighbours exhaust it before the walk reached the one
    ///    in-window claim behind them, and the caller would read the resulting
    ///    `[]` as "nothing changed since T" — the same silent inversion that
    ///    post-filtering a saturated candidate pool produces on the ANN legs.
    ///
    /// Truncation is still possible (a windowed walk can exceed
    /// `MAX_EXPANSION_VISITS` before filling the emission budget), so an empty
    /// return is "nothing in-window within the traversed neighbourhood", not a
    /// proof that nothing in-window is reachable. What it is no longer is an
    /// artefact of out-of-window rows crowding the budget.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if any underlying edge query fails.
    #[instrument(skip(pool, seed_ids))]
    pub async fn graph_expand_seeds_since(
        pool: &PgPool,
        seed_ids: &[Uuid],
        max_depth: u32,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<GraphExpansionHit>, DbError> {
        let max_depth = max_depth.clamp(1, 4) as i32;
        let seeds: std::collections::HashSet<Uuid> = seed_ids.iter().copied().collect();

        // Unwindowed, every visited node is emitted, so the emission cap is
        // the only bound that can bind and the walk is byte-identical to the
        // pre-window implementation. Windowed, the larger visit budget buys
        // the walk room to get past an out-of-window neighbourhood.
        let visit_budget = if since.is_some() {
            Self::MAX_EXPANSION_VISITS
        } else {
            Self::MAX_EXPANSION_NODES
        };

        let mut visited: std::collections::HashSet<Uuid> = seeds.clone();
        let mut discovered_at: std::collections::HashMap<Uuid, i32> =
            std::collections::HashMap::new();
        let mut frontier: Vec<Uuid> = seed_ids.to_vec();
        let mut depth = 0;
        let mut stop = false;

        while depth < max_depth && !frontier.is_empty() && !stop {
            depth += 1;
            let mut next_frontier = Vec::new();
            let mut level_new: Vec<Uuid> = Vec::new();
            'level: for &node in &frontier {
                let outgoing =
                    crate::repos::edge::EdgeRepository::get_by_source(pool, node, "claim").await?;
                for e in outgoing {
                    if !EXPANSION_RELATIONSHIPS.contains(&e.relationship.as_str()) {
                        continue;
                    }
                    if visited.insert(e.target_id) {
                        level_new.push(e.target_id);
                        next_frontier.push(e.target_id);
                        if visited.len() - seeds.len() >= visit_budget {
                            stop = true;
                            break 'level;
                        }
                    }
                }
            }

            // One batched membership round-trip per level (≤ 4 total), not one
            // per node and not a Rust-side filter over an already-truncated
            // page. Iterating `level_new` rather than the SQL row order keeps
            // emission deterministic when the budget truncates mid-level.
            let admitted: Vec<Uuid> = match since {
                None => level_new,
                Some(_) if level_new.is_empty() => level_new,
                Some(since) => {
                    let in_window: std::collections::HashSet<Uuid> = sqlx::query_scalar::<_, Uuid>(
                        "SELECT id FROM claims WHERE id = ANY($1) AND created_at >= $2",
                    )
                    .bind(&level_new)
                    .bind(since)
                    .fetch_all(pool)
                    .await?
                    .into_iter()
                    .collect();
                    level_new
                        .into_iter()
                        .filter(|id| in_window.contains(id))
                        .collect()
                }
            };

            for id in admitted {
                discovered_at.entry(id).or_insert(depth);
                if discovered_at.len() >= Self::MAX_EXPANSION_NODES {
                    stop = true;
                    break;
                }
            }

            frontier = next_frontier;
        }

        Ok(discovered_at
            .into_iter()
            .map(|(claim_id, hops)| GraphExpansionHit { claim_id, hops })
            .collect())
    }

    /// In-degree of epistemic-relationship edges (the full `link_epistemic`
    /// allowlist: supports/corroborates/elaborates/generalizes/specializes/
    /// contradicts/refutes) targeting each of `claim_ids`, batched in one
    /// round-trip. Claims with no such incoming edges are simply absent from
    /// the returned map (degree 0) rather than present with a zero — callers
    /// should treat a missing key as 0.
    ///
    /// One `GROUP BY` query for the whole batch, not one query per claim: the
    /// N+1 shape would be the naive approach given `recall_with_context`
    /// calls this once per page over its (already small, ≤200) candidate
    /// pool, not once per claim.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool, claim_ids))]
    pub async fn in_epistemic_degree_batch(
        pool: &PgPool,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, i64>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let relationships: Vec<String> = crate::repos::edge::EPISTEMIC_RELATIONSHIPS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rows = sqlx::query!(
            r#"
            SELECT target_id, COUNT(*) AS "degree!"
            FROM edges
            WHERE target_id = ANY($1)
              AND source_type = 'claim' AND target_type = 'claim'
              AND relationship = ANY($2)
            GROUP BY target_id
            "#,
            claim_ids,
            &relationships[..],
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|r| (r.target_id, r.degree)).collect())
    }

    /// Live-dispute signal for each of `claim_ids`, batched in one round-trip
    /// (backlog 34d3400d).
    ///
    /// Deliberately narrower than [`Self::in_epistemic_degree_batch`], which
    /// counts the whole `EPISTEMIC_RELATIONSHIPS` allowlist: only
    /// `contradicts`/`refutes` constitute dispute, and only from a contester
    /// that is still `is_current`. A superseded challenger is not live
    /// counter-evidence — without that filter a retracted contester would mark
    /// its target contested permanently.
    ///
    /// Claims with no live dispute are ABSENT from the returned map rather
    /// than present with a zero (same contract as
    /// [`Self::in_epistemic_degree_batch`]); callers treat a missing key as
    /// uncontested.
    ///
    /// `contesting_claim_ids` is capped at the three strongest contesters
    /// (by contesting `truth_value` DESC) so a heavily-disputed claim cannot
    /// bloat a recall page; `dispute_count` is the UNCAPPED total, so callers
    /// can tell "3 contesters" from "30".
    ///
    /// This is a post-fix batch query over ids already returned by retrieval —
    /// deliberately NOT a join inside the ANN/RRF SQL, which would put the
    /// HNSW plan at risk for a signal that does not affect ranking.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool, claim_ids))]
    pub async fn dispute_batch(
        pool: &PgPool,
        claim_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, ClaimDispute>, DbError> {
        if claim_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query!(
            r#"
            SELECT e.target_id,
                   COUNT(*) AS "dispute_count!",
                   (array_agg(e.source_id ORDER BY src.truth_value DESC, src.id))[1:3]
                       AS "contesting_claim_ids!"
            FROM edges e
            JOIN claims src ON src.id = e.source_id AND src.is_current
            WHERE e.target_id = ANY($1)
              AND e.source_type = 'claim' AND e.target_type = 'claim'
              AND e.relationship IN ('contradicts', 'refutes')
            GROUP BY e.target_id
            "#,
            claim_ids,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.target_id,
                    ClaimDispute {
                        dispute_count: r.dispute_count,
                        contesting_claim_ids: r.contesting_claim_ids,
                    },
                )
            })
            .collect())
    }
}

/// Live-dispute signal for a single claim, as returned by
/// [`ClaimRepository::dispute_batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimDispute {
    /// Total number of `is_current` claims contesting this one via
    /// `contradicts`/`refutes`. Uncapped.
    pub dispute_count: i64,
    /// The three strongest contesters (by their own `truth_value` DESC).
    pub contesting_claim_ids: Vec<Uuid>,
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
    /// Returns `DbError::NotFound` if the claim doesn't exist, or
    /// `DbError::InvalidData` if any label in `add` contains shell-variable syntax.
    #[instrument(skip(pool))]
    pub async fn update_labels(
        pool: &PgPool,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        // Reject unexpanded shell syntax on the ADD side only. `remove` stays
        // unvalidated so a bad label already in the array can still be deleted.
        crate::label_guard::reject_shell_expansion(add)?;

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
    ///
    /// This is the path [`Self::patch_claim_atomic_conn`] delegates to, so the
    /// guard below also covers MCP `patch_claim` and HTTP
    /// `PATCH /api/v1/claims/:id`.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if the claim doesn't exist, or
    /// `DbError::InvalidData` if any label in `add` contains shell-variable syntax.
    pub async fn update_labels_conn(
        conn: &mut sqlx::PgConnection,
        claim_id: Uuid,
        add: &[String],
        remove: &[String],
    ) -> Result<Vec<String>, DbError> {
        use sqlx::Row;

        // Reject unexpanded shell syntax on the ADD side only. `remove` stays
        // unvalidated so a bad label already in the array can still be deleted.
        crate::label_guard::reject_shell_expansion(add)?;

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
}

/// How a consolidation restates its sources. Recorded in
/// `properties.merge.mode`; the server does not interpret it — the caller
/// supplies the synthesized content either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsolidateMode {
    /// Combined restatement of all sources.
    Merge,
    /// Higher-level generalisation over the sources.
    Abstract,
    /// Refined restatement (typically N=2, near-identical inputs).
    Rewrite,
}

impl ConsolidateMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Abstract => "abstract",
            Self::Rewrite => "rewrite",
        }
    }

    /// Parse a wire-format mode string.
    ///
    /// # Errors
    /// Returns the offending string when it is not a known mode.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "merge" => Ok(Self::Merge),
            "abstract" => Ok(Self::Abstract),
            "rewrite" => Ok(Self::Rewrite),
            other => Err(other.to_string()),
        }
    }
}

/// Outcome of [`ClaimRepository::consolidate`].
#[derive(Debug, Clone)]
pub struct ConsolidateResult {
    pub merged_id: Uuid,
    pub superseded: Vec<Uuid>,
    pub edges_migrated: u64,
    pub edges_deduped: u64,
    /// `true` when an identical merged claim by this agent already existed and
    /// was returned instead of inserting a second one.
    pub already_existed: bool,
}

/// Minimum / maximum sources accepted by one consolidation.
pub const CONSOLIDATE_MIN_SOURCES: usize = 2;
pub const CONSOLIDATE_MAX_SOURCES: usize = 20;

impl ClaimRepository {
    /// Merge 2..=20 `is_current` claims into one new claim (backlog 44b19521).
    ///
    /// The CALLER supplies `merged_content`: synthesis is an agent-side
    /// concern, storage is the server's — the same division of labour as
    /// `epigraph-ingest-executor`.
    ///
    /// # Why the mark_duplicate convention, not supersede's
    ///
    /// `claims.supersedes` is a single UUID and an N→1 merge has N parents, so
    /// the supersede convention (new row points at the one row it replaced)
    /// cannot express this. Each retired source instead gets
    /// `supersedes = merged_id` as a forwarding pointer — the `mark_duplicate`
    /// convention — which additionally makes `mark_duplicate`'s existing
    /// "already superseded; refusing to overwrite" guard protect merged
    /// sources for free. The reverse fan-out is carried by N `supersedes`
    /// EDGES (merged → source) plus `properties.merge`.
    ///
    /// # Edge collision classes
    ///
    /// Unlike `mark_duplicate`'s canonical, the merged claim is brand new and
    /// therefore has no pre-existing edges — so the "diamond" class cannot
    /// arise here. What can, and is new to N→1, is the CROSS-SOURCE class:
    /// `T→[REL]→s1` and `T→[REL]→s2` both migrate onto `T→[REL]→merged`.
    ///
    /// That matters for two distinct reasons, confirmed by
    /// `docs/architecture/audit-edge-collision-mark-duplicate.md`:
    /// - `alternative_of` carries a symmetric partial unique index
    ///   (`edges_alternative_of_symmetric_uniq`, migration 042), so a collision
    ///   is a HARD error that rolls the whole merge back. Because the index is
    ///   keyed on `(LEAST, GREATEST)` it is direction-agnostic, so those edges
    ///   are deduped ignoring direction.
    /// - Every other relationship collides SILENTLY (migration 018 dropped the
    ///   triple-uniqueness constraint and nothing re-added it), producing
    ///   duplicate rows that feed the same Dempster-Shafer mass twice through
    ///   `auto_create_factor_from_edge`. Belief corruption, not an error.
    ///
    /// `AUTHORED` is excluded from deduplication (migration 017 explicitly
    /// allows it to accumulate) and `supersedes` from migration entirely.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` on a bad source set (wrong count,
    /// duplicates, non-current, already-superseded) and `DbError::NotFound`
    /// when a source id does not exist.
    #[instrument(skip(pool, merged_content), fields(n_sources = source_ids.len()))]
    #[allow(clippy::too_many_lines)]
    pub async fn consolidate(
        pool: &PgPool,
        source_ids: &[Uuid],
        merged_content: &str,
        merged_truth: f64,
        mode: ConsolidateMode,
        reason: &str,
        acting_agent_id: Uuid,
    ) -> Result<ConsolidateResult, DbError> {
        let protocol = |m: String| DbError::QueryFailed {
            source: sqlx::Error::Protocol(m),
        };

        if source_ids.len() < CONSOLIDATE_MIN_SOURCES || source_ids.len() > CONSOLIDATE_MAX_SOURCES
        {
            return Err(protocol(format!(
                "consolidate: need {CONSOLIDATE_MIN_SOURCES}..={CONSOLIDATE_MAX_SOURCES} sources, got {}",
                source_ids.len()
            )));
        }
        let unique: std::collections::HashSet<Uuid> = source_ids.iter().copied().collect();
        if unique.len() != source_ids.len() {
            return Err(protocol("consolidate: duplicate source ids".into()));
        }
        if merged_content.trim().is_empty() {
            return Err(protocol("consolidate: merged_content is empty".into()));
        }

        let mut tx = pool.begin().await?;

        // Lock every source up front so a concurrent merge/supersede cannot
        // interleave between validation and retirement.
        let locked = sqlx::query!(
            r#"
            SELECT id, is_current, supersedes, labels
            FROM claims WHERE id = ANY($1) FOR UPDATE
            "#,
            source_ids,
        )
        .fetch_all(&mut *tx)
        .await?;

        if locked.len() != source_ids.len() {
            let found: std::collections::HashSet<Uuid> = locked.iter().map(|r| r.id).collect();
            let missing = source_ids.iter().find(|id| !found.contains(id));
            return Err(DbError::NotFound {
                entity: "Claim".into(),
                id: missing.copied().unwrap_or_default(),
            });
        }
        for r in &locked {
            if !r.is_current {
                return Err(protocol(format!(
                    "consolidate: source {} is not current",
                    r.id
                )));
            }
            if r.supersedes.is_some() {
                return Err(protocol(format!(
                    "consolidate: source {} is already superseded; refusing to re-merge",
                    r.id
                )));
            }
        }

        // Labels union across sources (same carry rationale as supersede).
        // Properties are deliberately NOT carried — a blanket copy propagates
        // whatever bug the merge may be fixing.
        let mut labels: Vec<String> = locked
            .iter()
            .flat_map(|r| r.labels.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        labels.sort();

        let merge_props = serde_json::json!({
            "merge": {
                "mode": mode.as_str(),
                "merged_from": source_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "merged_at": chrono::Utc::now().to_rfc3339(),
                "reason": reason,
            }
        });
        let content_hash = epigraph_crypto::ContentHasher::hash(merged_content.as_bytes()).to_vec();

        // Post-107 (content_hash, agent_id) uniqueness: an identical merged
        // claim by this agent is returned rather than erroring (novelty-gate
        // style), so a retried merge is idempotent instead of fatal.
        if let Some(existing) = sqlx::query!(
            "SELECT id FROM claims WHERE content_hash = $1 AND agent_id = $2",
            content_hash.as_slice(),
            acting_agent_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.rollback().await?;
            return Ok(ConsolidateResult {
                merged_id: existing.id,
                superseded: vec![],
                edges_migrated: 0,
                edges_deduped: 0,
                already_existed: true,
            });
        }

        let merged_id = sqlx::query_scalar!(
            r#"
            INSERT INTO claims (content, content_hash, truth_value, agent_id, is_current,
                                labels, properties)
            VALUES ($1, $2, $3, $4, true, $5, $6)
            RETURNING id
            "#,
            merged_content,
            content_hash.as_slice(),
            merged_truth.clamp(0.0, 1.0),
            acting_agent_id,
            &labels[..],
            merge_props,
        )
        .fetch_one(&mut *tx)
        .await?;

        // ── Edge migration ──
        //
        // Collect every non-supersedes edge touching a source, dropping those
        // interior to the merge (both endpoints inside the source set) — those
        // would collapse to merged→merged self-loops.
        let candidates = sqlx::query!(
            r#"
            SELECT id, source_id, target_id, source_type, target_type,
                   relationship, created_at
            FROM edges
            WHERE relationship != 'supersedes'
              AND ( (source_id = ANY($1) AND source_type = 'claim')
                 OR (target_id = ANY($1) AND target_type = 'claim') )
            ORDER BY created_at, id
            "#,
            source_ids,
        )
        .fetch_all(&mut *tx)
        .await?;

        let src_set: &std::collections::HashSet<Uuid> = &unique;
        let mut to_delete: Vec<Uuid> = Vec::new();
        let mut survivors: Vec<Uuid> = Vec::new();
        let mut seen: std::collections::HashSet<(Uuid, String, String, i8)> =
            std::collections::HashSet::new();

        for e in &candidates {
            let src_in = e.source_type == "claim" && src_set.contains(&e.source_id);
            let tgt_in = e.target_type == "claim" && src_set.contains(&e.target_id);

            if src_in && tgt_in {
                // Interior to the merge: would become merged→merged.
                to_delete.push(e.id);
                continue;
            }
            // AUTHORED is allowed to accumulate (migration 017) — migrate, never dedupe.
            if e.relationship == "AUTHORED" {
                survivors.push(e.id);
                continue;
            }

            let (other, other_type) = if src_in {
                (e.target_id, e.target_type.clone())
            } else {
                (e.source_id, e.source_type.clone())
            };
            // alternative_of's unique index is keyed on (LEAST, GREATEST) and
            // is therefore direction-agnostic; every other relationship
            // duplicates per-direction.
            let direction = if e.relationship == "alternative_of" {
                0
            } else if src_in {
                1
            } else {
                -1
            };
            let key = (other, other_type, e.relationship.clone(), direction);
            if seen.insert(key) {
                survivors.push(e.id);
            } else {
                // Earliest edge already claimed this slot (ORDER BY created_at, id).
                to_delete.push(e.id);
            }
        }

        let mut edges_deduped = 0_u64;
        if !to_delete.is_empty() {
            edges_deduped = sqlx::query!("DELETE FROM edges WHERE id = ANY($1)", &to_delete[..])
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }

        let mut edges_migrated = 0_u64;
        if !survivors.is_empty() {
            edges_migrated += sqlx::query!(
                r#"
                UPDATE edges SET source_id = $1
                WHERE id = ANY($2) AND source_type = 'claim' AND source_id = ANY($3)
                "#,
                merged_id,
                &survivors[..],
                source_ids,
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();

            edges_migrated += sqlx::query!(
                r#"
                UPDATE edges SET target_id = $1
                WHERE id = ANY($2) AND target_type = 'claim' AND target_id = ANY($3)
                "#,
                merged_id,
                &survivors[..],
                source_ids,
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }

        // Retire sources. One statement: chk_deprecated_no_embedding (migration
        // 052) is a per-statement CHECK, so is_current=false and embedding=NULL
        // must land together.
        sqlx::query!(
            r#"
            UPDATE claims
            SET supersedes = $1, is_current = false, embedding = NULL, updated_at = NOW()
            WHERE id = ANY($2)
            "#,
            merged_id,
            source_ids,
        )
        .execute(&mut *tx)
        .await?;

        // Reverse fan-out: merged → each source, mirroring supersede()'s edge.
        for src in source_ids {
            sqlx::query!(
                r#"
                INSERT INTO edges (source_id, source_type, target_id, target_type,
                                   relationship, properties)
                VALUES ($1, 'claim', $2, 'claim', 'supersedes', $3)
                "#,
                merged_id,
                src,
                serde_json::json!({
                    "reason": reason,
                    "mode": mode.as_str(),
                    "merged_at": chrono::Utc::now().to_rfc3339(),
                }),
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(ConsolidateResult {
            merged_id,
            superseded: source_ids.to_vec(),
            edges_migrated,
            edges_deduped,
            already_existed: false,
        })
    }
}

/// One near-duplicate neighbour of a seed claim.
#[derive(Debug, Clone)]
pub struct ClaimNeighbor {
    pub claim_id: Uuid,
    pub distance: f64,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A claim eligible for the dedup sweep.
#[derive(Debug, Clone)]
pub struct SweepCandidate {
    pub id: Uuid,
    pub truth_value: f64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ClaimRepository {
    /// Page through `is_current` claims that carry an embedding and are
    /// eligible for semantic deduplication (backlog e3732d16).
    ///
    /// Exclusions are policy, not optimisation:
    /// - `telemetry`-labelled claims are never embedded by design (CLAUDE.md),
    ///   so they cannot participate in an ANN sweep at all.
    /// - claims carrying `properties->>'level'` are document-structure rows
    ///   (spine/paragraph/atom). Near-identical paragraphs across two papers
    ///   are a legitimate corpus fact, not a duplicate to collapse.
    /// - claims whose `supersedes` is already set have been merged or
    ///   deduplicated once; re-processing them would rewrite settled lineage.
    ///
    /// Ordered by `created_at, id` so `offset` paging is stable across calls —
    /// the sweep is resumable by design, since the corpus is far larger than
    /// one invocation should touch.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn enumerate_current_embedded(
        pool: &PgPool,
        agent_scope: Option<&[Uuid]>,
        labels_scope: Option<&[String]>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<SweepCandidate>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, truth_value, created_at
            FROM claims
            WHERE is_current
              AND embedding IS NOT NULL
              AND supersedes IS NULL
              AND NOT (labels @> ARRAY['telemetry']::text[])
              AND properties->>'level' IS NULL
              AND ($1::uuid[] IS NULL OR agent_id = ANY($1))
              AND ($2::text[] IS NULL OR labels @> $2)
            ORDER BY created_at, id
            LIMIT $3 OFFSET $4
            "#,
            agent_scope,
            labels_scope,
            limit.clamp(1, 2000),
            offset.max(0),
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| SweepCandidate {
                id: r.id,
                truth_value: r.truth_value,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Nearest `is_current` neighbours of a STORED claim, by cosine distance.
    ///
    /// Mirrors [`Self::nearest_by_embedding`] but seeds from a row already in
    /// the table rather than a caller-supplied vector, which is what a sweep
    /// over existing claims needs.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn nearest_neighbors_of_claim(
        pool: &PgPool,
        claim_id: Uuid,
        k: i64,
    ) -> Result<Vec<ClaimNeighbor>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT c2.id, c2.truth_value, c2.created_at,
                   (c2.embedding <=> (SELECT embedding FROM claims WHERE id = $1)) AS "distance!"
            FROM claims c2
            WHERE c2.is_current
              AND c2.embedding IS NOT NULL
              AND c2.supersedes IS NULL
              AND c2.id != $1
              AND NOT (c2.labels @> ARRAY['telemetry']::text[])
              AND c2.properties->>'level' IS NULL
            ORDER BY c2.embedding <=> (SELECT embedding FROM claims WHERE id = $1)
            LIMIT $2
            "#,
            claim_id,
            k.clamp(1, 50),
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ClaimNeighbor {
                claim_id: r.id,
                distance: r.distance,
                truth_value: r.truth_value,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Content hashes for a set of claims, so a sweep can tell an exact
    /// restatement (safe to `mark_duplicate`) from a merely-similar pair
    /// (needs synthesis via `consolidate`).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool, ids))]
    pub async fn content_hashes_for(
        pool: &PgPool,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<u8>>, DbError> {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query!(
            "SELECT id, content_hash FROM claims WHERE id = ANY($1)",
            ids,
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| (r.id, r.content_hash)).collect())
    }
}
