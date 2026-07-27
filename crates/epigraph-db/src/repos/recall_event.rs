//! Recall audit log (backlog 8cbffa0e / design F5).
//!
//! Records which claims a given recall query returned, so a decision made on
//! retrieved memory can be re-examined later. See `migrations/058_recall_events.sql`
//! for why the query embedding is stored as a BLAKE3 hash rather than a vector.
//!
//! # Best-effort contract
//!
//! [`RecallEventRepository::log`] is called AFTER the recall response is built
//! and is spawned fire-and-forget by its callers: an audit-log failure must
//! never fail, delay, or alter a recall that already has its results. This
//! mirrors the post-commit embedding contract in CLAUDE.md.

use epigraph_crypto::ContentHasher;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::errors::DbError;

/// Default retention window; override with `RECALL_EVENTS_RETENTION_DAYS`.
pub const DEFAULT_RETENTION_DAYS: i32 = 90;

/// One logged recall query.
#[derive(Debug, Clone)]
pub struct RecallEventRow {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    pub tool: String,
    pub query_text: String,
    pub query_embedding_hash: Option<Vec<u8>>,
    pub params: serde_json::Value,
    pub returned_claim_ids: Vec<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// What to record for one recall call.
#[derive(Debug, Clone)]
pub struct NewRecallEvent {
    /// Caller-supplied id. The handler generates this BEFORE spawning the
    /// fire-and-forget insert so it can return `recall_event_id` in the
    /// response without waiting on (or reading back from) the write.
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    pub tool: String,
    pub query_text: String,
    /// The pgvector literal used for the dense leg, if any. Hashed, never
    /// stored raw. `None` when the embedder was unavailable and the query
    /// degraded to lexical-only — which is itself audit-relevant.
    pub query_pgvector: Option<String>,
    pub params: serde_json::Value,
    pub returned_claim_ids: Vec<Uuid>,
}

pub struct RecallEventRepository;

impl RecallEventRepository {
    /// Insert one audit row, returning its id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails. Callers are
    /// expected to warn and continue rather than propagate.
    #[instrument(skip(pool, event), fields(tool = %event.tool))]
    pub async fn log(pool: &PgPool, event: NewRecallEvent) -> Result<Uuid, DbError> {
        let hash = event
            .query_pgvector
            .as_ref()
            .map(|v| ContentHasher::hash(v.as_bytes()).to_vec());

        let row = sqlx::query!(
            r#"
            INSERT INTO recall_events
                (id, agent_id, tool, query_text, query_embedding_hash, params, returned_claim_ids)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
            "#,
            event.id,
            event.agent_id,
            event.tool,
            event.query_text,
            hash.as_deref(),
            event.params,
            &event.returned_claim_ids[..],
        )
        .fetch_one(pool)
        .await?;

        Ok(row.id)
    }

    /// Query the audit log.
    ///
    /// `claim_id` answers "which queries ever surfaced this claim", served by
    /// the GIN index on `returned_claim_ids`.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        pool: &PgPool,
        agent_id: Option<Uuid>,
        claim_id: Option<Uuid>,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<RecallEventRow>, DbError> {
        let claim_filter = claim_id.map(|c| vec![c]);
        let rows = sqlx::query!(
            r#"
            SELECT id, agent_id, tool, query_text, query_embedding_hash,
                   params, returned_claim_ids, created_at
            FROM recall_events
            WHERE ($1::uuid   IS NULL OR agent_id = $1)
              AND ($2::uuid[] IS NULL OR returned_claim_ids @> $2)
              AND ($3::timestamptz IS NULL OR created_at >= $3)
              AND ($4::timestamptz IS NULL OR created_at <= $4)
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            agent_id,
            claim_filter.as_deref(),
            since,
            until,
            limit.clamp(1, 500),
            offset.max(0),
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| RecallEventRow {
                id: r.id,
                agent_id: r.agent_id,
                tool: r.tool,
                query_text: r.query_text,
                query_embedding_hash: r.query_embedding_hash,
                params: r.params,
                returned_claim_ids: r.returned_claim_ids,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Retention window from `RECALL_EVENTS_RETENTION_DAYS`, falling back to
    /// [`DEFAULT_RETENTION_DAYS`] when unset or unparseable.
    #[must_use]
    pub fn retention_days_from_env() -> i32 {
        std::env::var("RECALL_EVENTS_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok())
            .filter(|d| *d > 0)
            .unwrap_or(DEFAULT_RETENTION_DAYS)
    }

    /// Delete rows older than `retention_days`, returning how many were
    /// removed. Recall volume greatly exceeds claim volume, so this table
    /// grows without bound if nothing prunes it; the daily reconciler calls
    /// this.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the delete fails.
    #[instrument(skip(pool))]
    pub async fn prune_older_than(pool: &PgPool, retention_days: i32) -> Result<u64, DbError> {
        let days = retention_days.max(1);
        let result = sqlx::query!(
            r#"
            DELETE FROM recall_events
            WHERE created_at < NOW() - make_interval(days => $1)
            "#,
            days,
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}
