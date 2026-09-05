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

/// `events.event_type` values safe to delete on a retention schedule.
///
/// This is an ALLOWLIST, deliberately — not a denylist of types to keep. A new
/// event type added later is then never silently swept: it simply is not
/// pruned until someone adds it here on purpose. The inverse (prune everything
/// except a keep-list) would silently start deleting any future type.
///
/// `tool.invoked` is pure telemetry: the payload is `{"tool", "read_only"}`
/// with no query, result, or provenance content, so nothing is recoverable
/// from it that is not better recorded elsewhere.
///
/// NOT included, and not to be added without an explicit decision:
/// `claim.created` / `edge.added` / `agent.registered` / `claim.challenged` /
/// `conflict.*` / `synthesis.*` / `workflow.*` — these are the graph's
/// provenance record, and deleting them destroys history that cannot be
/// reconstructed.
pub const PRUNABLE_EVENT_TYPES: &[&str] = &["tool.invoked"];

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

        // ── Tenancy declaration (PR-16), AND A DELIBERATE NON-CHANGE ──
        //
        // `recall_events` has no parent and no inheritance arm, so migration
        // 074 requires this write to name both columns. `instance_wide()`
        // preserves EXACTLY the value the row carried under migration 062's
        // DEFAULT: ('public', world). Nothing about who can read this table
        // changes in PR-16.
        //
        // THAT IS NOT THE RIGHT LONG-TERM ANSWER, and it is recorded here
        // rather than left to be discovered. `query_text` is the querying
        // agent's raw search string, and plan §4.9's leak table rates
        // "MCP get_recall_events -- others' raw search text" a BLOCKER. The
        // correct declaration is `TenancyDecl::group(<the querying agent's
        // personal group>)`, which would make each agent's recall history
        // readable only by that agent.
        //
        // It is not made here, for two stated reasons rather than by omission:
        //   1. It is a READ-path behaviour change -- cross-agent reads of
        //      `get_recall_events` and `RecallEventRepository::list` start
        //      returning fewer rows -- and PR-16's charter is "declare, do not
        //      default". Changing the VALUE while changing the MECHANISM would
        //      make a read regression indistinguishable from a 074 defect.
        //   2. `log` is on the hot path of every `recall` / `recall_with_context`
        //      call, and resolving a personal group per event is an extra round
        //      trip per query. It wants the group threaded in on
        //      `NewRecallEvent`, resolved once by the caller.
        //
        // TRACKED, NOT JUST COMMENTED. A `grep -rn instance_wide` breadcrumb is
        // not a commitment; every other residual in this series carries a `D-`
        // id, and so does this one:
        // `D-PR16-recall-events-are-instance-wide` in
        // `docs/tenancy/progress.json`, owned by the read-path PR. Closing it
        // is a one-line change here plus a `NewRecallEvent` field, resolved
        // once by each of the three callers (`mcp/tools/recall.rs`,
        // `mcp/tools/memory.rs`, `engine/recall.rs`).
        let decl = epigraph_core::TenancyDecl::instance_wide();

        let row = sqlx::query!(
            r#"
            INSERT INTO recall_events
                (id, agent_id, tool, query_text, query_embedding_hash, params,
                 returned_claim_ids, visibility, owner_group_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
            event.id,
            event.agent_id,
            event.tool,
            event.query_text,
            hash.as_deref(),
            event.params,
            &event.returned_claim_ids[..],
            decl.visibility_bind(),
            decl.owner_group_bind(),
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
    #[instrument(skip(pool, viewer))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
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
              AND ($7::bool OR visibility = 'public' OR owner_group_id = ANY($8::uuid[]))
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            agent_id,
            claim_filter.as_deref(),
            since,
            until,
            limit.clamp(1, 500),
            offset.max(0),
            viewer.bypass_bind(),
            viewer.group_bind().unwrap_or(&[]),
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
    /// removed.
    ///
    /// MEASURED, not assumed (prod, 2026-07-28): recall runs ~30x/day
    /// (2,378 `tool.invoked` events over 79 days), so at 90-day retention this
    /// table stabilises around **half a megabyte**. The original design note —
    /// "recall volume greatly exceeds claim volume" — was inherited from the
    /// design doc and never checked against production; it is wrong. Retention
    /// here is housekeeping, NOT a disk-exhaustion control.
    ///
    /// The genuinely unbounded table is `events` (73k rows since 2026-03-06,
    /// nothing prunes it) — see [`Self::prune_telemetry_events`].
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

    /// Delete telemetry rows from `events` older than `retention_days`,
    /// returning how many were removed.
    ///
    /// Only types in [`PRUNABLE_EVENT_TYPES`] are touched. `events` is the
    /// table that actually grows without bound here — 73,236 rows had
    /// accumulated since 2026-03-06 with nothing pruning them — but most of
    /// its volume (`claim.created`, 51k rows) is provenance and must survive.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the delete fails.
    #[instrument(skip(pool))]
    pub async fn prune_telemetry_events(
        pool: &PgPool,
        retention_days: i32,
    ) -> Result<u64, DbError> {
        let days = retention_days.max(1);
        let types: Vec<String> = PRUNABLE_EVENT_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let result = sqlx::query!(
            r#"
            DELETE FROM events
            WHERE event_type = ANY($1)
              AND created_at < NOW() - make_interval(days => $2)
            "#,
            &types[..],
            days,
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Count telemetry rows that [`Self::prune_telemetry_events`] would delete.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    #[instrument(skip(pool))]
    pub async fn count_prunable_events(pool: &PgPool, retention_days: i32) -> Result<i64, DbError> {
        let days = retention_days.max(1);
        let types: Vec<String> = PRUNABLE_EVENT_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "n!" FROM events
            WHERE event_type = ANY($1)
              AND created_at < NOW() - make_interval(days => $2)
            "#,
            &types[..],
            days,
        )
        .fetch_one(pool)
        .await?;
        Ok(row.n)
    }
}
