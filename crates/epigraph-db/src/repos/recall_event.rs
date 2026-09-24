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
    /// The group that owns this audit row — the **querying principal's**
    /// personal group, resolved ONCE by the caller rather than per event by
    /// [`RecallEventRepository::log`], which sits on the tail of every recall.
    ///
    /// `None` means *there was no principal to resolve one from*, and is NOT a
    /// caller's choice about visibility. It selects the instance-wide
    /// declaration, so a caller that reaches it by collapsing a failure into
    /// "no principal" publishes the row.
    ///
    /// **That invariant is enforced by a type, not by this comment.** The MCP
    /// surfaces resolve through `tools::recall::recall_audit_owner_group`,
    /// which returns `Result<Uuid, AuditOwnerUnresolved>` — no variant of that
    /// error means "write it instance-wide", so an unresolvable identity drops
    /// the row. The remaining `None` producer is the library path in
    /// `epigraph-engine`, which has no principal at all and whose `agent_id` is
    /// `None` for the same reason (`recall_events.agent_id` is nullable for
    /// that caller on purpose). See [`RecallEventRepository::log`] for why that
    /// one caller cannot be given a group instead.
    pub owner_group_id: Option<Uuid>,
}

pub struct RecallEventRepository;

impl RecallEventRepository {
    /// Insert one audit row, returning its id.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the insert fails. Callers are
    /// expected to warn and continue rather than propagate.
    ///
    /// Generic over the executor so the MCP surfaces can write on the SAME
    /// transaction, stamped from the querying principal, that resolved the
    /// owner group: `recall_events_tenancy`'s WITH CHECK requires
    /// `agent_id = epigraph_principal_id()` for `epigraph_app`, so on an
    /// unstamped pool connection this insert is refused (batch F review,
    /// measured on the e2e harness: zero rows written).
    #[instrument(skip(executor, event), fields(tool = %event.tool))]
    pub async fn log<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        event: NewRecallEvent,
    ) -> Result<Uuid, DbError> {
        let hash = event
            .query_pgvector
            .as_ref()
            .map(|v| ContentHasher::hash(v.as_bytes()).to_vec());

        // ── Tenancy declaration ──
        //
        // `recall_events` has no parent and no inheritance arm, so migration
        // 074 requires this write to name both columns.
        //
        // `query_text` is the querying agent's raw search string, so the row
        // belongs to that agent and to nobody else: `group` over the agent's
        // personal group, resolved once by the caller and threaded in on
        // `NewRecallEvent` rather than looked up here, on the tail of every
        // recall.
        //
        // THE VISIBILITY IS THE LOAD-BEARING HALF, not the owner. `list`'s
        // predicate is `$bypass OR visibility = 'public' OR owner_group_id =
        // ANY($groups)`, and a `'public'` row satisfies the middle disjunct
        // whatever it is owned by -- which is why threading the group through
        // while leaving `'public'` would still filter nothing. The one-shot
        // backfill stamps these rows `('public', <the agent's personal
        // group>)`, so the owner alone was already right and the predicate was
        // still vacuous.
        //
        // THE AGENT-LESS CASE IS A MEASURED RESIDUAL, NOT A CHOICE. The library
        // path in `epigraph-engine` has no principal at all -- its `agent_id`
        // is `None` -- so there is no personal group to name, and the two
        // memberless sentinel groups cannot stand in for one: migration 062's
        // `recall_events_group_needs_real_group` CHECK forbids pairing `'group'`
        // with either the world or the seed group, because a group-visible row
        // owned by a memberless group is a black hole nobody, including its
        // author, can read back. Refusing the write instead is also wrong: this
        // function is best-effort by contract (see the module header) and
        // `recall_event_test.rs::agentless_event_is_accepted` pins that an
        // agent-less retrieval is still audited. So that ONE caller keeps the
        // instance-wide declaration, and it is the whole of what remains open:
        // `D-PR16-recall-events-are-instance-wide` in
        // `docs/tenancy/progress.json` records it, narrowed.
        let decl = match event.owner_group_id {
            Some(group) => epigraph_core::TenancyDecl::group(group),
            None => epigraph_core::TenancyDecl::instance_wide(),
        };

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
        .fetch_one(executor)
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
    #[instrument(skip(executor, viewer))]
    #[allow(clippy::too_many_arguments)]
    pub async fn list<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
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
        .fetch_all(executor)
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
