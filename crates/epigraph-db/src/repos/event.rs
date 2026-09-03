//! Repository for event log operations.
//!
//! Events track system-wide activity with monotonically increasing
//! graph versions for snapshotting.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Full event row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct EventRow {
    pub id: Uuid,
    pub event_type: String,
    pub actor_id: Option<Uuid>,
    pub payload: serde_json::Value,
    pub graph_version: i64,
    pub created_at: DateTime<Utc>,
}

pub struct EventRepository;

impl EventRepository {
    /// Insert a new event, auto-incrementing graph_version.
    pub async fn insert(
        pool: &PgPool,
        event_type: &str,
        actor_id: Option<Uuid>,
        payload: &serde_json::Value,
    ) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO events (id, event_type, actor_id, payload, graph_version, created_at) \
             VALUES ($1, $2, $3, $4, nextval('events_graph_version_seq'), NOW())",
        )
        .bind(id)
        .bind(event_type)
        .bind(actor_id)
        .bind(payload)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// Recent events, newest first, optionally filtered by type and actor.
    ///
    /// # Tenancy (PR-09)
    ///
    /// `events` is **not** in migration 062's `tier_a` array and has no
    /// `visibility` / `owner_group_id` of its own. But an event payload is not
    /// metadata: `epigraph-events/src/events.rs` puts `claim_id`, `agent_id`
    /// and `initial_truth` in it, so `list_events` was handing a stranger the
    /// id and asserted truth value of every claim written to the graph,
    /// corpus-wide, regardless of that claim's visibility.
    ///
    /// ## The rule, stated as the SQL actually implements it
    ///
    /// **An event is returned unless some uuid appearing anywhere in its
    /// payload names a `claims` row this viewer cannot read.**
    ///
    /// The first revision of this function keyed on `payload->>'claim_id'`
    /// alone, which was default-OPEN for every other payload shape and — worse
    /// — was documented as if it were not. The live emitters refute the
    /// narrower rule directly: `epigraph-api`'s `routes/conflicts.rs` writes
    /// `conflict.resolved` with `claim_a_id` / `claim_b_id` / `winner_id` and
    /// **no** `claim_id`; `routes/gaps.rs` writes `gap.surfaced` with
    /// `challenge_id`; and both MCP `publish_event` and
    /// `POST /api/v1/events` accept caller-supplied payloads, so the key set is
    /// open-ended by construction. Any rule written as an allowlist of keys is
    /// therefore a rule that the next emitter silently escapes.
    ///
    /// So the extraction is deliberately blunt: `regexp_matches` over
    /// `payload::text` with the `'g'` flag finds every uuid-shaped token in the
    /// whole document — nested objects, arrays, keys, and uuids embedded in
    /// free text alike. That over-collects (an `agent_id`, a `challenge_id`, a
    /// uuid quoted inside a `goal` string) and over-collecting is the safe
    /// direction: a token that names no `claims` row cannot suppress anything,
    /// because the `EXISTS` on the next line requires the row to exist first.
    ///
    /// [`crate::repos::ClaimRepository::hidden_claim_ids`] implements the same
    /// rule for the caller-side (in-memory) half of `epigraph-api`'s
    /// `list_events`, and `epigraph-api`'s `payload_uuids` is the Rust mirror
    /// of this regex. The three must agree; they are cross-referenced in all
    /// three places for that reason.
    ///
    /// ## Two shapes that deliberately survive the filter
    ///
    /// * **An event naming no claim at all** — most of them. `NOT EXISTS` over
    ///   an empty match set is true.
    /// * **An event naming a uuid that resolves to no `claims` row** (a
    ///   hard-deleted claim, an `agent_id`, a malformed or foreign id). There
    ///   is no row to classify, no owner to protect, and dropping it would make
    ///   `graph_snapshot`'s replay depend on referential integrity rather than
    ///   on visibility. The earlier revision dropped these; that was a
    ///   behaviour change unrelated to tenancy and it is reverted here.
    ///
    /// No `CASE` guard is needed around the cast, and its absence is not the
    /// short-circuit hazard the earlier revision documented: `regexp_matches`
    /// yields only substrings that already matched the uuid pattern, so
    /// `m[1]::uuid` cannot raise `22P02`. The hazard was real for
    /// `payload->>'claim_id'`, whose value is arbitrary text.
    ///
    /// ## Cost
    ///
    /// One regex pass over each event row the `created_at` ordering touches,
    /// plus a primary-key probe per uuid found. The overwhelming majority of
    /// rows pass, so `LIMIT n` still stops after roughly `n` rows.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`sqlx::Error`] if the query fails.
    pub async fn list(
        pool: &PgPool,
        viewer: &crate::visibility::Viewer,
        event_type: Option<&str>,
        actor_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<EventRow>, sqlx::Error> {
        let sql = viewer.splice(
            "SELECT e.id, e.event_type, e.actor_id, e.payload, e.graph_version, e.created_at \
             FROM events e \
             WHERE ($1::text IS NULL OR e.event_type = $1) \
               AND ($2::uuid IS NULL OR e.actor_id = $2) \
               AND NOT EXISTS ( \
                     SELECT 1 \
                     FROM regexp_matches(e.payload::text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-\
[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 'g') AS m \
                     WHERE EXISTS (SELECT 1 FROM claims cx WHERE cx.id = m[1]::uuid) \
                       AND NOT EXISTS ( \
                             SELECT 1 FROM claims c \
                             WHERE c.id = m[1]::uuid /* {VISIBILITY:c} */ \
                           ) \
                   ) \
             ORDER BY e.created_at DESC LIMIT $3",
            4,
        );
        let mut q = sqlx::query_as::<_, EventRow>(&sql)
            .bind(event_type)
            .bind(actor_id)
            .bind(limit);
        // Guarded, not `unwrap_or(&[])`: `render_predicate` emits nothing for a
        // `Bypass` viewer, so an unconditional bind would send one more
        // parameter than the rendered statement references.
        if let Some(g) = viewer.group_bind() {
            q = q.bind(g);
        }
        q.fetch_all(pool).await
    }

    /// Get the latest graph version number.
    pub async fn get_latest_version(pool: &PgPool) -> Result<i64, sqlx::Error> {
        let version: Option<i64> = sqlx::query_scalar("SELECT MAX(graph_version) FROM events")
            .fetch_one(pool)
            .await?;
        Ok(version.unwrap_or(0))
    }

    /// Fire-and-forget event publish: insert and swallow + log on failure.
    ///
    /// Used at persistence-side hooks (claim/agent creation, tool dispatch)
    /// where event emission must never roll back the underlying write.
    /// Returns the inserted event id on success, `None` on failure (after
    /// logging via `tracing::warn!`).
    ///
    /// This is the canonical sink for the MCP `list_events` surface and
    /// must be used wherever durable event observability is required.
    /// In-memory pushes to `EventStore::push` are NOT visible to MCP and
    /// should be paired with — or replaced by — a call to this method
    /// when MCP visibility is needed.
    pub async fn publish_or_log(
        pool: &PgPool,
        event_type: &str,
        actor_id: Option<Uuid>,
        payload: &serde_json::Value,
    ) -> Option<Uuid> {
        match Self::insert(pool, event_type, actor_id, payload).await {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::warn!(
                    event_type = event_type,
                    actor_id = ?actor_id,
                    error = %err,
                    "EventRepository::publish_or_log: failed to persist event; \
                     downstream write succeeded but observability is degraded"
                );
                None
            }
        }
    }

    /// Connection-scoped variant of `publish_or_log` for repository methods
    /// that operate on `&mut PgConnection` (typically inside a caller's
    /// transaction). Mirrors `publish_or_log` semantics: fire-and-forget,
    /// errors are swallowed and logged.
    ///
    /// **Transactional semantics:** the event INSERT rides the caller's
    /// transaction. If the caller rolls back, the event is rolled back too —
    /// which is the correct behavior here, since we do not want to log
    /// `claim.created` for a claim that never persisted.
    ///
    /// Uses runtime `sqlx::query` (not the compile-time macro) to avoid
    /// adding offline-data churn for callers in transactional contexts.
    pub async fn publish_or_log_conn(
        conn: &mut sqlx::PgConnection,
        event_type: &str,
        actor_id: Option<Uuid>,
        payload: &serde_json::Value,
    ) -> Option<Uuid> {
        let id = Uuid::new_v4();
        match sqlx::query(
            "INSERT INTO events (id, event_type, actor_id, payload, graph_version, created_at) \
             VALUES ($1, $2, $3, $4, nextval('events_graph_version_seq'), NOW())",
        )
        .bind(id)
        .bind(event_type)
        .bind(actor_id)
        .bind(payload)
        .execute(&mut *conn)
        .await
        {
            Ok(_) => Some(id),
            Err(err) => {
                tracing::warn!(
                    event_type = event_type,
                    actor_id = ?actor_id,
                    error = %err,
                    "EventRepository::publish_or_log_conn: failed to persist event; \
                     downstream write may or may not commit (caller's tx)"
                );
                None
            }
        }
    }
}
