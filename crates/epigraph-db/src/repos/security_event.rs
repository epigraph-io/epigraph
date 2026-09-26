//! Repository for security event audit log persistence
//!
//! # Design Notes
//!
//! This repository mirrors the `SecurityAuditLog` trait from `epigraph-api` but
//! uses async methods and primitive types to avoid a circular dependency.
//! The API layer adapts these into the synchronous `SecurityAuditLog` trait.
//!
//! Row types use primitives only. The `details` column stores a JSONB blob that
//! captures event-variant-specific fields (e.g. failure_reason, rotation_reason).
//! The `ip_address` column is INET and is returned as `Option<String>` via ::text cast.
//! The `correlation_id` column is VARCHAR(64) nullable.

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row from the `security_events` table.
///
/// Uses primitive types to avoid importing `epigraph-api` types and creating
/// a circular dependency. The API layer converts this to `SecurityEvent`.
#[derive(Debug, Clone)]
pub struct SecurityEventRow {
    pub id: Uuid,
    /// Discriminator string: "auth_attempt", "signature_verification", etc.
    pub event_type: String,
    /// Optional agent UUID (nullable for events like SuspiciousActivity).
    pub agent_id: Option<Uuid>,
    /// Whether the event was a success (null for events that have no success concept).
    pub success: Option<bool>,
    /// Event-variant-specific fields stored as JSONB.
    pub details: JsonValue,
    /// IP address as text (INET stored as String for portability). Nullable.
    pub ip_address: Option<String>,
    /// User-agent header string from the request. Nullable.
    pub user_agent: Option<String>,
    /// Request correlation ID for distributed tracing. Nullable (VARCHAR(64)).
    pub correlation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Filter criteria for querying `security_events`.
///
/// All fields are optional; omitting a field means "match any value".
#[derive(Debug, Clone, Default)]
pub struct SecurityEventFilter {
    /// Filter by agent UUID.
    pub agent_id: Option<Uuid>,
    /// Filter by event_type discriminator string.
    pub event_type: Option<String>,
    /// Filter events created on or after this time.
    pub from: Option<DateTime<Utc>>,
    /// Filter events created on or before this time.
    pub until: Option<DateTime<Utc>>,
    /// When true, only return rows where `success = false`.
    pub failures_only: bool,
    /// Maximum number of rows to return (ORDER BY created_at DESC).
    pub limit: Option<i64>,
}

/// Repository for `security_events` table operations.
///
/// All methods are async and take a `&PgPool`, following the project pattern.
/// No trait is implemented here to avoid circular dependencies with `epigraph-api`.
pub struct SecurityEventRepository;

impl SecurityEventRepository {
    /// Insert a new security event row. Returns the row as written.
    ///
    /// **The statement deliberately has no `RETURNING` clause.** PostgreSQL
    /// applies a table's SELECT policy to the rows a `RETURNING` produces, so
    /// once migration 077 gives `security_events` a principal-keyed
    /// `security_events_read`, an `INSERT … RETURNING` of an event whose
    /// `agent_id` is not the session principal is refused `42501 new row
    /// violates row-level security policy` — while the identical INSERT without
    /// `RETURNING` succeeds. That would have defeated the whole point of
    /// `security_events_append` being permissive, which exists so that an actor
    /// can never suppress its own audit record by failing a predicate. Both call
    /// sites (`middleware/rate_limit.rs` and `oauth/providers/provision.rs`)
    /// spawn this and discard the returned value behind a `tracing::warn!`, so
    /// the failure would not have surfaced as a 500 — the OAuth provisioning
    /// audit trail would simply have stopped being written. It is invisible to
    /// CI, which connects as a `BYPASSRLS` superuser.
    ///
    /// Echoing the input back is exact: every column is bound from `row`, and
    /// the database defaults nothing here.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the INSERT fails.
    #[instrument(skip(pool, row))]
    pub async fn log(pool: &PgPool, row: SecurityEventRow) -> Result<SecurityEventRow, DbError> {
        // ip_address is passed as text and cast to INET in the query.
        sqlx::query!(
            r#"
            INSERT INTO security_events (
                id, event_type, agent_id, success, details,
                ip_address, user_agent, correlation_id, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9)
            "#,
            row.id,
            row.event_type,
            row.agent_id,
            row.success,
            row.details,
            row.ip_address.clone() as Option<String>,
            row.user_agent,
            row.correlation_id,
            row.created_at,
        )
        .execute(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row)
    }

    /// Whether `client_id` (a token's `sub`) is an ACTIVE `oauth_clients` row
    /// that GRANTS `claims:admin` and is bound to `agent_id`: the exact
    /// predicate migration 111's `epigraph_admin_patch_claim` re-checks
    /// (`ADM02`), for admin writes that do not go through that definer.
    ///
    /// Batch H-b review: the workflow step ops accepted `claims:admin` from the
    /// token's SCOPE alone, so a token whose client record grants nothing (or
    /// whose client was de-scoped after the mint) kept cross-owner workflow
    /// mutation while the same token was refused on `update_labels`.
    /// `oauth_clients` has no row security (077 section 9 keeps it policy-free
    /// so the token mint can update it), so the application login reads it
    /// directly; nothing here needs a viewer.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the SELECT fails.
    pub async fn admin_grant_is_live<'e, E: sqlx::PgExecutor<'e>>(
        executor: E,
        client_id: Uuid,
        agent_id: Uuid,
    ) -> Result<bool, DbError> {
        let live: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM oauth_clients c \
                             WHERE c.id = $1 AND c.agent_id = $2 AND c.status = 'active' \
                               AND 'claims:admin' = ANY (c.granted_scopes))",
        )
        .bind(client_id)
        .bind(agent_id)
        .fetch_one(executor)
        .await?;
        Ok(live)
    }

    /// Query security events matching optional filter criteria.
    ///
    /// Results are ordered by `created_at DESC` (most recent first).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the SELECT fails.
    #[instrument(skip(pool))]
    pub async fn query(
        pool: &PgPool,
        filter: SecurityEventFilter,
    ) -> Result<Vec<SecurityEventRow>, DbError> {
        let limit = filter.limit.unwrap_or(1000).min(10_000);

        // All filter parameters are passed to the parameterized query.
        // NULL parameters are treated as "match any" via IS NULL checks in WHERE.
        // failures_only: when true, only rows with success=false are returned;
        //   success IS NULL rows are excluded (they are not failures by default).
        let rows = sqlx::query!(
            r#"
            SELECT
                id,
                event_type,
                agent_id,
                success,
                details,
                ip_address::text AS ip_address,
                user_agent,
                correlation_id,
                created_at
            FROM security_events
            WHERE
                ($1::uuid IS NULL        OR agent_id   = $1)
            AND ($2::text IS NULL        OR event_type = $2)
            AND ($3::timestamptz IS NULL OR created_at >= $3)
            AND ($4::timestamptz IS NULL OR created_at <= $4)
            AND (NOT $5                  OR success = false)
            ORDER BY created_at DESC
            LIMIT $6
            "#,
            filter.agent_id as Option<Uuid>,
            filter.event_type as Option<String>,
            filter.from as Option<DateTime<Utc>>,
            filter.until as Option<DateTime<Utc>>,
            filter.failures_only,
            limit,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::from)?;

        Ok(rows
            .into_iter()
            .map(|r| SecurityEventRow {
                id: r.id,
                event_type: r.event_type,
                agent_id: r.agent_id,
                success: r.success,
                details: r.details,
                ip_address: r.ip_address,
                user_agent: r.user_agent,
                correlation_id: r.correlation_id,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Count failure events for a specific agent since a given timestamp.
    ///
    /// A row is counted as a failure when `success = false`.
    /// This is used for lockout detection (e.g. brute-force auth attempts).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the COUNT query fails.
    #[instrument(skip(pool))]
    pub async fn count_recent_failures(
        pool: &PgPool,
        agent_id: Uuid,
        since: DateTime<Utc>,
    ) -> Result<i64, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM security_events
            WHERE agent_id   = $1
              AND success     = false
              AND created_at >= $2
            "#,
            agent_id,
            since,
        )
        .fetch_one(pool)
        .await
        .map_err(DbError::from)?;

        Ok(row.count)
    }

    /// Append a security event on a CALLER-SUPPLIED connection.
    ///
    /// [`Self::log`] takes a `&PgPool` and is right for the two call sites that
    /// fire-and-forget from a middleware. This one exists because FINAL-PLAN
    /// §6.5.5's sixth re-validation condition requires the event and the plan
    /// state flip to be the SAME transaction: the handler refuses to dispatch
    /// unless `dispatched_by` matches the `agent_id` on the `security_events`
    /// row the HTTP layer wrote for this `correlation_id`, and an event written
    /// on a separate pool connection can commit while the flip rolls back —
    /// leaving a correlation id that authorises a plan nobody dispatched.
    ///
    /// No `RETURNING`, for the reason [`Self::log`] gives at length: PostgreSQL
    /// applies the SELECT policy to a `RETURNING` projection, so an event whose
    /// `agent_id` is not the session principal would be refused `42501` while
    /// the identical INSERT without it succeeds.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the INSERT fails.
    pub async fn log_conn(
        conn: &mut sqlx::PgConnection,
        row: &SecurityEventRow,
    ) -> Result<(), DbError> {
        sqlx::query(
            r#"
            INSERT INTO security_events (
                id, event_type, agent_id, success, details,
                ip_address, user_agent, correlation_id, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9)
            "#,
        )
        .bind(row.id)
        .bind(&row.event_type)
        .bind(row.agent_id)
        .bind(row.success)
        .bind(&row.details)
        .bind(row.ip_address.as_deref())
        .bind(row.user_agent.as_deref())
        .bind(row.correlation_id.as_deref())
        .bind(row.created_at)
        .execute(&mut *conn)
        .await
        .map_err(DbError::from)
        .map(|_| ())
    }

    /// Does a `security_events` row of this `event_type` and `correlation_id`
    /// exist, attributed to this agent AND to this subject?
    ///
    /// The machine form of FINAL-PLAN §6.5.5's sixth condition. It is written as
    /// an `EXISTS` rather than as "fetch the row and compare" so that the
    /// no-such-row case and the wrong-agent case are the SAME answer — `false` —
    /// and neither can be mistaken for the other by a caller that forgets to
    /// handle an `Option`. A job payload whose correlation id names no event is
    /// exactly the hand-enqueued job this condition exists to refuse, and it must
    /// fail CLOSED.
    ///
    /// `agent_id IS NOT DISTINCT FROM $3` rather than `=`, because `agent_id` is
    /// nullable and `NULL = <uuid>` is `NULL`, which an `EXISTS` reads as false
    /// — the right answer here, but by accident rather than by statement.
    ///
    /// # `subject_key` / `subject` bind the row to what it authorises
    ///
    /// §6.5.5's wording is "the `security_events` row the HTTP layer wrote for
    /// THIS `correlation_id`" for THIS dispatch. Without the subject predicate
    /// the question degrades to "did this agent ever dispatch SOMETHING under
    /// this correlation id", and a correlation id issued for one plan would
    /// satisfy the condition for a job naming another plan of the same
    /// dispatcher. The dispatching route already writes the subject into
    /// `details`, so binding it costs one comparison. A row missing the key, or
    /// carrying a different value, is `false` — the same fail-closed answer as
    /// no row at all.
    ///
    /// # Which connection
    ///
    /// The MAINTENANCE one. Migration 077's `security_events_read` is keyed on
    /// the session principal, and a job handler has no principal, so on an app
    /// connection this returns `false` for every correlation id and the handler
    /// refuses every plan.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the query fails.
    pub async fn correlation_is_attributed_to_conn(
        conn: &mut sqlx::PgConnection,
        event_type: &str,
        correlation_id: &str,
        agent_id: Uuid,
        subject: (&str, Uuid),
    ) -> Result<bool, DbError> {
        let (subject_key, subject_id) = subject;
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM security_events e
                 WHERE e.event_type = $1
                   AND e.correlation_id = $2
                   AND e.agent_id IS NOT DISTINCT FROM $3
                   AND (e.details ->> $4) = $5::text)
            "#,
        )
        .bind(event_type)
        .bind(correlation_id)
        .bind(agent_id)
        .bind(subject_key)
        .bind(subject_id.to_string())
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_security_event_placeholder(_pool: sqlx::PgPool) {
        // Integration tests live in tests/security_event_tests.rs once
        // the migration for security_events exists.
    }
}
