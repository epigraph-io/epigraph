//! Labeled-claim view over network-access policies and their challenges.
//!
//! Policies and challenges are ordinary `claims` rows labelled `policy:active`
//! / `policy:network` / `policy:challenge`. These are the statements
//! `epigraph-api`'s `routes/policies.rs` used to hold inline, moved here
//! unchanged (same SQL, binds and row shapes) so that route stays free of SQL.
//! Errors are returned as `sqlx::Error` so the handler's own error mapping is
//! exactly what it was.

use serde_json::Value;
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// Statements behind `/api/v1/policies/*` and `/api/v1/policy-challenges*`.
pub struct PolicyRepository;

impl PolicyRepository {
    /// Active network policies with `truth_value >= min_truth`, highest first.
    pub async fn list_active_network<'e, E>(
        executor: E,
        min_truth: f64,
    ) -> Result<Vec<(Uuid, f64, Value)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT id, truth_value, properties \
             FROM claims \
             WHERE 'policy:active' = ANY(labels) \
               AND 'policy:network' = ANY(labels) \
               AND truth_value >= $1 \
             ORDER BY truth_value DESC",
        )
        .bind(min_truth)
        .fetch_all(executor)
        .await
    }

    /// One policy challenge's `(id, properties)` by id.
    pub async fn get_challenge<'e, E>(
        executor: E,
        id: Uuid,
    ) -> Result<Option<(Uuid, Value)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            "SELECT id, properties FROM claims \
             WHERE id = $1 AND 'policy:challenge' = ANY(labels)",
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Take the transaction-scoped advisory lock that serializes concurrent
    /// creates of the same challenge (keyed on its content). Touches no table.
    pub async fn lock_challenge_create(
        conn: &mut PgConnection,
        content: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtext('epigraph.policy_challenge'), hashtext($1))",
        )
        .bind(content)
        .execute(conn)
        .await
        .map(|_| ())
    }

    /// The oldest challenge already stored for `(content_hash, agent_id)`.
    pub async fn find_challenge_by_hash(
        conn: &mut PgConnection,
        content_hash: &[u8],
        agent_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT id FROM claims \
             WHERE content_hash = $1 AND agent_id = $2 \
               AND 'policy:challenge' = ANY(labels) \
             ORDER BY created_at, id \
             LIMIT 1",
        )
        .bind(content_hash)
        .bind(agent_id)
        .fetch_optional(conn)
        .await
    }

    /// Insert a pending challenge claim (truth 0.5, labels `policy`,
    /// `policy:challenge`) and return its id.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_challenge(
        conn: &mut PgConnection,
        content: &str,
        content_hash: &[u8],
        agent_id: Uuid,
        properties: &Value,
        visibility: Option<&str>,
        owner_group_id: Option<Uuid>,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query_scalar(
            "INSERT INTO claims (content, content_hash, agent_id, truth_value, labels, properties, \
                                 visibility, owner_group_id) \
             VALUES ($1, $2, $3, 0.5, ARRAY['policy','policy:challenge'], $4, $5, $6) \
             RETURNING id",
        )
        .bind(content)
        .bind(content_hash)
        .bind(agent_id)
        .bind(properties)
        .bind(visibility)
        .bind(owner_group_id)
        .fetch_one(conn)
        .await
    }
}
