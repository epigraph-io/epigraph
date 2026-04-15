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

    /// List events with optional type and actor filters.
    pub async fn list(
        pool: &PgPool,
        event_type: Option<&str>,
        actor_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<EventRow>, sqlx::Error> {
        if let Some(et) = event_type {
            if let Some(aid) = actor_id {
                sqlx::query_as::<_, EventRow>(
                    "SELECT id, event_type, actor_id, payload, graph_version, created_at \
                     FROM events WHERE event_type = $1 AND actor_id = $2 \
                     ORDER BY created_at DESC LIMIT $3",
                )
                .bind(et)
                .bind(aid)
                .bind(limit)
                .fetch_all(pool)
                .await
            } else {
                sqlx::query_as::<_, EventRow>(
                    "SELECT id, event_type, actor_id, payload, graph_version, created_at \
                     FROM events WHERE event_type = $1 \
                     ORDER BY created_at DESC LIMIT $2",
                )
                .bind(et)
                .bind(limit)
                .fetch_all(pool)
                .await
            }
        } else if let Some(aid) = actor_id {
            sqlx::query_as::<_, EventRow>(
                "SELECT id, event_type, actor_id, payload, graph_version, created_at \
                 FROM events WHERE actor_id = $1 \
                 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(aid)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as::<_, EventRow>(
                "SELECT id, event_type, actor_id, payload, graph_version, created_at \
                 FROM events ORDER BY created_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }

    /// Get the latest graph version number.
    pub async fn get_latest_version(pool: &PgPool) -> Result<i64, sqlx::Error> {
        let version: Option<i64> = sqlx::query_scalar("SELECT MAX(graph_version) FROM events")
            .fetch_one(pool)
            .await?;
        Ok(version.unwrap_or(0))
    }
}
