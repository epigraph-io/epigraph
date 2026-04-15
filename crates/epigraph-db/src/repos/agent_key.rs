//! Repository for agent key persistence
//!
//! # Design Notes
//!
//! The `KeyRepository` trait in `epigraph-api` is synchronous, which is incompatible
//! with sqlx async operations. Additionally, `epigraph-db` cannot depend on
//! `epigraph-api` without creating a circular dependency.
//!
//! This repository therefore implements a concrete `PgKeyRepository` with async
//! methods that mirror the operations `KeyManager` needs. The `epigraph-api` crate
//! adapts these into the synchronous `KeyRepository` trait using a blocking executor
//! or by restructuring `KeyManager` to accept async repos.
//!
//! The row type (`AgentKeyRow`) uses primitive types to stay decoupled from
//! `epigraph-api`'s domain models (`AgentKey`, `KeyType`, `KeyStatus`).

use crate::errors::DbError;
use chrono::{DateTime, Utc};
use epigraph_core::AgentId;
use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

/// A database row from the `agent_keys` table.
///
/// Uses primitive types to avoid importing `epigraph-api` types and creating
/// a circular dependency. The API layer converts this to `AgentKey`.
#[derive(Debug, Clone)]
pub struct AgentKeyRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    /// Ed25519 public key bytes (32 bytes)
    pub public_key: Vec<u8>,
    /// "signing", "encryption", or "dual_purpose"
    pub key_type: String,
    /// "active", "pending", "rotated", "revoked", or "expired"
    pub status: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub revoked_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Repository for `agent_keys` table operations.
///
/// All methods are async and take a `&PgPool` following the project pattern.
/// No trait is implemented here to avoid circular dependencies with `epigraph-api`.
pub struct AgentKeyRepository;

impl AgentKeyRepository {
    /// Store a new agent key.
    ///
    /// # Errors
    /// Returns `DbError::DuplicateKey` if a key with the same ID already exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(pool, public_key))]
    pub async fn store(
        pool: &PgPool,
        id: Uuid,
        agent_id: AgentId,
        public_key: &[u8],
        key_type: &str,
        status: &str,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Result<AgentKeyRow, DbError> {
        let agent_uuid: Uuid = agent_id.as_uuid();

        let row = sqlx::query!(
            r#"
            INSERT INTO agent_keys (
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            "#,
            id,
            agent_uuid,
            public_key,
            key_type,
            status,
            valid_from,
            valid_until,
            created_at,
        )
        .fetch_one(pool)
        .await
        .map_err(|err| {
            if let sqlx::Error::Database(ref db_err) = err {
                if db_err.is_unique_violation() {
                    return DbError::DuplicateKey {
                        entity: "AgentKey".to_string(),
                    };
                }
            }
            DbError::from(err)
        })?;

        Ok(AgentKeyRow {
            id: row.id,
            agent_id: row.agent_id,
            public_key: row.public_key,
            key_type: row.key_type,
            status: row.status,
            valid_from: row.valid_from,
            valid_until: row.valid_until,
            revocation_reason: row.revocation_reason,
            revoked_by: row.revoked_by,
            created_at: row.created_at,
        })
    }

    /// Get a key by its UUID.
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_by_id(pool: &PgPool, key_id: Uuid) -> Result<Option<AgentKeyRow>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            FROM agent_keys
            WHERE id = $1
            "#,
            key_id
        )
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| AgentKeyRow {
            id: r.id,
            agent_id: r.agent_id,
            public_key: r.public_key,
            key_type: r.key_type,
            status: r.status,
            valid_from: r.valid_from,
            valid_until: r.valid_until,
            revocation_reason: r.revocation_reason,
            revoked_by: r.revoked_by,
            created_at: r.created_at,
        }))
    }

    /// Get the active key for an agent (status = 'active').
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn get_active_key(
        pool: &PgPool,
        agent_id: AgentId,
    ) -> Result<Option<AgentKeyRow>, DbError> {
        let agent_uuid: Uuid = agent_id.as_uuid();

        let row = sqlx::query!(
            r#"
            SELECT
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            FROM agent_keys
            WHERE agent_id = $1
              AND status = 'active'
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            agent_uuid
        )
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| AgentKeyRow {
            id: r.id,
            agent_id: r.agent_id,
            public_key: r.public_key,
            key_type: r.key_type,
            status: r.status,
            valid_from: r.valid_from,
            valid_until: r.valid_until,
            revocation_reason: r.revocation_reason,
            revoked_by: r.revoked_by,
            created_at: r.created_at,
        }))
    }

    /// List all keys for an agent (all statuses).
    ///
    /// # Errors
    /// Returns `DbError::QueryFailed` if the database query fails.
    #[instrument(skip(pool))]
    pub async fn list_by_agent(
        pool: &PgPool,
        agent_id: AgentId,
    ) -> Result<Vec<AgentKeyRow>, DbError> {
        let agent_uuid: Uuid = agent_id.as_uuid();

        let rows = sqlx::query!(
            r#"
            SELECT
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            FROM agent_keys
            WHERE agent_id = $1
            ORDER BY created_at DESC
            "#,
            agent_uuid
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| AgentKeyRow {
                id: r.id,
                agent_id: r.agent_id,
                public_key: r.public_key,
                key_type: r.key_type,
                status: r.status,
                valid_from: r.valid_from,
                valid_until: r.valid_until,
                revocation_reason: r.revocation_reason,
                revoked_by: r.revoked_by,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Update a key's status (and optional revocation fields).
    ///
    /// Used for key rotation (status → 'rotated') and revocation (status → 'revoked').
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no key with the given ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update_status(
        pool: &PgPool,
        key_id: Uuid,
        status: &str,
        revocation_reason: Option<&str>,
        revoked_by: Option<Uuid>,
    ) -> Result<AgentKeyRow, DbError> {
        let row = sqlx::query!(
            r#"
            UPDATE agent_keys
            SET status            = $2,
                revocation_reason = COALESCE($3, revocation_reason),
                revoked_by        = COALESCE($4, revoked_by)
            WHERE id = $1
            RETURNING
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            "#,
            key_id,
            status,
            revocation_reason,
            revoked_by,
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(AgentKeyRow {
                id: r.id,
                agent_id: r.agent_id,
                public_key: r.public_key,
                key_type: r.key_type,
                status: r.status,
                valid_from: r.valid_from,
                valid_until: r.valid_until,
                revocation_reason: r.revocation_reason,
                revoked_by: r.revoked_by,
                created_at: r.created_at,
            }),
            None => Err(DbError::NotFound {
                entity: "AgentKey".to_string(),
                id: key_id,
            }),
        }
    }

    /// Full update of a key row.
    ///
    /// Replaces all mutable fields. Used by `KeyManager::rotate_key` and
    /// `KeyManager::revoke_key` after in-memory state changes.
    ///
    /// # Errors
    /// Returns `DbError::NotFound` if no key with the given ID exists.
    /// Returns `DbError::QueryFailed` for other database errors.
    #[instrument(skip(pool))]
    pub async fn update(
        pool: &PgPool,
        key_id: Uuid,
        status: &str,
        valid_until: Option<DateTime<Utc>>,
        revocation_reason: Option<&str>,
        revoked_by: Option<Uuid>,
    ) -> Result<AgentKeyRow, DbError> {
        let row = sqlx::query!(
            r#"
            UPDATE agent_keys
            SET status            = $2,
                valid_until       = $3,
                revocation_reason = $4,
                revoked_by        = $5
            WHERE id = $1
            RETURNING
                id, agent_id, public_key, key_type, status,
                valid_from, valid_until, revocation_reason, revoked_by, created_at
            "#,
            key_id,
            status,
            valid_until,
            revocation_reason,
            revoked_by,
        )
        .fetch_optional(pool)
        .await?;

        match row {
            Some(r) => Ok(AgentKeyRow {
                id: r.id,
                agent_id: r.agent_id,
                public_key: r.public_key,
                key_type: r.key_type,
                status: r.status,
                valid_from: r.valid_from,
                valid_until: r.valid_until,
                revocation_reason: r.revocation_reason,
                revoked_by: r.revoked_by,
                created_at: r.created_at,
            }),
            None => Err(DbError::NotFound {
                entity: "AgentKey".to_string(),
                id: key_id,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #[sqlx::test(migrations = "../../migrations")]
    async fn test_agent_key_placeholder(_pool: sqlx::PgPool) {
        // Integration tests live in tests/agent_key_tests.rs once migrations exist
    }
}
